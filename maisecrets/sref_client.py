"""Sensitive References: the resolver client of maisecrets (ai-gateway docs/security/sensitive-references-1576/
16-resolver-client-contract.md, profiles oauth-resolver-1, local-file-1, process-1 and display-1).

A gateway that writes canonical references (`⟦sref:<kind>:<id>⟧`, optionally with a display part) into tool results
resolves them for a client of its own: maisecrets logs in once (OAuth 2.1, PKCE S256, a loopback redirect, the
person consents in the browser), keeps the token in the store, and asks for the values when the model writes a
reference into a file or a command. The model sees only the reference. This is the successor of the vault
references (vault_refs.py, the Client-Vault header) and runs beside them behind the setting `sref_resolver` until it
is proven end to end.

- Discovery: `GET /.well-known/oauth-protected-resource[<path>]` names `sensitive_references.resolve_endpoint`,
  its scope and its sink profiles; the authorization server's metadata names the authorize, token and register
  endpoints.
- Resolve: `POST <resolve_endpoint>` with `Authorization: Bearer srefr_…`, the references, the sink type
  (`local_file` with the file's path, or `process` with the command's name) and gets all values or one error with
  counts. A refused batch is shown as counts; the client never retries one reference at a time.
- The token: `srefr_…` for one hour, a refresh token for 30 days that rotates on each use. Both live in the store,
  under one entry per gateway origin; never in a file of the plugin, never in a log.

An error message holds fixed text, the HTTP status, validated counts and the gateway's host name, which the person
configured in the MCP URL; never a string the gateway or the browser sent, as one could carry a value or an id.

Standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import platform
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

from .vault_refs import Refused, _is_json, _net_errors, _request, origin_of

OPEN, CLOSE = "⟦", "⟧"
# the canonical form, with the optional display part a gateway may add (it is for the model; the resolver reads the id).
# The gateway's contract (pii_display.SREF_TOKEN_RE): a display of 1 to 256 characters, colons allowed (an IPv6
# address), no bracket and no line break
SREF_RE = re.compile(rf"{OPEN}sref:(?P<kind>[A-Za-z0-9_-]{{1,32}}):(?P<id>[A-Za-z0-9_-]{{20,128}})"
                     rf"(?::(?P<display>[^{OPEN}{CLOSE}\r\n\u2028\u2029]{{1,256}}))?{CLOSE}")
SCOPE = "sensitive-references.resolve"
SINKS = {"local_file": "local-file-1", "process": "process-1", "display": "display-1"}
# the sink type of each profile name a server may list; "mcpgate-process-1" is the name before Concept 0.7
_PROFILE_TYPES = {"local-file-1": "local_file", "process-1": "process", "mcpgate-process-1": "process",
                  "display-1": "display"}
MAX_REFS = 100
MAX_REQUEST_BYTES = 64 * 1024
BUDGET = 8.0
# a command the person typed (sref login, sref status): no hook watchdog waits, and a slow mobile network needed more
# than 8 s for the two documents (field report, 2026-11-19). Each try gets this budget; one more try after a timeout
# or no connection
TYPED_BUDGET = 30.0
TYPED_TRIES = 2
# the last good discovery of an MCP URL stands in for a timeout or no connection this long
LAST_GOOD_KEEP = 7 * 86400
_STORE_PREFIX = "_maisecrets_sref_"


def find(text: str) -> list:
    """(reference, canonical, start, end) for each reference in the text; canonical drops the display part."""
    return [(m.group(0), f"{OPEN}sref:{m.group('kind')}:{m.group('id')}{CLOSE}", m.start(), m.end())
            for m in SREF_RE.finditer(text)]


# why the last discover() of this process found no resolver: "timeout", "network" (no connection), "http" (an
# answer other than 200 JSON), "json" (a body that is no JSON object), "absent" (a document that was read and names
# none), or "" when it found one; "status": the HTTP status of the last answer read (None before one came), "named": the
# gateway's document named a resolver, so a later failure is a failed discovery and no server without references
DISCOVERY: dict = {"why": "", "status": None, "named": False}


def _get_json(cfg: dict, url: str, deadline: float, patient: bool = False) -> dict | None:
    try:
        status, headers, body = _request(cfg, "GET", url, {"Accept": "application/json"}, None, deadline,
                                         **({"patient": True} if patient else {}))
    except _net_errors() as exc:
        import socket
        # socket.timeout is no TimeoutError before Python 3.10
        DISCOVERY["why"] = "timeout" if isinstance(exc, (TimeoutError, socket.timeout)) else "network"
        return None
    DISCOVERY["status"] = status
    if status != 200 or not _is_json(headers):
        DISCOVERY["why"] = "http"
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError, UnicodeError):
        DISCOVERY["why"] = "json"
        return None
    if not isinstance(data, dict):
        DISCOVERY["why"] = "json"
        return None
    return data


_SCOPE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


def login_scope(resolve_scope: str, process_scope: object, windows: bool | None = None,
                display_scope: object = None) -> str:
    """The scopes a login asks for: the resolve scope, and the gateway's process scope on top where maisecrets masks
    command output (macOS and Linux: Bash on Windows gets no server value, C27). Without it the gateway refuses the
    process sink (mcpgate 2.0.3815: 403 insufficient_scope), and a file still gets its value."""
    windows = platform.system() == "Windows" if windows is None else windows   # the same test as the Bash refusal
    scopes = [resolve_scope]
    if isinstance(process_scope, str) and _SCOPE_RE.fullmatch(process_scope) and process_scope != resolve_scope \
            and not windows:
        scopes.append(process_scope)
    # the screen of Claude Code with mods (show_values, #30): a click shows one reference's value, never to the AI
    if isinstance(display_scope, str) and _SCOPE_RE.fullmatch(display_scope) and display_scope not in scopes:
        scopes.append(display_scope)
    return " ".join(scopes)


def discover(cfg: dict, mcp_url: str, deadline: float | None = None, patient: bool = False) -> dict | None:
    """The resolver of the gateway behind an MCP URL: {"origin", "resolve", "scope", "sinks", "authorize", "token",
    "register"}, or None when the gateway names none. Every endpoint must be https on the same origin. `patient`:
    only the deadline bounds each request (vault_refs._request)."""
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET
    DISCOVERY.update(why="", status=None, named=False)
    origin = origin_of(mcp_url)
    if not origin:
        DISCOVERY["why"] = "absent"
        return None
    path = urlsplit(mcp_url).path
    path = "" if path == "/" else path
    meta = _get_json(cfg, f"{origin}/.well-known/oauth-protected-resource{path}", deadline, patient)
    if meta is None:
        return None                                   # DISCOVERY names why
    block = meta.get("sensitive_references")
    if not isinstance(block, dict) or origin_of(block.get("resolve_endpoint")) != origin:
        DISCOVERY["why"] = "absent"
        return None
    DISCOVERY["named"] = True
    auth = _get_json(cfg, f"{origin}/.well-known/oauth-authorization-server", deadline, patient)
    if auth is None:
        return None
    ends = {k: auth.get(f"{k}_endpoint") for k in ("authorization", "token", "registration")}
    if any(origin_of(v) != origin for v in ends.values()):
        DISCOVERY["why"] = "absent"
        return None
    sinks = block.get("sink_profiles")
    sinks = [x for x in sinks if isinstance(x, str)] if isinstance(sinks, list) else []
    # the sink type of each listed profile: from the sinks map (Concept 0.7), else from the names this client knows
    table = block.get("sinks") if isinstance(block.get("sinks"), dict) else {}
    types = sorted({(table[x].get("sink_type") if isinstance(table.get(x), dict) else None) or _PROFILE_TYPES.get(x)
                    for x in sinks} - {None})
    # the scope a sink needs on top of the resolve scope: sinks.<profile>.scopes (Concept 0.7), else the named fields
    resolve_scope = block.get("resolve_scope") or SCOPE
    extra: dict = {}
    for x in sinks:
        entry = table.get(x)
        if isinstance(entry, dict) and isinstance(entry.get("scopes"), list):
            more = [c for c in entry["scopes"] if isinstance(c, str) and c != resolve_scope]
            if len(more) == 1:
                extra.setdefault(entry.get("sink_type"), more[0])
    process_scope = block.get("process_scope") if isinstance(block.get("process_scope"), str) else extra.get("process")
    display_scope = block.get("display_scope") if isinstance(block.get("display_scope"), str) else extra.get("display")
    # the gateway's name detection (ai-gateway #1819): its endpoint on the same origin, its own scope. A login asks
    # for that scope only while /maisecrets:ner gateway names this origin: text of tool results goes there (#33)
    ner = None
    ner_scope = block.get("ner_scope")
    if origin_of(block.get("ner_endpoint")) == origin and isinstance(ner_scope, str) and _SCOPE_RE.fullmatch(ner_scope):
        size = block.get("ner_max_chars")
        ner = {"endpoint": block["ner_endpoint"], "scope": ner_scope,
               "max_chars": size if isinstance(size, int) and not isinstance(size, bool) and size > 0 else 20000}
        # its load and the person's quota, read with the same token (counts no quota)
        if origin_of(block.get("ner_status_endpoint")) == origin:
            ner["status"] = block["ner_status_endpoint"]
    conf = cfg.get("remote_detector") if isinstance(cfg, dict) else None
    wants_ner = bool(ner) and isinstance(conf, dict) and conf.get("gateway") == origin
    scope = login_scope(resolve_scope, process_scope, display_scope=display_scope)
    if wants_ner and ner["scope"] not in scope.split():
        scope += " " + ner["scope"]
    return {"origin": origin, "resolve": block["resolve_endpoint"], "ner": ner,
            "scope": scope,
            "process_scope": process_scope if isinstance(process_scope, str) else None,
            "display_scope": display_scope if isinstance(display_scope, str) else None,
            "sinks": sinks, "sink_types": types,
            "authorize": ends["authorization"], "token": ends["token"], "register": ends["registration"]}


def _same_origin(found: object, origin: str | None) -> bool:
    """A discovery record that discover() could have returned for this origin: every endpoint https on it."""
    if not origin or not isinstance(found, dict) or found.get("origin") != origin \
            or not isinstance(found.get("scope"), str) or not isinstance(found.get("sinks"), list):
        return False
    ends = [found.get(k) for k in ("resolve", "authorize", "token", "register")]
    ner = found.get("ner")
    if ner is not None:
        if not isinstance(ner, dict):
            return False
        ends += [ner.get("endpoint")] + ([ner["status"]] if "status" in ner else [])
    return all(origin_of(e) == origin for e in ends)


def _seconds(budgets: list) -> str:
    """"30 s, twice", "30 s" or "30 s and 4 s": the budget of each try."""
    words = [f"{b:.0f} s" for b in budgets]
    if len(words) == 2 and words[0] == words[1]:
        return f"{words[0]}, twice"
    return " and ".join(words)


NO_TIME = "not checked: no time left"


def discover_typed(cfg: dict, mcp_url: str, budget: float = TYPED_BUDGET, tries: int = TYPED_TRIES,
                   end: float | None = None, keep: float = LAST_GOOD_KEEP) -> tuple:
    """discover() for a command the person typed: (found, note). Each try gets `budget` seconds (never past `end`,
    the end of the command's whole discovery), and a timeout or no connection gets one more try. When every try
    failed that way, the last good discovery of this MCP URL (ner_gateway's cache, younger than `keep`) stands in,
    checked again as discover() checks a fresh one; `note` then says so. A failure that is no timeout and no lost
    connection (no document, an HTTP error, a broken answer) never uses it. found None: `note` names the failure for
    a timeout or no connection, else it is "" and DISCOVERY names why. `end` is hard: with less than 1 s left
    before it, no request goes out, and the note is NO_TIME. A login with a record from the cache still runs the
    whole OAuth flow against its endpoints."""
    from . import ner_gateway
    budgets: list = []
    for _ in range(max(1, tries)):
        left = budget if end is None else min(budget, end - time.monotonic())
        if left < 1.0:
            if budgets:
                break                              # no time left for one more try
            DISCOVERY.update(why="", status=None, named=False)
            return None, NO_TIME
        budgets.append(left)
        found = discover(cfg, mcp_url, time.monotonic() + left, True)
        if found:
            ner_gateway._keep(found["origin"], found, mcp_url)
            return found, ""
        if DISCOVERY.get("why") not in ("timeout", "network"):
            return None, ""
    origin = origin_of(mcp_url)
    old = ner_gateway.last_good(origin, mcp_url, keep) if origin else None
    timeout = DISCOVERY.get("why") == "timeout"
    if old and _same_origin(old[0], origin):
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(old[1]))
        return old[0], (f"the gateway {'did not answer in time' if timeout else 'could not be reached'}; maisecrets "
                        f"used the discovery from {when}")
    if timeout:
        return None, f"the gateway did not answer within {_seconds(budgets)}"
    return None, "no connection to the gateway" + (", twice" if len(budgets) == 2 else "")


def discovery_failed() -> bool:
    """The last discover() found no resolver because of a failure, not because the server offers none: no answer, a
    server error, a redirect, a broken document, or any failure after the gateway named a resolver. A 4xx answer or a
    page that is no JSON is an MCP server without the document (most servers), so it offers none."""
    why = DISCOVERY.get("why")
    if not why or (why == "absent" and not DISCOVERY.get("named")):
        return False
    if DISCOVERY.get("named") or why in ("timeout", "network", "json"):
        return True
    status = DISCOVERY.get("status")
    # a redirect is no answer of a server without references: the discovery does not follow it, so it failed
    return why == "http" and isinstance(status, int) and (status >= 500 or 300 <= status < 400)


# ---------------------------------------------------------------- the token in the store --
def _entry(origin: str) -> str:
    return _STORE_PREFIX + hashlib.sha256(origin.encode()).hexdigest()[:16]


def _load(backend, origin: str, deadline: float | None = None) -> dict:
    """The login record of `origin`. `deadline`: the read ends then, or the store raises its timeout (#76)."""
    from .vault import store_deadline
    try:
        with store_deadline(deadline):
            raw = backend.get(_entry(origin))
        data = json.loads(raw) if raw else {}
    except (ValueError, TypeError, AttributeError):
        data = {}
    return data if isinstance(data, dict) else {}


# Lock order, everywhere: the refresh lock (vault_refs.DIR/.sref-refresh.lock) first, then the store lock (HOME/.lock).
# The store lock guards every write of a login record: the jsonfile and encrypted-file stores rewrite the whole file,
# so a Vault write that read the file before a renewal stored its pair would put the spent token back.
STORE_WAIT = 30.0          # a Vault write holds it for moments; a rotated pair must never be dropped for it


def _store_lock():
    from .vault import HOME, _lock_for
    return _lock_for(HOME / ".lock").held(STORE_WAIT)


def _keep(backend, origin: str, data: dict) -> None:
    with _store_lock():
        backend.put(_entry(origin), json.dumps(data), label=f"maisecrets resolver login {origin}")


def _refresh_lock_held(wait: float):
    """The refresh lock for a login or a logout: they wait for a running refresh (at most `wait` seconds), so a
    refresh never restores a login that was just logged out, or overwrites a new one. When the wait ends, they go on
    without it: the refresh then finds another record than it read and drops its result (_refresh_locked)."""
    import contextlib
    from .vault import LockTimeout, _lock_for
    from .vault_refs import DIR

    @contextlib.contextmanager
    def held():
        lock = _lock_for(DIR / ".sref-refresh.lock")
        try:
            lock.enter(wait)
            entered = True
        except (LockTimeout, OSError):
            entered = False
        try:
            yield entered
        finally:
            if entered:
                lock.__exit__(None, None, None)
    return held()


def forget(backend, origin: str) -> None:
    """Log out of one gateway: the tokens and the client id go, after a refresh that runs."""
    with _refresh_lock_held(LOCK_WAIT), _store_lock():
        try:
            backend.delete(_entry(origin))
        except (KeyError, AttributeError):
            pass


def logged_in(backend, origin: str) -> bool:
    return bool(_load(backend, origin).get("refresh"))


# ---------------------------------------------------------------- login --
def pkce() -> tuple:
    """(verifier, S256 challenge)."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _unsent(exc: BaseException) -> bool:
    """The request surely never reached the gateway: no connection, no address, a certificate refused in the
    handshake. Anything else (a timeout, a connection that broke) may have reached it."""
    return isinstance(exc, (ConnectionRefusedError, _gaierror(), _cert_error()))


def register(cfg: dict, found: dict, redirect: str, deadline: float, patient: bool = False) -> str:
    """A client id from the gateway's registration endpoint (RFC 7591) for this loopback redirect. `patient` (a
    typed login): only the deadline bounds the request, and a request that surely never reached the gateway is sent
    once more inside the same deadline."""
    body = json.dumps({"client_name": "maisecrets resolver", "redirect_uris": [redirect],
                       "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                       "token_endpoint_auth_method": "none", "scope": found["scope"]}).encode()
    for attempt in (0, 1):
        try:
            status, headers, raw = _request(cfg, "POST", found["register"],
                                            {"Content-Type": "application/json", "Accept": "application/json"},
                                            body, deadline, **({"patient": True} if patient else {}))
            break
        except _net_errors() as exc:
            if patient and attempt == 0 and _unsent(exc) and deadline - time.monotonic() > 0.5:
                continue
            raise Refused(f"the gateway could not be reached ({type(exc).__name__})") from None
    try:
        client_id = json.loads(raw.decode("utf-8")).get("client_id") if _is_json(headers) else None
    except (ValueError, RecursionError, AttributeError):
        client_id = None
    if status not in (200, 201) or not isinstance(client_id, str) or not client_id:
        raise Refused(f"the gateway did not register the resolver (HTTP {status})")
    return client_id


_OAUTH_PARAMS = frozenset({"response_type", "client_id", "redirect_uri", "scope", "code_challenge",
                           "code_challenge_method", "state", "resource"})


def authorize_url(found: dict, client_id: str, redirect: str, challenge: str, state: str) -> str:
    from urllib.parse import parse_qsl, urlunsplit
    parts = urlsplit(found["authorize"])
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in _OAUTH_PARAMS] + list({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect, "scope": found["scope"],
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
        "resource": found["origin"]}.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _gaierror():
    import socket
    return socket.gaierror


def _cert_error():
    import ssl
    return ssl.SSLCertVerificationError


def _token(cfg: dict, found: dict, form: dict, deadline: float, patient: bool = False) -> dict:
    try:
        status, headers, raw = _request(cfg, "POST", found["token"],
                                        {"Content-Type": "application/x-www-form-urlencoded",
                                         "Accept": "application/json"}, urlencode(form).encode(), deadline,
                                        **({"patient": True} if patient else {}))
    except _net_errors() as exc:
        err = Refused(f"the gateway could not be reached ({type(exc).__name__})")
        err.unsent = _unsent(exc)
        raise err from None
    try:
        data = json.loads(raw.decode("utf-8")) if _is_json(headers) else None
    except (ValueError, RecursionError):
        data = None
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get("access_token"), str) \
            or not isinstance(data.get("refresh_token"), str):
        code = data.get("error") if isinstance(data, dict) else None
        if code == "invalid_grant" and status == 400:
            raise _Revoked(f"the gateway no longer accepts the login (HTTP {status}); send /maisecrets:sref login "
                           "again (with the server's name when more than one offers references)")
        raise Refused(f"the gateway gave no token (HTTP {status}"
                      f"{', ' + code if code in _TOKEN_ERRORS else ''}); send /maisecrets:sref login again")
    return data


def finish_login(cfg: dict, backend, found: dict, client_id: str, redirect: str, code: str, verifier: str,
                 deadline: float | None = None, patient: bool = False) -> None:
    """The code from the loopback redirect, exchanged for the tokens, which go into the store. `patient` (a typed
    login): only the deadline bounds the request. The code is good for one use: the exchange is sent once more only
    when the first request surely never reached the gateway, never after a lost answer."""
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "client_id": client_id,
            "code_verifier": verifier}
    try:
        data = _token(cfg, found, form, deadline, patient)
    except Refused as exc:
        if not (patient and getattr(exc, "unsent", False) and deadline - time.monotonic() > 0.5):
            raise
        data = _token(cfg, found, form, deadline, patient)
    # the pair and the end of the "login ended" mark in one section under the refresh lock: a renewal that ends a
    # login marks it under the same lock, so a newer "ended" is never erased by an older login
    with _refresh_lock_held(LOCK_WAIT):
        _keep(backend, found["origin"], {"client_id": client_id, "access": data["access_token"],
                                         "refresh": data["refresh_token"], "scope": _granted(data, found["scope"]),
                                         "account": _hint(data),
                                         "expires": time.time() + float(data.get("expires_in") or 3600)})
        _clear_ended(found["origin"])


def _hint(data: dict) -> str:
    """The masked account a token belongs to (`account_hint`, Concept 0.7), when the answer has one of a sane form;
    else "". Only shown: two accounts of one person resolve each other's references never (409 unknown)."""
    hint = data.get("account_hint")
    if not isinstance(hint, str) or not 1 <= len(hint) <= 256 or "@" not in hint and hint != "\u2026":
        return ""
    return "" if any(ord(c) < 32 or 0x7f <= ord(c) < 0xa0 for c in hint) else hint


def account(backend, origin: str) -> str:
    """The masked account of the stored login, or "" (an older login, or a gateway without the hint)."""
    hint = _load(backend, origin).get("account")
    return hint if isinstance(hint, str) else ""


def _granted(data: dict, asked: str) -> str:
    """The scope a token response granted: its `scope`, or the one asked for when it names none (RFC 6749 5.1)."""
    got = data.get("scope")
    return got if isinstance(got, str) and got.strip() else asked


def allows(backend, found: dict) -> list:
    """What the login at this gateway allows, in words: files, commands, the screen. A login from before 0.9.0 kept
    no scope and allows files only, as its refresh tokens do (mcpgate 2.0.3815)."""
    scopes = str(_load(backend, found["origin"]).get("scope") or "").split()
    out = ["files"]
    if found.get("process_scope") and found["process_scope"] in scopes:
        out.append("commands")
    if found.get("display_scope") and found["display_scope"] in scopes:
        out.append("the screen")
    return out


def could_allow(found: dict) -> list:
    """What a new login at this gateway would allow on this computer."""
    scopes = found["scope"].split()
    return ["files"] + [w for w, k in (("commands", "process_scope"), ("the screen", "display_scope"))
                        if found.get(k) and found[k] in scopes]


class _Revoked(Refused):
    """The authorization server refused the refresh token for good (invalid_grant): the login is gone."""


# the codes of the contract that an answer may name; any other string from the gateway is never shown, as it could
# carry a value or a reference id (codex review, 2026-11-02)
_TOKEN_ERRORS = frozenset({"invalid_grant", "invalid_client", "invalid_request", "unsupported_grant_type",
                           "access_denied", "invalid_scope", "invalid_target"})
_REASONS = frozenset({"unknown", "revoked", "expired", "malformed", "not_issued"})
_FORBIDDEN = {"insufficient_scope": "the login lacks the resolve scope", "not_enabled": "the person is not allowed to "
              "resolve references", "ineligible_sink": "this sink is not allowed"}


def _digest(token: str | None) -> str | None:
    return hashlib.sha256(token.encode()).hexdigest() if token else None


def _fresh(rec: dict, stale: str | None, margin: float = 60.0) -> str | None:
    """The access token of the record while it holds `margin` seconds, and is not the one the gateway just refused.
    `stale` is the sha256 of that token (_digest): the renewing child gets the digest, never a token, on its stdin."""
    if rec.get("access") and _digest(rec["access"]) != stale and float(rec.get("expires") or 0) - time.time() > margin:
        return rec["access"]
    return None


# ---------------------------------------------------------------- the login that ended --
# A refresh token the gateway refused for good (invalid_grant) ends the login: the record goes, and the time it ended
# is kept here, so the warning of a name source can say "the gateway ended the login" instead of "not logged in".
# The origin and a time only, no token.
def _ended_path():
    from .vault import HOME
    return HOME / "sref-ended.json"


def _update_ended(origin: str, mark: bool, why: str = "revoked") -> None:
    """Mark or clear one origin, read and written under the lock of this file: two processes that change two
    origins at once keep both changes."""
    from .vault import HOME, LockTimeout, _lock_for, atomic_write
    try:
        with _lock_for(HOME / ".sref-ended.lock"):
            try:
                data = json.loads(_ended_path().read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            data = data if isinstance(data, dict) else {}
            if mark:
                data[origin] = {"at": time.time(), "why": why}
            elif data.pop(origin, None) is None:
                return
            atomic_write(_ended_path(), json.dumps(data))
    except (OSError, LockTimeout):
        pass


def _mark_ended(origin: str, why: str = "revoked") -> None:
    """why: "revoked" (the gateway refused the refresh token: invalid_grant) or "uncertain" (a renewal of this token
    did not finish, so it may be spent, and it is not sent again)."""
    _update_ended(origin, True, why)


def _clear_ended(origin: str) -> None:
    _update_ended(origin, False)


def ended_why(origin: str) -> str | None:
    """Why the login at this origin ended, while no login came since: "revoked" (the gateway refused the refresh
    token) or "uncertain" (a renewal did not finish); None when it did not end."""
    try:
        data = json.loads(_ended_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    entry = data.get(origin) if isinstance(data, dict) else None
    if entry is None:
        return None
    why = entry.get("why") if isinstance(entry, dict) else None      # a bare time: a mark of an older version
    return why if why in ("revoked", "uncertain") else "revoked"


def ended(origin: str) -> bool:
    """True when the login at this origin ended (ended_why) and no login came since."""
    return ended_why(origin) is not None


# ---------------------------------------------------------------- the refresh --
RENEW_BUDGET = 30.0        # the renewing child: its wait for the lock, then the token request
LOCK_WAIT = RENEW_BUDGET + 5.0
# the exit codes of the renewing child
_OK, _NO_LOGIN, _REVOKED, _FAILED, _BUSY = 0, 2, 3, 4, 5
_renewals: list = []       # the children of this process, kept so that a poll reaps each


def _refresh_locked(cfg: dict, backend, found: dict, stale: str | None, deadline: float, margin: float = 60.0) -> str:
    """The refresh itself, under the refresh lock with a wait up to `deadline`: the record is read again under the
    lock, so a process that waited takes the pair another one just got, and two never present the same refresh token
    (#1743 H2). A refused refresh token is forgotten and marked as ended. Raises Refused, _Revoked or LockTimeout."""
    from .vault import _lock_for
    from .vault_refs import DIR
    host = urlsplit(found["origin"]).hostname
    lock = _lock_for(DIR / ".sref-refresh.lock")
    lock.enter(max(0.0, deadline - time.monotonic()))     # longer than the lock's own 6 s: a slow refresh
    try:
        rec = _load(backend, found["origin"])
        if not rec.get("refresh"):
            raise Refused(f"maisecrets is not logged in at {host}; the person runs /maisecrets:sref login")
        got = _fresh(rec, stale, margin)
        if got:
            return got
        # The limit of a rotating refresh token without a grace window (ai-gateway #1933, closed as specified): when
        # the answer of a refresh is lost after the gateway rotated (a kill, a crash, a broken connection), the new
        # token is gone and the old one is spent, so no client can keep that login. An unfinished refresh of this
        # very token is therefore never sent again (the gateway would end the login without a word): the login is
        # forgotten and marked as ended, and the person is told at once to log in again.
        old = _digest(rec["refresh"])
        if _inflight(found["origin"]) == old:
            forget(backend, found["origin"])
            _mark_ended(found["origin"], "uncertain")
            _set_inflight(found["origin"], None)
            raise _Revoked(f"the last renewal of the login at {host} did not finish, so its token may be spent; "
                           "send /maisecrets:sref login again")
        _set_inflight(found["origin"], old)
        try:
            data = _token(cfg, found, {"grant_type": "refresh_token", "refresh_token": rec["refresh"],
                                       "client_id": rec.get("client_id", "")}, deadline)
        except _Revoked:
            forget(backend, found["origin"])
            _mark_ended(found["origin"])
            _set_inflight(found["origin"], None)
            raise
        except Refused as exc:
            # only a request that surely never reached the gateway leaves the token unspent. Any answer may come
            # after the gateway rotated (a 5xx, a cut or malformed 200, a 4xx), so the record stays for it
            if getattr(exc, "unsent", False):
                _set_inflight(found["origin"], None)
            raise
        # a login or a logout that did not wait for this refresh (its wait ended) changed the record: this result
        # belongs to a login that is gone, and it never overwrites the newer state
        # under the store lock: the record read again, the new pair stored and the in-flight record cleared, with no
        # Vault write in between that could put the spent token back (lock order: refresh, then store)
        with _store_lock():
            if _digest(_load(backend, found["origin"]).get("refresh")) != old:
                _set_inflight(found["origin"], None)
                raise Refused(f"the login at {host} changed while it was renewed; the new state stays")
            # the new pair goes into the store before the lock is released: no other process can read the spent
            # token once the gateway rotated it (the gateway ends a login whose spent refresh token comes back,
            # ai-gateway #1933: by design, no grace window)
            _keep(backend, found["origin"], {**rec, "access": data["access_token"], "refresh": data["refresh_token"],
                                             "scope": _granted(data, str(rec.get("scope") or SCOPE)),
                                             "account": _hint(data) or rec.get("account", ""),
                                             "expires": time.time() + float(data.get("expires_in") or 3600)})
            _set_inflight(found["origin"], None)        # only after the new pair is in the store
        from . import older_versions
        older_versions.mark_run("refresh")      # versions.json: this version renewed a login (no value, never raises)
        return data["access_token"]
    finally:
        lock.__exit__(None, None, None)


def _inflight_path():
    from .vault import HOME
    return HOME / "sref-inflight.json"


def _inflight(origin: str) -> str | None:
    """The digest of the refresh token a refresh at this origin sent and did not finish, or None."""
    try:
        data = json.loads(_inflight_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    got = data.get(origin) if isinstance(data, dict) else None
    return got.get("old") if isinstance(got, dict) and isinstance(got.get("old"), str) else None


def _set_inflight(origin: str, old: str | None) -> None:
    """Record (old: the digest of the refresh token, never the token) or clear the refresh in flight. Under the
    refresh lock. A record that cannot be written stops the refresh: without it a lost answer would go unnoticed."""
    from .vault import atomic_write
    path = _inflight_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, ValueError):
        data = {}
    data = data if isinstance(data, dict) else {}
    if old is None and origin not in data:
        return
    if old is None:
        data.pop(origin, None)
    else:
        data[origin] = {"old": old, "at": time.time()}
    try:
        atomic_write(path, json.dumps(data))
    except OSError:
        if old is not None:
            raise Refused("the record of a renewal cannot be written; nothing was sent") from None


CHILD_LIFETIME = RENEW_BUDGET + 5.0


def _hard_cap(seconds: float) -> None:
    """End this process after `seconds`, whatever it waits for: SIGALRM (its default action ends the process) where
    there is one, else a watchdog thread that calls os._exit."""
    import os
    import signal
    if hasattr(signal, "alarm"):
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(max(1, int(seconds + 0.999)))
        return
    import threading
    t = threading.Timer(seconds, os._exit, (_FAILED,))
    t.daemon = True
    t.start()


_CHILD = ("import sys\nsys.path.insert(0, sys.argv[1])\nfrom maisecrets.sref_client import _renew_child\n"
          "sys.exit(_renew_child())\n")


def _renew_child() -> int:
    """The detached child of _access: {"cfg", "found", "stale"} on stdin (stale: a digest, no token), the refresh
    with its own budget, the new pair into the store, the exit code and one line of fixed text on stdout. A hard
    lifetime ends the child however it hangs (a lock, the network, a store that does not return): a child killed
    mid-refresh leaves its in-flight record, so the next refresh ends the login loudly instead of reusing the token."""
    import sys
    _hard_cap(CHILD_LIFETIME)
    try:
        job = json.loads(sys.stdin.read())
        cfg, found, stale = job["cfg"], job["found"], job.get("stale")
        from .vault import LockTimeout, make_backend
        try:
            # the store of the parent, by its kind: never the default of a cfg that names none
            backend = make_backend({"backend": job["backend"]})
            _refresh_locked(cfg, backend, found, stale, time.monotonic() + RENEW_BUDGET,
                            float(job.get("margin") or 60.0))
            code, why = _OK, ""
        except _Revoked as exc:
            code, why = _REVOKED, str(exc)
        except LockTimeout:
            code, why = _BUSY, ""
        except Refused as exc:
            code, why = (_NO_LOGIN if "not logged in" in str(exc) else _FAILED), str(exc)
    except Exception as exc:  # noqa: BLE001 - the parent names the failure by its code
        code, why = _FAILED, type(exc).__name__
    try:
        sys.stdout.write(why[:500])
        sys.stdout.flush()
    except (OSError, ValueError):
        pass                                   # the parent gave up and closed the pipe; the store has the pair
    return code


# the store kinds a child can open again by name (vault.make_backend); another backend refreshes in this process
_KINDS = {"JsonFileBackend": "jsonfile", "EncryptedFileBackend": "encrypted-file",
          "WindowsVaultBackend": "windows-vault", "KeychainBackend": "keychain"}


def _spawn(cfg: dict, found: dict, stale: str | None, kind: str, margin: float = 60.0):
    """The renewing child, detached: its own session (process group), so the end of the hook and the client's kill
    of the hook's group do not end the refresh it started; a refresh token the gateway rotated is always kept."""
    import os
    import subprocess
    import sys
    from pathlib import Path
    root = str(Path(__file__).resolve().parent.parent)
    flags: dict = {"start_new_session": True}
    if os.name == "nt":
        flags = {"creationflags": getattr(subprocess, "DETACHED_PROCESS", 0)
                 | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    proc = subprocess.Popen([sys.executable, "-I", "-c", _CHILD, root], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **flags)
    try:
        job = {"cfg": cfg, "found": found, "stale": stale, "backend": kind, "margin": margin}
        proc.stdin.write(json.dumps(job, default=str).encode())
        proc.stdin.close()
    except OSError:
        pass
    _renewals[:] = [p for p in _renewals if p.poll() is None] + [proc]
    return proc


RENEW_AHEAD = 900.0        # a token with less left than this is renewed early, in the background
_RENEW_EVERY = 30.0        # one early renewal per origin and this many seconds, however many hooks run


def renew_ahead(cfg: dict, backend, found: dict, margin: float = RENEW_AHEAD) -> bool:
    """At a calm moment (the session start, after a hook got its token): when the access token of a login has less
    than `margin` seconds left, a detached child renews it now, so that a renewal rarely falls into the short budget
    of a hook. Never waits. True when a child started."""
    try:
        rec = _load(backend, found["origin"])
        if not rec.get("refresh") or _fresh(rec, None, margin):
            return False
        kind = _KINDS.get(type(backend).__name__)
        if kind is None:
            return False
        if not _claim_renewal(found["origin"]):
            return False
        _spawn(cfg, found, None, kind, margin)
        return True
    except (OSError, ValueError):
        return False


def _claim_renewal(origin: str) -> bool:
    """True for one process per origin and _RENEW_EVERY seconds: the time of the last claim is read and written under
    a lock, so two hooks at once never both claim it. False when the lock is busy or the record cannot be written."""
    from .vault import HOME, LockTimeout, _lock_for, atomic_write
    mark = HOME / f".sref-renew-{_entry(origin)[-16:]}"
    lock = _lock_for(HOME / ".sref-renew.lock")
    try:
        with lock.held(0.5):            # a hook never waits long for an early renewal
            try:
                last = float(mark.read_text(encoding="utf-8") or 0)
            except (OSError, ValueError):
                last = 0.0
            if abs(time.time() - last) < _RENEW_EVERY:
                return False
            atomic_write(mark, repr(time.time()))
            return True
    except (OSError, LockTimeout):
        return False


_INLINE: dict = {}


def _inline_gate(origin: str):
    """The process-local lock of the inline renewal of one origin."""
    import threading
    return _INLINE.setdefault(origin, threading.Lock())


def _refresh_inline(cfg: dict, backend, found: dict, stale_d: str | None, deadline: float, host: str) -> str:
    """The refresh in a thread of this process, for when no child can start: the caller waits up to its deadline and
    never past CHILD_LIFETIME, whatever the store or the network do. A thread cannot be killed: one that hangs goes on
    in the background and ends with the process; its in-flight record makes the next refresh end the login loudly
    rather than reuse a token that may be spent."""
    import threading
    from .vault import LockTimeout
    end = min(deadline, time.monotonic() + CHILD_LIFETIME)
    box: dict = {}

    gate = _inline_gate(found["origin"])

    def run() -> None:
        # one refresh per origin in this process at a time, whatever the file lock does for threads
        if not gate.acquire(timeout=max(0.0, end - time.monotonic())):
            box["err"] = LockTimeout("an inline renewal of this origin runs")
            return
        try:
            box["ok"] = _refresh_locked(cfg, backend, found, stale_d, end)
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            box["err"] = exc
        finally:
            gate.release()
    t = threading.Thread(target=run, name="maisecrets-sref-refresh", daemon=True)
    t.start()
    t.join(max(0.0, end - time.monotonic()))
    if t.is_alive():
        raise Renewing(f"the login at {host} is being renewed (it takes longer than this call may wait)")
    if "err" in box:
        if isinstance(box["err"], LockTimeout):
            raise Refused(f"another session renews the login at {host} right now; try again") from None
        raise box["err"]
    return box["ok"]


class Renewing(Refused):
    """The refresh outlasted the caller's deadline; it goes on in a detached child, and the next call uses its pair."""


def _access(cfg: dict, backend, found: dict, deadline: float, stale: str | None = None) -> str:
    """An access token for the resolve. `stale` is a token the gateway answered 401 to. The refresh token rotates on
    each use, and a refresh that the caller abandons halfway loses the new token while the gateway already spent the
    old one: the next refresh then presents a spent token, and the gateway ends the login (field report, 0.9.15, a
    hook with a 2 s budget on a slow network). So the refresh runs in a detached child with its own budget
    (RENEW_BUDGET) under the refresh lock; the caller waits for it up to its own deadline and otherwise goes on
    without a token (Renewing), while the child keeps the new pair."""
    host = urlsplit(found["origin"]).hostname
    stale_d = _digest(stale)
    from .vault import is_store_timeout
    try:
        rec = _load(backend, found["origin"], deadline)
    except RuntimeError as exc:
        if not is_store_timeout(exc):
            raise
        raise Refused(f"the store of this computer did not answer in time for the login at {host}; try again")
    got = _fresh(rec, stale_d)
    if got:
        if not _fresh(rec, stale_d, RENEW_AHEAD):
            renew_ahead(cfg, backend, found)      # less than RENEW_AHEAD left: renewed now, in the background
        return got
    if not rec.get("refresh"):
        raise Refused(f"maisecrets is not logged in at {host}; the person runs /maisecrets:sref login")
    try:
        kind = _KINDS.get(type(backend).__name__)
        if kind is None:
            raise ValueError("a store a child cannot open")
        proc = _spawn(cfg, found, stale_d, kind)
    except (OSError, ValueError):
        # no child can start: the refresh in this process, with the same hard cap
        return _refresh_inline(cfg, backend, found, stale_d, deadline, host)
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(0.02)
    code = proc.poll()
    if code is None:
        raise Renewing(f"the login at {host} is being renewed (the gateway answers slowly); the next call uses it")
    try:
        why = proc.stdout.read(500).decode("utf-8", "replace") if proc.stdout else ""
        if proc.stdout:
            proc.stdout.close()
    except (OSError, ValueError):
        why = ""
    if code == _OK:
        got = _fresh(_load(backend, found["origin"]), stale_d)
        if got:
            return got
        raise Refused(f"the gateway gave no token for {host}; try again")
    if code == _REVOKED:
        raise _Revoked(why or f"the gateway no longer accepts the login at {host}")
    if code == _BUSY:
        raise Refused(f"another session renews the login at {host} right now; try again")
    # a fixed text of this module (Refused), or the error's type name: never a string of the gateway
    raise Refused(why or f"the login at {host} could not be renewed")


# ---------------------------------------------------------------- resolve --
def _counts(reasons: object, batch: int) -> str:
    """The reasons of a refused batch, only the categories of the contract with a plausible count."""
    if not isinstance(reasons, dict):
        return ""
    parts = [f"{n} {k}" for k, n in sorted(reasons.items(), key=lambda kv: str(kv[0]))
             if k in _REASONS and type(n) is int and 0 < n <= batch]
    return ", ".join(parts)


def resolve(cfg: dict, backend, found: dict, refs: list, sink_type: str, destination: str,
            deadline: float | None = None) -> dict:
    """canonical reference -> value for every reference, or Refused (with counts, never a value or an id). All or
    nothing. sink_type is "local_file" (destination: the file's path) or "process" (the command's name)."""
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET
    canon = list(dict.fromkeys(refs))
    if not canon:
        return {}
    host = urlsplit(found["origin"]).hostname
    if sink_type not in SINKS:
        raise Refused("unknown sink type")
    offered = found.get("sink_types")
    if offered is None:   # a found record of an older client: the profile names it knows
        offered = [_PROFILE_TYPES.get(x) for x in found.get("sinks", [])]
    if sink_type not in offered:
        what = {"local_file": "a file", "process": "a command", "display": "the screen"}[sink_type]
        raise Refused(f"{host} does not resolve into {what}")
    if not isinstance(destination, str) or not 1 <= len(destination) <= 4096:
        raise Refused("the destination must be 1 to 4096 characters")
    if len(canon) > MAX_REFS:
        raise Refused(f"{len(canon)} references in one call; at most {MAX_REFS} go in one call")
    body = json.dumps({"references": canon, "sink_type": sink_type, "destination": destination}).encode()
    if len(body) > MAX_REQUEST_BYTES:
        raise Refused(f"the request to {host} is larger than 64 KB")
    token = None
    for attempt in (0, 1):
        token = _access(cfg, backend, found, deadline, stale=token if attempt == 1 else None)
        try:
            status, headers, raw = _request(cfg, "POST", found["resolve"],
                                            {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                             "Accept": "application/json"}, body, deadline)
        except _net_errors() as exc:
            raise Refused(f"{host} could not be reached ({type(exc).__name__})") from None
        try:
            answer = json.loads(raw.decode("utf-8")) if _is_json(headers) else None
        except (ValueError, RecursionError):
            answer = None
        answer = answer if isinstance(answer, dict) else {}
        if status == 401 and attempt == 0:
            continue                       # an access token that expired early: one refresh, then once again
        break
    if status == 200:
        values = answer.get("values")
        if isinstance(values, dict) and all(isinstance(values.get(r), str) for r in canon):
            return {r: values[r] for r in canon}
        raise Refused(f"{host} gave no usable answer (a value is missing or not text)")
    code = answer.get("error")
    if status == 409 and code == "unresolvable":
        detail = _counts(answer.get("reasons"), len(canon))
        raise Refused(f"{host} resolved none of the {len(canon)} references"
                      + (f" ({detail})" if detail else "") + "; use only references from a current result")
    if status == 429:
        raise Refused(f"{host} reached the daily limit of resolved values; try again tomorrow")
    if status == 401:
        raise Refused(f"the login at {host} is no longer valid (consent withdrawn or expired); "
                      "the person runs /maisecrets:sref login")
    if status == 403:
        if code == "insufficient_scope" and sink_type == "display":
            raise Refused(f"the login at {host} does not allow showing values on the screen; the person runs "
                          "/maisecrets:sref login again and allows it on the consent page")
        if code == "insufficient_scope" and sink_type == "process":
            # mcpgate 2.0.3815: a command needs a login whose consent allowed it; a file still works
            raise Refused(f"the login at {host} does not allow real values in commands; the person runs "
                          "/maisecrets:sref login again and allows commands on the consent page")
        why = _FORBIDDEN.get(code, "forbidden") if isinstance(code, str) else "forbidden"
        raise Refused(f"{host} refused the resolve ({why})")
    raise Refused(f"{host} gave no usable answer (HTTP {status})")


def login(cfg: dict, backend, found: dict, open_browser, wait: float = 300.0, budget: float = BUDGET,
          patient: bool = False, end: float | None = None) -> None:
    """The whole login: a loopback listener on 127.0.0.1 (a free port), the registration for its redirect, the
    browser at the authorize URL (`open_browser(url)`), the code back from the redirect (its state must match), and
    the tokens into the store. The listener answers one request and closes. The registration and the token exchange
    get `budget` seconds each (`patient`: only that deadline bounds them). `end`: the whole login ends by then, so the
    wait for the browser leaves `budget` seconds for the token exchange."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs

    box: dict = {}
    state = secrets.token_urlsafe(16)

    done = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        timeout = 5                       # a connection that sends nothing holds its own thread for 5 s, no more

        def log_message(self, *a) -> None:
            pass

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(parts.query).items()}
            ok = parts.path == "/callback" and q.get("state") == state and bool(q.get("code"))
            if ok:
                box.setdefault("code", q["code"])
                done.set()
            elif parts.path == "/callback" and q.get("state") == state and q.get("error") == "access_denied":
                box["denied"] = True
                done.set()
            page = (b"maisecrets: logged in. You can close this tab." if ok else
                    b"maisecrets: the login did not complete. Run it again.")
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

    slots = threading.BoundedSemaphore(16)

    class Listener(ThreadingHTTPServer):
        daemon_threads = True

        def process_request(self, request, client_address):
            # at most 16 connections at once: one more is closed at once, and the listener stays open for the
            # browser's callback (many slow local connections cannot exhaust the threads; codex review, round 3)
            if not slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                slots.release()           # the thread did not start, so it cannot release the slot
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                slots.release()

    httpd = Listener(("127.0.0.1", 0), Handler)
    redirect = f"http://127.0.0.1:{httpd.server_address[1]}/callback"
    # until the callback of this login, the person's refusal or the time: another local process that sends wrong
    # requests, many of them, or a slow one, gets an error page or holds one thread, and the login goes on (codex
    # review, 2026-11-02, two rounds)
    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    try:
        client_id = register(cfg, found, redirect, time.monotonic() + budget, patient)
        if end is not None:
            wait = min(wait, end - budget - time.monotonic())
        verifier, challenge = pkce()
        t.start()
        open_browser(authorize_url(found, client_id, redirect, challenge, state))
        done.wait(max(0.0, wait))
    finally:
        if t.is_alive():
            httpd.shutdown()
        httpd.server_close()
    if "code" not in box:
        raise Refused("the login did not complete: " + ("the person declined it" if box.get("denied") else
                                                         "no matching answer from the browser in time"))
    finish_login(cfg, backend, found, client_id, redirect, box["code"], verifier, time.monotonic() + budget, patient)
