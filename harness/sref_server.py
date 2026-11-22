"""A fake gateway for Sensitive References (ai-gateway docs/security/sensitive-references-1576/
16-resolver-client-contract.md): the resolver side, so that maisecrets/sref_client.py can be tested without a gateway.

- `GET /.well-known/oauth-protected-resource/mcp`: the `sensitive_references` block (resolve endpoint, scope, sink
  profiles local-file-1 and process-1).
- `GET /.well-known/oauth-authorization-server`: the authorize, token and registration endpoints.
- `POST /register` (RFC 7591): a client id for a loopback redirect only.
- `GET /auth/authorize`: PKCE S256 required, scope `sensitive-references.resolve`; the person's consent is given at
  once (`consent = True`) and the answer redirects to the loopback with `code` and `state`.
- `POST /auth/token`: the code (with its verifier) or a refresh token for an access token of one hour and a refresh
  token that rotates on each use.
- `POST /sensitive-references/pairing` (#91, while `pairing` is True): `{"nonce"}` with the person's access token gives
  `{"proof"}`, base64url(HMAC-SHA256(the user's key, "sref-pairing-v1:" + nonce)) without padding; `proof(nonce)`
  computes it as a connector of this gateway would.
- `POST /sensitive-references/resolve`: all values or one error with counts (`unresolvable` 409, `quota_exceeded`
  429, `ineligible_sink` 403, `invalid_token` 401), as the contract says. A success names the gateway's audit event
  of the release (`audit_id`, RESOLVER-PROFILE 12.4); `audit_id = None` answers without it, as an older gateway.

- `POST /sensitive-references/deposit` (#100, while `deposit` is True; maisecrets docs/design/e2e-connector-values.md):
  the values of one call for handles, with the deposit scope; `call(tool, arguments)` is the gateway's replacement at
  call time: the upstream arguments, or the tool result `deposit_refused: <code>`. The targets are the gateway's
  concrete choice (ai-gateway #2008): gitlab_write_actions with the action create_webhook or update_webhook, path
  /token.

`mint(kind, value)` makes a canonical reference; `revoke(ref)` withdraws one; `withdraw()` ends the consent, so every
token dies. Every resolve is recorded in `resolved` (sink type, destination, count; never a value). Standard library
and the openssl command (harness/vault_server.py makes the certificate).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlsplit

from vault_server import _QuietServer, make_cert

PROCESS_SCOPE = "sensitive-references.resolve.process"
DISPLAY_SCOPE = "sensitive-references.resolve.display"
NER_SCOPE = "sensitive-references.ner"
DEPOSIT_SCOPE = "sensitive-references.deposit"
DEPOSIT_TARGETS = [{"tool": "gitlab_write_actions", "when": {"/action": "create_webhook"}, "paths": ["/token"]},
                   {"tool": "gitlab_write_actions", "when": {"/action": "update_webhook"}, "paths": ["/token"]}]
SINK_PROFILES = {"local_file": "local-file-1", "process": "process-1", "display": "display-1"}


class SrefServer:
    def __init__(self, folder: str | None = None, cert: tuple | None = None) -> None:
        self.folder = folder or tempfile.mkdtemp(prefix="sref-server-")
        self.cert, self.key = cert or make_cert(self.folder)
        self.values: dict = {}           # canonical reference -> value
        self.revoked: set = set()
        self.clients: dict = {}          # client_id -> redirect uri
        self.codes: dict = {}            # code -> (client_id, redirect, challenge)
        self.access: dict = {}           # access token -> expiry
        self.refresh: dict = {}          # refresh token -> client_id
        self.consent = True
        self.quota = 1000
        self.used = 0
        self.sinks = list(SINK_PROFILES.values())
        self.resolved: list = []
        self.access_ttl = 3600
        self.evil = False                # True: the error answers carry a reference id in their strings
        self.token_answer = None         # (status, body): the token endpoint answers this to a refresh
        self.refresh_delay = 0.0         # seconds the token endpoint waits before it spends a refresh token
        self.refreshes: list = []        # every refresh token presented, in order (a reuse shows twice)
        # ai-gateway #1933: a reuse window in seconds (None: none, and no field in the metadata). Inside it the token
        # replaced last gets the same pair once more, until the new access token is first used; any other reuse
        # revokes the whole family (every token of that client)
        self.reuse_interval = None
        self.reuse: dict = {}            # spent refresh token -> {"pair", "at", "used"}
        self.families_revoked = 0
        self.renewing: set = set()       # refresh tokens whose renewal runs now: a second use of one is a reuse
        self.drop_answers = 0            # refreshes that rotate and then close the connection without an answer
        self.process_scope = True        # mcpgate 2.0.3815: the process sink needs its own scope
        self.display_scope = True        # ai-gateway #1804: the display sink needs its own scope
        self.scopes: dict = {}           # access or refresh token -> the scope it was granted
        self.pairing = True              # #91: the pairing endpoint in the metadata, and its answer
        self.pair_key = secrets.token_bytes(32)   # K_user of the one user of this fake
        self.pair_answer = None          # (status, body): the pairing endpoint answers this instead
        self.pairing_named = None        # what the metadata names as pairing_endpoint instead (a broken one)
        self.pairings: list = []         # the nonce of each pairing request (a test checks what the client sent)
        self.deposit = False             # #100: the deposit fields in the metadata, and the deposit endpoint
        self.deposit_fields: dict = {}   # fields that replace or add to the deposit fields of the metadata
        self.deposit_answer = None       # (status, body, headers): the deposit endpoint answers this instead
        self.deposit_delay = 0.0         # seconds the deposit endpoint waits before it answers
        self.deposits: dict = {}         # handle -> record (the value, as the gateway keeps it until the call)
        self.deposit_requests: list = [] # each request as received, with the values unpadded
        self.upstream: list = []         # the arguments each call sent upstream, after the replacement
        self.ner = False                 # ai-gateway #1819: the name endpoint and its scope, while the switch is on
        self.ner_answer = None           # (status, body): the name endpoint answers this instead
        self.ner_texts: list = []        # every text the name endpoint got
        self.ner_word = "Okafor"         # the endpoint finds this word as a person
        self.ner_delay = 0.0             # seconds the endpoint waits before it answers
        # RESOLVER-PROFILE 12.4 (SC-28): a success names the audit event of the release; a refusal never does. "auto":
        # a new id per success (kept in `audit_ids`); None: no field, as an older gateway; anything else as it is
        self.audit_id: object = "auto"
        self.audit_ids: list = []
        # the protected resource document of /mcp: each GET takes the next delay of this list (seconds) before it
        # answers, and each GET while `discovery_drops` is above 0 closes the connection without an answer
        self.discovery_delays: list = []
        self.discovery_drops = 0
        self.discovery_gets = 0
        # POST /register and the exchange of a code: each takes the next delay of its list (seconds) before it
        # answers; every code exchange is counted (a code is spent at once, as on the gateway)
        self.register_delays: list = []
        self.code_delays: list = []
        self.code_exchanges = 0
        # GET /sensitive-references/ner/status (ai-gateway v2.0.3913): the load, the client slot and the quota
        self.ner_status = {"service": {"workers": 4, "busy_workers": 1, "waiting_requests": 0, "in_use_share": 0.25},
                           "client_path": {"free": True, "gateway_lookups_running": False},
                           "quota": {"requests_per_minute": 60, "requests_left": 59, "chars_per_minute": 200000,
                                     "chars_left": 199951, "resets_in_s": 59}, "max_chars": 20000}
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a) -> None:
                pass

            def _send(self, status: int, body: object, extra: dict | None = None) -> None:
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                if parts.path == "/sensitive-references/ner/status" and server.ner:
                    auth = self.headers.get("Authorization", "")
                    token = auth[7:] if auth.startswith("Bearer ") else ""
                    if float(server.access.get(token, 0)) < time.time():
                        return self._send(401, {"error": "invalid_token"})
                    if NER_SCOPE not in server.scopes.get(token, "").split():
                        return self._send(403, {"error": "insufficient_scope"})
                    return self._send(200, server.ner_status)
                if parts.path == "/.well-known/oauth-protected-resource/mcp":
                    server.discovery_gets += 1
                    if server.discovery_drops > 0:
                        server.discovery_drops -= 1
                        self.close_connection = True
                        self.connection.close()
                        return None
                    if server.discovery_delays:
                        time.sleep(server.discovery_delays.pop(0))
                    return self._send(200, {
                        "resource": server.url + "/mcp", "authorization_servers": [server.url],
                        "sensitive_references": {"resolve_endpoint": server.url + "/sensitive-references/resolve",
                                                 "resolve_scope": "sensitive-references.resolve",
                                                 **({"process_scope": PROCESS_SCOPE} if server.process_scope else {}),
                                                 **({"display_scope": DISPLAY_SCOPE} if server.display_scope else {}),
                                                 "resolver_profiles": ["oauth-resolver-1"],
                                                 **({"pairing_endpoint":
                                                     server.url + "/sensitive-references/pairing"
                                                     if server.pairing_named is None else server.pairing_named}
                                                    if server.pairing else {}),
                                                 **({"refresh_reuse_interval": server.reuse_interval}
                                                    if server.reuse_interval is not None else {}),
                                                 "sink_profiles": server.sinks,
                                                 "sinks": {p: {"sink_type": t} for t, p in SINK_PROFILES.items()
                                                           if p in server.sinks},
                                                 **({"ner_endpoint": server.url + "/sensitive-references/ner",
                                                     "ner_scope": NER_SCOPE, "ner_format": "hf",
                                                     "ner_max_chars": 20000, "ner_labels": ["PER", "ORG", "LOC"],
                                                     "ner_status_endpoint":
                                                         server.url + "/sensitive-references/ner/status"}
                                                    if server.ner else {}),
                                                 **(server._deposit_meta() if server.deposit else {}),
                                                 "status": "experimental"}})
                if parts.path == "/.well-known/oauth-authorization-server":
                    return self._send(200, {"issuer": server.url,
                                            "authorization_endpoint": server.url + "/auth/authorize",
                                            "token_endpoint": server.url + "/auth/token",
                                            "registration_endpoint": server.url + "/register",
                                            "code_challenge_methods_supported": ["S256"]})
                if parts.path == "/auth/authorize":
                    q = {k: v[0] for k, v in parse_qs(parts.query).items()}
                    redirect = q.get("redirect_uri", "")
                    if (server.clients.get(q.get("client_id")) != redirect or q.get("code_challenge_method") != "S256"
                            or q.get("scope") not in server._login_scopes() or not server.consent
                            or q.get("response_type") != "code" or q.get("resource") != server.url):
                        return self._send(400, {"error": "invalid_request"})
                    code = secrets.token_urlsafe(16)
                    server.codes[code] = (q["client_id"], redirect, q.get("code_challenge", ""), q["scope"])
                    self.send_response(302)
                    self.send_header("Location",
                                     redirect + "?" + urlencode({"code": code, "state": q.get("state", "")}))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                self._send(404, {"error": "not_found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                if self.path == "/register":
                    if server.register_delays:
                        time.sleep(server.register_delays.pop(0))
                    body = json.loads(raw or b"{}")
                    uris = body.get("redirect_uris") or []
                    target = urlsplit(uris[0]) if len(uris) == 1 else None
                    if (target is None or target.scheme != "http" or target.hostname not in ("127.0.0.1", "::1")
                            or not target.port or target.path != "/callback"):
                        return self._send(400, {"error": "invalid_redirect_uri"})
                    if (body.get("grant_types") != ["authorization_code", "refresh_token"]
                            or body.get("response_types") != ["code"]
                            or body.get("token_endpoint_auth_method") != "none"
                            or body.get("scope") not in server._login_scopes()):
                        return self._send(400, {"error": "invalid_client_metadata"})
                    cid = "c_" + secrets.token_hex(8)
                    server.clients[cid] = uris[0]
                    return self._send(201, {"client_id": cid, "redirect_uris": uris})
                if self.path == "/auth/token":
                    form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                    if form.get("grant_type") == "authorization_code":
                        server.code_exchanges += 1
                        got = server.codes.pop(form.get("code", ""), None)
                        if server.code_delays:
                            time.sleep(server.code_delays.pop(0))
                        verifier = form.get("code_verifier", "")
                        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()) \
                            .rstrip(b"=").decode()
                        if not got or got[1] != form.get("redirect_uri") or got[2] != challenge \
                                or got[0] != form.get("client_id"):
                            return self._send(400, {"error": "invalid_grant"})
                        return self._send(200, server._pair(got[0], got[3]))
                    if form.get("grant_type") == "refresh_token" and server.token_answer is not None:
                        return self._send(*server.token_answer)
                    if form.get("grant_type") == "refresh_token":
                        old = form.get("refresh_token", "")
                        server.refreshes.append(old)
                        if server.reuse_interval is not None and old in server.renewing:
                            # the real gateway sees a second use while the first renewal runs: the family ends
                            server.families_revoked += 1
                            cid = server.refresh.get(old)
                            for tok in [t for t, c in server.refresh.items() if c == cid]:
                                server.refresh.pop(tok, None)
                            return self._send(400, {"error": "invalid_grant"})
                        server.renewing.add(old)
                        try:
                            time.sleep(server.refresh_delay)
                        finally:
                            server.renewing.discard(old)
                        cid = server.refresh.pop(old, None)   # it rotates: used once
                        if not cid and server.reuse_interval is not None and old in server.reuse:
                            got = server._reuse(old, form.get("client_id"))
                            if got and server.drop_answers > 0:
                                server.drop_answers -= 1
                                self.close_connection = True
                                self.connection.close()
                                return None
                            return self._send(200, got) if got else self._send(400, {"error": "invalid_grant"})
                        if not cid or not server.consent or cid != form.get("client_id"):
                            return self._send(400, {"error": "invalid_grant"})
                        pair = server._pair(cid, server.scopes.get(old, "sensitive-references.resolve"))
                        if server.reuse_interval is not None:
                            # only the token replaced last keeps a window: an older one is a plain reuse now
                            server.reuse = {k: {**v, "last": False} for k, v in server.reuse.items()}
                            server.reuse[old] = {"pair": pair, "at": time.time(), "used": False, "last": True,
                                                 "cid": cid}
                        if server.drop_answers > 0:
                            server.drop_answers -= 1
                            self.close_connection = True
                            self.connection.close()
                            return None
                        return self._send(200, pair)
                    return self._send(400, {"error": "unsupported_grant_type"})
                if self.path == "/sensitive-references/resolve":
                    return self._resolve(raw)
                if self.path == "/sensitive-references/pairing" and server.pairing:
                    return self._pairing(raw)
                if self.path == "/sensitive-references/ner" and server.ner:
                    return self._ner(raw)
                if self.path == "/sensitive-references/deposit" and server.deposit:
                    return self._deposit(raw)
                self._send(404, {"error": "not_found"})

            def _pairing(self, raw: bytes) -> None:
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else ""
                if not server.consent or float(server.access.get(token, 0)) < time.time():
                    return self._send(401, {"error": "invalid_token"})
                if server.pair_answer is not None:
                    return self._send(*server.pair_answer)
                try:
                    nonce = json.loads(raw or b"{}").get("nonce")
                except (ValueError, AttributeError):
                    nonce = None
                if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{22,64}", nonce):
                    return self._send(400, {"error": "invalid_nonce"})
                server.pairings.append(nonce)
                return self._send(200, {"proof": server.proof(nonce)})

            def _deposit(self, raw: bytes) -> None:
                time.sleep(server.deposit_delay)
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else ""
                if not server.consent or float(server.access.get(token, 0)) < time.time():
                    return self._send(401, {"error": "invalid_token"})
                if server.deposit_answer is not None:
                    return self._send(*server.deposit_answer)
                if DEPOSIT_SCOPE not in server.scopes.get(token, "").split():
                    need = f'Bearer error="insufficient_scope", scope="{DEPOSIT_SCOPE}"'
                    return self._send(403, {"error": "insufficient_scope"}, {"WWW-Authenticate": need})
                if len(raw) > 64 * 1024:
                    return self._send(413, {"error": "request_too_large"})
                return self._send(*server._take_deposit(raw))

            def _ner(self, raw: bytes) -> None:
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else ""
                if float(server.access.get(token, 0)) < time.time():
                    return self._send(401, {"error": "invalid_token"})
                if NER_SCOPE not in server.scopes.get(token, "").split():
                    return self._send(403, {"error": "insufficient_scope"})
                if server.ner_answer is not None:
                    return self._send(*server.ner_answer)
                text = json.loads(raw or b"{}").get("inputs", "")
                server.ner_texts.append(text)
                time.sleep(server.ner_delay)
                at = text.find(server.ner_word)
                spans = [] if at < 0 else [{"entity_group": "PER", "word": server.ner_word, "start": at,
                                            "end": at + len(server.ner_word), "score": 0.99}]
                return self._send(200, spans)

            def _resolve(self, raw: bytes) -> None:
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else ""
                for entry in server.reuse.values():
                    if entry["pair"]["access_token"] == token:
                        entry["used"] = True       # the first use of the new access token ends the window
                if not server.consent or server.access.get(token, 0) < time.time():
                    return self._send(401, {"error": "invalid_token"},
                                      {"WWW-Authenticate": 'Bearer error="invalid_token"'})
                if len(raw) > 64 * 1024:
                    return self._send(413, {"error": "request_too_large"})
                try:
                    body = json.loads(raw)
                except ValueError:
                    return self._send(400, {"error": "invalid_request"})
                refs, sink, dest = body.get("references"), body.get("sink_type"), body.get("destination")
                if not isinstance(refs, list) or not refs or not isinstance(dest, str) or not 1 <= len(dest) <= 4096:
                    return self._send(400, {"error": "invalid_request"})
                if len(refs) > 100:
                    return self._send(413, {"error": "too_many_references"})
                if server.evil:
                    leak = refs[0] if refs else "x"
                    return self._send(409 if sink == "local_file" else 403,
                                      {"error": "unresolvable" if sink == "local_file" else leak,
                                       "reasons": {leak: 1, "unknown": True, "revoked": -1}})
                if SINK_PROFILES.get(sink) not in server.sinks:
                    return self._send(403, {"error": "ineligible_sink"})
                if sink == "display" and server.display_scope \
                        and DISPLAY_SCOPE not in server.scopes.get(token, "").split():
                    need = f"sensitive-references.resolve {DISPLAY_SCOPE}"
                    return self._send(403, {"error": "insufficient_scope", "scope": need},
                                      {"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{need}"'})
                if sink == "process" and server.process_scope \
                        and PROCESS_SCOPE not in server.scopes.get(token, "").split():
                    need = f"sensitive-references.resolve {PROCESS_SCOPE}"
                    text = ("This sign-in does not allow real values in commands. Sign in again and allow commands "
                            "on the consent page.")
                    return self._send(403, {"error": "insufficient_scope", "error_description": text, "scope": need},
                                      {"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{need}"'})
                reasons: dict = {}
                for r in refs:
                    if r in server.revoked:
                        reasons["revoked"] = reasons.get("revoked", 0) + 1
                    elif r not in server.values:
                        reasons["unknown"] = reasons.get("unknown", 0) + 1
                if reasons:
                    return self._send(409, {"error": "unresolvable", "reasons": reasons})
                if server.used + len(refs) > server.quota:
                    return self._send(429, {"error": "quota_exceeded"})
                server.used += len(refs)
                server.resolved.append({"sink_type": sink, "destination": dest, "count": len(refs)})
                answer = {"values": {r: server.values[r] for r in refs}}
                if server.audit_id == "auto":
                    answer["audit_id"] = secrets.token_urlsafe(16)    # the gateway's form: 22 of [A-Za-z0-9_-]
                    server.audit_ids.append(answer["audit_id"])
                elif server.audit_id is not None:
                    answer["audit_id"] = server.audit_id
                return self._send(200, answer)

        self.httpd = _QuietServer(("127.0.0.1", 0), Handler)
        ctx = __import__("ssl").SSLContext(__import__("ssl").PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def _deposit_meta(self) -> dict:
        return {"deposit_endpoint": self.url + "/sensitive-references/deposit", "deposit_profile": "deposit-1",
                "deposit_scope": DEPOSIT_SCOPE, "deposit_max_lifetime": 600, "deposit_targets": DEPOSIT_TARGETS,
                **self.deposit_fields}

    def _take_deposit(self, raw: bytes) -> tuple:
        """The deposit endpoint's checks (contract section 7.1) and the handles; (status, body)."""
        from maisecrets import deposit as D
        try:
            body = json.loads(raw)
        except ValueError:
            return 400, {"error": "invalid_request"}
        values = body.get("values") if isinstance(body, dict) else None
        if body.get("profile") != "deposit-1" or body.get("resource") != self.url + "/mcp" \
                or not isinstance(values, list) or not 1 <= len(values) <= 32 \
                or not isinstance(body.get("args_digest"), str) or not isinstance(body.get("lifetime"), int):
            return 400, {"error": "invalid_request"}
        targets = [t for t in DEPOSIT_TARGETS if t["tool"] == body.get("tool")]
        if not all(any(v.get("path") in t["paths"] for t in targets) for v in values):
            return 403, {"error": "not_a_target"}
        got = []
        for v in values:
            if not isinstance(v.get("placeholder"), str) or not D.PLACEHOLDER_RE.fullmatch(v["placeholder"]):
                return 400, {"error": "invalid_request"}
            try:
                value = D.unpad(v.get("value", "")).decode("utf-8")
            except (ValueError, UnicodeError):
                return 400, {"error": "invalid_request"}
            if not 8 <= len(value.encode()) <= 4096:
                return 400, {"error": "invalid_request"}
            got.append({**v, "value": value})
        self.deposit_requests.append({**body, "values": got})
        life = min(body["lifetime"], 600)
        handles = []
        for v in got:
            # contract 7.2: base64url of a 16-byte id, then of a 32-byte key: 7 + 22 + 43 characters
            handle = "msdep1_" + "".join(base64.urlsafe_b64encode(secrets.token_bytes(n)).rstrip(b"=").decode()
                                         for n in (16, 32))
            self.deposits[handle] = {**v, "tool": body["tool"], "args_digest": body["args_digest"],
                                     "expires": time.time() + life}
            handles.append(handle)
        return 200, {"handles": handles, "expires_in": life}

    def call(self, tool: str, arguments: dict) -> object:
        """The gateway's replacement at call time (contract section 7.3): the arguments that go upstream, or the tool
        result `deposit_refused: <code>` with isError true."""
        from maisecrets import deposit as D

        def refused(code: str) -> dict:
            return {"content": [{"type": "text", "text": "deposit_refused: " + code}], "isError": True}
        found = D.HANDLE_RE.findall(json.dumps(arguments))
        if len(found) != len(set(found)):
            return refused("used")
        recs = {h: self.deposits.pop(h, None) for h in found}
        if any(r is None for r in recs.values()):
            return refused("unknown_handle")
        if any(r["expires"] < time.time() for r in recs.values()):
            return refused("expired")
        template = json.loads(D.HANDLE_RE.sub(lambda m: recs[m.group(0)]["placeholder"], json.dumps(arguments)))
        if any(r["tool"] != tool or r["args_digest"] != D.args_digest(template) for r in recs.values()):
            return refused("binding_mismatch")
        sent = json.loads(D.HANDLE_RE.sub(lambda m: recs[m.group(0)]["value"], json.dumps(arguments)))
        self.upstream.append(sent)
        return sent

    def _login_scopes(self) -> tuple:
        base = "sensitive-references.resolve"
        process = [PROCESS_SCOPE] if self.process_scope else []
        display = [DISPLAY_SCOPE] if self.display_scope else []
        ner = [NER_SCOPE] if self.ner else []
        dep = [DEPOSIT_SCOPE] if self.deposit else []
        out = []
        for p in ([], process):
            for d in ([], display):
                for n in ([], ner):
                    for x in ([], dep):
                        out.append(" ".join([base, *p, *d, *n, *x]))
        return tuple(dict.fromkeys(out))

    def _pair(self, client_id: str, scope: str = "sensitive-references.resolve") -> dict:
        access, refresh = "srefr_" + secrets.token_urlsafe(24), "srefr_refresh_" + secrets.token_urlsafe(24)
        self.access[access] = time.time() + self.access_ttl
        self.refresh[refresh] = client_id
        self.scopes[access] = self.scopes[refresh] = scope
        return {"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl,
                "refresh_token": refresh, "scope": scope, "account_hint": "ope\u2026@example.com"}

    def _reuse(self, old: str, client_id: str | None):
        """A spent refresh token presented again: the same pair inside the window (once), else the family ends."""
        entry = self.reuse[old]
        if (entry["last"] and not entry["used"] and entry.get("again") is None and client_id == entry["cid"]
                and time.time() - entry["at"] <= self.reuse_interval
                and entry["pair"]["refresh_token"] in self.refresh):
            entry["again"] = time.time()
            return entry["pair"]
        self.families_revoked += 1
        for tok in [t for t, c in self.refresh.items() if c == entry["cid"]]:
            self.refresh.pop(tok, None)
        for k in list(self.reuse):
            self.reuse[k]["last"] = False
        return None

    def proof(self, nonce: str, key: bytes | None = None) -> str:
        """The pairing proof of this gateway's user (or of another key) for a nonce."""
        mac = hmac.new(key or self.pair_key, b"sref-pairing-v1:" + nonce.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()

    def __enter__(self) -> "SrefServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def mint(self, kind: str, value: str) -> str:
        ref = f"⟦sref:{kind}:{secrets.token_urlsafe(24)}⟧"
        self.values[ref] = value
        return ref

    def revoke(self, ref: str) -> None:
        self.revoked.add(ref)

    def withdraw(self) -> None:
        self.consent = False
        self.access.clear()
        self.refresh.clear()
