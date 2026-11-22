"""The deposit (#100, docs/design/e2e-connector-values.md sections 3 to 6 and appendix A): a stored value for the call
of a claude.ai connector goes to the person's gateway over maisecrets' own TLS connection (the sref login, C31), and
the call carries a one-time handle in its place. Anthropic's connector proxy then sees the handle, never the value.

The order of the paths (section 3): a directly configured MCP server gets the value (hooks._pre_mcp); a claude.ai
connector gets a deposit when every condition of section 6.1 holds; in every other case the refusal of #99
(connector_proxy.refusal), with the first condition that failed. Nothing here can select clear text: every failure,
timeout or unknown answer ends in that refusal.

Standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import time
from decimal import Decimal
from urllib.parse import urlsplit

from .placeholder import REF_RE, key_of
from .vault_refs import Refused as _VaultRefused

PROFILE = "deposit-1"
HANDLE_MARK = "msdep1_"
HANDLE_RE = re.compile(r"msdep1_[A-Za-z0-9_-]{65}")
# the placeholder as section 5.1 takes it; a form outside it (a legacy <TYPE_cN>, an empty display) gets no deposit.
# The type is the part before the LAST `_c<digits>`: the greedy type backtracks to it, and a type has no lower-case
# letter, so no `_c` inside a type can shift the split
_KEY_FORM = "([A-Z][A-Z0-9_]{0,31})_c[0-9]{1,9}"
_KEY_RE = re.compile(_KEY_FORM)
PLACEHOLDER_RE = re.compile("⟦" + _KEY_FORM + "(?::[^⟦⟧]{1,200})?⟧")
TOOL_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_SCOPE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
LIFETIME = 300                 # D3: the client asks for 300 s, the gateway allows at most 600 s
MAX_LIFETIME = 600
MAX_TARGETS = 1000
MAX_VALUES = 32
MIN_BYTES, MAX_BYTES = 8, 4096         # D15
MAX_REQUEST_BYTES = 64 * 1024
BUDGET = 5.0                   # section 6.4: the metadata read, a token renewal and the deposit request together
METADATA_TTL = 3600            # section 4.4
# D9: an issuer name of a known interception CA. It catches an accidental interception; an attacker chooses the name
INTERCEPTION_MARKS = ("interception ca", "egress gateway")
CALL_CODES = ("expired", "unknown_handle", "binding_mismatch", "used", "unavailable")
_REFUSED_RE = re.compile(r"\s*deposit_refused: (" + "|".join(CALL_CODES) + r")\s*")
_MAC_ENTRY = "_maisecrets_binding_mac"
# deposit_any_field (section 6.1.5): the personal types whose placeholder may stand in any string of a listed tool's
# call. maisecrets applies the intersection with the gateway's list, so a gateway can narrow it; only `all_types` as
# the JSON boolean true widens it to every class. Else ID_NUMBER, CARD, SECRET and every type not named here stay
# strict (deposit_targets only)
ANY_FIELD_TYPES = frozenset({"ADDRESS", "BIRTH_DATE", "EMAIL", "IBAN", "IP", "IPV6", "NAME", "PHONE", "USERNAME"})
# an own rule, a term, an import and a model's finding stay strict whatever type they carry
STRICT_KINDS = ("user:", "term:", "import:", "remote:")
# a later match of an own rule or an import marks an entry that a built-in rule stored strict (Vault.put, put_many);
# a model's later finding does not: the name service finds most names that a rule found before
MARKS_STRICT = ("user:", "import:")


class Refused(_VaultRefused):
    """The first condition of section 6.1 that failed, as a clause for the refusal."""


class NotCanonical(ValueError):
    """Arguments that JCS cannot write the same on both sides (section 5.3, appendix A.2)."""


# ------------------------------------------------------------------------------------------------ JCS (5.3) --
def _number(x: object) -> str:
    """ECMAScript Number.prototype.toString of the double of x (RFC 8785 3.2.2.3)."""
    if isinstance(x, int):
        if abs(x) > 2 ** 53:
            raise NotCanonical("an integer above 2^53")
        x = float(x)
    if not math.isfinite(x):
        raise NotCanonical("a number that is not finite")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    t = Decimal(repr(abs(x))).normalize().as_tuple()          # repr: the shortest digits that read back the same
    digits = "".join(map(str, t.digits))
    k = len(digits)
    n = t.exponent + k
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise NotCanonical("a lone surrogate")
        out.append(_ESC.get(ch) or (f"\\u{o:04x}" if o < 0x20 else ch))
    out.append('"')
    return "".join(out)


def _utf16(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def jcs(node: object) -> str:
    """The JSON Canonicalization Scheme (RFC 8785) text of a parsed JSON value."""
    if node is None:
        return "null"
    if node is True:
        return "true"
    if node is False:
        return "false"
    if isinstance(node, (int, float)):
        return _number(node)
    if isinstance(node, str):
        return _string(node)
    if isinstance(node, list):
        return "[" + ",".join(jcs(x) for x in node) + "]"
    if isinstance(node, dict):
        if not all(isinstance(k, str) for k in node):
            raise NotCanonical("an object key that is no string")
        return "{" + ",".join(_string(k) + ":" + jcs(node[k]) for k in sorted(node, key=_utf16)) + "}"
    raise NotCanonical("a value that is no JSON")


def args_digest(template: object) -> str:
    """base64url(SHA-256(UTF-8(JCS(template)))) without padding."""
    return _b64(hashlib.sha256(jcs(template).encode("utf-8")).digest())


def loads_strict(text: str) -> object:
    """json.loads that refuses what both sides refuse (appendix A.2): a duplicate key, and NaN or Infinity."""
    def pairs(items):
        keys = [k for k, _v in items]
        if len(set(keys)) != len(keys):
            raise NotCanonical("a duplicate key")
        return dict(items)

    def constant(name):
        raise NotCanonical("a number that is not finite")
    node = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    jcs(node)                                    # a lone surrogate or a large integer
    return node


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------------------------- padding (5.1) --
def pad(value: str) -> str:
    """base64url of the value, one byte 0x80 and zero bytes up to max(64, 32 * ceil((n + 1) / 32)) (ISO/IEC 7816-4)."""
    raw = value.encode("utf-8")
    size = max(64, 32 * math.ceil((len(raw) + 1) / 32))
    return _b64(raw + b"\x80" + b"\x00" * (size - len(raw) - 1))


def unpad(text: str) -> bytes:
    """The gateway's side of pad(), for the tests and the fake gateway: ValueError on a wrong padding."""
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    body = raw.rstrip(b"\x00")
    if not body.endswith(b"\x80"):
        raise ValueError("invalid_request")
    return body[:-1]


# ---------------------------------------------------------------------------------------- pointers (4.3) --
def _escape(seg: str) -> str:
    return seg.replace("~", "~0").replace("/", "~1")


def _segments(pointer: str) -> list | None:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return None
    return [s.replace("~1", "/").replace("~0", "~") for s in pointer[1:].split("/")]


def occurrences(template: object) -> list:
    """(pointer, segments, start, end, placeholder) of each placeholder of the template, in the order of its JCS text:
    keys in UTF-16 order, arrays in order, and inside a string from left to right. A segment is (text, is_index)."""
    out: list = []

    def walk(node: object, segs: tuple) -> None:
        if isinstance(node, dict):
            for k in sorted(node, key=_utf16):
                walk(node[k], segs + ((k, False),))
        elif isinstance(node, list):
            for i, x in enumerate(node):
                walk(x, segs + ((str(i), True),))
        elif isinstance(node, str):
            for m in REF_RE.finditer(node):
                pointer = "".join("/" + _escape(s) for s, _i in segs)
                out.append((pointer, segs, m.start(), m.end(), m.group(0)))
    walk(template, ())
    return out


def _at(doc: object, pointer: str) -> object:
    node = doc
    for seg in _segments(pointer) or []:
        if isinstance(node, dict) and seg in node:
            node = node[seg]
        elif isinstance(node, list) and re.fullmatch(r"0|[1-9][0-9]*", seg) and int(seg) < len(node):
            node = node[int(seg)]
        else:
            return None
    return node


def _path_matches(pattern: str, segs: tuple) -> bool:
    """A path of a target names this string: each segment equal, or `*` for one array index (and nothing else)."""
    want = _segments(pattern)
    if want is None or len(want) != len(segs):
        return False
    return all(w == s or (w == "*" and is_index) for w, (s, is_index) in zip(want, segs))


def matching_targets(targets: list, tool: str, template: dict) -> list:
    """The targets of this tool whose `when` conditions all hold: each pointer names a string exactly equal."""
    return [t for t in targets if t["tool"] == tool
            and all(isinstance(_at(template, p), str) and _at(template, p) == v for p, v in t.get("when", {}).items())]


# ---------------------------------------------------------------------------------------- metadata (4.2) --
def fields(block: object, origin: str | None) -> dict | None:
    """The deposit fields of a `sensitive_references` block, checked, in the block's own names; None when a field is
    missing or wrong (the whole deposit is then unusable, section 4.2)."""
    from .vault_refs import origin_of
    if not isinstance(block, dict) or not origin or origin_of(block.get("deposit_endpoint")) != origin:
        return None
    if block.get("deposit_profile") != PROFILE:
        return None
    scope = block.get("deposit_scope")
    if not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope):
        return None
    life = block.get("deposit_max_lifetime", LIFETIME)
    if not isinstance(life, int) or isinstance(life, bool) or not 1 <= life <= MAX_LIFETIME:
        return None
    raw = block.get("deposit_targets")
    if not isinstance(raw, list) or len(raw) > MAX_TARGETS:
        return None
    targets = []
    for t in raw:
        if not isinstance(t, dict) or not isinstance(t.get("tool"), str) or not TOOL_RE.fullmatch(t["tool"]):
            return None
        when = t.get("when", {})
        if not isinstance(when, dict) or not all(_segments(p) is not None and isinstance(v, str)
                                                 for p, v in when.items()):
            return None
        paths = t.get("paths")
        if not isinstance(paths, list) or not paths or not all(_segments(p) is not None for p in paths):
            return None
        targets.append({"tool": t["tool"], "when": dict(when), "paths": list(paths)})
    out = {"deposit_endpoint": block["deposit_endpoint"], "deposit_profile": PROFILE, "deposit_scope": scope,
           "deposit_max_lifetime": life, "deposit_targets": targets}
    free = any_field(block.get("deposit_any_field"))
    if free:
        out["deposit_any_field"] = free
    return out


def any_field(raw: object) -> dict | None:
    """The `deposit_any_field` of the metadata, narrowed to ANY_FIELD_TYPES; None when it is absent or has a wrong
    shape. A wrong shape drops only this field: deposit_targets still apply. `actions` names, per tool, the actions
    that take a personal value; when it is missing or no object, no tool gets one, and a tool whose entry is no list
    of strings gets none either."""
    if not isinstance(raw, dict):
        return None
    types, tools = raw.get("types"), raw.get("tools")
    if not isinstance(types, list) or not isinstance(tools, list) or len(types) > 64 or len(tools) > MAX_TARGETS:
        return None
    if not all(isinstance(t, str) for t in types) or not all(isinstance(t, str) and TOOL_RE.fullmatch(t)
                                                             for t in tools):
        return None
    acts = raw.get("actions")
    if not isinstance(acts, dict) or len(acts) > MAX_TARGETS:
        acts = {}
    actions = {t: sorted(set(names)) for t, names in acts.items()
               if isinstance(names, list) and len(names) <= MAX_TARGETS and all(isinstance(a, str) for a in names)}
    # all_types: only the JSON boolean true lets every class through (a string "true", 1 or null keeps the 9 types)
    return {"types": sorted(ANY_FIELD_TYPES.intersection(types)), "tools": sorted(set(tools)), "actions": actions,
            "all_types": raw.get("all_types") is True}


ACTION_LINE = "this action of the connector does not take a stored value; it was not sent"


def listed_action(free: dict, name: str, args: object) -> bool:
    """The call's `action` argument is a string that `actions[name]` lists (section 6.1.5)."""
    acts = (free.get("actions") or {}).get(name)
    act = args.get("action") if isinstance(args, dict) else None
    return isinstance(acts, list) and isinstance(act, str) and act in acts


def class_of(key: object) -> str | None:
    """The type of a canonical key (EMAIL_c3 -> EMAIL, BIRTH_DATE_c2 -> BIRTH_DATE) by the split of section 5.1; None
    for a key outside that form."""
    m = _KEY_RE.fullmatch(key) if isinstance(key, str) else None
    return m.group(1) if m else None


def any_field_class(vault, placeholder: str, every: bool = False) -> str | None:
    """The class of a placeholder for deposit_any_field: the type of its vault entry, never text the model wrote. None
    (strict) when the entry is missing, purged or weak (a word, the plugin's own name, a model's finding), or when its
    stored type differs from the prefix of the key. Without `every` (the gateway's all_types) also None for an own
    rule, a term, an import, a model's finding and an entry with the strict mark of a later own rule or import."""
    key = key_of(placeholder)
    meta = vault._index.get("entries", {}).get(key) if key else None
    if not isinstance(meta, dict) or meta.get("purged") or meta.get("weak"):
        return None
    kind = meta.get("type")
    if not isinstance(kind, str) or kind != class_of(key):
        return None
    if every:
        return kind
    if meta.get("strict"):
        return None
    if str(meta.get("kind", "")).startswith(STRICT_KINDS):
        return None
    return kind


def _in_a_key(node: object) -> bool:
    if isinstance(node, dict):
        return any(REF_RE.search(k) or _in_a_key(v) for k, v in node.items())
    return isinstance(node, list) and any(_in_a_key(x) for x in node)


def _cache_path():
    from .vault import HOME
    return HOME / "sref" / "deposit-metadata.json"


def _meta_mac(backend, url: str, t: object, found: object, create: bool) -> str | None:
    """The MAC of a kept metadata copy, with the binding key in the store (seal, D7): a copy that a process changed
    without that key is read again from the gateway. None when the store holds no key and `create` is False."""
    from .vault_refs import profile
    k = _mac_key(backend, create)
    if k is None:
        return None
    blob = json.dumps(["maisecrets-deposit-metadata-1", profile(), url, t, found], sort_keys=True)
    return hmac.new(k, blob.encode("utf-8"), hashlib.sha256).hexdigest()


def metadata(cfg: dict, url: str, deadline: float, backend=None) -> dict:
    """The gateway's discovery record with usable deposit fields, read over the direct channel (sref_client.discover)
    and kept at most an hour. A copy older than that is read again; a failed read refuses and never extends it. The
    copy carries a MAC with the binding key (_meta_mac); a copy whose MAC does not match is read again."""
    from . import sref_client
    from .vault import atomic_write
    from .vault_refs import origin_of
    origin = origin_of(url)
    host = urlsplit(url).hostname
    now = time.time()
    try:
        data = json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    data = data if isinstance(data, dict) else {}
    kept = data.get(url) if isinstance(data.get(url), dict) else {}
    t, found = kept.get("t"), kept.get("found")
    mac = _meta_mac(backend, url, t, found, False) if backend is not None else None
    if isinstance(mac, str) and isinstance(kept.get("mac"), str) and hmac.compare_digest(mac, kept["mac"]) \
            and isinstance(t, (int, float)) and not isinstance(t, bool) and now - METADATA_TTL < t <= now + 60 \
            and sref_client._same_origin(found, origin) and isinstance(found, dict) \
            and fields(found.get("deposit"), origin) == found.get("deposit") and found.get("deposit"):
        return found
    found = sref_client.discover(cfg, url, deadline)
    if not found:
        raise Refused(f"maisecrets could not read the metadata of {host} in time")
    if not found.get("deposit"):
        raise Refused(f"{host} offers no deposit (its metadata names no usable deposit fields)")
    data = {u: v for u, v in data.items() if isinstance(v, dict) and isinstance(v.get("t"), (int, float))
            and now - METADATA_TTL < v["t"] <= now + 60}
    data[url] = {"t": now, "found": found}
    if backend is not None:
        try:
            data[url]["mac"] = _meta_mac(backend, url, now, found, True)
        except Exception:  # noqa: BLE001 - without a MAC the copy is read again next time
            pass
    try:
        _cache_path().parent.mkdir(parents=True, exist_ok=True)
        atomic_write(_cache_path(), json.dumps(data))
    except OSError:
        pass                                     # the next call reads the metadata again
    return found


# ------------------------------------------------------------------------------------------ the binding (D7) --
def _profile_binding(key: str, url: str) -> bytes:
    from .vault_refs import profile
    return json.dumps(["maisecrets-binding-1", profile(), key, url]).encode("utf-8")


def _mac_key(backend, create: bool) -> bytes | None:
    raw = backend.get(_MAC_ENTRY)
    if isinstance(raw, str) and re.fullmatch(r"[0-9a-f]{64}", raw):
        return bytes.fromhex(raw)
    if not create:
        return None
    import secrets
    k = secrets.token_bytes(32)
    backend.put(_MAC_ENTRY, k.hex(), label="maisecrets connector binding key")
    return k


def seal(backend, key: str, url: str) -> str:
    """D7: the MAC of a binding that a pairing proof made, with a key in the store. A process of the same user can
    read that key (A3); the seal stops a binding file that was changed without it."""
    return hmac.new(_mac_key(backend, True), _profile_binding(key, url), hashlib.sha256).hexdigest()


def binding(backend, payload: dict, tool: str) -> tuple:
    """(connector key, MCP URL) of the binding this call goes to: the one bound connector whose tool prefix
    `mcp__claude_ai_<key>__` the tool name has, bound by a pairing proof, with a seal that the store's key confirms.
    The model names no gateway: all of it comes from the binding. Limit: the prefix is Claude Code's spelling of a
    claude.ai connector; Cowork drops `claude_ai_` (`mcp__<display name>__<tool>`), so no binding is found by tool name
    there (the caller refuses in Cowork before this; docs/KNOWN-GAPS.md)."""
    from .vault_refs import _connector_data, connector_key, connectors, own_servers
    server = payload.get("mcp_server") if isinstance(payload.get("mcp_server"), dict) else {}
    named = connector_key(server.get("name"))
    # the server's own name decides; without it a `__` inside a connector's or tool's name could route the handle
    # of one connector to another
    if named is None:
        raise Refused("the call names no claude.ai connector as its MCP server (a Claude Code older than 2.1.330 may "
                      "send no server name; update Claude Code)")
    keys = [k for k in connectors() if tool.startswith(f"mcp__claude_ai_{k}__") and k not in own_servers()
            and named == k]
    if len(keys) != 1:
        return None, None
    key = keys[0]
    url = connectors()[key]
    entry = (_connector_data().get("bound") or {}).get(key)
    if not isinstance(entry, dict) or entry.get("paired") is not True:
        raise Refused(f"the binding of the claude.ai connector {key} carries no seal of a pairing proof (it was made "
                      f"without a proof, or by an older maisecrets); pair it again: /maisecrets sref logout {key}, "
                      f"let the connector show a reference, then /maisecrets sref login {key}")
    k = _mac_key(backend, False)
    mac = entry.get("mac")
    if k is None or not isinstance(mac, str) or not hmac.compare_digest(
            hmac.new(k, _profile_binding(key, url), hashlib.sha256).hexdigest(), mac):
        raise Refused(f"the binding of the claude.ai connector {key} does not carry a valid seal; bind it again "
                      f"(/maisecrets sref logout {key}, then /maisecrets sref login {key} once it names its gateway)")
    return key, url


# -------------------------------------------------------------------------------------- the request (5.1) --
def tripwire(cert: object) -> None:
    """D9: refuse when the issuer of the gateway's certificate names a known interception CA."""
    issuer = cert.get("issuer", ()) if isinstance(cert, dict) else ()
    words = " ".join(str(v) for rdn in issuer for pair in rdn for v in pair[1:]).lower()
    if any(m in words for m in INTERCEPTION_MARKS):
        raise Refused("the certificate of the gateway comes from an interception CA, so the connection is not direct")


_ERRORS = {"invalid_request": "refused the request as malformed", "not_a_target": "takes no deposit for this call",
           "not_allowed": "allows no deposits for this account", "request_too_large": "found the request too large",
           "rate_limited": "reached a limit of deposits; try again later",
           "unavailable": "could not store the deposit now"}


def send(cfg: dict, backend, found: dict, key: str, body: bytes, count: int, deadline: float) -> list:
    """The handles for a deposit request, from the gateway's deposit endpoint, with the person's access token over the
    direct channel. A 401 gets one renewal and one more try. Refused on any other answer."""
    from . import sref_client
    from .vault_refs import _is_json, _net_errors, _request
    host = urlsplit(found["origin"]).hostname
    url = found["deposit"]["deposit_endpoint"]
    token = None
    status, headers, answer = 0, {}, {}
    for attempt in (0, 1):
        token = sref_client._access(cfg, backend, found, deadline, stale=token if attempt else None)
        try:
            status, headers, raw = _request(cfg, "POST", url, {
                "Authorization": f"Bearer {token}", "Content-Type": "application/json",
                "Accept": "application/json"}, body, deadline, peer_check=tripwire)
        except _net_errors() as exc:
            raise Refused(f"{host} did not answer the deposit in time ({type(exc).__name__})") from None
        try:
            answer = json.loads(raw.decode("utf-8")) if _is_json(headers) else {}
        except (ValueError, RecursionError, UnicodeError):
            answer = {}
        answer = answer if isinstance(answer, dict) else {}
        if status != 401 or attempt:
            break
    code = answer.get("error") if isinstance(answer.get("error"), str) else ""
    if status == 200:
        handles = answer.get("handles")
        if not isinstance(handles, list) or len(handles) != count or len(set(map(str, handles))) != count \
                or not all(isinstance(h, str) and HANDLE_RE.fullmatch(h) for h in handles):
            raise Refused(f"{host} gave no usable handles")
        return handles
    if status == 401:
        raise Refused(f"the login at {host} is no longer valid; the person types /maisecrets sref login {key}")
    if status == 403 and (code == "insufficient_scope" or "insufficient_scope" in headers.get("www-authenticate", "")):
        raise Refused(f"the login at {host} does not allow deposits; the person types /maisecrets sref login {key} "
                      "again and allows deposits on the consent page")
    if code in _ERRORS:
        raise Refused(f"{host} {_ERRORS[code]}")
    raise Refused(f"{host} gave no usable answer to the deposit (HTTP {status})")


# ------------------------------------------------------------------------------------------- the hook (6) --
def _calls_path():
    from .vault import HOME
    return HOME / "sref" / "deposit-calls.json"


def _note_call(call: object, keys: list) -> None:
    """The keys of a call that carries handles, for the line of section 6.5. Never a value or a handle."""
    if not isinstance(call, str) or not call:
        return
    from .vault import HOME, LockTimeout, _lock_for, atomic_write
    try:
        with _lock_for(HOME / "sref" / ".deposit-calls.lock"):
            try:
                data = json.loads(_calls_path().read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            now = time.time()
            data = {c: v for c, v in (data.items() if isinstance(data, dict) else [])
                    if isinstance(v, dict) and isinstance(v.get("t"), (int, float)) and now - 3600 < v["t"]}
            data[call] = {"t": now, "keys": keys}
            atomic_write(_calls_path(), json.dumps(dict(list(data.items())[-200:])))
    except (OSError, LockTimeout):
        pass


def _keys_of_call(call: object) -> list | None:
    try:
        data = json.loads(_calls_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    rec = data.get(call) if isinstance(data, dict) and isinstance(call, str) else None
    keys = rec.get("keys") if isinstance(rec, dict) else None
    return [k for k in keys if isinstance(k, str)] if isinstance(keys, list) else None


def pre_tool(payload: dict, cfg: dict, tool: str, tool_input: dict, found: list) -> dict:
    """The PreToolUse answer for a claude.ai connector's call that holds placeholders: the deposit, or the refusal of
    #99 with the first condition that failed. Any failure refuses."""
    from . import connector_proxy, hooks
    start = time.monotonic()               # 6.4: the budget counts from here, the store reads included
    try:
        return _deposit(payload, cfg, tool, tool_input, found, start)
    except Refused as exc:
        why = str(exc)
    except Exception as exc:  # noqa: BLE001 - every failure gives the refusal, never clear text
        why = f"an internal error ({type(exc).__name__})"
    return hooks._deny(connector_proxy.refusal(tool, found) + f" No deposit at a gateway: {why}.")


def _deposit(payload: dict, cfg: dict, tool: str, tool_input: dict, found: list, start: float) -> dict:
    import os

    from . import connector_proxy, hooks, rehydration, sref_client
    from .vault import Vault
    from .vault_refs import origin_of
    # Cowork names a connector's tools `mcp__<display name>__<tool>`, without `claude_ai_` (measured 2026-11-22), so
    # the prefix of section 6.2 does not name the connector there; and Cowork has no sref login (D8). The deposit is
    # off there and in the desktop app's local agent session (docs/KNOWN-GAPS.md)
    if os.environ.get("CLAUDE_CODE_ENTRYPOINT") in connector_proxy.FAIL_CLOSED_ENTRYPOINTS:
        raise Refused("the deposit does not work in Cowork or in a local agent session of the desktop app yet")
    vault = Vault(cfg)
    backend = vault.backend
    key, url = binding(backend, payload, tool)                                       # 6.1.2 and D7
    if not key:
        raise Refused("this connector is not bound to a gateway of yours")
    origin, host = origin_of(url), urlsplit(url).hostname
    if not sref_client.logged_in(backend, origin):                                    # 6.1.3
        raise Refused(f"maisecrets has no login at {host}; the person types /maisecrets sref login {key}")
    deadline = start + BUDGET                                                         # 6.4
    meta = metadata(cfg, url, deadline, backend)                                      # 6.1.4
    dep = meta["deposit"]
    granted = str(sref_client._load(backend, origin).get("scope") or "").split()
    if dep["deposit_scope"] not in granted:
        raise Refused(f"the login at {host} does not allow deposits; the person types /maisecrets sref login {key} "
                      "again and allows deposits on the consent page")
    name = tool[len(f"mcp__claude_ai_{key}__"):]                                      # 6.2
    if not TOOL_RE.fullmatch(name):
        raise Refused("the tool name has no form a gateway lists")
    places = occurrences(tool_input)                                                  # 6.1.5
    if _in_a_key(tool_input):
        raise Refused("a placeholder stands in a key of the arguments, and a deposit takes only a string value")
    targets = matching_targets(dep["deposit_targets"], name, tool_input)
    free = dep.get("deposit_any_field") or {}
    listed_tool = name in free.get("tools", ())
    free_tool = listed_tool and listed_action(free, name, tool_input)
    every = free.get("all_types") is True                  # every class, on a listed tool and action only
    if not places or not (targets or listed_tool):
        raise Refused(f"{host} takes no deposit for this call of {name}")
    loose = set()                      # the keys that stand outside a target's paths, by their class
    for pointer, segs, _a, _b, ph in places:
        if any(_path_matches(p, segs) for t in targets for p in t["paths"]):
            continue
        cls = any_field_class(vault, ph, every)
        if listed_tool and cls is not None and (every or cls in free.get("types", ())):
            if not free_tool:          # an action that actions[name] does not list: refused before any deposit
                raise Refused(ACTION_LINE)
            loose.add(key_of(ph))
            continue
        raise Refused(f"{host} takes no deposit at {pointer} of {name}")
    if HANDLE_MARK in json.dumps(tool_input, ensure_ascii=False):                     # 6.1.6
        raise Refused("the arguments already hold a deposit handle")
    for t in dep["deposit_targets"]:
        for p in t["when"] if t["tool"] == name else ():
            got = _at(tool_input, p)
            if isinstance(got, str) and REF_RE.search(got):
                raise Refused(f"a placeholder stands at {p}, which decides the action")
    try:
        digest = args_digest(tool_input)
    except NotCanonical as exc:
        raise Refused(f"the arguments hold {exc}") from None
    if len(places) > MAX_VALUES:
        raise Refused(f"{len(places)} placeholders in one call; a deposit takes at most {MAX_VALUES}")
    bad = [ph for *_x, ph in places if not PLACEHOLDER_RE.fullmatch(ph)]
    if bad:
        raise Refused(f"the placeholder {bad[0]} has no form a deposit takes")
    keys = list(dict.fromkeys(key_of(ph) for *_x, ph in places))
    session = payload.get("session_id")
    for k in keys:
        # 6.1.6 before 6.1.7; a key the session rule refuses is not measured (its length is no answer to give)
        raw = backend.get(k) if vault.status(k, session) == "ok" else None
        if raw is not None and not MIN_BYTES <= len(raw.encode("utf-8")) <= MAX_BYTES:
            raise Refused(f"\u27e6{k}\u27e7 has {len(raw.encode('utf-8'))} bytes, and a deposit takes "
                          f"{MIN_BYTES} to {MAX_BYTES}")
    names = ", ".join("⟦" + k + "⟧" for k in keys)
    stop = rehydration.refusal(cfg, "mcp", hooks.client_of(payload), names, "The call did not run.")   # 6.1.7
    if stop:
        return hooks._deny(stop)
    fresh = hooks._protect_fresh(cfg, tool, tool_input, keys)
    failed = hooks._precheck(vault, keys, session)
    if failed:
        return hooks._deny(hooks._deny_reason(failed))
    values: dict = {}
    for k in keys:
        value, status = vault.get(k, session)
        if status != "ok":
            return hooks._deny(hooks._deny_reason([f"{k} ({status})"]))
        if not MIN_BYTES <= len(value.encode("utf-8")) <= MAX_BYTES:          # the value changed since
            raise Refused(f"⟦{k}⟧ has {len(value.encode('utf-8'))} bytes, and a deposit takes "
                          f"{MIN_BYTES} to {MAX_BYTES}")
        if k in loose and "\u27e6sref:" in value:     # the only guard of a gateway reference (not weak since !639)
            raise Refused(f"⟦{k}⟧ holds a reference of a gateway, and such a value goes only to a target's path")
        values[k] = value
    stop = hooks._unnoted(cfg, hooks._note_destinations(cfg, payload, tool, tool_input, keys), keys,
                          "The call did not run.")                                    # C23
    if stop:
        return stop
    lifetime = min(LIFETIME, dep["deposit_max_lifetime"])
    body = json.dumps({"profile": PROFILE, "resource": url, "tool": name, "args_digest": digest,
                       "lifetime": lifetime,
                       "values": [{"path": p, "placeholder": ph, "value": pad(values[key_of(ph)])}
                                  for p, _s, _a, _b, ph in places]}).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise Refused(f"the deposit request to {host} is larger than 64 KB")
    # C7: a deposit counts as one use of each key, also one that fails, as the value leaves the computer; the audit
    # line names the key, "deposit", the host, the tool, the paths and the lifetime, never the value or the handle
    for k in keys:
        paths = " ".join(dict.fromkeys(p for p, _s, _a, _b, ph in places if key_of(ph) == k))
        status = vault.record_resolve(k, session, tool, f"deposit {host} {name} {paths} {lifetime}s")
        if status != "ok":
            return hooks._deny(hooks._deny_reason([f"{k} ({status})"]))
    handles = send(cfg, backend, meta, key, body, len(places), deadline)              # 6.1.8
    by_place = {(p, a): h for (p, _s, a, _b, _ph), h in zip(places, handles)}

    def put(node: object, segs: tuple) -> object:
        if isinstance(node, dict):
            return {k: put(v, segs + (k,)) for k, v in node.items()}
        if isinstance(node, list):
            return [put(x, segs + (str(i),)) for i, x in enumerate(node)]
        if isinstance(node, str):
            pointer = "".join("/" + _escape(s) for s in segs)
            out = node
            for m in reversed(list(REF_RE.finditer(node))):
                out = out[:m.start()] + by_place[(pointer, m.start())] + out[m.end():]
            return out
        return node
    new_input = put(tool_input, ())
    _note_call(payload.get("tool_use_id"), keys)
    return hooks._rehydrated(payload, cfg, "mcp", new_input,
                             f"maisecrets: {names} went to {host} as a one-time deposit over maisecrets' own "
                             f"connection; this call of {name} carries only its handle, which {host} replaces with "
                             "the value. Allow it only if you asked for this call.", fresh)


def _line(code: str, keys: list) -> str:
    names = ", ".join("⟦" + k + "⟧" for k in keys) or "the stored value"
    return "maisecrets: " + {
        "expired": f"the deposit for {names} expired before the call ran. Call the tool again.",
        "used": f"the gateway took the deposit for {names} as used already. Call the tool again.",
        "unknown_handle": f"the gateway knows no deposit for {names} for this account. Call the tool again.",
        "binding_mismatch": f"the gateway did not run this call with {names}, and the value was not sent. Either "
                            "the call did not match its deposit, or this action of the connector does not take a "
                            "stored value: an action that encodes its body (for example a Gmail send) or an action "
                            "whose fields go into the URL. Do not change the call to get around this; tell the "
                            "user.",
        "unavailable": "the deposit store of the gateway did not answer, so the call did not run. Try again later.",
    }[code]


def post_tool(payload: dict) -> dict | None:
    """Section 6.5: a gateway's `deposit_refused: <code>` for a call that carried handles becomes one line for the
    model. It never retries by itself. None for every other result, and on any failure (the redaction goes on)."""
    try:
        return _post_line(payload)
    except Exception:  # noqa: BLE001 - the line is a convenience; the normal redaction runs then
        return None


def post_tool_failure(payload: dict) -> dict | None:
    """A refused deposit comes back with isError, so Claude Code (2.1.330) reports it as PostToolUseFailure, whose
    answer cannot replace the output (anthropics/claude-code#97278): the line of section 6.5 goes to the model as
    additional context next to the gateway's code. None for every other failure, and on any failure here."""
    try:
        return _failure_line(payload)
    except Exception:  # noqa: BLE001 - the line is a convenience; the failure path goes on as before
        return None


def _failure_line(payload: dict) -> dict | None:
    tool, error = str(payload.get("tool_name") or ""), payload.get("error")
    if not tool.startswith("mcp__") or not isinstance(error, str) or "deposit_refused: " not in error:
        return None
    try:
        parsed = loads_strict(error)
    except ValueError:
        parsed = error
    code = _sole_block(error) or _sole_refusal(parsed)
    keys = _keys_of_call(payload.get("tool_use_id")) if code else None
    if keys is None:
        return None
    return {"hookSpecificOutput": {"hookEventName": "PostToolUseFailure", "additionalContext": _line(code, keys)}}


def _sole_block(node: object) -> str | None:
    if isinstance(node, str):
        m = _REFUSED_RE.fullmatch(node)
        return m.group(1) if m else None
    if isinstance(node, list) and len(node) == 1 and isinstance(node[0], dict) \
            and set(node[0]) <= {"type", "text"} and node[0].get("type") == "text":
        return _sole_block(node[0].get("text"))
    return None


def _sole_refusal(response: object) -> str | None:
    """The code when the whole result is one `deposit_refused: <code>` block and nothing else (the text, a list of
    one text block, or a result whose content is that list, with isError and at most the gateway's structured
    code); else None. A result with any other part keeps the normal redaction (review H1)."""
    if not isinstance(response, dict):
        return _sole_block(response)
    if not set(response) <= {"content", "isError", "structuredContent"} or response.get("isError") not in (None, True):
        return None
    code = _sole_block(response.get("content"))
    extra = response.get("structuredContent")
    return code if extra is None or extra == {"deposit_error": code} else None


def _post_line(payload: dict) -> dict | None:
    tool, call = str(payload.get("tool_name") or ""), payload.get("tool_use_id")
    response = payload.get("tool_response")
    if not tool.startswith("mcp__") or response is None:
        return None
    if "deposit_refused: " not in json.dumps(response, ensure_ascii=False):
        return None
    keys = _keys_of_call(call)
    if keys is None:
        return None
    code = _sole_refusal(response)
    if code is None:
        return None                    # anything next to the refusal goes through the normal redaction
    line = _line(code, keys)
    if isinstance(response, str):
        new: object = line
    elif isinstance(response, list):
        new = [{"type": "text", "text": line}]
    else:
        new = {**response, "content": [{"type": "text", "text": line}]}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": new}}
