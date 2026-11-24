"""Whether the name source of /maisecrets ner can be used, said to the person once, with the cause and the step.

A source that is set and cannot be asked leaves the names of tool results to the rules. Before 0.9.16 the person saw
a grey line under each such result ("names not checked: the name service cannot be asked"), the same words for every
cause; a gateway login that the gateway had ended went on like that for hours (field report). Now:

- the session start checks the source cheaply (the gateway: a login in the store, no network; a url or the local
  container: an answer within a second) and names a source that cannot be used in its first line;
- a tool result names it once per session, when the state first turns bad, and again only when the cause changes;
- /maisecrets status and the panel show a `names` note (a warn: secrets are still protected).

What the AI is told at each unchecked result does not change (remote_layer.unchecked_context).
"""
from __future__ import annotations

import hashlib
import json
import time

from .home import HOME

# cause -> (fact, step). {name}: the MCP server of the gateway in the person's configuration
CAUSES = {
    "login_ended": ("the gateway ended the login", "/maisecrets sref login {name}"),
    "renewal_uncertain": ("the last renewal did not finish; log in again", "/maisecrets sref login {name}"),
    "no_login": ("not logged in at the gateway", "/maisecrets sref login {name}"),
    # an older maisecrets (before 0.9.16) in another session can end the login and leaves no mark of why
    "older_ended": ("not logged in at the gateway; an older maisecrets in another session can end the login",
                    "restart the sessions that run it (/maisecrets status), then /maisecrets sref login {name}"),
    "no_scope": ("the login lacks the name scope", "/maisecrets sref login {name}"),
    "no_ner": ("the gateway offers no name detection", "/maisecrets ner"),
    "local_down": ("the local container is not running", "/maisecrets ner local"),
    "not_ours": ("the local service is not the container maisecrets started", "/maisecrets ner local"),
    "no_answer": ("the name service does not answer", "/maisecrets ner"),
    "slow": ("the name service answers too slowly", "/maisecrets ner"),
    "busy": ("the gateway's name service is busy", "/maisecrets ner"),
    "rate_limited": ("the gateway's limit per minute was reached", "/maisecrets ner"),
    "other": ("the name service cannot be used", "/maisecrets ner"),
}
STATE = HOME / "ner-state.json"          # the last cause of this computer, for the status; gone when names work
_WARNED = HOME / "ner-warned.json"       # session digest -> the cause the person last heard of
_WARNED_MAX = 1000


def _conf(cfg) -> dict:
    conf = cfg.get("remote_detector") if isinstance(cfg, dict) else None
    return conf if isinstance(conf, dict) and conf.get("url") else {}


def _is_local(conf: dict) -> bool:
    from .ner_setup import LOCAL_URL
    return str(conf.get("url") or "").rstrip("/") == LOCAL_URL.rstrip("/")


def cause_of(conf: dict, reason: str) -> str | None:
    """The cause of an unchecked tool result: the reason of the service's status, and for a gateway that gave no
    detector the cause ner_gateway.detector recorded. None for a result that is only too long."""
    if reason == "too_long" or not reason:
        return None
    if conf.get("gateway") and reason == "setup":
        from .ner_gateway import LAST
        return LAST.get("cause") or "other"
    if reason == "forbidden":
        return "no_scope" if conf.get("gateway") else "other"
    if reason == "not_enabled":
        return "no_ner"                     # no login step helps: the gateway offers no name service now
    if reason == "not_ours":
        return "not_ours"
    if reason == "refused":
        return "local_down" if _is_local(conf) else "no_answer"
    if reason in ("network", "http", "unauthorized", "policy"):
        return "no_answer"
    if reason in ("busy", "rate_limited"):
        return reason
    if reason == "timeout":
        return "slow"
    return "other"


def server_name(conf: dict) -> str:
    """The name of the MCP server of the gateway this source uses, or ""."""
    from . import ner_setup
    from .vault_refs import origin_of
    origin = str(conf.get("gateway") or "")
    if not origin:
        return ""
    servers = ner_setup._servers()
    exact = [n for n, u in servers.items() if conf.get("gateway_url") and u == conf.get("gateway_url")]
    same = [n for n, u in sorted(servers.items()) if origin_of(u) == origin]
    return (exact or same or [""])[0]


def fact_and_step(cause: str, conf: dict, codex: bool = False) -> tuple:
    fact, step = CAUSES.get(cause, CAUSES["other"])
    step = step.format(name=server_name(conf) if "{name}" in step else "").strip()
    if codex:
        from .forms import codex as _codex
        step = _codex(step)
    return fact, step


def line(cause: str, conf: dict, codex: bool = False) -> str:
    fact, step = fact_and_step(cause, conf, codex)
    return f"⚠️ maisecrets: names are NOT checked — {fact} → {step}"


# ------------------------------------------------------------------ the state --
OK_FOR = 3600.0            # a checked result this recent lets the status say the names are checked
_OK_EVERY = 60.0           # a checked result writes the record at most this often


def source_key(conf: dict) -> str:
    """The configured source, as the status compares it: its address and its gateway (never a token)."""
    return hashlib.sha256(f"{conf.get('url')}|{conf.get('gateway')}".encode("utf-8")).hexdigest()[:16]


def _state() -> dict:
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def record(cause: str, conf: dict) -> None:
    """The cause of the source `conf`, keyed by that source: after a switch, the other source's cause is not shown."""
    from .home import atomic_write
    key = source_key(conf)
    try:
        st = _state()
        if st.get("cause") == cause and st.get("source") == key:
            return
        atomic_write(STATE, json.dumps({"cause": cause, "source": key, "at": time.time()}))
    except (OSError, ValueError):
        pass


def clear(conf: dict | None = None) -> None:
    """Names were checked by the source `conf`: the recorded cause goes, and the time of the check is kept for the
    status (written at most once a minute)."""
    from .home import atomic_write
    old = _state()
    key = source_key(conf) if isinstance(conf, dict) and conf.get("url") else None
    if not old.get("cause") and (key is None or (old.get("source") == key
                                                 and time.time() - float(old.get("ok_at") or 0) < _OK_EVERY)):
        return
    try:
        atomic_write(STATE, json.dumps({"ok_at": time.time(), "source": key} if key else {}))
    except (OSError, ValueError):
        pass


def checked_ago(conf: dict) -> str | None:
    """How long ago a tool result of this very source was checked, in words ("12 min ago"), within OK_FOR; else None.
    A past fact, never a claim that the source answers now: the status asks no service on the network."""
    st = _state()
    if st.get("cause") or st.get("source") != source_key(conf):
        return None
    age = time.time() - float(st.get("ok_at") or 0)
    if not 0 <= age < OK_FOR:
        return None
    return "under a minute ago" if age < 60 else f"{int(age // 60)} min ago"


def checked_recently(conf: dict) -> bool:
    """True when a tool result of this very source was checked within OK_FOR seconds."""
    st = _state()
    return (not st.get("cause") and st.get("source") == source_key(conf)
            and time.time() - float(st.get("ok_at") or 0) < OK_FOR)


def recorded(conf: dict) -> str | None:
    """The recorded cause of this very source, or None."""
    st = _state()
    cause = st.get("cause") if st.get("source") == source_key(conf) else None
    return cause if cause in CAUSES else None


def claim(session, cause: str, conf: dict | None = None) -> bool:
    """True when this session has not heard of this cause of this source as its last one: once per session and
    source, again when the cause changes. False when the record cannot be written (no line rather than one per
    result). Under a lock."""
    if not session:
        return False
    from .home import LockTimeout, _lock_for, atomic_write
    source = source_key(conf) if isinstance(conf, dict) else ""
    key = hashlib.sha256(f"{session}|{source}".encode("utf-8")).hexdigest()[:16]
    try:
        with _lock_for(HOME / ".ner-warned.lock"):
            try:
                seen = json.loads(_WARNED.read_text(encoding="utf-8"))
                seen = seen if isinstance(seen, dict) else {}
            except (OSError, ValueError):
                seen = {}
            if seen.get(key) == cause:
                return False
            seen.pop(key, None)
            seen[key] = cause
            atomic_write(_WARNED, json.dumps(dict(list(seen.items())[-_WARNED_MAX:])))
    except (OSError, LockTimeout):
        return False
    return True


# ------------------------------------------------------------------ the checks --
def ended_cause(origin: str) -> str:
    """The cause of a gateway without a login: an older maisecrets that runs in another session (it ends a login
    without the mark of why, before 0.9.16), a renewal that did not finish, a login the gateway ended
    (invalid_grant), or none at all."""
    from . import older_versions, sref_client
    if older_versions.seen_at_start() is not None:
        # an older version still runs and renews: it is the likely cause, and a new login ends again until it stops
        return "older_ended"
    return {"uncertain": "renewal_uncertain", "revoked": "login_ended"}.get(sref_client.ended_why(origin) or "",
                                                                            "no_login")


def gateway_cause(cfg: dict, conf: dict, backend=None) -> str | None:
    """A gateway source without the network: a login in the store, and its name scope when the discovery is cached."""
    from . import ner_gateway, sref_client
    from .vault import make_backend
    origin = str(conf.get("gateway") or "")
    if not origin:
        return None
    backend = backend if backend is not None else make_backend(cfg)
    rec = sref_client._load(backend, origin)
    if not rec.get("refresh"):
        return ended_cause(origin)
    found = ner_gateway._cached(origin)
    if found and found.get("ner") and found["ner"].get("scope") not in str(rec.get("scope") or "").split():
        return "no_scope"
    return None


def start_check(cfg: dict, backend=None, starting: bool = False, timeout: float = 1.0) -> str | None:
    """The cause at a session start, or None (no source, or it can be used). `starting`: the local container is being
    started in the background right now, so its silence is no cause. A gateway login with little time left is renewed
    in the background here (sref_client.renew_ahead), at a calm moment rather than in a hook's short budget."""
    conf = _conf(cfg)
    if not conf:
        return None
    if conf.get("gateway"):
        cause = gateway_cause(cfg, conf, backend)
        if cause is None:
            from . import ner_gateway, sref_client
            from .vault import make_backend
            found = ner_gateway._cached(str(conf["gateway"]))
            if found:
                sref_client.renew_ahead(cfg, backend if backend is not None else make_backend(cfg), found)
        return cause
    url = str(conf.get("url") or "")
    if starting and _is_local(conf):
        return None
    if url.startswith("unix:"):
        return None if _socket_answers(url[len("unix:"):], timeout) else "no_answer"
    if _is_local(conf):
        proof = local_proof(cfg, timeout)
        return {"down": "local_down", "not_ours": "not_ours"}.get(proof)
    from . import ner_setup
    ok, _line = ner_setup.probe(conf, timeout=timeout)
    return None if ok else "no_answer"


def _socket_answers(path: str, timeout: float) -> bool:
    """A Unix socket source: something accepts a connection on it within `timeout` (no text is sent)."""
    import socket
    if not hasattr(socket, "AF_UNIX"):
        return True                        # no Unix sockets here: no claim either way
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()


def local_proof(cfg: dict, timeout: float = 1.0) -> str:
    """The local container, asked as a tool result asks it: "proven" (it proved the secret `run.sh ner start` kept,
    the challenge of remote._prove), "not_ours" (something answers and cannot prove it), "down" (nothing answers),
    or "unproven" (no secret is kept: a container started by hand, which no /health answer can prove)."""
    from . import ner_setup, remote_layer
    det, _why = remote_layer.from_config(cfg)
    if det is None or not det.proves:
        ok, _line = ner_setup.probe(_conf(cfg), timeout=timeout)
        return "unproven" if ok else "down"
    try:
        det._prove(time.monotonic() + timeout)
    except (OSError, TimeoutError):
        return "down"
    except Exception:  # noqa: BLE001 - _NotOurs, or an answer of another shape: not the container maisecrets started
        return "not_ours"
    return "proven"


def _seen_by_person(payload: dict, codex: bool) -> bool:
    """The gates of the hints (remote_layer.hint): not a subagent, which has no conversation with the person, and
    only where a person sees the hook's lines (not `claude -p`, the Agent SDK or `codex exec`). Elsewhere the line is
    neither shown nor claimed, so the person's own session still gets it."""
    from . import settings
    return not payload.get("agent_id") and settings.person_sees_hook_lines(payload, codex)


def start_line(cfg: dict, payload: dict, backend=None, starting: bool = False, codex: bool = False) -> str | None:
    """The session start's line, once per session and cause, or None."""
    cause = start_check(cfg, backend, starting)
    if cause is None:
        return None
    record(cause, _conf(cfg))
    if not _seen_by_person(payload, codex):
        return None
    return line(cause, _conf(cfg), codex) if claim(payload.get("session_id"), cause, _conf(cfg)) else None


def result_line(cfg: dict, payload: dict, reason: str, codex: bool = False) -> str | None:
    """The line of an unchecked tool result: once per session and cause, or None."""
    conf = _conf(cfg)
    cause = cause_of(conf, reason) if conf else None
    if cause is None:
        return None
    record(cause, conf)
    if not _seen_by_person(payload, codex):
        return None
    return line(cause, conf, codex) if claim(payload.get("session_id"), cause, conf) else None


def verdict(cfg: dict, backend=None):
    """The `names` check of /maisecrets status and the panel: None without a source; a warn with the cause and the
    step when the source cannot be used; ok otherwise. Never a FAIL: the secrets are still protected."""
    from .status_verdict import Check
    conf = _conf(cfg)
    if not conf:
        return None
    proof = None
    if conf.get("gateway"):
        # the login is read now; a recorded login cause is older than the store (a login since then)
        cause = gateway_cause(cfg, conf, backend)
        if cause is None:
            cause = recorded(conf)
            login = ("login_ended", "renewal_uncertain", "no_login", "older_ended", "no_scope")
            cause = None if cause in login else cause
    elif _is_local(conf):
        proof = local_proof(cfg, 0.5)
        cause = {"down": "local_down", "not_ours": "not_ours"}.get(proof)
        if proof == "unproven" and not checked_recently(conf):
            # a /health answer proves nothing: any listener on the port gives one
            return Check("n/a", "names", "set, not proven yet", None,
                         "the local service answers, but it holds no secret of `run.sh ner start` to prove")
    else:
        cause = recorded(conf)
    ago = checked_ago(conf) if cause is None else None
    if ago:
        return Check("ok", "names", f"checked {ago}", None,
                     f"a tool result of this source was checked {ago}; the status does not ask the service now")
    if cause is None and proof == "proven":
        # it proved it is the container maisecrets started; "checked" needs a tool result it really checked
        return Check("n/a", "names", "ready, not used yet in this session", None,
                     "the local container proved its secret; no tool result of it was checked in the last hour")
    if cause is None:
        # a login in the store or a url that is set proves no answer: neutral until a result of it was checked
        return Check("n/a", "names", "set, not used yet in this session", None,
                     "no tool result of this source was checked in the last hour")
    fact, step = fact_and_step(cause, conf)
    return Check("warn", "names", fact, step, f"names are not checked: {fact}; the rules alone mask tool results")
