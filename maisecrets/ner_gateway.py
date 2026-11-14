"""The gateway of /maisecrets:sref login as the source of names for tool results (#33, ai-gateway #1819).

/maisecrets:ner gateway URL sets the source: `remote_detector` gets {"gateway": <origin>, "url": <origin>,
"allow_network": true}. At each tool result, from_config() asks here for the gateway's name endpoint (its protected
resource metadata names `ner_endpoint`, `ner_scope` and `ner_max_chars`; kept for an hour in ner-gateway.json, never
a token) and for an access token of the login (sref_client, refreshed under its lock). The login must hold the name
scope: a login asks for it only while this source is set (sref_client.discover), so the person logs in once more
after the switch. A prompt goes to this source only after `/maisecrets:ner prompts on`, typed while this source is set
(C30a: remote_layer.prompt_names); the rules' findings and the stored values go there as filler, as for a tool result.
"""
from __future__ import annotations

import json
import time

from .vault import HOME

CACHE = HOME / "ner-gateway.json"
CACHE_S = 3600
# a request waits this long by default: the gateway's round trip and its own lookups (#1819: 5 s deadline there);
# the person's timeout_ms of this source wins. Measured: p95 600 ms with 8 sessions at once, and 2 of 45 requests
# over 2 s (README "Names from a service")
DEFAULT_TIMEOUT_MS = 3000


def origin_of(conf) -> str:
    """The gateway origin the setting names, or ""."""
    return str(conf.get("gateway") or "") if isinstance(conf, dict) else ""


def _cached(origin: str) -> dict | None:
    try:
        data = json.loads(CACHE.read_text(encoding="utf-8"))
        rec = data.get(origin) if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None
    if isinstance(rec, dict) and time.time() - float(rec.get("at") or 0) < CACHE_S and isinstance(rec.get("found"),
                                                                                                   dict):
        return rec["found"]
    return None


def _keep(origin: str, found: dict) -> None:
    try:
        data = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
        data = data if isinstance(data, dict) else {}
        data[origin] = {"at": time.time(), "found": found}
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(data), encoding="utf-8")
    except (OSError, ValueError, TypeError):
        pass


def found_for(cfg: dict, origin: str, url: str, deadline: float) -> dict | None:
    """The discovery of the gateway at `url` (sref_client.discover), from the cache while it is fresh."""
    from . import sref_client
    got = _cached(origin)
    if got is None:
        got = sref_client.discover(cfg, url, deadline)
        if got:
            _keep(origin, got)
    return got


def status(cfg: dict, conf: dict) -> tuple:
    """(the status document of the gateway's name service, "") or (None, why there is none): GET ner_status_endpoint
    with the token of the login. Numbers only: the load of the service, whether the one client slot is free, and the
    person's quota in the current minute."""
    import json
    from . import sref_client
    from .vault import make_backend
    origin = origin_of(conf)
    deadline = time.monotonic() + 3.0
    found = found_for(cfg, origin, str(conf.get("gateway_url") or origin), deadline)
    if found and found.get("ner") and "status" not in found["ner"]:
        # a cache of a version before the status endpoint: ask the gateway again, not in an hour
        CACHE.unlink(missing_ok=True)
        found = found_for(cfg, origin, str(conf.get("gateway_url") or origin), deadline)
    url = ((found or {}).get("ner") or {}).get("status")
    if not url:
        return None, "the gateway names no status endpoint"
    try:
        token = sref_client._access(cfg, make_backend(cfg), found, deadline)
        code, headers, body = sref_client._request(cfg, "GET", url, {"Accept": "application/json",
                                                                    "Authorization": "Bearer " + token}, None, deadline)
    except sref_client.Refused as exc:
        return None, str(exc)
    except Exception as exc:  # noqa: BLE001 - the status is a help, never an error of the source
        return None, type(exc).__name__
    if code != 200:
        return None, f"the status endpoint answers HTTP {code}"
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeError):
        return None, "the status endpoint gives no answer it can read"
    return (doc, "") if isinstance(doc, dict) else (None, "the status endpoint gives no answer it can read")


def _int(v):
    # Infinity and 1e999 parse as JSON numbers; int() of them raises (Gate A)
    import math
    ok = isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v >= 0
    return int(v) if ok else None


def status_line(doc) -> str:
    """One line for /maisecrets:ner from the status document."""
    if not isinstance(doc, dict):
        return "load: no load data"
    parts = []
    svc = doc.get("service") if isinstance(doc.get("service"), dict) else None
    if svc and _int(svc.get("workers")):
        share = svc.get("in_use_share")
        used = (f", {share * 100:.0f} % in use" if isinstance(share, (int, float)) and not isinstance(share, bool)
                and 0 <= share <= 1 else "")
        parts.append(f"{_int(svc['workers'])} workers{used}")
        if _int(svc.get("waiting_requests")) is not None:
            parts.append(f"{_int(svc['waiting_requests'])} waiting")
    path = doc.get("client_path") if isinstance(doc.get("client_path"), dict) else {}
    if path.get("free") is False:
        parts.append("the client slot is busy now (a text is answered busy)")
    q = doc.get("quota") if isinstance(doc.get("quota"), dict) else {}
    left, per = _int(q.get("requests_left")), _int(q.get("requests_per_minute"))
    cleft, cper = _int(q.get("chars_left")), _int(q.get("chars_per_minute"))
    if left is not None and per:
        parts.append(f"your quota this minute: {left} of {per} requests"
                     + (f", {cleft:,} of {cper:,} characters" if cleft is not None and cper else ""))
    return ("load: " + "; ".join(parts)) if parts else "load: no load data"


def detector(cfg: dict, conf: dict, make) -> tuple:
    """(RemoteDetector or None, why not). `make(url, token, max_chars)` builds the detector with the person's tuning.
    No login, no name endpoint or a login without the name scope: no detector, and the rules alone, with the reason."""
    from . import sref_client
    from .vault import make_backend
    origin = origin_of(conf)
    deadline = time.monotonic() + 2.0
    found = found_for(cfg, origin, str(conf.get("gateway_url") or origin), deadline)
    if not found or not found.get("ner"):
        return None, f"{origin} names no name detection (the gateway's admin switch may be off)"
    backend = make_backend(cfg)
    scopes = str(sref_client._load(backend, origin).get("scope") or "").split()
    if found["ner"]["scope"] not in scopes:
        return None, "the login lacks the name scope; the person runs /maisecrets:sref login once more"
    try:
        token = sref_client._access(cfg, backend, found, deadline)
    except sref_client.Refused as exc:
        return None, str(exc)
    return make(found["ner"]["endpoint"], token, int(found["ner"].get("max_chars") or 20000)), ""
