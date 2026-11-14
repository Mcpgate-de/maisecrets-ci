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
