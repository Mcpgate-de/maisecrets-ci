"""The load of a name service from its GET /metrics (mcpgate/ner from ai-gateway #1869), for /maisecrets:ner.

The service answers the same counters as JSON with `Accept: application/json`, so no Prometheus parser is needed.
Two samples about a second apart give the share of the workers in use (the growth of worker_busy_seconds_total per
second and worker), the requests that wait for a worker, and from the cgroup the CPU share of the limit and the share
of throttled periods. Numbers only: the answer holds no text of any request. A service without /metrics (an older
image, a service of another kind) gives "no load data", never an error.
"""
from __future__ import annotations

import json
import math
import time
import urllib.error
import urllib.request

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
MAX_BYTES = 65536


def bearer_of(secret: str) -> str:
    """The bearer of /metrics for a container with NER_CLIENT_SECRET: HMAC-SHA256(secret, "metrics") in hex. It is
    not the bearer of a text (HMAC(secret, "bearer")), so a token that reads the load cannot send a text."""
    import hashlib
    import hmac
    return hmac.new(secret.encode("utf-8"), b"metrics", hashlib.sha256).hexdigest()


def sample(url: str, timeout: float = 1.0, bearer: str = "") -> tuple[dict | None, str]:
    """(the counters, "") or (None, why there are none), within `timeout` for the whole request: a socket timeout
    counts per read, and a server that sends a byte now and then would hold the status command (Gate A)."""
    import threading
    box: dict = {}
    t = threading.Thread(target=lambda: box.update(r=_sample(url, timeout, bearer)), daemon=True)
    t.start()
    t.join(timeout + 0.5)
    return box.get("r") or (None, "/metrics gives no answer in time")


def _sample(url: str, timeout: float, bearer: str) -> tuple[dict | None, str]:
    headers = {"Accept": "application/json", **({"Authorization": "Bearer " + bearer} if bearer else {})}
    req = urllib.request.Request(url.rstrip("/") + "/metrics", headers=headers)
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            doc = json.loads(r.read(MAX_BYTES).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code in (401, 403):
            return None, "the service wants a metrics token"
        return None, "the service has no /metrics" if exc.code == 404 else f"/metrics answers HTTP {exc.code}"
    except (OSError, urllib.error.URLError, ValueError, UnicodeError):
        return None, "/metrics gives no answer it can read"
    if not isinstance(doc, dict) or not isinstance(doc.get("ner"), dict):
        return None, "/metrics gives no answer it can read"
    return doc, ""


def _num(doc: dict, *path) -> float | None:
    for key in path:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(key)
    if isinstance(doc, bool) or not isinstance(doc, (int, float)) or not math.isfinite(doc) or doc < 0:
        return None
    return float(doc)


def _share(after: dict, before: dict, num: tuple, den: tuple) -> float | None:
    a, b, c, d = _num(after, *num), _num(before, *num), _num(after, *den), _num(before, *den)
    if None in (a, b, c, d) or c - d <= 0 or a < b:
        return None
    return min(1.0, (a - b) / (c - d))


def load(before: dict, after: dict, seconds: float) -> dict:
    """The load between two samples: workers, in_use (0..1), waiting, cpu (0..1 of the limit), throttled (0..1),
    memory_mb, memory_limit_mb; a key is absent when the service does not give it."""
    out: dict = {}
    workers = _num(after, "ner", "workers")
    if workers:
        out["workers"] = int(workers)
        a, b = _num(after, "ner", "worker_busy_seconds_total"), _num(before, "ner", "worker_busy_seconds_total")
        if a is not None and b is not None and a >= b and seconds > 0:
            out["in_use"] = min(1.0, (a - b) / seconds / workers)
    waiting = _num(after, "ner", "waiting_requests")
    if waiting is not None:
        out["waiting"] = int(waiting)
    cores = _num(after, "cgroup", "cpu_limit_cores")
    a, b = _num(after, "cgroup", "cpu_usage_seconds_total"), _num(before, "cgroup", "cpu_usage_seconds_total")
    if cores and a is not None and b is not None and a >= b and seconds > 0:
        out["cpu"] = min(1.0, (a - b) / seconds / cores)
        out["cores"] = cores
    throttled = _share(after, before, ("cgroup", "cpu_throttled_periods_total"), ("cgroup", "cpu_periods_total"))
    if throttled is not None:
        out["throttled"] = throttled
    mem, limit = _num(after, "cgroup", "memory_bytes"), _num(after, "cgroup", "memory_limit_bytes")
    if mem is not None:
        out["memory_mb"] = round(mem / 2**20)
        if limit:
            out["memory_limit_mb"] = round(limit / 2**20)
    return out


def load_line(url: str, gap: float = 1.0, timeout: float = 1.0, bearer: str = "") -> str:
    """One line for /maisecrets:ner: the load of the service at `url`, or why there is none. `bearer`: the metrics
    bearer of a container with a secret (bearer_of)."""
    first, why = sample(url, timeout, bearer)
    if first is None:
        return f"load: no load data ({why})"
    t0 = time.monotonic()
    time.sleep(gap)
    second, why = sample(url, timeout, bearer)
    if second is None:
        return f"load: no load data ({why})"
    got = load(first, second, time.monotonic() - t0)
    parts = []
    if "workers" in got:
        used = f", {got['in_use'] * 100:.0f} % in use" if "in_use" in got else ""
        parts.append(f"{got['workers']} workers{used}")
    if "waiting" in got:
        parts.append(f"{got['waiting']} waiting")
    if "cpu" in got:
        parts.append(f"CPU {got['cpu'] * 100:.0f} % of {got['cores']:g} cores")
    if "throttled" in got:
        parts.append(f"throttled {got['throttled'] * 100:.0f} %")
    if "memory_mb" in got:
        limit = f" of {got['memory_limit_mb']}" if "memory_limit_mb" in got else ""
        parts.append(f"memory {got['memory_mb']}{limit} MB")
    if not parts:
        return "load: no load data (/metrics names no counter maisecrets reads)"
    saturated = " (saturated: requests wait for a worker)" if got.get("waiting") else ""
    return "load: " + ", ".join(parts) + saturated
