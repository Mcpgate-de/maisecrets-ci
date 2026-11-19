"""An older maisecrets that still runs in another session. A session keeps the plugin version it started with until it
restarts, so after an update an open session can run the old code for days. A field case: a session on a version before
0.9.16 renewed a gateway login with the old logic; the gateway saw the spent refresh token again 14 s after a rotation
and ended the login (0.9.16, commit 1f14aa0f, fixed the logic).

versions.json in the maisecrets home holds, per plugin version, three times: `first` (the first session start of that
version), `start` (its last session start) and `refresh` (its last gateway renewal). No value, no session id, no
session text. It is written at a session start and after a gateway renewal (mark_run), never on a prompt or a tool call.

The session start and /maisecrets:status of the newest version read it. An older version that started a session or
renewed a login after the newest version's first start, within WINDOW, may still be open somewhere: the marker
cannot see a session end. A version before this
module writes no marker; its trace is its lines in events.log, each of which names the version that wrote it (one per
detection). So an old session that detects nothing and only renews a login is not seen: the limit of this check.

The session start says it once a day, and only where a gateway login was used (sref-inflight.json, which each
renewal since 0.9.16 writes, or a renewal in the marker), because the risk is the renewal.
"""
from __future__ import annotations

import json
import time

from .home import HOME, atomic_write

MARKER = HOME / "versions.json"
EVENTS = HOME / "events.log"
INFLIGHT = HOME / "sref-inflight.json"
WINDOW = 24 * 3600          # an older version's run within this time counts
KEEP = 30 * 86400           # a version with no run for this long leaves the marker
KINDS = ("start", "refresh")


def _tuple(v) -> tuple | None:
    try:
        parts = tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return None
    return parts if len(parts) == 3 else None


def _current() -> str:
    from .events import plugin_version
    return plugin_version()


def _read() -> dict:
    """The marker as {"versions": {version: {kind: time}}, "told": day}; a missing or damaged file is an empty one."""
    try:
        data = json.loads(MARKER.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"versions": {}}
    if not isinstance(data, dict) or not isinstance(data.get("versions"), dict):
        return {"versions": {}}
    versions = {}
    for v, times in data["versions"].items():
        if _tuple(v) is None or not isinstance(times, dict):
            continue
        kept = {k: float(t) for k, t in times.items()
                if k in ("first",) + KINDS and isinstance(t, (int, float)) and not isinstance(t, bool)}
        if kept:
            versions[v] = kept
    out = {"versions": versions}
    if isinstance(data.get("told"), str):
        out["told"] = data["told"]
    return out


def _write(data: dict, now: float) -> None:
    data["versions"] = {v: t for v, t in data["versions"].items() if max(t.values()) > now - KEEP}
    try:
        atomic_write(MARKER, json.dumps(data, sort_keys=True))
    except OSError:
        pass


def _mark(data: dict, kind: str, now: float) -> None:
    v = _current()
    if _tuple(v) is None:
        return
    times = data["versions"].setdefault(v, {})
    times["first"] = min(times.get("first", now), now)
    times[kind] = max(times.get(kind, now), now)      # a later time another process wrote stays


LOCK_WAIT = 2.0


def _locked():
    """The lock of versions.json: a read, a mark and a write of two processes never cross, so neither loses the other's
    time (an old version's renewal and a new start at once, Gate A of !591). Raises LockTimeout or OSError."""
    from .home import _lock_for
    lock = _lock_for(HOME / ".versions.lock")
    lock.enter(LOCK_WAIT)
    return lock


def mark_run(kind: str, now: float | None = None) -> None:
    """This version ran: a session start ("start") or a gateway renewal ("refresh"). Never raises."""
    if kind not in KINDS:
        return
    try:
        now = time.time() if now is None else now
        lock = _locked()
        try:
            data = _read()
            _mark(data, kind, now)
            _write(data, now)
        finally:
            lock.__exit__(None, None, None)
    except Exception:  # noqa: BLE001 - a marker never stops a hook
        pass


def _from_events(since: float) -> dict:
    """{version: the time of its last line} in events.log, for lines after `since`; read only when the file changed
    after `since` (one stat)."""
    try:
        if EVENTS.stat().st_mtime <= since:
            return {}
        lines = EVENTS.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return {}
    out: dict = {}
    for line in lines:
        try:
            e = json.loads(line)
            t = time.mktime(time.strptime(e["ts"], "%Y-%m-%dT%H:%M:%S"))
        except (ValueError, KeyError, TypeError, OverflowError):
            continue
        v = e.get("version") if isinstance(e, dict) else None
        if isinstance(v, str) and _tuple(v) is not None and t > since:
            out[v] = max(out.get(v, 0.0), t)
    return out


def finding(data: dict, now: float) -> tuple | None:
    """(the oldest version that ran recently, the first start of this version) or None. An older version counts when it
    started a session, renewed a login or wrote an events.log line after this version's first start, within WINDOW;
    and only where a gateway login was used."""
    cur = _current()
    mine = _tuple(cur)
    if mine is None:
        return None
    first = data["versions"].get(cur, {}).get("first", now)
    since = max(first, now - WINDOW)
    seen: dict = {}
    for v, times in data["versions"].items():
        t = max((times.get(k, 0.0) for k in KINDS), default=0.0)
        if t > since:
            seen[v] = t
    for v, t in _from_events(since).items():
        seen[v] = max(seen.get(v, 0.0), t)
    older = sorted((v for v in seen if (_tuple(v) or mine) < mine), key=_tuple)
    if not older:
        return None
    renewals = any("refresh" in t for t in data["versions"].values())
    try:
        gateway = renewals or INFLIGHT.exists()
    except OSError:
        gateway = renewals
    return (older[0], first) if gateway else None


def text(version: str, first: float) -> str:
    day = time.strftime("%Y-%m-%d %H:%M", time.localtime(first))
    return (f"An older maisecrets ({version}) ran in the last day and may still be open in another session. Its "
            f"gateway renewals can end your login. Restart the sessions that started before {day}.")


def start(now: float | None = None) -> str | None:
    """At a session start: note this version, and the warning once a day (None otherwise). One read, one write."""
    try:
        now = time.time() if now is None else now
        lock = _locked()
        try:
            data = _read()
            _mark(data, "start", now)
            found = finding(data, now)
            day = time.strftime("%Y-%m-%d", time.localtime(now))
            line = None
            if found and data.get("told") != day:
                data["told"] = day
                line = "maisecrets: " + text(*found)
            _write(data, now)
        finally:
            lock.__exit__(None, None, None)
        return line
    except Exception:  # noqa: BLE001 - a warning never stops a session start
        return None


def status(now: float | None = None) -> tuple | None:
    """For /maisecrets:status: (version, the warning) whenever it holds; it marks nothing."""
    try:
        now = time.time() if now is None else now
        found = finding(_read(), now)
    except Exception:  # noqa: BLE001 - a note that cannot be read is no check
        return None
    return (found[0], text(*found)) if found else None
