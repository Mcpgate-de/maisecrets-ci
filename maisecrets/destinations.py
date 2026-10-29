"""Where each stored secret was sent (setting `secret_destinations`: observe by default, protect, or off).
Mcpgate-de/maisecrets#13.

This module never decides whether a call runs. It notes, on this computer only, each destination a stored secret
went to, and shows it in /maisecrets:list. With observe a seen destination is a record, never a permission. With
protect the hook asks before a network destination that new_hosts() names: a host the secret was never `seen` at,
after its first call. `allowed` is kept apart in the store and is not used by any decision yet.

Destinations:
- network: a host from a URL in a Bash command, an ssh host (as maisecrets/ssh_consent.py reads it), an MCP server
  and tool. The tool, not the server, because one gateway server carries many services, one tool each; an `action`
  is the operation inside a service, not a destination (scripts/measure_binding.py, 2026-10-07: with `action` in the
  key 16 of 56 secrets would have several destinations, with server and tool 5). A tool that serves several services
  names its service in a `service` or `provider` field, which then joins the key.
- local: a file (Write, Edit) or a Bash command without a host. Listed, never a destination, never a hint.
A label is cleaned (one printable line, a secret shape hidden, a service field only as a name), and the record of a
secret keeps its MAX_PER_SECRET most recent destinations.

The one hint (maisecrets/settings.py HINTS) comes at the first pattern break: a secret with ESTABLISHED_USES uses on
one day at one network destination goes to a network destination it never went to. 3 uses on one day was measured
as the threshold (scripts/measure_binding.py over 90 days of one user's transcripts: 1/1 gave 56 breaks, 2/1 18,
3/1 8, 3/2 1, 5/2 0); a stricter one would almost never fire, a looser one counts the setup of a new token.
"""
from __future__ import annotations

import json
import math
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from .vault import HOME, LockTimeout, _Lock, atomic_write

ESTABLISHED_USES = 3
STORE = "destinations.json"
class _ShortLock(_Lock):
    """The vault lock waits up to 6 s, which is right for the store and wrong here: a busy record must cost a call
    at most this long, and then the record is skipped (codex review of 0.6.7: two keys waited 12 s)."""
    LOCK_DEADLINE = 0.3


_LOCK = _ShortLock(HOME / ".destinations.lock")
_URL = re.compile(r"https?://[^\s'\"<>`|;)]+", re.I)    # HTTPS:// is a URL to curl too (Fable review)
_MAX_SESSIONS = 50


def _path() -> Path:
    return HOME / STORE


class Corrupt(ValueError):
    pass


_FIELDS = {"kind": str, "label": str, "uses": int, "first": (int, float), "last": (int, float), "day": str,
           "day_uses": int, "max_day_uses": int}
MAX_PER_SECRET = 50       # a call the model writes chooses a label; the record of one secret stays bounded
# a call is noted as pending when the value is handed out (PreToolUse) and becomes `seen` only when the client
# reports that it ran (PostToolUse or PostToolUseFailure): a call the person declines leaves no record (ChatGPT
# review of 0.6.7). A pending call that never ran goes after this time; at most this many wait at once. The time
# counts from the hand-out, before the permission dialog, so it is long: a dialog left open is still a call to come
PENDING_SECONDS = 24 * 3600
MAX_PENDING = 100
# protect: the check claims a key's first call before its value is resolved; the call pends (or not) within the same
# hook run, so a claim that no pending call carries ends after this time, not after a day (a refused first call
# must not lock its key: Fable review of protect)
CLAIM_SECONDS = 30


def _call_key(call: str, session: str | None, agent: str | None) -> str:
    """A tool_use_id is unique only in its session (Codex numbers them: call_1): the end of a call in another
    session or agent must not commit this one (codex review of 0.6.8)."""
    return "\x1f".join((session or "", agent or "", call))


def _well_formed(d) -> bool:
    return isinstance(d, dict) and all(isinstance(d.get(k), t) and not isinstance(d.get(k), bool)
                                       and not (isinstance(d.get(k), float) and not math.isfinite(d[k]))
                                       for k, t in _FIELDS.items())


def _clean(data: dict) -> dict:
    """Keep only well-formed records: a file another program changed must not crash the list (codex review)."""
    secrets = data.get("secrets") if isinstance(data.get("secrets"), dict) else {}
    kept = {}
    for key, rec in secrets.items():
        if not (isinstance(key, str) and isinstance(rec, dict) and isinstance(rec.get("seen", {}), dict)):
            continue
        seen = {i: d for i, d in rec.get("seen", {}).items() if isinstance(i, str) and _well_formed(d)}
        if len(seen) > MAX_PER_SECRET:
            seen = dict(sorted(seen.items(), key=lambda kv: kv[1]["last"])[-MAX_PER_SECRET:])
        kept[key] = {"seen": seen, "allowed": rec.get("allowed") if isinstance(rec.get("allowed"), dict) else {}}
    data["secrets"] = kept
    claims = data.get("claims") if isinstance(data.get("claims"), dict) else {}
    data["claims"] = {k: t for k, t in claims.items() if isinstance(k, str) and _a_time(t)}
    calls = data.get("pending_calls") if isinstance(data.get("pending_calls"), dict) else {}
    data["pending_calls"] = {i: c for i, c in calls.items() if isinstance(i, str) and _pending_well_formed(c)}
    return data


def _a_time(t) -> bool:
    return isinstance(t, (int, float)) and not isinstance(t, bool) and math.isfinite(t)


def _pending_well_formed(c) -> bool:
    return (isinstance(c, dict) and isinstance(c.get("keys"), list) and all(isinstance(k, str) for k in c["keys"])
            and isinstance(c.get("found"), list) and len(c["found"]) <= MAX_PER_SECRET
            and all(isinstance(f, list) and len(f) == 2 and f[0] in ("network", "local") and isinstance(f[1], str)
                    for f in c["found"])
            and all(c.get(k) is None or isinstance(c.get(k), str) for k in ("session", "agent"))
            and isinstance(c.get("t"), (int, float)) and not isinstance(c.get("t"), bool) and math.isfinite(c["t"]))


def _load(strict: bool = False) -> dict:
    """The store, cleaned. With strict, a file that exists and does not parse raises Corrupt: a writer must not
    replace what it cannot read (it moves it aside first, see _load_for_write)."""
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {}
    except (OSError, ValueError, RecursionError):
        if strict:
            raise Corrupt(STORE)
        data = {}
    if not isinstance(data, dict):
        if strict:
            raise Corrupt(STORE)
        data = {}
    data = _clean(data)
    for k in ("secrets", "pending_hint", "interactive", "pending_calls", "claims"):
        if not isinstance(data.get(k), dict if k != "interactive" else list):
            data[k] = {} if k != "interactive" else []
    return data


def _save(data: dict) -> None:
    atomic_write(_path(), json.dumps(data, indent=1, sort_keys=True) + "\n")


def _load_for_write() -> dict:
    """Under the lock: the store to change. A corrupt file is moved aside (destinations.json.corrupt) and a new one
    begins, so nothing the person had is overwritten unseen; /maisecrets:status lists the file."""
    try:
        return _load(strict=True)
    except Corrupt:
        aside = _path().with_name(STORE + ".corrupt")
        n = 0
        while aside.exists():
            n += 1
            aside = _path().with_name(f"{STORE}.corrupt.{int(time.time())}.{n}")
        os.replace(_path(), aside)   # an OSError ends this note: a file not moved aside is never written over
        return _load()


def hosts_in(command: str) -> list[str]:
    hosts = set()
    for url in _URL.findall(command or ""):
        try:
            host = urlparse(url).hostname
        except ValueError:
            continue
        if host:
            hosts.add(host.lower())
    return sorted(hosts)


_UNPRINTABLE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def clean_label(text: str) -> str:
    """One printable line of at most 80 characters: a label comes from a call the model wrote (a service field, a
    path), and a newline or a terminal escape in it must not draw lines into /maisecrets:list (codex review)."""
    text = _UNPRINTABLE.sub("?", str(text))
    text = re.sub(r"\s+", " ", text).strip()
    text = "".join(c if c.isprintable() else "?" for c in text)   # format characters too: U+2060, U+00AD (codex)
    from . import detect
    for m in sorted(detect.scan(text), key=lambda m: -m.start):
        if m.type == "SECRET":
            text = text[:m.start] + "<hidden>" + text[m.end:]
    return text[:77] + "..." if len(text) > 80 else text


def destinations_of(tool: str, tool_input: dict, ssh_hosts: list[str] | None = None) -> list[tuple[str, str]]:
    """(kind, label) per destination of one call: kind "network" or "local". The label is what the person reads."""
    return [(k, label) for k, label, _exact in exact_destinations(tool, tool_input, ssh_hosts)]


def exact_destinations(tool: str, tool_input: dict,
                       ssh_hosts: list[str] | None = None) -> list[tuple[str, str, bool]]:
    """(kind, label, exact) per destination: exact is False when the label does not name the destination one to
    one (cut at 80 characters, a secret shape hidden, a character replaced, a service field that is no name). Two
    such destinations can share a label, so protect never takes one as known (codex review of protect)."""
    def one(kind: str, raw: str, exact: bool = True) -> tuple[str, str, bool]:
        label = clean_label(raw)
        return kind, label, exact and label == raw
    if tool in ("Bash", "PowerShell"):
        command = str(tool_input.get("command") or "")
        if tool == "Bash":
            from .hooks import _shell_contexts, comment_is_sure   # a URL in a # comment goes nowhere (codex review)
            ctxs = _shell_contexts(command)
            command = "".join(" " if cx == "comment" and comment_is_sure(command, ctxs, k) else ch
                              for k, (ch, cx) in enumerate(zip(command, ctxs)))
        # the ssh hosts first: a bounded record keeps the first entries, and many URLs must not push them out (Opus)
        found = [("network", "ssh " + h) for h in sorted(set(ssh_hosts or []))]
        found += [("network", h) for h in hosts_in(command)]
        return [one(k, v) for k, v in found] or [("local", "a command on this computer", True)]
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        # the whole rest is the tool: mcp__gw__foo__bar is not mcp__gw__foo (codex review of protect)
        server, name = parts[1] if len(parts) > 1 else "?", "__".join(parts[2:]) or "?"
        service = "+".join(str(tool_input[f]) for f in ("service", "provider") if tool_input.get(f))
        # a field that is there must be a name, also a false one (0, []): else it would share the bare tool's label
        named = all(isinstance(tool_input[f], str) and bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", tool_input[f]))
                    for f in ("service", "provider") if f in tool_input)
        # a name, not free text: the model writes this field, and a value in it must not land in the record (Opus)
        if not (named and service):          # both fields, when both are there: service+provider
            service = ""
        label = f"MCP {server} · {name}" + (f" · {service}" if service else "")
        return [one("network", label, named)]
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"):
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        folder = os.path.dirname(path) or "."
        home = str(Path.home())
        if folder == home or folder.startswith(home.rstrip(os.sep) + os.sep):    # not /home/anna for /home/ann
            folder = "~" + folder[len(home):]
        if os.sep == "\\":
            folder = folder.replace("\\", "/")         # one separator in a label: ~/proj/, not ~\proj/ (Windows CI)
        return [one("local", f"a file in {folder}/")]
    return [one("local", f"a {tool} call")]


def note(keys: list[str], session: str | None, agent: str | None, destinations: list[tuple[str, str]]) -> bool:
    """Record one use per key and destination, all keys of a call under one short lock. True when the call is a
    pattern break (the caller gives the hint only once, globally). Never raises: a record that cannot be written
    must not stop the call. For a call the client did not yet report as run, use pend() and commit()."""
    try:
        with _LOCK:
            data = _load_for_write()
            pattern_break = _note_locked(data, keys, session, agent, destinations)
            _save(data)
            return pattern_break
    except (OSError, LockTimeout, ValueError, TypeError, KeyError):
        return False


def _note_locked(data: dict, keys: list[str], session: str | None, agent: str | None,
                 destinations: list[tuple[str, str]]) -> bool:
    pattern_break = False
    for key in dict.fromkeys(keys):
        pattern_break = _note_one(data, key, destinations) or pattern_break
        data["claims"].pop(key, None)
    if pattern_break and session and not agent and session in data["interactive"]:
        data["pending_hint"][session] = time.time()
    data["pending_hint"] = {s: t for s, t in data["pending_hint"].items() if s in data["interactive"]}
    return pattern_break


def pend(call: str, keys: list[str], session: str | None, agent: str | None,
         destinations: list[tuple[str, str]]) -> bool:
    """The value is handed out to this call: wait for the client to report that it ran. Nothing is `seen` yet and
    no pattern break is counted. Never raises; False when the record could not be written (protect refuses then:
    a first call that left no pending record would leave its key free for another first call)."""
    try:
        with _LOCK:
            data = _load_for_write()
            now = time.time()
            calls = {i: c for i, c in data["pending_calls"].items() if now - c["t"] < PENDING_SECONDS}
            found = list(destinations)[:MAX_PER_SECRET]     # bounded, as a record (destinations_of names a host once)
            calls[_call_key(call, session, agent)] = {"keys": list(dict.fromkeys(keys)), "session": session,
                                                      "agent": agent, "found": [[k, v] for k, v in found], "t": now}
            if len(calls) > MAX_PENDING:
                calls = dict(sorted(calls.items(), key=lambda kv: kv[1]["t"])[-MAX_PENDING:])
            data["pending_calls"] = calls
            _save(data)
            return True
    except (OSError, LockTimeout, ValueError, TypeError, KeyError) as exc:
        from . import incidents
        incidents.note("destinations.pend", exc)
        return False


def commit(call: str, session: str | None, agent: str | None) -> bool:
    """The client reports that this call ran (also one that failed: the tool had the value). Its pending record
    becomes `seen`, however late the report comes: it is the proof (Opus review of 0.6.8). True when it is a pattern
    break. A call with no pending record changes nothing and takes no lock. Never raises."""
    key = _call_key(call, session, agent)
    try:
        if key not in _load()["pending_calls"]:
            return False                 # most calls carry no value: no lock and no write for them
        with _LOCK:
            data = _load_for_write()
            c = data["pending_calls"].pop(key, None)
            if c is None:
                return False
            pattern_break = _note_locked(data, c["keys"], c["session"], c["agent"],
                                         [(k, v) for k, v in c["found"]])
            _save(data)
            return pattern_break
    except (OSError, LockTimeout, ValueError, TypeError, KeyError) as exc:
        from . import incidents
        incidents.note("destinations.commit", exc)
        return False


def _note_one(data: dict, key: str, destinations: list[tuple[str, str]]) -> bool:
    rec = data["secrets"].setdefault(key, {"seen": {}, "allowed": {}})
    seen = rec.setdefault("seen", {})
    rec.setdefault("allowed", {})          # kept apart from seen; no decision reads it yet
    now = time.time()
    today = time.strftime("%Y-%m-%d")
    established = any(d.get("kind") == "network" and d.get("max_day_uses", 0) >= ESTABLISHED_USES
                      for d in seen.values())
    pattern_break = False
    for kind, label in destinations:
        ident = f"{kind}:{label}"
        d = seen.get(ident)
        if d is None:
            if kind == "network" and established:
                pattern_break = True
            if len(seen) >= MAX_PER_SECRET:
                del seen[min(seen, key=lambda i: seen[i]["last"])]     # the oldest goes
            d = seen[ident] = {"kind": kind, "label": label, "uses": 0, "first": now, "last": now,
                               "day": today, "day_uses": 0, "max_day_uses": 0}
        if d.get("day") != today:
            d["day"], d["day_uses"] = today, 0
        d["uses"] += 1
        d["day_uses"] += 1
        d["max_day_uses"] = max(d.get("max_day_uses", 0), d["day_uses"])
        d["last"] = now
    return pattern_break


def mark_interactive(session: str) -> None:
    """The person typed a prompt in this session: a hint here has a reader (a headless run has none)."""
    try:
        with _LOCK:
            data = _load_for_write()
            if session in data["interactive"]:
                return
            data["interactive"] = (data["interactive"] + [session])[-_MAX_SESSIONS:]
            _save(data)
    except (OSError, LockTimeout, ValueError, RecursionError):
        pass


def take_pending(session: str | None) -> bool:
    """A pattern break of this session waits for its hint; take it (once)."""
    if not session:
        return False
    try:
        with _LOCK:
            data = _load_for_write()
            if data["pending_hint"].pop(session, None) is None:
                return False
            _save(data)
            return True
    except (OSError, LockTimeout, ValueError):
        return False


def of_strict(key: str) -> dict | None:
    """The record of a key, or None; raises when the record cannot be read (protect fails closed)."""
    return _load(strict=True)["secrets"].get(key)


def of(key: str) -> dict:
    return _load()["secrets"].get(key, {"seen": {}, "allowed": {}})


def summary() -> tuple[int, int, int]:
    """(secrets with a network destination, network destinations, secrets with more than one)."""
    secrets = _load()["secrets"]
    counts = [sum(1 for d in r.get("seen", {}).values() if d.get("kind") == "network") for r in secrets.values()]
    counts = [c for c in counts if c]
    return len(counts), sum(counts), sum(1 for c in counts if c > 1)


def new_hosts(keys: list[str], found: list[tuple[str, str, bool]]) -> list[str]:
    """The network destinations of a call that ask under protect (found: exact_destinations). A key that never had a
    call that ran, and that no other call claimed, asks nothing: the destinations of its first call are its own, and
    this call claims that first call under the lock, so a parallel call of the same key asks. The claim holds while
    the call pends (until it ran, at most PENDING_SECONDS); a claim that no pending call carries (the call was refused
    after the check) ends after CLAIM_SECONDS. A key keeps its record while any destination
    is in it, so local uses that push its network entries out do not make it new. After that, a network destination
    asks when
    the key was never `seen` at it, or when its label does not name it exactly. A call the person allowed becomes
    `seen` when it ran (commit), so the next call to that destination asks nothing. Raises when the record cannot
    be read, or when it does not hold what its file holds for a key of this call: the caller asks for every network
    destination (fail closed)."""
    network = [(label, exact) for kind, label, exact in found if kind == "network"]
    with _LOCK:            # also for a local call: it is a first call too, and claims it (codex review of protect)
        data = _load(strict=True)
        raw = json.loads(_path().read_text(encoding="utf-8")) if _path().exists() else {}
        # what cleaning dropped for a key of this call, or of the claims, is damage: a null record must not read as
        # a first call (codex review of protect)
        secrets, claims = raw.get("secrets", {}), raw.get("claims", {})
        if not isinstance(secrets, dict) or not isinstance(claims, dict):
            raise Corrupt(STORE)
        now = time.time()
        pending = raw.get("pending_calls", {})
        if not isinstance(pending, dict):
            raise Corrupt(STORE)
        dropped = [c for i, c in pending.items() if i not in data["pending_calls"]]
        for key in keys:
            if key in claims and (claims[key] != data["claims"].get(key) or claims[key] > now + 5):
                raise Corrupt(STORE)        # a claim from the future is damage too (codex review of protect)
            if any(not isinstance(c, dict) or not isinstance(c.get("keys"), list) or key in c["keys"]
                   for c in dropped):
                raise Corrupt(STORE)        # a pending call of this key that cleaning dropped
            if key in secrets and (key not in data["secrets"] or json.dumps(secrets[key], sort_keys=True)
                                   != json.dumps(data["secrets"][key], sort_keys=True)):
                raise Corrupt(STORE)
        new: list[str] = []
        claimed = []
        for key in dict.fromkeys(keys):
            rec = data["secrets"].get(key)
            claim = data["claims"].get(key)
            in_flight = (claim is not None and 0 <= now - claim < CLAIM_SECONDS) or any(
                key in c["keys"] and now - c["t"] < PENDING_SECONDS for c in data["pending_calls"].values())
            if rec is None and not in_flight:
                claimed.append(key)                # its first call: its own destinations
                continue
            seen = {d["label"] for d in (rec or {}).get("seen", {}).values() if d.get("kind") == "network"}
            new += [label for label, exact in network if not exact or label not in seen]
        if claimed:
            for key in claimed:
                data["claims"][key] = now
            _save(data)
    return list(dict.fromkeys(new))


ASK_DAYS = 30


def would_have_asked(days: int = ASK_DAYS, now: float | None = None) -> tuple[int, int, int]:
    """(questions, secrets, days covered): how often a protect mode would have asked in the last `days` days. It
    asks when a secret goes to a network host it never went to; the hosts of a secret's first call (local or not) are
    its own, so a new secret asks nothing. One call is one question, also with two new hosts (a call notes all its
    destinations at one time). The days covered end at the oldest record: the record begins with its first use, not
    with the install. A label that does not name its host exactly asks each time under protect and is counted once
    here."""
    now = time.time() if now is None else now
    since = now - days * 86400
    questions, asked, oldest = 0, 0, now
    for rec in _load()["secrets"].values():
        seen = rec.get("seen", {}).values()
        oldest = min([oldest] + [d["first"] for d in seen])     # a local use is recorded too: it counts as covered
        begun = min([d["first"] for d in seen] or [now])     # its first call, local or not
        firsts = {d["first"] for d in seen if d.get("kind") == "network"}
        n = sum(1 for t in firsts if t > begun and t >= since)
        questions += n
        asked += 1 if n else 0
    return questions, asked, min(days, int((now - oldest) // 86400) + 1) if oldest < now else 0


NEW_SECONDS = 24 * 3600   # `new` in the list: first seen in the last day. Not "since the list was opened": the
                          # model runs the list too (commands/list.md), and a list it ran would clear the marks (Opus)


def uses_text(n: int) -> str:
    return "1×" if n <= 1 else "2–9×" if n < 10 else "10+×"


def when_text(ts: float, now: float | None = None) -> str:
    age = max(0.0, (now or time.time()) - ts)
    if age < 3600:
        return "less than an hour ago"
    if age < 86400:
        return f"{int(age // 3600)} hours ago" if age >= 7200 else "1 hour ago"
    days = int(age // 86400)
    return "1 day ago" if days == 1 else f"{days} days ago"


def forget(keys: list[str]) -> bool:
    """Drop the records of these keys. False when the record could not be written: the caller says so."""
    try:
        with _LOCK:
            data = _load_for_write()
            for k in keys:
                data["secrets"].pop(k, None)
                data["claims"].pop(k, None)
            gone = set(keys)
            for i, c in list(data["pending_calls"].items()):      # a call that did not yet run names the key too
                c["keys"] = [k for k in c["keys"] if k not in gone]
                if not c["keys"]:
                    del data["pending_calls"][i]
            _save(data)
            return True
    except (OSError, LockTimeout, ValueError):
        return False


def wipe() -> bool:
    """Delete the whole record under its lock (a writer that holds it would write it back after an unlink)."""
    try:
        with _LOCK:
            for p in [_path(), *HOME.glob(STORE + ".corrupt*")]:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
            return True
    except (OSError, LockTimeout):
        return False
