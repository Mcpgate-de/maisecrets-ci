"""The Sensitive References a session received: maisecrets resolves a reference only when an MCP result of the same
session showed it, as it does for the tokens of a vault (vault_refs.note_result, C27).

A note is kept per profile, gateway origin and reference id (kind and id; the display part may change or go). It
holds the sessions that saw the reference in the last NOTE_TTL. A reference that the model itself sent to the gateway
in a call is never noted, then or later: a gateway that stores text and shows it again would give a planted reference
a sighting (the same rule as vault_refs SENT). Only an MCP server of the user's own configuration (user scope) counts.
"""
from __future__ import annotations

import json
import time

from . import sref_client
from .vault import HOME, _lock_for, atomic_write
from .vault_refs import MAX_NOTES_PER_ORIGIN, MAX_SESSIONS_PER_NOTE, NOTE_BUDGET, NOTE_TTL, _bounded, _read_json, \
    origin_of, profile, user_servers

DIR = HOME / "sref"
NOTES = DIR / "notes.json"            # profile -> origin -> "kind:id" -> {"t", "sessions": [ids], "url": MCP URL}
SENT = DIR / "sent.json"              # profile -> origin -> "kind:id" -> time: references the model sent in a call
HINTS = DIR / "hints.json"            # profile -> origin -> [session ids]: the sessions told that a login is missing


def _lock(deadline: float | None):
    return _bounded(_lock_for(DIR / ".lock"), deadline)


def ref_key(ref: str) -> str | None:
    """"kind:id" of a reference in any form, or None."""
    m = sref_client.SREF_RE.fullmatch(ref)
    return f"{m.group('kind')}:{m.group('id')}" if m else None


def _keys(node, into: set) -> None:
    if isinstance(node, str):
        if "sref:" in node:
            for m in sref_client.SREF_RE.finditer(node):
                into.add(f"{m.group('kind')}:{m.group('id')}")
    elif isinstance(node, list):
        for x in node:
            _keys(x, into)
    elif isinstance(node, dict):
        for x in node.values():
            _keys(x, into)


def note_result(payload: dict, deadline: float | None = None) -> int:
    """PostToolUse of an MCP tool: note each reference of the result for this session. Returns the number noted."""
    tool = str(payload.get("tool_name") or "")
    server = payload.get("mcp_server") if isinstance(payload.get("mcp_server"), dict) else {}
    if not tool.startswith("mcp__") or server.get("source") != "user" or not isinstance(server.get("name"), str):
        return 0
    found: set = set()
    asked: set = set()
    _keys(payload.get("tool_response"), found)
    _keys(payload.get("tool_input"), asked)     # sent now: filtered below by the sent list, as later ones
    session = payload.get("session_id")
    url = user_servers().get(server["name"])
    origin = origin_of(url)
    if not (found or asked) or not origin or not isinstance(session, str) or not session:
        return 0
    now = time.time()
    deadline = deadline if deadline is not None else time.monotonic() + NOTE_BUDGET
    with _lock(deadline):
        sent_all = _read_json(SENT) or {}
        sent = sent_all.setdefault(profile(), {}).setdefault(origin, {})
        stale = [k for k, t in sent.items() if not (isinstance(t, (int, float)) and t > now - NOTE_TTL)]
        for k in stale:
            del sent[k]
        for k in asked:
            sent.pop(k, None)
            sent[k] = now
        while len(sent) > MAX_NOTES_PER_ORIGIN:
            del sent[next(iter(sent))]
        if asked or stale:
            DIR.mkdir(parents=True, exist_ok=True)
            atomic_write(SENT, json.dumps(sent_all, indent=1))
        found = {k for k in found if k not in sent}
        if not found:
            return 0
        data = _read_json(NOTES) or {}
        mine = data.setdefault(profile(), {}).setdefault(origin, {})
        for k in sorted(found):
            note = mine.pop(k, None)
            note = note if isinstance(note, dict) else {}
            sessions = [s for s in (note.get("sessions") or []) if isinstance(s, str) and s != session]
            mine[k] = {"t": now, "sessions": (sessions + [session])[-MAX_SESSIONS_PER_NOTE:], "url": url}
        for k in [k for k, n in mine.items() if not (isinstance(n, dict) and isinstance(n.get("t"), (int, float))
                                                     and n["t"] > now - NOTE_TTL)]:
            del mine[k]
        while len(mine) > MAX_NOTES_PER_ORIGIN:
            del mine[next(iter(mine))]
        DIR.mkdir(parents=True, exist_ok=True)
        atomic_write(NOTES, json.dumps(data, indent=1))
    return len(found)


def first_hint(origin: str, session: str | None, deadline: float | None = None) -> bool:
    """Whether this session has not yet been told that this gateway offers references without a login here; records
    that it is told now. Once per session and gateway: a hint on every result would be noise."""
    if not isinstance(session, str) or not session:
        return False
    deadline = deadline if deadline is not None else time.monotonic() + NOTE_BUDGET
    with _lock(deadline):
        data = _read_json(HINTS) or {}
        told = data.setdefault(profile(), {}).setdefault(origin, [])
        if not isinstance(told, list) or session in told:
            return False
        told.append(session)
        data[profile()][origin] = told[-MAX_SESSIONS_PER_NOTE:]
        DIR.mkdir(parents=True, exist_ok=True)
        atomic_write(HINTS, json.dumps(data, indent=1))
    return True


def noted(refs: list, session: str | None) -> dict:
    """reference -> (origin, MCP URL) of the gateway that noted it for this session in the last NOTE_TTL, for the
    references of `refs` that one did; any other reference stays text."""
    if not isinstance(session, str) or not session:
        return {}
    now = time.time()
    mine = (_read_json(NOTES) or {}).get(profile())
    out: dict = {}
    if not isinstance(mine, dict):
        return out
    for ref in refs:
        k = ref_key(ref)
        for origin, notes in mine.items():
            note = notes.get(k) if isinstance(notes, dict) and k else None
            if isinstance(note, dict) and isinstance(note.get("t"), (int, float)) and note["t"] > now - NOTE_TTL \
                    and session in (note.get("sessions") or []):
                out[ref] = (origin, note.get("url") if isinstance(note.get("url"), str) else "")
                break
    return out


def noted_elsewhere(refs: list, session: str | None) -> list:
    """The references of `refs` that this profile noted, but not for this session or not in the last NOTE_TTL: they
    get a reason. A reference never noted stays text."""
    here = noted(refs, session)
    mine = (_read_json(NOTES) or {}).get(profile())
    if not isinstance(mine, dict):
        return []
    return [r for r in refs if r not in here
            and any(isinstance(n, dict) and ref_key(r) in n for n in mine.values())]
