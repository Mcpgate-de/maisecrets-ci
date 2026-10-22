"""Experimental, never imported by maisecrets: the PERSON layer inside the real hook path (docs/NER-EXPERIMENT.md,
"The hook path"). `install()` wraps the detector's `scan` (maisecrets.detect is the same module object), so every hook
that redacts a tool result runs the deterministic scan first and then asks the local service of bench/ner/sidecar.py
within a time budget. What the wrapper promises, and bench/ner/hook_experiment.py proves:

- the deterministic findings come first and are returned as they are; a PERSON span is added only where none lies;
- a slow service (over the budget), a dead one, a refused connection or an answer it cannot read: the deterministic
  findings alone, as without the layer;
- installed but switched off: the hooks answer byte for byte as without it.

Only the tool channel (a tool result, a file): a typed prompt keeps today's path."""
from __future__ import annotations

import json
import socket
import time

from maisecrets.detection import core

STATE = {"active": False, "socket": "", "budget_s": 0.3, "calls": 0, "asked": 0, "added": 0, "timeouts": 0,
         "errors": 0, "ner_s": []}
_ORIGINAL = core.scan


def begin_call() -> None:
    """One hook call starts: all of its scans share one budget (a tool result of several strings scans each, and a
    budget per scan let one call wait 1.6 s against a budget of 0.3 s, 2026-10-21)."""
    STATE["call_deadline"] = time.monotonic() + STATE["budget_s"]


def _ask(text: str, occupied: list) -> list:
    deadline = min(time.monotonic() + STATE["budget_s"], STATE.get("call_deadline") or float("inf"))
    if deadline <= time.monotonic():
        raise TimeoutError
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(max(0.001, deadline - time.monotonic()))
        s.connect(STATE["socket"])
        s.sendall((json.dumps({"text": text, "occupied": occupied}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError
            s.settimeout(left)
            chunk = s.recv(65536)
            if not chunk:
                raise ConnectionError
            buf += chunk
        return json.loads(buf)["add"]
    finally:
        s.close()


def layered_scan(text, enabled=None, channel="prompt", path="", rule_list=None):
    found = _ORIGINAL(text, enabled, channel, path, rule_list)          # deterministic first, always
    if not STATE["active"] or channel != "tool" or rule_list is not None or enabled is not None or not text:
        return found
    STATE["calls"] += 1
    occupied = [[m.start, m.end, m.type] for m in found]
    t = time.monotonic()
    try:
        STATE["asked"] += 1
        add = _ask(text, occupied)
    except (TimeoutError, socket.timeout):
        STATE["timeouts"] += 1
        return found
    except Exception:                  # a dead service, a refused socket, an answer it cannot read: no word of it
        STATE["errors"] += 1
        return found
    finally:
        STATE["ner_s"].append(time.monotonic() - t)
    extra = []
    try:
        for s, e, _score in add:
            s, e = int(s), int(e)
            if 0 <= s < e <= len(text) and not any(s < m.end and m.start < e for m in found) and \
                    not any(s < x.end and x.start < e for x in extra):
                extra.append(core.Match("ner-person", "NAME", text[s:e], s, e))
    except Exception:
        STATE["errors"] += 1
        return found
    STATE["added"] += len(extra)
    return sorted(found + extra, key=lambda m: m.start) if extra else found


# the hook entry points that redact a tool result or a tool call; each is one hook call with one budget
HOOK_CALLS = ("user_prompt", "pre_tool", "post_tool", "post_tool_failure")
_WRAPPED: list = []          # (module, name, original) of each wrapped entry point


def _one_budget(fn):
    def call(*args, **kwargs):
        begin_call()
        try:
            return fn(*args, **kwargs)
        finally:
            STATE.pop("call_deadline", None)
    return call


def install(socket_path: str, budget_ms: int = 300, active: bool = True, hooks=None) -> None:
    """Wrap the detector's scan, and each hook entry point of `hooks` (maisecrets.hooks unless given) so that all scans
    of one hook call share one budget, without the caller's help."""
    STATE.update(active=active, socket=socket_path, budget_s=budget_ms / 1000, calls=0, asked=0, added=0, timeouts=0,
                 errors=0, ner_s=[])
    core.scan = layered_scan
    if hooks is None:
        from maisecrets import hooks
    for name in HOOK_CALLS:
        fn = getattr(hooks, name, None)
        if fn is not None and not any(m is hooks and n == name for m, n, _ in _WRAPPED):
            _WRAPPED.append((hooks, name, fn))
            setattr(hooks, name, _one_budget(fn))


def uninstall() -> None:
    core.scan = _ORIGINAL
    for hooks, name, fn in _WRAPPED:
        setattr(hooks, name, fn)
    _WRAPPED.clear()
