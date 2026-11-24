"""The second net for a tool result (claude-mod/maisecrets-mod.mjs, `session.append` on the door `tool-result`).

In Claude Code a PostToolUse hook that fails does not withhold the output, and a failed command takes the
PostToolUseFailure path, whose answer cannot replace it. The mod sees each row before the client stores and sends it.

The mod decides from positive evidence only. While the settings hooks of a tool result run, the mod sets
MAISECRETS_MOD_NET to a random nonce of its process, and the tool-result hooks then end their additionalContext with a
marker line (mark_answers): `[maisecrets: result masked NONCE HASH]` when the answer replaces the output (HASH: of the
texts of that output, output_hash), else `[maisecrets: result checked NONCE]`, and only after the handler scanned a
result. The mod accepts the marker only as the last line of an entry, with its own nonce, and `masked` only when the
output that reaches it has the same hash; it takes the marker out, so it never reaches the model. A result without such
a marker goes to mask_result (`hooks/dispatch.py mod-result`).
"""
from __future__ import annotations

import hashlib
import os
import re

from .placeholder import KEY_RE

ENV = "MAISECRETS_MOD_NET"
_NONCE = re.compile(r"[0-9a-f]{32}")
_EVENTS = {"post-tool": "PostToolUse", "post-tool-failure": "PostToolUseFailure"}
_KEY = re.compile("\u27e6(" + KEY_RE + ")(?::[^\u27e7\n]{0,80})?\u27e7")
_AGENT = re.compile(r"[A-Za-z0-9_-]{1,64}")
# The mod waits RESULT_MS (20 s) for mask_result (claude-mod/maisecrets-mod.mjs). Inside it the name check of a tool
# result gets the window of a hook (remote_layer.tool_deadline: min(8 s, half the window), #105): without one, all
# pieces of a long text shared the wait of one piece and the text ended `partial` after the first. 16 s leaves 4 s for
# the Python start, the masking and the answer; the store calls end a second before the window (vault.hook_deadline)
WINDOW_S = 16.0


def _texts_of(node, out: list) -> list:
    """The strings of an output in a fixed order (an object's keys sorted, each key before its value); numbers and the
    rest are left out, because JSON gives them no single written form in both languages."""
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, list):
        for x in node:
            _texts_of(x, out)
    elif isinstance(node, dict):
        for k in sorted(node, key=str):
            out.append(str(k))
            _texts_of(node[k], out)
    return out


def output_hash(output) -> str:
    """The first 16 hex digits of the SHA-256 of an output's strings joined by NUL: the mod computes the same."""
    return hashlib.sha256("\0".join(_texts_of(output, [])).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def band() -> dict | None:
    """The rest of the name check of this process's result for the mod's band (#105, B11): {"share", "mode"}, or None.
    The share and the mode only, never a text of the result."""
    from . import remote_layer
    b = remote_layer.NER_DOWN.get("band")
    return {"share": int(b[0]), "mode": str(b[1])} if b else None


def _rest() -> str:
    """` rest SHARE MODE` for the marker when the name check left a rest, else ""."""
    try:
        b = band()
    except Exception:  # noqa: BLE001 - no band; the marker stands
        return ""
    return f" rest {b['share']} {b['mode']}" if b else ""


def mark(obj: dict, event: str, nonce: str) -> dict:
    """The answer of a tool-result hook with the marker line of maisecrets at the end of its additionalContext. A Codex
    answer (a decision) and an event that is no tool-result event stay as they are. Holds no value."""
    name = _EVENTS.get(event)
    if not name or not isinstance(obj, dict) or "decision" in obj:
        return obj
    hso = dict(obj.get("hookSpecificOutput") or {})
    hso["hookEventName"] = name
    key = next((k for k in ("updatedToolOutput", "updatedMCPToolOutput") if k in hso), None)
    rest = _rest() if event == "post-tool" else ""
    tag = (f"[maisecrets: result masked {nonce} {output_hash(hso[key])}{rest}]" if key
           else f"[maisecrets: result checked {nonce}{rest}]")
    ctx = hso.get("additionalContext")
    hso["additionalContext"] = f"{ctx}\n\n{tag}" if isinstance(ctx, str) and ctx else tag
    return {**obj, "hookSpecificOutput": hso}


def mark_answers(hooks_module, event: str) -> None:
    """Every answer this hook process writes after its handler scanned a result (the handler's, the watchdog's, a
    crash's) carries the marker: they all go out through hooks._out. Only when the mod gave its nonce (ENV): without the
    mod the text would reach the model. A payload with no result to scan gets no marker, so the mod masks it."""
    nonce = os.environ.get(ENV) or ""
    if not _NONCE.fullmatch(nonce) or event not in _EVENTS:
        return
    scanned = {"v": False}
    name = "post_tool" if event == "post-tool" else "post_tool_failure"
    handler = getattr(hooks_module, name)

    def watched(payload, *args, **kwargs):
        if isinstance(payload, dict) and (payload.get("tool_response") is not None if event == "post-tool" else
                                          isinstance(payload.get("error"), str) and payload.get("error")):
            scanned["v"] = True
        return handler(payload, *args, **kwargs)
    setattr(hooks_module, name, watched)
    write = hooks_module._out
    hooks_module._out = lambda obj: write(mark(obj, event, nonce) if scanned["v"] else obj)


def _keys(text: str) -> set:
    return {m.group(1) for m in _KEY.finditer(text)}


def mask_result(payload: dict) -> dict:
    """The texts of a result that no tool-result hook of maisecrets marked, masked as hooks.post_tool masks them, with
    the note on unchecked names that post_tool's hook adds. Answers {"texts": [...], "changed": bool, "note": str},
    the texts in the same order, or {"withheld": True} when the name setting withholds an unchecked result. Raises on
    any failure: the mod then withholds the result. Writes no row: hooks.log counts hook runs, and this is none."""
    texts = payload.get("texts")
    if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
        raise ValueError("texts")
    session = payload.get("session_id") if isinstance(payload.get("session_id"), str) else None
    from . import detect, hooks, vault_refs
    from .home import regions_from_config
    from .placeholder import REFERENCES
    from .sources import PLUGIN_SOURCES
    from .tool_withhold import with_unchecked_names
    from .vault import load_config
    detect.use_regions(regions_from_config)
    detect.use_sources(PLUGIN_SOURCES)
    detect.use_references(REFERENCES)
    vault_refs.use_client("claude")
    # the shape of a Claude Code payload (prompt_id): the answer is Claude's updatedToolOutput. No file path, so a
    # value in a test file is masked here, where post_tool may keep it as a fixture
    tool = str(payload.get("tool_name") or "tool")[:80]
    hook_payload = {"hook_event_name": "PostToolUse", "prompt_id": "mod", "session_id": session,
                    "cwd": str(payload.get("cwd") or ""), "tool_name": tool, "tool_input": {},
                    "tool_response": list(texts)}
    from .vault import hook_deadline
    hook_deadline(WINDOW_S)
    from .remote_layer import NER_DOWN
    NER_DOWN["band"] = None               # the band of this result only
    try:                                  # the window holds until the answer: the store calls of the scrub too
        out = hooks.post_tool(hook_payload)
        out = with_unchecked_names(hook_payload, out if isinstance(out, dict) else {}, False, load_config)
        hso = out.get("hookSpecificOutput") or {}
        new = hso.get("updatedToolOutput")
        note = hso.get("additionalContext") if isinstance(hso.get("additionalContext"), str) else ""
        rest = band()                     # the mod's band: the share and the mode, no text (#105, B11)
        extra = {"rest": rest} if rest else {}
        if new is None:
            return {"texts": texts, "changed": False, "note": note, **extra}
        if isinstance(new, str):
            return {"withheld": True, **extra}     # with_unchecked_names withheld it: one text in place of the result
        if not isinstance(new, list) or len(new) != len(texts) or not all(isinstance(t, str) for t in new):
            raise ValueError("answer")
        _scrub_later(texts, new, session, payload.get("agent_id"))
        return {"texts": new, "changed": new != texts, "note": note, **extra}
    finally:
        hook_deadline(None)


def _scrub_later(texts: list, new: list, session: str | None, agent) -> None:
    """The client keeps the tool's own record of the result (toolUseResult) as the tool made it, and writes the row
    after this answer: a detached child masks the values of the new placeholders in the transcript of this session,
    found by its id, and for a subagent's result in that subagent's transcript (<session>/subagents/agent-<id>.jsonl).
    The values come from the store by the keys the masking put in. Never raises."""
    try:
        from .vault import Vault, load_config
        cfg = load_config()
        if not cfg.get("scrub_transcript", True):
            return
        keys = set().union(*(_keys(t) for t in new)) - set().union(*(_keys(t) for t in texts))
        vault = Vault(cfg)
        values = [v for v in (vault.backend.get(k) for k in sorted(keys)) if v]
        if not values:
            return
        from .hooks import _SESSION_ID_RE, _scrub_transcript_later
        _scrub_transcript_later("", values, [], session=session)
        if isinstance(agent, str) and _AGENT.fullmatch(agent) and session and _SESSION_ID_RE.fullmatch(session):
            from pathlib import Path
            base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "projects"
            name = agent if agent.startswith("agent-") else "agent-" + agent
            for path in base.glob(f"*/{session}/subagents/{name}.jsonl"):
                _scrub_transcript_later(str(path), values, [])
    except Exception:  # noqa: BLE001 - the answer stands; the scrub is the transcript's, not the model's
        pass
