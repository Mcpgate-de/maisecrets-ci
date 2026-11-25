"""#107: the mod's rewrite of an MCP task's result that the client sent as a notification. The result is a server's
output, so each block's result goes through hooks.post_tool as the tool result of that MCP call: the tool channel of
the detector, the store's exact values (also the short and quiet ones), the invisible characters (C20). A prompt path
would miss what only the tool path masks (review of #107). The envelope stays as the client wrote it."""
from __future__ import annotations

import re

from .agent_reports import _NOTIFICATION_RE, _mcp_tool_name, mcp_tasks
from .placeholder import find_refs

_RESULT_RE = re.compile(r"\n<result>\n(?P<text>.*)\n</result>\Z", re.S)


def _masked(payload: dict, text: str, tool: str, transcript: str) -> str | None:
    """`text` as post_tool gives it to the model: the masked text, `text` when nothing changed, or None when its answer
    is no replaced text (the prompt hook then decides the whole prompt)."""
    from . import hooks
    ans = hooks.post_tool({"session_id": payload.get("session_id"), "prompt_id": "mod", "cwd": payload.get("cwd"),
                           "hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": {},
                           "tool_response": text, "transcript_path": transcript})
    if not ans:
        return text
    out = (ans.get("hookSpecificOutput") or {}).get("updatedToolOutput")
    return out if isinstance(out, str) and ans.get("decision") != "block" else None


def rewrite(payload: dict, session: str) -> dict:
    """The mod's answer for a notification prompt of origin `task-notification`: {"text", "count"} when every block
    proves itself as an MCP task of this session and post_tool masked something; {} otherwise."""
    from . import demo, hooks
    from .vault import Vault, load_config
    prompt = payload.get("prompt") or ""
    transcript = demo._find_transcript(session) or ""
    tasks = mcp_tasks(prompt, transcript)
    if not tasks:
        return {}
    parts, pos = [], 0
    for m, (_tid, name) in zip(_NOTIFICATION_RE.finditer(prompt), tasks):
        r = _RESULT_RE.search(m.group("body"))
        if r is None:
            continue                        # no result: nothing of the server's in it
        tool = min(_mcp_tool_name(name))
        text = _masked(payload, r.group("text"), tool, transcript)
        if text is None:
            return {}
        a, b = m.start("body") + r.start("text"), m.start("body") + r.end("text")
        parts += [prompt[pos:a], text]
        pos = b
    parts.append(prompt[pos:])
    new = "".join(parts)
    if new == prompt:
        return {}
    cfg = load_config()
    keys = list(dict.fromkeys(k for k, _a, _b in find_refs(new)))
    before = {k for k, _a, _b in find_refs(prompt)}
    if cfg.get("scrub_transcript", True):
        # the client's own record of the notification keeps the text as it came (as for a prompt the mod rewrote)
        vault = Vault(cfg)
        values = [v for v in (vault.get(k, session=session)[0] for k in keys if k not in before) if v]
        if values:
            hooks._scrub_transcript_later("", values, [], session=session)
    return {"text": new, "count": len([k for k in keys if k not in before])}
