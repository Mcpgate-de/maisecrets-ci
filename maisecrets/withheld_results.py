"""#107: an MCP task's result that the prompt hook blocked (no mod) never reaches the model, and the model waits for
it. The next hook answer that reaches the model (a prompt that passes, a tool result) carries this note once
(hooks.main). A block's own additionalContext does not reach the model (measured on Claude Code 2.1.332)."""
from __future__ import annotations

import json
import os
import time

from . import incidents
from .hooks import _SESSION_ID_RE, client_of

SECONDS = 3600


def path_of(session: str):
    from .vault import HOME
    return HOME / "withheld" / f"{session}.json"


def note(session: str | None, tasks: list | None) -> None:
    """Keep the note for the next answer that reaches the model; nothing without a proven task."""
    if not tasks or not session or not _SESSION_ID_RE.fullmatch(session):
        return
    try:
        p = path_of(session)
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"at": time.time(), "tasks": tasks}, f)
    except OSError as exc:
        incidents.note("prompt.withheld", exc)


def take(session: str | None) -> str | None:
    """The note for the model on the MCP results the hook withheld in this session, once; None without one."""
    if not session or not _SESSION_ID_RE.fullmatch(session):
        return None
    p = path_of(session)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        p.unlink()
    except (OSError, ValueError):
        return None
    try:
        tasks = data["tasks"] if time.time() - float(data["at"]) <= SECONDS else None
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(tasks, list) or not tasks:
        return None
    try:
        named = ", ".join(f"task {t} ({n})" for t, n in tasks[:4] if isinstance(t, str) and isinstance(n, str))
    except (TypeError, ValueError):
        return None                        # a damaged file
    return (f"maisecrets: the result of the MCP call that went to the background ({named}) held a value (a secret "
            "or personal data), so maisecrets blocked it and it did not reach you. Do not wait for it. The user can "
            "send it with placeholders: /maisecrets send. Or make the call again from a subagent (the Agent tool), "
            "where it runs in the foreground and maisecrets masks its result; first check whether the call already "
            "did its work.")


def with_note(event: str, payload: dict, obj: dict) -> dict:
    """`obj` with the withheld note (take) as additionalContext, when it is an answer that reaches the model:
    a prompt that passes, or a tool result. Claude Code only."""
    if event not in ("user-prompt", "post-tool") or client_of(payload) != "claude" or obj.get("decision") == "block":
        return obj
    if payload.get("agent_id"):
        return obj          # a subagent's call: its answer reaches the subagent, not the model that waits
    name = "UserPromptSubmit" if event == "user-prompt" else "PostToolUse"
    hso = obj.get("hookSpecificOutput")
    if hso is not None and (not isinstance(hso, dict) or hso.get("hookEventName") != name):
        return obj
    note = take(payload.get("session_id"))
    if note is None:
        return obj
    hso = dict(hso or {"hookEventName": name})
    hso["additionalContext"] = f"{hso['additionalContext']}\n\n{note}" if hso.get("additionalContext") else note
    return {**obj, "hookSpecificOutput": hso}


def hits(prompt: str) -> list:
    """The values of a notification the prompt hook judges (no mod, or the mod failed or ran out of time): the prompt
    rules' findings and those of the tool channel, which a tool result gets (a password export, a card number alone).
    A tool finding counts where no prompt finding lies (review of #107, probe B)."""
    from . import detect
    found = list(detect.findings(prompt))
    for m in detect.findings(prompt, channel="tool"):
        if all(m.end <= f.start or m.start >= f.end for f in found):
            found.append(m)
    return sorted(found, key=lambda m: (m.start, m.end))


def hidden(prompt: str) -> bool:
    """Whether a notification holds invisible characters that PostToolUse would remove (C20)."""
    from .tool_output import strip_hidden
    from .vault import load_config
    return bool(load_config().get("strip_hidden_characters", True)) and strip_hidden(prompt)[1] > 0


def hidden_block(payload: dict) -> dict:
    out = {"decision": "block", "reason": "maisecrets kept a notification from the AI: it holds invisible characters "
           "(Unicode tag characters or variation selectors) that can hide instructions. It was not sent."}
    if client_of(payload) != "codex":
        out["hookSpecificOutput"] = {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}
    return out


def rewrite(payload: dict, session: str) -> dict:
    """The mod's rewrite of an MCP task's notification (mcp_task_results.rewrite); hooks.py reaches it here."""
    from .mcp_task_results import rewrite as mt_rewrite
    return mt_rewrite(payload, session)
