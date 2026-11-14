"""The PostToolUse answers that keep a tool result from the AI or name its unchecked names (#33). Out of hooks.py,
which the plugin directory caps at 200,000 bytes."""
from __future__ import annotations


def withheld(payload: dict, text: str, codex: bool) -> dict:
    """The PostToolUse answer that puts `text` in place of the tool output, in the shape each tool needs."""
    if codex:
        return {"decision": "block", "reason": text.strip("[]")}
    response = payload.get("tool_response")
    if payload.get("tool_name") == "Bash" and isinstance(response, dict) and response.get("isImage") is True:
        # an image of a Bash result: a string fails open here too; the client's Bash shape with isImage off removes
        # the image (measured live, review of block 4)
        return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": {
            **response, "stdout": text, "stderr": "", "isImage": False}}}
    if payload.get("tool_name") == "Read":
        # a string fails the shape check of Read and the client sends the original, a PDF or an image too (measured,
        # harness/probe_file_reads.py): only a text Read withholds it
        from .file_reads import text_result
        path = (payload.get("tool_input") or {}).get("file_path") if isinstance(payload.get("tool_input"), dict) else ""
        return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                       "updatedToolOutput": text_result(str(path or ""), text)}}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": text}}


def with_unchecked_names(payload: dict, result: dict, codex: bool, load_config) -> dict:
    """A tool result whose names the service of /maisecrets:ner did not check: a line on the person's screen each
    time (#33), and with `unavailable: withhold` the result kept from the AI. A text over the service's max_chars is
    named on the screen but not withheld: each long file would be."""
    from . import remote_layer as _rl
    if not _rl.NER_DOWN.get("unchecked"):
        return result
    why = str(_rl.NER_DOWN.get("why") or "")
    conf = _rl.conf_of(load_config())
    withhold = conf.get("unavailable") == "withhold" and _rl.NER_DOWN.get("state") == "unavailable"
    if withhold:
        _rl.NER_DOWN["v"] = False      # the note for the AI says the rules masked the result; none did here
    out = withheld(payload, _rl.withhold_text(why), codex) if withhold else dict(result or {})
    if not withhold and not codex:
        hso = dict(out.get("hookSpecificOutput") or {"hookEventName": "PostToolUse"})
        note = _rl.unchecked_context(why)
        hso["additionalContext"] = f"{hso['additionalContext']}\n\n{note}" if hso.get("additionalContext") else note
        out["hookSpecificOutput"] = hso
    line = _rl.screen_line(why, withhold)
    out["systemMessage"] = f"{out['systemMessage']} {line}" if out.get("systemMessage") else line
    return out
