"""The PostToolUse answers that keep a tool result from the AI or name its unchecked names (#33). Out of hooks.py,
which the plugin directory caps at 200,000 bytes.

The unchecked rest of a result (#105, B9). With `unavailable: withhold`, a `partial` result (the pieces up to
`checked_to` were checked) does not pass its rest to the AI. remote_layer.prepare puts the short strings of a result
first in the joined text, so the strings of its shape (enums, MIME types, ids, urls, paths) lie in the first piece and
the rest is the end of a long text. The walk of hooks.post_tool calls `cut` for each string value: Layer.rest_of maps
`checked_to` to the offset in that string. The checked part goes on, masked as usual; the rest is replaced by one line
that names it (lines, or characters for a text without a line break before the cut) and tells the AI to fetch it again
in a narrower form. Every string keeps its place, so the result keeps its shape: Bash, Read, Grep, WebFetch, an Agent
or an MCP result and the texts of the mod's second net (maisecrets/second_net.py, the same number of texts) alike. The
cut never splits a finding, a placeholder or a stored value (Layer.held: the exact spans of the store).

Withheld whole instead, through `withheld` (it knows the Read and Bash shapes), never string by string: a result with
no checked part (a short text or a long one whose first piece got no answer), and a partial result whose rest would
touch a string without white space (Layer.whole): a cut there would break the shape, and the client then sends the
original. A source without pieces (the gateway until ai-gateway #2141) keeps `too_long` as before 0.9.29: a text over
max_chars is not cut and not withheld, and its line says so.

Not covered by the cut: a key of a JSON result keeps the rules alone (the client checks the keys of its shape: a Bash
result without `stderr` fails open), so a name in a key after the cut can reach the AI; the folder part of an Agent's
outputFile is redacted outside the cut (tool_output._keep; its head is no string of the join), so only Layer.whole
covers it when a rest would touch that path; the output of a failed command without the mod (PostToolUseFailure cannot
replace it); a resumed Codex session, which reads the raw output from its rollout. Without `withhold` (the default) the
rest keeps the rules and the share is named (`with_unchecked_names`)."""
from __future__ import annotations

FIRST = ("[maisecrets withheld {part} from the AI: the name service did not check it ({why}), and the person keeps "
         "such a part from you (/maisecrets ner unavailable withhold). The tool ran and finished. To see it, fetch "
         "{it} again in a narrower form: sed -n with a line range, Read with offset and limit, or the next page.]")
AGAIN = "[maisecrets withheld {part}: not checked by the name service]"


def cut(layer, s: str, found: list) -> tuple:
    """(the checked part of `s`, its findings, the line that stands for the rest), or (s, found, "") when no rest of
    `s` is withheld. The cut moves back to a line start, else after a space (a value seldom holds one), and before any
    finding, placeholder or stored value it would split: no half of a value stays visible."""
    r = layer.rest_of(s) if layer is not None else None
    if r is None:
        return s, found, ""
    if r:
        line = s.rfind("\n", 0, r)
        space = max(s.rfind(" ", 0, r), s.rfind("\t", 0, r))
        r = line + 1 if line >= 0 else (space + 1 if space >= 0 else r)
    moved = True
    while moved and r:
        moved = False
        for a, b in [(m.start, m.end) for m in found] + list(layer.held.get(s, ())):
            if a < r < b:
                r, moved = a, True
        ref = s.rfind("⟦", 0, r)
        if ref > s.rfind("⟧", 0, r):
            r, moved = ref, True
    from . import remote_layer as _rl
    if not r:
        part, it = "this text", "it"
    elif s[r - 1] == "\n":
        last = s.count("\n") + (0 if s.endswith("\n") else 1)
        part, it = f"lines {s.count(chr(10), 0, r) + 1} to {last} of this text", "those lines"
    else:
        part, it = f"characters {r + 1} to {len(s)} of this text", "that part"
    first = not _rl.NER_DOWN.get("cut")
    _rl.NER_DOWN["cut"] = int(_rl.NER_DOWN.get("cut") or 0) + 1
    why = _rl._TOOL_WHY.get(str(_rl.NER_DOWN.get("why") or ""), "no usable answer")
    line = (FIRST.format(part=part, why=why, it=it) if first else AGAIN.format(part=part))
    head = s[:r]
    return head, [m for m in found if m.end <= r], ("\n" if head and not head.endswith("\n") else "") + line


def rest_only(payload: dict, new_response, codex: bool | None = None) -> dict:
    """The answer of post_tool for a result in which nothing was masked: {} unless the walk withheld a rest; then the
    walked result in place of the output (Codex: a block whose reason is the output)."""
    from . import remote_layer as _rl
    if not _rl.NER_DOWN.get("cut"):
        return {}
    if codex is None:
        from .hooks import client_of
        codex = client_of(payload) == "codex"
    if codex:
        import json
        text = new_response if isinstance(new_response, str) else json.dumps(new_response, ensure_ascii=False)
        return {"decision": "block",
                "reason": f"[maisecrets: the tool ran and finished; this is not an error.]\n\n{text}"}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": new_response}}


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


def with_unchecked_names(payload: dict, result: dict, codex: bool | None = None, load_config=None) -> dict:
    """A tool result whose names the service of /maisecrets ner did not check: a note for the AI each time, a line
    for the person once per session and cause (ner_health), and with `unavailable: withhold` the result kept from the
    AI. A result with an unchecked rest: with `withhold` the walk already withheld the rest (`cut`), else it keeps the
    rules; either way its line names the share."""
    from . import remote_layer as _rl
    if not _rl.NER_DOWN.get("unchecked"):
        return result
    if codex is None or load_config is None:     # hooks._post_tool_guarded_rest: this hook's client and setting
        from .hooks import client_of, load_config as _load
        codex = client_of(payload) == "codex" if codex is None else codex
        load_config = load_config or _load
    why = str(_rl.NER_DOWN.get("why") or "")
    conf = _rl.conf_of(load_config())
    cut_ = bool(_rl.NER_DOWN.get("cut"))
    # no answer (a short text, or a long one whose first piece failed), or a rest that would touch a string of the
    # result's shape (`whole`): the whole result, in the shape withheld() gives each tool
    whole = bool(_rl.NER_DOWN.get("whole"))
    withhold = conf.get("unavailable") == "withhold" and (_rl.NER_DOWN.get("state") == "unavailable" or whole)
    if withhold:
        _rl.NER_DOWN["v"] = False      # the note for the AI says the rules masked the result; none did here
    out = withheld(payload, _rl.withhold_text(why), codex) if withhold else dict(result or {})
    share = int(_rl.NER_DOWN.get("share") or 0)
    if not withhold:
        # Codex too: only additionalContext reaches its model, a systemMessage is a warning for the person
        # (docs/CLIENTS.md); next to a block's reason the output schema allows it
        hso = dict(out.get("hookSpecificOutput") or {"hookEventName": "PostToolUse"})
        note = _rl.cut_context(why, share) if cut_ else _rl.unchecked_context(why, share)
        hso["additionalContext"] = f"{hso['additionalContext']}\n\n{note}" if hso.get("additionalContext") else note
        out["hookSpecificOutput"] = hso
    lines = []
    if _rl.NER_DOWN.get("state") in ("too_long", "partial"):
        # this result alone is too long, or only a part of it was checked (#105): under each one, with the share
        lines.append(_rl.screen_line(why, True) if whole and withhold else _rl.screen_line(why, cut_, share))
    else:
        # a source that cannot be used: once per session with the cause and the step, again when the cause changes
        # (ner_health), withheld or not; the AI's note above still comes with each result. It replaces the
        # once-per-session note of remote_layer.hint, which named no step
        from . import ner_health
        _rl.NER_DOWN["v"] = False
        _rl.NER_DOWN.pop("not_ours", None)
        lines.append(ner_health.result_line(load_config(), payload, why, codex))
        if withhold:
            lines.append(_rl.screen_line(why, True))    # an act on this result: under each one
    line = " ".join(x for x in lines if x)
    if line:
        out["systemMessage"] = f"{out['systemMessage']} {line}" if out.get("systemMessage") else line
    return out
