"""/maisecrets:demo on|off (Codex: `maisecrets: demo on|off`): the person tries maisecrets with real data before any of
it reaches the AI. While the demo is on in a session, maisecrets answers each prompt of that session itself: the
prompt as the AI would get it (with placeholders), the count per type, and the step that ends the demo. No prompt
reaches the model: the prompt hook blocks it, and in Claude Code the mod drops it.

A demo prompt takes the normal path of a prompt: its values are stored in the vault as when the person sends it, so
the placeholders are the normal ones and the screen can show their values (show_values). Only the sending is replaced
by the answer. No blocked prompt is kept for /maisecrets:send, so /ms during the demo sends nothing.

Only the person's typed prompt switches it, as a setting (C22): a subagent, a program (`claude -p`, the Agent SDKs), a
scheduled prompt, another session or a tool call changes nothing. The state lives in the maisecrets home (STATE), for
one session: it ends with `off` or with the end of that session (SessionEnd), and it holds a session id and a time,
never a prompt. The only extra record is one events.log line for each switch (events.record_demo).

During the demo only the exact forms of the person's own maisecrets commands pass (_OWN_RE); a subagent's report that
proves itself passes before this gate (C19), and a message of another session only when the client says it did not
come from the person.
"""
from __future__ import annotations

import contextlib
import json
import math
import re
import time

from .home import HOME, atomic_write
from .lazy_regex import LazyRx as _LazyRx      # compiled at first use: a hook imports this module on every call

STATE = HOME / "demo.json"          # session id -> the time the demo began; no prompt, no value
SHOWN_LINES = 20                    # the lines of the masked prompt in the answer; the clipboard gets all of it
SHOWN_CHARS = 4000                  # and at most this many characters of them: a block reason is no file

# the whole prompt, nothing else: the command and one word
_CMD_RE = _LazyRx(r"\A\s*(?:/maisecrets:demo|maisecrets:[ \t]*demo)(?:[ \t]+(?P<arg>[^\r\n]*?))?\s*\Z", re.I)
# the same command in a tool call: a nested client would type it for the model, and the writer called by name would
# skip the prompt. A text match (the C22 class): a form built at run time is not seen
IN_A_COMMAND_RE = _LazyRx(r"/maisecrets:demo\b|maisecrets:\s*demo\b|\bswitch_typed\b", re.I)
IN_A_COMMAND = ("maisecrets: this command carries /maisecrets:demo; only the person switches the demo, as their own "
                "prompt. The command did not run. Tell the user the prompt to send.")
_KEY = r"(?:⟦)?[A-Z][A-Z0-9_]*_c\d+(?:⟧)?"
# the person's own maisecrets commands that pass the demo, in their exact forms only: a command name of commands/*.md
# (and the skill) with no argument or one of its own arguments. A slash command whose arguments are free text would
# reach the model with them, and the client sends an unknown plugin command as plain text (Gate A of #57).
# /maisecrets:send and /ms are not here: during the demo they get the demo answer and send nothing. The settings, term,
# not-a-secret, forget import and demo commands are answered before the gate
FORMS = {"status": r"all|test", "list": "", "audit": r"\d{1,4}", "rules": "",
         "report": r"last|incident(?:[ \t]+[\w./-]{1,80})?", "ner": "",
         "sref": r"status|(?:login|logout)(?:[ \t]+[\w.-]{1,64})?",
         "put": "", "forget": _KEY + r"(?:[ \t]+" + _KEY + r")*", "guard": r"install|remove|status",
         "shortcut": r"--remove|[a-z][a-z0-9-]{0,30}", "settings": r"--all", "term": "", "secret-hygiene": ""}
NOT_PASSED = ("send", "not-a-secret", "demo")      # commands/*.md names that FORMS leaves out on purpose
_OWN_RE = _LazyRx(r"\A\s*(?:/maisecrets:|maisecrets:[ \t]*)(?:" + "|".join(
    re.escape(name) + (rf"(?:[ \t]+(?:{args}))?" if args else "") for name, args in FORMS.items()) + r")\s*\Z")


def parse(prompt) -> str | None:
    """"on", "off" or "show" (no word, or another word) for a demo prompt; None for any other prompt."""
    if not isinstance(prompt, str) or "demo" not in prompt.lower():
        return None
    m = _CMD_RE.match(prompt)
    if not m:
        return None
    arg = (m.group("arg") or "").strip().lower()
    return arg if arg in ("on", "off") else "show"


def in_a_command(command: str) -> bool:
    """Whether a tool call's command text carries the command or names its writer: as written, or with the quotes,
    escapes and line continuations a shell takes out (value_files._JOINED_FORMS)."""
    from .value_files import _JOINED_FORMS
    return bool(IN_A_COMMAND_RE.search(command)
                or any(IN_A_COMMAND_RE.search(form.sub("", command)) for form in _JOINED_FORMS))


def own_command(prompt: str) -> bool:
    return bool(_OWN_RE.match(prompt))


# ------------------------------------------------------------ the state --
class Damaged(Exception):
    """demo.json is there but cannot be read, or holds something other than session id -> time."""


DAMAGED = ("maisecrets demo: the demo state cannot be read, so nothing was sent. {off} resets it.")


def _read() -> dict:
    """The sessions in the demo. Only a missing file means none: a file that cannot be read or parsed, or one of
    another shape, raises Damaged, and the gate then blocks the prompt of every session (fail closed, Gate A round 2
    of #57). A valid file written by another process is the limit of C8 and C22."""
    try:
        text = _text()
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise Damaged(type(exc).__name__) from exc
    try:
        data = json.loads(text, parse_constant=_no_constant)     # NaN, Infinity and -Infinity are no time
    except ValueError as exc:
        raise Damaged("json") from exc
    if not isinstance(data, dict) or not all(_session_ok(k) and _time_ok(v) for k, v in data.items()):
        raise Damaged("shape")
    return data


SESSION_CHARS = 128          # a session id of Claude Code and a thread id of Codex have 36


def _no_constant(name: str):
    raise ValueError(f"the constant {name} is no time")


def _session_ok(key) -> bool:
    return isinstance(key, str) and 0 < len(key) <= SESSION_CHARS


def _time_ok(value) -> bool:
    """A finite time after 1970: an int or a float, never a bool, never 0 or below."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def _text() -> str:
    return STATE.read_text(encoding="utf-8")


def damaged() -> bool:
    try:
        _read()
    except Damaged:
        return True
    return False


def active(session) -> bool:
    """The session is in the demo; with a damaged state every session counts as in it."""
    try:
        data = _read()
    except Damaged:
        return True
    return isinstance(session, str) and bool(session) and session in data


def active_in(sessions) -> bool:
    """active() for any of these session ids (/maisecrets:status gets a list)."""
    return any(active(s) for s in sessions or [])


def _lock():
    from .home import _lock_for
    return _lock_for(HOME / ".demo.lock")


def _write(data: dict) -> None:
    if data:
        atomic_write(STATE, json.dumps(data, indent=1))
    else:
        with contextlib.suppress(FileNotFoundError):
            STATE.unlink()


def end_session(session) -> None:
    """SessionEnd: the demo of this session ends with it."""
    if not isinstance(session, str) or not STATE.exists():
        return
    with _lock():
        try:
            data = _read()
        except Damaged:
            return              # it stays closed until the person types /maisecrets:demo off
        if data.pop(session, None) is not None:
            _write(data)


def switch_typed(verb: str, session: str, route: str, codex: bool) -> str:
    """Switch the demo of `session` on or off and write one events.log line. Only the prompt hook calls it, for the
    person's typed prompt."""
    with _lock():
        try:
            data, reset = _read(), False
        except Damaged:
            if verb != "off":
                # only off resets it: an `on` that wrote a valid state would let the prompts of every other
                # session through (Gate A round 5 of #57)
                return DAMAGED.format(off="maisecrets: demo off" if codex else "/maisecrets:demo off")
            data, reset = {}, True          # the person's off rewrites it: never locked out
        was = session in data
        if verb == "on":
            data[session] = data.get(session) or time.time()
        else:
            data.pop(session, None)
        _write(data)
    from . import events
    events.record_demo(verb, route)
    if verb == "on":
        return ("maisecrets demo is on in this session. Send any prompt: maisecrets answers with what it would mask "
                "and stores the values as for a sent prompt, and nothing reaches the AI. A new session or /clear "
                "ends the demo.\n" + _footer(codex))
    if reset:
        return ("maisecrets demo is off. Its state could not be read, so it was reset: the demo is off in every "
                "session, and your next prompts go to the AI again, with the values masked.")
    if not was:
        return "maisecrets demo was not on in this session. Your prompts go to the AI as before."
    return "maisecrets demo is off. Your next prompts go to the AI again, with the values masked."


def _footer(codex: bool) -> str:
    return f"{'maisecrets: demo off' if codex else '/maisecrets:demo off'} to send again"


def _block(reason: str, codex: bool) -> dict:
    if codex:
        return {"decision": "block", "reason": reason}
    return {"decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}


def answer(payload: dict, verb: str, typed: bool, codex: bool) -> dict:
    """The prompt hook's answer to the command: always a block, so the command never reaches the model. Only a typed
    prompt of the person changes something; any other says where it came from."""
    session = payload.get("session_id")
    if verb == "show":
        if damaged():
            return _block(DAMAGED.format(off="maisecrets: demo off" if codex else "/maisecrets:demo off"), codex)
        reason = (f"maisecrets demo is {'on' if active(session) else 'off'} in this session. /maisecrets:demo on "
                  "answers each prompt with what maisecrets would mask, and nothing reaches the AI; /maisecrets:demo "
                  "off ends it (Codex: maisecrets: demo on, maisecrets: demo off).")
    elif not typed:
        from .settings import came_from
        reason = ("maisecrets: /maisecrets:demo counts only when you type it as your prompt; this one came from "
                  f"{came_from(payload)}, so nothing was changed.")
    elif not isinstance(session, str) or not session:
        reason = "maisecrets: this prompt names no session, so the demo cannot be switched. Nothing was changed."
    else:
        route = "slash command" if str(payload.get("prompt", "")).lstrip().startswith("/") else "typed prompt"
        try:
            reason = switch_typed(verb, session, route, codex)
        except Exception as exc:  # noqa: BLE001 - the answer says it failed
            reason = f"maisecrets: the demo could not be switched ({type(exc).__name__}). Nothing was changed."
    return _block(reason, codex)


# ------------------------------------------------------------ the gate of the prompt hook --
def gate(payload: dict, cfg: dict, typed: bool) -> dict | None:
    """The prompt hook's step for the demo, after the subagent report pass and the person's own commands: the answer
    to /maisecrets:demo, the demo answer for a prompt of a session in the demo, or None."""
    prompt = payload.get("prompt")
    if not isinstance(prompt, str):
        # no text: an image alone gives "[Image #1]" in the terminal and "" in claude -p (measured on 2.1.325); a
        # missing field counts as an empty prompt, which the demo blocks too
        prompt, payload = "", {**payload, "prompt": ""}
    from .hooks import client_of
    codex = client_of(payload) == "codex"
    verb = parse(prompt)
    if verb:
        return answer(payload, verb, typed and not payload.get("agent_id"), codex)
    if not active(payload.get("session_id")):
        return None
    if damaged():
        # only the person's exact typed own commands pass a damaged state: no report, no message of another session
        if typed and not payload.get("agent_id") and own_command(prompt):
            return None
        return _block(DAMAGED.format(off="maisecrets: demo off" if codex else "/maisecrets:demo off"), codex)
    if passes(payload, prompt, typed and not payload.get("agent_id")):
        return None
    try:
        text = _hook_text(payload, cfg, typed and not payload.get("agent_id"), codex)
    except Exception as exc:  # noqa: BLE001 - a demo answer that fails must not let the prompt through
        text = f"maisecrets demo: nothing was sent to the AI. The answer could not be built ({type(exc).__name__})."
    return _block(text, codex)


def passes(payload: dict, prompt: str, typed: bool) -> bool:
    """A prompt the demo leaves to its own rules: the exact form of the person's own maisecrets command when the person
    typed it (a subagent, a program or a scheduled prompt could send the same words, Gate A of #57), or a message of
    another session that the client did not mark as the person's (a header the person types is the person's prompt).
    A subagent's report that proves itself has passed before the gate (C19); any other text with a report tag gets
    the demo answer."""
    from .settings import TYPED_SOURCES, peer_sender
    if typed and own_command(prompt):
        return True
    return peer_sender(prompt) is not None and payload.get("source") not in TYPED_SOURCES


def _hook_text(payload: dict, cfg: dict, typed: bool, codex: bool, one_line: bool = False) -> str:
    """The normal steps of hooks.user_prompt for a prompt (the {{name}} marker, the placeholders the person typed, the
    values taken out and stored, the transcript scrub, the events line), then the demo answer in place of the block
    notice. No blocked prompt is kept for /maisecrets:send."""
    from . import events, hooks, term_files
    from .placeholder import find_refs
    from .settings import peer_sender
    prompt = original = payload["prompt"]
    session = payload.get("session_id")
    if typed:
        with contextlib.suppress(OSError):
            prompt, _marked = term_files.take_markers(prompt, hooks._name_ttl(cfg))
    refs = find_refs(prompt)
    matches = hooks._prompt_hits(prompt)
    vault = None
    if refs or matches or hooks._has_live(cfg):
        vault = hooks.Vault(cfg)
        if peer_sender(prompt) is None and not payload.get("agent_id"):
            for key, _s, _e in refs:
                vault.admit(key, session)
    rewritten, entries, values, _stored, _m = hooks._take_values_out(prompt, matches, cfg, vault, session)
    if values and cfg.get("scrub_transcript", True):
        path = str(payload.get("transcript_path") or "")
        hooks._scrub_transcript(path, values, [e.ref for e in entries])
        # without a path (the mod's drop) the child finds the transcript by the session id, as the mod's rewrite does
        hooks._scrub_transcript_later(path, values, [e.ref for e in entries], session=session)
    events.record("UserPromptSubmit", hooks.client_of(payload), entries, outcome="demo")
    return render(original, rewritten, codex, one_line)


# ------------------------------------------------------------ the mod's step --
def mod_answer(payload: dict, cfg: dict) -> dict | None:
    """The mod's step (hooks.rewrite_prompt), for a session in the demo: {} for what the prompt hook answers or lets
    pass (the person's commands, a prompt of report blocks alone), else a drop with the demo answer after the mod's
    normal rewrite, which stores the values. None outside the demo, and inside that rewrite."""
    prompt = payload.get("prompt")
    if _INSIDE or not isinstance(prompt, str) or not active(payload.get("session_id")):
        return None
    typed = payload.get("origin") in ("composer", "bridge")      # `sdk`: claude -p, a program
    if parse(prompt) or (typed and own_command(prompt)) or _answered_by_the_hook(prompt):
        return {}
    if damaged():
        return {"drop": DAMAGED.format(off="/maisecrets:demo off")}     # before the report pass: none passes
    if _only_reports(prompt):
        return {}
    from . import hooks
    _INSIDE.append(1)
    try:
        out = hooks.rewrite_prompt(payload)
    finally:
        _INSIDE.pop()
    # one line: the client prints each line break of a drop as a replacement character, in `claude -p` (2.1.301) and
    # in the interactive client (2.1.325, measured with a pseudo-terminal), so a line break of the prompt is a ↵
    if isinstance(out.get("text"), str):
        return {"drop": render(prompt, out["text"], False, one_line=True)}
    # the rewrite left it to the prompt hook (nothing to rewrite, a mention, a report tag inside other text): the
    # hook's normal steps, and a drop all the same
    return {"drop": _hook_text({**payload, "transcript_path": ""}, cfg, typed, False, one_line=True)}


_INSIDE: list = []      # the mod's own rewrite runs inside mod_answer: its demo step steps aside


def _answered_by_the_hook(prompt: str) -> bool:
    """The person's commands that the prompt hook answers before its gate (rewrite_prompt leaves them to it too)."""
    from . import not_a_secret, settings, term_files, value_files
    from .hooks import _GRANT_RE
    return bool(term_files.parse_command(prompt) or value_files.parse_removal(prompt) or not_a_secret.parse(prompt)
                or settings.parse_prompt(prompt) or _GRANT_RE.match(prompt))


def _only_reports(prompt: str) -> bool:
    """One or more report blocks and nothing else: the prompt hook proves them (C19) or gives the demo answer."""
    from .agent_reports import _NOTIFICATION_RE
    return "<task-notification>" in prompt and not _NOTIFICATION_RE.sub("", prompt).strip()


# ------------------------------------------------------------ the answer --
def render(original: str, masked: str, codex: bool, one_line: bool = False) -> str:
    """What the person reads: the head, the count per type, the masked prompt (cut), the footer. The count is of the
    placeholders the rewrite put in; a placeholder the person typed is no finding. Placeholders only, never a value."""
    from .placeholder import find_refs
    typed = {k for k, _s, _e in find_refs(original)}
    types: dict = {}
    for key, _s, _e in find_refs(masked):
        if key not in typed and "_c" in key:
            t = key.rsplit("_c", 1)[0]
            types[t] = types.get(t, 0) + 1
    if types and masked != original:
        _copy(masked)
    head = ["maisecrets demo: nothing was sent to the AI.",
            ("It masks " + ", ".join(_count(t, n) for t, n in types.items()) + ".") if types
            else "It finds nothing to mask in this prompt."]
    shown, rest = _cut(masked)
    footer = _footer(codex)
    if one_line:
        return " ".join(head + ["«" + " ↵ ".join(shown.splitlines()) + "»"]
                        + ([rest] if rest else []) + [footer])
    return "\n".join(head + ["", shown] + ([rest] if rest else []) + ["", footer])


def _copy(text: str) -> bool:
    """The full masked text to the clipboard, as the block notice copies it (hooks._clipboard); only when the demo
    masked something, so a clean prompt leaves the clipboard as it was."""
    from . import hooks
    return bool(hooks._clipboard(text))


def _count(type_: str, n: int) -> str:
    from .notices import CLASS_WORDS, TYPE_WORDS
    words = TYPE_WORDS.get(type_)
    if words is None:
        from .detection.vocabulary import TYPES
        words = CLASS_WORDS.get((TYPES.get(type_) or {}).get("class", ""))
    if words is None:
        return f"{n} {'value' if n == 1 else 'values'} of the type {type_}"
    return f"{n} {words[0] if n == 1 else words[1]}"


def _cut(text: str) -> tuple:
    """(the first SHOWN_LINES lines, at most SHOWN_CHARS characters; the line that says what was left out, or "")."""
    lines = text.splitlines() or [""]
    shown = "\n".join(lines[:SHOWN_LINES])
    more = len(lines) - SHOWN_LINES
    if len(shown) > SHOWN_CHARS:
        cut = len(shown) - SHOWN_CHARS
        return shown[:SHOWN_CHARS], (f"… {cut} more characters" + (f" and {more} more lines" if more > 0 else ""))
    return shown, (f"… {more} more lines" if more > 0 else "")
