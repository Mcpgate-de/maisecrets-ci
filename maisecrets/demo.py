"""/maisecrets:demo on (Codex: `maisecrets: demo on`): the person tries maisecrets with real data, and nothing goes to
the AI. In a session in the demo each prompt takes the normal way of a prompt: maisecrets stores its values and puts
placeholders in place of them, and in Claude Code the mod lets the masked prompt enter, so the person's row shows as
on a sent prompt (show_values draws the values with a lock). No model request goes out: the mod answers each step of
the turn itself (`turn.step`, claude-mod/maisecrets-mod.mjs) with one line, DEMO_LINE. Where the mod did not let the
prompt enter (Codex, a client without mods, a mod that failed), the prompt hook blocks it with the same line.

Only the person's typed prompt switches it on, as a setting (C22): a subagent, a program (`claude -p`, the Agent
SDKs), a scheduled prompt, another session or a tool call changes nothing. It starts only in a session with no turn
yet (has_turns: the transcript holds no model answer), because the only way out is /clear, which starts a new session
and leaves this conversation behind. The demo rows stay in the session's transcript, so the demo does not end with
`off` and not with SessionEnd (a resumed session must stay in the demo, or its rows would go to the AI with the next
real request). The transcript is the lasting truth: a session whose last answer is the demo answer (DEMO_LINE, which
only the mod writes) is in the demo whatever demo.json says. STATE (the maisecrets home: a session id and a time,
never a prompt) carries it from `demo on` to the first demo answer. The only extra record is one events.log line for
each switch (events.record_demo).

A demo.json that cannot be read or has another shape blocks every session (fail closed) until the person types
/maisecrets:demo off, which resets it.
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
PASS_DIR = HOME / "demo-pass"       # session id -> the hash of the prompt the mod let enter; no prompt, no value
PASS_SECONDS = 120
DEMO_LINE = "Demo mode: nothing was sent to the AI. /clear to switch it off."
TITLE = "maisecrets demo"
DEMO_LINE_CODEX = "Demo mode: nothing was sent to the AI. A new session switches it off."
ON = "Demo mode is on: what you send stays here, nothing goes to the AI. /clear switches it off."
ON_CODEX = "Demo mode is on: what you send stays here, nothing goes to the AI. A new session switches it off."
OFF = "The demo ends with /clear: it starts a new conversation, so the demo lines do not go to the AI."
OFF_ALREADY = "Demo mode is off in this session. Nothing was changed."
OFF_CODEX = "The demo ends with a new session: the demo lines of this one do not go to the AI."
NOT_FIRST = "Start the demo in a new session (or after /clear), so this conversation stays as it is."
NOT_FIRST_CODEX = "Start the demo in a new session, so this conversation stays as it is."

# the whole prompt, nothing else: the command and one word
_CMD_RE = _LazyRx(r"\A\s*(?:/maisecrets:demo|maisecrets:[ \t]*demo)(?:[ \t]+(?P<arg>[^\r\n]*?))?\s*\Z", re.I)
# the same command in a tool call: a nested client would type it for the model, and the writer called by name would
# skip the prompt. A text match (the C22 class): a form built at run time is not seen
# and a call of the demo's writers or of the mod's questions: the module by name (maisecrets.demo, `from maisecrets
# import demo`, `import demo`), the pass writer, the dispatcher entries mod-demo and mod-prompt (Gate A, demo turn)
IN_A_COMMAND_RE = _LazyRx(r"/maisecrets:demo\b|maisecrets:\s*demo\b|\bswitch_typed\b|\b_write_pass\b|"
                          r"\bmaisecrets\s*\.\s*demo\b|\bfrom\s+maisecrets\s+import\b[^\n;]*\bdemo\b|"
                          r"\bimport\s+demo\b|\bmod-demo\b|\bmod-prompt\b", re.I)
IN_A_COMMAND = ("maisecrets: this command carries /maisecrets:demo or calls the demo's writers; only the person "
                "switches the demo, as their own prompt. The command did not run. Tell the user the prompt to send.")
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


DAMAGED = ("Demo mode: the demo state cannot be read, so nothing was sent. {off} resets it.")


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


def active(session, transcript: str | None = None) -> bool:
    """The session is in the demo: demo.json lists it (from `demo on` until its first demo answer), or its transcript
    holds a demo answer (has_demo_rows), which outlives any change of demo.json. With a damaged state every session
    counts as in it. `transcript`: the path the hook payload gives; without it the transcript is found by the id."""
    try:
        data = _read()
    except Damaged:
        return True
    if not isinstance(session, str) or not session:
        return False
    return session in data or has_demo_rows(session, transcript)


def _find_transcript(session: str) -> str | None:
    """Claude Code's transcript of `session`: projects/*/<id>.jsonl in its config folder, as the scrub child finds
    it (the mod gives no path)."""
    import glob
    import os
    from .hooks import _SESSION_ID_RE
    if not _SESSION_ID_RE.fullmatch(session):
        return None
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    found = glob.glob(os.path.join(glob.escape(base), "projects", "*", glob.escape(session) + ".jsonl"))
    return found[0] if found else None


def has_demo_rows(session: str, transcript: str | None = None) -> bool:
    """Whether the session is in the demo by its transcript: its last assistant text is DEMO_LINE, which only the mod
    writes (its answer to a model step). A demo session is left only with /clear, a new session id, so once it has a
    demo row no real answer can follow in it: the last answer tells. Only the tail is read (TAIL bytes, widened while
    it holds no answer). A transcript that exists but cannot be read counts as in the demo: it can hold demo rows, and
    its prompt would carry them to the AI (fail closed; /clear starts a new, empty one). No transcript: no demo row
    (Codex never has one: its demo prompts are blocked and never enter the history)."""
    import os
    path = transcript if isinstance(transcript, str) and transcript else _find_transcript(session)
    if not path:
        return False
    try:
        size = os.stat(path).st_size
        with open(path, "rb") as f:
            want = TAIL
            while True:
                start = max(0, size - want)
                f.seek(start)
                chunk = f.read(size - start)
                last = _last_answer(chunk if start == 0 else chunk[chunk.find(b"\n") + 1:])
                if last is not None or start == 0:
                    return last == ("mod", DEMO_LINE)
                want *= 4
    except FileNotFoundError:
        return False
    except OSError:
        return True


TAIL = 64 * 1024


def _last_answer(chunk: bytes) -> tuple | None:
    """(who, text) of the last assistant record with text in these whole lines (a record of tool calls alone has
    none), or None. who is "mod" for an answer a hook gave without a request, which the model cannot write: the client
    marks the record `answeredWithoutRequest` and gives it an id `msg_hook_…` (measured on Claude Code 2.1.326), so a
    model that writes the demo sentence does not make a demo session; "model" otherwise."""
    for line in reversed(chunk.splitlines()):
        if b'"assistant"' not in line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue                    # the last line may still be written
        if not isinstance(r, dict) or r.get("type") != "assistant" or not isinstance(r.get("message"), dict):
            continue
        content = r["message"].get("content")
        blocks = content if isinstance(content, list) else [{"type": "text", "text": content}]
        texts = [b.get("text") for b in blocks if isinstance(b, dict) and b.get("type") == "text"
                 and isinstance(b.get("text"), str)]
        if texts:
            hook = r.get("answeredWithoutRequest") is True and str(r["message"].get("id", "")).startswith("msg_hook_")
            return ("mod" if hook else "model", "".join(texts))
    return None


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


def has_turns(payload: dict) -> bool:
    """Whether the session has a turn already: a model answer in its transcript. Measured on Claude Code 2.1.326 and
    codex-cli 0.169.0: the transcript of a new session does not exist yet when the first prompt's hook runs (Claude
    Code) or holds no assistant message (Codex); a resumed session with a turn has one. /clear starts a new session
    id. A payload without a transcript path counts as no turn: the client gave nothing to check."""
    path = payload.get("transcript_path")
    if not isinstance(path, str) or not path:
        return False
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if '"assistant"' not in line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(r, dict):
                    continue
                if r.get("type") == "assistant":                                     # Claude Code
                    return True
                pl = r.get("payload")
                if r.get("type") == "response_item" and isinstance(pl, dict) and pl.get("role") == "assistant":
                    return True                                                       # Codex
    except FileNotFoundError:
        return False
    return False


def switch_typed(verb: str, session: str, route: str, codex: bool, payload: dict | None = None) -> str:
    """`on` puts `session` in the demo, in a session with no turn yet; `off` changes nothing (the demo ends with /clear)
    unless the state is damaged, which it resets. One events.log line for each change. Only the prompt hook calls it,
    for the person's typed prompt."""
    with _lock():
        try:
            data, reset = _read(), False
        except Damaged:
            if verb != "off":
                # only off resets it: an `on` that wrote a valid state would let the prompts of every other
                # session through (Gate A round 5 of #57)
                return DAMAGED.format(off="maisecrets: demo off" if codex else "/maisecrets:demo off")
            data, reset = {}, True          # the person's off rewrites it: never locked out
        if verb == "off":
            if not reset:
                if session not in data and not has_demo_rows(session, (payload or {}).get("transcript_path")):
                    return OFF_ALREADY
                return OFF_CODEX if codex else OFF
            _write(data)
        elif session in data or has_demo_rows(session, (payload or {}).get("transcript_path")):
            return ON_CODEX if codex else ON
        elif has_turns(payload or {}):
            return NOT_FIRST_CODEX if codex else NOT_FIRST
        else:
            data[session] = time.time()
            _write(data)
    from . import events
    events.record_demo(verb, route)
    if reset:
        return ("Demo mode: its state could not be read, so it was reset. A session with demo lines stays in the demo "
                "until /clear; a session that had only switched it on is out of it.")
    return ON_CODEX if codex else ON


def _line(codex: bool) -> str:
    return DEMO_LINE_CODEX if codex else DEMO_LINE


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
        reason = ((ON_CODEX if codex else ON) if active(session, payload.get("transcript_path")) else
                  "Demo mode is off in this session. /maisecrets:demo on, in a new session, keeps what you send here "
                  "and sends nothing to the AI (Codex: maisecrets: demo on).")
    elif not typed:
        from .settings import came_from
        reason = ("maisecrets: /maisecrets:demo counts only when you type it as your prompt; this one came from "
                  f"{came_from(payload)}, so nothing was changed.")
    elif not isinstance(session, str) or not session:
        reason = "maisecrets: this prompt names no session, so the demo cannot be switched. Nothing was changed."
    else:
        route = "slash command" if str(payload.get("prompt", "")).lstrip().startswith("/") else "typed prompt"
        try:
            reason = switch_typed(verb, session, route, codex, payload)
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
    if not active(payload.get("session_id"), payload.get("transcript_path")):
        return None
    if damaged():
        # only the person's exact typed own commands pass a damaged state: no report, no message of another session
        if typed and not payload.get("agent_id") and own_command(prompt):
            return None
        return _block(DAMAGED.format(off="maisecrets: demo off" if codex else "/maisecrets:demo off"), codex)
    if passes(payload, prompt, typed and not payload.get("agent_id")):
        return None
    if not codex and _took_pass(payload.get("session_id"), prompt) and not _has_value(prompt, cfg):
        # the mod let this text enter, and it answers each step of the turn. A pass that a program forged (a write into
        # the maisecrets home, C8) lets in one prompt with no value in it; without the mod that prompt and the masked
        # demo rows reach the AI (the same-user limit of C22). The title of its own spares the session the client's
        # title request, which would carry the prompt to the AI (`generate_session_title`, measured on 2.1.326)
        return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "sessionTitle": TITLE}}
    try:
        _hook_text(payload, cfg, typed and not payload.get("agent_id"), codex)    # the values, as for a sent prompt
    except Exception:  # noqa: BLE001 - the block below holds no value; the prompt does not go either way
        pass
    return _block(_line(codex), codex)


def _has_value(prompt: str, cfg: dict) -> bool:
    """A value the prompt hook would take out: a detected one, or one the store holds (the mod's text has none)."""
    from . import hooks
    from .prompt_values import carries_value
    return bool(hooks._prompt_hits(prompt)) or bool(carries_value(prompt, cfg, None))


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


def _hook_text(payload: dict, cfg: dict, typed: bool, codex: bool) -> str:
    """The normal steps of hooks.user_prompt for a prompt the demo blocks (the {{name}} marker, the placeholders the
    person typed, the values taken out and stored, the transcript scrub, the events line); the masked text. No blocked
    prompt is kept for /maisecrets:send."""
    from . import events, hooks, term_files
    from .placeholder import find_refs
    from .settings import peer_sender
    prompt = payload["prompt"]
    session = payload.get("session_id")
    if typed:
        with contextlib.suppress(OSError):
            prompt, _marked = term_files.take_markers(prompt, hooks._name_ttl(cfg))
        from .prompt_commands import take_inline
        prompt, inline, inline_values = take_inline(prompt, cfg, session)      # ms:(value) inside the prompt
    else:
        inline, inline_values = [], []
    refs = find_refs(prompt)
    matches = hooks._prompt_hits(prompt)
    vault = None
    if refs or matches or hooks._has_live(cfg):
        vault = hooks.Vault(cfg)
        if peer_sender(prompt) is None and not payload.get("agent_id"):
            for key, _s, _e in refs:
                vault.admit(key, session)
    rewritten, entries, values, _stored, _m = hooks._take_values_out(prompt, matches, cfg, vault, session)
    entries, values = inline + entries, inline_values + values
    if values and cfg.get("scrub_transcript", True):
        path = str(payload.get("transcript_path") or "")
        hooks._scrub_transcript(path, values, [e.ref for e in entries])
        # without a path (the mod's drop) the child finds the transcript by the session id, as the mod's rewrite does
        hooks._scrub_transcript_later(path, values, [e.ref for e in entries], session=session)
    events.record("UserPromptSubmit", hooks.client_of(payload), entries, outcome="demo")
    return rewritten


# ------------------------------------------------------------ the mod's step --
def mod_answer(payload: dict, cfg: dict) -> dict | None:
    """The mod's step (hooks.rewrite_prompt), for a session in the demo: {} for what the prompt hook answers or lets
    pass, a drop for a damaged state, else the mod's normal rewrite with `demo: true`: the masked prompt enters (its
    values stored as for a sent prompt), and the mod answers each step of its turn. A pass record tells the prompt hook
    that this exact text may enter. None outside the demo, and inside that rewrite."""
    prompt = payload.get("prompt")
    session = payload.get("session_id")
    if _INSIDE or not isinstance(prompt, str) or not active(session):
        return None
    typed = payload.get("origin") in ("composer", "bridge")      # `sdk`: claude -p, a program
    if parse(prompt) or _answered_by_the_hook(prompt):
        return {}
    if typed and own_command(prompt):
        return {"drop": own_answer(prompt, session)}
    if damaged():
        return {"drop": DAMAGED.format(off="/maisecrets:demo off")}     # before the report pass: none passes
    if _only_reports(prompt):
        return {}
    from . import hooks
    _INSIDE.append(1)
    hooks.LAST_NAMES_WHY[0] = None
    try:
        out = hooks.rewrite_prompt(payload)
    finally:
        _INSIDE.pop()
    if isinstance(out.get("text"), str):
        text = out["text"]
    elif out or hooks.AT_MENTION_RE.search(prompt):
        return {}           # another answer, or an @mention: the prompt hook decides it, and blocks it in the demo
    else:
        text = prompt       # nothing to mask
    _write_pass(session, text)
    return {"text": text, "count": out.get("count", 0), "demo": True, "masked": masked_line(prompt, text),
            "namesUnchecked": not _names_checked(cfg, hooks.LAST_NAMES_WHY[0])}


_KINDS = {"SECRET": ("secret", "secrets"), "EMAIL": ("e-mail", "e-mails"), "NAME": ("name", "names"),
          "PHONE": ("phone number", "phone numbers"), "IBAN": ("IBAN", "IBANs")}


def masked_line(prompt: str, text: str) -> str:
    """"masked: 1 secret, 1 e-mail" for the placeholders the text has and the typed prompt had not; "" for none."""
    from collections import Counter
    from .placeholder import find_refs
    kinds = Counter(k.rsplit("_c", 1)[0] for k, _s, _e in find_refs(text))
    kinds.subtract(Counter(k.rsplit("_c", 1)[0] for k, _s, _e in find_refs(prompt)))
    parts = []
    for kind, n in kinds.items():
        if n > 0:
            one, many = _KINDS.get(kind, (kind.lower(), kind.lower()))
            parts.append(f"{n} {one if n == 1 else many}")
    return "masked: " + ", ".join(parts) if parts else ""


def _names_checked(cfg: dict, why) -> bool:
    """Whether a name service read this prompt: one is set for prompts, and it answered (why == "")."""
    conf = cfg.get("remote_detector")
    return isinstance(conf, dict) and bool(conf.get("url")) and conf.get("prompts") is not False and why == ""


# the person's own commands in the demo: each runs as its command file runs it, without the model. A form that needs
# the model or a browser does not run, and the line says so
_OWN_SPLIT = _LazyRx(r"\A\s*(?:/maisecrets:|maisecrets:[ \t]*)(?P<name>[a-z-]+)(?:[ \t]+(?P<args>.*?))?\s*\Z",
                     re.I | re.S)
_ARGV = {"status": ["status"], "list": ["list"], "audit": ["audit"], "rules": ["rules"], "ner": ["ner"],
         "sref": ["sref"], "put": ["put", "--clipboard"], "forget": ["forget"], "guard": ["guard"],
         "shortcut": ["shortcut"], "settings": ["settings"], "term": ["terms"]}
NEEDS_THE_AI = ("maisecrets: {cmd} needs the AI or a browser, or it changes your commands, so it did not run in the "
                "demo. /clear ends the demo; then send it again.")
OUTPUT_CHARS = 6000


def own_argv(prompt: str) -> list | None:
    """The CLI words of an own command that runs without the model, or None for one that needs the model."""
    m = _OWN_SPLIT.match(prompt)
    if not m:
        return None
    name, args = m.group("name").lower(), (m.group("args") or "").split()
    if name not in _ARGV or (name == "status" and args == ["test"]) or (
            name == "sref" and args[:1] not in ([], ["status"])) or (name == "shortcut" and args != ["status"]):
        return None
    return _ARGV[name] + args


def own_answer(prompt: str, session) -> str:
    """The output of the person's own command, run here as its command file runs it; or the line that it needs the
    AI. The output holds no value (each command prints masked forms only), and it is shown, never sent."""
    import contextlib
    import io
    import os
    import shlex
    import sys
    argv = own_argv(prompt)
    if argv is None:
        return NEEDS_THE_AI.format(cmd=" ".join(prompt.split()[:2])[:80])
    from . import cli
    old_env = os.environ.get("CLAUDE_CODE_SESSION_ID")
    if isinstance(session, str) and session:
        os.environ["CLAUDE_CODE_SESSION_ID"] = session       # status names this session (its demo line)
    out = io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(" ".join(shlex.quote(a) for a in argv[1:]))
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                code = cli.main([argv[0], "--args-stdin"])
            except SystemExit as exc:
                code = exc.code
    except Exception as exc:  # noqa: BLE001 - the line names the failure, never a value
        return f"maisecrets: {argv[0]} failed in the demo ({type(exc).__name__})."
    finally:
        sys.stdin = old_stdin
        if old_env is None:
            os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
        else:
            os.environ["CLAUDE_CODE_SESSION_ID"] = old_env
    text = out.getvalue().strip()
    if len(text) > OUTPUT_CHARS:
        text = text[:OUTPUT_CHARS] + "\n…"
    return text or f"maisecrets: {argv[0]} ran (exit {code})."


def _pass_path(session):
    from .hooks import _SESSION_ID_RE
    return PASS_DIR / f"{session}.json" if isinstance(session, str) and _SESSION_ID_RE.fullmatch(session) else None


def _write_pass(session, text: str) -> None:
    """The hash of the text the mod lets enter, for the prompt hook that runs next on that text."""
    path = _pass_path(session)
    if path is None:
        return
    import hashlib
    PASS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_write(path, json.dumps({"sha": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
                                   "t": time.time()}))


def _took_pass(session, prompt: str) -> bool:
    """True once for the prompt the mod let enter in this session (same text, within PASS_SECONDS); the record goes.
    Any other prompt of a demo session is blocked: the mod did not run for it."""
    path = _pass_path(session)
    if path is None:
        return False
    import hashlib
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
        path.unlink()
    except (OSError, ValueError):
        return False
    return (isinstance(rec, dict) and isinstance(rec.get("t"), (int, float)) and 0 <= time.time() - rec["t"]
            <= PASS_SECONDS and rec.get("sha") == hashlib.sha256(prompt.encode("utf-8", "surrogatepass")).hexdigest())


def mod_demo(payload: dict) -> dict:
    """The mod's question at a model step (dispatch.py mod-demo): is this session in the demo? A damaged state says
    yes (fail closed). With `prompt`, the person's typed own maisecrets command of a session in the demo: `drop` holds
    what it printed (own_answer), as the mod shows it in place of a model turn."""
    session = payload.get("session_id")
    on = bool(active(session))
    if damaged():
        return {"demo": True, "damaged": True}      # the mod keeps no true of a damaged state
    prompt = payload.get("prompt")
    if (on and isinstance(prompt, str) and payload.get("origin") in ("composer", "bridge")
            and not parse(prompt) and not _answered_by_the_hook(prompt) and own_command(prompt)):
        return {"demo": on, "drop": own_answer(prompt, session)}
    return {"demo": on}


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
