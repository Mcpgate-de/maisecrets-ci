"""The prompt path's answers that need more than the detector: ms:(…) as the whole prompt (a check, check_answer),
ms:(value) inside a prompt (take_inline), and the mod's answer to the person's own maisecrets commands in Claude Code
(mod_command). They lived in hooks.py, which ships under the release file limit (scripts/check_release_sizes.py).

Every name of hooks.py is read on that module at call time (`h.Vault`, `h._scrub_transcript_later`): a test that
patches one on hooks patches it here too, and this module imports nothing of hooks at its own import.
"""
from __future__ import annotations

import re

from . import check_value, demo, detect, incidents, not_a_secret, term_files, value_files
from .lazy_regex import LazyRx


def _allowed_by_the_list(value: str) -> str | None:
    """Why the allow list lets this value through, or None. Only for a value no rule caught: the scan with every rule,
    without the allow list, shows whether the list took a hit out (`rule: <id>` or an exact value)."""
    return detect.explain_allowed(value)


def _store_unseen(payload: dict, cfg: dict, value: str, session: str | None, exact: bool) -> str:
    """No rule and no stored value caught `value`: store it as /maisecrets:put does, so that it is masked from now
    on, and say where maisecrets finds it again. Each case where storing is not allowed or would not help says so."""
    from . import hooks as h
    from . import settings as settings_mod
    allowed = _allowed_by_the_list(value)
    if allowed:
        from .user_rules import ALLOW_FILE
        why = allowed[len("your allow list "):] if allowed.startswith("your allow list ") else allowed
        return check_value.not_caught(f"Your allow list lets it through: it {why}. It was not stored. To protect it, "
                                      f"remove that line from {ALLOW_FILE}.")
    if not exact:
        return check_value.not_caught("It was not stored, because the prompt does not start with ms:( exactly. Send "
                                      "it again as ms:(…) to store it.")
    # the mod names who sent the prompt: only the person at the terminal or in Remote Control stores (an `sdk` turn can
    # come from a program, as for a settings change)
    if not settings_mod.typed_by_the_person(payload) or payload.get("agent_id") or \
            payload.get("origin") not in (None, "composer", "bridge"):
        return check_value.not_caught("It was not stored: maisecrets stores a value only from a prompt that you "
                                      "type yourself.")
    if h.find_refs(value):
        return check_value.not_caught("It holds a maisecrets placeholder, so it was not stored. Check the value "
                                      "without the placeholder.")
    if "\n" in value or "\r" in value:
        return check_value.not_caught("It has more than one line, so it was not stored. maisecrets finds a stored "
                                      "value only on one line. Use /maisecrets:put for it.")
    if len(value) < h._EXACT_MIN_LEN:
        return check_value.not_caught(f"maisecrets finds a stored value only from {h._EXACT_MIN_LEN} characters on, "
                                      "so it was not stored.")
    if not check_value.looks_like_a_credential(value):
        # a check of ordinary words stored them for good, and every later prompt with them was blocked (field report,
        # 0.6.32): only a value that the credential checks of the detector take is stored here
        return check_value.not_caught(check_value.TEST_VALUE if check_value.names_a_test_value(value)
                                      else check_value.ORDINARY)
    try:
        e = h.Vault(cfg).put(value, "SECRET", "manual", session=session)
    except Exception as exc:  # noqa: BLE001 - the answer says it; the prompt stays blocked
        incidents.note("prompt.check-store", exc)
        return check_value.not_caught(f"It could not be stored (an internal error, {type(exc).__name__}). Try "
                                      "/maisecrets:put, or /maisecrets:report incident.")
    h._live_cache.clear()        # the store holds a value now: the checks below must look for it
    alone = any(h._verdict(value, cfg, session)[1:3])
    in_text = any(h._verdict(f"see {value} here", cfg, session)[1:3])
    seconds = int(round(e.expires - e.created))
    return check_value.stored_text(e.ref, alone, in_text, h._hours(seconds)) + check_value.format_report(value)


def check_answer(payload: dict, groups: list) -> dict:
    """The answer to ms:(…): always a block, whatever the verdict. Each group of the prompt (check_value.parse_all)
    gets its own verdict, from the same calls as a normal prompt with that value. The reason goes to the person and
    says what each hit is masked as and how it was found (maisecrets/verdict.py), never the value; the transcript
    loses the prompt as typed."""
    from . import hooks as h
    cfg = h.load_config()
    session = payload.get("session_id")
    codex = h.client_of(payload) == "codex"
    entries: list = []
    values: list = []
    lines: list = []
    seen: dict = {}
    for value, exact in groups:
        if value in seen:                  # the same value again: the same line, and it is stored once
            lines.append(lines[seen[value]])
            continue
        seen[value] = len(lines)
        got, taken, line = _check_one(payload, cfg, session, value, exact)
        entries += got
        values += taken
        lines.append(line)
    # a value no rule caught is stored after every group has its verdict: a group never sees what a check before it
    # in the same prompt stored, so each verdict is the one its normal prompt gets alone
    stored: dict = {}
    for i, line in enumerate(lines):
        if isinstance(line, tuple):
            if line[1] not in stored:
                stored[line[1]] = _store_unseen(payload, cfg, *line[1:])
            lines[i] = stored[line[1]]
    if len(lines) == 1:
        reason = lines[0] + "\n\n" + check_value.NOT_SENT
    else:
        reason = "\n".join(f"Value {i}: {line}" for i, line in enumerate(lines, 1)) + "\n\n" + check_value.NOT_SENT
    if cfg.get("scrub_transcript", True):
        raw = payload.get("prompt") if isinstance(payload.get("prompt"), str) else ""
        forms = check_value.scrub_forms(raw, [v for v, _exact in groups])
        scrub = [x for x in dict.fromkeys(forms + list(values)) if x]
        h._scrub_transcript(payload.get("transcript_path", ""), scrub, [])
        h._scrub_transcript_later(payload.get("transcript_path", ""), scrub, [], session=session)
    from . import events
    events.record("UserPromptSubmit", h.client_of(payload), entries, outcome="ms:( check")   # key, type, rule: no value
    if codex:
        return {"decision": "block", "reason": reason}
    return {"decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}


def _check_one(payload: dict, cfg: dict, session: str | None, value: str, exact: bool) -> tuple:
    """(entries, values taken out, verdict line) of one group of a check. The line ends without the sentence that the
    prompt was not sent: check_answer adds it once. For a value no rule caught, the line is a tuple that names the
    store step, which check_answer runs after the verdicts of all groups."""
    from . import hooks as h
    if not value.strip():
        return [], [], check_value.USAGE_LINE
    if check_value.only_placeholders(value, h.find_refs(value)):
        return [], [], check_value.A_PLACEHOLDER_LINE
    entries, matches, n_stored, values = h._verdict(value, cfg, session)
    if matches or n_stored:
        from . import verdict
        return entries, values, verdict.caught(value, matches, entries)
    return entries, values, ("store", value, session, exact)     # check_answer stores it after the last verdict


def take_inline(prompt: str, cfg: dict, session: str | None) -> tuple:
    """ms:(value) inside a prompt the person typed (check_value.inline_marks): each value is stored as /maisecrets:put
    stores it, and its placeholder stands in place of the whole mark. (prompt, entries, values)."""
    from . import hooks as h
    marks = check_value.inline_marks(prompt)
    if not marks:
        return prompt, [], []
    vault = h.Vault(cfg)
    parts, entries, values, last = [], [], [], 0
    for start, end, value in marks:
        if check_value.only_placeholders(value, h.find_refs(value)):
            continue                    # placeholders alone are no value: the mark stays as typed
        # a placeholder next to other text: the whole mark is stored, so the text never goes out (Gate A)
        e = vault.put(value, "SECRET", "manual", session=session)
        parts += [prompt[last:start], e.ref]
        last = end
        entries.append(e)
        values.append(value)
    parts.append(prompt[last:])
    if entries:
        h._live_cache.clear()             # the store holds a value now
    return "".join(parts), entries, values


# the Codex form of a maisecrets command, `maisecrets: NAME ARGS` (Codex has no plugin slash commands)
_TYPED_FORM_RE = LazyRx(r"\A\s*maisecrets[ \t]*:[ \t]*(?P<name>[a-z][a-z-]*)(?:[ \t]+(?P<args>[^\r\n]*?))?\s*\Z",
                        re.I)


def mod_command(payload: dict) -> dict | None:
    """The mod's answer to the person's own maisecrets command in Claude Code, so that none reaches the model and none
    reads as a block (night UX test, findings C and F): {"drop": answer} for a command the prompt hook answers (the
    same call, hooks.user_prompt) and for a Codex form that runs without the model (demo.own_answer); {"drop": line,
    "fill": the slash form} for a Codex form that needs the model. None for every other prompt, and for a prompt the
    person did not type (the hook path stays as it is: Codex, claude -p, a client without the mod)."""
    from . import hooks as h
    if payload.get("origin") not in ("composer", "bridge"):
        return None
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or "maisecrets" not in prompt.lower():
        return None
    # the pending self-test value goes on to the real prompt hook: its pass proves that hook ran (Gate A)
    st = h._selftest()
    if not st.typed_command(prompt) and st.claims(prompt):
        return None
    from . import settings as settings_mod
    slash = prompt.lstrip().startswith("/")
    hook = (incidents.recognize(prompt, "claude") or demo.parse(prompt) or term_files.parse_command(prompt)
            or value_files.parse_removal(prompt) or not_a_secret.parse(prompt)
            # a slash settings change runs on after a success (it shows the new state): the hook keeps it
            or (not slash and settings_mod.parse_prompt(prompt))
            or (h._GRANT_RE.match(prompt) and h.load_config().get("ssh_consent")))
    if hook:
        session = payload.get("session_id")
        # the demo asks the transcript whether the session has a turn; the mod gives no path
        found = demo._find_transcript(session) if isinstance(session, str) and session else None
        out = h.user_prompt({**payload, "prompt_id": "mod", "transcript_path": found or ""})
        if out.get("decision") == "block" and isinstance(out.get("reason"), str):
            return {"drop": out["reason"]}
        return {}
    m = _TYPED_FORM_RE.match(prompt)
    name = m.group("name").lower() if m else ""
    # the command names of commands/*.md and the skill (demo.FORMS and the names it leaves out): another word after
    # `maisecrets:` is a question for the AI
    if name not in demo.FORMS and name not in demo.NOT_PASSED:
        return None
    # in the demo a form that needs the model gets the demo's line that it did not run (demo.own_answer)
    if demo.own_command(prompt) and (demo.own_argv(prompt) is not None or demo.active(payload.get("session_id"))):
        return {"drop": demo.own_answer(prompt, payload.get("session_id"))}
    form = f"/maisecrets:{name}" + (f" {m.group('args')}" if m.group("args") else "")
    return {"drop": f"maisecrets: in Claude Code this is {form}. It is in your input box: press Enter to run it.",
            "fill": form}
