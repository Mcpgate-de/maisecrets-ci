"""/maisecrets:not-a-secret KEY (Codex: `maisecrets: not a secret KEY`): the person says that a stored value is no
secret and no personal data. It deletes the entry from the store and puts that exact value on the person's allow list
(user_rules.ALLOW_FILE), so neither a rule nor the name service masks it again. One exact value, never a pattern.

Only the person's typed prompt does it, as a setting (C22): a subagent, a program, a scheduled prompt, another session
or a tool call changes nothing. A key type (a secret, a card, an IBAN, an official, tax or bank number, or a type that
the vocabulary does not know) needs the same typed command twice within CONFIRM_SECONDS; the first one only asks.

`/maisecrets:not-a-secret undo ID` (Codex: `maisecrets: undo not a secret ID`) takes an allowance back. The ID is the
key the value had (a key is never given twice, so it stays unique after the entry is gone); /maisecrets:list shows
each allowance with its ID, its type, its date and the masked form. The record (ALLOWED) keeps no value: the masked
form and a salted hash (_digest), which outlives a wipe of the store. Undo deletes only the line directly under the
comment line `# not-a-secret ID` and only when its hash matches, so a line the person wrote stays. A value that was on
the list before gets no record: that line is the person's.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time

from pathlib import Path

from .home import HOME, atomic_write
from .lazy_regex import LazyRx as _LazyRx      # compiled at first use: a hook imports this module on every call
from .placeholder import CLOSE, OPEN

ALLOWED = HOME / "allowed.json"                 # the allowances this command made: masked form and fingerprint only
PENDING = HOME / ".not-a-secret-pending.json"    # the first command for a key type: key, session, time; no value
CONFIRM_SECONDS = 120
MARK = "# not-a-secret "                        # the comment line above a value this command wrote in allow.txt
# the types that need no second command: personal data that is not a key to anything
NO_KEY_CLASSES = ("pii.name", "pii.email", "pii.phone", "pii.ip", "pii.address", "pii.birth_date", "pii.username")
NO_KEY_TYPES = ("IPV6",)

# the whole prompt, nothing else: the command, `undo` (in the slash form after the name, typed before it), one key
_CMD_RE = _LazyRx(r"\A\s*(?:/maisecrets:not-a-secret(?P<slash_undo>[ \t]+undo\b)?|maisecrets:[ \t]*"
                  r"(?P<typed_undo>undo[ \t]+)?not[ \t]+a[ \t]+secret)(?:[ \t]+(?P<arg>[^\r\n]*?))?\s*\Z", re.I)
_KEY_RE = _LazyRx("(?:" + re.escape(OPEN) + r")?([A-Z][A-Z0-9_]*_c\d+(?:-\d+)?)(?::[^\r\n]*?)?(?:"
                  + re.escape(CLOSE) + r")?\.?")
# the same command in a tool call: a nested client would type it for the model, and the writers called by name would
# skip the prompt. A text match (the C22 class): a form built at run time is not seen
IN_A_COMMAND_RE = _LazyRx(r"/maisecrets:not-a-secret\b|maisecrets:\s*(?:undo\s+)?not\s+a\s+secret\b|"
                          r"\b(?:allow_typed|undo_typed)\b", re.I)
IN_A_COMMAND = ("maisecrets: this command carries /maisecrets:not-a-secret, which makes detection weaker; only the "
                "person does that, as their own prompt. The command did not run. Tell the user the prompt to send.")
USAGE = ("maisecrets: name one stored value by its key, as /maisecrets:list shows it: /maisecrets:not-a-secret "
         "NAME_c12 (Codex: maisecrets: not a secret NAME_c12). To take one back: /maisecrets:not-a-secret undo "
         "NAME_c12. Nothing was changed.")


def parse(prompt) -> tuple | None:
    """("allow" | "undo" | "usage", the key or "") for a not-a-secret prompt, or None for any other prompt."""
    if not isinstance(prompt, str) or "secret" not in prompt.lower():
        return None
    m = _CMD_RE.match(prompt)
    if not m:
        return None
    verb = "undo" if (m.group("slash_undo") or m.group("typed_undo")) else "allow"
    k = _KEY_RE.fullmatch((m.group("arg") or "").strip())
    if not k or (verb == "allow" and "-" in k.group(1)):
        return ("usage", "")
    return (verb, k.group(1))


def in_a_command(command: str) -> bool:
    """Whether a tool call's command text carries the command or names its writers: as written, or with the quotes,
    escapes and line continuations a shell takes out (value_files._JOINED_FORMS)."""
    from .value_files import _JOINED_FORMS
    return bool(IN_A_COMMAND_RE.search(command)
                or any(IN_A_COMMAND_RE.search(form.sub("", command)) for form in _JOINED_FORMS))


def needs_confirmation(type_: str) -> bool:
    """A key type: anything but personal data that opens nothing. A type the vocabulary does not know (a rule of your
    own) counts as a key type: the stricter side."""
    if type_ in NO_KEY_TYPES:
        return False
    from .detection.vocabulary import TYPES
    return (TYPES.get(type_) or {}).get("class") not in NO_KEY_CLASSES


# ------------------------------------------------------------ the records --
def _read(path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def records() -> dict:
    """id -> {key, type, display, fp, t} of every allowance this command made."""
    return {k: v for k, v in _read(ALLOWED).items() if isinstance(v, dict)}


def _lock():
    from .home import _lock_for
    return _lock_for(HOME / ".allow.lock")


def _fits_a_line(value: str) -> bool:
    """The allow list reads one stripped line per value; a line that starts with # is a comment and `rule:` a rule
    id (user_rules._allow_lines). A value that cannot be such a line would never match."""
    return (bool(value) and value == value.strip() and "\n" not in value and "\r" not in value
            and not value.startswith("#") and not value.lower().startswith("rule:"))


def _digest(salt: str, text: str) -> str:
    """The salted hash of a line, which finds it again at undo. It tells nothing that allow.txt next to it does not
    hold in clear, and a wipe of the store leaves it valid (the vault fingerprint key does not)."""
    return hashlib.sha256((salt + "\0" + text).encode("utf-8", "surrogatepass")).hexdigest()


def _already(value: str) -> bool:
    """The value is a line of allow.txt already (the person wrote it): it is not written twice, and gets no record."""
    from .user_rules import ALLOW_FILE
    try:
        old = ALLOW_FILE.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return False
    return value in {line.strip() for line in old.splitlines()}


def _append(rid: str, value: str) -> None:
    """The value as one line of allow.txt, with a comment line above it. Appended (0600 when new), so the lines the
    person wrote stay as they are, and a symlink stays a symlink."""
    from .user_rules import ALLOW_FILE
    ALLOW_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        old = ALLOW_FILE.read_bytes()
    except FileNotFoundError:
        old = b""
    head = b"" if not old or old.endswith(b"\n") else b"\n"
    fd = os.open(ALLOW_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "ab") as f:
        f.write(head + f"{MARK}{rid} {time.strftime('%Y-%m-%d')}\n{value}\n".encode("utf-8"))


def _inside_home() -> bool:
    """allow.txt (through any link) lies in the maisecrets home. A link to a shared or team file would carry the
    value there in clear."""
    from .user_rules import ALLOW_FILE
    home = os.path.realpath(HOME)
    return os.path.commonpath([home, os.path.realpath(ALLOW_FILE)]) == home


def _new_id(key: str, taken: dict) -> str:
    """The key, or key-2, key-3 … when a wipe started the counters again and the key had an allowance before."""
    rid, n = key, 1
    while rid in taken:
        n += 1
        rid = f"{key}-{n}"
    return rid


# ------------------------------------------------------------ the commands --
def allow_typed(key: str, session: str | None, route: str, cfg: dict | None = None) -> str:
    """Delete the stored value `key` and put its exact value on the allow list; the answer names the key and the
    masked form, never the value. Only the prompt hook calls it, for the person's typed prompt."""
    from .vault import Vault
    v = Vault(cfg)
    meta = v._index["entries"].get(key)
    if meta is None:
        if key in records():
            return (f"maisecrets: {key} is already on your allow list (see /maisecrets:list). Nothing was changed.")
        return f"maisecrets: there is no stored value {key} (see /maisecrets:list). Nothing was changed."
    kind, type_ = str(meta.get("kind", "")), str(meta.get("type", ""))
    if kind.startswith(("term:", "import:")):
        where = "your term list (/maisecrets:term remove)" if kind.startswith("term:") else \
            "an import of values (/maisecrets:forget import:ID)"
        return f"maisecrets: {key} comes from {where}; take it out there. Nothing was changed."
    if meta.get("purged") or meta.get("expires", 0) < time.time():
        return (f"maisecrets: {key} has expired, so its value is no longer stored and cannot go on the allow list. "
                "Nothing was changed.")
    shown = f"{key} ({meta.get('display')})" if meta.get("display") else key
    if needs_confirmation(type_) and not _inside_home():
        return (f"maisecrets: your allow list is a link to a file outside the maisecrets folder, and {shown} is a key "
                "type: its value would be written there in clear. Nothing was changed. Make allow.txt a file of your "
                f"own, or delete the value with /maisecrets:forget {key}.")
    if needs_confirmation(type_) and not _confirmed(key, session):
        from .notices import type_word
        return (f"maisecrets: {shown} is {type_word(type_)}, a key type. Type the command again within "
                f"{CONFIRM_SECONDS // 60} minutes to allow it. Nothing was changed.")
    value = v.backend.get(key)
    if not value:
        return f"maisecrets: the store did not give the value of {key}. Nothing was changed."
    if not _fits_a_line(value):
        return (f"maisecrets: the value of {shown} cannot be one line of the allow list (it has a line break, a space "
                f"at an end, or starts with # or rule:). Nothing was changed; /maisecrets:forget {key} deletes it.")
    if v.forget(key, route=route) != "ok":
        return f"maisecrets: the store refused to delete {key}. Nothing was changed."
    from . import events
    try:
        with _lock():
            if _already(value):
                _reset()
                return (f"maisecrets: {shown} is deleted from the store. Its exact value is a line you wrote in your "
                        "allow list already, so maisecrets does not mask it; to mask it again, delete that line.")
            taken = records()
            rid = _new_id(key, taken)
            _append(rid, value)
            salt = os.urandom(16).hex()
            taken[rid] = {"key": key, "type": type_, "display": meta.get("display"), "salt": salt,
                          "hash": _digest(salt, value), "t": int(time.time())}
            atomic_write(ALLOWED, json.dumps(taken, indent=1))
    except OSError as exc:
        return (f"maisecrets: {key} was deleted, but the allow list could not be written ({type(exc).__name__}), so "
                "maisecrets masks the value again where it finds it.")
    events.record_weakening("allow", rid, route)       # the next session start names it to the person
    _reset()
    return (f"maisecrets: {shown} is deleted from the store, and this exact value is on your allow list, so "
            "maisecrets does not mask it again. A longer value that contains it is still masked. To take it back: "
            f"/maisecrets:not-a-secret undo {rid} (Codex: maisecrets: undo not a secret {rid}).")


def _confirmed(key: str, session: str | None) -> bool:
    """True for the second typed command for `key` in this session within CONFIRM_SECONDS (the record goes); else the
    first one is recorded and False. The record lives in the maisecrets home: each hook call is a new process."""
    now = time.time()
    with _lock():
        last = _read(PENDING)
        if last.get("key") == key and last.get("session") == (session or "") and \
                isinstance(last.get("t"), (int, float)) and 0 <= now - last["t"] <= CONFIRM_SECONDS:
            try:
                PENDING.unlink()
            except OSError:
                pass
            return True
        atomic_write(PENDING, json.dumps({"key": key, "session": session or "", "t": now}))
    return False


def undo_typed(rid: str, cfg: dict | None = None) -> str:
    """Take the allowance `rid` back: the line directly under its comment line, when its hash matches, leaves
    allow.txt with the comment line, and the record goes. A matching line anywhere else may be the person's own: then
    nothing changes and the answer says how to remove it by hand. The value is masked again when a rule or the name
    service finds it; it is no stored value any more, so nothing hunts it."""
    from .user_rules import ALLOW_FILE
    with _lock():
        taken = records()
        rec = taken.get(rid)
        if rec is None:
            return f"maisecrets: there is no allowance {rid} (see /maisecrets:list). Nothing was changed."
        try:
            lines = ALLOW_FILE.read_text(encoding="utf-8").splitlines(keepends=True)
        except FileNotFoundError:
            lines = []
        except (OSError, UnicodeDecodeError) as exc:
            return f"maisecrets: the allow list cannot be read ({type(exc).__name__}). Nothing was changed."
        salt, want = str(rec.get("salt", "")), rec.get("hash")
        shown = f"{rid} ({rec.get('display')})" if rec.get("display") else rid

        def mark(text: str) -> bool:
            return text.startswith(MARK.strip() + " ") and text.split()[2:3] == [rid]

        keep, gone, i = [], 0, 0
        while i < len(lines):
            if mark(lines[i].strip()) and i + 1 < len(lines) and _digest(salt, lines[i + 1].strip()) == want:
                gone, i = gone + 1, i + 2
                continue
            keep.append(lines[i])
            i += 1
        if not gone:
            if any(_digest(salt, x.strip()) == want for x in lines):
                return (f"maisecrets: the line of {shown} no longer stands directly under its comment line "
                        f"`{MARK}{rid}`, so it may be a line you wrote. The value is still on your allow list and is "
                        f"not masked. Nothing was changed. To mask it again, delete that line from {ALLOW_FILE}, then "
                        "send this command again.")
            keep = [x for x in lines if not mark(x.strip())]
        if len(keep) != len(lines):
            atomic_write(Path(os.path.realpath(ALLOW_FILE)), "".join(keep))   # through a link to the file it names
        del taken[rid]
        atomic_write(ALLOWED, json.dumps(taken, indent=1))
    _reset()
    if not gone:
        return (f"maisecrets: the allowance {shown} is taken back; its line was no longer in your allow list. "
                "maisecrets masks the value again where it finds it.")
    return f"maisecrets: the allowance {shown} is taken back. maisecrets masks the value again where it finds it."


def _reset() -> None:
    """The detector of this process reads the allow list again (a hook is one process; tests run many prompts)."""
    from . import detect
    detect.reset_rules()


def answer(payload: dict, cmd: tuple, typed: bool, client: str) -> dict:
    """The prompt hook's answer: always a block, so the command never reaches the model. Only a typed prompt of the
    person changes something; any other says where it came from. The prompt carries a key, never a value."""
    verb, key = cmd
    if verb == "usage":
        reason = USAGE
    elif not typed:
        from .settings import came_from
        reason = ("maisecrets: /maisecrets:not-a-secret counts only when you type it as your prompt; this one came "
                  f"from {came_from(payload)}, so nothing was changed.")
    else:
        route = "slash command" if str(payload.get("prompt", "")).lstrip().startswith("/") else "typed prompt"
        try:
            reason = (allow_typed(key, payload.get("session_id"), route) if verb == "allow" else undo_typed(key))
        except Exception as exc:  # noqa: BLE001 - the answer says it failed; a half step says so in its own text
            reason = f"maisecrets: this did not work ({type(exc).__name__}). Nothing more was changed."
    if client == "codex":
        return {"decision": "block", "reason": reason}
    return {"decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}


# ------------------------------------------------------------ what the person reads --
def hint(entries: list) -> str:
    """One short hint for the line that tells the person what was masked: the key when there is one, else KEY. None
    for the values the person chose (a term, an import) and for a key type: the model can make that line appear, and
    it should never read as an invitation to unmask a secret."""
    keys = list(dict.fromkeys(e.key for e in entries if getattr(e, "key", None)
                              and not str(getattr(e, "kind", "")).startswith(("term:", "import:"))
                              and not needs_confirmation(str(getattr(e, "type", "")))))
    if not keys:
        return ""
    return f" Wrong? Type /maisecrets:not-a-secret {keys[0] if len(keys) == 1 else 'KEY'}"


def list_lines() -> list:
    """The allowances for /maisecrets:list: id, type, date and masked form, never a value."""
    rows = sorted(records().items(), key=lambda kv: kv[1].get("t", 0))
    if not rows:
        return []
    out = [f"Allowed by you with /maisecrets:not-a-secret ({len(rows)}): not masked again",
           f"{'id':<14} {'type':<7} {'allowed':<10}  shown as"]
    for rid, r in rows:
        day = time.strftime("%Y-%m-%d", time.localtime(r.get("t", 0))) if isinstance(r.get("t"), int) else "?"
        out.append(f"{rid:<14} {str(r.get('type', '?')):<7} {day:<10}  {r.get('display') or '-'}")
    out.append("To take one back: /maisecrets:not-a-secret undo ID (Codex: maisecrets: undo not a secret ID).")
    return out
