"""ms:(…) - the person checks whether maisecrets would catch a value, and the value never reaches the model.

A typed prompt that starts with `ms:(` is always blocked (hooks.user_prompt; the mod leaves it to that hook). The
value is the text between `ms:(` and the last `)`, or up to the end when the `)` is missing; `ms:(a) ms:(b)` checks two
values, each with its own verdict (parse_all). The verdict comes from the same calls as for a normal prompt with that
value (hooks._prompt_hits and hooks._take_values_out). A value no rule caught is stored only when it looks like a
credential (looks_like_a_credential). The answer
goes to the person only, in the block reason, and names types and rule ids, never the value (README "Check a value
first").
"""
from __future__ import annotations

import re
import urllib.parse

class _Lazy:
    """A pattern compiled on its first use: the hook start compiles only what a prompt needs (tests/test_hook_start)."""

    def __init__(self, pattern: str, flags: int = 0) -> None:
        self._args, self._rx = (pattern, flags), None

    def __getattr__(self, name: str):
        if self._rx is None:
            self._rx = re.compile(*self._args)
        return getattr(self._rx, name)


# `Ms:(` too: a phone keyboard in Remote Control writes the first letter in capitals, and that prompt would go out.
# The near forms of the same trigger count too, because a miss sends a value without a shape to the model: blanks
# around the colon (`ms: (`), and the full-width colon and bracket of an input method (`ms：（`). Before it, every
# blank that the mod's `\s` takes (JavaScript counts U+FEFF, Python does not) and the zero-width characters: a prompt
# that the mod passes on as a check must be a check here too, or the hook would send it (claude-mod CHECK)
_BLANK = r"[\s\ufeff\u200b-\u200d\u2060]*"
TRIGGER_RE = re.compile(r"\A" + _BLANK + "ms" + _BLANK + "[:\uff1a]" + _BLANK + "[(\uff08]", re.I)
# the start as the README writes it: only this one stores a value no rule caught. A near form is blocked as a check, but
# `MS: (Microsoft Teams) the sync fails` would else put a product name into the store for good (Gate B, round 2)
EXACT_RE = re.compile(r"\A" + _BLANK + r"ms:\(", re.I)
# one blank at most on each side: `ms:( value )` and a key on its own lines between `ms:(` and `)`
_EDGES = ("\r\n", "\n", " ", "\t")

TIP_CLAUDE = "Tip: check a value first with ms:(…)"
TIP_CODEX = ("maisecrets: check a value first: send ms:(your value) alone as your prompt. maisecrets says whether it "
             "would mask the value, and the value does not reach the AI.")
NOT_SENT = "This prompt was not sent. The value did not reach the AI."
# the verdict of one group ends without NOT_SENT: the answer adds it once, after the last group
USAGE_LINE = ("maisecrets: put the value between the brackets, for example ms:(my-value). maisecrets then says whether "
              "it would mask it.")
A_PLACEHOLDER_LINE = ("maisecrets: this is a maisecrets placeholder, not a value. Put the value itself between the "
                      "brackets.")
NOT_CAUGHT = "⚠ maisecrets would NOT have caught this."
ORDINARY = "It looks like ordinary text, so it was not stored. If it is a secret, store it with /maisecrets:put."


def exact(prompt) -> bool:
    return isinstance(prompt, str) and EXACT_RE.match(prompt) is not None


# the next group of a prompt with several checks: blanks and `ms:(` in any of the forms of the first one (`ms: (`,
# `ms：（`). The group before it ends at its last `)`, as the last group does; without a `)` it ends at the blanks, so a
# group never holds the start of the next one
_NEXT_RE = _Lazy(r"(?:[\s\ufeff\u200b-\u200d\u2060]+|(?<=[)\uff09]))ms" + _BLANK + "[:\uff1a]" + _BLANK
                 + "[(\uff08]", re.I)


def parse_all(prompt) -> list | None:
    """The groups of a check prompt as (value, exact) pairs, or None when the prompt is no check. `ms:(a) ms:(b)` holds
    two groups. Each group ends at its last `)` before the next `ms:(` (the last one: before the end), or, without a
    `)`, at the blanks before the next `ms:(` (the last one: at the end). So a `)` inside a value works in each group,
    and no value holds the `ms:(` of the next group. exact: the prompt starts with `ms:(` as the README writes it (only
    then a group stores a value)."""
    if not isinstance(prompt, str):
        return None
    m = TRIGGER_RE.match(prompt)
    if not m:
        return None
    groups: list = []
    is_exact, start = EXACT_RE.match(prompt) is not None, m.end()
    while True:
        nxt = _NEXT_RE.search(prompt, start)
        if nxt is None:
            rest = prompt[start:]
            close = max(rest.rfind(")"), rest.rfind("\uff09"))
            groups.append((_trim(rest[:close] if close >= 0 else rest), is_exact))
            return groups
        raw = prompt[start:nxt.start()]
        close = max(raw.rfind(")"), raw.rfind("\uff09"))
        groups.append((_trim(raw[:close] if close >= 0 else raw), is_exact))
        start = nxt.end()       # a later group stores only when the first one may: `MS: (Teams) ms:(…)` stores nothing


def parse(prompt) -> str | None:
    """The value of a check prompt (the first group of several), or None when the prompt is no check. An empty value
    is "" (the prompt is still a check and is blocked)."""
    groups = parse_all(prompt)
    return groups[0][0] if groups else None


def _trim(value: str) -> str:
    for edge in _EDGES:
        if value.startswith(edge):
            value = value[len(edge):]
            break
    for edge in _EDGES:
        if value.endswith(edge):
            value = value[:-len(edge)]
            break
    return value


_KEY_LIKE_RE = re.compile(r"[A-Za-z_]+")


def scrub_forms(prompt: str, values) -> list[str]:
    """The texts of a check to mask in the transcript: the prompt as typed and without its outer blanks, and each value
    alone. A value alone only from 8 characters on and when it is not letters only: a short value or a word such as
    `true` or `content` would be masked in every record and break the JSON of the transcript (Gate B, round 1); the
    prompt as typed covers it. Random letters that a check stores (looks_like_a_credential) are masked alone too."""
    forms = [prompt, prompt.strip()]
    for value in [values] if isinstance(values, str) else values:
        if len(value) >= 8 and (not _KEY_LIKE_RE.fullmatch(value) or looks_like_a_credential(value)):
            forms.append(value)
    return [f for f in dict.fromkeys(forms) if f]


def only_placeholders(value: str, refs: list) -> bool:
    """The value is placeholders and blanks only: nothing to check."""
    rest, last = [], 0
    for _key, a, b in refs:
        rest.append(value[last:a])
        last = b
    rest.append(value[last:])
    return bool(refs) and not "".join(rest).strip()


def hit_label(type_: str, kind: str, stored: bool = False) -> str:
    """One hit as the person reads it: the type and the rule id. A term names no entity, a stored value no key."""
    if stored:
        return f"{type_} (stored value)"
    if kind.startswith("import:"):
        return f"{type_} (import:{kind.split(':')[1]})"
    if kind.startswith("term:"):
        return f"{type_} (term)"
    return f"{type_} ({kind})"


def caught_line(labels: list[str]) -> str:
    return f"✓ maisecrets would mask this: {', '.join(dict.fromkeys(labels))}"


def not_caught(why: str) -> str:
    return f"{NOT_CAUGHT} {why}"


# the fixed start of a token format: a few small letters (or capitals) before _ - or ., once or twice (sb_pat_,
# NRAK-, hvs.). Only before a random rest of 16 characters and more: a password such as summer_rain42 keeps its start
_FORMAT_PREFIX_RE = _Lazy(r"(?:[a-z]{2,8}|[A-Z]{2,6})[_.-](?:[a-z]{2,8}[_.-])?")


def format_shape(value: str) -> dict:
    """The shape of a value for a report of its format, never the value: the fixed start (or none), the length of
    the rest, its kinds of character, and the same as one compact pattern (`sb_pat_[A-Za-z0-9]{32}`)."""
    m = _FORMAT_PREFIX_RE.match(value)
    rest = value[m.end():] if m else value
    prefix = m.group(0) if m and len(rest) >= 16 and len(set(rest)) >= 8 else ""
    rest = value[len(prefix):]
    kinds = [name for name, test in (("small letters", str.islower), ("capitals", str.isupper),
                                     ("digits", str.isdigit)) if any(test(c) for c in rest)]
    signs = "".join(sorted({c for c in rest if not c.isalnum()}))
    span = "".join(r for name, r in (("capitals", "A-Z"), ("small letters", "a-z"), ("digits", "0-9")) if name in kinds)
    span += "".join("\\" + c if c in "\\]^-" else c for c in signs)
    return {"prefix": prefix, "length": len(rest), "kinds": kinds, "signs": signs,
            "pattern": f"{prefix}[{span}]{{{len(rest)}}}"}


# the template of the report on the GitHub tracker (.github/ISSUE_TEMPLATE/format.yml) holds the questions, so the
# link carries only the title and stays short enough for one line of a terminal: a link of 600 characters wrapped,
# and the indented second line could not be copied whole (2026-10-23)
FORMAT_TEMPLATE = "format.yml"


def format_report(value: str) -> str:
    """Lines that offer to report the format of a value maisecrets did not catch: the shape and a short issue link on
    a line of its own (docs/DETECTION-COVERAGE.md, loop 4). Only for a value with a fixed start: without one no
    format rule can follow, and the report would be an issue nobody can act on. Empty when reporting is off."""
    from . import events
    sh = format_shape(value)
    if not sh["prefix"]:
        return ""
    shape = (f"`{sh['prefix']}` and {sh['length']} characters of {', '.join(sh['kinds']) or 'signs'}"
             + (f" and `{sh['signs']}`" if sh["signs"] else ""))
    try:
        tracker = events.tracker()
    except Exception:  # noqa: BLE001 - a broken config must not stop the answer; the report is an extra
        return ""
    if not tracker:
        return ""
    repo = events.github_repo(tracker)
    url = (f"https://github.com/{repo}/issues/new?" + urllib.parse.urlencode(
        {"template": FORMAT_TEMPLATE, "title": f"Token format: {sh['pattern']}"}) if repo else tracker)
    return (f"\nUnknown format? Report its shape ({shape}), never the value:\n{url}\n"
            "Check the start first: if it is part of your secret and not the service's fixed prefix, do not send it.")


def stored_text(ref: str, alone: bool, in_text: bool) -> str:
    if alone and in_text:
        return not_caught(f"It is now stored ({ref}). From now on it is masked wherever it stands as a word of its "
                          "own.")
    if alone:
        return not_caught(f"It is now stored ({ref}). From now on it is masked where it stands alone on a line or "
                          "after a colon or an equals sign (password: …). Inside a sentence maisecrets does not find "
                          "it, because it has spaces.")
    return not_caught(f"It is now stored ({ref}), but maisecrets does not find it again in a prompt. Please report "
                      "this with /maisecrets:report bug (the report holds no value).")


# the signs around a word of a sentence or of code: `5!`, `(room)` and `"name",` carry no sign of a password
_AROUND = "\"'`()[]{}<>.,;:!?"
# code, not a passphrase: quotes, brackets, an assignment, a redirection
_CODE_SIGNS = frozenset("\"'`()[]{}<>=")
# a digest, an id or an address in hex: a sha256 sum, `sha256:…`, a UUID, a MAC address, a colour (#0f0f0f), 0x7ffe…
_HEX_ID_RE = _Lazy(r"#?(?:(?i:sha\d*|md5|blake\w*)[-:]|0x)?[0-9a-fA-F]+(?:[-:][0-9a-fA-F]+)*")
# a version with its pre-release and build parts (v1.2.3-rc.4, 2.0.0+build.7)
_SEMVER_RE = _Lazy(r"(?i:v|version[-_]?v?)?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?")
# the name before a colon: letters joined by - _ .
_LABEL_RE = _Lazy(r"[^\W\d_]+(?:[-_.][^\W\d_]+)*")
# an assignment or a flag with its value (`DB_HOST=db1`, `db=x`, `--level=3`, `path.to=x`): a flag, or a name of
# small letters or of capitals, also with _ . - in it. A random password with `=` inside (Kx7=pLm2#zR9) stays a value
_ASSIGNMENT_RE = _Lazy(r"(?:-{1,2}[A-Za-z][\w-]*|[a-z]{2,}|[A-Z]{2,}|[a-z][a-z0-9]*(?:[_.-][a-z0-9]+)+"
                       r"|[A-Z][A-Z0-9]*(?:[_.-][A-Z0-9]+)+)=.*")
# a version pin of a package (`keyring~=24.3`, `passlib>=1.7,<2`, `x==2`): a version after the operator, so a
# password with `>` or `<` before a digit (Kq9>4mPq!zLx) stays a value
_PIN_RE = _Lazy(r"[A-Za-z][\w.\-\[\]]*(?:(?:[~=!<>]=|[<>])\d+(?:\.\d+)+|[~=!]=\d+)"
                r"(?:,(?:[~=!<>]=|[<>])\d+(?:\.\d+)*)*")
# a word that says it is no value: the word parts of detect._LITERAL_PLACEHOLDER_RE, not its signs ($x, <x>, ...),
# which a random password holds as often as any other sign
_PLACEHOLDER_WORD_RE = _Lazy(r"(?i)x{4,}|\*{3,}|your[_-]|example|sample|dummy|placeholder|changeme|change_me|"
                                  r"redacted|lorem|foobar|secret_here")
# a date and a time (2026-10-17T12:30:00Z), an issue of small letters (ai-gateway#1191; Hamburg#2026 and
# Sommer2026#1 stay values), a file with its type (IMG_2026.jpg)
_DATE_ID_FILE_RE = _Lazy(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?"
                              r"|[a-z][a-z0-9]*(?:[-/][a-z0-9]+)*#\d{1,7}|[\w.-]+\.(?i:jpe?g|png|gif|svg|pdf|txt|md|py|js|ts|json|ya?ml|toml|zip|gz|"
                              r"tar|csv|log|html?|sh|go|rs|java|kt|swift)")
# an id in capitals and digits: a key id, a serial number, a licence, a ticket (AKIA…, SN4711X9). A secret of this
# alphabet has a rule of its own (the access key id has none: it names a key)
_CAPS_ID_RE = _Lazy(r"[A-Z0-9]+")
# the scripts of East Asia and the full-width signs: a sentence there needs no blank (密码：至少8位)
_WIDE_RE = _Lazy("[\\u3000-\\u9fff\\uac00-\\ud7af\\uff00-\\uffef]")


def _credential_word(v: str) -> bool:
    """One value without blanks reads as a credential by the checks the detector already has: the value of a password
    label (detect._pw_literal_ok: no word after undoing leet with evidence of chance, or a word, a number and a sign),
    or a key above the entropy floor of its alphabet (0.6.24) that reads as no word. A digest or an id in hex, an
    assignment, a version pin, an id in capitals and digits, a date, an issue, a file name, a version, a word of a
    language (detect.reads_as_word), a placeholder word and a sentence of East Asia are no credential."""
    from . import detect
    if len(v) < 8 or any(c.isspace() for c in v) or _ASSIGNMENT_RE.fullmatch(v) or _PIN_RE.fullmatch(v):
        return False
    core = v.strip(_AROUND)
    if _HEX_ID_RE.fullmatch(core) or _CAPS_ID_RE.fullmatch(core) or _WIDE_RE.search(v):
        return False
    if v.endswith(":") and _LABEL_RE.fullmatch(core):
        return False   # a label of YAML or of a list (`npm-github:`)
    if _DATE_ID_FILE_RE.fullmatch(core) or _SEMVER_RE.fullmatch(core) or detect.reads_as_word(core):
        return False   # a date, an issue, a file, a version; a name or a label (`npm-github:`, `Wartungsfenster`)
    if _PLACEHOLDER_WORD_RE.search(v):
        return False
    return detect.bare_value_is_a_credential(v)


def looks_like_a_credential(value: str) -> bool:
    """Whether a check stores a value that no rule caught. One word: _credential_word. A passphrase with blanks:
    each word holds a letter and a digit or a sign (the signs around a word of a sentence do not count), no word is
    code (a quote, a bracket, `=`, a flag) or a hex id, and the words joined pass _credential_word. Plain prose
    (`correct horse battery staple`, `Call me at 5!`) and a command line are never stored by a check;
    /maisecrets:put stores such a value on purpose."""
    words = value.split()
    if not words:
        return False
    if len(words) == 1:
        # a quoted or bracketed word is judged without its quotes: `"wartung",` is a word of code
        return _credential_word(words[0].strip(_AROUND) if words[0][0] in _CODE_SIGNS else words[0])
    for w in words:
        core = w.strip(_AROUND)
        if (not any(c.isalpha() for c in core) or core.isalpha() or _CODE_SIGNS & set(core) or core.startswith("-")
                or _HEX_ID_RE.fullmatch(core)):
            return False
    return _credential_word("".join(words))
