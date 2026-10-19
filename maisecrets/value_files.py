"""Where the imported values live (maisecrets/values.py, C26), and whether any import is there.

A hook reads this module alone while no import exists: maisecrets/values.py loads the term matcher (about 13 ms at
import), and every hook call is a new process. values.py reads its files through these names, so the check and the
matcher cannot disagree about a source.

An import is one file `~/.maisecrets/imports/<id>.jsonl` that maisecrets writes itself (0600, in the maisecrets
folder, which the agent cannot read or write: C8). The id is opaque (`v` and 8 hex digits), never the name of the
file it came from: a file named like one of its values would print that value.
"""
from __future__ import annotations

import os
import re

from .lazy_regex import LazyRx as _LazyRx      # compiled at first use: a hook imports this module on every call
from .home import HOME

IMPORTS = HOME / "imports"
SUFFIX = ".jsonl"
CACHE_FILE = HOME / ".values-cache"
STATE_FILE = HOME / ".values-state"     # what the last session start said about the imports
KIND_PREFIX = "import:"
STORE_PREFIX = "maisecrets-import:"     # the store value of an import hit: its ids, never the value
ID_RE = _LazyRx(r"v[0-9a-f]{8}")


def _any_import() -> bool:
    """An import file is there, or the folder cannot be read: values.py then reads it, and a folder it cannot read
    stops the hooks (fail closed). Only a folder that is not there, or holds no import, is no source."""
    try:
        with os.scandir(IMPORTS) as entries:
            return any(e.name.endswith(SUFFIX) for e in entries)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return True


_THERE: list = []    # [bool] of present(), once per process until forget()


def present() -> bool:
    """Whether an import is there, once per process. values.reset() and detect.reset_rules() forget it."""
    if not _THERE:
        _THERE.append(_any_import())
    return _THERE[0]


def forget() -> None:
    _THERE.clear()


def start_note_due(cfg: dict) -> bool:
    """Whether the session start has to load values.py: an import is there, a value file is set, or the last start
    saw an import (an import that went away is said once)."""
    files = cfg.get("value_files")
    return present() or bool(isinstance(files, list) and files) or STATE_FILE.exists()


# ------------------------------------------- what a hook asks without the matcher --
def is_import_kind(kind) -> bool:
    return isinstance(kind, str) and kind.startswith(KIND_PREFIX)


def is_mask_only(kind) -> bool:
    """A hit whose placeholder is never resolved: a term (term_files) or an imported value."""
    return isinstance(kind, str) and kind.startswith(("term:", KIND_PREFIX))


def store_value(kind: str) -> str:
    """What the store keeps for an import hit: the import id and the value id, never the value."""
    return STORE_PREFIX + kind[len(KIND_PREFIX):]


def import_of(kind: str) -> str:
    """The import id of an import hit (`import:<id>:<value id>`)."""
    return kind[len(KIND_PREFIX):].split(":", 1)[0]


# the person's prompt that removes imports: /maisecrets:forget import:ID [import:ID ...], in Codex
# `maisecrets: forget import:ID`. The whole prompt, nothing else
_REMOVAL_RE = _LazyRx(r"\A\s*(?:/maisecrets:forget|maisecrets:[ \t]*forget)\s+((?:import:\S+\s*)+)\Z", re.I)


def parse_removal(prompt) -> list | None:
    """The import ids of a removal prompt, or None when the prompt is no removal."""
    if not isinstance(prompt, str):
        return None
    m = _REMOVAL_RE.match(prompt)
    if not m:
        return None
    return [w[len(KIND_PREFIX):] for w in m.group(1).split()]


# the same removal in a tool call: the prompt typed by a nested client, the CLI form, or the remover called by name.
# A text match (the C22 class): a name built at run time is not seen, which README "Values from your own tools" says.
# The command name and `import:` in either order, at any distance, after quotes and line continuations are taken
# out: a shell joins `"/maisecrets:forget "'import:v1'`, `"…forget "import:v1`, a backslash or backtick line end and a
# printf into the removal prompt (Gate B, round 3). A command that only names both is refused too: acceptable
_FORGET = r"(?:/maisecrets:forget|maisecrets:\s*forget)"
IN_A_COMMAND_RE = _LazyRx(
    _FORGET + r"[\s\S]*?import:|import:[\s\S]*?" + _FORGET
    + r"|\bvalues[\s\"']+(?:remove|forget|delete)\b"
    r"|\b(?:remove_typed|_remove_import|_import_bytes)\b", re.I)
# Each form is checked in turn, and a command is refused when any of them matches, so a later form only adds
# refusals (a strict widening of each round):
# - the line ends of a continuation (a backslash or a backtick before a line break, also inside a word: for\<NL>get)
#   and the quotes, as round 3 had it;
# - every backslash and backtick (an escape inside a word: imp\ort, imp`ort) and a PowerShell `+` with the space
#   around it ('…imp' + 'ort:v1'), as round 4 had it;
# - both, with the line ends of a continuation taken out first: the shell joins the pieces again (Gate B, round 5).
# A form built at run time (brace expansion, an empty variable inside a word, a character code, -join) is not seen:
# the text-match limit of C22, named in README "Values from your own tools".
_JOINED_FORMS = (_LazyRx(r"\\\r?\n|`\r?\n|[\"']"),                # round 3
                 _LazyRx(r"[\"'\\`]|\s*\+\s*"),                        # round 4: keeps the line break of a
                 _LazyRx(r"\\\r?\n|`\r?\n|[\"'\\`]|\s*\+\s*"))     # continuation; round 5 drops it


def removal_in_command(command: str) -> bool:
    """Whether a tool call's command text carries the removal of an import (IN_A_COMMAND_RE): as written, or in one
    of the _JOINED_FORMS."""
    return bool(IN_A_COMMAND_RE.search(command)
                or any(IN_A_COMMAND_RE.search(form.sub("", command)) for form in _JOINED_FORMS))


IN_A_COMMAND = ("maisecrets: this command removes an import of values, which makes detection weaker; only the person "
                "removes one, as their own prompt (/maisecrets:forget import:ID, in Codex: maisecrets: forget "
                "import:ID). The command did not run. Tell the user the prompt to send.")
