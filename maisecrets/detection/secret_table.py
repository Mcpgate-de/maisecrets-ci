"""The values under a secret column of a table whose cells a bar or a tab separates, for personal.py (moved here:
personal.py is at the size limit of the release tree)."""
from __future__ import annotations

import re

from .lazy_regex import LazyRx as _LazyRx

# a header that names a secret besides a password (_password_column): a secret, a token, a passcode, a PIN. The
# columns of a table separated by bars or tabs, with or without the separator row of Markdown (field case, 2026-11-08:
# | Account | Passwort | with a password on each row; `Account | Password` and tab tables stayed in the clear)
_SECRET_COL_RE = _LazyRx(r"(?:(?!(?:hash|hashed|encrypted|enc|crypt|crypted|salted|salt|is|has)_)[a-z0-9]{1,16}_){0,2}"
                         r"(?:secret|token|passcode|kenncode|zugangscode)")
_PIN_COL_RE = _LazyRx(r"(?:[a-z0-9]{1,16}_)?pin(?:_?code|_?nummer|_?number)?")
_TABLE_HEAD_RE = _LazyRx(r"[^\W\d_][\w.-]{0,30}(?: [\w.-]{1,30}){0,3}")
_MD_SEP_LOOSE_RE = _LazyRx(r"[ \t]*\|?(?:[ \t]*:?-+:?[ \t]*\|)+(?:[ \t]*:?-+:?[ \t]*)?")
_IDENTIFIER_RE = _LazyRx(r"[A-Z][A-Z0-9_]*")


def _secret_column(name: str) -> str:
    """"password" for a column of passwords, secrets or tokens, "pin" for one of PINs, "" for any other."""
    from .personal import _fold, _password_column
    folded = _fold(re.sub(r"_{2,}", "_", name))
    if _password_column(name) or _SECRET_COL_RE.fullmatch(folded):
        return "password"
    return "pin" if _PIN_COL_RE.fullmatch(folded) else ""


def _pin_cell(v: str) -> bool:
    """4 to 8 digits, no placeholder (0000, 1234) and no year."""
    from .personal import _placeholder_digits
    return v.isascii() and v.isdigit() and 4 <= len(v) <= 8 and not _placeholder_digits(v) \
        and not (len(v) == 4 and v[:2] in ("19", "20"))


def _row_cells(line: str, sep: str) -> list:
    if sep == "|":
        from .personal import _md_cells
        return _md_cells(line)
    out, a = [], 0
    for part in line.split("\t"):
        out.append((a, a + len(part)))
        a += len(part) + 1
    return out


def secret_table_hits(text: str) -> list:
    """The values under a secret column of a table whose cells a bar or a tab separates. The header row is column names
    only; each row has the header's number of cells, and an empty line or another shape ends the table."""
    from .personal import _CSV_ROWS, _md_column, _password_cell
    out = []
    lines = text.split("\n")
    pos = [0]
    for ln in lines:
        pos.append(pos[-1] + len(ln) + 1)
    li = 0
    while li < len(lines) - 1:
        hdr = lines[li]
        sep = "|" if "|" in hdr else "\t" if "\t" in hdr else ""
        li += 1
        if not sep or len(hdr) > 2000:
            continue
        head = [hdr[a:b].strip().strip("*`").strip() for a, b in _row_cells(hdr, sep)]
        kinds = [_secret_column(_md_column(h)) for h in head]
        if len(head) < 2 or not any(kinds) or not all(_TABLE_HEAD_RE.fullmatch(h) for h in head):
            continue
        if sep == "|" and _MD_SEP_LOOSE_RE.fullmatch(lines[li]):
            li += 1
        rows = 0
        while li < len(lines) and rows < _CSV_ROWS:
            line = lines[li]
            cells = _row_cells(line, sep) if line.strip() and sep in line else []
            if len(cells) != len(head):
                break
            for (a, b), kind in zip(cells, kinds):
                v = line[a:b].strip().strip("*`")
                if kind and v and (_pin_cell(v) if kind == "pin" else
                                   _password_cell(v) and not _IDENTIFIER_RE.fullmatch(v)):
                    s0 = pos[li] + a + line[a:b].index(v)
                    out.append((s0, s0 + len(v), "secret-under-password-column", "SECRET"))
            li += 1
            rows += 1
    return out
