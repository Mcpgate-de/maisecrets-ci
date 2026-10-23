"""Where an address with its @ as %40 is an address: a mail word or `=` before it, `sent to` in prose, or a column of
a CSV export whose header names addresses.

maisecrets/detection/core.py imports each name of this module, so `core.<name>` (and `detect.<name>`) is the same
object. A patch of one of these names on the core does not reach the functions of this module: patch this module."""
from __future__ import annotations

import re

from .lazy_regex import LazyRx as _LazyRx
from .text_index import _line_start


# an encoded address is an address after `=` (email=, to=, login=), after mailto%3A, or after a mail word; elsewhere
# name%40version.com is a package, a git ref or an asset name (codex review)
_ENCODED_MAIL_CONTEXT_RE = _LazyRx(
    r"(?i)(?:=|%3d|mailto(?::|%3a)"
    r"|\b(?:to|from|cc|bcc)[ \t]*[:=][ \t]*"   # `to` and `from` alone are paths and imports: path/to/pkg%40v.com
    r"|\b(?:e-?mail|mail|sender|recipient|bounce|reply-to|contact|login|users?|username)[ \t]*[:=/]?[ \t]*)$")
# `sent to name%40host` in prose: `to` and spaces, not `path/to/` or `import x to`
_ENCODED_MAIL_TO_RE = _LazyRx(r"(?i)(?<![/\w])(?:sent|send|mailed|forwarded|reply|replied|receipt|invoice|copy)"
                                 r"[^\n/]{0,20}?(?<![/\w])to[ \t]+$")


def _encoded_mail_expected(text: str, start: int, end: int) -> bool:
    """Where an address with its @ as %40 is an address: after a mail word or `=` (_ENCODED_MAIL_CONTEXT_RE), after
    `sent to` in prose, or as a whole cell of a CSV row (a column of a roster export, holdout 2026-10-15)."""
    line = _line_start(text, start)
    if _ENCODED_MAIL_CONTEXT_RE.search(text, max(line, start - 40), start) or _ENCODED_MAIL_TO_RE.search(
            text, max(line, start - 40), start):
        return True
    value = text[start:end]
    # a cell may have spaces around it (`Dana, name%40host.de`) and quotes ("name%40host.de"), in that order
    while start > line and text[start - 1] == " ":
        start -= 1
    while text[end:end + 1] == " ":
        end += 1
    if text[start - 1:start] == '"' and text[end:end + 1] == '"':
        start, end = start - 1, end + 1   # a quoted cell: "name%40host.de"
        while start > line and text[start - 1] == " ":
            start -= 1
        while text[end:end + 1] == " ":
            end += 1
    before, after = text[start - 1:start] if start > line else "", text[end:end + 1]
    if before not in ("", ",", ";", "\t") or after not in ("", "\n", "\r", ",", ";", "\t") or start - line > 4000:
        return False
    # the column's header names a mail address: a CSV header in the first five lines (a file, an export, a query
    # result with a line before it); a row without such a header stays text (review of 0.6.24)
    sep = before or (after if after in (",", ";", "\t") else ",")
    if not before and not after:
        return False   # a value alone on its line is no cell of a row
    labels = value.rsplit("%40", 1)[-1].lower().split(".")
    if labels[-1] in _FILE_EXTENSIONS or sum(x.isdigit() for x in labels) >= 2:
        return False   # logo%402x.png is an asset at twice the size, pkg%401.0.0-beta.rc a version
    import csv   # here: the hooks pay for every module at import
    col = len(next(csv.reader([text[line:start + 1]], delimiter=sep), [""])) - 1
    # the first five lines of the text, and up to 20 lines above the row within 4,000 characters: a header after a
    # preamble of an export (review of 0.6.25)
    above = text[max(0, line - 4000):max(0, line - 1)].split("\n")[-20:]
    for head in text[:4000].split("\n")[:5] + above[::-1]:
        cells = next(csv.reader([head], delimiter=sep), [])
        # a header holds names, not values: a row with an address in it is data, even with mailbox.org in it. Each
        # line counts on its own: a title line above the header (`Report for user list, 2026-10-01`) does not hide it
        if (len(cells) > col and "%40" not in head and "@" not in head and text.find(head) < line
                and _names_a_mail_column(cells[col])):
            return True
    return False


# a header cell of a column of addresses: a mail word in a few languages, or a word that names who an address
# belongs to (contact, login, user, recipient). Before 0.6.25 only "mail" counted, and an encoded address under a
# header such as `contact` or `login` passed. `to` and `from` are left out: a migration table has them as columns
_MAIL_COLUMN_RE = _LazyRx(r"(?i)mail|courriel|correo|e-?post(?![a-z])|s\u00e4hk\u00f6posti")
# the owner word must be the last word of the header: login_user and user are addresses, end_user_id and
# contact_asset are an id and a file (review of 0.6.25)
_OWNER_WORDS = frozenset({"contact", "contacts", "login", "logins", "user", "users", "username", "usernames",
                          "sender", "recipient", "recipients", "upn", "benutzer", "benutzername", "kontakt",
                          "empf\u00e4nger", "absender", "destinataire", "exp\u00e9diteur", "utilisateur"})
_OWNER_PAIRS = (["user", "name"], ["reply", "to"], ["principal", "name"])
# an owner word before one of these is the same column: Recipient Address, Login Name, sender_addr
_OWNER_TAILS = frozenset({"address", "addr", "name", "adresse"})
# the extension of a file that an asset name ends in: name%402x.png is an image at twice the size
_FILE_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "bmp", "tif", "tiff", "js",
                              "mjs", "cjs", "ts", "css", "map", "json", "html", "htm", "xml", "txt", "pdf",
                              "woff", "woff2", "ttf", "otf", "mp3", "mp4", "webm", "wasm", "gz", "tgz", "jar",
                              "heic", "heif", "lottie", "scss", "sass", "less", "jsx", "tsx", "csv", "yaml", "yml",
                              "toml", "lock", "wav", "ogg", "mov", "zip", "md", "mdx", "vue", "svelte", "rst",
                              "adoc", "ipynb"})


def _names_a_mail_column(cell: str) -> bool:
    cell = cell.strip().strip("\"'")
    if _MAIL_COLUMN_RE.search(cell):
        return True
    words = [w.lower() for w in re.findall(r"[^\W\d_]+", re.sub(r"([^\W\d_])(?<=[a-z\u00df-\u00ff])([A-Z])", r"\1 \2",
                                                                  cell))]
    if words and words[-1] in _OWNER_TAILS and len(words) >= 2 and words[-2] in _OWNER_WORDS:
        return True
    return bool(words) and (words[-1] in _OWNER_WORDS or words[-2:] in _OWNER_PAIRS)
