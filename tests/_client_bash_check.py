"""The first Bash check of Claude Code (2.1.327), ported: it blanks every { inside '…', "…" and `…`, then
refuses a command where an unquoted { has a quote before the next }: "Contains brace with quote character
(expansion obfuscation)". Interactive, the client then asks; headless (`claude -p`), the command does not run
(measured 2026-11-18). A rewrite of maisecrets must never trip it."""
import re

_BRACE_WITH_QUOTE = re.compile(r"""\{[^}]*['"]""")


def _blank_quoted_braces(e: str) -> str:
    if "{" not in e:
        return e
    t: list[str] = []
    sq = dq = bt = False
    word_start = True
    o = 0
    while o < len(e):
        c = e[o]
        if bt:
            if c == "\\" and e[o + 1:o + 2] in ("`", "\\", "$"):
                t += [c, e[o + 1]]
                o += 2
                continue
            if c == "`":
                bt = False
            t.append(" " if c == "{" else c)
            o += 1
        elif sq:
            if c == "'":
                sq = False
            t.append(" " if c == "{" else c)
            o += 1
        elif dq:
            if c == "\\" and e[o + 1:o + 2] in ('"', "\\", "`"):
                t += [c, e[o + 1]]
                o += 2
            elif c == "`":
                bt = True
                t.append(c)
                o += 1
            else:
                if c == '"':
                    dq = False
                t.append(" " if c == "{" else c)
                o += 1
        elif c == "\\" and o + 1 < len(e):
            t += [c, e[o + 1]]
            if e[o + 1] != "\n":
                word_start = False
            o += 2
        elif c == "#" and word_start:
            while o < len(e) and e[o] != "\n":
                t.append(e[o])
                o += 1
            word_start = True
        elif c == "`":
            bt = True
            word_start = False
            t.append(c)
            o += 1
        else:
            if c == "'":
                sq = True
            elif c == '"':
                dq = True
            word_start = c in " \t\n;|&()<>"
            t.append(c)
            o += 1
    return "".join(t)


def refused_as_obfuscation(command: str) -> bool:
    return bool(_BRACE_WITH_QUOTE.search(_blank_quoted_braces(command)))
