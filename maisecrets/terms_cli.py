"""`maisecrets terms`: the term lists (maisecrets/terms.py) and `terms suggest FILE`.

`terms` prints counts, labels, files and line numbers, never a term: the output goes to the model when the agent runs
it. `terms suggest` prints no name, not in a terminal either (an agent can open a pseudo-terminal): it overwrites the
private proposal terms.suggested.txt in the maisecrets folder (mode 0600, under the terms lock) and prints the count
and the path. The person copies the lines they want; nothing is added to the terms.
"""
from __future__ import annotations

import csv
import io
import re
from collections import Counter
from pathlib import Path

from . import terms

USAGE = ("maisecrets terms                   your term lists: counts, files, lines left out; never a term\n"
         "maisecrets terms suggest FILE      propose terms from a text or CSV file into the private file\n"
         "                                   terms.suggested.txt (overwritten; no name is printed)\n"
         "Add a term: type /maisecrets:term add Jan Kowalski as your prompt, or mark it once as {{Jan Kowalski}}.")


def show() -> int:
    loaded = terms.load(strict=False)
    print("maisecrets terms\n")
    print(f"  {terms._shown_path()}: "
          + (f"unusable: {loaded.error}" if loaded.error else f"{loaded.personal} term(s)"))
    for f in loaded.files:
        print(f"  {f.source}: {f.entities} term(s) · hash {f.digest}")
    print(f"  marked in prompts ({{{{…}}}}): {loaded.marked} name(s), until their lifetime ends")
    if loaded.refused:
        print(f"\nLeft out of the team lists ({len(loaded.refused)}), each with the check it failed:")
        for r in loaded.refused:
            print(f"  {r.source}" + (f" line {r.line}" if r.line else "") + f" · {r.reason}")
    print("\n" + USAGE.rsplit("\n", 1)[1])
    return 1 if loaded.error else 0


# -------------------------------------------------------------- suggest --
_W = r"[^\W\d_]+(?:[-'’][^\W\d_]+)*"          # a word of letters, a hyphen or an apostrophe inside
_SALUTATIONS = frozenset("herr herrn frau mr mrs ms dr prof dear liebe lieber lieben hallo hello hi pan pani "
                         "sehr geehrte geehrter geehrten".split())
_SALUTATION_RE = re.compile(r"\b(?:Herrn?|Frau|Mr|Mrs|Ms|Dr|Prof|Dear|Liebe[rn]?|Hallo|Hello|Hi|Pan|Pani|"
                            r"[Ss]ehr geehrte[rn]?(?: (?:Herr|Frau))?)\.? +"
                            rf"({_W}(?: {_W}){{0,2}})")
_LABEL_RE = re.compile(r"(?im)^\s*(?:name|full name|vorname|nachname|kunde|kundin|customer|client|mandant(?:in)?|"
                       r"patient(?:in)?|contact|kontakt|ansprechpartner(?:in)?|empfänger|recipient)\s*[:=][ \t]*"
                       rf"({_W}(?:[ \t]+{_W}){{0,3}})")
_WORDS_RE = re.compile(_W)
_COLUMN_RE = re.compile(r"(?i)^(?:name|full_?name|first_?name|last_?name|surname|given_?name|vorname|nachname|"
                        r"kunde|customer|client|mandant|contact|kontakt)$")


def _csv_names(text: str) -> list[str]:
    """The values of the name columns of a CSV file (a header with name, vorname, customer, …)."""
    head = text.split("\n", 1)[0]
    if not any(sep in head for sep in ",;\t"):
        return []
    try:
        dialect = csv.Sniffer().sniff(head, delimiters=",;\t")
        rows = list(csv.reader(io.StringIO(text), dialect))
    except csv.Error:
        return []
    if len(rows) < 2:
        return []
    cols = [i for i, h in enumerate(rows[0]) if _COLUMN_RE.match(h.strip())]
    first = [i for i in cols if re.match(r"(?i)first|given|vor", rows[0][i].strip())]
    last = [i for i in cols if re.match(r"(?i)last|sur|nach", rows[0][i].strip())]
    out = []
    for row in rows[1:]:
        if first and last and max(first[0], last[0]) < len(row):
            out.append(f"{row[first[0]].strip()} {row[last[0]].strip()}".strip())
        else:
            out += [row[i].strip() for i in cols if i < len(row)]
    return [x for x in out if x and re.search(r"[^\W\d_]", x)]


def candidates(text: str) -> list[str]:
    """Names in a text, most frequent first: after a salutation, after a `Name:` label, in the name columns of a
    CSV file, and pairs of capitalised words where neither is a common word."""
    stop = terms.stoplist()
    found: Counter = Counter()
    for name in _csv_names(text):
        found[" ".join(name.split())] += 2
    for rx in (_SALUTATION_RE, _LABEL_RE):
        for m in rx.finditer(text):
            words = []
            for w in m.group(1).split():     # the capitalised words that follow
                if not w[0].isupper():
                    break
                words.append(w)
            if words:
                found[" ".join(words)] += 2
    toks = list(_WORDS_RE.finditer(text))
    for x, y in zip(toks, toks[1:]):
        a, b = x.group(), y.group()
        before = text[:x.start()].rstrip()
        if (text[x.end():y.start()] == " " and a[0].isupper() and b[0].isupper() and before
                and before[-1] not in ".!?:\n" and a.lower() not in stop and b.lower() not in stop
                and a.lower() not in _SALUTATIONS):
            found[f"{a} {b}"] += 1
    # a name that only stands inside a longer one is the longer one
    names = [n for n in found if not any(n != o and f" {n} " in f" {o} " for o in found)]
    return sorted(names, key=lambda n: (-found[n], n))


def inflections(name: str, words: set) -> str | None:
    """`stem*` when the last word of the name comes in 2 or more endings in the text, with a stem of 5 or more
    letters: Kowalski, Kowalskiego, Kowalskiej give Kowalsk*."""
    last = name.split()[-1]
    if len(last) < 5:
        return None
    low = last.lower()
    forms = {w for w in words if len(w) >= 5 and w.lower()[:5] == low[:5]}
    if len(forms) < 2:
        return None
    stem = forms.pop()
    for w in forms:
        while not w.lower().startswith(stem.lower()):
            stem = stem[:-1]
    if len(stem) < 5 or not low.startswith(stem.lower()):
        return None
    return stem + "*"


def suggest(args: list[str]) -> int:
    if len(args) != 1:
        print(USAGE)
        return 2
    path = Path(args[0]).expanduser()
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"maisecrets terms suggest: cannot read {path} as UTF-8 text ({type(exc).__name__}). "
              "For a PDF, extract its text first (pdftotext FILE.pdf out.txt).")
        return 1
    names = candidates(text)
    words = set(re.findall(r"[^\W\d_]+", text))
    known = terms.load(strict=False).entities
    known_variants = {v.text.lower() for e in known for v in e.variants}
    lines = []
    for name in names:
        if name.lower() in known_variants:
            continue
        stem = inflections(name, words)
        lines.append(" | ".join([name] + ([stem] if stem else [])))
    # never on the screen: an agent can run this in a pseudo-terminal and read what a terminal shows (codex review of
    # block 2). The proposal goes into the maisecrets folder (C8: the agent cannot read it), mode 0600
    body = (f"# {len(lines)} candidate(s) from {path.name}. Nothing was added. Copy the lines you want into "
            f"{terms._shown_path()} (one name per line; Kowalsk* = any ending), or type /maisecrets:term add NAME.\n"
            + "".join(f"NAME_S{n}  {line}\n" for n, line in enumerate(lines, 1)))
    from .vault import atomic_write
    try:
        with terms._lock():       # a wipe takes the same lock: the proposal never comes back after it
            atomic_write(terms.SUGGESTED, body, mode=0o600)
    except OSError as exc:
        print(f"maisecrets terms suggest: cannot write the proposal ({type(exc).__name__}). Nothing was written.")
        return 1
    print(f"maisecrets terms suggest: {len(lines)} candidate(s) in {path.name}. The proposal is in "
          f"{terms._shown_suggested()}; open it yourself in an editor or a terminal (the AI cannot read that "
          "folder). Nothing was added to your terms.")
    return 0


def main(args: list[str]) -> int:
    if not args:
        return show()
    if args[0] == "suggest":
        return suggest(args[1:])
    print(USAGE)
    return 2
