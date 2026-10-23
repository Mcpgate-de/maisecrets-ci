#!/usr/bin/env python3
"""Draft prefix rules from researched token formats (docs/DETECTION-COVERAGE.md, loop 6).

    python3 scripts/draft_researched_rules.py FORMATS.jsonl [--out DIR]

FORMATS.jsonl holds one researched format per line: `provider`, `variant`, `regex` (the whole token, Python `re`, no
anchors), `source` (a URL pinned to a commit, or a dated page) and `evidence` (`code`, `doc` or `announcement`: the
provider's own code or documentation). A format found only in a third-party scanner is no evidence here: that is
loop 2 (scripts/draft_format_rules.py).

For each format the script generates tokens from its regex (five seeds) and keeps a draft rule only when:

- the evidence is the provider's own, and the format is no public id (client id, publishable key, public key);
- the regex starts with a literal of four characters or more that holds a letter and is no generic word (`live_`,
  `test_`, `access_`, …): a generic start would match names in code;
- no existing rule finds any of the tokens whole already (a format of another length is often only a variant);
- the drafted rule finds every token whole: bare, in a sentence, after a label, and before `.`, `,` and `)` (a body
  that may end on a dot or a colon took the full stop into the value in 0.7.10).

It writes, never with a token: DIR/prefixes-draft.txt (lines in the form of rules/prefixes.txt), DIR/sources-draft.txt
(the `(id, regex)` pairs for SOURCES in tests/test_researched_formats.py, the oracle kept apart from the rule) and
DIR/dropped.txt (each format left out and why). Nothing is added by itself: a person or an agent reviews the draft,
runs the false-positive bank, scripts/measure_catalog_coverage.py and the release gate, and merges.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import measure_catalog_coverage as mcc  # noqa: E402
from draft_format_rules import P, lead_split, lit, unparse  # noqa: E402

EVIDENCE = ("code", "doc", "announcement")
PUBLIC = re.compile(r"(?i)client.?id|app.?id|application.?id|publishable|public|site.?key|pub.?key|key.?id\b")
GENERIC = re.compile(r"(?i)^(?:live|test|prod|dev|access|account|master|private|secret|token|key|api|pat|sat|auth)"
                     r"[_.:-]?$")
SEEDS = 5


def detector():
    from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host
    return Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="draft"),
                    sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="b", year=2026))


def found_by(det, tok: str) -> str | None:
    """The kind of an existing finding that takes the token whole, bare in a sentence."""
    text = f"is {tok} ok"
    return next((m.kind for m in det.findings(text, channel="tool", path="") if m.start == 3
                 and m.end == 3 + len(tok)), None)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:50].rstrip("-")


def takes_whole(crx: re.Pattern, tok: str) -> bool:
    texts = (tok, f"x {tok} y", f"key={tok}\n", f"is {tok}. ok", f"a {tok}, b", f"({tok})")
    return all(any(m.group(0) == tok for m in crx.finditer(t)) for t in texts)


def draft(rows: list, det, existing: set) -> tuple:
    """(kept, dropped): kept are dicts with id, line and source; dropped maps a name to its reason."""
    kept, dropped, used = [], {}, set(existing)
    for r in rows:
        name = f"{r.get('provider', '')} {r.get('variant', '')}".strip()
        rx = r.get("regex") or ""
        if r.get("evidence") not in EVIDENCE or not r.get("source"):
            dropped[name] = "no first-party source"
            continue
        if PUBLIC.search(name):
            dropped[name] = "a public id"
            continue
        try:
            lead, rest = lead_split(list(P.parse(rx)))
            body = unparse(rest)
        except Exception as e:  # noqa: BLE001 - an unusual pattern is left out, with its reason
            dropped[name] = f"pattern: {type(e).__name__}"
            continue
        if len(lead) < 4 or not re.search(r"[A-Za-z]", lead):
            dropped[name] = "no literal start of four characters"
            continue
        if GENERIC.match(lead):
            dropped[name] = f"generic start {lead!r}"
            continue
        rnd = random.Random(name)
        toks = [mcc.new_secret(rx, rnd) for _ in range(SEEDS)]
        if not all(t and re.fullmatch(rx, t) for t in toks):
            dropped[name] = "no token from the regex"
            continue
        other = next((k for k in (found_by(det, t) for t in toks) if k), None)
        if other:
            dropped[name] = f"found already by {other}"
            continue
        esc = "".join(lit(ord(ch)) for ch in lead)
        line_rx = f"{esc}(?:(?<![A-Za-z0-9_-]{esc})|(?<=\\\\[nrt]{esc})){body}(?![A-Za-z0-9_-])"
        try:
            crx = re.compile(line_rx)
        except re.error:
            dropped[name] = "does not compile"
            continue
        if not all(takes_whole(crx, t) for t in toks):
            dropped[name] = "the rule does not take every token whole (a body that may end on a dot or a colon?)"
            continue
        rid = slug(name)
        if rid in used:
            rid = slug(name + " bare")
        if rid in used:
            dropped[name] = f"id {rid} is taken"
            continue
        used.add(rid)
        kept.append({"id": rid, "line": f"{rid:50s} {line_rx}", "source": rx})
    return kept, dropped


def main(argv: list) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("formats", type=Path)
    ap.add_argument("--out", type=Path, default=Path("format-drafts"))
    a = ap.parse_args(argv)
    rows = [json.loads(line) for line in a.formats.read_text(encoding="utf-8").splitlines() if line.strip()]
    det = detector()
    kept, dropped = draft(rows, det, {r.id for r in det.rules()})
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "prefixes-draft.txt").write_text("".join(k["line"] + "\n" for k in kept), encoding="utf-8")
    (a.out / "sources-draft.txt").write_text("".join(f"    ({k['id']!r},\n     {k['source']!r}),\n" for k in kept),
                                             encoding="utf-8")
    (a.out / "dropped.txt").write_text("".join(f"{k}\t{v}\n" for k, v in sorted(dropped.items())), encoding="utf-8")
    print(f"{len(rows)} formats: drafted {len(kept)} prefix rules; left out {len(dropped)} "
          f"(see {a.out / 'dropped.txt'})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
