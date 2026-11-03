#!/usr/bin/env python3
"""Write maisecrets/detection/rules/leading_literals.json: the leading literal of each built-in pattern of every
region and language, and for a pattern without one the literals one of which every match holds, so a hook process
reads them instead of parsing 920 patterns (prefilter.leading_literal, prefilter.required_literals).

    python3 scripts/gen_leading_literals.py          # write the file
    python3 scripts/gen_leading_literals.py --check  # exit 1 when the file differs from the patterns

tests/test_leading_literals.py runs the same check."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from maisecrets.detection import core, prefilter, registry  # noqa: E402
from maisecrets.detection.regions import REGION_LANGUAGE, Active, label_languages_available  # noqa: E402


def every_region() -> Active:
    return Active(regions=("generic", *sorted(REGION_LANGUAGE)), languages=tuple(label_languages_available()),
                  source="leading literals")


def wanted() -> dict:
    """{key: [literal, ignore_case]} for each built-in pattern that leading_literal would parse."""
    out = {}
    for source, rules in core._rule_sources(every_region()):
        for r in rules:
            matcher = registry.matcher_of(r.id, source)
            pattern = getattr(r.regex, "pattern", None)
            if r.keywords or source == "user" or matcher not in ("", "regex") or not isinstance(pattern, str):
                continue
            lit, icase = prefilter.parsed_literal(r.regex)
            entry = [lit, bool(icase) if lit else False]
            if not lit:      # the literals one of which every match holds (prefilter.required_literals)
                entry.append(list(prefilter.parsed_required(r.regex)))
            out[prefilter.literal_key(pattern, r.regex.flags)] = entry
    return dict(sorted(out.items()))


def main(argv: list) -> int:
    want = wanted()
    text = json.dumps(want, indent=0, ensure_ascii=True) + "\n"
    if "--check" in argv:
        have = prefilter.LITERALS_FILE.read_text(encoding="utf-8") if prefilter.LITERALS_FILE.exists() else ""
        if have != text:
            print(f"{prefilter.LITERALS_FILE.relative_to(ROOT)} is stale: run scripts/gen_leading_literals.py")
            return 1
        print(f"leading literals: {len(want)} patterns, up to date")
        return 0
    prefilter.LITERALS_FILE.write_text(text, encoding="utf-8")
    print(f"wrote {len(want)} patterns")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
