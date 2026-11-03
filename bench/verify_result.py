"""Compare a result file of bench/run.py with a published one: the same cases, and the same counts.

    python3 bench/verify_result.py MINE.json PUBLISHED.json[.gz]

It compares the hash of the cases, the metrics, the Benchmark V3 block and the outcome of each case; it ignores the
date, the timing, the paths and the commits of the two runs. It prints only the names of the parts that differ, never
a value or a text, and exits 1 when one differs (docs/REPRODUCE.md).
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

PARTS = ("cases_sha256", "metrics", "v3", "per_case")


def load(path: Path) -> dict:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def compare(mine: dict, published: dict) -> list:
    """The parts that differ; a part that one of the two files does not have counts as different."""
    return [p for p in PARTS if p not in mine or p not in published or mine[p] != published[p]]


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    mine, published = load(Path(argv[0])), load(Path(argv[1]))
    differ = compare(mine, published)
    print(f"{mine.get('source')}/{mine.get('split')}: {mine.get('cases')} cases; "
          + ("the same cases and the same counts" if not differ else "differs in: " + ", ".join(differ)))
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
