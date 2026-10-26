#!/usr/bin/env python3
"""Set B of the structured corpus: the independent holdout (docs/BENCHMARK-STRUCTURED.md, "The holdout SPEC").

    python3 bench/structured_b.py verify CASES_FILE      the file matches its seal; prints counts only

A second author wrote set B from the SPEC alone, without sight of set A, a miss list or the detector
(ATTESTATION.json in the private directory). Its templates, generators and cases stay private. This module knows only
the seal: the sha256 of `cases.jsonl` and the counts of MANIFEST.json, which bench/HOLDOUT-LOG.md records.

`bench/run.py --source structured-b --holdout CASES_FILE --release-candidate` runs a scanner on it. The run is refused
when the sha256 differs, and it writes totals only: no case id, no outcome per case, no value (bench/run.py, the
holdout path). Run it once per release candidate; never write or tune a rule on its totals."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from bench import cases as casefmt  # noqa: E402

NAME = "structured-b"
# the seal of 2026-10-25 (bench/HOLDOUT-LOG.md, "Structured corpus, set B")
SHA256 = "bdcb963988f169d65089305783b1507d1b8e31c16e1ce055466f996de57c03b9"
CASES = 2000
NEGATIVE_CASES = 500


class SealError(ValueError):
    """The file is not the sealed set B. The message names a count or a field, never a value."""


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _case(obj: dict, n: int) -> dict:
    """One case in the format of bench/cases.py: spans with start and end, or the « » marks of the bank."""
    where = f"line {n}"
    if obj.get("split") != "holdout" or (obj.get("source") or {}).get("name") != NAME:
        raise SealError(f"{where}: split or source.name is not holdout / {NAME}")
    spans = obj.get("spans", [])
    if all("start" in s and "end" in s for s in spans):
        text = obj["text"]
        for s in spans:
            if s.get("class") not in casefmt.CLASSES or not 0 <= s["start"] < s["end"] <= len(text):
                raise SealError(f"{where}: a span with an unknown class or outside the text")
        if obj.get("channel") not in casefmt.CHANNELS or obj.get("context") not in casefmt.CONTEXTS:
            raise SealError(f"{where}: channel or context is not one of the known values")
        return obj
    try:
        return casefmt.bank_case(obj, where)
    except casefmt.CaseError as e:
        raise SealError(str(e)) from None


def verify(path: Path, sha256: str = SHA256, count: int = CASES) -> list:
    """The cases of the sealed file, or SealError: the sha256 first, then the count, the split and the classes."""
    path = Path(path)
    if not path.is_file():
        raise SealError("no cases file")
    if sha256_of(path) != sha256:
        raise SealError("the sha256 of the cases file differs from the seal")
    out = [_case(json.loads(line), n) for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
           if line.strip()]
    if len(out) != count:
        raise SealError(f"{len(out)} cases, the seal says {count}")
    if len({c["id"] for c in out}) != len(out):
        raise SealError("a case id is there twice")
    return out


def main(argv) -> int:
    if len(argv) != 2 or argv[0] != "verify":
        sys.stderr.write(__doc__)
        return 2
    try:
        cs = verify(Path(argv[1]))
    except SealError as e:
        print(f"refused: {e}")
        return 1
    negative = sum(1 for c in cs if not any(not s.get("neutral") for s in c["spans"]))
    print(f"{len(cs)} cases ({negative} negative) match the seal {SHA256[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
