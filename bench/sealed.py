"""A sealed split of an external dataset: dev, val and holdout, written once outside the repository.

A record goes to a split by its group, so one document (or one dialogue in all its languages) never crosses splits:
the first 8 hex digits of HMAC-SHA256(salt, group) modulo 10, 0-5 `dev`, 6-7 `val`, 8-9 `holdout`. The halves are
written read-only and their sha256 is pinned in the loader; a read refuses a file that differs. No function here prints
a value or a text."""
from __future__ import annotations

import collections
import hashlib
import hmac
import json
import os
from pathlib import Path

SPLITS = ("dev", "val", "holdout")
CASES_FILE = "cases.jsonl"


class DataError(ValueError):
    """The data does not have its pinned shape. The message names a place, never a value."""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def split_of(salt: bytes, group: str) -> str:
    n = int(hmac.new(salt, group.encode("utf-8"), hashlib.sha256).hexdigest()[:8], 16) % 10
    return "dev" if n < 6 else "val" if n < 8 else "holdout"


def write(records, salt: bytes, out: Path) -> dict:
    """Write OUT/<split>/cases.jsonl from records that carry a `group`, read-only. Refused when a split exists."""
    lines = {s: [] for s in SPLITS}
    counts = collections.Counter()
    groups = {s: set() for s in SPLITS}
    for rec in records:
        s = split_of(salt, rec["group"])
        lines[s].append(json.dumps(rec, sort_keys=True, ensure_ascii=False))
        groups[s].add(rec["group"])
        counts[f"{s} records"] += 1
    for s in SPLITS:
        counts[f"{s} groups"] = len(groups[s])
        if (Path(out) / s / CASES_FILE).exists():
            raise DataError(f"{s}/{CASES_FILE} exists: the split is sealed")
    hashes = {}
    for s in SPLITS:
        d = Path(out) / s
        d.mkdir(parents=True, exist_ok=True)
        data = ("\n".join(lines[s]) + "\n").encode("utf-8")
        f = d / CASES_FILE
        f.write_bytes(data)
        os.chmod(f, 0o444)
        hashes[s] = sha(data)
    return {"counts": dict(counts), "sha256": hashes}


def read(data: Path, split: str, sealed: dict, name: str):
    """The records of one sealed split, refused when its file differs from the seal or more than one is asked for."""
    if split not in SPLITS:
        raise DataError(f"{name} has the splits {', '.join(SPLITS)}, one at a time")
    f = Path(data) / split / CASES_FILE
    if not f.is_file():
        raise DataError(f"{split}/{CASES_FILE} is missing: run the seal of bench/{name}.py first")
    raw = f.read_bytes()
    if sha(raw) != sealed.get(split):
        raise DataError(f"{split}/{CASES_FILE} does not match its sealed sha256")
    for line in raw.decode("utf-8").split("\n"):
        if line.strip():
            yield json.loads(line)


def trim(text: str, start: int, end: int) -> tuple:
    """A span without the white space at its ends (a label that took the space after a word)."""
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def verify(data: Path, sealed: dict) -> dict:
    return {s: (Path(data) / s / CASES_FILE).is_file()
            and sha((Path(data) / s / CASES_FILE).read_bytes()) == sealed.get(s) for s in SPLITS}
