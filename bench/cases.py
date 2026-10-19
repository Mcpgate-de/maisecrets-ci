"""The case format of Benchmark V1 (docs/BENCHMARK-V1.md, "The case format"): load a case file of the bank, read its
marks, and give each public record its split.

A case file of the bank is JSON Lines. Its text cannot hold a real-looking secret (scripts/scan_tree.py scans the
tree), so the author writes two marks that the loader removes: `§` splits a value, and `«` `»` enclose an expected
span. The classes of the spans are in `spans`, in the order of the marks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SPLIT_MARK = "§"            # §
OPEN, CLOSE = "«", "»"  # « »
CHANNELS = ("prompt", "tool")
CONTEXTS = ("prose", "shell", "log", "json", "yaml", "config", "code", "stacktrace", "doc", "url")
SPLITS = ("dev", "val", "holdout")
FAMILIES = ("secret", "pii")
CLASSES = (
    "secret.token", "secret.webhook", "secret.url_credential", "secret.password", "secret.private_key",
    "secret.connection_string", "secret.generic",
    "pii.email", "pii.phone", "pii.iban", "pii.card", "pii.national_id", "pii.tax_id", "pii.name", "pii.address",
    "pii.birth_date", "pii.username", "pii.ip", "pii.bank_account",
)


class CaseError(ValueError):
    pass


def split_of(source: str, record: str) -> str:
    """The split of a public record: the first 8 hex digits of sha256("<source>/<record>") modulo 10; 0-5 dev,
    6-7 val, 8-9 holdout. A new release of a source keeps the split of each old record."""
    n = int(hashlib.sha256(f"{source}/{record}".encode()).hexdigest()[:8], 16) % 10
    return "dev" if n < 6 else "val" if n < 8 else "holdout"


def unmark(raw: str) -> tuple[str, list[tuple[int, int]]]:
    """Remove the § splits and the « » marks; return the text and the offsets of each marked span."""
    raw = raw.replace(SPLIT_MARK, "")
    out, spans, start = [], [], None
    for ch in raw:
        if ch == OPEN:
            if start is not None:
                raise CaseError("a « inside a marked span")
            start = sum(map(len, out))
        elif ch == CLOSE:
            if start is None:
                raise CaseError("a » without its «")
            spans.append((start, sum(map(len, out))))
            start = None
        else:
            out.append(ch)
    if start is not None:
        raise CaseError("a « without its »")
    return "".join(out), spans


def bank_case(obj: dict, where: str) -> dict:
    """One case of the bank: check the fields, read the marks, put the offsets into the spans."""
    for key in ("id", "text", "channel", "context", "spans", "split", "source"):
        if key not in obj:
            raise CaseError(f"{where}: no {key}")
    if obj["channel"] not in CHANNELS or obj["context"] not in CONTEXTS or obj["split"] not in SPLITS:
        raise CaseError(f"{where}: channel, context or split is not one of the known values")
    if not safe_path(obj.get("path")):
        raise CaseError(f"{where}: the path is absolute or leaves its folder")
    text, marks = unmark(obj["text"])
    if len(marks) != len(obj["spans"]):
        raise CaseError(f"{where}: {len(marks)} marked spans, {len(obj['spans'])} in spans")
    spans = []
    for (s, e), sp in zip(marks, obj["spans"]):
        if sp.get("class") not in CLASSES:
            raise CaseError(f"{where}: unknown class {sp.get('class')!r}")
        if e <= s:
            raise CaseError(f"{where}: an empty span")
        for rng in ([sp["core"]] if "core" in sp else []) + list(sp.get("alt", [])):
            if not (isinstance(rng, (list, tuple)) and len(rng) == 2
                    and all(isinstance(x, int) and not isinstance(x, bool) for x in rng) and s <= rng[0] < rng[1] <= e):
                raise CaseError(f"{where}: a core or alt range is not a non-empty range inside its span")
        spans.append({**sp, "start": s, "end": e})
    return {**obj, "text": text, "spans": spans}


def load_bank(directory: Path, split: str | None = None) -> list[dict]:
    """Every case of the *.jsonl files under directory, sorted by id; ids must be unique."""
    cases, seen = [], set()
    for f in sorted(Path(directory).rglob("*.jsonl")):
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            case = bank_case(json.loads(line), f"{f.name}:{n}")
            if case["id"] in seen:
                raise CaseError(f"{f.name}:{n}: the id {case['id']} is there twice")
            seen.add(case["id"])
            if split is None or case["split"] == split:
                cases.append(case)
    return sorted(cases, key=lambda c: c["id"])


def safe_path(path) -> bool:
    """A case path is relative and stays below its folder: a file scanner writes the case there."""
    if path is None:
        return True
    parts = str(path).replace("\\", "/").split("/")
    return bool(path) and not str(path).startswith(("/", "\\")) and ":" not in str(path) and ".." not in parts


def family(cls: str) -> str:
    return cls.split(".", 1)[0]


def in_scope(cls: str, scope) -> bool:
    return any(cls == s or cls.startswith(s) for s in scope)
