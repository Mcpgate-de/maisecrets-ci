#!/usr/bin/env python3
"""The nym multilingual PII set (`Wismut/nym-pii-multilingual-data`, MIT; docs/BENCHMARK-V3.md, "External PII sets").

    python3 -I bench/nym.py seal RAW_DIR DATA_DIR     split train/validation/test.jsonl into DATA_DIR/<split>, once
    python3 -I bench/nym.py verify DATA_DIR           each split still matches its pinned sha256

805,000 synthetic texts in about 23 languages. A local LLM wrote templates with `[LABEL]` slots, Faker filled them, so
each span is exact by construction (Python character offsets); about 13 % are texts without a span and about 20 % carry
OCR or typing noise. The values are fake, but no script here prints a value or a text.

The split is by template: the group is the sequence of the labels of a text (5,444 sequences for the card's 5,959
template shapes), so the fills of one template never lie in two splits (bench/sealed.py, salt below); two templates
with the same sequence share a group. A text without a span is grouped by its letters, so a noisy fill of a negative
template can fall into another split. The record id is `<file>/<line>` of the pinned revision. Holdout: never read,
totals only."""
from __future__ import annotations

import collections
import hashlib
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench import sealed  # noqa: E402
from bench.sources import TYPE_CLASS  # noqa: E402

NAME = "nym"
URL = "https://huggingface.co/datasets/Wismut/nym-pii-multilingual-data"
REVISION = "abe23bf08c305f5824b1643dc4f079f06ccb2ad1"
LICENCE = "MIT"
FILES = {"train": "ca04c6c56b9cfa3e702b5c8c541ada60c9e3c0fb4ad6866d8940550753636afb",
         "validation": "2970f8eabdfc1a956cd0001e931fb1427476ae1819b2978d7aebf2475bb24d4e",
         "test": "7b07818ec2767c0ac81b91ed3701771d5f23038da1b71ba4705f02fa5fe85ff9"}
SALT = b"maisecrets/nym/2026-10-25"
# the sealed splits (2026-10-25): sha256 of DATA_DIR/<split>/cases.jsonl
SEALED = {"dev": "234eeac791def8fbc5b4980531d6e0bddbcc39617b9f99298f96f1e48b87d3cc",
          "val": "84c5989f805bbba4b3b885e4403e6bcc6e97a4b8071501facd31d76aeb403ec9",
          "holdout": "5d4a711b9d732a4111a808f8a03af42dc4120a1bcb0de091ea43d6e4d8ea0fee"}

# the labels of the set to the classes of the benchmark; a label that is absent here is neutral (a finding on it is
# neither right nor wrong). Fixed on aggregate counts of dev (docs/BENCHMARK-V3.md, "External PII sets").
# The map follows Nemotron's in scripts/measure_datasets.py where the label names agree: city, state, country, ZIP,
# dates, times, ages, gender, company, URL, MAC, CVV, PIN, SWIFT, customer and employee ids and plates are neutral.
LABEL_CLASS = {
    "GIVEN_NAME": TYPE_CLASS["NAME"], "SURNAME": TYPE_CLASS["NAME"], "EMAIL": TYPE_CLASS["EMAIL"],
    "PHONE": TYPE_CLASS["PHONE"], "FAX_NUMBER": TYPE_CLASS["PHONE"], "DATE_OF_BIRTH": TYPE_CLASS["BIRTH_DATE"],
    "STREET_ADDRESS": TYPE_CLASS["ADDRESS"], "STREET_NAME": TYPE_CLASS["ADDRESS"],
    "BUILDING_NUMBER": TYPE_CLASS["ADDRESS"], "SECONDARY_ADDRESS": TYPE_CLASS["ADDRESS"],
    "CREDIT_DEBIT_CARD": TYPE_CLASS["CARD"], "IBAN": TYPE_CLASS["IBAN"],
    "ACCOUNT_NUMBER": TYPE_CLASS["US_BANK_NUMBER"], "ROUTING_NUMBER": TYPE_CLASS["ABA_ROUTING_NUMBER"],
    "SSN": TYPE_CLASS["US_SSN"], "GOVERNMENT_ID": TYPE_CLASS["ID_NUMBER"], "PASSPORT": TYPE_CLASS["ID_NUMBER"],
    "DRIVERS_LICENSE": TYPE_CLASS["ID_NUMBER"], "TAX_ID": TYPE_CLASS["ID_NUMBER"],
    "MEDICAL_RECORD_NUMBER": TYPE_CLASS["ID_NUMBER"], "USERNAME": TYPE_CLASS["USERNAME"],
    "PASSWORD": "secret.password", "API_KEY": "secret.token",
}
NEUTRAL = ("AGE", "CITY", "COMPANY_NAME", "COUNTRY", "CUSTOMER_ID", "CVV", "DATE", "EMPLOYEE_ID", "GENDER",
           "LICENSE_PLATE", "MAC_ADDRESS", "PIN", "STATE", "SWIFT_BIC", "TIME", "URL", "ZIP_CODE")


def group_of(text: str, entities: list) -> str:
    """The template of a fill: the sequence of its labels in text order. A text without a span: its letters outside
    any span, case-folded. (The first key, the letters around the labels, gave 143,535 groups for about 5,959
    template shapes, because noise and inflected values change the letters; it was discarded before any read.)"""
    if entities:
        key = "\x00".join(e["label"] for e in sorted(entities, key=lambda e: (e["start"], e["end"])))
    else:
        key = "\x01" + "".join(ch for ch in text.casefold() if ch.isalpha())
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def raw_records(raw: Path):
    for name, digest in FILES.items():
        f = Path(raw) / f"{name}.jsonl"
        data = f.read_bytes()
        if sealed.sha(data) != digest:
            raise sealed.DataError(f"{name}.jsonl does not match its pinned sha256")
        for n, line in enumerate(data.decode("utf-8").split("\n")):
            if line.strip():
                r = json.loads(line)
                labelled = [{"start": int(e["start"]), "end": int(e["end"]), "label": str(e["label"])}
                            for e in r["entities"]]
                yield {"id": f"{name}/{n}", "group": group_of(r["text"], labelled), "text": r["text"],
                       "entities": labelled}


def cases_of(record: dict, split: str, stats: collections.Counter):
    """The case of one record, in the tool channel like the other PII sets (scripts/measure_datasets.py): maisecrets
    takes names, addresses and birth dates in a tool result only (maisecrets/detection/personal.py, `hits`)."""
    text, spans = record["text"], []
    for e in record["entities"]:
        if not (0 <= e["start"] < e["end"] <= len(text)):
            stats["spans outside the text (left out)"] += 1
            continue
        start, end = sealed.trim(text, e["start"], e["end"])
        if end <= start:
            stats["spans of white space only (left out)"] += 1
            continue
        if (start, end) != (e["start"], e["end"]):
            stats["spans with outer space (trimmed)"] += 1
        cls = LABEL_CLASS.get(e["label"])
        sp = {"start": start, "end": end, "class": cls or "pii.other", "label": e["label"]}
        if cls is None:
            sp["neutral"] = True
        spans.append(sp)
    stats["cases"] += 1
    yield {"id": f"{NAME}/{record['id']}", "text": text, "channel": "tool", "context": "prose", "path": None,
           "spans": sorted(spans, key=lambda s: (s["start"], s["end"])), "split": split, "tags": [],
           "region": "-", "lang": "-",
           "source": {"name": NAME, "url": URL, "revision": REVISION, "licence": LICENCE, "record": record["id"]}}


def load(data: Path, split: str, stats: collections.Counter, limit: int = 0):
    n = 0
    for rec in sealed.read(data, split, SEALED, NAME):
        for case in cases_of(rec, split, stats):
            yield case
            n += 1
            if limit and n >= limit:
                return


def main(argv) -> int:
    if argv[:1] == ["seal"] and len(argv) == 3:
        print(json.dumps(sealed.write(raw_records(Path(argv[1])), SALT, Path(argv[2])), indent=1, sort_keys=True))
        return 0
    if argv[:1] == ["verify"] and len(argv) == 2:
        for s, ok in sealed.verify(Path(argv[1]), SEALED).items():
            print(f"{s}: {'matches the seal' if ok else 'DIFFERS from the seal or is missing'}")
        return 0
    sys.stderr.write(__doc__ + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
