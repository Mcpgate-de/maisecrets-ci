#!/usr/bin/env python3
"""DialogPII (Zenodo 20863452, version 1.0, CC BY 4.0; docs/BENCHMARK-V3.md, "External PII sets").

    python3 -I bench/dialogpii.py seal ZIP DATA_DIR    split the dialogues into DATA_DIR/<split>, once
    python3 -I bench/dialogpii.py verify DATA_DIR      each split still matches its pinned sha256

Synthetic dialogues of eight scenarios (147 per language) in 11 languages, each as written ("original") and as a
speech-recognition transcript of its reading ("transcript"). Two annotators labelled the English text and a curator
merged it; an LLM translated it with its labels and a reviewer per language corrected them. The labels follow TAB:
names, contact data, codes, places, organisations, professions, products, dates, quantities. The texts are fake;
no script here prints a value or a text. Attribution: the DialogPII authors, doi:10.5281/zenodo.20863452.

The split is by dialogue: the group is `<scenario>/<chat_number>`, so a dialogue lies in one split in every language
and in both forms (bench/sealed.py, salt below). A case is one dialogue, one turn per line as `<speaker>: <text>`.
Holdout: never read, totals only."""
from __future__ import annotations

import collections
import json
import sys
import zipfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench import sealed  # noqa: E402
from bench.sources import TYPE_CLASS  # noqa: E402

NAME = "dialogpii"
URL = "https://zenodo.org/records/20863452"
DOI = "10.5281/zenodo.20863452"
LICENCE = "CC BY 4.0"
ZIP_SHA256 = "70e7d3a419e40034352af550c4d5658fc5f8b663b6731fec689c28b236c9221c"
SALT = b"maisecrets/dialogpii/2026-10-25"
# the sealed splits (2026-10-25): sha256 of DATA_DIR/<split>/cases.jsonl
SEALED = {"dev": "f38e81019e73a68913668325deb10505e981d4cdbec37c49e1a8c3cb60b73447",
          "val": "0521ea3f6b60a2cd96a0a5cdb81d8ed728590c2bfbb90d0c42283f6aca5b1605",
          "holdout": "bb5ea2d32d6a838fb8de0e149f3ceb6f47c857a2873b744016196ab50f4a7421"}
LANG = {"SP": "es"}     # the set's language code to ISO 639-1; the others are their code in lower case

# the labels of the set to the classes of the benchmark; a label that is absent here is neutral (a finding on it is
# neither right nor wrong). Fixed on aggregate counts of dev (docs/BENCHMARK-V3.md, "External PII sets").
# CODE holds ids of many kinds (insurance, passport, account, plate numbers) and so has no one class; it is neutral,
# like the places other than the street, dates, ages, organisations, professions, products, quantities and MISC.
LABEL_CLASS = {"PERSON": TYPE_CLASS["NAME"], "PERSON_EMAIL": TYPE_CLASS["EMAIL"], "CODE_PHONE": TYPE_CLASS["PHONE"],
               "LOC_STREET": TYPE_CLASS["ADDRESS"], "LOC_HOUSENUMBER": TYPE_CLASS["ADDRESS"]}
NEUTRAL = ("CODE", "CODE_URL", "DATETIME", "DATETIME_AGE", "LOC_CITY", "LOC_COUNTRY", "LOC_OTHER", "LOC_ZIP", "MISC",
           "ORG", "PERSON_SOCIAL_RELATION", "PRODUCT", "PROFESSION", "QUANTITY")


def raw_records(zip_path: Path):
    if sealed.sha(Path(zip_path).read_bytes()) != ZIP_SHA256:
        raise sealed.DataError("the zip does not match its pinned sha256")
    with zipfile.ZipFile(zip_path) as z:
        for member in sorted(i.filename for i in z.infolist() if i.filename.endswith(".json")):
            o = json.loads(z.read(member))
            form = "transcript" if "/transcripts/" in member else "original"
            for d in o["dialogs"]:
                group = f"{o['scenario']}/{int(d['chat_number'])}"
                yield {"id": f"{form}/{o['language']}/{group}", "group": group, "form": form,
                       "language": o["language"], "scenario": o["scenario"], "chat_number": int(d["chat_number"]),
                       "version": o["version"], "turns": d["dialog"]["turns"]}


def text_of(record: dict, stats: collections.Counter) -> tuple:
    """The dialogue as one text, one turn per line, and its spans in that text."""
    parts, spans, at = [], [], 0
    for turn in record["turns"]:
        head = f"{turn['speaker']}: "
        body = turn["text"]
        for a in turn["annotations"]:
            s, e = int(a["start"]), int(a["end"])
            if not (0 <= s < e <= len(body)):
                stats["spans outside their turn (left out)"] += 1
                continue
            if body[s:e] != a["text"]:
                stats["spans whose text differs from the turn (left out)"] += 1
                continue
            ts, te = sealed.trim(body, s, e)
            if te <= ts:
                stats["spans of white space only (left out)"] += 1
                continue
            if (ts, te) != (s, e):
                stats["spans with outer space (trimmed)"] += 1
            spans.append((at + len(head) + ts, at + len(head) + te, a["type"]))
        line = head + body + "\n"
        parts.append(line)
        at += len(line)
    return "".join(parts), spans


def cases_of(record: dict, split: str, stats: collections.Counter):
    """The case of one record, in the tool channel like the other PII sets (scripts/measure_datasets.py): maisecrets
    takes names, addresses and birth dates in a tool result only (maisecrets/detection/personal.py, `hits`)."""
    text, raw = text_of(record, stats)
    spans = []
    for s, e, label in raw:
        cls = LABEL_CLASS.get(label)
        sp = {"start": s, "end": e, "class": cls or "pii.other", "label": label}
        if cls is None:
            sp["neutral"] = True
        spans.append(sp)
    lang = LANG.get(record["language"], record["language"].lower())
    stats["cases"] += 1
    yield {"id": f"{NAME}/{record['id']}", "text": text, "channel": "tool", "context": "prose", "path": None,
           "spans": sorted(spans, key=lambda s: (s["start"], s["end"])), "split": split,
           "tags": [f"form:{record['form']}", f"scenario:{record['scenario']}"], "region": lang, "lang": lang,
           "source": {"name": NAME, "url": URL, "revision": ZIP_SHA256[:16], "licence": LICENCE,
                      "record": record["id"]}}


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
