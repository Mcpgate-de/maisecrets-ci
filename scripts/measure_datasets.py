"""Measure maisecrets on labelled PII and secret datasets, per type and channel. docs/BENCHMARKS.md has the pinned
data, the method and the results.

    python3 scripts/measure_datasets.py fetch [--data DIR] [--only gretel,nemotron,mendeley,piilo]
    python3 scripts/measure_datasets.py run [--data DIR] [--only ...] [--maisecrets DIR] [--channel prompt,tool]
        [--regions by-language|de|us,...] [--workers N] [--limit N] [--out result.json]

fetch downloads each dataset at its pinned version into the data directory (default ~/.cache/maisecrets-datasets,
never inside the repository) and checks the sha256 of each file. The Hugging Face datasets come as parquet; fetch
converts them to gzipped JSON lines once, and that step needs pyarrow (docs/BENCHMARKS.md, "Repeat this
measurement"). run needs the standard library only and runs on Python 3.9.

run loads each dataset, cleans its labels, maps them to maisecrets types and scans every text with
detect.scan(text, channel=...) in a fresh temp home. The cleaning is the method of a public fork of maisecrets
(Apache-2.0, see "Credit" in docs/BENCHMARKS.md): a labelled value that fails its own check (a checksum, a placeholder,
a reserved domain, a private address) is "uncertain" and counts neither as a miss nor as a false alarm; a span with
nothing of its type in it is a label error and becomes negative; a span wider than its value is trimmed to the
value, but never by cutting groups off until a checksum passes; a span whose offset is off is moved back onto its
value, or else becomes uncertain. The checks are written here and do not use the measured checkout, so a release
cannot change its own gold.

Counts per type: TP is a labelled value that a detection of any type overlaps, FN one that none overlaps, FP a
detection that overlaps no labelled value of any type and no uncertain one. P is the share of a type's detections on
a labelled value of that type among those and its FP; a detection on a value of another type only counts in neither.
R counts values. "R own" counts a value only when a detection of its own type overlaps it, "R covered" only when the
detections cover every character of it, "R raw" counts the labels before cleaning, at their original offsets.

The script prints counts only, never a value or a text, and --out writes counts and per-sample results (sample ids,
offsets, labels, types, rule ids), never a value. The downloaded data is read as data; nothing in it is run.
"""
from __future__ import annotations

import argparse
import ast
import collections
import functools
import gzip
import hashlib
import inspect
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = Path.home() / ".cache" / "maisecrets-datasets"
USER_AGENT = "maisecrets-measure (+https://github.com/Mcpgate-de/maisecrets)"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
CHANNELS = ("prompt", "tool")

# ------------------------------------------------------------------------------------------------- pinned sources
HF = "https://huggingface.co/datasets/{repo}/resolve/{revision}/{path}"
SOURCES = {
    "gretel": {
        "title": "Gretel synthetic_pii_finance_multilingual",
        "licence": "Apache-2.0", "attribution": "Gretel.ai",
        "url": "https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual",
        "repo": "gretelai/synthetic_pii_finance_multilingual",
        "revision": "7b844d16738527a04264f50214cb426a4cea0897",
        "files": {
            "data/train-00000-of-00001.parquet":
                "89bfe27e37e50098347f47f974e5e43f64a521f38171b618600ea7aa9b4fa430",
            "data/test-00000-of-00001.parquet":
                "014e1057978f030fce4f4cad7c93b9e3377fd0ded713d2bf4c7de00e3e3c8c72",
        },
        "columns": ["index", "language", "document_type", "quality_score", "generated_text", "pii_spans"],
    },
    "nemotron": {
        "title": "NVIDIA Nemotron-PII",
        "licence": "CC BY 4.0", "attribution": "NVIDIA",
        "url": "https://huggingface.co/datasets/nvidia/Nemotron-PII",
        "repo": "nvidia/Nemotron-PII",
        "revision": "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed",
        "files": {
            "data/test-00000-of-00001.parquet":
                "1a4b0512ecb5370f0992d29d0f9c07351e6de13f0d7ea33bb18cecb984780247",
        },
        "columns": ["uid", "locale", "document_format", "text", "spans"],
    },
    "mendeley": {
        "title": "Synthetic Dataset for PII Detection and Anonymization in Financial Documents (Mendeley Data)",
        "licence": "CC BY 4.0", "attribution": "the dataset's authors, doi 10.17632/tzrjx692jy.1",
        "url": "https://doi.org/10.17632/tzrjx692jy.1",
        "files": {
            "Training_Set.xlsx": "5f960d4f2d17762b75317565dc61b6382d99693983ae7e8a2d2a0070ec96942c",
            "Testing_Set.xlsx": "abf209b309704cda0f6c7f0cab64d8885d0aa07ce78e770343a8130fa57c20c5",
        },
        "download": {
            "Training_Set.xlsx": "https://data.mendeley.com/public-files/datasets/tzrjx692jy/files/"
                                 "5bc97a4f-bfaf-4324-8381-07de9bb51746/file_downloaded",
            "Testing_Set.xlsx": "https://data.mendeley.com/public-files/datasets/tzrjx692jy/files/"
                                "2e9569a9-368f-4245-ac66-1032159b098a/file_downloaded",
        },
    },
    "piilo": {
        "title": "PIILO (PII Labeling and Obfuscation), The Learning Agency Lab",
        "licence": "CC BY 4.0", "attribution": "PIILO (c) 2024 by The Learning Agency Lab",
        "url": "https://www.kaggle.com/datasets/lburleigh/piilo-dataset",
        "archive": "https://www.kaggle.com/api/v1/datasets/download/lburleigh/piilo-dataset?datasetVersionNumber=2",
        "files": {"train.json": "8276cd44f3b2eb357dfb405b3c5d8e9f821388e984cbf66e92e7df03f1b13117"},
    },
    # added for Benchmark V2 (2026-10-20) as a set nobody had read for tuning; its mapping below was fixed from the
    # dataset card and the label inventory before the first run of any scanner (docs/BENCHMARK-V2.md)
    "privy": {
        "title": "Privy English (synthetic protocol traces: JSON, SQL, HTML, XML)",
        "licence": "MIT", "attribution": "the Pixie authors (pixie-io/pixie, src/datagen/pii/privy)",
        "url": "https://huggingface.co/datasets/beki/privy",
        "repo": "beki/privy",
        "revision": "dc137a6a976f6b5bb8768e9bb51ec58df930ccd1",
        "archive_file": "privy-dataset.zip",
        "archive_sha256": "ad4ffbc8f7102a92f01f8d8023ddf4f5244fea6b23c3f116641fe6bbd8cbbde4",
        "files": {"test-small.json": "7ccbf2338f1b1d0f2192e5ad727e270f9cdf44dbe522a16af52d500f8c6c30f9"},
    },
}
DATASETS = tuple(SOURCES)

# ------------------------------------------------------------------------------------------ label -> maisecrets type
# A label maps to a maisecrets type where maisecrets claims that type, else to OUT_OF_SCOPE: a detection on an
# out-of-scope value is neither a find nor a false alarm. docs/BENCHMARKS.md has the same tables. The types fall
# into two tiers: the shapes maisecrets claims since its first releases (CORE), and the personal data that 0.6.21
# takes after a label or in a fixed form, in the tool channel only (PERSONAL, maisecrets/detection/personal.py). A
# release
# before 0.6.21 has no rule for the second tier; its rows show what a later rule class finds.
CORE = ("SECRET", "EMAIL", "PHONE", "IP", "IBAN", "CARD", "US_SSN", "ABA_ROUTING_NUMBER", "US_BANK_NUMBER")
PERSONAL = ("NAME", "ADDRESS", "BIRTH_DATE", "ID_NUMBER", "USERNAME")
TIERS = {"core": CORE, "personal": PERSONAL}
_OOS = OUT_OF_SCOPE
LABELS = {
    "gretel": {
        "email": "EMAIL", "phone_number": "PHONE", "ipv4": "IP", "ipv6": "IP", "iban": "IBAN",
        "credit_card_number": "CARD", "password": "SECRET", "api_key": "SECRET", "ssn": "US_SSN",
        "bank_routing_number": "ABA_ROUTING_NUMBER",
        "name": "NAME", "first_name": "NAME", "last_name": "NAME", "street_address": "ADDRESS",
        "date_of_birth": "BIRTH_DATE", "passport_number": "ID_NUMBER", "driver_license_number": "ID_NUMBER",
        "user_name": "USERNAME",
        **{k: _OOS for k in ("account_pin", "credit_card_security_code", "bban", "swift_bic_code", "customer_id",
                             "employee_id", "company", "local_latlng", "date", "date_time", "time")},
    },
    "nemotron": {
        "email": "EMAIL", "phone_number": "PHONE", "fax_number": "PHONE", "ipv4": "IP", "ipv6": "IP",
        "credit_debit_card": "CARD", "password": "SECRET", "api_key": "SECRET", "ssn": "US_SSN",
        "bank_routing_number": "ABA_ROUTING_NUMBER", "account_number": "US_BANK_NUMBER",
        "first_name": "NAME", "last_name": "NAME", "street_address": "ADDRESS", "date_of_birth": "BIRTH_DATE",
        "national_id": "ID_NUMBER", "tax_id": "ID_NUMBER", "medical_record_number": "ID_NUMBER",
        "health_plan_beneficiary_number": "ID_NUMBER", "certificate_license_number": "ID_NUMBER",
        "user_name": "USERNAME",
        **{k: _OOS for k in ("http_cookie", "pin", "cvv", "swift_bic", "customer_id", "employee_id", "unique_id",
                             "license_plate", "vehicle_identifier", "device_identifier", "mac_address",
                             "biometric_identifier", "url", "coordinate", "company_name", "city", "county", "state",
                             "country", "postcode", "date", "date_time", "time", "age", "gender", "blood_type",
                             "race_ethnicity", "religious_belief", "political_view", "sexuality", "language",
                             "education_level", "employment_status", "occupation")},
    },
    "mendeley": {
        "email": "EMAIL", "phone": "PHONE", "ssn": "US_SSN", "credit_card": "CARD", "name": "NAME",
        "address": "ADDRESS",
        **{k: _OOS for k in ("company", "url")},
    },
    "piilo": {
        "EMAIL": "EMAIL", "PHONE_NUM": "PHONE", "NAME_STUDENT": "NAME", "STREET_ADDRESS": "ADDRESS",
        "ID_NUM": "ID_NUMBER", "USERNAME": "USERNAME",
        **{k: _OOS for k in ("URL_PERSONAL",)},
    },
    # LOC mixes cities, countries and street addresses: out of scope, as city and country are for Nemotron
    "privy": {
        "PER": "NAME", "CREDIT_CARD": "CARD", "US_BANK_NUMBER": "US_BANK_NUMBER", "US_DRIVER_LICENSE": "ID_NUMBER",
        "US_PASSPORT": "ID_NUMBER", "US_ITIN": "ID_NUMBER", "PASSWORD": "SECRET",
        **{k: _OOS for k in ("LOC", "DATE_TIME", "NRP", "TITLE", "FINANCIAL", "ORG", "US_LICENSE_PLATE", "IMEI",
                             "AGE", "MAC_ADDRESS")},
    },
}
TIER_OF = {t: tier for tier, types in TIERS.items() for t in types}

# the regions setting and the system locale per language: a country's rules run on its own language's text
LANGUAGE_GROUP = {"en": ("us", "en_US"), "de": ("de", "de_DE"), "fr": ("fr", "fr_FR"), "es": ("es", "es_ES"),
                  "it": ("it", "it_IT"), "nl": ("nl", "nl_NL"), "sv": ("se", "sv_SE")}


class DataError(Exception):
    """A dataset that does not have the shape its loader expects. The message names the place, never a value."""


# ------------------------------------------------------------------------------------------------------- fetch
def _get(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    tmp = dest.with_name(dest.name + ".part")
    with urllib.request.urlopen(req, timeout=600) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh, 1 << 20)
    tmp.replace(dest)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _verified(path: Path, want: str) -> bool:
    return path.is_file() and sha256_of(path) == want


def check_data_dir(data: Path) -> Path:
    data = data.expanduser().resolve()
    if data == ROOT or ROOT in data.parents:
        raise DataError(f"{data} is inside the repository; the data stays outside it")
    return data


def fetch(name: str, data: Path) -> None:
    src = SOURCES[name]
    into = data / name
    into.mkdir(parents=True, exist_ok=True)
    if name == "privy":
        target = into / "test-small.json"
        if not _verified(target, src["files"]["test-small.json"]):
            archive = into / src["archive_file"]
            if not _verified(archive, src["archive_sha256"]):
                _get(HF.format(repo=src["repo"], revision=src["revision"], path=src["archive_file"]), archive)
            _require(archive, src["archive_sha256"], name)
            with zipfile.ZipFile(archive) as z, z.open("test-small.json") as zf, open(target, "wb") as fh:
                shutil.copyfileobj(zf, fh, 1 << 20)
        _require(target, src["files"]["test-small.json"], name)
        return
    if name == "piilo":
        target = into / "train.json"
        if not _verified(target, src["files"]["train.json"]):
            archive = into / "archive.zip"
            _get(src["archive"], archive)
            with zipfile.ZipFile(archive) as z:
                if z.getinfo("train.json").file_size > 1 << 30:
                    raise DataError("piilo: train.json in the archive is larger than 1 GiB")
                with z.open("train.json") as zf, open(target, "wb") as fh:
                    shutil.copyfileobj(zf, fh, 1 << 20)
            archive.unlink()
        _require(target, src["files"]["train.json"], name)
        return
    for path, want in src["files"].items():
        dest = into / Path(path).name
        if not _verified(dest, want):
            url = src["download"][path] if name == "mendeley" else HF.format(repo=src["repo"],
                                                                           revision=src["revision"], path=path)
            _get(url, dest)
        _require(dest, want, name)
        if dest.suffix == ".parquet":
            _parquet_to_jsonl(dest, src["columns"], want)


def _require(path: Path, want: str, name: str) -> None:
    if not _verified(path, want):
        raise DataError(f"{name}: {path.name} does not match its pinned sha256; delete it and fetch again")


def _parquet_to_jsonl(path: Path, columns: list, sha: str) -> None:
    """The parquet file as gzipped JSON lines with the columns the loader reads; done once per pinned file."""
    out = path.with_suffix(".jsonl.gz")
    stamp = path.with_suffix(".jsonl.sha256")
    if out.is_file() and stamp.is_file() and stamp.read_text().strip() == sha:
        return
    try:
        import pyarrow.parquet as pq
    except ImportError:
        raise DataError("fetch needs pyarrow to read parquet: python3 -m venv <dir> && <dir>/bin/pip install pyarrow, "
                        "then run fetch with <dir>/bin/python") from None
    table = pq.read_table(path, columns=columns)
    with gzip.GzipFile(out, "wb", mtime=0) as gz:
        for batch in table.to_batches(10000):
            for row in batch.to_pylist():
                gz.write((json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n").encode("utf-8"))
    stamp.write_text(sha + "\n")


# ------------------------------------------------------------------------------------------------------- loaders
# A sample: {"id", "lang", "tags", "text", "spans": [{"start", "end", "label", "expect"?}]}. "expect" is the text the
# dataset says the span holds (Nemotron's own copy, Mendeley's column value), for the offset check.
def _jsonl(path: Path):
    if not path.is_file():
        raise DataError(f"{path} is missing: run `fetch` first")
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)


GRETEL_LANG = {"English": "en", "German": "de", "France": "fr", "French": "fr", "Spanish": "es", "Italian": "it",
               "Dutch": "nl", "Swedish": "sv"}
GRETEL_STRUCTURED = {"CSV", "EDI", "SWIFT Message", "FIX Protocol", "BAI Format", "XBRL", "FpML", "MT940"}
GRETEL_MIN_QUALITY = 90


def gretel_samples(records, stats: collections.Counter):
    """One sample per generated document. A record below Gretel's own quality_score 90 is left out and counted."""
    for split, r in records:
        sid = f"{split}:{r['index']}"
        if r["quality_score"] is None or float(r["quality_score"]) < GRETEL_MIN_QUALITY:
            stats["records below quality 90"] += 1
            continue
        lang = GRETEL_LANG.get(r["language"])
        if lang is None:
            raise DataError(f"gretel: {sid}: a language without a code")
        try:
            spans = json.loads(r["pii_spans"])
        except (TypeError, ValueError):
            raise DataError(f"gretel: {sid}: pii_spans is not JSON") from None
        fmt = "structured" if r["document_type"] in GRETEL_STRUCTURED else "unstructured"
        yield {"id": sid, "lang": lang, "tags": [f"format:{fmt}"], "text": r["generated_text"] or "",
               "spans": [{"start": s["start"], "end": s["end"], "label": s["label"]} for s in spans]}


def nemotron_samples(records, stats: collections.Counter):
    """One sample per record of the test split; the spans column is a Python literal, read with literal_eval."""
    for r in records:
        sid = f"{r['locale']}:{r['uid']}"
        try:
            spans = ast.literal_eval(r["spans"] or "[]")
        except (ValueError, SyntaxError):
            raise DataError(f"nemotron: {sid}: spans is not a literal list") from None
        if not isinstance(spans, list):
            raise DataError(f"nemotron: {sid}: spans is not a list")
        yield {"id": sid, "lang": "en", "tags": [f"locale:{r['locale']}", f"format:{r['document_format']}"],
               "text": r["text"] or "",
               "spans": [{"start": s["start"], "end": s["end"], "label": s["label"], "expect": str(s.get("text", ""))}
                         for s in spans]}


def privy_samples(records, stats: collections.Counter):
    """One sample per record of test-small.json; `O` marks the text between the values and is no span."""
    for i, r in enumerate(records):
        stats["records"] += 1
        yield {"id": f"test-small:{i}", "lang": "en", "tags": [f"template:{r.get('template_id')}"],
               "text": r["full_text"],
               "spans": [{"start": s["start_position"], "end": s["end_position"], "label": s["entity_type"],
                          "expect": s.get("entity_value", "")} for s in r["spans"] if s["entity_type"] != "O"]}


def _cp1252(lo: int, hi: int) -> str:
    return "".join(bytes([b]).decode("cp1252", errors="ignore") for b in range(lo, hi + 1))


# UTF-8 read as cp1252: a lead byte (0xC2-0xF4) and one to three continuation bytes (0x80-0xBF)
_MOJIBAKE_RE = re.compile(f"[{re.escape(_cp1252(0xC2, 0xF4))}][{re.escape(_cp1252(0x80, 0xBF))}]{{1,3}}")


def repair_mojibake(text: str) -> str:
    """Mendeley's texts are UTF-8 read as cp1252, and its offsets count the characters of the right text."""
    def fix(m):
        try:
            return m.group(0).encode("cp1252").decode("utf-8")
        except UnicodeError:
            return m.group(0)
    return _MOJIBAKE_RE.sub(fix, text)


_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
MENDELEY_COLUMNS = ["Name", "Credit Card", "Email", "URL", "Phone", "Address", "Company", "SSN", "Text",
                    "True Predictions"]
MENDELEY_COLUMN_OF = {"name": "A", "credit_card": "B", "email": "C", "url": "D", "phone": "E", "address": "F",
                      "company": "G", "ssn": "H"}


def read_xlsx(path: Path):
    """The rows of the first sheet by column letter, the header checked. The standard library only."""
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).iter(f"{_NS}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{_NS}t")))
        sheet = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
    for n, row in enumerate(sheet.iter(f"{_NS}row")):
        out = {}
        for c in row.iter(f"{_NS}c"):
            col = re.match(r"[A-Z]+", c.get("r", "")).group(0)
            v = c.find(f"{_NS}v")
            if c.get("t") == "s" and v is not None:
                out[col] = shared[int(v.text)]
            elif c.get("t") == "inlineStr":
                out[col] = "".join(t.text or "" for t in c.iter(f"{_NS}t"))
            else:
                out[col] = v.text if v is not None else None
        if n == 0:
            got = [out.get(chr(65 + i)) for i in range(len(MENDELEY_COLUMNS))]
            if got != MENDELEY_COLUMNS:
                raise DataError(f"mendeley: {path.name}: the header is not the expected one")
            continue
        yield {**out, "_row": int(row.get("r", n + 1))}


def mendeley_samples(files, stats: collections.Counter):
    """files: (file stem, rows). The text is repaired first; "True Predictions" is a literal list of (start, end,
    label), read with literal_eval; the column of each label is the value the span should hold."""
    for stem, rows in files:
        for r in rows:
            sid = f"{stem}:{r['_row']}"
            raw = r.get("I") or ""
            text = repair_mojibake(raw)
            if text != raw:
                stats["texts with mojibake repaired"] += 1
            try:
                preds = ast.literal_eval(r.get("J") or "[]")
            except (ValueError, SyntaxError):
                raise DataError(f"mendeley: {sid}: True Predictions is not a literal list") from None
            spans = []
            for p in preds:
                start, end, label = p
                col = MENDELEY_COLUMN_OF.get(label)
                expect = repair_mojibake(r.get(col) or "") if col else ""
                spans.append({"start": start, "end": end, "label": label, "expect": expect})
            yield {"id": sid, "lang": "en", "tags": [], "text": text, "spans": spans}


def piilo_samples(records, stats: collections.Counter):
    """One sample per essay: the text is rebuilt from the tokens and must equal full_text; BIO labels become spans."""
    for r in records:
        sid = str(r["document"])
        starts, parts, at = [], [], 0
        for tok, ws in zip(r["tokens"], r["trailing_whitespace"]):
            starts.append(at)
            parts.append(tok + (" " if ws else ""))
            at += len(parts[-1])
        text = "".join(parts)
        if text != r["full_text"] or len(r["labels"]) != len(r["tokens"]):
            stats["records whose tokens do not rebuild the text"] += 1
            continue
        spans, run = [], None
        for i, lab in enumerate(r["labels"]):
            end = starts[i] + len(r["tokens"][i])
            if lab.startswith("I-") and run and run[0] == lab[2:]:
                run[2] = end
                continue
            if run:
                spans.append(run)
            run = [lab[2:], starts[i], end] if lab != "O" else None
        if run:
            spans.append(run)
        yield {"id": sid, "lang": "en", "tags": [], "text": text,
               "spans": [{"start": a, "end": b, "label": lab} for lab, a, b in spans]}


def load(name: str, data: Path, stats: collections.Counter):
    d = data / name
    if name == "gretel":
        recs = ((split, r) for split in ("train", "test")
                for r in _jsonl(d / f"{split}-00000-of-00001.jsonl.gz"))
        return gretel_samples(recs, stats)
    if name == "nemotron":
        return nemotron_samples(_jsonl(d / "test-00000-of-00001.jsonl.gz"), stats)
    if name == "mendeley":
        for f in SOURCES["mendeley"]["files"]:
            _require(d / f, SOURCES["mendeley"]["files"][f], name)
        return mendeley_samples(((Path(f).stem, read_xlsx(d / f)) for f in sorted(SOURCES["mendeley"]["files"])),
                                stats)
    if name == "privy":
        _require(d / "test-small.json", SOURCES["privy"]["files"]["test-small.json"], name)
        with open(d / "test-small.json", encoding="utf-8") as fh:
            return privy_samples(json.load(fh), stats)
    if name == "piilo":
        _require(d / "train.json", SOURCES["piilo"]["files"]["train.json"], name)
        with open(d / "train.json", encoding="utf-8") as fh:
            return piilo_samples(json.load(fh), stats)
    raise DataError(f"no loader for {name}")


# ------------------------------------------------------------------------------------------------------- checks
# Each check says whether a labelled value is a valid value of its type. They are written here, not taken from the
# measured checkout. The rules follow the fork's validgold.py and audit.py (docs/BENCHMARKS.md, "Credit").
def _digits(v: str) -> str:
    return re.sub(r"\D", "", v)


def luhn_ok(v: str) -> bool:
    d = _digits(v)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def iban_ok(v: str) -> bool:
    """ISO 13616: two letters, two check digits, 11 to 30 letters or digits, mod 97 = 1."""
    s = re.sub(r"\s", "", v).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


def aba_ok(v: str) -> bool:
    d = _digits(v)
    if len(d) != 9:
        return False
    n = [int(c) for c in d]
    return (3 * (n[0] + n[3] + n[6]) + 7 * (n[1] + n[4] + n[7]) + n[2] + n[5] + n[8]) % 10 == 0


# numbers the Social Security Administration never issues to a person: the advertising numbers and the wallet card
SSN_PLACEHOLDERS = {"123456789", "078051120", "219099999"} | {f"98765432{i}" for i in range(10)}


def ssn_ok(v: str) -> bool:
    d = _digits(v)
    return (len(d) == 9 and d[:3] not in ("000", "666") and d[0] != "9" and d[3:5] != "00" and d[5:] != "0000"
            and d not in SSN_PLACEHOLDERS)


_EXTENSION = re.compile(r"(?i)\s*(?:ext\.?|x|#)\s*\d{1,6}\s*$")
_US_LAYOUT = re.compile(r"\(?\d{3}\)?[-. ]?\d{3}[-. ]\d{4}")
_NANP_PREFIX = re.compile(r"\s*(?:\+\s?1|1(?=[-. (]))[-. ]?")


def phone_reasons(v: str, lang: str = "en") -> list:
    """Why a phone label is no number: letters, not 7 to 15 digits, one repeated digit, or a North American number
    whose area code or exchange starts with 0 or 1 or whose area code has a 9 in the middle ((123) 456-7890,
    (800) 123-4567, 555-555-5555 are placeholders). A number is North American when it starts with +1 or 1, or, in
    English text only, when it has the US layout without a leading 0 (an Italian 3xx xxx xxxx is not judged)."""
    v = _EXTENSION.sub("", v.strip())
    out = []
    if re.search(r"[^\W\d_]", v):
        out.append("letters")
    digits = _digits(v.replace("(0)", ""))
    if digits.startswith("00"):
        digits = digits[2:]
    if not 7 <= len(digits) <= 15:
        out.append("digit count")
    if digits and len(set(digits)) == 1:
        out.append("placeholder")
    national = None
    m = _NANP_PREFIX.match(v)
    if m and len(_digits(v[m.end():])) == 10:
        national = _digits(v[m.end():])
    elif lang == "en" and _US_LAYOUT.fullmatch(v) and not _digits(v).startswith("0"):
        national = _digits(v)
    if national:
        if national[0] in "01" or national[3] in "01" or national[1] == "9":
            out.append("placeholder")
    return out


_LABEL = r"[^\W_](?:[\w-]*[^\W_])?"
_EMAIL = re.compile(rf"[^\s@]+@{_LABEL}(?:\.{_LABEL})*\.[^\W\d_]{{2,63}}")
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
RESERVED_TLDS = ("test", "example", "invalid", "localhost")


def email_reasons(v: str) -> list:
    v = v.strip()
    if not _EMAIL.fullmatch(v):
        return ["syntax"]
    domain = v.rsplit("@", 1)[1].lower()
    if domain in RESERVED_DOMAINS or domain.endswith(tuple("." + d for d in RESERVED_DOMAINS)) \
            or domain.rsplit(".", 1)[1] in RESERVED_TLDS:
        return ["reserved domain"]
    return []


def ip_reasons(v: str) -> list:
    try:
        addr = ipaddress.ip_address(v.strip())
    except ValueError:
        return ["syntax"]
    return [] if addr.is_global else ["not public"]


def bank_reasons(v: str) -> list:
    out = []
    if re.search(r"[^\W\d_]", v):
        out.append("letters")
    if not 4 <= len(_digits(v)) <= 17:
        out.append("digit count")
    return out


def _from(ok, reason):
    return lambda v: [] if ok(v) else [reason]


# type -> (pattern of the value or None, reasons(value) -> [] when valid, may the cut shrink a match)
CHECKS = {
    "IBAN": (re.compile(r"[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}"), _from(iban_ok, "checksum"), True),
    "CARD": (re.compile(r"\d(?:[ -]?\d){12,18}"), _from(luhn_ok, "checksum"), True),
    "US_SSN": (re.compile(r"\d{3}[- ]?\d{2}[- ]?\d{4}"), _from(ssn_ok, "checksum"), True),
    "ABA_ROUTING_NUMBER": (re.compile(r"\d{4}-?\d{4}-?\d"), _from(aba_ok, "checksum"), True),
    "PHONE": (re.compile(r"\+?\(?\d[\d ().-]*\d(?:\s*(?:ext\.?|x)\s*\d{1,6})?"), phone_reasons, False),
    "EMAIL": (re.compile(r"[^\s@\[\]<>()\"']+@[^\s@\[\]<>()\"']+"), email_reasons, False),
    "IP": (re.compile(r"[0-9A-Fa-f:.]*[0-9A-Fa-f]"), ip_reasons, False),
    "US_BANK_NUMBER": (None, bank_reasons, False),
}
# a span with nothing of its type in it is a label error ("[Phone Number]", "adresse e-mail"): negative
NOT_THE_TYPE = {"PHONE": lambda v: not any(c.isdigit() for c in v), "EMAIL": lambda v: "@" not in v,
                "IP": lambda v: not any(c.isdigit() for c in v)}
_GROUP = re.compile(r"[A-Za-z0-9]+")


def cut_ok(kept: str, dropped: str) -> bool:
    """A cut may drop only what a greedy pattern took after the value: it falls at a separator, and the first group it
    drops differs in length from the last group it keeps (the ` 12` of an expiry after a card number). Cutting a fake
    card or IBAN at a group boundary passes the checksum by chance (1 in 10, 1 in 97) and leaves a fragment no
    detector reports."""
    if not dropped or dropped[0].isalnum():
        return False
    last, nxt = _GROUP.findall(kept), _GROUP.findall(dropped)
    return not (last and nxt and len(last[-1]) == len(nxt[0]))


def _reasons(fn, v: str) -> list:
    try:
        return fn(v)
    except (ValueError, IndexError, TypeError):
        return ["syntax"]


_TRAILING_PUNCT = ".,;:"


def check_value(text: str, start: int, end: int, typ: str, lang: str = "en"):
    """(verdict, start, end, reason): verdict valid, trimmed or invalid; the bounds of the value when one passes."""
    rx, reasons, shrink = CHECKS[typ]
    if typ == "PHONE":
        reasons = functools.partial(phone_reasons, lang=lang)
    value = text[start:end]
    if typ == "EMAIL" and value.rstrip(_TRAILING_PUNCT + " ") != value.rstrip():
        # a sentence's full stop after an address is no part of it: the value ends before it
        cut = len(value.rstrip()) - len(value.rstrip().rstrip(_TRAILING_PUNCT))
        verdict, a, b, why = check_value(text, start, end - (len(value) - len(value.rstrip())) - cut, typ, lang)
        return ("trimmed" if verdict == "valid" else verdict), a, b, why
    lead = len(value) - len(value.lstrip())
    core = value.strip()
    first = _reasons(reasons, core)
    if (rx is None or rx.fullmatch(core)) and not first:
        return "valid", start + lead, start + lead + len(core), ""
    if rx is not None:
        for m in rx.finditer(value):
            for stop in range(m.end(), m.start() if shrink else m.end() - 1, -1):
                cand = value[m.start():stop]
                if cand != cand.strip() or not rx.fullmatch(cand):
                    continue
                if stop < m.end() and not cut_ok(cand, value[stop:]):
                    continue
                if not _reasons(reasons, cand):
                    if cand == core:
                        return "valid", start + lead, start + lead + len(core), ""
                    return "trimmed", start + m.start(), start + stop, ""
    return "invalid", start, end, (first[0] if first else "no value of the type")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def place(text: str, span: dict):
    """The span's bounds after the offset check, and what happened: "" (in place), "repaired" (moved onto the text the
    dataset says it holds, the nearest copy within 64 characters) or "broken" (outside the text, or no copy near)."""
    a, b = span["start"], span["end"]
    expect = _norm(span.get("expect") or "")
    in_range = isinstance(a, int) and isinstance(b, int) and 0 <= a < b <= len(text)
    if not expect:
        return (a, b, "") if in_range else (a, b, "broken")
    if in_range and expect in _norm(text[a:b]):
        return a, b, ""
    raw = (span.get("expect") or "").strip()
    best = None
    if raw and isinstance(a, int):
        lo = max(0, a - 64)
        for m in re.finditer(re.escape(raw), text[lo:a + 64 + len(raw)], re.I):
            d = abs(lo + m.start() - a)
            if best is None or d < best[0]:
                best = (d, lo + m.start(), lo + m.end())
    if best:
        return best[1], best[2], "repaired"
    return a, b, "broken"


def clean(dataset: str, sample: dict, counts: dict) -> list:
    """The gold spans of one sample: {start, end, label, type, gold, reason, raw}. gold is pos, neg, uncertain or oos;
    raw holds the original bounds for the raw recall. counts: type -> reason -> n."""
    table = LABELS[dataset]
    text = sample["text"]
    out = []
    for sp in sample["spans"]:
        label = sp["label"]
        if label not in table:
            raise DataError(f"{dataset}: {sample['id']}: a label without a type in the table")
        typ = table[label]
        a, b, moved = place(text, sp)
        raw = (sp["start"], sp["end"]) if 0 <= sp["start"] < sp["end"] <= len(text) else None
        c = counts.setdefault(typ, collections.Counter())
        c["labelled"] += 1
        if moved == "broken" and not (0 <= a < b <= len(text)):
            c["dropped: offset outside the text"] += 1
            continue
        if moved:
            c["offset " + moved] += 1
        g = {"start": a, "end": b, "label": label, "type": typ, "gold": "pos", "reason": "", "raw": raw}
        if typ == OUT_OF_SCOPE:
            g["gold"] = "oos"
        elif moved == "broken":
            g.update(gold="uncertain", reason="offset broken")
        elif typ in NOT_THE_TYPE and NOT_THE_TYPE[typ](text[a:b]):
            g.update(gold="neg", reason="label error")
        elif typ in CHECKS:
            verdict, va, vb, why = check_value(text, a, b, typ, sample.get("lang", "en"))
            if verdict == "invalid" and typ == "US_BANK_NUMBER":
                iv, ia, ib, _ = check_value(text, a, b, "IBAN")
                if iv != "invalid":
                    c["retyped as IBAN"] += 1
                    g.update(start=ia, end=ib, type="IBAN")
                    out.append(g)
                    counts.setdefault("IBAN", collections.Counter())["valid (retyped from US_BANK_NUMBER)"] += 1
                    continue
            if verdict == "invalid":
                g.update(gold="uncertain", reason=why)
            elif verdict == "trimmed":
                g.update(start=va, end=vb, reason="trimmed")
            else:
                g.update(start=va, end=vb)
        c[g["gold"] if not g["reason"] else f"{g['gold']}: {g['reason']}"] += 1
        out.append(g)
    return _merge(out, counts)


def _merge(gold: list, counts: dict) -> list:
    """Positive spans of one type that overlap are one value (Gretel labels some values twice): their union stays,
    and each span merged away is counted."""
    out: list = []
    for g in sorted(gold, key=lambda g: (g["gold"] != "pos", g["type"], g["start"], g["end"])):
        last = out[-1] if out else None
        if (g["gold"] == "pos" and last is not None and last["gold"] == "pos" and last["type"] == g["type"]
                and g["start"] < last["end"]):
            last["end"] = max(last["end"], g["end"])
            counts[g["type"]]["merged: overlaps a value of its type"] += 1
            continue
        out.append(dict(g))
    return sorted(out, key=lambda g: (g["start"], g["end"], g["type"]))


def merge_original(original: list) -> list:
    """The original labels with overlapping spans of one type merged, for the raw recall."""
    out: list = []
    for typ, a, b in sorted(original):
        if out and out[-1][0] == typ and a < out[-1][2]:
            out[-1] = (typ, out[-1][1], max(out[-1][2], b))
            continue
        out.append((typ, a, b))
    return out


# -------------------------------------------------------------------------------------------------------- scan
_detect = None
_has_channel = True


def _init(ms_dir: str) -> None:
    global _detect, _has_channel
    sys.path.insert(0, ms_dir)
    from maisecrets import detect
    detect.rules()
    _detect = detect
    _has_channel = "channel" in inspect.signature(detect.scan).parameters


def _scan(job):
    idx, text, channels = job
    out = {}
    for ch in channels:
        ms = _detect.scan(text, channel=ch) if _has_channel else _detect.scan(text)
        out[ch] = sorted((m.start, m.end, m.type, m.kind) for m in ms)
    return idx, out


def _describe(_):
    a = _detect.active_regions()
    return list(a.regions), list(a.languages)


def scan_group(ms_dir: str, regions: list, locale: str, texts: list, channels: tuple, workers: int):
    """Detections per text and channel, in workers whose temp home has this group's regions."""
    home = tempfile.mkdtemp(prefix="maisecrets-datasets-")
    saved = {k: os.environ.get(k) for k in ("MAISECRETS_HOME", "MAISECRETS_LOCALE")}
    try:
        with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
            json.dump({"backend": "jsonfile", "allow_plaintext_store": True, "regions": regions}, fh)
        os.environ["MAISECRETS_HOME"] = home
        os.environ["MAISECRETS_LOCALE"] = locale
        order = sorted(range(len(texts)), key=lambda i: -len(texts[i]))
        res = [None] * len(texts)
        with Pool(workers, initializer=_init, initargs=(ms_dir,)) as pool:
            active = pool.apply(_describe, (None,))
            for idx, out in pool.imap_unordered(_scan, ((i, texts[i], channels) for i in order), chunksize=8):
                res[idx] = out
        return res, active
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(home, ignore_errors=True)


# -------------------------------------------------------------------------------------------------------- score
def _overlaps(a0, a1, b0, b1) -> bool:
    return a0 < b1 and b0 < a1


def _covered(a: int, b: int, dets: list) -> bool:
    """Do the detections together cover every character of a..b?"""
    at = a
    for s, e, *_ in sorted(dets):
        if s > at:
            return False
        at = max(at, e)
        if at >= b:
            return True
    return at >= b


def score_sample(gold: list, dets: list, original: list):
    """Per type: tp (labelled values a detection overlaps), fn, fp (detections on no labelled or uncertain value),
    hits (detections on a labelled value of their own type), cross (detections on a labelled value of another type
    only), same_type (values found by a detection of their own type), covered (values the detections cover
    character by character), unc_hit
    (uncertain values a detection overlaps), raw_tp and raw_fn (the original in-scope labels, before cleaning).
    Also the detection classes for the per-sample file."""
    c: dict = {}

    def bump(t, k):
        c.setdefault(t, collections.Counter())[k] += 1

    pos = [g for g in gold if g["gold"] == "pos"]
    neutral = [g for g in gold if g["gold"] in ("oos", "uncertain")]
    classes = []
    for s, e, t, rule in dets:
        on = [g for g in pos if _overlaps(s, e, g["start"], g["end"])]
        if on:
            bump(t, "hits" if any(g["type"] == t for g in on) else "cross")
            classes.append("tp")
        elif any(_overlaps(s, e, g["start"], g["end"]) for g in neutral):
            classes.append("neutral")
        else:
            bump(t, "fp")
            classes.append("fp")
    found = []
    for g in gold:
        hit = [d for d in dets if _overlaps(d[0], d[1], g["start"], g["end"])]
        found.append(bool(hit))
        if g["gold"] == "pos":
            bump(g["type"], "tp" if hit else "fn")
            if any(d[2] == g["type"] for d in hit):
                bump(g["type"], "same_type")
            if _covered(g["start"], g["end"], hit):
                bump(g["type"], "covered")
        elif g["gold"] == "uncertain" and hit:
            bump(g["type"], "unc_hit")
    for typ, a, b in original:
        bump(typ, "raw_tp" if any(_overlaps(d[0], d[1], a, b) for d in dets) else "raw_fn")
    return c, classes, found


def _rnd(x):
    return None if x is None else round(x, 4)


def metrics(c: collections.Counter) -> dict:
    tp, fn, fp, hits = c["tp"], c["fn"], c["fp"], c["hits"]
    p = hits / (hits + fp) if hits + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p is not None and r is not None and p + r else None
    rr = c["raw_tp"] / (c["raw_tp"] + c["raw_fn"]) if c["raw_tp"] + c["raw_fn"] else None
    ro = c["same_type"] / (tp + fn) if tp + fn else None
    rc = c["covered"] / (tp + fn) if tp + fn else None
    return {"tp": tp, "fn": fn, "fp": fp, "hits": hits, "cross": c["cross"], "same_type": c["same_type"],
            "covered": c["covered"], "unc_hit": c["unc_hit"], "raw_tp": c["raw_tp"], "raw_fn": c["raw_fn"],
            "P": _rnd(p), "R": _rnd(r), "F1": _rnd(f1), "R_own": _rnd(ro), "R_covered": _rnd(rc),
            "R_raw": _rnd(rr)}


def _keep(sid: str, limit: int, total: int) -> bool:
    """A fixed sample of about `limit` of `total` ids, by hash: the same ids on every machine."""
    return int(hashlib.sha256(sid.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF < limit / max(1, total)


def measure(name: str, a) -> dict:
    stats = collections.Counter()
    samples = list(load(name, a.data, stats))
    if a.limit:
        n = len(samples)
        samples = [s for s in samples if _keep(f"{name}:{s['id']}", a.limit, n)]
    samples.sort(key=lambda s: s["id"])
    ids = [s["id"] for s in samples]
    if len(set(ids)) != len(ids):
        raise DataError(f"{name}: a sample id repeats")
    cleaning: dict = {}
    golds = [clean(name, s, cleaning) for s in samples]
    groups: dict = {}
    for i, s in enumerate(samples):
        if a.regions == "by-language":
            regions, locale = LANGUAGE_GROUP[s["lang"]]
            key = (regions, locale)
        else:
            key = (a.regions, a.locale)
        groups.setdefault(key, []).append(i)
    channels = tuple(a.channel.split(","))
    dets = [None] * len(samples)
    group_info = {}
    for (regions, locale), idx in sorted(groups.items()):
        res, active = scan_group(a.maisecrets, [x for x in regions.split(",") if x], locale,
                                 [samples[i]["text"] for i in idx], channels, a.workers)
        group_info[f"{regions} {locale}"] = {"samples": len(idx), "regions": active[0], "languages": active[1]}
        for i, r in zip(idx, res):
            dets[i] = r
    result = {"dataset": name, "source": {k: v for k, v in SOURCES[name].items() if k != "columns"},
              "samples": len(samples), "records": dict(sorted(stats.items())),
              "cleaning": {t: dict(sorted(c.items())) for t, c in sorted(cleaning.items())},
              "groups": group_info, "channels": {}}
    rows = []
    for ch in channels:
        per_type: dict = {}
        per_tier: dict = {}
        for i, s in enumerate(samples):
            original = merge_original([(LABELS[name][sp["label"]], sp["start"], sp["end"]) for sp in s["spans"]
                                       if LABELS[name][sp["label"]] != OUT_OF_SCOPE
                                       and 0 <= sp["start"] < sp["end"] <= len(s["text"])])
            c, classes, found = score_sample(golds[i], dets[i][ch], original)
            region = LANGUAGE_GROUP[s["lang"]][0] if a.regions == "by-language" else a.regions
            for t, cc in c.items():
                if t == OUT_OF_SCOPE:
                    continue
                per_type.setdefault(t, collections.Counter()).update(cc)
                tier = per_tier.setdefault(TIER_OF.get(t, "other"), {"total": collections.Counter(), "regions": {},
                                                                     "tags": {}})
                tier["total"].update(cc)
                tier["regions"].setdefault(region, collections.Counter()).update(cc)
                for tag in s["tags"]:
                    tier["tags"].setdefault(tag, collections.Counter()).update(cc)
            if a.out:
                if ch == channels[0]:
                    rows.append({"id": s["id"], "tags": s["tags"],
                                 "gold": [[g["start"], g["end"], g["label"], g["type"], g["gold"], g["reason"]]
                                          for g in golds[i]], "found": {}, "detections": {}})
                rows[i]["found"][ch] = found
                rows[i]["detections"][ch] = [[d[0], d[1], d[2], d[3], k] for d, k in zip(dets[i][ch], classes)]
        result["channels"][ch] = {
            "types": {t: metrics(cc) for t, cc in sorted(per_type.items())},
            "tiers": {tier: {"total": metrics(v["total"]),
                             "regions": {g: metrics(cc) for g, cc in sorted(v["regions"].items())},
                             "tags": {t: metrics(cc) for t, cc in sorted(v["tags"].items())}}
                      for tier, v in sorted(per_tier.items())}}
    if a.out:
        result["rows"] = rows
    return result


# -------------------------------------------------------------------------------------------------------- print
def _f(x) -> str:
    return "  -  " if x is None else f"{x:.3f}"


def report(res: dict) -> None:
    print(f"{res['dataset']}: {res['samples']} samples")
    for k, v in res["records"].items():
        print(f"  records: {k} {v}")
    print("  cleaning (labelled values per type and verdict):")
    for t, c in res["cleaning"].items():
        print(f"    {t:22s} " + "  ".join(f"{k} {v}" for k, v in c.items()))
    for ch, m in res["channels"].items():
        print(f"  channel {ch}")
        print(f"    {'type':30s} {'TP':>6s} {'FN':>6s} {'FP':>6s} {'uncert':>6s} {'hits':>6s} {'P':>6s} {'R':>6s} "
              f"{'F1':>6s} {'R own':>6s} {'R cov':>6s} {'R raw':>6s}")
        rows = list(m["types"].items())
        for tier, v in m["tiers"].items():
            rows += [(f"{tier}: all", v["total"])] + [(f"{tier}: region {g}", x) for g, x in v["regions"].items()] \
                + [(f"{tier}: {t}", x) for t, x in v["tags"].items()]
        for t, v in rows:
            unc = sum(n for k, n in res["cleaning"].get(t, {}).items() if k.startswith("uncertain"))
            unc_s = f"{unc:6d}" if t in res["cleaning"] else "      "
            print(f"    {t:30s} {v['tp']:6d} {v['fn']:6d} {v['fp']:6d} {unc_s} {v['hits']:6d} {_f(v['P']):>6s} "
                  f"{_f(v['R']):>6s} {_f(v['F1']):>6s} {_f(v['R_own']):>6s} {_f(v['R_covered']):>6s} "
                  f"{_f(v['R_raw']):>6s}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for cmd in ("fetch", "run"):
        p = sub.add_parser(cmd)
        p.add_argument("--data", type=Path, default=DEFAULT_DATA, help="the data directory, outside the repository")
        p.add_argument("--only", default=",".join(DATASETS), help="datasets, comma-separated")
    r = sub.choices["run"]
    r.add_argument("--maisecrets", default=str(ROOT), help="maisecrets checkout to measure (default: this one)")
    r.add_argument("--channel", default="prompt,tool")
    r.add_argument("--regions", default="by-language",
                   help="by-language (a country's rules on its language's text) or one regions setting, such as us")
    r.add_argument("--locale", default="en_US", help="the system locale with a fixed --regions (default en_US)")
    r.add_argument("--workers", type=int, default=max(1, min(8, (os.cpu_count() or 2) - 1)))
    r.add_argument("--limit", type=int, default=0, help="about this many samples per dataset, a fixed choice")
    r.add_argument("--out", help="write counts and per-sample results (no values) to this JSON file")
    a = ap.parse_args(argv)
    names = [x for x in a.only.split(",") if x]
    unknown = [x for x in names if x not in SOURCES]
    if unknown:
        ap.error(f"unknown dataset(s): {', '.join(unknown)}; known: {', '.join(DATASETS)}")
    try:
        a.data = check_data_dir(a.data)
        if a.cmd == "fetch":
            for n in names:
                t0 = time.time()
                fetch(n, a.data)
                print(f"{n}: fetched and verified ({time.time() - t0:.0f} s)", file=sys.stderr)
            return 0
        for ch in a.channel.split(","):
            if ch not in CHANNELS:
                ap.error(f"--channel: {ch} is not prompt or tool")
        results = []
        for n in names:
            t0 = time.time()
            res = measure(n, a)
            report(res)
            print(f"{n}: {time.time() - t0:.0f} s", file=sys.stderr)
            results.append(res)
    except DataError as exc:
        print(f"measure_datasets: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - a traceback could quote a dataset value: name the type only
        print(f"measure_datasets: {type(exc).__name__} (the message is left out: it can quote a dataset value)",
              file=sys.stderr)
        return 3
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump({"settings": {"channel": a.channel, "regions": a.regions, "limit": a.limit,
                                    "python": sys.version.split()[0]},
                       "datasets": results}, fh, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
