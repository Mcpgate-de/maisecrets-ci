#!/usr/bin/env python3
"""The GitHub-issues secret set (MSR 2026, arXiv:2410.23657; docs/BENCHMARK-V3.md, "GitHub issues").

    python3 bench/ghissues.py seal ZIP DATA_DIR      split main_data.csv into DATA_DIR/dev and DATA_DIR/holdout, once
    python3 bench/ghissues.py verify DATA_DIR        both halves still match their pinned sha256

The set holds 54,203 candidate strings from real GitHub issues that the SecretBench regexes found, each labelled by
hand as a true secret (1) or not (0), with the full issue body. The values are REAL leaked secrets of third parties:
no script here prints a value or a text, and the data stays outside the repository.

The split is by issue, so one issue never lies in both halves: `holdout` when the first 8 hex digits of
HMAC-SHA256(SALT, issue id) are odd, else `dev`. The issue id is `<owner>/<repo>#<number>` from the issue url, the
owner and the repository in lower case. The holdout half was written and hashed before any case of either half was
read; it runs for totals only (bench/run.py) and is never read to write a rule.

A case is one issue body. A true candidate is a span at each place its value occurs in the body; its core is the
secret inside the regex match (`core_of`), so a scanner that masks the value and keeps the key name counts as whole.
A false candidate is no span: it is listed in the case's `negatives`, and a finding on it is a false positive.
A finding on text that no candidate covers is out of the dataset's scope (`metrics`). A value labelled both ways is
neutral. The rule of the core and the classes were fixed on aggregate counts of the dev half before the first run."""
from __future__ import annotations

import collections
import csv
import hashlib
import hmac
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path

NAME = "ghissues"
URL = "https://zenodo.org/records/17430335"
FILE_URL = "https://zenodo.org/api/records/19622962/files/Secret-Leak-Detection-Issue-Report.zip/content"
LICENCE = "CC BY 4.0"
# CC BY 4.0, 3(a)(2): the attribution by a URI to the record that names the creators
ATTRIBUTION = ('"Secret Leak Detection in Software Issue Reports using LLMs" (MSR 2026, arXiv:2410.23657), '
               "credited as listed in https://zenodo.org/records/17430335")
ZIP_SHA256 = "0512d4aebc0612c161e9036d26746573acc00fb8a29d7fe3d8156486de559cbf"
MEMBER = "Secret-Leak-Detection-Issue-Report/Data/main_data.csv"
SALT = b"maisecrets/ghissues/2026-10-25"
CASES_FILE = "cases.jsonl"
# the sealed halves (2026-10-25): sha256 of DATA_DIR/<split>/cases.jsonl
SEALED = {"dev": "3af20af9a17e748d63a4c7899056c24652127ecd4117fb11e752711ac66ab02d",
          "holdout": "ff6689f2dd5fe5a6050e95f7bee090eadbef7c40ae0723ef47d9ad268fc28aed"}
SPLITS = tuple(SEALED)


class DataError(ValueError):
    """The data does not have its pinned shape. The message names a place, never a value."""


def issue_of(url: str) -> str:
    m = re.search(r"github\.com/(?:repos/)?([^/]+)/([^/]+)/issues/(\d+)$", url)
    if not m:
        raise DataError("an url that is not a GitHub issue url")
    return f"{m.group(1).lower()}/{m.group(2).lower()}#{m.group(3)}"


def split_of(issue: str) -> str:
    return "holdout" if int(hmac.new(SALT, issue.encode(), hashlib.sha256).hexdigest()[:8], 16) % 2 else "dev"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seal(zip_path: Path, out: Path) -> dict:
    """Write DATA_DIR/<split>/cases.jsonl: one record per issue (url, title, created_at, and per distinct body its
    candidates with value, label, secret_type), read-only. Refused when a half exists. Returns counts and hashes."""
    if _sha(Path(zip_path).read_bytes()) != ZIP_SHA256:
        raise DataError("the zip does not match its pinned sha256")
    csv.field_size_limit(1 << 30)
    with zipfile.ZipFile(zip_path) as z:
        rows = list(csv.DictReader(io.TextIOWrapper(z.open(MEMBER), encoding="utf-8", newline="")))
    issues: dict = {}
    for n, r in enumerate(rows):
        iid = issue_of(r["url"])
        rec = issues.setdefault(iid, {"issue": iid, "url": r["url"], "repository_url": r["repository_url"],
                                      "created_at": r["created_at"], "title": r["title"], "texts": {}})
        rec["texts"].setdefault(r["body"], []).append({"row": n, "value": r["candidate_string"],
                                                       "label": int(r["label"]), "secret_type": r["secret_type"],
                                                       "context_window": r["context_window"]})
    lines = {s: [] for s in SPLITS}
    counts = collections.Counter()
    for iid in sorted(issues):
        rec, s = issues[iid], split_of(iid)
        rec["texts"] = [{"body": b, "candidates": cs} for b, cs in rec["texts"].items()]
        lines[s].append(json.dumps(rec, sort_keys=True, ensure_ascii=False))
        counts[f"{s} issues"] += 1
        for t in rec["texts"]:
            for cand in t["candidates"]:
                counts[f"{s} rows label {cand['label']}"] += 1
    hashes = {}
    for s in SPLITS:
        d = Path(out) / s
        d.mkdir(parents=True, exist_ok=True)
        f = d / CASES_FILE
        if f.exists():
            raise DataError(f"{s}/{CASES_FILE} exists: the split is sealed")
        data = ("\n".join(lines[s]) + "\n").encode("utf-8")
        f.write_bytes(data)
        os.chmod(f, 0o444)
        hashes[s] = _sha(data)
    return {"counts": dict(counts), "sha256": hashes}


def records(data: Path, split: str):
    """The issue records of one sealed half, refused when its file differs from the seal."""
    if split not in SPLITS:
        raise DataError(f"{NAME} has the splits {', '.join(SPLITS)} only, never both at once")
    f = Path(data) / split / CASES_FILE
    if not f.is_file():
        raise DataError(f"{split}/{CASES_FILE} is missing: run `bench/ghissues.py seal` first")
    raw = f.read_bytes()
    if _sha(raw) != SEALED[split]:
        raise DataError(f"{split}/{CASES_FILE} does not match its sealed sha256")
    for line in raw.decode("utf-8").split("\n"):
        if line.strip():
            yield json.loads(line)


# --------------------------------------------------------------------------------------- the core of a candidate
# A candidate is the match of a SecretBench regex: often the key name, the separator and quotes around the secret,
# sometimes more than one line. The core is the secret inside it:
#   a private key block                         -> the whole candidate
#   a URL with user and password                -> the password
#   a candidate of token characters only        -> all of it (`=` only as padding at its end)
#   a value after `:` `=` `=>` (quotes skipped)  -> the longest such value
#   else                                        -> the longest run of token characters (8 or more)
#   else                                        -> the whole candidate without outer space and quotes
_URI_PASSWORD = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]*:([^@\s/]+)@")
_TOKEN_CHARS = r"A-Za-z0-9+/_.~-"     # `=` only as the padding at the end: `key=value` is no token
_TOKEN = re.compile(rf"[{_TOKEN_CHARS}]+={{0,2}}")
_ASSIGNED = re.compile(r"(?:=>|[:=])\s*[\"'`]?([^\s\"'`,;&)\]}>]{6,})")   # a query string ends at &
_RUN = re.compile(rf"[{_TOKEN_CHARS}]{{8,}}={{0,2}}")
_OUTER = " \t\r\n\"'`"


def core_of(value: str) -> tuple:
    """(start, end) of the secret inside a candidate string."""
    lo, hi = 0, len(value)
    while lo < hi and value[lo] in _OUTER:
        lo += 1
    while hi > lo and value[hi - 1] in _OUTER:
        hi -= 1
    inner = value[lo:hi]
    if "-----BEGIN" in inner or not inner:
        return lo, hi
    m = _URI_PASSWORD.search(inner)
    if m:
        return lo + m.start(1), lo + m.end(1)
    if _TOKEN.fullmatch(inner):
        return lo, hi
    best = max(_ASSIGNED.finditer(inner), key=lambda x: (len(x.group(1)), x.start()), default=None)
    if best:
        return lo + best.start(1), lo + best.end(1)
    best = max(_RUN.finditer(inner), key=lambda x: (len(x.group(0)), x.start()), default=None)
    if best:
        return lo + best.start(), lo + best.end()
    return lo, hi


# the regex name of SecretBench to the class of the benchmark; every other name is a token of one provider
CLASS_OF_TYPE = {"Generic Pattern": "secret.generic", "GENERIC_SECRET": "secret.generic",
                 "Zipbooks Password": "secret.password", "APIMatic Password": "secret.password",
                 "Uri": "secret.url_credential", "Jdbc Token": "secret.connection_string",
                 "Slack Webhook": "secret.webhook"}


def class_of(secret_type: str, value: str) -> str:
    if "-----BEGIN" in value and "PRIVATE KEY" in value:
        return "secret.private_key"
    return CLASS_OF_TYPE.get(secret_type, "secret.token")


def _places(text: str, value: str) -> list:
    out, at = [], text.find(value) if value else -1
    while at >= 0:
        out.append(at)
        at = text.find(value, at + len(value))
    return out


def cases_of(record: dict, split: str, stats: collections.Counter):
    """The cases of one issue: one per distinct body."""
    for k, t in enumerate(record["texts"]):
        text = t["body"]
        labels = collections.defaultdict(set)
        types = {}
        for c in t["candidates"]:
            labels[c["value"]].add(c["label"])
            types.setdefault(c["value"], c["secret_type"])
        spans, negatives, cores = [], [], set()
        for value in sorted(labels, key=lambda v: (-len(v), v)):
            lab = labels[value]
            kind = "conflict" if len(lab) > 1 else "true" if 1 in lab else "false"
            places = _places(text, value)
            stats[f"{kind} values"] += 1
            if not places:
                stats[f"{kind} values not in the body (left out)"] += 1
                continue
            stats[f"{kind} places"] += len(places)
            for at in places:
                if kind == "false":
                    negatives.append({"start": at, "end": at + len(value)})
                    continue
                a, b = core_of(value)
                core = (at + a, at + b)
                if core in cores:
                    stats["true places whose core another candidate has (merged)"] += 1
                    continue
                cores.add(core)
                sp = {"start": at, "end": at + len(value), "class": class_of(types[value], value),
                      "label": types[value]}
                if core != (at, at + len(value)):
                    sp["core"] = list(core)
                if kind == "conflict":
                    sp["neutral"] = True
                spans.append(sp)
        stats["cases"] += 1
        stats["cases without a true span"] += not any(not s.get("neutral") for s in spans)
        record_id = f"{record['issue']}/{k}"
        yield {"id": f"{NAME}/{record_id}", "text": text, "channel": "tool", "context": "doc", "path": None,
               "spans": sorted(spans, key=lambda s: (s["start"], s["end"])),
               "negatives": sorted(negatives, key=lambda s: (s["start"], s["end"])),
               "split": split, "tags": [], "region": "us", "lang": "en",
               "source": {"name": NAME, "url": URL, "revision": ZIP_SHA256[:16], "licence": LICENCE,
                          "record": record_id}}


def load(data: Path, split: str, stats: collections.Counter, limit: int = 0):
    n = 0
    for rec in records(data, split):
        for case in cases_of(rec, split, stats):
            yield case
            n += 1
            if limit and n >= limit:
                return


# --------------------------------------------------------------------------------------------- the metrics
def _overlaps(s: int, e: int, ranges) -> bool:
    return any(s < r["end"] and e > r["start"] for r in ranges)


def _fbeta(p, r, beta: float):
    if p is None or r is None:
        return None
    b2 = beta * beta
    return round((1 + b2) * p * r / (b2 * p + r), 4) if p + r else 0.0


def metrics(results) -> dict:
    """Precision over the dataset's candidates: a finding on a true span is right (bench/score.py, on_target), a
    finding on a false candidate is wrong, a finding on no candidate is out of scope and counted apart. Strict recall
    as bench/score.py counts it (the core masked whole). Also per candidate: a candidate is flagged when a finding
    overlaps it."""
    on_target = fp = out = fp_secret = 0
    spans = full = partial = 0
    flagged = collections.Counter()
    for case, sc in results:
        on_target += sum(sc["on_target"].values())
        for s, e, cls in sc["fp_found"]:
            if _overlaps(s, e, case.get("negatives", ())):
                fp += 1
                fp_secret += str(cls).split(".", 1)[0] == "secret"
            else:
                out += 1
        for o in sc["spans"]:
            spans += 1
            full += o["outcome"] == "full"
            partial += o["outcome"] == "partial"
        found = sc.get("found", ())
        for sp in case["spans"]:
            if not sp.get("neutral"):
                flagged["true candidates"] += 1
                flagged["true flagged"] += _overlaps(sp["start"], sp["end"], [{"start": s, "end": e}
                                                                             for s, e in found])
        for ng in case.get("negatives", ()):
            flagged["false candidates"] += 1
            flagged["false flagged"] += any(s < ng["end"] and e > ng["start"] for s, e in found)
    p = round(on_target / (on_target + fp), 4) if on_target + fp else None
    r = round(full / spans, 4) if spans else None
    out_d = {"spans": spans, "full": full, "partial": partial, "missed": spans - full - partial,
             "recall_strict": r, "recall_lenient": round((full + partial) / spans, 4) if spans else None,
             "on_target": on_target, "fp_on_false_candidates": fp, "fp": fp, "findings_out_of_scope": out,
             "precision": p, "f1": _fbeta(p, r, 1.0), "f0_5": _fbeta(p, r, 0.5),
             # added after the first run (2026-10-25): a scanner that also finds personal data is not wrong when an
             # e-mail address inside a false secret candidate is one; only its secret findings count here
             "fp_secret_findings": fp_secret,
             "precision_secret_findings": round(on_target / (on_target + fp_secret), 4) if on_target + fp_secret
             else None}
    if "true candidates" in flagged:
        tp, fpc = flagged["true flagged"], flagged["false flagged"]
        out_d["per_candidate"] = {**dict(flagged), "precision": round(tp / (tp + fpc), 4) if tp + fpc else None,
                                  "recall": round(tp / flagged["true candidates"], 4)}
    return out_d


def main(argv) -> int:
    if argv[:1] == ["seal"] and len(argv) == 3:
        print(json.dumps(seal(Path(argv[1]), Path(argv[2])), indent=1, sort_keys=True))
        return 0
    if argv[:1] == ["verify"] and len(argv) == 2:
        for s in SPLITS:
            f = Path(argv[1]) / s / CASES_FILE
            ok = f.is_file() and _sha(f.read_bytes()) == SEALED[s]
            print(f"{s}: {'matches the seal' if ok else 'DIFFERS from the seal or is missing'}")
        return 0
    sys.stderr.write(__doc__ + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
