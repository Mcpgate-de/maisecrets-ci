#!/usr/bin/env python3
"""maisecrets as the mcpgate gateway runs it: one call per string leaf of a tool response, in-process, with the
field name in front ("username: jdoe"), the configuration of the gateway's MaisecretsDetector (regions generic and
de, languages en and de, channel tool, no sources, no host user), no NER. It reads bench/gatewaygen.py and reports

- recall per class and per field label, precision per field label (the parent key for person-like keys, as the
  gateway's metric names them: author.username), with each false positive named by the look-alike it falls on;
- with --mode fields, the same with the field path given as fields= instead of the prefix;
- the time of each call, by leaf length (the fastest of --repeat calls), and the time of a whole response (every leaf
  once, the fastest of --repeat whole passes), which is what the gateway's shadow measures.

Precision counts findings: a finding on a labelled span is right, one elsewhere is a false positive.

The gateway rules (detector_shadow._leaves and _label_prefix, ai-gateway 7b5470bd8): a dict key adds ".key" to the
path, a list item keeps its list's path, the prefix is the last key and ": " unless that key is empty, a number or a
cursor field, and a leaf over 32 KiB is skipped. It prints counts, field labels and kinds only, never a value.

    python3 bench/gateway_report.py [--maisecrets DIR] [--split dev] [--json OUT] [--repeat 3]

Times need a quiet host (the netcup reference host, docs/BENCHMARK-V3.md); the counts do not."""
from __future__ import annotations

import argparse
import collections
import json
import re
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import gatewaygen, score  # noqa: E402
from bench.adapters import maisecrets as adapter  # noqa: E402

MAX_LEAF = 32 * 1024
PERSON_KEYS = {"name", "username", "displayname", "email", "fullname"}
_CURSOR = re.compile(
    r"^(?:(?:next|prev|previous|delta)_?link|(?:(?:next|prev|previous|start|starting|end|ending|search)_?)?"
    r"(?:page_?token|cursor|sync_?token|continuation(?:_?token)?|etag|marker|after|before|offset_?token|"
    r"resume_?token|scroll_?id|page))$", re.I)
BUCKETS = (32, 128, 512, 2048, 8192, MAX_LEAF)


def leaves(obj, path: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from leaves(v, path)
    elif isinstance(obj, str):
        yield path, obj


def prefix(path: str) -> str:
    last = path.rsplit(".", 1)[-1]
    return "" if not last or last.isdigit() or _CURSOR.match(last) else f"{last}: "


def label(path: str) -> str:
    parts = path.split(".")
    return ".".join(parts[-2:]) if len(parts) > 1 and parts[-1].lower() in PERSON_KEYS else parts[-1]


def bucket(n: int) -> str:
    return next(f"<={b}" for b in BUCKETS if n <= b)


def detector(root: Path):
    sys.path.insert(0, str(root))
    from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host, resolve_regions
    active = resolve_regions({"regions": ["de"]}, locale="en")
    return Detector(regions=Active(regions=active.regions, languages=active.languages, source="gateway"),
                    sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=None))


def run(det, items, repeat: int, mode: str = "prefix") -> dict:
    spans, fps, hits = [], [], collections.Counter()
    leaf_ms, resp_ms = collections.defaultdict(list), collections.defaultdict(list)
    det.findings("warm: a first call loads the rules", channel="tool")
    for case, o, obj in items:
        service = case["tags"][0].split(":", 1)[1]
        calls = []
        for path, raw in leaves(obj):
            text, sp, looks = o.leaf(raw)
            if len(text) > MAX_LEAF:
                continue
            pre = prefix(path) if mode == "prefix" else ""
            fields = [(0, len(text), tuple(path.split(".")))] if mode == "fields" and path and text else None
            calls.append((path, text, sp, looks, pre, fields))
        # the response as the gateway reads it: every leaf once, in order; the fastest of `repeat` whole passes
        best, found_of, leaf_best = None, [], [None] * len(calls)
        for _ in range(repeat):
            found_of, total = [], 0.0
            for k, (path, text, sp, looks, pre, fields) in enumerate(calls):
                t = time.perf_counter()
                found_of.append(det.findings(pre + text, channel="tool", fields=fields))
                d = time.perf_counter() - t
                total += d
                leaf_best[k] = d if leaf_best[k] is None else min(leaf_best[k], d)
            best = total if best is None else min(best, total)
        resp_ms[service].append(best * 1000)
        for (path, text, sp, looks, pre, fields), found, d in zip(calls, found_of, leaf_best):
            leaf_ms[bucket(len(text))].append(d * 1000)
            n = len(pre)
            ms = [(m.start - n, m.end - n, m.type) for m in found if m.end > n]
            sc = score.score_case({"text": text, "spans": sp}, ms, adapter.SCOPE)
            hits[label(path)] += sum(sc["on_target"].values())
            for s, out in zip(sp, sc["spans"]):
                spans.append({"class": s["class"], "outcome": out["outcome"], "label": label(path),
                              "service": service, "lang": case["lang"]})
            for s, e, typ in sc["fp_found"]:
                look = next((lk for lk in looks if s < lk["end"] and e > lk["start"]), None)
                fps.append({"type": typ, "label": label(path), "kind": look["kind"] if look else "structure",
                            "service": service})
    return {"spans": spans, "fps": fps, "hits": hits, "leaf_ms": leaf_ms, "resp_ms": resp_ms}


def _pct(xs, q):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(q * len(xs)))], 3) if xs else None


def summary(r: dict) -> dict:
    def table(key):
        rows = collections.defaultdict(collections.Counter)
        for s in r["spans"]:
            rows[key(s)]["spans"] += 1
            rows[key(s)][s["outcome"]] += 1
        return {k: {**v, "recall": round(v["full"] / v["spans"], 3)} for k, v in sorted(rows.items())}
    found = sum(r["hits"].values())   # findings on a labelled span, each finding once
    fp_label = collections.Counter(f["label"] for f in r["fps"])
    all_resp = [x for v in r["resp_ms"].values() for x in v]
    return {
        "spans": len(r["spans"]), "fp": len(r["fps"]),
        "precision": round(found / max(1, found + len(r["fps"])), 4),
        "by_class": table(lambda s: s["class"]),
        "by_label": table(lambda s: f"{s['label']}/{s['class']}"),
        "by_service": table(lambda s: s["service"]),
        "precision_by_label": {k: {"findings": r["hits"][k] + fp_label[k], "fp": fp_label[k],
                                   "precision": round(r["hits"][k] / (r["hits"][k] + fp_label[k]), 4)}
                               for k in sorted(set(r["hits"]) | set(fp_label)) if r["hits"][k] + fp_label[k]},
        "fp_by_kind": dict(collections.Counter(f["kind"] for f in r["fps"]).most_common()),
        "fp_by_kind_label_type": [[*k, n] for k, n in collections.Counter(
            (f["kind"], f["label"], f["type"]) for f in r["fps"]).most_common(40)],
        "leaf_ms": {k: {"n": len(v), "p50": _pct(v, .5), "p95": _pct(v, .95), "max": round(max(v), 3)}
                    for k, v in sorted(r["leaf_ms"].items(), key=lambda kv: int(kv[0][2:]))},
        "response_ms": {"all": {"n": len(all_resp), "p50": _pct(all_resp, .5), "p95": _pct(all_resp, .95),
                                "mean": round(statistics.fmean(all_resp), 3)},
                        **{k: {"n": len(v), "p50": _pct(v, .5), "p95": _pct(v, .95)}
                           for k, v in sorted(r["resp_ms"].items())}},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--maisecrets", type=Path, default=ROOT)
    ap.add_argument("--split", default="dev", choices=("dev", "val", "all"))
    ap.add_argument("--repeat", type=int, default=3, help="calls per leaf; the fastest counts")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--mode", default="prefix", choices=("prefix", "fields"),
                    help="the field name as a prefix in the text (the gateway today) or as fields= (since 0.8)")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    items = [x for x in gatewaygen.objects() if a.split == "all" or x[0]["split"] == a.split]
    if a.limit:
        items = items[:a.limit]
    det = detector(a.maisecrets.resolve())
    rep = {"split": a.split, "cases": len(items), "repeat": a.repeat, "mode": a.mode,
           **summary(run(det, items, a.repeat, a.mode))}
    out = json.dumps(rep, indent=1, sort_keys=True)
    if a.json:
        a.json.write_text(out + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
