#!/usr/bin/env python3
"""Personal data and secrets in JSON API responses: each tool in its own mode, scored per string field.

    python3 bench/json_bench.py OUT [--n 40] [--seed 7] [--tools maisecrets_record,maisecrets_text,presidio_text,...]

The responses come from bench/json_shapes.py (four service shapes, synthetic values, the expected classes of each
string field). Each tool gets them the way a user of that tool would give them:

- maisecrets_record: `leaves.findings_by_leaf(detector, obj)`, the library's call for a parsed response.
- maisecrets_text, presidio_text, pii_anon_text, detect_secrets_text: the response as JSON text
  (`json.dumps(obj, ensure_ascii=False)`), through the tool's bench adapter; a finding belongs to the string its first
  character stands in (`leaves.json_text` gives the place of each string).
- presidio_structured: presidio-structured's JsonAnalysisBuilder, one entity per key. It does not take a list of
  objects (ValueError), so the response is cut at each list into list-free parts, each analysed alone, as a user
  would have to.

A field is scored per class: a class the field holds and the tool names there is found, one it misses is missed, one
it names that the field does not hold is a false alarm. Timing: CPU time of the scan per response, inside each tool's
own process (the adapters' `times_s`), median and the sum over all responses.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import json_shapes  # noqa: E402

# the classes of the bench adapters (pii.*, secret.*) and of maisecrets' types, as json_shapes.CLASSES
_PII = {"pii.name": "name", "pii.email": "email", "pii.phone": "phone", "pii.iban": "iban", "pii.address": "address",
        "pii.username": "username", "pii.card": "card", "pii.ip": "ip"}
_MS = {"NAME": "name", "EMAIL": "email", "PHONE": "phone", "IBAN": "iban", "ADDRESS": "address",
       "USERNAME": "username", "CARD": "card", "IP": "ip", "SECRET": "secret"}
_PRESIDIO = {"PERSON": "name", "EMAIL_ADDRESS": "email", "PHONE_NUMBER": "phone", "IBAN_CODE": "iban",
             "LOCATION": "address", "CREDIT_CARD": "card", "IP_ADDRESS": "ip"}


def _cls(c: str) -> str:
    if c.startswith("secret"):
        return "secret"
    return _PII.get(c, "other")


def _by_leaf(text_leaves, spans) -> dict:
    """{path: set of classes} from findings in the JSON text: each finding to the string its start stands in."""
    out: dict = {}
    for s, _e, cls in spans:
        for leaf in text_leaves:
            if leaf.start <= s < leaf.end:
                out.setdefault(leaf.path, set()).add(cls)
                break
    return out


def run_maisecrets_record(resps):
    from maisecrets.detection import Active, Detector, leaves
    det = Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="json-bench"))
    preds, times = [], []
    leaves.findings_by_leaf(det, {"warm": "up"})
    for _name, obj, _t in resps:
        t0 = time.process_time()
        found = leaves.findings_by_leaf(det, obj)
        times.append(time.process_time() - t0)
        p: dict = {}
        for leaf, m in found:
            if leaf is not None:
                p.setdefault(leaf.path, set()).add(_MS.get(m.type, "other"))
        preds.append(p)
    return preds, times


def _text_cases(resps):
    from maisecrets.detection import leaves
    cases, places = [], []
    for i, (_name, obj, _t) in enumerate(resps):
        text, lv = leaves.json_text(obj)
        cases.append({"id": i, "text": text, "channel": "tool", "path": None})
        places.append(lv)
    return cases, places


def run_text_tool(resps, tool: str):
    cases, places = _text_cases(resps)
    if tool == "maisecrets_text":
        from bench.adapters import maisecrets as a
        found, timing = a.scan(cases, ROOT, regions="de,us")
    else:
        from importlib import import_module
        a = import_module("bench.adapters." + tool.rsplit("_", 1)[0])
        found, timing = a.scan(cases)
    preds = [_by_leaf(places[i], [(s, e, _cls(c)) for s, e, c, *_ in f]) for i, f in enumerate(found)]
    return preds, list(timing.get("times_s") or [])


_STRUCTURED_WORKER = r'''
import json, sys, time
t0 = time.perf_counter()
from presidio_structured import JsonAnalysisBuilder
builder = JsonAnalysisBuilder()

def parts(x, path=()):
    """List-free parts of x: (path of the part, the part)."""
    if isinstance(x, list):
        for i, v in enumerate(x):
            yield from parts(v, path + (i,))
        return
    if not isinstance(x, dict):
        return
    flat, rest = {}, []
    for k, v in x.items():
        if isinstance(v, list):
            rest.append((k, v))
        elif isinstance(v, dict):
            sub = list(parts(v, path + (k,)))
            for p, part in sub:
                if p == path + (k,):
                    flat[k] = part
                else:
                    rest.append((None, (p, part)))
        else:
            flat[k] = v
    if flat:
        yield path, flat
    for k, v in rest:
        if k is None:
            yield v
        else:
            yield from parts(v, path + (k,))

first, times = None, []
with open(sys.argv[1], encoding="utf-8") as fin, open(sys.argv[2], "w", encoding="utf-8") as fout:
    for line in fin:
        obj = json.loads(json.loads(line)["text"])
        t = time.perf_counter()
        out, failed = [], 0
        for path, part in parts(obj):
            try:
                mapping = builder.generate_analysis(part).entity_mapping
            except Exception:
                failed += 1
                continue
            for key, entity in mapping.items():
                out.append([list(path) + key.split("."), entity])
        times.append(time.perf_counter() - t)
        if first is None:
            first = time.perf_counter() - t0
        fout.write(json.dumps({"fields": out, "failed": failed}) + "\n")
json.dump({"cold_start_s": first, "times_s": times}, sys.stdout)
'''


def run_presidio_structured(resps):
    python = os.environ.get("BENCH_PRESIDIO_PYTHON") or sys.executable
    cases = [{"id": i, "text": json.dumps(obj, ensure_ascii=False), "path": None} for i, (_n, obj, _t) in
             enumerate(resps)]
    tmp_found, timing = _run_raw(python, cases)
    preds = []
    for f in tmp_found:
        p: dict = {}
        for path, entity in f["fields"]:
            key = tuple(int(x) if isinstance(x, str) and x.isdigit() else x for x in path)
            p.setdefault(key, set()).add(_PRESIDIO.get(entity, "other"))
        preds.append(p)
    return preds, list(timing.get("times_s") or [])


def _run_raw(python: str, cases):
    """The worker without the span check of _proc.run_worker (this worker writes fields, not spans)."""
    import shutil
    import tempfile
    from bench.adapters import _proc
    tmp = tempfile.mkdtemp(prefix="bench-presidio-structured-")
    try:
        home = os.path.join(tmp, "home")
        os.mkdir(home)
        inp, out, worker = (os.path.join(tmp, n) for n in ("in.jsonl", "out.jsonl", "worker.py"))
        Path(worker).write_text(_STRUCTURED_WORKER, encoding="utf-8")
        with open(inp, "w", encoding="utf-8") as f:
            for c in cases:
                f.write(json.dumps({"text": c["text"]}) + "\n")
        p = _proc.run([python, "-I", worker, inp, out], "presidio_structured", env=_proc.minimal_env(home), cwd=tmp)
        if p.returncode:
            raise RuntimeError(f"presidio_structured: the worker failed with exit code {p.returncode}")
        with open(out, encoding="utf-8") as f:
            return [json.loads(line) for line in f], json.loads(p.stdout)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def score(resps, preds) -> dict:
    per: dict = {}
    for (_name, _obj, truth), pred in zip(resps, preds):
        for path in set(truth) | set(pred):
            want, got = truth.get(path, set()), pred.get(path, set())
            for c in want | got:
                row = per.setdefault(c, {"found": 0, "missed": 0, "false_alarm": 0})
                if c in want and c in got:
                    row["found"] += 1
                elif c in want:
                    row["missed"] += 1
                else:
                    row["false_alarm"] += 1
    tot = {k: sum(r[k] for r in per.values()) for k in ("found", "missed", "false_alarm")}
    real = tot["found"] + tot["missed"]
    flagged = tot["found"] + tot["false_alarm"]
    return {"per_class": per, "total": tot, "recall": round(tot["found"] / real, 4) if real else None,
            "precision": round(tot["found"] / flagged, 4) if flagged else None}


TOOLS = ("maisecrets_record", "maisecrets_text", "presidio_text", "presidio_structured", "pii_anon_text",
         "detect_secrets_text")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--tools", default=",".join(TOOLS))
    a = ap.parse_args()
    resps = json_shapes.responses(a.seed, a.n)
    kb = sum(len(json.dumps(o, ensure_ascii=False).encode()) for _n, o, _t in resps) / 1024
    report = {"responses": len(resps), "kb": round(kb, 1), "seed": a.seed, "tools": {}}
    for tool in a.tools.split(","):
        if tool == "maisecrets_record":
            preds, times = run_maisecrets_record(resps)
        elif tool == "presidio_structured":
            preds, times = run_presidio_structured(resps)
        else:
            preds, times = run_text_tool(resps, tool)
        s = score(resps, preds)
        s["cpu_ms_median"] = round(statistics.median(times) * 1000, 2) if times else None
        s["cpu_ms_per_kb"] = round(sum(times) * 1000 / kb, 2) if times else None
        report["tools"][tool] = s
        print(tool, json.dumps({k: s[k] for k in ("recall", "precision", "total", "cpu_ms_per_kb")}), flush=True)
    Path(a.out).mkdir(parents=True, exist_ok=True)
    Path(a.out, "json-bench.json").write_text(json.dumps(report, indent=1, default=list), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
