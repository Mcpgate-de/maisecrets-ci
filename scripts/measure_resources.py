#!/usr/bin/env python3
"""Speed and resources of each scanner, measured the same way on the same machine, one scanner after the other.

    python3 scripts/measure_resources.py CANDIDATE OUT [--scanners a,b,...] [--quick]

For each scanner whose environment is set (BENCH_*_PYTHON, BENCH_<BINARY>; maisecrets always) and each text (a short
prompt of about 300 characters, a tool result of 10 KB and one of 1 MB, cut from the candidate's own source and docs as
scripts/release_gate.py cuts its time text):

- **cold start**: the first call in a new process, the import and any model load included (the worker's
  `cold_start_s`, as bench/run.py reports it);
- **warm latency**: median and 95th percentile of the later calls in the same process (the worker's `times_s`). A
  release binary keeps no state between runs, so for it each run is a new process: its latency is one process over
  one file, cold each time, and the table says so;
- **peak RSS**: the maximum resident set size of the process tree (`/usr/bin/time -l` on macOS, `-v` on Linux);
- **install footprint**: the size on disk of the scanner's environment (its virtual environment, its binary, or the
  `maisecrets/` folder of the candidate) and of the model files in it (spaCy and transformer weights), and whether
  torch is installed. Network at run time: a binary runs under a deny-network sandbox on macOS; a Python worker is not
  blocked, and the bench does not observe its network.

The scanners run through their bench adapters (bench/adapters/), so each one has the configuration of Benchmark V3.
The machine (CPU, RAM, OS) and the load average at the start and the end are recorded: other programs share the
machine, and a load above the CPU count makes the times say little. The local NER layer of maisecrets
(docs/NER-EXPERIMENT.md) is measured when BENCH_NER_PYTHON and BENCH_NER are set; otherwise the table repeats the
figures that document states and marks them as not measured here. Writes OUT/resources.json and OUT/resources.md.
Counts and times only; no text is printed."""
from __future__ import annotations

import argparse
import datetime
import importlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import release_gate  # noqa: E402

ORDER = ("maisecrets", "presidio", "preserve", "pii_anon", "gitleaks", "betterleaks", "trufflehog", "detect_secrets",
         "kingfisher", "noseyparker")
ENV = {"presidio": "BENCH_PRESIDIO_PYTHON", "preserve": "BENCH_PRESERVE_PYTHON", "pii_anon": "BENCH_PII_ANON_PYTHON",
       "detect_secrets": "BENCH_DETECT_SECRETS_PYTHON", "gitleaks": "BENCH_GITLEAKS",
       "betterleaks": "BENCH_BETTERLEAKS", "trufflehog": "BENCH_TRUFFLEHOG", "kingfisher": "BENCH_KINGFISHER",
       "noseyparker": "BENCH_NOSEYPARKER"}
BINARIES = ("gitleaks", "betterleaks", "trufflehog", "kingfisher", "noseyparker")
PROMPT = ("Hi, the deploy of the billing service fails since this morning. The build step times out after ten "
          "minutes and the log shows a retry loop on the artifact upload. Could you check the runner config and the "
          "cache settings? Contact me at ops-team@example.org if you need the full log from the job page, thanks.")
# repeats per text: (calls in one worker process, separate runs of a binary)
REPEATS = {"prompt": (200, 9), "tool_10kb": (50, 7), "tool_1mb": (4, 3)}
QUICK = {"prompt": (40, 3), "tool_10kb": (15, 3), "tool_1mb": (2, 2)}
# docs/NER-EXPERIMENT.md, "Cost" and the service table: the figures used when the layer cannot be measured here
NER_DOC = {"source": "docs/NER-EXPERIMENT.md (not measured in this run)",
           "spacy en_core_web_sm": {"per_document_ms": "12 / 38 (median / p95)", "memory_mb": "137 after load, 168 "
                                    "after the documents"},
           "D3 (the support-copilot setting)": {"per_document_ms": "33 / 88", "memory": "+ 0.7 GB"},
           "GLiNER multi v2.1": {"per_document_ms": "152 / 411", "memory": "+ 3.5 GB"}}


def machine() -> dict:
    out = {"os": f"{platform.system()} {platform.release()}", "machine": platform.machine(),
           "cpus": os.cpu_count()}
    if sys.platform == "darwin":
        q = lambda key: subprocess.run(["sysctl", "-n", key], capture_output=True, text=True).stdout.strip()  # noqa
        out["cpu"] = q("machdep.cpu.brand_string")
        out["ram_gb"] = round(int(q("hw.memsize") or 0) / 2 ** 30, 1)
        out["os"] = "macOS " + subprocess.run(["sw_vers", "-productVersion"], capture_output=True,
                                              text=True).stdout.strip()
    else:
        try:
            info = Path("/proc/cpuinfo").read_text()
            m = re.search(r"model name\s*:\s*(.+)", info)
            out["cpu"] = m.group(1) if m else platform.processor()
            mem = re.search(r"MemTotal:\s*(\d+)", Path("/proc/meminfo").read_text())
            out["ram_gb"] = round(int(mem.group(1)) / 2 ** 20, 1) if mem else None
        except OSError:
            out["cpu"] = platform.processor()
    return out


def texts(cand: Path, scratch: Path) -> dict:
    big = release_gate._time_text(cand, scratch / "resources-text.txt").read_text(encoding="utf-8")
    return {"prompt": PROMPT, "tool_10kb": big[:10_240], "tool_1mb": big[:1_000_000]}


# ------------------------------------------------------------------ the process wrapper: peak RSS of every child

TIME_CMD = ["/usr/bin/time", "-l"] if sys.platform == "darwin" else ["/usr/bin/time", "-v"]


def peak_rss_bytes(stderr: str) -> int | None:
    """The maximum resident set size that /usr/bin/time wrote: bytes on macOS (-l), kilobytes on Linux (-v)."""
    m = re.search(r"(\d+)\s+maximum resident set size", stderr)
    if m:
        return int(m.group(1))
    m = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr)
    return int(m.group(1)) * 1024 if m else None


class Recorder:
    """Wraps bench/adapters/_proc.run: each scanner process runs under /usr/bin/time; the peak RSS and the wall time
    of each are recorded. Only the RSS line of stderr is read; stderr can hold a case value and is never shown."""

    def __init__(self):
        from bench.adapters import _proc
        self.proc, self.orig, self.calls = _proc, _proc.run, []

    def __enter__(self):
        def run(cmd, name, env, cwd, timeout=0):
            t0 = time.perf_counter()
            p = self.orig(TIME_CMD + list(cmd), name, env, cwd, timeout)
            self.calls.append({"rss": peak_rss_bytes(p.stderr or ""), "wall_s": time.perf_counter() - t0})
            return p
        self.proc.run = run
        return self

    def __exit__(self, *exc):
        self.proc.run = self.orig


def _stats(xs: list) -> dict:
    xs = sorted(xs)
    if not xs:
        return {}
    return {"median_ms": round(1000 * statistics.median(xs), 3), "p95_ms": round(1000 * xs[int(0.95 * (len(xs) - 1))],
                                                                                   3), "n": len(xs)}


def _case(text: str, kind: str, n: int) -> dict:
    return {"id": f"{kind}-{n}", "text": text, "channel": "prompt" if kind == "prompt" else "tool",
            "context": "prose" if kind == "prompt" else "log", "path": None, "spans": []}


def measure_cell(scanner: str, text: str, kind: str, cand: Path, repeats: tuple) -> dict:
    """One scanner on one text: cold start, warm latency, peak RSS."""
    module = importlib.import_module(f"bench.adapters.{scanner}")
    calls, runs = repeats
    try:
        with Recorder() as rec:
            if scanner in BINARIES:
                per_run = []
                for i in range(runs):
                    before = len(rec.calls)
                    _, timing = module.scan([_case(text, kind, i)])
                    # every process of the run: noseyparker runs `scan`, then `report`
                    per_run.append(sum(c["wall_s"] for c in rec.calls[before:]))
                out = {"mode": "one process per run (a binary keeps no state)", "cold_start_ms":
                       round(1000 * per_run[0], 1), "warm": _stats(per_run[1:] or per_run)}
            else:
                cases = [_case(text, kind, i) for i in range(calls)]
                if scanner.startswith("maisecrets"):
                    _, timing = module.scan(cases, cand, "de,us")
                else:
                    _, timing = module.scan(cases)
                times = timing.get("times_s") or []
                out = {"mode": "one process, calls in a row", "cold_start_ms":
                       round(1000 * (timing.get("cold_start_s") or 0), 1), "warm": _stats(times[1:])}
            rss = [c["rss"] for c in rec.calls if c["rss"]]
            out["peak_rss_mb"] = round(max(rss) / 2 ** 20, 1) if rss else None
            return out
    except Exception as e:   # one cell that fails (a size limit, a crash) does not stop the matrix
        # the message of an adapter names only the scanner; any other message is left out, it could quote the text
        from bench.adapters import _proc
        return {"error": type(e).__name__ + (": " + str(e)[:160] if isinstance(e, _proc.AdapterError) else "")}


def du(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            p = os.path.join(root, f)
            if not os.path.islink(p):
                try:
                    total += os.path.getsize(p)
                except OSError:
                    pass
    return total


MODEL_DIRS = re.compile(r"^(en_core_web_\w+|de_core_news_\w+|xx_\w+|models--.+|gliner\w*)$")


def footprint(scanner: str, cand: Path, env: dict) -> dict:
    if scanner.startswith("maisecrets"):
        return {"what": "maisecrets/ of the candidate (Python standard library only)",
                "disk_mb": round(du(cand / "maisecrets") / 2 ** 20, 1), "models_mb": 0, "torch": False}
    target = env.get(ENV[scanner], "")
    if scanner in BINARIES:
        return {"what": "the release binary", "disk_mb": round(du(Path(target)) / 2 ** 20, 1), "models_mb": 0,
                "torch": False}
    venv = Path(target).parent.parent   # <venv>/bin/python
    models = 0
    for root, dirs, _files in os.walk(venv):
        for d in list(dirs):
            if MODEL_DIRS.match(d):
                models += du(Path(root) / d)
                dirs.remove(d)
    torch = any((p / "torch").is_dir() for p in venv.glob("lib/python*/site-packages"))
    return {"what": "its virtual environment", "disk_mb": round(du(venv) / 2 ** 20, 1),
            "models_mb": round(models / 2 ** 20, 1), "torch": torch}


def network_note(scanner: str) -> str:
    if scanner.startswith("maisecrets"):
        return "no (standard library, no network code in the detector)"
    if scanner in BINARIES:
        return "denied by the sandbox on macOS (validation off by flag)"
    return "not blocked, not observed"


def available(scanner: str, env: dict) -> bool:
    if scanner == "maisecrets":
        return True
    if scanner == "maisecrets_ner":
        return bool(env.get("BENCH_NER_PYTHON") and env.get("BENCH_NER"))
    return bool(env.get(ENV.get(scanner, "")))


def markdown(res: dict) -> str:
    m, load = res["machine"], res["load_average"]
    lines = ["## Speed and resources", "",
             f"Machine: {m.get('cpu')}, {m.get('cpus')} CPUs, {m.get('ram_gb')} GB RAM, {m.get('os')}. "
             f"Load average {load['start']} at the start, {load['end']} at the end"
             + (" (above the CPU count: the times say little)" if max(load["start"], load["end"]) > (m.get("cpus") or 1)
                else "") + ". One scanner after the other; peak RSS of the scanner's process tree.", "",
             "| Scanner | Text | Mode | Cold start ms | Warm median ms | Warm p95 ms | Peak RSS MB |",
             "|---|---|---|---:|---:|---:|---:|"]
    for s, r in res["scanners"].items():
        if r.get("skipped"):
            lines.append(f"| {s} | – | {r['skipped']} | | | | |")
            continue
        for kind, c in r["cells"].items():
            if "error" in c:
                lines.append(f"| {s} | {kind} | failed: {c['error'][:60]} | | | | |")
                continue
            w = c.get("warm") or {}
            mode = "process per run" if c["mode"].startswith("one process per run") else "warm process"
            lines.append(f"| {s} | {kind} | {mode} | {c['cold_start_ms']} | {w.get('median_ms', '–')} | "
                         f"{w.get('p95_ms', '–')} | {c.get('peak_rss_mb', '–')} |")
    lines += ["", "| Scanner | Install footprint | Disk MB | Model files MB | torch | Network at run time | GPU |",
              "|---|---|---:|---:|---|---|---|"]
    for s, r in res["scanners"].items():
        f = r.get("footprint") or {}
        if f:
            lines.append(f"| {s} | {f['what']} | {f['disk_mb']} | {f['models_mb']} | {'yes' if f['torch'] else 'no'} | "
                         f"{r['network']} | not used (CPU only) |")
    if res.get("ner_doc"):
        lines += ["", "maisecrets with the local NER layer: not measured here (BENCH_NER_PYTHON, BENCH_NER not set). "
                  "The figures of docs/NER-EXPERIMENT.md: " + "; ".join(
                      f"{k}: {v['per_document_ms']} ms per document, memory {v.get('memory_mb') or v.get('memory')}"
                      for k, v in res["ner_doc"].items() if isinstance(v, dict)) + "."]
    return "\n".join(lines) + "\n"


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("candidate", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--scanners", default=",".join(ORDER + ("maisecrets_ner",)))
    ap.add_argument("--quick", action="store_true", help="fewer repeats (a check of the command, not a measurement)")
    a = ap.parse_args(argv)
    cand, env = a.candidate.resolve(), dict(os.environ)
    a.out.mkdir(parents=True, exist_ok=True)
    tx = texts(cand, a.out)
    repeats = QUICK if a.quick else REPEATS
    res = {"date": datetime.date.today().isoformat(), "machine": machine(),
           "candidate": release_gate._git("rev-parse", "HEAD", cwd=cand), "quick": a.quick,
           "texts": {k: len(v.encode("utf-8")) for k, v in tx.items()},
           "load_average": {"start": round(os.getloadavg()[0], 1)}, "scanners": {}}
    for s in [x for x in a.scanners.split(",") if x]:
        if not available(s, env):
            res["scanners"][s] = {"skipped": "not installed here (its environment variable is not set)"}
            if s == "maisecrets_ner":
                res["ner_doc"] = NER_DOC
            continue
        cells = {}
        for kind in ("prompt", "tool_10kb", "tool_1mb"):
            cells[kind] = measure_cell(s, tx[kind], kind, cand, repeats[kind])
            print(f"{s} {kind}: " + json.dumps(cells[kind]), flush=True)
        res["scanners"][s] = {"cells": cells, "footprint": footprint(s, cand, env), "network": network_note(s)}
    res["load_average"]["end"] = round(os.getloadavg()[0], 1)
    (a.out / "resources.json").write_text(json.dumps(res, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    text = markdown(res)
    (a.out / "resources.md").write_text(text, encoding="utf-8")
    (a.out / "resources-text.txt").unlink(missing_ok=True)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
