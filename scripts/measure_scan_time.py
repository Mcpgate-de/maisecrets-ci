"""Measure how long one detector scan takes, on synthetic inputs. docs/BENCHMARKS.md has the results per release.

    python3 scripts/measure_scan_time.py [--maisecrets DIR] [--channel prompt|tool] [--runs 15]

Inputs: a typed prompt of 1 KB, 70 KB of Python code (the start of maisecrets/detection/core.py, or detect.py, of
the measured checkout),
a 70 KB log, and 70 KB of configuration with about 2,100 password labels. Each is scanned once to warm up and then
--runs times; the script prints the median. "import + first scan" runs in a new process, as each hook call does.
The inputs are built at run time and nothing is printed but the times. The store is a fresh temp directory.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def inputs(ms_dir: str) -> dict:
    rnd = random.Random(3)
    prompt = ("Kannst du bitte im Service den Retry-Mechanismus anpassen? Der Test test_retry_backoff schlaegt fehl, "
              "wenn das Timeout unter 200 ms liegt. Schau dir src/net/client.py an und die Config in config.yaml. ") * 5
    core = Path(ms_dir, "maisecrets", "detection", "core.py")
    code = (core if core.is_file() else Path(ms_dir, "maisecrets", "detect.py")).read_text(encoding="utf-8")[:70_000]
    log = "\n".join(f"2026-10-14T10:{i % 60:02d}:00Z INFO request id={rnd.getrandbits(64):016x} user=u{i} "
                    f"path=/api/v1/items/{i} status=200 ms={i % 97}" for i in range(700))[:70_000]
    letters = "abcdefghijklmnopqrstuvwxyz"
    config = "\n".join(f"db_password_{i} = \"{''.join(rnd.choice(letters) for _ in range(12))}\""
                       for i in range(2200))[:70_000]
    sizes = {name: len(text) for name, text in (("prompt", prompt), ("code", code), ("log", log), ("config", config))}
    assert sizes == {"prompt": 1005, "code": 70_000, "log": 70_000, "config": 70_000}, sizes
    return {"prompt 1 KB": prompt, "code 70 KB": code, "log 70 KB": log,
            f"config 70 KB, {config.count(chr(10)) + 1:,} password labels": config}


def first_scan(ms_dir: str, channel: str) -> float:
    """Import plus one scan of the prompt in a new process, the cost each hook call pays."""
    code = ("import sys,time; t=time.perf_counter(); sys.path.insert(0, sys.argv[1]); from maisecrets import detect;"
            "import inspect; kw={'channel': sys.argv[2]} if 'channel' in inspect.signature(detect.scan).parameters "
            "else {}; detect.scan('password: see the wiki page', **kw); print(time.perf_counter()-t)")
    times = []
    for _ in range(5):
        r = subprocess.run([sys.executable, "-B", "-c", code, ms_dir, channel], capture_output=True, text=True,
                           check=True)
        times.append(float(r.stdout.strip()))
    return statistics.median(times)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--maisecrets", default=str(ROOT))
    ap.add_argument("--channel", default="prompt", choices=("prompt", "tool"))
    ap.add_argument("--runs", type=int, default=15)
    a = ap.parse_args(argv)

    home = tempfile.mkdtemp(prefix="maisecrets-time-")
    try:
        with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
            json.dump({"backend": "jsonfile", "allow_plaintext_store": True, "regions": ["de"]}, fh)
        os.environ["MAISECRETS_HOME"] = home
        os.environ["MAISECRETS_LOCALE"] = "de_DE"
        sys.path.insert(0, a.maisecrets)
        import inspect

        from maisecrets import detect
        kw = {"channel": a.channel} if "channel" in inspect.signature(detect.scan).parameters else {}

        print(f"Python {sys.version.split()[0]}, channel {a.channel}, median of {a.runs} runs")
        print(f"  {'import + first scan (new process)':40s} {first_scan(a.maisecrets, a.channel) * 1000:8.1f} ms")
        for name, text in inputs(a.maisecrets).items():
            detect.scan(text, **kw)
            xs = []
            for _ in range(a.runs):
                t = time.perf_counter()
                detect.scan(text, **kw)
                xs.append(time.perf_counter() - t)
            print(f"  {name:40s} {statistics.median(xs) * 1000:8.1f} ms")
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
