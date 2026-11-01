"""Run the bench/run.py jobs of bench/run_all_v3.sh side by side, one process per CPU.

    python3 bench/run_jobs.py JOBS.jsonl [N]

JOBS.jsonl holds one JSON list per line: the arguments of one job, the first one the output file. N is the number of
jobs at once (0 or none: the CPUs of this machine). Each job is its own process and writes its own output file, so the
results are the same as one after the other; its console text goes to OUT.log and is printed whole when the job ends.
The exit is 1 when a job failed, after all have ended. CPU time is not measured here: the release gate times the
detector apart, in turns, on a quiet machine (scripts/release_gate.py --time)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def run(args: list) -> tuple:
    out = Path(args[0])
    t0 = time.monotonic()
    with open(str(out) + ".log", "w", encoding="utf-8") as log:
        rc = subprocess.run(args[1:], stdout=log, stderr=subprocess.STDOUT).returncode
    return out, rc, time.monotonic() - t0


def main(argv: list) -> int:
    jobs = [json.loads(line) for line in Path(argv[0]).read_text(encoding="utf-8").splitlines() if line.strip()]
    n = int(argv[1]) if len(argv) > 1 and int(argv[1]) > 0 else (os.cpu_count() or 1)
    failed = 0
    with ThreadPoolExecutor(max_workers=n) as pool:
        for out, rc, sec in pool.map(run, jobs):
            print(Path(str(out) + ".log").read_text(encoding="utf-8"), end="")
            print(f"[{out.name}: exit {rc}, {sec:.0f} s]", flush=True)
            failed += rc != 0
    print(f"{len(jobs)} jobs, {n} at once, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
