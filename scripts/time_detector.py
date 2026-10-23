#!/usr/bin/env python3
"""The CPU time of one checkout's detector on fixed texts, for the release gate.

    python3 -I scripts/time_detector.py CHECKOUT TEXT_FILE

Prints one JSON line: {"tool_1mb": s, "prompt": ms}, both CPU time of this process (time.process_time), the median
of five runs after a warm-up. CPU time counts this process only, so another program on the machine changes it less
than the wall clock; the gate still measures base and candidate in turns and reports the load average. TEXT_FILE is
the same file for both checkouts, so they scan the same characters. Standard library only; no home folder is read.
"""
from __future__ import annotations

import json
import statistics
import sys
import time

PROMPT = "please check the deploy, it fails since this morning with a timeout on the build step " * 3


def main(argv: list[str]) -> int:
    checkout, text_file = argv
    sys.path.insert(0, checkout)
    from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host
    det = Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="time"),
                   sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="time", year=2026))
    text = open(text_file, encoding="utf-8").read()
    det.findings(text[:20000], channel="tool", path="")   # loads and compiles the rules: not part of a scan
    runs = []
    for _ in range(5):
        t0 = time.process_time()
        det.findings(text, channel="tool", path="")
        runs.append(time.process_time() - t0)
    t0 = time.process_time()
    for _ in range(200):
        det.findings(PROMPT, channel="prompt", path="")
    prompt_ms = (time.process_time() - t0) / 200 * 1000
    print(json.dumps({"tool_1mb": round(statistics.median(runs), 3), "prompt": round(prompt_ms, 3)}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
