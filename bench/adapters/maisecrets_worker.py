"""Scan cases with the maisecrets checkout under --root, in this process. bench/adapters/maisecrets.py starts it with
python -I, a fresh temp home and no variable of a client, so the checkout under test is the only maisecrets it can
import.

    python -I maisecrets_worker.py --root DIR --regions de,us IN.jsonl OUT.jsonl

IN holds {"text", "channel", "path"} per line; OUT gets one JSON list of [start, end, type, rule] per line. A checkout
with maisecrets.detection.Detector (0.6.39 and later) is scanned through it, with no sources, no references and a
fixed host, so nothing of this computer changes the result; an older checkout through detect.scan."""
from __future__ import annotations

import argparse
import json
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--regions", default="de,us")
    ap.add_argument("inp")
    ap.add_argument("out")
    a = ap.parse_args()
    sys.path.insert(0, a.root)
    t0 = time.perf_counter()
    regions = tuple(r for r in a.regions.split(",") if r)
    languages = ("en", "de") if "de" in regions else ("en",)
    try:
        from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host
        det = Detector(regions=Active(regions=("generic",) + regions, languages=languages, source="bench"),
                       sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="benchuser", year=2026))

        def scan(text, channel, path):
            return det.findings(text, channel=channel, path=path or "")
        api = "Detector"
    except ImportError:
        from maisecrets import detect     # before 0.6.39: the regions come from the temp home's config
        api = "detect.scan"

        def scan(text, channel, path):
            return detect.scan(text, channel=channel, path=path or "")
    first = None
    times = []
    with open(a.inp, encoding="utf-8") as fin, open(a.out, "w", encoding="utf-8") as fout:
        for line in fin:
            c = json.loads(line)
            t = time.perf_counter()
            hits = scan(c["text"], c["channel"], c.get("path"))
            times.append(time.perf_counter() - t)
            if first is None:
                first = time.perf_counter() - t0
            fout.write(json.dumps([[m.start, m.end, m.type, m.kind] for m in hits]) + "\n")
    json.dump({"api": api, "cold_start_s": first, "times_s": times}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
