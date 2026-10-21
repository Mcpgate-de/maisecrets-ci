"""The cost of a PERSON layer, apart from its quality (docs/NER-EXPERIMENT.md, "Performance"). Runs in the Python of
the NER environment; prints one JSON object. No text is printed.

    python -I bench/ner/perf.py BACKEND TEXTS.jsonl

TEXTS.jsonl holds {"text"} per line (the documents to time). Measured in this one process: the import and model load,
the first call, each document once (median and 95th percentile, throughput), one input of 1 MB made of the documents
joined, and 1,000 calls of one short text on the loaded model; the peak memory after each step."""
from __future__ import annotations

import json
import os
import resource
import statistics
import sys
import time

T0 = time.perf_counter()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import person_worker  # noqa: E402


def rss_mb() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(r / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)


def pct(xs, q):
    xs = sorted(xs)
    return round(1000 * xs[min(len(xs) - 1, int(q * (len(xs) - 1)))], 2)


def main() -> int:
    backend, path = sys.argv[1:3]
    texts = [json.loads(line)["text"] for line in open(path, encoding="utf-8")]
    out = {"documents": len(texts), "bytes": sum(len(t.encode("utf-8")) for t in texts)}
    t = time.perf_counter()
    find, desc = person_worker.load(backend)
    out.update(desc)
    out["load_s"] = round(time.perf_counter() - t, 3)
    out["rss_after_load_mb"] = rss_mb()
    t = time.perf_counter()
    find("The report was signed on Monday.")
    out["first_call_ms"] = round(1000 * (time.perf_counter() - t), 1)
    out["cold_start_s"] = round(time.perf_counter() - T0, 3)
    times = []
    for text in texts:
        t = time.perf_counter()
        find(text)
        times.append(time.perf_counter() - t)
    out.update(warm_p50_ms=pct(times, 0.5), warm_p95_ms=pct(times, 0.95),
               warm_mean_ms=round(1000 * statistics.mean(times), 2),
               kb_per_s=round(out["bytes"] / 1024 / sum(times), 1), rss_after_documents_mb=rss_mb())
    big = "\n".join(texts)
    while len(big.encode("utf-8")) < 1_000_000:
        big += "\n" + big
    big = big.encode("utf-8")[:1_000_000].decode("utf-8", "ignore")
    t = time.perf_counter()
    found = find(big)
    out.update(one_mb_s=round(time.perf_counter() - t, 2), one_mb_spans=len(found), rss_after_one_mb_mb=rss_mb())
    short = "Please forward the invoice to the team before Friday."
    times = []
    for _ in range(1000):
        t = time.perf_counter()
        find(short)
        times.append(time.perf_counter() - t)
    out.update(repeat_1000_p50_ms=pct(times, 0.5), repeat_1000_p95_ms=pct(times, 0.95),
               repeat_1000_first_ms=round(1000 * times[0], 2), repeat_1000_last_ms=round(1000 * times[-1], 2),
               rss_after_repeat_mb=rss_mb())
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
