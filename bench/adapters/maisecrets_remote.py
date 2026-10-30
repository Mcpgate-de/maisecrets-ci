"""maisecrets with its remote detector (maisecrets/detection/remote.py) against a running service: the deterministic
detector of the checkout first, unchanged, then RemoteDetector.ask of the same checkout per case, as the library
does. It proves that the remote path adds nothing and loses nothing against the NER experiment's layer
(bench/adapters/maisecrets_ner.py) when both read the same model.

    BENCH_REMOTE_URL=http://127.0.0.1:8765/   the service (examples/ner_service.py, or any service of the format)
    BENCH_REMOTE_FORMAT=hf                    hf or presidio
    BENCH_REMOTE_MASK=1                       1: the rules' findings go out as filler (the default of the library);
                                              0: the whole text, as the experiment's model read it

No time budget: each request may take 60 s, so the benchmark measures what the service finds, not how fast it is.
BENCH_NER_SIDECAR, when set, gets per case the spans the layer added, as for maisecrets_ner."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from bench.adapters import _proc
from bench.adapters import maisecrets as det

NAME = "maisecrets+remote"
SCOPE = det.SCOPE


def _remote(root: Path):
    sys.path.insert(0, str(root))
    try:
        from maisecrets.detection import remote
    finally:
        sys.path.remove(str(root))
    url = os.environ.get("BENCH_REMOTE_URL", "")
    if not url:
        raise _proc.AdapterError("maisecrets_remote: BENCH_REMOTE_URL names no service")
    return remote.RemoteDetector(url, format=os.environ.get("BENCH_REMOTE_FORMAT", "hf"), timeout=60,
                                 max_chars=10 ** 9, mask=os.environ.get("BENCH_REMOTE_MASK", "1") != "0")


def describe(root: Path, regions: str) -> dict:
    d = det.describe(root, regions)
    d.update(scanner=NAME, remote={"url": os.environ.get("BENCH_REMOTE_URL", ""),
                                   "format": os.environ.get("BENCH_REMOTE_FORMAT", "hf"),
                                   "mask": os.environ.get("BENCH_REMOTE_MASK", "1") != "0"},
             network="loopback only", dependencies="Python standard library; the remote service")
    return d


def scan(cases, root: Path, regions: str = "de,us", languages: str = ""):
    found, timing = det.scan(cases, root, regions, languages=languages) if languages else det.scan(cases, root, regions)
    ner = _remote(root)
    added, times = [], []
    for c, fs in zip(cases, found):
        t = time.monotonic()
        spans, status = ner.ask(c["text"], [(s, e) for s, e, _cls, _rule in fs])
        times.append(time.monotonic() - t)
        if status.state != "ok":
            raise _proc.AdapterError(f"maisecrets_remote: the service was {status.state} ({status.reason}) "
                                     f"for case {c['id']}")
        added.append([[s, e, score] for s, e, _type, score in spans])
    side = os.environ.get("BENCH_NER_SIDECAR")
    if side:
        with open(side, "w", encoding="utf-8") as f:
            for c, row in zip(cases, added):
                # the library drops a span on a finding of the rules without naming it: no conflicts here
                f.write(json.dumps({"id": c["id"], "add": row, "conflicts": []}) + "\n")
    merged = [list(fs) + [(s, e, "pii.name", "ner:person") for s, e, _score in row] for fs, row in zip(found, added)]
    t = [a + b for a, b in zip(timing.get("times_s", []), times)] or times
    return _proc.check("maisecrets_remote", cases, merged), {**timing, "times_s": t, "ner_times_s": times}


if __name__ == "__main__":
    sys.exit("run through bench/run.py --scanner maisecrets_remote")
