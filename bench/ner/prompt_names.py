"""Names in typed prompts with the local name service (0.8.7, `/maisecrets:ner local`). Counts and times only, no text
of a case is printed or written.

    python3 bench/ner/prompt_names.py dialogpii DATA_DIR CUT OUT.json [--url URL] [--timeout-ms MS] [--parallel N]
    python3 bench/ner/prompt_names.py ghissues DATA_DIR CUT OUT.json [--url URL] [--timeout-ms MS] [--parallel N]

Each case of the `dev` split is cut to its first CUT characters, at the last space before CUT (the length of a typed
prompt; 0 keeps the whole text). The rules run first (bench adapter `maisecrets`, regions de and us); the service
then gets the text with each finding of the rules as filler, as the plugin sends a prompt, within the timeout of the
plugin (300 ms by default). A request that does not answer in time counts as no name, as in the plugin.

- dialogpii: the labelled names (class pii.name) found whole by the rules, and by the rules and the service; the
  service's spans that overlap no labelled value of any class, per 1,000 words.
- ghissues: names are not labelled there, so each span of the service counts, per 1,000 words: an upper bound for
  the false masks in developer prose.
- Both: the time of each request (median, 95th percentile) and the requests that got no answer in time.

`--parallel N` keeps N requests open at once, as N people (or a gateway with N tool results) would; 1 sends one
request after the other."""
from __future__ import annotations

import argparse
import collections
import json
import re
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from bench import dialogpii, ghissues  # noqa: E402
from bench.adapters import maisecrets as det  # noqa: E402
from maisecrets.detection import remote  # noqa: E402

WORD = re.compile(r"\w+")


def cut_case(c: dict, cut: int) -> dict:
    text = c["text"]
    if not cut or len(text) <= cut:
        return c
    end = text.rfind(" ", 0, cut)
    end = end if end > 0 else cut
    return dict(c, text=text[:end], spans=[s for s in c.get("spans", []) if s["end"] <= end])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source", choices=("dialogpii", "ghissues"))
    ap.add_argument("data")
    ap.add_argument("cut", type=int)
    ap.add_argument("out")
    ap.add_argument("--url", default="http://127.0.0.1:8765/")
    ap.add_argument("--timeout-ms", type=int, default=300)
    ap.add_argument("--parallel", type=int, default=1)
    a = ap.parse_args()
    mod = dialogpii if a.source == "dialogpii" else ghissues
    cases = [cut_case(c, a.cut) for c in mod.load(Path(a.data), "dev", collections.Counter())]
    found, _ = det.scan(cases, ROOT, "de,us")
    local = threading.local()

    def ask(pair):
        if not hasattr(local, "ner"):      # one client per thread
            local.ner = remote.RemoteDetector(a.url, timeout=a.timeout_ms / 1000, max_chars=10 ** 9)
        c, fs = pair
        spans, status = local.ner.ask(c["text"], [(s, e) for s, e, _cls, _rule in fs])
        return status.ms, status.state == "ok", [(x, y) for x, y, _t, _sc in spans] if status.state == "ok" else []
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=a.parallel) as pool:
        answers = list(pool.map(ask, zip(cases, found)))
    wall = time.monotonic() - t0
    ms = [m for m, _ok, _sp in answers]
    late = sum(not ok for _m, ok, _sp in answers)
    added = [sp for _m, _ok, sp in answers]
    words = sum(len(WORD.findall(c["text"])) for c in cases)
    ms.sort()
    out = {"source": a.source, "split": "dev", "cut": a.cut, "timeout_ms": a.timeout_ms, "parallel": a.parallel,
           "cases": len(cases),
           "words": words, "no_answer_in_time": late, "requests_per_second": round(len(cases) / wall, 1),
           "ms_median": round(statistics.median(ms), 1), "ms_p95": round(ms[int(len(ms) * 0.95)], 1)}
    spans = sum(len(x) for x in added)
    if a.source == "dialogpii":
        names = whole_rules = whole_ner = wrong = 0
        for c, fs, add in zip(cases, found, added):
            gold = [s for s in c["spans"] if s["class"] == "pii.name"]
            names += len(gold)
            rules = [(s, e) for s, e, _cls, _r in fs]
            whole_rules += sum(any(s <= g["start"] and e >= g["end"] for s, e in rules) for g in gold)
            whole_ner += sum(any(s <= g["start"] and e >= g["end"] for s, e in rules + add) for g in gold)
            wrong += sum(not any(x < s["end"] and s["start"] < y for s in c["spans"]) for x, y in add)
        out.update({"names": names, "names_whole_rules": whole_rules, "names_whole_rules_ner": whole_ner,
                    "ner_spans_on_no_labelled_value": wrong,
                    "ner_false_per_1000_words": round(wrong / words * 1000, 2)})
    else:
        out.update({"ner_spans": spans, "ner_spans_per_1000_words": round(spans / words * 1000, 2),
                    "texts_with_a_span": sum(bool(x) for x in added)})
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
