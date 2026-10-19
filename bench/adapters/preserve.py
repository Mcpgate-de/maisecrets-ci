"""The Preserve adapter (thirtysix/Preserve, preserve-pii, MIT). It runs in a new process of the Python that
BENCH_PRESERVE_PYTHON names (an environment with preserve-pii installed from the pinned commit).

Each case is one `Scrubber(PreserveConfig()).scrub(text)` with the default configuration (no LLM review, so no
network); a finding is an entry of `result.detections`. Preserve scrubs personal data and secrets, so its scope is both
families. Its type names are mapped to the classes of the benchmark by their words (KEY, TOKEN, ... is a secret)."""
from __future__ import annotations

import os
import sys

from bench.adapters import _proc

NAME = "preserve"
SCOPE = ("secret.", "pii.")
COMMIT = "01dbd7710de79e21bef851aaa8b6cbfb4b1188ad"

_WORKER = r'''
import json, sys, time
t0 = time.perf_counter()
from importlib.metadata import version
from preserve import PreserveConfig, Scrubber
WORDS = [(("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE", "JWT", "WEBHOOK", "CONNECTION"),
          "secret"), (("EMAIL",), "pii.email"), (("PHONE",), "pii.phone"), (("IBAN",), "pii.iban"),
         (("CARD", "CREDIT"), "pii.card"), (("IP",), "pii.ip"), (("NAME", "PERSON"), "pii.name"),
         (("ADDRESS", "STREET"), "pii.address"), (("DOB", "BIRTH"), "pii.birth_date"),
         (("USER",), "pii.username"), (("TAX",), "pii.tax_id")]

def cls_of(t):
    u = t.upper()
    for words, cls in WORDS:
        if any(w in u for w in words):
            return cls
    return "pii.national_id" if any(c.isdigit() for c in u) or "ID" in u or "SSN" in u else "pii.other"

config = PreserveConfig()
scrubber = Scrubber(config)
first, times, types = None, [], set()
with open(sys.argv[1], encoding="utf-8") as fin, open(sys.argv[2], "w", encoding="utf-8") as fout:
    for line in fin:
        text = json.loads(line)["text"]
        t = time.perf_counter()
        res = scrubber.scrub(text)
        times.append(time.perf_counter() - t)
        if first is None:
            first = time.perf_counter() - t0
        out = []
        for d in res.detections:
            types.add(d.replacement_type)
            out.append([d.start, d.end, cls_of(d.replacement_type), d.pattern_name])
        fout.write(json.dumps(out) + "\n")
json.dump({"api": "Scrubber.scrub", "version": version("preserve-pii"), "types_seen": sorted(types),
           "config": {k: str(v) for k, v in config.model_dump().items() if not isinstance(v, (list, dict))},
           "cold_start_s": first, "times_s": times}, sys.stdout)
'''


def _python() -> str:
    return os.environ.get("BENCH_PRESERVE_PYTHON") or sys.executable


def describe() -> dict:
    ident = _proc.identity(_python(), "preserve-pii", version="", commit=COMMIT)
    return {"scanner": NAME, "version": ident["version"], "commit": ident["commit"],
            "configuration": "PreserveConfig() defaults (no LLM review)", "detectors": "patterns, validators, "
            "normalcy and context scoring of the defaults", "network": False,
            "dependencies": "pydantic, phonenumbers, email-validator, dateparser, names-dataset, wordfreq, openai "
                            "(imported, not called)", "region": "default", "scope": list(SCOPE),
            "python": _python(),
            "python_version": ident["python_version"], "installed": _proc.installed(_python())}


def scan(cases):
    return _proc.run_worker("preserve", _python(), _WORKER, cases, fields=("text",))
