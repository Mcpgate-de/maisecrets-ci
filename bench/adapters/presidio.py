"""The Presidio adapter (microsoft/presidio, presidio-analyzer, MIT). It runs in a new process of the Python that
BENCH_PRESIDIO_PYTHON names (an environment with presidio-analyzer and its default spaCy model en_core_web_lg, every
distribution pinned in requirements/presidio.txt).

maisecrets vendors Presidio's recognizers (maisecrets/detection/rules/PRESIDIO_VERSION), so this adapter runs the same
version: the comparison shows what maisecrets adds on top of them and what Presidio's NER model finds that a pattern
cannot. Each case is one `AnalyzerEngine().analyze(text, language="en")` as the README shows it: the default
recognizers and NLP engine, no score threshold.

Entity types map to the classes of Benchmark V1. DATE_TIME, NRP and URL have no class there and are left out: a date
or a URL is not personal data by itself, and kept they would count as false positives against every birth date and
address class. The mapping is part of the frozen configuration (docs/BENCHMARK-V2.md)."""
from __future__ import annotations

import os
import sys

from bench.adapters import _proc

NAME = "presidio"
SCOPE = ("pii.",)
VERSION = "2.2.364"

_WORKER = r'''
import json, sys, time
t0 = time.perf_counter()
from importlib.metadata import version
from presidio_analyzer import AnalyzerEngine
CLS = {"EMAIL_ADDRESS": "pii.email", "PHONE_NUMBER": "pii.phone", "CREDIT_CARD": "pii.card", "IBAN_CODE": "pii.iban",
       "IP_ADDRESS": "pii.ip", "PERSON": "pii.name", "LOCATION": "pii.address", "US_BANK_NUMBER": "pii.bank_account"}
DROPPED = {"DATE_TIME", "NRP", "URL", "CRYPTO"}
engine = AnalyzerEngine()
first, times, seen = None, [], set()
with open(sys.argv[1], encoding="utf-8") as fin, open(sys.argv[2], "w", encoding="utf-8") as fout:
    for line in fin:
        text = json.loads(line)["text"]
        t = time.perf_counter()
        results = engine.analyze(text=text, language="en")
        times.append(time.perf_counter() - t)
        if first is None:
            first = time.perf_counter() - t0
        out = []
        for r in results:
            seen.add(r.entity_type)
            if r.entity_type in DROPPED:
                continue
            # every other recognizer of the default set names an id of a country (US_SSN, UK_NHS, ...)
            out.append([r.start, r.end, CLS.get(r.entity_type, "pii.national_id"), r.entity_type])
        fout.write(json.dumps(out) + "\n")
json.dump({"api": "AnalyzerEngine.analyze", "version": version("presidio-analyzer"),
           "model": version("en_core_web_lg"), "entities_seen": sorted(seen), "cold_start_s": first,
           "times_s": times}, sys.stdout)
'''


def _python() -> str:
    return os.environ.get("BENCH_PRESIDIO_PYTHON") or sys.executable


def describe() -> dict:
    ident = _proc.identity(_python(), "presidio-analyzer", version=VERSION)
    return {"scanner": NAME, "version": ident["version"], "commit": ident["commit"],
            "configuration": "AnalyzerEngine().analyze(text, language='en'): the default recognizers and NLP engine "
                             "(spaCy en_core_web_lg), no score threshold; DATE_TIME, NRP, URL and CRYPTO left out",
            "detectors": "the default recognizer registry and the spaCy NER model", "network": False,
            "dependencies": "spaCy, en_core_web_lg (requirements/presidio.txt)", "region": "en",
            "scope": list(SCOPE), "python": _python(), "python_version": ident["python_version"],
            "installed": _proc.installed(_python())}


def scan(cases):
    return _proc.run_worker("presidio", _python(), _WORKER, cases, fields=("text",))
