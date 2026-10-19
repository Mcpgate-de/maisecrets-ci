"""The pii-anon adapter (subhash-holla/pii-anon, Apache-2.0). It runs in a new process of the Python that
BENCH_PII_ANON_PYTHON names (an environment with pii-anon installed from the pinned commit, plus numpy: the package
imports numpy but does not declare it, measured at commit 2171ace).

Each case is one `PIIOrchestrator.run` with the profile of the README (mode weighted_consensus, language en, no
segmentation); a finding is an entry of `ensemble_findings` with its span. Without an extra installed, only its
regex engine (`regex-oss`) runs. pii-anon finds personal data, so its scope is `pii.`."""
from __future__ import annotations

import os
import sys

from bench.adapters import _proc

NAME = "pii-anon"
SCOPE = ("pii.",)
COMMIT = "2171ace5847a0d2add555419c02b41c47155cabe"

_WORKER = r'''
import json, sys, time
t0 = time.perf_counter()
from importlib.metadata import version
from pii_anon import PIIOrchestrator
from pii_anon.types import ProcessingProfileSpec, SegmentationPlan
CLS = {"EMAIL_ADDRESS": "pii.email", "PHONE_NUMBER": "pii.phone", "CREDIT_CARD": "pii.card", "IBAN": "pii.iban",
       "IBAN_CODE": "pii.iban", "IP_ADDRESS": "pii.ip", "PERSON": "pii.name", "PERSON_NAME": "pii.name",
       "NAME": "pii.name", "US_SSN": "pii.national_id", "ADDRESS": "pii.address", "LOCATION": "pii.address",
       "DATE_OF_BIRTH": "pii.birth_date", "USERNAME": "pii.username", "API_KEY": "secret", "PASSWORD": "secret"}
orch = PIIOrchestrator(token_key="bench")
profile = ProcessingProfileSpec(profile_id="default", mode="weighted_consensus", language="en")
first, times, engines = None, [], set()
with open(sys.argv[1], encoding="utf-8") as fin, open(sys.argv[2], "w", encoding="utf-8") as fout:
    for line in fin:
        text = json.loads(line)["text"]
        t = time.perf_counter()
        r = orch.run({"text": text}, profile=profile, segmentation=SegmentationPlan(enabled=False), scope="etl",
                     token_version=1)
        times.append(time.perf_counter() - t)
        if first is None:
            first = time.perf_counter() - t0
        out = []
        for f in r.get("ensemble_findings", []):
            sp = f.get("span") or {}
            if f.get("field_path", "text") == "text" and "start" in sp:
                engines.update(f.get("engines") or [])
                out.append([sp["start"], sp["end"], CLS.get(f["entity_type"], "pii.other"), f["entity_type"]])
        fout.write(json.dumps(out) + "\n")
json.dump({"api": "PIIOrchestrator.run", "version": version("pii-anon"), "engines_seen": sorted(engines),
           "cold_start_s": first, "times_s": times}, sys.stdout)
'''


def _python() -> str:
    return os.environ.get("BENCH_PII_ANON_PYTHON") or sys.executable


def describe() -> dict:
    ident = _proc.identity(_python(), "pii-anon", version="", commit=COMMIT)
    return {"scanner": NAME, "version": ident["version"], "commit": ident["commit"],
            "configuration": "PIIOrchestrator.run, profile default, mode weighted_consensus, language en, "
                             "no segmentation (the README's example)",
            "detectors": "the engines installed: regex-oss only without extras", "network": False,
            "dependencies": "pydantic, numpy (undeclared)", "region": "en", "scope": list(SCOPE),
            "python": _python(),
            "python_version": ident["python_version"], "installed": _proc.installed(_python())}


def scan(cases):
    return _proc.run_worker("pii-anon", _python(), _WORKER, cases, fields=("text",))
