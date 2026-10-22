"""The AI Gateway's built-in PII detector (devs/ai-gateway, PIISanitizer), read through its detector seam
(src/security/detector_port.py, GatewayDetector). It runs in a new process of the Python that BENCH_GATEWAY_PYTHON
names, with the gateway checkout BENCH_GATEWAY_REPO on its path.

Each case is one GatewayDetector().findings(text): the sanitizer on a throwaway mapping, no field name, no
service, the spans read back from the tokens it wrote. A case the seam cannot read back (AlignmentError) or
the sanitizer left unscanned (Unscanned) returns no finding and is counted in "errors".

Scope: only the classes the gateway claims. It finds no names, no postal addresses and no secrets (secrets go
through another path of the gateway, secret_shapes), so those classes are out of scope and not scored.

A consumer of this project, not a foreign scanner: no requirements file pins it. The result names the gateway's
commit, and a gateway tree with changes is refused, as a modified maisecrets checkout is. Written by the gateway's
own session (2026-10-21) and taken into Benchmark V3 unchanged in what it measures."""
from __future__ import annotations

import os
import sys

from bench.adapters import _proc

NAME = "ai_gateway"
SCOPE = ("pii.email", "pii.phone", "pii.iban", "pii.card", "pii.ip", "pii.tax_id", "pii.national_id")

_WORKER = r'''
import json, os, sys, time
os.environ.setdefault("TESTING", "true")
os.environ.setdefault("ENVIRONMENT", "test")
sys.path.insert(0, sys.argv[3])
os.chdir(sys.argv[3])
t0 = time.perf_counter()
from src.security import detector_port as dp
CLS = {"email": "pii.email", "phone": "pii.phone", "iban": "pii.iban", "credit_card": "pii.card",
       "ip_address": "pii.ip", "ip_address_v6": "pii.ip",
       "de_tax_id": "pii.tax_id", "de_tax_number": "pii.tax_id", "de_vat_id": "pii.tax_id",
       "de_social_security": "pii.national_id", "de_health_insurance": "pii.national_id",
       "de_id_card": "pii.national_id", "de_passport": "pii.national_id", "de_lanr": "pii.national_id",
       "de_bsnr": "pii.national_id"}
det = dp.GatewayDetector()
first, times, errors, seen = None, [], {}, set()
with open(sys.argv[1], encoding="utf-8") as fin, open(sys.argv[2], "w", encoding="utf-8") as fout:
    for line in fin:
        text = json.loads(line)["text"]
        t = time.perf_counter()
        try:
            found = det.findings(text)
        except (dp.AlignmentError, dp.Unscanned) as exc:
            errors[type(exc).__name__] = errors.get(type(exc).__name__, 0) + 1
            found = ()
        times.append(time.perf_counter() - t)
        if first is None:
            first = time.perf_counter() - t0
        out = []
        for f in found:
            seen.add(f.category)
            out.append([f.start, f.end, CLS.get(f.category, "pii.other"), f.rule])
        fout.write(json.dumps(out) + "\n")
json.dump({"api": "detector_port.GatewayDetector.findings", "categories_seen": sorted(seen),
           "errors": errors, "cold_start_s": first, "times_s": times}, sys.stdout)
'''


def _python() -> str:
    return os.environ.get("BENCH_GATEWAY_PYTHON") or sys.executable


def _repo() -> str:
    repo = os.environ.get("BENCH_GATEWAY_REPO")
    if not repo:
        raise _proc.AdapterError("ai_gateway: set BENCH_GATEWAY_REPO to an ai-gateway checkout")
    return repo


def _commit(repo: str) -> str:
    import subprocess
    p = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True)
    return p.stdout.strip()


def _dirty(repo: str) -> bool:
    import subprocess
    # an untracked file counts: the gateway's modules are imported from this tree (ignored files do not)
    p = subprocess.run(["git", "-C", repo, "status", "--porcelain", "--untracked-files=all"], capture_output=True,
                       text=True)
    return p.returncode != 0 or bool(p.stdout.strip())


def describe() -> dict:
    repo = _repo()
    if _dirty(repo):
        raise _proc.AdapterError("ai_gateway: the gateway checkout has changes; measure a commit")
    return {"scanner": NAME, "version": open(os.path.join(repo, "VERSION")).read().strip(), "commit": _commit(repo),
            "configuration": "GatewayDetector().findings(text): PIISanitizer on a throwaway mapping, no field name, "
                             "no service; spans read back from its tokens",
            "detectors": "the gateway's Layer-1 regexes, national phone pass, German identifiers", "network": False,
            "dependencies": "the ai-gateway source tree", "region": "de",
            "scope": list(SCOPE), "python": _python(), "installed": _proc.installed(_python())}


def scan(cases):
    return _proc.run_worker("ai_gateway", _python(), _WORKER, cases, fields=("text",), argv=(_repo(),))
