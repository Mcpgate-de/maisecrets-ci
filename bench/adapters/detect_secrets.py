"""The detect-secrets adapter (Yelp, Apache-2.0). It runs in a new process of the Python that
BENCH_DETECT_SECRETS_PYTHON names (an environment with `pip install detect-secrets==1.5.0`), else this Python.

Each case is written to a file at its path (else input.txt) and scanned with `detect_secrets.core.scan.scan_file`
under the default settings (all plugins, the default filters), as `detect-secrets scan` does, but before
`SecretsCollection` keeps one entry per value and type: a value found on two lines is two findings. One plugin
reports a value once per line, so a value twice on one line is one finding (a limit of the tool, not of the
adapter). A finding is a secret value it reports; its offset is the place of that value in its line (a value
reported twice on a line goes to its first and its second place). Every plugin of detect-secrets finds secrets, so
its scope is `secret.`."""
from __future__ import annotations

import os
import sys

from bench.adapters import _proc

NAME = "detect-secrets"
SCOPE = ("secret.",)
VERSION = "1.5.0"
COMMIT = ""   # from PyPI: the version is pinned and checked

_WORKER = r'''
import json, os, sys, tempfile, time
t0 = time.perf_counter()
from detect_secrets.core.scan import scan_file
from detect_secrets.__version__ import VERSION
from detect_secrets.settings import default_settings
first, times = None, []
work = tempfile.mkdtemp(prefix="ds-case-", dir=os.getcwd())
with default_settings() as settings, open(sys.argv[1], encoding="utf-8") as fin, \
        open(sys.argv[2], "w", encoding="utf-8") as fout:
    plugins = sorted(settings.plugins)
    for n, line in enumerate(fin):
        case = json.loads(line)
        text = case["text"]
        rel = case.get("path") or "input.txt"
        d = os.path.join(work, str(n))
        path = os.path.join(d, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        t = time.perf_counter()
        # the generator before SecretsCollection, which keeps one entry per value and type in a file
        secrets = list(scan_file(path))
        times.append(time.perf_counter() - t)
        if first is None:
            first = time.perf_counter() - t0
        lines = text.split("\n")
        starts = [0]
        for ln in lines:
            starts.append(starts[-1] + len(ln) + 1)
        out, used = [], {}
        for secret in sorted(secrets, key=lambda s: (s.line_number, s.type)):
            v, i = secret.secret_value, secret.line_number - 1
            if v and 0 <= i < len(lines):
                # a value reported again on its line goes to its next place there, not to the first one again
                at = lines[i].find(v, used.get((i, v), 0))
                if at < 0:
                    at = lines[i].find(v)
                if at >= 0:
                    used[(i, v)] = at + 1
                    out.append([starts[i] + at, starts[i] + at + len(v), "secret", secret.type])
        fout.write(json.dumps(out) + "\n")
json.dump({"api": "detect_secrets.core.scan.scan_file", "version": VERSION, "plugins": plugins, "cold_start_s": first,
           "times_s": times}, sys.stdout)
'''


def _python() -> str:
    return os.environ.get("BENCH_DETECT_SECRETS_PYTHON") or sys.executable


def describe() -> dict:
    ident = _proc.identity(_python(), "detect-secrets", version="1.5.0", commit=COMMIT)
    return {"scanner": NAME, "version": ident["version"], "commit": ident["commit"],
            "configuration": "default settings (all plugins, default filters), core.scan.scan_file per case",
            "detectors": "all plugins of the release", "network": False,
            "dependencies": "detect-secrets and its requirements (pyyaml, requests)", "region": "none",
            "scope": list(SCOPE), "python": _python(),
            "python_version": ident["python_version"], "installed": _proc.installed(_python())}


def scan(cases):
    return _proc.run_worker("detect-secrets", _python(), _WORKER, cases, fields=("text", "path"))
