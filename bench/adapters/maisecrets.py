"""The maisecrets adapter: scans a checkout (--maisecrets DIR) in a new process with a fresh temp home."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from bench.adapters import _proc

NAME = "maisecrets"
SCOPE = ("secret.", "pii.")
WORKER = Path(__file__).with_name("maisecrets_worker.py")
_HOME_VAR = "MAISECRETS" + "_HOME"
_PII = {"EMAIL": "pii.email", "PHONE": "pii.phone", "IBAN": "pii.iban", "CARD": "pii.card", "IP": "pii.ip",
        "NAME": "pii.name", "ADDRESS": "pii.address", "BIRTH_DATE": "pii.birth_date", "USERNAME": "pii.username",
        # a bank account is no national id (Benchmark V3: the per-class tables put us-bank under the wrong class)
        "US_BANK_NUMBER": "pii.bank_account", "ABA_ROUTING_NUMBER": "pii.bank_account"}


def cls_of(placeholder_type: str) -> str:
    if placeholder_type == "SECRET":
        return "secret"
    if placeholder_type in _PII:
        return _PII[placeholder_type]
    if placeholder_type.endswith(("_TAX_ID", "_UID")):
        return "pii.tax_id"
    return "pii.national_id"


def _git(root: Path, *args):
    """git in the checkout, without the GIT_* of a caller; None when git cannot answer (no repository, no git)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        p = subprocess.run(["git", "-C", str(root), "-c", "core.fsmonitor=false", *args], capture_output=True,
                           text=True, env=env, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def describe(root: Path, regions: str) -> dict:
    manifest = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    commit = _git(root, "rev-parse", "HEAD")
    # untracked files count: the worker imports from this checkout (ignored files such as __pycache__ do not)
    status = _git(root, "status", "--porcelain", "--untracked-files=all") if commit else None
    # dirty is None when the state is unknown (a copy without git): the report refuses it like a modified tree
    return {"scanner": NAME, "version": manifest.get("version"), "commit": commit,
            "dirty": None if status is None else bool(status),
            "configuration": {"regions": ["generic"] + regions.split(","), "sources": "none", "references": "none",
                              "host": "fixed user, year 2026"},
            "detectors": "all built-in rules", "network": False, "dependencies": "Python standard library",
            "scope": list(SCOPE), "python": sys.executable, "python_version": sys.version.split()[0],
            "installed": _proc.installed(sys.executable)}


def _clean_env(home: str) -> dict:
    return _proc.minimal_env(home, {_HOME_VAR: home})


def scan(cases, root: Path, regions: str = "de,us", python: str = sys.executable):
    """One list of (start, end, cls, rule) per case, and the timing of the worker."""
    tmp = tempfile.mkdtemp(prefix="bench-ms-")
    try:
        home = os.path.join(tmp, "home")
        os.mkdir(home)
        Path(home, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}',
                                             encoding="utf-8")
        inp, out = os.path.join(tmp, "in.jsonl"), os.path.join(tmp, "out.jsonl")
        with open(inp, "w", encoding="utf-8") as f:
            for c in cases:
                f.write(json.dumps({"text": c["text"], "channel": c["channel"], "path": c.get("path")}) + "\n")
        p = _proc.run([python, "-I", str(WORKER), "--root", str(root), "--regions", regions, inp, out], "maisecrets",
                      env=_clean_env(home), cwd=tmp)
        if p.returncode:
            raise _proc.AdapterError(f"maisecrets: the worker failed with exit code {p.returncode} (its stderr is "
                                     f"not shown: it can hold a case value)")
        timing = json.loads(p.stdout)
        with open(out, encoding="utf-8") as f:
            found = [[(s, e, cls_of(t), k) for s, e, t, k in json.loads(line)] for line in f]
        return _proc.check("maisecrets", cases, found), timing
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
