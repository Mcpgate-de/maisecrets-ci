#!/usr/bin/env python3
"""Library smoke test for maisecrets.detection outside the plugin repository (docs/DETECTION.md).

    python3 scripts/library_smoke.py [<maisecrets checkout>]

Copies only maisecrets/__init__.py and maisecrets/detection/ into a new directory, makes a fresh virtual environment
(no site packages), points HOME at a directory that does not exist, and in a process started with -I imports the
package, builds a Detector with all four arguments given, and scans a text. Prints the files copied, the import time,
the modules of the plugin that got imported (must be none), and the hits by rule id (no value)."""
import atexit
import json
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

src = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent).resolve()
work = Path(tempfile.mkdtemp(prefix="ms-lib-"))
atexit.register(shutil.rmtree, work, True)   # also when a copy or the venv fails
pkg = work / "site" / "maisecrets"
shutil.copytree(src / "maisecrets" / "detection", pkg / "detection",
                ignore=shutil.ignore_patterns("__pycache__"))
shutil.copy(src / "maisecrets" / "__init__.py", pkg / "__init__.py")
env_dir = work / "venv"
venv.EnvBuilder(with_pip=False, clear=True).create(env_dir)
py = env_dir / "bin" / "python"
probe = r'''
import json, sys, time
t = time.perf_counter()
from maisecrets.detection import Active, Detector, Host, NO_REFERENCES, NO_SOURCES
imported = time.perf_counter() - t
d = Detector(regions=Active(regions=("generic", "de"), languages=("en", "de"), source="smoke"),
             sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="someone", year=2026))
tok = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
mail = "jonas.brandt" + "@" + "posteo.de"
text = f"token {tok} and mail {mail} and iban DE89 3704 0044 0532 0130 00"
t = time.perf_counter()
hits = d.findings(text, channel="tool")
first_scan = time.perf_counter() - t
plugin = sorted(m for m in sys.modules if m.startswith("maisecrets") and not m.startswith("maisecrets.detection")
                and m != "maisecrets")
print(json.dumps({"import_ms": round(imported * 1000, 1), "first_scan_ms": round(first_scan * 1000, 1),
                  "plugin_modules": plugin, "hits": sorted((m.kind, m.type) for m in hits),
                  "python": sys.version.split()[0], "prefix": sys.prefix}))
'''
# PYTHONDONTWRITEBYTECODE: Apple's Python 3.9 writes its bytecode cache under ~/Library/Caches/com.apple.python
env = {"PATH": "/usr/bin:/bin", "HOME": str(work / "no-such-home"), "PYTHONPATH": str(work / "site"),
       "PYTHONDONTWRITEBYTECODE": "1"}
p = subprocess.run([str(py), "-c", probe], capture_output=True, text=True, env=env, cwd=work)
print("files copied:", sum(1 for _ in pkg.rglob("*") if _.is_file()), "size KB:",
      sum(f.stat().st_size for f in pkg.rglob("*") if f.is_file()) // 1024)
print("exit", p.returncode)
print(p.stdout.strip() or p.stderr[-3000:])
home = (work / "no-such-home").exists()
print("home created:", home)
res = json.loads(p.stdout) if p.returncode == 0 else {}
kinds = {k for k, _t in res.get("hits", [])}
ok = p.returncode == 0 and not res["plugin_modules"] and not home and {"email", "github-pat", "iban"} <= kinds
print("OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
