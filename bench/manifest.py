#!/usr/bin/env python3
"""Write the environment of a benchmark run next to its results (Benchmark V2, reproducible configurations).

    python3 bench/manifest.py OUT_DIR [MAISECRETS_CHECKOUT]

environment.json holds: the date, the operating system and the machine, the benchmark commit and whether its tree is
modified, the maisecrets checkout and its state, each scanner's Python (from the BENCH_*_PYTHON variables run_all.sh
reads) with its version and every installed distribution, the pinned datasets and the commits of the catalogs. It
records; it changes nothing about how a run measures."""
from __future__ import annotations

import datetime
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER_ENVS = {"maisecrets": "BENCH_PYTHON", "detect-secrets": "BENCH_DETECT_SECRETS_PYTHON",
                "secret-scan": "BENCH_SECRET_SCAN_PYTHON", "pii-anon": "BENCH_PII_ANON_PYTHON",
                "preserve": "BENCH_PRESERVE_PYTHON", "presidio": "BENCH_PRESIDIO_PYTHON"}


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60)
    return r.stdout.strip() if r.returncode == 0 else ""


def _tree(repo: Path) -> dict:
    return {"path": str(repo), "commit": _git(repo, "rev-parse", "HEAD") or None,
            "dirty": bool(_git(repo, "status", "--porcelain")) if _git(repo, "rev-parse", "HEAD") else None}


def _python(exe: str) -> dict:
    v = subprocess.run([exe, "-I", "-c", "import sys; print(sys.version.split()[0])"], capture_output=True, text=True,
                       timeout=60)
    f = subprocess.run([exe, "-I", "-m", "pip", "freeze", "--all"], capture_output=True, text=True, timeout=120)
    return {"python": exe, "version": v.stdout.strip() or None,
            "distributions": sorted(f.stdout.split()) if f.returncode == 0 else None}


def manifest(maisecrets: Path, env: dict) -> dict:
    sys.path.insert(0, str(ROOT / "scripts"))
    import measure_datasets as md
    datasets = {name: {k: src[k] for k in ("title", "licence", "revision", "files", "archive_sha256") if k in src}
                for name, src in md.SOURCES.items()}
    catalogs = {}
    if env.get("BENCH_CATALOGS"):
        base = Path(env["BENCH_CATALOGS"])
        catalogs = {d.name: _git(d, "rev-parse", "HEAD") for d in sorted(base.iterdir()) if (d / ".git").exists()}
    scanners = {name: _python(env[var]) for name, var in SCANNER_ENVS.items() if env.get(var)}
    return {"date": datetime.date.today().isoformat(),
            "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
            "benchmark": _tree(ROOT), "maisecrets": _tree(maisecrets), "scanners": scanners,
            "datasets": datasets, "catalogs": catalogs}


def main(argv) -> int:
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    out = Path(argv[0])
    out.mkdir(parents=True, exist_ok=True)
    m = manifest(Path(argv[1]).resolve() if len(argv) > 1 else ROOT, dict(os.environ))
    (out / "environment.json").write_text(json.dumps(m, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"environment: {out / 'environment.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
