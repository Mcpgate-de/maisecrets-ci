#!/usr/bin/env python3
"""Check the files the sync scripts write to maisecrets/detection/rules/, as data, without running any of them.

Usage: scripts/check_vendored_rules.py

Each generated file is a regular file (no symlink) of a sane size, every JSON file parses, each
version file holds one version, and the JSON of detect-secrets and Presidio names the version its
version file names: a commit that moves one of these two version files alone is red. betterleaks.json
carries no version, so for betterleaks only the sync script keeps the two together. own_secret_rules.json holds
maisecrets' own secret rules, derived from gitleaks v8.30.1 patterns, with that license.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = "maisecrets/detection/rules"
GENERATED = ("BETTERLEAKS_VERSION", "betterleaks.toml", "betterleaks.json", "LICENSE-betterleaks",
             "own_secret_rules.json", "LICENSE-gitleaks",
             "DETECT_SECRETS_VERSION", "detect_secrets.json", "LICENSE-detect-secrets",
             "PRESIDIO_VERSION", "presidio.json", "LICENSE-presidio")
MAX_BYTES = 2_000_000
VERSION_RE = {"BETTERLEAKS_VERSION": r"v\d+\.\d+\.\d+", "DETECT_SECRETS_VERSION": r"v\d+\.\d+\.\d+",
              "PRESIDIO_VERSION": r"\d+\.\d+\.\d+"}


def problems(root: Path = ROOT) -> list[str]:
    out, rules = [], root / RULES
    for name in GENERATED:
        p = rules / name
        if p.is_symlink() or not p.is_file():
            out.append(f"{name}: not a regular file")
        elif p.stat().st_size > MAX_BYTES:
            out.append(f"{name}: larger than {MAX_BYTES} bytes")
    if out:
        return out
    data = {}
    for name in GENERATED:
        if name.endswith(".json"):
            try:
                data[name] = json.loads((rules / name).read_text(encoding="utf-8"))
            except ValueError as e:
                out.append(f"{name}: no JSON ({type(e).__name__})")
    version = {}
    for name, rx in VERSION_RE.items():
        version[name] = (rules / name).read_text(encoding="utf-8").strip()
        if not re.fullmatch(rx, version[name]):
            out.append(f"{name}: not a version")
    for json_name, key, version_name in (("detect_secrets.json", "detect_secrets_version", "DETECT_SECRETS_VERSION"),
                                         ("presidio.json", "presidio_version", "PRESIDIO_VERSION")):
        got = data.get(json_name, {}).get(key) if isinstance(data.get(json_name), dict) else None
        if got != version[version_name]:
            out.append(f"{json_name} is for {got!r}, {version_name} names {version[version_name]!r}")
    for name in ("betterleaks.json", "own_secret_rules.json"):
        if not isinstance(data.get(name), dict) or not data[name].get("rules"):
            out.append(f"{name}: no rules")
    return out


def main(argv: list[str]) -> int:
    found = problems()
    for p in found:
        print(p)
    print("vendored rules: ok" if not found else f"vendored rules: {len(found)} problem(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
