#!/usr/bin/env python3
"""Refresh the vendored betterleaks ruleset to a pinned tag.

Usage: scripts/sync_betterleaks.py v1.9.0
Writes maisecrets/detection/rules/betterleaks.toml, betterleaks.json, LICENSE-betterleaks and BETTERLEAKS_VERSION.
The rules are consumed as data by maisecrets/detection/core.py; no betterleaks binary is used. betterleaks is the
successor
of gitleaks by the same maintainers (gitleaks takes security patches only since v8.30.1, Mcpgate-de/maisecrets#18).

The files are written as upstream ships them. maisecrets' corrections to single rules (a keyword the prefilter
lacks, a regex that rejects a real token) live in BETTERLEAKS_PATCHES in maisecrets/detection/core.py and apply when the
rules load, so a sync keeps them. After a sync, run tests/test_rules_from_the_catalogs.py: it fails when a patched
rule changed upstream. Then check the correction against the new rule and drop it if upstream fixed the gap.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

tag = sys.argv[1] if len(sys.argv) > 1 else ""
if not tag or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):   # it becomes part of a URL
    print("usage: sync_betterleaks.py vX.Y.Z")
    sys.exit(2)
dst = Path(__file__).resolve().parent.parent / "maisecrets" / "detection" / "rules"
base = f"https://raw.githubusercontent.com/betterleaks/betterleaks/{tag}/"
for src, name in (("config/betterleaks.toml", "betterleaks.toml"), ("LICENSE", "LICENSE-betterleaks")):
    with urllib.request.urlopen(base + src, timeout=30) as r:
        (dst / name).write_bytes(r.read())
(dst / "BETTERLEAKS_VERSION").write_text(tag + "\n")

# the detector reads the JSON form: tomllib is Python 3.11+, and the stock python3 of macOS is 3.9
import tomllib  # noqa: E402

cfg = tomllib.loads((dst / "betterleaks.toml").read_text(encoding="utf-8"))
(dst / "betterleaks.json").write_text(json.dumps(cfg, ensure_ascii=False, indent=0, sort_keys=True) + "\n",
                                      encoding="utf-8")
print("vendored betterleaks", tag, "rules:", len(cfg.get("rules", [])))
