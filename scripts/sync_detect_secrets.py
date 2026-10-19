#!/usr/bin/env python3
"""Refresh the vendored detect-secrets keyword and basic-auth regexes to a pinned tag.

Usage: scripts/sync_detect_secrets.py v1.5.0
Fetches keyword.py and basic_auth.py from Yelp/detect-secrets at that tag,
reads the regexes and their secret group numbers from the source as data
(scripts/_static_python.py; nothing upstream is executed), and writes maisecrets/detection/rules/detect_secrets.json,
LICENSE-detect-secrets and DETECT_SECRETS_VERSION. Only the "config" and
"quotes required" regex sets are kept; the other sets are file-type specific.
"""
import ast
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _static_python import Rx, bind  # noqa: E402

tag = sys.argv[1] if len(sys.argv) > 1 else None
if not tag or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):   # it becomes part of a URL
    print("usage: sync_detect_secrets.py vX.Y.Z")
    sys.exit(2)
base = f"https://raw.githubusercontent.com/Yelp/detect-secrets/{tag}/"


def fetch(path: str) -> str:
    with urllib.request.urlopen(base + path, timeout=30) as r:
        return r.read().decode()


src = fetch("detect_secrets/plugins/keyword.py")
# read as data, never executed: the regexes are string constants, `.format`, `join` and `re.compile`
ns: dict = {}
bind(ast.parse(src).body, ns)
names = {v: k for k, v in ns.items() if isinstance(v, Rx)}
rules, seen = [], set()
for setname in ("CONFIG_DENYLIST_REGEX_TO_GROUP", "QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP"):
    for rx, group in ns[setname].items():
        rid = "ds-keyword-" + names[rx].replace("_REGEX", "").replace("FOLLOWED_BY_", "").replace("_", "-").lower()
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({"id": rid, "regex": rx.pattern, "ignorecase": bool(rx.flags & re.IGNORECASE),
                      "group": group, "set": setname.split("_DENYLIST")[0].lower()})
reserved, sub = ":/?#[]@", "!$&'()*+,;="
esc = re.escape(reserved + sub)
rules.append({"id": "ds-basic-auth", "regex": r"://[^{}\s]+:([^{}\s]+)@".format(esc, esc),
              "ignorecase": False, "group": 1, "set": "basic_auth"})
dst = Path(__file__).resolve().parent.parent / "maisecrets" / "detection" / "rules"
json.dump({"detect_secrets_version": tag, "denylist": list(ns["DENYLIST"]), "rules": rules},
          open(dst / "detect_secrets.json", "w"), indent=1)
(dst / "DETECT_SECRETS_VERSION").write_text(tag + "\n")
(dst / "LICENSE-detect-secrets").write_text(fetch("LICENSE"))
print(f"vendored {len(rules)} detect-secrets rules, {tag}")
