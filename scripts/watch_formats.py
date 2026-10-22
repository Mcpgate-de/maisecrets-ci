#!/usr/bin/env python3
"""Watch the public lists of token formats for entries that maisecrets has not looked at yet.

    python3 scripts/watch_formats.py check     exit 1 and list each new entry, per source
    python3 scripts/watch_formats.py update    write the current lists to docs/format-watch.txt

The vendored rule sets are kept current by Renovate (renovate.json). These sources are not vendored, and a format
can be in one of them long before it reaches a vendored set, or never (the Storyblok `sb_pat_` token, 2026-10-22):

- github: the secret types of GitHub secret scanning (names only; GitHub keeps the patterns of its partners
  private), src/secret-scanning/data/pattern-docs/fpt/public-docs.yml in github/docs
- trufflehog: its detectors, one folder each under pkg/detectors
- betterleaks: the rule ids of config/betterleaks.toml on main, ahead of the release that Renovate takes
- veles: the secret plugins of Google's OSV-SCALIBR, one folder each under veles/secrets (kingfisher imports them)

A new entry is a reason to look, not a rule: whoever looks writes a prefix rule with a test when the format has a
fixed prefix (maisecrets/detection/rules/prefixes.txt), or adds the entry to the snapshot with `update`. The
snapshot is a text file, a `[source]` line and one id per line, so no id list reads as a label and its value. The
scheduled pipeline runs `check`; a red job is the notice. Standard library only; GITHUB_TOKEN is used when set.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "docs" / "format-watch.txt"
API = "https://api.github.com/repos/"
RAW = "https://raw.githubusercontent.com/"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "maisecrets-format-watch"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(API):
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def _folders(repo: str, path: str) -> list[str]:
    """The folder names under `path` on the default branch: the tree of that path, not a recursive listing."""
    parent, _, leaf = path.rpartition("/")
    entries = json.loads(_get(f"{API}{repo}/contents/{parent}"))
    sha = next(e["sha"] for e in entries if e["name"] == leaf and e["type"] == "dir")
    tree = json.loads(_get(f"{API}{repo}/git/trees/{sha}"))["tree"]
    return sorted(e["path"] for e in tree if e["type"] == "tree")


def github_types(text: str) -> list[str]:
    return sorted(set(re.findall(r"^\s*secretType:\s*['\"]?([\w.-]+)", text, re.M)))


def betterleaks_ids(text: str) -> list[str]:
    return sorted(set(re.findall(r'^\s*id\s*=\s*"([^"]+)"', text, re.M)))


SOURCES = {
    "github": lambda: github_types(_get(RAW + "github/docs/main/src/secret-scanning/data/pattern-docs/fpt/"
                                        "public-docs.yml").decode("utf-8")),
    "trufflehog": lambda: _folders("trufflesecurity/trufflehog", "pkg/detectors"),
    "betterleaks": lambda: betterleaks_ids(_get(RAW + "betterleaks/betterleaks/main/config/betterleaks.toml")
                                           .decode("utf-8")),
    "veles": lambda: _folders("google/osv-scalibr", "veles/secrets"),
}


def new_entries(snapshot: dict, current: dict) -> dict:
    """Per source, the entries of `current` that the snapshot does not hold. A source missing from the snapshot
    counts every entry as new; an entry that left a source is no news."""
    return {name: sorted(set(items) - set(snapshot.get(name, []))) for name, items in current.items()
            if set(items) - set(snapshot.get(name, []))}


def dump(lists: dict) -> str:
    return "".join(f"[{name}]\n" + "".join(f"{i}\n" for i in sorted(items)) + "\n"
                   for name, items in sorted(lists.items()))


def load(text: str) -> dict:
    out, name = {}, None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
            out[name] = []
        elif line and name:
            out[name].append(line)
    return out


def fetch_all() -> dict:
    out = {}
    for name, fetch in SOURCES.items():
        items = fetch()
        if not items:
            raise SystemExit(f"{name}: the source gave no entry; its layout changed, so the watch would see nothing")
        out[name] = items
    return out


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("check", "update"):
        print(__doc__.strip().splitlines()[2])
        return 2
    current = fetch_all()
    if argv[0] == "update":
        SNAPSHOT.write_text(dump(current), encoding="utf-8")
        print(f"wrote {SNAPSHOT.relative_to(ROOT)}: " + ", ".join(f"{k} {len(v)}" for k, v in current.items()))
        return 0
    snapshot = load(SNAPSHOT.read_text(encoding="utf-8"))
    news = new_entries(snapshot, current)
    for name, items in news.items():
        print(f"{name}: {len(items)} new: {', '.join(items)}")
    if not news:
        print("no new entry: " + ", ".join(f"{k} {len(v)}" for k, v in current.items()))
    return 1 if news else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
