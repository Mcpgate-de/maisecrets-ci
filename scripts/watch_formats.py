#!/usr/bin/env python3
"""Watch the public lists of token formats for entries that maisecrets has not looked at yet.

    python3 scripts/watch_formats.py check     exit 1 and list each new or changed entry, per source
    python3 scripts/watch_formats.py update    write the current lists to docs/format-watch.txt and their
                                               fingerprints to docs/format-watch-fp.txt

The vendored rule sets are kept current by Renovate (renovate.json). These sources are not vendored, and a format
can be in one of them long before it reaches a vendored set, or never (the Storyblok `sb_pat_` token, 2026-10-22):

- github: the secret types of GitHub secret scanning (names only; GitHub keeps the patterns of its partners
  private), src/secret-scanning/data/pattern-docs/fpt/public-docs.yml in github/docs
- trufflehog: its detectors, one folder each under pkg/detectors
- betterleaks: the rule ids of config/betterleaks.toml on main, ahead of the release that Renovate takes
- veles: the secret plugins of Google's OSV-SCALIBR, one folder each under veles/secrets (kingfisher imports them)
- gitleaks: the rule ids of config/gitleaks.toml on master
- trivy: the ids of its built-in secret rules, pkg/fanal/secret/builtin-rules.go
- noseyparker: the rule ids of its built-in rule files, crates/noseyparker/data/default/builtin/rules
- nuclei: the names under file/keys of nuclei-templates, one file or folder per provider

A new entry is a reason to look, not a rule: whoever looks writes a prefix rule with a test when the format has a
fixed prefix (maisecrets/detection/rules/prefixes.txt), or adds the entry to the snapshot with `update`. The
snapshot is a text file, a `[source]` line and one id per line, so no id list reads as a label and its value. The
scheduled pipeline runs `check`; a red job is the notice. Standard library only; GITHUB_TOKEN is used when set.

An entry also has a fingerprint (docs/format-watch-fp.txt): the first 12 hex digits of the sha256 of its rule text
(a TOML or YAML rule, a Go rule literal, a secret type's entry), or the git object id of its folder or file. A
provider that changes a known format (a new length, a second prefix) keeps its id and changes its fingerprint; until
0.7.16 the watch saw only new ids, so such a change went unseen.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "docs" / "format-watch.txt"
FINGERPRINTS = ROOT / "docs" / "format-watch-fp.txt"
API = "https://api.github.com/repos/"
RAW = "https://raw.githubusercontent.com/"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "maisecrets-format-watch"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(API):
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def fp(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def blocks(text: str, start: str, id_re: str) -> dict:
    """{id: fingerprint} of the parts of `text` that begin where `start` matches, each named by its first `id_re`
    group. A part with no id is left out; two parts with one id share a fingerprint of both."""
    starts = [m.start() for m in re.finditer(start, text, re.M)] + [len(text)]
    out: dict = {}
    for a, b in zip(starts, starts[1:]):
        part = text[a:b]
        m = re.search(id_re, part, re.M)
        if m:
            out[m.group(1)] = fp(out.get(m.group(1), "") + part)
    return out


def _folders(repo: str, path: str) -> dict:
    """{folder name: git tree id} under `path` on the default branch: the tree of that path, not a recursive
    listing. The tree id changes with any file in the folder."""
    parent, _, leaf = path.rpartition("/")
    entries = json.loads(_get(f"{API}{repo}/contents/{parent}"))
    sha = next(e["sha"] for e in entries if e["name"] == leaf and e["type"] == "dir")
    tree = json.loads(_get(f"{API}{repo}/git/trees/{sha}"))["tree"]
    return {e["path"]: e["sha"][:12] for e in tree if e["type"] == "tree"}


def _names(repo: str, path: str) -> dict:
    """{name: git object id} of the files and folders under `path`."""
    return {e["name"]: e["sha"][:12] for e in json.loads(_get(f"{API}{repo}/contents/{path}"))}


def github_entries(text: str) -> dict:
    return blocks(text, r"^\s*-\s+provider:", r"^\s*secretType:\s*['\"]?([\w.-]+)")


def toml_rules(text: str) -> dict:
    return blocks(text, r"^\s*\[\[rules\]\]", r'^\s*id\s*=\s*"([^"]+)"')


def trivy_rules(text: str) -> dict:
    return blocks(text, r'^\s*ID:\s*"', r'^\s*ID:\s*"([\w.-]+)"')


def yaml_rules(text: str) -> dict:
    return blocks(text, r"^\s*-\s+name:", r"^\s*id:\s*['\"]?([\w.-]+)")


def noseyparker_rules() -> dict:
    base = "praetorian-inc/noseyparker/main/crates/noseyparker/data/default/builtin/rules/"
    files = [n for n in _names("praetorian-inc/noseyparker", "crates/noseyparker/data/default/builtin/rules")
             if n.endswith(".yml")]
    out: dict = {}
    for f in files:
        out.update(yaml_rules(_get(RAW + base + f).decode("utf-8")))
    return out


SOURCES = {
    "github": lambda: github_entries(_get(RAW + "github/docs/main/src/secret-scanning/data/pattern-docs/fpt/"
                                          "public-docs.yml").decode("utf-8")),
    "trufflehog": lambda: _folders("trufflesecurity/trufflehog", "pkg/detectors"),
    "betterleaks": lambda: toml_rules(_get(RAW + "betterleaks/betterleaks/main/config/betterleaks.toml")
                                      .decode("utf-8")),
    "veles": lambda: _folders("google/osv-scalibr", "veles/secrets"),
    "gitleaks": lambda: toml_rules(_get(RAW + "gitleaks/gitleaks/master/config/gitleaks.toml").decode("utf-8")),
    "trivy": lambda: trivy_rules(_get(RAW + "aquasecurity/trivy/main/pkg/fanal/secret/builtin-rules.go")
                                 .decode("utf-8")),
    "noseyparker": noseyparker_rules,
    "nuclei": lambda: _names("projectdiscovery/nuclei-templates", "file/keys"),
}


def as_fingerprints(items) -> dict:
    """A source gives {id: fingerprint}, or a list of ids (no fingerprint, so no change can be seen)."""
    return dict(items) if isinstance(items, dict) else {i: "" for i in items}


def changed_entries(snapshot_fp: dict, current: dict) -> dict:
    """Per source, the ids whose fingerprint differs from the snapshot's. An id without a fingerprint on either side
    (a new id, or a source that gives no fingerprints) is no change."""
    out = {}
    for name, items in current.items():
        cur, old = as_fingerprints(items), snapshot_fp.get(name, {})
        diff = sorted(i for i, f in cur.items() if f and old.get(i) and old[i] != f)
        if diff:
            out[name] = diff
    return out


def dump_fp(lists: dict) -> str:
    return "".join(f"[{name}]\n" + "".join(f"{i}\t{f}\n" for i, f in sorted(as_fingerprints(items).items()) if f)
                   + "\n" for name, items in sorted(lists.items()))


def load_fp(text: str) -> dict:
    out: dict = {}
    for name, rows in load(text).items():
        out[name] = dict(r.split("\t", 1) for r in rows if "\t" in r)
    return out


def new_entries(snapshot: dict, current: dict) -> dict:
    """Per source, the entries of `current` that the snapshot does not hold. A source missing from the snapshot
    counts every entry as new; an entry that left a source is no news."""
    return {name: sorted(set(as_fingerprints(items)) - set(snapshot.get(name, []))) for name, items in current.items()
            if set(as_fingerprints(items)) - set(snapshot.get(name, []))}


def dump(lists: dict) -> str:
    return "".join(f"[{name}]\n" + "".join(f"{i}\n" for i in sorted(as_fingerprints(items))) + "\n"
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
        FINGERPRINTS.write_text(dump_fp(current), encoding="utf-8")
        print(f"wrote {SNAPSHOT.relative_to(ROOT)} and {FINGERPRINTS.relative_to(ROOT)}: "
              + ", ".join(f"{k} {len(v)}" for k, v in current.items()))
        return 0
    news, changed = diff_against_snapshot(current)
    for name, items in news.items():
        print(f"{name}: {len(items)} new: {', '.join(items)}")
    for name, items in changed.items():
        print(f"{name}: {len(items)} changed: {', '.join(items)}")
    if not news and not changed:
        print("no new or changed entry: " + ", ".join(f"{k} {len(v)}" for k, v in current.items()))
    return 1 if news or changed else 0


def diff_against_snapshot(current: dict) -> tuple:
    """(new, changed) against docs/format-watch.txt and docs/format-watch-fp.txt. A missing fingerprint file is
    no change: the first `update` writes it."""
    snapshot = load(SNAPSHOT.read_text(encoding="utf-8"))
    fps = load_fp(FINGERPRINTS.read_text(encoding="utf-8")) if FINGERPRINTS.exists() else {}
    return new_entries(snapshot, current), changed_entries(fps, current)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
