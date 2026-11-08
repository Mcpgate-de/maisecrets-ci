#!/usr/bin/env python3
"""Keep the baselines in bench/results small: the newest KEEP release baselines (`<date>-v3-<version>`) and every
folder that a file outside bench/results names stay; the others leave the tree (git keeps them: `git show
v0.8.20:bench/results/…`).

The claude.ai organisation sync takes the whole repository and refuses a plugin above 200 MB uncompressed; with
about 4 MB of baseline per release the tree reached 202 MB at 0.9.0 and the sync of 0.9.0 failed. The release gate
calls this after it writes a new baseline, and tests/test_tree_size.py fails above TREE_MAX_MB.

    python3 scripts/prune_baselines.py [--dry-run]
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "bench" / "results"
KEEP = 3
_RELEASE = re.compile(r"\d{4}-\d{2}-\d{2}-v3-(\d+)\.(\d+)\.(\d+)")


def named(root: Path = ROOT) -> set:
    """The folders of bench/results that a tracked file outside bench/results names."""
    out = set()
    folders = [p.name for p in (root / "bench" / "results").iterdir() if p.is_dir()]
    text = subprocess.run(["git", "grep", "-h", "-o", "-E", r"bench/results/[A-Za-z0-9._-]+", "--", ".",
                           ":!bench/results", ":!bench/HOLDOUT-LOG.md", ":!CHANGELOG.md"],
                          cwd=root, capture_output=True, text=True).stdout
    for ref in set(text.split()):
        name = ref.split("/", 2)[2]
        for f in folders:
            if name.startswith(f):          # the folder, a file in it, f.md, or a run named after it (f-prompt-ner)
                out.add(f)
    # a doc may name a run by its folder name alone (2026-10-21-v3)
    words = subprocess.run(["git", "grep", "-h", "-o", "-E", r"20[0-9]{2}-[0-9]{2}-[0-9]{2}-[A-Za-z0-9._-]+", "--",
                            ".", ":!bench/results", ":!bench/HOLDOUT-LOG.md", ":!CHANGELOG.md"],
                           cwd=root, capture_output=True, text=True).stdout
    for w in set(words.split()):
        out.update(f for f in folders if w.startswith(f))
    return out


def to_remove(root: Path = ROOT, keep: int = KEEP) -> list:
    folders = [p for p in (root / "bench" / "results").iterdir() if p.is_dir()]
    releases = sorted((p for p in folders if _RELEASE.fullmatch(p.name)),
                      key=lambda p: tuple(int(g) for g in _RELEASE.fullmatch(p.name).groups()))
    newest = {p.name for p in releases[-keep:]}
    keep_names = newest | named(root)
    return sorted(p for p in releases if p.name not in keep_names)


def main(argv: list) -> int:
    gone = to_remove()
    for p in gone:
        print(("would remove " if "--dry-run" in argv else "removed ") + str(p.relative_to(ROOT)))
        if "--dry-run" not in argv:
            shutil.rmtree(p)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
