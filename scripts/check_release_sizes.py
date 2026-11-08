#!/usr/bin/env python3
"""Every file the release tree ships is under its size limit (build_release_tree.FILE_BYTES), measured on a commit.

The test of the release tree finds a file over the limit only in CI, minutes after a push (hooks.py, MR !467); this
is the same check in under a second, for the pre-push hook. The release tree splits betterleaks.json, so it is left
out here, as are the files it does not ship.

Usage: python3 scripts/check_release_sizes.py [COMMIT]   (default HEAD; exit 1 names each file over the limit)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_release_tree as tree  # noqa: E402


def too_big(commit: str = "HEAD") -> list[str]:
    rows = subprocess.run(["git", "ls-tree", "-r", "-l", commit], capture_output=True, text=True, check=True,
                          cwd=ROOT).stdout.splitlines()
    out = []
    for row in rows:
        meta, path = row.split("\t", 1)
        if not path.startswith(tree.RUNTIME) or path in tree.NOT_SHIPPED or path == tree.BETTERLEAKS_JSON:
            continue
        size = meta.split()[3]
        if size != "-" and int(size) >= tree.FILE_BYTES:
            out.append(f"{path} ({int(size)} bytes, limit {tree.FILE_BYTES})")
    return out


if __name__ == "__main__":
    big = too_big(sys.argv[1] if len(sys.argv) > 1 else "HEAD")
    for line in big:
        print("over the release file limit:", line)
    sys.exit(1 if big else 0)
