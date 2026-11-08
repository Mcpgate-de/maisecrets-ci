#!/usr/bin/env python3
"""The repository must not carry a value the detector would hide: scan every file on its own.

The CI job used to pipe all files into one `maisecrets.cli scan`. A PNG in the tree crashed the
strict decode without output, which read as "nothing found" for weeks, and one long stream let
a label at the end of one file pair with the first word of the next (2026-09-27). Each file is
read as bytes, decoded with replacement, and scanned alone; a hit prints the path, the line and
the rule, never the value.

    python3 scripts/scan_tree.py [ROOT]
"""
from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# the built-in rules only, in a temp home: the developer's own terms.txt, rule folders and allow list are no part of
# the tree check, and the scan must never read them (gate review of block 2, L5)
_HOME = tempfile.mkdtemp(prefix="scan-tree-home-")
atexit.register(shutil.rmtree, _HOME, True)
Path(_HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}', encoding="utf-8")
os.environ["MAISECRETS_HOME"] = _HOME
from maisecrets import detect  # noqa: E402

SKIP = {".git", ".claude", "__pycache__", "dist", "node_modules"}
VENDORED = ("maisecrets/detection/rules/",)   # the rule sets carry secret shapes by design


def scan_file(path: str, rel: str) -> tuple:
    """(scanned, [line of each hit]) of one file; a binary file is not scanned."""
    raw = Path(path).read_bytes()
    if b"\x00" in raw[:4096]:
        return False, []
    text = raw.decode("utf-8", errors="replace")
    return True, [f"{rel}:{text.count(chr(10), 0, m.start) + 1}: {m.kind}"
                  for m in detect.scan(text) if m.type == "SECRET"]


def main(argv: list[str]) -> int:
    root = Path(argv[0]) if argv else ROOT
    todo = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for name in filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if not rel.startswith(VENDORED):
                todo.append((path.stat().st_size, str(path), rel))
    # one file per task on every core, the largest first: the same scan of each file, in about a sixth of the time
    # of one core (2026-11-07). Each worker imports the detector itself, in its own temp home
    todo.sort(reverse=True)
    with ProcessPoolExecutor(max_workers=min(8, os.cpu_count() or 1)) as pool:
        results = list(pool.map(scan_file, [p for _s, p, _r in todo], [r for _s, _p, r in todo]))
    files = sum(1 for scanned, _h in results if scanned)
    lines = sorted(h for _s, found in results for h in found)
    for line in lines:
        print(line)
    hits = len(lines)
    print(f"scanned {files} files: {hits} secret-shaped value(s)")
    if files == 0:
        print("no file was scanned: the scan proves nothing")
        return 1
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
