"""Measure what maisecrets would act on in a real tree: the detector's hits, and the hits a Read of each file would
still redact after the test-code rule. A reality check for the false-positive rate, not a gate.

    python3 scripts/measure_false_alarms.py <dir> [--samples]

It prints no value and no line: only the rule, the file, the end of the label before the value, and the shape of
the value (letters as a/A, digits as 9). A tree of your own may hold real secrets; this output does not carry them.
The store is a fresh temp directory, never ~/.maisecrets. Measured on 2026-09-29: the Python standard library
(36.6 MB) and a real service repository (58.9 MB), before and after the 0.5.15 changes (CHANGELOG).
"""
from __future__ import annotations

import collections
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".rs", ".php", ".cs", ".json", ".toml",
       ".yaml", ".yml", ".md", ".rst", ".txt", ".cfg", ".ini", ".sh", ".env", ".example", ".html", ".xml", ".sql"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def shape(v: str) -> str:
    s = re.sub(r"[A-Z]", "A", v)
    s = re.sub(r"[a-z]", "a", s)
    s = re.sub(r"[0-9]", "9", s)
    return re.sub(r"(.)\1+", r"\1+", s)[:20]


def load_detect():
    """The detector, with a fresh temp store as its home, never the user's own."""
    home = tempfile.mkdtemp(prefix="maisecrets-measure-")
    Path(home, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
    os.environ["MAISECRETS_HOME"] = home
    sys.path.insert(0, str(ROOT))
    from maisecrets import detect

    return detect


def measure(tree: Path, detect, samples: bool = False) -> dict:
    """The files and characters read, and per (where, type, rule) the hits and the hits a Read would act on. With
    samples, up to six lines per key: the file, the end of the label and the shape of the value, never the value."""
    raw: collections.Counter = collections.Counter()
    acted: collections.Counter = collections.Counter()
    seen: dict = collections.defaultdict(list)
    files = size = 0
    for dp, dn, fn in os.walk(tree):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            if os.path.splitext(f)[1] not in EXT and f not in ("Dockerfile", "Makefile"):
                continue
            path = os.path.join(dp, f)
            rel = os.path.relpath(path, tree)
            try:
                text = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            if len(text) > 2_000_000:
                continue
            files += 1
            size += len(text)
            where = "tests" if detect.is_test_path(rel) else "other"
            for m in detect.scan(text):
                key = (where, m.type, m.kind.split("#")[0])
                raw[key] += 1
                if detect.is_fixture(m, text, rel):
                    continue
                acted[key] += 1
                if samples and len(seen[key]) < 6:
                    a = text.rfind("\n", 0, m.start) + 1
                    label = re.sub(r"[^\w .:=\-\[\]\"'()]", "?", text[a:m.start][-28:])
                    seen[key].append(f"{rel[-48:]} | {label!r} | {shape(m.value)} len {len(m.value)}")
    return {"files": files, "size": size, "raw": raw, "acted": acted, "seen": seen}


def main(argv: list[str]) -> int:
    if not argv or argv[0].startswith("-"):
        print(__doc__.strip())
        return 2
    r = measure(Path(argv[0]), load_detect(), "--samples" in argv)
    files, size, raw, acted, seen = r["files"], r["size"], r["raw"], r["acted"], r["seen"]
    print(f"{files} files, {size / 1e6:.1f} MB")
    print(f"{'where':6} {'type':18} {'rule':40} {'hits':>6} {'acted':>6}")
    for key in sorted(raw, key=lambda k: -raw[k]):
        print(f"{key[0]:6} {key[1]:18} {key[2]:40} {raw[key]:6} {acted[key]:6}")
    for key, lines in sorted(seen.items(), key=lambda kv: -acted[kv[0]]):
        print(f"\n== {' '.join(key)}: {acted[key]}")
        for line in lines:
            print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
