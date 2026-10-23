#!/usr/bin/env python3
"""Build the standalone skill zip for a skill upload (ChatGPT "Skills", claude.ai "Upload").

The upload wants one skill root at the top of the zip. Inside the plugin the skill scripts
import the detector from the plugin root; the standalone zip carries a copy of the detector
and its rules next to the scripts instead, with the rule licenses. Nothing else is copied:
no vault, no hooks, no config.

    python3 scripts/build_skill_zip.py [--out dist/secret-hygiene.zip]
"""
from __future__ import annotations

import argparse
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "secret-hygiene"
# the detection core without personal.py, the names of maisecrets.* that the skill scripts import (the same module
# objects), and the placeholder form of the plugin
DETECTOR = ("maisecrets/__init__.py", "maisecrets/detection/__init__.py", "maisecrets/detection/checksums.py",
            "maisecrets/detection/core.py", "maisecrets/detection/value_checks.py", "maisecrets/detection/own_rules.py",
            "maisecrets/detection/text_index.py", "maisecrets/detection/encoded_mail.py",
            "maisecrets/detection/lazy_regex.py", "maisecrets/detection/normalise.py",
            "maisecrets/detection/regions.py", "maisecrets/detection/registry.py",
            "maisecrets/detection/rule_filter.py", "maisecrets/detection/rulespec.py",
            "maisecrets/detect.py", "maisecrets/checksums.py", "maisecrets/lazy_regex.py", "maisecrets/normalise.py",
            "maisecrets/regions.py", "maisecrets/registry.py", "maisecrets/rule_filter.py", "maisecrets/rulespec.py",
            "maisecrets/placeholder.py", "maisecrets/rules/freemail_domains.txt")
OPENAI_NAME = "maisecrets-secret-hygiene"


def members() -> list[tuple[Path, str]]:
    out = []
    for path in sorted(SKILL.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            out.append((path, f"secret-hygiene/{path.relative_to(SKILL).as_posix()}"))
    for rel in DETECTOR:
        out.append((ROOT / rel, f"secret-hygiene/scripts/{rel}"))
    rules = ROOT / "maisecrets" / "detection" / "rules"
    for path in sorted(rules.rglob("*")):
        if path.is_file():
            rel = path.relative_to(rules).as_posix()
            out.append((path, f"secret-hygiene/scripts/maisecrets/detection/rules/{rel}"))
    out.append((ROOT / "LICENSE", "secret-hygiene/LICENSE"))
    out.append((ROOT / "NOTICE", "secret-hygiene/NOTICE"))
    return out


def build(out: Path, flat: bool = False) -> Path:
    """flat=True puts SKILL.md at the zip root, the layout the ChatGPT skill upload reads as "one
    skill root"; it refused a single top folder with "must contain one skill root or one
    directory of skill roots" (2026-09-27). Directory entries are written too: some readers find
    folders only through them."""
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [(src, arc.split("/", 1)[1] if flat else arc) for src, arc in members()]
    dirs = sorted({"/".join(arc.split("/")[:i]) + "/" for _src, arc in rows for i in range(1, arc.count("/") + 1)})
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        # ZipInfo defaults to mode 0600 with no directory bit: unzip then made folders that nobody
        # could enter, and the scripts could not read their rules (found in a Codex test,
        # 2026-09-27). Folders are 0755 directories, a written file 0644
        for d in dirs:
            info = zipfile.ZipInfo(d)
            info.external_attr = (0o40755 << 16) | 0x10
            z.writestr(info, "")
        for src, arc in rows:
            if flat and arc == "SKILL.md":
                # ChatGPT skills share one namespace and the skill stands alone there: it carries
                # the brand. In the plugin Claude Code shows it as maisecrets:secret-hygiene.
                text = src.read_text(encoding="utf-8")
                info = zipfile.ZipInfo(arc, date_time=time.localtime(src.stat().st_mtime)[:6])
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, text.replace("\nname: secret-hygiene\n", f"\nname: {OPENAI_NAME}\n", 1))
                continue
            z.write(src, arc)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist" / "secret-hygiene.zip"))
    ap.add_argument("--flat", action="store_true", help="SKILL.md at the zip root (ChatGPT skill upload)")
    args = ap.parse_args(argv)
    out = build(Path(args.out), flat=args.flat)
    print(f"wrote {out} ({len(members())} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
