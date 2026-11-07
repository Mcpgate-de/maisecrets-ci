#!/usr/bin/env python3
"""Is HEAD the release commit of TAG? The checks of the GitLab job verify_release, for a CI that has no such job (the
PyPI workflow of the GitHub mirror):

    python3 scripts/verify_release_commit.py TAG [MAIN_REF]

- the release job made it (author ci@maisecrets.local) with the subject `chore(release): <TAG>`;
- it changes only the release files (both manifests of Claude Code, the Codex manifest and CHANGELOG.md);
- it is on main (MAIN_REF, default origin/main), and the manifest carries the version of the tag.

Exit 0 when all hold, 1 with the reason otherwise."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE_FILES = sorted([".claude-plugin/marketplace.json", ".claude-plugin/plugin.json", ".codex-plugin/plugin.json",
                        "CHANGELOG.md"])


def git(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def problems(tag: str, main_ref: str) -> list:
    out = []
    changed = sorted(git("diff", "--name-only", "HEAD^", "HEAD").stdout.split())
    if changed != RELEASE_FILES:
        out.append(f"the release commit changes {changed}, not only the release files")
    if git("log", "-1", "--format=%s", "HEAD").stdout.strip() != f"chore(release): {tag}":
        out.append("HEAD is not the release commit of the tag")
    if git("log", "-1", "--format=%ae", "HEAD").stdout.strip() != "ci@maisecrets.local":
        out.append("the release commit was not made by the release job")
    if git("merge-base", "--is-ancestor", "HEAD", main_ref).returncode != 0:
        out.append(f"HEAD is not on {main_ref}")
    version = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))["version"]
    if f"v{version}" != tag:
        out.append(f"the manifest carries {version}, the tag is {tag}")
    return out


def main(argv: list) -> int:
    if not 1 <= len(argv) <= 2:
        print(__doc__)
        return 2
    found = problems(argv[0], argv[1] if len(argv) == 2 else "origin/main")
    for p in found:
        print("FAIL", p)
    if not found:
        print(f"HEAD is the release commit of {argv[0]}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
