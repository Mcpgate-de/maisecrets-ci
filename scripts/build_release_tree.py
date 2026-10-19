#!/usr/bin/env python3
"""Build the tree of the `release` branch: only the files the plugin needs at run time.

The Anthropic directory checks every file it gets, and it blocked two versions on literals in the
test files (2026-09-27). The tests, the CI files, the release scripts and the developer docs are
never run by the plugin, so the `release` branch leaves them out. The allowlist below is the
whole content: a new runtime folder must be added here, and a test checks that every path the
hooks and the commands name is in the tree.

    python3 scripts/build_release_tree.py list [<ref>]       the paths, one per line
    python3 scripts/build_release_tree.py commit <ref> [<parent>] -m <message>
                                                              write a commit, print its id

`commit` writes the tree into a temporary index, so the working copy and the real index stay as
they are. With <parent> the new commit continues that history; without it, it starts one.

The `release` branch also carries its own `hooks/hooks.json` (`directory_hooks`). The directory refused 0.5.15 and
0.5.16 with UNPINNED_NPX: a hook command may hold no variable, command substitution, wildcard or inline program.
The hooks on `main` are one program for bash and PowerShell, and they block when an update removed the plugin
folder of an open session. The directory flavor names one program per hook, and gives up two things: a hook
without Git Bash on Windows (Claude Code), and the block after a synced update removed the folder. A marketplace
install, as the directory makes it, keeps the old version folder for 14 days.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile

# folders and files of the plugin at run time, and the documents a user reads
# no .codex-plugin/: Codex installs from main, and the directory held every version because that manifest names
# image files (UNREAD_ASSET_REFERENCED, 2026-09-30: "the plugin stays held for review")
RUNTIME = (".claude-plugin/", "hooks/", "claude-mod/", "maisecrets/", "commands/", "skills/", "assets/",
           "LICENSE", "NOTICE", "README.md", "PRIVACY.md", "SECURITY.md", "CHANGELOG.md",
           "docs/CLIENTS.md", "docs/PROTOCOL.md", "docs/THREAT-MODEL.md", "docs/label-sources.md", "docs/DETECTION.md")


def _git(*args: str, env: dict | None = None, text: bool = True) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=text, env=env)
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def paths(ref: str = "HEAD") -> list[str]:
    tracked = _git("ls-tree", "-r", "--name-only", ref).splitlines()
    keep = [p for p in tracked
            if any(p == r or (r.endswith("/") and p.startswith(r)) for r in RUNTIME) and "__pycache__" not in p
            # a skill's Codex metadata names its icon images, which the directory flags the same way
            and not (p.startswith("skills/") and "/agents/" in p and p.endswith("openai.yaml"))]
    return sorted(keep)


HOOKS = "hooks/hooks.json"


def directory_hooks(text: str) -> str:
    """The hooks of `main` with each command reduced to one program by its full path from ${CLAUDE_PLUGIN_ROOT}."""
    data = json.loads(text)
    for entries in data["hooks"].values():
        for entry in entries:
            for h in entry.get("hooks", []):
                sub = re.search(r'hooks/run\.sh" ([\w-]+)', h["command"]).group(1)
                h["command"] = f'bash "${{CLAUDE_PLUGIN_ROOT}}/hooks/run.sh" {sub}'
                if "commandWindows" in h:
                    h["commandWindows"] = f'"${{CLAUDE_PLUGIN_ROOT}}/hooks/run.cmd" {sub}'
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def commit(ref: str, parent: str | None, message: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(d, "index"))
        _git("read-tree", "--empty", env=env)
        # NUL-separated bytes both ways: in text mode Windows writes CRLF into the pipe, and git
        # then reads paths that end in a carriage return (the release tree test on windows-latest)
        rows = subprocess.run(["git", "ls-tree", "-r", "-z", ref], capture_output=True, check=True).stdout
        wanted = {p.encode() for p in paths(ref)}
        info = b"".join(row + b"\0" for row in rows.split(b"\0") if row and row.split(b"\t", 1)[1] in wanted
                        and row.split(b"\t", 1)[1] != HOOKS.encode())
        hooks = directory_hooks(_git("show", f"{ref}:{HOOKS}"))
        blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], input=hooks.encode("utf-8"),
                              capture_output=True, check=True).stdout.decode().strip()
        info += f"100644 {blob}\t{HOOKS}".encode() + b"\0"
        r = subprocess.run(["git", "update-index", "-z", "--index-info"], input=info, env=env, capture_output=True)
        if r.returncode != 0:
            raise SystemExit(f"git update-index failed: {r.stderr.decode(errors='replace').strip()[:300]}")
        tree = _git("write-tree", env=env).strip()
    args = ["commit-tree", tree, "-m", message] + (["-p", parent] if parent else [])
    # the release identity when none is configured: a CI container has no git identity
    ident = dict(os.environ)
    for role in ("AUTHOR", "COMMITTER"):
        ident.setdefault(f"GIT_{role}_NAME", "maisecrets release")
        ident.setdefault(f"GIT_{role}_EMAIL", "ci@maisecrets.local")
    return _git(*args, env=ident).strip()


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "list":
        print("\n".join(paths(argv[2] if len(argv) > 2 else "HEAD")))
        return 0
    if len(argv) >= 5 and argv[1] == "commit" and "-m" in argv:
        i = argv.index("-m")
        rest = argv[2:i]
        print(commit(rest[0], rest[1] if len(rest) > 1 else None, argv[i + 1]))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
