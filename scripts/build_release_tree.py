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

Two more files differ from `main` (0.7.9). The directory blocked 0.7.7 and 0.7.8 with SECRET_IN_SCRIPT in README.md
and in maisecrets/detection/rules/prefixes.txt, and named no line. The release tree ships `docs/DIRECTORY-README.md`
as its README.md: what the plugin, its hooks and its mod do, with no example value; the full README stays on `main`.
It ships the prefix rules as `prefixes.json` (`directory_prefixes`), in the form of the other rule files, which the
directory passed; the loader reads that file when it is there.

The mod joins `hooks/hooks.json` as a module, and `plugin.json` names no hooks file (0.7.15). That is how each of
the 72 mods that the directory served on 2026-10-23 is declared. `main` keeps the mod's own file
(`claude-mod/maisecrets-mod.json`), because Codex refuses a `hooks/hooks.json` with a key it does not know.
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
    # UTF-8 both ways: in text mode Windows decodes with its code page, and the release README's placeholder brackets
    # (U+27E6, U+27E7) came out wrong there (the release tree test on windows-latest, MR !218)
    r = subprocess.run(["git", *args], capture_output=True, text=text, env=env,
                       encoding="utf-8" if text else None)
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def paths(ref: str = "HEAD") -> list[str]:
    tracked = _git("ls-tree", "-r", "--name-only", ref).splitlines()
    keep = [p for p in tracked
            if any(p == r or (r.endswith("/") and p.startswith(r)) for r in RUNTIME) and "__pycache__" not in p
            # a skill's Codex metadata names its icon images, which the directory flags the same way
            and not (p.startswith("skills/") and "/agents/" in p and p.endswith("openai.yaml"))]
    return sorted(PREFIXES_JSON if p == PREFIXES_TXT else p for p in keep)   # see directory_prefixes


HOOKS = "hooks/hooks.json"
MANIFEST = ".claude-plugin/plugin.json"
MOD_JSON = "claude-mod/maisecrets-mod.json"
MOD_FROM_HOOKS = "../claude-mod/maisecrets-mod.mjs"
README = "README.md"
DIRECTORY_README = "docs/DIRECTORY-README.md"
PREFIXES_TXT = "maisecrets/detection/rules/prefixes.txt"
PREFIXES_JSON = "maisecrets/detection/rules/prefixes.json"


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
    # the mod joins this file as every mod the directory serves does (`modules` beside `hooks`); `main` keeps it in a
    # file of its own, as Codex refuses a hooks.json with a key it does not know (HooksFile, deny_unknown_fields), and
    # the directory installs nothing for Codex
    data["modules"] = [MOD_FROM_HOOKS]
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def directory_manifest(text: str) -> str:
    """plugin.json without its `hooks` entry: in the directory flavor the mod is a module of hooks/hooks.json."""
    data = json.loads(text)
    assert data.pop("hooks", None) == "./" + MOD_JSON, "plugin.json names another hooks file than the mod's"
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def directory_prefixes(text: str) -> str:
    """The rules of prefixes.txt (`id  regex` per line) as a JSON list of {"id", "regex"}, in the same order."""
    rules = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rule_id, regex = line.split(None, 1)
            rules.append({"id": rule_id, "regex": regex.strip()})
    return json.dumps(rules, indent=1, ensure_ascii=False) + "\n"


# the files the release tree replaces: path -> (source of the content on <ref>, transform)
def _replaced(ref: str) -> dict:
    return {HOOKS: directory_hooks(_git("show", f"{ref}:{HOOKS}")),
            MANIFEST: directory_manifest(_git("show", f"{ref}:{MANIFEST}")),
            README: _git("show", f"{ref}:{DIRECTORY_README}"),
            PREFIXES_JSON: directory_prefixes(_git("show", f"{ref}:{PREFIXES_TXT}"))}


def commit(ref: str, parent: str | None, message: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(d, "index"))
        _git("read-tree", "--empty", env=env)
        # NUL-separated bytes both ways: in text mode Windows writes CRLF into the pipe, and git
        # then reads paths that end in a carriage return (the release tree test on windows-latest)
        rows = subprocess.run(["git", "ls-tree", "-r", "-z", ref], capture_output=True, check=True).stdout
        wanted = {p.encode() for p in paths(ref)}
        replaced = _replaced(ref)
        dropped = {p.encode() for p in replaced} | {PREFIXES_TXT.encode(), MOD_JSON.encode()}
        info = b"".join(row + b"\0" for row in rows.split(b"\0") if row and row.split(b"\t", 1)[1] in wanted
                        and row.split(b"\t", 1)[1] not in dropped)
        for path, content in replaced.items():
            blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], input=content.encode("utf-8"),
                                  capture_output=True, check=True).stdout.decode().strip()
            info += f"100644 {blob}\t{path}".encode() + b"\0"
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
