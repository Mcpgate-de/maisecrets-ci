#!/usr/bin/env python3
"""Build the tree of a release branch on GitHub: only the files the plugin needs at run time.

Three flavors, one per branch (docs/REPO-STANDARDS.md, "Release branches"):
- `directory`: the branch `release`, which the Anthropic directory reviews (the default; described below).
- `claude`: the branch `release-claude`, which Claude Code installs from. The runtime files of the tag with the
  tag's own hooks/hooks.json and README.md. Only betterleaks.json ships in parts: no file may reach FILE_BYTES.
- `codex`: the branch `release-codex`, which Codex installs from. The files of `claude` plus `.codex-plugin/` and
  each skill's agents/openai.yaml, all under `plugin/`: Codex installs a Git source only from a sub-directory
  (`path`), and without `.codex-plugin/` it reads `.claude-plugin/plugin.json`, whose `hooks` names the mod file,
  and loads no hook.

The Anthropic directory checks every file it gets, and it blocked two versions on literals in the
test files (2026-09-27). The tests, the CI files, the release scripts and the developer docs are
never run by the plugin, so the `release` branch leaves them out. The allowlist below is the
whole content: a new runtime folder must be added here, and a test checks that every path the
hooks and the commands name is in the tree.

    python3 scripts/build_release_tree.py list [<ref>] [--flavor F]       the paths, one per line
    python3 scripts/build_release_tree.py commit <ref> [<parent>] -m <message> [--flavor F]
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
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

# folders and files of the plugin at run time, and the documents a user reads
# no .codex-plugin/ but in the codex flavor: the directory held every version because that manifest names image
# files (UNREAD_ASSET_REFERENCED, 2026-09-30: "the plugin stays held for review")
# no docs/: nothing at run time reads them, they are on GitHub, and THREAT-MODEL.md quotes the download-and-run
# commands that C21 guards, which the directory lists as RUNTIME_FETCH_EXEC (0.7.17)
RUNTIME = (".claude-plugin/", "hooks/", "claude-mod/", "maisecrets/", "commands/", "skills/", "assets/",
           "LICENSE", "NOTICE", "README.md", "PRIVACY.md", "SECURITY.md", "CHANGELOG.md")
# the rule source that scripts/sync_betterleaks.py converts to betterleaks.json; the detector reads only the JSON
NOT_SHIPPED = ("maisecrets/detection/rules/betterleaks.toml",)


def _git(*args: str, env: dict | None = None, text: bool = True) -> str:
    # UTF-8 both ways: in text mode Windows decodes with its code page, and the release README's placeholder brackets
    # (U+27E6, U+27E7) came out wrong there (the release tree test on windows-latest, MR !218)
    r = subprocess.run(["git", *args], capture_output=True, text=text, env=env,
                       encoding="utf-8" if text else None)
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:300]}")
    return r.stdout


FLAVORS = ("directory", "claude", "codex")
# the folder the codex flavor puts the plugin in: a Codex Git source names it as its `path`, which cannot be "."
CODEX_ROOT = "plugin/"


def _shipped(ref: str, flavor: str) -> list[str]:
    """The tracked files of <ref> that the flavor ships, before any replacement."""
    tracked = _git("ls-tree", "-r", "--name-only", ref).splitlines()
    runtime = RUNTIME + ((".codex-plugin/",) if flavor == "codex" else ())
    return [p for p in tracked
            if any(p == r or (r.endswith("/") and p.startswith(r)) for r in runtime) and "__pycache__" not in p
            and p not in NOT_SHIPPED
            # a skill's Codex metadata names its icon images, which the directory flags; only Codex reads it
            and (flavor == "codex" or not (p.startswith("skills/") and "/agents/" in p and p.endswith("openai.yaml")))]


def _prefix(flavor: str) -> str:
    return CODEX_ROOT if flavor == "codex" else ""


def paths(ref: str = "HEAD", flavor: str = "directory") -> list[str]:
    replaced = _replaced(ref, flavor)
    # the sources that a replacement stands in for: prefixes.txt becomes prefixes.json in the directory flavor only
    gone = set(replaced) | {BETTERLEAKS_JSON} | ({PREFIXES_TXT} if flavor == "directory" else set())
    keep = [p for p in _shipped(ref, flavor) if p not in gone] + list(replaced)
    return sorted(_prefix(flavor) + p for p in keep)


HOOKS = "hooks/hooks.json"
README = "README.md"
DIRECTORY_README = "docs/DIRECTORY-README.md"
PREFIXES_TXT = "maisecrets/detection/rules/prefixes.txt"
PREFIXES_JSON = "maisecrets/detection/rules/prefixes.json"
BETTERLEAKS_JSON = "maisecrets/detection/rules/betterleaks.json"
# the rules whose filter lists literal keys that betterleaks allows (public example keys): the directory version
# ships each key as its sha256. A betterleaks sync that adds such a list elsewhere turns the release tree test red
HASHED_ALLOW_LISTS = ("gcp-api-key",)
PART_BYTES = 150_000
# the largest file the release tree may hold: the directory read 207 KB and held 271 KB unread (0.7.17 to 0.7.19)
FILE_BYTES = 200_000


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


def directory_prefixes(text: str) -> str:
    """The rules of prefixes.txt (`id  regex` per line) as a JSON list of {"id", "regex"}, in the same order."""
    rules = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rule_id, regex = line.split(None, 1)
            rules.append({"id": rule_id, "regex": regex.strip()})
    return json.dumps(rules, indent=1, ensure_ascii=False) + "\n"


_ALLOW_LIST = re.compile(r'matchesAny\(finding\["secret"\], \[(?P<items>[^\]]*)\]\)')


def _hashed_allow_list(rule_id: str, text: str) -> str:
    """The filter with its list of literal keys written as equalsAnySha256 over their sha256. betterleaks matches
    each pattern with search; the rule's secret has the length of the keys, so a match is an equal string."""
    def sub(m: re.Match) -> str:
        items = re.findall(r"`([^`]*)`", m.group("items"))
        if not items or any(not re.fullmatch(r"[A-Za-z0-9_-]{20,}", x) for x in items):
            raise SystemExit(f"{rule_id}: the allow list holds a pattern that is no literal key")
        digests = ", ".join(f'"{hashlib.sha256(x.encode()).hexdigest()}"' for x in items)
        return f'equalsAnySha256(finding["secret"], [{digests}])'
    out, n = _ALLOW_LIST.subn(sub, text)
    if not n:
        raise SystemExit(f"{rule_id}: no allow list of literal keys in its filter")
    return out


def directory_betterleaks(text: str) -> dict:
    """betterleaks.json as betterleaks.part1.json, part2, …, each under PART_BYTES: the directory held every version
    whose betterleaks.json (349 KB) it could not read whole (BINARIES_NOT_INSPECTED, 0.7.17). The allow lists of
    HASHED_ALLOW_LISTS ship as sha256, so a readable part holds no key (SECRET_IN_SCRIPT). The loader
    (core.betterleaks_config) joins the parts; the first one carries the other top-level keys."""
    cfg = json.loads(text)
    rules = cfg.pop("rules")
    for r in rules:
        if r.get("id") in HASHED_ALLOW_LISTS:
            r["filter"] = _hashed_allow_list(r["id"], r["filter"])
    def dump(i: int, chunk: list) -> str:
        return json.dumps({**(cfg if i == 1 else {}), "rules": chunk}, indent=1, ensure_ascii=False) + "\n"
    parts: list = [[]]
    for r in rules:
        parts[-1].append(r)
        if len(parts[-1]) > 1 and len(dump(len(parts), parts[-1]).encode()) >= PART_BYTES:
            parts[-1].pop()
            parts.append([r])
    return {f"maisecrets/detection/rules/betterleaks.part{i}.json": dump(i, chunk)
            for i, chunk in enumerate(parts, 1)}


# the files the release tree replaces: path -> content made from <ref>. Only the directory flavor changes the hooks,
# the README and the prefix rules; every flavor ships betterleaks.json in parts (FILE_BYTES)
def _replaced(ref: str, flavor: str = "directory") -> dict:
    if flavor not in FLAVORS:
        raise SystemExit(f"unknown flavor {flavor!r}; one of {', '.join(FLAVORS)}")
    parts = directory_betterleaks(_git("show", f"{ref}:{BETTERLEAKS_JSON}"))
    if flavor != "directory":
        return parts
    return {HOOKS: directory_hooks(_git("show", f"{ref}:{HOOKS}")),
            README: _git("show", f"{ref}:{DIRECTORY_README}"),
            PREFIXES_JSON: directory_prefixes(_git("show", f"{ref}:{PREFIXES_TXT}")),
            **parts}


def commit(ref: str, parent: str | None, message: str, flavor: str = "directory") -> str:
    prefix = _prefix(flavor).encode()
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(d, "index"))
        _git("read-tree", "--empty", env=env)
        # NUL-separated bytes both ways: in text mode Windows writes CRLF into the pipe, and git
        # then reads paths that end in a carriage return (the release tree test on windows-latest)
        rows = subprocess.run(["git", "ls-tree", "-r", "-z", ref], capture_output=True, check=True).stdout
        replaced = _replaced(ref, flavor)
        wanted = {p[len(prefix):].encode() for p in paths(ref, flavor)} - {p.encode() for p in replaced}
        info = b""
        for row in rows.split(b"\0"):
            if row and row.split(b"\t", 1)[1] in wanted:
                meta, path = row.split(b"\t", 1)
                info += meta + b"\t" + prefix + path + b"\0"
        for path, content in replaced.items():
            blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], input=content.encode("utf-8"),
                                  capture_output=True, check=True).stdout.decode().strip()
            info += f"100644 {blob}\t".encode() + prefix + path.encode() + b"\0"
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
    argv = list(argv)
    flavor = "directory"
    if "--flavor" in argv:
        i = argv.index("--flavor")
        if i + 1 >= len(argv) or argv[i + 1] not in FLAVORS:
            print(f"--flavor takes one of {', '.join(FLAVORS)}")
            return 2
        flavor = argv[i + 1]
        del argv[i:i + 2]
    if len(argv) >= 2 and argv[1] == "list":
        print("\n".join(paths(argv[2] if len(argv) > 2 else "HEAD", flavor)))
        return 0
    if len(argv) >= 5 and argv[1] == "commit" and "-m" in argv:
        i = argv.index("-m")
        rest = argv[2:i]
        print(commit(rest[0], rest[1] if len(rest) > 1 else None, argv[i + 1], flavor))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
