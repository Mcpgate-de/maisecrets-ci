#!/usr/bin/env python3
"""Lint the plugin files the way a directory check reads them. Exit 1 on the first class of error.

The directory check refused commands/report.md with FRONTMATTER_YAML_INVALID: an unquoted
`argument-hint: [last | …] [--create]` starts a YAML list and the text after `]` breaks it.
`claude plugin validate --strict` passed the same file (2026-09-28). This linter runs in the
pre-commit hook, in the CI lint job and before every release.

    python3 scripts/lint_plugin.py

Checks:
  1. the frontmatter of every command, skill and agent file: a strict line check always, and a
     YAML parse with text values when PyYAML is installed (CI installs it); required keys
  2. every JSON manifest parses
  3. every hook command in hooks/hooks.json names a file that exists
  4. every `run.sh <command>` in a command file names a command dispatch.py handles or passes to
     the CLI, and every name dispatch.py passes on is a CLI command
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSON_FILES = (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", ".codex-plugin/plugin.json",
              "hooks/hooks.json", "claude-mod/maisecrets-mod.json")
REQUIRED = {"commands": ("description",), "skills": ("name", "description"), "agents": ("name", "description")}
# a plain (unquoted) YAML scalar must not start with one of these, and must not hold ": " or " #"
_INDICATORS = tuple("[]{}&*!|>%@`\"'#,?-:")
_LINE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*):(?: (.*))?$")


def component_files(root: Path = ROOT) -> list[Path]:
    return sorted([*root.glob("commands/*.md"), *root.glob("skills/*/SKILL.md"), *root.glob("agents/*.md")])


def frontmatter(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 4)
    return None if end < 0 else text[4:end + 1]


def line_problems(block: str) -> list[str]:
    """What a strict YAML reader would refuse, or read as something other than text."""
    out, seen = [], set()
    for n, line in enumerate(block.splitlines(), 1):
        if not line.strip():
            continue
        m = _LINE_RE.match(line)
        if not m:
            out.append(f"line {n}: not a plain `key: value` line: {line!r}")
            continue
        key, value = m.group(1), (m.group(2) or "").strip()
        if key in seen:
            out.append(f"line {n}: duplicate key {key}")
        seen.add(key)
        if not value:
            out.append(f"line {n}: {key} has no value")
        elif value[0] in "\"'":
            if len(value) < 2 or value[-1] != value[0]:
                out.append(f"line {n}: {key}: the quote is not closed")
        elif value.startswith(_INDICATORS) or ": " in value or " #" in value or value.endswith(":"):
            out.append(f"line {n}: {key}: quote this value (it starts with a YAML indicator or holds ': ' or ' #')")
    return out


def yaml_problems(block: str) -> list[str] | None:
    """None when PyYAML is not installed; else what a YAML parse finds."""
    try:
        import yaml
    except ImportError:
        return None
    try:
        data = yaml.safe_load(block)
    except yaml.YAMLError as exc:
        return [f"YAML: {str(exc).splitlines()[0]}"]
    if not isinstance(data, dict):
        return ["YAML: the frontmatter is not a mapping"]
    # a key the client documents as a boolean must be one; every other key must be text
    return [f"YAML: {k} is read as {type(v).__name__}, not as "
            + ("a boolean" if k in BOOLEAN_KEYS else "text")
            for k, v in data.items() if not isinstance(v, bool if k in BOOLEAN_KEYS else str)]


# the frontmatter keys Claude Code reads as a boolean (disable-model-invocation: the model cannot run the command
# itself; measured with claude -p 2.1.295 in the diagnostics review, round 5)
BOOLEAN_KEYS = frozenset({"disable-model-invocation"})


def check_frontmatter(root: Path = ROOT) -> tuple[list[str], bool]:
    errors, parsed = [], False
    for path in component_files(root):
        rel = path.relative_to(root).as_posix()
        block = frontmatter(path)
        if block is None:
            errors.append(f"{rel}: no frontmatter between --- lines")
            continue
        errors += [f"{rel}: {p}" for p in line_problems(block)]
        yp = yaml_problems(block)
        if yp is not None:
            parsed = True
            errors += [f"{rel}: {p}" for p in yp]
        keys = {m.group(1) for m in (_LINE_RE.match(line) for line in block.splitlines()) if m}
        for key in REQUIRED[rel.split("/", 1)[0]]:
            if key not in keys:
                errors.append(f"{rel}: the key {key} is missing")
    return errors, parsed


def check_json(root: Path = ROOT) -> list[str]:
    errors = []
    for rel in JSON_FILES:
        try:
            json.loads((root / rel).read_text(encoding="utf-8"))
        except FileNotFoundError:
            errors.append(f"{rel}: missing")
        except ValueError as exc:
            errors.append(f"{rel}: not valid JSON: {exc}")
    return errors


# the events hooks/hooks.json may name: a client rejects or skips an event it does not know, and a rejected manifest
# loads no hook at all (Claude Code 2.1.223 and userConfig). This check ran only in the CI job `manifests` before,
# and a new event first failed there (2026-10-07)
# SessionEnd: Claude Code has it; Codex since openai/codex#33895 (2026-07-17), older than each Codex maisecrets
# supports
HOOK_EVENTS = {"UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionStart", "SessionEnd",
               "Setup"}


def check_hook_paths(root: Path = ROOT) -> list[str]:
    errors = []
    try:
        hooks = json.loads((root / "hooks/hooks.json").read_text(encoding="utf-8"))["hooks"]
    except (OSError, ValueError, KeyError):
        return ["hooks/hooks.json: cannot read its hooks"]
    unknown = sorted(set(hooks) - HOOK_EVENTS)
    if unknown:
        errors.append(f"hooks/hooks.json: events {unknown} are not in HOOK_EVENTS; add one there only after a client "
                      "that does not know it was measured to still load the others (PostToolUseFailure: codex-cli "
                      "0.159.2)")
    for event, groups in hooks.items():
        for group in groups:
            for h in group.get("hooks", []):
                for field in ("command", "commandWindows"):
                    for ref in re.findall(r"\$\{CLAUDE_PLUGIN_ROOT\}/([^\"\s]+)", h.get(field, "")):
                        if not (root / ref).is_file():
                            errors.append(f"hooks/hooks.json: {event} {field} names {ref}, which does not exist")
    return errors


def dispatcher_names(root: Path = ROOT) -> tuple[set[str], set[str]]:
    """(names dispatch.py handles itself, names it passes to the CLI), read from its source."""
    src = (root / "hooks/dispatch.py").read_text(encoding="utf-8")
    own = set(re.findall(r'sys\.argv\[1\] == "([a-z][a-z-]*)"', src))
    m = re.search(r"sys\.argv\[1\] in \(([^)]*)\)", src)
    to_cli = set(re.findall(r'"([a-z][a-z-]*)"', m.group(1))) if m else set()
    return own, to_cli


def check_cli_commands(root: Path = ROOT) -> list[str]:
    """A command file's `run.sh X` works only when dispatch.py handles X or passes it to the CLI,
    and the CLI has X; any other name would run as a hook event."""
    sys.path.insert(0, str(root))
    try:
        from maisecrets.cli import COMMANDS
    finally:
        sys.path.pop(0)
    own, to_cli = dispatcher_names(root)
    errors = [f"hooks/dispatch.py passes {n} to the CLI, which has no such command"
              for n in sorted(to_cli - set(COMMANDS))]
    for path in sorted(root.glob("commands/*.md")):
        for sub in re.findall(r'hooks/run\.sh"\s+([a-z][a-z-]*)', path.read_text(encoding="utf-8")):
            if sub not in own and sub not in to_cli:
                errors.append(f"{path.relative_to(root).as_posix()}: run.sh {sub} is neither handled by dispatch.py "
                              "nor passed to the CLI")
    return errors


def check_mod(root: Path = ROOT) -> list[str]:
    """The mod: the manifest names the mod's hooks file, its module exists, and each launcher command the module asks
    is one dispatch.py handles, for each of the three Python names. Otherwise the mod gets no answer and every prompt
    is blocked again, which no test of the hook alone would notice."""
    errors = []
    try:
        named = json.loads((root / ".claude-plugin/plugin.json").read_text(encoding="utf-8")).get("hooks")
        modules = json.loads((root / "claude-mod/maisecrets-mod.json").read_text(encoding="utf-8")).get("modules") or []
    except (OSError, ValueError):
        return ["claude-mod/maisecrets-mod.json or .claude-plugin/plugin.json cannot be read"]
    if named != "./claude-mod/maisecrets-mod.json":
        errors.append(f'.claude-plugin/plugin.json: "hooks" is {named!r}, not "./claude-mod/maisecrets-mod.json"')
    for module in modules:
        path = root / "claude-mod" / module
        if not path.is_file():
            errors.append(f"claude-mod/maisecrets-mod.json names {module}, which does not exist")
            continue
        text = path.read_text(encoding="utf-8")
        # the command lines are fixed text (the directory reads them): the three Python names, one command each
        calls = {argv: set(re.findall(argv + r", 'hooks/dispatch\.py', '([a-z][a-z-]*)'\]", text))
                 for argv in (r"\['python3'", r"\['py', '-3'", r"\['python'")}
        cmds = set().union(*calls.values())
        if not cmds or any(c != cmds for c in calls.values()) or not cmds <= dispatcher_names(root)[0]:
            errors.append(f"claude-mod/{module}: its commands {sorted(cmds) or '(none)'} are not commands that "
                          "hooks/dispatch.py handles, each for all of python3, py -3 and python")
    return errors


def main() -> int:
    fm, parsed = check_frontmatter()
    errors = fm + check_json() + check_hook_paths() + check_cli_commands() + check_mod()
    for e in errors:
        print(f"lint_plugin: {e}")
    n = len(component_files())
    how = "strict line check and YAML parse" if parsed else "strict line check (PyYAML not installed)"
    print(f"lint_plugin: {n} component files ({how}), {len(JSON_FILES)} JSON files: "
          + ("ok" if not errors else f"{len(errors)} error(s)"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
