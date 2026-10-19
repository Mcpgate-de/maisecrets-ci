"""Invariant I3: no tool of the agent reads vault material.

Vault material is every file in the vault home (store, index, key file, logs, config) and in the
value run directory (the FIFOs a resolve serves). THREAT-MODEL C8 has the controls; this module
holds the goal over every tool that can read a file and every spelling of a path: absolute,
relative, `~`, `..`, a doubled slash, a symlink, a hardlink, another case, a parent directory
for a recursive search, a Glob pattern, a `file://` URI in an MCP argument, and Bash with the
configured home.

Bash is a text match (C8 calls it a backstop, not a boundary): a command that builds the path
at run time is out of scope, and so is a program the command starts. What is in scope is a
command that names the path the way a person or a model writes it.

The tool population is written out below. A tool the matcher in hooks/hooks.json does not
reach never meets a guard, so each tool that reads a path must be in the matcher, and each tool
left out must say why.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

CLIENTS = {"claude": CLAUDE, "codex": {**CODEX, "model": "m"}}

# The tool population comes from tests/client_tools.json, which the harness checks against the tool
# list of the real client on every run: a tool the client adds and nobody classified fails there, so
# this module no longer depends on a list written by hand. Codex: its shell arrives as Bash; its file
# edits arrive as apply_patch, whose headers name the paths (tests/client_payloads/codex-apply-patch.json).
INVENTORY = json.loads((ROOT / "tests" / "client_tools.json").read_text(encoding="utf-8"))
_CLAUDE_TOOLS = INVENTORY["claude-code"]["tools"]
READERS = {name: t["field"] for name, t in _CLAUDE_TOOLS.items() if t["class"] in ("reads-path", "edits-path")}
RESOURCE_READERS = {name: t["field"] for name, t in _CLAUDE_TOOLS.items() if t["class"] == "mcp-resource"}
NO_PATH = {name: t["why"] for name, t in _CLAUDE_TOOLS.items() if t["class"] == "no-path"}


def deny(out: dict) -> bool:
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision") == "deny"


def pre(tool: str, tool_input: dict, cwd: str, client: str = "claude") -> dict:
    hooks._live_cache.clear()
    return hooks.pre_tool({"tool_name": tool, "tool_input": tool_input, "session_id": "S1", "cwd": cwd,
                           "transcript_path": "", **CLIENTS[client]})


class _Store:
    """A store with real files in the vault home and a value run directory with a file in it."""

    def __init__(self) -> None:
        self.v = Vault()
        self.v.put("St" + secrets.token_hex(8), "SECRET", "manual", session="S1")
        self.home = Path(os.path.realpath(HOME))
        self.files = sorted(p for p in self.home.iterdir() if p.is_file())
        assert self.files, "the store wrote no file"
        self.run = Path(hooks._protected_dirs()[-1])
        self.run.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.fifo_like = self.run / ("v-" + secrets.token_hex(4))
        self.fifo_like.write_text("value", encoding="utf-8")
        self.outside = Path(tempfile.mkdtemp(prefix="outside-"))

    def cleanup(self) -> None:
        shutil.rmtree(self.outside, ignore_errors=True)
        try:
            self.fifo_like.unlink()
        except FileNotFoundError:
            pass


def _case_variant(path: Path) -> str | None:
    """The path with its last component in another case, if the file system does not tell them apart."""
    other = str(path.parent / path.name.swapcase())
    return other if other != str(path) and os.path.exists(other) else None


class FileToolTests(unittest.TestCase):
    def setUp(self):
        self.s = _Store()
        self.addCleanup(self.s.cleanup)

    def spellings(self) -> dict[str, tuple[str, str]]:
        """(path, cwd) per spelling of a path into the store; each must be refused."""
        s = self.s
        f = next((p for p in s.files if p.name.startswith("index")), s.files[0])
        link_dir = s.outside / "looks-harmless"
        os.symlink(s.home, link_dir)
        link_file = s.outside / "notes.txt"
        os.symlink(f, link_file)
        out = {
            "absolute": (str(f), "/"),
            "the home itself": (str(s.home), "/"),
            "trailing slash": (str(s.home) + "/", "/"),
            "doubled slash": (str(s.home) + "//" + f.name, "/"),
            "dot segment": (str(s.home) + "/./" + f.name, "/"),
            "dot-dot": (str(s.home / ".." / s.home.name / f.name), "/"),
            "relative": (os.path.join(s.home.name, f.name), str(s.home.parent)),
            "relative with dot-dot": (os.path.join("..", s.home.name, f.name), str(s.home.parent / "sub")),
            "tilde": ("~/" + s.home.name + "/" + f.name, "/"),
            "symlinked directory": (str(link_dir / f.name), "/"),
            "symlinked file": (str(link_file), "/"),
            "run directory file": (str(s.fifo_like), "/"),
        }
        try:
            hard = s.outside / "copy.json"
            os.link(f, hard)
            out["hardlink"] = (str(hard), "/")
        except OSError:
            pass                            # a file system without hard links has no such path
        variant = _case_variant(f)
        if variant:
            out["another case"] = (variant, "/")
        return out

    def test_every_reading_tool_refuses_every_spelling_of_a_store_path(self):
        spellings = self.spellings()
        bad = []
        with mock.patch.dict(os.environ, {"HOME": str(self.s.home.parent), "USERPROFILE": str(self.s.home.parent)}):
            for tool, field in READERS.items():
                for label, (path, cwd) in spellings.items():
                    tool_input = {field: path}
                    if tool in ("Edit", "MultiEdit"):
                        tool_input.update({"old_string": "a", "new_string": "b"})
                    if tool == "Write":
                        tool_input["content"] = "x"
                    if tool == "Grep":
                        tool_input["pattern"] = "."
                    if tool == "Glob":
                        tool_input["pattern"] = "*"
                    for client in CLIENTS:
                        if not deny(pre(tool, tool_input, cwd, client)):
                            bad.append(f"{tool} / {label} / {client}: {path} (cwd {cwd}) was not refused")
        self.assertEqual(bad, [], f"{len(bad)} reads:\n" + "\n".join(bad[:20]))

    def test_a_search_that_covers_the_store_is_refused(self):
        s = self.s
        parent = str(s.home.parent)
        cases = {
            "Grep over the parent": ("Grep", {"pattern": "fingerprint", "path": parent}, "/"),
            "Grep without a path in the parent": ("Grep", {"pattern": "fingerprint"}, parent),
            "Grep with a glob into the store": ("Grep", {"pattern": ".", "path": parent,
                                                         "glob": s.home.name + "/*"}, "/"),
            "Glob with the store in its pattern": ("Glob", {"pattern": str(s.home) + "/*.json"}, "/"),
            "Glob relative into the store": ("Glob", {"pattern": s.home.name + "/**", "path": parent}, "/"),
            "Grep over the run directory's parent": ("Grep", {"pattern": "v", "path": str(s.run.parent)}, "/"),
        }
        bad = [f"{label} / {client}" for label, (tool, ti, cwd) in cases.items() for client in CLIENTS
               if not deny(pre(tool, ti, cwd, client))]
        self.assertEqual(bad, [], "\n".join(bad))

    def test_an_mcp_argument_that_names_the_store_is_refused(self):
        s = self.s
        f = s.files[0]
        cases = {
            "path": {"path": str(f)},
            "nested list": {"args": {"paths": ["/tmp/a", str(f)]}},
            "tilde": {"file": "~/" + s.home.name + "/" + f.name},
            # as_uri() is `file:///C:/…` on Windows and `file:///var/…` elsewhere
            "file URI": {"uri": f.as_uri()},
            "file URI encoded": {"uri": f.as_uri().replace(".", "%2E")},
            "file URI with localhost": {"uri": "file://localhost" + f.as_uri()[len("file://"):]},
            "symlink": {"path": str(s.outside / "l")},
        }
        os.symlink(f, s.outside / "l")
        bad = []
        # `~` comes from USERPROFILE on Windows and from HOME elsewhere
        with mock.patch.dict(os.environ, {"HOME": str(s.home.parent), "USERPROFILE": str(s.home.parent)}):
            for label, ti in cases.items():
                for client in CLIENTS:
                    if not deny(pre("mcp__fs__read_file", ti, "/", client)):
                        bad.append(f"{label} / {client}: {ti}")
        self.assertEqual(bad, [], "\n".join(bad))

    def test_a_resource_read_that_names_the_store_is_refused(self):
        s = self.s
        f = s.files[0]
        bad = []
        for tool in RESOURCE_READERS:
            for uri in (f.as_uri(), "file://localhost" + f.as_uri()[len("file://"):], s.home.as_uri()):
                for client in CLIENTS:
                    if not deny(pre(tool, {"server": "fs", "uri": uri}, "/", client)):
                        bad.append(f"{tool} / {client}: {uri}")
            # a resource outside the store is no business of the guard
            if deny(pre(tool, {"server": "fs", "uri": (s.outside / "notes.txt").as_uri()}, "/")):
                bad.append(f"{tool}: a resource outside the store was refused")
        self.assertTrue(RESOURCE_READERS, "the inventory must name the resource tools")
        self.assertEqual(bad, [], "\n".join(bad))

    def test_a_path_outside_the_store_still_passes(self):
        # the guard is only worth something if it leaves the rest alone
        s = self.s
        other = s.outside / "app.log"
        other.write_text("x", encoding="utf-8")
        near = s.home.parent / (s.home.name + "-other")
        near.mkdir(exist_ok=True)
        self.addCleanup(shutil.rmtree, near, True)
        bad = []
        for tool, field in READERS.items():
            for path in (str(other), str(near), str(near / "f.json")):
                ti = {field: path, "pattern": "*", "old_string": "a", "new_string": "b", "content": "x"}
                if deny(pre(tool, ti, "/")):
                    bad.append(f"{tool}: {path}")
        self.assertEqual(bad, [], "\n".join(bad))


class BashTests(unittest.TestCase):
    """Bash names the store by its default spelling or by the configured home. The configured home
    is a directory without the word maisecrets, as a person sets it."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="bash-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / ("vh-" + secrets.token_hex(3))
        self.home.mkdir(mode=0o700)
        (self.home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

    def run_pre(self, command: str) -> dict:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX"))}
        env.update({"MAISECRETS_HOME": str(self.home), "PYTHONUTF8": "1"})
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "S1", "cwd": "/",
                   "transcript_path": "", **CLAUDE}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "pre-tool"], env=env,
                           input=json.dumps(payload), capture_output=True, encoding="utf-8", timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout) if r.stdout.strip() else {}

    def test_a_command_that_names_the_store_is_refused(self):
        h = str(self.home)
        commands = {
            "cat the default home": "cat ~/.maisecrets/vault.enc.json",
            "cat the configured home": f"cat {h}/index.json",
            "the configured home quoted": f'less "{h}/key"',
            "copy the configured home": f"cp -r {h} /tmp/x",
            "archive it": f"tar czf /tmp/a.tgz -C {self.root} {self.home.name} {h}",
            "python open": f"python3 -c \"print(open('{h}/index.json').read())\"",
            "keychain": "security find-generic-password -s maisecrets -w",
            "the delivery path": "cat /tmp/maisecrets-501/v-abc",
            "the environment variable": "cat $MAISECRETS_HOME/index.json",
            "a wildcard for the default home": "cat ~/.maisec*/index.json",
            "get through the launcher": 'bash "$CLAUDE_PLUGIN_ROOT/hooks/run.sh" ' + "get" + " SECRET_c1",
            "get through dispatch": "python3 $CLAUDE_PLUGIN_ROOT/hooks/dispatch.py " + "get" + " SECRET_c1",
        }
        bad = [label for label, c in commands.items() if not deny(self.run_pre(c))]
        self.assertEqual(bad, [], "\n".join(bad))

    def test_a_command_near_the_store_still_runs(self):
        h = str(self.home)
        for c in (f"ls {self.root}", f"cat {h}-other/notes.txt", "echo maisecrets is installed", "ls ~/.m*.txt",
                  "ls ~/.config/*.json"):
            with self.subTest(c):
                self.assertFalse(deny(self.run_pre(c)), c)


REF = "\u27e6SECRET_c1\u27e7"      # a placeholder, escaped: the live plugin of a session resolves the literal


class PowerShellTests(BashTests):
    """PowerShell, the shell tool of Claude Code on Windows without Git Bash: the Bash backstop, and a
    Windows path matches in any case and with either slash."""

    def run_pre(self, command: str) -> dict:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX"))}
        env.update({"MAISECRETS_HOME": str(self.home), "PYTHONUTF8": "1"})
        payload = {"tool_name": "PowerShell", "tool_input": {"command": command}, "session_id": "S1", "cwd": "/",
                   "transcript_path": "", **CLAUDE}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "pre-tool"], env=env,
                           input=json.dumps(payload), capture_output=True, encoding="utf-8", timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout) if r.stdout.strip() else {}

    def test_a_windows_spelling_of_the_store_is_refused(self):
        h = str(self.home)
        commands = {
            "Get-Content the default home": r"Get-Content $env:USERPROFILE\.maisecrets\vault.enc.json",
            "the configured home with backslashes": "Get-Content " + h.replace("/", "\\") + "\\index.json",
            "the configured home in upper case": "type " + h.upper() + "/index.json",
            "the file name in upper case": r"gc C:\Users\x\.MAISECRETS\VAULT.ENC.JSON",
            "the environment variable": r"Get-ChildItem $env:MAISECRETS_HOME",
            "the guard script": r"python $env:USERPROFILE\.claude\maisecrets-guard.py --off",
            "the session id": "$env:CLAUDE_CODE_SESSION_ID = 'other'",
            "a trailing dot on the home": "Get-Content " + h.replace("/", "\\") + ".\\index.json",
            "the 8.3 name of the default home": r"type C:\Users\x\MAISEC~1\vault.json",
            "a wildcard for the default home": r"Get-Content $HOME\.maisec*\index.json",
            "every credential of the Locker": "$v = New-Object Windows.Security.Credentials.PasswordVault; "
                                              "$v.RetrieveAll()",
            "get through the Windows launcher": "& $env:CLAUDE_PLUGIN_ROOT\\hooks\\run.cmd " + "get" + " SECRET_c1",
        }
        bad = [label for label, c in commands.items() if not deny(self.run_pre(c))]
        self.assertEqual(bad, [], "\n".join(bad))

    def test_a_placeholder_gets_no_value(self):
        out = self.run_pre("Write-Output " + REF)
        self.assertTrue(deny(out), out)
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn(REF, reason)
        self.assertIn("PowerShell", reason)
        self.assertNotIn("updatedInput", out["hookSpecificOutput"])
        self.assertEqual(self.run_pre("Get-ChildItem C:\\work"), {}, "a command without a placeholder runs as it is")


class PopulationTests(unittest.TestCase):
    def test_every_shell_tool_meets_the_store_backstop(self):
        # a shell tool the hook code does not handle by name passes every command (PowerShell on Windows
        # without Git Bash reached no guard in 0.5.11: measured on a hosted Windows runner, 2026-09-29)
        shells = [name for name, t in _CLAUDE_TOOLS.items() if t["class"] == "shell"]
        self.assertIn("PowerShell", shells)
        for tool in shells:
            for cmd in ("cat ~/.maisecrets/vault.enc.json", "cat $MAISECRETS_HOME/index.json"):
                with self.subTest(tool=tool, cmd=cmd):
                    self.assertTrue(deny(pre(tool, {"command": cmd}, "/tmp")), f"{tool}: {cmd}")

    def test_every_tool_that_reads_a_path_is_in_the_matcher(self):
        hooks_json = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        matchers = [m.get("matcher", "") for m in hooks_json["hooks"]["PreToolUse"]]
        guarded = [name for name, t in _CLAUDE_TOOLS.items() if t["class"] not in ("no-path",)]
        missing = [t for t in guarded + ["mcp__fs__read_file"] if not any(re.fullmatch(m, t) for m in matchers)]
        self.assertEqual(missing, [], "a tool the matcher does not reach meets no guard")
        classes = {t["class"] for t in _CLAUDE_TOOLS.values()}
        self.assertEqual(classes - {"reads-path", "edits-path", "shell", "mcp-resource", "no-path"}, set())
        self.assertTrue(all(t.get("why") for t in _CLAUDE_TOOLS.values() if t["class"] == "no-path"),
                        "a tool without a guard must say why it needs none")

    def test_every_codex_tool_with_a_path_is_in_the_matcher_by_its_own_name(self):
        # Codex 0.163.0-alpha on Windows (field report, 2026-10-19): apply_patch inside functions.exec reached no
        # PreToolUse hook. The Mac build maps it to the aliases Write and Edit, which the matcher names; that build
        # did not, so a placeholder went into the file unchecked. The matcher must name the tool itself
        hooks_json = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        matchers = [m.get("matcher", "") for m in hooks_json["hooks"]["PreToolUse"]]
        codex_tools = INVENTORY["codex"]["tools"]
        with_path = sorted(n for n, t in codex_tools.items() if t["class"] in ("edits-path", "reads-path"))
        self.assertIn("apply_patch", with_path)
        missing = [t for t in with_path if not any(re.fullmatch(m, t) for m in matchers)]
        self.assertEqual(missing, [],
                         "a Codex tool reached only through an alias meets no guard where the alias is missing")

    def test_a_codex_patch_never_touches_the_store(self):
        codex_tools = INVENTORY["codex"]["tools"]
        edits = sorted(n for n, t in codex_tools.items() if t["class"] == "edits-path")
        self.assertEqual(edits, ["apply_patch"], "a Codex tool that edits a path needs its own case here")
        home = str(HOME)
        for header in ("Add File", "Update File", "Delete File"):
            spellings = [home + "/config.json", home + "/../" + Path(home).name + "/x", "~/.maisecrets/config.json"]
            if __import__("platform").system() in ("Darwin", "Windows"):   # case-insensitive file systems
                spellings.append(home.upper() + "/config.json")
            for path in spellings:
                patch = f"*** Begin Patch\n*** {header}: {path}\n+x\n*** End Patch"
                with self.subTest(header=header, path=path):
                    self.assertTrue(deny(pre("apply_patch", {"command": patch}, "/tmp", "codex")), patch)
        # indented headers: codex-cli 0.158.0 trims them and applies the patch (review, 2026-09-29)
        # and every other whitespace Codex trims (NBSP, \f, \v, \r, U+2003, U+3000: measured by review round 2)
        for indent in (" ", "\t", "   ", "\u00a0", "\x0c", "\x0b", "\r", "\u2003", "\u3000", "\x85", "\u2028"):
            patch = f"*** Begin Patch\n{indent}*** Add File: {home}/config.json\n+x\n*** End Patch"
            with self.subTest(indent=repr(indent)):
                self.assertTrue(deny(pre("apply_patch", {"command": patch}, "/tmp", "codex")), patch)
        # the heredoc form Codex also applies is a patch like any other
        heredoc = f"<<'EOF'\n*** Begin Patch\n*** Add File: {home}/config.json\n+x\n*** End Patch\nEOF"
        self.assertTrue(deny(pre("apply_patch", {"command": heredoc}, "/tmp", "codex")))
        beside_heredoc = "<<'EOF'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n*** End Patch\nEOF"
        self.assertFalse(deny(pre("apply_patch", {"command": beside_heredoc}, "/tmp", "codex")),
                         "a heredoc patch next to the store is a normal edit")
        # nor rewrite the guard script with a file tool
        guard_script = os.path.join(os.environ["CLAUDE_CONFIG_DIR"], "maisecrets-guard.py")
        for tool, ti in (("Write", {"file_path": guard_script, "content": "print('{}')"}),
                         ("Edit", {"file_path": guard_script, "old_string": "a", "new_string": "b"})):
            with self.subTest(tool=tool):
                self.assertTrue(deny(pre(tool, ti, "/tmp")), tool)
        patch = f"*** Begin Patch\n*** Update File: {guard_script}\n@@\n-a\n+b\n*** End Patch"
        self.assertTrue(deny(pre("apply_patch", {"command": patch}, "/tmp", "codex")))
        # the agent cannot switch the guard off: its --off is for the person at a terminal
        for cmd in ("python3 ~/.claude/maisecrets-guard.py --off", "cat ~/.maisecrets/guard.json"):
            with self.subTest(cmd=cmd):
                self.assertTrue(deny(pre("Bash", {"command": cmd}, "/tmp")), cmd)
        guard_cmd = "python3 ~/.claude/" + "maisecrets-guard.py --off"
        reason = pre("Bash", {"command": guard_cmd}, "/tmp")["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("the maisecrets guard", reason)
        self.assertNotIn("own store", reason, "the guard is not the store (seen in a live session, 2026-09-29)")
        # no patch text: nothing names the paths, so nothing is resolved or allowed
        for ti in ({}, {"patch": f"*** Begin Patch\n*** Add File: {home}/x\n+x\n*** End Patch"}, {"command": 5}):
            with self.subTest(tool_input=str(ti)[:40]):
                self.assertTrue(deny(pre("apply_patch", ti, "/tmp", "codex")))
        # a move into the store is a write into it
        moved = f"*** Begin Patch\n*** Update File: a.txt\n*** Move to: {home}/a.txt\n@@\n-x\n+y\n*** End Patch"
        self.assertTrue(deny(pre("apply_patch", {"command": moved}, "/tmp", "codex")))
        # the other side: a patch next to the store passes
        beside = "*** Begin Patch\n*** Add File: " + home + "-other/notes.txt\n+x\n*** End Patch"
        self.assertFalse(deny(pre("apply_patch", {"command": beside}, "/tmp", "codex")))

    def test_the_hook_code_knows_no_reading_tool_this_module_does_not(self):
        # a tool name the hook code handles by name is a tool that reads or writes: it must be here
        named = set(hooks._READ_TOOLS) | set(hooks._FILE_TOOLS) | set(hooks._MCP_RESOURCE_TOOLS)
        self.assertEqual(named - set(READERS) - set(RESOURCE_READERS), set(),
                         "a tool the hooks handle is missing from tests/client_tools.json")


if __name__ == "__main__":
    unittest.main()
