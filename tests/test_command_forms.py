"""Every slash command names a bash form and a PowerShell form.

The ChatGPT desktop client on Windows ran `/maisecrets:status` in PowerShell, which has no bash (2026-09-30).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class CommandFormTests(unittest.TestCase):
    def test_every_command_has_a_powershell_form(self):
        for f in sorted((ROOT / "commands").glob("*.md")):
            s = f.read_text(encoding="utf-8")
            if "!`bash" in s:
                continue   # send.md: Claude Code expands !` itself, before the model sees the text
            with self.subTest(command=f.name):
                sub = re.search(r'hooks/run\.sh" (\w+)', s).group(1)
                self.assertIn(f'& "${{CLAUDE_PLUGIN_ROOT}}/hooks/run.cmd" {sub}', s)
                self.assertIn(f'PowerShell(& "${{CLAUDE_PLUGIN_ROOT}}/hooks/run.cmd" {sub}', s)
                # the Codex sandbox on Windows runs the command as another user (measured 2026-09-30)
                self.assertIn("outside the sandbox, with escalated permissions", s)
                if "--args-stdin" in s:
                    # a single-quoted here-string, so PowerShell expands nothing in the arguments
                    self.assertRegex(s, r"@'\n\$ARGUMENTS\n'@ \| & ")


class ArgsStdinFormTests(unittest.TestCase):
    """The bash form of each command file that passes its arguments on stdin is a call the PreToolUse hook lets
    run: sref was missing from the list of the hook, and /maisecrets:sref status was refused (0.8.22)."""

    def test_each_args_stdin_command_passes_the_hook(self):
        import sys
        sys.path.insert(0, str(ROOT))
        from maisecrets import hooks
        names = []
        form = re.compile(r"```\n(bash \"\$\{CLAUDE_PLUGIN_ROOT\}/hooks/run\.sh\" [^\n]*--args-stdin.*?)```", re.S)
        for f in sorted((ROOT / "commands").glob("*.md")):
            block = form.search(f.read_text(encoding="utf-8"))
            if not block:
                continue
            names.append(f.stem)
            for arguments in ("", "status", "two words"):
                cmd = block.group(1).replace("${CLAUDE_PLUGIN_ROOT}", "/opt/p").replace("$ARGUMENTS", arguments)
                with self.subTest(command=f.name, arguments=arguments):
                    self.assertIsNone(hooks._args_call_refusal(cmd.rstrip("\n")))
        self.assertIn("sref", names)        # the population: every command of this form, sref among them
        self.assertGreaterEqual(len(names), 8)

    def test_a_delimiter_line_in_the_arguments_names_its_cause(self):
        import sys
        sys.path.insert(0, str(ROOT))
        from maisecrets import hooks
        end = "MAISECRETS_ARGS_END"
        head = "bash \"/opt/p/hooks/run.sh\" sref --args-stdin <<'" + end + "'\n"
        self.assertIn("must not contain a line", hooks._args_call_refusal(head + end + "\nx\n" + end))
        self.assertIn("exactly the form", hooks._args_call_refusal("bash \"/opt/p/hooks/run.sh\" nope --args-stdin"))


def _powershell_block(name: str) -> str:
    text = (ROOT / "commands" / name).read_text(encoding="utf-8")
    return re.search(r"run this instead:\n\n```\n(.*?)```", text, re.S).group(1)


class PowerShellFormRunTests(unittest.TestCase):
    """The PowerShell form of a command runs in a real PowerShell (the GitHub Windows runner has it)."""

    def setUp(self):
        self.shell = shutil.which("pwsh") or (shutil.which("powershell") if os.name == "nt" else None)
        if not self.shell:
            self.skipTest("pwsh is not installed")
        if os.name != "nt":
            self.skipTest("cmd.exe runs on Windows only; run.cmd needs it")
        self.home = tempfile.mkdtemp(prefix="maisecrets-ps-home-")
        Path(self.home, "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
        self.addCleanup(shutil.rmtree, self.home, True)

    def run_block(self, name: str, arguments: str = "") -> subprocess.CompletedProcess:
        script = _powershell_block(name).replace("$ARGUMENTS", arguments)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
        env.update(MAISECRETS_HOME=self.home, CLAUDE_PLUGIN_ROOT=str(ROOT))
        script = script.replace("${CLAUDE_PLUGIN_ROOT}", str(ROOT))
        return subprocess.run([self.shell, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", env=env, timeout=120)

    def test_status_runs(self):
        r = self.run_block("status.md")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("maisecrets", r.stdout)

    def test_the_arguments_reach_the_plugin_as_they_are(self):
        # a single-quoted here-string: PowerShell expands neither $env: nor a backtick in the arguments
        r = self.run_block("forget.md", "no$env:PATH`x")
        self.assertIn("There is no no$env ", r.stdout + r.stderr)   # unexpanded: $env stays text
        self.assertNotIn(os.environ.get("PATH", "")[:20] or "\0", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
