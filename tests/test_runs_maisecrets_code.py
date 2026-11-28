"""#98: a shell command that imports a module of maisecrets is refused.

The Bash guard knew only the hook entries (run.sh, dispatch.py with an event). `python3 -c "from maisecrets import
vault_refs; …"` passed, and so did a heredoc into Python and a script file that imports the hub. Such code can bind a
connector or reach what only the person's typed commands start. The check is a text match in import positions
(C22: a backstop for the forms an agent writes); the library `maisecrets.detection` and the CLI stay allowed.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks, shell_commands  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402


def decision(command: str, cwd: str, client: dict = CLAUDE, tool: str = "Bash") -> str:
    hooks._live_cache.clear()
    out = hooks.pre_tool({"tool_name": tool, "tool_input": {"command": command}, "session_id": "S1", "cwd": cwd,
                          "transcript_path": "", **client})
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision") or "pass"


class RunsMaisecretsCodeTests(unittest.TestCase):
    def setUp(self):
        self.cwd = tempfile.mkdtemp(prefix="ms98-")
        Path(self.cwd, "binds.py").write_text(
            "import os\nfrom maisecrets import (\n    detection,\n    vault_refs,\n)\n")
        Path(self.cwd, "detects.py").write_text("from maisecrets.detection import Detector\nimport maisecrets\n")

    def test_python_code_in_the_command_that_imports_maisecrets_is_refused(self):
        for cmd in ('python3 -c "from maisecrets import vault_refs; vault_refs.bind_connector(1)"',
                    "python3 -c 'import maisecrets.vault as v'",
                    "python3 -c 'import os, maisecrets.hub'",
                    'python3 -c "from maisecrets.sref_hooks import pair_connector"',
                    "python3 -c 'from maisecrets import detection, vault_refs'",
                    "python3 -m maisecrets.hub",
                    "python3 -c \"import importlib; importlib.import_module('maisecrets.vault')\"",
                    "python3 - <<'EOF'\nfrom maisecrets import hub\nEOF",
                    "echo 'from maisecrets import vault' | python3",
                    "cd /tmp && uv run python -c 'from maisecrets import vault_refs'",
                    # Gate A of #98: the CLI imported hands over its Vault; keyword and sys.modules forms
                    "python3 -c 'from maisecrets import cli; print(cli.Vault)'",
                    "python3 -c 'import maisecrets.cli as c'",
                    "python3 -c 'import importlib; importlib.import_module(name=\"maisecrets.hub\")'",
                    "python3 -c 'import runpy; runpy.run_module(mod_name=\"maisecrets.hub\")'",
                    "python3 -c 'import sys; sys.modules[\"maisecrets.vault\"]'",
                    # Gate B of #98: literal names in other forms, and a backslash continuation
                    "python3 -c '__import__(\"maisecrets\", fromlist=[\"hub\"])'",
                    "python3 -c 'import importlib; importlib.import_module(\".hub\", \"maisecrets\")'",
                    "python3 -c 'import importlib; importlib.import_module(\".hub\", package=\"maisecrets\")'",
                    "python3 - <<'EOF'\nfrom maisecrets import \\\n    hub\nEOF"):
            with self.subTest(cmd=cmd):
                self.assertEqual(decision(cmd, self.cwd), "deny")
                self.assertEqual(decision(cmd, self.cwd, CODEX), "deny")

    def test_a_script_run_by_path_that_imports_maisecrets_is_refused(self):
        other = tempfile.mkdtemp(prefix="ms98-other-")
        Path(other, "run.py").write_text("from maisecrets.hub import mod_answer\n")
        Path(self.cwd, "run.py").write_text("print(1)\n")        # the file of the same name where the hook starts
        for cmd in ("python3 binds.py", f"python3 {self.cwd}/binds.py", "uv run binds.py", "uv run python binds.py",
                    "python3 -u -W ignore binds.py --x", "python3 -m pytest binds.py", "pytest -q binds.py",
                    "SCRIPT=binds.py; python3 \"$SCRIPT\"", "export S=binds.py && python3 ${S}",
                    f"cd {other} && python3 run.py", f"cd {other}; python3 ./run.py",
                    # Gate B of #98: a local module by -m, code on Python's input, flag clusters, option values
                    "python3 -m binds", "python3 -Im binds", "python3 -m unittest binds", "poetry run python -m binds",
                    "python3 < binds.py", "python3 - < binds.py", "cat binds.py | python3",
                    "python3 -Im pytest binds.py", "uv run --with requests binds.py",
                    "python3 --check-hash-based-pycs never binds.py", "python3 -X dev -W ignore binds.py"):
            with self.subTest(cmd=cmd):
                self.assertEqual(decision(cmd, self.cwd), "deny")
        out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "python3 binds.py"}, "session_id": "S1",
                              "cwd": self.cwd, "transcript_path": "", **CLAUDE})
        self.assertIn("maisecrets.vault_refs in binds.py", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_the_library_the_cli_and_mentions_pass(self):
        for cmd in ("python3 -c 'from maisecrets.detection import Detector; print(1)'",
                    "python3 -c 'import maisecrets; print(maisecrets.__version__)'",
                    "python3 -c 'from maisecrets.detect import findings'",
                    "python3 -m maisecrets.detection < in.json",
                    "python3 -m maisecrets.cli status",
                    "python3 detects.py",
                    "python3 -m unittest tests.test_guard",
                    "grep -rn 'from maisecrets import vault' src/",
                    "git commit -m 'refuse from maisecrets import vault_refs'",
                    "curl -d '{\"contract\": \"maisecrets.detect/1\"}' https://gw.example/detect",
                    "curl https://maisecrets.dev/x",
                    "cat maisecrets.log",
                    "pip show maisecrets",
                    "python3 missing.py",
                    "python3 run.py --output binds.py",            # an argument of the script is no script
                    "python3 -m maisecrets.cli status",
                    "python3 -c 'print(1)' binds.py",
                    "python3 \"$UNSET_98\"",
                    # Gate B of #98: searches of the import text in a checkout run
                    "rg 'import maisecrets.hooks' maisecrets",
                    "git grep -n 'from maisecrets import hub'",
                    "git log -S 'from maisecrets import vault_refs'",
                    "ls maisecrets  # from maisecrets import hub",
                    "python3 -m detects",
                    "cat detects.py | python3"):
            with self.subTest(cmd=cmd):
                self.assertEqual(decision(cmd, self.cwd), "pass")

    def test_a_script_of_a_maisecrets_checkout_passes(self):
        # the repository's own scripts and the plugin folder import maisecrets by design
        self.assertTrue(shell_commands._a_checkout(str(ROOT / "scripts" / "derived_counts.py")))
        self.assertEqual(decision(f"python3 {ROOT}/skills/secret-hygiene/scripts/audit_transcripts.py --help",
                                  self.cwd), "pass")
        self.assertFalse(shell_commands._a_checkout(os.path.join(self.cwd, "binds.py")))

    def test_a_search_that_runs_a_program_is_no_mention(self):
        for cmd in ("git -c alias.grep='!python3 -c \"from maisecrets import hub\"' grep x",
                    "rg 'from maisecrets import hub' . | python3",
                    "grep -h 'from maisecrets import hub' notes.txt > x.py && python3 x.py"):
            with self.subTest(cmd=cmd):
                self.assertEqual(decision(cmd, self.cwd), "deny")

    def test_the_unpacked_secret_hygiene_skill_runs_its_scripts(self):
        # the skill zip ships a copy of the detector, not hooks.py; its audit script imports the store
        skill = Path(tempfile.mkdtemp(prefix="ms98-skill-")) / "secret-hygiene"
        (skill / "scripts").mkdir(parents=True)
        (skill / "maisecrets" / "detection").mkdir(parents=True)
        (skill / "maisecrets" / "detection" / "core.py").write_text("")
        (skill / "scripts" / "audit_transcripts.py").write_text("from maisecrets import vault\n")
        self.assertEqual(decision("python3 scripts/audit_transcripts.py --estimate", str(skill)), "pass")

    def test_powershell_refuses_the_import_too(self):
        self.assertEqual(decision("python -c 'from maisecrets import vault_refs'", self.cwd, tool="PowerShell"), "deny")
        self.assertEqual(decision("python -c 'from maisecrets.detection import Detector'", self.cwd,
                                  tool="PowerShell"), "pass")

    def test_only_real_modules_outside_the_allowed_ones_count(self):
        self.assertEqual(shell_commands.imported_modules("from maisecrets import Detector, vault, nosuch"), ["vault"])
        self.assertEqual(shell_commands.imported_modules("import maisecrets.detection.core as c"), [])
        self.assertIn("vault_refs", shell_commands._package_modules())
        self.assertIn("detection", shell_commands._package_modules())


if __name__ == "__main__":
    unittest.main()
