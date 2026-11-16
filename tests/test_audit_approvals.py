"""audit_approvals.py: the approvals and settings that Claude Code and Codex keep outside the repository (#56).

Each test builds a temp home for both clients (HOME, CLAUDE_CONFIG_DIR, CODEX_HOME), puts a token that is made at
run time into one file, and runs the script as the skill tells the model to. Every run writes the full report to a
file, and `audit` checks stdout, stderr and that file: no run of 8 characters of any secret of the test may appear
in them (Gate A round 2: a check of the whole token missed a token printed in pieces)."""
from __future__ import annotations

import importlib.util
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
SCRIPT = ROOT / "skills" / "secret-hygiene" / "scripts" / "audit_approvals.py"
ALNUM = string.ascii_letters + string.digits


def _rnd(n: int) -> str:
    """n random letters and digits, with at least one digit and one letter."""
    while True:
        s = "".join(secrets.choice(ALNUM) for _ in range(n))
        if any(c.isdigit() for c in s) and any(c.isalpha() for c in s):
            return s


def _letters(n: int) -> str:
    return "".join(secrets.choice(string.ascii_letters) for _ in range(n))


def _digits(n: int) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))


def _token() -> str:
    return "gh" + "p_" + _rnd(36)


def _module():
    spec = importlib.util.spec_from_file_location("audit_approvals_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Run:
    def __init__(self, r: subprocess.CompletedProcess, report: str) -> None:
        self.rc, self.stdout, self.stderr, self.report = r.returncode, r.stdout, r.stderr, report
        self.text = r.stdout + r.stderr + report

    def rows(self) -> list[str]:
        return [line for line in self.report.splitlines() if line.startswith("  S")]


class ApprovalAuditTests(unittest.TestCase):
    def setUp(self):
        # a fixed folder name that is not a plain name: the temp folders always print as <claude config> and
        # <codex home>, whatever name mkdtemp chose
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-approvals-")) / "run7x8y9z"
        self.home = self.dir / "home"
        self.claude = self.dir / "claude-config"
        self.codex = self.dir / "codex-home"
        for d in (self.home, self.claude, self.codex):
            d.mkdir(parents=True)
        self.token = _token()
        self.secrets = [self.token]      # every string no output may hold 8 characters of
        self.runs = 0
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "CLAUDE_", "CODEX_"))}
        self.env.update(PYTHONUTF8="1", HOME=str(self.home), USERPROFILE=str(self.home),
                        CLAUDE_CONFIG_DIR=str(self.claude), CODEX_HOME=str(self.codex))

    def tearDown(self):
        shutil.rmtree(self.dir.parent, ignore_errors=True)

    # -- helpers --------------------------------------------------------------------------------------------
    def write_json(self, path: Path, doc) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return path

    def assert_no_run_of_a_secret(self, text: str) -> None:
        for s in self.secrets:
            for i in range(len(s) - 7):
                self.assertNotIn(s[i:i + 8], text, f"8 characters of a secret (at {i}) are in the output")

    def audit(self, *args, env=None, out: bool = True, cwd=None) -> Run:
        """Run the script; with ``out`` the full report goes to a file of the test. stdout, stderr and the report
        are checked for every secret of the test, in each run."""
        self.runs += 1
        report = self.dir / f"report-{self.runs}.txt"
        extra = ["--out", str(report)] if out else []
        r = subprocess.run([sys.executable, str(SCRIPT), *args, *extra], capture_output=True, text=True,
                           encoding="utf-8", env=env or self.env, timeout=120, cwd=cwd)
        run = Run(r, report.read_text(encoding="utf-8") if report.exists() else "")
        self.assert_no_run_of_a_secret(run.text)
        self.assertNotIn("Traceback", run.stderr)
        return run

    def assert_found(self, run: Run, label: str, place: str, fix: str = "remove this approval entry",
                     rule: str = "github-pat") -> None:
        self.assertEqual(run.rc, 1, run.text)
        rows = [line for line in run.rows() if f" {label}  " in line and place in line]
        self.assertEqual(len(rows), 1, run.report)
        self.assertIn(rule, rows[0])
        self.assertIn("len 40", rows[0])
        self.assertIn(fix, run.report)
        self.assertIn("references/rotation.md", run.report)

    def approve(self) -> str:
        return f"Bash(gh auth login --with-token {self.token})"

    # -- (a) a user-level Claude Code permission rule ----------------------------------------------------------
    def test_a_user_level_claude_permission_rule_is_found_and_not_shown(self):
        self.write_json(self.claude / "settings.json",
                        {"permissions": {"allow": ["Bash(ls:*)", "Read", self.approve()]}})
        self.assert_found(self.audit(), "<claude config>/settings.json", "permissions.allow[2]")

    def test_the_user_level_local_settings_are_read_too(self):
        self.write_json(self.claude / "settings.local.json", {"permissions": {"ask": [self.approve()]}})
        self.assert_found(self.audit(), "<claude config>/settings.local.json", "permissions.ask[0]")

    def test_a_value_in_a_setting_gets_the_setting_fix(self):
        self.write_json(self.claude / "settings.json", {"env": {"GH_TOKEN": self.token}})
        self.assert_found(self.audit(), "<claude config>/settings.json", "env.[key 1]",
                          fix="take the value out of this setting")

    # -- (b) a project allowedTools entry in the client config --------------------------------------------------
    def test_a_project_allowed_tools_entry_in_the_client_config_is_found_and_not_shown(self):
        folder = "/srv/" + _rnd(40)                  # a folder name is never printed
        self.secrets.append(folder[5:])
        self.write_json(self.claude / ".claude.json", {
            "oauthAccount": {"emailAddress": "someone@example.test"},
            "projects": {folder: {"allowedTools": ["Read", self.approve()]}}})
        run = self.audit()
        self.assert_found(run, "<claude config>/.claude.json", "projects[<project 1>].allowedTools[1]")
        self.assertIn("project 1 (from <claude config>/.claude.json)", run.report)

    def test_without_claude_config_dir_the_client_config_is_in_the_home(self):
        env = dict(self.env)
        del env["CLAUDE_CONFIG_DIR"]
        self.write_json(self.home / ".claude.json", {"projects": {"/p": {"allowedTools": [self.approve()]}}})
        self.assert_found(self.audit(env=env), "~/.claude.json", ".allowedTools[0]")

    def test_the_settings_of_each_project_in_the_client_config_are_read(self):
        project = self.dir / "work" / "repo"
        self.write_json(self.claude / ".claude.json", {"projects": {str(project): {"allowedTools": []}}})
        self.write_json(project / ".claude" / "settings.local.json", {"permissions": {"allow": [self.approve()]}})
        self.assert_found(self.audit(), "<project 1>/.claude/settings.local.json", "permissions.allow[0]")

    # -- (c) a Codex prefix_rule -----------------------------------------------------------------------------------
    def test_a_codex_prefix_rule_is_found_and_not_shown(self):
        f = self.codex / "rules" / "default.rules"
        f.parent.mkdir()
        # the form Codex appends (codex-rs/execpolicy/src/amend.rs blocking_append_allow_prefix_rule)
        f.write_text('prefix_rule(pattern=["ls"], decision="allow")\n'
                     f'prefix_rule(pattern=["gh", "auth", "login", "--with-token", "{self.token}"], '
                     'decision="allow")\n', encoding="utf-8")
        self.assert_found(self.audit(), "<codex home>/rules/default.rules", "line 2", fix="remove this prefix_rule")

    def test_a_value_in_the_codex_config_names_its_table_and_key(self):
        (self.codex / "config.toml").write_text(f'model = "x"\n\n[mcp_servers.gh.env]\nGITHUB_TOKEN = "{self.token}"\n',
                                                encoding="utf-8")
        self.assert_found(self.audit(), "<codex home>/config.toml", "line 4 (mcp_servers.[key 1].env.[key 2])",
                          fix="take the value out of this setting")

    def test_the_rules_of_a_codex_project_are_read(self):
        project = self.dir / "work" / "repo"
        (self.codex / "config.toml").write_text(f'[projects."{project.as_posix()}"]\ntrust_level = "trusted"\n',
                                                encoding="utf-8")
        f = project / ".codex" / "rules" / "team.rules"
        f.parent.mkdir(parents=True)
        f.write_text(f'prefix_rule(pattern=["gh", "auth", "--with-token", "{self.token}"])\n', encoding="utf-8")
        self.assert_found(self.audit(), "<project 1>/.codex/rules/[file 1]", "line 1", fix="remove this prefix_rule")

    def test_the_config_toml_of_a_codex_project_is_read(self):
        project = self.dir / "work" / "repo"
        (self.codex / "config.toml").write_text(f'[projects."{project.as_posix()}"]\ntrust_level = "trusted"\n',
                                                encoding="utf-8")
        f = project / ".codex" / "config.toml"
        f.parent.mkdir(parents=True)
        f.write_text(f'[mcp_servers.gh.env]\nGITHUB_TOKEN = "{self.token}"\n', encoding="utf-8")
        self.assert_found(self.audit(), "<project 1>/.codex/config.toml", "line 2 (mcp_servers.[key 1].env.[key 2])",
                          fix="take the value out of this setting")

    # -- sources no test read before Gate A ----------------------------------------------------------------------
    def test_the_client_config_backups_are_read(self):
        """A backup in the client's own form (code.claude.com/docs/en/errors: .claude.json.backup.<ms>) prints by
        its kind and a number, never by its digits (Gate A round 4, F2)."""
        digits = _digits(13)
        self.secrets.append(digits)
        self.write_json(self.claude / "backups" / f".claude.json.backup.{digits}", {"projects": {"/p": {
            "allowedTools": [self.approve()]}}})
        self.assert_found(self.audit(), "<claude config>/backups/.claude.json.backup 1", ".allowedTools[0]")

    def test_the_legacy_config_json_is_read(self):
        self.write_json(self.claude / ".config.json", {"projects": {"/p": {"allowedTools": [self.approve()]}}})
        self.assert_found(self.audit(), "<claude config>/.config.json", ".allowedTools[0]")

    def test_the_custom_oauth_client_config_is_read_when_its_variable_is_set(self):
        self.write_json(self.claude / ".claude-custom-oauth.json", {"projects": {"/p": {
            "allowedTools": [self.approve()]}}})
        self.assertEqual(self.audit().rc, 0, "without the variable the client does not use it")
        env = dict(self.env, CLAUDE_CODE_CUSTOM_OAUTH_URL="https://login.example.test")
        self.assert_found(self.audit(env=env), "<claude config>/.claude-custom-oauth.json", ".allowedTools[0]")

    # -- Gate A B1: a token whose only copy is a path or a file name -----------------------------------------
    def test_a_value_in_a_project_path_and_its_allowed_tools_is_found_in_both(self):
        self.write_json(self.claude / ".claude.json", {"projects": {f"/srv/{self.token}": {"allowedTools": [
            self.approve()]}}})
        run = self.audit()
        self.assertEqual(run.rc, 1)
        self.assertIn("projects[<project 1>].allowedTools[0]", run.report)

    def test_a_token_only_in_a_claude_project_path_is_a_finding(self):
        self.write_json(self.claude / ".claude.json", {"projects": {f"/srv/{self.token}": {"allowedTools": ["Read"]}}})
        self.assert_found(self.audit(), "<claude config>/.claude.json", "<project 1> (project path)",
                          fix="a project folder name holds the credential")

    def test_a_token_only_in_a_project_path_after_a_nul_is_a_finding(self):
        self.write_json(self.claude / ".claude.json", {"projects": {f"/srv/\x00{self.token}": {}}})
        self.assert_found(self.audit(), "<claude config>/.claude.json", "<project 1> (project path)",
                          fix="a project folder name holds the credential")

    def test_a_token_only_in_a_codex_rules_file_name_is_a_finding(self):
        f = self.codex / "rules" / f"{self.token}.rules"
        f.parent.mkdir()
        f.write_text('prefix_rule(pattern=["ls"])\n', encoding="utf-8")
        self.assert_found(self.audit(), "<codex home>/rules/[file 1]", "(path)", fix="a file or folder name")

    def test_a_token_only_in_a_codex_project_path_is_a_finding(self):
        (self.codex / "config.toml").write_text(f'[projects."/srv/{self.token}"]\ntrust_level = "trusted"\n',
                                                encoding="utf-8")
        self.assertEqual(self.audit().rc, 1)

    # -- Gate A round 2, H1: a TOML escape in a Codex project header ---------------------------------------------
    def test_a_codex_project_header_with_a_toml_escape_is_decoded_found_and_read(self):
        folder = self.dir / "work" / self.token
        (folder / ".codex").mkdir(parents=True)
        (folder / ".codex" / "config.toml").write_text('model = "x"\n', encoding="utf-8")
        escaped = folder.as_posix().replace(self.token, "\\u0067" + self.token[1:])
        (self.codex / "config.toml").write_text(f'[projects."{escaped}"]\ntrust_level = "trusted"\n', encoding="utf-8")
        run = self.audit()
        self.assert_found(run, "<codex home>/config.toml", "<project 1> (project path)",
                          fix="a project folder name holds the credential")
        read = run.report.split("Files read:")[1].split("Files that do not exist:")[0]
        self.assertIn("<project 1>/.codex/config.toml (Codex project config)", read, "the decoded folder is read")

    def test_toml_basic_strings_decode_as_codex_decodes_them(self):
        mod = _module()
        self.assertEqual(mod.toml_basic(r"a\tb\u0067\U0001F600\\\"\n\x41\e"), 'a\tbg\U0001F600\\"\nA\x1b')
        self.assertEqual(mod.toml_basic(r"\uZZZZ\q"), r"\uZZZZ\q", "an invalid escape stays as it is")

    # -- Gate A round 2, H2: no name a person or a client chose is printed ------------------------------------
    def test_a_project_folder_of_random_characters_is_never_printed(self):
        folder = "/srv/" + _rnd(40)
        self.secrets.append(folder[5:])
        self.write_json(self.claude / ".claude.json", {"projects": {folder: {"allowedTools": ["Read"]}}})
        (self.codex / "config.toml").write_text(f'[projects."{folder}x"]\n', encoding="utf-8")
        run = self.audit()
        self.assertEqual(run.rc, 0, run.text)
        self.assertIn("<project 1>/.claude/settings.json", run.report)
        self.assertIn("<project 2>/.codex/config.toml", run.report)

    def test_a_token_split_by_a_slash_in_a_project_folder_is_never_printed(self):
        head, tail = "gh" + "p_" + _rnd(18), _rnd(18)
        self.secrets += [head, tail]
        self.write_json(self.claude / ".claude.json", {"projects": {f"/srv/{head}/{tail}": {}}})
        rules = self.dir / "w" / head / tail / ".codex" / "rules"
        rules.mkdir(parents=True)
        (self.codex / "config.toml").write_text(f'[projects."{rules.parent.parent.as_posix()}"]\n', encoding="utf-8")
        (rules / "a.rules").write_text("", encoding="utf-8")
        run = self.audit()
        self.assertIn("<project 2>/.codex/rules/[file 1]", run.report)

    def test_other_name_forms_from_the_review_are_never_printed(self):
        parts = [_rnd(18) for _ in range(4)]
        akia = "AK" + "IA" + "".join(secrets.choice(string.ascii_uppercase + "234567") for _ in range(16))
        self.secrets += parts + [akia]
        self.write_json(self.claude / ".claude.json", {"projects": {
            f"/a/gh%5F{parts[0]}{parts[1]}": {}, f"/b/gh{chr(10)}p_{parts[0]}": {}, f"/c/ghp_\x01{parts[1]}": {},
            f"/d/{akia}X": {}, "/e/" + "a" * 6000: {}}})
        self.write_json(self.claude / "backups" / f".claude.json.gh{'p'}_{parts[2]}.{parts[3]}", {})
        (self.codex / "rules").mkdir()
        (self.codex / "rules" / f"gh{'p'}_{parts[2]}.{parts[3]}.rules").write_text("", encoding="utf-8")
        (self.codex / "config.toml").write_text(f'[projects."/f/ghp_{parts[0]}\\"{parts[1]}"]\n', encoding="utf-8")
        run = self.audit()
        self.assertNotIn("a" * 64, run.text, "a 6000-character folder is not printed")
        self.assertIn("<codex home>/rules/[file", run.report)
        self.assertIn("<claude config>/backups/[file", run.report)

    def test_an_unset_config_folder_prints_as_its_default_and_a_set_one_never(self):
        env = dict(self.env)
        del env["CLAUDE_CONFIG_DIR"], env["CODEX_HOME"]
        run = self.audit(env=env)
        self.assertIn("~/.claude/settings.json (Claude Code user settings)", run.report)
        self.assertIn("~/.codex/config.toml (Codex config)", run.report)
        self.assertNotIn(str(self.home), run.text)

    # -- Gate A round 3: names print only from a fixed vocabulary ------------------------------------------------
    def test_a_rules_file_name_of_letters_or_digits_prints_as_a_number(self):
        (self.codex / "rules").mkdir()
        for name in (_letters(40), _digits(16), "-".join(_digits(4) for _ in range(4))):
            self.secrets.append(name)
            (self.codex / "rules" / f"{name}.rules").write_text("", encoding="utf-8")
        (self.codex / "rules" / "default.rules").write_text("", encoding="utf-8")
        run = self.audit()
        self.assertEqual(run.rc, 0, run.text)
        for n in (1, 2, 3):
            self.assertIn(f"<codex home>/rules/[file {n}] (Codex approval rules)", run.report)
        self.assertIn("<codex home>/rules/default.rules (Codex approval rules)", run.report, "the client's own name")

    def test_a_backup_name_outside_the_clients_pattern_prints_as_a_number(self):
        name = ".claude.json.backup" + _letters(30)
        digits = [_digits(13) for _ in range(3)]
        self.secrets += [name[19:]] + digits
        self.write_json(self.claude / "backups" / name, {})
        for d in digits:
            self.write_json(self.claude / "backups" / f".claude.json.corrupted.{d}", {})
        run = self.audit()
        self.assertIn("<claude config>/backups/[file 1] (Claude Code client config)", run.report)
        for n in (1, 2, 3):
            self.assertIn(f"<claude config>/backups/.claude.json.corrupted {n} (Claude Code client config)",
                          run.report)

    def test_a_set_config_folder_always_prints_as_its_placeholder(self):
        cases = [("relative letters", Path(_letters(40))), ("plain parts", self.dir / "plain" / _letters(40)),
                 ("digits", self.dir / _digits(16)), ("card form", self.dir / "-".join(_digits(4) for _ in range(4))),
                 ("split token", self.dir / ("gh" + "p_" + _rnd(18)) / _rnd(18))]
        for what, folder in cases:
            with self.subTest(what):
                self.secrets += [x for x in folder.parts if len(x) >= 8 and x not in self.dir.parts]
                (self.dir / folder).mkdir(parents=True, exist_ok=True)
                env = dict(self.env, CLAUDE_CONFIG_DIR=str(folder), CODEX_HOME=str(folder))
                run = self.audit(env=env, cwd=str(self.dir))
                self.assertIn("<claude config>/settings.json", run.report)
                self.assertIn("<codex home>/config.toml", run.report)
                # the error path prints the placeholder too
                (self.dir / folder / "settings.json").mkdir(exist_ok=True)
                run = self.audit(env=env, cwd=str(self.dir))
                self.assertEqual(run.rc, 2, run.text)
                self.assertIn("<claude config>/settings.json (Claude Code user settings): ", run.report)

    def test_a_json_key_of_letters_digits_or_a_split_token_prints_as_a_number(self):
        head, a, b = "gh" + "p_" + _rnd(12), _rnd(12), _rnd(12)
        self.secrets += [head + a + b]
        name = _letters(40)
        self.secrets.append(name)
        self.write_json(self.claude / "settings.json", {"env": {name: self.token}, head: {a: {b: self.token}}})
        run = self.audit()
        self.assertEqual(run.rc, 1, run.text)
        self.assertIn("env.[key 1]", run.report)
        self.assertIn("[key 2].[key 3].[key 4]", run.report)

    def test_a_toml_section_and_key_of_letters_or_a_split_token_print_as_numbers(self):
        head, tail = "gh" + "p_" + _rnd(18), _rnd(18)
        sec, key = _letters(40), _letters(40)
        self.secrets += [head + tail, sec, key]
        (self.codex / "config.toml").write_text(f'[{sec}]\n{key} = "{self.token}"\n[{head}]\n{tail} = "{self.token}"\n',
                                                encoding="utf-8")
        run = self.audit()
        self.assertIn("line 2 ([key 1].[key 2])", run.report)
        self.assertIn("line 4 ([key 3].[key 4])", run.report)

    # -- Gate A round 4 ----------------------------------------------------------------------------------------------
    def test_a_rule_id_of_the_persons_own_prints_by_number(self):
        """A rule from rules.d (JSON and .prefixes) has the kind user:<id>, and the person chooses the id (F1). The
        run gets a vault home of its own, a temp folder of this test."""
        home = self.dir / "vault-home"
        (home / "rules.d").mkdir(parents=True)
        (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}', encoding="utf-8")
        json_id, prefix_id = _letters(16), _letters(16)
        self.secrets += [json_id, prefix_id]
        (home / "rules.d" / "team.json").write_text(json.dumps({"rules": [
            {"id": json_id, "regex": r"zqvk_[A-Za-z0-9]{24}", "keywords": ["zqvk_"]}]}), encoding="utf-8")
        (home / "rules.d" / "more.prefixes").write_text(f"{prefix_id}  wxjb-  [0-9a-f]{{32}}\n", encoding="utf-8")
        v1, v2 = "zqvk_" + _rnd(24), "wxjb-" + "".join(secrets.choice("0123456789abcdef") for _ in range(32))
        self.secrets += [v1, v2]
        self.write_json(self.claude / "settings.json", {"permissions": {"allow": [f"Bash(deploy --key {v1})",
                                                                                 f"Bash(build --key {v2})"]}})
        env = dict(self.env)
        env["MAISECRETS" + "_HOME"] = str(home)
        run = self.audit(env=env)
        self.assertEqual(run.rc, 1, run.text)
        rows = run.rows()
        self.assertEqual(len(rows), 2, run.report)
        self.assertEqual(sorted(" ".join(r.split()[2:5]) for r in rows), ["user rule 1", "user rule 2"])

    def test_a_term_kind_prints_by_number_and_a_built_in_rule_by_name(self):
        names = _module().Names()
        self.assertEqual(names.rule("term:0123456789ab"), "term 1")
        self.assertEqual(names.rule("user:" + _letters(16)), "user rule 2")
        self.assertEqual(names.rule("github-pat"), "github-pat")

    def test_an_mcp_server_with_a_setting_name_prints_by_number(self):
        self.write_json(self.claude / "settings.json", {"mcpServers": {"filesystem": {"env": {"sqlite": self.token}}}})
        self.assert_found(self.audit(), "<claude config>/settings.json", "mcpServers.[key 1].env.[key 2]",
                          fix="take the value out of this setting")
        (self.claude / "settings.json").unlink()
        (self.codex / "config.toml").write_text(f'[mcp_servers.filesystem.env]\nsearch = "{self.token}"\n',
                                                encoding="utf-8")
        self.assert_found(self.audit(), "<codex home>/config.toml", "line 2 (mcp_servers.[key 1].env.[key 2])",
                          fix="take the value out of this setting")

    def test_a_withheld_client_config_label_keeps_its_project_finding_and_its_project_list_entry(self):
        """The origin of a project is the Source itself: a label that layer 2 withholds still names its project
        finding, and the Projects list prints the checked label (F2)."""
        import contextlib
        import io
        from unittest import mock
        self.write_json(self.claude / ".claude.json", {"projects": {f"/srv/{self.token}": {}}})
        mod = _module()
        real = mod.joined_check

        def withhold(detect, rules, label):
            return "[label withheld]" if label.endswith(".claude.json") else real(detect, rules, label)
        mod.joined_check = withhold
        buf = io.StringIO()
        env = {k: v for k, v in self.env.items() if k != "PYTHONUTF8"}
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(buf):
            rc = mod.main([])
        out = buf.getvalue()
        self.assert_no_run_of_a_secret(out)
        self.assertEqual(rc, 1, out)
        self.assertIn("[label withheld]  <project 1> (project path)", out)
        self.assertIn("project 1 (from [label withheld])", out)

    def test_a_known_setting_name_prints_by_name(self):
        self.write_json(self.claude / "settings.json",
                        {"hooks": {"PreToolUse": [{"hooks": [{"command": self.approve()}]}]}})
        self.assert_found(self.audit(), "<claude config>/settings.json", "hooks.PreToolUse[0].hooks[0].command",
                          fix="take the value out of this setting")

    def test_a_label_whose_parts_form_a_token_is_withheld_whole(self):
        mod = _module()
        detect = mod._detector.load()
        rules = mod._detector.secret_rules(detect)
        head, tail = "gh" + "p_" + _rnd(18), _rnd(18)
        self.assertEqual(mod.joined_check(detect, rules, f"<x>/{head}/{tail}.rules"), "[label withheld]")
        self.assertEqual(mod.joined_check(detect, rules, f"[{head}].[{tail}]"), "[label withheld]")
        self.assertEqual(mod.joined_check(detect, rules, "<codex home>/rules/default.rules"),
                         "<codex home>/rules/default.rules")

    # -- Gate A M1 and round 2 M1 -------------------------------------------------------------------------------
    def test_the_guard_withholds_a_value_in_its_json_escaped_and_control_escaped_forms(self):
        mod = _module()
        value = 'pw"\\é\x01' + self.token
        lines = [f"a {json.dumps(value)} b", f"c {json.dumps(value, ensure_ascii=False)} d", f"e {mod.shown(value)}"]
        for line in mod.guard(lines, {value: "S1"}):
            self.assertIn("[withheld]", line)
            self.assertNotIn(self.token, line)

    def test_a_nul_in_a_codex_project_header_is_no_traceback(self):
        (self.codex / "config.toml").write_text('[projects."/x/\\u0000y"]\n', encoding="utf-8")
        run = self.audit()
        self.assertEqual(run.rc, 0, run.text)

    def test_a_lone_surrogate_and_a_control_character_print_escaped(self):
        """The labels hold no chosen name, so no run reaches this today; it keeps a line that would hold one
        encodable."""
        mod = _module()
        self.assertEqual(mod.shown("a\ud800b\x01c"), "a\\ud800b\\x01c")
        mod.shown("a\ud800b").encode("utf-8")

    def test_a_lone_surrogate_in_a_project_key_is_no_traceback(self):
        (self.claude / ".claude.json").write_text('{"projects": {"/x/\\ud800y": {"allowedTools": ["Read"]}}}',
                                                 encoding="utf-8")
        for out in (True, False):
            run = self.audit(out=out)
            self.assertEqual(run.rc, 0, run.text)

    def test_any_error_in_the_run_is_exit_two_with_its_class_name_only(self):
        import contextlib
        import io
        mod = _module()

        def boom(_args):
            raise RuntimeError(self.token)
        mod.run = boom
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(mod.main([]), 2)
        self.assertIn("RuntimeError", buf.getvalue())
        self.assert_no_run_of_a_secret(buf.getvalue())

    # -- Gate A L1 and round 2 L1: a key that is itself a credential -------------------------------------------
    def test_a_key_that_looks_like_a_credential_is_not_printed(self):
        # not a plain name of letters alone (only the character class catches it); not a plain name; random 24;
        # random 11
        for name in ("only!letters", _rnd(23) + "!", _rnd(24), _rnd(11), _letters(40), _digits(16)):
            with self.subTest(length=len(name)):
                self.secrets.append(name.rstrip("!"))
                self.write_json(self.claude / "settings.json", {"env": {"X": {name: self.token}}})
                self.assert_found(self.audit(), "<claude config>/settings.json", "env.[key 1].[key 2]",
                                  fix="take the value out of this setting")

    def test_a_toml_key_that_is_not_a_plain_name_is_not_printed(self):
        key = _rnd(12)
        self.secrets.append(key)
        (self.codex / "config.toml").write_text(f'[env]\n"{key}!" = "{self.token}"\n{key} = "{self.token}"\n',
                                                encoding="utf-8")
        run = self.audit()
        self.assertIn("line 2 (env.[key 1])", run.report)
        self.assertIn("line 3 (env.[key 2])", run.report)

    # -- Gate A M2, M3, M4 ------------------------------------------------------------------------------------------
    @unittest.skipIf(sys.platform == "win32", "no FIFO on Windows")
    def test_a_fifo_in_place_of_a_file_does_not_hang_and_exits_two(self):
        os.mkfifo(self.claude / "settings.json")
        run = self.audit()
        self.assertEqual(run.rc, 2, run.text)
        self.assertIn("<claude config>/settings.json (Claude Code user settings): not a regular file", run.report)

    def test_a_file_larger_than_the_cap_is_not_read_and_exits_two(self):
        self.write_json(self.claude / "settings.json", {"permissions": {"allow": ["Bash(ls:*)"] * 200}})
        run = self.audit("--max-mb", "0.001")
        self.assertEqual(run.rc, 2, run.text)
        self.assertIn("too large", run.report)
        self.assertEqual(self.audit().rc, 0, "under the default cap it is read")

    def test_a_deeply_nested_file_is_an_error_not_a_finding(self):
        # balanced: Python 3.9 json raises RecursionError, 3.12 parses it and the walk over the strings raises it
        (self.claude / "settings.json").write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
        run = self.audit()
        self.assertEqual(run.rc, 2, run.text)
        self.assertIn("RecursionError", run.report)

    def test_a_file_that_cannot_be_read_exits_two(self):
        (self.claude / "settings.json").mkdir()      # a folder in place of the file: unreadable also as root
        run = self.audit(out=False)
        self.assertEqual(run.rc, 2, run.text)
        self.assertIn("could NOT be read", run.stdout)

    def test_findings_win_over_an_unreadable_file(self):
        (self.claude / "settings.json").mkdir()
        self.write_json(self.claude / "settings.local.json", {"permissions": {"allow": [self.approve()]}})
        self.assertEqual(self.audit().rc, 1)

    # -- Gate A L2 and round 2 L2: --out ---------------------------------------------------------------------------
    def test_out_naming_a_source_file_is_refused_and_the_file_is_kept(self):
        f = self.write_json(self.claude / "settings.json", {"permissions": {"allow": ["Bash(ls:*)"]}})
        before = f.read_bytes()
        run = self.audit("--out", str(f), out=False)
        self.assertEqual(run.rc, 2, run.text)
        self.assertIn("names a file this script reads", run.stdout)
        self.assertEqual(f.read_bytes(), before)
        run = self.audit("--out", str(self.claude / "settings.local.json"), out=False)
        self.assertEqual(run.rc, 2, "an absent source is refused too: the client would read it")
        self.assertFalse((self.claude / "settings.local.json").exists())

    def test_the_out_file_name_is_not_printed(self):
        name = "report-" + _rnd(20) + ".txt"
        self.secrets.append(name[7:27])
        run = self.audit("--out", str(self.dir / name), out=False)
        self.assertEqual(run.rc, 0, run.text)
        self.assertIn("Wrote the full report to the --out file.", run.stdout)
        self.assertTrue((self.dir / name).is_file())

    # -- the report, clean configs, the environment, no write --------------------------------------------------
    def test_the_report_file_holds_the_rows_and_stdout_only_the_summary(self):
        self.write_json(self.claude / "settings.json", {"permissions": {"allow": [self.approve()]}})
        run = self.audit()
        self.assertIn("permissions.allow[0]", run.report)
        self.assertNotIn("permissions.allow[0]", run.stdout, "the rows go to the file")
        self.assertIn("Findings: 1 distinct value(s)", run.stdout)

    def test_a_clean_config_has_no_finding_and_exits_zero(self):
        self.write_json(self.claude / "settings.json", {"permissions": {"allow": [
            "Bash(npm run test:*)", "Bash(git log:*)", "WebFetch(domain:docs.example.test)"]},
            "env": {"DEBUG": "1"}, "model": "opus"})
        self.write_json(self.claude / ".claude.json", {"projects": {"/p": {"allowedTools": ["Bash(make:*)"]}}})
        (self.codex / "rules").mkdir()
        (self.codex / "rules" / "default.rules").write_text(
            'prefix_rule(pattern=["git", "status"], decision="allow")\n', encoding="utf-8")
        (self.codex / "config.toml").write_text('model = "x"\napproval_policy = "on-request"\n', encoding="utf-8")
        run = self.audit(out=False)
        self.assertEqual(run.rc, 0, run.text)
        self.assertIn("Findings: 0 distinct value(s)", run.stdout)
        self.assertNotIn("  S1 ", run.stdout)

    def test_the_report_names_the_files_read_and_the_files_absent(self):
        self.write_json(self.claude / "settings.json", {})
        run = self.audit()
        self.assertEqual(run.rc, 0, run.text)
        read = run.report.split("Files read:")[1].split("Files that do not exist:")[0]
        absent = run.report.split("Files that do not exist:")[1]
        self.assertIn("<claude config>/settings.json", read)
        for label in ("<claude config>/settings.local.json", "<claude config>/.claude.json",
                      "<codex home>/config.toml", "<codex home>/rules/*.rules"):
            self.assertIn(label, absent)

    def test_claude_config_dir_and_codex_home_are_honoured_and_the_defaults_are_not_read(self):
        self.write_json(self.home / ".claude" / "settings.json", {"permissions": {"allow": [self.approve()]}})
        rules = self.home / ".codex" / "rules" / "default.rules"
        rules.parent.mkdir(parents=True)
        rules.write_text(f'prefix_rule(pattern=["gh", "{self.token}"])\n', encoding="utf-8")
        run = self.audit()
        self.assertEqual(run.rc, 0, run.text)
        self.assertNotIn("~/.claude", run.report)
        self.assertNotIn("~/.codex", run.report)
        env = {k: v for k, v in self.env.items() if k not in ("CLAUDE_CONFIG_DIR", "CODEX_HOME")}
        run = self.audit(env=env)
        self.assertEqual(run.rc, 1, run.text)
        self.assertIn("~/.claude/settings.json", run.report)
        self.assertIn("~/.codex/rules/default.rules", run.report)

    def test_no_file_is_changed(self):
        f = self.write_json(self.claude / "settings.json", {"permissions": {"allow": [self.approve()]}})
        before = (f.read_bytes(), f.stat().st_mtime_ns)
        self.audit(out=False)
        self.assertEqual((f.read_bytes(), f.stat().st_mtime_ns), before)
        self.assertEqual(sorted(p.name for p in self.claude.iterdir()), ["settings.json"])


if __name__ == "__main__":
    unittest.main()
