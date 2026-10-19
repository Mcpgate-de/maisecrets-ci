"""The secret-hygiene skill: its output goes to a cloud model, so no value may appear in it.

Each test builds a throwaway git repository with a generated token, runs the scripts the way
the skill tells the model to, and searches every byte of output for the token."""
from __future__ import annotations

import hashlib
import io
import importlib.util
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
SKILL = ROOT / "skills" / "secret-hygiene"
SCRIPTS = SKILL / "scripts"
HAS_GIT = shutil.which("git") is not None


def _token() -> str:
    return "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


def _clean_env() -> dict:
    """The environment without GIT_*: inside a git hook, GIT_INDEX_FILE, GIT_DIR and the author
    variables point at the repository being committed, and a test repository would inherit them
    (the author of a test commit became the committer of the real one; 2026-09-27)."""
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=_clean_env())


def _run(script: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    env = dict(_clean_env(), PYTHONUTF8="1")
    return subprocess.run([sys.executable, str(script), *args], cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", env=env, timeout=120)


class SkillFileTests(unittest.TestCase):
    def test_the_skill_has_front_matter_the_loaders_accept(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"))
        head = text.split("---\n", 2)[1]
        fields = dict(line.split(": ", 1) for line in head.strip().splitlines())
        self.assertEqual(fields["name"], SKILL.name, "the folder name must match the skill name")
        self.assertTrue(fields["description"] and "\n" not in fields["description"])
        self.assertLessEqual(len(fields["description"]), 1024)
        for rel in ("scripts/scan_secrets.py", "scripts/redact_copy.py", "scripts/audit_transcripts.py",
                    "scripts/protection_status.py", "references/rotation.md"):
            self.assertIn(rel, text, rel)
            self.assertTrue((SKILL / rel).is_file(), rel)


class SkillListingTests(unittest.TestCase):
    def test_the_chatgpt_listing_names_the_skill_and_its_icons_exist(self):
        """ChatGPT shows a skill's name and icon from agents/openai.yaml; without it the upload
        showed the folder name and a generic icon (2026-09-27)."""
        text = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
        fields = {}
        for line in text.splitlines()[1:]:
            if line.startswith("  ") and not line.startswith("    "):
                key, _sep, val = line.strip().partition(": ")
                fields[key] = val.strip('"')
        self.assertIn("maisecrets", fields["display_name"])
        self.assertLessEqual(len(fields["short_description"]), 64)
        for key in ("icon_small", "icon_large"):
            self.assertTrue((SKILL / fields[key]).is_file(), fields[key])
        self.assertRegex(fields["brand_color"], r"^#[0-9A-Fa-f]{6}$")


@unittest.skipUnless(HAS_GIT, "git is needed for the history scan")
class SkillScriptTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-skill-"))
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        self.token = _token()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@example.org")
        _git(self.repo, "config", "user.name", "t")
        (self.repo / ".env").write_text(f"GITHUB_TOKEN={self.token}\n", encoding="utf-8")
        (self.repo / "app.py").write_text("print(1)\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "one")
        (self.repo / ".env").unlink()
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "two")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_a_value_only_in_the_history_is_found_and_never_printed(self):
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Working tree: 0 finding(s)", r.stdout)
        self.assertIn("Git history: 1 finding(s)", r.stdout)
        self.assertIn("only in history", r.stdout)
        self.assertIn(".env:1", r.stdout)
        for part in (self.token, self.token[4:], self.token[-12:]):
            self.assertNotIn(part, r.stdout + r.stderr)

    def test_a_history_finding_says_when_who_and_whether_it_was_pushed(self):
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        row = next(line for line in r.stdout.splitlines() if "commit " in line and line.startswith("  S"))
        self.assertRegex(row, r"commit [0-9a-f]{7,} \d{4}-\d{2}-\d{2} by t")
        self.assertIn("no remote", row)
        self.assertIn("github-pat", row, "a keyword match on a provider token is named by the provider")
        self.assertIn("shape", row)

    def test_a_pushed_commit_is_marked_pushed_and_a_new_one_local_only(self):
        remote = self.dir / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, capture_output=True, env=_clean_env())
        _git(self.repo, "remote", "add", "origin", str(remote))
        _git(self.repo, "push", "-q", "origin", "HEAD:refs/heads/main")
        _git(self.repo, "fetch", "-q", "origin")
        (self.repo / "later.cfg").write_text(f"token = {_token()}\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "three")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        rows = [line for line in r.stdout.splitlines() if "commit " in line and line.startswith("  S")]
        self.assertTrue(any("pushed" in row and ".env:1" in row for row in rows), r.stdout)
        self.assertTrue(any("local only" in row and "later.cfg:1" in row for row in rows), r.stdout)

    def test_a_cut_history_scan_says_so_and_does_not_exit_clean(self):
        clean = self.dir / "clean"
        clean.mkdir()
        _git(clean, "init", "-q")
        _git(clean, "config", "user.email", "t@example.org")
        _git(clean, "config", "user.name", "t")
        for i in range(3):
            (clean / "f.txt").write_text(f"{i}\n", encoding="utf-8")
            _git(clean, "add", ".")
            _git(clean, "commit", "-qm", str(i))
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", "--max-commits", "1", cwd=clean)
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertIn("stopped after 1 of 3 commits", r.stdout)

    def test_a_large_file_is_scanned_whole_and_a_limit_is_named(self):
        big = self.repo / "dump.sql"
        big.write_text("INSERT INTO t VALUES (1);\n" * 90_000 + f"token = {self.token}\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "dump")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        self.assertIn("dump.sql:90001", r.stdout, "no default size limit: the value at the end is found")
        self.assertNotIn("NOT scanned", r.stdout)
        cut = _run(SCRIPTS / "scan_secrets.py", ".", "--history", "--max-mb", "1", cwd=self.repo)
        self.assertIn("NOT scanned, larger than 1 MB", cut.stdout)
        self.assertIn("dump.sql in commit", cut.stdout)

    def test_a_folder_without_git_still_reports_its_files(self):
        plain = self.dir / "plain"
        plain.mkdir()
        (plain / "a.env").write_text(f"GITHUB_TOKEN={self.token}\n", encoding="utf-8")
        r = _run(SCRIPTS / "scan_secrets.py", str(plain), "--history", cwd=self.dir)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("a.env:1", r.stdout)
        self.assertIn("not a git repository", r.stdout)
        self.assertNotIn(self.token, r.stdout)

    def test_the_full_report_can_go_to_a_file_and_the_model_sees_the_summary(self):
        out = self.dir / "report.txt"
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", "--out", str(out), cwd=self.repo)
        self.assertNotIn(".env:1", r.stdout)
        self.assertIn("Summary:", r.stdout)
        self.assertIn(".env:1", out.read_text(encoding="utf-8"))
        self.assertNotIn(self.token, out.read_text(encoding="utf-8"))

    def test_an_added_line_that_starts_with_plus_plus_is_content_not_a_path(self):
        (self.repo / "notes.txt").write_text(f"++ token={self.token}\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "notes")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        self.assertNotIn(self.token, r.stdout + r.stderr)
        self.assertNotIn(self.token[4:], r.stdout)
        history = [line for line in r.stdout.splitlines() if " commit " in line]
        self.assertTrue(any(line.endswith("notes.txt:1") for line in history), r.stdout)

    def test_an_author_name_that_looks_like_a_secret_is_not_printed(self):
        _git(self.repo, "config", "user.name", self.token)
        (self.repo / "b.cfg").write_text(f"token = {_token()}\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "b")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        self.assertNotIn(self.token, r.stdout)
        self.assertIn("an author name that looks like a secret", r.stdout)

    def test_redact_never_writes_over_the_original_even_with_force(self):
        src = self.repo / "log.txt"
        src.write_text(f"key {self.token}\n", encoding="utf-8")
        r = _run(SCRIPTS / "redact_copy.py", "log.txt", "--out", "log.txt", "--force", cwd=self.repo)
        self.assertEqual(r.returncode, 2)
        self.assertIn(self.token, src.read_text(encoding="utf-8"))

    def test_a_clean_tree_exits_zero(self):
        r = _run(SCRIPTS / "scan_secrets.py", ".", cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_same_value_carries_one_id_in_the_tree_and_the_history(self):
        (self.repo / "log.txt").write_text(f"token {self.token}\n", encoding="utf-8")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        ids = {line.split()[0] for line in r.stdout.splitlines() if line.startswith("  S")}
        self.assertEqual(ids, {"S1"}, r.stdout)
        self.assertIn("value also at", r.stdout)
        self.assertNotIn(self.token, r.stdout)

    def test_the_redacted_copy_holds_no_value_and_the_original_is_kept(self):
        src = self.repo / "log.txt"
        src.write_text(f"mail anna.schmidt@firma-xyz.de\nkey {self.token}\nagain {self.token}\n", encoding="utf-8")
        before = src.read_bytes()
        r = _run(SCRIPTS / "redact_copy.py", "log.txt", cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        copy = (self.repo / "log.redacted.txt").read_text(encoding="utf-8")
        self.assertNotIn(self.token, copy + r.stdout + r.stderr)
        self.assertNotIn("anna.schmidt", copy + r.stdout)
        self.assertEqual(copy.count("⟦SECRET_1⟧"), 2, "the same value gets the same tag")
        self.assertIn("NOT replaced: names", r.stdout)
        self.assertIn("inside a git repository", r.stdout)
        self.assertEqual(src.read_bytes(), before)
        again = _run(SCRIPTS / "redact_copy.py", "log.txt", cwd=self.repo)
        self.assertEqual(again.returncode, 2, "an existing copy is not overwritten without --force")
        same = _run(SCRIPTS / "redact_copy.py", "log.txt", "--out", "log.txt", cwd=self.repo)
        self.assertEqual(same.returncode, 2, "the original is never the output")
        self.assertEqual(src.read_bytes(), before)


def _digest_parts(value: str) -> list[str]:
    """Every hex digest of the value a script could print: md5, sha1, sha256, sha512, whole and as
    an 8 to 16 character prefix."""
    out = []
    for alg in ("md5", "sha1", "sha256", "sha512"):
        h = hashlib.new(alg, value.encode("utf-8")).hexdigest()
        out += [h] + [h[:n] for n in range(8, 17)]
    return out


@unittest.skipUnless(HAS_GIT, "git is needed for the history scan")
class NeverALineOrAHashTests(unittest.TestCase):
    """THREAT-MODEL C17: the scripts print locations, types, lengths and per-run ids, never a
    value, a line or a hash of a value. A non-secret sentinel shares the line with the value: a
    script that printed the line would print the sentinel."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-c17-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.token = _token()
        self.sentinel = "Sentinel" + secrets.token_hex(6)
        self.line = f"note {self.sentinel} GITHUB_TOKEN={self.token}"
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@example.org")
        _git(self.repo, "config", "user.name", "t")
        (self.repo / "old.env").write_text(self.line + "\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "one")
        (self.repo / "old.env").unlink()
        (self.repo / "now.log").write_text(self.line + "\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "two")
        self.claude, self.codex = self.dir / "claude", self.dir / "codex"
        proj = self.claude / "projects" / "-x"
        proj.mkdir(parents=True)
        (self.codex / "sessions").mkdir(parents=True)
        session = proj / "s.jsonl"
        session.write_text(json.dumps({"type": "user", "timestamp": "2026-09-20T10:00:00Z",
                                       "message": {"content": self.line}}) + "\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(session, (old, old))

    def outputs(self) -> dict[str, str]:
        out: dict[str, str] = {}
        report, audit_report = self.dir / "report.txt", self.dir / "audit.txt"
        for name, args in (("tree", ["."]), ("history", [".", "--history"]),
                           ("history --out", [".", "--history", "--out", str(report)])):
            r = _run(SCRIPTS / "scan_secrets.py", *args, cwd=self.repo)
            self.assertEqual(r.returncode, 1, f"{name} found nothing: {r.stdout}")
            out[f"scan {name}"] = r.stdout + r.stderr
        out["scan report file"] = report.read_text(encoding="utf-8")
        r = _run(SCRIPTS / "redact_copy.py", "now.log", cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out["redact"] = r.stdout + r.stderr
        env = dict(_clean_env(), PYTHONUTF8="1", CLAUDE_CONFIG_DIR=str(self.claude), CODEX_HOME=str(self.codex))
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--out", str(audit_report)],
                           capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        out["audit"] = r.stdout + r.stderr
        out["audit report file"] = audit_report.read_text(encoding="utf-8")
        return out

    def test_no_output_holds_the_value_its_line_or_a_hash_of_it(self):
        parts = [self.token, self.token[4:], self.sentinel] + _digest_parts(self.token) + _digest_parts(self.line)
        for name, text in self.outputs().items():
            with self.subTest(name):
                self.assertTrue(text.strip(), "an empty output proves nothing")
                low = text.lower()
                self.assertEqual([p for p in parts if p.lower() in low], [], text[-600:])


class SkillChannelTests(unittest.TestCase):
    """The skill scripts read files, commits and tool results as the tool hook reads them, and a typed prompt as the
    prompt hook does: letters after a password label count in a file, not in a prompt (0.6.17)."""
    FILE_PW = "pozk" + "emva"     # random small letters: only the tool channel takes them
    PROMPT_PW = "vurk" + "apzo"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-skill-channel-"))
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_a_file_scan_and_a_redacted_copy_take_letters_after_a_password_label(self):
        (self.dir / "db.rs").write_text(f'let password = Some("{self.FILE_PW}");\n', encoding="utf-8")
        r = _run(SCRIPTS / "scan_secrets.py", str(self.dir), cwd=self.dir)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("db.rs:1", r.stdout)
        self.assertNotIn(self.FILE_PW, r.stdout + r.stderr)
        r = _run(SCRIPTS / "redact_copy.py", "db.rs", cwd=self.dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn(self.FILE_PW, (self.dir / "db.redacted.rs").read_text(encoding="utf-8"))

    def test_the_audit_takes_them_in_a_tool_result_and_not_in_a_prompt(self):
        claude = self.dir / "claude"
        proj = claude / "projects" / "-Users-x-repo"
        proj.mkdir(parents=True)
        rows = [{"type": "user", "timestamp": "2026-10-14T10:00:00Z",
                 "message": {"content": f'password = Some("{self.PROMPT_PW}"),'}},
                {"type": "user", "timestamp": "2026-10-14T10:01:00Z",
                 "message": {"content": [{"type": "tool_result", "content": f'password = Some("{self.FILE_PW}"),'}]}}]
        session = proj / "abcdef12-0001.jsonl"
        session.write_text("\n".join(json.dumps(x) for x in rows) + "\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(session, (old, old))
        env = dict(_clean_env(), PYTHONUTF8="1", CLAUDE_CONFIG_DIR=str(claude), CODEX_HOME=str(self.dir / "codex"))
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py")], capture_output=True, text=True,
                           encoding="utf-8", env=env, timeout=120)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Reached the AI provider: 1 distinct value(s).", r.stdout)
        row = next(line for line in r.stdout.splitlines() if line.startswith("  S1"))
        self.assertIn("tool result", row)
        self.assertNotIn("prompt", row)
        for v in (self.FILE_PW, self.PROMPT_PW):
            self.assertNotIn(v, r.stdout + r.stderr)


def _rnd(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _files_full_of_secrets() -> dict:
    """{file name: (text, values)}: a password export, a HAR recording, a contact and a calendar export, each value
    generated at run time."""
    pw = ["Tp" + _rnd(10) + "!", "testpass" + _rnd(6), "kx" + _rnd(12)]
    csv = "name,url,username,password,note\n" + "".join(
        f"site{i},https://site{i}.example.com/login,user{i},{p},\n" for i, p in enumerate(pw))
    bearer = "ey" + "J" + _rnd(20) + "." + _rnd(30) + "." + _rnd(24)
    cookie, cookie2 = _rnd(32, "0123456789abcdef"), _rnd(26, "0123456789abcdef")
    token = "gh" + "p_" + _rnd(36)
    har = json.dumps({"log": {"version": "1.2", "entries": [{
        "request": {"method": "GET", "url": "https://api.example.com/v1/me",
                    "headers": [{"name": "Authorization", "value": "Bearer " + bearer},
                                {"name": "Cookie", "value": "session=" + cookie},
                                {"name": "X-Token", "value": token}],
                    "cookies": [{"name": "sid", "value": cookie2}]},
        "response": {"status": 200, "headers": [], "cookies": []}}]}}, indent=2)
    domain = "mail" + "box.org"
    mail, tel = "jane.roe." + _rnd(5).lower() + "@" + domain, "+49 151 " + _rnd(8, string.digits)
    vcf = ("BEGIN:VCARD\nVERSION:3.0\nFN:Jane Roe\nN:Roe;Jane;;;\n"
           f"EMAIL;TYPE=INTERNET:{mail}\nTEL;TYPE=CELL:{tel}\nEND:VCARD\n")
    mail2, meeting_code = "john.doe." + _rnd(5).lower() + "@" + domain, _rnd(24)
    ics = ("BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nSUMMARY:Planning\n"
           f"ATTENDEE;CN=John Doe:mailto:{mail2}\n"
           f"LOCATION:https://meet.example.com/j/123456789?pwd={meeting_code}\nEND:VEVENT\nEND:VCALENDAR\n")
    return {"passwords.csv": (csv, pw), "session.har": (har, [bearer, cookie, cookie2, token]),
            "contacts.vcf": (vcf, [mail, tel]), "meeting.ics": (ics, [mail2, meeting_code])}


class ReadAFileFullOfSecretsTests(unittest.TestCase):
    """Before the model reads a file full of secrets (a password export, a .har, a .vcf, an .ics), the skill stops,
    offers a masked copy and reads only the copy: the hooks replace only what their rules find, and a file read whole
    sends every value in it to the provider (after danszymkowiak/maisecrets 53c839e)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-skill-export-"))
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_the_skill_stops_offers_a_masked_copy_and_reads_only_the_copy(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        head = text.split("---\n", 2)[1]
        self.assertIn("about to read a file full of secrets", head)
        section = text.split("## Before you read a file full of secrets", 1)[1].split("\n## ", 1)[0]
        for sign in ("passwords.csv", "logins.csv", ".har", ".vcf", ".ics", "header row"):
            self.assertIn(sign, section, sign)
        for step in ("Do not open it", "offer a masked copy", "python3 scripts/redact_copy.py <file>",
                     "Read only the copy, never the original", "If the user says no, do not read the file"):
            self.assertIn(step, section, step)

    def test_a_masked_copy_of_each_file_holds_no_value_and_the_original_is_kept(self):
        for name, (text, values) in _files_full_of_secrets().items():
            with self.subTest(name):
                src = self.dir / name
                src.write_text(text, encoding="utf-8")
                before = src.read_bytes()
                r = _run(SCRIPTS / "redact_copy.py", name, cwd=self.dir)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                copy = (self.dir / (src.stem + ".redacted" + src.suffix)).read_text(encoding="utf-8")
                for i, v in enumerate(values):
                    self.assertNotIn(v, copy, f"value {i} of {name} is in the copy")
                    self.assertNotIn(v, r.stdout + r.stderr)
                self.assertEqual(src.read_bytes(), before)
                if name.endswith(".har"):
                    json.loads(copy)   # a masked recording stays a recording

    def test_a_password_export_is_read_by_its_file_name(self):
        """A secret column with no entry column is an export's only when the file name says so: the copy reads it
        as the Read hook does, with the file name."""
        pw = [_rnd(10), _rnd(9)]
        (self.dir / "passwords.csv").write_text("folder,password\n" + "".join(f"f{i},{p}\n" for i, p in enumerate(pw)),
                                                encoding="utf-8")
        r = _run(SCRIPTS / "redact_copy.py", "passwords.csv", cwd=self.dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        copy = (self.dir / "passwords.redacted.csv").read_text(encoding="utf-8")
        for p in pw:
            self.assertNotIn(p, copy)

    def test_a_har_header_that_names_no_credential_stays(self):
        har = json.dumps({"log": {"entries": [{"request": {"headers": [
            {"name": "Accept", "value": "application/json"}, {"name": "User-Agent", "value": "probe-agent/1.0"}]}}]}})
        (self.dir / "plain.har").write_text(har, encoding="utf-8")
        r = _run(SCRIPTS / "redact_copy.py", "plain.har", cwd=self.dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.dir / "plain.redacted.har").read_text(encoding="utf-8"), har)


    def test_a_har_value_in_another_json_escape_is_masked_too(self):
        """A writer may escape `/` as `\\/` or a letter as `\\u0041`: the copy is written again in one JSON form, so
        the search finds the value (review of 0.6.24)."""
        cookie = _rnd(6) + "/" + _rnd(6)
        raw = cookie.replace("/", "\\/")
        har = '{"log":{"entries":[{"request":{"cookies":[{"name":"sid","value":"' + raw + '"}]}}]}}'
        (self.dir / "escaped.har").write_text(har, encoding="utf-8")
        r = _run(SCRIPTS / "redact_copy.py", "escaped.har", cwd=self.dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        copy = (self.dir / "escaped.redacted.har").read_text(encoding="utf-8")
        self.assertNotIn(cookie, json.dumps(json.loads(copy)))
        self.assertNotIn(raw, copy)


class RedactSameValueTests(unittest.TestCase):
    def test_an_iban_with_and_without_spaces_gets_one_tag(self):
        work = Path(tempfile.mkdtemp(prefix="maisecrets-redact-"))
        try:
            text = "IBAN DE89 3704 0044 0532 0130 00 and DE89370400440532013000\n"
            (work / "t.txt").write_text(text, encoding="utf-8")
            r = _run(SCRIPTS / "redact_copy.py", "t.txt", cwd=work)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            copy = (work / "t.redacted.txt").read_text(encoding="utf-8")
            self.assertEqual(copy.count("⟦IBAN_1⟧"), 2, copy)
            self.assertNotIn("0532", copy)
        finally:
            shutil.rmtree(work, ignore_errors=True)


@unittest.skipUnless(HAS_GIT, "git is needed for the history scan")
class SkillZipTests(unittest.TestCase):
    def test_the_standalone_zip_has_one_skill_root_and_runs_without_the_plugin(self):
        spec = importlib.util.spec_from_file_location("build_skill_zip", ROOT / "scripts" / "build_skill_zip.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        work = Path(tempfile.mkdtemp(prefix="maisecrets-skillzip-"))
        try:
            flat = mod.build(work / "flat.zip", flat=True)
            with zipfile.ZipFile(flat) as z:
                names = z.namelist()
                self.assertIn("name: maisecrets-secret-hygiene\n", z.read("SKILL.md").decode(),
                              "the standalone ChatGPT skill carries the brand in its name")
                self.assertIn("SKILL.md", names, "the ChatGPT upload reads SKILL.md at the zip root")
                self.assertIn("scripts/", names, "directory entries are written")
                self.assertIn("scripts/maisecrets/detect.py", names)
                self.assertIn("scripts/maisecrets/detection/core.py", names)
                # the default ZipInfo mode is 0600 without the directory bit: unzip made folders
                # nobody could enter (found in a Codex test, 2026-09-27)
                import stat
                for info in z.infolist():
                    mode = info.external_attr >> 16
                    with self.subTest(info.filename):
                        if info.filename.endswith("/"):
                            self.assertTrue(stat.S_ISDIR(mode) and mode & 0o755 == 0o755, oct(mode))
                        else:
                            self.assertTrue(stat.S_ISREG(mode) and mode & 0o644 == 0o644, oct(mode))
            if shutil.which("unzip"):
                subprocess.run(["unzip", "-q", str(flat), "-d", str(work / "unzipped")], check=True)
                self.assertTrue((work / "unzipped" / "scripts" / "maisecrets" / "detection" / "rules"
                                 / "betterleaks.json").is_file())
            out = mod.build(work / "secret-hygiene.zip")
            with zipfile.ZipFile(out) as z:
                names = z.namelist()
                self.assertEqual({n.split("/", 1)[0] for n in names}, {"secret-hygiene"})
                self.assertIn("secret-hygiene/", names)
                self.assertIn("secret-hygiene/SKILL.md", names)
                self.assertIn("secret-hygiene/scripts/maisecrets/detect.py", names)
                self.assertIn("secret-hygiene/scripts/maisecrets/detection/rules/betterleaks.json", names)
                self.assertIn("secret-hygiene/scripts/maisecrets/detection/core.py", names)
                # without it the folder loads as a namespace package: the scripts run, the API is gone
                self.assertIn("secret-hygiene/scripts/maisecrets/detection/__init__.py", names)
                self.assertIn("secret-hygiene/scripts/maisecrets/rule_filter.py", names)
                self.assertIn("secret-hygiene/scripts/maisecrets/placeholder.py", names, "the reference form")
                self.assertFalse([n for n in names if "vault" in n or "hooks" in n or "__pycache__" in n], names)
                z.extractall(work / "x")
            repo = work / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")
            token = _token()
            (repo / "config.ini").write_text(f"token = {token}\n", encoding="utf-8")
            # a placeholder of the plugin is no finding of the zipped scanner either (it ships placeholder.py); the
            # same line with a value is one
            ref = chr(0x27E6) + "SECRET" + "_c7" + chr(0x27E7)
            flag = "-" + "u"
            (repo / "run.sh").write_text('cu' + f'rl {flag} "app:{ref}" https://x.test\n', encoding="utf-8")
            (repo / "run2.sh").write_text('cu' + f'rl {flag} "app:Qx7Kp2Lm9Vw4" https://x.test\n', encoding="utf-8")
            r = _run(work / "x" / "secret-hygiene" / "scripts" / "scan_secrets.py", ".", cwd=repo)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("config.ini:1", r.stdout)
            self.assertIn("run2.sh:1", r.stdout, "the premise: the line with a value is a finding")
            self.assertNotIn("run.sh:1", r.stdout, "the placeholder is no finding")
            self.assertNotIn(token, r.stdout + r.stderr)
        finally:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class TranscriptAuditTests(unittest.TestCase):
    """The audit reads agent transcripts, which hold everything a session saw. It must name what
    reached the provider without printing it, and scrub only after a yes."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-audit-"))
        self.claude = self.dir / "claude"
        self.codex = self.dir / "codex"
        self.token, self.other = _token(), _token()
        proj = self.claude / "projects" / "-Users-x-repo"
        proj.mkdir(parents=True)
        rows = [
            {"type": "user", "timestamp": "2026-09-20T10:00:00Z", "message": {"content": f"use {self.token} please"}},
            {"type": "user", "timestamp": "2026-09-21T10:00:00Z",
             "message": {"content": [{"type": "tool_result", "content": f"GITHUB_TOKEN={self.token}"}]}},
            {"type": "attachment", "timestamp": "2026-09-21T10:00:01Z", "attachment": {"type": "hook_success",
                                                                                      "content": self.other}},
        ]
        self.session = proj / "abcdef12-0000.jsonl"
        self.session.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(self.session, (old, old))
        (self.codex / "sessions" / "2026").mkdir(parents=True)
        (self.codex / "sessions" / "2026" / "rollout-x.jsonl").write_text(json.dumps(
            {"type": "response_item", "timestamp": "2026-09-22T09:00:00Z",
             "payload": {"type": "function_call_output", "output": f"token={self.token}"}}) + "\n", encoding="utf-8")
        self.env = dict(_clean_env(), PYTHONUTF8="1", CLAUDE_CONFIG_DIR=str(self.claude), CODEX_HOME=str(self.codex))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def audit(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), *args], capture_output=True,
                              text=True, encoding="utf-8", env=self.env, timeout=120)

    def test_the_report_names_what_reached_the_provider_and_no_value(self):
        r = self.audit()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Reached the AI provider: 1 distinct value(s). Only in local records: 1.", r.stdout)
        row = next(line for line in r.stdout.splitlines() if line.startswith("  S1"))
        self.assertIn("to Anthropic/OpenAI", row)
        self.assertIn("in 2 session(s)", row)
        self.assertIn("prompt", row)
        self.assertIn("tool result", row)
        self.assertIn("2026-09-20..2026-09-22", row)
        for part in (self.token, self.token[4:], self.other, self.other[4:]):
            self.assertNotIn(part, r.stdout + r.stderr)

    def test_scrub_asks_first_then_keeps_every_line_valid_json(self):
        dry = self.audit("--scrub", "--claude")
        self.assertIn("Nothing was changed", dry.stdout)
        self.assertIn(self.token, self.session.read_text(encoding="utf-8"))
        done = self.audit("--scrub", "--yes", "--claude")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        text = self.session.read_text(encoding="utf-8")
        self.assertNotIn(self.token, text)
        self.assertIn("⟦SCRUBBED_S", text)
        for line in text.splitlines():
            json.loads(line)
        self.assertIn("provider keeps what it received", done.stdout)
        self.assertNotIn(self.token, done.stdout)

    def test_scrub_keeps_other_lines_byte_for_byte_and_the_file_mode(self):
        extra = (b'{"type":"system","n":1.0e5}\r\n' + b'not json at all \xff\xfe\n'
                 + ("half line token=" + self.token + "\n").encode())
        with open(self.session, "ab") as fh:
            fh.write(extra)
        os.chmod(self.session, 0o600)
        old = time.time() - 3600
        os.utime(self.session, (old, old))
        report = self.audit("--claude")
        self.assertNotIn(self.token, report.stdout)
        done = self.audit("--scrub", "--yes", "--claude")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        raw = self.session.read_bytes()
        self.assertIn(b'{"type":"system","n":1.0e5}\r\n', raw, "an unchanged line stays byte for byte")
        self.assertIn(b"not json at all \xff\xfe\n", raw)
        self.assertNotIn(self.token.encode(), raw, "a line that is not JSON is cleaned as text")
        if os.name != "nt":   # Windows has no Unix mode bits (windows-latest, 2026-09-27)
            self.assertEqual(self.session.stat().st_mode & 0o777, 0o600)

    def test_a_running_session_is_not_scrubbed(self):
        os.utime(self.session, None)
        self.audit("--scrub", "--yes", "--claude")
        self.assertIn(self.token, self.session.read_text(encoding="utf-8"))


@unittest.skipIf(os.name == "nt", "the fake agent CLIs are shell scripts; the in-process tests below run on Windows")
class ProtectionStatusTests(unittest.TestCase):
    """The skill opens a conversation with this check and offers the install on NOT ACTIVE, so the
    verdict must follow this client's own hook run, and print nothing from the log (Ops and UX
    reviews, 2026-09-27)."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="maisecrets-status-"))
        self.bindir = self.home / "bin"
        self.bindir.mkdir()
        self.fake("python3", "#!/bin/sh\necho 3.12\n")      # the Python the hooks would use

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def fake(self, name: str, body: str) -> None:
        (self.bindir / name).write_text(body, encoding="utf-8")
        (self.bindir / name).chmod(0o755)

    def cli(self, name: str, installed: bool) -> None:
        """A fake agent CLI whose `plugin list --json` answers as the real one does."""
        if name == "codex":
            rows = [{"pluginId": "maisecrets@maisecrets", "enabled": True}] if installed else []
            out = json.dumps({"installed": rows, "available": []})
        else:
            out = json.dumps([{"id": "maisecrets@maisecrets", "enabled": True}] if installed else [])
        self.fake(name, f"#!/bin/sh\ncat <<'EOF'\n{out}\nEOF\n")

    def log(self, seconds_ago: int, event: str = "pre-tool", client: str = "codex", session: str = "S1"):
        import datetime as dt
        when = (dt.datetime.now() - dt.timedelta(seconds=seconds_ago)).isoformat(timespec="seconds")
        with open(self.home / "hooks.log", "a", encoding="utf-8") as f:
            f.write(f"{when}\t{event}\t{client}\t{session}\tBash\tpass\t3ms\tok\n")

    def status(self, **env: str):
        full = {k: v for k, v in _clean_env().items() if not k.startswith("CODEX_") and k != "CLAUDECODE"}
        full.update(MAISECRETS_HOME=str(self.home), PATH=f"{self.bindir}{os.pathsep}/usr/bin:/bin", **env)
        return subprocess.run([sys.executable, str(SCRIPTS / "protection_status.py")], capture_output=True,
                              text=True, env=full, timeout=60)

    def test_this_clients_pre_tool_run_a_moment_ago_is_active_and_nothing_of_the_log_is_printed(self):
        self.log(3, session="session-abc123")
        r = self.status(CODEX_THREAD_ID="t")
        self.assertEqual((r.returncode, r.stdout.splitlines()[0]), (0, "maisecrets protection: ACTIVE for Codex."))
        self.assertNotIn("session-abc123", r.stdout)

    def test_a_run_of_another_client_an_other_event_or_an_old_run_is_not_active(self):
        self.cli("codex", installed=False)
        for why, args in (("another client", dict(client="claude/cli")), ("a prompt, not the tool call",
                          dict(event="user-prompt")), ("two minutes old", dict(seconds_ago=120))):
            with self.subTest(why):
                (self.home / "hooks.log").unlink(missing_ok=True)
                self.log(**{"seconds_ago": 3, **args})
                r = self.status(CODEX_THREAD_ID="t")
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("NOT ACTIVE", r.stdout)

    def test_an_unknown_agent_is_active_only_as_not_confirmed(self):
        self.log(3, client="claude/cli")
        r = self.status()
        self.assertEqual(r.returncode, 0)
        self.assertIn("not confirmed", r.stdout)

    def test_not_active_names_the_commands_of_the_clis_here_and_their_undo(self):
        self.cli("codex", installed=False)
        r = self.status(CODEX_THREAD_ID="t")
        self.assertEqual(r.returncode, 1)
        self.assertIn("codex plugin marketplace add https://github.com/Mcpgate-de/maisecrets.git", r.stdout)
        self.assertIn("codex plugin add maisecrets@maisecrets", r.stdout)
        self.assertIn("Undo: codex plugin remove maisecrets@maisecrets", r.stdout)
        self.assertNotIn("claude plugin", r.stdout, "no Claude Code here, so no Claude Code command")

    def test_an_installed_plugin_whose_hooks_did_not_run_gets_the_last_step_not_an_install(self):
        self.cli("codex", installed=True)
        r = self.status(CODEX_THREAD_ID="t")
        self.assertEqual(r.returncode, 1)
        self.assertIn("installed, but its hooks did not run", r.stdout)
        self.assertIn("type /hooks in the chat box", r.stdout)
        self.assertNotIn("plugin marketplace add", r.stdout)

    def test_without_an_agent_nothing_is_offered(self):
        """A web or mobile chat, or a hosted sandbox: no agent CLI and no agent environment."""
        r = self.status()
        self.assertEqual(r.returncode, 2)
        self.assertIn("NOT AVAILABLE HERE", r.stdout)
        self.assertNotIn("plugin marketplace add", r.stdout)

    def test_inside_an_agent_without_its_cli_on_path_the_app_install_is_named(self):
        r = self.status(CODEX_THREAD_ID="t")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not on this computer's PATH", r.stdout)

    def test_a_timezone_stamp_does_not_crash_the_check(self):
        (self.home / "hooks.log").write_text("2026-09-27T12:00:00+14:00\tpre-tool\tcodex\tS\tBash\n",
                                             encoding="utf-8")
        self.cli("codex", installed=False)
        r = self.status(CODEX_THREAD_ID="t")
        self.assertIn(r.returncode, (0, 1), r.stderr)
        self.assertNotIn("Traceback", r.stderr)


class ProtectionStatusPythonTests(unittest.TestCase):
    """With no Python 3.9+ for the hooks, an install blocks every prompt: nothing is offered."""

    def load(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("protection_status", SCRIPTS / "protection_status.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_an_old_python_everywhere_is_cannot_protect_yet_and_offers_no_install(self):
        mod = self.load()
        old = subprocess.CompletedProcess([], 0, stdout="3.8\n", stderr="")
        with mock.patch.object(mod.shutil, "which", side_effect=lambda n: f"/fake/{n}"), \
                mock.patch.object(mod.subprocess, "run", return_value=old), \
                mock.patch.object(mod, "installed", return_value=False), \
                mock.patch.object(mod, "last_pre_tool", return_value=None), \
                mock.patch.dict(os.environ, {"CODEX_THREAD_ID": "t"}), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(mod.main(), 3)
        self.assertIn("CANNOT PROTECT YET", out.getvalue())
        self.assertNotIn("plugin marketplace add", out.getvalue())

    def test_the_search_follows_run_sh_and_takes_the_first_new_enough_python(self):
        mod = self.load()
        run_sh = (ROOT / "hooks" / "run.sh").read_text(encoding="utf-8")
        for name in mod.PYTHONS:
            self.assertIn(name, run_sh, "the check must search what the launcher searches")
        versions = {"python3": "3.8", "python": "3.12"}

        def run(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, stdout=versions.get(Path(argv[0]).name, "") + "\n", stderr="")
        with mock.patch.object(mod.shutil, "which", side_effect=lambda n: f"/fake/{n}" if n in versions else None), \
                mock.patch.object(mod.subprocess, "run", side_effect=run):
            self.assertEqual(mod.hook_python(), (True, "python 3.12"))

    def test_installed_runs_the_full_path_so_a_cmd_file_works_on_windows(self):
        mod = self.load()
        seen = []

        def run(argv, **kw):
            seen.append(argv[0])
            return subprocess.CompletedProcess(argv, 0, stdout='{"installed": []}', stderr="")
        with mock.patch.object(mod.shutil, "which", return_value="C:/npm/codex.cmd"), \
                mock.patch.object(mod.subprocess, "run", side_effect=run):
            self.assertIs(mod.installed("codex"), False)
        self.assertEqual(seen, ["C:/npm/codex.cmd"])
