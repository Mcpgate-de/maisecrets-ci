"""A weakening command in a tool call (#84): a Bash call that runs it is refused, a Bash call that only mentions it
passes (hooks._carries, shell_commands.only_mentions). A mention: the text stands in quotes, a heredoc body or a
comment, and each simple command of the line is on the allow list of programs that print, write or store a text
(echo, printf, cat, tee, the data commands of C21, git commit and tag, gh issue and pr comment, create and edit), with
their allowed options. Anything else is a call. A refusal of a text that stands only in data says how to
send it from a file (#104, data_hint). PowerShell has no word parser here and refuses every mention.

Each guard of the same class gets both sides: settings and term removal and the name service (C22, C26), the removal
of an import (C26), not-a-secret (C22) and the demo (C22). The ssh consent sentence (C21, frozen) keeps refusing every
mention.
Run: python3 -m unittest tests.test_mention_is_no_call -v
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks, not_a_secret  # noqa: E402
from maisecrets.shell_commands import DATA_HINT, only_mentions  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

CONFIG = Path(HOME, "config.json")
SESSION = "S1"
NAS = "/maisecrets:" + "not-a-secret"          # built from parts: the hook of the session that edits this file
NAS_CODEX = "maisecrets: " + "not a secret"
KEY = "NAME" + "_c1"
BODY = (f"Thanks for the report. To keep this value unmasked, type {NAS} {KEY} as your own prompt "
        f"(Codex: {NAS_CODEX} {KEY}). Codex users can also run the command in the terminal.")


def setUpModule():  # noqa: N802 - unittest hook
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))


def tearDownModule():  # noqa: N802 - unittest hook
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
    _hygiene.assert_pristine()


def _decision(command: str, tool: str = "Bash", **cfg) -> str:
    if cfg:
        CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **cfg}))
    hooks._live_cache.clear()
    try:
        out = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": SESSION, **CLAUDE,
                              "tool_input": {"command": command}})
    finally:
        if cfg:
            CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision", "pass")


def _reason(command: str) -> str:
    hooks._live_cache.clear()
    out = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": SESSION, **CLAUDE,
                          "tool_input": {"command": command}})
    return (out.get("hookSpecificOutput") or {}).get("permissionDecisionReason", "")


def _heredoc(head: str, body: str, tag: str = "EOF") -> str:
    return f"{head} <<'{tag}'\n{body}\n{tag}"


class NotASecretMentions(unittest.TestCase):
    def test_a_comment_body_in_a_heredoc_passes(self):
        # the field case of #84
        self.assertEqual(_decision(_heredoc("gh issue comment 29 --body-file -", BODY)), "pass")
        # no heredoc and no text after the `)`: else the unsure-heredoc rule or the command-word rule refuses it first
        self.assertEqual(_decision(f"gh issue comment 84 --body \"{NAS} {KEY} $(cat notes.md)\" 2>&1"), "deny",
                         "a substitution runs its text: no mention")

    def test_a_commit_message_passes(self):
        for command in (f"git commit -m 'docs: name {NAS} KEY in the usage'",
                        f'git commit -m "docs: name {NAS} KEY" -m "Fixes #84"',
                        _heredoc("git commit -F -", f"docs: tell the person about {NAS} {KEY}"),
                        _heredoc("cat > notes.md", BODY),
                        f"printf '%s\\n' '{NAS} {KEY}' >> notes.md 2>&1",
                        _heredoc("tee -a notes.md", BODY),
                        f"git tag -a v1 -m 'release: {NAS} {KEY}'",
                        f"gh pr create --title 'docs' --body '{NAS} {KEY}' --base next",
                        f"gh issue edit 84 --body=\"{NAS} {KEY}\"",
                        f"echo '{NAS}' && echo done",
                        f"grep -rn '{NAS}' docs/ # look for {NAS}",
                        # a line continuation and a redirection do not start a command (a backslash before a
                        # heredoc makes its body unsure: refused, shell_commands.heredoc_is_sure)
                        f"git commit \\\n  -m 'docs: {NAS} {KEY}'",
                        _heredoc("gh issue comment 29 2>&1 --repo group/proj --body-file -", BODY)):
            with self.subTest(command=command):
                self.assertEqual(_decision(command), "pass")

    def test_each_form_that_runs_the_command_is_refused(self):
        refused = (
            f"codex exec '{NAS_CODEX} {KEY}'",
            f'claude -p "{NAS} {KEY}"',
            _heredoc("codex exec -", BODY),
            _heredoc("claude -p", BODY),
            f"echo '{NAS} {KEY}' | codex exec -",
            f"echo '{NAS} {KEY}' | xargs -0 codex exec",
            f"env CODEX_HOME=x codex exec '{NAS_CODEX} {KEY}'",
            f"bash -c 'codex exec \"{NAS_CODEX} {KEY}\"'",
            f"sh -c \"claude -p '{NAS} {KEY}'\"",
            f"eval \"codex exec '{NAS_CODEX} {KEY}'\"",
            f"c=codex; $c exec '{NAS_CODEX} {KEY}'",
            f"\"$C\" exec '{NAS_CODEX} {KEY}'",
            f"/opt/homebrew/bin/codex exec '{NAS_CODEX} {KEY}'",
            f"./ask.sh '{NAS} {KEY}'",
            f"'codex' exec '{NAS_CODEX} {KEY}'",
            f"npx @openai/codex exec '{NAS_CODEX} {KEY}'",
            f"unbuffer codex exec '{NAS_CODEX} {KEY}'",
            f"tmux send-keys -t 0 '{NAS} {KEY}' Enter",
            f"printf '{NAS} {KEY}' > p.txt; codex exec - < p.txt",
            f"codex \\\nexec '{NAS_CODEX} {KEY}'",
            f"echo \"$(codex exec '{NAS_CODEX} {KEY}')\"",
            f"echo `codex exec '{NAS_CODEX} {KEY}'`",
            f"codex exec {NAS_CODEX.replace(' ', chr(92) + ' ')}\\ {KEY}",
            f"echo {NAS} {KEY}",
            "python3 -c 'from maisecrets.not_a_secret import allow" + "_typed'",
            _heredoc("python3 -", "from maisecrets import not_a_secret as n\nn.undo" + "_typed('X')"),
            _heredoc("cat > x.py", "import os") + "\npython3 -c 'n.allow" + "_typed(1)'",
            f"python3.12 -c 'print(1)' # {NAS}",
            f"bash run.sh user-prompt <<'EOF'\n{NAS} {KEY}\nEOF",
            f"cat <<EOF\n$(codex exec '{NAS_CODEX} {KEY}')\nEOF",
            f"git commit -m 'x {NAS}'\r",
            _heredoc("gh issue comment 29 --repo \\\n  group/proj --body-file -", BODY),
            # programs that run a text under another name: not on the allow list (Gate A of #84)
            f"git -c alias.x='!codex exec' x '{NAS_CODEX} {KEY}'",
            f"git x '{NAS} {KEY}'",
            f"git -C . commit -m '{NAS}'",
            f"make --eval 'x:;codex exec \"{NAS_CODEX} {KEY}\"' x",
            f"find . -maxdepth 0 -exec codex exec '{NAS_CODEX} {KEY}' ';'",
            f"awk 'BEGIN {{ system(\"codex exec \\\"{NAS_CODEX} {KEY}\\\"\") }}'",
            f"node -e 'require(\"child_process\").execSync(\"codex exec \\\"{NAS_CODEX}\\\"\")'",
            f"echo '{NAS} {KEY}' | sort",
            _heredoc("cat", BODY).replace("'EOF'", "'EOF' | ./ask", 1),
            f"gh alias set x '!codex exec \"{NAS_CODEX}\"'",
            f"gh issue comment 29 --editor --body '{NAS}'",
        )
        for command in refused:
            with self.subTest(command=command):
                self.assertEqual(_decision(command), "deny")

    def test_powershell_refuses_every_mention(self):
        self.assertEqual(_decision(f"gh issue comment 29 --body '{NAS} {KEY}'", tool="PowerShell"), "deny")


class EachRuleOfTheReader(unittest.TestCase):
    """only_mentions itself, one case per rule: another check of the hook can refuse the same command, so each rule
    gets a case that only it decides."""

    def mention(self, command: str) -> bool:
        return only_mentions(command, not_a_secret.in_a_command)

    def test_each_rule(self):
        text = f"'{NAS} {KEY}'"
        calls = {
            "a substitution inside quotes": f'echo {text} "$(codex e x)"',
            "a backtick": f"echo `true` {text}",
            "a carriage return": f"echo {text}\r",
            "the match in the code": f"echo {NAS}",
            "a heredoc after a backslash": _heredoc("echo \\x; gh issue comment 1 --body-file -", NAS),
            "a program off the list": f"ask {text}",
            "a pipe from an allowed program into another": f"echo {text} | ask",
            "the second command off the list": f"echo {text}; ask",
            "a path as the command word": f"/bin/echo {text}",
            "a quoted command word": f"'echo' {text}",
            "a variable as the command word": f"$E {text}",
            "an assignment before the command": f"GIT_EDITOR=ask git commit -m {text}",
            "a git option before the subcommand": f"git -c core.editor=ask commit -m {text}",
            "a git subcommand off the list": f"git notes add -m {text}",
            "a git option off the list": f"git commit --template=x -m {text}",
            "a gh command off the list": f"gh alias set x {text}",
            "a gh verb off the list": f"gh issue develop 1 --name {text}",
            "a gh option off the list": f"gh issue comment 1 --web --body {text}",
            "a bare git": f"git # {NAS}",
            "a signed tag": f"git tag -s v1 -m {text}",
            "a tag signed with a key": f"git tag -u KEYID v1 -m {text}",
            "a tag with --sign": f"git tag --sign v1 -m {text}",
            "a signed commit": f"git commit -S -m {text}",
            "a commit with --gpg-sign": f"git commit --gpg-sign -m {text}",
            "a commit template": f"git commit --template=t.txt -m {text}",
            "a commit through the editor": f"git commit -e -m {text}",
            "a commit with --edit": f"git commit --edit -m {text}",
            "a redirection into a startup file": f"echo {text} >> ~/.bashrc",
            "a redirection into a git hook": _heredoc("cat > .git/hooks/commit-msg", NAS),
            "a redirection into .envrc": f"printf %s {text} > .envrc",
            "tee into the git settings": f"echo {text} | tee -a ~/.gitconfig",
        }
        for why, command in calls.items():
            with self.subTest(why=why):
                self.assertFalse(self.mention(command))
        mentions = {
            "a heredoc body": _heredoc("gh issue comment 29 --body-file -", BODY),
            "a heredoc with a dash and a tab": f"cat > notes.md <<-'EOF'\n\t{NAS}\n\tEOF",
            "a quoted argument": f"git commit -m {text}",
            "a glued value": f"git commit -m{text}",
            "a value after =": f"gh issue comment 1 --body={text}",
            "a quoted option": f"gh issue comment 1 \"--body\" {text}",
            "a data command of C21": f"grep -n {text} docs/USING.md",
            "a redirection with &": f"gh issue comment 29 2>&1 --body-file - <<'EOF'\n{NAS}\nEOF",
            "a redirection before the command": f"2>/dev/null echo {text}",
            "a line continuation": f"git commit \\\n  -m {text}",
            "two allowed commands": f"echo {text} | tee -a notes.md",
            "an annotated tag": f"git tag -a v1 -m {text}",
            "a file next to a startup file": f"echo {text} > docs/bashrc-notes.md",
        }
        for why, command in mentions.items():
            with self.subTest(why=why):
                self.assertTrue(self.mention(command))


class PythonScriptsAndTheDataHint(unittest.TestCase):
    """#104: a Python script that carries a weakening command stays refused, also when it only sends the text to an
    HTTP API: an allow list of Python was too large a surface (an attribute chain reaches os.system, urlretrieve writes
    a file, the working directory comes first on sys.path). When every match stands in data and the line names no
    maisecrets entry point, no maisecrets code, no client and no shell, the refusal says how to send the text as data
    (shell_commands.data_hint): write it to a file with the Write tool and let the command read the file."""

    NER = "/maisecrets " + "ner gateway"
    SETTINGS = "/maisecrets:" + "settings tips off"
    RUN = '"/x/plugins/maisecrets/hooks/run.sh"'

    def script(self, *lines: str) -> str:
        return _heredoc("python3 -", "\n".join(lines))

    def field(self) -> str:
        # the field case of #104: a merge request description sent to an HTTP API
        return self.script("import json, os, urllib.request",
                           f"body = 'choose it with `{self.NER}`'",
                           "req = urllib.request.Request('https://git.example/api/v4/mr', method='PUT',",
                           "    data=json.dumps({'description': body}).encode(),",
                           "    headers={'PRIVATE-TOKEN': os.environ['T'], 'Content-Type': 'application/json'})",
                           "print(urllib.request.urlopen(req).status)")

    def test_a_python_script_with_the_command_is_refused(self):
        text = f"x = '{self.SETTINGS}'"
        refused = (
            self.field(),
            f"python3 -c 'print(\"{self.SETTINGS}\")'",
            # a maisecrets entry point gets the text
            f"bash {self.RUN} entry <<'EOF'\n{self.SETTINGS}\nEOF",
            _heredoc(f"python3 - | bash {self.RUN} user-prompt", f"print('{self.SETTINGS}')"),
            _heredoc(f"python3 {self.RUN.replace('run.sh', 'dispatch.py')} mod-settings", self.SETTINGS),
            "python3 -c 'import maisecrets.settings as s; s.apply" + f"_typed(\"{self.SETTINGS}\")'",
            self.script("from maisecrets import settings", text),
            # the script can start a program, load code or write a file
            self.script("import subprocess", text, "subprocess.run(['codex', 'exec', x])"),
            self.script("import os", text, "os.system('codex exec ' + x)"),
            self.script(text, "__import__('subprocess').run(['claude', '-p', x])"),
            self.script("import os", text, "getattr(os, 'system')(x)"),
            self.script(text, "open('ask.txt', 'w').write(x)"),
            # the ways around the allow list of the reverted python_data_only (review of !657)
            self.script("import os.path", text, "os.path.os.system('ask ' + x)"),
            self.script("import urllib.request", text, "urllib.request.os.system('ask ' + x)"),
            self.script("import typing", text, "typing.sys.modules['os'].system('ask ' + x)"),
            self.script("import urllib.request", text, "urllib.request.urlretrieve('data:,' + x, '/x/.bashrc')"),
            self.script("import json", text, "print(json.dumps(x))"),     # a planted ./json.py would run
            # the line gives the output to another program or a startup file
            f"python3 -c 'x = \"{self.SETTINGS}\"' > ~/.bashrc",
            self.script(text, "print(x)").replace("<<'EOF'", "<<'EOF' | codex exec -", 1),
            # the settings file itself
            _heredoc("cat > ~/.mai" + "secrets/config.json", '{"tips": false}'),
        )
        for command in refused:
            with self.subTest(command=command):
                self.assertEqual(_decision(command), "deny")

    def test_a_text_command_that_only_writes_or_posts_the_text_passes(self):
        for command in (f"printf '%s' 'choose it with {self.NER}' > notes.md",
                        f"gh issue comment 104 --body 'choose it with {self.NER}'",
                        _heredoc("gh issue comment 104 --body-file -", f"choose it with {self.NER}")):
            with self.subTest(command=command):
                self.assertEqual(_decision(command), "pass")

    def test_the_refusal_of_data_names_the_file_route(self):
        text = f"x = '{self.SETTINGS}'"
        for command in (self.field(),
                        f"python3 -c 'print(\"{self.SETTINGS}\")'",
                        self.script("import os.path", text, "os.path.os.system('ask ' + x)"),
                        _heredoc("node -", f"fetch('https://git.example', {{body: '{self.NER}'}})"),
                        f"curl -d 'description=choose it with {self.NER}' https://git.example/api"):
            with self.subTest(command=command):
                self.assertTrue(_reason(command).endswith(DATA_HINT))

    def test_no_file_route_where_the_text_runs(self):
        text = f"x = '{self.SETTINGS}'"
        for why, command in {
            "a maisecrets entry point": f"bash {self.RUN} entry <<'EOF'\n{self.SETTINGS}\nEOF",
            "dispatch.py": _heredoc(f"python3 {self.RUN.replace('run.sh', 'dispatch.py')} x", self.SETTINGS),
            "the maisecrets code": "python3 -c 'import maisecrets.settings as s; s.apply" + "_typed(1)'",
            "a from import of maisecrets": self.script("from maisecrets import settings", text),
            "a module run of maisecrets": f"python3 -m maisecrets '{self.SETTINGS}'",
            "an import of maisecrets": self.script("import maisecrets", text),
            "an attribute of maisecrets": self.script(text, "m = maisecrets.cli"),
            "a client": _heredoc("codex exec -", self.SETTINGS),
            "a client in a script": self.script("import subprocess", text, "subprocess.run(['claude', '-p', x])"),
            "a shell": f"bash -c 'echo \"{self.SETTINGS}\"'",
            "eval": f"eval 'ask \"{self.SETTINGS}\"'",
            "sh": f"sh -c 'echo \"{self.SETTINGS}\"'",
            "zsh": _heredoc("zsh", f"echo '{self.SETTINGS}'"),
            "tmux": f"tmux send-keys '{self.SETTINGS}' Enter",
            "run.cmd": f"cmd /c run.cmd entry '{self.SETTINGS}'",
            "the text in the code": f"ask {self.SETTINGS}",
            "an unquoted heredoc with a substitution": f"ask <<EOF\n{self.SETTINGS} $(date)\nEOF",
            "a carriage return": f"ask '{self.SETTINGS}'\r",
        }.items():
            with self.subTest(why=why):
                reason = _reason(command)
                self.assertTrue(reason.startswith("maisecrets:"), reason)
                self.assertNotIn(DATA_HINT, reason)

    def test_each_guard_of_its_class_gives_the_hint(self):
        for what, text in SiblingGuards.CASES:
            with self.subTest(what=what):
                self.assertTrue(_reason(_heredoc("python3 -", f"print('Type {text} yourself.')")).endswith(DATA_HINT))


class SiblingGuards(unittest.TestCase):
    """The same rule for each guard of a weakening command."""

    CASES = (
        ("settings", "/maisecrets:" + "settings tips off"),
        ("codex settings", "maisecrets: " + "set tips off"),
        ("term removal", "/maisecrets:" + "term remove Alex Example"),
        ("name service", "/maisecrets:" + "ner off"),
        ("import removal", "/maisecrets:" + "forget import:v1234abcd"),
        ("demo", "/maisecrets:" + "demo on"),
        ("writer", "apply" + "_typed"),
    )

    def test_a_mention_passes_and_a_call_is_refused(self):
        for what, text in self.CASES:
            with self.subTest(what=what):
                self.assertEqual(_decision(_heredoc("gh issue comment 29 --body-file -", f"Type {text} yourself.")),
                                 "pass")
                self.assertEqual(_decision(f"git commit -m 'docs: explain {text}'"), "pass")
                self.assertEqual(_decision(_heredoc("codex exec -", text)), "deny")
                self.assertEqual(_decision(f"claude -p '{text}'"), "deny")
                self.assertEqual(_decision(f"bash -c \"echo '{text}' | codex exec -\""), "deny")

    def test_the_ssh_consent_sentence_stays_refused_also_as_a_mention(self):
        # C21 is frozen since 0.6.12: its sentence check keeps the old text match
        sentence = "maisecrets: " + "allow ssh web1"
        self.assertEqual(_decision(_heredoc("gh issue comment 29 --body-file -", f"Type {sentence}."),
                                   ssh_consent=True), "deny")
        self.assertEqual(_decision(f"codex exec '{sentence}'", ssh_consent=True), "deny")


if __name__ == "__main__":
    unittest.main()
