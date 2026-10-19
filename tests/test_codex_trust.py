"""Codex runs a plugin hook only while the trust the person gave it still matches the hook.

Codex keeps `trusted_hash` per hook in config.toml and compares it with a hash of the hook as it is now
(codex-rs hooks/src/engine/discovery.rs, hook_hash). A different hash makes the hook "Modified", and a modified
hook does not run, with no message, until the person trusts it again; the ChatGPT app has no screen for that. The
hash covers the command text of the platform (commandWindows on Windows), the timeout and the matcher. The
recomputation (maisecrets/codex_trust.py) matched the hashes in two real config.toml files (macOS and Windows,
2026-09-30) and the hash Codex 0.164.0-alpha.4 gave for a fixture plugin (2026-10-19).

From Codex 0.164 on, the trust also covers the contents of the plugin folder (`trusted_content_hash`,
openai/codex#54619): each maisecrets update asks again, and a file the plugin writes into its own folder switches
its hooks off at once (measured: the next prompt with a token reached the model). /maisecrets:status says which.

So a change to a command or a matcher in hooks/hooks.json switches maisecrets off for every Codex user before 0.164.
If the change is meant, update the hashes here and say in the CHANGELOG that Codex users must trust the hooks again.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from maisecrets import codex_trust

ROOT = Path(__file__).resolve().parent.parent
# events Codex does not have: it skips them and loads the others (PostToolUseFailure, measured with codex-cli 0.159.2:
# harness/codex.py passed with it in hooks.json), so they carry no trust
NOT_IN_CODEX = {"PostToolUseFailure"}

# the hashes Codex stored when people trusted the hooks of 0.5.16 to 0.5.23 (posix) and 0.5.15 to 0.5.23 (windows)
TRUSTED = {
    "posix": {
        "session_start": "sha256:192782bd8413e5789b44fe8980e1170ce3bc76606dd1163ad8db243154c22447",
        "user_prompt_submit": "sha256:db3cb30fdc83870f43e5452b1abca1ddd76833eb0637c3ee44ee3cea6baf0626",
        "pre_tool_use": "sha256:6b1daad7c27b49db322e7fadcf59993a29e8c38ba6a691e300616719b73ba6e6",
        "post_tool_use": "sha256:da89673d4eba379ff9959005f328f139f446bc5ce2af4b1aada695bae906bc3d",
    },
    "windows": {
        "session_start": "sha256:5c887c5fb89ef7438e8c3b8b8aa61ad7f6a58d474d59e0aacfba6d01e16229e7",
        "user_prompt_submit": "sha256:0ce6f3cc3c1893e7ef41d95931a6fbad9ef960afdef7f8647a71316ed02e689e",
        "pre_tool_use": "sha256:0faee6bbf9d8d04cc2a426b28bded5badcda126dddfe189c0c9f8e97a38b22ad",
        "post_tool_use": "sha256:752908c82411d878240a3044702b5508118d7e9cb29028632a18ed8693031505",
    },
}

# a fixture plugin and the two hashes codex-cli 0.164.0-alpha.4 gave for it in hooks/list (currentHash
# "<declaration>/<contents>", 2026-10-19): upper case sorts first, bytecode is left out, an empty file counts
FIXTURE = {
    ".claude-plugin/marketplace.json": json.dumps({"name": "fxm", "owner": {"name": "t"}, "plugins": [
        {"name": "fx", "source": "./", "description": "fixture", "version": "1.0.0"}]}),
    ".codex-plugin/plugin.json": json.dumps({"name": "fx", "version": "1.0.0", "description": "fixture"}),
    "hooks/hooks.json": json.dumps({"hooks": {"UserPromptSubmit": [
        {"hooks": [{"type": "command", "command": "true", "timeout": 5}]}]}}),
    "B.txt": "upper\n",
    "a/b.txt": "nested\n",
    "a/__pycache__/c.pyc": "excluded\n",
    "empty": "",
}
FIXTURE_DECLARATION = "sha256:e730d6c05679736eaccc5349f8aa92ec34ebd81c0a29da55459ab65ebced4952"
FIXTURE_CONTENTS = "sha256:da1aaf212af5a401d5f881a2064ae182309936af54f0fd6069ce23e2eee3d477"
# the same fixture on windows-latest, codex-cli 0.164.0-alpha.4 (harness/codex_trust_probe.py, 2026-10-19): Codex
# spells the relative paths with "\\" there
FIXTURE_CONTENTS_WINDOWS = "sha256:d0f73e3e4b2efac73ea2f649f0ae78db7c431c45c6e5250241ccf5ed248dd74b"

# hook groups added after the trust above: Codex treats each as a new hook that needs its own trust, while the groups
# above keep theirs (an added group changes no hash of another). apply_patch by its own name (0.6.40): Codex
# 0.163.0-alpha on Windows maps it to no alias of the first group (field report, 2026-10-19). A group of its own and
# not a change of the first matcher: that would make the whole PreToolUse hook "Modified" on Codex 0.163 and older, and
# it would protect no tool until the person trusts it again. Where Codex maps apply_patch to Write or Edit, both groups
# run on it (measured on codex-cli 0.163.0, macOS: two equal rewrites, two audit lines).
ADDED_GROUPS = {("PreToolUse", "apply_patch")}


def codex_hashes(platform: str) -> dict:
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    out = {}
    for event, groups in hooks.items():
        if event in NOT_IN_CODEX:
            continue
        for g in groups:
            if (event, g.get("matcher")) in ADDED_GROUPS:
                continue
            out[codex_trust.EVENTS[event]] = codex_trust.declaration_hash(event, g, g["hooks"][0],
                                                                          platform == "windows")
    return out


def write_fixture(root: Path) -> None:
    for name, text in FIXTURE.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(text)


class CodexTrustTests(unittest.TestCase):
    def test_an_added_group_is_still_in_hooks_json(self):
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
        groups = {(e, g.get("matcher")) for e, gs in hooks.items() for g in gs}
        self.assertLessEqual(ADDED_GROUPS, groups, "an added group named here is gone from hooks.json")

    def test_the_hook_commands_keep_the_trust_codex_users_gave(self):
        for platform, want in TRUSTED.items():
            with self.subTest(platform):
                self.assertEqual(codex_hashes(platform), want,
                                 "a hook command changed: every Codex user's maisecrets hooks stop running until "
                                 "they trust them again (see the docstring)")

    def test_the_recipe_gives_the_hashes_codex_gave_for_the_fixture(self):
        root = Path(tempfile.mkdtemp(prefix="maisecrets-codex-fixture-"))
        self.addCleanup(shutil.rmtree, root, True)
        write_fixture(root)
        group = json.loads(FIXTURE["hooks/hooks.json"])["hooks"]["UserPromptSubmit"][0]
        self.assertEqual(codex_trust.declaration_hash("UserPromptSubmit", group, group["hooks"][0], False),
                         FIXTURE_DECLARATION)
        self.assertEqual(codex_trust.content_hash(root, windows=False), FIXTURE_CONTENTS)
        self.assertEqual(codex_trust.content_hash(root, windows=True), FIXTURE_CONTENTS_WINDOWS)
        self.assertEqual(codex_trust.content_hash(root),
                         FIXTURE_CONTENTS_WINDOWS if os.name == "nt" else FIXTURE_CONTENTS)

    def test_a_python_without_tomllib_says_unknown(self):
        # runs on every Python: the 3.9 and 3.10 the plugin supports have no tomllib
        home = Path(tempfile.mkdtemp(prefix="maisecrets-codex-home-"))
        self.addCleanup(shutil.rmtree, home, True)
        root = home / "plugins" / "cache" / "fxm" / "fx" / "1.0.0"
        write_fixture(root)
        with mock.patch.object(codex_trust, "_load_toml", return_value=None):
            self.assertEqual(codex_trust.status_lines(root, home),
                             ["codex hooks: unknown (needs Python 3.11 or newer to read Codex's config.toml)"])


class CodexTrustStatusTests(unittest.TestCase):
    """/maisecrets:status reads Codex's config.toml and says whether Codex runs the hooks of this folder."""

    def setUp(self):
        try:
            import tomllib  # noqa: F401
        except ImportError:
            self.skipTest("tomllib is Python 3.11+")
        self.home = Path(tempfile.mkdtemp(prefix="maisecrets-codex-home-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.root = self.home / "plugins" / "cache" / "fxm" / "fx" / "1.0.0"
        write_fixture(self.root)

    def config(self, state: dict | None, extra: str = "") -> None:
        text = '[plugins."fx@fxm"]\nenabled = true\n' + extra
        for key, entry in (state or {}).items():
            text += f'[hooks.state."{key}"]\n' + "".join(f'{k} = "{v}"\n' for k, v in entry.items())
        (self.home / "config.toml").write_text(text, encoding="utf-8")

    def lines(self) -> str:
        return "\n".join(codex_trust.status_lines(self.root, self.home, windows=False))

    KEY = "fx@fxm:hooks/hooks.json:user_prompt_submit:0:0"

    def test_trusted_for_these_contents(self):
        self.config({self.KEY: {"trusted_hash": FIXTURE_DECLARATION,
                                "trusted_content_hash": codex_trust.content_hash(self.root, windows=False)}})
        self.assertEqual(self.lines(), "codex hooks: trusted (1 of 1)")

    def test_a_file_written_into_the_folder_is_a_change_codex_skips_the_hooks_for(self):
        self.config({self.KEY: {"trusted_hash": FIXTURE_DECLARATION,
                                "trusted_content_hash": codex_trust.content_hash(self.root, windows=False)}})
        (self.root / "hooks" / "last-start.txt").write_text("x")
        self.assertIn("trusted for other contents", self.lines())
        self.assertIn("open /hooks", self.lines())

    def test_bytecode_is_no_change(self):
        self.config({self.KEY: {"trusted_hash": FIXTURE_DECLARATION,
                                "trusted_content_hash": codex_trust.content_hash(self.root, windows=False)}})
        (self.root / "hooks" / "__pycache__").mkdir()
        (self.root / "hooks" / "__pycache__" / "x.cpython-312.pyc").write_text("x")
        self.assertEqual(self.lines(), "codex hooks: trusted (1 of 1)")

    def test_no_trust_and_another_declaration_are_not_trusted(self):
        self.config(None)
        self.assertIn("1 of 1 not trusted", self.lines())
        self.config({self.KEY: {"trusted_hash": "sha256:" + "0" * 64}})
        self.assertIn("1 of 1 not trusted", self.lines())

    def test_on_windows_the_contents_are_checked_with_its_own_spelling(self):
        self.config({self.KEY: {"trusted_hash": FIXTURE_DECLARATION,
                                "trusted_content_hash": FIXTURE_CONTENTS_WINDOWS}})
        lines = "\n".join(codex_trust.status_lines(self.root, self.home, windows=True))
        self.assertEqual(lines, "codex hooks: trusted (1 of 1)")
        self.config({self.KEY: {"trusted_hash": FIXTURE_DECLARATION, "trusted_content_hash": FIXTURE_CONTENTS}})
        self.assertIn("trusted for other contents",
                      "\n".join(codex_trust.status_lines(self.root, self.home, windows=True)))

    def test_an_old_approval_is_trusted_until_codex_pins_it(self):
        self.config({self.KEY: {"trusted_hash": FIXTURE_DECLARATION}})
        self.assertIn("an approval from before Codex 0.164", self.lines())
        # Codex 0.164 pinned it to the contents of its first run (.hook-trust, named by config.toml and plugin id;
        # the name matched the file codex-cli 0.164.0-alpha.4 wrote, 2026-10-19)
        import hashlib
        import struct
        h = hashlib.sha256()
        for part in (os.fsencode(os.path.realpath(self.home / "config.toml")), b"fx@fxm"):
            h.update(struct.pack("<Q", len(part)) + part)
        (self.home / ".hook-trust").mkdir()
        (self.home / ".hook-trust" / h.hexdigest()).write_text(codex_trust.content_hash(self.root, windows=False))
        self.assertEqual(self.lines(), "codex hooks: trusted (1 of 1)")
        (self.root / "B.txt").write_text("changed")
        self.assertIn("trusted for other contents", self.lines())

    def test_another_maisecrets_install_is_named(self):
        self.root = self.home / "plugins" / "cache" / "maisecrets" / "maisecrets" / "0.6.40"
        write_fixture(self.root)
        self.config(None, '[plugins."maisecrets@old"]\nenabled = true\n[plugins."maisecrets@maisecrets"]\n'
                          'enabled = true\n')
        self.assertIn("another maisecrets is installed too (maisecrets@old)", self.lines())

    def test_a_folder_codex_did_not_install_gets_no_line(self):
        self.config(None)
        self.assertEqual(codex_trust.status_lines(ROOT, self.home), [])


if __name__ == "__main__":
    unittest.main()
