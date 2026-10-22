"""The `release` branch holds only the runtime files, and the plugin works from it alone.

Run: python3 -m unittest tests.test_release_tree -v
"""
from __future__ import annotations

import io
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

HAS_GIT = shutil.which("git") is not None and (ROOT / ".git").exists()


def _builder():
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_release_tree", ROOT / "scripts" / "build_release_tree.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(HAS_GIT, "git and a clone are needed")
class ReleaseTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _builder()
        cwd = os.getcwd()
        os.chdir(ROOT)
        try:
            cls.commit = cls.mod.commit("HEAD", None, "test release tree")
            cls.files = subprocess.run(["git", "ls-tree", "-r", "--name-only", cls.commit], capture_output=True,
                                       text=True, check=True).stdout.split()
            data = subprocess.run(["git", "archive", cls.commit], capture_output=True, check=True).stdout
        finally:
            os.chdir(cwd)
        cls.tree = Path(tempfile.mkdtemp(prefix="maisecrets-release-tree-"))
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            if sys.version_info >= (3, 12):
                t.extractall(cls.tree, filter="data")
            else:
                t.extractall(cls.tree)   # our own git archive, not an untrusted tar

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tree, ignore_errors=True)

    # the files the plugin never runs, named here and not taken from the builder: every other tracked
    # file must ship, so a runtime folder missing from the allowlist, or a new file nobody classified,
    # turns this red
    DEV_ONLY_PREFIXES = ("tests/", "scripts/", "harness/", "beliefs/", "bench/", ".github/", ".githooks/", "examples/",
                         # Codex installs from main; the directory held versions over the image refs in it
                         ".codex-plugin/")
    DEV_ONLY_FILES = {".gitlab-ci.yml", ".gitignore", ".gitattributes", ".ci-known-hosts-github", "CONTRIBUTING.md",
                      "CLAUDE.md", "pyproject.toml",
                      "docs/TESTING.md", "docs/REPO-STANDARDS.md", "docs/DIAGNOSTICS.md", "docs/BENCHMARKS.md",
                      "docs/BENCHMARK-V1.md", "docs/BENCHMARK-V2.md", "docs/BENCHMARK-V3.md",
                      "docs/BENCHMARK-V3-DRAFT.md",
                      "docs/NER-EXPERIMENT.md",
                      "docs/DETECTION-SPEC-DRAFT.md", "docs/DETECTION-CONTRACT-PROPOSAL.md",
                      "docs/rule-limits.json", "docs/ratchet-exceptions.json",
                      "docs/REGRESSION-POLICY.md",
                      "renovate.json", "docs/format-watch.txt",
                      # shipped as the tree's README.md (build_release_tree.py, the directory flavor)
                      "docs/DIRECTORY-README.md"}

    def test_every_tracked_file_ships_unless_it_is_named_developer_only(self):
        # the files of the commit the tree was built from; `git ls-files` also lists what is only
        # staged, and a pre-commit run then compared two different sets
        tracked = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD"], capture_output=True, text=True,
                                 check=True, cwd=ROOT).stdout.split("\n")
        # prefixes.txt ships as prefixes.json (build_release_tree.directory_prefixes)
        want = sorted(self.mod.PREFIXES_JSON if p == self.mod.PREFIXES_TXT else p
                      for p in tracked if p and not p.startswith(self.DEV_ONLY_PREFIXES)
                      and p not in self.DEV_ONLY_FILES and not p.endswith("/agents/openai.yaml"))
        self.assertEqual(sorted(self.files), want)

    def test_every_path_the_hooks_commands_and_manifests_name_is_in_the_tree(self):
        texts = [(p, (self.tree / p).read_text(encoding="utf-8")) for p in self.files
                 if p.endswith((".json", ".md", ".yaml")) and (p.startswith(("hooks/", "commands/", ".claude-plugin/",
                                                                              "skills/")))]
        named = set()
        for p, text in texts:
            named |= set(re.findall(r"\$\{CLAUDE_PLUGIN_ROOT\}/([\w./-]+)", text))
            # a relative path in a skill is relative to that skill's folder, elsewhere to the plugin root
            base = "/".join(p.split("/")[:2]) + "/" if p.startswith("skills/") else ""
            named |= {base + m[2:] for m in re.findall(r'"(\./[\w./-]+\.(?:png|svg|json|md|sh|cmd))"', text)}
        self.assertIn("hooks/run.sh", named, "the check must see the hook command")
        for rel in sorted(named):
            with self.subTest(rel):
                self.assertTrue((self.tree / rel).exists(), f"{rel} is named but not shipped")

    def test_the_hooks_block_a_secret_from_the_tree_alone(self):
        home = Path(tempfile.mkdtemp(prefix="maisecrets-release-home-"))
        try:
            (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
            env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
            # a sink for the clipboard copy of the cleaned prompt: pbcopy and xclip on PATH, and
            # MS_TEST_CLIP for tests/_platform_fakes.py on Windows
            sink = home / "bin"
            sink.mkdir()
            for tool in ("pbcopy", "xclip"):
                (sink / tool).write_text("#!/bin/sh\ncat >/dev/null\n", encoding="utf-8")
                (sink / tool).chmod(0o755)
            env.update(MAISECRETS_HOME=str(home), PYTHONUTF8="1", MS_TEST_CLIP=str(home / "clip"),
                       PATH=str(sink) + os.pathsep + env.get("PATH", ""))
            token = "glpat-" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
            payload = json.dumps({"prompt": f"use {token}", "session_id": "S1", "transcript_path": "",
                                  "prompt_id": "p1"})
            r = subprocess.run([sys.executable, str(self.tree / "hooks" / "dispatch.py"), "user-prompt"],
                               input=payload, capture_output=True, text=True, encoding="utf-8", env=env,
                               timeout=60, cwd=str(home))
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out.get("decision"), "block", r.stdout)
            self.assertNotIn(token, r.stdout)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def test_the_tree_ships_the_short_readme_and_the_prefix_rules_as_json(self):
        # the directory blocked 0.7.7 and 0.7.8 with SECRET_IN_SCRIPT in README.md and prefixes.txt (no line named)
        self.assertEqual((self.tree / "README.md").read_text(encoding="utf-8"),
                         (ROOT / "docs" / "DIRECTORY-README.md").read_text(encoding="utf-8"))
        self.assertNotIn(self.mod.PREFIXES_TXT, self.files)
        shipped = json.loads((self.tree / self.mod.PREFIXES_JSON).read_text(encoding="utf-8"))
        lines = [ln.split(None, 1) for ln in (ROOT / self.mod.PREFIXES_TXT).read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.startswith("#")]
        self.assertEqual([(d["id"], d["regex"]) for d in shipped], [(i, r.strip()) for i, r in lines])
        self.assertGreater(len(shipped), 40)

    def test_the_tree_loads_its_prefix_rules_from_the_json(self):
        # a runner token of rules/prefixes.txt is found by the detector of the tree alone, which has no prefixes.txt
        token = "glr" + "t-" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))
        code = ("import sys; sys.path.insert(0, sys.argv[1]);"
                "from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host;"
                "d = Detector(regions=Active(regions=('generic',), languages=('en',), source='t'), sources=NO_SOURCES,"
                " references=NO_REFERENCES, host=Host(user='t', year=2026));"
                "print(','.join(m.kind for m in d.findings(sys.stdin.read(), channel='tool', path='')))")
        r = subprocess.run([sys.executable, "-I", "-c", code, str(self.tree)], input=f"runner {token} here",
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "gitlab-runner-token")

    def test_each_directory_hook_names_one_program_and_nothing_computed(self):
        # the directory refused 0.5.15 and 0.5.16 (UNPINNED_NPX): no variable but the plugin root, no command
        # substitution, no wildcard, no inline program
        tree = json.loads((self.tree / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        # the hooks of the commit the tree was built from (HEAD), not of the working tree: in the pre-commit gate
        # the two differ when the commit changes hooks/hooks.json
        main = json.loads(subprocess.run(["git", "-C", str(ROOT), "show", "HEAD:hooks/hooks.json"],
                                         capture_output=True, text=True, check=True).stdout)
        for event, entries in tree["hooks"].items():
            for i, entry in enumerate(entries):
                for j, h in enumerate(entry["hooks"]):
                    for key in ("command", "commandWindows"):
                        with self.subTest(event=event, key=key):
                            cmd = h[key]
                            rest = cmd.replace("${CLAUDE_PLUGIN_ROOT}", "")
                            self.assertNotRegex(rest, r"[$`*?;&|<>(){}\n]", cmd)
                            self.assertRegex(cmd, r'^(?:bash )?"\$\{CLAUDE_PLUGIN_ROOT\}/hooks/run\.(?:sh|cmd)" '
                                                  r'[\w-]+$')
                    # the same events, matchers and timeouts as main: only the commands differ
                    m = main["hooks"][event][i]
                    self.assertEqual(entry.get("matcher"), m.get("matcher"))
                    self.assertEqual(h["timeout"], m["hooks"][j]["timeout"])
                    self.assertEqual(h["command"].split()[-1], re.search(r'run\.sh" ([\w-]+)',
                                                                          m["hooks"][j]["command"]).group(1))
        self.assertEqual(tree["hooks"].keys(), main["hooks"].keys())

    @unittest.skipIf(os.name == "nt", "the bash form; Windows runs commandWindows")
    def test_the_directory_hook_command_blocks_a_secret(self):
        tree = json.loads((self.tree / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        cmd = tree["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"].replace("${CLAUDE_PLUGIN_ROOT}",
                                                                                   str(self.tree))
        home = Path(tempfile.mkdtemp(prefix="maisecrets-release-home-"))
        try:
            (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
            env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
            sink = home / "bin"   # the clipboard copy of the cleaned prompt goes here, not to a real tool
            sink.mkdir()
            for tool in ("pbcopy", "xclip"):
                (sink / tool).write_text("#!/bin/sh\ncat >/dev/null\n", encoding="utf-8")
                (sink / tool).chmod(0o755)
            env.update(MAISECRETS_HOME=str(home), MS_TEST_CLIP=str(home / "clip"),
                       PATH=str(sink) + os.pathsep + env.get("PATH", ""))
            token = "glpat-" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
            payload = json.dumps({"prompt": f"use {token}", "session_id": "S1", "transcript_path": "",
                                  "prompt_id": "p1"})
            r = subprocess.run(["bash", "-c", cmd], input=payload, capture_output=True, text=True, env=env,
                               timeout=60, cwd=str(home))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout).get("decision"), "block", r.stdout)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def test_no_listing_file_of_the_tree_names_an_image(self):
        # UNREAD_ASSET_REFERENCED: a manifest that names an image file holds every version for a reviewer
        for p in self.files:
            if p.endswith((".json", ".yaml", ".yml")) and not p.startswith("hooks/"):
                with self.subTest(p):
                    image_ref = (r'"?(?:composerIcon|logo|screenshots|icon_small|icon_large)"?\s*:\s*'
                                 r'"[^"]+\.(?:png|jpg|svg)"')
                    self.assertNotRegex((self.tree / p).read_text(encoding="utf-8"), image_ref, p)

    def test_a_commit_continues_the_history_of_its_parent(self):
        cwd = os.getcwd()
        os.chdir(ROOT)
        try:
            child = self.mod.commit("HEAD", self.commit, "second")
            parents = subprocess.run(["git", "rev-list", "--parents", "-n", "1", child], capture_output=True,
                                     text=True, check=True).stdout.split()[1:]
        finally:
            os.chdir(cwd)
        self.assertEqual(parents, [self.commit])


if __name__ == "__main__":
    unittest.main()
