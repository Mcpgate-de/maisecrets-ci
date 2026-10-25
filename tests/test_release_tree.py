"""The release branches hold only the runtime files, and the plugin works from each of them alone.

`release` (directory flavor, the Anthropic directory), `release-claude` (Claude Code) and `release-codex` (Codex, the
plugin under `plugin/`): scripts/build_release_tree.py, docs/REPO-STANDARDS.md "Release branches".

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


def _build(flavor: str):
    """(builder, commit, files, extracted tree) of HEAD in the flavor."""
    mod = _builder()
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        commit = mod.commit("HEAD", None, f"test release tree {flavor}", flavor)
        files = subprocess.run(["git", "ls-tree", "-r", "--name-only", commit], capture_output=True,
                               text=True, check=True).stdout.split()
        data = subprocess.run(["git", "archive", commit], capture_output=True, check=True).stdout
    finally:
        os.chdir(cwd)
    tree = Path(tempfile.mkdtemp(prefix=f"maisecrets-release-tree-{flavor}-"))
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        if sys.version_info >= (3, 12):
            t.extractall(tree, filter="data")
        else:
            t.extractall(tree)   # our own git archive, not an untrusted tar
    return mod, commit, files, tree


def _paths(flavor: str) -> list:
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        return _builder().paths("HEAD", flavor)
    finally:
        os.chdir(cwd)


def _too_big(commit: str, limit: int) -> list:
    sizes = subprocess.run(["git", "ls-tree", "-r", "-l", commit], capture_output=True, text=True,
                           check=True, cwd=ROOT).stdout.splitlines()
    assert len(sizes) > 50, sizes
    return [row.split("\t")[1] for row in sizes if int(row.split()[3]) >= limit]


def _assert_the_hooks_block_and_clean(case: unittest.TestCase, plugin_root: Path) -> None:
    """The user-prompt hook of <plugin_root> blocks a prompt with a token and keeps the cleaned prompt for /ms. The
    cleaned prompt proves that the detector of the tree ran: a hook that cannot import its package blocks too."""
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
        r = subprocess.run([sys.executable, str(plugin_root / "hooks" / "dispatch.py"), "user-prompt"],
                           input=payload, capture_output=True, text=True, encoding="utf-8", env=env,
                           timeout=60, cwd=str(home))
        case.assertEqual(r.returncode, 0, r.stderr)
        case.assertEqual(json.loads(r.stdout).get("decision"), "block", r.stdout)
        case.assertNotIn(token, r.stdout)
        cleaned = home / "pending" / "S1.txt"
        case.assertTrue(cleaned.exists(), "no cleaned prompt: the detector of the tree did not run")
        text = cleaned.read_text(encoding="utf-8")
        case.assertIn("use ", text)
        case.assertNotIn(token, text)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _head(path: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), "show", f"HEAD:{path}"], capture_output=True, text=True,
                          encoding="utf-8", check=True).stdout


@unittest.skipUnless(HAS_GIT, "git and a clone are needed")
class ReleaseTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod, cls.commit, cls.files, cls.tree = _build("directory")

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
                      "docs/format-watch-fp.txt", "docs/format-feeds.txt", "docs/coverage.json",
                      "docs/coverage-rules.txt",
                      "docs/DETECTION-COVERAGE.md",
                      # shipped as the tree's README.md (build_release_tree.py, the directory flavor)
                      "docs/DIRECTORY-README.md",
                      # design documents, read on GitHub; nothing at run time opens them (0.7.19)
                      "docs/CLIENTS.md", "docs/PROTOCOL.md", "docs/THREAT-MODEL.md", "docs/label-sources.md",
                      "docs/DETECTION.md",
                      # the rule source of betterleaks.json; the detector reads only the JSON
                      "maisecrets/detection/rules/betterleaks.toml"}

    def test_every_tracked_file_ships_unless_it_is_named_developer_only(self):
        # the files of the commit the tree was built from; `git ls-files` also lists what is only
        # staged, and a pre-commit run then compared two different sets
        tracked = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD"], capture_output=True, text=True,
                                 check=True, cwd=ROOT).stdout.split("\n")
        # prefixes.txt ships as prefixes.json (build_release_tree.directory_prefixes)
        want = [self.mod.PREFIXES_JSON if p == self.mod.PREFIXES_TXT else p
                for p in tracked if p and not p.startswith(self.DEV_ONLY_PREFIXES)
                and p not in self.DEV_ONLY_FILES and not p.endswith("/agents/openai.yaml")]
        # betterleaks.json ships as betterleaks.part1.json, part2, … (build_release_tree.directory_betterleaks)
        want.remove(self.mod.BETTERLEAKS_JSON)
        parts = [p for p in self.files if re.fullmatch(r"maisecrets/detection/rules/betterleaks\.part\d+\.json", p)]
        self.assertGreaterEqual(len(parts), 2)
        self.assertEqual(sorted(self.files), sorted(want + parts))

    def test_every_file_is_small_enough_for_the_directory_to_read(self):
        # the directory reads a file only up to a size between 207 KB (read) and 271 KB (BINARIES_NOT_INSPECTED,
        # 0.7.17 to 0.7.19), and then holds the version; docs/REPO-STANDARDS.md, "What the directory flags"
        self.assertEqual(_too_big(self.commit, self.mod.FILE_BYTES), [])

    def test_the_betterleaks_parts_load_the_same_rules_and_ship_no_key(self):
        # the directory held every version whose betterleaks.json it could not read whole; the parts are each under
        # PART_BYTES, the release detector loads the same rules from them, and the gcp-api-key allow list decides the
        # same keys from their sha256, so no part holds a key (SECRET_IN_SCRIPT)
        rules_dir = self.tree / "maisecrets" / "detection" / "rules"
        parts = sorted(rules_dir.glob("betterleaks.part*.json"))
        self.assertGreaterEqual(len(parts), 2)
        self.assertFalse((rules_dir / "betterleaks.json").exists())
        for p in parts:
            # the blob the directory gets, not the file on disk: git archive on Windows writes CRLF
            size = subprocess.run(["git", "cat-file", "-s", f"{self.commit}:{p.relative_to(self.tree).as_posix()}"],
                                  capture_output=True, text=True, check=True, cwd=ROOT).stdout.strip()
            self.assertLess(int(size), self.mod.PART_BYTES)
        keys = re.compile(r"AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[abprs]-[0-9]{6,}")
        self.assertEqual([p.name for p in parts if keys.search(p.read_text(encoding="utf-8"))], [])
        main = json.loads((ROOT / self.mod.BETTERLEAKS_JSON).read_text(encoding="utf-8"))
        listed = re.findall(r"`(AIza[0-9A-Za-z_-]{35})`", next(r["filter"] for r in main["rules"]
                                                               if r["id"] == "gcp-api-key"))
        self.assertEqual(len(listed), 16)
        probe = ("import json, sys\n"
                 "from maisecrets.detection import core, rule_filter\n"
                 "cfg = core.betterleaks_config()\n"
                 "f = rule_filter.compile_filter(next(r['filter'] for r in cfg['rules'] if r['id'] == 'gcp-api-key'))\n"
                 "keys = json.loads(sys.stdin.read())\n"
                 "print(json.dumps({'ids': [r.id for r in core._load_betterleaks()],\n"
                 "                  'drops': [f({'secret': k}) for k in keys]}))\n")
        # a key of the same shape that is not listed, made at run time so the test file holds none: kept
        other = "AIza" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(35))
        results = []
        for root in (self.tree, ROOT):
            r = subprocess.run([sys.executable, "-c", probe], input=json.dumps(listed + [other]), capture_output=True,
                               text=True, cwd=root, env={**os.environ, "PYTHONPATH": str(root)})
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            results.append(json.loads(r.stdout))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]["drops"], [True] * 16 + [False])

    def test_no_hook_command_points_into_the_folder_of_the_mod_or_of_the_hooks_file_that_names_it(self):
        # the directory holds a version when it "couldn't confirm that the mod stays the same": the mod's files and
        # the hooks file that names it must lie in folders that no command points at. 0.7.15 declared the mod in
        # hooks/hooks.json, beside hooks/run.sh and run.cmd that every hook command names, and got that hold
        manifest = json.loads((self.tree / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        candidates = [manifest["hooks"].lstrip("./")] if isinstance(manifest.get("hooks"), str) else []
        mod_hooks_file = next(p for p in candidates + ["hooks/hooks.json"]
                              if json.loads((self.tree / p).read_text(encoding="utf-8")).get("modules"))
        mods = json.loads((self.tree / mod_hooks_file).read_text(encoding="utf-8"))["modules"]
        guarded = {Path(mod_hooks_file).parent.as_posix()}
        guarded |= {(self.tree / Path(mod_hooks_file).parent / m).resolve().parent.relative_to(self.tree.resolve())
                    .as_posix() for m in mods}
        commands = []
        for p in self.files:
            if p.endswith("hooks.json") or p == mod_hooks_file:
                for entries in (json.loads((self.tree / p).read_text(encoding="utf-8")).get("hooks") or {}).values():
                    commands += [h.get(k, "") for e in entries for h in e.get("hooks", [])
                                 for k in ("command", "commandWindows")]
        self.assertTrue(commands, "the tree has classic hook commands")
        pointed = {m.split("/")[0] for c in commands for m in re.findall(r"CLAUDE_PLUGIN_ROOT\}/([\w./-]+)", c)}
        self.assertEqual(guarded & pointed, set(), f"commands point at {pointed}, the mod lies in {guarded}")

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
        _assert_the_hooks_block_and_clean(self, self.tree)

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

    def test_the_json_entry_point_of_the_tree_gives_the_ruleset_of_the_checkout(self):
        # the tree has betterleaks parts with hashed allow lists and prefixes.json: the digest is over the loaded
        # rules, so both name the same ruleset (docs/DETECTION.md, "The JSON entry point")
        request = json.dumps({"contract": "maisecrets.detect/1", "text": "runner glrt-" + "x" * 3, "channel": "tool",
                              "regions": ["generic", "de", "us"], "languages": ["en", "de"]}).encode()
        out = []
        for root in (ROOT, self.tree):
            r = subprocess.run([sys.executable, "-m", "maisecrets.detection"], input=request, cwd=str(root),
                               capture_output=True, timeout=60,
                               env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
            self.assertEqual((r.returncode, r.stderr), (0, b""))
            out.append(json.loads(r.stdout)["engine"])
        self.assertEqual(out[0], out[1])

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
                    self.assertEqual(h.get("statusMessage"), m["hooks"][j].get("statusMessage"))
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


@unittest.skipUnless(HAS_GIT, "git and a clone are needed")
class ClaudeTreeTests(unittest.TestCase):
    """`release-claude`: the runtime files of the tag with its own hooks and README; Claude Code installs from it."""

    @classmethod
    def setUpClass(cls):
        cls.mod, cls.commit, cls.files, cls.tree = _build("claude")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tree, ignore_errors=True)

    def test_the_tree_is_the_runtime_files_with_the_hooks_and_readme_of_main(self):
        # the runtime folders named here, not taken from the builder: the developer files stay out, the Codex
        # metadata too, and betterleaks.json ships in parts (FILE_BYTES); every other file is the tag's own
        tracked = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD"], capture_output=True, text=True,
                                 check=True, cwd=ROOT).stdout.split("\n")
        runtime = (".claude-plugin/", "hooks/", "claude-mod/", "maisecrets/", "commands/", "skills/", "assets/")
        top = {"LICENSE", "NOTICE", "README.md", "PRIVACY.md", "SECURITY.md", "CHANGELOG.md"}
        want = [p for p in tracked if (p.startswith(runtime) or p in top) and not p.endswith("/agents/openai.yaml")
                and p not in (self.mod.BETTERLEAKS_JSON, "maisecrets/detection/rules/betterleaks.toml")]
        parts = [p for p in self.files if re.fullmatch(r"maisecrets/detection/rules/betterleaks\.part\d+\.json", p)]
        self.assertGreaterEqual(len(parts), 2)
        self.assertEqual(sorted(self.files), sorted(want + parts))
        self.assertIn(self.mod.PREFIXES_TXT, self.files)
        for path in ("hooks/hooks.json", "README.md", ".claude-plugin/plugin.json"):
            with self.subTest(path):
                self.assertEqual((self.tree / path).read_text(encoding="utf-8"), _head(path))

    def test_every_file_is_under_the_size_limit(self):
        self.assertEqual(_too_big(self.commit, self.mod.FILE_BYTES), [])

    def test_the_hooks_block_a_secret_from_the_tree_alone(self):
        _assert_the_hooks_block_and_clean(self, self.tree)


@unittest.skipUnless(HAS_GIT, "git and a clone are needed")
class CodexTreeTests(unittest.TestCase):
    """`release-codex`: the claude tree plus `.codex-plugin/` and the skills' Codex metadata, under `plugin/`.
    Without `.codex-plugin/` Codex reads `.claude-plugin/plugin.json`, whose `hooks` names the mod file, and loads no
    hook and says nothing (`harness/codex.py --tree codex` runs the hooks of this tree in a real Codex)."""

    @classmethod
    def setUpClass(cls):
        cls.mod, cls.commit, cls.files, cls.tree = _build("codex")
        cls.root = cls.tree / "plugin"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tree, ignore_errors=True)

    def test_the_tree_is_the_claude_tree_and_the_codex_files_under_plugin(self):
        tracked = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD"], capture_output=True, text=True,
                                 check=True, cwd=ROOT).stdout.split("\n")
        codex_only = [p for p in tracked if p.startswith(".codex-plugin/") or p.endswith("/agents/openai.yaml")]
        self.assertIn(".codex-plugin/plugin.json", codex_only)
        self.assertEqual(sorted(self.files), sorted("plugin/" + p for p in _paths("claude") + codex_only))

    def test_the_codex_manifest_lets_codex_read_the_hooks_file(self):
        manifest = json.loads((self.root / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        # Codex reads hooks/hooks.json only while the manifest defines no hooks key (docs/REPO-STANDARDS.md)
        self.assertNotIn("hooks", manifest)
        self.assertEqual((self.root / "hooks" / "hooks.json").read_text(encoding="utf-8"), _head("hooks/hooks.json"))
        named = re.findall(r'"(\./[\w./-]+)"', json.dumps(manifest))
        self.assertIn("./skills/", named)
        for rel in named:
            with self.subTest(rel):
                self.assertTrue((self.root / rel).exists(), f"{rel} is named by .codex-plugin/plugin.json")
        metas = sorted(self.root.glob("skills/*/agents/openai.yaml"))
        self.assertTrue(metas)
        for meta in metas:
            for rel in re.findall(r'"(\./[\w./-]+)"', meta.read_text(encoding="utf-8")):
                with self.subTest(meta.parent.parent.name, rel=rel):
                    self.assertTrue((meta.parent.parent / rel).exists(), f"{rel} is named by {meta}")

    def test_every_file_is_under_the_size_limit(self):
        self.assertEqual(_too_big(self.commit, self.mod.FILE_BYTES), [])

    def test_the_hooks_block_a_secret_from_the_plugin_folder_alone(self):
        _assert_the_hooks_block_and_clean(self, self.root)


class HookStatusMessageTests(unittest.TestCase):
    def test_every_hook_says_what_maisecrets_does(self):
        # the client shows it while the hook runs; Codex counts it in the declaration the person approves
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
        handlers = [(event, h) for event, groups in hooks.items() for g in groups for h in g["hooks"]]
        self.assertGreaterEqual(len(handlers), 5)
        for event, h in handlers:
            with self.subTest(event):
                self.assertRegex(h.get("statusMessage", ""), r"^maisecrets [a-z]")


if __name__ == "__main__":
    unittest.main()
