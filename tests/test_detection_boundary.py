"""The boundary of the detection core: what the rest of maisecrets may use of detect.py, and what a plain scan imports.

The core is the form-independent detector: __init__, detect, checksums, lazy_regex, normalise, regions, registry,
rulespec, rule_filter and personal. The standalone skill (scripts/build_skill_zip.py) ships it without personal.py
and with placeholder.py, the plugin's reference form. The plugin called private names of detect.py from
hooks, the value check and the rules of your own, so a change inside the core could break a caller it does not know.
These tests hold the line: a module outside the core uses detect only by its public names (the facade at the end of
detect.py), in the forms that private_uses() names, and a plain detect.scan() or findings() imports no module of the
plugin beyond the ones it imports today. That list may only get shorter.

Run: python3 -m unittest tests.test_detection_boundary -v
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import io
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

# the modules of the detection core (maisecrets/detection/) and the names of maisecrets.* that are the same module
# objects (maisecrets/detect.py and the others: compatibility names)
CORE_MODULES = ("checksums", "lazy_regex", "normalise", "regions", "registry", "rulespec", "rule_filter", "personal")
# the parts of core.py in modules of their own (they have no old name)
CORE_PARTS = ("value_checks", "own_rules", "text_index", "encoded_mail")
CORE = frozenset({"__init__", "detect", "detection", "detection.core", *CORE_MODULES,
                  *(f"detection.{m}" for m in CORE_MODULES + CORE_PARTS)})
# the modules of the plugin that a plain scan still imports. Each is a later step: the config read for the regions
# (home, through active_regions), the rules of your own and the allow list (user_rules), and the probes for a term
# list or an import (term_files, value_files). Remove a name when the scan no longer imports it; never add one. The
# exceptions so far: home.py took the file and config helpers out of vault.py (2026-10-18), and with it vault and
# placeholder left the scan; sources.py holds the plugin's readers that detect.py had (the default sources);
# placeholder.py came back as the default reference form (2026-10-18), which detect.py no longer knows itself. A
# scan that is given its regions, its sources and its references imports none of these (ReferencesTests).
NOT_YET_OUT = frozenset({"home", "placeholder", "sources", "term_files", "user_rules", "value_files"})
# a scan never imports the store, also with a term list and an import of values in place
NEVER = frozenset({"vault", "rehydration", "vault_refs", "hooks", "settings"})


def private_uses(source: str) -> list[tuple[int, str]]:
    """(line, name) of every private name of detect that a module uses in one of these forms. A module expression is
    a name bound to detect (`detect`; `import maisecrets.detect as d`; `from . import detect as d`; `d = <module
    expression>` or `d: T = <module expression>`, also chained) or `maisecrets.detect`. A use is an attribute
    `<module expression>._x`, a literal `getattr(<module expression>, "_x")`, `from .detect import _x`, or a string
    that starts with `detect._` or `maisecrets.detect._` (an annotation). Other forms, such as a name built at run time
    (`getattr(d, name)`) or a binding through a function call, are out of its reach: the test guards against an
    ordinary use, not against one that hides."""
    tree = ast.parse(source)
    names = {"detect"}
    packages: set = (
        set()
    )  # names bound to the package maisecrets.detection, whose `.core` is the core

    def ours(node, sub: str) -> bool:
        """An import from maisecrets.<sub>: absolute, or relative inside the plugin (`from .<sub>`, `from . import`)."""
        module = node.module or ""
        return module == ("maisecrets." + sub).rstrip(".") or (
            node.level >= 1 and module == sub
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {
                a.asname
                for a in node.names
                if a.asname
                and a.name in ("maisecrets.detect", "maisecrets.detection.core")
            }
            packages |= {
                a.asname
                for a in node.names
                if a.asname and a.name == "maisecrets.detection"
            }
        elif isinstance(node, ast.ImportFrom):
            names |= {
                a.asname or a.name
                for a in node.names
                if (a.name == "detect" and ours(node, ""))
                or (a.name == "core" and ours(node, "detection"))
            }
            packages |= {
                a.asname or a.name
                for a in node.names
                if a.name == "detection" and ours(node, "")
            }
    # no `names -= packages`: the walk does not see scopes, so a name bound to both (`d` as the module at the top, as
    # the package in a function) stays in both, and each of its uses is checked in both forms

    def is_package(e) -> bool:
        return (isinstance(e, ast.Name) and e.id in packages) or (
            isinstance(e, ast.Attribute) and e.attr == "detection" and isinstance(e.value, ast.Name)
            and e.value.id == "maisecrets")

    def is_module(e) -> bool:
        return (isinstance(e, ast.Name) and e.id in names) or (
            isinstance(e, ast.Attribute) and e.attr == "detect" and isinstance(e.value, ast.Name)
            and e.value.id == "maisecrets") or (
            isinstance(e, ast.Attribute) and e.attr == "core" and is_package(e.value))

    for _ in range(3):   # d = detect, then e = d (also p = detection, then c = p.core)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                bound = {t.id for t in targets if isinstance(t, ast.Name)}
                if is_package(node.value):
                    packages |= bound
                if is_module(node.value):
                    names |= bound
    def private(name) -> bool:   # `__name__` and the other dunders are not private names of the core
        name = str(name)
        return name.startswith("_") and not (name.startswith("__") and name.endswith("__"))

    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and private(node.attr) and is_module(node.value):
            out.append((node.lineno, node.attr))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" \
                and len(node.args) >= 2 and is_module(node.args[0]) and isinstance(node.args[1], ast.Constant) \
                and private(node.args[1].value):
            out.append((node.lineno, node.args[1].value))
        elif isinstance(node, ast.ImportFrom) and (
            ours(node, "detect") or ours(node, "detection.core")
        ):
            out += [(node.lineno, a.name) for a in node.names if private(a.name)]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith(
                ("detect._", "maisecrets.detect._", "detection.core._", "maisecrets.detection.core._")):
            out.append((node.lineno, node.value))   # a string such as an annotation: "detect._Lazy"
    return sorted(set(out))


def outside_the_core() -> list[Path]:
    detection = ROOT / "maisecrets" / "detection"
    return sorted([p for p in (ROOT / "maisecrets").rglob("*.py") if not (
        (p.parent.name == "maisecrets" and p.stem in CORE) or detection in p.parents)]
                  + list((ROOT / "hooks").rglob("*.py")))


class DetectionBoundaryTests(unittest.TestCase):
    def test_the_checker_sees_each_form_of_a_private_use_and_passes_a_public_one(self):
        # the vocabulary of the checker, pinned: a checker that sees nothing passes every module
        self.assertEqual(private_uses("from . import detect\nx = detect._ranked(1)\n"), [(2, "_ranked")])
        self.assertEqual(private_uses("from .detect import _LazyRx\n"), [(1, "_LazyRx")])
        self.assertEqual(private_uses("from maisecrets.detect import Match, _word_set\n"), [(1, "_word_set")])
        self.assertEqual(private_uses('def f() -> "detect._Lazy":\n    pass\n'), [(1, "detect._Lazy")])
        self.assertEqual(private_uses("import maisecrets.detect as d\nd._scan('x')\n"), [(2, "_scan")])
        self.assertEqual(private_uses("from . import detect as d\nd._ranked(1)\n"), [(2, "_ranked")])
        self.assertEqual(private_uses("from . import detect\nd = detect\ne = d\ne._lower('x')\n"), [(4, "_lower")])
        self.assertEqual(private_uses("import maisecrets.detect\nmaisecrets.detect._RULES\n"), [(2, "_RULES")])
        self.assertEqual(private_uses("from . import detect\ngetattr(detect, '_word_set')()\n"), [(2, "_word_set")])
        self.assertEqual(private_uses("from .detect import LazyRx as _LazyRx\nx = detect.findings('a')\n"), [])
        self.assertEqual(private_uses("from . import vault as v\nv._index\n"), [], "another module's private name")
        self.assertEqual(private_uses("from . import detect\nd: object = detect\nd._word_set()\n"), [(3, "_word_set")])
        self.assertEqual(private_uses("import maisecrets.detect\nd = maisecrets.detect\nd._word_set()\n"),
                         [(3, "_word_set")])
        self.assertEqual(private_uses("import maisecrets.detect\ngetattr(maisecrets.detect, '_word_set')()\n"),
                         [(2, "_word_set")])
        self.assertEqual(private_uses('def f(x: "maisecrets.detect._Lazy"):\n    pass\n'),
                         [(1, "maisecrets.detect._Lazy")])
        self.assertEqual(private_uses("from . import other\nother.detect._x\nd = other.detect\nd._y\n"), [],
                         "the detect of another object is not this module")
        # the core under its package name (maisecrets/detection/core.py): the same module, the same boundary
        self.assertEqual(private_uses("from .detection import core\ncore._ranked(1)\n"), [(2, "_ranked")])
        self.assertEqual(private_uses("from maisecrets.detection import core as c\nc._det()\n"), [(2, "_det")])
        self.assertEqual(private_uses("from .detection.core import _word_set\n"), [(1, "_word_set")])
        self.assertEqual(private_uses("import maisecrets.detection.core as c\nc._scan('x')\n"), [(2, "_scan")])
        self.assertEqual(private_uses("import maisecrets.detection.core\nmaisecrets.detection.core._det()\n"),
                         [(2, "_det")])
        self.assertEqual(private_uses('def f() -> "detection.core._Lazy":\n    pass\n'), [(1, "detection.core._Lazy")])
        self.assertEqual(private_uses("from .other import core\ncore._x\n"), [], "another package's core")
        # the core through a name of the package (Gate A after the merge of !122)
        self.assertEqual(
            private_uses("from maisecrets import detection\ndetection.core._det()\n"),
            [(2, "_det")],
        )
        self.assertEqual(
            private_uses("import maisecrets.detection as d\nd.core._det()\n"),
            [(2, "_det")],
        )
        self.assertEqual(
            private_uses(
                "from . import detection as p\nq = p\nc = q.core\nc._ranked(1)\n"
            ),
            [(4, "_ranked")],
        )
        self.assertEqual(
            private_uses(
                "import maisecrets.detection\nmaisecrets.detection.core._scan('x')\n"
            ),
            [(2, "_scan")],
        )
        self.assertEqual(
            private_uses("from maisecrets import detection\ndetection.Detector()\n"),
            [],
            "a public name of the package",
        )
        self.assertEqual(
            private_uses(
                "from maisecrets import detection as detect\np = detect\np.core._det()\n"
            ),
            [(3, "_det")],
            "a package alias named detect stays the package (Gate A round 2)",
        )
        self.assertEqual(
            private_uses("from other import detection\ndetection.core._det()\n"),
            [],
            "the detection package of another project",
        )
        self.assertEqual(
            private_uses("import other.detection as d\nd.core._det()\n"), []
        )
        self.assertEqual(
            private_uses("from other.detection import core\ncore._det()\n"), []
        )
        self.assertEqual(private_uses("from other.detection.core import _det\n"), [])
        self.assertEqual(
            private_uses("from ..detect import _det\n"),
            [(1, "_det")],
            "from a subpackage of the plugin",
        )
        self.assertEqual(
            private_uses("import maisecrets.detect as d\n"
                         "def f():\n    from maisecrets import detection as d\nd._scan()\n"),
            [(4, "_scan")], "a package alias in a function does not hide the module alias at the top")
        self.assertEqual(private_uses("import maisecrets.detect as d\nd.__name__\nd._scan\n"), [(3, "_scan")],
                         "a dunder is not a private name")

    def test_no_module_outside_the_core_uses_a_private_name_of_detect(self):
        files = outside_the_core()
        self.assertIn(ROOT / "maisecrets" / "hooks.py", files, "the population holds the plugin")
        self.assertIn(ROOT / "hooks" / "dispatch.py", files)
        self.assertGreater(len(files), 20)
        found = [f"{p.relative_to(ROOT)}:{line}: {name}" for p in files
                 for line, name in private_uses(p.read_text(encoding="utf-8"))]
        self.assertEqual(found, [], "use a public name of detect.py (its facade), or add one there")

    def test_every_core_module_exists(self):
        for name in sorted(CORE | NOT_YET_OUT):
            with self.subTest(name):
                rel = "detection/__init__" if name == "detection" else name.replace(".", "/")
                self.assertTrue((ROOT / "maisecrets" / f"{rel}.py").is_file(), "a renamed module: update the list")

    def test_a_name_that_left_the_core_keeps_its_old_import_where_the_core_can_give_it(self):
        # LazyRx moved to its own core module; a caller of detect.LazyRx gets the same class
        from maisecrets import detect, lazy_regex
        self.assertIs(detect.LazyRx, lazy_regex.LazyRx)
        # the two store helpers moved to the vault, which the core never imports: there is no re-export
        from maisecrets import vault
        self.assertTrue(callable(vault.is_dictionary_word) and callable(vault.code_word_spellings))
        self.assertFalse(hasattr(detect, "is_dictionary_word") or hasattr(detect, "code_word_spellings"))

    def test_a_plain_scan_imports_no_new_module_of_the_plugin(self):
        self.assert_imports("scan")

    def test_findings_import_no_new_module_of_the_plugin(self):
        self.assert_imports("findings")

    def test_a_scan_with_a_term_list_and_an_import_imports_no_store(self):
        home = Path(tempfile.mkdtemp(prefix="detect-boundary-", dir=_isolate.HOME))
        (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS_", "CLAUDE", "CODEX"))}
        env["MAISECRETS_HOME"] = str(home)
        name, other = "Annabell " + "Quarzfeld", "Ottilie " + "Brennwald"
        line = json.dumps({"value": other, "type": "NAME"}) + "\n"
        setup = (f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n"
                 "from maisecrets import terms, values\n"
                 f"assert terms.add_typed({name!r})[0]\n"
                 f"assert values.import_bytes({line.encode()!r}, 'probe').new\n")
        r = subprocess.run([sys.executable, "-I", "-c", setup], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        code = (f"import json, sys\nsys.path.insert(0, {str(ROOT)!r})\n"
                "from maisecrets import detect\n"
                f"kinds = [m.kind for m in detect.scan({name + ' and ' + other + ' met.'!r}, channel='tool')]\n"
                "print(json.dumps([kinds, sorted(m for m in sys.modules if m.startswith('maisecrets.'))]))\n")
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        kinds, mods = json.loads(r.stdout)
        self.assertTrue(any(k.startswith("term:") for k in kinds) and any(k.startswith("import:") for k in kinds),
                        f"the premise: both sources ran ({kinds})")
        loaded = {m.split(".", 1)[1] for m in mods}
        self.assertTrue({"terms", "values"} <= loaded, loaded)
        self.assertFalse(loaded & NEVER, f"a scan imports {sorted(loaded & NEVER)}")

    def assert_imports(self, call: str):
        """Each call in a process of its own: a module that only findings() imports must not count for scan()."""
        home = Path(tempfile.mkdtemp(prefix="detect-boundary-", dir=_isolate.HOME))
        (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        code = (
            "import json, sys\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from maisecrets import detect\n"
            "text = 'pass' + 'word: hunter2x9\\nmail me at someone@example.org, +49 30 1234567\\n'\n"
            "for ch in ('prompt', 'tool'):\n"
            f"    assert detect.{call}(text, channel=ch), ch\n"
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('maisecrets.'))))\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS_", "CLAUDE", "CODEX"))}
        env["MAISECRETS_HOME"] = str(home)
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        loaded = {m.split(".", 1)[1] for m in json.loads(r.stdout)}
        self.assertTrue({"detect", "detection.personal", "detection.registry"} <= loaded, loaded)
        beyond = loaded - CORE
        self.assertFalse(loaded & NEVER, f"{call}() imports {sorted(loaded & NEVER)}")
        self.assertFalse(beyond - NOT_YET_OUT, f"{call}() now imports {sorted(beyond - NOT_YET_OUT)}")
        self.assertFalse(NOT_YET_OUT - beyond, f"no longer imported: remove {sorted(NOT_YET_OUT - beyond)} "
                                               "from NOT_YET_OUT")


class GivenRegionsTests(unittest.TestCase):
    """A caller gives the regions of the scans (detect.use_regions); the detector then reads no config for them. The
    plugin gives its config reader in hooks.main, so a hook gets the regions of today."""

    def setUp(self):
        from maisecrets import detect, home, regions
        self.detect, self.home, self.regions = detect, home, regions
        self.addCleanup(detect.reset_rules)
        self.addCleanup(detect.use_regions, None)

    def ids(self, region: str) -> set:
        self.detect.use_regions(self.regions.resolve({"regions": [region]}))
        return {r.id for r in self.detect.rules()}

    def test_given_regions_decide_the_rules_and_no_config_is_read(self):
        with mock.patch.object(self.home, "load_config", side_effect=AssertionError("the detector read the config")):
            us, de = self.ids("us"), self.ids("de")
            self.assertNotEqual(us, de, "the premise: the two regions load different rules")
            given = self.regions.resolve({"regions": ["us"]})
            self.detect.use_regions(given)
            self.assertIs(self.detect.active_regions(), given)
            self.detect.scan("call +1 202 555 0143 today", channel="tool")
            self.assertEqual(self.detect._pii_regions_cached(), ("generic", "us"))

    def test_new_regions_drop_the_shape_rules_of_the_old_ones(self):
        self.ids("de")
        self.detect._shape_rule_ids()
        self.assertTrue(self.detect._DEFAULT._shape_ids, "the premise: the cache is filled")
        self.detect.use_regions(self.regions.resolve({"regions": ["us"]}))
        self.assertIsNone(self.detect._DEFAULT._shape_ids,
                          "is_fixture would judge with the shape rules of the old regions")
        form_of = self.detect._registry.form_of
        self.assertEqual(self.detect._shape_rule_ids(),
                         {r.id for r in self.detect.rules() if (r.form or form_of(r.id)) == "shape"})

    def test_a_home_module_that_cannot_load_counts_as_no_config(self):
        self.detect.use_regions(None)
        real = __import__
        def failing(name, *a, **k):
            if name in ("home", "maisecrets.home"):    # `from .home import …` in detect asks for "home", level 1
                raise RuntimeError("no home directory")
            return real(name, *a, **k)
        with mock.patch("builtins.__import__", failing):
            self.assertEqual(self.detect.active_regions().regions, ("generic", "de"))

    def test_a_given_reader_is_asked_at_each_use_not_when_it_is_given(self):
        asked = []

        def reader():
            asked.append(1)
            return self.regions.resolve({"regions": ["de"]})
        self.detect.use_regions(reader)
        self.assertEqual(asked, [])
        self.assertEqual(self.detect.active_regions().regions, ("generic", "de"))
        self.assertEqual(len(asked), 1)

    def test_without_given_regions_the_config_of_this_computer_decides(self):
        self.detect.use_regions(None)
        with mock.patch.object(self.home, "load_config", return_value={"regions": ["us"]}):
            self.assertEqual(self.detect.active_regions().regions, ("generic", "us"))
        with mock.patch.object(self.home, "load_config", side_effect=RuntimeError("broken")):
            self.assertEqual(self.detect.active_regions().regions, ("generic", "de"), "a bad config counts as none")

    def test_the_hook_entry_gives_the_config_reader(self):
        from maisecrets import hooks
        with mock.patch.object(self.detect, "use_regions") as given, \
                mock.patch.object(sys, "stdin", io.StringIO(json.dumps({
                    "hook_event_name": "PreToolUse", "session_id": "regions", "tool_name": "Grep",
                    "tool_input": {"pattern": "x", "path": "."}}))), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            hooks.main(["dispatch.py", "pre-tool"])
        given.assert_called_once_with(self.home.regions_from_config)

    def test_the_hook_entry_gives_the_plugin_sources(self):
        from maisecrets import hooks, sources
        with mock.patch.object(self.detect, "use_sources") as given, \
                mock.patch.object(sys, "stdin", io.StringIO(json.dumps({
                    "hook_event_name": "PreToolUse", "session_id": "sources", "tool_name": "Grep",
                    "tool_input": {"pattern": "x", "path": "."}}))), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            hooks.main(["dispatch.py", "pre-tool"])
        given.assert_called_once_with(sources.PLUGIN_SOURCES)

    def test_the_hook_entry_gives_the_plugin_reference_form(self):
        from maisecrets import hooks, placeholder
        with mock.patch.object(self.detect, "use_references") as given, \
                mock.patch.object(sys, "stdin", io.StringIO(json.dumps({
                    "hook_event_name": "PreToolUse", "session_id": "references", "tool_name": "Grep",
                    "tool_input": {"pattern": "x", "path": "."}}))), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            hooks.main(["dispatch.py", "pre-tool"])
        given.assert_called_once_with(placeholder.REFERENCES)

    def test_given_regions_need_no_home_module(self):
        code = (f"import json, sys\nsys.path.insert(0, {str(ROOT)!r})\n"
                "from maisecrets import detect, regions\n"
                "detect.use_regions(regions.resolve({'regions': ['us']}))\n"
                "a = detect.active_regions()\n"
                "print(json.dumps([list(a.regions), 'maisecrets.home' in sys.modules]))\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX"))}
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), [["generic", "us"], False])


_SCAN_WITH_GIVEN_SOURCES = """
import json, sys
sys.path.insert(0, sys.argv[1])
from maisecrets import detect, regions

NAME = "Annabell " + "Quarzfeld"


class Given(detect.Sources):
    def term_matches(self, text):
        at = text.find(NAME)
        return [] if at < 0 else [detect.Match("term:given", "NAME", NAME, at, at + len(NAME))]


detect.use_regions(regions.resolve({"regions": ["de"]}))
detect.use_sources(Given())
detect.use_references(detect.NO_REFERENCES)
text = NAME + " wrote to anna.probe" + "@" + "beispiel-firma.de"
kinds = sorted(m.kind for m in detect.scan(text, channel="tool")) + sorted(m.kind for m in detect.findings(text))
print(json.dumps([kinds, sorted(m for m in sys.modules if m.startswith("maisecrets."))]))
"""


class SourcesTests(unittest.TestCase):
    """One source boundary: a caller gives the rules of your own, the allow list, the term lists and the imported values
    as one object (detect.use_sources); the plugin's readers of the home folder are the default (sources.py)."""

    def setUp(self):
        from maisecrets import detect, regions
        self.detect, self.regions = detect, regions
        self.addCleanup(detect.reset_rules)
        self.addCleanup(detect.use_sources, None)
        self.addCleanup(detect.use_regions, None)

    def test_a_scan_with_given_regions_and_sources_imports_no_home(self):
        # the boundary of the core: input, rules and context in, findings out; no home folder, no plugin module
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX"))}
        r = subprocess.run([sys.executable, "-I", "-c", _SCAN_WITH_GIVEN_SOURCES, str(ROOT)], capture_output=True,
                           text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        kinds, mods = json.loads(r.stdout)
        self.assertEqual(kinds.count("term:given"), 2, f"the premise: the given term source ran ({kinds})")
        self.assertIn("email", kinds, "the built-in rules ran")
        loaded = {m.split(".", 1)[1] for m in mods}
        plugin = {"home", "sources", "user_rules", "term_files", "terms", "value_files", "values", "events",
                  "settings", "vault", "placeholder", "hooks"}
        self.assertEqual(sorted(loaded & plugin), [])
        self.assertEqual(loaded - CORE, set(), f"only core modules: {sorted(loaded - CORE)}")

    def test_given_sources_replace_the_plugin_ones_and_drop_what_those_gave(self):
        detect = self.detect
        text = "write to anna.probe" + "@" + "beispiel-firma.de"
        self.assertIn("email", [m.kind for m in detect.scan(text)], "the premise: the plugin sources allow it")

        class Off(detect.Sources):
            def allow_list(self):
                return frozenset(), frozenset({"email"})
        detect.use_sources(Off())
        self.assertNotIn("email", [m.kind for m in detect.scan(text)], "the given allow list switches the rule off")
        detect.use_sources(detect.NO_SOURCES)
        self.assertIn("email", [m.kind for m in detect.scan(text)], "a switch of sources drops the old allow list")

    def test_a_given_rule_of_your_own_and_a_given_import_are_scanned(self):
        detect = self.detect
        rule = detect.Rule(id="user:probe", type="SECRET", regex=detect.LazyRegex(r"probe-[0-9]{6}", 0))

        class Given(detect.Sources):
            def user_rules(self):
                return [rule]

            def import_matches(self, text):
                at = text.find("Ottilie")
                return [] if at < 0 else [detect.Match("import:given:1", "NAME", "Ottilie", at, at + 7)]
        detect.use_sources(Given())
        kinds = [m.kind for m in detect.scan("code probe-123456 for Ottilie", channel="tool")]
        self.assertIn("user:probe", kinds)
        self.assertIn("import:given:1", kinds)

    def test_a_rule_of_new_sources_does_not_inherit_the_time_of_an_old_rule_with_its_id(self):
        detect = self.detect
        slow = []

        class Given(detect.Sources):
            def __init__(self, rule):
                self.rule = rule

            def user_rules(self):
                return [self.rule]

            def note_slow(self, rule, ms):
                slow.append(rule.id)
        old = detect.Rule(id="user:probe", type="SECRET", regex=detect.LazyRegex(r"probe-[0-9]{6}", 0))
        detect.use_sources(Given(old))
        detect.scan("probe-123456", channel="tool")
        self.assertIn("user:probe", detect._DEFAULT._regex_time, "the premise: the old rule's time is counted")
        detect._DEFAULT._regex_time["user:probe"] = detect.USER_RULE_BUDGET * 10    # the old rule ran over its budget
        new = detect.Rule(id="user:probe", type="SECRET", regex=detect.LazyRegex(r"probe-[0-9]{6}", 0))
        slow.clear()   # a slow old rule under load is not this test's question
        detect.use_sources(Given(new))
        self.assertIsNone(detect.slowest_user_rule())
        self.assertIn("user:probe", [m.kind for m in detect.scan("probe-654321", channel="tool")])
        self.assertEqual(slow, [], "the new rule was taken out for the time of the old one")

    def test_reset_rules_asks_the_sources_to_read_again(self):
        asked = []

        class Counting(self.detect.Sources):
            def reset(self):
                asked.append(1)
        self.detect.use_sources(Counting())
        self.detect.reset_rules()
        self.assertEqual(asked, [1])


_OPEN, _CLOSE = chr(0x27E6), chr(0x27E7)
_PLUGIN_REF = _OPEN + "SECRET" + "_c7" + _CLOSE   # the plugin's form, built here: never as a literal in a test file

_SCAN_WITH_A_FOREIGN_REFERENCE_FORM = """
import json, sys
sys.path.insert(0, sys.argv[1])
from maisecrets import detect, regions


class Hashes(detect.References):
    # a foreign reference form: #ref-<key>#
    def hit_is_a_reference(self, text, start, secret):
        return secret.startswith("#ref-") and secret.endswith("#")

    def names_a_key(self, low):
        return low.startswith("#ref-")


detect.use_regions(regions.resolve({"regions": ["de"]}))
detect.use_sources(detect.NO_SOURCES)
detect.use_references(Hashes())
plugin_ref = chr(0x27E6) + "SECRET" + "_c7" + chr(0x27E7)
foreign = [m.kind for m in detect.scan('db_pass' 'word = "#ref-Qx7Kp2Lm9Vw4#"', channel="tool", path="/tmp/a.txt")]
plain = [m.kind for m in detect.scan('db_pass' 'word = "Qx7Kp2Lm9Vw4"', channel="tool", path="/tmp/a.txt")]
plugin = [m.kind for m in detect.scan('cu' 'rl -u "app:' + plugin_ref + '" https://x.test', channel="tool")]
print(json.dumps([foreign, plain, plugin, sorted(m for m in sys.modules if m.startswith("maisecrets."))]))
"""


class ReferencesTests(unittest.TestCase):
    """The detector asks a References object about the reference form (detect.use_references); the plugin's form
    (placeholder.REFERENCES) is the default. detect.py itself holds no part of that form."""

    def setUp(self):
        from maisecrets import detect, placeholder
        self.detect, self.placeholder = detect, placeholder
        self.addCleanup(detect.use_references, None)

    def test_a_foreign_reference_form_with_given_regions_sources_and_context_imports_no_plugin_module(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX"))}
        r = subprocess.run([sys.executable, "-I", "-c", _SCAN_WITH_A_FOREIGN_REFERENCE_FORM, str(ROOT)],
                           capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        foreign, plain, plugin, mods = json.loads(r.stdout)
        self.assertTrue(plain, "the premise: the same value without the foreign form is a hit")
        self.assertEqual(foreign, [], "the foreign form is a reference: no hit")
        self.assertEqual(plugin, ["curl-auth-user"], "the plugin's form is plain text to this caller")
        loaded = {m.split(".", 1)[1] for m in mods}
        self.assertEqual(loaded - CORE, set(), f"only core modules: {sorted(loaded - CORE)}")
        self.assertNotIn("placeholder", loaded)

    def test_the_plugin_form_is_the_default_and_a_caller_can_drop_it(self):
        flag = "-" + "u"   # split: the tree scan reads a curl user flag in a line as a value
        text = 'cu' + 'rl ' + flag + ' "app:' + _PLUGIN_REF + '" https://x.test'
        self.assertIs(self.detect._references(), self.placeholder.REFERENCES)
        self.assertEqual(self.detect.findings(text, channel="tool"), [], "the plugin's form is never a hit")
        self.detect.use_references(self.detect.NO_REFERENCES)
        self.assertEqual([m.kind for m in self.detect.findings(text, channel="tool")], ["curl-auth-user"])
        self.detect.use_references(None)
        self.assertEqual(self.detect.findings(text, channel="tool"), [])

    def kinds_with(self, refs, text: str) -> list:
        self.detect.use_references(refs)
        return sorted((m.kind, m.value) for ch in ("tool", "prompt") for m in self.detect.scan(text, channel=ch))

    def test_a_personal_value_with_a_reference_mark_is_left_to_the_other_rules(self):
        plugin = self.placeholder.REFERENCES

        class NoMarks(type(plugin)):
            def has_marks(self, value):
                return False
        text = "Adresse: Hauptstraße 5" + _CLOSE + ", 10115 Berlin"
        with_marks, without = self.kinds_with(plugin, text), self.kinds_with(NoMarks(), text)
        self.assertNotEqual(with_marks, without, "the premise: the question decides this text")
        self.assertFalse([v for _k, v in with_marks if _CLOSE in v], "a value with a mark is no personal-data hit")
        self.assertTrue([v for _k, v in without if _CLOSE in v])

    def test_a_value_glued_to_its_label_inside_an_open_reference_needs_the_longer_floor(self):
        plugin = self.placeholder.REFERENCES

        class NoInside(type(plugin)):
            def inside(self, text, pos):
                return False
        text = _OPEN + "pw" + "d=k3Y9xq"
        self.assertEqual(self.kinds_with(plugin, text), [], "inside an open reference the 6-character floor is off")
        self.assertTrue(self.kinds_with(NoInside(), text), "the premise: the question decides this text")

    def test_detect_py_holds_no_part_of_the_plugin_reference_form(self):
        # the brackets, their escapes, the c-key pattern, and an import of placeholder.py: each is the plugin's form,
        # which detect.py must ask References about, never know
        # core.py and the modules that hold its parts
        srcs = [(ROOT / "maisecrets" / "detection" / f"{m}.py").read_text(encoding="utf-8")
                for m in ("core",) + CORE_PARTS]
        src = "\n".join(srcs)
        # a ratchet of the spellings an ordinary change writes, not a proof against one that hides
        forms = {"open bracket": _OPEN, "close bracket": _CLOSE, "open escape": "\\u27e6",
                 "close escape": "\\u27e7", "open code point": "0x27e6", "close code point": "0x27e7",
                 "named open": "white square bracket", "key pattern": "_c\\d", "key class": "_c[0-9]"}
        self.assertEqual({name for name, form in forms.items() if form.lower() in src.lower()}, set())
        # placeholder.py is loaded in one place only, in any import form: as the default form (_references)
        importers = set()
        for f in (node for s in srcs for node in ast.parse(s).body):
            for n in ast.walk(f):
                names = []
                if isinstance(n, ast.ImportFrom):
                    names = [n.module or ""] + [(n.module or "") + "." + a.name for a in n.names]
                elif isinstance(n, ast.Import):
                    names = [a.name for a in n.names]
                elif isinstance(n, ast.Constant) and isinstance(n.value, str) and "." in n.value:
                    names = [n.value]   # importlib.import_module("maisecrets.placeholder"); the word alone is a value
                if any(x.split(".")[-1] == "placeholder" for x in names if x):
                    importers.add(f.name if isinstance(f, ast.FunctionDef) else "<module>")
        self.assertEqual(importers, {"_references"})
        plugin = (ROOT / "maisecrets" / "placeholder.py").read_text(encoding="utf-8")
        self.assertIn("_c\\d", plugin, "the premise: the checker's key pattern is the one the form uses")


if __name__ == "__main__":
    unittest.main()
