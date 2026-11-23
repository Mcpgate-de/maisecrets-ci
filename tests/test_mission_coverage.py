"""scripts/mission_coverage.py joins mission/*.toml, beliefs/*.toml, docs/THREAT-MODEL.md and the promises of
README.md and PRIVACY.md. Each finding class is checked on a small tree of its own, so a check that finds nothing
fails here."""
import contextlib
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import tomllib  # noqa: F401
except ImportError:     # Python < 3.11: the script needs tomllib, like replay_can_fail.py
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
sys.path.insert(0, str(ROOT / "scripts"))

THREAT_MODEL = """| # | control | defends against | ends where |
|---|---|---|---|
| C1 | a | A1 | x |
| C2 | b | A1 | x |
| C3 | c | A2 | x |

- **I1** an invariant
"""
README = """# x

## What it does

- **Masks output** before the model
  reads it.
- **Checks a value first:** without sending it.

## What it does not protect

- A name without a label.

## Other

- not gated
"""
HOW = """# h

## What the Claude Code mod does

- **Rewrites a prompt.**
"""
PRIVACY = """# p

## What it reads

- **Only the prompt.**

## What it stores, and where

- Nothing on disk.

## What leaves the machine

- Nothing, unless
  you ask.
"""
CLAIMS = """[[claim]]
source = "docs/HOW-IT-WORKS.md"
quote = "**Rewrites a prompt.**"
kind = "feature"

[[claim]]
source = "PRIVACY.md"
quote = "Nothing on disk."
kind = "feature"

[[claim]]
source = "PRIVACY.md"
quote = "**Only the prompt.**"
kind = "feature"

[[claim]]
source = "PRIVACY.md"
quote = "Nothing, unless you ask."
kind = "promise"
mission = "M1"

[[claim]]
source = "README.md"
quote = "**Masks output** before the model reads it."
kind = "promise"
mission = "M1"

[[claim]]
source = "README.md"
quote = "**Checks a value first:**"
kind = "feature"

[[claim]]
source = "README.md"
quote = "A name without a label."
kind = "limit"
mission = "M1"
"""


def toml_list(xs):
    return "[" + ", ".join(f'"{x}"' for x in xs) + "]"


def belief(name, control, serves=("M1.1",)):
    line = "" if serves is None else f'serves = "{serves}"\n' if isinstance(serves, str) \
        else f"serves = {toml_list(serves)}\n"
    return f'belief = "{name}"\ncontrol = "{control}"\n{line}statement = "s"\nrunner = ["t"]\n[proof]\nfile = "f"\n'


def mission(mid, controls, invariants=(), parts=("all",), measure='none = "a yes or no"'):
    """parts: the sentence of each part; its id is <mid>.<n> unless the item is (sentence, extra TOML lines)."""
    text = (f'mission = "{mid}"\npromise = "p"\ncontrols = {toml_list(controls)}\n'
            f'invariants = {toml_list(invariants)}\n')
    for i, part in enumerate(parts, 1):
        says, extra = (part, f'id = "{mid}.{i}"\n') if isinstance(part, str) else part
        text += f'\n[[part]]\n{extra}says = "{says}"\n'
    if measure is not None:
        text += f'\n[measure]\n{measure}\n'
    return text


def quiet(fn, argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(argv)


@unittest.skipIf(tomllib is None, "tomllib is Python 3.11+; the other CI Pythons run the script")
class MissionCoverageTests(unittest.TestCase):
    def tree(self, missions, beliefs, claims=CLAIMS, readme=README, privacy=PRIVACY, how=HOW):
        root = Path(tempfile.mkdtemp(prefix="maisecrets-mission-"))
        self.addCleanup(shutil.rmtree, root, True)
        for d in ("docs", "mission", "beliefs"):
            (root / d).mkdir()
        (root / "docs" / "THREAT-MODEL.md").write_text(THREAT_MODEL, encoding="utf-8")
        (root / "README.md").write_text(readme, encoding="utf-8")
        (root / "docs" / "HOW-IT-WORKS.md").write_text(how, encoding="utf-8")
        (root / "PRIVACY.md").write_text(privacy, encoding="utf-8")
        (root / "mission" / "claims.toml").write_text(claims, encoding="utf-8")
        (root / "mission" / "code.toml").write_text("[file]\n", encoding="utf-8")     # a tree without program files
        for name, text in missions.items():
            (root / "mission" / f"{name}.toml").write_text(text, encoding="utf-8")
        # each belief: its control, which serves M1.1, or (control, serves); serves None leaves the key out
        for i, b in enumerate(beliefs):
            control, serves = (b, ("M1.1",)) if isinstance(b, str) else b
            (root / "beliefs" / f"b{i}.toml").write_text(belief(f"b{i}", control, serves), encoding="utf-8")
        return root

    def covered(self):
        return {"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"])}

    def test_a_covered_tree_has_no_finding_and_passes_strict(self):
        import mission_coverage
        root = self.tree(self.covered(), ["C1", "C2", "C3", "I1"])
        r = mission_coverage.analyse(root)
        for key in ("gaps", "thin", "no_invariant", "orphans", "unknown", "claims", "undocumented_belief_controls"):
            self.assertEqual(r[key], [], key)
        self.assertEqual(r["unowned_beliefs"], {})
        self.assertEqual(quiet(mission_coverage.main, ["--strict", "--root", str(root)]), 0)

    def test_each_mission_finding_class_is_named(self):
        import mission_coverage
        missions = {"M1-x": mission("M1", ["C1", "C2", "C9"], parts=("one", "none", "many")),
                    "M7-y": mission("M2", [], parts=())}
        root = self.tree(missions, [("C1", ["M1.1"]), ("C2", ["M1.3"]), ("C2", ["M1.3"]), ("operations", [])])
        r = mission_coverage.analyse(root)
        self.assertEqual(r["thin"], ["M1.1: one belief: one"])
        self.assertIn("M1.2: no belief: none", r["gaps"])
        self.assertIn("M2: no part names a belief", r["gaps"])
        self.assertIn("M1: C9 is not in docs/THREAT-MODEL.md", r["unknown"])
        self.assertIn("M7-y.toml: the file name does not start with M2-", r["unknown"])
        self.assertEqual(r["no_invariant"], ["M1", "M2"])
        self.assertEqual(r["orphans"], ["C3 serves no mission", "I1 serves no mission"])
        self.assertEqual(r["unowned_beliefs"], {"operations": 1})
        self.assertEqual(r["undocumented_belief_controls"], ["operations"])

    def test_each_broken_link_between_a_belief_and_a_part_is_named(self):
        import mission_coverage
        parts = ("all", ("two", 'id = "M1.1"\n'), ("odd", 'id = "M2.7"\n'), ("glob", 'id = "M1.4"\nbeliefs = ["b*"]\n'))
        missions = {"M1-x": mission("M1", ["C1", "C2"], ["I1"], parts=parts)}
        beliefs = [("C1", ["M1.1"]), ("C1", None), ("C2", ["M9.1"]), ("C3", ["M1.1"]), ("C1", "M1.1"),
                   ("detector", ["M1.1"]), ("I1", ["M1.4"])]
        r = mission_coverage.analyse(self.tree(missions, beliefs))
        self.assertIn("M1.1: 2 parts have this id", r["unknown"])
        self.assertIn("M1, part 3: the id 'M2.7' is not M1.<number>", r["unknown"])
        self.assertIn("M1.4: a part names no beliefs; each belief names its parts in serves", r["unknown"])
        self.assertIn("b1: no serves list of part ids (serves = [] when it serves no promise)", r["unknown"])
        self.assertIn("b2: serves M9.1, which no mission has", r["unknown"])
        self.assertIn("b3: serves M1.1, but M1 does not name its control C3", r["unknown"])
        self.assertIn("b4: no serves list of part ids (serves = [] when it serves no promise)", r["unknown"])
        self.assertIn("b5: serves M1.1, but M1 does not name its control detector", r["unknown"])
        self.assertFalse(any(u.startswith(("b0:", "b6:")) for u in r["unknown"]),
                         "a served part whose mission names the belief's control is no finding")
        self.assertEqual(len(r["unknown"]), 8, r["unknown"])
        self.assertEqual(r["unowned_beliefs"], {}, "serves = [] is the only way to serve no promise")

    def test_ids_are_unique_over_all_missions_and_a_label_needs_its_mission(self):
        import mission_coverage
        labelled = mission("M1", ["C1", "C2", "C3"], ["I1"]).replace('invariants = ["I1"]\n',
                                                                     'invariants = ["I1"]\nlabels = ["ops", "C2"]\n')
        missions = {"M1-x": labelled, "M1-y": mission("M1", [], parts=(("again", 'id = "M1.1"\n'),)),
                    "M2-z": mission("M2", [], parts=(("own", 'id = "M2.1"\n'),))}
        beliefs = ["C1", "C2", "C3", "I1", ("ops", ["M1.1"]), ("ops", ["M2.1"])]
        r = mission_coverage.analyse(self.tree(missions, beliefs))
        self.assertIn("M1: 2 files name this mission", r["unknown"])
        self.assertIn("M1.1: 2 parts have this id", r["unknown"])
        self.assertIn("M1: C2 is a control; name it in controls or invariants, not labels", r["unknown"])
        self.assertIn("b5: serves M2.1, but M2 does not name its control ops", r["unknown"])
        self.assertFalse(any(u.startswith("b4:") for u in r["unknown"]), "M1 names the label ops")

    def test_a_belief_counts_only_for_the_parts_it_serves(self):
        import mission_coverage
        missions = {"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"], parts=("a", "b", "c"))}
        beliefs = [("C1", ["M1.1", "M1.2"]), ("C2", ["M1.2"]), ("C3", ["M1.2"]), ("I1", [])]
        r = mission_coverage.analyse(self.tree(missions, beliefs))
        self.assertEqual(r["missions"], [("M1", "p", [("M1.1", "a", 1), ("M1.2", "b", 3), ("M1.3", "c", 0)])])
        self.assertEqual(r["gaps"], ["M1.3: no belief: c"])
        self.assertEqual(r["unowned_beliefs"], {"I1": 1})

    def test_a_part_tested_elsewhere_is_still_a_gap_and_says_where(self):
        import mission_coverage
        m = mission("M1", ["C1", "C2", "C3"], ["I1"])
        m += '\n[[part]]\nid = "M1.2"\nsays = "the mod"\ntests = ["tests/mod.test.ts"]\n'
        r = mission_coverage.analyse(self.tree({"M1-x": m}, ["C1", "C2", "C3", "I1"]))
        self.assertEqual(r["gaps"], ["M1.2: no belief (tested only in tests/mod.test.ts, which no mutation proves): "
                                     "the mod"])

    def test_a_reworded_promise_and_an_unmapped_bullet_are_claim_findings(self):
        import mission_coverage
        readme = README.replace("before the model\n  reads it.", "before the model sees it.")
        readme = readme.replace("- A name without a label.", "- A name without a label.\n- A new limit.")
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], readme=readme))
        self.assertIn("claim not found in README.md: **Masks output** before the model reads it.", r["claims"])
        self.assertIn('README "What it does" bullet no claim maps: **Masks output** before the model sees it.',
                      r["claims"])
        self.assertIn('README "What it does not protect" bullet no claim maps: A new limit.', r["claims"])
        self.assertFalse(any("not gated" in c for c in r["claims"]), "a section outside the gate is free text")

    def test_privacy_bullets_are_gated_and_a_gated_section_cannot_go(self):
        import mission_coverage
        privacy = PRIVACY.replace("- Nothing, unless", "- A crash report goes out.\n- Nothing, unless")
        privacy = privacy.replace("## What it stores, and where", "## What it keeps")
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], privacy=privacy))
        self.assertEqual(r["claims"], ['PRIVACY.md has no section "What it stores, and where" with a bullet '
                                       '(GATED_SECTIONS)',
                                       'PRIVACY "What leaves the machine" bullet no claim maps: '
                                       'A crash report goes out.'])
        how = HOW.replace("## What the Claude Code mod does\n\n", "")
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], how=how))
        self.assertEqual(r["claims"], ['docs/HOW-IT-WORKS.md has no section "What the Claude Code mod does" '
                                       'with a bullet (GATED_SECTIONS)'])
        # the bullets moved out of a gated section: the claims still stand in the file, the section is empty
        privacy = PRIVACY.replace("- **Only the prompt.**\n", "").replace("# p\n", "# p\n\n- **Only the prompt.**\n")
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], privacy=privacy))
        self.assertEqual(r["claims"], ['PRIVACY.md has no section "What it reads" with a bullet (GATED_SECTIONS)'])
        root = self.tree(self.covered(), ["C1", "C2", "C3", "I1"])
        (root / "mission" / "claims.toml").unlink()
        self.assertEqual(mission_coverage.analyse(root)["claims"],
                         ["mission/claims.toml not found: no promise of README.md or PRIVACY.md is checked"])

    def test_a_quote_maps_a_bullet_of_its_own_source_and_only_by_its_start(self):
        import mission_coverage
        # a README quote that a PRIVACY bullet starts with, and a PRIVACY quote from the middle of a bullet
        privacy = PRIVACY.replace("- **Only the prompt.**",
                                  "- **Masks output** before the model reads it.\n- **Only the prompt.**")
        privacy = privacy.replace("- Nothing, unless", "- Here: Nothing, unless")
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], privacy=privacy))
        self.assertIn('PRIVACY "What it reads" bullet no claim maps: **Masks output** before the model reads it.',
                      r["claims"])
        self.assertIn('PRIVACY "What leaves the machine" bullet no claim maps: Here: Nothing, unless you ask.',
                      r["claims"])
        self.assertEqual(len(r["claims"]), 2, r["claims"])

    def test_a_mission_with_fields_of_the_wrong_type_is_named(self):
        import mission_coverage
        m = mission("M1", ["C1", "C2", "C3"], ["I1"])
        m = m.replace('invariants = ["I1"]', 'invariants = ["I1"]\nlabels = "ops"')
        m += '\n[[part]]\nid = "M1.2"\nsays = 3\n\n[[part]]\nid = "M2.5"\nsays = "odd"\n'
        r = mission_coverage.analyse(self.tree({"M1-x": m}, ["C1", "C2", "C3", "I1", ("C1", ["M2.5"])]))
        self.assertIn("M1: labels is not a list of names", r["unknown"])
        for bad in ('controls = "C1"', 'controls = [["C1"]]', "invariants = 5"):  # noqa: B007
            with self.subTest(bad):
                text = mission("M1", ["C1", "C2", "C3"], ["I1"])
                text = text.replace('controls = ["C1", "C2", "C3"]', bad) if bad.startswith("controls") \
                    else text.replace('invariants = ["I1"]', bad)
                key = bad.split(" ")[0]
                found = mission_coverage.analyse(self.tree({"M1-x": text}, ["C1", "C2", "C3", "I1"]))["unknown"]
                self.assertIn(f"M1: {key} is not a list of names", found)
        self.assertIn("M1.2: the part has no sentence in says", r["unknown"])
        self.assertIn("b4: serves M2.5, which no mission has", r["unknown"])

    def test_a_part_table_a_missing_promise_and_a_number_quote_are_findings_not_crashes(self):
        import mission_coverage
        single = mission("M1", ["C1", "C2", "C3"], ["I1"], parts=()) + '\n[part]\nid = "M1.1"\nsays = "x"\n'
        r = mission_coverage.analyse(self.tree({"M1-x": single.replace('promise = "p"\n', "")},
                                               ["C1", "C2", "C3", "I1"], claims=CLAIMS + "\n[[claim]]\nquote = 5\n"))
        self.assertIn("M1: part is not a list of [[part]] tables", r["unknown"])
        self.assertIn("M1: promise is not a sentence", r["unknown"])
        self.assertIn("claim with a quote or a source that is no text: 5", r["claims"])
        for bad in ('part = ["sentence"]', 'measure = "none"'):
            with self.subTest(bad):
                text = mission("M1", ["C1", "C2", "C3"], ["I1"], parts=(), measure=None) + bad + "\n"
                found = mission_coverage.analyse(self.tree({"M1-x": text}, ["C1", "C2", "C3", "I1"]))["unknown"]
                self.assertTrue(any(bad.split(" ")[0] + " is not" in u for u in found), found)

    def test_a_claim_needs_a_kind_and_an_existing_mission(self):
        import mission_coverage
        claims = CLAIMS.replace('kind = "limit"\nmission = "M1"', 'kind = "limit"\nmission = "M9"')
        claims = claims.replace('kind = "feature"', 'kind = "wish"', 1)
        claims = claims.replace('kind = "promise"\nmission = "M1"', 'kind = "promise"\nmission = "M8"', 1)
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], claims=claims))
        self.assertIn("claim names no existing mission (M9): A name without a label.", r["claims"])
        self.assertIn("claim kind 'wish' is not one of promise, limit, feature: **Rewrites a prompt.**", r["claims"])
        self.assertTrue(any(c.startswith("claim names no existing mission (M8)") for c in r["claims"]), r["claims"])

    def test_strict_fails_on_each_blocking_class_and_the_report_alone_does_not(self):
        import mission_coverage
        cases = {"claim": (self.covered(), ["C1", "C2", "C3", "I1"], CLAIMS.replace("A name without", "A cat with")),
                 "orphan": ({"M1-x": mission("M1", ["C1", "C2"], ["I1"])}, ["C1", "C2", "I1"], CLAIMS),
                 "gap": ({"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"], parts=("n",))}, [("C1", [])], CLAIMS),
                 "no serves": (self.covered(), ["C1", "C2", ("C3", None), "I1"], CLAIMS)}
        for name, (missions, beliefs, claims) in cases.items():
            with self.subTest(name):
                root = self.tree(missions, beliefs, claims=claims)
                self.assertEqual(quiet(mission_coverage.main, ["--root", str(root)]), 0)
                self.assertEqual(quiet(mission_coverage.main, ["--strict", "--root", str(root)]), 1)

    def test_a_measure_is_read_from_the_last_row_and_a_missing_one_is_named(self):
        import mission_coverage
        log = ("| Date | Source | Recall |\n|---|---|---|\n| d1 | holdout-v2 | 0.5 |\n| d2 | other | 0.1 |\n"
               "| d3 | holdout-v2 | 0.7 |\n")
        read = 'what = "recall"\nsource = "LOG.md"\nrow = "holdout-v2"\ncolumn = 3\ngate = "g"'
        missions = {"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"], measure=read),
                    "M2-y": mission("M2", [], measure=None),
                    "M3-z": mission("M3", [], measure=read.replace("holdout-v2", "holdout-v9"))}
        root = self.tree(missions, ["C1", "C2", "C3", "I1"])
        (root / "LOG.md").write_text(log, encoding="utf-8")
        r = mission_coverage.analyse(root)
        self.assertEqual(r["measures"], ["M1: 0.7 = recall (bound: g)"])
        self.assertIn("M2: no [measure], and no `none` that says why", r["unknown"])
        self.assertIn("M3: the measure cannot be read: no row with 'holdout-v9' in LOG.md", r["unknown"])

    def code_tree(self, register: str, threat_model: str = THREAT_MODEL, extra=()):
        """A tree with program files, beliefs whose proofs name them, and a register (mission/code.toml). `extra`:
        more beliefs, each (name, control, file, serves, kind line, replace)."""
        root = self.tree(self.covered(), ["C1", "C2", "C3", "I1"])
        (root / "docs" / "THREAT-MODEL.md").write_text(threat_model, encoding="utf-8")
        for f in ("maisecrets/a.py", "maisecrets/b.py", "maisecrets/undeclared.py", "hooks/run.sh",
                  "claude-mod/x.mjs", "skills/s/scripts/t.py", "maisecrets/rules/data.json", "docs/notes.py"):
            (root / f).parent.mkdir(parents=True, exist_ok=True)
            (root / f).write_text("x = 1\n", encoding="utf-8")
        # pe serves no promise, so it proves nothing for the register; pi is an invariant belief whose mutation only
        # injects code (its replace keeps the find text) into a file that carries no rule of it
        for name, control, f, serves, kind, replace in (
                ("pa", "C1", "maisecrets/a.py", '["M1.1"]', "", "x = 2"),
                ("pb", "C1", "maisecrets/b.py", '["M1.1"]', "", "x = 2"),
                ("pm", "C2", "claude-mod/x.mjs", '["M1.1"]', "", "x = 2"),
                ("pe", "C2", "maisecrets/a.py", "[]", "", "x = 2"),
                ("pi", "I1", "maisecrets/undeclared.py", '["M1.1"]', 'kind = "invariant"\n', "x = 1\\nimport socket"),
                *extra):
            (root / "beliefs" / f"{name}.toml").write_text(
                f'belief = "{name}"\ncontrol = "{control}"\nserves = {serves}\n{kind}statement = "s"\n'
                f'runner = ["t"]\n[proof]\nfile = "{f}"\nfind = "x = 1"\nreplace = "{replace}"\n', encoding="utf-8")
        (root / "mission" / "code.toml").write_text(register, encoding="utf-8")
        return root

    def test_each_code_finding_is_named_and_strict_fails_on_it(self):
        import mission_coverage
        register = ('[file]\n"maisecrets/a.py" = { controls = ["C1", "C2"] }\n'
                    '"maisecrets/b.py" = { none = "a helper" }\n'
                    '"maisecrets/gone.py" = { controls = ["C1"] }\n'
                    '"hooks/run.sh" = { controls = ["C1"], none = "both" }\n'
                    '"claude-mod/x.mjs" = { controls = ["C2", "C9"] }\n'
                    '"skills/s/scripts/t.py" = { none = "" }\n')
        model = THREAT_MODEL.replace("| C3 | c |", "| C3 | c (`maisecrets/a.py`, `maisecrets/missing.py`) |")
        r = mission_coverage.analyse(self.code_tree(register, model))
        self.assertEqual(r["code"], [
            "claude-mod/x.mjs: declares C9, which docs/THREAT-MODEL.md does not document",
            "hooks/run.sh: the entry needs controls (a list of C or I names) or none (a reason), not both",
            "skills/s/scripts/t.py: the entry needs controls (a list of C or I names) or none (a reason), not both",
            "maisecrets/undeclared.py: a program file that mission/code.toml does not declare",
            "maisecrets/gone.py: declared in mission/code.toml, but the file is gone",
            "claude-mod/x.mjs: declares C9, but no belief of C9 has a proof in this file",
            "maisecrets/a.py: declares C2, but no belief of C2 has a proof in this file",
            "maisecrets/b.py: a belief of C1 has a proof in this file, but its entry does not declare C1",
            "maisecrets/b.py: declared none, but a belief's mutation breaks a line of it",
            "maisecrets/gone.py: declares C1, but no belief of C1 has a proof in this file",
            "docs/THREAT-MODEL.md names maisecrets/a.py for C3, but mission/code.toml does not declare it",
            "docs/THREAT-MODEL.md names maisecrets/missing.py for C3, but the file does not exist"])
        self.assertEqual(r["code_counts"], {"files": 6, "with controls": 3, "none": 1})
        root = self.code_tree(register)
        self.assertEqual(quiet(mission_coverage.main, ["--root", str(root)]), 0)
        self.assertEqual(quiet(mission_coverage.main, ["--strict", "--root", str(root)]), 1)

    def test_a_register_that_matches_the_code_has_no_finding(self):
        import mission_coverage
        register = ('[file]\n"maisecrets/a.py" = { controls = ["C1"] }\n'
                    '"maisecrets/b.py" = { controls = ["C1"] }\n'
                    '"maisecrets/undeclared.py" = { none = "a helper" }\n'
                    '"hooks/run.sh" = { none = "a launcher" }\n'
                    '"claude-mod/x.mjs" = { controls = ["C2"] }\n'
                    '"skills/s/scripts/t.py" = { none = "a script" }\n')
        model = THREAT_MODEL.replace("| C1 | a |", "| C1 | a (`maisecrets/a.py`, `tests/test_a.py`) |")
        root = self.code_tree(register, model)
        (root / "tests").mkdir()
        (root / "tests" / "test_a.py").write_text("", encoding="utf-8")
        r = mission_coverage.analyse(root)
        self.assertEqual(r["code"], [])
        self.assertEqual(quiet(mission_coverage.main, ["--strict", "--root", str(root)]), 0)
        (root / "mission" / "code.toml").unlink()
        self.assertEqual(mission_coverage.analyse(root)["code"],
                         ["mission/code.toml not found: no program file says which controls it carries"])

    def test_a_none_file_that_a_mutation_targets_or_that_names_a_hook_answer_is_named(self):
        import mission_coverage
        register = ('[file]\n"maisecrets/a.py" = { controls = ["C1"] }\n'
                    '"maisecrets/b.py" = { none = "a helper" }\n'
                    '"maisecrets/undeclared.py" = { none = "a helper" }\n'
                    '"hooks/run.sh" = { none = "a launcher" }\n'
                    '"claude-mod/x.mjs" = { controls = ["C2"] }\n'
                    '"skills/s/scripts/t.py" = { none = "a script" }\n')
        # pc: an invariant belief of a control whose mutation breaks a real line; pr: a belief with a label
        extra = (("pc", "C1", "maisecrets/undeclared.py", '["M1.1"]', 'kind = "invariant"\n', "x = 2"),
                 ("pr", "operations", "hooks/run.sh", '["M1.1"]', "", "x = 2"))
        root = self.code_tree(register, extra=extra)
        for text, key in (('out = {"hookSpecificOutput": {"updatedToolOutput": "x"}}\n', "updatedToolOutput"),
                          ("return { decision: 'block' }\n", "decision"),
                          ("return dict(systemMessage=line)\n", "systemMessage"),
                          ("import sys\nsys.exit(2)\n", "sys.exit(2)"), ("exit 2\n", "exit 2"),
                          ("decision == 'block'\nx = 1\n", None)):
            with self.subTest(key=key):
                (root / "skills/s/scripts/t.py").write_text(text, encoding="utf-8")
                found = [c for c in mission_coverage.analyse(root)["code"] if c.startswith("skills/")]
                want = f"skills/s/scripts/t.py: declared none, but it names a hook answer key ({key})"
                self.assertEqual(found, [want] if key else [], "a comparison is no answer key")
        r = mission_coverage.analyse(root)
        self.assertEqual(r["code"], [
            "hooks/run.sh: declared none, but a belief's mutation breaks a line of it",
            "maisecrets/b.py: a belief of C1 has a proof in this file, but its entry does not declare C1",
            "maisecrets/b.py: declared none, but a belief's mutation breaks a line of it",
            "maisecrets/undeclared.py: a belief of C1 has a proof in this file, but its entry does not declare C1",
            "maisecrets/undeclared.py: declared none, but a belief's mutation breaks a line of it"])

    def test_the_repository_maps_every_promise_and_names_only_documented_controls(self):
        import mission_coverage
        r = mission_coverage.analyse(ROOT)
        self.assertGreaterEqual(len(r["missions"]), 1, "a population test must fail on an empty population")
        self.assertEqual(r["unknown"], [])
        self.assertEqual(r["gaps"], [], "every part of a mission rests on a belief that can fail")
        self.assertEqual(r["orphans"], [], "a documented control must serve a mission")
        self.assertEqual(r["claims"], [], "every promise of README.md and PRIVACY.md maps to a mission")
        self.assertEqual(r["code"], [], "each program file declares its controls; each one is proven there")
        self.assertGreaterEqual(r["code_counts"]["files"], 100, "a population test must fail on an empty population")


if __name__ == "__main__":
    unittest.main()
