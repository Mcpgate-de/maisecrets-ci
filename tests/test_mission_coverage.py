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
CLAIMS = """[[claim]]
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


def belief(name, control):
    return f'belief = "{name}"\ncontrol = "{control}"\nstatement = "s"\nrunner = ["t"]\n[proof]\nfile = "f"\n'


def toml_list(xs):
    return "[" + ", ".join(f'"{x}"' for x in xs) + "]"


def mission(mid, controls, invariants=(), parts=(("all", ["b*"]),), measure='none = "a yes or no"'):
    text = (f'mission = "{mid}"\npromise = "p"\ncontrols = {toml_list(controls)}\n'
            f'invariants = {toml_list(invariants)}\n')
    for says, beliefs in parts:
        text += f'\n[[part]]\nsays = "{says}"\nbeliefs = {toml_list(beliefs)}\n'
    if measure is not None:
        text += f'\n[measure]\n{measure}\n'
    return text


def quiet(fn, argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(argv)


@unittest.skipIf(tomllib is None, "tomllib is Python 3.11+; the other CI Pythons run the script")
class MissionCoverageTests(unittest.TestCase):
    def tree(self, missions, beliefs, claims=CLAIMS, readme=README):
        root = Path(tempfile.mkdtemp(prefix="maisecrets-mission-"))
        self.addCleanup(shutil.rmtree, root, True)
        for d in ("docs", "mission", "beliefs"):
            (root / d).mkdir()
        (root / "docs" / "THREAT-MODEL.md").write_text(THREAT_MODEL, encoding="utf-8")
        (root / "README.md").write_text(readme, encoding="utf-8")
        (root / "mission" / "claims.toml").write_text(claims, encoding="utf-8")
        for name, text in missions.items():
            (root / "mission" / f"{name}.toml").write_text(text, encoding="utf-8")
        for i, control in enumerate(beliefs):
            (root / "beliefs" / f"b{i}.toml").write_text(belief(f"b{i}", control), encoding="utf-8")
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
        missions = {"M1-x": mission("M1", ["C1", "C2", "C9"], parts=(("one", ["b0"]), ("none", ["zz*"]),
                                                                     ("many", ["b1", "b2"]))),
                    "M7-y": mission("M2", [], parts=())}
        root = self.tree(missions, ["C1", "C2", "C2", "operations"])
        r = mission_coverage.analyse(root)
        self.assertEqual(r["thin"], ["M1.1: one belief: one"])
        self.assertIn("M1.2: no belief: none", r["gaps"])
        self.assertIn("M2: no part names a belief", r["gaps"])
        self.assertIn("M1.2: zz* matches no belief", r["unknown"])
        self.assertIn("M1: C9 is not in docs/THREAT-MODEL.md", r["unknown"])
        self.assertIn("M7-y.toml: the file name does not start with M2-", r["unknown"])
        self.assertEqual(r["no_invariant"], ["M1", "M2"])
        self.assertEqual(r["orphans"], ["C3 serves no mission", "I1 serves no mission"])
        self.assertEqual(r["unowned_beliefs"], {"operations": 1})
        self.assertEqual(r["undocumented_belief_controls"], ["operations"])

    def test_a_part_tested_elsewhere_is_still_a_gap_and_says_where(self):
        import mission_coverage
        m = mission("M1", ["C1", "C2", "C3"], ["I1"])
        m += '\n[[part]]\nsays = "the mod"\nbeliefs = []\ntests = ["tests/mod.test.ts"]\n'
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

    def test_a_claim_needs_a_kind_and_an_existing_mission(self):
        import mission_coverage
        claims = CLAIMS.replace('kind = "limit"\nmission = "M1"', 'kind = "limit"\nmission = "M9"')
        claims = claims.replace('kind = "feature"', 'kind = "wish"')
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], claims=claims))
        self.assertIn("claim names no existing mission (M9): A name without a label.", r["claims"])
        self.assertIn("claim kind 'wish' is not one of promise, limit, feature: **Checks a value first:**",
                      r["claims"])

    def test_strict_fails_on_each_blocking_class_and_the_report_alone_does_not(self):
        import mission_coverage
        cases = {"claim": (self.covered(), ["C1", "C2", "C3", "I1"], CLAIMS.replace("A name without", "A cat with")),
                 "orphan": ({"M1-x": mission("M1", ["C1", "C2"], ["I1"])}, ["C1", "C2", "I1"], CLAIMS),
                 "gap": ({"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"], parts=(("n", []),))}, ["C1"], CLAIMS),
                 "empty glob": ({"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"], parts=(("n", ["b0", "zz"]),))},
                                ["C1"], CLAIMS)}
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
                    "M2-y": mission("M2", [], parts=(("all", ["b*"]),), measure=None),
                    "M3-z": mission("M3", [], parts=(("all", ["b*"]),),
                                    measure=read.replace("holdout-v2", "holdout-v9"))}
        root = self.tree(missions, ["C1", "C2", "C3", "I1"])
        (root / "LOG.md").write_text(log, encoding="utf-8")
        r = mission_coverage.analyse(root)
        self.assertEqual(r["measures"], ["M1: 0.7 = recall (bound: g)"])
        self.assertIn("M2: no [measure], and no `none` that says why", r["unknown"])
        self.assertIn("M3: the measure cannot be read: no row with 'holdout-v9' in LOG.md", r["unknown"])

    def test_the_repository_maps_every_promise_and_names_only_documented_controls(self):
        import mission_coverage
        r = mission_coverage.analyse(ROOT)
        self.assertGreaterEqual(len(r["missions"]), 1, "a population test must fail on an empty population")
        self.assertEqual(r["unknown"], [])
        self.assertEqual(r["orphans"], [], "a documented control must serve a mission")
        self.assertEqual(r["claims"], [], "every promise of README.md and PRIVACY.md maps to a mission")


if __name__ == "__main__":
    unittest.main()
