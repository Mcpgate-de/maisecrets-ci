"""The beliefs layer is a view over the tests: every file must name tests that exist and an
anchor that occurs exactly once, or the replay in CI would prove nothing. Static checks only;
the mutation itself is replayed by scripts/replay_can_fail.py, never inside the suite."""
import importlib
import sys
try:
    import tomllib
except ImportError:     # Python < 3.11: the belief files are checked on the CI Pythons
    tomllib = None
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
BELIEFS = sorted((ROOT / "beliefs").glob("*.toml"))


@unittest.skipIf(tomllib is None, "tomllib is Python 3.11+; the other CI Pythons check the belief files")
class BeliefsWellFormedTests(unittest.TestCase):
    def test_there_are_beliefs(self):
        self.assertGreaterEqual(len(BELIEFS), 10, "a population test must fail on an empty population")

    def test_every_belief_names_existing_tests_and_a_unique_anchor(self):
        for path in BELIEFS:
            with self.subTest(path.name):
                b = tomllib.loads(path.read_text(encoding="utf-8"))
                for key in ("belief", "control", "statement", "runner", "proof"):
                    self.assertIn(key, b)
                self.assertEqual(b["belief"], path.stem)
                self.assertTrue(b["runner"], "a belief without an owning test is prose")
                mod = [t for t in b["runner"] if t.partition("::")[0].endswith(".test.ts")]
                # the replay runs a belief's tests in one runner: the mod's (claude plugin test) or Python's
                self.assertIn(len(mod), (0, len(b["runner"])), f"{path.name}: mod and Python tests in one belief")
                for test_id in b["runner"]:
                    file, _, rest = test_id.partition("::")
                    self.assertTrue((ROOT / file).exists(), test_id)
                    if test_id in mod:
                        text = (ROOT / file).read_text(encoding="utf-8")
                        self.assertTrue(f"test('{rest}'" in text or f'test("{rest}"' in text,
                                        f"{test_id}: no test of that name in {file}")
                        continue
                    module = importlib.import_module(file[:-3].replace("/", "."))
                    obj = module
                    for part in rest.split("::"):
                        self.assertTrue(hasattr(obj, part), f"{test_id}: {part} not found")
                        obj = getattr(obj, part)
                proofs = b["proof"] if isinstance(b["proof"], list) else [b["proof"]]
                self.assertTrue(proofs, "a belief without a mutation proves nothing")
                for proof in proofs:
                    target = ROOT / proof["file"]
                    self.assertTrue(target.exists(), proof["file"])
                    text = target.read_text(encoding="utf-8")
                    self.assertEqual(text.count(proof["find"]), 1, f"{path.name}: anchor must occur exactly once")
                    self.assertNotEqual(proof["find"], proof["replace"],
                                        "a mutation that changes nothing proves nothing")
                if b.get("kind") == "invariant":
                    # one goal over every path: one test and one mutation would be a mechanism belief
                    self.assertGreaterEqual(len(b["runner"]), 2, f"{path.name}: an invariant needs several tests")
                    self.assertGreaterEqual(len(proofs), 2, f"{path.name}: an invariant needs several mutations")
                    for proof in proofs:
                        self.assertIn("path", proof, f"{path.name}: each mutation names the path it removes")
                else:
                    self.assertNotIn("kind", b, f"{path.name}: the only kind is \"invariant\"")
                    self.assertIsInstance(b["proof"], dict, f"{path.name}: several mutations make an invariant")

    def test_every_documented_control_with_code_has_a_belief(self):
        covered = set()
        for path in BELIEFS:
            covered.add(tomllib.loads(path.read_text(encoding="utf-8"))["control"])
        # C11 (TTL) is a data rule with no single removable line; every other control is enforced
        # by code that a mutation can remove, and each one needs a proof
        for control in ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C12", "C13", "C14", "C15", "C16",
                        "C17", "C20", "C24", "C25", "C26", "C28", "C29", "C31", "C33"):
            self.assertIn(control, covered, f"{control} has no belief")


if __name__ == "__main__":
    unittest.main()
