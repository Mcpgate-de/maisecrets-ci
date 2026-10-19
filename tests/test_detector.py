"""Two detectors in one process (detect.Detector): each keeps its own regions, sources and reference form, and the
caches that follow from them (the rule list, the allow list, the shape rules, the scan order, the label words, the
time of the rules of your own). Before the Detector, the configuration lived in the module: with the setters of
detect.py, two configurations in two threads gave the result of the other one (the `en` scan got the `de` rule in
300 of 300 runs, measured on ea2c8832)."""
import json
import os
import subprocess
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402
from test_detection_boundary import CORE  # noqa: E402

DE = regions.Active(regions=("generic", "de"), languages=("en", "de"), source="test")
US = regions.Active(regions=("generic", "us"), languages=("en",), source="test")
NAME = "Ada " + "Lovelace"
VALUE = "".join(("Tz8", "qLw2", "vR4", "Hm"))   # invented
REF_KEY = "".join(("k9", "Qz", "7Lm", "Wx2"))
# each text has a result that one part of the configuration decides
TEXTS = {
    "languages": "Kennwort: " + VALUE,                                  # Kennwort is a label word with German on
    "sources": "mail from " + NAME + " today",                          # a term of the sources of A
    "references": "db_pass" "word = " + '"#ref-' + REF_KEY + '#"',      # a reference in the form of A
    "regions us": "SSN: " + "-".join(("536", "22", "8726")),            # a US rule
    "regions de": "Hauptstraße 5, " + "10115" + " Berlin",              # a German address
}


# a label and its value as two arguments: only the pass of the label and literal values finds it (_literal_hits)
LITERAL = 'f("Kennwort", "' + VALUE + '")'
REF_LITERAL = "sec" "ret: #ref-" + REF_KEY + "#"


class Names(detect.Sources):
    """A term list of one name."""

    def term_matches(self, text):
        out, i = [], text.find(NAME)
        while i >= 0:
            out.append(detect.Match("term:person", "NAME", NAME, i, i + len(NAME)))
            i = text.find(NAME, i + 1)
        return out


class Hashes(detect.References):
    """A foreign reference form: #ref-<key>#."""

    def hit_is_a_reference(self, text, start, secret):
        return secret.startswith("#ref-") and secret.endswith("#")

    def names_a_key(self, low):
        return low.startswith("#ref-")


def detector_a():
    return detect.Detector(regions=DE, sources=Names(), references=Hashes())


def detector_b():
    return detect.Detector(regions=US, sources=detect.NO_SOURCES, references=detect.NO_REFERENCES)


def kinds(d, text):
    return [m.kind for m in d.scan(text, channel="tool")]


def alone():
    """The result of each text under each configuration, each detector new and on its own."""
    return {name: (kinds(detector_a(), t), kinds(detector_b(), t)) for name, t in TEXTS.items()}


class TwoDetectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.want = alone()

    def test_the_premise_each_part_of_the_configuration_decides_one_text(self):
        w = self.want
        self.assertEqual(w["languages"], (["ds-keyword-colon"], []), "Kennwort is a label only with German on")
        self.assertEqual(w["sources"], (["term:person"], []))
        self.assertEqual(w["references"][0], [], "a reference of A's form is no hit for A")
        self.assertTrue(w["references"][1], "the same text is a hit without A's form")
        self.assertEqual(w["regions us"], ([], ["us-ssn#2"]))
        self.assertEqual(w["regions de"], (["street-address"], []))

    def test_two_detectors_used_in_turn_keep_their_own_results(self):
        a, b = detector_a(), detector_b()
        for _ in range(3):
            for name, text in TEXTS.items():
                self.assertEqual((kinds(a, text), kinds(b, text)), self.want[name], name)
        self.assertIsNot(a.rules(), b.rules())
        self.assertNotEqual({r.id for r in a.rules()}, {r.id for r in b.rules()}, "the regions give other rules")

    def test_one_text_object_scanned_by_two_detectors_gets_the_result_of_each(self):
        # the per-text index of a thread keeps the label hits of a text (_literal_hits, the only pass that finds
        # this form); the label words follow the languages, so a second detector that scans the same str object
        # must not get the hits of the first one
        a, b = detector_a(), detector_b()
        text = LITERAL
        self.assertEqual((kinds(a, text), kinds(b, text), kinds(a, text)),
                         (["label-pw-literal"], [], ["label-pw-literal"]))

    def test_one_text_object_follows_a_change_of_the_default_detector(self):
        self.addCleanup(detect.use_regions, None)
        self.addCleanup(detect.use_references, None)
        text = LITERAL
        detect.use_regions(regions.Active(regions=("generic",), languages=("en",), source="test"))
        self.assertEqual([m.kind for m in detect.scan(text, channel="tool")], [])
        detect.use_regions(DE)
        self.assertEqual([m.kind for m in detect.scan(text, channel="tool")], ["label-pw-literal"], "new languages")
        # the reference form decides whether a value after a label is a key (_ds_value_ok). A keyword rule takes
        # this span before the label pass, so the cache itself is asked: first the form that makes the value a key
        # (no label hit), then no form (a label hit)
        ref = REF_LITERAL
        detect.use_references(Hashes())
        self.assertEqual(detect._literal_hits(ref, "tool"), [])
        detect.use_references(detect.NO_REFERENCES)
        self.assertEqual([h[0] for h in detect._literal_hits(ref, "tool")], ["label-secret-literal"], "a new form")

    def test_two_curl_rules_of_one_id_keep_their_own_patterns(self):
        head = r"\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})"   # a head that the curl matcher splits off
        user = detect.Rule(id="curl-probe", type="SECRET", regex=detect.LazyRegex(head + r"\s-u\s+(\S+)"),
                           secret_group=1)
        token = detect.Rule(id="curl-probe", type="SECRET", regex=detect.LazyRegex(head + r"\s--tok\s+(\S+)"),
                            secret_group=1)
        text = "cu" "rl -" "u " + "ab:cd" + " --tok " + "zzzz" + " https://x.test"
        got = [[m.value for m in detect.scan(text, channel="tool", rule_list=[r])] for r in (user, token, user)]
        self.assertEqual(got, [["ab:cd"], ["zzzz"], ["ab:cd"]])

    def test_a_changed_region_reader_takes_effect_at_reset_and_regions_names_the_loaded_ones(self):
        given = [DE]
        d = detect.Detector(regions=lambda: given[0], sources=detect.NO_SOURCES)
        self.assertEqual(kinds(d, TEXTS["regions us"]), [])
        given[0] = US
        self.assertEqual(d.regions(), DE, "the rule list is still the one of the first answer")
        self.assertEqual(kinds(d, TEXTS["regions us"]), [], "a scan keeps one configuration until reset()")
        d.reset()
        self.assertEqual(d.regions(), US)
        self.assertEqual(kinds(d, TEXTS["regions us"]), ["us-ssn#2"])

    def test_the_rule_specs_change_nothing_of_the_loaded_snapshot(self):
        given = [DE]
        d = detect.Detector(regions=lambda: given[0], sources=detect.NO_SOURCES)
        self.assertEqual(kinds(d, LITERAL), ["label-pw-literal"])
        given[0] = US
        d._run(detect.rule_specs)          # builds the rule list of the reader's new answer
        d.explain_allowed(VALUE)
        self.assertEqual(d.regions(), DE)
        self.assertEqual(kinds(d, "".join([LITERAL])), ["label-pw-literal"], "the label words of the loaded list")
        # the rules load, then the reader changes before the first scan: the scan keeps the loaded languages
        given[0] = DE
        fresh = detect.Detector(regions=lambda: given[0], sources=detect.NO_SOURCES)
        fresh.rules()
        given[0] = US
        self.assertEqual(kinds(fresh, "".join([LITERAL])), ["label-pw-literal"])

    def test_a_first_scan_with_a_rule_list_takes_the_label_words_of_the_detector(self):
        literal = [r for r in detector_a().rules() if r.id == "label-pw-literal"]
        self.assertEqual(len(literal), 1, "the premise: the rule of the label pass")
        fresh = detect.Detector(regions=DE, sources=detect.NO_SOURCES)
        self.assertEqual([m.kind for m in fresh.scan(LITERAL, channel="tool", rule_list=literal)], ["label-pw-literal"])
        english = detect.Detector(regions=US, sources=detect.NO_SOURCES)
        self.assertEqual([m.kind for m in english.scan(LITERAL, channel="tool", rule_list=literal)], [])
        # new regions on the default detector drop the label words of the old ones, before its rules load again
        self.addCleanup(detect.use_regions, None)
        detect.use_regions(DE)
        detect.rules()
        detect.use_regions(US)
        self.assertEqual([m.kind for m in detect.scan(LITERAL, channel="tool", rule_list=literal)], [])

    def test_a_curl_rule_keeps_its_own_flags(self):
        import re
        head = r"\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})"
        rule = detect.Rule(id="curl-probe", type="SECRET", regex=detect.LazyRegex(head + r"\s-u\s+(\S+)", re.I),
                           secret_group=1)
        text = "CU" "RL -" "U " + "ab:cd" + " https://x.test"
        self.assertEqual([m.value for m in detect.scan(text, channel="tool", rule_list=[rule])], ["ab:cd"])

    def test_a_curl_rule_whose_dot_crosses_every_line_runs_as_it_is(self):
        import re
        head = r"\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})"
        rule = detect.Rule(id="curl-probe", type="SECRET",
                           regex=detect.LazyRegex(head + r"\s-u\s+(\S+)", re.I | re.S), secret_group=1)
        text = "cu" "rl https://x.test" + " \\\n" * 11 + " -" "U " + "ab:cd"
        self.assertEqual([m.value for m in detect.scan(text, channel="tool", rule_list=[rule])], ["ab:cd"])

    def test_two_first_scans_of_one_detector_load_one_snapshot(self):
        # the first scan of A's thread loads the rules and waits inside its reader; a second thread's first scan
        # must wait for that snapshot, not load its own (a second answer of the reader made a hybrid one)
        asked, entered, release = [], threading.Event(), threading.Event()

        def reader():
            asked.append(threading.current_thread().name)
            if threading.current_thread().name == "first":
                entered.set()
                release.wait(5)
                return DE
            return US
        d = detect.Detector(regions=reader, sources=detect.NO_SOURCES)
        got = {}

        def run(name):
            got[name] = [kinds(d, "".join([t])) for t in (LITERAL, TEXTS["regions us"])]
        first = threading.Thread(target=run, args=("first",), name="first")
        second = threading.Thread(target=run, args=("second",), name="second")
        first.start()
        self.assertTrue(entered.wait(30), "the premise: the first load is inside its reader")
        second.start()
        second.join(timeout=0.5)        # the second scan waits for the first load (or, without a lock, loads)
        release.set()
        first.join(timeout=60)
        second.join(timeout=60)
        self.assertEqual(asked, ["first"], "one load, one answer of the reader")
        self.assertEqual(got["first"], got["second"])
        self.assertEqual(got["first"], [["label-pw-literal"], []], "the snapshot of the first answer")

    def test_one_detector_in_two_threads_counts_the_steps_of_both(self):
        entered = {"one": threading.Event(), "two": threading.Event()}
        release = threading.Event()

        class Waits:
            """A pattern whose step waits while its word is in the text: a rule of your own inside its regex."""
            flags, groups = 0, 0

            def __init__(self, word):
                self.pattern, self.word = word, word

            def finditer(self, text):
                if self.word in text:
                    entered[self.word].set()
                    release.wait(30)
                yield from ()

            def search(self, text):
                return None

        class TwoRules(detect.Sources):
            def user_rules(self):
                return [detect.Rule(id="user:" + w, type="SECRET", regex=Waits(w)) for w in ("one", "two")]
        d = detect.Detector(regions=DE, sources=TwoRules())
        d.rules()
        threads = [threading.Thread(target=d.scan, args=(w,), kwargs={"channel": "tool"}) for w in ("one", "two")]
        for t in threads:
            t.start()
        try:
            self.assertTrue(entered["one"].wait(30) and entered["two"].wait(30), "the premise: both steps run")
            self.assertEqual(sorted(rule.id for rule, _ in d._running.values()), ["user:one", "user:two"],
                             "a step of one thread hid the step of the other")
        finally:
            release.set()
            for t in threads:
                t.join(timeout=60)
        self.assertEqual(d._running, {})
        self.assertEqual(d._regex_chars, {"user:one": 6, "user:two": 6}, "each scan adds its characters once")

    def test_two_detectors_in_two_threads_keep_their_own_results(self):
        a, b = detector_a(), detector_b()
        wrong, errors = [], []

        def run(d, side):
            try:
                for _ in range(40):
                    for name, text in TEXTS.items():
                        got = kinds(d, text)
                        if got != self.want[name][side]:
                            wrong.append((side, name, got))
            except Exception as e:  # noqa: BLE001 - reported below
                errors.append(repr(e))
        interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            threads = [threading.Thread(target=run, args=(d, side)) for side, d in enumerate((a, b))]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=300)
        finally:
            sys.setswitchinterval(interval)
        self.assertFalse([t for t in threads if t.is_alive()], "a scan thread did not end")
        self.assertEqual(errors, [])
        self.assertEqual(wrong, [], "a detector read the configuration of the other one")

    def test_one_detector_in_four_threads_compiles_its_rules_without_a_crash(self):
        # a rule compiles at its first use; a thread that came second read a half-made keyword rule
        # (_KeywordTail: `_tail` was None after `_any` was set) and raised AttributeError
        text = TEXTS["languages"] + "\n" + TEXTS["references"]
        errors = []
        interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            for _ in range(15):
                d = detector_b()
                d.rules()
                gate = threading.Barrier(4)

                def run():
                    try:
                        gate.wait()
                        kinds(d, text)
                    except Exception as e:  # noqa: BLE001 - reported below
                        errors.append(repr(e))
                threads = [threading.Thread(target=run) for _ in range(4)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=300)
        finally:
            sys.setswitchinterval(interval)
        self.assertEqual(errors, [])

    def test_a_scan_of_one_detector_inside_a_scan_of_the_other_keeps_both_results(self):
        b = detector_b()
        inner = []

        class NamesThatAskB(Names):
            def term_matches(self, text):
                inner.append({name: kinds(b, t) for name, t in TEXTS.items()})
                return super().term_matches(text)
        a = detect.Detector(regions=DE, sources=NamesThatAskB(), references=Hashes())
        for name, text in TEXTS.items():
            self.assertEqual(kinds(a, text), self.want[name][0], name)
        self.assertTrue(inner, "the premise: B scanned inside the scans of A")
        for got in inner:
            self.assertEqual(got, {name: w[1] for name, w in self.want.items()}, "B inside A")

    def test_the_caches_belong_to_their_detector(self):
        a, b = detector_a(), detector_b()
        for text in TEXTS.values():
            kinds(a, text), kinds(b, text)
        a._run(detect._shape_rule_ids), b._run(detect._shape_rule_ids)   # is_fixture's shape rules
        self.assertIn("kennwort", a._pw_last_on)
        self.assertNotIn("kennwort", b._pw_last_on, "the label words of A's languages")
        for field in ("_rules", "_label_class", "_shape_ids", "_order", "_regex_time"):
            self.assertIsNot(getattr(a, field), getattr(b, field), field)
        for d in (a, b):
            self.assertEqual(d._shape_ids, {r.id for r in d.rules()
                                            if (r.form or detect._registry.form_of(r.id)) == "shape"})
        self.assertNotEqual(a._shape_ids, b._shape_ids, "the regions give other shape rules")

    def test_the_allow_list_belongs_to_its_detector(self):
        text = TEXTS["regions us"]

        class AllowsTheRule(detect.Sources):
            def allow_list(self):
                return frozenset(), frozenset({"us-ssn"})
        off = detect.Detector(regions=US, sources=AllowsTheRule())
        on = detector_b()
        self.assertEqual((kinds(off, text), kinds(on, text), kinds(off, text)), ([], ["us-ssn#2"], []))
        self.assertEqual(off.allow_list()[1], frozenset({"us-ssn"}))
        self.assertEqual(on.allow_list(), (frozenset(), frozenset()))

    def test_a_scan_adds_no_state_to_a_detector_that_its_constructor_did_not_make(self):
        made = set(vars(detector_a()))
        a = detector_a()
        for text in TEXTS.values():
            a.findings(text, channel="tool")
        a.explain_allowed(VALUE)
        self.assertEqual(set(vars(a)), made)

    def test_the_default_detector_is_not_touched_by_another_detector(self):
        detect.rules()
        before = detect._DEFAULT._rules
        default = {name: [m.kind for m in detect.scan(t, channel="tool")] for name, t in TEXTS.items()}
        a, b = detector_a(), detector_b()
        for text in TEXTS.values():
            kinds(a, text), kinds(b, text)
        self.assertIs(detect._DEFAULT._rules, before)
        self.assertEqual({name: [m.kind for m in detect.scan(t, channel="tool")] for name, t in TEXTS.items()},
                         default)

    def test_the_setters_of_the_module_configure_only_the_default_detector(self):
        a = detector_a()
        self.addCleanup(detect.use_regions, None)
        self.addCleanup(detect.use_sources, None)
        self.addCleanup(detect.use_references, None)
        detect.use_regions(US)
        detect.use_sources(detect.NO_SOURCES)
        detect.use_references(detect.NO_REFERENCES)
        for name, text in TEXTS.items():
            self.assertEqual(kinds(a, text), self.want[name][0], name)
            self.assertEqual([m.kind for m in detect.scan(text, channel="tool")], self.want[name][1], name)

    def test_a_setter_inside_activate_configures_the_default_detector_not_the_active_one(self):
        a = detector_a()
        self.addCleanup(detect.use_regions, None)
        with a.activate():
            detect.use_regions(US)
            self.assertEqual(kinds(a, TEXTS["regions de"]), ["street-address"], "A keeps its regions")
        self.assertEqual([m.kind for m in detect.scan(TEXTS["regions us"], channel="tool")], ["us-ssn#2"])

    def test_activate_routes_the_functions_of_the_module_to_a_detector_and_restores_the_default(self):
        a, b = detector_a(), detector_b()
        default = [m.kind for m in detect.scan(TEXTS["sources"], channel="tool")]
        with a.activate():
            self.assertEqual([m.kind for m in detect.scan(TEXTS["sources"], channel="tool")], ["term:person"])
            with b.activate():
                self.assertEqual([m.kind for m in detect.scan(TEXTS["regions us"], channel="tool")], ["us-ssn#2"])
            self.assertEqual([m.kind for m in detect.scan(TEXTS["regions us"], channel="tool")], [])
        self.assertEqual([m.kind for m in detect.scan(TEXTS["sources"], channel="tool")], default)

    def test_the_time_of_a_rule_of_your_own_belongs_to_its_detector(self):
        slow = []

        class OneRule(detect.Sources):
            def __init__(self):
                self.rule = detect.Rule(id="user:probe", type="SECRET", regex=detect.LazyRegex(r"probe-[0-9]{6}", 0))

            def user_rules(self):
                return [self.rule]

            def note_slow(self, rule, ms):
                slow.append(rule.id)
        a = detect.Detector(regions=DE, sources=OneRule())
        b = detect.Detector(regions=DE, sources=OneRule())
        self.assertEqual(kinds(a, "probe-123456"), ["user:probe"])
        a._regex_time["user:probe"] = detect.USER_RULE_BUDGET * 10    # A's rule ran over its budget
        kinds(a, "probe-123456")
        self.assertEqual(slow, ["user:probe"], "the premise: A takes its rule out")
        self.assertEqual(kinds(a, "probe-654321"), [])
        self.assertEqual(kinds(b, "probe-654321"), ["user:probe"], "B's rule of the same id keeps running")
        self.assertLess(b.slowest_user_rule()[1], detect.USER_RULE_BUDGET, "B counts its own time")


_TWO_DETECTORS_IN_A_FRESH_PROCESS = """
import json, sys
sys.path.insert(0, sys.argv[1])
from maisecrets import detect, regions


class Hashes(detect.References):
    def hit_is_a_reference(self, text, start, secret):
        return secret.startswith("#ref-") and secret.endswith("#")

    def names_a_key(self, low):
        return low.startswith("#ref-")


de = detect.Detector(regions=regions.Active(regions=("generic", "de"), languages=("en", "de"), source="test"),
                     sources=detect.NO_SOURCES, references=Hashes())
us = detect.Detector(regions=regions.Active(regions=("generic", "us"), languages=("en",), source="test"),
                     sources=detect.NO_SOURCES, references=detect.NO_REFERENCES)
text = sys.argv[2]
print(json.dumps([[m.kind for m in de.findings(text, channel="tool", path="/tmp/a.txt")],
                  [m.kind for m in us.findings(text, channel="tool", path="/tmp/a.txt")],
                  sorted(m for m in sys.modules if m.startswith("maisecrets."))]))
"""


class FreshProcessTests(unittest.TestCase):
    def test_two_explicit_detectors_import_only_core_modules(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX"))}
        text = TEXTS["regions us"] + "\n" + TEXTS["references"]
        r = subprocess.run([sys.executable, "-I", "-c", _TWO_DETECTORS_IN_A_FRESH_PROCESS, str(ROOT), text],
                           capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        de, us, mods = json.loads(r.stdout)
        self.assertEqual(de, [], "no US rule and the reference form of this detector")
        self.assertIn("us-ssn#2", us)
        self.assertGreater(len(us), 1, "the reference is a hit without the form")
        loaded = {m.split(".", 1)[1] for m in mods}
        self.assertEqual(loaded - CORE, set(), f"only core modules: {sorted(loaded - CORE)}")


if __name__ == "__main__":
    unittest.main()
