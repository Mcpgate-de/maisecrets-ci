"""A detector reads of its computer only what its caller did not give (detect.Host, regions.resolve(locale=)): the
person's own user name (their home path is no personal data), the year (a birth date lies before it) and the locale
(`auto` and the label language). Two detectors with other hosts give their own results in one process, and a
detector with an explicit configuration gives the same result on any host."""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402

ACTIVE = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
USER = "ad" + "a"
HOME = "see /home/" + USER + "/src/app.py"
BIRTH = "date of birth: " + "-".join(("2025", "03", "04"))   # a date of 2025


def kinds(d, text):
    return [m.kind for m in d.scan(text, channel="tool")]


def detector(user, year):
    return detect.Detector(regions=ACTIVE, sources=detect.NO_SOURCES, references=detect.NO_REFERENCES,
                           host=detect.Host(user=user, year=year))


class HostTests(unittest.TestCase):
    def test_two_detectors_with_other_hosts_give_their_own_results(self):
        own, other = detector(USER, 2020), detector("bob", 2030)
        self.assertEqual((kinds(own, HOME), kinds(other, HOME)), ([], ["user-in-home-path"]),
                         "the own user's home is no personal data")
        self.assertEqual((kinds(own, BIRTH), kinds(other, BIRTH)), ([], ["birth-date-after-label"]),
                         "a date of the year or later is no birth date")
        self.assertEqual(kinds(own, HOME), [], "in turn")

    def test_an_explicit_host_reads_nothing_of_the_computer(self):
        d = detector(USER, 2030)
        with mock.patch("getpass.getuser", side_effect=AssertionError("read the user")) as user, \
                mock.patch("time.gmtime", side_effect=AssertionError("read the clock")) as clock:
            self.assertEqual(kinds(d, HOME + "\n" + BIRTH), ["birth-date-after-label"])
        self.assertFalse(user.called or clock.called)

    def test_the_default_host_reads_the_computer(self):
        d = detect.Detector(regions=ACTIVE, sources=detect.NO_SOURCES)
        self.assertIs(d.host, detect.THIS_COMPUTER)
        with mock.patch("getpass.getuser", return_value=USER):
            self.assertEqual(kinds(d, HOME), [])
        with mock.patch("getpass.getuser", return_value="bob"):
            self.assertEqual(kinds(d, HOME), ["user-in-home-path"])
        with mock.patch("getpass.getuser", side_effect=KeyError("no passwd entry")):
            self.assertEqual(kinds(d, HOME), ["user-in-home-path"], "no user name: every home is a user's")

    def test_a_given_locale_decides_auto_and_reads_no_system_setting(self):
        with mock.patch.object(regions, "system_locale", side_effect=AssertionError("read the system")):
            de = regions.resolve({"regions": ["auto"]}, locale="de_DE")
            fr = regions.resolve({"regions": ["auto"]}, locale="fr_FR.UTF-8")
        self.assertEqual(de.regions, ("generic", "de"))
        self.assertIn("de", de.languages)
        self.assertEqual(fr.regions, ("generic", "fr"))
        with mock.patch.object(regions, "system_locale", return_value="it_IT"):
            self.assertEqual(regions.resolve({"regions": ["auto"]}).regions, ("generic", "it"), "else the system's")


_SCAN = """
import json, sys
sys.path.insert(0, sys.argv[1])
from maisecrets import detect, regions
explicit = sys.argv[2] == "explicit"
active = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
d = detect.Detector(regions=active if explicit else regions.resolve({"regions": ["auto"]}),
                    sources=detect.NO_SOURCES, references=detect.NO_REFERENCES,
                    host=detect.Host(user="carol", year=2030) if explicit else None)
print(json.dumps([[m.kind for m in d.scan(t, channel="tool")] for t in sys.argv[3:]]))
"""


class FreshProcessTests(unittest.TestCase):
    def run_on(self, user: str, lang: str, mode: str) -> list:
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("CLAUDE", "CODEX", "LC_", "LANG", "MAISECRETS_LOCALE"))}
        # getpass reads LOGNAME, USER, LNAME, USERNAME; MAISECRETS_LOCALE wins over the system setting everywhere
        env.update({"USER": user, "LOGNAME": user, "USERNAME": user, "LANG": lang, "LC_ALL": lang,
                    "MAISECRETS_LOCALE": lang})
        texts = [HOME, "SSN: " + "-".join(("536", "22", "8726")), "Kennwort: " + "".join(("Tz8", "qLw2", "vR4"))]
        r = subprocess.run([sys.executable, "-I", "-c", _SCAN, str(ROOT), mode, *texts], capture_output=True,
                           text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_an_explicit_detector_gives_one_result_on_two_hosts(self):
        a = self.run_on(USER, "de_DE.UTF-8", "explicit")
        b = self.run_on("bob", "en_US.UTF-8", "explicit")
        self.assertEqual(a, b)
        self.assertEqual(a[0], ["user-in-home-path"], "the given user is not the one of the path")

    def test_the_premise_a_detector_of_the_host_follows_the_host(self):
        own = self.run_on(USER, "en_US.UTF-8", "host")
        other = self.run_on("bob", "en_US.UTF-8", "host")
        self.assertEqual((own[0], other[0]), ([], ["user-in-home-path"]))
        us = self.run_on("bob", "en_US.UTF-8", "host")
        de = self.run_on("bob", "de_DE.UTF-8", "host")
        self.assertNotEqual(us[1:], de[1:], "auto follows the locale")


if __name__ == "__main__":
    unittest.main()
