"""Regions and label languages (maisecrets/detection/regions.py): the system setting, the config, the old
pii_regions key, the label files, and what the detector finds with each language on or off.

Run: python3 -m unittest tests.test_regions -v
Every value is generated at run time, so no literal sits in the tree.
"""
from __future__ import annotations

import json
import os
import platform
import random
import string
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one

from maisecrets import detect, regions, vault  # noqa: E402

_RND = random.Random(927)


def fake_value() -> str:
    body = "".join(_RND.choice(string.ascii_letters) for _ in range(9))
    return body + "".join(_RND.choice(string.digits) for _ in range(4))


class LocaleTests(unittest.TestCase):
    def test_a_locale_gives_its_language_and_country(self):
        for loc, want in [("de_DE.UTF-8", ("de", "de")), ("en-US", ("en", "us")), ("en_GB", ("en", "uk")),
                          ("de_AT@euro", ("de", "at")), ("fr", ("fr", None)), ("C", (None, None)),
                          ("POSIX", (None, None)), ("C.UTF-8", (None, None)), ("", (None, None)),
                          (None, (None, None)), ("zh-Hans-CN", ("zh", "cn"))]:
            with self.subTest(loc):
                self.assertEqual(regions.parse_locale(loc), want)

    def test_maisecrets_locale_wins_then_the_system_setting_then_lang(self):
        with mock.patch.dict(os.environ, {"MAISECRETS_LOCALE": "it_IT", "LANG": "en_US.UTF-8"}):
            self.assertEqual(regions.system_locale(), "it_IT")
        env = {k: v for k, v in os.environ.items() if k not in ("MAISECRETS_LOCALE", "LC_ALL", "LC_MESSAGES")}
        env["LANG"] = "en_US.UTF-8"
        with mock.patch.dict(os.environ, env, clear=True):
            # a German Mac whose terminal says en_US: the system setting decides
            with mock.patch.object(regions.sys, "platform", "darwin"), \
                    mock.patch.object(regions, "_macos_locale", return_value="de_DE"):
                self.assertEqual(regions.system_locale(), "de_DE")
            with mock.patch.object(regions.sys, "platform", "win32"), \
                    mock.patch.object(regions, "_windows_locale", return_value="de-CH"):
                self.assertEqual(regions.system_locale(), "de-CH")
            with mock.patch.object(regions.sys, "platform", "darwin"), \
                    mock.patch.object(regions, "_macos_locale", return_value=None):
                self.assertEqual(regions.system_locale(), "en_US.UTF-8")
            with mock.patch.object(regions.sys, "platform", "linux"):
                self.assertEqual(regions.system_locale(), "en_US.UTF-8")
        env.pop("LANG")
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(regions.sys, "platform", "linux"):
            self.assertIsNone(regions.system_locale())

    def test_the_macos_setting_is_read_from_the_global_preferences(self):
        import plistlib
        with tempfile.TemporaryDirectory() as home:
            prefs = Path(home, "Library", "Preferences")
            prefs.mkdir(parents=True)
            with mock.patch.object(regions.Path, "home", return_value=Path(home)):
                self.assertIsNone(regions._macos_locale(), "no file is no setting")
                (prefs / ".GlobalPreferences.plist").write_bytes(b"not a plist")
                self.assertIsNone(regions._macos_locale(), "a damaged file is no setting")
                (prefs / ".GlobalPreferences.plist").write_bytes(
                    plistlib.dumps({"AppleLocale": "de_DE"}, fmt=plistlib.FMT_BINARY))
                self.assertEqual(regions._macos_locale(), "de_DE")


class ResolveTests(unittest.TestCase):
    def resolve(self, cfg: dict, locale: str | None) -> regions.Active:
        with mock.patch.object(regions, "system_locale", return_value=locale):
            return regions.resolve(cfg)

    def test_auto_is_the_country_of_the_system_setting(self):
        a = self.resolve({"regions": ["auto"], "regions_from": "default"}, "de_DE")
        self.assertEqual((a.regions, a.languages), (("generic", "de"), ("en", "de")))
        self.assertIn("auto = de from the system setting", a.source)

    def test_without_a_system_setting_only_english_and_the_generic_rules(self):
        a = self.resolve({"regions": ["auto"]}, "C.UTF-8")
        self.assertEqual((a.regions, a.languages), (("generic",), ("en",)))
        self.assertIn("no system setting", a.source)
        self.assertEqual(self.resolve({}, None).regions, ("generic",), "no config key is auto")

    def test_the_language_of_each_region_and_of_the_system_count(self):
        # an English system in Austria: German labels come from the region
        a = self.resolve({"regions": ["at", "us"]}, "en_US")
        self.assertEqual((a.regions, a.languages), (("generic", "at", "us"), ("en", "de")))
        # a German system with US rules only: German labels come from the system language
        a = self.resolve({"regions": ["us"]}, "de_DE")
        self.assertEqual((a.regions, a.languages), (("generic", "us"), ("en", "de")))

    def test_codes_are_normalised_and_a_language_without_a_label_file_adds_nothing(self):
        a = self.resolve({"regions": [" GB ", "generic", "auto", "uk", "ar"]}, "hi_IN")
        self.assertEqual(a.regions, ("generic", "uk", "in", "ar"))
        self.assertEqual(a.languages, ("en",), "no hi.txt and no es for ar: a Hindi system gets English labels")

    def test_a_russian_chinese_or_japanese_system_turns_its_labels_on(self):
        for loc, want in [("ru_RU.UTF-8", ("en", "ru")), ("zh_CN", ("en", "zh")), ("zh-Hans_CN", ("en", "zh")),
                          ("zh_TW.UTF-8", ("en", "zh")), ("ja_JP", ("en", "ja")), ("en_JP", ("en", "ja"))]:
            with self.subTest(loc):
                self.assertEqual(self.resolve({}, loc).languages, want)

    def test_each_region_with_a_label_file_turns_its_language_on(self):
        for region, want in [("it", ("en", "it")), ("fr", ("en", "fr")), ("lu", ("en", "fr")),
                             ("be", ("en", "nl", "fr")), ("nl", ("en", "nl")), ("br", ("en", "pt")),
                             ("pt", ("en", "pt")), ("dk", ("en", "da")), ("no", ("en", "nb")),
                             ("cz", ("en", "cs")), ("se", ("en", "sv")), ("kr", ("en", "ko")),
                             ("ru", ("en", "ru")), ("cn", ("en", "zh")), ("tw", ("en", "zh")), ("hk", ("en", "zh")),
                             ("mo", ("en", "zh")), ("jp", ("en", "ja"))]:
            with self.subTest(region):
                self.assertEqual(self.resolve({"regions": [region]}, "C").languages, want)
        # a Norwegian system setting names the language "no" or "nb"; the file is nb.txt
        for loc in ("no_NO", "nb_NO"):
            self.assertEqual(self.resolve({"regions": []}, loc).languages, ("en", "nb"), loc)
        every = {x for r in regions.REGION_LANGUAGE for x in regions._region_languages(r)}
        self.assertEqual(every - set(regions.label_languages_available()), set(),
                         "a region names a language that has no label file")

    def test_an_empty_list_is_the_generic_rules_only(self):
        self.assertEqual(self.resolve({"regions": []}, "de_DE").regions, ("generic",))


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="regions-", dir=_isolate.HOME))
        self.policy = self.tmp / "policy.json"
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE_PLUGIN_OPTION_")}
        self.patches = [mock.patch.dict(vault.POLICY_PATHS, {platform.system(): self.policy}),
                        mock.patch.dict(os.environ, env, clear=True)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        # put the test store back instead of deleting the shared config: a module after this one then
        # reached for the real keychain (final review, 2026-09-28, module order reversed)
        vault.CONFIG.write_text('{"backend": "jsonfile", "allow_plaintext_store": true}', encoding="utf-8")

    def test_the_default_is_auto(self):
        vault.CONFIG.unlink(missing_ok=True)
        cfg = vault.load_config()
        self.assertEqual((cfg["regions"], cfg["regions_from"]), (["auto"], "default"))
        self.assertNotIn("pii_regions", cfg)

    def test_the_old_key_in_the_user_file_sets_the_same_countries(self):
        vault.CONFIG.write_text(json.dumps({"pii_regions": ["generic", "de", "us"]}), encoding="utf-8")
        cfg = vault.load_config()
        self.assertEqual((cfg["regions"], cfg["regions_from"]), (["de", "us"], "config.json"))
        self.assertEqual(cfg["config_warning"], "", "the old key is known, not an unknown key")
        vault.CONFIG.write_text(json.dumps({"pii_regions": ["generic"]}), encoding="utf-8")
        self.assertEqual(vault.load_config()["regions"], [], "generic only stays generic only")
        vault.CONFIG.write_text(json.dumps({"pii_regions": ["us"], "regions": ["it"]}), encoding="utf-8")
        self.assertEqual(vault.load_config()["regions"], ["it"], "the new key wins in the same file")

    def test_a_machine_policy_wins_with_either_key(self):
        vault.CONFIG.write_text(json.dumps({"regions": ["us"]}), encoding="utf-8")
        for key, value in (("regions", ["de"]), ("pii_regions", ["generic", "de"])):
            with self.subTest(key):
                self.policy.write_text(json.dumps({key: value}), encoding="utf-8")
                cfg = vault.load_config()
                self.assertEqual((cfg["regions"], cfg["regions_from"]), (["de"], "machine policy"))
                self.assertEqual(cfg["policy_keys"], [key], "status names the key the administrator wrote")


class LabelFileTests(unittest.TestCase):
    def test_every_label_file_parses_and_each_example_matches_its_label(self):
        import re
        langs = regions.label_languages_available()
        self.assertEqual(langs, ["cs", "da", "de", "en", "es", "fi", "fr", "it", "ja", "ko", "nb", "nl", "pl", "pt",
                                 "ru", "sv", "th", "tr", "zh"])
        for lang in langs:
            labels = regions.load_labels(lang)
            self.assertTrue(labels, lang)
            for lab in labels:
                self.assertTrue(lab.examples, f"{lang}: {lab.regex} has no example")
                self.assertEqual(lab.prefilter, lab.prefilter.lower())
                for ex in lab.examples:
                    with self.subTest(lang=lang, example=ex):
                        self.assertTrue(re.fullmatch(f"(?:{lab.regex})", ex, re.IGNORECASE) or
                                        re.search(f"(?:{lab.regex})$", ex, re.IGNORECASE), ex)
                        self.assertIn(lab.prefilter, ex.lower(), "the prefilter would skip this line")

    def test_a_line_without_three_fields_names_the_file_and_the_line(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "xx.txt").write_text("# comment\n\nonly\ttwo\n", encoding="utf-8")
            with mock.patch.object(regions, "LABELS_DIR", Path(d)):
                with self.assertRaisesRegex(ValueError, r"xx\.txt line 3: expected 3"):
                    regions.load_labels("xx")


class DetectorTests(unittest.TestCase):
    """What the prompt hook finds follows the label languages."""

    def found(self, text: str, languages: tuple[str, ...]) -> list[str]:
        active = regions.Active(regions=("generic",), languages=languages, source="test")
        with detect.Detector(regions=active).activate():
            return [text[m.start:m.end] for m in detect.scan(text) if m.type == "SECRET"]

    def test_a_german_label_is_a_label_only_with_german_on(self):
        value = fake_value()
        for label in ("Kennwort", "zugangsdaten", "geheimnis"):
            with self.subTest(label):
                self.assertEqual(self.found(f"{label}: {value}", ("en", "de")), [value])
                self.assertEqual(self.found(f"{label}: {value}", ("en",)), [])
        # the English label pass allows letters after it, so passwort is a label in every case
        self.assertEqual(self.found(f"passwort: {value}", ("en",)), [value])

    def test_english_labels_are_on_in_every_case(self):
        value = fake_value()
        for label in ("password", "pass", "token", "MY_TOKEN"):
            with self.subTest(label):
                self.assertEqual(self.found(f"{label}: {value}", ("en",)), [value])
                self.assertEqual(self.found(f"{label}: {value}", ("en", "de")), [value])

    def test_the_regions_select_the_presidio_rules(self):
        ids = {r.id.split("#")[0] for r in detect._load_presidio(("generic", "us"))}
        self.assertTrue(any(i.startswith("us-") for i in ids))
        self.assertFalse(any(i.startswith("de-") for i in ids))


if __name__ == "__main__":
    unittest.main()
