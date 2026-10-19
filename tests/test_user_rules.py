"""Rules of your own (maisecrets/user_rules.py, C25): rule folders with static checks and a quarantine, the allow
list of exact values and rule ids, the rule_dirs setting that only a typed prompt changes, the NAME type, the extension
point of the sources (detect.use_sources), and `maisecrets rules`.

Every value is made up and built from parts at run time, so scripts/scan_tree.py finds no shape in this file."""
from __future__ import annotations

import contextlib
import io
import json
import os
import platform
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import cli, detect, events, hooks, placeholder, settings, user_rules, vault  # noqa: E402
from maisecrets.vault import HOME, ConfigError, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")
OWN = Path(HOME, "rules.d")
ALLOW = Path(HOME, "allow.txt")
TAIL = "".join(["Rq4L", "m8Zt", "Kw2P"]) * 2          # 24 characters, no known shape
ADDRESS = "ada" + "@" + "firma-xyz.de"
OTHER_ADDRESS = "bob" + "@" + "firma-xyz.de"


def token(prefix: str = "tkx") -> str:
    return prefix + "_" + TAIL


def _clean() -> None:
    CONFIG.write_text(json.dumps(TEST_CONFIG))
    shutil.rmtree(OWN, ignore_errors=True)
    for p in (ALLOW, user_rules.STATE_FILE, events.EVENTS):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    detect.reset_rules()


def tearDownModule():  # noqa: N802 - unittest hook
    _clean()
    _hygiene.assert_pristine()


def write_rules(folder: Path, rules: list, name: str = "team.json") -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(json.dumps({"rules": rules}), encoding="utf-8")


def kinds(text: str) -> list[str]:
    return [m.kind for m in detect.scan(text)]




@contextlib.contextmanager
def later_pass(matcher):
    """A pass after the rules that finds what `matcher` returns and keeps the spans the rules took: the import pass of
    the plugin's sources with these hits added. The tests of detect.extra_matchers (removed: no caller outside the
    tests) use it; the sources are the one boundary for such a pass. Unlike the old loop, the import pass keeps the
    parts of a hit outside a taken span (_term_rest)."""
    from maisecrets.sources import PluginSources

    class WithHits(PluginSources):
        def import_matches(self, text):
            return list(super().import_matches(text)) + list(matcher(text))
    detect.use_sources(WithHits())
    try:
        yield
    finally:
        detect.use_sources(None)

class Base(unittest.TestCase):
    def setUp(self):
        _clean()
        self.addCleanup(_clean)
        self.tmp = Path(tempfile.mkdtemp(prefix="rules-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)


class RuleFolders(Base):
    def test_a_rule_in_the_own_folder_finds_its_shape_after_the_built_in_rules(self):
        write_rules(OWN, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])
        (OWN / "more.prefixes").write_text("# a comment\nbuild-key  bkx-[0-9a-f]{32}\n", encoding="utf-8")
        detect.reset_rules()
        found = detect.scan(f"deploy with {token()} now")
        self.assertEqual([(m.kind, m.type, m.value) for m in found], [("user:team-token", "SECRET", token())])
        self.assertEqual(kinds("key bkx-" + "0123456789abcdef" * 2), ["user:build-key"])
        ids = [r.id for r in detect.rules()]
        active = detect.active_regions()
        own = detect._load_own()
        parts = {"own secret rules": [r for r in own if r.type == "SECRET"],
                 "detect-secrets": detect._load_detect_secrets(active.languages),
                 "betterleaks": detect._load_betterleaks(), "own_secret_rules.json": detect._load_own_secret_rules(),
                 "presidio": detect._load_presidio(active.regions), "own PII": [r for r in own if r.type != "SECRET"]}
        for part, rules in parts.items():
            with self.subTest(part):
                self.assertTrue(rules)
                self.assertLess(max(ids.index(r.id) for r in rules if r.id in ids), ids.index("user:team-token"),
                                "every built-in rule runs before the rules of your own")
        # a built-in shape stays the built-in's: the user rule never takes the span first
        write_rules(OWN, [{"id": "my-webhook", "regex": r"whsec_[A-Za-z0-9+/=_-]{24,}", "keywords": ["whsec_"]}])
        detect.reset_rules()
        self.assertEqual(kinds("whsec_" + TAIL), ["webhook-signing-secret"])

    def test_a_rule_that_fails_a_check_is_quarantined_and_the_rest_load(self):
        good = {"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}
        bad = {
            "nested": ({"id": "nested", "regex": r"tky_(?:[a-z]+)+"}, "a nested quantifier"),
            "in-a-row": ({"id": "in-a-row", "regex": r"tkr_.*.*Z"}, "two repeats in a row"),
            "leading": ({"id": "leading", "regex": r"\w+tkz_secret"}, "starts with a quantifier"),
            "short": ({"id": "short", "regex": r"ab[0-9]{30}"}, "no keyword or literal of 4"),
            "long": ({"id": "long", "regex": "tkq_" + "a" * 300}, "longer than 300"),
            "broken": ({"id": "broken", "regex": r"tkw_(unclosed"}, "does not compile"),
            "bad-id": ({"id": "bad id!", "regex": r"tkv_[a-z]{20}"}, "an id that is not"),
            "bad-type": ({"id": "bad-type", "type": "PASSWORD", "regex": r"tku_[a-z]{20}"}, "a type that is not"),
            "short-kw": ({"id": "short-kw", "regex": r"[a-z]{3}_[0-9]{20}", "keywords": ["ab"]}, "no keyword or"),
        }
        write_rules(OWN, [good] + [r for r, _ in bad.values()])
        places = {rid: f"rule {n}" for n, rid in enumerate(bad, 2)}
        (OWN / "broken.json").write_text("{not json", encoding="utf-8")
        (OWN / "huge.prefixes").write_text("# x\n" * (user_rules.MAX_FILE_BYTES // 4 + 10), encoding="utf-8")
        detect.reset_rules()
        loaded = user_rules.load()
        self.assertEqual([r.id for r in loaded.rules], ["user:team-token"])
        reasons = {(q.file, q.rule): q.reason for q in loaded.quarantined}
        for rid, (rule, why) in bad.items():
            with self.subTest(rid):
                self.assertIn(why, reasons.get(("team.json", places[rid]), ""), reasons)
        self.assertIn("not valid JSON", reasons[("broken.json", "")])
        self.assertIn("larger than 64 KB", reasons[("huge.prefixes", "")])
        self.assertEqual(kinds(token()), ["user:team-token"], "the good rule of the same file still works")
        for q in loaded.quarantined:
            self.assertNotIn("tky_", q.reason + q.rule, "a reason names the check, never the regex")
            self.assertNotIn("nested", q.rule, "a refused rule is named by its place, never by a text of its own")

    def test_bounded_repeats_and_lookarounds_pass_the_checks(self):
        for rx in (r"(?<![a-z])tkb_(?:-[a-z0-9]{4}){3}", r"\btkc_[a-z]{1,63}(?:\.[a-z]{1,63}){1,5}",
                   r"(?i)acme[_-]?key[=:]\s?([a-f0-9]{32})", r"[A-Z]{4}-tkd_[0-9]{8}"):
            with self.subTest(rx):
                why, compiled, prefilter = user_rules.check_regex(rx)
                self.assertIsNone(why)
                self.assertTrue(prefilter and all(len(k) >= 4 for k in prefilter), prefilter)

    def test_a_folder_holds_at_most_500_rules_and_an_id_of_an_earlier_folder_runs_under_its_own_name(self):
        many = [{"id": f"r{i}", "regex": f"tk{i:03d}_[A-Za-z0-9]{{24}}"}
                for i in range(user_rules.MAX_RULES_PER_FOLDER + 7)]
        (OWN).mkdir(parents=True)
        for part in range(0, len(many), 200):      # several files, one limit for the folder
            write_rules(OWN, many[part:part + 200], f"part{part:04d}.json")
        team = self.tmp / "team"
        write_rules(team, [{"id": "r0", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        loaded = user_rules.load({"rule_dirs": [str(team)]})
        self.assertEqual(len(loaded.rules), user_rules.MAX_RULES_PER_FOLDER + 1)
        reasons = [q.reason for q in loaded.quarantined]
        self.assertIn("rules past the limit of 500 per folder (or of 2000 looked at); the rest of the folder is not "
                      "read", reasons)
        self.assertIn("an id that a rule of an earlier folder has; this rule runs as user:r0#2", reasons)
        self.assertEqual(loaded.rules[-1].id, "user:r0#2", "r0 of the second folder")

    def test_a_folder_inside_the_maisecrets_home_or_a_relative_one_is_not_read(self):
        for shown, why in ((str(HOME), "inside the maisecrets folder"), ("relative/rules", "not an absolute path")):
            with self.subTest(shown):
                loaded = user_rules.load({"rule_dirs": [shown]})
                (folder,) = [f for f in loaded.folders if f.shown == shown]
                self.assertIn(why, folder.state)
        loaded = user_rules.load({"rule_dirs": [str(self.tmp / "not-yet")]})
        self.assertEqual([f.state for f in loaded.folders if f.source == "setting"], ["missing"])

    def test_a_folder_reads_only_rule_files_never_an_allow_list(self):
        team = self.tmp / "team"
        write_rules(team, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])
        (team / "allow.txt").write_text(token() + "\nrule: email\n", encoding="utf-8")
        (team / "notes.txt").write_text("tkx_ is ours\n", encoding="utf-8")
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(team)]}))
        detect.reset_rules()
        self.assertEqual(kinds(f"{token()} and {ADDRESS}"), ["user:team-token", "email"])
        self.assertEqual(user_rules.load().quarantined, [], "the other files are not even read")

    def test_policy_folders_come_first_and_stay_when_the_person_removes_theirs(self):
        team, admin = self.tmp / "team", self.tmp / "admin"
        write_rules(team, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        write_rules(admin, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}", "type": "NAME"}])
        policy = self.tmp / "policy.json"
        policy.write_text(json.dumps({"rule_dirs": [str(admin)], "allow": ["rule: url-query-secret"]}))
        with mock.patch.dict(vault.POLICY_PATHS, {platform.system(): policy}):
            CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(team)]}))
            cfg = load_config()
            self.assertNotIn("rule_dirs", cfg["policy_keys"], "the person keeps their own folders")
            loaded = user_rules.load(cfg)
            self.assertEqual([(f.source, f.rules) for f in loaded.folders], [("policy", 1), ("own", 0), ("setting", 1)])
            self.assertEqual(loaded.rules[0].type, "NAME", "on one id the administrator's rule stays first")
            self.assertEqual([r.id for r in loaded.rules], ["user:tok", "user:tok#2"])
            self.assertEqual(user_rules.allow_list(cfg)[1], frozenset({"url-query-secret"}))
            self.assertIn(str(admin), settings.render(show_all=True, only="rule_dirs"))
            for broken in ({"rule_dirs": "not a list"}, {"rule_dirs": [1]}, {"allow": "rule: email"}):
                policy.write_text(json.dumps(broken))
                with self.assertRaises(ConfigError, msg="a broken policy still fails closed"):
                    load_config()


class AllowList(Base):
    def setUp(self):
        super().setUp()
        write_rules(OWN, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24,}", "keywords": ["tkx_"]}])

    def test_an_allow_entry_is_one_exact_value(self):
        ALLOW.write_text(f"# my own build token\n{token()}\n", encoding="utf-8")
        detect.reset_rules()
        self.assertEqual(kinds(f"use {token()} here"), [], "the exact value is never a hit")
        self.assertEqual(kinds(f"use {token()}XYZ here"), ["user:team-token"], "a longer value is another value")
        self.assertEqual(kinds(f"use tkx_{TAIL[1:]}Q here"), ["user:team-token"])
        ALLOW.write_text("tkx_.*\n", encoding="utf-8")
        detect.reset_rules()
        self.assertEqual(kinds(f"use {token()} here"), ["user:team-token"], "an entry is never a pattern")

    def test_an_allowed_value_keeps_its_span_so_no_later_rule_reports_a_part(self):
        address = ADDRESS
        ALLOW.write_text(address + "\n", encoding="utf-8")
        detect.reset_rules()
        self.assertEqual(kinds(f"mail {address} today"), [])
        self.assertEqual(kinds("mail " + OTHER_ADDRESS), ["email"])

        def first_name(t: str) -> list:      # a later matcher that finds a part of the allowed address
            at = t.find(address)
            return [detect.Match("term:person", "NAME", "ada", at, at + 3)] if at >= 0 else []
        with later_pass(first_name):
            self.assertEqual(kinds(f"mail {address} today"), [])

    def test_a_rule_id_switches_the_rule_off(self):
        ALLOW.write_text("rule: user:team-token\nrule: email\n", encoding="utf-8")
        detect.reset_rules()
        ids = {r.id for r in detect.rules()}
        self.assertNotIn("email", ids)
        self.assertNotIn("user:team-token", ids)
        self.assertEqual(kinds(f"{token()} {ADDRESS}"), [])
        self.assertIn("iban", {r.id.split("#")[0] for r in detect.rules()}, "only the named rules go")

    def test_an_unreadable_allow_list_allows_nothing(self):
        ALLOW.write_bytes(b"\xff\xfe" + token().encode())
        detect.reset_rules()
        self.assertEqual(kinds(token()), ["user:team-token"])


class RuleDirsSetting(Base):
    def _prompt(self, text: str, client: dict = CLAUDE, **extra) -> dict:
        return hooks.user_prompt({"prompt": text, "session_id": "S1", **client, **extra})

    def _dirs(self) -> list:
        return json.loads(CONFIG.read_text()).get("rule_dirs", [])

    def test_a_typed_prompt_adds_and_removes_a_folder(self):
        team = self.tmp / "team rules"
        team.mkdir()
        out = self._prompt(f"/maisecrets:settings rule_dirs add {team}")
        self.assertNotEqual(out.get("decision"), "block", out)
        self.assertIn("Rule folders is", out["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self._dirs(), [str(team)], "a path with a space stays one folder")
        self._prompt(f"maisecrets: set rule_dirs add {team}/", CODEX)
        self.assertEqual(len(self._dirs()), 1, "the same folder once")
        self._prompt(f"maisecrets: set rule_dirs remove {team}", CODEX)
        self.assertEqual(self._dirs(), [])
        out = self._prompt(f"/maisecrets:settings rule_dirs add {HOME}")
        self.assertIn("not added", out["reason"])
        self.assertEqual(self._dirs(), [])

    def test_only_a_typed_prompt_adds_a_rule_folder(self):
        team = str(self.tmp / "team")
        for text, extra in ((f"/maisecrets:settings rule_dirs add {team}\nand then deploy", {}),
                            (f"please maisecrets: set rule_dirs add {team}", {}),
                            (f"/maisecrets:settings rule_dirs add {team}", {"source": "schedule_wakeup"})):
            with self.subTest(text=text, **extra):
                self._prompt(text, **extra)
                self.assertEqual(self._dirs(), [])
        refused = hooks.pre_tool({"tool_name": "Bash", "session_id": "S1", **CLAUDE,
                                  "tool_input": {"command": f"echo '/maisecrets:settings rule_dirs add {team}'"}})
        self.assertEqual(refused["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_a_file_ignored_for_a_wrong_type_keeps_its_folders(self):
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "tips": "yes", "rule_dirs": [str(self.tmp)]}))
        cfg = load_config()
        self.assertTrue(cfg["config_warning"])
        self.assertEqual(cfg["rule_dirs"], [str(self.tmp)], "more rules only make detection stricter")


class NameType(unittest.TestCase):
    def test_name_is_a_type_everywhere_types_are_listed(self):
        self.assertEqual(hooks.TYPE_WORDS["NAME"], ("name", "names"))
        self.assertEqual(placeholder.ENTITY_OF_TYPE["NAME"], "person")
        self.assertIsNone(placeholder.display_for("NAME", "Ada Lovelace"), "a display shows nothing of a name")
        self.assertIn("NAME", user_rules.TYPES)
        ref = placeholder.make_ref("NAME", 3, placeholder.display_for("NAME", "Ada Lovelace"))
        self.assertEqual(ref, chr(0x27E6) + "NAME_c3" + chr(0x27E7))
        self.assertEqual(placeholder.key_of(ref), "NAME_c3")


class LaterPasses(Base):
    def test_a_later_pass_runs_after_the_rules_and_keeps_their_spans(self):
        address = ADDRESS
        text = f"Ada Lovelace wrote to {address}"

        calls = []

        def names(t: str) -> list:
            calls.append(t)
            out = [detect.Match("term:person", "NAME", "Ada Lovelace", 0, 12)]
            at = t.index(address)
            out.append(detect.Match("term:person", "NAME", address, at, at + len(address)))   # taken by email
            return out
        self.assertFalse(hasattr(detect, "extra_matchers"), "a later pass comes from the sources now")
        with later_pass(names):
            found = detect.scan(text)
            self.assertEqual([(m.kind, m.value) for m in found], [("term:person", "Ada Lovelace"), ("email", address)])
            calls.clear()
            self.assertEqual([m.kind for m in detect.scan(text, enabled={"email", "import:probe"})], ["email"],
                             "enabled holds for them too")
            self.assertTrue(calls, "the pass ran and enabled dropped its hit")
            self.assertEqual([m.kind for m in detect.scan(text, enabled={"email", "import"})], ["term:person", "email"],
                             "the pass enabled as a whole keeps its hit")
            ALLOW.write_text("Ada Lovelace\n", encoding="utf-8")
            detect.reset_rules()
            self.assertEqual([m.kind for m in detect.scan(text)], ["email"], "the allow list holds for them too")

    def test_the_terms_pass_runs_after_the_rules_and_a_term_claims_a_span_a_rule_took(self):
        # the terms are a pass of the registry (phase "terms"), not an extra matcher
        address = ADDRESS
        text = f"Ada Lovelace wrote to {address}"

        def names(t: str) -> list:
            at = t.index(address)
            return [detect.Match("term:person", "NAME", "Ada Lovelace", 0, 12),
                    detect.Match("term:person", "NAME", address, at, at + len(address))]   # taken by email
        from maisecrets import registry
        self.assertFalse(hasattr(detect, "extra_matchers"), "the terms are a pass of the sources")
        self.assertGreater(registry.PHASES["terms"], registry.PHASES["user"])
        with mock.patch.object(detect, "_term_matches", names):
            # a term that a rule took keeps the rule's span and type, and becomes the term: the store keeps the
            # entity id, and the placeholder is never resolved (C26)
            self.assertEqual([(m.kind, m.type, m.value) for m in detect.scan(text)],
                             [("term:person", "NAME", "Ada Lovelace"), ("term:person", "EMAIL", address)])
            self.assertEqual([m.kind for m in detect.scan(text, enabled={"email"})], ["email"])
            self.assertEqual([m.kind for m in detect.scan(text, enabled={"terms:term"})], ["term:person"] * 2)
            self.assertEqual([m.kind for m in detect.scan(text, rule_list=detect.rules())], ["email"],
                             "a rule list a caller built has no terms pass")
            ALLOW.write_text("Ada Lovelace\n", encoding="utf-8")
            detect.reset_rules()
            self.assertEqual([m.value for m in detect.scan(text)], [address], "the allow list holds for them too")


class Quarantine(Base):
    def test_the_session_start_names_a_new_quarantine_once_and_events_log_records_it(self):
        write_rules(OWN, [{"id": "nested", "regex": r"tky_(?:[a-z]+)+"}])
        detect.reset_rules()
        note = user_rules.session_note()
        self.assertIn("1 rule(s) of your own were left out", note)
        (line,) = events.load()
        self.assertEqual(line["hits"], [{"key": "", "type": "RULE", "kind": "user:?"}])
        self.assertIn("a nested quantifier", line["outcome"])
        self.assertIsNone(user_rules.session_note(), "unchanged: said once")
        with redirect_stdout(io.StringIO()) as out:
            cli.cmd_report(["last"])
        self.assertIn("no detection recorded yet", out.getvalue(), "a quarantine is no false alarm to report")


class BothChannels(Base):
    """A rule of your own is a detection rule: it runs in the prompt channel and in the tool channel (0.6.17), also
    on the cleaned copy of a tool result (0.6.18), and after every built-in rule in both."""

    def test_a_rule_of_your_own_finds_its_token_in_a_prompt_and_in_a_tool_result(self):
        write_rules(OWN, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])
        detect.reset_rules()
        text = f"deploy with {token()} and {ADDRESS}"
        for channel in ("prompt", "tool"):
            with self.subTest(channel):
                self.assertEqual([m.kind for m in detect.scan(text, channel=channel)], ["user:team-token", "email"])

    def test_a_rule_of_your_own_never_cuts_a_name_that_the_personal_data_rules_find(self):
        text = "customer record\nname: " + "Emma " + "Johan" + "sson" + "\ncity: Oslo"
        detect.reset_rules()
        before = [(m.kind, m.start, m.end) for m in detect.scan(text, channel="tool")]
        self.assertTrue(before, "the personal data rules of 0.6.21 find the name")
        write_rules(OWN, [{"id": "surname", "regex": "Johan" + "sson", "keywords": ["johansson"], "type": "NAME"}])
        detect.reset_rules()
        self.assertEqual([(m.kind, m.start, m.end) for m in detect.scan(text, channel="tool")], before)

    def test_a_rule_of_your_own_never_cuts_an_address_that_the_cleaned_copy_sees_whole(self):
        text = "user&#64;sample-shop.de wrote: hello"
        detect.reset_rules()
        before = [(m.kind, m.start, m.end) for m in detect.scan(text, channel="tool")]
        self.assertEqual([k for k, _, _ in before], ["email"], "main reads the address through the entity")
        write_rules(OWN, [{"id": "dom", "regex": r"shop\.de wrote", "keywords": ["shop.de"], "type": "NAME"}])
        detect.reset_rules()
        self.assertEqual([(m.kind, m.start, m.end) for m in detect.scan(text, channel="tool")][:1], before)

    def test_the_allow_list_holds_for_the_personal_data_rules(self):
        name = "Emma " + "Johan" + "sson"
        text = "customer record\nname: " + name + "\ncity: Oslo"
        detect.reset_rules()
        (hit,) = detect.scan(text, channel="tool")
        for line in (name, "rule: " + hit.kind):
            with self.subTest(line):
                ALLOW.write_text(line + "\n", encoding="utf-8")
                detect.reset_rules()
                self.assertEqual(detect.scan(text, channel="tool"), [])

    def test_a_rule_folder_taken_off_is_a_loosening_and_another_spelling_is_not(self):
        home = os.path.expanduser("~")
        self.assertTrue(settings.loosens("rule_dirs", ["~/team", "/opt/r"], ["/opt/r"]))
        self.assertFalse(settings.loosens("rule_dirs", ["~/team"], [home + "/team/"]))
        self.assertFalse(settings.loosens("rule_dirs", ["/opt/r"], ["/opt/r", "/opt/s"]))

    def test_the_tool_channel_finds_it_behind_a_colour_code(self):
        write_rules(OWN, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])
        detect.reset_rules()
        t = token()
        text = "deploy with " + t[:6] + "\x1b[0m" + t[6:]
        self.assertEqual([m.kind for m in detect.scan(text)], [], "the prompt channel reads the raw text")
        (m,) = detect.scan(text, channel="tool")
        self.assertEqual(m.kind, "user:team-token")
        self.assertEqual(text[m.start:m.end].replace("\x1b[0m", ""), t, "the whole token, colour code included")


class GateAOfBlock1(Base):
    """Findings of Gate A (codex) on the rebased branch of block 1."""

    def test_a_folder_the_agent_writes_cannot_take_out_a_rule_of_a_later_folder_by_its_id(self):
        decoy, kept = self.tmp / "checkout-a", self.tmp / "checkout-b"
        write_rules(decoy, [{"id": "acme-prod", "regex": r"never_[A-Z]{20}", "keywords": ["never_"]}])
        write_rules(kept, [{"id": "acme-prod", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(decoy), str(kept)]}))
        detect.reset_rules()
        self.assertEqual(kinds(f"deploy with {token()}"), ["user:acme-prod#2"])
        ALLOW.write_text("rule: user:acme-prod\n", encoding="utf-8")
        detect.reset_rules()
        self.assertEqual(kinds(f"deploy with {token()}"), [], "the allow list switches the id and its #n off together")

    def test_a_rule_the_budget_left_untested_waits_for_its_timed_test(self):
        write_rules(OWN, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])

        def no_time(sources, budget=None, limit_ms=None, info=None):
            if info is not None:
                info["budget"] = True
            return {}
        with mock.patch.object(user_rules, "probe", no_time):
            self.assertEqual(user_rules.load({}).rules, [], "untested: not in this scan")
        self.assertEqual([r.id for r in user_rules.load({}).rules], ["user:team-token"], "tested at the next load")

    def test_where_no_test_child_starts_the_static_checks_alone_stand(self):
        write_rules(OWN, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])
        with mock.patch.object(user_rules.sys, "executable", ""):
            self.assertEqual([r.id for r in user_rules.load({}).rules], ["user:team-token"])

    def test_a_folder_of_many_files_is_read_only_to_its_limits(self):
        team = self.tmp / "team"
        for i in range(12):
            write_rules(team, [{"id": f"r{i}", "regex": f"tk{i:03d}_[A-Za-z0-9]{{24}}"}], f"f{i:02d}.json")
        with mock.patch.object(user_rules, "MAX_FILES", 4):
            loaded = user_rules.load({"rule_dirs": [str(team)]})
        self.assertEqual([r.id for r in loaded.rules], [f"user:r{i}" for i in range(4)])
        self.assertIn("8 rule file(s) past the limit of 4 per folder", [q.reason for q in loaded.quarantined])
        with mock.patch.object(user_rules, "MAX_ENTRIES", 5):
            loaded = user_rules.load({"rule_dirs": [str(team)]})
            self.assertEqual(len(user_rules._rule_files(team)), 5)
        self.assertEqual(len(loaded.rules), 5)
        self.assertIn("a folder of more than 5 entries; the rest is not read", [q.reason for q in loaded.quarantined])


class GateBOfBlock1(Base):
    """Findings of Gate B (Opus) on the rebased branch of block 1."""

    def test_bounded_repeats_in_a_row_are_found_slow_by_the_timed_test(self):
        rx = "abcd" + "[a-z]{0,99}" * 3 + "Q"
        self.assertIsNone(user_rules.check_regex(rx)[0], "the static checks let it through")
        write_rules(OWN, [{"id": "poly", "regex": rx}])
        loaded = user_rules.load({})
        self.assertEqual(loaded.rules, [])
        (q,) = loaded.quarantined
        self.assertTrue(q.reason.startswith("slow"), q.reason)

    def test_a_full_folder_checks_no_further_rule(self):
        team = self.tmp / "team"
        write_rules(team, [{"id": f"r{i}", "regex": f"tk{i:03d}_[A-Za-z0-9]{{24}}"} for i in range(50)])
        calls = []
        real = user_rules.check_regex

        def counted(*a, **kw):
            calls.append(1)
            return real(*a, **kw)
        with mock.patch.object(user_rules, "MAX_RULES_PER_FOLDER", 3), \
                mock.patch.object(user_rules, "check_regex", counted):
            rules, quarantined, _ = user_rules.load_folder(team, "team")
        self.assertEqual(len(rules), 3)
        self.assertLessEqual(len(calls), 4, "only the first rule past the limit is checked")
        self.assertIn("rules past the limit of 3 per folder (or of 2000 looked at); the rest of the folder is not read",
                      [q.reason for q in quarantined])

    def test_refused_and_duplicate_rules_count_toward_the_rules_looked_at(self):
        team = self.tmp / "team"
        team.mkdir()
        lines = [f"r0  tail{i:04d}_[a-z]{{20}}" for i in range(30)] + ["bad id!  x"] * 30
        (team / "dup.prefixes").write_text("\n".join(lines) + "\n", encoding="utf-8")
        calls = []
        real = user_rules.check_regex

        def counted(*a, **kw):
            calls.append(1)
            return real(*a, **kw)
        with mock.patch.object(user_rules, "MAX_LOOKED", 10), mock.patch.object(user_rules, "check_regex", counted):
            rules, quarantined, _ = user_rules.load_folder(team, "team")
        self.assertEqual([r.id for r in rules], ["user:r0"])
        self.assertLessEqual(len(calls), 11, "a duplicate past the limit is not checked")
        self.assertIn("the rest of the folder is not read", quarantined[-1].reason)

    def test_a_duplicate_id_counts_once_toward_the_rules_looked_at(self):
        team = self.tmp / "team"
        team.mkdir()
        lines = "".join(f"r0  tail{i:04d}_[a-z]{{20}}\n" for i in range(9))
        (team / "dup.prefixes").write_text(lines, encoding="utf-8")
        with mock.patch.object(user_rules, "MAX_LOOKED", 9):
            rules, quarantined, _ = user_rules.load_folder(team, "team")
        self.assertEqual(len(rules), 1)
        self.assertEqual([q.reason for q in quarantined], ["an id that an earlier rule has"] * 8, "nine looked at")

    def test_an_oversized_file_counts_toward_the_bytes_of_the_folder(self):
        team = self.tmp / "team"
        team.mkdir()
        for i in range(3):
            (team / f"big{i}.json").write_text("x" * (user_rules.MAX_FILE_BYTES + 10), encoding="utf-8")
        write_rules(team, [{"id": "late", "regex": r"tkx_[A-Za-z0-9]{24}"}], "z.json")
        with mock.patch.object(user_rules, "MAX_FOLDER_BYTES", 2 * user_rules.MAX_FILE_BYTES + 100):
            rules, quarantined, _ = user_rules.load_folder(team, "team")
        self.assertEqual(rules, [])
        self.assertIn("big2.json and the files after it are not read", quarantined[-1].reason)

    def test_a_slow_branch_is_timed_with_its_own_literal(self):
        rx = "(?:abcd" + "[a-z]{0,99}" * 3 + "Q|safeprefix[A-Z]{8})"
        self.assertIn("abcd", user_rules._test_literals(rx, ("safeprefix",)))
        write_rules(OWN, [{"id": "poly", "regex": rx, "keywords": ["safeprefix"]}])
        loaded = user_rules.load({})
        self.assertEqual(loaded.rules, [])
        self.assertTrue(loaded.quarantined[0].reason.startswith("slow"), loaded.quarantined)

    def test_a_folder_reads_at_most_its_byte_limit(self):
        team = self.tmp / "team"
        for i in range(4):
            write_rules(team, [{"id": f"r{i}", "regex": f"tk{i:03d}_[A-Za-z0-9]{{24}}"}], f"f{i}.json")
        size = (team / "f0.json").stat().st_size
        with mock.patch.object(user_rules, "MAX_FOLDER_BYTES", 2 * size + 1):
            rules, quarantined, _ = user_rules.load_folder(team, "team")
        self.assertEqual([r.id for r in rules], ["user:r0", "user:r1"])
        self.assertIn("f2.json and the files after it are not read", quarantined[-1].reason)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "a FIFO is POSIX")
    def test_a_fifo_in_place_of_a_rule_file_does_not_hold_the_read(self):
        fifo = self.tmp / "swapped.json"
        os.mkfifo(fifo)
        with self.assertRaises(IsADirectoryError):
            user_rules._read(fifo)

    def test_a_file_name_is_printed_without_control_characters(self):
        self.assertEqual(user_rules._shown_name("ok\x1b[2J.prefixes"), "ok?[2J.prefixes")


class SessionStartLine(Base):
    """The start line names the active rules of your own; a folder of rule_dirs that does not load gets a warning."""

    def test_without_rules_of_your_own_the_start_line_has_nothing_to_add(self):
        detect.reset_rules()
        self.assertEqual(user_rules.active_phrase(), "")
        self.assertIsNone(user_rules.broken_folders_note(), "a missing rules.d of your own is no broken setup")

    def test_the_start_line_counts_the_active_rules_and_their_folders(self):
        team = self.tmp / "team"
        write_rules(OWN, [{"id": "one", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]},
                          {"id": "two", "regex": r"tky_[A-Za-z0-9]{24}", "keywords": ["tky_"]}])
        write_rules(team, [{"id": "three", "regex": r"tkz_[A-Za-z0-9]{24}", "keywords": ["tkz_"]},
                           {"id": "nested", "regex": r"tkq_(?:[a-z]+)+"}])
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(team)]}))
        detect.reset_rules()
        self.assertEqual(user_rules.active_phrase(), ", with 3 rules of your own from 2 folders",
                         "a quarantined rule is no active rule")
        shutil.rmtree(OWN)
        detect.reset_rules()
        self.assertEqual(user_rules.active_phrase(), ", with 1 rule of your own from 1 folder")

    def test_a_missing_folder_of_the_setting_is_named_at_every_start(self):
        gone = self.tmp / "gone"
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(gone)]}))
        for _ in range(2):
            detect.reset_rules()
            self.assertEqual(user_rules.broken_folders_note(), f"Warning: the rule folder {gone} (setting) is missing, "
                                                               "so its rules of your own do not run.")
        self.assertEqual(user_rules.active_phrase(), "")

    def test_a_missing_folder_of_the_policy_and_an_unreadable_one_are_named_in_one_sentence(self):
        gone, locked = self.tmp / "gone", self.tmp / "locked"
        write_rules(locked, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        policy = self.tmp / "policy.json"
        policy.write_text(json.dumps({"rule_dirs": [str(gone)]}))
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(locked)]}))
        with mock.patch.dict(vault.POLICY_PATHS, {platform.system(): policy}), \
                mock.patch.object(user_rules, "load_folder", side_effect=self._refuse_locked(locked)):
            detect.reset_rules()
            note = user_rules.broken_folders_note()
        self.assertEqual(note, f"Warning: 2 rule folders do not load, so their rules of your own do not run: "
                               f"{gone} (machine policy, is missing); {locked} (setting, cannot be read).")
        self.assertEqual(note.count(". "), 0, "one sentence")

    def test_a_folder_name_with_a_control_character_is_shown_without_it(self):
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(self.tmp / "a\nb")]}))
        detect.reset_rules()
        note = user_rules.broken_folders_note()
        self.assertIn("a?b (setting) is missing", note)

    def test_the_readme_section_opens_with_the_recipe_for_administrators(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        start = readme.index("\n## Rules of your own\n")
        recipe = readme[start:readme.index("You can add detection rules", start)]
        self.assertIn("**For administrators.**", recipe)
        flat = " ".join(recipe.split())
        steps = ["`maisecrets rules init DIR`", "in a repository", "on each machine",
                 "`rule_dirs` in the machine policy", "run `maisecrets rules check`"]
        self.assertEqual([s for s in steps if s in flat], steps)
        self.assertEqual(sorted(steps, key=flat.index), steps, "the steps in this order")
        self.assertIn("maisecrets reads local folders only", flat)

    @staticmethod
    def _refuse_locked(locked: Path):
        real = user_rules.load_folder

        def load_folder(path, *a, **kw):
            if path == locked:
                raise PermissionError("a folder this user cannot read")   # chmod 000 means nothing to root in CI
            return real(path, *a, **kw)
        return load_folder


class RulesCommand(Base):
    def run_cli(self, *args: str, stdin: str = "") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        stdin_file = io.TextIOWrapper(io.BytesIO(stdin.encode("utf-8")), encoding="utf-8")
        with redirect_stdout(out), redirect_stderr(err), mock.patch("sys.stdin", stdin_file):
            rc = cli.main(["rules", *args])
        return rc, out.getvalue(), err.getvalue()

    def test_check_fails_a_rule_the_started_test_child_gave_no_answer_for(self):
        team = self.tmp / "team"
        write_rules(team, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])

        def silent(sources, budget=None, limit_ms=None, info=None):
            if info is not None:
                info["child"] = True
            return {}
        with mock.patch.object(user_rules, "probe", silent):
            rc, out, _ = self.run_cli("check", str(team))
        self.assertEqual(rc, 1, out)
        self.assertIn("the timed test gave no answer for it", out)

    def test_a_check_keeps_its_timings_so_the_next_hook_call_runs_the_rules(self):
        team = self.tmp / "team"
        write_rules(team, [{"id": f"r{i}", "regex": f"tk{i:03d}_[A-Za-z0-9]{{24}}", "keywords": [f"tk{i:03d}_"]}
                           for i in range(5)])
        rc, out, _ = self.run_cli("check", str(team))
        self.assertEqual(rc, 0, out)
        loaded = user_rules.load({"rule_dirs": [str(team)]}, budget=0)
        self.assertEqual(len(loaded.rules), 5, "no time for a test in this call, and none is needed")

    def test_init_writes_a_folder_that_its_own_check_passes(self):
        top = self.tmp / "team-rules"
        rc, out, _ = self.run_cli("init", str(top))
        self.assertEqual(rc, 0)
        for name in ("README.md", "rules/example.json", "rules/example.prefixes", "samples.txt",
                     ".github/workflows/rules.yml", ".gitlab-ci.yml"):
            self.assertTrue((top / name).is_file(), name)
        readme = (top / "README.md").read_text()
        # the README shows the folder as a person types it (`~/…` under the home folder, where the
        # Windows runner keeps its temp folder); the test takes the same form as the code
        from maisecrets import rules_cli
        self.assertIn("/maisecrets:settings rule_dirs add " + rules_cli._home_form(top.resolve()), readme)
        self.assertIn("No names", readme)
        rc, out, _ = self.run_cli("check", str(top))
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"ok      user:example-internal-token  \d+\.\d ms")
        self.assertIn("samples: all pass", out)
        self.assertEqual(self.run_cli("init", str(top))[0], 1, "never over a folder that has the files")

    def test_check_fails_on_a_refused_rule_and_on_a_sample_and_names_no_text(self):
        top = self.tmp / "t"
        write_rules(top / "rules", [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"},
                                    {"id": "nested", "regex": r"tky_(?:[a-z]+)+"}])
        (top / "samples.txt").write_text(f"hit tok {token()}\nmiss plain words\nmiss {token()}\n", encoding="utf-8")
        rc, out, _ = self.run_cli("check", str(top))
        self.assertEqual(rc, 1)
        self.assertIn("refused team.json:rule 2  a nested quantifier", out)
        self.assertIn("samples.txt line 3: a hit of user:tok where none belongs", out)
        self.assertNotIn(TAIL, out, "a sample's text is never printed")

    def test_show_and_test_print_no_value(self):
        write_rules(OWN, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"}, {"id": "bad", "regex": r"\w+x"}])
        ALLOW.write_text(token() + "\nrule: email\n", encoding="utf-8")
        detect.reset_rules()
        rc, out, _ = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertRegex(out, r"rules\.d \(own\) · 1 rule\(s\) · hash [0-9a-f]{12}")
        self.assertIn("team.json · rule 2 · a regex that starts with a quantifier", out)
        self.assertIn("1 exact value(s), 1 rule id(s) switched off (email)", out)
        self.assertNotIn(TAIL, out)
        ALLOW.unlink()
        detect.reset_rules()
        rc, out, _ = self.run_cli("test", stdin=f"run {token()}\n")
        self.assertEqual(rc, 0)
        self.assertIn("user:tok", out)
        self.assertNotIn(TAIL, out)

    @unittest.skipIf(sys.version_info < (3, 11), "tomllib is Python 3.11+")
    def test_import_converts_the_gitleaks_form_and_refuses_what_it_cannot_read(self):
        toml = self.tmp / "gitleaks.toml"
        toml.write_text(
            '[[rules]]\nid = "acme"\nregex = \'\'\'acme_[a-z0-9]{32}\'\'\'\nkeywords = ["acme_"]\nentropy = 3.5\n'
            '[[rules.allowlists]]\nstopwords = ["example"]\n'
            '[[rules]]\nid = "filtered"\nregex = \'\'\'fltr_[a-z]{20}\'\'\'\n'
            'filter = \'\'\'len(finding["secret"]) > 3\'\'\'\n'
            '[[rules]]\nid = "floor"\nregex = \'\'\'flor_[a-z]{20}\'\'\'\n'
            'filter = \'\'\'entropy(finding["secret"]) <= 3\'\'\'\n'
            '[[rules]]\nid = "slow"\nregex = \'\'\'\\w+slow\'\'\'\n', encoding="utf-8")
        rc, out, err = self.run_cli("import", str(toml))
        self.assertEqual(rc, 1)
        rules = json.loads(out)["rules"]
        self.assertEqual([r["id"] for r in rules], ["acme", "floor"])
        self.assertEqual(rules[0]["allowlists"], [{"stopwords": ["example"]}])
        self.assertEqual(rules[1]["entropy"], 3.0)
        self.assertIn("refused filtered: a filter maisecrets cannot read", err)
        self.assertIn("refused slow: a regex that starts with a quantifier", err)
        team = self.tmp / "imported"
        write_rules(team, rules)
        self.assertEqual(len(user_rules.load_folder(team, "x")[0]), 2, "the output loads")


def iban_complete(cc: str, bban: str) -> str:
    """ISO 13616 check digits (independent of detect._iban_ok)."""
    num = "".join(str(int(c, 36)) for c in bban + cc + "00")
    return f"{cc}{98 - int(num) % 97:02d}{bban}"


SLOW_RX = r"abcd(a|aa)+Z"          # exponential: each `a` doubles the tries when the Z is missing
SLOW_TEXT = "abcd" + "a" * 40 + "!"
SPLIT_RX = r"abcd[ac-y]{1,99}[bc-y]{1,99}[ac-y]{1,99}[bc-y]{1,99}[ac-y]{1,99}Z"   # slow on a run of c only
SLOW_SHAPES = (r"abcd.*.*.*.*Z", r"abcd(?:[a-z]{1,30}){1,30}Z", r"abcd(?=.*.*.*Z)", r"xkey(a|a)*$",
               r"abcd(?:a?){25}a{25}", r"x?[a-z]+abcd", r"acme_(a|aa)+$", r"abcd(x)\1", r"abcd\w+\d+Z")


class OrderAndAllow(Base):
    """Opus review of block 1 (H1): a rule of your own took a span before the PII rules, and an allowed value kept a
    span that a longer built-in hit needed."""

    def test_a_rule_of_your_own_never_cuts_a_built_in_hit(self):
        mail = "max.mueller" + "@" + "example-firma.de"
        iban = iban_complete("DE", "370400440532013000")
        phone = "+49 30 9" + "1234567"
        write_rules(OWN, [{"id": "surname", "type": "NAME", "regex": r"(?i)mueller"},
                          {"id": "bank", "type": "NAME", "regex": iban[4:12]},
                          {"id": "line", "type": "NAME", "regex": r"9" + phone[-7:-3]}])
        detect.reset_rules()
        for text, kind, value in ((f"mail {mail} now", "email", mail), (f"IBAN {iban}", "iban", iban),
                                  (f"Tel. {phone}", "phone", phone)):
            with self.subTest(kind):
                found = detect.scan(text)
                self.assertEqual([(m.kind, m.value == value) for m in found], [(kind, True)])

    def test_an_allowed_domain_and_a_team_rule_leave_the_address_masked(self):
        domain = "example-firma.de"
        mail = "ada" + "@" + domain
        ALLOW.write_text(domain + "\n", encoding="utf-8")
        write_rules(OWN, [{"id": "domain", "type": "NAME", "regex": r"example-firma\.de"}])
        detect.reset_rules()
        self.assertEqual([(m.kind, m.value == mail) for m in detect.scan(f"write to {mail}")], [("email", True)])
        self.assertEqual(kinds(f"see {domain} today"), [], "the exact value alone stays allowed")

    def test_an_allowed_hit_of_a_rule_of_your_own_reserves_no_span(self):
        write_rules(OWN, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        ALLOW.write_text(token() + "\n", encoding="utf-8")
        detect.reset_rules()

        def part(t: str) -> list:          # a later matcher that finds a part of the allowed token
            at = t.find(TAIL)
            return [detect.Match("term:x", "NAME", TAIL[:8], at, at + 8)] if at >= 0 else []
        with later_pass(part):
            self.assertEqual(kinds(f"use {token()} here"), ["term:x"])

    def test_an_allowed_value_never_hides_a_longer_built_in_hit(self):
        short = detect.Rule(id="short-shape", type="SECRET", regex=detect._Lazy(r"tks_[a-z]{8}"))
        long_ = detect.Rule(id="long-shape", type="SECRET", regex=detect._Lazy(r"tks_[a-z]{8}\.[A-Za-z0-9]{24}"))
        value = "tks_abcdefgh"
        ALLOW.write_text(value + "\n", encoding="utf-8")
        detect.reset_rules()
        detect.allow_list()
        with mock.patch.object(detect, "rules", lambda: [short, long_]):
            self.assertEqual(kinds(f"{value}.{TAIL}"), ["long-shape"])
            self.assertEqual(kinds(f"{value} alone"), [])


class Robust(Base):
    """Opus and codex review of block 1 (H2): one odd file, name or number lost every rule of every folder."""

    def _team(self, rules=None, name="team.json"):
        team = self.tmp / "team"
        write_rules(team, rules or [], name)
        return team

    def test_a_number_out_of_range_quarantines_one_rule_and_the_others_stay(self):
        team = self.tmp / "team"
        team.mkdir()
        (team / "big.json").write_text('{"rules": [{"id": "big", "regex": "tkx_[a-z]{20}", "secretGroup": 1e400},'
                                       ' {"id": "inf", "regex": "tki_[a-z]{20}", "entropy": "inf"},'
                                       ' {"id": "ok", "regex": "tkk_[a-z]{20}"}]}', encoding="utf-8")
        write_rules(OWN, [{"id": "mine", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        loaded = user_rules.load({"rule_dirs": [str(team)]})
        self.assertEqual(sorted(r.id for r in loaded.rules), ["user:mine", "user:ok"])
        self.assertEqual({(q.rule, q.reason[:10]) for q in loaded.quarantined},
                         {("rule 1", "an entropy"), ("rule 2", "an entropy")})

    def test_random_rule_files_never_stop_the_load_and_never_cost_another_folder(self):
        import random
        rnd = random.Random(20261012)
        keys = ["rules", "id", "regex", "keywords", "entropy", "secretGroup", "allowlists", "regexes", "stopwords",
                "regexTarget", "condition", "type", "paths"]

        def value(depth: int = 0):
            forms = [lambda: None, lambda: True, lambda: rnd.randint(-10**30, 10**30),
                     lambda: rnd.choice([1e308, -0.0, 3.5]),
                     lambda: rnd.choice(["", "tkf_[a-z]{9}", "(a+)+", "AND", "line", "x" * 400, "\udcff"]),
                     lambda: rnd.choice(["SECRET", "NAME", "zz"]),
                     lambda: [value(depth + 1) for _ in range(rnd.randrange(4))],
                     lambda: {rnd.choice(keys): value(depth + 1) for _ in range(rnd.randrange(5))},
                     lambda: {"rules": [{rnd.choice(keys): value(depth + 1) for _ in range(5)}]}]
            return forms[rnd.randrange(9 if depth < 3 else 6)]()
        write_rules(OWN, [{"id": "mine", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        team = self.tmp / "team"
        team.mkdir()
        self.assertIn("user:mine", [r.id for r in user_rules.load({}).rules], "tested once; budget=0 tests no more")
        for i in range(300):
            data = value()
            text = json.dumps(data) if rnd.random() < 0.9 else json.dumps(data)[:-1]
            (team / "fuzz.json").write_text(text, encoding="utf-8", errors="surrogatepass")
            (team / "fuzz.prefixes").write_text(rnd.choice(["", "id", "id  (", "x" * 70 + " tkp_[a-z]{9}",
                                                            "ok  tkq_[a-z]{9}\n#\n  \n"]), encoding="utf-8")
            loaded = user_rules.load({"rule_dirs": [str(team)]}, budget=0)
            self.assertIn("user:mine", [r.id for r in loaded.rules], f"round {i}")

    def test_a_file_name_that_is_no_utf_8_is_read_and_named(self):
        team = self._team([{"id": "ok", "regex": r"tkk_[a-z]{20}"}])
        try:
            fd = os.open(os.path.join(os.fsencode(team), b"bad\xff.json"), os.O_WRONLY | os.O_CREAT, 0o600)
        except (OSError, UnicodeError):
            # APFS refuses such a name; Windows cannot even pass it (its names are UTF-16, os.open decodes the bytes)
            self.skipTest("this file system refuses a name that is no UTF-8 (APFS, Windows)")
        os.write(fd, json.dumps({"rules": [{"id": "odd", "regex": r"tko_[a-z]{20}"}]}).encode())
        os.close(fd)
        write_rules(OWN, [{"id": "mine", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        loaded = user_rules.load({"rule_dirs": [str(team)]})
        self.assertEqual(sorted(r.id for r in loaded.rules), ["user:mine", "user:odd", "user:ok"])
        with redirect_stdout(io.StringIO()):
            user_rules.reset()
            CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(team)]}))
            self.assertEqual(cli.main(["rules"]), 0)

    @unittest.skipIf(os.name == "nt", "a Windows file name is UTF-16: no name holds an undecodable byte")
    def test_a_file_name_that_is_no_utf_8_counts_in_the_hash_and_prints(self):
        # APFS refuses such a name, so the listing is faked here; Linux runs the test above with a real file
        name = os.fsdecode(b"bad\xff.prefixes")
        entry = mock.Mock(is_symlink=lambda: False, is_file=lambda follow_symlinks=True: True)
        entry.name = name
        listing = mock.MagicMock()
        listing.__enter__.return_value = [entry]
        with mock.patch.object(user_rules.os, "scandir", return_value=listing), \
                mock.patch.object(user_rules, "_read", return_value=b"odd  tko_[a-z]{20}\nodd  (\n"):
            rules, quarantined, digest = user_rules.load_folder(self.tmp, "x")
        self.assertEqual([r.id for r in rules], ["user:odd"])
        self.assertEqual([(q.file, q.rule) for q in quarantined], [("bad�.prefixes", "line 2")])
        self.assertRegex(digest, r"\A[0-9a-f]{12}\Z")

    def test_a_folder_that_fails_costs_only_its_own_rules(self):
        team, other = self._team([{"id": "ok", "regex": r"tkk_[a-z]{20}"}]), self.tmp / "other"
        write_rules(other, [{"id": "more", "regex": r"tkm_[a-z]{20}"}])
        real = user_rules.load_folder

        def broken(path, *a, **k):
            if path == team:
                raise RuntimeError("a folder that fails in a way nobody planned")
            return real(path, *a, **k)
        with mock.patch.object(user_rules, "load_folder", broken):
            loaded = user_rules.load({"rule_dirs": [str(team), str(other)]})
        self.assertEqual([r.id for r in loaded.rules], ["user:more"])
        self.assertEqual([f.state for f in loaded.folders if f.source == "setting"],
                         ["refused: the folder cannot be read", "ok"])

    def test_a_symbolic_link_is_not_followed_and_a_linked_folder_is_read_once(self):
        outside = self.tmp / "notes.txt"
        line = "SYNTH" + "VALUEAAAA1111BBBB2222"
        outside.write_text(f"{line}\nnext tkn_[a-z]{{20}}\n", encoding="utf-8")
        team = self._team([{"id": "ok", "regex": r"tkk_[a-z]{20}"}])
        try:
            (team / "linked.prefixes").symlink_to(outside)
            (self.tmp / "alias").symlink_to(team)
        except (OSError, NotImplementedError):
            self.skipTest("no symbolic links here")
        (team / ".git").mkdir()
        (team / ".git" / "HEAD").write_text("ref: ../../notes.txt\n", encoding="utf-8")
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(team), str(self.tmp / "alias")]}))
        detect.reset_rules()
        loaded = user_rules.load()
        self.assertEqual([r.id for r in loaded.rules], ["user:ok"], "the linked file is not read")
        self.assertEqual(len([f for f in loaded.folders if f.source == "setting"]), 1, "one folder under two names")
        self.assertEqual([(q.file, q.reason[:15]) for q in loaded.quarantined],
                         [("linked.prefixes", "a symbolic link")])
        rc, out, err = RulesCommand.run_cli(self, "check")
        self.assertNotIn("commit", RulesCommand.run_cli(self)[1], "no git metadata is read")
        self.assertNotIn(line, out + err)

    def test_a_refused_line_is_named_by_its_number_never_by_its_text(self):
        line = "SYNTH" + "VALUEAAAA1111BBBB2222"
        OWN.mkdir(parents=True)
        (OWN / "team.prefixes").write_text(f"# rules\n{line}\nok  tkk_[a-z]{{20}}\n{line}x  (\n", encoding="utf-8")
        detect.reset_rules()
        loaded = user_rules.load()
        self.assertEqual([(q.rule, q.reason) for q in loaded.quarantined],
                         [("line 2", "a line without a regex"), ("line 4", "a regex that does not compile")])
        user_rules.session_note()
        rc, out, err = RulesCommand.run_cli(self)
        rc2, out2, err2 = RulesCommand.run_cli(self, "check", str(OWN))
        self.assertIn("refused team.prefixes:line 2", out2)
        for text in (out, err, out2, err2, events.EVENTS.read_text(encoding="utf-8")):
            self.assertNotIn(line, text)

    def test_unreadable_and_non_utf_8_files_say_which(self):
        OWN.mkdir(parents=True)
        (OWN / "latin.prefixes").write_bytes(b"ok tkk_[a-z]{20} \xe4\n")
        (OWN / "locked.prefixes").write_text("ok2 tkl_[a-z]{20}\n", encoding="utf-8")
        os.chmod(OWN / "locked.prefixes", 0)
        self.addCleanup(os.chmod, OWN / "locked.prefixes", 0o600)
        loaded = user_rules.load({})
        reasons = {q.file: q.reason for q in loaded.quarantined}
        self.assertEqual(reasons["latin.prefixes"], "a file that is not UTF-8")
        # root reads the file anyway (CI); Windows has no geteuid, and mode 0 does not stop a read there
        if os.name != "nt" and os.geteuid() != 0:
            self.assertEqual(reasons["locked.prefixes"], "a file that cannot be read")


class FolderForms(Base):
    def test_a_team_repository_is_read_from_rules_by_the_hook_and_the_check_alike(self):
        top = self.tmp / "team-rules"
        write_rules(top / "rules", [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        (top / "package.json").write_text('{"name": "x"}', encoding="utf-8")
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(top)]}))
        detect.reset_rules()
        loaded = user_rules.load()
        self.assertEqual([r.id for r in loaded.rules], ["user:tok"])
        self.assertEqual(loaded.quarantined, [], "the files at the top are not read")
        self.assertEqual(kinds(token()), ["user:tok"])
        rc, out, _ = RulesCommand.run_cli(self, "check", str(top))
        self.assertEqual((rc, out.count("ok      user:tok")), (0, 1))

    def test_a_folder_without_rule_files_says_so(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(empty)]}))
        detect.reset_rules()
        rc, out, _ = RulesCommand.run_cli(self)
        self.assertIn("0 rule(s)", out)
        self.assertIn("no *.json or *.prefixes file here", out)
        self.assertEqual(RulesCommand.run_cli(self, "check", str(empty))[0], 1)
        CONFIG.write_text(json.dumps(TEST_CONFIG))
        said = hooks.user_prompt({"prompt": f"/maisecrets:settings rule_dirs add {empty}", "session_id": "S1",
                                  **CLAUDE})
        self.assertIn("holds no *.json or *.prefixes file", said["hookSpecificOutput"]["additionalContext"])

    def test_an_allowlist_with_condition_and_is_dropped_and_named(self):
        write_rules(OWN, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}", "allowlists": [
            {"condition": "AND", "regexes": [r"tkx_"], "stopwords": ["zzzz"]}]}])
        detect.reset_rules()
        self.assertEqual(kinds(token()), ["user:tok"], "the AND allowlist allows nothing")
        (note,) = user_rules.load().quarantined
        self.assertEqual((note.rule, note.kept), ("user:tok", True))
        self.assertIn("condition AND was dropped", note.reason)
        self.assertIsNone(user_rules.session_note(), "a dropped allowlist is no rule left out")

    def test_check_without_a_folder_fails_on_a_missing_setting_folder_only(self):
        rc, out, _ = RulesCommand.run_cli(self, "check")
        self.assertEqual(rc, 0, out)
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(self.tmp / "gone")]}))
        rc, out, _ = RulesCommand.run_cli(self, "check")
        self.assertEqual(rc, 1)
        self.assertIn("gone (setting): missing", out)

    def test_test_says_no_finding_and_report_names_a_rule_event(self):
        rc, out, _ = RulesCommand.run_cli(self, "test", "hello")
        self.assertEqual((rc, out), (0, "no finding\n"))
        write_rules(OWN, [{"id": "nested", "regex": r"tky_(?:[a-z]+)+"}])
        detect.reset_rules()
        user_rules.session_note()
        with redirect_stdout(io.StringIO()) as out:
            cli.cmd_report(["1"])
        self.assertIn("only left out a rule of your own", out.getvalue())


class Backtracking(Base):
    """Opus review of block 1 (B1): a rule of your own held a hook for 53 s; the thread watchdog could not run, and
    the client's timeout lets the action through."""

    def test_the_shapes_that_backtrack_are_refused(self):
        for rx in SLOW_SHAPES:
            with self.subTest(rx):
                self.assertTrue(user_rules.check_regex(rx)[0])
                self.assertTrue(user_rules.check_regex(rx, allowlist=True)[0] or rx.startswith("x?"),
                                "an allowlist regex must not backtrack either")

    def _slow_rule_passes_the_static_checks(self):
        return mock.patch.object(user_rules, "_backtracks", lambda items: "")

    def test_a_slow_rule_is_timed_out_at_load_once_and_the_verdict_is_kept(self):
        write_rules(OWN, [{"id": "slow", "regex": SLOW_RX}, {"id": "ok", "regex": r"tkk_[a-z]{20}"}])
        with self._slow_rule_passes_the_static_checks(), mock.patch.object(user_rules, "PROBE_DEADLINE", 0.3):
            detect.reset_rules()
            loaded = user_rules.load()
            self.assertEqual([r.id for r in loaded.rules], ["user:ok"])
            (q,) = loaded.quarantined
            self.assertEqual(q.rule, "user:slow")
            self.assertIn("slow: a test text took more than 300 ms", q.reason)
            detect.reset_rules()
            with mock.patch.object(user_rules, "probe", side_effect=AssertionError("tested again")):
                self.assertEqual([r.id for r in user_rules.load().rules], ["user:ok"], "the verdict is kept")
            rc, out, _ = RulesCommand.run_cli(self, "check", str(OWN))
        self.assertEqual(rc, 1)
        self.assertIn("slow    user:slow", out)

    def test_a_rule_over_its_budget_in_a_scan_is_left_out_from_then_on(self):
        write_rules(OWN, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        detect.reset_rules()
        with mock.patch.object(detect, "USER_RULE_BUDGET", -1.0):
            self.assertEqual(kinds(token()), ["user:tok"], "the scan that measured it still reports")
        self.assertEqual(kinds(token()), [], "out of this process")
        (line,) = events.load()
        self.assertEqual(line["hits"][0]["kind"], "user:tok")
        detect.reset_rules()
        (q,) = user_rules.load().quarantined
        self.assertEqual(q.rule, "user:tok")
        self.assertIn("slow: one scan took", q.reason)

    def test_a_slow_text_split_over_many_strings_adds_up(self):
        # each string costs the rule about 15 ms, far under the budget; 100 of them do not (Opus review, round 3)
        write_rules(OWN, [{"id": "rows", "regex": SPLIT_RX}])
        detect.reset_rules()
        with mock.patch.object(user_rules, "probe", return_value={}):     # the load test is not the subject here
            user_rules.load()
        scans = 0
        while "user:rows" in {r.id for r in detect.rules()} and scans < 400:
            detect.scan("row: abcd" + "c" * 50 + "!")
            scans += 1
        self.assertLess(scans, 400, "the regex time of the many scans adds up to the budget")
        self.assertGreater(scans, 1, "one scan alone stays under the budget")
        detect.reset_rules()
        (q,) = user_rules.load(budget=0).quarantined
        self.assertEqual(q.rule, "user:rows")
        self.assertRegex(q.reason, r"slow: one scan took \d+ ms")

    def test_a_correct_rule_with_many_hits_survives_a_watchdog_answer(self):
        # the work on each hit is no time of the rule: only its regex counts (Opus review, round 3). The scan is
        # real and so is its clock; the watchdog's question is asked right after it
        import time
        write_rules(OWN, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])
        detect.reset_rules()
        text = " ".join("tkx_" + "ab" * 6 + "%012d" % i for i in range(40000))
        started = time.perf_counter()
        self.assertGreater(len(detect.scan(text)), 30000)
        elapsed = time.perf_counter() - started
        rule, took = detect.slowest_user_rule()
        self.assertEqual(rule.id, "user:tok", "the rule ran: the test is not empty")
        self.assertLess(took, 0.5 * elapsed, "its regex is a small part of the scan")
        hooks._quarantine_running_rule(elapsed)
        self.assertEqual(user_rules._read_state().get("slow", {}), {}, "a correct rule is not blamed for its hits")
        hooks._quarantine_running_rule(took * 1.5)        # had the regex held the call, it would be the one
        self.assertEqual(len(user_rules._read_state().get("slow", {})), 1)

    def test_the_timing_runs_the_characters_of_the_rule_s_own_repeats(self):
        for rx in (r"tkr_" + r"[b-y]{1,99}" * 5 + "Z",      # slow only on a run of b..y
                   SPLIT_RX):                                 # slow only on a run of what both sets take
            with self.subTest(rx):
                self.assertIsNone(user_rules.check_regex(rx)[0], "passes the static checks")
                write_rules(OWN, [{"id": "rows", "regex": rx}])
                with mock.patch.object(user_rules, "PROBE_DEADLINE", 0.5):
                    detect.reset_rules()
                    (q,) = user_rules.load().quarantined
                self.assertEqual(q.rule, "user:rows")
                self.assertIn("slow: a test text took more than 500 ms", q.reason)

    @unittest.skipIf(os.name == "nt", "a shell script as the interpreter")
    def test_the_test_child_start_counts_against_the_budget(self):
        import time
        slow_python = self.tmp / "slow-python"
        slow_python.write_text(f'#!/bin/sh\nsleep 4\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
        os.chmod(slow_python, 0o755)
        src = user_rules._Source("h1", "f", "x.json", r"tkx_[a-z]{9}", ("tkx_",), ())
        started = time.monotonic()
        with mock.patch.object(user_rules.sys, "executable", str(slow_python)):
            self.assertEqual(user_rules.probe([src], budget=0.3), {})
        self.assertLess(time.monotonic() - started, 3)

    def test_check_keeps_a_rule_out_that_a_real_scan_found_slow(self):
        write_rules(OWN, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        detect.reset_rules()
        user_rules.load()
        (rule,) = detect.rules()[-1:]
        user_rules.note_slow(rule, 900.0)
        rc, out, _ = RulesCommand.run_cli(self, "check", str(OWN))
        self.assertEqual(rc, 1, out)
        self.assertIn("slow    user:tok  the hooks leave it out: a real scan found it slow; change the rule", out)
        detect.reset_rules()
        self.assertEqual(user_rules.load().rules, [], "the check cannot take the verdict back")
        write_rules(OWN, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{25}"}])
        detect.reset_rules()
        self.assertEqual([r.id for r in user_rules.load().rules], ["user:tok"], "a changed rule is checked again")

    @unittest.skipIf(os.name == "nt", "Windows has no SIGALRM: the thread watchdog stays alone there (README)")
    def test_a_hook_process_answers_fail_closed_inside_a_slow_regex_and_leaves_the_rule_out(self):
        import subprocess
        import time
        home = self.tmp / "home"
        home.mkdir()
        team = self.tmp / "team"
        write_rules(team, [{"id": "slow", "regex": SLOW_RX}])
        (home / "config.json").write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(team)]}))
        key = user_rules._hash("json", SLOW_RX, [], [], [])       # the checks passed and the test was fast: seeded
        (home / ".rules-state").write_text(json.dumps({"checks": {key: {"why": None, "kw": ["abcd"]}},
                                                       "tested": {key: 1.0}}))
        env = {**os.environ, "MAISECRETS_HOME": str(home), "MAISECRETS_TEST_HOME_OWNED": str(home),
               "MAISECRETS_TEST_WATCHDOG": "2"}
        payload = {"hook_event_name": "PostToolUse", "session_id": "s1", "tool_name": "Bash", "tool_use_id": "t1",
                   "tool_input": {"command": "cat notes.txt"}, "tool_response": {"stdout": SLOW_TEXT, "stderr": ""}}

        def run() -> tuple[float, str]:
            started = time.monotonic()
            p = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "post-tool"],
                               input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=30)
            return time.monotonic() - started, p.stdout
        took, out = run()
        self.assertIn("took longer than 2s", out, "the alarm answers inside the regex")
        self.assertLess(took, 2 + 3)
        state = json.loads((home / ".rules-state").read_text())
        self.assertIn(key, state["slow"], "the rule that ran is left out from the next call on")
        took, out = run()
        self.assertNotIn("took longer", out)
        self.assertLess(took, 2)
