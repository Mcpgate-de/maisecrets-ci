"""The vault over the days a real user goes through: config and policy, every backend through one
contract, the index on disk, the life cycle of an entry from paste to purge, and the lock.

0.4.0 shipped with every read of an expired entry raising TypeError and with `expire` outside
its lock, while 144 tests were green: they covered a fresh store. The tests here move a clock,
damage files and run two processes against one index.

The keychain and the Credential Locker are never touched: their backends run against an
emulator of the `security` CLI and of the PowerShell calls, which refuses any other command.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# the vault home is fixed at the first import of maisecrets.vault (another test module may have
# imported it first); everything below takes the home from the module, never from the environment
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import vault  # noqa: E402
from maisecrets.vault import (  # noqa: E402
    FP_KEY_ENTRY, ConfigError, EncryptedFileBackend, Entry, JsonFileBackend, KeychainBackend, LockTimeout, Vault,
    WindowsVaultBackend,
)

HOME = vault.HOME
BASE_CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
JSONCFG = {"backend": "jsonfile", "allow_plaintext_store": True}
T0 = 1_800_000_000.0


_REAL_RUN = subprocess.run


def _refuse_native_stores(args, *a, **kw):
    """No test in this file reaches the real keychain or Credential Locker: a real `security`
    call under a temp HOME opened a macOS dialog on the user's screen (2026-09-27)."""
    if args and Path(str(args[0])).name.lower() in ("security", "powershell", "powershell.exe"):
        raise AssertionError(f"test tried to run the real {args[0]}")
    return _REAL_RUN(args, *a, **kw)


_GUARD = mock.patch.object(vault, "subprocess", types.SimpleNamespace(
    run=_refuse_native_stores, CompletedProcess=subprocess.CompletedProcess, PIPE=subprocess.PIPE,
    TimeoutExpired=subprocess.TimeoutExpired))


def setUpModule():
    _GUARD.start()


def tearDownModule():
    _GUARD.stop()
    import _hygiene
    _hygiene.assert_pristine()


def _reset() -> None:
    for f in ("index.json", "vault.json", "vault.enc.json", "key", "audit.log", "events.log"):
        p = HOME / f
        if p.is_dir():
            shutil.rmtree(p)
        else:
            try:
                p.unlink()
            except FileNotFoundError:
                pass
    vault.CONFIG.write_text(BASE_CONFIG, encoding="utf-8")


FAKE_BIN = HOME / "fake-bin"
NATIVE_MARK = HOME / "a-native-store-binary-ran"


def _child_env(home: Path) -> dict:
    """A child sees only this vault home, no GIT_* variable, and a `security` and `powershell`
    first on PATH that leave a mark and fail: a child that reaches for a native store is seen."""
    FAKE_BIN.mkdir(exist_ok=True)
    for name in ("security", "powershell"):
        script = FAKE_BIN / name
        script.write_text(f'#!/bin/sh\ntouch "{NATIVE_MARK}"\nexit 99\n', encoding="utf-8")
        script.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["MAISECRETS_HOME"] = str(home)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PATH"] = str(FAKE_BIN) + os.pathsep + env.get("PATH", "")
    return env


class Clock:
    """A stand-in for the `time` module inside maisecrets.vault: the life cycle runs over days
    without a sleep."""

    def __init__(self, now: float = T0) -> None:
        self.now = now
        self.module = types.SimpleNamespace(time=lambda: self.now, sleep=lambda s: None,
                                            strftime=time.strftime, localtime=time.localtime)

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def patch(self):
        return mock.patch.object(vault, "time", self.module)


# ------------------------------------------------------------------ config --
class ConfigTests(unittest.TestCase):
    WRONG = {str: 5, int: "5", bool: "yes", dict: ["x"], list: "generic", (str, type(None)): 5}

    def setUp(self):
        _reset()
        self.tmp = Path(tempfile.mkdtemp(prefix="policy-", dir=HOME))
        self.policy = self.tmp / "policy.json"
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE_PLUGIN_OPTION_")}
        self.patches = [mock.patch.dict(vault.POLICY_PATHS, {platform.system(): self.policy}),
                        mock.patch.dict(os.environ, env, clear=True)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)
        _reset()

    def _user(self, data) -> None:
        vault.CONFIG.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")

    def test_every_default_key_is_type_checked(self):
        missing = sorted(set(vault.DEFAULT_CONFIG) - set(vault._CONFIG_TYPES))
        self.assertEqual(missing, [], "a default without a type check reaches the code unchecked")

    def test_each_key_with_a_wrong_type_is_ignored_and_the_warning_names_the_key_never_the_value(self):
        checked = 0
        for key, want in vault._CONFIG_TYPES.items():
            wrongs = [self.WRONG[want]] + ([True] if want is int else [])
            for wrong in wrongs:
                with self.subTest(key=key, wrong=wrong):
                    # a valid key next to the wrong one is ignored too: the whole file falls back
                    self._user({key: wrong, "renew_on_use": False} if key != "renew_on_use" else {key: wrong})
                    cfg = vault.load_config()
                    self.assertIn(key, cfg["config_warning"])
                    self.assertIn("ignored", cfg["config_warning"])
                    self.assertNotIn(str(wrong), cfg["config_warning"].replace(key, ""))
                    self.assertTrue(cfg["renew_on_use"], "the fallback is the strict defaults")
                    if key in ("rehydration", "read_pdf", "read_image"):
                        # a value that is no policy or mode: the fallback is block, never looser
                        self.assertEqual(cfg[key], "block")
                    elif key in vault.DEFAULT_CONFIG:
                        self.assertEqual(cfg[key], vault.DEFAULT_CONFIG[key])
                    checked += 1
        self.assertGreaterEqual(checked, len(vault.DEFAULT_CONFIG))

    def test_ttl_seconds_values_must_be_integers(self):
        self._user({"ttl_seconds": {"default": "3600"}})
        cfg = vault.load_config()
        self.assertIn("ttl_seconds values must be integers", cfg["config_warning"])
        self.assertEqual(cfg["ttl_seconds"], vault.DEFAULT_CONFIG["ttl_seconds"])

    def test_an_unknown_key_is_named_and_dropped_and_the_known_keys_still_apply(self):
        self._user({"keep_purged_days": 3, "renew_on_uses": False, "policy_keys": ["backend"]})
        cfg = vault.load_config()
        self.assertEqual(cfg["keep_purged_days"], 3)
        self.assertNotIn("renew_on_uses", cfg)
        self.assertEqual(cfg["policy_keys"], [], "the user file cannot claim a key came from the policy")
        # a typo of a real key is named, any other key only counted: it may be a pasted value
        self.assertIn("unknown key(s) renew_on_uses, 1 more that are not near a known key ignored",
                      cfg["config_warning"])

    def test_a_user_file_that_is_not_json_or_not_an_object_falls_back_to_the_defaults(self):
        for text, want in [("{nope", "not valid JSON"), ("[1, 2]", "must hold one JSON object")]:
            with self.subTest(text):
                self._user(text)
                cfg = vault.load_config()
                self.assertIn(want, cfg["config_warning"])
                self.assertEqual(cfg["backend"], "keychain")
                # invalid JSON and JSON that is no object: the file may have said block
                self.assertEqual(cfg["rehydration"], "block", "an unreadable file may have said block")
                self.assertTrue(cfg["rehydration_fallback"])
        vault.CONFIG.unlink()
        cfg = vault.load_config()
        self.assertEqual(cfg["config_warning"], "", "no file is not a problem")
        self.assertEqual(cfg["rehydration"], "automatic", "and no file is the default")

    def test_a_file_ignored_for_a_wrong_type_keeps_what_it_made_stricter(self):
        # user file -> (rehydration, resolve_in_files, ssh_via_sandbox, block set by the fallback)
        for user, want in (({"rehydration": "block", "tips": "yes"}, ("block", True, True, False)),
                           ({"rehydration": "confirm", "tips": "yes"}, ("confirm", True, True, False)),
                           ({"resolve_in_files": False, "ssh_via_sandbox": False, "tips": "yes"},
                            ("automatic", False, False, False)),
                           ({"rehydration": "automatic", "resolve_in_files": True, "tips": "yes"},
                            ("automatic", True, True, False)),
                           ({"rehydration": "strict", "tips": "yes"}, ("block", True, True, True)),
                           # a per-path object or a list: no TypeError, and no lock-out of the client
                           ({"rehydration": {"mcp": "confirm"}}, ("block", True, True, True)),
                           ({"rehydration": ["block"]}, ("block", True, True, True))):
            with self.subTest(user):
                self._user(user)
                cfg = vault.load_config()
                self.assertIn("ignored", cfg["config_warning"])
                self.assertEqual((cfg["rehydration"], cfg["resolve_in_files"], cfg["ssh_via_sandbox"],
                                  cfg.get("rehydration_fallback", False)), want)
                self.assertTrue(cfg["renew_on_use"], "a looser or other key of the file is not taken")

    def test_a_settings_file_that_cannot_be_read_as_written_never_loosens_rehydration(self):
        # a policy file that exists and cannot be read is not "no policy": the hooks fail closed
        self.policy.mkdir()                     # IsADirectoryError, an OSError that is not "missing"
        with self.assertRaises(vault.ConfigError) as ctx:
            vault.load_config()
        self.assertIn("cannot be read", str(ctx.exception))
        self.policy.rmdir()
        # an administrator's key spelled wrong: its intent is unknown, rehydration stops; "_" is a comment
        self.policy.write_text(json.dumps({"rehydraton": "block", "_note": "rollout 3"}))
        cfg = vault.load_config()
        self.assertEqual((cfg["rehydration"], cfg["rehydration_fallback"]), ("block", True))
        self.assertIn("1 unknown key(s)", cfg["config_warning"])
        self.policy.write_text(json.dumps({"_note": "rollout 3"}))
        self.assertEqual(vault.load_config()["rehydration"], "automatic", "a comment key blocks nothing")
        # a schema link, a tool's comment or a key of a newer version: a warning, and the policy still works
        self.policy.write_text(json.dumps({"rehydration": "confirm", "$schema": "x", "comment": "y",
                                           "max_resolves_per_day": 9, "rehydration_mcp": "automatic"}))
        cfg = vault.load_config()
        self.assertEqual((cfg["rehydration"], cfg.get("rehydration_fallback", False)), ("confirm", False))
        self.assertIn("3 unknown key(s) ignored", cfg["config_warning"])
        self.assertNotIn("misspelled", cfg["config_warning"], "a longer key of a newer version is no typo")
        # a valid policy setting is the administrator's, never explained as the user's broken file
        self._user("{not json")
        self.policy.write_text(json.dumps({"rehydration": "block"}))
        cfg = vault.load_config()
        self.assertEqual((cfg["rehydration"], cfg["rehydration_fallback"]), ("block", False))
        self.policy.unlink()
        # the user file: a safety key spelled wrong is a stricter wish, another typo is not
        self._user({"rehydraton": "block"})
        self.assertEqual(vault.load_config()["rehydration"], "block")
        # the file's own rehydration key does not undo it (review round 3)
        for user in ({"rehydration": "automatic", "resolve_in_file": False},
                     {"rehydration": "confirm", "ssh_via_sandbx": False}):
            with self.subTest(user):
                self._user(user)
                cfg = vault.load_config()
                self.assertEqual((cfg["rehydration"], cfg["rehydration_fallback"]), ("block", True))
        self._user({"renew_on_uses": False})
        self.assertEqual(vault.load_config()["rehydration"], "automatic")
        # a user file that exists and cannot be read
        vault.CONFIG.unlink()
        vault.CONFIG.mkdir()
        try:
            cfg = vault.load_config()
            self.assertEqual((cfg["rehydration"], cfg["rehydration_fallback"]), ("block", True))
            self.assertIn("cannot be read", cfg["config_warning"])
        finally:
            vault.CONFIG.rmdir()

    def test_the_limiter_counts_a_key_once_per_call(self):
        v = vault.Vault()
        v.cfg["max_resolves_per_hour"] = 1
        e = v.put("limit-once-" + "value-1", "SECRET", "manual", session="S1")
        self.assertEqual(v._limit_all([e.key, e.key], "S1"), [], "one key named twice is one resolve")
        f = v.put("limit-once-" + "value-2", "SECRET", "manual", session="S1")
        self.assertIn("max_resolves_per_hour", v._limit_all([e.key, f.key], "S1")[0])
        # a cap lowered below the keys this session already used: known keys still pass, a new one is named
        v.cfg["max_resolves_per_hour"] = 60
        v._record(e.key, "S1", "t", "c")
        v._record(f.key, "S1", "t", "c")
        v.cfg["max_keys_per_session"] = 1
        self.assertEqual(v._limit_all([e.key, f.key], "S1"), [])
        g = v.put("limit-once-" + "value-3", "SECRET", "manual", session="S1")
        got = v._limit_all([e.key, g.key], "S1")
        self.assertTrue(got and got[0].startswith(g.key) and "max_keys_per_session" in got[0], got)
        v.cfg["max_resolves_per_hour"] = 1                 # lowered below the resolves of the last hour
        self.assertEqual(v._limit_all([], "S1"), [], "no keys: no IndexError")

    def test_the_plugin_options_from_the_environment(self):
        self._user({"backend": "encrypted-file"})
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_OPTION_BACKEND": "auto",
                                          "CLAUDE_PLUGIN_OPTION_PII_REGIONS": " DE, ,at ",
                                          "CLAUDE_PLUGIN_OPTION_TTL_HOURS": "1.5",
                                          "CLAUDE_PLUGIN_OPTION_REPORT_URL": " https://example.invalid/r "}):
            cfg = vault.load_config()
        self.assertEqual(cfg["backend"], "encrypted-file", "auto keeps the file's choice")
        self.assertEqual((cfg["regions"], cfg["regions_from"]), (["de", "at"], "plugin option"))
        self.assertEqual(cfg["ttl_seconds"]["default"], 5400)
        self.assertEqual(cfg["report_url"], "https://example.invalid/r")
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_OPTION_TTL_HOURS": "soon",
                                          "CLAUDE_PLUGIN_OPTION_BACKEND": "windows-vault"}):
            cfg = vault.load_config()
        self.assertEqual(cfg["ttl_seconds"]["default"], 86400)
        self.assertEqual(cfg["backend"], "windows-vault")

    def test_the_policy_wins_over_the_user_file_and_the_environment(self):
        self._user({"scrub_transcript": False, "backend": "encrypted-file", "keep_purged_days": 90})
        self.policy.write_text(json.dumps({"scrub_transcript": True, "backend": "keychain",
                                           "keep_purged_days": 7}), encoding="utf-8")
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_OPTION_BACKEND": "windows-vault"}):
            cfg = vault.load_config()
        self.assertTrue(cfg["scrub_transcript"])
        self.assertEqual(cfg["backend"], "keychain")
        self.assertEqual(cfg["keep_purged_days"], 7)
        self.assertEqual(cfg["policy_keys"], ["backend", "keep_purged_days", "scrub_transcript"])

    def test_a_broken_policy_fails_closed(self):
        for text in ("{nope", json.dumps({"max_ttl_seconds": "long"}), json.dumps({"renew_on_use": 1})):
            with self.subTest(text):
                self.policy.write_text(text, encoding="utf-8")
                with self.assertRaises(ConfigError):
                    vault.load_config()

    def test_a_policy_that_is_not_one_json_object_fails_closed(self):
        """A policy of `[...]` or `"..."` was valid JSON and was ignored without a word: the
        administrator's keys vanished while an invalid-JSON policy refused to start."""
        for text in ('["backend", "keychain"]', '"keychain"', "42", "null"):
            with self.subTest(text):
                self.policy.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ConfigError, "one JSON object"):
                    vault.load_config()

    def test_no_file_can_raise_the_ttl_ceiling_above_30_days(self):
        self._user({"max_ttl_seconds": 90 * 86400})
        self.assertEqual(vault.load_config()["max_ttl_seconds"], 30 * 86400)
        self.policy.write_text(json.dumps({"max_ttl_seconds": 365 * 86400}), encoding="utf-8")
        self.assertEqual(vault.load_config()["max_ttl_seconds"], 30 * 86400)
        self.policy.write_text(json.dumps({"max_ttl_seconds": 3600}), encoding="utf-8")
        self.assertEqual(vault.load_config()["max_ttl_seconds"], 3600, "a policy may tighten it")

    def test_the_plaintext_store_needs_its_own_opt_in_from_every_source(self):
        self._user({"backend": "jsonfile"})
        with self.assertRaises(ConfigError):
            vault.load_config()
        self._user({})
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_OPTION_BACKEND": "jsonfile"}):
            with self.assertRaises(ConfigError):
                vault.load_config()
        self.policy.write_text(json.dumps({"backend": "jsonfile"}), encoding="utf-8")
        with self.assertRaises(ConfigError):
            vault.load_config()
        self._user({"allow_plaintext_store": True})
        self.assertEqual(vault.load_config()["backend"], "jsonfile")


class BackendChoiceTests(unittest.TestCase):
    def test_make_backend_per_name_and_per_platform(self):
        self.assertIsInstance(vault.make_backend({"backend": "jsonfile"}), JsonFileBackend)
        self.assertIsInstance(vault.make_backend({"backend": "encrypted-file"}), EncryptedFileBackend)
        self.assertIsInstance(vault.make_backend({"backend": "windows-vault"}), WindowsVaultBackend)
        for system, cls in [("Darwin", KeychainBackend), ("Windows", WindowsVaultBackend),
                            ("Linux", EncryptedFileBackend)]:
            with self.subTest(system), mock.patch.object(vault.platform, "system", return_value=system):
                self.assertIsInstance(vault.make_backend({"backend": "keychain"}), cls)

    def test_the_store_is_the_platform_store_and_never_silently_the_plaintext_one(self):
        """THREAT-MODEL C12: keychain on macOS, Credential Locker on Windows, the encrypted file
        elsewhere. Only the literal name jsonfile gives the plaintext store; no default, no
        unknown or misspelt name and no platform falls back to it."""
        want = {"Darwin": KeychainBackend, "Windows": WindowsVaultBackend, "Linux": EncryptedFileBackend,
                "FreeBSD": EncryptedFileBackend, "": EncryptedFileBackend}
        for system, cls in want.items():
            for cfg in ({}, {"backend": "keychain"}, {"backend": "json-file"}, {"backend": "JSONFILE"},
                        {"backend": None}, {"backend": "plaintext"}, {"allow_plaintext_store": True}):
                with self.subTest(system=system, cfg=cfg), \
                        mock.patch.object(vault.platform, "system", return_value=system):
                    b = vault.make_backend(cfg)
                    self.assertIs(type(b), cls)
                    self.assertFalse(b.test_mode, "a platform store is never the test store")
        for system in want:
            with self.subTest(explicit=system), mock.patch.object(vault.platform, "system", return_value=system):
                self.assertIs(type(vault.make_backend({"backend": "encrypted-file"})), EncryptedFileBackend)
                self.assertTrue(vault.make_backend({"backend": "jsonfile"}).test_mode)

    def test_a_test_home_never_shares_the_keychain_namespace_of_the_real_one(self):
        self.assertNotEqual(vault.SERVICE, "maisecrets")
        self.assertEqual(vault.SERVICE, "maisecrets@" + hashlib.sha256(str(HOME).encode()).hexdigest()[:8])

    def test_the_descriptions_say_plain_text_for_the_test_store(self):
        self.assertIn("TEST MODE", vault.describe_backend(JsonFileBackend()))
        self.assertIn("PLAIN TEXT", vault.intro_line(JsonFileBackend()))
        for b in (KeychainBackend(), WindowsVaultBackend(), EncryptedFileBackend()):
            with self.subTest(type(b).__name__):
                self.assertNotIn("TEST MODE", vault.describe_backend(b))
                self.assertNotIn("PLAIN TEXT", vault.intro_line(b))
                self.assertIn(str(vault.CONFIG), vault.describe_backend(b))


# ---------------------------------------------------------------- emulators --
def _tokenize(line: str) -> list[str]:
    """The `security -i` command reader: double quotes group, a backslash escapes inside them."""
    out: list[str] = []
    cur = None
    quoted = False
    i = 0
    while i < len(line):
        c = line[i]
        if quoted:
            if c == "\\" and i + 1 < len(line):
                cur += line[i + 1]
                i += 2
                continue
            if c == '"':
                quoted = False
            else:
                cur += c
        elif c == '"':
            quoted, cur = True, cur or ""
        elif c.isspace():
            if cur is not None:
                out.append(cur)
                cur = None
        else:
            cur = (cur or "") + c
        i += 1
    if quoted:
        raise ValueError("unterminated quote")
    if cur is not None:
        out.append(cur)
    return out


class FakeSecurity:
    """The parts of macOS `security` the backend uses, with the two traps that bit the real one:
    `-i` reads at most 4096 bytes per line and runs the rest as another command, and
    `find-generic-password -w` prints a non-ASCII password as hex."""
    LINE_LIMIT = 4096

    def __init__(self) -> None:
        self.items: dict = {}
        self.calls: list = []
        self.rc: dict = {}          # command name -> forced return code

    def _done(self, args, rc, out, text):
        return subprocess.CompletedProcess(args, rc, out if text else out.encode(), "" if text else b"")

    def run(self, args, input=None, capture_output=False, text=False, timeout=None, **kw):
        self.calls.append((list(args), input))
        if not args or args[0] != "security":
            raise AssertionError(f"unexpected program {args[:1]}")
        if list(args[1:]) == ["-i"]:
            data = input.decode("utf-8") if isinstance(input, bytes) else input
            rc = 0
            for line in data.split("\n"):
                raw = line.encode("utf-8")
                for i in range(0, len(raw), self.LINE_LIMIT):
                    try:
                        argv = _tokenize(raw[i:i + self.LINE_LIMIT].decode("utf-8", errors="replace"))
                    except ValueError:
                        rc = 1
                        continue
                    r, _out = self._cmd(argv)
                    rc = rc or r
            return self._done(args, rc, "", text)
        rc, out = self._cmd(list(args[1:]))
        return self._done(args, rc, out, text)

    @staticmethod
    def _opts(argv: list[str]) -> dict:
        opts, i = {}, 0
        while i < len(argv):
            if argv[i] in ("-U", "-w") and (argv[i] == "-U" or i + 1 == len(argv) or argv[i + 1].startswith("-")):
                opts[argv[i]] = True
                i += 1
            else:
                opts[argv[i]] = argv[i + 1]
                i += 2
        return opts

    def _cmd(self, argv: list[str]) -> tuple[int, str]:
        name, opts = argv[0], self._opts(argv[1:]) if len(argv) > 1 else {}
        if name in self.rc:
            return self.rc[name], ""
        if name == "add-generic-password":
            k = (opts["-s"], opts["-a"])
            if k in self.items and "-U" not in opts:
                return 45, ""
            self.items[k] = {"pw": opts["-w"], "label": opts.get("-l"), "comment": opts.get("-j")}
            return 0, ""
        if name == "find-generic-password":
            item = self.items.get((opts["-s"], opts["-a"]))
            if item is None:
                return 44, ""
            pw = item["pw"]
            return 0, (pw if pw.isascii() else pw.encode("utf-8").hex()) + "\n"
        if name == "delete-generic-password":
            for k in list(self.items):
                if k[0] == opts["-s"] and ("-a" not in opts or k[1] == opts["-a"]):
                    del self.items[k]
                    return 0, ""
            return 44, ""
        if name == "dump-keychain":
            out = []
            for (svce, acct) in self.items:
                out += ['keychain: "/Users/x/Library/Keychains/login.keychain-db"', 'class: "genp"', "attributes:",
                        f'    "acct"<blob>="{acct}"', f'    "svce"<blob>="{svce}"']
            return 0, "\n".join(out) + "\n"
        raise AssertionError(f"unexpected security command {name}")

    def values_on_argv(self) -> list[str]:
        return [a for args, _ in self.calls for a in args]


class FakePowerShell:
    """The PowerShell calls of WindowsVaultBackend against an in-memory Credential Locker."""

    def __init__(self) -> None:
        self.items: dict = {}
        self.calls: list = []

    def run(self, args, input=None, capture_output=False, text=False, timeout=None, **kw):
        import re
        self.calls.append((list(args), input))
        if list(args[:4]) != ["powershell", "-NoProfile", "-NonInteractive", "-Command"]:
            raise AssertionError(f"unexpected program {args[:4]}")
        script = args[4]
        assert script.startswith(WindowsVaultBackend._PRELUDE)
        body = script[len(WindowsVaultBackend._PRELUDE):]

        def done(rc, out=""):
            return subprocess.CompletedProcess(args, rc, out, "")
        if "ReadToEnd" in body:
            svc, key = re.search(r"PasswordCredential\('([^']*)', '([^']*)', \$p\)", body).groups()
            self.items[(svc, key)] = base64.b64decode(input.strip()).decode("utf-8")
            return done(0)
        if body.startswith("foreach"):
            inner = re.search(r"@\((.*?)\)\) \{", body).group(1)
            svc = re.search(r"Retrieve\('([^']*)', \$k\)", body).group(1)
            keys = re.findall(r"'([^']*)'", inner)
            lines = [k + " " + base64.b64encode(self.items[(svc, k)].encode()).decode()
                     for k in keys if (svc, k) in self.items]
            return done(0, "".join(ln + "\r\n" for ln in lines))
        if "FindAllByResource" in body:
            svc = re.search(r"FindAllByResource\('([^']*)'\)", body).group(1)
            return done(0, "".join(k + "\r\n" for s, k in self.items if s == svc))
        if body.startswith("try { $v.Remove($v.Retrieve("):
            svc, key = re.search(r"Retrieve\('([^']*)', '([^']*)'\)", body).groups()
            self.items.pop((svc, key), None)
            return done(0)
        if "RetrievePassword(); [Console]::Out.Write(" in body:
            svc, key = re.search(r"Retrieve\('([^']*)', '([^']*)'\)", body).groups()
            if (svc, key) not in self.items:
                return done(3)
            return done(0, base64.b64encode(self.items[(svc, key)].encode()).decode())
        raise AssertionError("unexpected PowerShell script")


# --------------------------------------------------------------- backends --
LONG = "".join(chr(ord("a") + (i * 7) % 26) for i in range(5000))
AWKWARD = [
    "plain-fake-value-0001",
    'quo"te\'s and \\back\\slashes',
    "line one\nline two\n",
    "pässwörd-Üß-ÄÖ-€",
    "$(echo no) `x` ;|&",
    LONG,
]


class BackendContract:
    """One contract, run against every backend."""

    def make(self):
        raise NotImplementedError

    def setUp(self):
        _reset()
        self.env = mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != "MAISECRETS_KEY_FILE"},
                                   clear=True)
        self.env.start()
        self.backend = self.make()

    def tearDown(self):
        self.env.stop()
        _reset()

    def test_round_trip_of_awkward_values(self):
        for i, value in enumerate(AWKWARD):
            with self.subTest(i=i, head=value[:12]):
                key = f"SECRET_c{i + 1}"
                self.backend.put(key, value, label=f"maisecrets {key} (manual)",
                                 comment="fake \"quoted comment \\ with a backslash")
                self.assertEqual(self.backend.get(key), value)

    def test_put_replaces_the_value_of_a_key(self):
        self.backend.put("SECRET_c1", "first-fake-value")
        self.backend.put("SECRET_c1", "second-fake-value")
        self.assertEqual(self.backend.get("SECRET_c1"), "second-fake-value")
        self.assertEqual(self.backend.keys(), ["SECRET_c1"])

    def test_delete_removes_one_key_and_a_missing_key_is_quiet(self):
        self.backend.put("SECRET_c1", "fake-one")
        self.backend.put("SECRET_c2", "fake-two")
        self.backend.delete("SECRET_c1")
        self.backend.delete("SECRET_c9")
        self.assertIsNone(self.backend.get("SECRET_c1"))
        self.assertEqual(self.backend.get("SECRET_c2"), "fake-two")
        self.assertIsNone(self.backend.get("NEVER_c1"))

    def test_keys_lists_every_key_and_nothing_else(self):
        self.assertEqual(self.backend.keys(), [])
        for k in ("SECRET_c1", "EMAIL_c1", FP_KEY_ENTRY):
            self.backend.put(k, "fake-" + k)
        self.assertEqual(sorted(self.backend.keys()), sorted(["SECRET_c1", "EMAIL_c1", FP_KEY_ENTRY]))

    def test_wipe_everything_leaves_the_store_empty(self):
        v = Vault(dict(JSONCFG))
        v.backend = self.backend
        e = v.put("wipe-me-fake-value-77", "SECRET", "manual", session="S1")
        self.backend.put("ORPHAN_c4", "fake-orphan")   # a store item the index does not know
        with mock.patch.object(vault, "make_backend", lambda cfg: self.backend):
            n, problems = vault.wipe_everything({})
        self.assertEqual(problems, [])
        self.assertGreaterEqual(n, 3)
        self.assertEqual(self.backend.keys(), [])
        self.assertIsNone(self.backend.get(e.key))
        self.assertFalse(vault.INDEX.exists())


class FileStoreContract:
    """The part of the contract that only a backend with its own store file has."""
    store_file = ""

    def test_a_corrupt_store_file_is_never_overwritten(self):
        self.backend.put("SECRET_c1", "fake-before")
        path = HOME / self.store_file
        path.write_text("{damaged", encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)   # the next test in this process must not read it
        for op in (lambda: self.backend.put("SECRET_c2", "fake-after"), lambda: self.backend.delete("SECRET_c1")):
            with self.assertRaises(RuntimeError):
                op()
            self.assertEqual(path.read_text(encoding="utf-8"), "{damaged")
        self.assertIsNone(self.backend.get("SECRET_c1"), "a read reports nothing rather than guess")
        self.assertEqual(self.backend.keys(), [])


class JsonFileBackendTests(FileStoreContract, BackendContract, unittest.TestCase):
    store_file = "vault.json"

    def make(self):
        return JsonFileBackend()


@unittest.skipIf(shutil.which("openssl") is None, "no openssl")
class EncryptedFileBackendTests(FileStoreContract, BackendContract, unittest.TestCase):
    store_file = "vault.enc.json"

    def make(self):
        return EncryptedFileBackend()

    def test_the_file_holds_no_value_and_a_foreign_tag_is_refused(self):
        self.backend.put("SECRET_c1", "enc-fake-value-4711")
        text = (HOME / "vault.enc.json").read_text(encoding="utf-8")
        self.assertNotIn("enc-fake-value-4711", text)
        if os.name == "posix":
            self.assertEqual((HOME / "key").stat().st_mode & 0o777, 0o600)
        data = json.loads(text)
        data["SECRET_c1"]["t"] = "0" * 64
        (HOME / "vault.enc.json").write_text(json.dumps(data), encoding="utf-8")
        self.assertIsNone(self.backend.get("SECRET_c1"), "a tag that does not match fails closed")

    def test_a_ciphertext_that_openssl_rejects_reads_as_missing(self):
        self.backend.put("SECRET_c1", "enc-fake-value-4712")
        data = json.loads((HOME / "vault.enc.json").read_text(encoding="utf-8"))
        blob = b"Salted__" + b"\x00" * 8 + b"\x01" * 15   # not a multiple of the block size
        data["SECRET_c1"] = {"c": base64.b64encode(blob).decode(), "t": self.backend._tag(blob)}
        (HOME / "vault.enc.json").write_text(json.dumps(data), encoding="utf-8")
        self.assertIsNone(self.backend.get("SECRET_c1"))

    def test_the_key_file_can_live_elsewhere_and_wipe_removes_it(self):
        other = Path(tempfile.mkdtemp(prefix="keyfile-", dir=HOME)) / "sub" / "k"
        with mock.patch.dict(os.environ, {"MAISECRETS_KEY_FILE": str(other)}):
            b = EncryptedFileBackend()
            b.put("SECRET_c1", "enc-fake-value-4713")
        self.assertTrue(other.exists())
        self.assertFalse((HOME / "key").exists())
        self.assertEqual(b.wipe(), 1)
        self.assertFalse(other.exists())
        shutil.rmtree(other.parent.parent, ignore_errors=True)


class KeychainBackendTests(BackendContract, unittest.TestCase):
    def make(self):
        self.fake = FakeSecurity()
        self.sp = mock.patch.object(vault, "subprocess", types.SimpleNamespace(
            run=lambda *a, **k: self.fake.run(*a, **k), CompletedProcess=subprocess.CompletedProcess,
            TimeoutExpired=subprocess.TimeoutExpired))
        self.sp.start()
        self.addCleanup(self.sp.stop)
        return KeychainBackend()

    def test_a_short_value_goes_through_stdin_and_never_onto_the_command_line(self):
        self.backend.put("SECRET_c1", "short-fake-value-99")
        stored = "b64:" + base64.b64encode(b"short-fake-value-99").decode()
        self.assertNotIn(stored, self.fake.values_on_argv())
        self.assertEqual(self.fake.calls[0][0], ["security", "-i"])
        self.assertIn(stored.encode(), self.fake.calls[0][1])

    def test_a_value_above_the_line_limit_goes_on_the_command_line_whole(self):
        self.backend.put("SECRET_c1", LONG)
        self.assertEqual(self.fake.calls[0][0][:2], ["security", "add-generic-password"])
        self.assertEqual(self.backend.get("SECRET_c1"), LONG)

    def test_the_value_is_stored_base64_so_an_umlaut_does_not_come_back_as_hex(self):
        self.backend.put("SECRET_c1", "grüße-fake")
        self.assertTrue(self.fake.items[(vault.SERVICE, "SECRET_c1")]["pw"].startswith("b64:"))
        self.assertEqual(self.backend.get("SECRET_c1"), "grüße-fake")

    def test_an_entry_from_before_0_3_22_and_a_damaged_one(self):
        self.fake.items[(vault.SERVICE, "SECRET_c1")] = {"pw": "legacy-plain-fake"}
        self.fake.items[(vault.SERVICE, "SECRET_c2")] = {"pw": "b64:!!notbase64"}
        self.assertEqual(self.backend.get("SECRET_c1"), "legacy-plain-fake")
        self.assertIsNone(self.backend.get("SECRET_c2"))

    def test_failures_raise_without_the_value_and_rc_44_is_a_successful_delete(self):
        self.fake.rc["add-generic-password"] = 1
        with self.assertRaisesRegex(RuntimeError, r"keychain add failed \(rc 1\)") as cm:
            self.backend.put("SECRET_c1", "fail-fake-value-31")
        self.assertNotIn("fail-fake-value-31", str(cm.exception))
        with self.assertRaisesRegex(RuntimeError, r"\(rc 1\)"):
            self.backend.put("SECRET_c1", LONG)
        del self.fake.rc["add-generic-password"]
        with mock.patch.object(KeychainBackend, "get", return_value="something else"):
            with self.assertRaisesRegex(RuntimeError, "read-back differs"):
                self.backend.put("SECRET_c1", "fail-fake-value-32")
        self.backend.delete("SECRET_c7")        # rc 44
        self.fake.rc["delete-generic-password"] = 51
        with self.assertRaises(RuntimeError):
            self.backend.delete("SECRET_c1")
        with self.assertRaises(RuntimeError):
            self.backend.wipe()
        self.fake.rc["dump-keychain"] = 1
        self.assertEqual(self.backend.keys(), [])

    def test_wipe_deletes_every_item_of_this_service_and_no_other(self):
        for k in ("SECRET_c1", "SECRET_c2", FP_KEY_ENTRY):
            self.backend.put(k, "fake-" + k)
        self.fake.items[("maisecrets", "SECRET_c1")] = {"pw": "the real vault"}
        self.assertEqual(self.backend.wipe(), 3)
        self.assertEqual(list(self.fake.items), [("maisecrets", "SECRET_c1")])


class WindowsVaultBackendTests(BackendContract, unittest.TestCase):
    def make(self):
        self.fake = FakePowerShell()
        self.sp = mock.patch.object(vault, "subprocess", types.SimpleNamespace(
            run=lambda *a, **k: self.fake.run(*a, **k), CompletedProcess=subprocess.CompletedProcess,
            TimeoutExpired=subprocess.TimeoutExpired))
        self.sp.start()
        self.addCleanup(self.sp.stop)
        return WindowsVaultBackend()

    def test_the_value_travels_on_stdin_only(self):
        self.backend.put("SECRET_c1", "win-fake-value-55")
        b64 = base64.b64encode(b"win-fake-value-55").decode()
        for args, _stdin in self.fake.calls:
            self.assertFalse(any("win-fake-value-55" in a or b64 in a for a in args))
        self.assertEqual(self.fake.calls[0][1], b64)

    def test_get_many_reads_all_values_in_one_start_and_never_splices_a_foreign_key(self):
        self.backend.put("SECRET_c1", "win-fake-1")
        self.backend.put("EMAIL_c2", "wïn-fake-2")
        self.fake.calls.clear()
        got = self.backend.get_many(["SECRET_c1", "EMAIL_c2", "SECRET_c3", "X'); Remove-Item C:\\ ; ('"])
        self.assertEqual(got, {"SECRET_c1": "win-fake-1", "EMAIL_c2": "wïn-fake-2"})
        self.assertEqual(len(self.fake.calls), 1)
        self.assertNotIn("Remove-Item", self.fake.calls[0][0][4])
        self.assertEqual(self.backend.get_many([]), {})

    def test_a_failed_add_raises_and_a_failed_read_is_none(self):
        with mock.patch.object(self.fake, "run", return_value=subprocess.CompletedProcess([], 1, "", "")):
            with self.assertRaises(RuntimeError):
                self.backend.put("SECRET_c1", "win-fake-3")
            self.assertEqual(self.backend.keys(), [])
            self.assertEqual(self.backend.get_many(["SECRET_c1"]), {})
        with mock.patch.object(self.fake, "run", return_value=subprocess.CompletedProcess([], 0, "SECRET_c1 a", "")):
            self.assertIsNone(self.backend.get("SECRET_c1"))
            self.assertEqual(self.backend.get_many(["SECRET_c1"]), {})


# ------------------------------------------------------------------ index --
class IndexFileTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def test_atomic_write_uses_a_temp_file_of_its_own_process_and_leaves_none_behind(self):
        seen = []
        real = os.replace

        def spy(src, dst):
            seen.append(str(src))
            return real(src, dst)
        target = HOME / "atomic-probe.json"
        with mock.patch.object(vault.os, "replace", spy):
            vault.atomic_write(target, "{}")
        self.assertEqual(len(seen), 1)
        self.assertIn(f".{os.getpid()}.", Path(seen[0]).name)
        self.assertEqual(target.read_text(encoding="utf-8"), "{}")
        self.assertEqual([p.name for p in HOME.iterdir() if p.name.endswith(".tmp")], [])
        if os.name == "posix":
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        target.unlink()

    def test_atomic_write_waits_out_a_reader_and_gives_up_last(self):
        target = HOME / "atomic-probe.json"
        real = os.replace
        calls = {"n": 0}

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] < 3:
                raise PermissionError(13, "in use")
            return real(src, dst)
        with mock.patch.object(vault.os, "replace", flaky), mock.patch.object(vault.time, "sleep"):
            vault.atomic_write(target, "[1]")
        self.assertEqual(target.read_text(encoding="utf-8"), "[1]")
        with mock.patch.object(vault.os, "replace", side_effect=PermissionError(13, "in use")), \
                mock.patch.object(vault.time, "sleep"):
            with self.assertRaises(PermissionError):
                vault.atomic_write(target, "[2]")
        self.assertEqual(target.read_text(encoding="utf-8"), "[1]")
        self.assertEqual([p.name for p in HOME.iterdir() if p.name.endswith(".tmp")], [])
        target.unlink()

    def test_the_index_never_holds_a_value(self):
        v = Vault(dict(JSONCFG))
        v.put("index-fake-value-QQ81", "SECRET", "manual", session="S1")
        self.assertNotIn("index-fake-value-QQ81", vault.INDEX.read_text(encoding="utf-8"))

    def test_a_damaged_index_stays_damaged_until_repair(self):
        v = Vault(dict(JSONCFG))
        for i in range(3):
            v.put(f"repair-fake-value-{i}", "SECRET", "manual", session="S1")
        v.put("repair-fake-mail@example.invalid", "EMAIL", "manual", session="S1")
        vault.INDEX.write_text("{damaged", encoding="utf-8")
        for _ in range(2):
            with self.assertRaisesRegex(RuntimeError, "repair"):
                Vault(dict(JSONCFG))
        self.assertEqual(vault.INDEX.read_text(encoding="utf-8"), "{damaged", "the guard lasts, not one call")
        info = Vault.__new__(Vault)
        info.cfg, info.backend = dict(JSONCFG), vault.make_backend(JSONCFG)
        result = info.repair()
        self.assertEqual(result["counters"], {"SECRET": 3, "EMAIL": 1})
        self.assertEqual(result["keys_seen"], 5)
        self.assertEqual(sorted(info.backend.keys()), [FP_KEY_ENTRY], "nothing old resolves after a repair")
        v = Vault(dict(JSONCFG))
        e = v.put("after-repair-fake-value", "SECRET", "manual", session="S1")
        self.assertEqual(e.key, "SECRET_c4", "a new entry never overwrites an old counter")

    def test_repair_refuses_a_store_that_cannot_enumerate_itself(self):
        v = Vault(dict(JSONCFG))
        v.backend = types.SimpleNamespace(get=lambda k: None)
        with self.assertRaises(RuntimeError):
            v.repair()

    def test_an_index_of_the_wrong_shape_is_refused(self):
        for text in ("[]", "{}"):
            with self.subTest(text):
                vault.INDEX.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "unexpected shape"):
                    Vault(dict(JSONCFG))


# -------------------------------------------------------------- life cycle --
class LifeCycleTests(unittest.TestCase):
    """What a person goes through over days, with a clock instead of sleeps."""

    def setUp(self):
        _reset()
        self.clock = Clock()
        self.p = self.clock.patch()
        self.p.start()
        self.cfg = dict(JSONCFG, ttl_seconds={"default": 3600}, max_ttl_seconds=7200, keep_purged_days=1)

    def tearDown(self):
        self.p.stop()
        _reset()

    def v(self) -> Vault:
        return Vault(dict(self.cfg))

    def test_from_paste_to_purge_and_back(self):
        value = "lifecycle-fake-" + "Zq8vLm2Rt9"
        e = self.v().put(value, "SECRET", "manual", session="A")
        self.assertEqual((e.key, e.expires, e.max_expires), ("SECRET_c1", T0 + 3600, T0 + 7200))
        # another session never saw it come in
        self.assertEqual(self.v().get(e.key, "B"), (None, "foreign-session"))
        self.assertEqual(self.v().grant(e.key, "B", "Bash", "echo"), (None, "foreign-session"))
        self.assertEqual(self.v().get(e.key), (None, "no-session"))
        # a human typed the reference into session B
        self.v().admit(e.key, "B")
        self.clock.advance(1800)
        self.assertEqual(self.v().get(e.key, "B"), (value, "ok"))
        meta = self.v()._index["entries"][e.key]
        self.assertEqual(meta["expires"], T0 + 1800 + 3600, "a use renews the TTL")
        self.assertEqual(meta["uses"], 1)
        self.assertEqual(sorted(meta["sessions"]), ["A", "B"])
        # renewal stops at the ceiling set when the value came in
        self.clock.advance(3200)
        self.assertEqual(self.v().get(e.key, "A"), (value, "ok"))
        self.assertEqual(self.v()._index["entries"][e.key]["expires"], T0 + 7200)
        # expired: the value goes, the metadata stays
        self.clock.advance(2201)
        purge_time = self.clock.now
        self.assertEqual(self.v().get(e.key, "A"), (None, "expired"))
        meta = self.v()._index["entries"][e.key]
        self.assertTrue(meta["purged"])
        self.assertEqual(meta["purged_at"], purge_time)
        self.assertIsNone(self.v().backend.get(e.key))
        listed = {x.key: x for x in self.v().list()}
        self.assertTrue(listed[e.key].purged, "list reads a purged record")
        self.assertEqual(self.v().status(e.key, "A"), "expired")
        self.assertEqual(self.v().forget("SECRET_c99"), "unknown")
        # the same value pasted again gets a fresh key
        self.clock.advance(100)
        again = self.v().put(value, "SECRET", "manual", session="A")
        self.assertEqual(again.key, "SECRET_c2")
        self.assertEqual(self.v().get(again.key, "A"), (value, "ok"))
        fp = again.fingerprint
        self.assertEqual(fp, e.fingerprint)
        self.assertEqual(self.v()._index["by_fingerprint"][fp], "SECRET_c2")
        # after keep_purged_days the old metadata goes; the fingerprint now names the new entry
        self.clock.advance(86400 + 1)
        self.v().expire(limit=None)
        idx = self.v()._index
        self.assertNotIn("SECRET_c1", idx["entries"])
        self.assertTrue(idx["entries"]["SECRET_c2"]["purged"])
        self.assertEqual(idx["by_fingerprint"][fp], "SECRET_c2")
        # and again: never an old counter
        third = self.v().put(value, "SECRET", "manual", session="C")
        self.assertEqual(third.key, "SECRET_c3")
        self.assertEqual(self.v().forget(third.key), "ok")
        self.assertEqual(self.v().put(value, "SECRET", "manual", session="C").key, "SECRET_c4")

    def test_a_statement_keyword_stored_by_an_old_detector_is_quieted_not_deleted(self):
        # before 0.5.15 `if not token: continue` stored `continue`, and maisecrets redacted the word in every
        # later text until the entry expired (field report, 2026-09-29). The start marks it weak: it is no longer
        # hunted, and nothing is deleted without the person (Codex review, 2026-09-29)
        old = self.v().put("continue", "SECRET", "ds-keyword-colon", session="A")
        semi = self.v().put("Return;", "SECRET", "ds-keyword-equal-signs", session="A")
        real = self.v().put("Sommerwiese", "SECRET", "ds-keyword-colon", session="A")
        # the same word from another rule is not the detector's error and stays hunted
        other = self.v().put("break", "SECRET", "manual", session="A")
        real_get = JsonFileBackend.get

        def only_the_fingerprint_key(backend, key):
            if key != FP_KEY_ENTRY:
                raise AssertionError(f"the value of {key} was read")
            return real_get(backend, key)
        with mock.patch.object(JsonFileBackend, "get", only_the_fingerprint_key), \
                mock.patch.object(JsonFileBackend, "delete", side_effect=AssertionError("a value was deleted")):
            quieted = self.v().quiet_code_words()
        self.assertEqual(sorted(quieted), sorted([old.key, semi.key]))
        idx = self.v()._index
        self.assertEqual(sorted(idx["entries"]), sorted([old.key, semi.key, real.key, other.key]))
        self.assertEqual({k for k in (old.key, semi.key, real.key, other.key) if idx["entries"][k].get("weak")},
                         {old.key, semi.key})
        self.assertEqual(self.v().get(old.key, "A"), ("continue", "ok"), "its placeholder still resolves")
        self.assertEqual(sorted(self.v().live_fingerprints().values()), sorted([real.key, other.key]))
        self.assertEqual(self.v().quiet_code_words(), [], "a second run finds nothing")

    def test_the_code_word_cleanup_makes_no_fingerprint_key_in_an_empty_store(self):
        self.assertEqual(self.v().quiet_code_words(), [])
        self.assertIsNone(self.v().backend.get(FP_KEY_ENTRY))

    def test_repair_never_hands_out_a_key_an_old_placeholder_still_names(self):
        # the store keeps only live values; after a purge the key lives on in the index and in old
        # transcripts. A repair that counted the store alone went back to 0 and gave the old key
        # to the next value, so an old placeholder resolved to it.
        for gone in ("purged", "forgotten from the index"):
            with self.subTest(gone):
                for p in list(vault.INDEX.parent.iterdir()) if vault.INDEX.parent.exists() else []:
                    if p.is_file():
                        p.unlink()
                old = [self.v().put(f"repair-old-fake-value-{i}", "SECRET", "manual", session="A") for i in range(3)]
                self.clock.advance(3601)
                self.v().expire(limit=None)
                if gone != "purged":
                    self.clock.advance(86400 + 1)
                    self.v().expire(limit=None)
                    self.assertNotIn(old[0].key, self.v()._index["entries"], "only the counters name it now")
                self.assertNotIn(old[0].key, self.v().backend.keys(), "the store no longer names it")
                self.v().repair()
                fresh = self.v().put("repair-new-fake-value", "SECRET", "manual", session="B")
                self.assertNotIn(fresh.key, [e.key for e in old])
                self.assertEqual(fresh.key, "SECRET_c4")
                self.assertNotEqual(self.v().get(old[0].key, "B")[0], "repair-new-fake-value")

    def test_a_purge_that_waited_on_a_locked_store_counts_its_retention_from_the_purge(self):
        v = self.v()
        e = v.put("locked-store-fake-value", "SECRET", "manual", session="A")
        self.clock.advance(3601)
        with mock.patch.object(JsonFileBackend, "delete", side_effect=RuntimeError("locked")):
            for _ in range(3):     # the keychain stays locked for three days
                v = self.v()
                self.assertEqual((v.expire(limit=None), v.last_refused), (0, 1), "a refused delete is no purge")
                self.clock.advance(86400)
        self.assertFalse(self.v()._index["entries"][e.key]["purged"], "the next sweep tries again")
        self.assertEqual(self.v().get(e.key, "A"), (None, "expired"))   # purges it now
        self.assertIsNone(JsonFileBackend().get(e.key))
        self.clock.advance(86400 - 10)
        self.v().expire(limit=None)
        self.assertIn(e.key, self.v()._index["entries"], "a day from the purge, not from the expiry")
        self.clock.advance(20)
        self.v().expire(limit=None)
        self.assertNotIn(e.key, self.v()._index["entries"])

    def test_a_refused_delete_counts_against_the_sweep_cap(self):
        # a locked keychain refuses each delete after a wait; without the cap every hook call
        # would wait for all of them
        self.v().put_many([(f"cap-refused-fake-value-{i:02d}", "SECRET", "manual") for i in range(30)], session="A")
        self.clock.advance(3601)
        with mock.patch.object(JsonFileBackend, "delete", side_effect=RuntimeError("locked")) as delete:
            v = self.v()
            self.assertEqual((v.expire(limit=25), v.last_refused), (0, 25))
            self.assertEqual(delete.call_count, 25)

    def test_a_record_without_purged_at_ages_from_its_expiry(self):
        e = self.v().put("old-record-fake-value", "SECRET", "manual", session="A")
        data = json.loads(vault.INDEX.read_text(encoding="utf-8"))
        data["entries"][e.key].update(purged=True)
        vault.INDEX.write_text(json.dumps(data), encoding="utf-8")
        self.clock.advance(3600 + 86400 + 1)
        self.v().expire(limit=None)
        self.assertNotIn(e.key, self.v()._index["entries"])

    def test_a_sweep_is_capped_and_the_rest_goes_on_the_next_call(self):
        v = self.v()
        v.put_many([(f"sweep-fake-value-{i:02d}", "SECRET", "manual") for i in range(30)], session="A")
        self.clock.advance(3601)
        self.assertEqual(self.v().expire(), 25)
        self.assertEqual(self.v().expire(), 5)
        self.assertEqual(self.v().expire(), 0)

    def test_renew_on_use_off_keeps_the_first_expiry(self):
        self.cfg["renew_on_use"] = False
        e = self.v().put("norenew-fake-value", "SECRET", "manual", session="A")
        self.clock.advance(1000)
        self.assertEqual(self.v().get(e.key, "A")[1], "ok")
        self.assertEqual(self.v()._index["entries"][e.key]["expires"], T0 + 3600)

    def test_per_type_ttl_and_a_requested_ttl_never_pass_the_ceiling(self):
        self.cfg["ttl_seconds"] = {"default": 3600, "CARD": 60}
        card = self.v().put("4111-fake-card", "CARD", "manual", session="A")
        self.assertEqual(card.expires, T0 + 60)
        long = self.v().put("ttl-fake-value", "SECRET", "manual", session="A", ttl=10 ** 9)
        self.assertEqual(long.expires, T0 + 7200)

    def test_the_same_live_value_in_a_second_session_is_the_same_entry_and_admits_it(self):
        e = self.v().put("shared-fake-value-81", "SECRET", "manual", session="A")
        same = self.v().put("shared-fake-value-81", "SECRET", "manual", session="B")
        self.assertEqual(same.key, e.key)
        self.assertEqual(self.v().status(e.key, "B"), "ok")
        self.assertEqual(self.v()._index["counters"], {"SECRET": 1})

    def test_an_entry_written_before_0_3_0_resolves_in_its_own_session(self):
        e = self.v().put("legacy-fake-value", "SECRET", "manual", session="A")
        data = json.loads(vault.INDEX.read_text(encoding="utf-8"))
        del data["entries"][e.key]["sessions"]
        vault.INDEX.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(self.v().status(e.key, "A"), "ok")
        self.assertEqual(self.v().status(e.key, "B"), "foreign-session")
        self.v().admit(e.key, "B")
        self.assertEqual(self.v().status(e.key, "B"), "ok")
        self.v().admit("SECRET_c77", "B")      # unknown: nothing happens
        self.v().admit(e.key, None)

    def test_a_value_the_store_lost_reads_as_expired(self):
        e = self.v().put("lost-fake-value", "SECRET", "manual", session="A")
        JsonFileBackend().delete(e.key)
        self.assertEqual(self.v().get(e.key, "A"), (None, "expired"))
        self.assertEqual(self.v().get("SECRET_c55", "A"), (None, "unknown"))

    def test_put_many_stores_at_most_the_cap_of_new_values(self):
        self.cfg["max_new_entries_per_result"] = 3
        known = self.v().put("known-fake-value", "SECRET", "manual", session="A")
        out = self.v().put_many([("known-fake-value", "SECRET", "m")] +
                                [(f"many-fake-{i}", "SECRET", "m") for i in range(5)], session="B")
        self.assertEqual(out[0].key, known.key)
        self.assertEqual([o.key if o else None for o in out[1:]],
                         ["SECRET_c2", "SECRET_c3", "SECRET_c4", None, None])
        self.assertEqual(self.v().status(known.key, "B"), "ok")
        self.assertEqual(len(JsonFileBackend().keys()), 1 + 1 + 3)   # the fingerprint key too

    def test_put_many_saves_every_ten_new_values(self):
        saves = []
        real = Vault._save_index

        def count(self):
            saves.append(len(self._index["entries"]))
            return real(self)
        with mock.patch.object(Vault, "_save_index", count):
            self.v().put_many([(f"batch-fake-{i:02d}", "SECRET", "m") for i in range(25)], session="A")
        self.assertIn(10, saves)
        self.assertIn(20, saves)


class GrantAndLimiterTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.clock = Clock()
        self.p = self.clock.patch()
        self.p.start()
        self.cfg = dict(JSONCFG, max_keys_per_session=2, max_resolves_per_hour=5)

    def tearDown(self):
        self.p.stop()
        _reset()

    def v(self) -> Vault:
        return Vault(dict(self.cfg))

    def test_a_grant_is_used_at_most_three_times_within_two_minutes_for_its_own_key(self):
        e = self.v().put("grant-fake-value-12", "SECRET", "manual", session="A")
        other = self.v().put("grant-fake-other-13", "SECRET", "manual", session="A")
        nonce, st = self.v().grant(e.key, "A", "Bash", "cat x")
        self.assertEqual(st, "ok")
        self.assertEqual(self.v().redeem(other.key, nonce), (None, "no-grant"))
        self.assertEqual(self.v().redeem(e.key, "made-up"), (None, "no-grant"))
        for _ in range(3):
            self.assertEqual(self.v().redeem(e.key, nonce), ("grant-fake-value-12", "ok"))
        self.assertEqual(self.v().redeem(e.key, nonce), (None, "grant-used"))
        late, _ = self.v().grant(e.key, "A", "Bash", "cat y")
        self.clock.advance(Vault.GRANT_TTL + 1)
        self.assertEqual(self.v().redeem(e.key, late), (None, "grant-expired"))
        self.v().grant(e.key, "A", "Bash", "cat z")
        self.assertNotIn(nonce, self.v()._index["grants"], "used and expired grants are swept")
        self.assertNotIn(late, self.v()._index["grants"])

    def test_no_grant_without_its_audit_line(self):
        e = self.v().put("audit-fake-value-14", "SECRET", "manual", session="A")
        (HOME / "audit.log").mkdir()
        self.assertEqual(self.v().grant(e.key, "A", "Bash", "x"), (None, "audit log not writable"))
        self.assertEqual(self.v()._index.get("grants"), {})
        self.assertEqual(self.v().record_resolve(e.key, "A", "mcp__x", "{}"), "audit log not writable")

    def test_the_limiter_caps_keys_per_session_and_resolves_per_hour(self):
        keys = [self.v().put(f"limit-fake-{i}", "SECRET", "manual", session="A").key for i in range(3)]
        self.assertEqual(self.v().record_resolve(keys[0], "A", "t", "c"), "ok")
        self.assertEqual(self.v().record_resolve(keys[1], "A", "t", "c"), "ok")
        self.assertIn("max_keys_per_session", self.v().record_resolve(keys[2], "A", "t", "c"))
        self.assertIn("max_keys_per_session", self.v().grant(keys[2], "A", "t", "c")[1])
        self.assertEqual(self.v().record_resolve(keys[0], "A", "t", "c"), "ok", "a key already used is not new")
        self.assertEqual(self.v().grant(keys[1], "A", "t", "c")[1], "ok")
        self.assertEqual(self.v().record_resolve(keys[1], "A", "t", "c"), "ok")
        self.assertIn("max_resolves_per_hour", self.v().record_resolve(keys[0], "A", "t", "c"))
        self.clock.advance(3601)
        self.assertEqual(self.v().record_resolve(keys[2], "A", "t", "c"), "ok", "the window slides")

    def test_record_resolve_keeps_the_session_rule_and_writes_one_clean_line(self):
        e = self.v().put("record-fake-value-15", "SECRET", "manual", session="A-session-long-id")
        self.assertEqual(self.v().record_resolve(e.key, "B", "mcp__x", "{}"), "foreign-session")
        self.assertFalse((HOME / "audit.log").exists())
        self.assertEqual(self.v().record_resolve(e.key, "A-session-long-id", "mcp__x__y",
                                                 "line1\nline2\tcol" + "z" * 300), "ok")
        line = (HOME / "audit.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(line), 1)
        stamp, sess, key, tool, ctx = line[0].split("\t")
        self.assertEqual((sess, key, tool), ("A-sessio", e.key, "mcp__x__y"))
        self.assertTrue(ctx.startswith("line1 line2 col"))
        self.assertEqual(len(ctx), 160)
        self.assertNotIn("record-fake-value-15", line[0])


class FingerprintTests(unittest.TestCase):
    """C10: a fingerprint is keyed, so the index alone gives nothing to try candidates against."""

    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def test_the_fingerprint_is_keyed_and_the_key_lives_in_the_store(self):
        value = "0151" + "23456789"
        e = Vault(dict(JSONCFG)).put(value, "PHONE", "manual", session="A")
        index = vault.INDEX.read_text(encoding="utf-8")
        for unkeyed in (hashlib.sha256(value.encode()).hexdigest(), hashlib.md5(value.encode()).hexdigest()):
            self.assertNotIn(unkeyed[:16], index)
        self.assertNotIn(FP_KEY_ENTRY, index)
        self.assertIn(FP_KEY_ENTRY, JsonFileBackend().keys())
        key = bytes.fromhex(JsonFileBackend().get(FP_KEY_ENTRY))
        self.assertEqual(len(key), 32)
        self.assertEqual(e.fingerprint, vault.fingerprint(value, key))
        self.assertNotEqual(vault.fingerprint(value, key), vault.fingerprint(value, os.urandom(32)))

    def test_the_key_survives_across_processes_so_a_value_keeps_its_reference(self):
        first = Vault(dict(JSONCFG)).put("stable-fake-value", "SECRET", "manual", session="A")
        self.assertEqual(Vault(dict(JSONCFG)).fingerprint("stable-fake-value"), first.fingerprint)
        self.assertEqual(Vault(dict(JSONCFG)).live_fingerprints(), {first.fingerprint: first.key})


class EntryTests(unittest.TestCase):
    META = {"key": "EMAIL_c1", "type": "EMAIL", "kind": "k", "fingerprint": "f", "display": "a…@x",
            "created": 1.0, "last_used": 1.0, "expires": 2.0, "max_expires": 3.0}

    def test_from_meta_takes_an_expired_record_and_the_ref_carries_the_display(self):
        from maisecrets.placeholder import CLOSE, OPEN
        e = Entry.from_meta(dict(self.META, purged=True, purged_at=5.0))
        self.assertTrue(e.purged)
        self.assertEqual(e.ref, f"{OPEN}EMAIL_c1:a…@x{CLOSE}")
        self.assertEqual(Entry.from_meta(dict(self.META, display=None)).ref, f"{OPEN}EMAIL_c1{CLOSE}")


# -------------------------------------------------------------------- lock --
class LockTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def test_one_lock_object_per_path_and_process(self):
        a = vault._lock_for(HOME / ".lock")
        self.assertIs(a, vault._lock_for(HOME / ".lock"))
        self.assertIs(Vault(dict(JSONCFG))._lock, Vault(dict(JSONCFG))._lock)
        self.assertIsNot(a, vault._lock_for(HOME / "other.lock"))

    def test_the_lock_is_reentrant_and_released_after_the_outer_exit(self):
        lk = vault._lock_for(HOME / ".lock")
        with lk:
            with lk:
                self.assertEqual(lk.depth, 2)
            self.assertIsNotNone(lk.fd)
        self.assertEqual((lk.depth, lk.fd), (0, None))

    @unittest.skipUnless(os.name == "posix", "flock")
    def test_a_busy_lock_times_out_with_a_reason_and_leaves_nothing_held(self):
        path = HOME / "busy.lock"
        holder = subprocess.Popen(
            [sys.executable, "-c", "import fcntl,os,sys\nfd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT)\n"
             "fcntl.flock(fd,fcntl.LOCK_EX)\nprint('held',flush=True)\nsys.stdin.read()", str(path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=_child_env(HOME))
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")
            lk = vault._Lock(path)
            lk.LOCK_DEADLINE = 0.2
            with self.assertRaises(LockTimeout):
                with lk:
                    pass
            self.assertEqual((lk.depth, lk.fd), (0, None))
        finally:
            holder.stdin.close()
            holder.wait(timeout=10)
            holder.stdout.close()
        with lk:
            self.assertEqual(lk.depth, 1)

    def test_a_mutation_reloads_the_index_so_a_stale_vault_loses_nothing(self):
        v1, v2 = Vault(dict(JSONCFG)), Vault(dict(JSONCFG))
        a = v2.put("stale-fake-value-a", "SECRET", "manual", session="A")
        b = v1.put("stale-fake-value-b", "SECRET", "manual", session="A")
        self.assertNotEqual(a.key, b.key)
        on_disk = json.loads(vault.INDEX.read_text(encoding="utf-8"))
        self.assertEqual(sorted(on_disk["entries"]), ["SECRET_c1", "SECRET_c2"])

    def test_a_mutation_that_raises_saves_nothing(self):
        v = Vault(dict(JSONCFG))
        v.put("raise-fake-value", "SECRET", "manual", session="A")
        before = vault.INDEX.read_text(encoding="utf-8")
        with self.assertRaises(ValueError):
            with v._exclusive():
                v._index["counters"]["SECRET"] = 99
                raise ValueError("abort")
        self.assertEqual(vault.INDEX.read_text(encoding="utf-8"), before)
        self.assertEqual(v._lock.depth, 0)

    def test_a_damaged_index_met_inside_a_mutation_releases_the_lock(self):
        """_Mutation took the lock and then re-read the index; when the read raised, `with`
        never called __exit__, and the process kept the lock: every other hook process then
        ran into LockTimeout, and later mutations in this process ran at depth 2, so they
        neither re-read nor saved the index."""
        v = Vault(dict(JSONCFG))
        v.put("leak-fake-value-1", "SECRET", "manual", session="A")
        vault.INDEX.write_text("{damaged", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "repair"):
            v.put("leak-fake-value-2", "SECRET", "manual", session="A")
        self.assertEqual((v._lock.depth, v._lock.fd), (0, None))
        vault.INDEX.unlink()
        v = Vault(dict(JSONCFG))
        with v._exclusive():
            v._index["counters"]["PROBE"] = 1
        self.assertIn("PROBE", json.loads(vault.INDEX.read_text(encoding="utf-8"))["counters"])

    def test_every_index_save_runs_under_the_lock(self):
        """The AST test in test_operations.py reads the decorators; this one watches the calls."""
        saves = []
        real = Vault._save_index

        def watched(self):
            saves.append(self._lock.depth)
            return real(self)
        clock = Clock()
        with mock.patch.object(Vault, "_save_index", watched), clock.patch():
            v = Vault(dict(JSONCFG, ttl_seconds={"default": 60}))
            e = v.put("watch-fake-value-1", "SECRET", "manual", session="A")
            v.put_many([("watch-fake-value-2", "SECRET", "m")], session="A")
            v.admit(e.key, "B")
            v.get(e.key, "A")
            nonce, _ = v.grant(e.key, "A", "Bash", "x")
            v.redeem(e.key, nonce)
            v.record_resolve(e.key, "A", "mcp", "{}")
            clock.advance(61)
            v.expire(limit=None)
            v.forget(e.key)
        self.assertGreaterEqual(len(saves), 9)
        self.assertNotIn(0, saves, "an index save outside the lock")


class BackendTimeoutTests(unittest.TestCase):
    """A store call that hits its timeout raised subprocess.TimeoutExpired out of vault.py: the
    sweep and forget catch RuntimeError only, and the exception text lists the argv, which holds
    the stored value on the keychain's long-value path (CLI test agent, 2026-09-27)."""
    VALUE = "timeout-fake-value-" + "Q7" * 3000     # long: the keychain puts it on argv

    def _timing_out(self, args, *a, **kw):
        raise subprocess.TimeoutExpired(args, kw.get("timeout", 5))

    def _check(self, name: str, op, word: str) -> None:
        import traceback
        with self.subTest(name), mock.patch.object(vault, "subprocess", types.SimpleNamespace(
                run=self._timing_out, CompletedProcess=subprocess.CompletedProcess,
                TimeoutExpired=subprocess.TimeoutExpired)):
            with self.assertRaises(RuntimeError) as cm:
                op()
            text = "".join(traceback.format_exception(type(cm.exception), cm.exception, cm.exception.__traceback__))
            self.assertIn(word, str(cm.exception))
            self.assertIn("timed out", str(cm.exception))
            stored = base64.b64encode(self.VALUE.encode()).decode()
            for secret in (self.VALUE[:40], stored[:40]):
                self.assertNotIn(secret, text)

    def test_every_keychain_call_that_times_out_raises_a_runtime_error_without_the_value(self):
        b = KeychainBackend()
        for name, op in [("put long", lambda: b.put("SECRET_c1", self.VALUE)),
                         ("put short", lambda: b.put("SECRET_c1", "short-fake-value")),
                         ("get", lambda: b.get("SECRET_c1")), ("delete", lambda: b.delete("SECRET_c1")),
                         ("keys", b.keys), ("wipe", b.wipe)]:
            self._check(name, op, "keychain")

    def test_every_credential_locker_call_that_times_out_raises_a_runtime_error(self):
        b = WindowsVaultBackend()
        for name, op in [("put", lambda: b.put("SECRET_c1", self.VALUE)), ("get", lambda: b.get("SECRET_c1")),
                         ("delete", lambda: b.delete("SECRET_c1")), ("keys", b.keys),
                         ("get_many", lambda: b.get_many(["SECRET_c1"])), ("wipe", b.wipe)]:
            self._check(name, op, "Credential Locker")

    def test_an_openssl_call_that_times_out_raises_a_runtime_error(self):
        _reset()
        b = EncryptedFileBackend()
        self._check("put", lambda: b.put("SECRET_c1", self.VALUE), "openssl")
        _reset()


class ConcurrencyTests(unittest.TestCase):
    CHILD = (
        "import os, sys, time\n"
        "from pathlib import Path\n"
        "from maisecrets.vault import JsonFileBackend, Vault\n"
        "# a slow store, as a keychain call is (~10 ms): it widens the window a lock must cover\n"
        "_put = JsonFileBackend.put\n"
        "def slow_put(self, *a, **k):\n"
        "    time.sleep(0.003)\n"
        "    return _put(self, *a, **k)\n"
        "JsonFileBackend.put = slow_put\n"
        "tag, n, go = sys.argv[1], int(sys.argv[2]), Path(sys.argv[3])\n"
        "while not go.exists():\n"
        "    time.sleep(0.005)\n"
        "for i in range(n):\n"
        "    v = Vault()\n"
        "    e = v.put(f'race-fake-{tag}-{i:03d}', 'SECRET', 'manual', session='S-' + tag)\n"
        "    if i % 3 == 0:\n"
        "        v.record_resolve(e.key, 'S-' + tag, 'Bash', 'x')\n"
        # a waiter polls the lock every 20 ms and a writer in a tight loop takes it back at once:
        # on windows-latest one child waited the whole 6 s deadline (2026-09-27). A hook writes
        # once per event, so each child pauses one poll interval between its writes
        "    time.sleep(0.025)\n"
        "print('done')\n"
    )

    def test_two_processes_writing_the_index_at_once_lose_no_entry(self):
        home = Path(tempfile.mkdtemp(prefix="race-", dir=HOME))
        (home / "config.json").write_text(BASE_CONFIG, encoding="utf-8")
        env = _child_env(home)
        try:
            seed = subprocess.run([sys.executable, "-c", "from maisecrets.vault import Vault\n"
                                   "Vault().put('race-fake-seed', 'SECRET', 'manual', session='S0')"],
                                  env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(seed.returncode, 0, seed.stderr)
            go, n = home / "go", 40
            procs = [subprocess.Popen([sys.executable, "-c", self.CHILD, tag, str(n), str(go)], env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for tag in ("a", "b")]
            time.sleep(0.3)
            go.touch()
            for p in procs:
                out, err = p.communicate(timeout=120)
                self.assertEqual(p.returncode, 0, err)
            index = json.loads((home / "index.json").read_text(encoding="utf-8"))
            store = json.loads((home / "vault.json").read_text(encoding="utf-8"))
            self.assertEqual(len(index["entries"]), 2 * n + 1)
            self.assertEqual(index["counters"], {"SECRET": 2 * n + 1})
            self.assertEqual(len(index["by_fingerprint"]), 2 * n + 1)
            self.assertEqual(sorted(k for k in store if k != FP_KEY_ENTRY), sorted(index["entries"]))
            self.assertEqual(len(index["resolves"]), 2 * len(range(0, n, 3)))
            values = sorted(store[k] for k in index["entries"])
            self.assertEqual(values, sorted(["race-fake-seed"] + [f"race-fake-{t}-{i:03d}"
                                                                  for t in "ab" for i in range(n)]))
            self.assertEqual([p.name for p in home.iterdir() if p.name.endswith(".tmp")], [])
            self.assertFalse(NATIVE_MARK.exists(), "a child ran a native store binary")
        finally:
            shutil.rmtree(home, ignore_errors=True)


class RaceAgainstPutTests(unittest.TestCase):
    """One process puts while another expires, forgets or wipes, against one index. The lock makes
    each call one read-modify-write; without it a stale index is saved over the other's work: an
    entry is lost, or an index entry names a value that is gone (suite review, 2026-09-27)."""

    # process A: puts only. Its own sweep is off, so the expired seeds are left for process B.
    # It pauses 50 ms outside the lock after each put, as separate hook processes do (each call is a new
    # process; one call stores its values with one put_many). The lock is a poll: a waiter tries every 20 ms
    # (31 ms with Windows' 15.6 ms timer). Without the pause, A re-took the lock within a millisecond of its
    # release, B's poll almost never fell into that gap, and on a slow Windows runner A's 25 puts outlasted
    # B's 6 s deadline: LockTimeout in B (windows-latest, 2026-10-15). The pause is longer than one poll,
    # so B gets the lock after at most one put of A.
    WRITER = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from maisecrets.home import _Lock\n"
        "from maisecrets.vault import JsonFileBackend, Vault\n"
        "_put = JsonFileBackend.put\n"
        "def slow_put(self, *a, **k):\n"
        "    time.sleep(0.003)\n"
        "    return _put(self, *a, **k)\n"
        "JsonFileBackend.put = slow_put\n"
        "Vault.expire = lambda self, limit=25: 0\n"
        "_Lock.LOCK_DEADLINE = 60.0\n"
        "n, go = int(sys.argv[1]), Path(sys.argv[2])\n"
        "while not go.exists():\n"
        "    time.sleep(0.002)\n"
        "for i in range(n):\n"
        "    e = Vault().put(f'race-fake-w-{i:03d}', 'SECRET', 'manual', session='S-w')\n"
        "    print(e.key, i, flush=True)\n"
        "    time.sleep(0.05)\n"
    )
    # process B: a slow delete (a keychain call takes ~10 ms) widens the window a lock must cover. 30 ms: with
    # 3 ms, B's forgets fit into A's pauses, and without the lock 8 of 30 test runs stayed green
    # (10 rounds, measured 2026-10-16); with 30 ms, 30 of 30 went red.
    OTHER = (
        "import json, os, sys, time\n"
        "from pathlib import Path\n"
        "from maisecrets.vault import JsonFileBackend, Vault, load_config, wipe_everything\n"
        "_delete = JsonFileBackend.delete\n"
        "def slow_delete(self, *a, **k):\n"
        "    time.sleep(0.03)\n"
        "    return _delete(self, *a, **k)\n"
        "JsonFileBackend.delete = slow_delete\n"
        "from maisecrets.home import _Lock\n"
        "_Lock.LOCK_DEADLINE = 60.0\n"
        "mode, go, keys = sys.argv[1], Path(sys.argv[2]), sys.argv[3:]\n"
        "while not go.exists():\n"
        "    time.sleep(0.002)\n"
        "time.sleep(0.02)\n"
        "if mode == 'expire':\n"
        "    for _ in range(3):\n"
        "        Vault().expire(limit=None)\n"
        "elif mode == 'forget':\n"
        "    for key in keys:\n"
        "        assert Vault().forget(key) == 'ok', key\n"
        "else:\n"
        "    index = Path(os.environ['MAISECRETS_HOME']) / 'index.json'\n"
        # read_text_retry: on Windows a read while the writer's os.replace runs raises PermissionError
        "    from maisecrets.vault import read_text_retry\n"
        "    def writes():\n"
        "        entries = json.loads(read_text_retry(index))['entries']\n"
        "        return sum(m.get('session') == 'S-w' for m in entries.values())\n"
        "    while writes() < 8:\n"
        "        time.sleep(0.002)\n"
        "    n, problems = wipe_everything(load_config())\n"
        "    assert not problems, problems\n"
        "print('done')\n"
    )
    # both children wait up to 60 s for the lock, not the 6 s of a hook: this test asks whether the lock keeps every
    # entry, not whether a lock comes within a hook's deadline (other tests own that). On a loaded windows-latest
    # runner B waited longer than 6 s for one forget and the test failed with LockTimeout (2026-10-15, 2026-10-19)
    SEEDS, N = 10, 25

    def _race(self, mode: str, expired_seeds: bool = False) -> tuple[Path, dict, dict, dict[str, int], list[str]]:
        home = Path(tempfile.mkdtemp(prefix="race-", dir=HOME))
        self.addCleanup(shutil.rmtree, home, True)
        (home / "config.json").write_text(BASE_CONFIG, encoding="utf-8")
        env = _child_env(home)
        seed = subprocess.run([sys.executable, "-c",
                               "import json, sys, time\nfrom maisecrets.vault import INDEX, Vault\n"
                               "keys = [Vault().put(f'race-fake-seed-{i:02d}', 'SECRET', 'manual', session='S0').key "
                               "for i in range(int(sys.argv[1]))]\n"
                               "if sys.argv[2] == '1':\n"
                               "    data = json.loads(INDEX.read_text())\n"
                               "    for k in keys:\n"
                               "        data['entries'][k]['expires'] = time.time() - 10\n"
                               "    INDEX.write_text(json.dumps(data))\n"
                               "print(' '.join(keys))\n", str(self.SEEDS), "1" if expired_seeds else "0"],
                              env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(seed.returncode, 0, seed.stderr)
        seeds = seed.stdout.split()
        go = home / "go"
        procs = [subprocess.Popen([sys.executable, "-c", self.WRITER, str(self.N), str(go)], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True),
                 subprocess.Popen([sys.executable, "-c", self.OTHER, mode, str(go), *seeds], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)]
        time.sleep(0.1)          # both children import maisecrets and wait for the go file
        go.touch()
        outs = []
        for p in procs:
            out, err = p.communicate(timeout=60)
            self.assertEqual(p.returncode, 0, err[-800:])
            outs.append(out)
        last: dict[str, int] = {}
        for line in outs[0].split("\n"):
            if line:
                key, i = line.split()
                last[key] = int(i)
        index = json.loads((home / "index.json").read_text(encoding="utf-8")) if (home / "index.json").exists() \
            else {"entries": {}, "by_fingerprint": {}, "counters": {}}
        store = json.loads((home / "vault.json").read_text(encoding="utf-8"))
        live = sorted(k for k, m in index["entries"].items() if not m.get("purged"))
        # no value without a live entry, no live entry without its value
        self.assertEqual(sorted(k for k in store if k != FP_KEY_ENTRY), live)
        self.assertEqual([p.name for p in home.iterdir() if p.name.endswith(".tmp")], [])
        self.assertFalse(NATIVE_MARK.exists(), "a child ran a native store binary")
        return home, index, store, last, seeds

    def _all_writes_kept(self, index: dict, store: dict, last: dict[str, int]) -> None:
        self.assertEqual(sorted(last.values()), list(range(self.N)))
        for key, i in last.items():
            self.assertIn(key, index["entries"], "an entry the writer put was lost")
            self.assertEqual(store.get(key), f"race-fake-w-{i:03d}")

    def test_put_against_expire_loses_no_entry_and_purges_every_expired_one(self):
        _home, index, store, last, seeds = self._race("expire", expired_seeds=True)
        self._all_writes_kept(index, store, last)
        for key in seeds:
            self.assertTrue(index["entries"][key].get("purged"), key)
            self.assertNotIn(key, store, "an expired value came back")
        self.assertEqual(index["counters"], {"SECRET": self.SEEDS + self.N})

    def test_put_against_forget_loses_no_entry_and_brings_no_forgotten_one_back(self):
        _home, index, store, last, seeds = self._race("forget")
        self._all_writes_kept(index, store, last)
        for key in seeds:
            self.assertNotIn(key, index["entries"], "a forgotten entry came back")
        self.assertEqual(len(index["by_fingerprint"]), self.N)
        self.assertEqual(index["counters"], {"SECRET": self.SEEDS + self.N})

    def test_put_against_wipe_keeps_exactly_the_writes_after_the_wipe(self):
        _home, index, store, last, _seeds = self._race("wipe")
        self.assertFalse(any(m.get("session") == "S0" for m in index["entries"].values()), "a wiped entry came back")
        kept = sorted(last[k] for k in index["entries"])
        # the writes after the wipe, all of them, and none from before it
        self.assertEqual(kept, list(range(self.N - len(kept), self.N)))
        self.assertLessEqual(len(kept), self.N - 8, "the wipe ran after the eighth write")
        for key in index["entries"]:
            self.assertEqual(store[key], f"race-fake-w-{last[key]:03d}")


if __name__ == "__main__":
    unittest.main()
