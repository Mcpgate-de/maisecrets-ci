"""The keychain store against a fake `security` that runs as a real program first on PATH (tests/fake_security.py).

#75: a value never stands on the command line of `security`, where `ps` of any process of the user shows it, at any
length. #76: a keychain that does not answer holds no hook past its own time; the hook fails closed and says why.

The real `security` and the real keychain are never reached: the fake comes first on PATH, before the tripwires of
tests/_isolate.py.

Run: python3 -m unittest tests.test_keychain_process -v
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import vault  # noqa: E402
from maisecrets.vault import CodedError, KeychainBackend  # noqa: E402

FAKE = Path(__file__).resolve().parent / "fake_security.py"


def make_fake(where: Path) -> dict:
    """A `security` in its own bin folder, and the environment that puts it first on PATH."""
    bin_dir = where / "bin"
    bin_dir.mkdir(parents=True)
    tool = bin_dir / "security"
    tool.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n', encoding="utf-8")
    tool.chmod(0o755)
    return {"PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""), "FAKE_SECURITY_DIR": str(where)}


def random_text(n: int) -> str:
    """A value with no repeated window, so any 16 characters of it on a command line are found."""
    return secrets.token_urlsafe(n)[:n]


@unittest.skipIf(os.name == "nt", "the fake is a shell script; the keychain is macOS only")
class FakeKeychain(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fake-security-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        env = mock.patch.dict(os.environ, make_fake(self.dir))
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(vault.hook_deadline, None)
        shutil.rmtree(vault.PARTS_PENDING, True)       # the markers of an earlier test
        self.addCleanup(shutil.rmtree, vault.PARTS_PENDING, True)
        self.backend = KeychainBackend()

    def calls(self) -> list[dict]:
        try:
            lines = (self.dir / "calls.jsonl").read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        return [json.loads(ln) for ln in lines]

    def items(self) -> dict:
        try:
            return json.loads((self.dir / "items.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}


class NoValueOnTheCommandLineTests(FakeKeychain):
    """#75: before 0.9.18 a record above 3900 bytes went to `security add-generic-password -w <value>`."""

    def assert_not_on_argv(self, value: str) -> None:
        stored = base64.b64encode(value.encode("utf-8")).decode("ascii")
        argv = "\0".join(a for c in self.calls() for a in c["argv"])
        for text in (value, stored):
            for i in range(0, max(1, len(text) - 16), 8):
                window = text[i:i + 16]
                self.assertFalse(window in argv, "a part of the value stands on the command line of `security`")
        stdin = "".join(c["stdin"] for c in self.calls())
        self.assertIn(stored[:64], stdin, "the value goes through stdin")

    def test_a_short_value_goes_through_stdin(self):
        value = random_text(40)
        self.backend.put("SECRET_c1", value)
        self.assertEqual(self.backend.get("SECRET_c1"), value)
        self.assert_not_on_argv(value)

    def test_a_long_value_goes_through_stdin_in_parts(self):
        for n, key in ((5000, "SECRET_c2"), (40000, "SECRET_c3")):
            with self.subTest(length=n):
                value = random_text(n)
                self.backend.put(key, value, label=f"maisecrets {key} (manual)", comment="a fake comment")
                self.assertEqual(self.backend.get(key), value)
                self.assert_not_on_argv(value)

    def test_a_long_token_pair_of_a_gateway_login(self):
        from maisecrets import sref_client
        origin = "https://gateway.example.test"
        record = {"access": random_text(1800), "refresh": random_text(1800), "client_id": "fake-client",
                  "scope": "refs ner", "expires": 1_800_000_000}
        sref_client._keep(self.backend, origin, record)
        self.assertEqual(sref_client._load(self.backend, origin), record)
        self.assert_not_on_argv(json.dumps(record))

    def test_each_line_fits_the_line_limit_of_security_i(self):
        self.backend.put("SECRET_c4", random_text(30000))
        for c in self.calls():
            for line in c["stdin"].split("\n"):
                self.assertLessEqual(len(line.encode("utf-8")), KeychainBackend.MAX_LINE)

    def test_a_replaced_or_deleted_long_value_leaves_no_part_behind(self):
        long1, long2, short = random_text(9000), random_text(12000), random_text(30)
        self.backend.put("SECRET_c5", long1)
        self.backend.put("SECRET_c5", long2)
        self.assertEqual(self.backend.get("SECRET_c5"), long2)
        head = next(v for k, v in self.items().items() if k.endswith("\0SECRET_c5"))
        gen = head.split(":")[2]
        parts = [k for k in self.items() if ".part" in k]
        self.assertEqual(len(parts), int(head.split(":")[1]) - 1)
        self.assertTrue(all(k.endswith("." + gen) for k in parts), "the parts of long1 are gone")
        self.backend.put("SECRET_c5", short)
        self.assertEqual(self.backend.get("SECRET_c5"), short)
        self.assertEqual(len(self.items()), 1)
        self.backend.put("SECRET_c5", long1)
        self.assertEqual(self.backend.keys(), ["SECRET_c5"])  # the parts are no keys of their own
        self.backend.delete("SECRET_c5")
        self.assertEqual(self.items(), {})
        self.assertIsNone(self.backend.get("SECRET_c5"))

    def test_a_part_of_another_value_reads_as_nothing(self):
        # a put that stopped halfway, or two writers: the head and a part of two values of the same length
        self.backend.put("SECRET_c6", random_text(9000))
        self.backend.put("SECRET_c7", random_text(9000))
        items = self.items()
        mine = next(k for k in items if "SECRET_c6.part1." in k)
        items[mine] = items[next(k for k in items if "SECRET_c7.part1." in k)]
        (self.dir / "items.json").write_text(json.dumps(items), encoding="utf-8")
        self.assertIsNone(self.backend.get("SECRET_c6"))

    def test_a_value_too_long_for_the_stdin_form_is_refused_and_not_put_on_the_command_line(self):
        value = random_text(KeychainBackend.MAX_PARTS * 3700)
        with self.assertRaisesRegex(CodedError, "too long") as cm:
            self.backend.put("SECRET_c7", value)
        self.assertNotIn(value[:16], str(cm.exception))
        self.assertEqual(self.items(), {})
        self.assertFalse([c for c in self.calls() if c["argv"][:1] == ["add-generic-password"]])


class ExitZeroOnFailureTests(FakeKeychain):
    """Gate A of #75: `security -i` can exit 0 although its command failed. The fake does so by default; only a
    read-back proves an add, and a failed add never costs the old value."""

    def env(self, **kw) -> None:
        p = mock.patch.dict(os.environ, kw)
        p.start()
        self.addCleanup(p.stop)

    def test_a_failed_part_or_head_keeps_the_old_long_value(self):
        for fail in (r"\.part2\.", r"^SECRET_c1$"):
            with self.subTest(fail=fail):
                old = random_text(9000)
                os.environ.pop("FAKE_SECURITY_FAIL_ADD", None)
                self.backend.put("SECRET_c1", old)
                with mock.patch.dict(os.environ, {"FAKE_SECURITY_FAIL_ADD": fail}):
                    with self.assertRaises(CodedError):
                        self.backend.put("SECRET_c1", random_text(12000))
                self.assertEqual(self.backend.get("SECRET_c1"), old)

    def test_a_failed_short_add_keeps_the_old_value(self):
        for old in (random_text(30), random_text(9000)):
            with self.subTest(length=len(old)):
                self.backend.put("SECRET_c2", old)
                with mock.patch.dict(os.environ, {"FAKE_SECURITY_FAIL_ADD": r"^SECRET_c2$"}):
                    with self.assertRaisesRegex(CodedError, "read-back"):
                        self.backend.put("SECRET_c2", random_text(30))
                self.assertEqual(self.backend.get("SECRET_c2"), old)

    def test_a_line_break_in_a_name_a_label_or_a_comment_is_refused_before_any_call(self):
        for kw in ({"key": "SECRET_c3\ndelete-generic-password -s x"}, {"label": "a\r\nlabel"},
                   {"comment": "a\0comment"}):
            with self.subTest(kw=kw):
                with self.assertRaisesRegex(CodedError, "line break"):
                    self.backend.put(kw.get("key", "SECRET_c3"), "fake-value-0003", label=kw.get("label"),
                                     comment=kw.get("comment"))
        self.assertFalse([c for c in self.calls() if c["argv"] == ["-i"]])
        self.backend.put("SECRET_c4", "a value\nwith a line break")     # the value itself goes as base64
        self.assertEqual(self.backend.get("SECRET_c4"), "a value\nwith a line break")

    def test_orphan_parts_are_removed_and_the_parts_of_a_readable_head_stay(self):
        keep = random_text(9000)
        self.backend.put("SECRET_c5", keep)
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_FAIL_ADD": r"^SECRET_c6$"}):
            with self.assertRaises(CodedError):
                self.backend.put("SECRET_c6", random_text(9000))     # its parts stay without a head
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_FAIL_ADD": r"\.part3\."}):
            with self.assertRaises(CodedError):
                self.backend.put("SECRET_c5", random_text(12000))    # a new generation stopped halfway
        self.assertTrue(vault._parts_pending())
        orphans = [k for k in self.items() if ".part" in k and ("SECRET_c6" in k or "SECRET_c5" in k)]
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_FIND_FAIL": r"^SECRET_c7$:51"}):
            self.backend.put("SECRET_c8", random_text(9000))
            items = self.items()
            items[vault.SERVICE + "\0SECRET_c7.part1.0123456789ab"] = "QUJD"   # its head cannot be read: kept
            (self.dir / "items.json").write_text(json.dumps(items), encoding="utf-8")
            removed = self.backend.remove_orphan_parts()
        left = self.items()
        self.assertEqual(self.backend.get("SECRET_c5"), keep)
        self.assertEqual(removed, len(orphans) - (int(left[vault.SERVICE + "\0SECRET_c5"].split(":")[1]) - 1))
        self.assertFalse([k for k in left if "SECRET_c6" in k])
        self.assertIn(vault.SERVICE + "\0SECRET_c7.part1.0123456789ab", left)
        # Gate A round 2: a head that could not be read keeps the sweep pending, so the next full sweep looks again
        self.assertTrue(vault._parts_pending())
        self.assertEqual(self.backend.remove_orphan_parts(), 1)
        self.assertNotIn(vault.SERVICE + "\0SECRET_c7.part1.0123456789ab", self.items())
        self.assertFalse(vault._parts_pending())

    def test_two_writers_do_not_clear_each_others_marker_or_parts(self):
        # Gate A round 2: one global marker, and a writer that finished cleared it under a writer that still ran.
        # Writer A: its marker and its first part stand, its head is not written yet
        gen = "0" * 12
        mark = vault._pending_mark("SECRET_c12", gen)
        items = self.items()
        items[vault.SERVICE + "\0SECRET_c12.part1." + gen] = "QUJD"
        (self.dir / "items.json").write_text(json.dumps(items), encoding="utf-8")
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_FAIL_ADD": r"^SECRET_c13$"}):
            with self.assertRaises(CodedError):
                self.backend.put("SECRET_c13", random_text(9000))    # writer C stopped: its parts are orphans
        self.backend.put("SECRET_c14", random_text(9000))            # writer B finished
        self.assertTrue(mark.exists(), "writer B cleared the marker of writer A")
        self.assertTrue(vault._parts_pending())
        self.backend.remove_orphan_parts()
        left = self.items()
        self.assertIn(vault.SERVICE + "\0SECRET_c12.part1." + gen, left, "the sweep took a running put's part")
        self.assertFalse([k for k in left if "SECRET_c13" in k])
        self.assertTrue(mark.exists())
        self.assertFalse(vault._parts_pending())                     # only a running put is left
        os.utime(mark, (0, 0))                                       # writer A was stopped long ago
        self.assertTrue(vault._parts_pending())
        self.assertEqual(self.backend.remove_orphan_parts(), 1)
        self.assertFalse(mark.exists())

    def test_the_full_sweep_and_the_repair_remove_orphan_parts(self):
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_FAIL_ADD": r"^SECRET_c9$"}):
            with self.assertRaises(CodedError):
                self.backend.put("SECRET_c9", random_text(9000))
        for run in ("expire", "repair"):
            with self.subTest(run=run):
                if run == "repair":
                    with mock.patch.dict(os.environ, {"FAKE_SECURITY_FAIL_ADD": r"^SECRET_c9$"}):
                        with self.assertRaises(CodedError):
                            self.backend.put("SECRET_c9", random_text(9000))
                self.assertTrue([k for k in self.items() if "SECRET_c9.part" in k])
                v = open_vault(self, self.backend)
                v.expire(limit=None) if run == "expire" else v.repair()
                self.assertFalse([k for k in self.items() if "SECRET_c9.part" in k])

    def test_a_put_whose_old_head_cannot_be_read_writes_nothing(self):
        # the parts of the old value would be lost from sight under a new head
        self.backend.put("SECRET_c11", random_text(9000))
        before = self.items()
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_FIND_FAIL": r"^SECRET_c11$:51"}):
            with self.assertRaisesRegex(CodedError, "rc 51"):
                self.backend.put("SECRET_c11", random_text(30))
        self.assertEqual(self.items(), before)

    def test_a_delete_whose_head_read_fails_keeps_the_head_and_its_parts(self):
        self.backend.put("SECRET_c10", random_text(9000))
        before = self.items()
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_FIND_FAIL": r"^SECRET_c10$:51"}):
            with self.assertRaisesRegex(RuntimeError, "rc 51"):
                self.backend.delete("SECRET_c10")
        self.assertEqual(self.items(), before)


class AfterTheHeadTests(FakeKeychain):
    """Gate A round 2 of #75: once the new head is read back, the new value is stored. A failure in the removal of the
    old parts after that raised, and the caller read it as "the old value stays"."""

    def parts_of(self, key: str) -> set:
        return {k.split(".")[-1] for k in self.items() if f"\0{key}.part" in k}

    def test_old_parts_that_do_not_go_are_left_to_the_sweep_and_the_put_succeeds(self):
        old, new = random_text(9000), random_text(12000)
        self.backend.put("SECRET_c15", old)
        old_gen = self.parts_of("SECRET_c15")
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_DELETE_FAIL": r"^SECRET_c15\.part:51"}):
            self.backend.put("SECRET_c15", new)                       # no raise: the new value is stored
        self.assertEqual(self.backend.get("SECRET_c15"), new)
        self.assertTrue(old_gen < self.parts_of("SECRET_c15"), "the old parts wait for the sweep")
        self.assertTrue(vault._parts_pending())
        self.backend.remove_orphan_parts()
        self.assertFalse(old_gen & self.parts_of("SECRET_c15"))
        self.assertEqual(self.backend.get("SECRET_c15"), new)
        self.assertFalse(vault._parts_pending())

    def test_a_removal_of_old_parts_that_runs_out_of_time_is_no_failed_put(self):
        old, new = random_text(9000), random_text(12000)
        self.backend.put("SECRET_c16", old)
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_SLEEP": "delete-generic-password:30"}):
            vault.hook_deadline(vault.STORE_MARGIN + 3.0)
            self.backend.put("SECRET_c16", new)
            vault.hook_deadline(None)
        self.assertEqual(self.backend.get("SECRET_c16"), new)
        self.assertTrue(vault._parts_pending())

    def test_a_head_whose_read_back_fails_leaves_one_whole_value_and_the_sweep_pending(self):
        # the head add may have taken or not: the put raises, and a read gives one whole value, never a mix
        old, new = random_text(9000), random_text(12000)
        self.backend.put("SECRET_c17", old)
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_FIND_ONCE": "^SECRET_c17$:36:2"}):   # 1: the read before
            with self.assertRaises(CodedError):
                self.backend.put("SECRET_c17", new)
        self.assertIn(self.backend.get("SECRET_c17"), (old, new))
        self.assertTrue(vault._parts_pending())
        self.backend.remove_orphan_parts()
        self.assertIn(self.backend.get("SECRET_c17"), (old, new))
        self.assertEqual(len(self.parts_of("SECRET_c17")), 1, "one generation of parts is left")


class Stopped(BaseException):
    """A process stopped at one step: the tests also switch off _pending_stale, as a kill runs no handler."""


class StoppedPutTests(FakeKeychain):
    """Gate A round 3 of #75: a put stopped after its head was proven and before the marker of the old parts left
    those parts with no marker, and no later sweep looked for them. And a marker that could not be written was
    ignored while the write went on."""

    def orphans(self, key: str) -> list:
        raw = self.items().get(vault.SERVICE + "\0" + key, "")
        head = KeychainBackend._split_head(raw)
        named = {KeychainBackend._part_name(key, i, head[1]) for i in range(1, head[0])} if head else set()
        return [k.split("\0")[1] for k in self.items() if f"\0{key}.part" in k and k.split("\0")[1] not in named]

    def stop_at(self, step: str):
        """Stop the put at `step`: after the head add, at the marker of the old parts, or before the old parts go."""
        real_add, real_mark = KeychainBackend._add, vault._pending_mark

        def add(backend, line, account=None, stored=None):
            real_add(backend, line, account, stored)
            if step == "head" and account is not None and ".part" not in account:
                raise Stopped()

        def mark(key, gen, stale=False):
            path = real_mark(key, gen, stale)
            if step == "old-marker" and stale:
                raise Stopped()
            return path

        def delete_parts(backend, key, head):
            raise Stopped()
        patches = [mock.patch.object(vault, "_pending_stale", lambda path: None),
                   mock.patch.object(KeychainBackend, "_add", add), mock.patch.object(vault, "_pending_mark", mark)]
        if step == "old-parts":
            patches.append(mock.patch.object(KeychainBackend, "_delete_parts", delete_parts))
        return patches

    def test_a_put_stopped_at_any_step_leaves_no_part_without_a_marker(self):
        for step in ("head", "old-marker", "old-parts"):
            for new_len in (12000, 30):                 # long to long, long to short
                with self.subTest(step=step, new=new_len):
                    shutil.rmtree(vault.PARTS_PENDING, True)
                    key = f"SECRET_c3{len(step)}{new_len % 7}"
                    old, new = random_text(9000), random_text(new_len)
                    self.backend.put(key, old)
                    patches = self.stop_at(step)
                    for p in patches:
                        p.start()
                    try:
                        with self.assertRaises(Stopped):
                            self.backend.put(key, new)
                    finally:
                        for p in reversed(patches):
                            p.stop()
                    self.assertIn(self.backend.get(key), (old, new))
                    for path, _k, _g, _fresh in vault._pending_marks():
                        os.utime(path, (0, 0))           # long after the stop: no put runs any more
                    if self.orphans(key):
                        self.assertTrue(vault._parts_pending(), "parts without a head and without a marker")
                    self.backend.remove_orphan_parts()
                    self.assertEqual(self.orphans(key), [])
                    self.assertIn(self.backend.get(key), (old, new))

    def test_a_marker_that_cannot_be_written_refuses_the_put_before_any_write(self):
        self.backend.put("SECRET_c40", random_text(9000))
        blocker = self.dir / "not-a-folder"
        blocker.write_text("x", encoding="utf-8")
        for new in (random_text(12000), random_text(30)):    # a long value; a short one over a long one
            with self.subTest(length=len(new)):
                before = self.items()
                with mock.patch.object(vault, "PARTS_PENDING", blocker / "keychain-parts"):
                    with self.assertRaisesRegex(CodedError, "marker"):
                        self.backend.put("SECRET_c40", new)
                self.assertEqual(self.items(), before)
        self.backend.put("SECRET_c41", random_text(9000))
        with mock.patch.object(vault, "PARTS_PENDING", blocker / "keychain-parts"):
            with self.assertRaisesRegex(CodedError, "marker"):
                self.backend.put("SECRET_c42", random_text(9000))
        self.assertFalse([k for k in self.items() if "SECRET_c42" in k])


class FailedDumpTests(FakeKeychain):
    """Gate A round 3 of #75: `keys()` read a failed `dump-keychain` as an empty store, and repair then wrote an
    index with no entries over the good one."""

    def test_a_repair_with_a_failed_dump_raises_and_keeps_the_index(self):
        v = open_vault(self, self.backend)
        v.put("fake-value-0021", "SECRET", "manual")
        before = vault.INDEX.read_bytes()
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_DUMP_RC": "51"}):
            with self.assertRaisesRegex(CodedError, "rc 51"):
                self.backend.keys()
            with self.assertRaises(CodedError):
                v.repair()
        self.assertEqual(vault.INDEX.read_bytes(), before)

    def test_a_wipe_with_a_failed_dump_names_the_problem(self):
        with mock.patch.dict(os.environ, {"FAKE_SECURITY_DUMP_RC": "51"}), \
                mock.patch.object(vault, "make_backend", return_value=self.backend):
            _n, problems = vault.wipe_everything({"backend": "jsonfile", "allow_plaintext_store": True})
        self.assertTrue([p for p in problems if "not listed" in p], problems)


class FailedFindTests(FakeKeychain):
    """Gate A round 2 of #75: a find that failed for another reason than "no such item" (rc 44) read as absent. The
    fingerprint key was then made again over the old one, and every fingerprint in the index was lost."""

    def once(self, account: str, rc: int, n: int = 1):
        return mock.patch.dict(os.environ, {"FAKE_SECURITY_FIND_ONCE": f"^{account}$:{rc}:{n}"})

    def test_a_failed_find_of_the_fingerprint_key_does_not_replace_it(self):
        key = open_vault(self, self.backend).fp_key()
        with self.once(vault.FP_KEY_ENTRY, 51):
            with self.assertRaisesRegex(CodedError, "rc 51"):
                open_vault(self, self.backend).fp_key()
        self.assertEqual(open_vault(self, self.backend).fp_key(), key)

    def test_a_failed_find_of_a_stored_value_or_of_its_part_is_no_absent_value(self):
        self.backend.put("SECRET_c1", random_text(9000))
        for account in ("SECRET_c1", r"SECRET_c1\.part1\..*"):
            with self.subTest(account=account), self.once(account, 36):
                with self.assertRaisesRegex(CodedError, "rc 36") as cm:
                    self.backend.get("SECRET_c1")
                self.assertEqual(cm.exception.incident_rc, 36)
        self.assertIsNone(self.backend.get("SECRET_c2"))            # rc 44: no such item
        self.assertEqual(len(self.backend.get("SECRET_c1")), 9000)


def open_vault(test: unittest.TestCase, backend):
    """A Vault of the test home on this backend; the index goes at the end of the test."""
    def clean():
        for f in ("index.json", "audit.log", "events.log"):
            try:
                (vault.HOME / f).unlink()
            except FileNotFoundError:
                pass
    clean()
    test.addCleanup(clean)
    with mock.patch.object(vault, "make_backend", return_value=backend):
        return vault.Vault({"backend": "jsonfile", "allow_plaintext_store": True})


class SlowKeychainTests(FakeKeychain):
    """#76: a keychain read waited its own 5 s, also when the hook had less time left."""

    def slow(self, name: str, seconds: float) -> None:
        env = mock.patch.dict(os.environ, {"FAKE_SECURITY_SLEEP": f"{name}:{seconds}"})
        env.start()
        self.addCleanup(env.stop)

    def test_a_read_ends_with_the_hooks_time(self):
        self.backend.put("SECRET_c1", "fake-value-0001")
        self.slow("find-generic-password", 30)
        vault.hook_deadline(vault.STORE_MARGIN + 1.0)
        started = time.monotonic()
        with self.assertRaises(CodedError) as cm:
            self.backend.get("SECRET_c1")
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertTrue(vault.is_store_timeout(cm.exception))
        self.assertNotIn("fake-value-0001", str(cm.exception))

    def test_a_write_ends_with_the_hooks_time(self):
        self.slow("add-generic-password", 30)
        vault.hook_deadline(vault.STORE_MARGIN + 1.0)
        started = time.monotonic()
        with self.assertRaises(CodedError):
            self.backend.put("SECRET_c1", "fake-value-0002")
        self.assertLess(time.monotonic() - started, 2.5)

    def test_no_call_starts_when_no_time_is_left(self):
        vault.hook_deadline(vault.STORE_MARGIN - 0.5)
        with mock.patch.object(vault.subprocess, "run") as run, self.assertRaises(CodedError) as cm:
            self.backend.get("SECRET_c1")
        run.assert_not_called()
        self.assertTrue(vault.is_store_timeout(cm.exception))

    def test_a_sweep_and_the_word_checks_do_not_swallow_a_store_timeout(self):
        # Gate A of #76: each of them caught every RuntimeError, so a keychain that did not answer read as "skip"
        v = open_vault(self, self.backend)
        e = v.put("fake-value-0004", "SECRET", "generic-secret-shape", session="S1")
        f = v.put("fake-value-0005", "SECRET", "label-password", session="S1")
        meta, label = v._index["entries"][e.key], v._index["entries"][f.key]
        meta.update(wordcheck=False, quiet=True, weak=False)
        label.pop("weak", None)
        v._save_index()                                          # each check reads the index again
        self.slow("find-generic-password", 30)
        for name in ("weaken_quiet_words", "weaken_word_hits", "mark_weak_entries", "expire"):
            with self.subTest(name=name):
                if name == "expire":
                    meta["expires"] = 0                          # expired: the sweep deletes it
                    v._index["entries"][e.key] = meta
                    v._save_index()
                vault.hook_deadline(vault.STORE_MARGIN + 0.6)
                with self.assertRaises(CodedError) as cm:
                    getattr(v, name)()
                self.assertTrue(vault.is_store_timeout(cm.exception))

    def test_the_encrypted_store_does_not_read_a_timeout_as_an_expired_value(self):
        from maisecrets.vault import EncryptedFileBackend
        home = Path(tempfile.mkdtemp(prefix="enc-store-"))
        self.addCleanup(shutil.rmtree, home, True)
        with mock.patch.dict(os.environ, {"MAISECRETS_KEY_FILE": str(home / "key")}), \
                mock.patch.object(vault, "HOME", home):
            b = EncryptedFileBackend()
            b.put("SECRET_c1", "fake-value-0006")
            late = CodedError("openssl call timed out", "store.timeout-openssl", "timeout")
            with mock.patch.object(b, "_openssl", side_effect=late), self.assertRaises(CodedError):
                b.get("SECRET_c1")
            refused = CodedError("openssl failed", "store.openssl", "rc", 1)
            with mock.patch.object(b, "_openssl", side_effect=refused):
                self.assertIsNone(b.get("SECRET_c1"))

    def test_a_shorter_budget_of_a_caller_counts_inside_its_block(self):
        self.slow("find-generic-password", 30)
        vault.hook_deadline(6.0)
        started = time.monotonic()
        with self.assertRaises(CodedError), vault.store_deadline(time.monotonic() + 0.8):
            self.backend.get("SECRET_c1")
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(vault.store_time_left() > 3, True)   # the block's limit ends with the block

    def test_the_gateway_login_read_of_the_name_service_ends_with_its_deadline(self):
        from maisecrets import sref_client
        origin = "https://gateway.example.test"
        sref_client._keep(self.backend, origin, {"access": "a", "refresh": "r"})
        self.slow("find-generic-password", 30)
        found = {"origin": origin, "token_endpoint": origin + "/token"}
        started = time.monotonic()
        with self.assertRaisesRegex(sref_client.Refused, "did not answer"):
            sref_client._access({}, self.backend, found, time.monotonic() + 0.8)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_the_name_service_of_a_gateway_leaves_the_names_unchecked_as_with_a_slow_service(self):
        from maisecrets import ner_gateway, sref_client
        origin = "https://gateway.example.test"
        sref_client._keep(self.backend, origin, {"access": "a", "refresh": "r", "scope": "ner"})
        self.slow("find-generic-password", 30)
        found = {"origin": origin, "ner": {"scope": "ner", "endpoint": origin + "/ner"}}
        started = time.monotonic()
        with mock.patch.object(ner_gateway, "found_for", return_value=found), \
                mock.patch("maisecrets.vault.make_backend", return_value=self.backend):
            got, why = ner_gateway.detector({}, {"gateway": origin}, lambda *a: "a detector", time.monotonic() + 0.8)
        self.assertIsNone(got)
        self.assertIn("did not answer in time", why)
        self.assertEqual(ner_gateway.LAST["cause"], "slow")
        self.assertLess(time.monotonic() - started, 2.0)


class HookPathCatchesTests(unittest.TestCase):
    """Gate A round 2 of #76: catches on hook paths that took every RuntimeError also took a store timeout, so a
    keychain that did not answer read as "skip". A timeout goes on; any other store refusal stays best effort."""

    LATE = CodedError("keychain call timed out", "store.timeout-keychain", "timeout")
    REFUSED = CodedError("keychain delete failed (rc 51)", "store.expire", "rc", 51)

    def backend(self, exc):
        b = mock.Mock()
        b.delete.side_effect = exc
        return b

    def test_the_prune_of_server_values(self):
        from maisecrets import vault_refs
        data = {"s1": [{"name": "_maisecrets_vrel_a", "t": 0}, {"name": "_maisecrets_vrel_b", "t": 0}]}
        with self.assertRaises(CodedError):
            vault_refs._prune(self.backend(self.LATE), json.loads(json.dumps(data)), time.time())
        b = self.backend(self.REFUSED)
        self.assertEqual(vault_refs._prune(b, json.loads(json.dumps(data)), time.time()), data)
        self.assertEqual(b.delete.call_count, 2)

    def test_the_session_end(self):
        from maisecrets import vault_refs
        from maisecrets.home import atomic_write
        self.addCleanup(lambda: vault_refs.RELEASED.unlink() if vault_refs.RELEASED.exists() else None)
        for exc in (self.LATE, self.REFUSED):
            with self.subTest(exc=exc.incident_cause):
                vault_refs.DIR.mkdir(parents=True, exist_ok=True)
                atomic_write(vault_refs.RELEASED, json.dumps(
                    {"s1": [{"name": "_maisecrets_vrel_a", "t": time.time()},
                            {"name": "_maisecrets_vrel_b", "t": time.time()}]}))
                b = self.backend(exc)
                if exc is self.LATE:
                    with self.assertRaises(CodedError):
                        vault_refs.end_session(b, "s1")
                    self.assertEqual(b.delete.call_count, 1, "no wait for each name")
                else:
                    self.assertEqual(vault_refs.end_session(b, "s1"), 0)
                    self.assertEqual(b.delete.call_count, 2)
                left = json.loads(vault_refs.RELEASED.read_text(encoding="utf-8"))["s1"]
                self.assertEqual([i["t"] for i in left], [0, 0], "expired and indexed: the next prune deletes them")

    def test_the_notes_of_a_tool_result(self):
        from maisecrets import hooks, sref_hooks, vault_refs
        mcp = {"hook_event_name": "PostToolUse", "tool_name": "mcp__fake__read", "session_id": "S1",
               "tool_input": {}, "tool_response": "fake output"}
        bash = {**mcp, "tool_name": "Bash", "tool_input": {"command": "true"}}
        for name, target, payload in (("note_result", mock.patch.object(vault_refs, "note_result"), mcp),
                                      ("sref note", mock.patch.object(hooks, "_sref_note"), bash),
                                      ("account", mock.patch.object(sref_hooks, "account_notice"), bash)):
            with self.subTest(name=name):
                with target as fake:
                    fake.side_effect = self.LATE
                    with self.assertRaises(CodedError):
                        if name == "account":
                            sref_hooks.note(bash)
                        else:
                            hooks._post_tool_guarded(payload)
                    fake.side_effect = self.REFUSED                  # best effort: the output goes on
                    if name == "account":
                        self.assertIsNone(sref_hooks.note(bash))
                    else:
                        self.assertIsInstance(hooks._post_tool_guarded(payload), dict)


@unittest.skipIf(os.name == "nt", "the fake is a shell script")
class HookFailsClosedTests(unittest.TestCase):
    """The whole hook, as the client starts it: a keychain that does not answer ends in the hook's own answer, which
    names the keychain, before the watchdog."""

    SCRIPT = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets import hooks, vault\n"
              "vault.make_backend = lambda cfg: vault.KeychainBackend()\n"
              "sys.exit(hooks.main(['hook', sys.argv[2]]))\n")

    def test_a_prompt_with_a_value_and_a_keychain_that_waits(self):
        home = Path(tempfile.mkdtemp(prefix="maisecrets-slow-keychain-"))
        self.addCleanup(shutil.rmtree, home, True)
        (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
        env.update(make_fake(home / "fake"))
        env.update({"MAISECRETS_HOME": str(home), "MAISECRETS_TEST_HOME_OWNED": str(home),
                    "MAISECRETS_TEST_WATCHDOG": "4", "PYTHONDONTWRITEBYTECODE": "1",
                    "FAKE_SECURITY_SLEEP": "find-generic-password:30"})
        payload = {"session_id": "s1", "hook_event_name": "UserPromptSubmit",
                   "prompt": "deploy with glpat-" + "abcdefghijKLMNOPQRST"}
        started = time.monotonic()
        r = subprocess.run([sys.executable, "-c", self.SCRIPT, str(ROOT), "user-prompt"], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=20)
        took = time.monotonic() - started
        answer = json.loads(r.stdout)
        self.assertEqual(answer.get("decision"), "block", r.stdout)
        self.assertIn("keychain did not answer", answer["reason"])
        self.assertNotIn("took longer", answer["reason"])
        self.assertLess(took, 4 + 2)


if __name__ == "__main__":
    unittest.main()
