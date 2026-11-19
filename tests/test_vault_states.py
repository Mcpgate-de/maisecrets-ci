"""The state of a vault-reference server in the person's words: the notice, /maisecrets:status, the session-start hint
and the deny reason of a Write, Edit or Bash call (maisecrets/vault_refs.py, "the state").

The fake server of harness/vault_server.py plays each state: no binding yet (the header is written, the client has not
sent it), pending, active, the operator switch off, and quarantined. The probe of the status is a resolve with no refs;
no request goes out before a server token, and no value is in any message.

Run: python3 -m unittest tests.test_vault_states -v
"""
from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import unittest
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
import test_vault_refs as base  # noqa: E402
from test_vault_refs import CLAUDE, HOME, VALUES, tok  # noqa: E402

from maisecrets import hooks, vault_refs  # noqa: E402
from maisecrets.vault import CodedError, Vault, load_config  # noqa: E402

RECONNECT = "header written — type /mcp reconnect demo (or start Claude Code again)"
WAITING = (r"waiting for activation until \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ — activate it on the server's connections "
           r"page, or sign in to demo again in the browser")
LOST = ("this key is quarantined (used by two accounts) or revoked — maisecrets makes a new key at the next start of "
        "Claude Code")
SWITCH = "the server's operator switch is off"


@unittest.skipUnless(base.HAS_OPENSSL, "the fake server needs openssl")
class States(base.OnlineBase):
    def mcp_request(self) -> None:
        """What the client sends after `/mcp reconnect demo`: an MCP request with the header; the kid becomes
        pending on the server (SPEC 6.2)."""
        header = self.headers_of()["demo"]
        req = urllib.request.Request(self.srv.url + "/mcp", headers={"Client-Vault": header,
                                                                       "Content-Type": "application/json"},
                                     data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode())
        urllib.request.urlopen(req, context=ssl.create_default_context(cafile=self.srv.cert)).read()

    def status(self) -> str:
        return vault_refs.status_lines(load_config(), Vault().backend)[-1]

    def session_start(self) -> str | None:
        cfg = load_config()
        return vault_refs.session_check(cfg, Vault(cfg).backend)

    def kid(self) -> str:
        return base.kid_from_header(self.headers_of()["demo"])

    def no_value_anywhere(self, *texts: str) -> None:
        """No server value, and no form of K: the store holds K as hex, the resolve sends it as base64url."""
        secrets_ = list(VALUES)
        k = vault_refs._key(Vault().backend, vault_refs.origin_of(self.srv.url), create=False)
        if k is not None:
            secrets_ += [k.hex(), vault_refs.bearer_of(k)]
        logs = [(HOME / n).read_text(errors="ignore") for n in ("audit.log", "hooks.log", "events.log")
                if (HOME / n).exists()]
        for text in list(texts) + logs:
            for secret in secrets_:
                self.assertNotIn(secret, text or "")

    def test_each_state_in_the_deny_the_status_and_the_session_start(self):
        self.assertIn("demo (", self.status())
        self.assertTrue(self.status().endswith(": not used yet (no server token seen, or the server names no vault "
                                               "endpoint)"), self.status())
        notice = self.call("demo", f"customers: {tok('EMAIL_1', 'va•••')} {tok('NAME_2')}").get("systemMessage")
        self.assertIn("Type /mcp reconnect demo (or start Claude Code again).", notice)
        self.assertNotIn("next start", notice)
        # header written, not yet sent: the deny and the status say what to type; the start says nothing new
        self.assertIn(f"the state of the MCP server demo (127.0.0.1) is: {RECONNECT}.", self.denied(self.write(
            tok("EMAIL_1"))))
        self.assertIn(f": {RECONNECT} (checked ", self.status())
        self.assertIsNone(self.session_start(), "the notice told it already")
        # the client sent it: pending
        self.mcp_request()
        reason = self.denied(self.write(tok("EMAIL_1")))
        self.assertRegex(reason, "the state of the MCP server demo \\(127.0.0.1\\) is: " + WAITING)
        self.assertRegex(self.status(), ": " + WAITING)
        self.assertIsNone(self.session_start(), "the status showed it: no hint for it")
        # the person activates it on the server
        self.srv.activate()
        hint = self.session_start()
        self.assertEqual(hint, "maisecrets: vault references of demo: active.")
        self.assertIsNone(self.session_start(), "once")
        self.assertEqual(self.write(tok("EMAIL_1"))["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0])
        # the operator turns the feature off
        self.srv.mode = "disabled"
        self.assertIn(f"is: {SWITCH}.", self.denied(self.write(tok("NAME_2"))))
        self.assertIn(f": {SWITCH} (checked ", self.status())
        self.srv.mode = None
        self.assertEqual(self.session_start(), "maisecrets: vault references of demo: active.")
        # a second account brought the same kid: quarantined, the server answers as for an unknown key
        self.srv.quarantine()
        self.assertEqual(self.session_start(), f"maisecrets: vault references of demo: {LOST}.")
        self.assertIn(f"is: {LOST}.", self.denied(self.write(tok("EMAIL_1"))))
        self.assertIn(f": {LOST} (checked ", self.status())
        self.no_value_anywhere(notice, reason, hint, self.status(), (HOME / "vault-refs" / "states.json").read_text(),
                               self.start() or "")

    @unittest.skipUnless(base.BASH and os.name != "nt", "bash on POSIX")
    def test_bash_and_edit_name_the_state_and_nothing_runs(self):
        self.enable()
        self.result("demo", tok("NAME_2"))
        marker = self.work / "ran"
        out = hooks.pre_tool({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                              "tool_input": {"command": f"touch {marker}; echo {tok('NAME_2')}"}})
        self.assertIn(f"is: {RECONNECT}. Do not ask the user for the value; tell them this reason. The command did "
                      "not run.", self.denied(out))
        self.assertFalse(marker.exists())
        self.mcp_request()
        out = hooks.pre_tool({"tool_name": "Edit", "session_id": "s1", **CLAUDE, "cwd": str(self.work),
                              "tool_input": {"file_path": str(self.work / "f.txt"), "old_string": "a",
                                             "new_string": tok("NAME_2")}})
        self.assertRegex(self.denied(out), WAITING + r"\. .*Nothing was written\.")

    def test_unknown_key_before_any_binding_is_no_quarantine(self):
        """401 before the key was ever bound means the client has not sent the header yet: no new key."""
        self.enable()
        self.result("demo", tok("EMAIL_1"))
        kid = self.kid()
        self.assertIn(RECONNECT, self.denied(self.write(tok("EMAIL_1"))))
        self.assertIsNone(self.start(), "no new key, no notice")
        self.assertEqual(self.kid(), kid)

    def test_a_quarantined_key_is_replaced_at_the_next_start(self):
        self.ready()
        self.assertEqual(self.write(tok("EMAIL_1"))["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0],
                         "an answer of the server shows the key was bound")
        old_kid = self.kid()
        self.srv.quarantine()
        self.assertIn(LOST, self.denied(self.write(tok("EMAIL_1"))))
        self.assertEqual(self.kid(), old_kid, "the hook of a call changes no config")
        note = self.start()
        self.assertIn("127.0.0.1 no longer accepted the key of this computer (quarantined or revoked), so maisecrets "
                      "made a new key", note)
        self.assertIn("Type /mcp reconnect demo (or start Claude Code again)", note)
        self.assertNotEqual(self.kid(), old_kid)
        self.assertEqual(vault_refs._known_keys()[vault_refs.origin_of(self.srv.url)]["entries"],
                         [["demo", self.srv.url + "/mcp"]], "the entry stays enabled")
        self.assertIn(RECONNECT, self.denied(self.write(tok("EMAIL_1"))), "the new key is not bound yet")
        self.assertIsNone(self.session_start(), "the notice told it")
        self.assertIsNone(self.start(), "one new key, once")
        self.login()                                   # the next login binds the new kid
        self.assertEqual(self.write(tok("EMAIL_1"))["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0])

    def test_the_probe_sends_no_ref_and_no_value(self):
        self.ready()
        sent = []
        real = vault_refs._request

        def spy(cfg, method, url, headers, body, deadline):
            sent.append((method, url, dict(headers), body))
            return real(cfg, method, url, headers, body, deadline)
        with mock.patch.object(vault_refs, "_request", spy):
            self.status()
            self.session_start()
        posts = [s for s in sent if s[0] == "POST"]
        self.assertEqual(len(posts), 2, "one probe for the status, one for the session start")
        for _m, url, headers, body in posts:
            self.assertEqual(json.loads(body)["refs"], [])
            self.assertEqual(url, self.srv.url + "/vault/resolve")
            self.no_value_anywhere(body.decode())        # the bearer is in Authorization, as the protocol says
            self.assertEqual(sorted(headers), ["Accept", "Authorization", "Content-Type"])
        self.assertEqual(self.srv.resolved[-1], {}, "the server released nothing")

    def test_no_request_and_no_hint_before_a_server_token(self):
        self.assertIsNone(self.start())
        self.assertIsNone(self.session_start())
        self.status()
        self.assertEqual(self.srv.log, [])
        self.assertFalse((HOME / "vault-refs" / "states.json").exists())

    def test_a_probe_without_a_key_asks_nothing(self):
        rec, why = vault_refs.check_state(load_config(), Vault().backend, vault_refs.origin_of(self.srv.url),
                                          self.srv.url + "/mcp")
        self.assertEqual((rec, why), ({}, "this computer has no key for it"))
        self.assertEqual(self.srv.log, [])

    def test_an_entry_without_the_header_is_not_used_yet_beside_one_with_it(self):
        self.client_config({"demo": {"type": "http", "url": self.srv.url + "/mcp"},
                            "copy": {"type": "http", "url": self.srv.url + "/mcp"}})
        self.enable("demo")
        self.login()
        lines = vault_refs.status_lines(load_config(), Vault().backend)
        self.assertIn(": not used yet (no server token seen, or the server names no vault endpoint)",
                      [ln for ln in lines if ln.startswith("vault references: copy (")][0])
        self.assertIn(": active (checked ", [ln for ln in lines if ln.startswith("vault references: demo (")][0])

    def test_one_probe_per_origin(self):
        self.client_config({"demo": {"type": "http", "url": self.srv.url + "/mcp"},
                            "copy": {"type": "http", "url": self.srv.url + "/mcp"}})
        self.enable("demo", "copy")
        self.login()
        lines = vault_refs.status_lines(load_config(), Vault().backend)
        self.assertEqual(sum(": active (checked " in ln for ln in lines), 2, "both entries have the header")
        self.session_start()
        resolves = [e for e in self.srv.log if e["path"] == "/vault/resolve"]
        self.assertEqual(len(resolves), 2, "one for the status and one for the start, for two entries")

    def test_the_session_start_ends_inside_its_budget(self):
        self.ready()
        self.srv.sleep = 3.0
        with mock.patch.object(vault_refs, "BUDGET", 1.0):
            t0 = time.monotonic()
            self.assertIsNone(self.session_start(), "no answer: no line, and the old state stays")
            self.assertLess(time.monotonic() - t0, 2.5)
        self.srv.sleep = 0
        self.assertIn("not checked now: it could not be reached", vault_refs._state_line(
            "demo", "o", *vault_refs.check_state(load_config(), Vault().backend, vault_refs.origin_of(self.srv.url),
                                                 self.srv.url + "/mcp", time.monotonic() + 0.05)))

    def test_a_failed_state_write_still_denies_with_the_state(self):
        self.enable()
        self.result("demo", tok("EMAIL_1"))
        self.mcp_request()                     # a new state: the deny must write it
        real = vault_refs.atomic_write
        tried = []

        def full(path, text):
            if path == vault_refs.STATES:
                tried.append(path)
                raise OSError("disk full")
            return real(path, text)
        with mock.patch.object(vault_refs, "atomic_write", full):
            self.assertRegex(self.denied(self.write(tok("EMAIL_1"))), WAITING)
        self.assertTrue(tried, "the state write was tried and failed")

    def test_a_busy_state_lock_still_denies_with_the_state(self):
        self.enable()
        self.result("demo", tok("EMAIL_1"))
        self.mcp_request()
        real = vault_refs._own_lock
        tried = []

        def busy(deadline=None):
            import traceback
            if any(f.name == "_set_state" for f in traceback.extract_stack()):
                tried.append(1)
                raise vault_refs.LockTimeout("busy")
            return real(deadline)
        with mock.patch.object(vault_refs, "_own_lock", busy):
            self.assertRegex(self.denied(self.write(tok("EMAIL_1"))), WAITING)
        self.assertTrue(tried, "the state lock was asked for and was busy")

    def test_crafted_local_files_make_no_key_and_no_request(self):
        """keys.json and states.json alone, with no key in the store, never make a key (Gate B review)."""
        origin = vault_refs.origin_of(self.srv.url)
        profile = vault_refs.profile()
        (HOME / "vault-refs").mkdir(parents=True, exist_ok=True)
        vault_refs.KEYS.write_text(json.dumps({profile: {origin: {"kid": "X", "created": "",
                                                                  "entries": [["demo", self.srv.url + "/mcp"]]}}}))
        vault_refs.STATES.write_text(json.dumps({profile: {origin: {"kid": "X", "state": "lost", "bound": True,
                                                                    "t": 0}}}))
        self.assertIsNone(self.start())
        self.assertIsNone(self.session_start())
        self.assertEqual(self.headers_of(), {"demo": None})
        self.assertEqual(self.srv.log, [])
        self.assertIsNone(vault_refs._key(Vault().backend, origin, create=False))

    def test_a_damaged_state_file_blocks_nothing(self):
        self.ready()
        vault_refs.STATES.write_text(json.dumps({vault_refs.profile(): ["damaged"]}))
        self.assertEqual(self.write(tok("EMAIL_1"))["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0])
        self.assertIn(": active (checked ", self.status())

    def test_a_parallel_answer_never_takes_bound_back(self):
        """A 401 whose hook read the record before a parallel 200 was written still sees the binding (Gate A)."""
        self.ready()
        origin = vault_refs.origin_of(self.srv.url)
        vault_refs._set_state(origin, "active")
        real = vault_refs._mine
        snapshot = []

        def before_the_200(path):
            if path == vault_refs.STATES and not snapshot:
                snapshot.append(path)
                return {}                       # the first read of _set_state, before the lock: no record yet
            return real(path)
        with mock.patch.object(vault_refs, "_mine", before_the_200):
            rec = vault_refs._set_state(origin, "unknown_key")
        self.assertTrue(snapshot, "the read before the lock saw no record")
        self.assertEqual(rec["state"], "lost", "the read under the lock found the binding")
        self.assertEqual(vault_refs.state_of(origin)["state"], "lost")

    def test_two_starts_at_once_make_one_new_key(self):
        """Two session starts (two processes) both see `lost`; the second one, under the lock, finds the key the
        first one made and keeps it (Gate A review). The other start runs between the first check and the lock."""
        self.ready()
        self.assertIn("updatedInput", self.write(tok("EMAIL_1"))["hookSpecificOutput"])
        self.srv.quarantine()
        self.denied(self.write(tok("EMAIL_1")))
        backend = Vault(load_config()).backend
        real = vault_refs.user_servers
        other = []

        def the_other_start_rotates_now(*a, **kw):
            if not other:
                other.append(None)
                with mock.patch.object(vault_refs, "user_servers", real):
                    other[0] = vault_refs.rotate_lost(backend)
            return real(*a, **kw)
        with mock.patch.object(vault_refs, "user_servers", the_other_start_rotates_now):
            mine = vault_refs.rotate_lost(backend)
        self.assertEqual(len(other[0]), 1, "the other start made a new key")
        self.assertEqual(mine, [], "this start keeps it")

    def test_a_new_key_needs_a_live_entry(self):
        self.ready()
        self.assertIn("updatedInput", self.write(tok("EMAIL_1"))["hookSpecificOutput"])
        self.srv.quarantine()
        self.denied(self.write(tok("EMAIL_1")))
        origin = vault_refs.origin_of(self.srv.url)
        before = vault_refs._key(Vault().backend, origin, create=False)
        self.client_config({"other": {"type": "http", "url": "https://other.example/mcp"}})
        self.assertEqual(vault_refs.rotate_lost(Vault().backend), [], "the entry is gone: no new key")
        self.assertEqual(vault_refs._key(Vault().backend, origin, create=False), before)

    def test_a_failed_new_key_keeps_the_header_repair_of_the_start(self):
        self.ready()
        config = json.loads((self.profile / ".claude.json").read_text())
        del config["mcpServers"]["demo"]["headers"]               # the client lost the header
        (self.profile / ".claude.json").write_text(json.dumps(config))
        with mock.patch.object(vault_refs, "rotate_lost", side_effect=OSError("store busy")):
            self.assertIn("demo supports Client-Vault", self.start() or "")
        self.assertIsNotNone(self.headers_of()["demo"])

    def test_a_store_error_that_is_no_os_error_keeps_the_header_repair_too(self):
        """A store backend has its own errors (a keychain, a Credential Locker): not only OSError."""
        self.ready()
        config = json.loads((self.profile / ".claude.json").read_text())
        del config["mcpServers"]["demo"]["headers"]
        (self.profile / ".claude.json").write_text(json.dumps(config))
        with mock.patch.object(vault_refs, "rotate_lost", side_effect=RuntimeError("the keychain refused")):
            self.assertIn("demo supports Client-Vault", self.start() or "")
        self.assertIsNotNone(self.headers_of()["demo"])

    def test_a_store_key_that_keys_json_does_not_name_is_not_replaced(self):
        """A crash between the store write and the keys.json write leaves a key in the store whose kid keys.json does
        not name. The `lost` record is for the kid of keys.json, not for that key: no new key goes on top of it."""
        self.lose_the_key()
        origin = vault_refs.origin_of(self.srv.url)
        backend = Vault().backend
        other = bytes(range(32))
        vault_refs._put_key(backend, origin, other)
        self.assertNotEqual(vault_refs.kid_of(other), vault_refs._kid_now(origin))
        self.assertEqual(vault_refs.state_of(origin)["state"], "lost")
        self.assertEqual(vault_refs.rotate_lost(backend), [])
        self.assertEqual(vault_refs._key(backend, origin, create=False), other)

    def lose_the_key(self) -> bytes:
        """A bound key that the server then quarantines; returns the old K."""
        self.ready()
        self.assertIn("updatedInput", self.write(tok("EMAIL_1"))["hookSpecificOutput"])
        self.srv.quarantine()
        self.assertIn(LOST, self.denied(self.write(tok("EMAIL_1"))))
        return vault_refs._key(Vault().backend, vault_refs.origin_of(self.srv.url), create=False)

    def test_a_failed_keys_write_puts_the_old_key_back_and_the_next_start_tries_again(self):
        old = self.lose_the_key()
        origin = vault_refs.origin_of(self.srv.url)
        real = vault_refs.atomic_write

        def keys_fail(path, text):
            # the write of the new kid fails; the mark of the new kid as `rotating` before the key write goes through
            if path == vault_refs.KEYS and '"rotating"' not in text:
                raise OSError("disk full")
            return real(path, text)
        with mock.patch.object(vault_refs, "atomic_write", keys_fail):
            self.assertNotIn("made a new key", self.start() or "")
        self.assertEqual(vault_refs._key(Vault().backend, origin, create=False), old, "the store and keys.json agree")
        self.assertEqual(vault_refs.kid_of(old), vault_refs._kid_now(origin))
        self.assertIn("rotating", vault_refs._known_keys()[origin], "premise: the new key was written")
        self.assertIn("made a new key", self.start() or "", "the next start tries again")
        self.assertNotEqual(vault_refs._key(Vault().backend, origin, create=False), old)

    def put_key_without_proof(self, takes: bool):
        """_put_key as a keychain whose read-back fails after the add: the new key is stored (takes) or not; the put
        of the old key back fails the same way and writes nothing."""
        real = vault_refs._put_key
        calls = []

        def put(backend, origin, k):
            calls.append(k)
            if takes and len(calls) == 1:
                real(backend, origin, k)
            raise CodedError("keychain call timed out", "store.timeout-keychain", "timeout")
        return mock.patch.object(vault_refs, "_put_key", put)

    def test_a_new_key_stored_without_proof_is_settled_by_the_store_at_the_next_start(self):
        """Gate A round 3 of #75: the add took, its read-back did not answer. keys.json kept the old kid, the store held
        the new key, and no later start replaced or named it: every reference of the server stayed unreadable."""
        old = self.lose_the_key()
        origin = vault_refs.origin_of(self.srv.url)
        backend = Vault().backend
        with self.put_key_without_proof(takes=True):
            with self.assertRaises(CodedError):
                vault_refs.rotate_lost(backend)
        new = vault_refs._key(backend, origin, create=False)
        self.assertNotEqual(new, old, "premise: the add took")
        self.assertEqual(vault_refs._kid_now(origin), vault_refs.kid_of(old), "premise: keys.json names the old kid")
        self.start()                                     # the next start settles it by the store
        self.assertEqual(vault_refs._kid_now(origin), vault_refs.kid_of(new))
        self.assertNotIn("rotating", vault_refs._known_keys()[origin])
        self.assertEqual(vault_refs._key(backend, origin, create=False), new, "no second new key")
        self.login()
        self.assertEqual(self.write(tok("EMAIL_1"))["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0])

    def test_a_late_answer_for_the_old_key_does_not_keep_an_unsettled_new_key(self):
        """Gate A round 4 of #75: the new key was stored without proof, and a late answer for the old key set the
        state to active. rotate_lost then skipped the origin before it settled, and `rotating` stayed for good."""
        old = self.lose_the_key()
        origin = vault_refs.origin_of(self.srv.url)
        backend = Vault().backend
        with self.put_key_without_proof(takes=True):
            with self.assertRaises(CodedError):
                vault_refs.rotate_lost(backend)
        new = vault_refs._key(backend, origin, create=False)
        vault_refs._set_state(origin, "active", kid=vault_refs.kid_of(old))    # the late answer
        self.assertEqual(vault_refs.state_of(origin).get("state"), "active", "premise: the old kid looks active")
        self.assertEqual(vault_refs.rotate_lost(backend), [], "no second new key")
        self.assertNotIn("rotating", vault_refs._known_keys()[origin])
        self.assertEqual(vault_refs._kid_now(origin), vault_refs.kid_of(new))
        self.assertEqual(vault_refs._key(backend, origin, create=False), new)

    def test_a_new_key_that_was_not_stored_is_made_again_at_the_next_start(self):
        old = self.lose_the_key()
        origin = vault_refs.origin_of(self.srv.url)
        backend = Vault().backend
        with self.put_key_without_proof(takes=False):
            with self.assertRaises(CodedError):
                vault_refs.rotate_lost(backend)
        self.assertEqual(vault_refs._key(backend, origin, create=False), old)
        self.assertIn("rotating", vault_refs._known_keys()[origin], "keys.json names both kids")
        vault_refs._settle_rotation(backend, origin)     # the store holds the old key: only `rotating` goes
        self.assertNotIn("rotating", vault_refs._known_keys()[origin])
        self.assertEqual(vault_refs._kid_now(origin), vault_refs.kid_of(old))
        self.assertIn("made a new key", self.start() or "")
        self.assertNotIn("rotating", vault_refs._known_keys()[origin])
        self.assertEqual(vault_refs._kid_now(origin), vault_refs.kid_of(vault_refs._key(backend, origin, create=False)))

    def test_a_late_answer_for_the_old_key_does_not_change_the_new_one(self):
        old = self.lose_the_key()
        self.start()                                     # a new key
        self.login()                                     # bound at once
        origin = vault_refs.origin_of(self.srv.url)
        self.assertEqual(self.write(tok("EMAIL_1"))["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0])
        self.assertEqual(vault_refs.state_of(origin)["state"], "active")
        rec = vault_refs._set_state(origin, "unknown_key", kid=vault_refs.kid_of(old))     # the old request returns
        self.assertEqual(rec["state"], "active", "the deny of the old request names the state of the new key")
        self.assertEqual(vault_refs.state_of(origin)["state"], "active", "the record of the new key stays")
        self.assertEqual(vault_refs.rotate_lost(Vault().backend), [], "no second new key")

    def test_a_late_answer_takes_no_lock(self):
        """The first check: an answer for a key that is no longer the key of the origin writes nothing at all."""
        old = self.lose_the_key()
        self.start()
        origin = vault_refs.origin_of(self.srv.url)
        with mock.patch.object(vault_refs, "_own_lock", side_effect=AssertionError("no write for an old key")):
            vault_refs._set_state(origin, "unknown_key", kid=vault_refs.kid_of(old))

    def test_a_new_key_between_the_check_and_the_lock_is_kept(self):
        """The check under the lock: the new key came after the first check (another session start)."""
        old = self.lose_the_key()
        self.start()
        self.login()
        origin = vault_refs.origin_of(self.srv.url)
        self.assertIn("updatedInput", self.write(tok("EMAIL_1"))["hookSpecificOutput"])
        real = vault_refs._kid_now
        calls = []

        def before_the_new_key(o):
            calls.append(o)
            return vault_refs.kid_of(old) if len(calls) == 1 else real(o)
        with mock.patch.object(vault_refs, "_kid_now", before_the_new_key):
            vault_refs._set_state(origin, "unknown_key", kid=vault_refs.kid_of(old))
        self.assertGreater(len(calls), 1, "the check under the lock ran")
        self.assertEqual(vault_refs.state_of(origin)["state"], "active")

    # A real request with the old key is on its way while a new key comes (Gate review of 0.6.36): the server answers
    # the old key, then other sessions and a session start act, and only then the answer arrives. Each call site of
    # _set_state must give the kid of the key it sent; the kid of now is the new key.
    def answer_late(self, ask, meanwhile):
        real = vault_refs._request
        late = []

        def on_the_way(cfg, method, url, headers, body, deadline):
            answer = real(cfg, method, url, headers, body, deadline)
            if url.endswith("/vault/resolve") and not late:
                late.append(url)
                with mock.patch.object(vault_refs, "_request", real):
                    meanwhile()
            return answer
        with mock.patch.object(vault_refs, "_request", on_the_way):
            out = ask()
        self.assertTrue(late, "the request went out")
        return out

    def probe(self) -> dict:
        return vault_refs.check_state(load_config(), Vault().backend, vault_refs.origin_of(self.srv.url),
                                      self.srv.url + "/mcp")[0]

    def a_new_key_not_bound_yet(self) -> None:
        """Meanwhile: a second account brings the kid, a probe sees `lost`, and a session start makes a new key."""
        self.srv.quarantine()
        self.assertEqual(self.probe()["state"], "lost")
        self.assertIn("made a new key", self.start() or "")

    def a_new_key_bound_and_active(self) -> None:
        """Meanwhile: a session start makes a new key, the login binds it, and a probe sees it active."""
        self.assertIn("made a new key", self.start() or "")
        self.login()
        self.assertEqual(self.probe()["state"], "active")

    def an_active_old_key(self) -> str:
        self.ready()
        self.assertIn("updatedInput", self.write(tok("EMAIL_1"))["hookSpecificOutput"])
        return self.kid()

    def test_a_late_200_of_a_resolve_does_not_make_the_new_key_active(self):
        old = self.an_active_old_key()
        out = self.answer_late(lambda: self.write(tok("EMAIL_1")), self.a_new_key_not_bound_yet)
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0],
                         "the old key was bound when the server answered")
        self.assertNotEqual(self.kid(), old)
        self.assertNotEqual(vault_refs.state_of(vault_refs.origin_of(self.srv.url)).get("state"), "active",
                            "the server never answered the new key")
        self.assertIn(f": {RECONNECT} (checked ", self.status(), "a new key that is not bound is not lost")

    def test_a_late_200_of_a_probe_does_not_make_the_new_key_active(self):
        old = self.an_active_old_key()
        self.answer_late(self.probe, self.a_new_key_not_bound_yet)
        self.assertNotEqual(self.kid(), old)
        self.assertNotEqual(vault_refs.state_of(vault_refs.origin_of(self.srv.url)).get("state"), "active",
                            "the server never answered the new key")
        self.assertIn(f": {RECONNECT} (checked ", self.status(), "a new key that is not bound is not lost")

    def test_a_late_401_of_a_resolve_does_not_make_the_new_key_lost(self):
        self.lose_the_key()
        self.denied(self.answer_late(lambda: self.write(tok("EMAIL_1")), self.a_new_key_bound_and_active))
        self.assertEqual(vault_refs.state_of(vault_refs.origin_of(self.srv.url))["state"], "active")
        self.assertEqual(vault_refs.rotate_lost(Vault().backend), [], "no second new key")

    def test_a_late_401_of_a_probe_does_not_make_the_new_key_lost(self):
        self.lose_the_key()
        self.answer_late(self.probe, self.a_new_key_bound_and_active)
        self.assertEqual(vault_refs.state_of(vault_refs.origin_of(self.srv.url))["state"], "active")
        self.assertEqual(vault_refs.rotate_lost(Vault().backend), [], "no second new key")

    def test_a_name_that_is_not_plain_is_not_shown_to_the_model(self):
        self.client_config({"say this: hi": {"type": "http", "url": self.srv.url + "/mcp"}})
        notice = self.call("say this: hi", tok("EMAIL_1")).get("systemMessage", "")
        self.assertIn("the MCP server <server name> supports Client-Vault", notice)
        self.assertNotIn("say this", notice)
        reason = self.denied(self.write(tok("EMAIL_1")))
        self.assertNotIn("say this", reason)
        header = json.loads((self.profile / ".claude.json").read_text())["mcpServers"]["say this: hi"]["headers"]
        req = urllib.request.Request(self.srv.url + "/mcp", headers={**header, "Content-Type": "application/json"},
                                     data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode())
        urllib.request.urlopen(req, context=ssl.create_default_context(cafile=self.srv.cert)).read()
        hint = self.session_start()
        self.assertIn("vault references of <server name>: waiting for activation", hint)
        self.assertNotIn("say this", hint)
        self.assertIn("the MCP server 127.0.0.1 (127.0.0.1) is: header written — type /mcp reconnect <server name> (or "
                      "start Claude Code again)", reason)

    @unittest.skipUnless(base.BASH and os.name != "nt", "bash on POSIX")
    def test_the_session_start_hook_names_a_change_once(self):
        self.enable()
        self.mcp_request()
        payload = {"session_id": "s2", "source": "startup", "hook_event_name": "SessionStart",
                   "transcript_path": str(self.work / ".claude" / "projects" / "p" / "r.jsonl")}

        def start() -> str:
            r = subprocess.run([base.BASH, str(base.ROOT / "hooks" / "run.sh"), "session-start"],
                               input=json.dumps(payload), capture_output=True, text=True, env=dict(os.environ),
                               timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            return json.loads(r.stdout).get("systemMessage", "")
        self.assertRegex(start(), "maisecrets: vault references of demo: " + WAITING + r"\.")
        self.assertNotIn("vault references of demo", start())

    def test_a_cli_status_names_the_state(self):
        self.ready()
        env = {**os.environ, "PYTHONPATH": str(base.ROOT)}
        r = subprocess.run([shutil.which("python3") or "python3", "-m", "maisecrets.cli", "status", "all"],
                           env=env,
                           capture_output=True, text=True, timeout=60, cwd=str(base.ROOT))
        # `status all` groups the servers by state: the active ones by name
        self.assertRegex(r.stdout, r"vault references: active: demo\b", r.stderr)


if __name__ == "__main__":
    unittest.main()
