"""The deposit of a stored value for a claude.ai connector (#100, docs/design/e2e-connector-values.md; PROTOCOL.md
section 6): the JCS digest, the refusals and the padding of appendix A, the deposit fields of the metadata, the
target predicate, and the PreToolUse hook end to end against the fake gateway (harness/sref_server.py): the call
carries a one-time handle, the gateway puts the value in, and every condition that fails gives the refusal of #99.
Temp homes and synthetic values only.

Run: python3 -m unittest tests.test_deposit -v
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import deposit as D, hooks, sref_client as S, sref_hooks, vault_refs  # noqa: E402
from maisecrets.vault import HOME, JsonFileBackend, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402
import test_sref_client as T  # noqa: E402

OPEN, CLOSE = "⟦", "⟧"
S1 = OPEN + "SECRET_c1" + CLOSE
E2 = OPEN + "EMAIL_c2:ab•••@•••.com" + CLOSE
VALUE = "deposit-value-7Qx2-synthetic"
TOOL = "mcp__claude_ai_Team_GW__gitlab_write_actions"
SERVER = {"name": "claude.ai Team GW", "source": "claudeai"}
NONCE = "n" * 21 + "_" + "A1-b" * 5 + "z"

# appendix A.1: the template as JSON text, and its digest
VECTORS = [
    ('{}', 'RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o'),
    ('{"b":"2","a":"1"}', 'Ifdt-_5t_iH3YggO9IQRLPKVKXTO8wdB_Rkx4cbZIRI'),
    ('{"n":[1.0,1e21,-0,0.000001,1e-7,123456789012,4.50,333333333.33333329,-1.5e-10]}',
     '15WDcD5twf9J7rd8_vV9e4VRxapPGncIJMopGULyrTA'),
    ('{"ﬁ":"ligature","\U0001f600":"emoji","\xe9":"e-acute","a\\u0000b":""}',
     'JODjioboUpxxH3brnu-Ubn3HmI714TwZfpI0PfTAU6I'),
    ('{"a":[[],[""],{"":""}],"z":null,"t":true,"f":false}', 'HTHHfkQuY_afO7LuXs4BMtDXhPSRCrGfP5HAzm9zA0U'),
    ('{"s":"line\\nTab\\t\\"q\\" \\\\ \\u001f \\u007f   /"}', 'LxDao4TSZZgtNOT0nR2faOuz3MIOInG-LSF6ccPJ7b0'),
    (json.dumps({"action": "create_variable", "params": {"key": "API_TOKEN", "value": S1, "masked": True}}),
     '1E9XEPBywTSpjnk7CS1RPOfvAHgMOLraCRXjy5YLmyA'),
    (json.dumps({"action": "send", "params": {"text": "user " + E2 + " key " + S1}}),
     'Y5GbrenBFsJRgbaX_VXhHaPgwxltKe35pTt_j2Yv448'),
    (json.dumps({"action": "send", "params": {"text": "user " + S1 + " key " + E2}}),
     'Tz2j7aOOJC3zihl7n16buVOzUEF9VBmEZkH8C90BhR0'),
]
A3_PADDED = "w4CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


class VectorTests(unittest.TestCase):
    def test_every_digest_vector_of_appendix_a1(self):
        for i, (text, digest) in enumerate(VECTORS, 1):
            with self.subTest(vector=i):
                self.assertEqual(D.args_digest(D.loads_strict(text)), digest)

    def test_the_jcs_text_of_the_number_and_order_vectors(self):
        self.assertEqual(D.jcs(D.loads_strict(VECTORS[2][0])),
                         '{"n":[1,1e+21,0,0.000001,1e-7,123456789012,4.5,333333333.3333333,-1.5e-10]}')
        self.assertEqual(D.jcs(D.loads_strict(VECTORS[4][0])), '{"a":[[],[""],{"":""}],"f":false,"t":true,"z":null}')
        keys = list(json.loads(D.jcs(D.loads_strict(VECTORS[3][0]))))
        self.assertEqual(keys, ["a\x00b", "\xe9", "\U0001f600", "ﬁ"], "UTF-16 order: the emoji before U+FB01")

    def test_a_swap_of_two_placeholders_changes_the_digest(self):
        self.assertNotEqual(VECTORS[7][1], D.args_digest(D.loads_strict(VECTORS[8][0])))

    def test_both_sides_refuse_the_vectors_of_appendix_a2(self):
        for text, why in (('{"a":1,"a":2}', "duplicate"), ('{"n":9007199254740993}', "2^53"),
                          ('{"s":"\\ud800"}', "surrogate"), ('{"n":NaN}', "finite")):
            with self.subTest(text=text), self.assertRaises(D.NotCanonical) as got:
                D.loads_strict(text)
            self.assertIn(why, str(got.exception))
        self.assertEqual(D.jcs({"n": 2 ** 53}), '{"n":9007199254740992}', "2^53 itself is written")

    def test_the_padding_of_appendix_a3(self):
        self.assertEqual(D.pad("\xc0"), A3_PADDED)
        self.assertEqual(D.unpad(A3_PADDED), b"\xc3\x80", "the zeros and exactly one 0x80 go")
        for n, size in ((8, 64), (63, 64), (64, 96), (95, 96), (96, 128), (4096, 4128)):
            with self.subTest(n=n):
                padded = D.pad("x" * n)
                raw = __import__("base64").urlsafe_b64decode(padded + "=" * (-len(padded) % 4))
                self.assertEqual(len(raw), size)
                self.assertEqual(D.unpad(padded), b"x" * n)
        with self.assertRaises(ValueError):
            D.unpad(D._b64(b"value-without-mark" + b"\x00" * 10))


class FieldTests(unittest.TestCase):
    ORIGIN = "https://gateway.example.com"

    def block(self, **change) -> dict:
        base = {"deposit_endpoint": self.ORIGIN + "/sensitive-references/deposit", "deposit_profile": "deposit-1",
                "deposit_scope": "sensitive-references.deposit", "deposit_max_lifetime": 600,
                "deposit_targets": [{"tool": "gitlab_write_actions", "when": {"/action": "create_webhook"},
                                     "paths": ["/token", "/items/*/secret"]}]}
        return {k: v for k, v in {**base, **change}.items() if v is not None}

    def test_usable_fields_are_kept(self):
        got = D.fields(self.block(), self.ORIGIN)
        self.assertEqual(got["deposit_scope"], "sensitive-references.deposit")
        self.assertEqual(D.fields(got, self.ORIGIN), got, "a kept copy passes the same check")
        self.assertEqual(D.fields(self.block(deposit_max_lifetime=None), self.ORIGIN)["deposit_max_lifetime"], 300)

    def test_a_wrong_field_makes_the_whole_deposit_unusable(self):
        for change in ({"deposit_endpoint": "https://other.example.com/d"}, {"deposit_endpoint": "http://gateway."
                       "example.com/d"}, {"deposit_profile": "deposit-2"}, {"deposit_scope": 7},
                       {"deposit_max_lifetime": 601}, {"deposit_max_lifetime": True}, {"deposit_targets": {}},
                       {"deposit_targets": [{"tool": "x y", "paths": ["/a"]}]},
                       {"deposit_targets": [{"tool": "t", "paths": []}]},
                       {"deposit_targets": [{"tool": "t", "paths": ["a"]}]},
                       {"deposit_targets": [{"tool": "t", "when": {"/a": 1}, "paths": ["/a"]}]},
                       {"deposit_targets": [{"tool": "t", "paths": ["/a"]}] * 1001}):
            with self.subTest(change=str(change)[:80]):
                self.assertIsNone(D.fields(self.block(**change), self.ORIGIN))

    def test_a_target_matches_on_its_tool_and_each_when_string(self):
        targets = D.fields(self.block(), self.ORIGIN)["deposit_targets"]
        self.assertTrue(D.matching_targets(targets, "gitlab_write_actions", {"action": "create_webhook"}))
        for tool, args in (("gitlab_write_actions", {"action": "list_webhooks"}),
                           ("gitlab_write_actions", {"action": "create_webhook "}), ("other", {"action": "x"}),
                           ("gitlab_write_actions", {"action": ["create_webhook"]}), ("gitlab_write_actions", {})):
            with self.subTest(args=args):
                self.assertEqual(D.matching_targets(targets, tool, args), [])

    def test_a_star_matches_one_array_index_and_nothing_else(self):
        places = {p: segs for p, segs, *_x in D.occurrences(
            {"items": [{"secret": S1}], "obj": {"0": {"secret": S1}}})}
        self.assertTrue(D._path_matches("/items/*/secret", places["/items/0/secret"]))
        self.assertFalse(D._path_matches("/obj/*/secret", places["/obj/0/secret"]), "a key is no array index")

    def test_the_tripwire_reads_the_issuer(self):
        D.tripwire({"issuer": ((("commonName", "R11"),), (("organizationName", "Let's Encrypt"),))})
        for name in ("Example Egress Gateway CA", "Corp TLS Interception CA 2"):
            with self.subTest(name=name), self.assertRaises(D.Refused):
                D.tripwire({"issuer": ((("commonName", name),),)})


_TRIP_CERT: tuple | None = None


def _trip_cert() -> tuple:
    global _TRIP_CERT
    if _TRIP_CERT is None:
        _TRIP_CERT = T.make_cert(tempfile.mkdtemp(prefix="deposit-trip-cert-"), ca_name="Example Egress Gateway CA")
    return _TRIP_CERT


class _Base(unittest.TestCase):
    @classmethod
    def tearDownClass(cls) -> None:
        _hygiene.assert_children_ended()

    def setUp(self, cert: tuple | None = None) -> None:
        _hygiene.watch_children(self)
        HOME.mkdir(parents=True, exist_ok=True)
        for name in ("sref", "vault-refs", "index.json", "vault.json", "audit.log", "sref-pairing.json",
                     "destinations.json"):
            p = HOME / name
            if p.is_dir():
                shutil.rmtree(p)
            elif p.exists():
                p.unlink()
        self.srv = T.SrefServer(cert=cert or T._cert()).__enter__()
        self.addCleanup(self.srv.__exit__)
        self.srv.deposit = True
        self.write_config({})
        profile = Path(tempfile.mkdtemp(prefix="deposit-profile-"))
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(profile), "CLAUDE_CODE_ENTRYPOINT": "cli"})
        env.start()
        self.addCleanup(env.stop)
        (profile / ".claude.json").write_text(json.dumps({"mcpServers": {}}))
        hooks._live_cache.clear()
        self.cfg = {"client_vault_cafile": self.srv.cert}
        self.url = self.srv.url + "/mcp"
        self.backend = JsonFileBackend()
        self.addCleanup(self.backend.delete, D._MAC_ENTRY)
        self.ref = Vault().put(VALUE, "SECRET", "manual", session="s1").ref
        self.addCleanup(S.forget, self.backend, "https://127.0.0.1:" + self.srv.url.rsplit(":", 1)[1])

    def write_config(self, extra: dict) -> None:
        (HOME / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                      "client_vault_cafile": self.srv.cert, **extra}))

    def login(self) -> dict:
        found = S.discover(self.cfg, self.url)
        helper = T.SrefClientTests("test_discovery_names_the_resolver_and_its_sinks")
        helper.srv = self.srv
        S.login(self.cfg, self.backend, found, helper.browser, wait=10)
        return found

    def bind(self, login: bool = True, key: str = "Team_GW") -> None:
        """The connector proposes its gateway, the person logs in, and its pairing proof binds it (#91)."""
        _key, url, why = vault_refs.propose_connector("claude_ai_" + key, json.dumps({"resource": self.url}))
        self.assertIsNone(why)
        if login:
            self.login()
        self.assertTrue(vault_refs.mark_login(key, self.url))
        got = sref_hooks.pair_connector(key, NONCE, json.dumps({"resource": self.url,
                                                                "proof": self.srv.proof(NONCE)}))
        self.assertTrue(got["bound"], got)

    def args(self, **change) -> dict:
        return {"action": "create_webhook", "project": "group/app", "url": "https://hooks.example.com/in",
                "token": self.ref, **change}

    def pre(self, tool_input: dict | None = None, call: str = "t1", tool: str = TOOL, server: object = SERVER) -> dict:
        hooks._live_cache.clear()
        payload = {"tool_name": tool, "tool_input": tool_input or self.args(), "session_id": "s1",
                   "tool_use_id": call, "transcript_path": "", **CLAUDE}
        if server is not None:
            payload["mcp_server"] = server
        out = hooks.pre_tool(payload)
        self.assertNotIn(VALUE, json.dumps(out, ensure_ascii=False), "the value never reaches the hook's answer")
        return out.get("hookSpecificOutput", {})

    def audit(self) -> str:
        p = HOME / "audit.log"
        return p.read_text(encoding="utf-8") if p.exists() else ""

    def assert_refused(self, hso: dict, why: str) -> None:
        self.assertEqual(hso.get("permissionDecision"), "deny", hso)
        self.assertNotIn("updatedInput", hso)
        reason = hso["permissionDecisionReason"]
        self.assertIn("connector proxy", reason, "the refusal of #99")
        self.assertIn(why, reason)



@unittest.skipUnless(T.HAS_OPENSSL and os.name != "nt", "openssl on POSIX")
class DepositHookTests(_Base):
    # ------------------------------------------------------------------------------------------ end to end --
    def test_a_connector_call_gets_a_handle_and_the_gateway_puts_the_value_in(self):
        self.bind()
        hso = self.pre()
        handle = hso["updatedInput"]["token"]
        self.assertRegex(handle, D.HANDLE_RE.pattern)
        self.assertEqual({k: v for k, v in hso["updatedInput"].items() if k != "token"},
                         {k: v for k, v in self.args().items() if k != "token"}, "the other arguments stay")
        req = self.srv.deposit_requests[0]
        self.assertEqual((req["resource"], req["tool"], req["lifetime"]), (self.url, "gitlab_write_actions", 300))
        self.assertEqual([(v["path"], v["placeholder"], v["value"]) for v in req["values"]],
                         [("/token", self.ref, VALUE)])
        self.assertEqual(req["args_digest"], D.args_digest(self.args()), "the digest of the arguments as written")
        # the gateway at call time: the value goes upstream in place of the handle
        self.assertEqual(self.srv.call("gitlab_write_actions", hso["updatedInput"])["token"], VALUE)
        # the audit names the key, deposit, host, tool, path and lifetime; never the value or the handle
        line = self.audit()
        self.assertIn("deposit 127.0.0.1 gitlab_write_actions /token 300s", line)
        self.assertIn(self.ref[1:-1], line)
        self.assertNotIn(VALUE, line)
        self.assertNotIn(handle, line)
        self.assertNotIn(handle[:12], line)

    def test_a_changed_argument_or_a_second_use_fails_at_the_gateway(self):
        self.bind()
        hso = self.pre()
        moved = {**hso["updatedInput"], "url": "https://attacker.example.com/in"}
        self.assertEqual(self.srv.call("gitlab_write_actions", moved)["content"][0]["text"],
                         "deposit_refused: binding_mismatch")
        self.assertEqual(self.srv.call("gitlab_write_actions", hso["updatedInput"])["content"][0]["text"],
                         "deposit_refused: unknown_handle", "a handle works once")
        self.assertEqual(self.srv.upstream, [])

    def test_with_confirm_the_person_is_asked_with_the_keys_and_the_host(self):
        self.write_config({"rehydration": "confirm"})
        self.bind()
        hso = self.pre()
        self.assertEqual(hso["permissionDecision"], "ask")
        self.assertRegex(hso["updatedInput"]["token"], D.HANDLE_RE.pattern)
        self.assertIn(self.ref, hso["permissionDecisionReason"])
        self.assertIn("went to 127.0.0.1", hso["permissionDecisionReason"])

    def test_block_refuses_before_any_value_leaves(self):
        self.write_config({"rehydration": "block"})
        self.bind()
        self.assertEqual(self.pre()["permissionDecision"], "deny")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_a_failed_deposit_counts_and_gives_the_refusal(self):
        self.bind()
        self.srv.deposit_answer = (503, {"error": "unavailable"})
        self.assert_refused(self.pre(), "could not store the deposit now")
        self.assertIn("deposit 127.0.0.1", self.audit(), "the value left the computer: it counts (C7)")
        index = json.loads((HOME / "index.json").read_text())
        self.assertEqual([r["key"] for r in index["resolves"]], [self.ref[1:-1]])

    def test_handles_are_checked_for_their_form_count_and_distinctness(self):
        self.bind()
        good = "msdep1_" + "A" * 65
        two = self.args(token=self.ref + " " + self.ref)
        for handles, tool_input in (([good], two), ([good, good], two), (["msdep1_short"], None),
                                    (["msdep2_" + "A" * 65], None)):
            with self.subTest(handles=handles):
                self.srv.deposit_answer = (200, {"handles": handles, "expires_in": 300})
                self.assert_refused(self.pre(tool_input), "gave no usable handles")

    def test_two_placeholders_get_two_handles_in_jcs_order(self):
        self.bind()
        hso = self.pre(self.args(token="a " + self.ref + " b " + self.ref))
        got = hso["updatedInput"]["token"].split(" ")
        self.assertEqual((got[0], got[2]), ("a", "b"))
        self.assertNotEqual(got[1], got[3])
        self.assertEqual(self.srv.call("gitlab_write_actions", hso["updatedInput"])["token"],
                         f"a {VALUE} b {VALUE}")

    # ------------------------------------------------------------------------------------- the conditions --
    def test_a_binding_without_a_pairing_proof_gets_no_deposit(self):
        vault_refs.propose_connector("claude_ai_Team_GW", json.dumps({"resource": self.url}))
        self.login()
        self.assertTrue(vault_refs.bind_connector("Team_GW", self.url))      # the typed-login fallback, no seal
        self.assert_refused(self.pre(), "carries no seal of a pairing proof (it was made without a proof, or by an "
                                        "older maisecrets); pair it again: /maisecrets sref logout Team_GW, let the "
                                        "connector show a reference, then /maisecrets sref login Team_GW")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_a_changed_binding_file_stops_the_deposit(self):
        self.bind()
        path = HOME / "sref" / "connectors.json"
        data = json.loads(path.read_text())
        entry = data[vault_refs.profile()]["bound"]["Team_GW"]
        for change in ({"url": self.srv.url + "/other"}, {"mac": "0" * 64}, {"mac": None}):
            with self.subTest(change=change):
                data[vault_refs.profile()]["bound"]["Team_GW"] = {**entry, **change}
                path.write_text(json.dumps(data))
                self.assert_refused(self.pre(), "does not carry a valid seal")
        self.assertEqual(self.srv.deposit_requests, [])
        data[vault_refs.profile()]["bound"]["Team_GW"] = entry
        path.write_text(json.dumps(data))
        self.assertRegex(self.pre()["updatedInput"]["token"], D.HANDLE_RE.pattern)

    def test_without_a_login_there_is_no_deposit(self):
        self.bind()
        S.forget(self.backend, S.discover(self.cfg, self.url)["origin"])
        self.assert_refused(self.pre(), "maisecrets has no login at 127.0.0.1")

    def test_the_login_asks_for_the_deposit_scope_only_where_the_gateway_names_it(self):
        self.assertIn("sensitive-references.deposit", S.discover(self.cfg, self.url)["scope"].split())
        self.srv.deposit = False
        found = S.discover(self.cfg, self.url)
        self.assertNotIn("sensitive-references.deposit", found["scope"].split())
        self.assertIsNone(found["deposit"])

    def test_an_older_login_is_told_to_log_in_again_and_no_value_leaves(self):
        self.srv.deposit = False
        self.login()                                     # a login from before the gateway named the deposit
        self.srv.deposit = True
        self.bind(login=False)
        self.assert_refused(self.pre(), "does not allow deposits; the person types /maisecrets sref login Team_GW")
        self.assertEqual(self.srv.deposit_requests, [])
        self.assertEqual(self.audit(), "", "nothing left the computer, nothing counts")

    def test_the_gateway_s_insufficient_scope_tells_the_person_to_log_in_again(self):
        self.bind()
        self.srv.deposit_answer = (403, {}, {"WWW-Authenticate": 'Bearer error="insufficient_scope"'})
        self.assert_refused(self.pre(), "does not allow deposits")

    def test_without_deposit_fields_there_is_no_deposit(self):
        self.bind()
        self.srv.deposit_fields = {"deposit_profile": "deposit-9"}
        self.assert_refused(self.pre(), "offers no deposit")

    def test_a_call_outside_the_targets_gets_no_deposit(self):
        self.bind()
        for args, why in ((self.args(action="list_webhooks"), "takes no deposit for this call"),
                          (self.args(token="x", url=self.ref), "takes no deposit at /url"),
                          ({"action": "create_webhook", "token": "x", "extra": [self.ref]}, "at /extra/0")):
            with self.subTest(args=args):
                self.assert_refused(self.pre(args), why)
        self.assert_refused(self.pre(tool="mcp__claude_ai_Team_GW__gitlab_read_actions"),
                            "takes no deposit for this call")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_arguments_with_a_handle_or_a_placeholder_in_the_action_are_refused(self):
        self.bind()
        self.assert_refused(self.pre(self.args(project="msdep1_x")), "already hold a deposit handle")
        self.srv.deposit_fields = {"deposit_targets": [{"tool": "gitlab_write_actions", "when": {"/action": "x"},
                                                        "paths": ["/token"]},
                                                       {"tool": "gitlab_write_actions",
                                                        "paths": ["/token", "/action"]}]}
        (HOME / "sref" / "deposit-metadata.json").unlink()
        self.assert_refused(self.pre(self.args(action=self.ref)), "stands at /action, which decides the action")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_a_value_shorter_than_8_bytes_gets_no_deposit(self):
        self.bind()
        short = Vault().put("pin-123", "SECRET", "manual", session="s1").ref
        self.assert_refused(self.pre(self.args(token=short)), "has 7 bytes, and a deposit takes 8 to 4096")

    def test_the_size_is_checked_before_the_policy_and_the_limiter(self):
        # contract 6.1: the size (step 6) before the rehydration policy, the session rule and the limiter (step 7)
        self.write_config({"rehydration": "block"})
        self.bind()
        short = Vault().put("pin-123", "SECRET", "manual", session="s1").ref
        self.assert_refused(self.pre(self.args(token=short)), "has 7 bytes, and a deposit takes 8 to 4096")
        # a key of another session is not measured: its length is no answer
        other = Vault().put("pin-456", "SECRET", "manual", session="s2").ref
        hso = self.pre(self.args(token=other))
        self.assertNotIn("bytes", hso["permissionDecisionReason"])

    def test_a_call_without_its_mcp_server_gets_no_deposit(self):
        # without the server's own name, a `__` inside a connector's or a tool's name could route a handle elsewhere
        self.bind()
        self.assert_refused(self.pre(server=None), "names no claude.ai connector as its MCP server (a Claude Code "
                                                   "older than 2.1.330 may send no server name; update Claude Code)")
        self.assert_refused(self.pre(server={"name": "Gmail", "source": "sdk"}), "names no claude.ai connector")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_the_budget_counts_from_the_start_of_the_hook(self):
        # slow store reads before the network work use up the same 5 s
        self.bind()
        slow = S.logged_in

        def logged_in(*a, **k):
            time.sleep(2.5)
            return slow(*a, **k)
        self.srv.discovery_delays = [1.5]
        self.srv.deposit_delay = 1.5
        with mock.patch.object(S, "logged_in", logged_in):
            self.assert_refused(self.pre(call="late"), "did not answer the deposit in time")
        self.assertEqual(self.audit().count("deposit 127.0.0.1"), 1, "the request was sent and counts")

    def test_the_metadata_is_kept_at_most_an_hour(self):
        self.bind()
        self.pre(call="a")
        gets = self.srv.discovery_gets
        self.pre(call="b")
        self.assertEqual(self.srv.discovery_gets, gets, "a copy younger than an hour is used")
        path = HOME / "sref" / "deposit-metadata.json"
        data = json.loads(path.read_text())
        data[self.url]["t"] = time.time() - 3601
        path.write_text(json.dumps(data))
        self.srv.deposit_fields = {"deposit_profile": "deposit-9"}       # the gateway switched the deposit off
        self.assert_refused(self.pre(call="c"), "offers no deposit")
        self.assertEqual(self.srv.discovery_gets, gets + 1)

    def test_a_deposit_ends_within_its_5_s_budget(self):
        # one deadline for the metadata read and the deposit request together: each of them alone stays under the
        # socket timeout of one read (4 s), together they pass 5 s
        self.bind()
        self.srv.discovery_delays = [3.0]
        self.srv.deposit_delay = 3.0
        start = time.monotonic()
        self.assert_refused(self.pre(call="slow"), "did not answer the deposit in time")
        self.assertLess(time.monotonic() - start, 6.5)

    def test_cowork_keeps_the_refusal(self):
        self.bind()
        for entry in ("remote_cowork", "local-agent"):
            with self.subTest(entry=entry), mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": entry}):
                self.assert_refused(self.pre(), "does not work in Cowork")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_a_display_name_with_runs_of_marks_finds_its_binding(self):
        # Claude Code 2.1.330 (its function xn) spells "claude.ai Acme (prod)" as claude_ai_Acme_prod in the tool name:
        # each run of `_` becomes one and a `_` at either end goes. The key from the hook's display name must be the
        # same, for the deposit and for the noting of a gateway reference (C31)
        for display, key in (("claude.ai Acme (prod)", "Acme_prod"), ("claude.ai Team  GW", "Team_GW"),
                             ("claude.ai GW.", "GW"), ("claude.ai Ops / GW", "Ops_GW")):
            with self.subTest(display=display):
                self.assertEqual(vault_refs.connector_key(display), key)
                self.assertEqual(vault_refs.connector_key("claude_ai_" + key), key)
                self.bind(key=key, login=not S.logged_in(self.backend, "https://127.0.0.1:"
                                                         + self.srv.url.rsplit(":", 1)[1]))
                server = {"name": display, "source": "claudeai"}
                self.assertEqual(vault_refs.server_key({"mcp_server": server}), key, "the C31 noting finds it")
                hso = self.pre(tool=f"mcp__claude_ai_{key}__gitlab_write_actions", server=server, call=key)
                self.assertRegex(hso["updatedInput"]["token"], D.HANDLE_RE.pattern)
                self.assertTrue(vault_refs.forget_connector(key))
        self.assertEqual(vault_refs.connector_key("Acme (prod)"), None, "no claude.ai name, no key")
        self.assertEqual(vault_refs.connector_key("Claude.ai X"), None, "the prefix is exact: a capital C gives no key")
        self.assertEqual(vault_refs.mangled("my  server"), "my__server", "other names keep their runs")

    def test_another_connector_name_on_a_bound_tool_gets_the_refusal(self):
        self.bind()
        self.assert_refused(self.pre(server={"name": "claude.ai Other", "source": "claudeai"}),
                            "this connector is not bound to a gateway of yours")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_another_connector_or_an_unbound_one_gets_the_refusal(self):
        self.bind()
        self.assert_refused(self.pre(tool="mcp__claude_ai_Other__gitlab_write_actions"),
                            "this connector is not bound to a gateway of yours")

    # -------------------------------------------------------------------------------------- the result (6.5) --
    def test_a_refusal_block_next_to_a_block_with_the_value_keeps_the_redaction(self):
        self.bind()
        hso = self.pre(call="t11")
        result = {"content": [{"type": "text", "text": "deposit_refused: expired"},
                              {"type": "text", "text": "echo: " + VALUE}], "isError": True}
        out = hooks._post_tool_guarded({"tool_name": TOOL, "tool_use_id": "t11", "session_id": "s1",
                                        "mcp_server": SERVER, "tool_input": hso["updatedInput"],
                                        "tool_response": result, **CLAUDE})
        text = json.dumps(out, ensure_ascii=False)
        self.assertNotIn(VALUE, text, "the value in the second block is masked")
        self.assertIn("echo: " + self.ref, text, "the normal redaction ran on the whole result")
        # the whole result is one refusal: the line, in the shape of the result
        for shape in ("deposit_refused: used", [{"type": "text", "text": "deposit_refused: used"}],
                      {"content": [{"type": "text", "text": "deposit_refused: used"}], "isError": True,
                       "structuredContent": {"deposit_error": "used"}}):
            with self.subTest(shape=shape):
                out = hooks._post_tool_guarded({"tool_name": TOOL, "tool_use_id": "t11", "session_id": "s1",
                                                "mcp_server": SERVER, "tool_input": {}, "tool_response": shape,
                                                **CLAUDE})
                self.assertIn("took the deposit for " + self.ref + " as used already",
                              json.dumps(out["hookSpecificOutput"]["updatedToolOutput"], ensure_ascii=False))
        for shape in ({"content": [{"type": "text", "text": "deposit_refused: used"}],
                       "structuredContent": {"deposit_error": "expired"}},
                      [{"type": "text", "text": "deposit_refused: used", "annotations": {}}]):
            with self.subTest(shape=shape):
                self.assertIsNone(D.post_tool({"tool_name": TOOL, "tool_use_id": "t11", "tool_response": shape}))

    def test_a_refusal_of_the_gateway_becomes_one_line_for_the_model(self):
        self.bind()
        hso = self.pre(call="t9")
        self.srv.deposits.clear()                         # the deposit is gone at the gateway (its TTL)
        result = self.srv.call("gitlab_write_actions", hso["updatedInput"])
        out = hooks._post_tool_guarded({"tool_name": TOOL, "tool_use_id": "t9", "session_id": "s1",
                                        "mcp_server": SERVER, "tool_input": hso["updatedInput"],
                                        "tool_response": result["content"], **CLAUDE})
        text = json.dumps(out["hookSpecificOutput"]["updatedToolOutput"], ensure_ascii=False)
        self.assertNotIn("deposit_refused", text)
        self.assertIn("the gateway knows no deposit for " + self.ref, text)
        # a call without a deposit keeps its text
        out = hooks._post_tool_guarded({"tool_name": TOOL, "tool_use_id": "t10", "session_id": "s1",
                                        "mcp_server": SERVER, "tool_input": {}, "tool_response": result["content"],
                                        **CLAUDE})
        self.assertNotIn("knows no deposit", json.dumps(out))


@unittest.skipUnless(T.HAS_OPENSSL and os.name != "nt", "openssl on POSIX")
class TripwireTests(_Base):
    """D9 against a gateway whose certificate an interception CA issued."""

    def setUp(self) -> None:
        super().setUp(cert=_trip_cert())

    def test_an_interception_ca_stops_the_deposit_before_the_value_is_sent(self):
        self.bind()
        self.assert_refused(self.pre(), "comes from an interception CA")
        self.assertEqual(self.srv.deposit_requests, [])


if __name__ == "__main__":
    unittest.main()
