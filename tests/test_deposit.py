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
        with mock.patch("secrets.token_urlsafe", lambda n: NONCE):   # the mod asks Python for the nonce (#98)
            self.assertEqual(sref_hooks.pair_due(key), NONCE)
        got = sref_hooks.pair_connector(key, NONCE, json.dumps({"resource": self.url,
                                                                "proof": self.srv.proof(NONCE)}))
        self.assertTrue(got["bound"], got)

    def args(self, **change) -> dict:
        return {"action": "create_webhook", "project": "group/app", "url": "https://hooks.example.com/in",
                "token": self.ref, **change}

    def pre(self, tool_input: dict | None = None, call: str = "t1", tool: str = TOOL, server: object = SERVER,
            extra: dict | None = None) -> dict:
        hooks._live_cache.clear()
        payload = {"tool_name": tool, "tool_input": tool_input or self.args(), "session_id": "s1",
                   "tool_use_id": call, "transcript_path": "", **CLAUDE, **(extra or {})}
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

    def test_in_auto_mode_the_person_is_asked_for_a_deposit_call(self):
        self.bind()
        hso = self.pre(extra={"permission_mode": "auto"})
        self.assertEqual(hso["permissionDecision"], "ask", "auto mode would deny a changed MCP input (#31)")
        self.assertRegex(hso["updatedInput"]["token"], D.HANDLE_RE.pattern)
        self.assertEqual(len(self.srv.deposit_requests), 1)
        self.assertNotIn("permissionDecision", self.pre(call="t2"), "with automatic and no auto mode no question")

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
        # signed again, so only the age decides (an unsigned copy is read again for its MAC alone)
        data[self.url]["mac"] = D._meta_mac(self.backend, self.url, data[self.url]["t"], data[self.url]["found"], False)
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

    def test_a_refusal_that_comes_as_a_failed_call_gets_its_line_too(self):
        # live probe 2026-11-22: the refusal has isError, so Claude Code 2.1.330 sends PostToolUseFailure, whose
        # answer cannot replace the output (#97278): the line goes to the model as additional context. The error of an
        # MCP isError result in the 2.1.330 bundle: the text of its blocks joined by "\n" (McpToolCallError message),
        # then trimmed, no prefix. The JSON of one block is not that form; it stays read for another client
        self.bind()
        hso = self.pre(call="t12")
        self.assertTrue(hso["updatedInput"])
        for error in ("deposit_refused: expired", json.dumps([{"type": "text", "text": "deposit_refused: expired"}])):
            with self.subTest(error=error):
                out = hooks.post_tool_failure({"tool_name": TOOL, "tool_use_id": "t12", "session_id": "s1",
                                               "mcp_server": SERVER, "tool_input": {}, "error": error, **CLAUDE})
                self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUseFailure")
                self.assertIn("the deposit for " + self.ref + " expired before the call ran",
                              out["hookSpecificOutput"]["additionalContext"])
        # a call that carried no deposit, and a refusal next to other text, keep the failure path as it was
        for call, error in (("t13", "deposit_refused: expired"), ("t12", "deposit_refused: expired; echo: x"),
                            ("t12", "deposit_refused: expired\necho: x")):     # two blocks, as 2.1.330 joins them
            with self.subTest(call=call, error=error):
                out = hooks.post_tool_failure({"tool_name": TOOL, "tool_use_id": call, "session_id": "s1",
                                               "mcp_server": SERVER, "tool_input": {}, "error": error, **CLAUDE})
                self.assertNotIn("expired before the call ran", json.dumps(out))

    def refusal_lines(self, code: str, call: str) -> tuple:
        """The line of a gateway's `deposit_refused: <code>` in PostToolUse (the output it replaces) and in
        PostToolUseFailure (the context next to the code), for a call that carried a deposit."""
        self.bind()
        self.assertTrue(self.pre(call=call)["updatedInput"])
        refusal = "deposit_refused: " + code
        post = hooks._post_tool_guarded({"tool_name": TOOL, "tool_use_id": call, "session_id": "s1",
                                         "mcp_server": SERVER, "tool_input": {}, **CLAUDE,
                                         "tool_response": {"content": [{"type": "text", "text": refusal}],
                                                           "isError": True}})
        failed = hooks.post_tool_failure({"tool_name": TOOL, "tool_use_id": call, "session_id": "s1",
                                          "mcp_server": SERVER, "tool_input": {}, "error": refusal, **CLAUDE})
        self.assertEqual(failed["hookSpecificOutput"]["hookEventName"], "PostToolUseFailure")
        lines = (json.dumps(post["hookSpecificOutput"]["updatedToolOutput"], ensure_ascii=False),
                 failed["hookSpecificOutput"]["additionalContext"])
        for line in lines:
            self.assertNotIn(VALUE, line)
            self.assertIn(self.ref, line)
            self.assertIn("the value was not sent", line)
        self.assertNotIn("deposit_refused", lines[0], "the line replaces the code in PostToolUse")
        return lines

    def test_a_weak_secret_refusal_names_the_ways_out_in_both_paths(self):
        # ai-gateway #2048: a SECRET too weak to fingerprint is refused at call time, before the upstream request
        for line in self.refusal_lines("weak_secret", "t14"):
            with self.subTest(line=line):
                self.assertIn("too short or too simple to be protected on a later read", line)
                self.assertIn("a stronger value", line)
                self.assertIn("a directly added MCP server", line)

    def test_an_unusable_fingerprint_store_says_do_not_retry_in_both_paths(self):
        # the person's fingerprint store at the gateway does not open: only the gateway operator's reset helps
        for line in self.refusal_lines("fingerprints_unusable", "t15"):
            with self.subTest(line=line):
                self.assertIn("Do not try again", line)
                self.assertIn("ask the gateway operator to reset the store", line)
                self.assertNotIn("Try again later", line)


MAIL = "anyfield.person@example.com"          # synthetic, example.com
ANY_TOOL = "gitlab_write_actions"


class AnyFieldShapeTests(unittest.TestCase):
    """deposit_any_field of the metadata: a wrong shape drops the field alone, and the gateway can only narrow."""
    ORIGIN = "https://gateway.example.com"

    def block(self, free: object) -> dict:
        return {"deposit_endpoint": self.ORIGIN + "/d", "deposit_profile": "deposit-1",
                "deposit_scope": "sensitive-references.deposit",
                "deposit_targets": [{"tool": ANY_TOOL, "paths": ["/token"]}], "deposit_any_field": free}

    def test_a_wrong_any_field_is_ignored_and_the_targets_stay(self):
        for free in ([], "EMAIL", {"types": "EMAIL", "tools": [ANY_TOOL]}, {"types": ["EMAIL"]},
                     {"types": ["EMAIL"], "tools": ANY_TOOL}, {"types": [1], "tools": [ANY_TOOL]},
                     {"types": ["EMAIL"], "tools": [7]}, {"types": ["EMAIL"], "tools": ["a tool"]},
                     {"types": ["EMAIL"] * 65, "tools": [ANY_TOOL]}):
            with self.subTest(free=str(free)[:60]):
                got = D.fields(self.block(free), self.ORIGIN)
                self.assertIsNotNone(got, "the deposit stays usable")
                self.assertNotIn("deposit_any_field", got)
                self.assertEqual(got["deposit_targets"], [{"tool": ANY_TOOL, "when": {}, "paths": ["/token"]}])

    def test_the_gateway_can_narrow_the_list_and_never_widen_it(self):
        wide = ["EMAIL", "SECRET", "CARD", "ID_NUMBER", "FUTURE_TYPE", "PHONE"]
        got = D.fields(self.block({"types": wide, "tools": ["b", ANY_TOOL]}), self.ORIGIN)
        self.assertEqual(got["deposit_any_field"], {"types": ["EMAIL", "PHONE"], "tools": ["b", ANY_TOOL],
                                                    "actions": {}, "all_types": False})
        self.assertEqual(D.fields(got, self.ORIGIN), got, "a kept copy passes the same check")

    def test_missing_or_malformed_actions_allow_no_action(self):
        base = {"types": ["EMAIL"], "tools": [ANY_TOOL]}
        for acts in (None, [ANY_TOOL], "create_issue", {ANY_TOOL: "create_issue"}, {ANY_TOOL: ["create_issue", 1]},
                     {ANY_TOOL: None}):
            with self.subTest(actions=acts):
                free = {**base, "actions": acts} if acts is not None else base
                got = D.fields(self.block(free), self.ORIGIN)["deposit_any_field"]
                self.assertEqual(got["actions"], {}, "no tool has a listed action")
                self.assertFalse(D.listed_action(got, ANY_TOOL, {"action": "create_issue"}))
        got = D.fields(self.block({**base, "actions": {ANY_TOOL: ["update_issue", "create_issue"], "other": 7}}),
                       self.ORIGIN)
        self.assertEqual(got["deposit_any_field"]["actions"], {ANY_TOOL: ["create_issue", "update_issue"]},
                         "a malformed entry drops only its own tool")
        self.assertEqual(D.fields(got, self.ORIGIN), got, "a kept copy passes the same check")

    def test_the_own_list_holds_only_personal_types(self):
        from maisecrets.detection import personal
        self.assertLessEqual({personal.NAME, personal.ADDRESS, personal.BIRTH_DATE, personal.USERNAME,
                              personal.PHONE}, D.ANY_FIELD_TYPES)
        self.assertFalse({"SECRET", "CARD", personal.ID_NUMBER} & D.ANY_FIELD_TYPES)

    def test_the_class_is_the_type_before_the_last_c_and_digits(self):
        from maisecrets.placeholder import key_of
        for key, kind in (("BIRTH_DATE_c3", "BIRTH_DATE"), ("IPV6_c12", "IPV6"), ("X__c9", "X_"),
                          ("EMAIL_c1", "EMAIL")):
            with self.subTest(key=key):
                self.assertEqual(D.class_of(key), kind)
                self.assertIsNotNone(D.PLACEHOLDER_RE.fullmatch(OPEN + key + ":ab•••" + CLOSE))
        # a type has no lower-case letter, so `_c1` inside a type cannot shift the split: such a key has no form
        for key in ("A_c1_c2", "BIRTH_DATE_c3_c4", "EMAIL_c1x"):
            with self.subTest(key=key):
                self.assertIsNone(D.class_of(key))
                self.assertIsNone(D.PLACEHOLDER_RE.fullmatch(OPEN + key + CLOSE))
                self.assertIsNone(key_of(OPEN + key + CLOSE), "the placeholder module takes no such key either")

    def test_a_type_has_at_most_32_characters(self):
        for kind in ("A" * 32, "B" + "_" * 30 + "9"):
            with self.subTest(kind=kind):
                self.assertEqual(D.class_of(kind + "_c1"), kind)
                self.assertIsNotNone(D.PLACEHOLDER_RE.fullmatch(OPEN + kind + "_c1" + CLOSE))
        for kind in ("A" * 33, "B" + "_" * 31 + "9"):
            with self.subTest(kind=kind):
                self.assertIsNone(D.class_of(kind + "_c1"))
                self.assertIsNone(D.PLACEHOLDER_RE.fullmatch(OPEN + kind + "_c1" + CLOSE))

    def test_the_binding_mismatch_line_names_the_other_causes_and_no_value(self):
        line = D._line("binding_mismatch", ["EMAIL_c1"])
        self.assertIn("this action of the connector does not take a stored value", line)
        self.assertIn("the value was not sent", line)
        self.assertIn("encodes its body (for example a Gmail send)", line)
        self.assertIn("fields go into the URL", line)
        self.assertIn("tell the user", line)
        self.assertIn("EMAIL_c1", line)


@unittest.skipUnless(T.HAS_OPENSSL and os.name != "nt", "openssl on POSIX")
class AnyFieldTests(_Base):
    """Section 6.1.5 with deposit_any_field: a personal placeholder in any string value of a listed tool's call."""

    def free(self, types: list | None = None, tools: list | None = None, actions: object = "default",
             all_types: object = "absent") -> None:
        free = {"types": types or sorted(D.ANY_FIELD_TYPES), "tools": tools or [ANY_TOOL]}
        if all_types != "absent":
            free["all_types"] = all_types
        if actions == "default":
            actions = {t: ["create_issue", "create_webhook"] for t in free["tools"]}
        if actions is not None:
            free["actions"] = actions
        self.srv.deposit_fields = {"deposit_any_field": free}

    def assert_action_refused(self, hso: dict) -> None:
        self.assert_refused(hso, "this action of the connector does not take a stored value; it was not sent")
        self.assertEqual(self.srv.deposit_requests, [])
        self.assertNotIn("deposit 127.0.0.1", self.audit(), "refused before any deposit: no value left the computer")

    def put(self, value: str, type_: str, kind: str = "manual") -> str:
        return Vault().put(value, type_, kind, session="s1").ref

    def change(self, ref: str, **meta) -> None:
        v = Vault()
        v._index["entries"][ref[1:-1].split(":", 1)[0]].update(meta)
        v._save_index()

    def issue(self, text: str) -> dict:
        return {"action": "create_issue", "project": "group/app", "params": {"title": "t", "description": text}}

    def test_a_personal_value_goes_into_any_string_of_a_listed_tool(self):
        self.free()
        self.bind()
        mail = self.put(MAIL, "EMAIL", "email")
        hso = self.pre(self.issue("write to " + mail + " today"))
        text = hso["updatedInput"]["params"]["description"]
        self.assertRegex(text, r"^write to msdep1_[A-Za-z0-9_-]{65} today$")
        req = self.srv.deposit_requests[0]
        self.assertEqual([(v["path"], v["value"]) for v in req["values"]], [("/params/description", MAIL)])
        self.assertEqual(self.srv.call(ANY_TOOL, hso["updatedInput"])["params"]["description"],
                         "write to " + MAIL + " today")

    def test_a_birth_date_goes_into_any_string_of_a_listed_tool(self):
        self.free()
        self.bind()
        born = self.put("1990-01-02", "BIRTH_DATE", "birth_date")
        hso = self.pre(self.issue("born " + born))
        self.assertRegex(hso["updatedInput"]["params"]["description"], r"^born msdep1_[A-Za-z0-9_-]{65}$")
        req = self.srv.deposit_requests[0]
        self.assertEqual([(v["path"], v["value"]) for v in req["values"]], [("/params/description", "1990-01-02")])

    def test_without_actions_no_action_takes_a_personal_value(self):
        self.free(actions=None)
        self.bind()
        self.assert_action_refused(self.pre(self.issue(self.put(MAIL, "EMAIL", "email"))))
        self.assertIn("updatedInput", self.pre(call="t2"), "the targets still apply")

    def test_malformed_actions_let_no_action_take_a_personal_value(self):
        self.free(actions=[ANY_TOOL])
        self.bind()
        mail = self.put(MAIL, "EMAIL", "email")
        self.assert_action_refused(self.pre(self.issue(mail)))
        self.free(actions={ANY_TOOL: "create_issue"})                      # the tool's entry is no list
        (HOME / "sref" / "deposit-metadata.json").unlink()
        self.assert_action_refused(self.pre(self.issue(mail), call="t2"))

    def test_an_action_outside_the_list_is_refused_before_the_deposit(self):
        self.free()
        self.bind()
        self.assert_action_refused(self.pre({**self.issue(self.put(MAIL, "EMAIL", "email")), "action": "close_issue"}))

    def test_a_call_without_an_action_argument_is_refused(self):
        self.free()
        self.bind()
        args = self.issue(self.put(MAIL, "EMAIL", "email"))
        del args["action"]
        self.assert_action_refused(self.pre(args))

    def test_an_action_argument_that_is_no_string_is_refused(self):
        self.free()
        self.bind()
        self.assert_action_refused(self.pre({**self.issue(self.put(MAIL, "EMAIL", "email")),
                                             "action": ["create_issue"]}))

    def test_all_types_lets_every_class_go_on_a_listed_action(self):
        self.free(all_types=True)
        self.bind()
        own = self.put("own." + MAIL, "EMAIL", "user:my-mails")
        hso = self.pre(self.issue("key " + self.ref + " owner " + own))
        self.assertRegex(hso["updatedInput"]["params"]["description"],
                         r"^key msdep1_[A-Za-z0-9_-]{65} owner msdep1_[A-Za-z0-9_-]{65}$")
        self.assertEqual(sorted(v["value"] for v in self.srv.deposit_requests[0]["values"]),
                         sorted([VALUE, "own." + MAIL]))

    def test_all_types_other_than_true_keeps_a_secret_strict(self):
        self.bind()
        for at in ("absent", "true", False, 1, None, {}, [1]):
            with self.subTest(all_types=at):
                self.free(all_types=at)
                cache = HOME / "sref" / "deposit-metadata.json"
                if cache.exists():
                    cache.unlink()
                self.assert_refused(self.pre(self.issue(self.ref), call="t-" + str(at)),
                                    "takes no deposit at /params/description")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_all_types_passes_each_strict_kind_and_the_strict_mark(self):
        self.free(all_types=True)
        self.bind()
        refs = {kind: self.put(kind + "." + MAIL, "EMAIL", kind) for kind in ("term:t1", "import:i1", "remote:r1")}
        refs["strict mark"] = self.put("marked." + MAIL, "EMAIL", "email")
        for kind in ("remote:r1", "strict mark"):
            self.change(refs[kind], weak=False, **({"strict": True} if kind == "strict mark" else {}))
        for kind, ref in refs.items():
            with self.subTest(kind=kind):
                self.assertIsNone(D.any_field_class(Vault(), ref), "strict without all_types")
                self.assertEqual(D.any_field_class(Vault(), ref, every=True), "EMAIL")

    def test_an_unlisted_tool_stays_refused_inside_the_loop(self):
        # the call matches a target, so the early check passes; the second placeholder needs the any-field rule
        self.free(tools=["slack_write_actions"], all_types=True)
        self.bind()
        other = self.put(VALUE + "-second", "SECRET")
        self.assert_refused(self.pre(self.args(description=other)), "takes no deposit at /description")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_all_types_keeps_the_tool_list(self):
        self.free(tools=["slack_write_actions"], all_types=True)
        self.bind()
        self.assert_refused(self.pre(self.issue(self.ref)), "takes no deposit for this call")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_all_types_keeps_the_action_list(self):
        self.free(all_types=True)
        self.bind()
        self.assert_action_refused(self.pre({**self.issue(self.ref), "action": "close_issue"}))

    def test_all_types_keeps_a_weak_entry_strict(self):
        self.free(all_types=True)
        self.bind()
        ref = self.put("weak." + MAIL, "EMAIL", "email")
        self.change(ref, weak=True)
        self.assert_refused(self.pre(self.issue(ref)), "takes no deposit at /params/description")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_all_types_keeps_a_value_with_a_gateway_reference_strict(self):
        self.free(all_types=True)
        self.bind()
        ref = self.put(OPEN + "sref:gw:anyfield-synthetic-reference" + CLOSE, "NAME", "name")
        self.assert_refused(self.pre(self.issue(ref)), "holds a reference of a gateway")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_all_types_keeps_the_type_check(self):
        self.free(all_types=True)
        self.bind()
        ref = self.put(VALUE + "-other", "SECRET")
        self.change(ref, type="EMAIL")
        self.assert_refused(self.pre(self.issue(ref)), "takes no deposit at /params/description")
        self.assertNotIn("deposit 127.0.0.1", self.audit(), "no value left the computer")

    def test_without_the_field_a_personal_value_stays_strict(self):
        self.bind()
        mail = self.put(MAIL, "EMAIL", "email")
        self.assert_refused(self.pre(self.issue(mail)), "takes no deposit for this call")
        self.srv.deposit_fields = {"deposit_any_field": {"types": ["EMAIL"]}}          # a wrong shape
        (HOME / "sref" / "deposit-metadata.json").unlink()
        self.assert_refused(self.pre(self.issue(mail)), "takes no deposit for this call")
        self.assertEqual(self.srv.deposit_requests, [])
        self.assertIn("updatedInput", self.pre(call="t2"), "the targets still apply")

    def test_secret_card_and_id_number_stay_strict_when_the_gateway_lists_them(self):
        self.free(types=["SECRET", "CARD", "ID_NUMBER", "EMAIL"])
        self.bind()
        for value, type_ in ((VALUE, "SECRET"), ("anyfield-card-synthetic", "CARD"),
                             ("anyfield-id-synthetic", "ID_NUMBER")):
            with self.subTest(type_=type_):
                self.assert_refused(self.pre(self.issue(self.put(value, type_))),
                                    "takes no deposit at /params/description")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_an_own_rule_or_a_term_stays_strict(self):
        self.free()
        self.bind()
        ref = self.put("own." + MAIL, "EMAIL", "user:my-mails")
        self.assert_refused(self.pre(self.issue(ref)), "takes no deposit at /params/description")
        self.assertEqual(self.srv.deposit_requests, [])
        # a term is never resolved (hooks._term_keys); its class is strict too, should it ever reach a deposit
        term = self.put("term." + MAIL, "EMAIL", "term:abc123")
        self.assertIsNone(D.any_field_class(Vault(), term))
        plain = self.put("plain." + MAIL, "EMAIL", "email")
        self.assertEqual(D.any_field_class(Vault(), plain), "EMAIL")

    def test_a_models_finding_stays_strict(self):
        self.free()
        self.bind()
        ref = self.put("Anyfield Modelfound", "NAME", "remote:x")
        self.change(ref, weak=False)                    # a model's finding is weak; the kind alone must hold
        self.assert_refused(self.pre(self.issue(ref)), "takes no deposit at /params/description")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_an_import_stays_strict(self):
        self.free()
        self.bind()
        ref = self.put("import." + MAIL, "EMAIL", "import:abc123")
        # an import is never resolved (hooks._term_keys); its class is strict too, should it ever reach a deposit
        self.assertEqual(self.pre(self.issue(ref)), {})
        self.assertIsNone(D.any_field_class(Vault(), ref))
        self.assertEqual(self.srv.deposit_requests, [])

    def test_a_later_own_rule_match_marks_a_stored_entry_strict(self):
        self.free()
        self.bind()
        # a tool result: a built-in rule stored the value first, an own rule finds it later (Vault.put_many)
        tool_ref = self.put("tool." + MAIL, "EMAIL", "email")
        Vault().put_many([("tool." + MAIL, "EMAIL", "user:my-mails")], session="s1", tool=True)
        self.assert_refused(self.pre(self.issue(tool_ref)), "takes no deposit at /params/description")
        # a prompt: the same through Vault.put
        typed_ref = self.put("typed." + MAIL, "EMAIL", "email")
        self.assertEqual(self.put("typed." + MAIL, "EMAIL", "user:my-mails"), typed_ref, "the first kind stays")
        self.assert_refused(self.pre(self.issue(typed_ref), call="t2"), "takes no deposit at /params/description")
        self.assertEqual(self.srv.deposit_requests, [])
        # a model's later finding does not mark it: the name service finds most names a rule found before
        model_ref = self.put("model." + MAIL, "EMAIL", "email")
        Vault().put_many([("model." + MAIL, "EMAIL", "remote:x")], session="s1", tool=True)
        self.assertIn("updatedInput", self.pre(self.issue(model_ref), call="t3"))

    def test_a_weak_entry_stays_strict(self):
        self.free()
        self.bind()
        ref = self.put("weak." + MAIL, "EMAIL", "email")
        self.change(ref, weak=True)
        self.assert_refused(self.pre(self.issue(ref)), "takes no deposit at /params/description")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_a_value_with_a_gateway_reference_stays_strict(self):
        self.free()
        self.bind()
        ref = self.put(OPEN + "sref:gw:anyfield-synthetic-reference" + CLOSE, "NAME", "name")
        self.change(ref, weak=False)                    # the normal state: a stored reference is not weak (!639)
        self.assert_refused(self.pre(self.issue(ref)), "holds a reference of a gateway")
        self.assertEqual(self.srv.deposit_requests, [])

    def test_the_class_is_the_type_of_the_vault_entry_never_the_key_prefix(self):
        self.free()
        self.bind()
        ref = self.put(VALUE + "-other", "SECRET")
        self.change(ref, type="EMAIL")                  # the entry claims a personal type its key does not carry
        self.assert_refused(self.pre(self.issue(ref)), "takes no deposit at /params/description")
        self.assertNotIn("deposit 127.0.0.1", self.audit(), "no value left the computer")

    def test_a_placeholder_in_an_object_key_is_refused(self):
        self.free()
        self.bind()
        mail = self.put(MAIL, "EMAIL", "email")
        self.assert_refused(self.pre({"action": "create_issue", "params": {mail: mail}}),
                            "stands in a key of the arguments")
        # a placeholder only in a key is no string value: the hook finds none, and the call keeps the placeholder
        self.assertEqual(self.pre({"action": "create_issue", "params": {mail: "x"}}, call="t2"), {})
        self.assertEqual(self.srv.deposit_requests, [])

    def test_a_tool_outside_the_list_is_refused(self):
        self.free(tools=["slack_write_actions"])
        self.bind()
        self.assert_refused(self.pre(self.issue(self.put(MAIL, "EMAIL", "email"))), "takes no deposit for this call")
        self.assertEqual(self.srv.deposit_requests, [])
        self.assertNotIn("deposit 127.0.0.1", self.audit(), "maisecrets refused it: no value left the computer")

    def test_a_kept_metadata_copy_with_a_widened_list_is_read_again(self):
        self.free(types=["EMAIL"])
        self.bind()
        self.assertIn("updatedInput", self.pre(self.issue(self.put(MAIL, "EMAIL", "email"))))
        cache = HOME / "sref" / "deposit-metadata.json"
        data = json.loads(cache.read_text(encoding="utf-8"))
        for url, rec in data.items():                   # a process with the store key widens the kept copy (A3)
            rec["found"]["deposit"]["deposit_any_field"]["types"].append("SECRET")
            rec["mac"] = D._meta_mac(self.backend, url, rec["t"], rec["found"], False)
        cache.write_text(json.dumps(data), encoding="utf-8")
        self.assert_refused(self.pre(self.issue(self.ref), call="t2"), "takes no deposit at /params/description")
        self.assertEqual(len(self.srv.deposit_requests), 1)
        self.assertEqual(sum("deposit 127.0.0.1" in line for line in self.audit().splitlines()), 1,
                         "only the deposit of the e-mail address; the secret never left the computer")
        kept = json.loads(cache.read_text(encoding="utf-8"))
        self.assertEqual([r["found"]["deposit"]["deposit_any_field"]["types"] for r in kept.values()], [["EMAIL"]],
                         "the gateway's metadata was read again over the direct channel")

    def test_a_kept_metadata_copy_changed_without_the_key_is_read_again(self):
        self.free()
        self.bind()
        self.assertIn("updatedInput", self.pre(self.issue(self.put(MAIL, "EMAIL", "email"))))
        cache = HOME / "sref" / "deposit-metadata.json"
        data = json.loads(cache.read_text(encoding="utf-8"))
        for rec in data.values():                       # a process without the store key switches all_types on
            self.assertIsInstance(rec.get("mac"), str)
            rec["found"]["deposit"]["deposit_any_field"]["all_types"] = True
        cache.write_text(json.dumps(data), encoding="utf-8")
        self.assert_refused(self.pre(self.issue(self.ref), call="t2"), "takes no deposit at /params/description")
        self.assertEqual(len(self.srv.deposit_requests), 1, "the secret never left the computer")
        kept = json.loads(cache.read_text(encoding="utf-8"))
        self.assertEqual([r["found"]["deposit"]["deposit_any_field"]["all_types"] for r in kept.values()], [False],
                         "the gateway's metadata was read again over the direct channel")

    def test_in_a_mixed_call_each_placeholder_passes_one_of_the_two_rules(self):
        self.free()
        self.bind()
        mail = self.put(MAIL, "EMAIL", "email")
        hso = self.pre(self.args(description="owner " + mail))
        self.assertRegex(hso["updatedInput"]["token"], r"^msdep1_[A-Za-z0-9_-]{65}$")
        self.assertRegex(hso["updatedInput"]["description"], r"^owner msdep1_[A-Za-z0-9_-]{65}$")
        self.assertEqual(sorted(v["path"] for v in self.srv.deposit_requests[0]["values"]), ["/description", "/token"])
        # a secret outside the target's paths fails both rules, and the whole call is refused
        self.assert_refused(self.pre(self.args(token="x", description=self.ref + " " + mail), call="t2"),
                            "takes no deposit at /description")
        self.assertEqual(len(self.srv.deposit_requests), 1)


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
