"""The rehydration matrix: for every path, client and policy, does maisecrets defer, allow, ask or deny?

Two layers (maisecrets/rehydration.py). Capability: a shape the rewrite cannot keep as data is
refused under every policy. Policy: for a path that can take the value, "automatic" (the default)
adds no ask of ours, "confirm" asks (Claude Code) or refuses (Codex, which cannot ask with a
rewritten input), "block" refuses.

The expected table below is written by hand and read by nothing else: the code has its own table
(rehydration.outcome). Each cell drives the real pre_tool with a real stored value and checks the
decision, where the value went, that no reason names it, and that a refusal resolved nothing.

Run: python3 -m unittest tests.test_rehydration_matrix -v
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

BASH = shutil.which("bash")
VALUE = "matrix-value 'q\" $(no) \\z"
CLIENTS = {"claude": CLAUDE, "codex": CODEX}

# path -> client -> policy -> decision. "defer": no permissionDecision, the client's own rules decide.
# A change to any cell must be a change to this table, made on purpose.
EXPECTED = {
    "bash": {"claude": {"automatic": "defer", "confirm": "ask", "block": "deny"},
             "codex": {"automatic": "allow", "confirm": "deny", "block": "deny"}},
    "ssh": {"claude": {"automatic": "defer", "confirm": "ask", "block": "deny"},
            # capability: Codex has no sandbox host allowlist, the route is Claude Code only
            "codex": {"automatic": "deny", "confirm": "deny", "block": "deny"}},
    "mcp": {"claude": {"automatic": "defer", "confirm": "ask", "block": "deny"},
            "codex": {"automatic": "allow", "confirm": "deny", "block": "deny"}},
    # a field a tool publishes: the same as any MCP field; the sink adds no ask of its own
    "mcp_text": {"claude": {"automatic": "defer", "confirm": "ask", "block": "deny"},
                 "codex": {"automatic": "allow", "confirm": "deny", "block": "deny"}},
    "file": {"claude": {"automatic": "defer", "confirm": "ask", "block": "deny"},
             "codex": {"automatic": "allow", "confirm": "deny", "block": "deny"}},
}

# Windows: capabilities the POSIX rewrite has and Windows has not; every other cell is the same
WINDOWS = {
    ("bash", "codex"): "deny",     # Codex runs PowerShell there; its quoting is not built
    ("ssh", "claude"): "deny",     # the ssh route is POSIX only
}


def expected(path: str, client: str, pol: str) -> str:
    if os.name == "nt" and (path, client) in WINDOWS:
        return WINDOWS[(path, client)]
    return EXPECTED[path][client][pol]


# payloads captured from the real client (tests/client_payloads): a client-specific row uses the shape the
# client sends, not the shape another client sends. The file row simulated Codex with Claude's Write, and
# Codex sends apply_patch (ChatGPT review, 2026-09-29): every cell was green while real edits went through
PAYLOADS = {p.stem: json.loads(p.read_text(encoding="utf-8"))
            for p in (ROOT / "tests" / "client_payloads").glob("*.json")}
CODEX_PATCH = PAYLOADS["codex-apply-patch"]


def _patch(ref: str, path: str = "notes.txt") -> dict:
    """The captured Codex patch with this test's placeholder and path."""
    command = CODEX_PATCH["tool_input"]["command"].replace("⟦SECRET_c1⟧", ref).replace("notes.txt", path)
    return {"command": command}


# shapes the rewrite cannot keep as data, or a client cannot take: refused under every policy
UNSUPPORTED = {
    "bash_nested_shell": ("Bash", lambda r: {"command": f"bash -c 'echo {r}'"}),
    "bash_encoder": ("Bash", lambda r: {"command": f"printf %s {r} | base64"}),
    "bash_backticks": ("Bash", lambda r: {"command": f"echo `echo {r}`"}),
    "ssh_remote_shell": ("Bash", lambda r: {"command": f"printf '%s' {r} | ssh aux01 bash"}),
    "ssh_value_in_arguments": ("Bash", lambda r: {"command": f"ssh aux01 echo {r}"}),
    "mcp_placeholder_as_key": ("mcp__x__y", lambda r: {r: "x", "y": r}),
    "file_into_the_store": ("Write", lambda r: {"file_path": str(Path(HOME, "config.json")), "content": r}),
    "patch_into_the_store": ("apply_patch", lambda r: _patch(r, str(Path(HOME, "config.json")))),
    "patch_placeholder_in_a_path": ("apply_patch", lambda r: _patch("x", r + ".txt")),
    "patch_placeholder_in_an_indented_path": ("apply_patch", lambda r: {
        "command": _patch("x", r + ".txt")["command"].replace("\n*** Add File:", "\n  *** Add File:")}),
}


def _input(path: str, ref: str, client: str = "claude") -> tuple[str, dict]:
    if path == "bash":
        return "Bash", {"command": f"printf 'got:%s' {ref}"}
    if path == "ssh":
        return "Bash", {"command": f"printf '%s' {ref} | ssh aux01 'grep -F -f - /var/log/mail.log'"}
    if path == "mcp":
        return "mcp__svc__lookup", {"id": ref}
    if path == "mcp_text":
        return "mcp__slack__post", {"channel": "C1", "text": "the password is " + ref}
    if client == "codex":
        return CODEX_PATCH["tool_name"], _patch(ref)
    return "Write", {"file_path": "/tmp/maisecrets-matrix.env", "content": "K=" + ref}


def _side_effects() -> dict:
    """What a resolve leaves behind: audit lines, approval tokens, value FIFOs waiting in the run dir."""
    audit = Path(HOME, "audit.log")
    approvals = Path(HOME, "ssh-approvals.json")
    try:
        run = sorted(n for n in os.listdir(hooks._run_dir()) if n.startswith("v-"))
    except OSError:
        run = []
    try:
        sealed = sorted(os.listdir(os.path.join(hooks._run_dir(), "sealed")))
    except OSError:
        sealed = []    # mode 0300: its owner cannot list it either; the approvals file names the token
    return {"audit": audit.read_text(encoding="utf-8").strip() if audit.exists() else "",
            "pending": approvals.read_text(encoding="utf-8") if approvals.exists() else "",
            "fifos": run + sealed}


def _nothing_left(case: unittest.TestCase, before: dict, what: str) -> None:
    after = _side_effects()
    case.assertEqual(after["audit"], "", f"{what}: a refusal wrote an audit line")
    case.assertFalse('"pending": {"' in after["pending"], f"{what}: a refusal left an approval token")
    case.assertEqual(sorted(set(after["fifos"]) - set(before["fifos"])), [], f"{what}: a refusal left a value waiting")


def _decision(hso: dict) -> str:
    return hso.get("permissionDecision", "defer" if "updatedInput" in hso else "none")


def _reset() -> None:
    Path(HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
    for f in ("index.json", "vault.json", "audit.log", "ssh-approvals.json"):
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()
    alive = _hygiene.wait_for_no_serving_child()
    if alive:
        raise AssertionError(f"value-serving children still run after the module: {alive}")


class RehydrationMatrixTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        _reset()

    def pre(self, tool: str, tool_input: dict, client: str, **cfg) -> dict:
        payload = {"tool_name": tool, "tool_input": tool_input, "session_id": "S1", "transcript_path": "",
                   **CLIENTS[client]}
        with mock.patch.object(hooks, "load_config", return_value={**hooks.load_config(), **cfg}):
            hso = hooks.pre_tool(payload).get("hookSpecificOutput", {})
        cmd = (hso.get("updatedInput") or {}).get("command", "")
        if cmd:
            self.addCleanup(lambda c=cmd: hooks._unserve(_fifos(c)))
        return hso

    def check_cell(self, path: str, client: str, pol: str, want: str, **cfg) -> None:
        _reset()
        ref = Vault().put(VALUE, "SECRET", "manual", session="S1").ref
        tool, tool_input = _input(path, ref, client)
        before = _side_effects()
        hso = self.pre(tool, tool_input, client, rehydration=pol, **cfg)
        got = _decision(hso)
        self.assertEqual(got, want, f"{path}/{client}/{pol}: {hso.get('permissionDecisionReason', '')[:200]}")
        self.assertNotIn(VALUE, hso.get("permissionDecisionReason", ""), "a reason never names the value")
        if want == "deny":
            self.assertNotIn("updatedInput", hso)
            # a refusal comes before the resolve: no audit line, no token, nothing served
            _nothing_left(self, before, f"{path}/{client}/{pol}")
            return
        new = hso["updatedInput"]
        if want == "ask":
            # the ask says what the user allows: the key and, for a published-text field, the warning
            reason = hso["permissionDecisionReason"]
            self.assertIn(ref, reason)
            self.assertEqual("WARNING" in reason, path == "mcp_text", f"{path}: the published-text warning")
        if tool == "Bash":
            # the command carries no value: the shell reads it from a FIFO in the main shell
            self.assertNotIn(VALUE, new["command"])
            if path == "bash" and os.name != "nt":
                run = subprocess.run([BASH, "-c", new["command"]], capture_output=True, text=True)
                self.assertEqual(run.stdout, "got:" + VALUE, "the value arrives byte for byte")
        else:
            text = "\n".join(_strings(new))
            self.assertIn(VALUE, text, "the tool gets the real value")
            self.assertNotIn(ref, text, "and no placeholder is left")

    def test_every_cell_of_the_matrix(self):
        for path, by_client in EXPECTED.items():
            for client, by_policy in by_client.items():
                for pol in by_policy:
                    with self.subTest(path=path, client=client, policy=pol):
                        self.check_cell(path, client, pol, expected(path, client, pol))

    def test_a_codex_row_uses_the_payload_codex_sends(self):
        self.assertEqual(CODEX_PATCH["tool_name"], "apply_patch")
        self.assertEqual(_input("file", "⟦SECRET_c1⟧", "codex")[0], "apply_patch")
        # the corpus file has every key the real client sent, so a key the hooks start to read is there
        self.assertLessEqual({"session_id", "tool_name", "tool_input", "turn_id", "model", "cwd"}, set(CODEX_PATCH))

    def test_the_matrix_covers_every_path_client_and_policy_the_code_knows(self):
        from maisecrets import rehydration
        self.assertEqual(rehydration.POLICIES, ("automatic", "confirm", "block"))
        self.assertEqual(rehydration.DEFAULT, "automatic")
        paths = {"mcp_text": "mcp"}
        self.assertEqual({paths.get(p, p) for p in EXPECTED}, set(rehydration.PATHS))
        for by_client in EXPECTED.values():
            self.assertEqual(set(by_client), set(CLIENTS))
            for by_policy in by_client.values():
                self.assertEqual(set(by_policy), set(rehydration.POLICIES))

    def test_the_default_is_automatic_on_every_path(self):
        # no rehydration key at all: the config a new install has
        for path, by_client in EXPECTED.items():
            for client in by_client:
                with self.subTest(path=path, client=client):
                    _reset()
                    ref = Vault().put(VALUE, "SECRET", "manual", session="S1").ref
                    tool, tool_input = _input(path, ref, client)
                    payload = {"tool_name": tool, "tool_input": tool_input, "session_id": "S1",
                               "transcript_path": "", **CLIENTS[client]}
                    hso = hooks.pre_tool(payload).get("hookSpecificOutput", {})
                    if hso.get("updatedInput", {}).get("command"):
                        self.addCleanup(lambda c=hso["updatedInput"]["command"]: hooks._unserve(_fifos(c)))
                    self.assertEqual(_decision(hso), expected(path, client, "automatic"))

    def test_a_setting_that_is_not_a_policy_blocks(self):
        for bad in ("strict", "Automatic", "", "ask"):
            for client in CLIENTS:
                with self.subTest(value=bad, client=client):
                    self.check_cell("mcp", client, bad, "deny")

    def test_resolve_in_files_off_blocks_only_the_file_path(self):
        for client in CLIENTS:
            with self.subTest(client=client):
                self.check_cell("file", client, "automatic", "deny", resolve_in_files=False)
                self.check_cell("mcp", client, "automatic", expected("mcp", client, "automatic"),
                                resolve_in_files=False)

    @unittest.skipIf(os.name == "nt", "the ssh route is POSIX only")
    def test_ssh_approval_per_session_matters_only_under_confirm(self):
        # automatic: no ask even on the first use, and no approval token is written
        self.check_cell("ssh", "claude", "automatic", "defer", ssh_approval="per-session")
        self.assertFalse(Path(HOME, "ssh-approvals.json").exists())
        self.check_cell("ssh", "claude", "confirm", "ask", ssh_approval="per-session")
        # confirm with per-session: the first use offers the session scope and leaves a pending token
        self.assertTrue(Path(HOME, "ssh-approvals.json").exists(), "the per-session branch ran")
        _reset()
        ref = Vault().put(VALUE, "SECRET", "manual", session="S1").ref
        tool, tool_input = _input("ssh", ref)
        hso = self.pre(tool, tool_input, "claude", rehydration="confirm", ssh_approval="per-session")
        self.assertIn("without asking again", hso["permissionDecisionReason"])
        hso = self.pre(tool, tool_input, "claude", rehydration="confirm")
        self.assertNotIn("without asking again", hso["permissionDecisionReason"], "per-command: no session scope")

    def test_a_good_key_next_to_a_refused_one_resolves_nothing(self):
        good = Vault().put(VALUE, "SECRET", "manual", session="S1").ref
        foreign = Vault().put(VALUE + "-2", "SECRET", "manual", session="S9").ref
        shapes = {"mcp": ("mcp__svc__lookup", {"id": good, "other": foreign}),
                  "file": ("Write", {"file_path": "/tmp/maisecrets-matrix.env", "content": good + "\n" + foreign}),
                  "bash": ("Bash", {"command": f"printf '%s %s' {good} {foreign}"})}
        for path, (tool, tool_input) in shapes.items():
            for client in CLIENTS:
                for pol in ("automatic", "confirm"):
                    with self.subTest(path=path, client=client, policy=pol):
                        before = _side_effects()
                        hso = self.pre(tool, tool_input, client, rehydration=pol)
                        self.assertEqual(hso.get("permissionDecision"), "deny")
                        self.assertNotIn("updatedInput", hso)
                        _nothing_left(self, before, f"{path}/{client}/{pol}")

    def test_two_new_keys_over_the_cap_resolve_nothing(self):
        # each key alone is under the cap, both together are over it
        a = Vault().put(VALUE, "SECRET", "manual", session="S1").ref
        b = Vault().put(VALUE + "-2", "SECRET", "manual", session="S1").ref
        for cap in ({"max_keys_per_session": 1}, {"max_resolves_per_hour": 1}):
            for tool, tool_input in (("mcp__svc__lookup", {"id": a, "other": b}),
                                     ("Write", {"file_path": "/tmp/maisecrets-matrix.env", "content": a + b}),
                                     ("Bash", {"command": f"printf '%s %s' {a} {b}"})):
                with self.subTest(cap=cap, tool=tool):
                    before = _side_effects()
                    hso = self.pre(tool, tool_input, "claude", **cap)
                    self.assertEqual(hso.get("permissionDecision"), "deny")
                    self.assertIn("limit:", hso["permissionDecisionReason"])
                    _nothing_left(self, before, f"{tool} {cap}")

    @unittest.skipIf(os.name == "nt", "the ssh route is POSIX only")
    def test_a_key_the_session_may_not_resolve_leaves_no_approval_token(self):
        ref = Vault().put(VALUE, "SECRET", "manual", session="S9").ref   # minted in another session
        tool, tool_input = _input("ssh", ref)
        hso = self.pre(tool, tool_input, "claude", rehydration="confirm", ssh_approval="per-session")
        self.assertEqual(hso.get("permissionDecision"), "deny")
        self.assertIn("(not given in this session)", hso["permissionDecisionReason"])
        store = Path(HOME, "ssh-approvals.json")
        self.assertFalse(store.exists() and '"pending": {}' not in store.read_text(encoding="utf-8"),
                         "a refused key left a pending approval token")

    def test_an_unsupported_shape_is_refused_under_every_policy(self):
        for name, (tool, make) in UNSUPPORTED.items():
            for client in CLIENTS:
                for pol in ("automatic", "confirm", "block"):
                    with self.subTest(shape=name, client=client, policy=pol):
                        _reset()
                        ref = Vault().put(VALUE, "SECRET", "manual", session="S1").ref
                        before = _side_effects()
                        hso = self.pre(tool, make(ref), client, rehydration=pol,
                                       ssh_approval="per-session")
                        self.assertEqual(hso.get("permissionDecision"), "deny", hso)
                        _nothing_left(self, before, f"{name}/{client}/{pol}")
                        self.assertNotIn("updatedInput", hso)
                        self.assertNotIn(VALUE, hso.get("permissionDecisionReason", ""))


class PatchValueTests(unittest.TestCase):
    """A value with line breaks inside a Codex patch (a PEM key, a multi-line put): each further line of the
    value stays file content and never becomes a patch operation (Codex review, 2026-09-29)."""

    def setUp(self):
        _reset()

    def patched(self, value: str, line_prefix: str = "+") -> dict:
        ref = Vault().put(value, "SECRET", "manual", session="S1").ref
        patch = f"*** Begin Patch\n*** Add File: notes.txt\n{line_prefix}key={ref}\n*** End Patch"
        payload = {"tool_name": "apply_patch", "tool_input": {"command": patch}, "session_id": "S1",
                   "transcript_path": "", **CODEX}
        return hooks.pre_tool(payload).get("hookSpecificOutput", {})

    def test_an_injected_header_in_a_value_stays_file_content(self):
        value = "top\n*** Add File: " + str(Path(HOME, "config.json")) + "\n*** Delete File: ../target.json\nend"
        hso = self.patched(value)
        self.assertEqual(hso.get("permissionDecision"), "allow")
        command = hso["updatedInput"]["command"]
        self.assertEqual(hooks._patch_headers(command), [("*** Add File: notes.txt", "notes.txt")],
                         "the patch names only the file the checked patch named")
        self.assertIn("\n+*** Add File: ", command, "the injected line is a content line of notes.txt")

    def test_a_multi_line_key_lands_line_by_line(self):
        pem = "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----"
        command = self.patched(pem)["updatedInput"]["command"]
        self.assertIn("\n+key=-----BEGIN KEY-----\n+AAAA\n+BBBB\n+-----END KEY-----\n", command)

    def test_what_a_patch_cannot_carry_is_refused(self):
        self.assertEqual(self.patched("a\rb").get("permissionDecision"), "deny", "a carriage return")
        # a context line with a value that starts a header after its prefix space
        value = "x\n*** Add File: y.txt"
        self.assertEqual(self.patched(value, line_prefix=" ").get("permissionDecision"), "deny")


class RefusalReasonTests(unittest.TestCase):
    """The reason names the real cause: the fallback for an unreadable config, or the user's own setting."""

    def test_the_refusal_names_the_fallback_only_when_the_fallback_set_it(self):
        from maisecrets import rehydration
        base = {"rehydration": "block", "config_warning": "config.json: tips has the wrong type; the file was ignored"}
        got = rehydration.refusal({**base, "rehydration_fallback": True}, "mcp", "claude", "⟦K⟧", "No.")
        self.assertIn("while the maisecrets settings cannot be read as written", got)
        # the file itself said block, or confirm on Codex: fixing the typo would change nothing
        self.assertIn("set to block", rehydration.refusal(base, "mcp", "claude", "⟦K⟧", "No."))
        got = rehydration.refusal({**base, "rehydration": "confirm"}, "mcp", "codex", "⟦K⟧", "No.")
        self.assertIn("Codex cannot ask", got)


class DecisionSitesTests(unittest.TestCase):
    """Every hook answer that carries a rewritten input goes through the policy. A new path that calls
    _updated or _ask on its own would skip it: this test names the call sites that exist."""

    def test_every_rewrite_decision_goes_through_the_policy(self):
        tree = ast.parse(Path(ROOT, "maisecrets", "hooks.py").read_text(encoding="utf-8"))
        sites: dict[str, list[str]] = {}
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef):
                for node in ast.walk(fn):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                            and node.func.id in ("_updated", "_ask"):
                        sites.setdefault(fn.name, []).append(node.func.id)
        self.assertEqual({k: sorted(v) for k, v in sites.items()}, {
            "_rehydrated": ["_ask", "_updated"],
            # the ssh route under the policy: automatic or a session approval, the ask of confirm per
            # session, the ask of confirm per command; and the ssh consent (#8): the ask for a command with no
            # value (its input unchanged: a yes allows that one command), and one ask for consent and value together
            # (a consent window never skips the value policy: the consent asks before the policy decides)
            "_pre_bash": ["_ask", "_ask", "_ask", "_ask", "_updated"],
            # ssh consent outside Bash (PowerShell text, a file under ~/.ssh): asks with the input unchanged
            "_consent_gate": ["_ask"],
            # a message to another session: values out, placeholders in; no value goes into the call
            "_pre_send_message": ["_updated"],
        })
        src = Path(ROOT, "maisecrets", "hooks.py").read_text(encoding="utf-8")
        self.assertEqual(src.count('"permissionDecision": "allow"'), 1, "allow is written in _updated only")
        # a rewrite built by hand next to them would skip the policy: updatedInput lives in _ask and _updated
        def builds_a_rewrite(fn) -> bool:
            return any(isinstance(n, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == "updatedInput"
                                                       for k in n.keys) for n in ast.walk(fn))
        owners = sorted(fn.name for fn in ast.walk(tree) if isinstance(fn, ast.FunctionDef) and builds_a_rewrite(fn))
        self.assertEqual(owners, ["_ask", "_updated"])


def _strings(node) -> list[str]:
    if isinstance(node, dict):
        return [s for v in node.values() for s in _strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in _strings(v)]
    return [node] if isinstance(node, str) else []


def _fifos(command: str) -> list[str]:
    import re
    return re.findall(r"\$\(cat '([^']+)'\)", command) or re.findall(r"\$\(cat ([^ )]+)\)", command)


if __name__ == "__main__":
    unittest.main()
