"""Invariant I2 (Claude Code): a rewrite never grants more than the original call.

When a PreToolUse answer carries updatedInput, the call that runs must be the call the model wrote,
with each placeholder standing where it stood, plus only what maisecrets needs to deliver the value
and nothing that widens what the call may do:

* Claude Code never gets permissionDecision "allow" from maisecrets: the answer carries no decision
  (the user's own permission rules apply to the rewritten call) or "ask";
* MCP, Write and Edit: put each placeholder back for its value and the input is the original,
  field for field;
* Bash: in front, only the reads of the values (`__ms_N="$(cat <fifo in the run directory>)"`, each
  ending the whole command with exit 97 when the value is not delivered) and, for ssh, the sandbox
  guard; after `ssh`, only the options that narrow it (no connection sharing, the plugin's own
  proxy); the rest, with each variable put back as its placeholder, is the original command.

Codex is the named exception (docs/THREAT-MODEL.md C5): Codex takes updatedInput only with "allow",
and "allow" skips its approval prompt. A test below records that; it fails when it stops being true,
so the exception is removed from the docs, not forgotten.

The checker is this file's own: it knows the delivery forms as text and never calls the product's
rewrite helpers.
"""
from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path

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

CODEX_P = {**CODEX, "model": "m"}

# a value read into a variable, and the whole command ends when it is not delivered
# the FIFO path is one shell word ending in v-<token>: a path with `; command` in it is not a read
_READ = re.compile(r'__ms_(\d+)="\$\(cat (/[A-Za-z0-9._/-]+/v-[A-Za-z0-9_-]+)\)" \|\| \{ echo "maisecrets: the value '
                   r'for ([A-Z_]+_c\d+) was not delivered[^"]*" >&2; exit 97; \}; ')
# Windows Git Bash reads a value through the plugin's own resolver under a one-time grant
_READ_WIN = re.compile(r'__ms_(\d+)="\$\("([^"]+)" "([^"]+/hooks/resolve\.py)" ([A-Z_]+_c\d+) '
                       r'--grant ([A-Za-z0-9_-]+)\)" '
                       r'\|\| \{ echo "maisecrets: the value for \4 was not delivered[^"]*" >&2; exit 97; \}; ')
# the sandbox guard of the ssh route: the value is read only after it passed
_GUARD = re.compile(r'\S+ \S+/hooks/sandbox_probe\.py \|\| \{ echo "maisecrets: [^"]*" >&2; exit 97; \}; ')
# the options the ssh route puts after `ssh`: no shared connection, the plugin's own proxy
_SSH_OPTS = re.compile(r"(?<![\w-])ssh -o ControlMaster=no -o ControlPath=none "
                       r"-o 'ProxyCommand=\S+ \S+/hooks/proxy_connect\.py %h %p' ")


def ph(key: str) -> str:
    return chr(0x27E6) + key + chr(0x27E7)


def undo_bash(original: str, rewritten: str, run_dir: str) -> list[str]:
    """What the rewrite added beyond the delivery forms; empty when it granted nothing more."""
    problems: list[str] = []
    rest = rewritten
    ssh = bool(re.search(r"(?<![\w-])ssh ", original))
    if ssh:
        g = _GUARD.match(rest)
        if not g:
            return ["an ssh rewrite that does not start with the sandbox guard"]
        rest = rest[g.end():]
    keys: dict[str, str] = {}
    while True:
        m = _READ.match(rest)
        w = None if m else _READ_WIN.match(rest)
        if not m and not w:
            break
        if m:
            n, path, key = m.groups()
            if "/../" in path or "/./" in path or \
                    os.path.dirname(os.path.realpath(path)) != os.path.realpath(run_dir):
                problems.append(f"a value is read from {path}, outside the run directory")
        else:
            n, py, script, key, _nonce = w.groups()
            if Path(script).resolve() != (ROOT / "hooks" / "resolve.py").resolve():
                problems.append(f"a value is read by {script}, not by the plugin's resolver")
            if Path(py).resolve() != Path(sys.executable).resolve():
                problems.append(f"the resolver runs under {py}, not the hook's Python")
            m = w
        if n in keys:
            problems.append(f"__ms_{n} is read twice")
        keys[n] = key
        rest = rest[m.end():]
    if not keys:
        problems.append("a rewrite without a read of the value")
    # Claude Code: the exit-0 trap after the reads (maisecrets/exit_wrap.py), once, so a failed output is masked
    from maisecrets import exit_wrap
    if rest.startswith(exit_wrap.trap() + "; "):
        rest = rest[len(exit_wrap.trap()) + 2:]
    if ssh:
        rest, k = _SSH_OPTS.subn("ssh ", rest)
        if k != 1:
            problems.append(f"the ssh options were added {k} times, not once")
    for n, key in keys.items():
        for form in (f"'\"${{__ms_{n}}}\"'", f"\"${{__ms_{n}}}\"", f"${{__ms_{n}}}"):
            rest = rest.replace(form, ph(key))
    if "__ms_" in rest:
        problems.append("a variable the reads did not define")
    if rest != original:
        problems.append(f"the command changed: {original!r} became {rest!r}")
    return problems


def undo_values(node, values: dict[str, str]):
    """Put every value back as its placeholder, in every string of a tool input."""
    if isinstance(node, dict):
        return {k: undo_values(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [undo_values(v, values) for v in node]
    if isinstance(node, str):
        for key, value in sorted(values.items(), key=lambda kv: -len(kv[1])):
            node = node.replace(value, ph(key))
    return node


def reset() -> None:
    for f in ("index.json", "vault.json", "audit.log"):
        try:
            os.unlink(HOME / f)
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


BASH_TEMPLATES = [
    "curl -H 'X-Token: {A}' https://api.example.com/v1/items",
    'curl -H "Authorization: Bearer {A}" https://api.example.com',
    "echo {A} | wc -c",
    'psql "postgres://app:{A}@db.example.com/app" -c "select 1"',
    "export T={A}; ./deploy.sh",
    "T={A} ./deploy.sh --env prod",
    "git clone https://x:{A}@git.example.com/r.git",
    "cat <<EOF > .env\nTOKEN={A}\nEOF",
    "docker login -u ci -p {A} registry.example.com && docker push img",
    "for h in a b; do curl -u " + "u:{A} https://$h.example.com; done",   # assembled: the repo scan flags it
    "printf '%s\\n' {A} {B} > creds.txt",
    "echo '{A}' '{B}'",
    "mysql -u root -p'{A}' -e 'show databases'",
    "( cd /tmp && curl -d token={A} https://x.example.com )",
    "if true; then echo {A}; fi",
    'echo "a {A} b" && echo {B}',
    "curl 'https://x.example.com/?k={A}&z=1'",
    "printf '%s' {A} | ssh prod01 'zgrep -F -f - /var/log/x'",
    "printf '%s' {A} | ssh -p 2222 ops@prod01 'sudo zgrep -hcF -f - /var/log/mail.log'",
    "echo {A} {A} {B}",
]


class ClaudeRewriteTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        reset()
        v = Vault()
        self.values = {}
        for name in ("A", "B"):
            value = "I2v" + name + "-" + "7" * 6 + "q"
            e = v.put(value, "SECRET", "manual", session="S1")
            self.values[e.key] = value
            setattr(self, name, e)

    def pre(self, tool: str, tool_input: dict, client: dict = CLAUDE) -> dict:
        return hooks.pre_tool({"tool_name": tool, "tool_input": tool_input, "session_id": "S1",
                               "transcript_path": "", "cwd": "/", **client})

    def test_no_bash_rewrite_grants_more_than_the_command(self):
        bad, rewritten = [], 0
        for t in BASH_TEMPLATES:
            command = t.format(A=self.A.ref, B=self.B.ref)
            out = self.pre("Bash", {"command": command})
            h = out.get("hookSpecificOutput") or {}
            if h.get("permissionDecision") == "deny" or "updatedInput" not in h:
                continue
            rewritten += 1
            if h.get("permissionDecision") not in (None, "ask"):
                bad.append(f"{t!r}: decision {h.get('permissionDecision')!r}")
            if set(h["updatedInput"]) != {"command"}:
                bad.append(f"{t!r}: fields {sorted(h['updatedInput'])}")
            bad += [f"{t!r}: {p}" for p in undo_bash(command, h["updatedInput"]["command"], hooks._run_dir())]
        self.assertGreaterEqual(rewritten, 15, "the population must reach the rewrite")
        self.assertEqual(bad, [], "\n".join(bad))

    def test_no_mcp_or_file_rewrite_grants_more_than_the_input(self):
        A, B = self.A.ref, self.B.ref
        cases = [
            ("mcp__srv__call", {"token": A, "nested": {"list": [B, "x"], "n": 3}}),
            ("mcp__db__query", {"dsn": f"postgres://u:{A}@h/db", "sql": "select 1"}),
            ("mcp__srv__call", {"headers": [{"name": "Authorization", "value": f"Bearer {A}"}]}),
            ("mcp__srv__call", {"params": json.dumps({"key": A}, ensure_ascii=False)}),
            ("Write", {"file_path": "/tmp/i2.env", "content": f"A={A}\nB={B}\n"}),
            ("Edit", {"file_path": "/tmp/i2.env", "old_string": "A=x", "new_string": f"A={A}"}),
        ]
        bad, rewritten = [], 0
        for tool, ti in cases:
            out = self.pre(tool, ti)
            h = out.get("hookSpecificOutput") or {}
            if "updatedInput" not in h:
                bad.append(f"{tool}: no rewrite ({h.get('permissionDecision')})")
                continue
            rewritten += 1
            if h.get("permissionDecision") not in (None, "ask"):
                bad.append(f"{tool}: decision {h.get('permissionDecision')!r}")
            back = undo_values(h["updatedInput"], {self.A.key: self.values[self.A.key],
                                                   self.B.key: self.values[self.B.key]})
            if back != ti:
                bad.append(f"{tool}: {ti!r} became {back!r}")
        self.assertEqual(bad, [], "\n".join(bad))
        self.assertEqual(rewritten, len(cases))

    def test_a_call_without_a_placeholder_is_not_answered_with_a_grant(self):
        for tool, ti in (("Bash", {"command": "ls -la"}), ("mcp__srv__call", {"q": "x"}),
                         ("Write", {"file_path": "/tmp/i2.txt", "content": "plain"})):
            for client in (CLAUDE, CODEX_P):
                with self.subTest(tool=tool, client=client):
                    h = self.pre(tool, ti, client).get("hookSpecificOutput") or {}
                    self.assertNotIn(h.get("permissionDecision"), ("allow",))
                    self.assertNotIn("updatedInput", h)


@unittest.skipIf(os.name == "nt", "Codex on Windows refuses a shell placeholder (PowerShell quoting is not built)")
class CodexExceptionTests(unittest.TestCase):
    """docs/THREAT-MODEL.md C5: on Codex a rewrite carries "allow", which skips Codex's approval
    prompt. This records the exception; when it stops being true, remove it from the docs."""

    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        reset()
        self.e = Vault().put("I2c-" + "5" * 8, "SECRET", "manual", session="S1")

    def test_codex_gets_allow_with_a_rewrite_and_the_rewrite_itself_adds_nothing(self):
        out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": f"echo {self.e.ref} | wc -c"},
                              "session_id": "S1", "transcript_path": "", "cwd": "/", **CODEX_P})
        h = out["hookSpecificOutput"]
        self.assertEqual(h.get("permissionDecision"), "allow",
                         "Codex no longer gets allow: remove the exception from THREAT-MODEL C5 and README")
        self.assertEqual(undo_bash(f"echo {self.e.ref} | wc -c", h["updatedInput"]["command"], hooks._run_dir()), [])


if __name__ == "__main__":
    unittest.main()
