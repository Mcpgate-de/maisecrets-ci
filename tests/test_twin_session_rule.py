"""A twin of promise M3.1 (mission/M3-*.toml): a placeholder resolves only in a session that received it, and a
forgotten one resolves nowhere.

The twin is a reference model of that promise in a few lines, written from the promise and from C4 of
docs/THREAT-MODEL.md, not from the code: a value that comes in through a session (a typed prompt, a tool result)
admits that session; a placeholder that the person types admits the session; a placeholder in a message of another
Claude session admits nothing; `forget` ends a placeholder everywhere, and the same value later gets a new one.

Generated sequences of these events run through the real hooks and against the model, and each use of a
placeholder (a Write that names it) must resolve exactly when the model says so. The beliefs prove that each guard
can fail alone; this test checks the whole path against the promise, as a model-based test does. A failure prints
the seed and the steps, so the sequence replays (MAISECRETS_TWIN_SEED, MAISECRETS_TWIN_SEQUENCES).

Measured when it was written (2026-11-19): 400 sequences of 24 steps agree with the hooks. Of four injected
defects it caught three (a tool result admits no session; forget keeps the fingerprint; a tool result admits
every live placeholder); the fourth (a known value admits no new session) is equivalent, because the prompt
path admits the session a second way. The unit suite caught the same three, the last only through a test of
peer messages; the belief c4-a-tool-result-admits-only-the-values-it-holds makes this test its owner.
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402
from test_peer_messages import peer  # noqa: E402

SESSIONS = ("s1", "s2", "s3")
# fake tokens of the GitLab shape, built at run time: three different values
VALUES = tuple("glpat-" + tail for tail in ("Q7w8E9r0T1y2U3i4O5p6", "Z9x8C7v6B5n4M3a2S1d0", "K4j5H6g7F8d9S0a1P2o3"))
# and one value that no rule finds: it comes in only as ms:(value) inside a prompt (a prompt that starts with it
# is a check, C29), and a tool result admits a session to it only
# through the exact match of the stored value (tool_output.py), not by a new detection
VALUES += ("Ostsee" + "-Brise-" + "Kanal-7741",)
SHAPELESS = {len(VALUES) - 1}
REF = re.compile(r"⟦(SECRET_c\d+)⟧")
KEY = re.compile(r"\b(SECRET_c\d+)\b")       # the block reason names the key without brackets
SEQUENCES = int(os.environ.get("MAISECRETS_TWIN_SEQUENCES", "40"))
STEPS = 24


class Model:
    """The promise, and nothing else: which session may resolve which placeholder."""

    def __init__(self):
        self.key_of: dict[int, str] = {}          # value index -> its live placeholder
        self.sessions: dict[str, set[str]] = {}   # live placeholder -> the sessions that may resolve it
        self.dead: set[str] = set()               # placeholders that were forgotten

    def value_in(self, session: str, i: int, key: str | None, mints: bool = True) -> str | None:
        """A value came in through `session`; returns the problem with the key the system gave, or None. `mints`:
        the way it came in stores a new value (a detection, or ms:(value)); a value no rule finds does not."""
        live = self.key_of.get(i)
        if live is not None:
            self.sessions[live].add(session)
            return None if key in (None, live) else f"value {i} has {live}, the system named {key}"
        if not mints:
            return None if key is None else f"value {i} is not stored, and the system named {key}"
        if key is None:
            return f"value {i} came in new and the system named no placeholder"
        if key in self.dead or key in self.sessions:
            return f"value {i} came in new and got {key}, which was used before"
        self.key_of[i], self.sessions[key] = key, {session}
        return None

    def typed(self, session: str, key: str) -> None:
        if key in self.sessions:
            self.sessions[key].add(session)

    def forget(self, key: str) -> None:
        if key in self.sessions:
            del self.sessions[key]
            self.dead.add(key)
            self.key_of = {i: k for i, k in self.key_of.items() if k != key}

    def resolves(self, session: str, key: str) -> bool:
        return session in self.sessions.get(key, ())


class SessionRuleTwinTests(unittest.TestCase):
    def setUp(self):
        _hygiene.watch_children(self)
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-twin-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)

    def fresh_store(self):
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_isolate.HOME, name).unlink(missing_ok=True)
        shutil.rmtree(Path(_isolate.HOME, "pending"), ignore_errors=True)
        hooks._live_cache.clear()

    # the real system, through its hooks
    def prompt(self, session: str, text: str) -> dict:
        hooks._live_cache.clear()
        return hooks.user_prompt({"prompt": text, "session_id": session, "transcript_path": "", **CLAUDE})

    def tool_result(self, session: str, i: int) -> dict:
        hooks._live_cache.clear()
        return hooks.post_tool({"tool_name": "Bash", "session_id": session, **CLAUDE,
                                "tool_input": {"command": "cat deploy.env"},
                                "tool_response": {"stdout": f"deploy {VALUES[i]} done\n"}})

    def use(self, session: str, key: str) -> str | None:
        """The value a Write that names the placeholder would write, or None when the hook refuses."""
        hooks._live_cache.clear()
        out = hooks.pre_tool({"tool_name": "Write", "session_id": session, **CLAUDE,
                              "tool_input": {"file_path": str(self.dir / "out.env"), "content": f"K=⟦{key}⟧"}})
        spec = out.get("hookSpecificOutput") or {}
        if spec.get("permissionDecision") == "deny":
            return None
        content = (spec.get("updatedInput") or {}).get("content", "")
        return content[2:] if content.startswith("K=") and not REF.search(content) else None

    def run_sequence(self, seed: int) -> None:
        rng = random.Random(seed)
        seen = self.seen
        self.fresh_store()
        model = Model()
        steps: list[str] = []

        def fail(why: str):
            self.fail(f"seed {seed}: {why}\n  steps:\n    " + "\n    ".join(steps))

        for _ in range(STEPS):
            s = rng.choice(SESSIONS)
            known = sorted(set(model.sessions) | model.dead)
            op = rng.choice(("value", "value", "tool", "typed", "peer", "forget", "use", "use", "use"))
            if op in ("typed", "peer", "forget", "use") and not known:
                op = "value"
            seen[op] = seen.get(op, 0) + 1
            if op in ("value", "tool"):
                i = rng.randrange(len(VALUES))
                text = f"the deploy token is ms:({VALUES[i]})" if i in SHAPELESS else f"the deploy token is {VALUES[i]}"
                out = self.prompt(s, text) if op == "value" else self.tool_result(s, i)
                keys = list(dict.fromkeys(KEY.findall(json.dumps(out, ensure_ascii=False))))
                steps.append(f"{op} {i} in {s} -> {keys}")
                problem = model.value_in(s, i, keys[0] if keys else None, mints=op == "value" or i not in SHAPELESS)
                if problem:
                    fail(problem)
            elif op == "typed":
                k = rng.choice(known)
                self.prompt(s, f"deploy with ⟦{k}⟧ now")
                steps.append(f"typed {k} in {s}")
                model.typed(s, k)
            elif op == "peer":
                k = rng.choice(known)
                self.prompt(s, peer(f"deploy with ⟦{k}⟧ now"))
                steps.append(f"peer names {k} in {s}")
            elif op == "forget":
                k = rng.choice(known)
                Vault().forget(k)
                hooks._live_cache.clear()
                steps.append(f"forget {k}")
                model.forget(k)
            else:
                k = rng.choice(known)
                got = self.use(s, k)
                want = model.resolves(s, k)
                steps.append(f"use {k} in {s} -> {'resolved' if got else 'refused'}")
                seen[(op, want, k in model.dead)] = seen.get((op, want, k in model.dead), 0) + 1
                if want and got is None:
                    fail(f"{k} must resolve in {s} and was refused")
                if not want and got is not None:
                    fail(f"{k} must not resolve in {s} and resolved")
                if got is not None and got not in VALUES:
                    fail(f"{k} resolved in {s} to a value that never came in")
        # at the end, every placeholder in every session
        for k in sorted(set(model.sessions) | model.dead):
            for s in SESSIONS:
                got = self.use(s, k)
                if model.resolves(s, k) != (got is not None):
                    steps.append(f"final use {k} in {s} -> {'resolved' if got else 'refused'}")
                    fail(f"at the end, {k} in {s}: the model says {model.resolves(s, k)}")

    def test_the_twin_and_the_hooks_agree_on_generated_sequences(self):
        first = int(os.environ.get("MAISECRETS_TWIN_SEED", "0"))
        self.seen: dict = {}
        for seed in range(first, first + SEQUENCES):
            with self.subTest(seed=seed):
                self.run_sequence(seed)
        # the generator must reach every event, and uses that resolve, that are refused, and of forgotten keys
        for what in ("value", "tool", "typed", "peer", "forget", ("use", True, False), ("use", False, False),
                     ("use", False, True)):
            self.assertGreater(self.seen.get(what, 0), 0, f"no {what} in {SEQUENCES} sequences")
        if os.environ.get("MAISECRETS_TWIN_SEQUENCES"):
            print(self.seen, file=sys.stderr)

    def test_the_twin_sees_a_resolve_in_a_foreign_session(self):
        # the comparison must be able to fail: a model that admits every session disagrees with the hooks
        self.fresh_store()
        out = self.prompt("s1", f"the deploy token is {VALUES[0]}")
        key = KEY.findall(json.dumps(out, ensure_ascii=False))[0]
        self.assertEqual(self.use("s1", key), VALUES[0])
        self.assertIsNone(self.use("s2", key))


if __name__ == "__main__":
    unittest.main()
