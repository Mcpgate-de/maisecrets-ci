"""Secret destinations, observe mode (Mcpgate-de/maisecrets#13, maisecrets/destinations.py): maisecrets notes where
each stored secret goes, never stops a call for it, keeps `seen` apart from `allowed`, and gives the AI one hint at
the first pattern break on a network destination."""
from __future__ import annotations

import json
import os
import re
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import destinations, hooks, settings  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

CONFIG = Path(HOME, "config.json")
STORE = Path(HOME, "destinations.json")
HINTS = Path(HOME, "hints.json")
OPEN, CLOSE = "⟦", "⟧"        # the placeholder brackets, built so this file holds no placeholder
_SERVED: list[str] = []


def setUpModule():  # noqa: N802 - unittest hook
    _reset()


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    hooks._unserve(list(_SERVED))
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    for f in (STORE, HINTS, Path(HOME, "index.json"), Path(HOME, "vault.json"), Path(HOME, "audit.log")):
        try:
            os.unlink(f)
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


def _secret(value: str = "dest-probe-value-1234567") -> str:
    """A stored value this session may use; returns its placeholder."""
    key = Vault(load_config()).put(value, "SECRET", "test", session="S1").key
    return OPEN + key + CLOSE


def _curl(ref: str, host: str) -> str:
    """A command that sends the value to a host; assembled, so the repository's own scan sees no credential."""
    return "curl -s -u " + "u" + ":" + ref + " https://" + host + "/"


class _LockTakes:
    """The takes of the record's lock in a block (the outer ones; the lock is re-entrant) and the waits that ran out.
    A count says what a fixed time bound said, without the load of the machine in it: a fixed 1.0 s failed under
    load (2026-10-16)."""

    def __enter__(self) -> "_LockTakes":
        self.takes = self.timeouts = 0
        real = destinations._ShortLock.__enter__

        def counting(lock):
            if lock.depth == 0:
                self.takes += 1
            try:
                return real(lock)
            except destinations.LockTimeout:
                self.timeouts += 1
                raise
        self.patch = mock.patch.object(destinations._ShortLock, "__enter__", counting)
        self.patch.start()
        return self

    def __exit__(self, *exc) -> None:
        self.patch.stop()


def _norm(out: dict, ref: str) -> str:
    """An answer with the parts that differ per call made equal: FIFO paths, nonces and the key itself."""
    text = json.dumps(out, sort_keys=True).replace(_key(ref), "KEY")
    text = re.sub(r"cat '?[^)'\"\s]+", "cat FIFO", text)
    text = re.sub(r"--grant [A-Za-z0-9_-]+", "--grant N", text)      # the Windows path: a one-time grant token
    return re.sub(r"[0-9a-f]{16,}", "N", text)


def _key(ref: str) -> str:
    return ref.strip(OPEN + CLOSE)


_CALLS = []          # the call ids _pre handed out: a real client sends one in PreToolUse and PostToolUse


def _pre(tool: str, tool_input: dict, client: dict = CLAUDE, **extra) -> dict:
    extra.setdefault("tool_use_id", f"auto-{len(_CALLS)}")
    _CALLS.append(extra["tool_use_id"])
    out = hooks.pre_tool({"tool_name": tool, "tool_input": tool_input, "session_id": "S1", **client, **extra})
    cmd = out.get("hookSpecificOutput", {}).get("updatedInput", {}).get("command", "")
    _SERVED.extend(re.findall(r"\$\(cat '?([^')]+)'?\)", cmd if isinstance(cmd, str) else ""))
    return out


def _ran(tool: str, tool_input: dict, client: dict = CLAUDE, **extra) -> dict:
    """A call that ran: its PreToolUse, then the end of the same call commits its destinations (the PostToolUse
    path itself is tested in SeenOnlyAfterTheCall). Returns the PreToolUse answer."""
    out = _pre(tool, tool_input, client, **extra)
    hooks._commit_destinations({"session_id": "S1", **client, **{k: v for k, v in extra.items() if k == "agent_id"},
                                "tool_use_id": _CALLS[-1]})
    return out


def _post(command: str = "true", client: dict = CLAUDE, **extra) -> dict:
    """The end of the last call _pre handed out, unless the test names another id."""
    if _CALLS:
        extra.setdefault("tool_use_id", _CALLS[-1])
    return hooks._post_tool_guarded({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1",
                                     "tool_input": {"command": command}, **client, **extra,
                                     "tool_response": {"stdout": "ok", "stderr": ""}})


def _typed(session: str = "S1") -> None:
    hooks.user_prompt({"prompt": "go on", "session_id": session, **CLAUDE})


def _seen(ref: str) -> dict:
    return destinations.of(_key(ref))["seen"]


class Recording(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_each_resolve_path_notes_its_destination_and_seen_is_never_allowed(self):
        ref = _secret()
        _ran("Bash", {"command": f"curl -s -H 'Authorization: Bearer {ref}' https://API.example.com/v1/x"})
        _ran("mcp__gw__gitlab_write_actions", {"action": "create_issue", "token": ref})
        _ran("mcp__multi__smart_actions", {"service": "jira", "token": ref})
        _ran("Write", {"file_path": str(Path.home() / "proj" / ".env"), "content": f"T={ref}\n"})
        _ran("Bash", {"command": f"printf '%s' {ref} > /tmp/dest-probe.txt"})
        seen = _seen(ref)
        labels = {d["label"]: d["kind"] for d in seen.values()}
        self.assertEqual(labels, {"api.example.com": "network", "MCP gw · gitlab_write_actions": "network",
                                  "MCP multi · smart_actions · jira": "network", "a file in ~/proj/": "local",
                                  "a command on this computer": "local"}, labels)
        self.assertEqual(destinations.of(_key(ref))["allowed"], {}, "a destination that was seen is never allowed")
        self.assertNotIn("create_issue", json.dumps(seen), "the action is an operation, not a destination")
        self.assertNotIn("dest-probe-value", STORE.read_text(), "the store never holds a value")

    def test_an_ssh_host_is_a_network_destination(self):
        self.assertEqual(destinations.destinations_of("Bash", {"command": "x"}, ["root@web1:2222"]),
                         [("network", "ssh root@web1:2222")])

    def test_observing_never_changes_the_answer_and_a_failing_record_never_stops_the_call(self):
        ref = _secret()
        call = {"command": _curl(ref, "api.example.com")}
        observed = _norm(_ran("Bash", call), ref)
        self.assertTrue(destinations.of(_key(ref))["seen"], "premise: observe noted the call")
        _reset(secret_destinations="off")
        ref2 = _secret()
        off = _norm(_ran("Bash", {"command": call["command"].replace(ref, ref2)}), ref2)
        self.assertEqual(observed, off, "the whole answer is the same with the record on and off")
        self.assertFalse(STORE.exists() and destinations.of(_key(ref2))["seen"], "off notes nothing")
        _reset()
        ref3 = _secret()
        # pend: a client with a call id, as Claude Code and Codex are, records through it in PreToolUse
        with mock.patch.object(destinations, "pend", side_effect=RuntimeError("disk")):
            failed = _norm(_ran("Bash", {"command": call["command"].replace(ref, ref3)}), ref3)
        self.assertEqual(failed, observed, "a record that fails leaves the answer as it is")

    def test_a_busy_record_costs_a_call_one_short_wait(self):
        # codex review of 0.6.7: each key waited for the 6 s vault lock, two keys 12 s, past the hook's watchdog.
        # The claim is counted: one wait of the short lock per call, whatever the number of keys. A fixed bound on
        # what the busy lock adds (1.0 s) failed under load (2026-10-16); 5 s over the same call with a free lock
        # only catches the wait of the vault lock (6 s)
        import subprocess
        self.assertLessEqual(destinations._ShortLock.LOCK_DEADLINE, 0.5)
        free = [_secret(f"dest-free-value-{i}xxxxxxxxx{i}") for i in range(8)]
        started = time.monotonic()
        _ran("Bash", {"command": "; ".join(_curl(r, "api.example.com") for r in free)})
        baseline = time.monotonic() - started
        holder = subprocess.Popen([sys.executable, "-c", (       # the same lock call as vault._Lock, per platform
            "import os, sys, time; fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
            "if os.name == 'nt':\n    import msvcrt; msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)\n"
            "else:\n    import fcntl; fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "print('held', flush=True); time.sleep(8)"),
            str(Path(HOME, ".destinations.lock"))], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")
            refs = [_secret(f"dest-busy-value-{i}xxxxxxxxx{i}") for i in range(8)]
            with _LockTakes() as lock:
                started = time.monotonic()
                out = _ran("Bash", {"command": "; ".join(_curl(r, "api.example.com") for r in refs)})
                took = time.monotonic() - started
        finally:
            holder.kill()
            holder.wait()
        self.assertIn("updatedInput", out["hookSpecificOutput"], "the call still gets its values")
        self.assertEqual(lock.timeouts, 1, "one wait for the busy record, not one per key")
        self.assertLess(took - baseline, 5.0,
                        f"a busy record added {took - baseline:.1f}s for 8 keys ({took:.1f}s against {baseline:.1f}s)")

    def test_a_damaged_record_is_kept_aside_and_never_breaks_the_list(self):
        from maisecrets import cli
        ref = _secret()
        aside = Path(HOME, "destinations.json.corrupt")
        STORE.write_text("{not json")
        _ran("Bash", {"command": _curl(ref, "api.example.com")})       # a record written by a call
        self.assertEqual(aside.read_text(), "{not json", "the damaged file is kept aside, not overwritten")
        self.assertTrue(_seen(ref), "and a new record begins")
        STORE.write_text("{not json either")
        with mock.patch("sys.stdout"):
            self.assertEqual(cli.main(["list"]), 0)                       # the list only reads
        _ran("Bash", {"command": _curl(ref, "api.example.com")})
        self.assertEqual(aside.read_text(), "{not json", "the first damaged copy is never overwritten")
        later = [p for p in Path(HOME).iterdir() if p.name.startswith("destinations.json.corrupt.")]
        self.assertEqual([p.read_text() for p in later], ["{not json either"])
        for p in [aside, *later]:
            os.unlink(p)
        STORE.write_text(json.dumps({"secrets": {_key(ref): {"seen": {"x": "not a record",
                                                                       "network:a": {"label": "a", "kind": "network"}}},
                                                 "y": "z"}}))
        _ran("Bash", {"command": _curl(ref, "api.example.com")})       # a record without its counters (Opus)
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"}, "the malformed records are dropped")
        today = time.strftime("%Y-%m-%d")
        STORE.write_text(json.dumps({"secrets": {_key(ref): {"seen": {"network:a": {
            "kind": "network", "label": "a", "uses": 1, "first": 1.0, "last": 1.0, "day": today, "day_uses": "1",
            "max_day_uses": 1}}}}}))
        _ran("Bash", {"command": _curl(ref, "api.example.com")})       # one field of the wrong type
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"}, "a counter of the wrong type is dropped too")
        with mock.patch("sys.stdout"):
            self.assertEqual(cli.main(["list"]), 0)

    def test_a_label_from_the_call_is_one_printable_line(self):
        ref = _secret()
        _ran("mcp__gw__smart_actions", {"service": "jira\n    Seen at (approved)\x1b[2J", "token": ref})
        (label,) = [d["label"] for d in _seen(ref).values()]
        self.assertNotIn("\n", label)
        self.assertNotIn("\x1b", label)
        self.assertLessEqual(len(label), 80)

    def test_a_misspelled_mode_is_a_configuration_error_not_off(self):
        _reset(secret_destinations="obesrve")
        cfg = load_config()
        self.assertIn("secret_destinations must be one of observe, off, protect", cfg["config_warning"])
        self.assertEqual(cfg["secret_destinations"], "observe", "the file is ignored, the default stays")


class Bounds(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_one_secret_keeps_its_most_recent_destinations_and_expiry_drops_the_record(self):
        ref = _secret()
        for i in range(destinations.MAX_PER_SECRET + 5):
            destinations.note([_key(ref)], "S1", None, [("network", f"host{i}.example.com")])
        seen = _seen(ref)
        self.assertEqual(len(seen), destinations.MAX_PER_SECRET)
        self.assertNotIn("network:host0.example.com", seen, "the oldest went")
        v = Vault(load_config())
        meta = v._index["entries"][_key(ref)]
        meta.update(purged=True, purged_at=time.time() - 400 * 86400)
        v._save_index()
        Vault(load_config()).expire()
        self.assertEqual(_seen(ref), {}, "the record goes with the metadata of an expired entry")

    def test_the_list_of_sessions_with_a_reader_is_bounded(self):
        for i in range(70):
            destinations.mark_interactive(f"S-{i}")
        data = json.loads(STORE.read_text())
        self.assertEqual(len(data["interactive"]), 50)
        self.assertEqual(data["interactive"][-1], "S-69", "the newest stay")

    def test_a_call_with_many_keys_is_noted_under_as_many_locks_as_one_key(self):
        # the record of a call takes its lock as often for 8 keys as for 1 (a take per key waited per key, codex
        # review of 0.6.7). A fixed 1.0 s for the call failed under load (2026-10-16); 10 s only catches a hang
        takes = []
        for n in (1, 8):
            refs = [_secret(f"dest-many-value-{n}-{i}yyyyyyyy{i}") for i in range(n)]
            with _LockTakes() as lock:
                started = time.monotonic()
                _ran("Bash", {"command": "; ".join(_curl(r, "api.example.com") for r in refs)})
                self.assertLess(time.monotonic() - started, 10.0)
            self.assertTrue(all(_seen(r) for r in refs))
            takes.append(lock.takes)
        self.assertGreater(takes[0], 0, "the count sees the lock")
        self.assertEqual(takes[0], takes[1])

    def test_wipe_everything_takes_the_record(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "api.example.com")})
        with mock.patch.object(destinations, "wipe", wraps=destinations.wipe) as wiped:
            from maisecrets import vault as vault_mod
            vault_mod.wipe_everything(load_config())
        self.assertEqual(wiped.call_count, 1)
        self.assertFalse(STORE.exists())

    def test_a_secret_shape_or_free_text_never_becomes_a_label(self):
        ref = _secret()
        token = "ghp_" + "aB3dE5fG7h" + "J9kL1mN2pQ" + "4rS6tU8vW0" + "xY2zA4"     # 40: it fits the name rule
        _ran("mcp__gw__x_write", {"service": "token=" + token, "token": ref})
        _ran("Bash", {"command": _curl(ref, "api.example.com") + " # " + token})
        self.assertNotIn(token, STORE.read_text())
        self.assertIn("MCP gw · x_write", {d["label"] for d in _seen(ref).values()})
        _ran("mcp__gw__y_write", {"service": token, "token": ref})     # a secret shape that reads as a name
        self.assertNotIn(token, STORE.read_text())
        self.assertIn("MCP gw · y_write · <hidden>", {d["label"] for d in _seen(ref).values()})


class RoundThree(unittest.TestCase):
    """The repairs of review round 3 (codex, Opus), each against the code it names."""

    def setUp(self):
        _reset()

    def _break(self, agent):
        destinations.mark_interactive("S1")
        for _ in range(destinations.ESTABLISHED_USES):
            destinations.note(["K1"], "S1", None, [("network", "api.example.com")])
        destinations.note(["K1"], "S1", agent, [("network", "other.example.net")])
        return json.loads(STORE.read_text())["pending_hint"]

    def test_note_alone_keeps_a_subagent_break_from_the_hint(self):
        self.assertEqual(self._break("sub1"), {}, "a break in a subagent waits for no hint")
        _reset()
        self.assertIn("S1", self._break(None), "the premise: the same break in the main thread does")

    def test_only_a_prompt_the_person_typed_marks_the_session(self):
        hooks.user_prompt({"prompt": "go on", "session_id": "S7", **CLAUDE, "source": "sdk"})
        self.assertFalse(STORE.exists() and "S7" in json.loads(STORE.read_text())["interactive"])
        hooks.user_prompt({"prompt": "go on", "session_id": "S7", **CLAUDE, "source": "user"})
        self.assertIn("S7", json.loads(STORE.read_text())["interactive"])

    def test_with_the_setting_off_a_prompt_writes_no_record(self):
        _reset(secret_destinations="off")
        _typed("S6")
        self.assertFalse(STORE.exists())

    def test_a_deeply_nested_file_never_blocks_a_prompt_or_a_call(self):
        STORE.write_text("[" * 100_000)
        out = hooks.user_prompt({"prompt": "go on", "session_id": "S5", **CLAUDE})
        self.assertNotEqual(out.get("decision"), "block", out)
        from maisecrets import cli
        with mock.patch("sys.stdout"):
            self.assertEqual(cli.main(["list"]), 0, "the list reads past it")
        ref = _secret()
        self.assertIn("updatedInput", json.dumps(_ran("Bash", {"command": _curl(ref, "api.example.com")})))
        copies = list(Path(HOME).glob("destinations.json.corrupt*"))
        self.assertEqual(len(copies), 1, "the nested file is damage: it is moved aside, and the record goes on")
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"})
        for p in copies:
            os.unlink(p)

    def test_a_flag_or_a_number_that_is_no_number_is_no_record(self):
        good = {"kind": "network", "label": "a", "uses": 1, "first": 1.0, "last": 1.0, "day": "2026-01-01",
                "day_uses": 1, "max_day_uses": 1}
        STORE.write_text(json.dumps({"secrets": {"K1": {"seen": {
            "network:a": good, "network:b": {**good, "label": "b", "uses": True},
            "network:c": {**good, "label": "c", "last": float("inf")},
            "network:d": {**good, "label": "d", "first": float("nan")}}}}}))
        self.assertEqual(set(destinations.of("K1")["seen"]), {"network:a"})

    def test_a_record_read_from_disk_keeps_the_cap(self):
        good = {"kind": "network", "label": "a", "uses": 1, "first": 1.0, "day": "2026-01-01", "day_uses": 1,
                "max_day_uses": 1}
        seen = {f"network:h{i}": {**good, "label": f"h{i}", "last": float(i)} for i in range(60)}
        STORE.write_text(json.dumps({"secrets": {"K1": {"seen": seen}}}))
        kept = destinations.of("K1")["seen"]
        self.assertEqual(len(kept), destinations.MAX_PER_SECRET)
        self.assertIn("network:h59", kept)
        self.assertNotIn("network:h0", kept, "the oldest go")

    def test_a_damaged_file_that_cannot_be_moved_aside_is_left_alone(self):
        STORE.write_text("{damaged")
        real = os.replace

        def replace(src, dst):           # only the move aside fails; the atomic write of the store still works
            if "corrupt" in str(dst):
                raise OSError("busy")
            return real(src, dst)
        with mock.patch("maisecrets.destinations.os.replace", side_effect=replace):
            self.assertFalse(destinations.note(["K1"], "S1", None, [("network", "api.example.com")]))
        self.assertEqual(STORE.read_text(), "{damaged")
        os.unlink(STORE)

    def test_an_aside_copy_is_never_overwritten_and_wipe_takes_them_all(self):
        for text in ("{one", "{two", "{three"):
            STORE.write_text(text)
            destinations.note(["K1"], "S1", None, [("network", "api.example.com")])
        copies = sorted(p.read_text() for p in Path(HOME).glob("destinations.json.corrupt*"))
        self.assertEqual(copies, ["{one", "{three", "{two"], "three damaged files in one second, three copies")
        self.assertTrue(destinations.wipe())
        self.assertEqual(list(Path(HOME).glob("destinations.json*")), [])

    def test_wipe_everything_reports_a_record_it_could_not_delete(self):
        with mock.patch.object(destinations, "wipe", return_value=False):
            from maisecrets import vault as vault_mod
            _, problems = vault_mod.wipe_everything(load_config())
        self.assertIn("destinations.json not deleted", problems)

    def test_forget_of_an_unknown_key_still_takes_an_orphan_record(self):
        destinations.note(["SECRET_orphan"], "S1", None, [("network", "api.example.com")])
        self.assertEqual(Vault(load_config()).forget("SECRET_orphan"), "unknown")
        self.assertEqual(destinations.of("SECRET_orphan")["seen"], {})

    def test_a_lock_file_that_cannot_be_opened_leaves_no_lock_counted(self):
        with mock.patch("maisecrets.vault.os.open", side_effect=OSError("no")):
            self.assertFalse(destinations.note(["K1"], "S1", None, [("network", "api.example.com")]))
        self.assertEqual(destinations._LOCK.depth, 0, "a later call must take the lock again")
        self.assertTrue(destinations.note(["K1"], "S1", None, [("network", "api.example.com")]) is not None)
        self.assertEqual(set(destinations.of("K1")["seen"]), {"network:api.example.com"})


class Hint(unittest.TestCase):
    def setUp(self):
        _reset()

    def _establish(self, ref: str, host: str = "api.example.com", n: int = destinations.ESTABLISHED_USES) -> None:
        for _ in range(n):
            _ran("Bash", {"command": _curl(ref, host)})

    def test_the_first_pattern_break_on_a_network_destination_gives_one_hint(self):
        _typed()
        ref = _secret()
        self._establish(ref)
        self.assertNotIn("maisecrets notes", json.dumps(_post()), "an established destination alone is no break")
        _ran("Bash", {"command": _curl(ref, "other.example.net")})
        out = _post()
        text = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("named a host that this secret was not used with before", text)
        self.assertIn("/maisecrets:list", text)
        self.assertNotIn("other.example.net", text, "the hint names no destination")
        self.assertNotIn(_key(ref), text, "and no secret")
        # once, globally: a second break, another secret, another session
        ref2 = _secret("dest-probe-value-other-99")
        self._establish(ref2, "b.example.org")
        _ran("Bash", {"command": _curl(ref2, "c.example.org")})
        self.assertNotIn("maisecrets notes", json.dumps(_post()))

    def test_one_use_short_of_the_threshold_is_no_break(self):
        _typed()
        ref = _secret()
        self._establish(ref, n=destinations.ESTABLISHED_USES - 1)
        _ran("Bash", {"command": _curl(ref, "other.example.net")})
        self.assertNotIn("maisecrets notes", json.dumps(_post()))

    def test_a_local_use_never_gives_the_hint(self):
        _typed()
        ref = _secret()
        self._establish(ref)
        _ran("Write", {"file_path": "/tmp/dest-probe/.env", "content": f"T={ref}\n"})
        _ran("Bash", {"command": f"printf '%s' {ref} > /tmp/dest-probe.txt"})
        self.assertNotIn("maisecrets notes", json.dumps(_post()))
        self.assertNotIn("S1", json.loads(STORE.read_text())["pending_hint"])

    def test_a_prompt_in_a_subagent_does_not_make_the_session_interactive(self):
        hooks.user_prompt({"prompt": "go on", "session_id": "S9", "agent_id": "sub1", **CLAUDE})
        self.assertNotIn("S9", json.loads(STORE.read_text()).get("interactive", []) if STORE.exists() else [])
        _typed("S9")
        self.assertIn("S9", json.loads(STORE.read_text())["interactive"], "the premise: a typed prompt marks it")

    def test_each_subagent_guard_holds_alone(self):
        # Opus: the guard in note() and the one in the hint path masked each other; each must hold without the other
        for leave_out in ("note", "hint"):
            with self.subTest(leave_out):
                _reset()
                _typed()
                ref = _secret()
                self._establish(ref)
                if leave_out == "note":
                    real = destinations.note
                    with mock.patch.object(destinations, "note", lambda k, s, a, d: real(k, s, None, d)):
                        _ran("Bash", {"command": _curl(ref, "other.example.net")}, agent_id="sub1")
                    self.assertNotIn("maisecrets notes", json.dumps(_post(agent_id="sub1")))
                else:
                    _ran("Bash", {"command": _curl(ref, "other.example.net")}, agent_id="sub1")
                    with mock.patch.object(destinations, "take_pending", return_value=True):
                        self.assertNotIn("maisecrets notes", json.dumps(_post(agent_id="sub1")))

    def test_off_takes_no_lock_after_a_call(self):
        _reset(secret_destinations="off")
        with mock.patch.object(destinations, "take_pending") as taken:
            _post()
        self.assertEqual(taken.call_count, 0)

    def test_no_hint_in_a_subagent_without_a_typed_prompt_after_a_decision_or_with_tips_off(self):
        for why, setup, extra in (("no typed prompt", lambda: None, {}),
                                  ("a subagent", _typed, {"agent_id": "sub1"}),
                                  ("decided", lambda: (_typed(), _reset_keep(secret_destinations="observe")), {}),
                                  ("tips off", lambda: (_typed(), _reset_keep(tips=False)), {})):
            with self.subTest(why):
                _reset()
                setup()
                ref = _secret()
                self._establish(ref)
                _ran("Bash", {"command": _curl(ref, "other.example.net")}, **extra)
                self.assertNotIn("maisecrets notes", json.dumps(_post(**extra)))

    def test_codex_gets_the_hint_in_its_block_answer(self):
        _typed()
        ref = _secret()
        self._establish(ref)
        _ran("Bash", {"command": _curl(ref, "other.example.net")})
        result = {"decision": "block", "reason": "[maisecrets: the command ran and finished]\n\nok"}
        with mock.patch.object(hooks, "post_tool", return_value=result):
            out = _post(client=CODEX)
        self.assertIn("maisecrets: set secret_destinations observe", out["reason"])


def _reset_keep(**user) -> None:
    cfg = json.loads(CONFIG.read_text())
    cfg.update(user)
    CONFIG.write_text(json.dumps(cfg))


class Shown(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_the_list_says_record_not_permission_and_marks_what_is_new(self):
        from maisecrets import cli
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "api.example.com")})
        _ran("Write", {"file_path": "/tmp/dest-probe/x.cfg", "content": ref})

        def listing() -> str:
            with mock.patch("sys.stdout") as stdout:
                cli.main(["list"])
            return "".join(c.args[0] for c in stdout.write.call_args_list)
        first = listing()
        self.assertIn("Sent to (a record only; it allows nothing)", first)
        self.assertIn("Used on this computer", first)
        self.assertIn("api.example.com", first)
        self.assertNotIn("allowed", first.lower(), "observe shows no permission at all")
        # `new` is the age of the destination, not state the list writes: the model runs the list too (Opus)
        data = json.loads(STORE.read_text())
        data["secrets"][_key(ref)]["seen"]["network:api.example.com"]["first"] = time.time() - 2 * 86400
        STORE.write_text(json.dumps(data))
        before = STORE.read_text()
        second = listing()
        self.assertEqual(STORE.read_text(), before, "showing the list changes nothing")
        self.assertFalse(next(ln for ln in second.splitlines() if "api.example.com" in ln).rstrip().endswith("new"))
        _ran("Bash", {"command": _curl(ref, "second.example.com")})
        third = listing()
        line = next(ln for ln in third.splitlines() if "second.example.com" in ln)
        self.assertTrue(line.rstrip().endswith("new"), line)

    def test_forget_and_wipe_remove_the_record(self):
        from maisecrets import cli
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "api.example.com")})
        self.assertTrue(_seen(ref))
        Vault(load_config()).forget(_key(ref))
        self.assertEqual(_seen(ref), {})
        ref = _secret("dest-forget-value-2222222")
        _ran("Bash", {"command": _curl(ref, "api.example.com")})
        with mock.patch.object(destinations, "forget", return_value=False), mock.patch("sys.stdout") as stdout:
            cli.main(["forget", _key(ref)])
        self.assertIn("could not be deleted now", "".join(c.args[0] for c in stdout.write.call_args_list))
        self.assertTrue(destinations.wipe())
        self.assertFalse(STORE.exists())

    def test_the_settings_card_names_the_mode_and_what_was_seen(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "api.example.com")})
        text = settings.render()
        self.assertIn("Where secrets were sent · observe · not decided", text)
        self.assertIn("Seen so far: 1 secret(s), 1 destination(s), 0 with more than one.", text)
        self.assertIn("protect would have asked about 0 time(s) in the last 1 day(s), for 0 secret(s): an "
                      "estimate", text)
        self.assertIn("Ask before a new host: /maisecrets:settings secret_destinations protect", text)
        self.assertEqual(settings.parse_prompt("/maisecrets:settings secret_destinations protect"),
                         ("secret_destinations", "protect"))
        self.assertTrue(settings.apply_typed("secret_destinations", "protect")[0])
        text = settings.render()
        self.assertIn("Where secrets were sent · protect · set by you", text)
        self.assertIn("protect would have asked about 0 time(s)", text)
        self.assertNotIn("Ask before a new host:", text)
        self.assertIn("takes observe, protect, off", settings.apply_typed("secret_destinations", "ask")[1])


class WouldHaveAsked(unittest.TestCase):
    """The settings card says how often asking before a new host would have asked, from the person's own record."""

    def setUp(self):
        _reset()

    def _at(self, days_ago: float, key: str, *found: tuple[str, str]) -> None:
        with mock.patch.object(destinations.time, "time", return_value=self.now - days_ago * 86400):
            destinations.note([key], "S1", None, list(found))

    def test_a_new_host_of_a_used_secret_asks_and_its_first_hosts_do_not(self):
        self.now = time.time()
        self._at(40, "A", ("network", "one.example.com"))
        self._at(35, "A", ("network", "old.example.com"))                 # before the window
        self._at(10, "A", ("network", "two.example.com"))
        self._at(5, "A", ("network", "three.example.com"), ("network", "four.example.com"))   # one call
        self._at(4, "A", ("network", "two.example.com"), ("local", "a file in ~/x/"))          # nothing new
        self._at(1, "B", ("network", "one.example.com"), ("network", "two.example.com"))      # its first call
        self._at(1, "C", ("local", "a command on this computer"))
        self._at(0.5, "C", ("network", "one.example.com"))     # after a local first call: a new host asks
        self.assertEqual(destinations.would_have_asked(now=self.now), (3, 2, 30))
        self._at(0.2, "B", ("network", "five.example.com"))
        self.assertEqual(destinations.would_have_asked(now=self.now), (4, 3, 30))

    def test_the_days_end_where_the_record_begins(self):
        self.assertEqual(destinations.would_have_asked(), (0, 0, 0), "no record, no period")
        self.assertNotIn("protect would have asked", settings.render(), "no record, no count")
        self.now = time.time()
        self._at(2.5, "A", ("local", "a file in ~/x/"))
        self._at(1, "A", ("network", "one.example.com"))
        self._at(0.5, "A", ("network", "two.example.com"))
        self.assertEqual(destinations.would_have_asked(now=self.now), (2, 1, 3), "the local call came first")


if __name__ == "__main__":
    unittest.main()


def _decision(out: dict) -> str | None:
    return out.get("hookSpecificOutput", {}).get("permissionDecision")


class Protect(unittest.TestCase):
    """secret_destinations protect: a secret that goes to a network host it never went to asks first (Claude Code),
    or is refused before any value is resolved (Codex). The hosts of its first call are its own."""

    def setUp(self):
        _reset(secret_destinations="protect")

    def test_a_new_host_asks_until_a_call_to_it_ran(self):
        ref = _secret()
        self.assertIsNone(_decision(_ran("Bash", {"command": _curl(ref, "one.example.com")})), "its first host")
        self.assertIsNone(_decision(_ran("Bash", {"command": _curl(ref, "one.example.com")})), "a known host")
        out = _pre("Bash", {"command": _curl(ref, "two.example.com")})
        self.assertEqual(_decision(out), "ask")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("never used with: two.example.com.", reason)
        self.assertIn("updatedInput", out["hookSpecificOutput"], "the person who says yes runs the real call")
        self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "two.example.com")})), "ask",
                         "a declined call (no end of the call) leaves the host new")
        self.assertEqual(_decision(_ran("Bash", {"command": _curl(ref, "two.example.com")})), "ask")
        self.assertIsNone(_decision(_ran("Bash", {"command": _curl(ref, "two.example.com")})),
                          "a call that ran makes the host known")

    def test_only_the_new_host_of_a_call_is_named(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        out = _pre("Bash", {"command": _curl(ref, "one.example.com") + " https://three.example.com/"})
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("never used with: three.example.com.", reason)
        self.assertNotIn("one.example.com", reason)

    @unittest.skipIf(os.name == "nt", "Codex on Windows refuses a shell placeholder (PowerShell quoting is not built)")
    def test_codex_refuses_a_new_host_before_any_value_is_resolved(self):
        ref = _secret()
        self.assertEqual(_decision(_ran("Bash", {"command": _curl(ref, "one.example.com")}, CODEX)), "allow")
        audit = Path(HOME, "audit.log")
        before = audit.read_text() if audit.exists() else ""
        self.assertIn(_key(ref), before, "premise: a use that ran has its audit line")
        out = _pre("Bash", {"command": _curl(ref, "two.example.com")}, CODEX)
        self.assertEqual(_decision(out), "deny")
        self.assertIn("Codex cannot ask the user first", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertNotIn("updatedInput", out["hookSpecificOutput"])
        self.assertEqual(audit.read_text() if audit.exists() else "", before, "no use was recorded")
        self.assertNotIn("network:two.example.com", json.dumps(destinations._load()["pending_calls"]))

    def test_an_mcp_tool_asks_and_a_file_never_does(self):
        ref = _secret()
        _ran("mcp__gw__gitlab_write_actions", {"token": ref})
        self.assertIsNone(_decision(_ran("mcp__gw__gitlab_write_actions", {"token": ref})))
        out = _pre("mcp__gw__jira_write_actions", {"token": ref})
        self.assertEqual(_decision(out), "ask")
        self.assertIn("MCP gw · jira_write_actions", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertEqual(_decision(_pre("mcp__gw__jira_write_actions", {"token": ref}, CODEX)), "deny")
        out = _ran("Write", {"file_path": str(Path.home() / "proj" / ".env"), "content": f"T={ref}\n"})
        self.assertIsNone(_decision(out), "a file is a local use")

    def test_a_record_that_cannot_be_read_asks(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        STORE.write_text("{not json")
        self.addCleanup(lambda: [p.unlink() for p in Path(HOME).glob("destinations.json.corrupt*")])
        self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")})), "ask")

    @unittest.skipIf(os.name == "nt", "the ssh route is POSIX only")
    def test_a_new_ssh_host_asks_where_the_ssh_route_would_pass(self):
        ref = _secret()

        def ssh(host: str) -> str:
            return f"printf '%s' {ref} | ssh {host} 'grep -F -f - /var/log/app.log'"
        first = _ran("Bash", {"command": ssh("one.example.com")})
        self.assertIsNone(_decision(first), "premise: the automatic ssh route passes its first host")
        self.assertIn("updatedInput", first["hookSpecificOutput"])
        out = _pre("Bash", {"command": ssh("two.example.com")})
        self.assertEqual(_decision(out), "ask")
        self.assertIn("never used with: ssh two.example.com.", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_the_list_says_the_known_hosts_ask_no_more(self):
        from maisecrets import cli
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        with mock.patch("sys.stdout") as stdout:
            cli.main(["list"])
        text = "".join(c.args[0] for c in stdout.write.call_args_list)
        self.assertIn("Sent to (protect asks before a host not listed, or one cut with ...)", text)
        self.assertNotIn("it allows nothing", text)

    def test_a_secret_used_only_on_this_computer_asks_at_its_first_host(self):
        ref = _secret()
        _ran("Write", {"file_path": str(Path.home() / "proj" / ".env"), "content": f"T={ref}\n"})
        self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")})), "ask")
        self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")}, CODEX)), "deny")

    def test_a_parallel_first_call_asks(self):
        ref = _secret()
        self.assertIsNone(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")})), "the first call")
        self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "two.example.com")})), "ask",
                         "a second call before the first ran claims no first call of its own")

    def test_a_first_call_holds_its_claim_while_it_pends_and_two_checks_before_it_pend_share_one(self):
        ref = _secret()
        found = [("network", "one.example.com", True)]
        self.assertEqual(destinations.new_hosts([_key(ref)], found), [], "the first check claims the first call")
        self.assertEqual(destinations.new_hosts([_key(ref)], found), ["one.example.com"],
                         "a second check before the first call pends finds the claim")
        _reset(secret_destinations="protect")
        ref = _secret("dest-probe-value-1111111")
        self.assertIsNone(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")})), "pends, not yet ran")
        later = time.time() + destinations.CLAIM_SECONDS + 60
        with mock.patch.object(destinations.time, "time", return_value=later):
            out = _pre("Bash", {"command": _curl(ref, "two.example.com")})
        self.assertEqual(_decision(out), "ask", "the pending first call still holds the key after the claim time")

    def test_a_label_that_does_not_name_its_host_never_counts_as_known(self):
        ref = _secret()
        long_host = "a" * 60 + ".b" * 20 + ".example.com"
        _ran("Bash", {"command": _curl(ref, long_host)})
        _ran("Bash", {"command": _curl(ref, long_host)})
        self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, long_host)})), "ask", "cut at 80 characters")
        tool = "mcp__gw__smart_actions"
        _ran(tool, {"token": ref})
        self.assertIsNone(_decision(_ran(tool, {"token": ref})), "premise: the bare tool is known")
        for bad in ("ji ra", 0, [], ""):
            self.assertEqual(_decision(_pre(tool, {"service": bad, "token": ref})), "ask",
                             f"a service field that is no name ({bad!r}) would share the label of the bare tool")
        _ran(tool, {"service": "gitlab", "provider": "a", "token": ref})
        self.assertIsNone(_decision(_ran(tool, {"service": "gitlab", "provider": "a", "token": ref})))
        self.assertEqual(_decision(_pre(tool, {"service": "gitlab", "provider": "b", "token": ref})), "ask",
                         "both fields name the destination")
        self.assertEqual(_decision(_pre(tool + "__other", {"token": ref})), "ask",
                         "a tool whose name goes on after __ is another tool")

    def test_local_uses_that_fill_the_record_do_not_make_a_secret_new(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        for i in range(destinations.MAX_PER_SECRET):
            destinations.note([_key(ref)], "S1", None, [("local", f"a file in ~/p{i}/")])
        self.assertFalse([d for d in _seen(ref).values() if d["kind"] == "network"], "premise: the host fell out")
        self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "two.example.com")})), "ask")

    def test_a_record_that_parses_but_lost_part_of_a_key_asks(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        data = json.loads(STORE.read_text())
        data["secrets"][_key(ref)]["seen"] = "damaged"
        STORE.write_text(json.dumps(data))
        self.addCleanup(lambda: [p.unlink() for p in Path(HOME).glob("destinations.json.corrupt*")])
        out = _pre("Bash", {"command": _curl(ref, "one.example.com")})
        self.assertEqual(_decision(out), "ask")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("one.example.com (the destination record could not be read", reason)
        self.assertNotIn("never used with", reason, "a known host is not called new")

    def test_a_null_record_or_damaged_claims_ask_and_never_read_as_a_first_call(self):
        self.addCleanup(lambda: [p.unlink() for p in Path(HOME).glob("destinations.json.corrupt*")])
        for damage in ({"secrets": {"KEY": None}}, {"secrets": {}, "claims": {"KEY": "x"}}, {"secrets": []},
                       {"secrets": {}, "claims": []}):
            with self.subTest(damage=damage):
                _reset(secret_destinations="protect")
                ref = _secret()
                STORE.write_text(json.dumps(damage).replace("KEY", _key(ref)))
                self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")})), "ask")
                STORE.write_text(json.dumps(damage).replace("KEY", _key(ref)))
                self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")}, CODEX)), "deny")

    @unittest.skipIf(os.name == "nt", "Codex on Windows refuses a shell placeholder (PowerShell quoting is not built)")
    def test_a_damaged_claim_of_another_key_does_not_block_this_one(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")}, CODEX)
        data = json.loads(STORE.read_text())
        data["claims"] = {"OTHER": True}
        STORE.write_text(json.dumps(data))
        self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")}, CODEX)), "allow")

    def test_a_first_use_whose_record_could_not_be_written_is_refused_and_a_later_one_is_not(self):
        for client in (CLAUDE, CODEX):
            for tool, call in (("Bash", lambda r: {"command": _curl(r, "one.example.com")}),
                               ("mcp__gw__jira_write_actions", lambda r: {"token": r}),
                               ("Bash", lambda r: {"command": f"printf '%s' {r} > /tmp/dest-probe.txt"}),
                               ("Write", lambda r: {"file_path": "/tmp/dest-probe/x.cfg", "content": r})):
                if os.name == "nt" and client is CODEX and tool == "Bash":
                    continue          # Codex on Windows refuses a shell placeholder before protect
                with self.subTest(client="codex" if client is CODEX else "claude", tool=tool):
                    _reset(secret_destinations="protect")
                    ref = _secret()
                    with mock.patch.object(destinations, "pend", return_value=False):
                        out = _pre(tool, call(ref), client)
                    self.assertEqual(_decision(out), "deny")
                    self.assertIn("could not be written", out["hookSpecificOutput"]["permissionDecisionReason"])
                    self.assertNotIn("updatedInput", out["hookSpecificOutput"])
        _reset(secret_destinations="protect")
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        with mock.patch.object(destinations, "pend", return_value=False):
            self.assertIsNone(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")})),
                              "a key that had its first call loses only this record")
        _reset()
        ref = _secret()
        with mock.patch.object(destinations, "pend", return_value=False):
            self.assertIsNone(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")})), "observe asks not")

    def test_a_local_first_call_claims_the_first_call(self):
        ref = _secret()
        self.assertEqual(destinations.new_hosts([_key(ref)], [("local", "a file in /tmp/", True)]), [])
        self.assertEqual(destinations.new_hosts([_key(ref)], [("network", "one.example.com", True)]),
                         ["one.example.com"], "a check before the file call pends finds its claim")

    def test_a_claim_from_the_future_or_a_dropped_pending_call_of_the_key_asks(self):
        self.addCleanup(lambda: [p.unlink() for p in Path(HOME).glob("destinations.json.corrupt*")])
        for damage in ({"secrets": {}, "claims": {"KEY": time.time() + 3600}},
                       {"secrets": {}, "pending_calls": {"x": {"keys": ["KEY"], "t": "late"}}},
                       {"secrets": {}, "pending_calls": []}):
            with self.subTest(damage=list(damage)[-1]):
                _reset(secret_destinations="protect")
                ref = _secret()
                STORE.write_text(json.dumps(damage).replace("KEY", _key(ref)))
                self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref, "one.example.com")}, CODEX)), "deny")

    def test_a_url_in_capitals_names_its_host(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        out = _pre("Bash", {"command": "curl -s -u " + "u" + ":" + ref + " HTTPS://Two.Example.com/"})
        self.assertEqual(_decision(out), "ask")
        self.assertIn("never used with: two.example.com.", out["hookSpecificOutput"]["permissionDecisionReason"])

    @unittest.skipIf(os.name == "nt", "the ssh route is POSIX only")
    def test_the_ssh_route_names_a_host_the_classifier_cannot_read(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        cmd = {"command": f"printf '%s' {ref} | ssh [2001:db8::1] 'grep -F -f - /var/log/app.log'"}
        out = _ran("Bash", cmd)
        self.assertEqual(_decision(out), "ask")
        self.assertIn("never used with: ssh [2001:db8::1].", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertIsNone(_decision(_pre("Bash", cmd)), "a call to it ran: known")

    @unittest.skipIf(os.name == "nt", "the ssh route is POSIX only")
    def test_a_copy_beside_the_ssh_route_does_not_hide_the_route_host(self):
        ref = _secret()
        _ran("Bash", {"command": "scp ./a.txt b.example.com:/tmp/ && " + _curl(ref, "one.example.com")})
        out = _pre("Bash", {"command": f"printf '%s' {ref} | ssh [2001:db8::1] 'grep -F -f - /var/log/x'; "
                                       "scp ./a.txt b.example.com:/tmp/"})
        self.assertEqual(_decision(out), "ask")
        self.assertIn("ssh [2001:db8::1]", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_a_command_that_only_mentions_ssh_asks_only_for_its_new_hosts(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        out = _pre("Bash", {"command": "scp local.txt ./backup/ && " + _curl(ref, "one.example.com")})
        self.assertIsNone(_decision(out), "a local copy names no host")

    @unittest.skipIf(os.name == "nt", "Codex on Windows refuses a shell placeholder (PowerShell quoting is not built)")
    def test_a_first_call_refused_after_the_check_does_not_lock_its_key(self):
        _reset(secret_destinations="protect", max_resolves_per_hour=1)
        ref1, ref2 = _secret(), _secret("dest-probe-value-7654321")
        _ran("Bash", {"command": _curl(ref1, "one.example.com")}, CODEX)
        self.assertEqual(_decision(_pre("Bash", {"command": _curl(ref2, "one.example.com")}, CODEX)), "deny",
                         "premise: the limiter refuses the first call of the second key")
        CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                      "secret_destinations": "protect"}))
        later = time.time() + destinations.CLAIM_SECONDS + 1
        with mock.patch.object(destinations.time, "time", return_value=later):
            out = _pre("Bash", {"command": _curl(ref2, "one.example.com")}, CODEX)
        self.assertEqual(_decision(out), "allow", "the refused call left no claim that holds")

    def test_codex_never_gets_a_question_with_a_rewritten_input(self):
        out = hooks._rehydrated({"session_id": "S1", **CODEX}, {}, "bash", {"command": "x"}, "r",
                                ["two.example.com"])
        self.assertEqual(_decision(out), "deny")
        self.assertNotIn("updatedInput", out["hookSpecificOutput"])

    def test_observe_never_asks(self):
        _reset()
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        self.assertIsNone(_decision(_pre("Bash", {"command": _curl(ref, "two.example.com")})))

    def test_confirm_keeps_its_question_and_names_the_new_host(self):
        _reset(secret_destinations="protect", rehydration="confirm")
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "one.example.com")})
        out = _pre("Bash", {"command": _curl(ref, "two.example.com")})
        self.assertEqual(_decision(out), "ask")
        self.assertIn("never used with: two.example.com.", out["hookSpecificOutput"]["permissionDecisionReason"])


class RoundFour(unittest.TestCase):
    """The repairs of review round 4 (codex)."""

    def setUp(self):
        _reset()

    def test_a_value_that_expires_takes_its_record_at_once(self):
        ref = _secret()
        destinations.note([_key(ref)], "S1", None, [("network", "api.example.com")])
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"}, "the premise: a record exists")
        v = Vault(load_config())
        v._index["entries"][_key(ref)]["expires"] = time.time() - 1
        v._save_index()
        Vault(load_config()).expire()
        self.assertTrue(Vault(load_config())._index["entries"][_key(ref)]["purged"], "the metadata stays")
        self.assertEqual(_seen(ref), {}, "the list shows no purged entry, so no record may stay behind it")

    def test_a_url_in_a_shell_comment_is_no_destination(self):
        ref = _secret()
        _ran("Bash", {"command": _curl(ref, "api.example.com") + "  # mirror: https://other.example.net/x"})
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"})

    def test_a_hash_that_is_no_comment_hides_no_destination(self):
        ref = _secret()
        # Opus round 5: the shell reads no comment after (( x |, and the second curl runs
        _ran("Bash", {"command": _curl(ref, "api.example.com") + "; (( x |# 2 )); curl https://other.example.net/"})
        self.assertEqual(set(_seen(ref)), {"network:api.example.com", "network:other.example.net"})

    def test_a_label_keeps_no_character_that_does_not_print(self):
        for ch in ("\u2060", "\ufff9", "\u00ad", "\u2028", "\ud800"):
            label = destinations.clean_label("api" + ch + ".example.com")
            self.assertTrue(label.isprintable(), repr(label))
            self.assertEqual(label.replace("?", "").replace(" ", ""), "api.example.com", repr(label))

    def test_a_folder_next_to_home_is_not_shown_as_home(self):
        home = str(Path.home())
        sibling = home.rstrip(os.sep) + "x"
        found = destinations.destinations_of("Write", {"file_path": os.path.join(sibling, "a.txt")})
        self.assertNotIn("~", found[0][1], "a folder that only starts with the home path is not home")
        found = destinations.destinations_of("Write", {"file_path": os.path.join(home, "proj", "a.txt")})
        self.assertEqual(found, [("local", "a file in ~/proj/")])


class SeenOnlyAfterTheCall(unittest.TestCase):
    """A value is handed out in PreToolUse, before the client asks the person. The destination becomes `seen` only
    when a PostToolUse or PostToolUseFailure of the same tool_use_id says the call ran (ChatGPT review of 0.6.7)."""

    def setUp(self):
        _reset()

    def _ran(self, ref: str, host: str, call: str) -> None:
        _pre("Bash", {"command": _curl(ref, host)}, tool_use_id=call)
        _post(tool_use_id=call)

    def test_a_declined_call_leaves_no_record(self):
        ref = _secret()
        out = _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id="T1")
        self.assertIn("updatedInput", out["hookSpecificOutput"], "the premise: the value was handed out")
        self.assertEqual(_seen(ref), {}, "no PostToolUse came: the person declined, nothing was sent")
        self.assertIn("S1\x1f\x1fT1", json.loads(STORE.read_text())["pending_calls"], "it waits as pending")

    def test_a_call_that_ran_is_seen(self):
        ref = _secret()
        self._ran(ref, "api.example.com", "T1")
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"})
        self.assertEqual(json.loads(STORE.read_text())["pending_calls"], {}, "and waits no longer")

    def test_a_failed_call_is_seen_too(self):
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id="T1")
        hooks.HANDLERS["post-tool-failure"]({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                             "session_id": "S1", "tool_use_id": "T1", **CLAUDE,
                                             "tool_input": {}, "error": "exit 1"})
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"}, "the tool had the value")

    def test_the_end_of_another_call_commits_nothing(self):
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id="T1")
        _post(tool_use_id="T2")
        _post(tool_use_id=None)
        self.assertEqual(_seen(ref), {})

    def test_a_pattern_break_waits_for_the_call_and_its_hint_comes_with_it(self):
        _typed()
        ref = _secret()
        for i in range(destinations.ESTABLISHED_USES):
            self._ran(ref, "api.example.com", f"E{i}")
        _pre("Bash", {"command": _curl(ref, "other.example.net")}, tool_use_id="B1")
        self.assertEqual(json.loads(STORE.read_text())["pending_hint"], {}, "a declined break gives no hint")
        self.assertNotIn("maisecrets notes", json.dumps(_post(tool_use_id="X9")))
        out = _post(tool_use_id="B1")
        self.assertIn("named a host that this secret was not used with before",
                      out["hookSpecificOutput"]["additionalContext"], "the break of the call that ran, in its answer")

    def _age(self, seconds: float) -> None:
        data = json.loads(STORE.read_text())
        for c in data["pending_calls"].values():
            c["t"] -= seconds
        STORE.write_text(json.dumps(data))

    def test_a_late_end_of_the_call_still_counts(self):
        # Opus review of 0.6.8: the time counts from the hand-out, and a permission dialog can stay open; the Post
        # event of the same call is the proof however late it comes
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id="T1")
        self._age(destinations.PENDING_SECONDS + 3600)     # past the cleanup age: only pend() sweeps, not commit
        _post(tool_use_id="T1")
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"})

    def test_a_pending_call_that_never_ran_goes_when_the_next_one_waits(self):
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id="T1")
        self._age(destinations.PENDING_SECONDS + 1)
        _pre("Bash", {"command": _curl(ref, "other.example.net")}, tool_use_id="T2")
        self.assertEqual(list(json.loads(STORE.read_text())["pending_calls"]), ["S1\x1f\x1fT2"])

    def test_the_same_call_id_in_another_session_or_agent_commits_nothing(self):
        # codex review of 0.6.8: Codex numbers its calls (call_1), so an id is unique only in its session
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id="call_1")
        _post(tool_use_id="call_1", session_id="S2")
        _post(tool_use_id="call_1", agent_id="sub1")
        self.assertEqual(_seen(ref), {}, "the declined call of S1 stays unseen")
        _post(tool_use_id="call_1")
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"}, "its own end commits it")

    def test_a_failed_call_that_breaks_the_pattern_gets_its_hint_in_its_own_answer(self):
        _typed()
        ref = _secret()
        for i in range(destinations.ESTABLISHED_USES):
            self._ran(ref, "api.example.com", f"E{i}")
        _pre("Bash", {"command": _curl(ref, "other.example.net")}, tool_use_id="B1")
        out = hooks.HANDLERS["post-tool-failure"]({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                                   "session_id": "S1", "tool_use_id": "B1", **CLAUDE,
                                                   "tool_input": {}, "error": "exit 1"})
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUseFailure")
        self.assertIn("named a host that this secret was not used with before",
                      out["hookSpecificOutput"]["additionalContext"])
        self.assertNotIn("maisecrets notes", json.dumps(_post(tool_use_id="X9")), "and not again on the next call")

    def test_a_pending_call_keeps_at_most_the_bound_of_destinations(self):
        _reset(max_resolves_per_hour=1000)
        ref = _secret()
        hosts = " ".join(f"https://h{i}.example.com/" for i in range(destinations.MAX_PER_SECRET + 10))
        _pre("Bash", {"command": _curl(ref, "api.example.com") + " " + hosts + " " + hosts}, tool_use_id="T1")
        (c,) = json.loads(STORE.read_text())["pending_calls"].values()
        self.assertEqual(len(c["found"]), destinations.MAX_PER_SECRET, "no more than a record holds")
        _pre("Bash", {"command": _curl(ref, "api.example.com") + " https://h1.example.com/" * 3}, tool_use_id="T2")
        calls = json.loads(STORE.read_text())["pending_calls"]
        self.assertEqual(len(calls["S1\x1f\x1fT2"]["found"]), 2, "a host the command names twice counts once")

    def test_an_ssh_hint_and_a_destination_hint_due_together_both_come(self):
        # codex review of 0.6.8: with `or`, the destination hint of this call waited for an unrelated later one
        with mock.patch.object(hooks, "_ssh_hint", return_value="SSH-HINT"), \
                mock.patch.object(hooks, "_destination_hint", return_value="DEST-HINT"):
            out = hooks._with_hint({"session_id": "S1", **CLAUDE}, {})
        text = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("SSH-HINT", text)
        self.assertIn("DEST-HINT", text)

    def test_the_ssh_host_stays_when_many_urls_fill_the_bound(self):
        found = destinations.destinations_of(
            "Bash", {"command": " ".join(f"https://h{i}.example.com/" for i in range(80))}, ["web1"])
        self.assertEqual(found[0], ("network", "ssh web1"))

    def test_a_pending_call_with_more_destinations_than_the_bound_is_dropped(self):
        big = [["network", f"h{i}.example.com"] for i in range(destinations.MAX_PER_SECRET + 1)]
        STORE.write_text(json.dumps({"secrets": {}, "pending_calls": {"S1\x1f\x1fT1": {
            "keys": ["K1"], "session": "S1", "agent": None, "found": big, "t": time.time()}}}))
        self.assertEqual(destinations._load()["pending_calls"], {})

    def test_the_end_of_a_call_with_no_value_takes_no_lock(self):
        _secret()
        # on the class: Python looks a dunder method up on the type, so a patch on the instance would not apply
        with mock.patch.object(type(destinations._LOCK), "__enter__", side_effect=AssertionError("a lock was taken")):
            self.assertFalse(destinations.commit("T1", "S1", None))

    def test_the_pending_calls_are_bounded(self):
        _reset(max_resolves_per_hour=1000)          # the premise: more calls than the bound get their values
        ref = _secret()
        for i in range(destinations.MAX_PENDING + 5):
            _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id=f"T{i}")
        calls = json.loads(STORE.read_text())["pending_calls"]
        self.assertEqual(len(calls), destinations.MAX_PENDING)
        self.assertNotIn("S1\x1f\x1fT0", calls, "the oldest goes")

    def test_forget_takes_a_pending_call_too(self):
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id="T1")
        self.assertTrue(destinations.forget([_key(ref)]))
        self.assertEqual(json.loads(STORE.read_text())["pending_calls"], {})
        _post(tool_use_id="T1")
        self.assertEqual(_seen(ref), {})

    def test_a_malformed_pending_call_is_dropped(self):
        STORE.write_text(json.dumps({"pending_calls": {"T1": {"keys": "K1", "found": [], "t": 1}},
                                     "secrets": {}}))
        self.assertEqual(destinations._load()["pending_calls"], {})
        self.assertFalse(destinations.commit("T1", "S1", None))

    def test_a_client_without_a_call_id_leaves_no_record(self):
        # ChatGPT review of 0.6.8: without a call id nothing can show that the call ran, and a declined call must
        # not be listed. Claude Code and Codex send one in PreToolUse and PostToolUse (harness/golden, client_payloads)
        ref = _secret()
        out = _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id=None)
        self.assertIn("updatedInput", out["hookSpecificOutput"], "the premise: the value was handed out")
        _post(tool_use_id=None)
        self.assertEqual(_seen(ref), {})
        self.assertFalse(STORE.exists() and json.loads(STORE.read_text()).get("pending_calls"))

    def test_a_bash_command_names_its_hosts_for_each_secret_in_it(self):
        # command-level, not value-flow-level (ChatGPT review of 0.6.7): the second URL gets no value, and it is
        # noted for the secret all the same. Measured first, before any parser follows the value
        ref = _secret()
        self._ran_command(_curl(ref, "api.example.com") + "; curl -s https://status.example.org/", "T1")
        self.assertEqual(set(_seen(ref)), {"network:api.example.com", "network:status.example.org"})

    def _ran_command(self, command: str, call: str) -> None:
        _pre("Bash", {"command": command}, tool_use_id=call)
        _post(tool_use_id=call)

    def test_a_commit_that_fails_never_changes_the_answer(self):
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id="T1")

        def post(call):          # an output that holds the value: the answer redacts it, so it is not empty
            return hooks._post_tool_guarded({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1",
                                             "tool_input": {"command": "true"}, **CLAUDE, "tool_use_id": call,
                                             "tool_response": {"stdout": "got dest-probe-value-1234567", "stderr": ""}})
        plain = post("T9")
        self.assertTrue(plain, "the premise: an answer with something in it")
        with mock.patch.object(destinations, "commit", side_effect=RuntimeError("disk")):
            out = post("T1")
            failed = hooks.HANDLERS["post-tool-failure"]({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                                          "session_id": "S1", "tool_use_id": "T1", **CLAUDE,
                                                          "tool_input": {}, "error": "exit 1"})
        self.assertEqual(_norm(out, ref), _norm(plain, ref), "the PostToolUse answer is the one without a record")
        self.assertEqual(failed, {}, "and the PostToolUseFailure answer too")

    def test_every_recorded_client_payload_carries_a_call_id_and_codex_ends_its_own_call(self):
        # the client invariant that C23 rests on, from payloads the real clients sent (codex review of 0.6.9)
        root = Path(__file__).resolve().parent
        payloads = [json.loads(p.read_text(encoding="utf-8")) for p in (root / "client_payloads").glob("*.json")]
        golden = (root.parent / "harness" / "golden").glob("*ToolUse*.json")
        payloads += [json.loads(p.read_text(encoding="utf-8")) for p in golden]
        tools = [p for p in payloads if "tool_name" in p or "top" in p]
        self.assertGreaterEqual(len(tools), 10, "the premise: the recorded payloads were read")
        for p in tools:
            keys = p["top"] if "top" in p else p
            self.assertIn("tool_use_id", keys)
        pre = json.loads((root / "client_payloads" / "codex-exec-bash-pre.json").read_text(encoding="utf-8"))
        post = json.loads((root / "client_payloads" / "codex-exec-bash-post.json").read_text(encoding="utf-8"))
        self.assertEqual(pre["tool_use_id"], post["tool_use_id"])
        self.assertEqual(pre["session_id"], post["session_id"])

    @unittest.skipIf(os.name == "nt", "Codex for Windows: a placeholder in a shell command is refused (hooks.py), "
                                      "so no value goes out and no record is right")
    def test_a_captured_codex_call_is_seen_once_its_post_event_comes(self):
        root = Path(__file__).resolve().parent
        pre = json.loads((root / "client_payloads" / "codex-exec-bash-pre.json").read_text(encoding="utf-8"))
        post = json.loads((root / "client_payloads" / "codex-exec-bash-post.json").read_text(encoding="utf-8"))
        ref = _secret()
        # through _pre, which collects the child that serves the value (the module's hygiene check)
        fields = {k: v for k, v in pre.items() if k not in ("_captured", "tool_name", "tool_input", "session_id")}
        out = _pre(pre["tool_name"], {"command": _curl(ref, "api.example.com")}, client={}, **fields)
        self.assertIn("updatedInput", out.get("hookSpecificOutput", {}), "the premise: the value was handed out")
        self.assertEqual(_seen(ref), {}, "pending until the call ran")
        end = {k: v for k, v in post.items() if k != "_captured"}
        end.update(session_id="S1")
        hooks._post_tool_guarded(end)
        self.assertEqual(set(_seen(ref)), {"network:api.example.com"})

    def test_with_the_setting_off_nothing_waits(self):
        _reset(secret_destinations="off")
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")}, tool_use_id="T1")
        self.assertFalse(STORE.exists() and json.loads(STORE.read_text()).get("pending_calls"))
