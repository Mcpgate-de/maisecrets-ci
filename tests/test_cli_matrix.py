"""Every command through the real entry point, against every store state.

0.4.0 shipped with /maisecrets:status and /maisecrets:list crashing as soon as one stored value
had expired: 144 tests were green, because no test ran the commands against a store with an
expired entry (field report, 2026-09-27). This module closes that class of gap:

* a population test derives the command names from commands/*.md, hooks/dispatch.py and
  cli.COMMANDS, and fails when no test here dispatched the name through the real entry point;
* a state matrix runs each command as `python3 hooks/dispatch.py <cmd>` in a fresh
  MAISECRETS_HOME for each store state, and requires a defined exit code, no traceback and no
  stored value in the output; for list, status, audit, expire, forget, wipe and repair it also
  requires the exact output of that state and the index and store after it.

Only generated values. The subprocess gets a temp HOME, a temp CLAUDE_CONFIG_DIR, a temp TMPDIR,
no GIT_/CODEX_/CLAUDE_PLUGIN_OPTION_ variables, and fake pbcopy/pbpaste/xclip/open on PATH, so no
run reads the real clipboard, opens a browser, or touches ~/.maisecrets, ~/.claude or ~/.codex.
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
DISPATCH = ROOT / "hooks" / "dispatch.py"
NOTHING_WAITING = "(maisecrets: no blocked prompt is waiting. A blocked prompt waits 15 minutes.)"
RESOLVE = ROOT / "hooks" / "resolve.py"
sys.path.insert(0, str(ROOT))
# the in-process tests import maisecrets; its home is fixed at the first import and must be a
# temp dir with the plaintext test store, never the keychain (same set-up as test_gates.py)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
import _hygiene  # noqa: E402
VERSION = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))["version"]

# a policy file lives in /Library or /etc; the subprocess gets the path through this wrapper,
# which patches POLICY_PATHS and then runs dispatch.py as __main__ (the code has no env override).
# The same wrapper makes the store refuse every delete, as a locked keychain over SSH does.
_WRAPPER = (
    "import platform, runpy, sys\n"
    "from pathlib import Path\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import maisecrets.vault as v\n"
    "if sys.argv[2]:\n"
    "    v.POLICY_PATHS[platform.system()] = Path(sys.argv[2])\n"
    "if sys.argv[3] == '1':\n"
    "    def _refuse(self, key):\n"
    "        raise RuntimeError('the store refused the delete (test fault)')\n"
    "    v.EncryptedFileBackend.delete = v.JsonFileBackend.delete = _refuse\n"
    "sys.argv = [sys.argv[4]] + sys.argv[5:]\n"
    "runpy.run_path(sys.argv[0], run_name='__main__')\n"
)

_FAKE_TOOLS = {
    "pbcopy": 'cat > "$MS_TEST_CLIP"\n',
    "pbpaste": 'cat "$MS_TEST_CLIP" 2>/dev/null\n',
    "xclip": 'case " $* " in *" -o "*) cat "$MS_TEST_CLIP" 2>/dev/null ;; *) cat > "$MS_TEST_CLIP" ;; esac\n',
    "open": 'printf "%s\\n" "$*" >> "$MS_TEST_OPENED"\n',
    "xdg-open": 'printf "%s\\n" "$*" >> "$MS_TEST_OPENED"\n',
    # tripwires: a sandbox process must never reach the real keychain or Credential Locker (a
    # run with a temp HOME opened a macOS "no keychain found" dialog on 2026-09-27)
    "security": 'echo "security $*" >> "$MS_TEST_TRIPWIRE"; exit 1\n',
    "powershell": 'echo "powershell $*" >> "$MS_TEST_TRIPWIRE"; exit 1\n',
}
_DROP_PREFIXES = ("GIT_", "CODEX_", "CLAUDE_PLUGIN_OPTION_", "MAISECRETS_")
_DROP = {"CLAUDECODE", "CLAUDE_CONFIG_DIR", "XDG_RUNTIME_DIR", "CLAUDE_CODE_ENTRYPOINT"}


# every command name a test in this process ran through hooks/dispatch.py or hooks/resolve.py
DISPATCHED: set[str] = set()


def fake_value(prefix: str = "Fk") -> str:
    """A generated value no rule and no person has ever seen."""
    return prefix + secrets.token_hex(10)


class Sandbox:
    """One temp world: vault home, user home, tmp, fake tools, optional policy file."""

    def __init__(self, config: dict | None = None, policy: object | None = None,
                 backend: str = "encrypted-file", refuse_delete: bool = False) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="maisecrets-matrix-"))
        self.home = self.root / "ms"
        self.user_home = self.root / "home"
        self.bin = self.root / "bin"
        for d in (self.home, self.user_home, self.bin, self.root / "tmp"):
            d.mkdir(mode=0o700)
        for name, body in _FAKE_TOOLS.items():
            p = self.bin / name
            p.write_text("#!/bin/sh\n" + body, encoding="utf-8")
            p.chmod(0o700)
        self.clip = self.root / "clip"
        self.opened = self.root / "opened"
        self.policy: Path | None = None
        self.refuse_delete = refuse_delete
        self.values: list[str] = []
        self.by_key: dict[str, str] = {}
        # the backend is forced through the environment as well: a config file with a wrong type
        # is ignored as a whole, and the default on macOS is the keychain
        self.backend = backend
        if config is not None:
            (self.home / "config.json").write_text(json.dumps(config), encoding="utf-8")
        if policy is not None:
            self.policy = self.root / "policy.json"
            self.policy.write_text(policy if isinstance(policy, str) else json.dumps(policy), encoding="utf-8")

    def copy(self) -> "Sandbox":
        """A fresh copy of this world, so a mutating command never sees another's result."""
        new = Sandbox.__new__(Sandbox)
        new.root = Path(tempfile.mkdtemp(prefix="maisecrets-matrix-"))
        shutil.rmtree(new.root)
        shutil.copytree(self.root, new.root, symlinks=True)
        new.home, new.user_home, new.bin = new.root / "ms", new.root / "home", new.root / "bin"
        new.clip, new.opened = new.root / "clip", new.root / "opened"
        new.policy = (new.root / "policy.json") if self.policy else None
        new.refuse_delete = self.refuse_delete
        new.values = list(self.values)
        new.by_key = dict(self.by_key)
        new.backend = self.backend
        return new

    def env(self, **extra: str) -> dict:
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(_DROP_PREFIXES) and k not in _DROP}
        # the locale tests/_isolate.py pins: without it a child reads the system setting of the
        # machine, and a German Mac and a C-locale container expect different label languages
        env["MAISECRETS_LOCALE"] = os.environ["MAISECRETS_LOCALE"]
        env.update({
            "HOME": str(self.user_home), "USERPROFILE": str(self.user_home),
            "MAISECRETS_HOME": str(self.home), "TMPDIR": str(self.root / "tmp"),
            "CLAUDE_CONFIG_DIR": str(self.user_home / ".claude"),
            "PATH": str(self.bin) + os.pathsep + env.get("PATH", ""),
            "MS_TEST_CLIP": str(self.clip), "MS_TEST_OPENED": str(self.opened),
            # the fake clipboard tools are shell scripts; with four cells at a time they took longer than 3 s
            "MAISECRETS_CLIPBOARD_TIMEOUT": "30",
            "MS_TEST_TRIPWIRE": str(self.root / "tripwire"), "CLAUDE_PLUGIN_OPTION_BACKEND": self.backend,
            "CLAUDE_PLUGIN_ROOT": str(ROOT), "PYTHONUTF8": "1",
            # a local desktop for the fake opener in self.bin: without a display, or over ssh, the report opens
            # no browser (a Linux CI runner has neither a display nor a browser)
            "DISPLAY": ":0",
        })
        for k in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "WAYLAND_DISPLAY"):
            env.pop(k, None)
        env.update(extra)
        return env

    def run(self, *args: str, stdin: str = "", env: dict | None = None,
            script: Path = DISPATCH) -> subprocess.CompletedProcess:
        if (self.policy is not None or self.refuse_delete) and script == DISPATCH:
            argv = [sys.executable, "-c", _WRAPPER, str(ROOT), str(self.policy or ""),
                    "1" if self.refuse_delete else "0", str(script), *args]
        else:
            argv = [sys.executable, str(script), *args]
        # the cwd is the sandbox: a value-serving child a hook leaves behind inherits it, and
        # tearDownModule finds it by it
        # the child writes UTF-8 (PYTHONUTF8=1); text=True decodes with the locale, cp1252 on Windows
        r = subprocess.run(argv, input=stdin, capture_output=True, encoding="utf-8", errors="replace", timeout=60,
                           env=env if env is not None else self.env(), cwd=str(self.root))
        trip = self.root / "tripwire"
        if trip.exists():
            raise AssertionError(f"a sandbox process called the platform store: {trip.read_text()}")
        # what the entry point actually handled: a name that fell through to the dispatcher's
        # usage error ran nothing and covers nothing
        if script in (DISPATCH, RESOLVE) and "usage: dispatch.py" not in r.stderr:
            DISPATCHED.add("resolve" if script == RESOLVE else (args[0] if args else ""))
        return r

    # state helpers ---------------------------------------------------------
    def index(self) -> dict:
        return json.loads((self.home / "index.json").read_text(encoding="utf-8"))

    def write_index(self, data: dict) -> None:
        (self.home / "index.json").write_text(json.dumps(data), encoding="utf-8")

    def put(self, type_: str = "SECRET") -> str:
        """Store a generated value through `put` (stdin) and return its key."""
        value = fake_value()
        r = self.run("put", f"--type={type_}", stdin=value + "\n")
        m = re.search(r"placeholder (?:is )?\u27e6(\w+)", r.stdout)
        if r.returncode != 0 or not m:
            raise AssertionError(f"seed put failed: {r.returncode} {r.stdout} {r.stderr}")
        self.values.append(value)
        self.by_key[m.group(1)] = value
        return m.group(1)

    def block_prompt(self, session: str = "S1") -> str:
        """A prompt with a labelled value through the real UserPromptSubmit hook: an entry, an
        event and a pending prompt, as a person would leave them."""
        value = fake_value("Pw")
        r = self.run("user-prompt", stdin=json.dumps({"prompt": f"password: {value}", "session_id": session,
                                                      "transcript_path": "", "prompt_id": "p1"}))
        out = json.loads(r.stdout)
        if out.get("decision") != "block":
            raise AssertionError(f"seed prompt not blocked: {r.stdout} {r.stderr}")
        self.values.append(value)
        # the notice names no key since 0.4.2; the newest entry in the index is the one just stored
        entries = self.index()["entries"]
        newest = max(entries, key=lambda k: entries[k]["created"])
        self.by_key[newest] = value
        return value

    def backdate(self) -> None:
        """Every entry past its expiry, as the index says after the TTL; no sweep has run yet."""
        data = self.index()
        for meta in data["entries"].values():
            meta["expires"] = time.time() - 10
        self.write_index(data)

    def expire_all(self) -> None:
        self.backdate()
        r = self.run("expire")
        if r.returncode != 0:
            raise AssertionError(f"seed expire failed: {r.stdout} {r.stderr}")

    def remove(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


# ------------------------------------------------------------------ states --
ENC = {"backend": "encrypted-file"}
JSONFILE = {"backend": "jsonfile", "allow_plaintext_store": True}


def _seed_live(sb: Sandbox) -> None:
    sb.put()
    sb.put("EMAIL")
    sb.block_prompt()


def _seed_expired(sb: Sandbox) -> None:
    sb.put()
    sb.expire_all()
    if not all(m.get("purged") and m.get("purged_at") for m in sb.index()["entries"].values()):
        raise AssertionError("seed: the entry is not purged")


def _seed_expired_unpurged(sb: Sandbox) -> None:
    sb.put()
    data = sb.index()
    for meta in data["entries"].values():
        meta["expires"] = time.time() - 10
    sb.write_index(data)


def _seed_expired_unswept(sb: Sandbox) -> None:
    """Past its expiry, value still in the store: the state between the TTL and the next sweep."""
    sb.put()
    sb.backdate()


def _seed_old_purged(sb: Sandbox) -> None:
    _seed_expired(sb)
    data = sb.index()
    for meta in data["entries"].values():
        meta["purged_at"] = time.time() - 40 * 86400    # keep_purged_days is 30 by default
    sb.write_index(data)


def _seed_damaged(sb: Sandbox) -> None:
    sb.put()
    (sb.home / "index.json").write_text('{"entries": {', encoding="utf-8")


# name -> (config.json, policy file, backend, seed, kind). The kind decides the expected exit
# codes: "ok" works, "index" has an unreadable index, "config" has a configuration that does not load
STATES = {
    "empty": (ENC, None, "encrypted-file", lambda sb: None, "ok"),
    "live": (ENC, None, "encrypted-file", _seed_live, "ok"),
    "expired-unswept": (ENC, None, "encrypted-file", _seed_expired_unswept, "ok"),
    # an expired entry whose delete the store refuses: it stays unpurged, the value stays stored
    "store-refuses-delete": (ENC, None, "encrypted-file", _seed_expired_unswept, "ok"),
    "expired-purged": (ENC, None, "encrypted-file", _seed_expired, "ok"),
    "expired-not-yet-purged": (ENC, None, "encrypted-file", _seed_expired_unpurged, "ok"),
    "purged-past-retention": (ENC, None, "encrypted-file", _seed_old_purged, "ok"),
    "damaged-index": (ENC, None, "encrypted-file", _seed_damaged, "index"),
    "config-wrong-type": ({"backend": "encrypted-file", "tips": "yes"}, None, "encrypted-file",
                          lambda sb: sb.put(), "ok"),
    "policy": (ENC, {"keep_purged_days": 3, "max_keys_per_session": 5}, "encrypted-file",
               lambda sb: sb.put(), "ok"),
    "policy-wrong-type": (ENC, {"keep_purged_days": "thirty"}, "encrypted-file", lambda sb: None, "config"),
    "jsonfile": (JSONFILE, None, "jsonfile", _seed_live, "ok"),
    "jsonfile-not-allowed": ({"backend": "jsonfile"}, None, "jsonfile", lambda sb: None, "config"),
}

# command -> invocations (args, stdin, expected exit code per state kind). A dict in a slot
# overrides the code per state ("*" is the rest). KEY becomes the first seeded key; SCANVALUE
# and PUTVALUE become fresh generated values.
_K = "KEY"
_ALL0 = {"ok": 0, "index": 0, "config": 0}
_ALL2 = {"ok": 2, "index": 2, "config": 2}
_ALL1 = {"ok": 1, "index": 1, "config": 1}
_STORE = {"ok": 0, "index": 1, "config": 1}
MATRIX: dict[str, list[tuple[list[str], str, dict]]] = {
    "list": [([], "", _STORE)],
    "status": [([], "", _STORE)],
    "audit": [([], "", _ALL0), (["3"], "", _ALL0), (["x"], "", _ALL2)],
    "expire": [([], "", {"ok": {"store-refuses-delete": 1, "*": 0}, "index": 1, "config": 1})],
    "forget": [([_K], "", {"ok": {"empty": 1, "store-refuses-delete": 1, "*": 0}, "index": 1, "config": 1}),
               (["NOPE_c9"], "", {"ok": 1, "index": 1, "config": 1}),
               ([], "", _ALL2)],
    "wipe": [([], "", _ALL2), (["--yes"], "", {"ok": 0, "index": 0, "config": 1})],
    "repair": [([], "", {"ok": 0, "index": 0, "config": 1})],
    "report": [([], "", _ALL0), (["last", "a build id"], "", _ALL0), (["1"], "", _ALL0),
               (["bug", "the notice is long"], "", _ALL0), (["feature", "ask first"], "", _ALL0)],
    "config": [([], "", {"ok": 0, "index": 0, "config": 1})],
    # it only shows the settings: KEY VALUE shows that setting's card (the prompt hook made the change), and an
    # unknown word exits 1; none of them writes a setting (tests/test_settings.py)
    "settings": [([], "", {"ok": 0, "index": 0, "config": 1}), (["--all"], "", {"ok": 0, "index": 0, "config": 1}),
                 (["ssh_consent", "on"], "", {"ok": 0, "index": 0, "config": 1}),
                 (["ssh_autonomous_hosts", "add", "ops1"], "", {"ok": 0, "index": 0, "config": 1}),
                 (["ssh_autonomous_hosts", "nonsense", "ops1"], "", _ALL1),
                 (["hints"], "", _ALL0), (["nosuchkey"], "", _ALL1)],
    # the labels are assembled so the repo's own pre-commit scan does not take the fixtures for secrets
    "scan": [(["pass" "word: SCANVALUE"], "", _ALL0), ([], "api" "_key=SCANVALUE", _ALL0)],
    "get": [([_K], "", {"ok": {"live": 0, "jsonfile": 0, "config-wrong-type": 0, "policy": 0, "*": 1},
                        "index": 1, "config": 1}),
            ([], "", _ALL2)],
    "put": [(["--type=SECRET"], "PUTVALUE", _STORE), (["--clipboard"], "", _STORE), ([], "", _ALL2)],
    "shortcut": [([], "", _ALL0), (["--remove"], "", _ALL0)],
    # the guard is POSIX only: `guard install` refuses on Windows with exit 1 and says why
    "guard": [([], "", _ALL0), (["install"], "", _ALL1 if os.name == "nt" else _ALL0), (["status"], "", _ALL0),
              (["remove"], "", _ALL0)],
    "pending": [([], "", _ALL0)],
    # it reads the transcripts of the sandbox's own CLAUDE_CONFIG_DIR, never the store: every state answers alike
    "consent-report": [(["ssh", "--json"], "", _ALL0), (["ssh", "--last", "7d"], "", _ALL0), ([], "", _ALL2)],
    # the rule folders are read without the store, and a config that does not load means no extra folder: every
    # state answers alike (tests/test_user_rules.py)
    "rules": [([], "", _ALL0), (["check"], "", _ALL0), (["nonsense"], "", _ALL2)],
    # the term lists are read without the store; suggest of a missing file exits 1 (tests/test_terms_hooks.py)
    "terms": [([], "", _ALL0), (["suggest", "/nonexistent/notes.txt"], "", _ALL1), (["nonsense"], "", _ALL2)],
    # the imports are read without the store; an import of a missing file and any removal exit 1 (tests/test_values.py)
    "values": [([], "", _ALL0), (["import", "/nonexistent/values.jsonl"], "", _ALL1),
               (["remove", "v1234abcd"], "", _ALL1), (["nonsense"], "", _ALL2)],
}

_BASES: dict[str, Sandbox] = {}
REFUSING = {"store-refuses-delete"}


def base_state(name: str) -> Sandbox:
    """The seeded world of one state, built once; every run works on a copy."""
    if name not in _BASES:
        config, policy, backend, seed, _kind = STATES[name]
        sb = Sandbox(config, policy, backend, refuse_delete=name in REFUSING)
        seed(sb)
        _BASES[name] = sb
    return _BASES[name]


def tearDownModule() -> None:  # noqa: N802 - unittest hook
    for sb in _BASES.values():
        sb.remove()
    # pytest-xdist can run this before more tests of the module: they must seed a new base
    _BASES.clear()
    _hygiene.assert_pristine()
    # a child a hook subprocess left behind runs with the sandbox as its working directory
    alive = _hygiene.wait_for_no_serving_child(cwd_root=_isolate.TMP)
    if alive:
        raise AssertionError(f"value-serving children still run after the module: {alive}")


def seeded_key(sb: Sandbox) -> str:
    try:
        keys = sorted(sb.index()["entries"])
    except (OSError, ValueError):
        keys = []
    return keys[0] if keys else "SECRET_c1"


def _expected(state: str, spec: dict) -> int:
    want = spec[STATES[state][4]]
    if isinstance(want, dict):
        return want.get(state, want["*"])
    return want


def run_cell(state: str, command: str, args: list[str], stdin: str, spec: dict) -> list[str]:
    """Run one command in one state; return the problems found (empty when the cell is right)."""
    sb = base_state(state).copy()
    try:
        key = seeded_key(sb)
        args = [key if a == _K else a for a in args]
        fresh = {"SCANVALUE": fake_value("Sc"), "PUTVALUE": fake_value("Pt")}
        for k, v in fresh.items():
            args = [a.replace(k, v) for a in args]
            stdin = stdin.replace(k, v)
        clip_value = fake_value("Cl")      # what the user copied before the command ran
        sb.clip.write_text(clip_value, encoding="utf-8")
        before = snapshot(sb)
        r = sb.run(command, *args, stdin=stdin)
        out = r.stdout + r.stderr
        cell = f"{state}: {command} {' '.join(args)}"
        problems = []
        want = _expected(state, spec)
        if r.returncode != want:
            problems.append(f"{cell}: exit {r.returncode}, expected {want}: {out[-400:]!r}")
        if "Traceback" in out:
            problems.append(f"{cell}: printed a traceback: {out[-400:]!r}")
        values = sb.values + list(fresh.values()) + [clip_value]
        if command == "get" and r.returncode == 0:
            # the one command that prints a value: exactly the value of the key asked for
            if r.stdout != sb.by_key.get(key, "?") + "\n":
                problems.append(f"{cell}: get did not print exactly the value of {key}")
            values.remove(sb.by_key.get(key, "?")) if sb.by_key.get(key) in values else None
        if any(v in out for v in values):
            problems.append(f"{cell}: printed a value")
        if command == "put" and r.returncode == 0:
            clip = sb.clip.read_text(encoding="utf-8")
            if any(v in clip for v in values) or "⟦" not in clip:
                problems.append(f"{cell}: the clipboard holds {clip[:3]}..., not the reference")
        if r.returncode == want:
            problems += [f"{cell}: {p}" for p in transition_problems(state, command, args, r, before, snapshot(sb))]
        return problems
    finally:
        sb.remove()


def snapshot(sb: Sandbox) -> SimpleNamespace:
    """What a command may change: the index (raw and parsed), the store items, the files."""
    raw = (sb.home / "index.json").read_text(encoding="utf-8") if (sb.home / "index.json").exists() else None
    try:
        index = json.loads(raw) if raw is not None else None
    except ValueError:
        index = None
    store = None
    for name in ("vault.enc.json", "vault.json"):
        if (sb.home / name).exists():
            store = sorted(json.loads((sb.home / name).read_text(encoding="utf-8")))
    pending = sorted(p.name for p in (sb.home / "pending").iterdir()) if (sb.home / "pending").is_dir() else []
    files = sorted(p.name for p in sb.home.iterdir())
    return SimpleNamespace(raw=raw, index=index, store=store, pending=pending, files=files)


_KEEP_DAYS = {"policy": 3}
_NOTICE = ("maisecrets wipe deletes every stored value, the index, the audit, event and hook logs and the "
           "pending prompts of this user. Run `wipe --yes` to do it.\n")
_STATE_CHANGING = {"list", "status", "audit", "expire", "forget", "wipe", "repair"}


def _retained(state: str, index: dict) -> dict:
    """key -> purged, for the entries a read keeps: an expired value is purged, and the metadata
    of a purged one goes after keep_purged_days."""
    keep = _KEEP_DAYS.get(state, 30) * 86400
    out = {}
    for k, m in index["entries"].items():
        purged = bool(m.get("purged")) or m["expires"] < time.time()
        if m.get("purged") and time.time() - float(m.get("purged_at") or m["expires"]) > keep:
            continue
        out[k] = purged
    return out


def transition_problems(state: str, command: str, args: list[str], r: subprocess.CompletedProcess,
                        before: SimpleNamespace, after: SimpleNamespace) -> list[str]:
    """What each state-changing command must print in this state, and what the home holds after."""
    if state in REFUSING:
        # a store that refuses every delete has its own answers (forget reports the refusal, the
        # entry stays counted); RefusingStoreTests checks them, the generic transitions do not apply
        return []
    if command not in _STATE_CHANGING:
        return []
    kind = STATES[state][4]
    p: list[str] = []

    def expect(cond: bool, what: str) -> None:
        if not cond:
            p.append(f"{what}: stdout {r.stdout[-300:]!r} stderr {r.stderr[-300:]!r}")

    def unchanged(what: str) -> None:
        expect((after.raw, after.store, after.pending) == (before.raw, before.store, before.pending),
               f"{what} changed the index, the store or the pending prompts")

    usage = r.returncode == 2
    if command == "audit":
        # no state has an audit.log; audit reads nothing else and changes nothing
        expect(r.stdout == ("" if usage else "(no stored value was used yet)\n"), "audit output")
        expect(r.stderr == ("usage: audit [n]\n" if usage else ""), "audit stderr")
        unchanged("audit")
        return p
    if usage:
        text = {"forget": ("", "usage: maisecrets forget <KEY> [KEY ...]   (keys as /maisecrets:list shows them)\n"),
                "wipe": (_NOTICE, "")}[command]
        expect((r.stdout, r.stderr) == text, f"{command} usage")
        unchanged(f"{command} without its argument")
        expect(after.files == before.files, "files appeared or went")
        return p
    if kind == "config":
        head = f"maisecrets {VERSION} at {ROOT}\n" if command == "status" else ""
        expect(r.stdout == head, "a configuration error prints nothing else on stdout")
        expect(r.stderr.startswith(f"maisecrets {command}: configuration error: "), "names the configuration error")
        expect(after.files == ["config.json"], "a configuration error creates nothing")
        return p
    if kind == "index" and command not in ("wipe", "repair"):
        expect(f"maisecrets {command}: its list of stored values (index.json) is damaged" in r.stderr,
               "names the damaged index")
        expect("run.sh repair in a terminal" in r.stderr or "run.cmd repair in a terminal" in r.stderr,
               "names repair")
        unchanged(f"{command} on a damaged index")
        return p
    if command == "wipe":
        n = len(before.store or [])
        expect(r.stdout == f"wiped: {n} stored value(s), index, logs. The config file stays.\n", "wipe count")
        expect(not after.store and after.pending == [] and after.index is None, "wipe left a value or the index")
        # locks stay with their files
        # sessions-seen holds no value, only when each session began: a wipe that removed it would let the next
        # prompt note a later start, and a file copied into a clean folder before then would pass (C28)
        # hints.json records which hints were given (a feature name and a date, no value), with its lock
        kept = {".lock", ".destinations.lock", ".incidents.lock", ".terms.lock", "config.json", "pending", "vault.json",
                "sessions-seen", "hints.json", ".settings.lock"}
        expect(set(after.files) <= kept, f"wipe left {after.files}")
        return p
    if command == "repair":
        m = re.fullmatch(r"Repaired\. (\d+) stored value\(s\) were deleted; new placeholders continue after the "
                         r"old numbers(?: \(last: (.*)\))?\.\n", r.stdout)
        expect(m is not None, "repair output")
        want: dict = {}
        # a key an old placeholder still names is never handed out again: the store, every key the
        # old index names (a purged one too) and the old counters all count
        old_index = before.index if isinstance(before.index, dict) else {}
        for k in list(before.store or []) + list(old_index.get("entries", {})):
            type_, _c, num = k.rpartition("_c")
            if _c and num.isdigit():
                want[type_] = max(want.get(type_, 0), int(num))
        for type_, num in old_index.get("counters", {}).items():
            want[type_] = max(want.get(type_, 0), num)
        values = [k for k in before.store or [] if k != "_maisecrets_fpkey"]
        if m:
            expect(int(m.group(1)) == len(values), f"repair count, expected {len(values)}")
            last = dict(k.rsplit("_c", 1) for k in m.group(2).split(", ")) if m.group(2) else {}
            expect({t: int(n) for t, n in last.items()} == want, f"repair counters, expected {want}")
        expect(after.index == {"entries": {}, "counters": want, "by_fingerprint": {}}, "repair index")
        want_store = ["_maisecrets_fpkey"] if before.store is not None else None   # the fingerprint key stays
        expect(after.store == want_store, f"repair left {after.store} in the store")
        return p
    # an ok state from here: forget, list, status, expire
    ret = _retained(state, before.index) if before.index else {}
    newly = sorted(k for k, purged in ret.items() if purged and not before.index["entries"][k].get("purged"))
    live = sorted(k for k, purged in ret.items() if not purged)
    expired = sorted(k for k, purged in ret.items() if purged)
    after_entries = (after.index or {}).get("entries", {})
    if command == "forget":
        key = args[0]
        if key in (before.index or {}).get("entries", {}):
            expect(r.stdout == f"{key}: deleted. A placeholder for it no longer works anywhere.\n", "forget")
            expect(key not in after_entries and key not in (after.store or []), f"{key} is still there")
            expect(key not in (after.index or {}).get("by_fingerprint", {}).values(), "the fingerprint stays")
            others = sorted(k for k in ret if k != key)
            expect(sorted(after_entries) == others, f"forget left {sorted(after_entries)}, expected {others}")
        else:
            expect(r.stdout == f"{key}: not found (see /maisecrets:list)\n", "forget of an unknown key")
            expect(after.store == before.store and after_entries == (before.index or {}).get("entries", {}),
                   "forget of an unknown key changed the store")
        return p
    # list, status and expire sweep: an expired value leaves the store, old metadata goes
    expect(sorted(after_entries) == sorted(ret), f"after {command} the index holds {sorted(after_entries)}")
    for k in expired:
        if state in REFUSING:
            # the store refused the delete: the entry stays for the next sweep, and get refuses it
            expect(not after_entries.get(k, {}).get("purged") and k in (after.store or []),
                   f"{k} looks purged although the store refused the delete")
            continue
        expect(after_entries.get(k, {}).get("purged") is True, f"{k} is not purged")
        expect(k not in (after.store or []), f"the expired {k} is still in the store")
    for k in live:
        expect(not after_entries[k].get("purged") and k in (after.store or []), f"{k} was lost")
    if command == "list":
        if not ret:
            expect(r.stdout == "Nothing is stored.\n", "list of nothing")
        else:
            lines = r.stdout.splitlines()
            expect(lines[0] == f"{len(live)} value(s) stored, {len(expired)} expired (only the masked form is kept).",
                   "list headline")
            rows = [ln for ln in lines[2:] if re.match(r"[A-Z]+_c\d+ ", ln)]
            expect(sorted(ln.split()[0] for ln in rows) == sorted(ret), "list rows")
            for ln in rows:
                k, typ = ln.split()[:2]
                expect(typ == before.index["entries"][k]["type"], f"{k} row type")
                expect((ln.split()[5] == "expired") == (k in expired), f"{k} row expiry")
            expect(("TEST MODE" in r.stdout) == (STATES[state][2] == "jsonfile"), "list names the test store")
    elif command == "status":
        kept = _KEEP_DAYS.get(state, 30)
        expect(f"\nstored values: {len(live)}, {len(expired)} expired (metadata kept {kept} days)\n" in r.stdout,
               "status counts")
    elif command == "expire":
        expect(r.stdout == f"purged {len(newly)} expired value(s)\n", f"expire should purge {newly}")
        refused = state in REFUSING and bool(expired)
        expect(("still in the store" in r.stderr) == refused, "expire names a refused delete, and only that")
    return p


def all_cells() -> list[tuple[str, str, list[str], str, dict]]:
    return [(state, command, args, stdin, spec)
            for state in STATES for command, invs in MATRIX.items() for args, stdin, spec in invs]


# ------------------------------------------------------------ populations --
def commands_in_markdown() -> dict[str, set[str]]:
    """What each slash command runs: `bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" <cmd> ...`."""
    return {md.name: set(re.findall(r'hooks/run\.sh"\s+([a-z][\w-]*)', md.read_text(encoding="utf-8")))
            for md in sorted((ROOT / "commands").glob("*.md"))}


def commands_in_dispatch() -> set[str]:
    """Every string dispatch.py compares sys.argv[1] with, read from its syntax tree."""
    tree = ast.parse(DISPATCH.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or ast.unparse(node.left) != "sys.argv[1]":
            continue
        for comp in node.comparators:
            for c in ast.walk(comp):
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    names.add(c.value)
    return names


def cli_commands() -> set[str]:
    from maisecrets import cli
    return set(cli.COMMANDS)


def hook_events() -> set[str]:
    from maisecrets import hooks
    return set(hooks.HANDLERS)


class PopulationTests(unittest.TestCase):
    def test_the_derivation_finds_a_command_in_every_slash_command(self):
        found = commands_in_markdown()
        self.assertGreaterEqual(len(found), 8)
        for name, cmds in found.items():
            self.assertTrue(cmds, f"commands/{name} names no run.sh command the test can see")
        self.assertIn("session-start", commands_in_dispatch())
        self.assertIn("pending", commands_in_dispatch())

    def test_every_slash_command_runs_a_command_the_dispatcher_knows(self):
        """A slash command whose name the dispatcher lacks falls through to the hook usage error."""
        known = commands_in_dispatch()
        for name, cmds in commands_in_markdown().items():
            self.assertEqual(sorted(cmds - known), [], f"commands/{name}")

    def test_every_cli_command_is_reachable_and_every_dispatched_one_exists(self):
        # mod-prompt is the question of the mod (claude-mod/maisecrets-mod.mjs), not a command of the CLI
        dispatched = commands_in_dispatch() - {"pending", "session-start", "mod-prompt"}
        self.assertEqual(sorted(dispatched - cli_commands()), [], "dispatch.py sends these to cli.main")
        # resolve is reached through hooks/resolve.py, which the Bash hook writes into a command
        self.assertEqual(sorted(cli_commands() - dispatched), ["resolve"])


class StateMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name in STATES:        # seeded one after the other; the cells then run in parallel
            base_state(name)

    def test_every_command_in_every_store_state(self):
        from concurrent.futures import ThreadPoolExecutor
        cells = all_cells()
        with ThreadPoolExecutor(max_workers=4) as pool:
            problems = [p for ps in pool.map(lambda c: run_cell(*c), cells) for p in ps]
        self.assertEqual(problems, [], f"{len(problems)} of {len(cells)} cells wrong:\n" + "\n".join(problems[:15]))

    def test_the_states_hold_what_they_claim(self):
        """A seed that silently failed would make every cell of its state vacuous."""
        live = base_state("live").index()["entries"]
        self.assertEqual(sorted(live), ["EMAIL_c1", "SECRET_c1", "SECRET_c2"])
        self.assertFalse(any(m.get("purged") for m in live.values()))
        (exp,) = base_state("expired-purged").index()["entries"].values()
        self.assertTrue(exp["purged"] and exp["purged_at"])
        (due,) = base_state("expired-not-yet-purged").index()["entries"].values()
        self.assertTrue(due["expires"] < time.time() and not due.get("purged"))
        for name in ("expired-unswept", "store-refuses-delete"):
            (unswept,) = base_state(name).index()["entries"].values()
            self.assertLess(unswept["expires"], time.time(), name)
            self.assertFalse(unswept.get("purged"), name)
            self.assertIn('"SECRET_c1"', (base_state(name).home / "vault.enc.json").read_text(), name)
        self.assertTrue(base_state("store-refuses-delete").refuse_delete)
        (old,) = base_state("purged-past-retention").index()["entries"].values()
        self.assertGreater(time.time() - old["purged_at"], 30 * 86400)
        self.assertRaises(ValueError, base_state("damaged-index").index)
        self.assertTrue((base_state("jsonfile").home / "vault.json").exists())
        self.assertTrue((base_state("live").home / "vault.enc.json").exists())
        self.assertTrue((base_state("live").home / "events.log").exists())

    def _run(self, state: str, *args: str, stdin: str = "") -> tuple[Sandbox, subprocess.CompletedProcess]:
        sb = base_state(state).copy()
        self.addCleanup(sb.remove)
        return sb, sb.run(*args, stdin=stdin)

    def test_list_and_status_show_an_expired_entry_as_expired(self):
        sb, r = self._run("expired-purged", "list")
        self.assertIn("0 value(s) stored, 1 expired", r.stdout)
        self.assertRegex(r.stdout, r"SECRET_c1\s+SECRET\s+you\s+\S+\s+0\s+expired")
        sb, r = self._run("expired-purged", "status")
        self.assertIn("stored values: 0, 1 expired (metadata kept 30 days)", r.stdout)

    def test_an_expired_entry_before_its_sweep_is_expired_to_every_command(self):
        sb, r = self._run("expired-unswept", "list")
        self.assertIn("0 value(s) stored, 1 expired", r.stdout)
        self.assertNotIn('"SECRET_c1"', (sb.home / "vault.enc.json").read_text(), "the read swept the value")
        sb, r = self._run("expired-unswept", "get", "SECRET_c1")
        self.assertEqual((r.returncode, r.stdout), (1, ""))
        self.assertIn("SECRET_c1: expired", r.stderr)

    def test_a_store_that_refuses_the_delete_keeps_the_entry_and_never_hands_out_the_value(self):
        """The sweep leaves an entry the store will not delete unpurged, and `get` skipped the
        expiry on the human path: `maisecrets get` printed a value past its TTL (suite review,
        2026-09-27)."""
        sb, r = self._run("store-refuses-delete", "get", "SECRET_c1")
        self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
        self.assertIn("SECRET_c1: expired", r.stderr)
        self.assertFalse(any(v in r.stdout + r.stderr for v in sb.values))
        r = sb.run("forget", "SECRET_c1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("the store refused to delete it; nothing was changed", r.stdout)
        self.assertIn("SECRET_c1", sb.index()["entries"], "nothing looks deleted that is not")
        r = sb.run("expire")
        self.assertEqual((r.returncode, r.stdout), (1, "purged 0 expired value(s)\n"), r.stderr)
        self.assertIn("1 expired value(s) are still in the store", r.stderr)
        self.assertFalse(sb.index()["entries"]["SECRET_c1"].get("purged"), "a refused delete is no purge")

    def test_metadata_past_keep_purged_days_is_deleted_by_the_next_read(self):
        sb, r = self._run("purged-past-retention", "list")
        self.assertEqual(r.stdout.strip(), "Nothing is stored.")
        self.assertEqual(sb.index()["entries"], {})
        self.assertEqual(sb.index()["by_fingerprint"], {})

    def test_status_names_the_policy_keys_and_the_config_warning(self):
        _sb, r = self._run("policy", "status")
        self.assertIn("settings from a machine policy: keep_purged_days, max_keys_per_session", r.stdout)
        self.assertIn("metadata kept 3 days", r.stdout)
        _sb, r = self._run("config-wrong-type", "status")
        self.assertIn("WARNING: config.json: tips has the wrong type; the file was ignored", r.stdout)
        _sb, r = self._run("empty", "status")
        self.assertIn("settings from a machine policy: none", r.stdout)
        self.assertIn("stored values in tool calls: automatic (no ask of maisecrets; the client's permission rules "
                      "decide)\n",
                      r.stdout)
        # a file ignored for a wrong type that set no rehydration: the default stays
        _sb, r = self._run("config-wrong-type", "status")
        self.assertIn("stored values in tool calls: automatic (", r.stdout)
        self.assertIn("encrypted file", r.stdout)

    def test_the_test_store_says_so(self):
        _sb, r = self._run("jsonfile", "list")
        self.assertIn("backend: jsonfile (TEST MODE", r.stdout)
        _sb, r = self._run("jsonfile", "status")
        self.assertIn("PLAINTEXT file", r.stdout)
        _sb, r = self._run("live", "list")
        self.assertNotIn("TEST MODE", r.stdout)

    def test_a_damaged_index_names_repair_and_repair_brings_the_store_back(self):
        sb, r = self._run("damaged-index", "list")
        self.assertEqual(r.returncode, 1)
        self.assertRegex(r.stderr, r"run\.(sh|cmd) repair in a terminal")
        self.assertNotIn("Traceback", r.stderr)
        r = sb.run("repair")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("new placeholders continue after the old numbers", r.stdout)
        self.assertEqual(sb.run("list").stdout.strip(), "Nothing is stored.")
        r = sb.run("put", stdin=fake_value())
        self.assertRegex(r.stdout, r"placeholder (?:is )?\u27e6SECRET_c2\b", "the counter continues past the old key")

    def test_a_configuration_error_names_the_file_and_changes_nothing(self):
        for state, where in (("policy-wrong-type", "policy.json: keep_purged_days has the wrong type"),
                             ("jsonfile-not-allowed", "backend jsonfile is the TEST store")):
            with self.subTest(state):
                sb, r = self._run(state, "put", stdin=fake_value())
                self.assertEqual(r.returncode, 1)
                self.assertIn("configuration error", r.stderr)
                self.assertIn(where, r.stderr)
                self.assertNotIn("Traceback", r.stderr)
                self.assertFalse((sb.home / "index.json").exists())

    def test_wipe_yes_deletes_values_index_and_logs_and_keeps_the_config(self):
        sb, r = self._run("live", "wipe", "--yes")
        self.assertIn("wiped: 4 stored value(s)", r.stdout)     # three values and the fingerprint key
        # hooks.log carries the session ids; the notice promises the hook logs go too
        for name in ("index.json", "events.log", "hooks.log", "vault.enc.json", "key"):
            self.assertFalse((sb.home / name).exists(), name)
        self.assertEqual(list((sb.home / "pending").iterdir()), [], "the blocked prompt goes too")
        self.assertTrue((sb.home / "config.json").exists())
        self.assertEqual(sb.run("get", "SECRET_c1").returncode, 1)

    def test_report_prints_a_link_that_names_the_rule_carries_no_value_and_opens_nothing(self):
        sb, r = self._run("live", "report", "last", "a build id")
        link = [x for x in r.stdout.splitlines() if x.startswith("prefilled link: ")]
        self.assertEqual(len(link), 1, r.stdout)
        self.assertIn("https://github.com/Mcpgate-de/maisecrets/issues/new?", link[0])
        self.assertIn("ds-keyword-colon", link[0])
        self.assertIn("a+build+id", link[0])
        self.assertFalse(any(v in r.stdout for v in sb.values))
        self.assertFalse(sb.opened.exists(), "no browser: the person opens the link (docs/DIAGNOSTICS.md, D1)")
        _sb, r = self._run("live", "report")
        self.assertRegex(r.stdout, r"1\s+\S+\s+UserPromptSubmit\s+claude\s+SECRET/ds-keyword-colon")

    def test_put_from_the_clipboard_swaps_the_value_for_the_reference(self):
        sb = base_state("empty").copy()
        self.addCleanup(sb.remove)
        value = fake_value("Cb")
        sb.clip.write_text(value + "\n", encoding="utf-8")
        r = sb.run("put", "--clipboard", "--type=email")
        self.assertIn("Stored. Its placeholder ⟦EMAIL_c1⟧ is in your clipboard: paste it where the value is needed.",
                      r.stdout)
        self.assertEqual(sb.clip.read_text(encoding="utf-8"), "⟦EMAIL_c1⟧")
        self.assertEqual(sb.run("get", "EMAIL_c1").stdout, value + "\n")
        sb.clip.write_text("", encoding="utf-8")
        r = sb.run("put", "--clipboard")
        self.assertEqual(r.returncode, 2)
        self.assertIn("the clipboard is empty. Copy the value first", r.stderr)

    def test_forget_deletes_the_value_and_the_placeholder_stops_resolving(self):
        sb, r = self._run("live", "forget", "⟦SECRET_c1⟧", "EMAIL_c1:x")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(r.stdout.count("deleted"), 2)
        self.assertEqual(sorted(sb.index()["entries"]), ["SECRET_c2"])
        self.assertIn("unknown", sb.run("get", "SECRET_c1").stderr)

    def test_audit_prints_the_newest_rows_and_skips_malformed_ones(self):
        sb = base_state("empty").copy()
        self.addCleanup(sb.remove)
        rows = [f"2026-09-27T10:00:0{i}\tS1\tSECRET_c{i}\tBash\techo ⟦SECRET_c{i}⟧" for i in range(1, 4)]
        (sb.home / "audit.log").write_text("\n".join(rows[:2] + ["broken line"] + rows[2:]) + "\n", encoding="utf-8")
        out = sb.run("audit", "2").stdout.splitlines()
        self.assertEqual(out[0].split(), ["time", "session", "placeholder", "tool", "command"])
        self.assertEqual(len(out), 2, out)          # the header and the newest valid row
        self.assertIn("SECRET_c3", out[1])

    def test_shortcut_installs_under_the_config_dir_and_refuses_a_path_as_a_name(self):
        sb = base_state("empty").copy()
        self.addCleanup(sb.remove)
        r = sb.run("shortcut", "../evil")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Installed /ms.", r.stdout)
        commands = sb.user_home / ".claude" / "commands"
        self.assertEqual(sorted(p.name for p in commands.iterdir()), ["ms.md"])
        self.assertFalse((sb.user_home / ".claude" / "evil.md").exists())
        self.assertEqual((sb.home / ".shortcut").read_text().strip(), "installed")
        r = sb.run("shortcut", "--remove")
        self.assertIn("ms.md", r.stdout)
        self.assertFalse((commands / "ms.md").exists())
        self.assertEqual((sb.home / ".shortcut").read_text().strip(), "removed")

    @unittest.skipIf(os.name == "nt", "the guard is POSIX only; `guard install` refuses on Windows")
    def test_the_guard_installs_beside_the_settings_and_keeps_the_users_own_hooks(self):
        sb = base_state("empty").copy()
        self.addCleanup(sb.remove)
        claude = sb.user_home / ".claude"
        claude.mkdir(parents=True, exist_ok=True)
        own = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/my-own-hook"}]}
        (claude / "settings.json").write_text(json.dumps({"model": "x", "hooks": {"PreToolUse": [own]}}))
        for _ in range(2):                                   # installing twice leaves one entry per event
            r = sb.run("guard", "install")
            self.assertEqual(r.returncode, 0, r.stderr)
        settings = json.loads((claude / "settings.json").read_text())
        self.assertEqual(settings["model"], "x", "only the hooks change")
        plugin = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]
        for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse"):
            ours = [e for e in settings["hooks"][event] if "maisecrets-guard.py" in e["hooks"][0]["command"]]
            self.assertEqual(len(ours), 1, event)
            self.assertEqual(ours[0].get("matcher"), plugin[event][0].get("matcher"), f"{event}: the plugin's matcher")
        self.assertIn(own, settings["hooks"]["PreToolUse"], "the user's own hook stays")
        self.assertTrue((claude / "maisecrets-guard.py").exists())
        self.assertEqual(json.loads((sb.home / "guard.json").read_text()), {"expect": "synced"})
        self.assertTrue(list(claude.glob("settings.json.bak-maisecrets-*")), "a backup before the change")
        self.assertIn("registered in", sb.run("guard", "status").stdout)
        r = sb.run("guard", "remove")
        settings = json.loads((claude / "settings.json").read_text())
        self.assertEqual(settings["hooks"], {"PreToolUse": [own]}, "remove takes out ours and only ours")
        self.assertFalse((claude / "maisecrets-guard.py").exists())
        self.assertFalse((sb.home / "guard.json").exists(), "no guard, no heartbeat")

    def test_pending_hands_out_the_blocked_prompt_once(self):
        sb, r = self._run("live", "pending")
        self.assertEqual(r.stdout.strip(), "password: ⟦SECRET_c2⟧")
        self.assertEqual(sb.run("pending").stdout.strip(), NOTHING_WAITING)

    def test_a_false_positive_report_names_the_value_to_forget_and_deletes_nothing(self):
        sb = base_state("live").copy()
        self.addCleanup(sb.remove)
        sb.block_prompt(session="SR")
        entries = sb.index()["entries"]
        newest = max(entries, key=lambda k: entries[k]["created"])
        before = set(entries)
        r = sb.run("report", "last", "a product word, not a password")
        self.assertIn(f"/maisecrets:forget {newest}", r.stdout)
        # the events are shared by all sessions, and a model can run this command: nothing goes by itself
        self.assertEqual(set(sb.index()["entries"]), before)

    def test_pending_takes_the_prompt_of_its_own_session_when_two_wait(self):
        sb = base_state("live").copy()          # the base is shared: every run works on a copy
        self.addCleanup(sb.remove)
        a = sb.block_prompt(session="SA")
        b = sb.block_prompt(session="SB")
        # without a session id the command cannot tell them apart and says so
        self.assertIn("two sessions are waiting", sb.run("pending").stdout)
        r = sb.run("pending", env=sb.env(CLAUDE_CODE_SESSION_ID="SB"))
        self.assertIn("password: ", r.stdout)
        self.assertNotIn(a, r.stdout)
        self.assertNotIn(b, r.stdout, "the pending prompt holds placeholders, never the value")
        # a session with no prompt of its own never gets another session's
        r = sb.run("pending", env=sb.env(CLAUDE_CODE_SESSION_ID="SC"))
        self.assertEqual(r.stdout.strip(), NOTHING_WAITING)
        r = sb.run("pending", env=sb.env(CLAUDE_CODE_SESSION_ID="SA"))
        self.assertIn("password: ", r.stdout)
        self.assertEqual(sb.run("pending", env=sb.env(CLAUDE_CODE_SESSION_ID="SA")).stdout.strip(),
                         NOTHING_WAITING, "handed out once")

    def test_a_session_id_is_a_name_never_a_path(self):
        sb = base_state("live").copy()
        self.addCleanup(sb.remove)
        sb.block_prompt(session="SA")
        for bad in ("../pending/SA", "SA/../SA", ".hidden", "a b"):
            with self.subTest(bad):
                r = sb.run("pending", env=sb.env(CLAUDE_CODE_SESSION_ID=bad))
                self.assertEqual(r.stdout.strip(), NOTHING_WAITING)

    def test_scan_prints_positions_not_the_text(self):
        value = fake_value("Sc")
        _sb, r = self._run("empty", "scan", f"password: {value}")
        self.assertRegex(r.stdout, r"^SECRET\s+\S+\s+at 10-32 \(len 22\)$")


# ----------------------------------------------------------- session start --
def _start(case: unittest.TestCase, sb: Sandbox, payload: object = None, stdin: str | None = None,
           **env: str) -> dict:
    text = stdin if stdin is not None else json.dumps(payload if payload is not None else {})
    r = sb.run("session-start", stdin=text, env=sb.env(**env))
    case.assertEqual(r.returncode, 0, r.stderr)
    case.assertNotIn("Traceback", r.stdout + r.stderr)
    return json.loads(r.stdout)


class SessionStartTests(unittest.TestCase):
    def sandbox(self, config: dict | None = None, **kw) -> Sandbox:
        sb = Sandbox(config if config is not None else ENC, **kw)
        self.addCleanup(sb.remove)
        return sb

    def test_the_try_it_example_is_one_the_prompt_hook_stops(self):
        from maisecrets import tips
        self.assertIn(tips.TRY_IT_EXAMPLE, tips.try_it_line())
        sb = self.sandbox()
        r = sb.run("user-prompt", stdin=json.dumps({"prompt": tips.TRY_IT_EXAMPLE, "session_id": "S1",
                                                    "transcript_path": "", "prompt_id": "p1"}))
        out = json.loads(r.stdout)
        self.assertEqual(out.get("decision"), "block", r.stdout + r.stderr)
        self.assertIn("personal data was found", out.get("reason", "") + out.get("systemMessage", ""))
        self.assertEqual([m["type"] for m in sb.index()["entries"].values()], ["EMAIL"])

    def test_first_start_introduces_later_starts_rotate_a_tip_then_stay_short(self):
        from maisecrets import hooks, tips
        sb = self.sandbox()
        out = _start(self, sb, CLAUDECODE="1")
        msg = out["systemMessage"]
        self.assertTrue(msg.startswith(f"maisecrets {VERSION} is on. It keeps passwords"), msg)
        self.assertIn("in an encrypted file", msg)
        self.assertIn("/maisecrets:status shows the details", msg)
        self.assertIn(" " + tips.try_it_line() + " ", msg, "the first start says how to see it work")
        self.assertTrue(msg.endswith(" Tip: /maisecrets:shortcut adds /ms as a short form of /maisecrets:send."))
        self.assertEqual(out["hookSpecificOutput"], {"hookEventName": "SessionStart",
                                                     "additionalContext": hooks.primer()})
        self.assertEqual((sb.home / ".announced").read_text().strip(), "EncryptedFileBackend")
        self.assertEqual((sb.home / ".shortcut").read_text().strip(), "offered")
        self.assertFalse((sb.user_home / ".claude" / "commands").exists(), "the offer installs nothing")
        second = _start(self, sb, CLAUDECODE="1")["systemMessage"]
        self.assertEqual(second, f"maisecrets {VERSION} is on. {tips.TIPS[0]}")
        third = _start(self, sb, CLAUDECODE="1")
        self.assertEqual(third["systemMessage"], f"maisecrets {VERSION} is on.")
        self.assertEqual(third["hookSpecificOutput"]["additionalContext"], hooks.primer())

    def test_the_tip_comes_from_the_pool_of_the_client(self):
        from maisecrets import tips
        for client, env, pool in (("claude", {"CLAUDECODE": "1"}, tips.TIPS),
                                  ("codex", {"CODEX_THREAD_ID": "t1"}, tips.TIPS_CODEX)):
            with self.subTest(client):
                sb = self.sandbox()
                (sb.home / ".announced").write_text("EncryptedFileBackend\n")
                (sb.home / ".shortcut").write_text("offered\n")
                (sb.home / ".tip").write_text("2000-01-01 1\n")
                # the ms:(…) hint of Codex is given already (tests/test_check_value.py has its own case)
                (sb.home / "hints.json").write_text('{"check_value": {"revision": 99, "given": "2000-01-01"}}')
                msg = _start(self, sb, **env)["systemMessage"]
                self.assertEqual(msg, f"maisecrets {VERSION} is on. {pool[2]}")
        self.assertNotEqual(tips.TIPS[2], tips.TIPS_CODEX[2], "the case above must tell the pools apart")

    def test_the_start_line_names_the_rules_of_your_own_and_warns_of_a_missing_rule_folder(self):
        sb = self.sandbox()
        gone = str(sb.root / "team-rules")
        # no tips: the tip is one per calendar day, so two starts around midnight differed by a tip (CI, 00:00 UTC)
        (sb.home / "config.json").write_text(json.dumps({**ENC, "rule_dirs": [gone], "tips": False}),
                                             encoding="utf-8")
        (sb.home / ".announced").write_text("EncryptedFileBackend\n")
        (sb.home / ".shortcut").write_text("offered\n")
        (sb.home / "rules.d").mkdir()
        (sb.home / "rules.d" / "own.json").write_text(json.dumps({"rules": [
            {"id": "one", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]},
            {"id": "two", "regex": r"tky_[A-Za-z0-9]{24}", "keywords": ["tky_"]}]}), encoding="utf-8")
        warning = f"Warning: the rule folder {gone} (setting) is missing, so its rules of your own do not run."
        first = _start(self, sb, CLAUDECODE="1")["systemMessage"]
        line = f"maisecrets {VERSION} is on, with 2 rules of your own from 1 folder."
        self.assertTrue(first.startswith(line + " "), first)
        self.assertTrue(first.endswith(" " + warning), first)
        again = _start(self, sb, CLAUDECODE="1")["systemMessage"]
        self.assertEqual(again, f"{line} {warning}",
                         "the warning comes at every start while the folder is missing")

    def test_codex_is_told_from_claude_code_by_transcript_then_claudecode_then_codex_vars(self):
        cases = [
            # (name, transcript path under the sandbox root or None, env, codex?)
            ("rollout under CODEX_HOME although CLAUDECODE=1", "codex/sessions/r.jsonl",
             {"CODEX_HOME": "codex", "CLAUDECODE": "1"}, True),
            ("rollout under the default ~/.codex", "home/.codex/sessions/r.jsonl", {}, True),
            ("Claude transcript although a CODEX_ variable is set", "home/.claude/projects/p/t.jsonl",
             {"CODEX_THREAD_ID": "t1"}, False),
            ("a sibling folder that only shares the prefix", "codex-other/r.jsonl", {"CODEX_HOME": "codex"}, False),
            ("no transcript: CLAUDECODE=1 wins over a CODEX_ variable", None,
             {"CLAUDECODE": "1", "CODEX_THREAD_ID": "t1"}, False),
            ("no transcript: a CODEX_ variable", None, {"CODEX_THREAD_ID": "t1"}, True),
            ("no transcript, no hint", None, {}, False),
        ]
        for name, transcript, env, codex in cases:
            with self.subTest(name):
                sb = self.sandbox()
                env = {k: (str(sb.root / v) if k == "CODEX_HOME" else v) for k, v in env.items()}
                payload = {"transcript_path": str(sb.root / transcript)} if transcript else {}
                msg = _start(self, sb, payload, **env)["systemMessage"]
                self.assertEqual("/maisecrets:" not in msg, codex, msg)
                self.assertEqual((sb.home / ".shortcut").exists(), not codex)

    def test_the_start_quiets_a_statement_keyword_an_old_detector_stored(self):
        # an entry of a version before 0.5.15: the current detector stores no such value, so it is seeded directly
        sb = self.sandbox()
        seed = ("from maisecrets.vault import Vault\n"
                "v = Vault()\n"
                "print(v.put('continue', 'SECRET', 'ds-keyword-colon', session='S0').key)\n"
                "print(v.put('Sommerwiese', 'SECRET', 'ds-keyword-colon', session='S0').key)\n")
        r = subprocess.run([sys.executable, "-c", seed], capture_output=True, encoding="utf-8", env=sb.env(),
                           cwd=str(ROOT), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        old, real = r.stdout.split()
        (sb.home / ".announced").write_text("EncryptedFileBackend\n")
        (sb.home / ".shortcut").write_text("offered\n")
        (sb.home / ".tip").write_text("2000-01-01 1\n")
        msg = _start(self, sb, CLAUDECODE="1")["systemMessage"]
        self.assertIn(f"1 stored word(s) are program code, not secrets ({old})", msg)
        self.assertIn("/maisecrets:forget deletes them", msg)
        entries = sb.index()["entries"]
        self.assertEqual(sorted(entries), sorted([old, real]), "nothing is deleted")
        self.assertIs(entries[old].get("weak"), True)
        self.assertNotIn("program code", _start(self, sb, CLAUDECODE="1")["systemMessage"], "said once")

    def test_the_start_marks_a_word_an_older_version_stored_so_it_is_not_hunted(self):
        sb = self.sandbox()
        seed = ("import json\nfrom maisecrets.vault import INDEX, Vault\n"
                "k = Vault().put('postgres', 'SECRET', 'ds-keyword-equal-signs', session='S0').key\n"
                "idx = json.loads(INDEX.read_text()); del idx['entries'][k]['weak']\n"
                "INDEX.write_text(json.dumps(idx))\n"
                "print(k)\n")
        r = subprocess.run([sys.executable, "-c", seed], capture_output=True, encoding="utf-8", env=sb.env(),
                           cwd=str(ROOT), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        key = r.stdout.strip()
        _start(self, sb, CLAUDECODE="1")
        self.assertIs(sb.index()["entries"][key].get("weak"), True)

    def test_the_test_store_introduces_itself_at_every_start(self):
        sb = self.sandbox(JSONFILE, backend="jsonfile")
        for _ in range(2):
            self.assertIn("in a PLAIN TEXT test file", _start(self, sb, CLAUDECODE="1")["systemMessage"])

    def test_shortcut_false_in_the_config_means_no_offer(self):
        sb = self.sandbox({"backend": "encrypted-file", "shortcut": False})
        msg = _start(self, sb, CLAUDECODE="1")["systemMessage"]
        self.assertNotIn("/maisecrets:shortcut", msg)
        self.assertFalse((sb.home / ".shortcut").exists())

    def test_a_config_warning_is_shown_and_a_config_error_blocks(self):
        sb = self.sandbox({"backend": "encrypted-file", "shortcutt": 1, "shortcut": False})
        msg = _start(self, sb, CLAUDECODE="1")["systemMessage"]
        self.assertTrue(msg.endswith(" Warning: config.json: unknown key(s) shortcutt ignored."), msg)
        sb = self.sandbox(policy={"keep_purged_days": "thirty"})
        out = _start(self, sb, CLAUDECODE="1")
        self.assertEqual(out, {"systemMessage": "maisecrets: configuration error: policy.json: keep_purged_days "
                                                "has the wrong type. Every prompt is blocked until the file is fixed."})
        self.assertFalse((sb.home / ".announced").exists())

    def test_a_damaged_index_is_reported_at_session_start_not_crashed(self):
        sb = self.sandbox()
        (sb.home / "index.json").write_text('{"entries": {', encoding="utf-8")
        out = _start(self, sb, CLAUDECODE="1")
        self.assertIn("its list of stored values (index.json) is damaged", out["systemMessage"])
        self.assertRegex(out["systemMessage"], r"run\.(sh|cmd) repair in a terminal")
        self.assertEqual((sb.home / "index.json").read_text(), '{"entries": {', "the damaged file stays")

    def test_a_payload_that_is_not_an_object_counts_as_empty(self):
        for text in ("not json", "[1, 2]"):
            with self.subTest(text):
                sb = self.sandbox()
                self.assertIn("is on. It keeps", _start(self, sb, stdin=text, CLAUDECODE="1")["systemMessage"])

    def test_session_start_purges_every_expired_value(self):
        sb = self.sandbox()
        keys = [sb.put() for _ in range(3)]
        sb.write_index({**sb.index(), "entries": {k: {**m, "expires": time.time() - 5}
                                                  for k, m in sb.index()["entries"].items()}})
        _start(self, sb, CLAUDECODE="1")
        entries = sb.index()["entries"]
        self.assertTrue(all(entries[k]["purged"] for k in keys))
        stored = json.loads((sb.home / "vault.enc.json").read_text())
        self.assertEqual(sorted(stored), ["_maisecrets_fpkey"])


# -------------------------------------------------------------- hook events --
class HookEventTests(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(self.sb.remove)

    def test_user_prompt_blocks_and_records_an_event_without_the_value(self):
        value = fake_value("Up")
        r = self.sb.run("user-prompt", stdin=json.dumps({"prompt": f"password: {value}", "session_id": "S1",
                                                         "transcript_path": "", "prompt_id": "p"}))
        out = json.loads(r.stdout)
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(value, r.stdout + r.stderr)
        events = (self.sb.home / "events.log").read_text()
        self.assertIn('"hook": "UserPromptSubmit"', events)
        self.assertNotIn(value, events)
        log = (self.sb.home / "hooks.log").read_text()
        self.assertRegex(log, r"\tuser-prompt\tclaude\tS1\t-\tblock\t\d+ms\tok\n")

    def test_the_mod_prompt_answers_a_rewrite_without_the_value_through_the_dispatcher(self):
        value = fake_value("Mp")
        r = self.sb.run("mod-prompt", stdin=json.dumps({"prompt": f"password: {value}", "session_id": "S1"}))
        out = json.loads(r.stdout)
        self.assertEqual((r.returncode, out["maisecrets"], out["text"]), (0, "mod-prompt", "password: ⟦SECRET_c1⟧"))
        self.assertNotIn(value, r.stdout + r.stderr)
        self.assertNotIn(value, (self.sb.home / "events.log").read_text())

    def test_pre_tool_and_post_tool_answer_through_the_dispatcher(self):
        r = self.sb.run("pre-tool", stdin=json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"},
                                                      "session_id": "S1", "prompt_id": "p"}))
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "{}"))
        value = fake_value("Po")
        r = self.sb.run("post-tool", stdin=json.dumps({"tool_name": "Bash", "session_id": "S1", "prompt_id": "p",
                                                       "tool_response": {"stdout": f"api_key={value}"}}))
        self.assertEqual(r.returncode, 0)
        self.assertNotIn(value, r.stdout)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["updatedToolOutput"],
                         {"stdout": "api_key=⟦SECRET_c1⟧"})

    def test_an_unknown_event_and_a_bad_payload_fail_closed(self):
        for args in (("bogus",), ()):
            r = self.sb.run(*args, stdin="{}")
            self.assertEqual(r.returncode, 2, args)
            self.assertIn("usage: dispatch.py", r.stderr)
        r = self.sb.run("user-prompt", stdin="not json")
        self.assertEqual((r.returncode, json.loads(r.stdout)["decision"]), (0, "block"))
        r = self.sb.run("post-tool-failure", stdin=json.dumps({"tool_name": "Bash", "session_id": "S1",
                                                                "error": "Exit code 1\nnothing here"}))
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "{}"), r.stderr)
        r = self.sb.run("post-tool", stdin="not json")
        self.assertEqual(r.returncode, 0, "exit 2 is ignored after a tool; the answer must withhold instead")
        self.assertIn("its output is withheld", json.loads(r.stdout)["hookSpecificOutput"]["updatedToolOutput"])


# ----------------------------------------------------- client x state x event --
PAIR_STATES = ("empty", "live", "expired-unswept", "expired-purged", "damaged-index", "policy")
PAIR_EVENTS = ("session-start", "user-prompt", "pre-tool", "post-tool")
# what a Bash reference to the newest key of each state gets: the value, or a deny that names why
PAIR_PRE = {"empty": "(no such placeholder)", "live": None, "expired-unswept": "(expired)",
            "expired-purged": "(expired)", "damaged-index": "did NOT run", "policy": "(not given in this session)"}


def pair_cells() -> list[tuple[str, str, str]]:
    """Every state with every event, the client alternating: each pair of the three factors
    (client-state, client-event, state-event) occurs in 24 runs instead of 48."""
    return [(state, event, ("claude", "codex")[(i + j) % 2])
            for i, state in enumerate(PAIR_STATES) for j, event in enumerate(PAIR_EVENTS)]


def newest_key(sb: Sandbox) -> str:
    try:
        entries = sb.index()["entries"]
    except (OSError, ValueError):
        return "SECRET_c1"
    return max(entries, key=lambda k: entries[k]["created"]) if entries else "SECRET_c1"


def run_pair(state: str, event: str, client: str) -> list[str]:
    """One hook event from one client in one store state, through hooks/dispatch.py."""
    sb = base_state(state).copy()
    try:
        cell = f"{state} / {event} / {client}"
        marker = {"prompt_id": "p"} if client == "claude" else {"turn_id": "t", "model": "m"}
        env = sb.env()
        key = newest_key(sb)
        fresh = fake_value("Pr")
        if event == "session-start":
            if client == "codex":
                env["CODEX_HOME"] = str(sb.user_home / ".codex")
                path = sb.user_home / ".codex" / "sessions" / "r.jsonl"
            else:
                env["CLAUDECODE"] = "1"
                path = sb.user_home / ".claude" / "projects" / "p" / "t.jsonl"
            payload = {"session_id": "S1", "transcript_path": str(path), "source": "startup"}
            if client == "codex":
                payload["model"] = "m"
        elif event == "user-prompt":
            payload = dict(marker, prompt=f"password: {fresh}", session_id="S1", transcript_path="")
        elif event == "pre-tool":
            payload = dict(marker, tool_name="Bash", tool_input={"command": f"printf '%s' ⟦{key}⟧"}, session_id="S1")
        else:
            # a value past its TTL is no longer one the store protects: the put of the fresh value
            # sweeps it first, so only a live stored value is expected back as a placeholder
            stored = "" if state.startswith("expired") else sb.by_key.get(key, "")
            payload = dict(marker, tool_name="Bash", session_id="S1", transcript_path="",
                           tool_response={"stdout": f"password: {fresh} and {stored}\n", "stderr": ""})
        r = sb.run(event, stdin=json.dumps(payload), env=env)
        problems = []
        if r.returncode != 0 or "Traceback" in r.stdout + r.stderr:
            return [f"{cell}: exit {r.returncode}: {(r.stdout + r.stderr)[-300:]!r}"]
        if any(v in r.stdout + r.stderr for v in sb.values + [fresh]):
            problems.append(f"{cell}: a value is in the answer")
        try:
            out = json.loads(r.stdout)
        except ValueError:
            return problems + [f"{cell}: not one JSON object: {r.stdout[:200]!r}"]
        hso = out.get("hookSpecificOutput") or {}
        damaged = state == "damaged-index"
        if event == "session-start":
            msg = out.get("systemMessage", "")
            if damaged:
                if " repair in a terminal" not in msg:
                    problems.append(f"{cell}: the message does not name repair: {msg!r}")
            elif hso != {"hookEventName": "SessionStart", "additionalContext": hooks_primer()}:
                problems.append(f"{cell}: no primer: {hso!r}")
            elif (client == "codex") == ("/maisecrets:" in msg):
                problems.append(f"{cell}: a slash command is {'named to Codex' if client == 'codex' else 'missing'}")
        elif event == "user-prompt":
            if out.get("decision") != "block":
                problems.append(f"{cell}: not blocked: {out!r}")
            if client == "codex" and set(out) != {"decision", "reason"}:
                problems.append(f"{cell}: Codex got fields it rejects: {sorted(out)}")
            if client == "claude" and hso.get("suppressOriginalPrompt") is not True:
                problems.append(f"{cell}: Claude Code would still send the prompt")
        elif event == "pre-tool":
            want = PAIR_PRE[state]
            reason = hso.get("permissionDecisionReason", "")
            if client == "codex" and os.name == "nt":
                # Codex for Windows runs PowerShell, whose quoting the rewrite does not support: every
                # command with a placeholder is refused, before the key is looked at (hooks._pre_bash)
                if hso.get("permissionDecision") != "deny" or not ("Codex for Windows" in reason or
                                                                   (want and want in reason)):
                    problems.append(f"{cell}: expected the Codex-for-Windows deny: {hso!r}")
            elif want is None:
                decision = hso.get("permissionDecision")
                if decision != ("allow" if client == "codex" else None):
                    problems.append(f"{cell}: permissionDecision {decision!r}")
                got = subprocess.run(["bash", "-c", hso.get("updatedInput", {}).get("command", "exit 9")],
                                     capture_output=True, text=True, env=env, timeout=30)
                if got.stdout != sb.by_key.get(key):
                    problems.append(f"{cell}: the value did not arrive: {got.returncode} {got.stderr[-200:]!r}")
            elif hso.get("permissionDecision") != "deny" or want not in reason:
                problems.append(f"{cell}: expected a deny naming {want!r}: {hso!r}")
        else:
            text = json.dumps(out, ensure_ascii=False)
            if damaged:
                if "withheld" not in text:
                    problems.append(f"{cell}: the output was not withheld: {text[:200]!r}")
            elif client == "codex" and (out.get("decision") != "block" or "⟦" not in out.get("reason", "")):
                problems.append(f"{cell}: Codex did not get the redacted text as the block reason")
            elif client == "claude" and "⟦" not in json.dumps(hso.get("updatedToolOutput"), ensure_ascii=False):
                problems.append(f"{cell}: Claude Code did not get updatedToolOutput")
        return problems
    finally:
        sb.remove()


def hooks_primer() -> str:
    from maisecrets import hooks
    return hooks.primer()


class ClientStateEventTests(unittest.TestCase):
    """The client (Claude Code or Codex payload) crossed with the store states for the four hook
    events, pairwise: the payload decides the answer shape, the state decides the outcome, and no
    run prints a value or leaves a value-serving child behind (suite review, 2026-09-27)."""
    RUNS = {"session-start", "user-prompt", "pre-tool", "post-tool"}

    def test_every_pair_of_client_state_and_event(self):
        from concurrent.futures import ThreadPoolExecutor
        cells = pair_cells()
        self.assertEqual(len({(s, c) for s, _e, c in cells}), 12)
        self.assertEqual(len({(e, c) for _s, e, c in cells}), 8)
        with ThreadPoolExecutor(max_workers=4) as pool:
            problems = [p for ps in pool.map(lambda c: run_pair(*c), cells) for p in ps]
        self.assertEqual(problems, [], f"{len(problems)} of {len(cells)} cells wrong:\n" + "\n".join(problems[:12]))
        self.assertEqual(_hygiene.wait_for_no_serving_child(cwd_root=_isolate.TMP), [])


# ------------------------------------------------------------------ resolve --
_GRANT = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets.vault import Vault; v = Vault(); "
          "e = v.put(sys.stdin.read(), 'SECRET', 'manual', session='S1'); "
          "n, st = v.grant(e.key, 'S1', 'Bash', 'echo ' + e.ref); print(e.key, n, st)")


class ResolveTests(unittest.TestCase):
    """hooks/resolve.py: the command the Bash hook writes in place of a placeholder on Windows."""
    def setUp(self):
        self.sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(self.sb.remove)
        # quotes, a substitution, a backtick, a backslash, spaces and a newline
        self.value = "pa$s'w\"ord`x $(echo no) y\\z\n" + fake_value("Rs")
        r = subprocess.run([sys.executable, "-c", _GRANT, str(ROOT)], input=self.value, capture_output=True,
                           text=True, env=self.sb.env(), timeout=60)
        self.key, self.nonce, status = r.stdout.split()
        self.assertEqual(status, "ok", r.stderr)

    def resolve(self, *args: str) -> subprocess.CompletedProcess:
        return self.sb.run(*args, script=RESOLVE)

    def test_a_grant_reads_the_value_byte_for_byte_and_is_used_up(self):
        for _ in range(3):
            r = self.resolve(self.key, "--grant", self.nonce)
            self.assertEqual((r.returncode, r.stdout), (0, self.value))
        r = self.resolve(self.key, "--grant", self.nonce)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, "")
        self.assertIn(f"maisecrets resolve {self.key}: grant-used", r.stderr)
        self.assertNotIn(self.value, r.stderr)

    def test_a_wrong_nonce_a_wrong_key_or_bad_arguments_read_nothing(self):
        for args, rc, word in (((self.key, "--grant", "x" * 22), 1, "no-grant"),
                               (("EMAIL_c1", "--grant", self.nonce), 1, "no-grant"),
                               ((self.key, self.nonce), 2, "usage"),
                               ((self.key, "--nonce", self.nonce), 2, "usage"),
                               ((), 2, "usage")):
            with self.subTest(args=args):
                r = self.resolve(*args)
                self.assertEqual((r.returncode, r.stdout), (rc, ""))
                self.assertIn(word, r.stderr)
        self.assertEqual(self.resolve(self.key, "--grant", self.nonce).stdout, self.value, "the grant is intact")

    def test_an_expired_grant_reads_nothing(self):
        data = self.sb.index()
        data["grants"][self.nonce]["expires"] = time.time() - 1
        self.sb.write_index(data)
        r = self.resolve(self.key, "--grant", self.nonce)
        self.assertEqual((r.returncode, r.stdout), (1, ""))
        self.assertIn("grant-expired", r.stderr)

    def test_the_audit_names_the_grant_and_never_the_value(self):
        r = self.sb.run("audit")
        self.assertRegex(r.stdout, rf"\n\S+\s+S1\s+{self.key}\s+Bash\s+echo ⟦{self.key}⟧")
        self.assertNotIn(self.value.split("\n")[1], (self.sb.home / "audit.log").read_text())


# ------------------------------------------------------------------- events --
class EventsTests(unittest.TestCase):
    def setUp(self):
        from maisecrets import events
        self.events = events
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-events-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        for name, val in (("EVENTS", self.dir / "events.log"), ("HOME", self.dir)):
            p = mock.patch.object(events, name, val)
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def hit(i: int = 1, **kw) -> SimpleNamespace:
        base = {"key": f"SECRET_c{i}", "type": "SECRET", "kind": "gitlab-pat",
                "value": fake_value("Ev"), "display": "glp…" + fake_value("Ds")}
        return SimpleNamespace(**{**base, **kw})

    def test_the_log_keeps_the_newest_KEEP_events(self):  # noqa: N802
        ev = self.events
        for i in range(ev.KEEP + 5):
            ev.record("UserPromptSubmit", "claude", [self.hit(i)])
        lines = ev.EVENTS.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), ev.KEEP)
        self.assertEqual(json.loads(lines[0])["hits"][0]["key"], "SECRET_c5")
        self.assertEqual(json.loads(lines[-1])["hits"][0]["key"], f"SECRET_c{ev.KEEP + 4}")

    def test_an_event_holds_key_type_and_kind_and_never_the_value_or_its_display(self):
        h = self.hit()
        self.events.record("PostToolUse", "codex", [h])
        text = self.events.EVENTS.read_text(encoding="utf-8")
        self.assertNotIn(h.value, text)
        self.assertNotIn(h.display, text)
        ev = json.loads(text)
        self.assertEqual(sorted(ev), ["client", "hits", "hook", "ts", "version"])
        self.assertEqual(ev["hits"], [{"key": "SECRET_c1", "type": "SECRET", "kind": "gitlab-pat"}])
        self.assertEqual((ev["hook"], ev["client"], ev["version"]), ("PostToolUse", "codex", VERSION))
        if os.name != "nt":  # Windows keeps no POSIX mode (st_mode & 0o777 is 0o666)
            self.assertEqual(self.events.EVENTS.stat().st_mode & 0o777, 0o600)

    def test_no_hit_writes_nothing_and_an_unwritable_home_raises_nothing(self):
        self.events.record("UserPromptSubmit", "claude", [])
        self.assertFalse(self.events.EVENTS.exists())
        blocker = self.dir / "file"
        blocker.write_text("x")
        with mock.patch.object(self.events, "HOME", blocker), \
                mock.patch.object(self.events, "EVENTS", blocker / "events.log"):
            self.events.record("UserPromptSubmit", "claude", [self.hit()])
            self.assertEqual(self.events.load(), [])

    def test_load_returns_the_last_n_and_skips_a_broken_line(self):
        good = [json.dumps({"hits": [], "n": i}) for i in range(4)]
        self.events.EVENTS.write_text("\n".join(good[:2] + ["{broken"] + good[2:]) + "\n", encoding="utf-8")
        self.assertEqual([e["n"] for e in self.events.load(2)], [2, 3])
        self.assertEqual([e["n"] for e in self.events.load()], [0, 1, 2, 3])

    def test_issue_url_names_the_first_rule_and_says_how_to_describe_a_shape(self):
        import urllib.parse
        ev = {"ts": "2026-09-27T10:00:00", "hook": "UserPromptSubmit", "client": "claude", "version": "9.9.9",
              "hits": [{"type": "SECRET", "kind": "gitlab-pat"}, {"type": "EMAIL", "kind": "email"}]}
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.events.issue_url(ev)).query)
        self.assertEqual(q["title"], ["False positive: gitlab-pat (SECRET)"])
        self.assertEqual(q["labels"], ["false-positive"])
        body = q["body"][0]
        self.assertIn("- hits: SECRET via `gitlab-pat`, EMAIL via `email`", body)
        self.assertIn("- plugin version: 9.9.9", body)
        self.assertIn("describe the shape of the text, not the value itself", body)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.events.issue_url({}, "my note")).query)
        self.assertEqual(q["title"], ["False positive: ? (?)"])
        self.assertIn("my note", q["body"][0])

    def test_a_bug_or_feature_link_without_text_asks_for_it(self):
        import urllib.parse
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.events.generic_issue_url("bug", "  ")).query)
        self.assertEqual(q["title"], ["Bug: (describe it)"])
        self.assertIn("## What happened\n(describe it here)", q["body"][0])
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.events.generic_issue_url("feature", "x" * 90)).query)
        self.assertEqual(q["title"], ["Feature: " + "x" * 70])
        self.assertEqual(q["labels"], ["enhancement"])
        self.assertIn(f"plugin version: {VERSION}", q["body"][0])

    def test_plugin_version_reads_the_manifest_and_falls_back(self):
        self.assertEqual(self.events.plugin_version(), VERSION)
        with mock.patch("pathlib.Path.read_text", side_effect=OSError):
            self.assertEqual(self.events.plugin_version(), "?")

    def test_no_report_form_opens_a_browser_or_starts_a_program(self):
        # docs/DIAGNOSTICS.md, D1: the person opens the link; maisecrets runs neither a browser nor gh
        from maisecrets import cli
        import webbrowser
        for args in (["bug", "a", "text"], ["feature", "x"], ["bug", "--create", "x"], ["--create", "incident"],
                     ["incident"], ["incident", "clear"], ["last"], []):
            with self.subTest(args), mock.patch("subprocess.run", side_effect=AssertionError("a program")), \
                    mock.patch("subprocess.Popen", side_effect=AssertionError("a program")), \
                    mock.patch.object(webbrowser, "open", side_effect=AssertionError("a browser")), \
                    mock.patch.object(os, "startfile", side_effect=AssertionError("a browser"), create=True), \
                    mock.patch.object(os, "system", side_effect=AssertionError("a program")), \
                    mock.patch.object(sys.stdout, "isatty", return_value=False), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.cmd_report(list(args)), 0)

    def test_the_incident_report_prints_to_a_terminal_only_and_starts_nothing_there(self):
        # the terminal branch (codex and Opus, code review round 1: no test reached it)
        from maisecrets import cli, incidents
        incidents.record_path().write_text(incidents.dumps(incidents.add({}, {
            "code": "store.lock", "cause": "lock", "class": "fail-closed", "event": "UserPromptSubmit"})))
        self.addCleanup(lambda: incidents.clear())
        for tty, want in ((True, "store.lock/lock"), (False, "shown to a person only")):
            out = io.StringIO()
            out.isatty = lambda tty=tty: tty
            with self.subTest(tty=tty), mock.patch("subprocess.run", side_effect=AssertionError("a program")), \
                    mock.patch("subprocess.Popen", side_effect=AssertionError("a program")), \
                    mock.patch.object(os, "system", side_effect=AssertionError("a program")), \
                    mock.patch.object(sys, "stdout", out):
                self.assertEqual(cli.cmd_report(["incident"]), 0)
            self.assertIn(want, out.getvalue())
            self.assertEqual("store.lock/lock" in out.getvalue(), tty, "the report only to a terminal")
        out = io.StringIO()
        out.isatty = lambda: True
        with mock.patch.object(sys, "stdout", out):
            cli.cmd_report(["incident", "clear"])
        self.assertIn("cleared:", out.getvalue())
        self.assertFalse(incidents.record_path().exists())

    def test_report_prints_the_text_and_the_link_and_create_is_gone(self):
        from maisecrets import cli
        out = io.StringIO()
        with redirect_stdout(out):
            cli.cmd_report(["bug", "the", "hook", "refused", "$(touch", "x)"])
        text = out.getvalue()
        self.assertIn("Title: Bug: the hook refused $(touch x)", text)
        self.assertIn("## What happened\nthe hook refused $(touch x)", text, "the text itself, not only a link")
        self.assertIn("prefilled link: https://github.com/", text)
        with redirect_stdout(io.StringIO()) as o2:
            cli.cmd_report(["bug", "--create", "a", "text"])
        self.assertIn("--create is gone", o2.getvalue())
        self.assertIn("prefilled link: https://github.com/", o2.getvalue())
        self.assertIn("a+text", o2.getvalue(), "--create is no part of the text")

    def test_report_follows_report_url_null_another_tracker_or_a_fork(self):
        from maisecrets import cli
        def run(url):
            out = io.StringIO()
            with mock.patch.object(self.events, "tracker", return_value=url), \
                    redirect_stdout(out), redirect_stderr(io.StringIO()):
                cli.cmd_report(["bug", "x"])
            return out.getvalue()
        text = run(None)
        self.assertIn("reporting is turned off", text)
        self.assertNotIn("Title:", text)
        text = run("https://tracker.example.org/new")
        self.assertIn("tracker: https://tracker.example.org/new", text)
        text = run("https://github.com/acme/fork/issues")
        self.assertIn("prefilled link: https://github.com/acme/fork/issues/new?", text)

    def test_slash_command_arguments_arrive_on_stdin_and_are_never_run(self):
        # feedback on 0.5.2: $ARGUMENTS spliced into the bash line ran `$(…)` in a report text
        marker = Path(tempfile.mkdtemp(prefix="maisecrets-args-")) / "ran"
        self.addCleanup(shutil.rmtree, marker.parent, True)
        for name in ("audit", "forget", "put", "report", "shortcut"):
            md = (ROOT / "commands" / f"{name}.md").read_text(encoding="utf-8")
            self.assertNotRegex(md, r"run\.sh\" [a-z -]*\$ARGUMENTS", name)
            self.assertIn("--args-stdin <<'MAISECRETS_ARGS_END'\n$ARGUMENTS\nMAISECRETS_ARGS_END", md, name)
        md = (ROOT / "commands" / "report.md").read_text(encoding="utf-8")
        block = md.split("```\n", 2)[1].split("```", 1)[0]
        args = f"bug it failed $(touch {marker}) | `touch {marker}` ; touch {marker} it's odd"
        line = block.replace("${CLAUDE_PLUGIN_ROOT}", str(ROOT)).replace("$ARGUMENTS", args)
        env = {**os.environ, "SSH_CONNECTION": "x"}   # no browser
        r = subprocess.run([shutil.which("bash") or "bash", "-c", line], capture_output=True, text=True, env=env,
                           timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(marker.exists(), "a shell read the report text as code")
        self.assertIn(f"$(touch {marker})", r.stdout, "the text arrives as it was written")


# --------------------------------------------------------------------- tips --
class TipsTests(unittest.TestCase):
    def setUp(self):
        from maisecrets import tips
        self.tips = tips
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-tips-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        for p in (mock.patch.object(tips, "HOME", self.dir), mock.patch.object(tips, "load_config", lambda: {})):
            p.start()
            self.addCleanup(p.stop)

    def test_codex_gets_a_tip_from_its_own_pool_and_no_slash_command(self):
        (self.dir / ".tip").write_text("2000-01-01 1\n")
        self.assertEqual(self.tips.tip_of_the_day(codex=True), self.tips.TIPS_CODEX[2])
        for tip in self.tips.TIPS_CODEX:
            self.assertNotIn("/maisecrets:", tip)

    def test_each_pool_has_a_tip_about_rules_of_your_own_with_a_step_that_works_in_its_client(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for pool, step in ((self.tips.TIPS, "/maisecrets:rules"),
                           (self.tips.TIPS_CODEX, "maisecrets: set rule_dirs add")):
            (tip,) = [t for t in pool if "rules for the tokens of your own services" in t]
            self.assertIn(step, tip)
            self.assertIn('README "Rules of your own"', tip)
        self.assertIn("\n## Rules of your own\n", readme, "the tip names a README section that exists")

    def test_the_rotation_wraps_and_a_damaged_state_starts_at_the_first_tip(self):
        (self.dir / ".tip").write_text(f"2000-01-01 {len(self.tips.TIPS) - 1}\n")
        self.assertEqual(self.tips.tip_of_the_day(), self.tips.TIPS[0])
        self.assertEqual((self.dir / ".tip").read_text(), time.strftime("%Y-%m-%d") + " 0\n")
        (self.dir / ".tip").write_text("garbage")
        self.assertEqual(self.tips.tip_of_the_day(), self.tips.TIPS[0])

    def test_an_unwritable_home_still_gives_the_tip(self):
        blocker = self.dir / "file"
        blocker.write_text("x")
        with mock.patch.object(self.tips, "HOME", blocker):
            self.assertEqual(self.tips.tip_of_the_day(), self.tips.TIPS[0])


# ---------------------------------------------------------------- cli units --
class CliUnitTests(unittest.TestCase):
    def call(self, fn, *args):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = fn(*args)
        return rc, out.getvalue(), err.getvalue()

    def test_main_answers_help_unknown_and_hook(self):
        from maisecrets import cli
        for argv in ([], ["-h"], ["--help"]):
            rc, out, _ = self.call(cli.main, argv)
            self.assertEqual(rc, 0)
            self.assertIn("maisecrets status | list", out)
        rc, _, err = self.call(cli.main, ["frobnicate"])
        self.assertEqual((rc, err.strip()), (2, "unknown command frobnicate"))
        rc, _, err = self.call(cli.main, ["hook", "bogus"])
        self.assertEqual(rc, 2)
        self.assertIn("usage: dispatch.py", err)

    def test_age_is_minutes_then_hours_then_days(self):
        from maisecrets.cli import _age
        now = time.time()
        self.assertEqual([_age(now - 120), _age(now - 7200), _age(now - 3 * 86400)], ["2m", "2h", "3d"])

    def test_the_shortcut_never_overwrites_or_deletes_a_command_of_the_user(self):
        from maisecrets import cli
        cfg = Path(tempfile.mkdtemp(prefix="maisecrets-cfg-"))
        self.addCleanup(shutil.rmtree, cfg, True)
        own = cfg / "commands" / "ms.md"
        own.parent.mkdir(parents=True)
        own.write_text("my own command\n")
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(cfg)}):
            self.assertIsNone(cli.install_shortcut(only_if_absent=True))
            self.assertEqual(own.read_text(), "my own command\n")
            removed = cli.remove_shortcut()
        self.assertEqual(own.read_text(), "my own command\n")
        self.assertNotIn(str(own), removed)


def derived_commands() -> set[str]:
    md = set().union(*commands_in_markdown().values())
    return md | commands_in_dispatch() | cli_commands() | hook_events()


_RUNNERS = (StateMatrixTests, SessionStartTests, HookEventTests, ResolveTests)


class ZzDispatchCoverageTests(unittest.TestCase):
    """Sorted last on purpose: it reads what the other classes of this module dispatched.

    A class used to claim a command by naming it in its source, and a name in the source is not
    a run (Codex review of the suite, 2026-09-27). Sandbox.run records each command the real
    entry point handled; this test compares that record with the derived population."""

    def test_every_command_was_dispatched_by_a_test_here(self):
        missing = derived_commands() - DISPATCHED
        if missing:
            # a filtered run (-k) did not run the classes that dispatch; run them now, so the
            # answer does not depend on the order or the selection of the tests
            loader = unittest.TestLoader()     # a fresh one: the default carries the -k patterns
            suite = unittest.TestSuite(loader.loadTestsFromTestCase(c) for c in _RUNNERS)
            suite.run(unittest.TestResult())
            missing = derived_commands() - DISPATCHED
        self.assertEqual(sorted(missing), [], "commands no test in tests/test_cli_matrix.py dispatched")

    def test_the_record_holds_only_what_ran(self):
        sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(sb.remove)
        sb.run("no-such-command", stdin="{}")
        self.assertNotIn("no-such-command", DISPATCHED, "a usage error covers nothing")
        sb.run("pending")
        self.assertIn("pending", DISPATCHED)


if __name__ == "__main__":
    unittest.main()


class RefusingStoreTests(unittest.TestCase):
    """A store that refuses every delete: nothing may look deleted that is not, and an expired
    value must not come back."""

    def test_forget_reports_the_refusal_and_keeps_the_entry(self):
        sb = base_state("store-refuses-delete")
        r = sb.run("forget", "SECRET_c1")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("refused", r.stdout)
        self.assertIn("SECRET_c1", sb.index()["entries"])

    def test_an_expired_value_that_could_not_be_deleted_is_not_handed_out(self):
        sb = base_state("store-refuses-delete")
        r = sb.run("get", "SECRET_c1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("expired", r.stdout + r.stderr)
        for v in sb.values:
            self.assertNotIn(v, r.stdout + r.stderr)

