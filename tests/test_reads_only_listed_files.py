"""PRIVACY.md "What it reads": the hooks read only the files that section lists.

Every hook event, each event the mod starts, and the guard run as a subprocess in a sandbox with decoy files of the
person: a private key in ~/.ssh, a note in ~/Documents, ~/.aws, a `.env` and a source file in the project. The
interpreter is a venv whose site-packages holds a `.pth` file with a `sys.addaudithook`: it loads in the hook process
and in each Python child the hook starts, also with `-I` (the transcript scrub, the server of a value), and writes each
path that the process opens to read or lists, to one log per event. Each path, after `realpath`, must fall into one
category of the section: maisecrets' own files (its home, the machine policy, the plugin folder); the client's
transcript and the folder it is found in; the client's configuration; the language setting of the system; the file of
a tool call; and the files of Python and of the system that hold no data of the person. A decoy fails by name.

What it does not check: a read that only a setting it leaves off starts (rule_dirs, value_files, a name service, a
vault server); an installed plugin's marketplace layout (the test runs from the repository); a program the hooks start
that is not Python, and a Python child started with -S, which loads no .pth (user_rules.py checks a rule of rule_dirs
so); a read of a child more than 3 s after the last event (the children are then stopped); and Windows. A `stat`
or an `exists` is no read here: they show that a file is there, not what it holds."""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import site
import subprocess
import sys
import sysconfig
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
import _hygiene  # noqa: E402
from test_cli_matrix import JSONFILE, ROOT, Sandbox, fake_value  # noqa: E402

# the fd is open before the hook is in place, and os.write raises no audit event: the hook cannot call itself. The log
# is named by the environment, so a child writes to the log of the event that started it
_AUDIT = '''
import os, sys
_log = os.environ.get("MS_TEST_READS")
if _log:
    _fd = os.open(_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)

    def _audit(event, args, _fd=_fd):
        if event not in ("open", "os.listdir", "os.scandir", "glob.glob") or not args:
            return
        p = args[0]
        if p is None or isinstance(p, int):
            return
        if event == "open":
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
            if isinstance(mode, str) and not set(mode) & set("r+"):
                return                              # open(..., "w" / "a" / "x"): a write only
            if mode is None and flags & 3 == os.O_WRONLY:
                return                              # os.open for writing only
        try:
            p = os.fsdecode(p)
        except Exception:
            return
        os.write(_fd, ("%d\\t%s\\t%s\\n" % (os.getpid(), event, p.replace("\\n", " "))).encode("utf-8", "replace"))
    sys.addaudithook(_audit)
'''
CHILD_SECONDS = 3.0


def _under(path: str, roots) -> bool:
    for r in roots:
        r = str(r).rstrip(os.sep)
        if r and (path == r or path.startswith(r + os.sep)):
            return True
    return False


def _real(p) -> str:
    return os.path.realpath(os.path.abspath(str(p)))


def _make_venv(where: Path) -> Path:
    """A venv of this Python with the audit in a .pth file: site loads it also under -I, which drops PYTHONPATH."""
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(where)], check=True, timeout=120,
                   capture_output=True)
    py = where / ("Scripts" if sys.platform == "win32" else "bin") / ("python.exe" if sys.platform == "win32"
                                                                      else "python")
    purelib = subprocess.run([str(py), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                             check=True, capture_output=True, text=True, timeout=60).stdout.strip()
    Path(purelib, "_ms_read_audit.py").write_text(_AUDIT, encoding="utf-8")
    Path(purelib, "_ms_read_audit.pth").write_text("import _ms_read_audit\n", encoding="utf-8")
    return py


class World:
    """The sandbox with the decoy files, and the categories of PRIVACY.md "What it reads" as paths."""

    def __init__(self, case: unittest.TestCase, python: Path, venv: Path):
        self.python, self.venv = python, venv
        self.sb = Sandbox(JSONFILE, backend="jsonfile")
        case.addCleanup(self.sb.remove)
        case.addCleanup(self.stop_children)          # runs first: the children work in the sandbox folder
        root, home = self.sb.root, self.sb.user_home
        site_dir = root / "site"
        site_dir.mkdir()
        # the platform fakes of tests/_isolate.py, for the hook process (a child with -I runs without them)
        shutil.copyfile(Path(_isolate.SITE, "sitecustomize.py"), site_dir / "sitecustomize.py")
        self.logs = root / "reads"
        self.logs.mkdir()
        self.env = self.sb.env(PYTHONPATH=str(site_dir), MAISECRETS_GUARD_WAIT="0.5")
        # no pinned locale: on macOS the hooks then read the language setting of the account, as they do for a person
        # who did not set MAISECRETS_LOCALE
        self.env.pop("MAISECRETS_LOCALE", None)
        self.project = root / "proj"
        self.decoys = [home / ".ssh" / "id_ed25519", home / "Documents" / "notes.txt", self.project / ".env",
                       self.project / "src" / "app.py", home / ".aws" / "credentials"]
        for d in self.decoys:
            d.parent.mkdir(parents=True, exist_ok=True)
            d.write_text("decoy\n", encoding="utf-8")
        self.decoy_paths = {_real(d) for d in self.decoys} | {_real(d.parent) for d in self.decoys}
        # the client's configuration, as Claude Code and Codex keep it
        self.claude = home / ".claude"
        (self.claude / "commands").mkdir(parents=True)
        (self.claude / "plugins").mkdir()
        (self.claude / "settings.json").write_text(json.dumps({"enabledPlugins": {"maisecrets@maisecrets": True}}),
                                                   encoding="utf-8")
        (self.project / ".claude").mkdir()
        (self.project / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
        # with CLAUDE_CONFIG_DIR set (the sandbox sets it), the client's config file lies in that folder
        servers = json.dumps({"mcpServers": {"srv": {"type": "http", "url": "https://mcp.example.com/"}}})
        for f in (home / ".claude.json", self.claude / ".claude.json"):
            f.write_text(servers, encoding="utf-8")
        self.codex = home / ".codex"
        self.codex.mkdir()
        (self.codex / "config.toml").write_text('[mcp_servers.srv]\nurl = "https://mcp.example.com/"\n',
                                                encoding="utf-8")
        self.read_file = self.project / "README.md"           # the file of a Read tool call
        self.read_file.write_text("hello\n", encoding="utf-8")
        self.script_file = self.project / "tool.py"         # a script a shell command runs by path (#98)
        self.script_file.write_text("print(1)\n", encoding="utf-8")
        # the values of the prompts stand in the transcripts already, as the client writes them: the scrub child then
        # runs its branch that finds and masks a value, not only its polls
        self.values = {k: fake_value(k) for k in ("Rd", "Rp", "Rx")}
        self.transcript = self.claude / "projects" / "proj" / "S1.jsonl"
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text("".join(json.dumps({"type": "user", "message": {
            "role": "user", "content": f"password: {self.values[k]}"}}) + "\n" for k in ("Rd", "Rp")), encoding="utf-8")
        self.rollout = self.codex / "sessions" / "2026" / "rollout-S2.jsonl"
        self.rollout.parent.mkdir(parents=True)
        self.rollout.write_text(json.dumps({"type": "session_meta", "payload": {"source": "cli"}}) + "\n" +
                                json.dumps({"type": "response_item", "payload": {
                                    "type": "message", "role": "user",
                                    "content": [{"type": "input_text", "text": f"password: {self.values['Rx']}"}]}})
                                + "\n", encoding="utf-8")

    def children(self) -> list[int]:
        """The Python processes that work in the sandbox folder: the children a hook left. By the working folder, not
        by the command: a framework Python on macOS starts itself again as Python.app."""
        if sys.platform == "win32":
            return []
        r = subprocess.run(["ps", "-A", "-o", "pid=,command="], capture_output=True, text=True, timeout=10)
        pids = [int(line.split(None, 1)[0]) for line in r.stdout.splitlines()
                if len(line.split(None, 1)) == 2 and "python" in line.split(None, 1)[1].lower()
                and int(line.split(None, 1)[0]) != os.getpid()]
        root = _real(self.sb.root)
        return [pid for pid, cwd in _hygiene._cwd_of(pids).items() if _under(_real(cwd), [root])]

    def stop_children(self) -> None:
        for pid in self.children():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        left = _hygiene.wait_for_no_serving_child(cwd_root=str(self.sb.root))
        if left:
            raise AssertionError(f"value-serving children still run: {left}")

    def category(self, raw: str) -> str | None:
        """The category of PRIVACY.md "What it reads" that a path falls into, after realpath; None for any other."""
        sb, home, claude, codex = self.sb, self.sb.user_home, self.claude, self.codex
        p = _real(raw)
        if p in self.decoy_paths:
            return None
        name = os.path.basename(p)
        R = _real   # noqa: N806
        if _under(p, [R(sb.home), R(ROOT)]) or p in {R(x) for x in _policy_paths()}:
            return "its own files"
        if _under(p, [R(sb.root / "site")]):
            return "Python and the system"           # the platform fakes of the tests, not a part of the plugin
        if p.startswith(R(sb.home) + ".") or os.path.dirname(p) == R(sb.root / "tmp"):
            return "its own files"                   # a lock beside its home; a temp file directly in TMPDIR
        projects = R(claude / "projects")
        if p in (R(self.transcript), R(self.rollout), projects) or \
                (os.path.dirname(os.path.dirname(p)) == projects and name == "S1.jsonl"):
            return "the client's transcript"       # the file, or the search for it by the session id
        plugins = R(claude / "plugins")
        files = {R(home / ".claude.json"), R(claude / ".claude.json"), R(claude / ".config.json"), R(claude), plugins,
                 R(claude / "plugins" / "installed_plugins.json"), R(claude / "plugins" / "known_marketplaces.json")}
        settings = name in ("settings.json", "settings.local.json") and \
            os.path.basename(os.path.dirname(p)) == ".claude"          # user, and each project folder up to the root
        if p in files or p in {R(x) for x in _managed()} or settings \
                or _under(p, [R(claude / "commands"), R(claude / "plugins" / "marketplaces")]) \
                or re.fullmatch(re.escape(plugins) + r"/(cache|synced)/[^/]+/maisecrets[^/]*(/.*)?", p):
            return "the client's configuration"
        if p in (R(codex), R(codex / "config.toml")) or (os.path.dirname(p) == R(codex) and name.endswith(".toml")) \
                or _under(p, [R(codex / ".hook-trust"), R(codex / ".tmp" / "marketplaces")]) \
                or re.fullmatch(re.escape(R(codex / "plugins" / "cache")) + r"(/[^/]+)?(/maisecrets(/.*)?)?", p):
            return "the client's configuration"
        if p == R(home / "Library" / "Preferences" / ".GlobalPreferences.plist"):
            return "the language setting of the system"
        if p in (R(self.read_file), R(self.script_file)):
            return "the file of a tool call"
        if _under(p, [R(x) for x in _python_dirs() + _pycache(home)] + [R(self.venv)]) or \
                p == "/etc/os-release" or _under(p, ["/proc", "/dev"]):
            return "Python and the system"
        return None

    def run(self, event: str, payload: dict, script: Path | None = None) -> tuple[subprocess.CompletedProcess, Path]:
        log = self.logs / f"{len(list(self.logs.iterdir())):02d}-{event or 'guard'}.log"
        log.write_text("", encoding="utf-8")
        body = {"transcript_path": str(self.transcript), "cwd": str(self.project), **payload}
        body = {k: v for k, v in body.items() if v is not None}
        argv = [str(self.python), str(script or ROOT / "hooks" / "dispatch.py")] + ([event] if event else [])
        r = subprocess.run(argv, input=json.dumps(body), capture_output=True, encoding="utf-8", errors="replace",
                           timeout=60, env={**self.env, "MS_TEST_READS": str(log)}, cwd=str(self.sb.root))
        return r, log

    def seen(self) -> list[tuple[str, str, str, str]]:
        """(log, pid, event, path) of every read in every log, after the children had time to read."""
        deadline = time.monotonic() + CHILD_SECONDS
        while self.children() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.stop_children()
        out = []
        for log in sorted(self.logs.iterdir()):
            for line in log.read_text(encoding="utf-8").splitlines():
                pid, what, p = (line.split("\t", 2) + ["", ""])[:3]
                out.append((log.stem, pid, what, p))
        return out


def _managed() -> list[str]:
    """The managed settings of Claude Code, as hooks/guard.py reads them."""
    sys.path.insert(0, str(ROOT / "hooks"))
    try:
        import guard
    finally:
        sys.path.pop(0)
    return list(guard.MANAGED.values())


def _policy_paths() -> list[str]:
    from maisecrets.home import POLICY_PATHS
    return [str(p) for p in POLICY_PATHS.values()]


def _pycache(home: Path) -> list[str]:
    """The byte code cache of a Python with a pycache prefix in the home folder (Apple's /usr/bin/python3 uses
    ~/Library/Caches/com.apple.python): in the sandbox it lies under the sandbox home."""
    prefix = sys.pycache_prefix or ""
    real = os.path.expanduser("~")
    if prefix and _under(prefix, [real]):
        return [str(home / os.path.relpath(prefix, real))]
    return [prefix] if prefix else []


def _python_dirs() -> list[str]:
    dirs = {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix, *sysconfig.get_paths().values()}
    try:
        dirs.update(site.getsitepackages())
    except AttributeError:
        pass
    dirs.add(site.getusersitepackages())
    return sorted(d for d in dirs if d)


def payloads(ref: str, key: str, world: World) -> list[tuple[str, dict]]:
    """One payload per hook event and per event of the mod, each on the path that does the most work; a Read of a
    file; and the Codex events (turn_id, the rollout as the transcript)."""
    read = {"tool_name": "Read", "tool_input": {"file_path": str(world.read_file)}, "session_id": "S1"}
    codex = {"session_id": "S2", "turn_id": "t", "model": "m", "transcript_path": str(world.rollout)}
    return [
        ("session-start", {"session_id": "S1", "source": "startup"}),
        ("user-prompt", {"prompt": f"password: {world.values['Rd']}", "session_id": "S1", "prompt_id": "p1"}),
        ("user-prompt", {"prompt": f"use {ref}", "session_id": "S1", "prompt_id": "p2"}),
        ("pre-tool", {"tool_name": "Bash", "tool_input": {"command": f"printf %s {ref}"}, "session_id": "S1",
                      "prompt_id": "p3"}),
        ("pre-tool", {"tool_name": "mcp__srv__echo", "tool_input": {"token": ref}, "session_id": "S1",
                      "prompt_id": "p4"}),
        ("pre-tool", {**read, "prompt_id": "p5"}),
        ("post-tool", {**read, "prompt_id": "p5", "tool_response": {"type": "text", "file": {
            "filePath": str(world.read_file), "content": f"api_key={fake_value('Rr')}", "numLines": 1,
            "startLine": 1, "totalLines": 1}}}),
        ("post-tool", {"tool_name": "Bash", "session_id": "S1", "prompt_id": "p6",
                       "tool_response": {"stdout": f"api_key={fake_value('Rb')}"}}),
        ("post-tool", {"tool_name": "mcp__srv__echo", "session_id": "S1", "prompt_id": "p7",
                       "tool_response": [{"type": "text", "text": f"token {fake_value('Rm')}"}]}),
        ("post-tool-failure", {"tool_name": "Bash", "tool_input": {"command": "false"}, "session_id": "S1",
                               "prompt_id": "p8", "error": f"api_key={fake_value('Rf')}"}),
        # the mod gets no transcript path: the scrub looks for the file by the session id
        ("mod-prompt", {"prompt": f"password: {world.values['Rp']}", "session_id": "S1", "transcript_path": None}),
        ("mod-values", {"keys": [key], "refs": [], "session_id": "S1", "transcript_path": None}),
        ("mod-reveal", {"ref": "⟦sref:secret:abc⟧", "session_id": "S1", "transcript_path": None}),
        ("mod-settings", {"session_id": "S1", "transcript_path": None}),
        ("mod-settings", {"action": "hooks_ran", "session_id": "S1", "since": 0, "transcript_path": None}),
        ("mod-result", {"session_id": "S1", "tool_name": "Bash", "texts": [f"api_key={fake_value('Rq')}"],
                        "transcript_path": None}),
        ("mod-demo", {"session_id": "S1", "prompt": "hi", "origin": "composer", "transcript_path": None}),
        ("session-start", {**codex, "source": "startup"}),
        ("user-prompt", {**codex, "prompt": f"password: {world.values['Rx']}"}),
        ("post-tool", {**codex, "tool_name": "Bash", "tool_response": {"stdout": f"api_key={fake_value('Ry')}"}}),
        ("session-end", {"session_id": "S1", "reason": "clear"}),
        # last, so the numbers of the events above stay: a script that a command runs by path (#98)
        ("pre-tool", {"tool_name": "Bash", "tool_input": {"command": f"python3 {world.script_file}"},
                      "session_id": "S1", "prompt_id": "p3s", "cwd": str(world.project)}),
    ]


@unittest.skipIf(sys.platform == "win32", "the categories name POSIX system paths (/dev, /proc); the Linux and macOS "
                 "runs check the same hook code")
class ReadsOnlyListedFilesTests(unittest.TestCase):
    """PRIVACY.md: "It reads no other file of yours, except through a tool call that you or the agent makes." """

    @classmethod
    def setUpClass(cls):
        cls.venv = Path(tempfile.mkdtemp(prefix="ms-read-audit-", dir=_isolate.TMP)) / "venv"
        cls.python = _make_venv(cls.venv)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.venv.parent, ignore_errors=True)

    def setUp(self):
        _hygiene.watch_children(self)

    def test_the_audit_sees_a_read_of_a_decoy_in_a_child_with_isolated_mode(self):
        # the premise: the hooks start their children with -I, which drops PYTHONPATH; the .pth must still load
        w = World(self, self.python, self.venv)
        decoy = w.decoys[0]
        log = w.logs / "premise.log"
        code = f"open({str(decoy)!r}).read(); import os; os.listdir({str(decoy.parent)!r})"
        subprocess.run([str(self.python), "-I", "-c", code], env={**w.env, "MS_TEST_READS": str(log)}, check=True,
                       timeout=30)
        seen = log.read_text(encoding="utf-8")
        self.assertIn(f"\topen\t{decoy}", seen)
        self.assertIn(f"\tos.listdir\t{decoy.parent}", seen)
        self.assertIsNone(w.category(str(decoy)))
        # a path that reaches a decoy through an allowed folder is the decoy
        self.assertIsNone(w.category(str(w.claude / "plugins" / ".." / ".." / ".ssh" / "id_ed25519")))
        self.assertIsNone(w.category(str(w.sb.root / "tmp" / ".." / "home" / ".ssh" / "id_ed25519")))

    def test_every_hook_event_reads_only_the_listed_files(self):
        w = World(self, self.python, self.venv)
        out = w.sb.run("put", stdin=fake_value("Rf"), env=w.env).stdout
        key = re.search(r"placeholder (?:is )?⟦(\w+)", out).group(1)
        for event, payload in payloads(f"⟦{key}⟧", key, w):
            with self.subTest(event=event, payload=sorted(payload)):
                r, _log = w.run(event, payload)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertNotIn("Traceback", r.stderr)
        seen = w.seen()
        outside = [f"{log}: {what} {p}" for log, _pid, what, p in seen if w.category(p) is None]
        self.assertEqual(outside, [])
        categories = {w.category(p) for _log, _pid, _what, p in seen}
        # the run reaches the categories it is for; the language setting only where the system keeps one in a file
        wanted = {"its own files", "the client's transcript", "the client's configuration"}
        if sys.platform == "darwin":
            wanted.add("the language setting of the system")
        self.assertLessEqual(wanted, categories)
        # each event wrote its log: an event that read nothing ran nothing
        self.assertEqual(len({log for log, _pid, _w, _p in seen}), len(payloads("x", key, w)))
        # the children with -I (the transcript scrub, the server of a value) wrote to the log of their event too
        pids = {}
        for log, pid, _w, _p in seen:
            pids.setdefault(log, set()).add(pid)
        with_child = {log for log, ps in pids.items() if len(ps) > 1}
        # each kind of child: the scrub of a prompt, the server of a value, the scrubs the mod starts, the Codex scrub
        for wanted_child in ("01-user-prompt", "03-pre-tool", "10-" + "mod-prompt", "15-" + "mod-result",
                             "18-user-prompt"):
            self.assertIn(wanted_child, with_child, "this event's child wrote no read")

    def test_the_guard_reads_only_the_client_configuration(self):
        w = World(self, self.python, self.venv)
        # the guard reads the settings to tell whether maisecrets should run here
        r, _log = w.run("", {"hook_event_name": "UserPromptSubmit", "session_id": "S1", "prompt_id": "g1",
                             "prompt": "hi"}, script=ROOT / "hooks" / "guard.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        seen = w.seen()
        self.assertEqual([f"{what} {p}" for _l, _pid, what, p in seen if w.category(p) is None], [])
        self.assertIn("the client's configuration", {w.category(p) for _l, _pid, _w, p in seen})


if __name__ == "__main__":
    unittest.main()
