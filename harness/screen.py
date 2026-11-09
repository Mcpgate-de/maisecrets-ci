"""The values on the person's screen (setting show_values): the real interactive claude client in a pseudo-terminal,
with this plugin and its mod, against the fake upstream (harness/fake_anthropic.py).

    python3 harness/screen.py            # needs pyte (pip install pyte==0.8.2), a POSIX pty and claude on PATH

Per layout it types a prompt with a synthetic token. The mod rewrites it to the placeholder SECRET_c1; the fake
model answers with that placeholder. Then it checks both ways:

- fullscreen (the default layout): the token stands on the screen in the reply, with the lock;
- main screen (CLAUDE_CODE_NO_FLICKER=0): the reply keeps the placeholder on the screen;
- both: the token is in no model request, no transcript, no debug log and no /export file.

Exit 0 when every check holds. Each run writes into a temp folder; nothing of the person's own config is read.
"""
from __future__ import annotations

import fcntl
import json
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time
import urllib.request
from pathlib import Path

import pyte

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "glpat-" + "Sv7kQm2xRt9LpW4nZb8c"   # synthetic: a GitLab token shape, no real token
PLACEHOLDER = "⟦" + "SECRET_c1" + "⟧"
REPLY = f"Der Token lautet {PLACEHOLDER} und gilt bis Freitag."
COLS, ROWS = 140, 40
TURNS: list | None = None     # another scenario for a probe or a screenshot; None: the checks below
KEY = "sk-ant-api03-" + "fakefakefake" * 6 + "-AAAA"


class _Screen(pyte.Screen):
    """pyte has no CSI S / CSI T (scroll within the margins); the client uses them."""
    def _m(self):
        m = self.margins
        return (m.top, m.bottom) if m else (0, self.lines - 1)

    def scroll_up(self, n=1, *a, **k):
        y, (_t, b) = self.cursor.y, self._m()
        self.cursor.y = b
        for _ in range(n or 1):
            self.index()
        self.cursor.y = y

    def scroll_down(self, n=1, *a, **k):
        y, (t, _b) = self.cursor.y, self._m()
        self.cursor.y = t
        for _ in range(n or 1):
            self.reverse_index()
        self.cursor.y = y


pyte.ByteStream.csi = dict(pyte.ByteStream.csi, S="scroll_up", T="scroll_down")


def run(layout: str, port: int) -> list[str]:
    """The failures of one layout ("fullscreen" or "main"), or none."""
    run_dir = Path(tempfile.mkdtemp(prefix=f"ms-screen-{layout}-"))
    cwd, out, cfg, home = (run_dir / n for n in ("proj", "upstream", "config", "home"))
    for d in (cwd, out, cfg, home):
        d.mkdir()
    (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
    (cfg / ".claude.json").write_text(json.dumps({
        "hasCompletedOnboarding": True, "theme": "dark", "numStartups": 5,
        "customApiKeyResponses": {"approved": [KEY[-20:]], "rejected": []},
        "projects": {str(cwd.resolve()): {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True}},
    }))
    turns = TURNS or [{"match": "Bitte pruefe", "text": REPLY},
             # a tool result with the placeholder: maisecrets puts the value into the command and masks the output
             {"match": "zeig die Datei", "tool": "Bash",
              "input": {"command": f"printf 'token=%s\\n' {PLACEHOLDER}", "description": "Datei zeigen"}},
             {"match": "token=", "text": "Die Datei ist gezeigt."},
             # a tool row that is not Bash (the mod rewrites its input for the drawing only)
             {"match": "schreib die Notiz", "tool": "Write",
              "input": {"file_path": str(cwd / "notiz.txt"), "content": f"token {PLACEHOLDER}\n"}},
             {"match": "notiz.txt", "text": "Notiz geschrieben."},
             {"text": "ok"}]
    (run_dir / "scenario.json").write_text(json.dumps({"turns": turns}))
    srv = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_anthropic.py"), str(run_dir / "scenario.json"),
                            str(out), str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=0.2)
                break
            except Exception:  # noqa: BLE001 - not up yet
                time.sleep(0.1)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "ANTHROPIC", "MAISECRETS"))}
        env.update(ANTHROPIC_BASE_URL=f"http://127.0.0.1:{port}", ANTHROPIC_API_KEY=KEY, CLAUDE_CONFIG_DIR=str(cfg),
                   CLAUDE_CODE_MAX_RETRIES="0", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", TERM="xterm-256color",
                   COLORTERM="truecolor", COLUMNS=str(COLS), LINES=str(ROWS), MAISECRETS_HOME=str(home),
                   MAISECRETS_GUARD_CLIPBOARD="off")
        if layout == "main":
            env["CLAUDE_CODE_NO_FLICKER"] = "0"
        args = [shutil.which("claude") or "claude", "--plugin-dir", str(ROOT), "--permission-mode", "default",
                "--allowedTools", "Bash,Write",
                "--debug-file", str(run_dir / "debug.log")]
        return _drive(args, env, cwd, out, cfg, run_dir, layout)
    finally:
        srv.terminate()


def _drive(args, env, cwd, out, cfg, run_dir, layout) -> list[str]:
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execvpe(args[0], args, env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    scr = _Screen(COLS, ROWS)
    stream = pyte.ByteStream(scr)

    def pump(secs):
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                try:
                    b = os.read(fd, 65536)
                except OSError:
                    return
                # pyte reads CSI > 4;2 m and CSI < u / > u (key modes) as SGR: drop them
                stream.feed(re.sub(rb"\x1b\[[<>?][0-9;]*[mu]", b"", b))

    def screen() -> str:
        return "\n".join("".join(scr.buffer[y][x].data for x in range(scr.columns)) for y in range(scr.lines))

    def typ(s, wait):
        for c in s:
            os.write(fd, c.encode())
            pump(0.02)
        pump(0.4)
        os.write(fd, b"\r")
        pump(wait)

    failures = []
    try:
        pump(10)
        typ(f"Bitte pruefe den Token {TOKEN} im CI", 12)
        reply = [line for line in screen().split("\n") if "Der Token lautet" in line]
        # the person's own prompt row (UserMessage): the value the person typed, on the fullscreen only
        asked = [line for line in screen().split("\n") if "Bitte pruefe den Token" in line]
        if not asked:
            failures.append(f"{layout}: the prompt row is not on the screen")
        # a secret is never drawn (0.9.3): the fullscreen shows its placeholder with the lock, the drawing's mark
        elif layout == "fullscreen" and (TOKEN in asked[0] or "\U0001F512" not in asked[0]):
            failures.append(f"{layout}: the prompt row shows the secret or no lock: {asked[0].strip()[:80]}")
        elif layout == "main" and TOKEN in asked[0]:
            failures.append(f"{layout}: the main screen shows the value in the prompt row")
        (run_dir / "screen.txt").write_text(screen())
        if not reply:
            failures.append(f"{layout}: the reply is not on the screen ({run_dir / 'screen.txt'})")
        elif layout == "fullscreen" and (TOKEN in reply[0] or "\U0001F512" not in reply[0]):
            failures.append(f"{layout}: the reply does not keep the secret behind its lock: {reply[0].strip()[:80]}")
        elif layout == "main" and TOKEN in reply[0]:
            failures.append(f"{layout}: the main screen shows the value (scrollback and /export keep it)")
        # after the drawing: a tool result with the value, and one more request that carries all of it
        typ("zeig die Datei", 15)
        typ("schreib die Notiz", 15)
        typ("danke", 8)
        typ("/export export.txt", 5)
        (run_dir / "screen-end.txt").write_text(screen())
    finally:
        for b in (b"\x03", b"\x03"):
            try:
                os.write(fd, b)
            except OSError:
                pass
            pump(0.8)
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    requests = sorted(out.glob("request_*.json"))
    if len(requests) < 6:
        failures.append(f"{layout}: {len(requests)} model requests, not the 6 of the scenario: the later turns did not "
                        "run, and a request after the drawing is not checked")
    transcripts = list((cfg / "projects").rglob("*.jsonl"))
    if not transcripts:
        failures.append(f"{layout}: no transcript was written: the check of the transcript would read nothing")
    if not list(cwd.glob("export*.txt")):
        failures.append(f"{layout}: /export wrote no file: the check of /export would read nothing")
    places = {"a model request": requests, "the transcript": transcripts,
              "the debug log": [run_dir / "debug.log"], "the /export file": list(cwd.glob("export*.txt"))}
    for where, files in places.items():
        hits = sum(f.read_text(errors="replace").count(TOKEN) for f in files if f.exists())
        if hits:
            failures.append(f"{layout}: the value is in {where} ({hits} times)")
    if requests and not any(PLACEHOLDER in f.read_text() for f in requests):
        failures.append(f"{layout}: no request carries the placeholder (the mod did not rewrite the prompt)")
    if not failures:
        shutil.rmtree(run_dir, ignore_errors=True)
    return failures


def main() -> int:
    failures = run("fullscreen", 8811) + run("main", 8812)
    for f in failures:
        print("FAIL", f)
    if not failures:
        print("OK  fullscreen keeps the secret behind its lock; main screen keeps the placeholder; no request, "
              "transcript, debug log or /export holds it")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
