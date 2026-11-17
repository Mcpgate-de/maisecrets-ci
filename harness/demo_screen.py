"""The demo mode in the real interactive client (maisecrets/demo.py, #57): every request the client makes in a demo
session, with the client's optional traffic on (no CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC), against the fake
upstream (harness/fake_anthropic.py), in a pseudo-terminal.

    python3 harness/demo_screen.py       # needs pyte (pip install pyte==0.8.2), a POSIX pty and claude on PATH

It types `/maisecrets:demo on`, two prompts with a synthetic token, waits 60 s, presses Tab and Enter on an empty
prompt (the client's next-prompt guess), types /compact, and waits 40 s more. Then it starts `claude --resume` of that
session (a new process: the mod knows nothing yet) and repeats: 30 s idle, Tab, /compact, one more prompt.
Each request in that window fails the run,
with its source as the client's debug log names it (title, prompt_suggestion, compact …): every one would carry demo
text. It also checks the screen (the person's row, the demo line) and that the transcript holds no token.

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screen import COLS, KEY, ROWS, _Screen  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "glpat-" + "DemoScreenRt9LpW4nZb"   # synthetic: a GitLab token shape, no real token
PORT = 8804
DEMO_LINE = "Demo mode: nothing was sent to the AI. /clear to switch it off."


def main() -> int:
    run_dir = Path(tempfile.mkdtemp(prefix="ms-demo-screen-"))
    cwd, out, cfg, home = (run_dir / n for n in ("proj", "upstream", "config", "home"))
    for d in (cwd, out, cfg, home):
        d.mkdir()
    (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                  "show_values": "always"}))
    (cfg / ".claude.json").write_text(json.dumps({
        "hasCompletedOnboarding": True, "theme": "dark", "numStartups": 5,
        "customApiKeyResponses": {"approved": [KEY[-20:]], "rejected": []},
        "projects": {str(cwd.resolve()): {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True}},
    }))
    (run_dir / "scenario.json").write_text(json.dumps({"turns": [{"text": "A-REQUEST-WENT-OUT"}] * 8}))
    srv = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_anthropic.py"), str(run_dir / "scenario.json"),
                            str(out), str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tw = run_dir / "tripwire-bin"           # no clipboard tool of this machine runs
    tw.mkdir()
    for tool in ("pbcopy", "pbpaste", "xclip", "xsel", "wl-copy", "wl-paste"):
        (tw / tool).write_text("#!/bin/sh\nexit 1\n")
        (tw / tool).chmod(0o755)
    failures: list[str] = []
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=0.2)
                break
            except Exception:  # noqa: BLE001 - not up yet
                time.sleep(0.1)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "ANTHROPIC", "MAISECRETS"))}
        env.update(ANTHROPIC_BASE_URL=f"http://127.0.0.1:{PORT}", ANTHROPIC_API_KEY=KEY, CLAUDE_CONFIG_DIR=str(cfg),
                   CLAUDE_CODE_MAX_RETRIES="0", TERM="xterm-256color", COLORTERM="truecolor", COLUMNS=str(COLS),
                   LINES=str(ROWS), MAISECRETS_GUARD_CLIPBOARD="off", PATH=str(tw) + os.pathsep + os.environ["PATH"])
        env["MAISECRETS_" + "HOME"] = str(home)
        args = [shutil.which("claude") or "claude", "--plugin-dir", str(ROOT), "--permission-mode", "default",
                "--debug-file", str(run_dir / "debug.log")]
        failures = _drive(args, env, cwd, out, cfg, run_dir)
        sessions = [t.stem for t in (cfg / "projects").rglob("*.jsonl")]
        if len(sessions) == 1:
            out2 = run_dir / "upstream-resumed"
            out2.mkdir()
            srv.terminate()
            srv = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_anthropic.py"),
                                    str(run_dir / "scenario.json"), str(out2), str(PORT)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            failures += [f"resumed: {f}" for f in _drive(args + ["--resume", sessions[0]], env, cwd, out2, cfg,
                                                         run_dir, resumed=True)]
        else:
            failures.append(f"expected one demo session to resume, found {len(sessions)}")
    finally:
        srv.terminate()
    print(f"[{'OK ' if not failures else 'FAIL'}] demo_screen  run_dir={run_dir}")
    for f in failures:
        print("     -", f)
    if not failures:
        shutil.rmtree(run_dir, ignore_errors=True)
    return 1 if failures else 0


def _drive(args, env, cwd, out, cfg, run_dir, resumed: bool = False) -> list[str]:
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
                stream.feed(re.sub(rb"\x1b\[[<>?][0-9;]*[mu]", b"", b))

    def screen() -> str:
        return "\n".join("".join(scr.buffer[y][x].data for x in range(scr.columns)) for y in range(scr.lines))

    def typ(s, wait):
        for _ in range(3):
            os.write(fd, b"\x15")
            pump(0.2)
        for c in s:
            os.write(fd, c.encode())
            pump(0.02)
        pump(0.6)
        os.write(fd, b"\r")
        pump(wait)

    failures = []
    try:
        pump(10)
        if not resumed:
            typ("/maisecrets:demo on", 8)
            typ(f"Bitte pruefe den Token {TOKEN} heute", 12)
            typ(f"Und noch einmal der Token {TOKEN}", 12)
            shown = screen()
            if not any("Bitte pruefe den Token" in ln and TOKEN not in ln for ln in shown.splitlines()):
                failures.append("the person's row is not on the screen, or it shows the token")
            if DEMO_LINE not in shown:
                failures.append("the demo line is not on the screen")
        pump(30 if resumed else 60)
        for _ in range(3):
            os.write(fd, b"\x15")
            pump(0.2)
        os.write(fd, b"\t")
        pump(8)
        os.write(fd, b"\r")
        pump(8)
        typ("/compact", 15)
        if resumed:
            typ(f"Nach dem Fortsetzen: Token {TOKEN}", 12)
            if DEMO_LINE not in screen():
                failures.append("the resumed session answered without the demo line")
        pump(40 if not resumed else 20)
        (run_dir / "screen.txt").write_text(screen().replace(TOKEN, "<TOKEN>"))
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
    if requests:
        sources = re.findall(r"\[API REQUEST\] \S+ source=(\S+)", (run_dir / "debug.log").read_text(errors="ignore"))
        sources = sources[-len(requests):]
        failures.append(f"{len(requests)} model request(s) in the demo window (sources: {sources})")
    transcripts = list((cfg / "projects").rglob("*.jsonl"))
    if not transcripts:
        failures.append("no transcript was written: the check of the transcript would read nothing")
    if any(TOKEN in t.read_text(errors="replace") for t in transcripts):
        failures.append("the token is in the transcript")
    return failures


if __name__ == "__main__":
    sys.exit(main())
