"""The band of #105 (B11) on the person's screen: the real interactive claude client in a pseudo-terminal, with this
plugin and its mod, against the fake upstream (harness/fake_anthropic.py) and a fake name service on this computer
(harness/fake_ner.py).

    python3 harness/band_screen.py       # needs pyte (pip install pyte==0.8.2), a POSIX pty and claude on PATH

The fake model runs two commands, one per prompt:

- `cat rows.log`, about 3,000 characters: the name service checks it in pieces of at most 1,000 and stalls on the
  last, so a rest remains. The band above the prompt names the share and that the rest went with the rules only;
- the second prompt takes the band away (the mod clears it when the person sends a prompt), and `cat short.txt`,
  one piece the service checks, leaves no rest, so no band comes back. tests/mod.test.ts holds each of the two alone.

`claude -p` draws no band (harness/run.py ner_rest_band reads the mod's debug line instead). No request to the model
holds the band. Exit 0 when every check holds. Each run writes into a temp folder; nothing of the person's own config
is read.
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

import screen as S
from fake_ner import FakeNer

ROOT = Path(__file__).resolve().parent.parent
PORT = 8814
BAND = "a result of this turn was checked for names in part ("
REST = "the rest went to the AI with the rules only"


def run() -> list[str]:
    run_dir = Path(tempfile.mkdtemp(prefix="ms-band-screen-"))
    cwd, out, cfg, home = (run_dir / n for n in ("proj", "upstream", "config", "home"))
    for d in (cwd, out, cfg, home):
        d.mkdir()
    (cwd / "rows.log").write_text("".join(f"row {i:03d} of the log, nothing personal in it\n" for i in range(70)))
    (cwd / "short.txt").write_text("a short file\n")
    ner = FakeNer(stall_on="row 069")
    (home / "config.json").write_text(json.dumps({
        "backend": "jsonfile", "allow_plaintext_store": True,
        "remote_detector": {"url": ner.url, "format": "hf", "max_chars": 1000, "timeout_ms": 1000,
                            "timeout_scales": False}}))
    (cfg / ".claude.json").write_text(json.dumps({
        "hasCompletedOnboarding": True, "theme": "dark", "numStartups": 5,
        "customApiKeyResponses": {"approved": [S.KEY[-20:]], "rejected": []},
        "projects": {str(cwd.resolve()): {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True}},
    }))
    (run_dir / "scenario.json").write_text(json.dumps({"turns": [
        {"match": "FIRST-PROMPT", "tool": "Bash", "input": {"command": "cat rows.log", "description": "show the log"}},
        {"match": "row 000", "text": "LOG-SHOWN"},
        {"match": "SECOND-PROMPT", "tool": "Bash", "input": {"command": "cat short.txt", "description": "show it"}},
        {"text": "SHORT-SHOWN"}]}))
    srv = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_anthropic.py"), str(run_dir / "scenario.json"),
                            str(out), str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=0.2)
                break
            except Exception:  # noqa: BLE001 - not up yet
                time.sleep(0.1)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "ANTHROPIC", "MAISECRETS"))}
        env.update(ANTHROPIC_BASE_URL=f"http://127.0.0.1:{PORT}", ANTHROPIC_API_KEY=S.KEY, CLAUDE_CONFIG_DIR=str(cfg),
                   CLAUDE_CODE_MAX_RETRIES="0", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", TERM="xterm-256color",
                   COLORTERM="truecolor", COLUMNS=str(S.COLS), LINES=str(S.ROWS), MAISECRETS_HOME=str(home),
                   MAISECRETS_GUARD_CLIPBOARD="off")
        args = [shutil.which("claude") or "claude", "--plugin-dir", str(ROOT), "--permission-mode", "default",
                "--allowedTools", "Bash", "--debug-file", str(run_dir / "debug.log")]
        failures = _drive(args, env, cwd, run_dir)
    finally:
        srv.terminate()
        ner.close()
    bodies = [f.read_text(encoding="utf-8", errors="replace") for f in sorted(out.glob("request_*.json"))]
    if len(bodies) < 4:
        failures.append(f"{len(bodies)} model requests, not the 4 of the scenario: a command did not run")
    if any(BAND in b for b in bodies):
        failures.append("the band reached the model")
    if failures:
        failures.append(f"run folder: {run_dir}")
    else:
        shutil.rmtree(run_dir, ignore_errors=True)
    return failures


def _drive(args, env, cwd, run_dir) -> list[str]:
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execvpe(args[0], args, env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", S.ROWS, S.COLS, 0, 0))
    scr = S._Screen(S.COLS, S.ROWS)
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
        return "\n".join("".join(scr.buffer[y][x].data for x in range(scr.columns)).rstrip() for y in range(scr.lines))

    def typ(s, wait):
        for c in s:
            os.write(fd, c.encode())
            pump(0.02)
        pump(0.6)
        os.write(fd, b"\r")
        pump(wait)

    failures = []
    try:
        pump(10)
        typ("FIRST-PROMPT: show the log", 20)
        first = screen()
        (run_dir / "screen-1.txt").write_text(first)
        if "LOG-SHOWN" not in first:
            failures.append(f"the first turn did not end ({run_dir / 'screen-1.txt'})")
        band = [row for row in first.split("\n") if BAND in row]
        if not band:
            failures.append(f"no band after a result with a rest ({run_dir / 'screen-1.txt'})")
        elif REST not in band[0] or not re.search(r"in part \(\d{1,2} %\)", band[0]):
            failures.append(f"the band does not name the share and the rules: {band[0].strip()[:140]}")
        else:
            print("band:", band[0].strip())
        typ("SECOND-PROMPT: show the short file", 20)
        second = screen()
        (run_dir / "screen-2.txt").write_text(second)
        if "SHORT-SHOWN" not in second:
            failures.append(f"the second turn did not end ({run_dir / 'screen-2.txt'})")
        elif BAND in second:
            failures.append(f"the band stays after the next prompt and a result without a rest "
                            f"({run_dir / 'screen-2.txt'})")
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
    return failures


def main() -> int:
    failures = run()
    for f in failures:
        print("FAIL", f)
    if not failures:
        print("OK  a result with a rest shows the band with its share; the next prompt and a result without a rest "
              "leave none; no model request holds it")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
