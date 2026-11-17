"""A one-time hint on the person's screen: the real interactive claude client in a pseudo-terminal, with this plugin,
against the fake upstream (harness/fake_anthropic.py).

    python3 harness/hint_screen.py       # needs pyte (pip install pyte==0.8.2), a POSIX pty and claude on PATH

The fake model reads a synthetic PNG in two prompts, while read_image is not decided. Checks:

- the read_image hint stands on the screen as the hook's line (PostToolUse:Read says: maisecrets: …), once;
- no request to the model holds it: the model cannot word it again or repeat it (field report 2026-11-17);
- hints.json records it.

`claude -p` cannot check this: it shows no systemMessage, and maisecrets gives no hint there (harness/run.py,
read_pdf_hint_for_the_person). Exit 0 when every check holds. Each run writes into a temp folder; nothing of the
person's own config is read.
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
import zlib
from pathlib import Path

import pyte

import screen as S

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PORT = 8813
LINE = "maisecrets: images go to the AI as they are"   # the start of HINTS["read_image"]["claude"]
PHRASE = "cannot mask inside"                            # a phrase of the line that nothing else says


def png(path: Path) -> None:
    raw = b"".join(b"\x00" + bytes([200, 30, 30] * 8) for _ in range(8))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def run() -> list[str]:
    run_dir = Path(tempfile.mkdtemp(prefix="ms-hint-screen-"))
    cwd, out, cfg, home = (run_dir / n for n in ("proj", "upstream", "config", "home"))
    for d in (cwd, out, cfg, home):
        d.mkdir()
    png(cwd / "probe.png")
    (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
    (cfg / ".claude.json").write_text(json.dumps({
        "hasCompletedOnboarding": True, "theme": "dark", "numStartups": 5,
        "customApiKeyResponses": {"approved": [S.KEY[-20:]], "rejected": []},
        "projects": {str(cwd.resolve()): {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True}},
    }))
    read = {"tool": "Read", "input": {"file_path": str(cwd / "probe.png")}}
    (run_dir / "scenario.json").write_text(json.dumps({"turns": [
        {"match": "FIRST-PROMPT", **read}, {"match": "SECOND-PROMPT", **read}, {"text": "IMG-DONE"}]}))
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
                "--debug-file", str(run_dir / "debug.log")]
        failures = _drive(args, env, cwd, run_dir)
    finally:
        srv.terminate()
    bodies = [f.read_text(encoding="utf-8", errors="replace") for f in sorted(out.glob("request_*.json"))]
    if len(bodies) < 4:
        failures.append(f"{len(bodies)} model requests, not the 4 of the scenario: a read did not run")
    if not any("tool_result" in b for b in bodies):
        failures.append("no request carries a tool result: the image was not read")
    if any(PHRASE in b for b in bodies):
        failures.append("the hint reached the model")
    try:
        given = json.loads((home / "hints.json").read_text())["read_image"]["revision"]
    except (OSError, ValueError, KeyError, TypeError):
        given = None
    if not given:
        failures.append("hints.json does not record the read_image hint")
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
        typ("FIRST-PROMPT: read probe.png", 20)
        first = screen()
        (run_dir / "screen-1.txt").write_text(first)
        if LINE not in first or PHRASE not in first:
            failures.append(f"the hint line is not on the screen after the first read ({run_dir / 'screen-1.txt'})")
        typ("SECOND-PROMPT: read probe.png again", 20)
        second = screen()
        (run_dir / "screen-2.txt").write_text(second)
        rows = second.split("\n")
        after = [i for i, row in enumerate(rows) if "SECOND-PROMPT" in row]
        if not after or not any("Read" in row for row in rows[after[0]:]):
            failures.append(f"the second read is not on the screen ({run_dir / 'screen-2.txt'})")
        elif any(PHRASE in row for row in rows[after[0]:]):
            failures.append(f"the hint came again after the second read ({run_dir / 'screen-2.txt'})")
        elif sum(row.count(PHRASE) for row in rows) > 1:
            failures.append(f"the hint stands on the screen more than once ({run_dir / 'screen-2.txt'})")
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
        print("OK  the read_image hint is one line on the person's screen, once, and in no model request")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
