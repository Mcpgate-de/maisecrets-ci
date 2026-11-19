"""`/maisecrets:sref login NAME` typed in the real interactive client: the mod runs the login with no model turn, and
the client stays free while the login waits for the consent in the browser (0.9.19).

    python3 harness/login_screen.py      # needs pyte (pip install pyte==0.8.2), openssl, a POSIX pty and claude on PATH

The gateway is the fake of harness/sref_server.py, the model the fake of harness/fake_anthropic.py, and the browser a
script of this run (BROWSER): it waits BROWSER_DELAY seconds, the time a person takes to give the consent, then
follows the authorize URL to the loopback. Checks:

- the status line says "maisecrets: waiting for your consent in the browser (team-gw)" while the login waits;
- a second prompt, typed while the login waits, gets the model's answer before the browser gives the consent: the
  prompt.submit hook returned at once, and the client is not blocked (the times are printed);
- the end is the toast "maisecrets: logged in at team-gw", and the store holds the login;
- `/maisecrets:list` shows its output in the pane;
- the second prompt makes the only model request: neither command had a model turn.

Each run writes into a temp folder: a client config folder, a maisecrets home and a project of its own; nothing of the
person's own config, store or keychain is read. Exit 0 when every check holds.
"""
from __future__ import annotations

import fcntl
import json
import os
import pty
import re
import select
import shutil
import stat
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
from sref_server import SrefServer

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PORT = 8814
BROWSER_DELAY = 12.0
WAITING = "waiting for your consent in the browser (team-gw)"
DONE = "logged in at team-gw"
LISTED = "Nothing is stored."                  # cli.cmd_list in an empty store
BROWSER = """#!/bin/sh
# the person in the browser: the consent after a while, then the redirect to the loopback of the login
sleep %(delay)s
exec %(python)s - "$1" <<'PY'
import ssl, sys, urllib.error, urllib.request
class Stop(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
ctx = ssl.create_default_context(cafile=%(cafile)r)
try:
    urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), Stop()).open(sys.argv[1])
except urllib.error.HTTPError as exc:
    urllib.request.urlopen(exc.headers["Location"], timeout=5).read()
PY
"""


def run() -> list[str]:
    run_dir = Path(tempfile.mkdtemp(prefix="ms-login-screen-"))
    cwd, out, cfg, home = (run_dir / n for n in ("proj", "upstream", "config", "home"))
    for d in (cwd, out, cfg, home):
        d.mkdir()
    srv = SrefServer().__enter__()
    browser = run_dir / "browser.sh"
    browser.write_text(BROWSER % {"delay": BROWSER_DELAY, "python": sys.executable, "cafile": srv.cert})
    browser.chmod(browser.stat().st_mode | stat.S_IXUSR)
    (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                  "client_vault_cafile": srv.cert}))
    (cfg / ".claude.json").write_text(json.dumps({
        "hasCompletedOnboarding": True, "theme": "dark", "numStartups": 5,
        "customApiKeyResponses": {"approved": [S.KEY[-20:]], "rejected": []},
        "projects": {str(cwd.resolve()): {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True}},
        "mcpServers": {"team-gw": {"type": "http", "url": srv.url + "/mcp"}},
    }))
    (run_dir / "scenario.json").write_text(json.dumps({"turns": [
        {"match": "SECOND-PROMPT", "text": "SECOND-ANSWER"}, {"text": "OTHER-ANSWER"}]}))
    up = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_anthropic.py"), str(run_dir / "scenario.json"),
                           str(out), str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    times: dict = {}
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
                   MAISECRETS_GUARD_CLIPBOARD="off", BROWSER=str(browser))
        args = [shutil.which("claude") or "claude", "--plugin-dir", str(ROOT), "--permission-mode", "default",
                "--debug-file", str(run_dir / "debug.log")]
        failures = _drive(args, env, cwd, run_dir, times)
    finally:
        up.terminate()
        srv.__exit__(None, None, None)
    bodies = [f.read_text(encoding="utf-8", errors="replace") for f in sorted(out.glob("request_*.json"))]
    # the request of the second prompt is the only one (the tool list names every command, so a search for the text
    # of a command in the requests proves nothing)
    if len(bodies) != 1 or "SECOND-PROMPT" not in bodies[0]:
        failures.append(f"{len(bodies)} model requests, not the one of the second prompt: a command had a model turn")
    if not srv.refresh:
        failures.append("the fake gateway gave no token: the login did not complete")
    for k, v in sorted(times.items(), key=lambda kv: kv[1]):
        print(f"  {v:6.1f} s  {k}")
    if failures:
        failures.append(f"run folder: {run_dir}")
    else:
        shutil.rmtree(run_dir, ignore_errors=True)
    return failures


def _drive(args, env, cwd, run_dir, times) -> list[str]:
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execvpe(args[0], args, env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", S.ROWS, S.COLS, 0, 0))
    scr = S._Screen(S.COLS, S.ROWS)
    stream = pyte.ByteStream(scr)

    def pump(secs, until=None):
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    b = os.read(fd, 65536)
                except OSError:
                    return False
                stream.feed(re.sub(rb"\x1b\[[<>?][0-9;]*[mu]", b"", b))
            if until and until in screen():
                return True
        return False

    def screen() -> str:
        return "\n".join("".join(scr.buffer[y][x].data for x in range(scr.columns)).rstrip() for y in range(scr.lines))

    def typ(s):
        for _ in range(3):
            os.write(fd, b"\x15")
            pump(0.2)
        for c in s:
            os.write(fd, c.encode())
            pump(0.02)
        pump(0.6)
        os.write(fd, b"\r")

    failures = []
    try:
        pump(10)
        typ("/maisecrets:sref login team-gw")
        t0 = time.time()
        if pump(15, WAITING):
            times["the status line waits for the consent"] = time.time() - t0
        else:
            failures.append(f"no status line '{WAITING}' ({run_dir / 'screen-wait.txt'})")
            (run_dir / "screen-wait.txt").write_text(screen())
        # Esc closes the output pane, so the next keys go to the prompt box
        os.write(fd, b"\x1b")
        pump(0.5)
        typ("SECOND-PROMPT: are you there?")
        times["the second prompt is sent"] = time.time() - t0
        if pump(BROWSER_DELAY + 5, "SECOND-ANSWER"):
            times["the second prompt has its answer"] = time.time() - t0
            if times["the second prompt has its answer"] >= BROWSER_DELAY:
                failures.append("the second answer came only after the consent: the client waited for the login")
        else:
            failures.append(f"no answer to the second prompt ({run_dir / 'screen-second.txt'})")
            (run_dir / "screen-second.txt").write_text(screen())
        if pump(40, DONE):
            times["the toast says: logged in"] = time.time() - t0
        else:
            failures.append(f"no toast '{DONE}' ({run_dir / 'screen-done.txt'})")
            (run_dir / "screen-done.txt").write_text(screen())
        # a short command: its output opens in the pane, with no model turn
        os.write(fd, b"\x1b")
        pump(0.5)
        t1 = time.time()
        typ("/maisecrets:list")
        if pump(15, LISTED):
            times["the output of /maisecrets:list is on the screen (from its Enter)"] = time.time() - t1
        else:
            failures.append(f"no output of /maisecrets:list ({run_dir / 'screen-list.txt'})")
            (run_dir / "screen-list.txt").write_text(screen())
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
    return failures


def main() -> int:
    failures = run()
    for f in failures:
        print("FAIL", f)
    if not failures:
        print("OK  the login ran in the mod with no model turn, and the client stayed free while it waited")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
