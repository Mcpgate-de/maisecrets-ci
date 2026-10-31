"""/maisecrets:ner: one source of names for tool results (setting `remote_detector`, maisecrets/remote_layer.py).

    /maisecrets:ner local          the service on this computer, http://127.0.0.1:8765/ (`on` is the same)
    /maisecrets:ner url URL        a service of the team on a private network
    /maisecrets:ner off            the rules alone
    /maisecrets:ner                which source is set, and whether it answers

Codex: `maisecrets: ner local` (or url URL, off) alone as the prompt. The change is a setting, so only a prompt the
person typed makes it (settings.py), with the limits of C22 (docs/THREAT-MODEL.md); a tool call that carries the
sentence is refused. Exactly one source: a
fallback to another one would send the text somewhere the person did not choose. A source that does not answer
leaves the rules alone, as before. The tuning keys of the setting (timeout_ms, classes, min_score, max_chars,
language) stay when the source changes.

A service that is not on this computer gets every finding of the rules as filler (remote.py), and the text of the
tool result goes there: a team decides that, not a default.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .detection import remote

LOCAL_URL = "http://127.0.0.1:8765/"
IMAGE = "mcpgate/ner"
START = f"docker run -d --name ner --restart unless-stopped -p 127.0.0.1:8765:8765 {IMAGE}"
# the keys a source sets; any other key of the setting is the person's tuning and stays
SOURCE_KEYS = ("url", "format", "model", "allow_network", "mask", "ask_labels")

_NER_RE = re.compile(r"\A\s*(?:/maisecrets:ner|maisecrets:\s*ner)\s+(?:(off|local|on)|url\s+(\S+)|"
                     r"fallback\s+(?:(off)|url\s+(\S+)))\s*\Z", re.I)
# the same sentence anywhere in a tool call (settings.IN_A_COMMAND_RE)
IN_A_COMMAND = r"(?:/maisecrets:ner|maisecrets:\s*ner)\s+(?:off|local|on|url|fallback)\b"


def parse(prompt) -> str | None:
    """`off`, `local`, `url:<URL>`, `fallback:off` or `fallback:url:<URL>` when the whole prompt is a change of the
    source, else None."""
    m = _NER_RE.match(prompt) if isinstance(prompt, str) else None
    if not m:
        return None
    if m.group(1):
        return "off" if m.group(1).lower() == "off" else "local"
    if m.group(2):
        return "url:" + m.group(2)
    return "fallback:off" if m.group(3) else "fallback:url:" + m.group(4)


def check_url(url: str) -> str:
    """Why maisecrets does not use this URL, or ""."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return "it is no address maisecrets can read"           # an open [ of an IPv6 address
    if parts.scheme.lower() not in ("http", "https") or not host:
        return "it is no http:// or https:// address with a host"
    if parts.username or parts.password:
        return "it holds a user name or a password; the service takes none"
    if parts.query or parts.fragment:
        return "it holds a ? or a # part"
    try:
        port = parts.port
    except ValueError:
        return "its port is no number from 1 to 65535"
    if port == 0:
        return "its port is no number from 1 to 65535"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None               # a name: its addresses are checked at each connection (remote.private_http_only)
    if parts.scheme.lower() == "http" and ip is not None and not remote._private(host):
        return ("it is plain http to a public address, so tool results would cross the internet in clear text; "
                "use https or a private address")
    return ""


def updated(current, word: str) -> dict:
    """The new value of the setting for `word` (from parse), the tuning keys of `current` kept."""
    current = dict(current) if isinstance(current, dict) else {}
    if word == "fallback:off":
        current.pop("fallback", None)
        return current
    if word.startswith("fallback:url:"):
        url = word[len("fallback:url:"):]
        current["fallback"] = {"url": url, "format": "hf", "ask_labels": True,
                               **({} if remote.is_local(url) else {"allow_network": True})}
        return current
    keep = {k: v for k, v in current.items() if k not in SOURCE_KEYS}
    if word == "off":
        keep.pop("fallback", None)          # off is off: no fallback answers either
        return keep
    url = LOCAL_URL if word == "local" else word[4:]
    # the service of this command is mcpgate/ner (examples/ner_service.py): it takes `labels` for classes in `classes`
    new = {**keep, "url": url, "format": "hf", "ask_labels": True}
    if not remote.is_local(url):
        new["allow_network"] = True
    return new


def describe(conf) -> str:
    """One line: the source in effect."""
    url = conf.get("url") if isinstance(conf, dict) else None
    if not url:
        return "names from a service: off (the rules alone)"
    where = ("on this computer" if remote.is_local(str(url))
             else "on the network; the findings of the rules go there as filler")
    fb = conf.get("fallback") if isinstance(conf.get("fallback"), dict) else {}
    tail = (f"; fallback {fb['url']} while it does not answer, tool results only" if fb.get("url") else "")
    return f"names from a service: {url} ({where}){tail}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None          # a redirect is an answer, not a second address to ask (codex review)


# no proxy and no redirect: the probe asks the address of the setting and no other
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def scope(conf) -> str:
    """One line: what the service reads. A prompt only on this computer and only where the client rewrites it."""
    url = str(conf.get("url") or "") if isinstance(conf, dict) else ""
    if remote.is_local(url) and conf.get("prompts") is not False:
        return ("It masks person names in what the AI reads (files, command output, tool results) and in your prompts "
                "in Claude Code. In Codex it covers what the AI reads only. It may mask a few extra words.")
    return ("It masks person names in what the AI reads (files, command output, tool results). Your prompts keep the "
            "rules alone. It may mask a few extra words.")


def _get(url: str, path: str, timeout: float):
    with _OPENER.open(url.rstrip("/") + path, timeout=timeout) as r:
        return r.status, r.read(65536)


def _http_allowed(url: str) -> bool:
    """https, or plain http whose host resolves to private addresses only (remote.private_http_only)."""
    import socket
    parts = urlsplit(url)
    if parts.scheme.lower() != "http":
        return True
    try:
        addrs = socket.getaddrinfo(parts.hostname, parts.port or 80, type=socket.SOCK_STREAM)
    except (OSError, ValueError):
        return False
    return bool(addrs) and all(remote._private(a[4][0]) for a in addrs)


def _plain(value, limit: int) -> str:
    """A value of the service's /info as one line of printable text: its answer must not add a line to the output that
    commands/ner.md reads (codex review: a `start:` line from /info)."""
    return "".join(c if c.isprintable() else "?" for c in str(value))[:limit]


def probe(conf, timeout: float = 1.0) -> tuple[bool, str]:
    """(answers, one line): GET /health, then /info for the model and the types it can name."""
    url = str(conf.get("url") or "") if isinstance(conf, dict) else ""
    if not url:
        return False, ""
    if url.startswith("unix:"):
        return False, "the service: a Unix socket; this command does not probe one"
    if not remote.is_local(url) and conf.get("allow_network") is not True:
        return False, "the service: not asked (not on this computer, and allow_network is not set)"
    if not remote.is_local(url) and not _http_allowed(url):
        # the rule the detector applies at each connection: a setting from before 0.8.7 is not shown as working
        return False, ("the service: not asked; plain http to an address that is not private is not used. Use "
                       "https or a private address (/maisecrets:ner url URL)")
    t0 = time.monotonic()
    try:
        status, _ = _get(url, "/health", timeout)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return False, f"the service: does not answer ({type(exc).__name__})"
    if status != 200:
        return False, f"the service: answers HTTP {status} at /health"
    ms = (time.monotonic() - t0) * 1000
    try:
        _, body = _get(url, "/info", timeout)
        info = json.loads(body)
        model = _plain(info.get("model", "?"), 120)
        labels = info.get("labels")
        kinds = ", ".join(_plain(x, 20) for x in labels[:10]) if isinstance(labels, list) else "PER"
    except (OSError, urllib.error.URLError, ValueError, AttributeError):
        return True, f"the service: answers ({ms:.0f} ms); /info does not name its model"
    return True, f"the service: answers ({ms:.0f} ms), model {model}, types {kinds}"


def container_tool() -> str:
    """The absolute path of docker or podman, the first one on PATH, or "". The restart runs this path, not a name
    that PATH resolves again (codex review of 0.8.7)."""
    for name in ("docker", "podman"):
        found = shutil.which(name)
        if found:
            return os.path.abspath(found)
    return ""


# a container named ner whose image is mcpgate/ner (any tag), started again: the plugin's own Python, the container
# tool by its absolute path, no shell and no value of the setting
_RESTART = ("import subprocess, sys\n"
            "t = sys.argv[1]\n"
            "r = subprocess.run([t, 'container', 'inspect', '-f', '{{.Config.Image}}', 'ner'], capture_output=True,"
            " text=True, timeout=30)\n"
            "img = r.stdout.strip()\n"
            "if r.returncode == 0 and (img == 'mcpgate/ner' or img.startswith('mcpgate/ner:')):\n"
            "    subprocess.run([t, 'start', 'ner'], capture_output=True, timeout=120)\n")


def restart_local(conf) -> bool:
    """At a session start: when the source is the local service and it does not answer, start the container `ner`
    again, but only when its image is mcpgate/ner (another container of that name is someone else's). In the
    background: the session start never waits for docker. True when a start was asked for."""
    url = str(conf.get("url") or "") if isinstance(conf, dict) else ""
    if url.rstrip("/") != LOCAL_URL.rstrip("/"):
        return False
    tool = container_tool()
    if not tool:
        return False
    ok, _line = probe(conf, timeout=0.3)
    if ok:
        return False
    subprocess.Popen([sys.executable, "-I", "-c", _RESTART, tool], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return True


def report(conf, wait: float = 0.0) -> tuple[int, list]:
    """(exit code, lines) for /maisecrets:ner: the source, whether it answers (waiting up to `wait` seconds), and for
    the local source that does not answer the command that starts it. The exit code is 0 when the source answers or
    is off, 3 when the local service needs a start, 1 otherwise."""
    lines = [describe(conf)]
    url = conf.get("url") if isinstance(conf, dict) else None
    if not url:
        lines.append("To turn it on: /maisecrets:ner local (the service on this computer) or "
                     "/maisecrets:ner url URL (a service of your team), as your own prompt.")
        return 0, lines
    lines.append(scope(conf))
    lines.append(counts_line())
    deadline = time.monotonic() + wait
    ok, line = probe(conf)
    while not ok and time.monotonic() < deadline:
        time.sleep(1)
        ok, line = probe(conf)
    lines.append(line)
    if ok:
        return 0, lines
    lines.append("Until it answers, the rules mask tool results alone, as without the service.")
    if str(url).rstrip("/") == LOCAL_URL.rstrip("/"):
        tool = container_tool()
        if tool:
            # commands/ner.md runs one of its two fixed commands on exit code 3; this line only names the tool
            lines.append(f"start: {START.replace('docker', os.path.basename(tool), 1)}")
            return 3, lines
        lines.append("Neither docker nor podman is installed. Install one of them (Docker Desktop, OrbStack, Podman), "
                     f"then run: {START}. Or use a service of your team: /maisecrets:ner url URL. Or turn it off: "
                     "/maisecrets:ner off.")
    elif not remote.is_local(str(url)):
        lines.append("Check the address with the team that runs the service.")
    return 1, lines


# --------------------------------------------------------- the down note --
DOWN_NOTE = ("maisecrets: the name service set with /maisecrets:ner did not answer, so the rules alone masked this "
             "tool result; names that only the service finds were not masked. Mention this once, in one sentence, "
             "after your answer, and tell the user that /maisecrets:ner shows the service and how to start it. Do not "
             "start or change the service or the setting yourself.")
FALLBACK_NOTE = ("maisecrets: the name service of this computer did not answer, so the fallback set with "
                 "/maisecrets:ner checked this tool result; the tool results of this session go there while the "
                 "local one is down, your prompts never do. Mention this once, in one sentence, after your answer, and "
                 "tell the user that /maisecrets:ner shows the counts per service. Do not change the setting "
                 "yourself.")
_NOTES_MAX = 1000          # sessions; an older one may get the note once more


def claim_down_note(home, session) -> bool:
    """True once per session: the first unavailable answer of the service in it. False when the record cannot be
    written (no note rather than one per tool result). Under a lock: two hooks at once give it once."""
    if not session:
        return False
    from .home import LockTimeout, _lock_for, atomic_write
    key = hashlib.sha256(str(session).encode("utf-8")).hexdigest()[:16]
    path = home / "ner-down-notes.json"
    try:
        with _lock_for(home / ".ner-down-notes.lock"):
            try:
                seen = json.loads(path.read_text(encoding="utf-8"))
                seen = seen if isinstance(seen, list) else []
            except (OSError, ValueError):
                seen = []
            if key in seen:
                return False
            atomic_write(path, json.dumps((seen + [key])[-_NOTES_MAX:]))
    except (OSError, LockTimeout):
        return False
    return True


# --------------------------------------------------------------- the NER log --
# One line per request: time, source (local, url, fallback, or rules when no service answered), kind (tool or
# prompt), characters and names. Never text: a sceptic can check where text went, and that no prompt ever went to a
# fallback (akruse-3b, 2026-10-31). /maisecrets:ner shows today's counts and the last lines.
LOG_MAX = 1_000_000          # bytes; above it the older half goes
LAST = {"source": ""}        # the source of the last request of this process (hooks._ner_hint reads it)


def _log_path():
    from .vault import HOME
    return HOME / "ner.log"


def log(source: str, kind: str, chars: int, names: int) -> None:
    LAST["source"] = source
    path = _log_path()
    line = json.dumps({"t": int(time.time()), "source": source, "kind": kind, "chars": chars, "names": names})
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        if path.stat().st_size > LOG_MAX:
            from .home import LockTimeout, _lock_for, atomic_write
            try:
                with _lock_for(path.with_name(".ner-log.lock")):
                    lines = path.read_text(encoding="utf-8").splitlines()
                    atomic_write(path, "\n".join(lines[len(lines) // 2:]) + "\n")
            except LockTimeout:
                pass
    except OSError:
        pass                 # the log is for the person; a full disk must not stop a tool result


def today_counts(now: float | None = None) -> dict:
    """{source: requests} of today (local time), and prompts per source under "prompt:<source>"."""
    start = time.mktime(time.localtime(now or time.time())[:3] + (0, 0, 0, 0, 0, -1))
    counts: dict = {}
    try:
        lines = _log_path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return counts
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict) or not isinstance(d.get("t"), int) or d["t"] < start:
            continue
        counts[d.get("source", "?")] = counts.get(d.get("source", "?"), 0) + 1
        if d.get("kind") == "prompt":
            key = "prompt:" + str(d.get("source", "?"))
            counts[key] = counts.get(key, 0) + 1
    return counts


def counts_line(now: float | None = None) -> str:
    c = today_counts(now)
    if not c:
        return "today: no request yet"
    parts = [f"{k} {c[k]}" for k in ("local", "url", "fallback", "rules") if c.get(k)]
    prompts = sum(v for k, v in c.items() if k.startswith("prompt:"))
    return (f"today: {', '.join(parts)} (rules = no service answered); prompts {prompts}, of them to a fallback "
            f"{c.get('prompt:fallback', 0)}")
