"""/maisecrets:ner: one source of names for tool results (setting `remote_detector`, maisecrets/remote_layer.py).

    /maisecrets:ner local          the service on this computer, http://127.0.0.1:8765/ (`on` is the same)
    /maisecrets:ner url URL        a service of the team on a private network
    /maisecrets:ner off            the rules alone
    /maisecrets:ner                which source is set, and whether it answers

Codex: `maisecrets: ner local` (or url URL, off) alone as the prompt. The change is a setting, so only a prompt the
person typed makes it (settings.py); a tool call that carries the sentence is refused. Exactly one source: a
fallback to another one would send the text somewhere the person did not choose. A source that does not answer
leaves the rules alone, as before. The tuning keys of the setting (timeout_ms, classes, min_score, max_chars,
language) stay when the source changes.

A service that is not on this computer gets every finding of the rules as filler (remote.py), and the text of the
tool result goes there: a team decides that, not a default.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .detection import remote

LOCAL_URL = "http://127.0.0.1:8765/"
IMAGE = "mcpgate/ner"
START = f"docker run -d --name ner --restart unless-stopped -p 127.0.0.1:8765:8765 {IMAGE}"
# the keys a source sets; any other key of the setting is the person's tuning and stays
SOURCE_KEYS = ("url", "format", "model", "allow_network", "mask")

_NER_RE = re.compile(r"\A\s*(?:/maisecrets:ner|maisecrets:\s*ner)\s+(?:(off|local|on)|url\s+(\S+))\s*\Z", re.I)
# the same sentence anywhere in a tool call (settings.IN_A_COMMAND_RE)
IN_A_COMMAND = r"(?:/maisecrets:ner|maisecrets:\s*ner)\s+(?:off|local|on|url)\b"


def parse(prompt) -> str | None:
    """`off`, `local` or `url:<URL>` when the whole prompt is a change of the source, else None."""
    m = _NER_RE.match(prompt) if isinstance(prompt, str) else None
    if not m:
        return None
    if m.group(1):
        return "off" if m.group(1).lower() == "off" else "local"
    return "url:" + m.group(2)


def check_url(url: str) -> str:
    """Why maisecrets does not use this URL, or ""."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "it is no http:// or https:// address with a host"
    if parts.username or parts.password:
        return "it holds a user name or a password; the service takes none"
    if parts.query or parts.fragment:
        return "it holds a ? or a # part"
    try:
        parts.port
    except ValueError:
        return "its port is no number from 0 to 65535"
    return ""


def updated(current, word: str) -> dict:
    """The new value of the setting for `word` (from parse), the tuning keys of `current` kept."""
    keep = {k: v for k, v in (current if isinstance(current, dict) else {}).items() if k not in SOURCE_KEYS}
    if word == "off":
        return keep
    url = LOCAL_URL if word == "local" else word[4:]
    new = {**keep, "url": url, "format": "hf"}
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
    return f"names from a service: {url} ({where})"


def _get(url: str, path: str, timeout: float):
    with urllib.request.urlopen(url.rstrip("/") + path, timeout=timeout) as r:   # noqa: S310 - the person's URL
        return r.status, r.read(65536)


def probe(conf, timeout: float = 1.0) -> tuple[bool, str]:
    """(answers, one line): GET /health, then /info for the model and the types it can name."""
    url = str(conf.get("url") or "") if isinstance(conf, dict) else ""
    if not url:
        return False, ""
    if url.startswith("unix:"):
        return False, "the service: a Unix socket; this command does not probe one"
    if not remote.is_local(url) and conf.get("allow_network") is not True:
        return False, "the service: not asked (not on this computer, and allow_network is not set)"
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
        model = str(info.get("model", "?"))[:120]
        labels = info.get("labels")
        kinds = ", ".join(str(x) for x in labels[:10]) if isinstance(labels, list) else "PER"
    except (OSError, urllib.error.URLError, ValueError, AttributeError):
        return True, f"the service: answers ({ms:.0f} ms); /info does not name its model"
    return True, f"the service: answers ({ms:.0f} ms), model {model}, types {kinds}"


def container_tool() -> str:
    """docker or podman, the first one on PATH, or ""."""
    for name in ("docker", "podman"):
        if shutil.which(name):
            return name
    return ""


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
            lines.append(f"start: {START.replace('docker', tool, 1)}")
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
_NOTES_MAX = 200


def claim_down_note(home, session) -> bool:
    """True once per session: the first unavailable answer of the service in it. False when the record cannot be
    written (no note rather than one per tool result)."""
    if not session:
        return False
    key = hashlib.sha256(str(session).encode("utf-8")).hexdigest()[:16]
    path = home / "ner-down-notes.json"
    try:
        seen = json.loads(path.read_text(encoding="utf-8"))
        seen = seen if isinstance(seen, list) else []
    except (OSError, ValueError):
        seen = []
    if key in seen:
        return False
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps((seen + [key])[-_NOTES_MAX:]), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return False
    return True
