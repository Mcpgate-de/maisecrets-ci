"""/maisecrets:ner: one source of names for tool results (setting `remote_detector`, maisecrets/remote_layer.py).

    /maisecrets:ner local          the service on this computer, http://127.0.0.1:8765/ (`on` is the same)
    /maisecrets:ner url URL        a service of the team on a private network
    /maisecrets:ner off            the rules alone
    /maisecrets:ner                which source is set, and whether it answers

Codex: `maisecrets: ner local` (or url URL, off) alone as the prompt. The change is a setting, so only a prompt the
person typed makes it (settings.py), with the limits of C22 (docs/THREAT-MODEL.md); a tool call that carries the
sentence is refused. Exactly one source: a
fallback to another one would send the text somewhere the person did not choose. A source that does not answer
leaves the rules alone, as before. The tuning keys of the setting (timeout_ms, max_timeout_ms, timeout_scales,
classes, min_score, max_chars, language) stay when the source changes.

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
# the first tag whose container proves its secret (NER_CLIENT_SECRET, #1699)
FIRST_SECRET_IMAGE = IMAGE + ":v2.0.3584"
# what `run.sh ner start` runs: a fixed tag, pinned by its digest (multi-arch index on Docker Hub, 2026-11-07), never
# `latest`, which docker does not pull again when an old one is on the machine
SECRET_IMAGE = IMAGE + ":v2.0.3798@sha256:38c0442e10f75e2b41bdcf5a66c6aee02961f9609bf7ebb7d1ce64c1f9c907cf"
START = f"docker run -d --name ner --restart unless-stopped -p 127.0.0.1:8765:8765 {IMAGE}"
# the keys a source sets; any other key of the setting is the person's tuning and stays
SOURCE_KEYS = ("url", "format", "model", "allow_network", "mask", "ask_labels", "gateway", "gateway_url")

_NER_RE = re.compile(r"\A\s*(?:/maisecrets:ner|maisecrets:\s*ner)\s+(?:(off|local|on)|url\s+(\S+)|"
                     r"gateway\s+(\S+)|"
                     r"fallback\s+(?:(off)|url\s+(\S+))|prompts\s+(on|off)|updates\s+(on|off)|"
                     r"unavailable\s+(rules|withhold))\s*\Z", re.I)
# the same sentence anywhere in a tool call (settings.IN_A_COMMAND_RE)
IN_A_COMMAND = (r"(?:/maisecrets:ner|maisecrets:\s*ner)\s+(?:off|local|on|url|gateway|fallback|prompts|updates|"
                r"unavailable)\b")


def parse(prompt) -> str | None:
    """`off`, `local`, `url:<URL>`, `fallback:off`, `fallback:url:<URL>`, `prompts:on`, `prompts:off`, `updates:on` or
    `updates:off` when the whole prompt is a change of the setting, else None."""
    m = _NER_RE.match(prompt) if isinstance(prompt, str) else None
    if not m:
        return None
    if m.group(1):
        return "off" if m.group(1).lower() == "off" else "local"
    if m.group(2):
        return "url:" + m.group(2)
    if m.group(3):
        return "gateway:" + m.group(3)
    if m.group(6):
        return "prompts:" + m.group(6).lower()
    if m.group(7):
        return "updates:" + m.group(7).lower()
    if m.group(8):
        return "unavailable:" + m.group(8).lower()
    return "fallback:off" if m.group(4) else "fallback:url:" + m.group(5)


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
    if word.startswith("prompts:"):
        # off is not a source key: it stays when the source changes. On for a service on the network is a choice for
        # that source alone (C30a): a change of the source takes it away below
        if word == "prompts:off":
            current["prompts"] = False
        elif current.get("url") and (current.get("gateway") or not remote.is_local(str(current["url"]))):
            current["prompts"] = True
        else:
            current.pop("prompts", None)
        return current
    if word.startswith("unavailable:"):
        # what a tool result gets while the service gives no answer: the rules alone (the default) or nothing
        if word == "unavailable:withhold":
            current["unavailable"] = "withhold"
        else:
            current.pop("unavailable", None)
        return current
    if word.startswith("updates:"):
        # not a source key either: the image of the local service follows the plugin unless this is false
        if word == "updates:off":
            current["auto_update"] = False
        else:
            current.pop("auto_update", None)
        return current
    if word == "fallback:off":
        current.pop("fallback", None)
        return current
    if word.startswith("fallback:url:"):
        url = word[len("fallback:url:"):]
        current["fallback"] = {"url": url, "format": "hf", "ask_labels": True,
                               **({} if remote.is_local(url) else {"allow_network": True})}
        return current
    keep = {k: v for k, v in current.items() if k not in SOURCE_KEYS}
    if keep.get("prompts") is True:
        del keep["prompts"]                 # prompts on was a choice for the old source (C30a)
    if word == "off":
        keep.pop("fallback", None)          # off is off: no fallback answers either
        return keep
    if word.startswith("gateway:"):
        # the gateway of /maisecrets:sref login (#33): its name endpoint and a token come at each tool result
        from .vault_refs import origin_of
        given = word[len("gateway:"):]
        origin = origin_of(given) or given
        return {**keep, "gateway": origin, "gateway_url": given, "url": origin, "format": "hf",
                "allow_network": True}
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
    prompts = "tool results and your prompts" if conf.get("prompts") is True else "tool results only"
    if conf.get("gateway"):
        return (f"names from a service: the gateway {conf['gateway']} (its login; {prompts}; the findings of "
                "the rules go there as filler)")
    where = ("on this computer" if remote.is_local(str(url))
             else f"on the network; {prompts}; the findings of the rules go there as filler")
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
    network = bool(url) and (bool(conf.get("gateway")) or not remote.is_local(url))
    if url and conf.get("prompts") is not False and (not network or conf.get("prompts") is True):
        where = (f" Your prompts go to {conf.get('gateway') or url} for this, with the rules' findings as filler."
                 if network else "")
        return ("It masks person names in what the AI reads (files, command output, tool results) and in your prompts "
                f"in Claude Code.{where} In Codex it covers what the AI reads only. It may mask a few extra words.")
    more = (" /maisecrets:ner prompts on sends your prompts there too, with the rules' findings as filler."
            if network and conf.get("prompts") is not False else "")
    return ("It masks person names in what the AI reads (files, command output, tool results). Your prompts keep the "
            f"rules alone.{more} It may mask a few extra words.")


def unavailable_line(conf) -> str:
    """One line: what a tool result gets while the service gives no answer."""
    if isinstance(conf, dict) and conf.get("unavailable") == "withhold":
        return ("While the name service gives no answer, maisecrets withholds the tool result from the AI, and your "
                "screen names the reason. /maisecrets:ner unavailable rules lets the rules alone mask it.")
    return ("While the name service gives no answer, the rules alone mask a tool result, and your screen shows "
            "'names not checked' with the reason. /maisecrets:ner unavailable withhold keeps such a result from "
            "the AI.")


def updates_line(conf) -> str:
    """One line: whether the image of the local service follows the plugin."""
    if isinstance(conf, dict) and conf.get("auto_update") is False:
        return ("The image of the local service stays as it is (updates off). /maisecrets:ner updates on lets it "
                "follow the plugin again.")
    return ("The image of the local service follows the plugin: a session start gives it the image this version "
            "pins. /maisecrets:ner updates off keeps it as it is.")


def _tag(image: str) -> str:
    return image.split("@", 1)[0].rpartition(":")[2] if ":" in image.split("@", 1)[0] else "latest"


def image_line(conf, tool: str) -> str:
    """One line for /maisecrets:ner: the image of the container `ner` against the one this version pins."""
    from . import ner_secret
    cid, _running, image, image_id = _inspect(tool, "ner")
    if not cid or not _ours_image(image):
        return ""
    pinned = _tag(SECRET_IMAGE)
    if image == SECRET_IMAGE:
        return f"image: {pinned}, the one this version pins"
    if _tag(image) == pinned:
        pinned += " by its digest"          # the same tag without the pin, or pushed again
    if not _behind(tool, image, image_id):
        return f"image: {_tag(image)}; this version pins {pinned}, an older one, so it stays"
    if cid != ner_secret.container_of(ner_secret.endpoint(LOCAL_URL)):
        return (f"image: {_tag(image)}; this version pins {pinned}, but the container was not set up by maisecrets, "
                f"so it is not updated. To change that: {os.path.basename(tool)} rm -f ner, then /maisecrets:ner "
                "again.")
    if isinstance(conf, dict) and conf.get("auto_update") is False:
        return f"image: {_tag(image)}; this version pins {pinned} (updates off: /maisecrets:ner updates on)"
    if _failed_recently():
        return (f"image: {_tag(image)}; a container of {pinned} did not start, so the old one runs on. maisecrets "
                "tries again in a day.")
    return f"image: {_tag(image)}; this version pins {pinned}, and the next session start updates it"


def _get(url: str, path: str, timeout: float):
    with _OPENER.open(url.rstrip("/") + path, timeout=timeout) as r:
        return r.status, r.read(65536)


def _address_refused(url: str, allow_network: bool, timeout: float) -> str:
    """Why the detector would refuse the addresses this URL gives now, or "": without allow_network every address must
    be loopback, and plain http only to private addresses (remote.RemoteDetector._connection). The lookup runs within
    `timeout`. The probe asks its own lookup again, so this is a check of the setting, not a pin: the probe never
    sends text (codex review of 0.8.7)."""
    import socket
    import threading
    parts = urlsplit(url)
    box: dict = {}

    def look() -> None:
        try:
            box["addrs"] = [a[4][0] for a in socket.getaddrinfo(parts.hostname, parts.port or 80,
                                                                 type=socket.SOCK_STREAM)]
        except (OSError, ValueError, UnicodeError) as exc:
            box["error"] = exc
    th = threading.Thread(target=look, daemon=True)
    th.start()
    th.join(timeout)
    addrs = box.get("addrs")
    if not addrs:
        return "its name does not resolve in time"
    if not allow_network and not all(remote._loopback(a) for a in addrs):
        return "its name resolves to another computer, and allow_network is not set"
    if parts.scheme.lower() == "http" and not all(remote._private(a) for a in addrs):
        return ("plain http to an address that is not private is not used; use https or a private address "
                "(/maisecrets:ner url URL)")
    return ""


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
    why = _address_refused(url, conf.get("allow_network") is True, timeout)
    if why:
        # the rules the detector applies at each connection: a setting it would refuse is not shown as working
        return False, f"the service: not asked; {why}"
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


def make_backend_for(conf) -> object:
    from .vault import load_config, make_backend
    return make_backend(load_config())


def _proves(conf) -> bool:
    """A real proof, as a tool result gets it: the detector of the setting asks the service with a neutral text."""
    from . import remote_layer
    from .vault import load_config
    det, _why = remote_layer.from_config(load_config())
    if det is None:
        return False
    _spans, status = det.ask("A check of the name service.", [])
    return status.state == "ok"


def _info(conf) -> dict:
    """GET /info of the source, or {} when it cannot be read."""
    try:
        with urllib.request.urlopen(str(conf.get("url")).rstrip("/") + "/info", timeout=2) as r:
            doc = json.loads(r.read(65536).decode("utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, urllib.error.URLError, ValueError, AttributeError):
        return {}


def container_tool() -> str:
    """The absolute path of docker or podman, the first one on PATH, or "". The restart runs this path, not a name
    that PATH resolves again (codex review of 0.8.7)."""
    for name in ("docker", "podman"):
        found = shutil.which(name)
        if found:
            return os.path.abspath(found)
    return ""


# the session start runs follow_pin in a process of its own: the plugin's Python, isolated (-I), the plugin folder as
# the only import path, the container tool by its absolute path; no shell and no value of the setting on its command
_KEEP = ("import sys\n"
         "sys.path.insert(0, sys.argv[1])\n"
         "from maisecrets import ner_setup\n"
         "ner_setup.follow_pin(sys.argv[2])\n")
PREV = "ner-prev"                 # the old container while a new image starts; renamed back if the new one fails
PROOF_WAIT_S = 90.0               # a new container loads its model before it can prove the secret
BACK_OFF_S = 86400.0              # a pin whose container did not start is tried again after a day, not at each start
START_WAIT_S = 10.0               # run.sh ner start waits this long for an update that holds the lock


def _quiet() -> dict:
    """No console window for docker on Windows (a hook may have none, and each call would open one)."""
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)} if os.name == "nt" else {}


def _docker(tool: str, *args: str, timeout: float = 120, env=None):
    return subprocess.run([tool, *args], capture_output=True, text=True, timeout=timeout, env=env, **_quiet())


def _norm(image: str) -> str:
    """An image reference as maisecrets writes it: podman may add docker.io/ (and library/) in front."""
    for prefix in ("docker.io/library/", "docker.io/"):
        if image.startswith(prefix):
            return image[len(prefix):]
    return image


def _ours_image(image: str) -> bool:
    image = _norm(image)
    return image == IMAGE or image.startswith((IMAGE + ":", IMAGE + "@"))


def _release(image: str):
    """The release in a tag of mcpgate/ner (v2.0.3798 → (2, 0, 3798)), or None (latest, a digest alone)."""
    m = re.search(r":v(\d+)\.(\d+)\.(\d+)(?:@|\Z)", _norm(image))
    return tuple(int(x) for x in m.groups()) if m else None


def _update_path():
    from .vault import HOME
    return HOME / "ner-update.json"


def _failed_recently(now: float | None = None) -> bool:
    """Whether a container of this pin did not start within BACK_OFF_S."""
    try:
        d = json.loads(_update_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(d, dict) or d.get("failed") != SECRET_IMAGE or not isinstance(d.get("t"), (int, float)):
        return False
    return (now or time.time()) - d["t"] < BACK_OFF_S


def _note_update(failed: bool) -> None:
    from .home import atomic_write
    try:
        if failed:
            atomic_write(_update_path(), json.dumps({"failed": SECRET_IMAGE, "t": int(time.time())}) + "\n")
        else:
            _update_path().unlink(missing_ok=True)
    except OSError:
        pass


def restart_local(conf) -> bool:
    """At a session start, for the local source: in the background, start the container `ner` again after a reboot,
    and give a container that maisecrets set up the image this plugin version pins (follow_pin). The session start
    never waits for docker. Without a container that maisecrets set up, a service that answers needs nothing. True
    when the background process was started."""
    url = str(conf.get("url") or "") if isinstance(conf, dict) else ""
    if url.rstrip("/") != LOCAL_URL.rstrip("/"):
        return False
    tool = container_tool()
    if not tool:
        return False
    from . import ner_secret
    if not ner_secret.container_of(ner_secret.endpoint(LOCAL_URL)):
        ok, _line = probe(conf, timeout=0.3)
        if ok:
            return False
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    flags = {}
    if os.name == "nt":
        # its own process group, no console: closing the client does not end an update halfway
        flags = {"creationflags": getattr(subprocess, "DETACHED_PROCESS", 0)
                 | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    else:
        flags = {"start_new_session": True}
    subprocess.Popen([sys.executable, "-I", "-c", _KEEP, root, tool], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **flags)
    return True


def _run_container(tool: str, secret: str, image: str) -> tuple[int, str, str]:
    """(exit code, container id, last error line) of a new container `ner` from `image` with `secret`. The secret goes
    to docker in the environment, never on the command line, where `ps` shows it."""
    env = dict(os.environ, NER_CLIENT_SECRET=secret)
    r = _docker(tool, "run", "-d", "--name", "ner", "--restart", "unless-stopped", "-e", "NER_CLIENT_SECRET",
                "-p", "127.0.0.1:8765:8765", image, timeout=900, env=env)
    cid = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    return r.returncode, cid, (r.stderr.strip().splitlines() or ["no reason given"])[-1][:200]


def _inspect(tool: str, name: str) -> tuple[str, str, str, str]:
    """(id, running, image reference, image id) of a container, or four empty strings."""
    r = _docker(tool, "container", "inspect", "-f", "{{.Id}} {{.State.Running}} {{.Image}} {{.Config.Image}}", name,
                timeout=30)
    if r.returncode != 0:
        return "", "", "", ""
    parts = r.stdout.strip().split(" ", 3)
    if len(parts) < 4:
        return "", "", "", ""
    cid, running, image_id, image = parts
    return cid, running, _norm(image), image_id


def _image_id(tool: str, image: str) -> str:
    r = _docker(tool, "image", "inspect", "-f", "{{.Id}}", image, timeout=30)
    return r.stdout.strip() if r.returncode == 0 else ""


def _behind(tool: str, image: str, image_id: str) -> bool:
    """Whether the image of the container is older than the pin: only forward. An older plugin version in an open
    session must not take a newer image back (Opus review)."""
    have, want = _release(image), _release(SECRET_IMAGE)
    if have is None or want is None:
        return False                  # no release to compare: never replaced on a guess
    if have != want:
        return have < want
    pinned = _image_id(tool, SECRET_IMAGE)
    return image != SECRET_IMAGE and (not pinned or pinned != image_id)    # the same tag, not the pinned digest


def _proved(conf, wait: float) -> bool:
    deadline = time.monotonic() + wait
    while True:
        try:
            if _proves(conf):
                return True
        except Exception:  # noqa: BLE001 - not yet: the model is still loading
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


def follow_pin(tool: str, conf=None) -> str:
    """The background work of a session start (restart_local), one session at a time (a lock; a second one does
    nothing). A stopped container `ner` of mcpgate/ner is started first. A container that maisecrets set up (its id
    is the one kept in ner-containers.json) whose image is older than SECRET_IMAGE gets the pinned image: pull while
    the old one runs (a failed pull changes nothing), stop the old one and rename it to ner-prev, run a new one with
    the same secret, and only when the new one proves the secret is the old one removed with its image. Otherwise the
    new one goes, ner-prev is renamed back and started, and this pin waits BACK_OFF_S. The setting
    `"auto_update": false` (/maisecrets:ner updates off) keeps the image. A container started by hand, or one with
    another image, is never replaced. Gives what it did, for the tests and the probes."""
    from . import ner_secret
    from .home import LockTimeout, _Lock
    from .vault import HOME, load_config
    if conf is None:
        conf = load_config().get("remote_detector")
    conf = conf if isinstance(conf, dict) else {}
    lock = _Lock(HOME / ".ner-update.lock")
    lock.LOCK_DEADLINE = 0.2
    ep = ner_secret.endpoint(LOCAL_URL)
    try:
        with lock:
            cid, running, image, image_id = _inspect(tool, "ner")
            if not cid:
                # an update that ended halfway (a kill, a logout): the old container waits as ner-prev
                prev = _inspect(tool, PREV)
                if prev[0] and prev[0] == ner_secret.container_of(ep):
                    _docker(tool, "rename", prev[0], "ner")
                    _docker(tool, "start", prev[0])
                    return "recovered"
                return "none"
            if not _ours_image(image):
                return "foreign"             # another container of that name is someone else's
            outcome = "running"
            if running != "true":
                _docker(tool, "start", "ner")    # after a reboot: the service first, a download later
                outcome = "started"
            if cid != ner_secret.container_of(ep) or conf.get("auto_update") is False:
                return outcome
            if not _behind(tool, image, image_id) or _failed_recently():
                return outcome
            secret = ner_secret.secret_of(make_backend_for(conf), ep)
            if not secret or _docker(tool, "pull", SECRET_IMAGE, timeout=3600).returncode != 0:
                return outcome
            _docker(tool, "stop", cid, timeout=60)
            _docker(tool, "rename", cid, PREV)
            rc, new, _err = _run_container(tool, secret, SECRET_IMAGE)
            if rc == 0 and new and _proved(conf, PROOF_WAIT_S):
                ner_secret.move(ep, new)
                _docker(tool, "rm", "-f", cid, timeout=60)
                if image_id and image_id != _image_id(tool, SECRET_IMAGE):
                    _docker(tool, "rmi", image_id)
                _note_update(failed=False)
                return "updated"
            # the new image did not prove the secret: it goes (by id; under the lock, a container named ner that is
            # not ner-prev can only be the one this run made), and the old one comes back as it was
            made = new or _inspect(tool, "ner")[0]
            if made and made != cid:
                _docker(tool, "rm", "-f", made, timeout=60)
            _docker(tool, "rename", cid, "ner")
            _docker(tool, "start", cid)
            _note_update(failed=True)
            return "kept"
    except (LockTimeout, OSError, subprocess.SubprocessError):
        return "busy"


def start_local(cfg: dict) -> tuple[int, list]:
    """`run.sh ner start` (#1699), run by the AI after the person said yes: the container `ner` on 127.0.0.1:8765 with
    a secret it must prove before each text. The secret goes to docker in the environment (never on the command line,
    where `ps` shows it) and into the store; the container id beside it. An existing container `ner` that maisecrets
    did not start is left as it is: it runs unchecked, and the output says how to replace it. It takes the lock of
    follow_pin: an update that runs is never crossed by a second container."""
    from .home import LockTimeout, _Lock
    from .vault import HOME
    tool = container_tool()
    if not tool:
        return 1, ["Neither docker nor podman is installed. Install one of them (Docker Desktop, OrbStack, Podman)."]
    lock = _Lock(HOME / ".ner-update.lock")
    lock.LOCK_DEADLINE = START_WAIT_S
    try:
        with lock:
            return _start_local(cfg, tool)
    except LockTimeout:
        return 1, ["maisecrets is updating the image of the local service right now (a download can take a few "
                   "minutes). Run /maisecrets:ner again in a minute."]


def _start_local(cfg: dict, tool: str) -> tuple[int, list]:
    from . import ner_secret
    from .vault import make_backend
    ep = ner_secret.endpoint(LOCAL_URL)
    backend = make_backend(cfg)
    r = _docker(tool, "container", "inspect", "-f", "{{.Id}} {{.Config.Image}}", "ner", timeout=30)
    if r.returncode == 0:
        cid, _, image = r.stdout.strip().partition(" ")
        if not _ours_image(image):
            return 1, ["A container named ner exists with another image. maisecrets leaves it alone; remove or rename "
                       "it to let maisecrets start its own."]
        _docker(tool, "start", "ner")
        if ner_secret.secret_of(backend, ep) and ner_secret.container_of(ep) == cid:
            return 0, ["started: the container ner that maisecrets set up; it proves its secret before each text."]
        return 0, ["started: the container ner, which was not set up by maisecrets, so it is not checked. To have it "
                   f"checked: {os.path.basename(tool)} rm -f ner, then /maisecrets:ner again."]
    secret = ner_secret.new_secret()
    rc, cid, err = _run_container(tool, secret, SECRET_IMAGE)
    if rc != 0:
        return 1, ["The container did not start: " + err]
    try:
        ner_secret.keep(backend, ep, secret, cid)
    except Exception as exc:  # noqa: BLE001 - a container whose secret is not kept would be checked by nobody
        # by its id, never by the name: a container ner that replaced it meanwhile is not this one
        if cid:
            _docker(tool, "rm", "-f", cid, timeout=60)
        return 1, [f"The secret could not be stored ({type(exc).__name__}); the container was removed again."]
    return 0, ["started: the container ner with a secret of its own; it proves the secret before each text."]


def report(conf, wait: float = 0.0) -> tuple[int, list]:
    """(exit code, lines) for /maisecrets:ner: the source, whether it answers (waiting up to `wait` seconds), and for
    the local source that does not answer the command that starts it. The exit code is 0 when the source answers or
    is off, 3 when the local service needs a start, 4 when the gateway source needs a login with the name scope
    (commands/ner.md runs it after the person's /maisecrets:ner gateway URL), 1 otherwise."""
    lines = [describe(conf)]
    url = conf.get("url") if isinstance(conf, dict) else None
    if not url:
        lines.append("To turn it on: /maisecrets:ner local (the service on this computer), url URL (a service of your "
                     "team) or gateway URL (the gateway of your login), as your own prompt.")
        return 0, lines
    lines.append(scope(conf))
    lines.append(unavailable_line(conf))
    lines.append(counts_line())
    if conf.get("gateway"):
        return _gateway_report(conf, lines)
    deadline = time.monotonic() + wait
    ok, line = probe(conf)
    while not ok and time.monotonic() < deadline:
        time.sleep(1)
        ok, line = probe(conf)
    lines.append(line)
    if ok and str(url).rstrip("/") == LOCAL_URL.rstrip("/"):
        from . import ner_secret
        ep = ner_secret.endpoint(LOCAL_URL)
        if not ner_secret.container_of(ep):
            lines.append("not checked: the container was not set up by maisecrets (run.sh ner start does that)")
        elif not ner_secret.secret_of(make_backend_for(conf), ep):
            lines.append("the secret maisecrets kept for the container cannot be read, so the container gets no text. "
                         "Remove it (docker rm -f ner) and run /maisecrets:ner again.")
            return 1, lines
        elif not _info(conf).get("client_secret"):
            # an image before the secret check: it gets no text, and the fault is the image, not an impostor
            lines.append(f"the container cannot prove its secret: its image is older than {FIRST_SECRET_IMAGE}. "
                         "Remove it (docker rm -f ner) and run /maisecrets:ner again; until then it gets no text.")
            return 1, lines
        elif not _proves(conf):
            lines.append("the service on 127.0.0.1:8765 is not the container that maisecrets started: it cannot prove "
                         "the secret, so it gets no text. Stop it, and run /maisecrets:ner again.")
            return 1, lines
        else:
            lines.append("checked: the container proved the secret maisecrets gave it, just now and before each text")
        tool = container_tool()
        try:
            line = image_line(conf, tool) if tool else ""
        except (OSError, subprocess.SubprocessError):
            line = ""
        if line:
            lines.append(line)
            lines.append(updates_line(conf))
    if ok:
        return 0, lines
    lines.append("Until it answers, the rules mask tool results alone, as without the service.")
    if str(url).rstrip("/") == LOCAL_URL.rstrip("/"):
        tool = container_tool()
        if tool:
            # commands/ner.md runs `run.sh ner start` on exit code 3 (a container with a secret, #1699)
            lines.append(f"start: run.sh ner start (with {os.path.basename(tool)})")
            return 3, lines
        lines.append("Neither docker nor podman is installed. Install one of them (Docker Desktop, OrbStack, Podman), "
                     f"then run: {START}. Or use a service of your team: /maisecrets:ner url URL. Or turn it off: "
                     "/maisecrets:ner off.")
    elif not remote.is_local(str(url)):
        lines.append("Check the address with the team that runs the service.")
    return 1, lines


def _gateway_report(conf: dict, lines: list) -> tuple[int, list]:
    """The gateway source as a tool result meets it: its discovery, the login with the name scope, one short request.
    /health of the gateway says nothing about the login, so it is not asked."""
    from . import remote_layer
    from .home import load_config
    det, why = remote_layer.from_config({**load_config(), "remote_detector": conf})
    if det is None:
        lines.append(f"the gateway: not asked; {why}")
        if "login" in why:
            name = gateway_server(conf)
            lines.append(f"login: run.sh sref login{(' ' + name) if name else ''}")
            return 4, lines
        return 1, lines
    _spans, st = det.ask("A check of the name service.", [])
    if st.available:
        lines.append(f"the gateway: answers ({st.ms:.0f} ms) with your login")
        return 0, lines
    lines.append(f"the gateway: gives no result ({st.reason or st.state}); the rules mask tool results alone until it "
                 "does")
    return 1, lines


def gateway_server(conf: dict) -> str:
    """The name of the MCP server of the user configuration whose origin is the gateway of this source, or ""."""
    from . import vault_refs
    from .vault_refs import origin_of
    want = str(conf.get("gateway") or "")
    try:
        servers = vault_refs.user_servers()
    except Exception:  # noqa: BLE001 - no name: `sref login` alone then works for one server
        return ""
    names = [k for k, v in servers.items() if origin_of(str(v)) == want]
    return names[0] if len(names) == 1 and re.fullmatch(r"[\w.-]{1,64}", names[0]) else ""


# --------------------------------------------------------- the down note --
DOWN_NOTE = ("maisecrets: the name service set with /maisecrets:ner gave no result ({why}), so the rules alone "
             "masked this tool result; names that only the service finds were not masked. Mention this once, in one "
             "sentence, with that reason, after your answer, and tell the user that /maisecrets:ner shows the "
             "service. Do not start or change the service or the setting yourself.")
NOT_OURS_NOTE = ("maisecrets: the service on 127.0.0.1:8765 is not the container that maisecrets started (it could not "
                 "prove the secret maisecrets gave that container), so no text went to it and the rules alone masked "
                 "this tool result. Mention this once, in one sentence, after your answer, and tell the user to run "
                 "/maisecrets:ner, which starts the right container. Do not start or stop a service yourself.")
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


_VERSION: list = []


def _version() -> str:
    """The plugin version, read once per process: a hook writes a log line for each tool result."""
    if not _VERSION:
        from .events import plugin_version
        _VERSION.append(plugin_version())
    return _VERSION[0]


def log(source: str, kind: str, chars: int, names: int, why: str = "", ms: float = 0.0) -> None:
    """`why`: the reason no service answered (timeout, too_long, refused …), for a line of the rules alone."""
    LAST["source"] = source
    path = _log_path()
    entry = {"t": int(time.time()), "source": source, "kind": kind, "chars": chars, "names": names, "ms": int(ms),
             "v": _version()}
    if why:
        entry["why"] = why
    line = json.dumps(entry)
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
    """{source: requests} of today (local time), prompts per source under "prompt:<source>", the reasons of the rules
    alone under "why:<reason>", and under "other_version" the lines of a plugin version other than this one. A line
    of the rules alone without a reason comes from a version before 0.8.29, which wrote none: a session keeps the
    version it started with, so these lines are not a failure of their own (#25)."""
    start = time.mktime(time.localtime(now or time.time())[:3] + (0, 0, 0, 0, 0, -1))
    counts: dict = {}
    try:
        lines = _log_path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return counts
    current = _version()
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict) or not isinstance(d.get("t"), int) or d["t"] < start:
            continue
        counts[d.get("source", "?")] = counts.get(d.get("source", "?"), 0) + 1
        if d.get("v") != current:
            counts["other_version"] = counts.get("other_version", 0) + 1
        if d.get("source") == "rules":
            key = "why:" + str(d.get("why") or ("older version" if "v" not in d else "unknown"))
            counts[key] = counts.get(key, 0) + 1
        if d.get("kind") == "prompt":
            key = "prompt:" + str(d.get("source", "?"))
            counts[key] = counts.get(key, 0) + 1
    return counts


def counts_line(now: float | None = None) -> str:
    c = today_counts(now)
    if not c:
        return "today, your sessions on this computer (ner.log): no request yet"
    parts = [f"{k} {c[k]}" for k in ("local", "url", "fallback", "rules") if c.get(k)]
    whys = sorted(((v, k[4:]) for k, v in c.items() if k.startswith("why:")), reverse=True)
    if whys and c.get("rules"):
        parts[-1] += " (" + ", ".join(f"{w} {v}" for v, w in whys) + ")"
    prompts = sum(v for k, v in c.items() if k.startswith("prompt:"))
    line = (f"today, your sessions on this computer (ner.log): {', '.join(parts)} (rules = no service answered); "
            f"prompts {prompts}, of them to a fallback {c.get('prompt:fallback', 0)}")
    if c.get("other_version"):
        line += (f"; requests from sessions of another version {c['other_version']} (a session keeps the version it "
                 f"started with; a restart moves it to {_version()})")
    return line
