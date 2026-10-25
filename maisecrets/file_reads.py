"""Reads of PDFs and images: what the person decides with the settings read_pdf and read_image.

maisecrets cannot look inside an image or a PDF: the client sends its bytes to the model, and a scan of the base64
text finds nothing real (a 1 MB image took 30 s and gave one false hit, which also broke the image). So the person
decides per type (C28):

    allow    the file goes to the model as it is (the default; a hint names the setting once)
    ask      Claude Code asks the person first; Codex cannot ask, so it refuses with a hint
    block    the read is refused
    convert  PDF only: the PDF never reaches the model. The text that `pdftotext` extracts on this computer takes
             its place, and the normal redaction masks it.

The shapes are measured (Claude Code 2.1.296, harness/probe_file_reads.py, goldens in harness/golden/). PreToolUse
gets the path; PostToolUse gets {type: "image" | "pdf" | "parts", file: {...}}. Only an answer in the shape of a
text Read removes the image or the PDF from the request: a string fails the client's shape check and the original
is sent, and a PDF-shaped answer with an empty base64 still sends the whole PDF. So every answer here that stands in
for a PDF or an image is `text_result()`, also a refusal. Folders in the list setting clean_dirs are the person's
own decision: a file there that was in place before the session passes as allow. A Bash result that the client
marks isImage (its stdout is a data:image URI) reaches the model as an image; it counts as an image read, and only
its stdout skips the scan. Only the client's own isImage counts: a text that only starts like a data URI is text,
and is scanned as text. A notebook Read whose outputs hold an image counts as an image read too: ask and block send
it as text without the images. A pasted image and an image in an MCP result never reach this module (known gaps,
README).
"""
from __future__ import annotations

import os
import re

MODES = {"read_pdf": ("allow", "ask", "block", "convert"), "read_image": ("allow", "ask", "block")}
SETTING = {"pdf": "read_pdf", "image": "read_image"}
# the extensions the Read tool sends as an image or a document; the response type below is the backstop
_IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
TEXT_KEYS = ("filePath", "content", "numLines", "startLine", "totalLines")

# the extraction must end well inside the 16 s watchdog of PostToolUse, and the redaction of its text after it. The
# redaction has no time cap of its own here: the cap on the text is the bound. Measured on 3.9 (stub pdftotext, the
# whole hook): the worst text found, AWS key shapes side by side, took 2.4 s at 32K characters, 8.2 s at 64K and
# 97 s at 256K (one rule grows with the square of the text); prose takes 0.5 s at 32K
EXTRACT_SECONDS = 6.0
MAX_PDF_BYTES = 100 * 1024 * 1024
# a file read under ask, or from a clean folder, is bound by its sha256 to the bytes the client returns: 10 MB costs
# 6-10 ms to hash and 23-32 ms to decode and hash (3.9 and 3.14). A larger file is never clean, and ask refuses it
BIND_MAX_BYTES = 64 * 1024 * 1024
MAX_TEXT_CHARS = 32 * 1024
# a crafted PDF of 3.6 MB took pdftotext to 1.5 GB in 2.4 s and on (poppler 26.10.0, 2026-10-14); one of 15 KB, to
# 234 MB. The largest normal PDF measured (858 pages) peaked at 27 MB. macOS does not enforce RLIMIT_AS or RLIMIT_DATA
# (a limit below the address space it gives every process is refused, one above it changes nothing: measured), so
# the hook reads the child's resident size while it waits and stops it above this. Linux enforces RLIMIT_AS as well
MAX_RSS_BYTES = 512 * 1024 * 1024
MAX_AS_BYTES = 1024 * 1024 * 1024
POLL_SECONDS = 0.05
ERR_KEEP_BYTES = 4096       # the end of pdftotext's messages that _cause reads
DIAGNOSE_SECONDS = 2.0      # the second run that reads them: 6 s + 2 s stay well inside the 16 s watchdog
# 25 characters that are not white space per page, on average: below that a PDF is a scan with page numbers or a
# header line at most (the rule of the ai-gateway's document review). A scan of 3 pages with only page numbers had 45
MIN_CHARS_PER_PAGE = 25
# a client started from the desktop has a short PATH; these hold pdftotext from Homebrew, MacPorts and Linux packages
_EXTRA_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/bin")
INSTALL = ("macOS: brew install poppler; Debian or Ubuntu: sudo apt install poppler-utils; Fedora: sudo dnf install "
           "poppler-utils; Windows: the poppler or Xpdf command line tools")


def kind_of_path(path: str) -> str | None:
    low = path.lower()
    if low.endswith(".pdf"):
        return "pdf"
    if low.endswith(_IMAGE_EXT):
        return "image"
    return None


def kind_of_response(tool: str, response) -> str | None:
    """What the client is about to send as a file: "pdf", "image" or None (text, or not a read)."""
    if not isinstance(response, dict):
        return None
    if tool == "Read":
        if response.get("type") == "notebook":
            return "image" if _notebook_images(response) else None
        return {"pdf": "pdf", "parts": "pdf", "image": "image"}.get(response.get("type"))
    if tool == "Bash" and response.get("isImage") is True:
        # the client's own flag, never a guess from the text: a stdout that only starts like a data URI is text,
        # and text is scanned (a guess here let every Bash output pass unscanned, review of block 4)
        return "image"
    return None


def _notebook_outputs(response: dict):
    file = response.get("file") if isinstance(response.get("file"), dict) else {}
    for cell in file.get("cells") or []:
        if isinstance(cell, dict):
            for out in cell.get("outputs") or []:
                if isinstance(out, dict):
                    yield cell, out


def _notebook_images(response: dict) -> int:
    return sum(1 for _c, out in _notebook_outputs(response) if out.get("image"))


def hold_images(response: dict) -> tuple:
    """A copy of a notebook result whose image data is empty, and the data taken out, in order. The scan walks the
    rest: base64 is no text to scan (300 KB took 7.5 s, review of block 4), the cells are."""
    import copy
    held = []
    out = copy.deepcopy(response)
    for _cell, o in _notebook_outputs(out):
        img = o.get("image")
        if isinstance(img, dict) and isinstance(img.get("image_data"), str):
            held.append(img["image_data"])
            img["image_data"] = ""
    return out, held


def put_back_images(response, held: list) -> None:
    if not isinstance(response, dict):
        return
    data = iter(held)
    for _cell, o in _notebook_outputs(response):
        img = o.get("image")
        if isinstance(img, dict) and img.get("image_data") == "":
            img["image_data"] = next(data, "")


def notebook_has_image(path: str) -> bool:
    """The file holds an image output (a mime type image/... in it). Too large or unreadable: True (ask)."""
    try:
        if os.path.getsize(path) > 50 * 1024 * 1024:
            return True
        with open(path, "rb") as f:
            return b'"image/' in f.read()
    except OSError:
        return True


def notebook_text(response: dict, note: str) -> str:
    """A notebook as text, every image output replaced by the note (measured: the text shape takes a notebook's
    image out of the request too, harness/golden/file_reads_model_view.json nb_replace_text)."""
    file = response.get("file") if isinstance(response.get("file"), dict) else {}
    parts = []
    for cell in file.get("cells") or []:
        if not isinstance(cell, dict):
            continue
        cid = str(cell.get("cell_id") or "")
        parts.append(f'<cell id="{cid}">{cell.get("source") or ""}</cell id="{cid}">')
        for out in cell.get("outputs") or []:
            if not isinstance(out, dict):
                continue
            if out.get("text"):
                parts.append(str(out["text"]))
            if out.get("ename") or out.get("evalue") or out.get("traceback"):
                tb = out.get("traceback")
                tb = "\n".join(map(str, tb)) if isinstance(tb, list) else str(tb or "")
                parts.append(f"{out.get('ename') or ''}: {out.get('evalue') or ''}" + (f"\n{tb}" if tb else ""))
            if out.get("image"):
                parts.append(f"[{note}]")
    return "\n\n".join(parts)


def mode(cfg: dict, kind: str) -> str:
    """The person's mode for this kind. A value that is no mode (a hand-edited file) blocks: it fails closed."""
    key = SETTING[kind]
    value = cfg.get(key, "allow")
    return value if value in MODES[key] else "block"


def _real(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


_SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
SEEN_DAYS = 30


def _seen_path(session):
    from .vault import HOME
    if not isinstance(session, str) or not _SESSION_RE.fullmatch(session):
        return None
    return os.path.join(str(HOME), "sessions-seen", session)


NESTED = "nested"
_CLIENTS = ("claude", "codex")


def nested_client() -> bool:
    """A client that runs below another client (an agent that started `claude -p` or `codex exec` in its shell). The
    environment cannot tell: Claude Code sets CLAUDECODE=1 and its own session id for a top-level session too
    (measured on 2.1.296). The process chain can: above the hook there is one client, or two. A process list that
    cannot be read counts as nested (no clean folder)."""
    import subprocess
    try:
        out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,comm="], capture_output=True, text=True, timeout=3,
                             stdin=subprocess.DEVNULL).stdout
    except (OSError, subprocess.SubprocessError):
        return True
    parent, name = {}, {}
    for line in out.splitlines():
        bits = line.split(None, 2)
        if len(bits) == 3 and bits[0].isdigit() and bits[1].isdigit():
            parent[int(bits[0])], name[int(bits[0])] = int(bits[1]), os.path.basename(bits[2].strip())
    pid, clients, steps = os.getpid(), 0, 0
    if pid not in parent:
        return True
    while pid in parent and pid > 1 and steps < 64:
        clients += name.get(pid) in _CLIENTS
        pid, steps = parent[pid], steps + 1
    # the session's own client and one more above it. A client that runs under another name (an npm install runs as
    # node) is not counted, so one nested in it is not seen (C28)
    return clients >= 2


def _root_key(d: str) -> str:
    return os.path.normpath(os.path.expanduser(d.strip()))


def root_identity(d: str):
    """(st_dev, st_ino) of a clean root, or None for a root that is or lies under a link (refused at add) or is gone."""
    import stat
    key = _root_key(d)
    try:
        if not os.path.isabs(key) or os.path.realpath(key) != key:
            return None
        st = os.lstat(key)
        return [st.st_dev, st.st_ino] if stat.S_ISDIR(st.st_mode) else None
    except OSError:
        return None


def _roots_now(cfg: dict) -> dict:
    out = {}
    for d in cfg.get("clean_dirs") or []:
        if isinstance(d, str) and d.strip():
            ident = root_identity(d)
            if ident:
                out[_root_key(d)] = ident
    return out


def _write_note(path: str, data: dict) -> None:
    """Write the note in place of the old one: a new file (never through a link), then a rename over the old name."""
    import json
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data))
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def link_roots(cfg: dict) -> list:
    """The clean folders that are a link or lie under one: never clean (a hand-edited file; add refuses them)."""
    out = []
    for d in cfg.get("clean_dirs") or []:
        if isinstance(d, str) and d.strip():
            key = _root_key(d)
            if os.path.isabs(key) and os.path.exists(key) and os.path.realpath(key) != key:
                out.append(d)
    return out


def note_session_start(payload: dict, cfg: dict | None = None) -> None:
    """SessionStart: note when this session began, the anchor of clean_dirs (C28). Only here: a prompt or a tool call
    never writes the note, so a note that the agent deletes is not made again with a later time (nothing is clean
    then). Not at a compaction, which the agent can bring about with a long output. A nested client gets a note that
    makes no folder clean."""
    if payload.get("source") == "compact":
        return
    session = payload.get("session_id")
    path = _seen_path(session)
    if not path or os.name == "nt":
        return
    folder = os.path.dirname(path)
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        if os.path.islink(folder) or os.path.lexists(path):
            return
        import json
        import time
        if nested_client():
            text = NESTED
        else:
            if cfg is None:
                from .vault import load_config
                cfg = load_config()
            # each clean root as it is now: a root that is later swapped for another folder is not clean
            text = json.dumps({"t": time.time(), "roots": _roots_now(cfg)})
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
    except OSError:
        pass


def note_clean_root(session, folder: str) -> None:
    """A clean root the person adds with a typed prompt during the session: its identity now goes into the note."""
    data = _read_note(session)
    path = _seen_path(session)
    if not data or not path:
        return
    ident = root_identity(folder)
    if not ident:
        return
    data["roots"][_root_key(folder)] = ident
    try:
        _write_note(path, data)
    except OSError:
        pass


def _full(payload: dict, path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(str(payload.get("cwd") or ""), path)


def file_digest(full: str):
    """{"sha", "size", "dev", "ino"} of the file, all from ONE open descriptor: the identity that keys a note and the
    checksum in it belong to the same file (codex verification of block 4: a stat and a second open could see two
    files). The resolved path is opened without following a link, and the file must not change while it is read
    (fstat before and after: device, inode, size, mtime). None: unreadable, changed, or larger than BIND_MAX_BYTES."""
    import hashlib
    import stat
    try:
        fd = os.open(os.path.realpath(full), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as f:
            before = os.fstat(f.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > BIND_MAX_BYTES:
                return None
            h = hashlib.sha256()
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
            after = os.fstat(f.fileno())
        same = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == \
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        return {"sha": h.hexdigest(), "size": before.st_size, "dev": before.st_dev, "ino": before.st_ino} \
            if same else None
    except OSError:
        return None


def _ask_path(payload: dict, kind: str, path: str, tag: str = "ask", ident=None):
    """The one-use note of this call (C28): `ask` when the PreToolUse asked the person, `clean` when it found the
    file in a clean folder. Keyed by session, tool use, kind, file, and the file's device and inode."""
    from .vault import HOME
    session, tid = payload.get("session_id"), payload.get("tool_use_id")
    if not isinstance(session, str) or not _SESSION_RE.fullmatch(session) or not isinstance(tid, str) or not tid:
        return None
    if not path:
        return None
    import hashlib
    full = _full(payload, path)
    if ident is None:
        try:
            st = os.stat(full)
        except OSError:
            return None
        ident = (st.st_dev, st.st_ino)
    key = hashlib.sha256("\0".join((tag, session, tid, kind, _real(full), str(ident[0]), str(ident[1])))
                         .encode()).hexdigest()[:40]
    return os.path.join(str(HOME), "asked", key)


def note_ask(payload: dict, kind: str, path: str, tag: str = "ask") -> bool:
    """Write the note with the file's sha256 and size. False: no note (too large, unreadable): nothing can pass."""
    import json
    digest = file_digest(_full(payload, path)) if path else None
    target = _ask_path(payload, kind, path, tag, (digest["dev"], digest["ino"])) if digest else None
    if not target:
        return False
    try:
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        if os.path.islink(os.path.dirname(target)):
            return False
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps({"sha": digest["sha"], "size": digest["size"]}))
        return True
    except OSError:
        return False


def take_ask(payload: dict, kind: str, path: str, tag: str = "ask"):
    """The note of this very call, once: it is removed as it is read. None without it."""
    import json
    import stat
    target = _ask_path(payload, kind, path, tag)
    if not target:
        return None
    try:
        if os.path.islink(os.path.dirname(target)) or not stat.S_ISREG(os.lstat(target).st_mode):
            return None
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd) as f:
            note = json.loads(f.read(4096))
        os.unlink(target)
        return note if isinstance(note, dict) and isinstance(note.get("sha"), str) else None
    except (OSError, ValueError):
        return None


def same_bytes(note, response: dict, full: str) -> bool:
    """The client returned the very file the PreToolUse checked (codex review of block 4: a file or a root swapped in
    and back between the two hooks passed). A PDF and an image the client did not re-encode carry the file itself
    as base64: its sha256 must match. A re-encoded image, PDF pages (images) and a notebook carry no copy: their
    originalSize and the file as it is now must match, which narrows the window but does not close it (C28)."""
    import base64
    import binascii
    import hashlib
    if not note:
        return False
    kind = response.get("type")
    file = response.get("file") if isinstance(response.get("file"), dict) else {}
    data = file.get("base64")
    if kind in ("pdf", "image") and isinstance(data, str):
        try:
            if hashlib.sha256(base64.b64decode(data)).hexdigest() == note["sha"]:
                return True
        except (ValueError, binascii.Error):
            return False
        if kind == "pdf":
            return False
    if kind in ("image", "parts") and file.get("originalSize") != note.get("size"):
        return False
    now = file_digest(full)
    return bool(now) and now["sha"] == note["sha"]


def prune_sessions() -> None:
    """SessionStart: the notes of sessions older than SEEN_DAYS go."""
    import time
    from .vault import HOME
    asked = os.path.join(str(HOME), "asked")       # asks the person answered with no: a day is enough
    try:
        if not os.path.islink(asked):
            for name in os.listdir(asked):
                f = os.path.join(asked, name)
                if os.lstat(f).st_mtime < time.time() - 86400:
                    os.unlink(f)
    except OSError:
        pass
    folder = os.path.dirname(_seen_path("x"))
    try:
        if os.path.islink(folder):
            return
        for name in os.listdir(folder):
            f = os.path.join(folder, name)
            if os.lstat(f).st_mtime < time.time() - SEEN_DAYS * 86400:
                os.unlink(f)
    except OSError:
        pass


def _read_note(session):
    """{"t": start, "roots": {root: [dev, ino]}} with t the earliest of the time in the note, its mtime and its inode
    change time (a touch or utime moves the two times of the file, never the text in it; a rewrite moves the change
    time to now). None: no note, a link, a nested client: nothing is clean."""
    import json
    import stat
    path = _seen_path(session)
    if not path:
        return None
    try:
        if stat.S_ISLNK(os.lstat(os.path.dirname(path)).st_mode):
            return None
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd) as f:
            text = f.read(65536).strip()
        if text == NESTED:
            return None
        data = json.loads(text)
        roots = data.get("roots") if isinstance(data.get("roots"), dict) else {}
        return {"t": min(float(data["t"]), st.st_mtime, st.st_ctime), "roots": roots}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None


def session_start(session) -> float | None:
    data = _read_note(session)
    return data["t"] if data else None


def in_clean_dir(path: str, cwd: str, cfg: dict, session=None) -> bool:
    """The file lies in a folder of clean_dirs and was there before the session began. Both sides are resolved first
    (links and ..), so a link inside a clean folder that points out of it, or a path that climbs out with .., is not
    inside. The file itself must have one name only (a hard link from outside has two) and an inode change time
    older than the start of this session (session_start): a copy, a move or a link that the agent makes into the
    folder changes that time, and no command sets it back. The note of the start lies in the maisecrets folder, which
    the agent's tools may not touch (C8); an obfuscated command can still move it (C8 matches the command text). No
    note: nothing is clean."""
    dirs = [d for d in cfg.get("clean_dirs") or [] if isinstance(d, str) and d.strip()]
    if not dirs or not path or os.name == "nt":
        # Windows: st_ctime is the creation time there, and a move keeps it. clean_dirs is for macOS and Linux
        return False
    full = path if os.path.isabs(os.path.expanduser(path)) else os.path.join(cwd or os.getcwd(), path)
    try:
        real = _real(os.path.expanduser(full))
        inside = None
        for d in dirs:
            d = os.path.expanduser(d.strip())
            if not os.path.isabs(d):
                continue
            base = _real(d)
            if real != base and os.path.commonpath([real, base]) == base:
                inside = (d, base)
                break
        if not inside:
            return False
        note = _read_note(session)
        if not note:
            return False
        # the root is still the folder the session started with (or the person added): a folder moved or linked in
        # under its name is another one (codex review of block 4)
        ident = root_identity(inside[0])
        if not ident or note["roots"].get(_root_key(inside[0])) != ident:
            return False
        started = note["t"]
        # every folder between the root and the file was there before the session: a renamed or moved folder has a
        # new change time, and its old files would pass on their own
        sub = os.path.dirname(os.path.realpath(os.path.expanduser(full)))
        root = os.path.realpath(inside[0])
        while sub != root and os.path.commonpath([sub, root]) == root:
            if os.lstat(sub).st_ctime >= started:
                return False
            sub = os.path.dirname(sub)
        st = os.stat(os.path.realpath(os.path.expanduser(full)))
        return started is not None and st.st_nlink == 1 and st.st_ctime < started
    except (OSError, ValueError):
        return False


def text_result(file_path: str, content: str) -> dict:
    """The measured shape of a text Read: the only answer that takes an image or a PDF out of the request."""
    lines = content.count("\n") + 1 if content else 1
    return {"type": "text", "file": {"filePath": file_path, "content": content, "numLines": lines, "startLine": 1,
                                     "totalLines": lines}}


def admin_groups() -> frozenset:
    """Groups whose members can become root anyway, so their write is no other account's write (maintainer's
    decision, Option B). Measured in the default sudoers and polkit rules (2026-10-14): macOS `%admin ALL = (ALL) ALL`,
    and wheel is gid 0, the group of root; Debian `%sudo`; Ubuntu `%sudo` and `%admin`; Fedora `%wheel`. Alpine and
    openSUSE name no group by default, so there none counts; a system not in this list keeps the strict rule."""
    import sys
    if sys.platform == "darwin":
        return frozenset({"admin", "wheel"})
    if not sys.platform.startswith("linux"):
        return frozenset()
    ids = set()
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
            for line in f:
                key, _, value = line.strip().partition("=")
                if key in ("ID", "ID_LIKE"):
                    ids.update(value.strip().strip("\"'").split())
    except OSError:
        return frozenset()
    groups = set()
    if ids & {"debian", "ubuntu"}:
        groups.add("sudo")
    if "ubuntu" in ids:
        groups.add("admin")
    if ids & {"fedora", "rhel", "centos"}:
        groups.add("wheel")
    return frozenset(groups)


def _group_has_other_writer(gid: int) -> bool:
    """Whether a group write lets another account in: True for every group but one whose members can become root
    (admin_groups). A member list cannot tell: macOS groups like everyone (12) and localaccounts (61) list no
    member and hold every account, and directory services add members the list does not show (review of block 4)."""
    try:
        import grp
        return grp.getgrgid(gid).gr_name not in admin_groups()
    except (ImportError, KeyError, OSError):
        return True


def _acl_lets_in(path: str) -> bool:
    """An access control list on the path that can grant a write beside the mode bits: on macOS an allow entry with
    a write right (`chmod +a`), on Linux any POSIX ACL (a named entry hides behind the group mask). Fail closed: a
    list that cannot be read counts as one."""
    import sys
    if sys.platform == "darwin":
        try:
            import ctypes
            lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            lib.acl_get_link_np.restype = ctypes.c_void_p
            lib.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
            lib.acl_to_text.restype = ctypes.c_void_p
            lib.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            lib.acl_free.argtypes = [ctypes.c_void_p]
            acl = lib.acl_get_link_np(os.fsencode(path), 0x100)          # ACL_TYPE_EXTENDED
            if not acl:
                return ctypes.get_errno() != 2                          # ENOENT: no list
            text = lib.acl_to_text(acl, None)
            try:
                body = ctypes.string_at(text).decode("utf-8", "replace") if text else None
            finally:
                if text:
                    lib.acl_free(text)
                lib.acl_free(acl)
        except (OSError, AttributeError, ValueError):
            return True
        return body is None or acl_text_grants_write(body)
    if sys.platform.startswith("linux"):
        try:
            os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)
            return True
        except OSError as exc:
            import errno
            return exc.errno not in (errno.ENODATA, errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP))
        except AttributeError:
            return False
    return False


def acl_text_grants_write(body: str) -> bool:
    """The text of a macOS ACL (acl_to_text) has an allow entry with a write right."""
    for line in body.splitlines()[1:]:
        fields = line.split(":")
        # group:<uuid>:<name>:<id>:allow|deny[,flags]:<rights>; the flags of inheritance share the field
        # (allow,file_inherit,directory_inherit or allow,inherited, measured by both reviews of round 2)
        if len(fields) >= 6 and "allow" in fields[-2].split(",") and set(fields[-1].split(",")) & _ACL_WRITES:
            return True
    return False


_ACL_WRITES = frozenset({"write", "append", "add_file", "add_subdirectory", "delete", "delete_child", "writeattr",
                         "writeextattr", "writesecurity", "chown"})


def _no_other_writer(path: str) -> bool:
    """Every component from / to the path is owned by root or this user, and nobody else can write it: no write for
    others, group write only for an admin group (admin_groups), and no access control list that grants a write. A
    folder with the sticky bit (/tmp) may be writable by all: only an entry's owner can rename it, and that owner is
    checked at the next component."""
    import stat
    if not hasattr(os, "getuid"):
        return False
    uid = os.getuid()
    parts = os.path.abspath(path).split(os.sep)
    current = os.sep
    for i, part in enumerate([""] + parts[1:]):
        current = os.path.join(current, part) if part else current
        try:
            st = os.lstat(current)
        except OSError:
            return False
        if st.st_uid not in (0, uid):
            return False
        if stat.S_ISLNK(st.st_mode):
            # Linux shows every link as 0777, and nobody can write a link: its owner is checked here, its folder
            # one step up and its target by the caller's realpath walk
            continue
        sticky = stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX
        if st.st_mode & stat.S_IWOTH and not sticky:
            return False
        if st.st_mode & stat.S_IWGRP and not sticky and _group_has_other_writer(st.st_gid):
            return False
        if _acl_lets_in(current):
            return False
    return True


def _outside(paths, cwd: str) -> bool:
    """None of the paths lies in the working folder."""
    if not cwd:
        return True
    work = os.path.realpath(cwd)
    return not any(os.path.commonpath([os.path.realpath(x), work]) == work for x in paths)


def trusted_tool(link: str, cwd: str = "") -> str | None:
    """The program a fixed-folder entry leads to, when both the entry and its target pass _no_other_writer and
    neither lies in the working folder; None otherwise."""
    try:
        if not (os.path.isfile(link) and os.access(link, os.X_OK)):
            return None
        real = os.path.realpath(link)
        if not (_no_other_writer(link) and _no_other_writer(real)):
            return None
        if not _outside((os.path.dirname(link), real), cwd):
            return None
    except (OSError, ValueError):
        return None
    return real


# ---------------------------------------------------------- the libraries --
# Homebrew's pdftotext loads 33 libraries from /opt/homebrew (poppler 26.10.0, measured with otool -L): a writable
# library runs code in the hook as surely as a writable program. Each one passes the same check as the program
_MACHO_LOAD = (0xC, 0x20, 0x80000018, 0x8000001F, 0x80000023)   # LOAD, LAZY_LOAD, LOAD_WEAK, REEXPORT, LOAD_UPWARD
_MACHO_RPATH = 0x8000001C
_HEAD_BYTES = 256 * 1024
_MAX_LIBRARIES = 400


def _macho_commands(path: str):
    """(libraries, rpaths) that the load commands of a Mach-O file name, for this machine's slice of a universal
    file; None for a file that is no Mach-O or cannot be read whole."""
    import platform
    import struct
    try:
        with open(path, "rb") as f:
            data = f.read(_HEAD_BYTES)
            magic = struct.unpack(">I", data[:4])[0]
            if magic in (0xCAFEBABE, 0xCAFEBABF):
                want = {"arm64": 0x0100000C, "x86_64": 0x01000007}.get(platform.machine())
                wide = magic == 0xCAFEBABF
                step = 32 if wide else 20
                for i in range(min(struct.unpack(">I", data[4:8])[0], 16)):
                    rec = data[8 + i * step:8 + (i + 1) * step]
                    off = struct.unpack(">Q", rec[8:16])[0] if wide else struct.unpack(">I", rec[8:12])[0]
                    if struct.unpack(">I", rec[:4])[0] == want:
                        f.seek(off)
                        data = f.read(_HEAD_BYTES)
                        break
                else:
                    return None
        if data[:4] != b"\xcf\xfa\xed\xfe":
            return None
        ncmds, size = struct.unpack("<II", data[16:24])
        if 32 + size > len(data):
            return None
        pos, libs, rpaths = 32, [], []
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack("<II", data[pos:pos + 8])
            if cmdsize < 12 or pos + cmdsize > 32 + size:
                return None
            if cmd in _MACHO_LOAD or cmd == _MACHO_RPATH:
                off = struct.unpack("<I", data[pos + 8:pos + 12])[0]
                name = data[pos + off:pos + cmdsize].split(b"\0", 1)[0].decode("utf-8")
                (rpaths if cmd == _MACHO_RPATH else libs).append(name)
            pos += cmdsize
    except (OSError, ValueError, struct.error, UnicodeDecodeError):
        return None
    return libs, rpaths


def _nearest_folder(path: str) -> list:
    """The folder itself, or for one that does not exist the nearest folder above it that does: whoever can write
    that one can make the missing folder and put a library in it (round 3). A name that is a dangling link counts
    twice: by the folder its name lies in, and by the folder it points to."""
    out = []
    for p in dict.fromkeys((os.path.abspath(path), os.path.realpath(path))):
        while not os.path.isdir(p) and os.path.dirname(p) != p:
            p = os.path.dirname(p)
        out.append(p)
    return out


def _macho_libraries(tool: str):
    """Every library a Mach-O program loads, also through the libraries it loads (no otool: without the developer
    tools it is a stub that asks to install them). A library under /usr/lib or /System that is not on disk lives
    in the system's shared cache, under SIP. None when a name cannot be resolved."""
    exe_dir = os.path.dirname(tool)
    seen, out, todo = set(), [], [(tool, ())]
    while todo:
        path, above = todo.pop()
        if path in seen:
            continue
        seen.add(path)
        parsed = _macho_commands(path)
        if parsed is None or len(seen) > _MAX_LIBRARIES:
            return None
        here = os.path.dirname(path)
        rpaths = tuple(r.replace("@loader_path", here).replace("@executable_path", exe_dir) for r in parsed[1]) + above
        for name in parsed[0]:
            if name.startswith(("/usr/lib/", "/System/")) and not os.path.lexists(name):
                continue
            if name.startswith("@rpath/"):
                hit = next((i for i, r in enumerate(rpaths) if os.path.isfile(os.path.join(r, name[7:]))), None)
                if hit is None:
                    return None
                # dyld takes the first folder that holds the name: a folder searched before it must stay closed too
                out.extend(f for r in rpaths[:hit] for f in _nearest_folder(r))
                name = os.path.join(rpaths[hit], name[7:])
            name = name.replace("@loader_path", here).replace("@executable_path", exe_dir)
            if not (os.path.isabs(name) and os.path.isfile(name)):
                return None
            out.append(name)
            todo.append((os.path.realpath(name), rpaths))
    return out


def _elf_libraries(tool: str):
    """The libraries ldd names for an ELF program, the loader too; None when ldd is not a trusted root program or
    fails. ldd runs the program's loader, never its code; the program passed the check before."""
    import subprocess
    ldd = next((p for p in ("/usr/bin/ldd", "/bin/ldd") if os.path.isfile(p)), None)
    if not ldd or not (_no_other_writer(ldd) and _no_other_writer(os.path.realpath(ldd))):
        return None
    try:
        r = subprocess.run([ldd, tool], capture_output=True, text=True, timeout=3, stdin=subprocess.DEVNULL,
                           env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if "=>" in line:
            target = line.split("=>", 1)[1].strip().split(" (", 1)[0].strip()
            if target == "not found":
                return None
            if target.startswith("/"):
                out.append(target)
        elif line.startswith("/"):
            out.append(line.split(" (", 1)[0])
    return out


def libraries(tool: str, _depth: int = 0):
    """The code the program loads besides itself: its libraries, or the interpreter of a script. None when that
    cannot be told; a program whose libraries cannot be told is not run."""
    import sys
    try:
        with open(tool, "rb") as f:
            head = f.read(256)
    except OSError:
        return None
    if head.startswith(b"#!"):
        words = head[2:].split(b"\n", 1)[0].split()
        # `#!/usr/bin/env x` lets the PATH choose the program: no fixed interpreter, no run
        if not words or not words[0].startswith(b"/") or os.path.basename(words[0]) == b"env":
            return None
        interpreter = os.fsdecode(words[0])
        # the interpreter's own libraries too; an interpreter that is a script again is not followed
        own = libraries(os.path.realpath(interpreter), 1) if _depth == 0 else None
        return None if own is None else [interpreter] + own
    if sys.platform == "darwin":
        return _macho_libraries(tool)
    if head.startswith(b"\x7fELF"):
        return _elf_libraries(tool)
    return None


def _trusted_libraries(tool: str, cwd: str = "") -> bool:
    libs = libraries(tool)
    if libs is None:
        return False
    try:
        return all(_no_other_writer(lib) and _no_other_writer(os.path.realpath(lib)) for lib in libs) \
            and _outside(libs, cwd)
    except (OSError, ValueError):
        return False


def pdftotext(cwd: str = "") -> str | None:
    """pdftotext from the fixed install folders only (Homebrew, MacPorts, /usr/local/bin, /usr/bin), never from the
    PATH: a folder on the PATH that the agent can write to would get its own program run by the hook (codex review of
    block 4). The program and every library it loads must have no other writer. The resolved program is returned,
    and extract() checks it again right before it starts it."""
    for d in _EXTRA_DIRS:
        real = trusted_tool(os.path.join(d, "pdftotext"), cwd)
        if real and _trusted_libraries(real, cwd):
            return real
    return None


def untrusted_tool() -> str | None:
    """A pdftotext in a fixed folder that maisecrets does not run (another account can change it, a folder above it
    or a library it loads)."""
    for d in _EXTRA_DIRS:
        link = os.path.join(d, "pdftotext")
        if os.path.isfile(link):
            real = trusted_tool(link)
            if not (real and _trusted_libraries(real)):
                return link
    return None


def missing_tool_text(codex: bool) -> str:
    change = "maisecrets: set read_pdf" if codex else "/maisecrets:settings read_pdf"
    found = untrusted_tool()
    if found:
        return (f"maisecrets: the setting read_pdf is convert, and maisecrets does not run the pdftotext in "
                f"{os.path.dirname(found)}: another account on this computer can change it, a folder above it or a "
                "library it loads. Nothing of the PDF reached you. Tell the user; they can install pdftotext where "
                f"only they, root and the admin group can write, or choose another mode with {change} allow, ask "
                "or block.")
    return (f"maisecrets: the setting read_pdf is convert, and convert needs the program pdftotext, which is not "
            f"installed in a fixed install folder ({', '.join(_EXTRA_DIRS) or 'none on this system'}; the PATH is "
            f"not used). Nothing of the PDF reached you. Tell the user to install it ({INSTALL}) "
            f"and to read the PDF again, or to choose another mode with {change} allow, ask or block.")


_PAGES_RE = re.compile(r"\A\s*(\d{1,5})\s*(?:-\s*(\d{1,5})\s*)?\Z")


def page_range(pages) -> tuple[int, int] | None | str:
    """The Read tool's `pages` ("3", "1-5") as (first, last); None for the whole file; a text when it is no range."""
    if pages in (None, ""):
        return None
    m = _PAGES_RE.match(str(pages))
    if not m:
        return f"the page range '{str(pages)[:20]}' is not one page or one range like 1-5"
    first, last = int(m.group(1)), int(m.group(2) or m.group(1))
    if first < 1 or last < first:
        return f"the page range '{str(pages)[:20]}' is not one page or one range like 1-5"
    return first, last


def _wait(thread, seconds: float) -> None:
    thread.join(seconds)


def _rss(pid: int):
    """The resident memory of a running process in bytes, or None when it cannot be read."""
    import sys
    if sys.platform == "darwin":
        try:
            import ctypes
            lib = ctypes.CDLL("/usr/lib/libproc.dylib")
            info = (ctypes.c_uint64 * 32)()
            # rusage_info_v0: a 16-byte uuid, then u64 fields; ri_resident_size is the 7th, ri_phys_footprint the 8th
            if lib.proc_pid_rusage(ctypes.c_int(pid), ctypes.c_int(0), ctypes.byref(info)) != 0:
                return None
            return max(info[8], info[9])
        except (OSError, AttributeError, ValueError):
            return None
    try:
        with open(f"/proc/{pid}/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


def _limit_memory(pid: int) -> None:
    """Linux: the kernel refuses the child more address space than MAX_AS_BYTES (set after the start: a preexec_fn
    is not safe beside the hook's watchdog thread; the watch of the resident size covers the first moment)."""
    try:
        import resource
        resource.prlimit(pid, resource.RLIMIT_AS, (MAX_AS_BYTES, MAX_AS_BYTES))
    except (ImportError, AttributeError, OSError, ValueError):
        pass


_RUNNING: set = set()


def kill_running() -> None:
    """End every pdftotext this hook started. The watchdog calls it before os._exit, which skips the finally of
    extract(): the child runs in its own session, so the client's kill of the hook does not reach it (review)."""
    for pid in list(_RUNNING):
        try:
            if os.name == "nt":
                os.kill(pid, 9)
            else:
                import signal
                os.killpg(pid, signal.SIGKILL)
        except OSError:
            pass


def _child_env() -> dict:
    """The environment of pdftotext without the variables that make the loader take other libraries."""
    return {k: v for k, v in os.environ.items() if not k.startswith(("DYLD_", "LD_"))}


def _stop(child) -> None:
    """End pdftotext and its process group, if it still runs."""
    if child.poll() is not None:
        return
    try:
        if os.name == "nt":
            child.kill()
        else:
            import signal
            os.killpg(child.pid, signal.SIGKILL)
    except OSError:
        child.kill()
    child.wait()


def _cut(text: str) -> str:
    """The text up to MAX_TEXT_CHARS, ended at a line and never inside a key block: a value cut in two is no longer
    the shape a rule finds (a PEM key needs its END line), and its first part would reach the model (review)."""
    cut = text[:MAX_TEXT_CHARS]
    # the text was cut by the character cap or by the byte cap of the reader: either way its last line is a part
    cut = cut[:cut.rfind("\n") + 1]
    begin = cut.rfind("-----BEGIN")
    if begin != -1 and "-----END" not in cut[begin:]:
        cut = cut[:begin]
    return cut


LOCKED = "the PDF is locked by a password"


def _cause(code: int, err: bytes) -> str:
    """The reason of a failed pdftotext, from its exit code and the last line of its messages (poppler 26.10.0,
    measured 2026-10-17): a user password (RC4, AES-128 or AES-256) ends the run with `Command Line Error: Incorrect
    password` and exit 1. Exit 3 is poppler's documented permission error; poppler 26.10.0 converts a PDF that forbids
    copying (measured), so this reason is for older versions. Any other failure is a damaged file or no PDF."""
    lines = [ln.strip() for ln in err.splitlines() if ln.strip()]
    if code == 1 and lines and lines[-1] == b"Command Line Error: Incorrect password":
        return LOCKED
    if code == 3:
        return "the PDF does not allow its text to be copied; pdftotext exit 3"
    return f"the file is damaged or no PDF; pdftotext exit {code}"


def _start(args: list, stdout, stderr):
    """pdftotext started in its own process group (a stop ends it and anything it started, so nobody holds a pipe
    open), without the loader variables, under the memory limit, and known to kill_running."""
    import subprocess
    child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                             env=_child_env(), **({} if os.name == "nt" else {"start_new_session": True}))
    _RUNNING.add(child.pid)
    _limit_memory(child.pid)
    return child


def _diagnose(tool: str, path: str) -> bytes:
    """The end of pdftotext's messages, for a run that failed: a second run without -q, of page 1 only, with the text
    to the null device. The conversion itself runs with -q: a PDF can make poppler print a warning per operator, and
    writing them took a 35 KB PDF from 0.8 s past the 6 s limit (Gate B). Bounded like the conversion; b"" when it
    cannot run or takes too long."""
    import subprocess
    import threading
    import time
    if not _no_other_writer(tool):
        return b""
    try:
        child = _start([tool, "-enc", "UTF-8", "-f", "1", "-l", "1", path, os.devnull], subprocess.DEVNULL,
                       subprocess.PIPE)
    except OSError:
        return b""
    err = bytearray()
    fd = child.stderr.fileno()

    def drain() -> None:
        # read all of it, so that a full pipe never blocks pdftotext; keep the end, where the message that ends the
        # run stands
        try:
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    return
                err.extend(chunk)
                del err[:-ERR_KEEP_BYTES]
        except (OSError, ValueError):
            return
    drainer = threading.Thread(target=drain, daemon=True)
    try:
        drainer.start()
        deadline = time.monotonic() + DIAGNOSE_SECONDS
        while drainer.is_alive() and time.monotonic() < deadline:
            _wait(drainer, POLL_SECONDS)
            used = _rss(child.pid) if child.poll() is None else 0
            if used is None or used > MAX_RSS_BYTES:
                return b""        # the memory limit of the conversion, without its message
        if drainer.is_alive():
            return b""
        try:
            child.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return b""
    finally:
        _stop(child)
        _RUNNING.discard(child.pid)
        drainer.join(0.5)
        if not drainer.is_alive():
            child.stderr.close()
    return bytes(err)


def extract(path: str, pages=None, cwd: str = "") -> tuple[str | None, str]:
    """(text, "") or (None, why). Every failure is a refusal: nothing of the PDF passes when the text is missing."""
    tool = pdftotext(cwd)
    if not tool:
        return None, "missing"
    rng = page_range(pages)
    if isinstance(rng, str):
        return None, rng
    try:
        size = os.path.getsize(path)
    except OSError:
        return None, "the file cannot be read"
    if size > MAX_PDF_BYTES:
        return None, f"the file is larger than {MAX_PDF_BYTES // (1024 * 1024)} MB"
    # once more right before the start: a change since the lookup is refused (the moment between this check and
    # the start remains: there is no portable way to start a checked file without its name)
    if not _no_other_writer(tool):
        return None, "pdftotext changed after it was checked"
    args = [tool, "-q", "-enc", "UTF-8"]
    if rng:
        args += ["-f", str(rng[0]), "-l", str(rng[1])]
    args += [path, "-"]
    import subprocess   # here, not at the top: this module loads on every PostToolUse
    import threading
    try:
        child = _start(args, subprocess.PIPE, subprocess.DEVNULL)
    except OSError as exc:
        return None, f"pdftotext did not start ({type(exc).__name__})"
    cap = MAX_TEXT_CHARS * 4          # UTF-8 bytes: at most 4 for one character
    buf = bytearray()

    def pump() -> None:
        # read in chunks up to the cap and no further: a huge text is never held in memory as a whole
        try:
            while len(buf) < cap:
                chunk = os.read(child.stdout.fileno(), min(65536, cap - len(buf)))
                if not chunk:
                    return
                buf.extend(chunk)
        except (OSError, ValueError):
            return
    reader = threading.Thread(target=pump, daemon=True)
    full = False
    import time
    try:
        reader.start()
        deadline = time.monotonic() + EXTRACT_SECONDS
        while reader.is_alive() and time.monotonic() < deadline:
            # a PDF can be built to make pdftotext take all memory: its resident size is read between the waits,
            # and a child the hook cannot measure is stopped too (fail closed)
            _wait(reader, POLL_SECONDS)
            if child.poll() is None:
                rss = _rss(child.pid)
                if rss is None or rss > MAX_RSS_BYTES:
                    if child.poll() is None:
                        return None, (f"pdftotext needed more than {MAX_RSS_BYTES // (1024 * 1024)} MB of memory, so "
                                      "maisecrets stopped it; the PDF may be built to use up memory"
                                      if rss is not None else "maisecrets cannot watch the memory of pdftotext")
        if reader.is_alive():
            return None, f"pdftotext took longer than {EXTRACT_SECONDS:g} s"
        full = len(buf) >= cap
        if not full:
            try:
                child.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                return None, f"pdftotext took longer than {EXTRACT_SECONDS:g} s"
    finally:
        # any way out, also an exception that a watchdog could raise here: the child ends with the hook. The
        # exception goes on to the fail-closed answer, which withholds the file
        _stop(child)
        _RUNNING.discard(child.pid)
        reader.join(0.5)
        try:
            child.stdout.close()
        except OSError:
            pass
    if not full and child.returncode is not None and child.returncode < 0:
        # a signal: on Linux an allocation over RLIMIT_AS ends pdftotext this way
        return None, (f"pdftotext stopped with signal {-child.returncode}; the PDF may be built to use up memory, or "
                      "it is damaged")
    if not full and child.returncode != 0:
        return None, _cause(child.returncode, _diagnose(tool, path))
    text = bytes(buf).decode("utf-8", errors="replace")
    # pdftotext ends each page with a form feed; a text that reached the cap is no scan
    pages = max(text.count("\f"), 1)
    scanned = not full and len(re.sub(r"\s+", "", text)) < MIN_CHARS_PER_PAGE * pages
    text = text.replace("\f", "\n")
    if full or len(text) > MAX_TEXT_CHARS:
        cut = _cut(text)
        text = (cut + f"\n[maisecrets: the text stops here, after {MAX_TEXT_CHARS} characters. "
                "Read the PDF again with `pages` set to a smaller range to see the rest.]") if cut.strip() else (
            f"[maisecrets: the first {MAX_TEXT_CHARS} characters of this text are one line, or end inside a key "
            "block, so nothing of it reached you; a smaller page range does not help when one line is that long.]")
    if scanned:
        # fail closed: a page number or a header line of a scan is no reason to send anything of it
        text = (f"[maisecrets: this PDF looks scanned: pdftotext found less than {MIN_CHARS_PER_PAGE} characters "
                f"of text per page ({pages} page(s)). maisecrets cannot read text in images, so the AI gets nothing "
                "of it.]")
    return text, ""


# --------------------------------------------------------------- messages --
def refusal(kind: str, why: str, codex: bool) -> str:
    """The text for a read that a mode stops (pre-tool deny, or the text that stands in for the file)."""
    key = SETTING[kind]
    noun = "PDF" if kind == "pdf" else "image"
    change = f"maisecrets: set {key}" if codex else f"/maisecrets:settings {key}"
    others = "allow, ask or convert" if kind == "pdf" else "allow or ask"
    if why == "config":
        return (f"maisecrets: this {noun} was not read. The maisecrets config.json cannot be read, so {key} counts "
                "as block until the file is fixed (the session start named the problem). Do not try to read it "
                "another way. Tell the user to fix the file.")
    if why == "block":
        return (f"maisecrets: this {noun} was not read; the setting {key} is block. Do not try to read it another "
                f"way. If the user wants it read, they send {change} {others} as their own prompt.")
    if why == "ask-codex":
        return (f"maisecrets: this {noun} was not read; the setting {key} is ask, and Codex cannot ask the user "
                "here. Do not try to read it another way. Tell the user: to allow it, they send "
                f"{change} allow alone as their own prompt.")
    if why == "ask-unseen":
        return (f"maisecrets: this {noun} was not shown to you; the setting {key} is ask, and the call did not "
                "name the file in a way maisecrets could ask about first. Tell the user the file name and ask "
                "them to read it themselves, or to change the setting.")
    if why == "missing":
        return missing_tool_text(codex)
    if why == "too-large":
        return (f"maisecrets: this {noun} was not read; the setting {key} is ask, and the file is larger than "
                f"{BIND_MAX_BYTES // (1024 * 1024)} MB or cannot be read, so maisecrets cannot check that you would "
                f"get the very file the user allowed. Tell the user; they can choose allow with {change} allow.")
    if why == LOCKED:
        return (f"maisecrets: this PDF was not converted to text: {LOCKED}, so nothing of it reached you. Do not "
                "try to read it another way, and do not ask the user for the password. Tell the user; they can save "
                "a copy without the password and ask you to read that copy.")
    return (f"maisecrets: this PDF was not converted to text ({why}), so nothing of it reached you. Do not try "
            f"to read it another way. Tell the user; they can choose another mode with {change}.")


def ask_reason(kind: str) -> str:
    noun = "PDF" if kind == "pdf" else "image"
    return (f"maisecrets: the AI wants to read this {noun}. maisecrets cannot look inside it, so all of it goes to "
            f"the AI as it is, including any password or personal data (setting {SETTING[kind]} ask). "
            "Allow it only if the file holds nothing secret.")


# ------------------------------------------------------------ hook steps --
def _block_why(cfg: dict) -> str:
    return "config" if cfg.get("read_fallback") else "block"


def _deny(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def pre_read(payload: dict, cfg: dict, codex: bool) -> dict:
    """PreToolUse of Read: stop a PDF or an image before its bytes exist in the session (the transcript keeps
    them). {} lets the read run."""
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    path = tool_input.get("file_path")
    notebook = isinstance(path, str) and path.lower().endswith(".ipynb")
    kind = "image" if notebook else (kind_of_path(path) if isinstance(path, str) else None)
    if not kind:
        return {}
    # a file in a clean folder passes, bound to its bytes: the PostToolUse checks that the client read this file
    if in_clean_dir(path, str(payload.get("cwd") or ""), cfg, payload.get("session_id")) \
            and note_ask(payload, kind, path, "clean"):
        return {}
    how = mode(cfg, kind)
    if notebook:
        # a notebook with an image output: ask before it, as for an image (its text is scanned anyway)
        if how != "ask" or codex or not notebook_has_image(_full(payload, path)):
            return {}
        if not note_ask(payload, kind, path):
            return _deny(refusal(kind, "too-large", codex))
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                       "permissionDecisionReason": ask_reason("image")}}
    if how == "allow":
        return {}
    if how == "block":
        return _deny(refusal(kind, _block_why(cfg), codex))
    if how == "ask":
        if codex:
            return _deny(refusal(kind, "ask-codex", codex))
        if not note_ask(payload, kind, path):
            # no note, no pass: asking for a file that is then withheld helps no one
            return _deny(refusal(kind, "too-large", codex))
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                       "permissionDecisionReason": ask_reason(kind)}}
    # convert: refuse now what the PostToolUse would refuse anyway, before the client renders the file
    if not pdftotext(str(payload.get("cwd") or "")):
        return _deny(refusal(kind, "missing", codex))
    rng = page_range(tool_input.get("pages"))
    if isinstance(rng, str):
        return _deny(refusal(kind, rng, codex))
    return {}


def _withheld(tool: str, response: dict, path: str, text: str) -> dict:
    if tool == "Bash":
        # the client's own Bash shape with isImage off: the text goes to the model as text
        return {**response, "stdout": text, "stderr": "", "isImage": False}
    return text_result(path, text)


def post_read(payload: dict, cfg: dict, codex: bool) -> tuple | None:
    """PostToolUse: None for any result that is no image or PDF (the normal redaction runs on it); ("pass",) for
    one that goes to the model as it is, unscanned (a Bash image: its stdout only); ("hold",) for a notebook whose
    image data passes while its cells are scanned; ("replace", response, note) for one this hook replaces. The
    replacement is always a text Read (or a text Bash result); the normal redaction then runs on it."""
    tool = payload.get("tool_name") or ""
    response = payload.get("tool_response")
    kind = kind_of_response(tool, response)
    if not kind:
        return None
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    path = tool_input.get("file_path") if isinstance(tool_input.get("file_path"), str) else ""
    asked_path = path              # the name the PreToolUse saw, the key of its ask note
    if not path and isinstance(response.get("file"), dict):
        path = str(response["file"].get("filePath") or "")
    full = _full(payload, path)
    clean = (tool == "Read" and in_clean_dir(path, str(payload.get("cwd") or ""), cfg, payload.get("session_id"))
             and same_bytes(take_ask(payload, kind, asked_path, "clean"), response, full))
    how = mode(cfg, kind)
    if tool == "Read" and response.get("type") == "notebook":
        # its cells are text and are scanned as always, its image data is held out of the scan; ask (without the
        # PreToolUse ask: Codex, or a file that changed) and block take the images out
        asked = how == "ask" and not codex and same_bytes(take_ask(payload, "image", asked_path), response, full)
        if how == "allow" or clean or asked:
            return ("hold",)
        why = _block_why(cfg) if how != "ask" else ("ask-codex" if codex else "ask-unseen")
        n = _notebook_images(response)
        text = notebook_text(response, f"maisecrets: an image output was withheld (setting read_image {how})")
        return ("replace", text_result(path, text + "\n\n[" + refusal(kind, why, codex) + "]"),
                f"maisecrets withheld {n} image(s) of this notebook from the AI (read_image {how}).")
    if clean:
        return ("pass",)
    key = SETTING[kind]
    noun = "PDF" if kind == "pdf" else "image"
    if how == "allow":
        return ("pass",)
    if how == "ask":
        if tool == "Read" and not codex and same_bytes(take_ask(payload, kind, asked_path), response, full):
            return ("pass",)          # the PreToolUse of this call asked, and the person said yes
        why = "ask-codex" if codex else "ask-unseen"
        return ("replace", _withheld(tool, response, path, refusal(kind, why, codex)),
                f"maisecrets withheld this {noun} from the AI ({key} ask).")
    if how == "convert" and tool == "Read":
        full = path if os.path.isabs(path) else os.path.join(str(payload.get("cwd") or ""), path)
        text, why = extract(full, tool_input.get("pages"), str(payload.get("cwd") or ""))
        if text is None:
            return ("replace", _withheld(tool, response, path, refusal(kind, why, codex)),
                    f"maisecrets withheld this PDF from the AI: it could not be converted to text ({why}).")
        return ("replace", text_result(path, text),
                "maisecrets sent this PDF to the AI as text only, with secrets and personal data masked "
                "(read_pdf convert).")
    return ("replace", _withheld(tool, response, path, refusal(kind, _block_why(cfg), codex)),
            f"maisecrets withheld this {noun} from the AI ({key} {how}).")


def hint(payload: dict, cfg: dict, codex: bool) -> str | None:
    """The one-time hint for read_pdf or read_image: the first image or PDF that reaches the model while the person
    has not decided. Not in a subagent: it has no conversation with the person."""
    if payload.get("agent_id"):
        return None
    kind = kind_of_response(payload.get("tool_name") or "", payload.get("tool_response"))
    if not kind or mode(cfg, kind) != "allow":
        return None
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    path = tool_input.get("file_path")
    if isinstance(path, str) and in_clean_dir(path, str(payload.get("cwd") or ""), cfg, payload.get("session_id")):
        return None
    from . import settings
    key = SETTING[kind]
    if not settings.hint_due(key, cfg) or not settings.claim_hint(key):
        return None
    return settings.HINTS[key]["codex" if codex else "claude"]


def as_text(response) -> str:
    """Codex has no updatedToolOutput: its block reason is the text the model reads."""
    if isinstance(response, dict) and isinstance(response.get("file"), dict):
        return str(response["file"].get("content", ""))
    if isinstance(response, dict) and "stdout" in response:
        return str(response.get("stdout", ""))
    return response if isinstance(response, str) else ""
