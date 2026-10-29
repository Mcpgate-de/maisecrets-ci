"""Local incident records: maisecrets' own internal failures, as closed codes, on this computer only.

Nothing here sends, opens a browser or runs a program (docs/DIAGNOSTICS.md, D1). Every field of a record is a
value from a closed list or a bounded number (D2): no exception text, no path, no prompt, no session id. A hook
queues codes while it works and writes them after its answer (D4); the CLI only reads.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
from pathlib import Path

# the internal hook event names (hooks.WATCHDOG_SECONDS) that a per-event code can carry
HOOK_EVENTS = ("user-prompt", "pre-tool", "post-tool", "post-tool-failure")

CODES = frozenset({
    "store.file-read", "store.keychain-add", "store.keychain-readback", "store.openssl", "store.locker-add",
    "store.index-read", "store.index-shape", "store.lock",
    "store.timeout-keychain", "store.timeout-openssl", "store.timeout-locker",
    "store.decrypt", "store.mark-weak", "store.expire",
    "config.policy-invalid", "config.user-ignored",
    "hook.run-dir", "hook.sealed-dir", "hook.payload", "hook.session-start",
    "destinations.pend", "destinations.commit", "destinations.protect",
    "scrub.start", "scrub.write", "prompt.pending", "prompt.clipboard", "prompt.tip", "prompt.check-store",
    "launcher.no-python", "launcher.import", "guard.fired",
} | {f"hook.{e}.{k}" for e in HOOK_EVENTS for k in ("unexpected", "watchdog")})

# run.cmd's folder under %LOCALAPPDATA%: its start record (last-start.txt) and its marker
LAUNCHER_DIR = "maisecrets-launcher"
# the codes a marker can carry: written by a place that cannot write the record (a launcher, the guard, a child,
# the watchdog in its last 0.3 s)
MARKER_CODES = frozenset({"launcher.no-python", "launcher.import", "guard.fired", "scrub.write", "hook.payload",
                          "hook.session-start"} | {f"hook.{e}.watchdog" for e in HOOK_EVENTS})

CAUSES = ("permission", "timeout", "lock", "parse", "io", "missing", "rc", "shape", "other")
NUMBER_RANGES = {"errno": (0, 4095), "winerror": (0, 65535), "exit": (-255, 255)}
CLASSES = ("best-effort", "fail-closed")
EVENTS = ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionStart", "launcher", "guard")
TOOL_CLASSES = ("Bash", "PowerShell", "MCP", "File", "Other", "-")
CLIENTS = ("claude", "codex", "-")
MAX_GROUPS = 50
MAX_DAYS = 7
WINDOW_DAYS = 30
MAX_COUNT = 9999
MAX_BYTES = 64 * 1024
URL_LIMIT = 4000
_VERSION_RE = re.compile(r"\A(?:0|[1-9]\d{0,2})\.(?:0|[1-9]\d{0,2})\.(?:0|[1-9]\d{0,2})\Z")
_DAY_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")
_SELECTOR_RE = re.compile(r"\A([a-z0-9.-]{1,48})/([a-z]{1,12})\Z")
MARKER_PREFIX = "incident-marker."
# a dot name, as the other locks of the home (.lock, .destinations.lock): a lock stays with its files
LOCK_NAME = ".incidents.lock"
_CLAIMED_RE = re.compile(r"\A" + re.escape(MARKER_PREFIX) + r"([a-z0-9.-]{1,48})\.claimed-\d{1,10}-\d{1,20}\Z")
# the command as Claude Code writes it before it expands it: a leading space or another spelling is not expanded
# and reaches the model as plain text (measured, Claude Code 2.1.295)
_COMMAND_RE = re.compile(r"\A/maisecrets:report(?=\s|\Z)")


def _home() -> Path:
    """The store's own folder. An empty variable means the default, as in run.sh and guard.py."""
    return Path(os.environ.get("MAISECRETS_HOME") or Path.home() / ".maisecrets")


def record_path() -> Path:
    return _home() / "incidents.json"


def _today() -> str:
    return time.strftime("%Y-%m-%d")


def _window(today: str) -> tuple[str, str]:
    t = time.mktime(time.strptime(today, "%Y-%m-%d"))
    return time.strftime("%Y-%m-%d", time.localtime(t - WINDOW_DAYS * 86400)), today


def _is_int(x) -> bool:
    return type(x) is int          # noqa: E721 - a bool is an int to isinstance, and it must not count


def _valid_day(d, lo: str, hi: str) -> bool:
    if not isinstance(d, str) or not _DAY_RE.match(d) or not (lo <= d <= hi):
        return False
    try:
        return time.strftime("%Y-%m-%d", time.strptime(d, "%Y-%m-%d")) == d
    except ValueError:
        return False


def valid_group(g, today: str | None = None) -> dict | None:
    """The group with only its closed fields, or None when one field is outside its form (the whole group goes)."""
    if not isinstance(g, dict):
        return None
    lo, hi = _window(today or _today())
    out = {}
    if g.get("code") not in CODES or g.get("cause") not in CAUSES:
        return None
    out["code"], out["cause"] = g["code"], g["cause"]
    kind, number = g.get("number_kind"), g.get("number")
    if kind is not None or number is not None:
        if kind not in NUMBER_RANGES or not _is_int(number):
            return None
        low, high = NUMBER_RANGES[kind]
        if not low <= number <= high:
            return None
        out["number_kind"], out["number"] = kind, number
    for field, allowed in (("class", CLASSES), ("event", EVENTS), ("tool_class", TOOL_CLASSES),
                           ("client", CLIENTS)):
        if g.get(field) not in allowed:
            return None
        out[field] = g[field]
    days = g.get("days")
    if not isinstance(days, list) or not 1 <= len(days) <= MAX_DAYS:
        return None
    if not all(_valid_day(d, lo, hi) for d in days) or len(set(days)) != len(days):
        return None
    out["days"] = sorted(days)
    count = g.get("count")
    if not _is_int(count) or not 1 <= count <= MAX_COUNT:
        return None
    out["count"] = count
    version = g.get("plugin_version")
    if not (version == "unknown" or (isinstance(version, str) and _VERSION_RE.match(version))):
        return None
    out["plugin_version"] = version
    return out


def seen(count: int) -> str:
    return "10+" if count >= 10 else "3+" if count >= 3 else str(count)


def _key(g: dict) -> str:
    return f"{g['code']}/{g['cause']}"


def _read_bounded(path: Path) -> bytes | None:
    """The file's bytes, or None when it is no regular file, larger than MAX_BYTES or unreadable. Never follows a
    symlink and never waits on a FIFO."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            return None
        data = os.read(fd, MAX_BYTES + 1)
        return None if len(data) > MAX_BYTES else data
    except OSError:
        return None
    finally:
        os.close(fd)


def load(path: Path | None = None, today: str | None = None) -> tuple[dict, bool]:
    """(groups by key, damaged). A missing file is empty and not damaged; a file that does not parse, is not a
    regular file or is too large is damaged. Groups outside the schema are dropped one by one."""
    path = path or record_path()
    if not os.path.lexists(path):
        return {}, False
    data = _read_bounded(path)          # no link followed, no FIFO waited on, a regular file only
    if data is None:
        return {}, True
    try:
        obj = json.loads(data.decode("utf-8"), parse_constant=_no_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return {}, True
    if not isinstance(obj, dict) or obj.get("version") != 1 or not isinstance(obj.get("groups"), dict):
        return {}, True
    groups = {}
    for g in obj["groups"].values():
        ok = valid_group(g, today)
        if ok:
            groups[_key(ok)] = ok
    return groups, False


def _no_constant(name: str):
    raise ValueError(f"no {name}")       # NaN and Infinity are no JSON numbers of this schema


def add(groups: dict, item: dict, today: str | None = None) -> dict:
    """The groups with one more occurrence of item (code, cause, class, event, tool_class, client and an optional
    number). An item outside the schema changes nothing. The oldest group goes when the 51st arrives."""
    today = today or _today()
    from .events import plugin_version
    version = plugin_version()
    base = {"code": item.get("code"), "cause": item.get("cause"), "class": item.get("class"),
            "event": item.get("event"), "tool_class": item.get("tool_class", "-"), "client": item.get("client", "-"),
            "days": [today], "count": 1, "plugin_version": version if _VERSION_RE.match(str(version)) else "unknown"}
    if item.get("number_kind") is not None:
        base["number_kind"], base["number"] = item.get("number_kind"), item.get("number")
    new = valid_group(base, today)
    if not new:
        return groups
    key = _key(new)
    old = groups.get(key)
    if old:
        days = sorted(set(old["days"]) | {today})[-MAX_DAYS:]
        new = dict(new, days=days, count=min(old["count"] + 1, MAX_COUNT))
    groups = dict(groups)
    groups[key] = new
    while len(groups) > MAX_GROUPS:
        del groups[min(groups, key=lambda k: groups[k]["days"][-1])]
    return groups


def dumps(groups: dict) -> str:
    return json.dumps({"version": 1, "groups": groups}, indent=1, sort_keys=True)


# --- the queue of a hook process and its write after the answer (D4) ---

_QUEUE: list[dict] = []
# the hook that runs in this process (hooks.main sets it): a swallowed failure is recorded only in a hook, never in
# a CLI run, which prints its own error and never writes the record
_CONTEXT: dict = {}


def set_context(event: str | None, tool_class: str = "-", client: str = "-") -> None:
    _CONTEXT.clear()
    if event:
        _CONTEXT.update(event=event, tool_class=tool_class, client=client)


def note(code: str, exc: BaseException | None = None, cause: str = "other") -> None:
    """A best-effort failure that the code swallows: queued in a hook process, ignored elsewhere. Never raises."""
    try:
        if not _CONTEXT:
            return
        kind = number = None
        if exc is not None:
            cause, kind, number = cause_of(exc)
        queue(code, cause, "best-effort", _CONTEXT["event"], _CONTEXT["tool_class"], _CONTEXT["client"], kind, number)
    except Exception:  # noqa: BLE001 - recording never changes an answer
        pass


def queue(code: str, cause: str, cls: str, event: str, tool_class: str = "-", client: str = "-",
          number_kind: str | None = None, number: int | None = None) -> None:
    """Remember one failure of this hook process. Never raises; the write comes after the answer."""
    try:
        item = {"code": code, "cause": cause, "class": cls, "event": event, "tool_class": tool_class,
                "client": client}
        low, high = NUMBER_RANGES.get(number_kind, (0, -1))
        if _is_int(number) and low <= number <= high:     # a number out of its range goes, the occurrence stays
            item.update(number_kind=number_kind, number=number)
        _QUEUE.append(item)
    except Exception:  # noqa: BLE001 - recording never changes an answer
        pass


def discard() -> None:
    _QUEUE.clear()


def code_of(exc: BaseException, event: str) -> tuple[str, str, str | None, int | None]:
    """(code, cause, number kind, number) for an exception that ended a hook: the code the raise site gave it
    (vault.CodedError, LockTimeout), else the hook's own unexpected code. The message is never read."""
    code = getattr(exc, "incident_code", None)
    if code in CODES:
        cause = getattr(exc, "incident_cause", "other")
        rc = getattr(exc, "incident_rc", None)
        return code, cause if cause in CAUSES else "other", ("exit" if _is_int(rc) else None), rc
    cause, kind, number = cause_of(exc)
    return f"hook.{event}.unexpected", cause, kind, number


def cause_of(exc: BaseException) -> tuple[str, str | None, int | None]:
    """A closed cause and number for an exception; the message is never read."""
    import errno as _errno
    import subprocess
    if isinstance(exc, subprocess.TimeoutExpired) or isinstance(exc, TimeoutError):
        return "timeout", None, None
    if isinstance(exc, PermissionError):
        return "permission", "errno", exc.errno if _is_int(exc.errno) else None
    if isinstance(exc, FileNotFoundError):
        return "missing", "errno", _errno.ENOENT
    if isinstance(exc, OSError):
        win = getattr(exc, "winerror", None)
        if _is_int(win):
            return "io", "winerror", win
        return "io", ("errno" if _is_int(exc.errno) else None), (exc.errno if _is_int(exc.errno) else None)
    if isinstance(exc, (ValueError, UnicodeError)):
        return "parse", None, None
    return "other", None, None


class _OneTry:
    """The record's own lock file, taken with one try: a busy lock skips the write (D4)."""

    def __init__(self, path: Path):
        self.path, self.fd = path, None

    def __enter__(self) -> bool:
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError:
            return False
        try:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except ImportError:
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            os.close(fd)
            return False
        self.fd = fd
        return True

    def __exit__(self, *exc) -> None:
        if self.fd is None:
            return
        try:
            try:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except ImportError:
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        finally:
            os.close(self.fd)
            self.fd = None


def flush(today: str | None = None) -> None:
    """After the answer: fold the markers and write the queue, under one try of the record's lock. Never raises,
    and a failure here is never recorded."""
    items, _QUEUE[:] = list(_QUEUE), []
    try:
        home = _home()
        if not home.is_dir() or home.is_symlink():
            return
        if not items and not _takeable_markers(home) and not _launcher_marker_is_there():
            return                                   # nothing to write: no file is touched
        with _OneTry(home / LOCK_NAME) as locked:
            if not locked:
                return
            today = today or _today()
            path = record_path()
            groups, damaged = load(path, today)
            if damaged:
                _set_aside(path)
            taken = _claim_markers(home) + _claim_launcher_marker()
            for code, day in taken:
                groups = add(groups, _marker_item(code), day if _valid_day(day, *_window(today)) else today)
            for item in items:
                groups = add(groups, item, today)
            if items or taken or damaged:
                from .vault import atomic_write
                atomic_write(path, dumps(groups))
    except Exception:  # noqa: BLE001 - recording never changes an answer
        pass


def _set_aside(path: Path) -> None:
    """Keep one aside copy of a damaged record; a symlink is removed, never followed and never kept."""
    try:
        if os.path.islink(path):
            os.unlink(path)
            return
        os.replace(path, path.with_name(path.name + ".corrupt"))
    except OSError:
        pass


def _marker_item(code: str) -> dict:
    event = "launcher" if code.startswith("launcher.") else "guard" if code == "guard.fired" else (
        "SessionStart" if code == "hook.session-start" else _EVENT_OF.get(code.split(".")[1], "UserPromptSubmit"))
    cls = "best-effort" if code in ("scrub.write", "hook.session-start") else "fail-closed"
    cause = {"launcher.no-python": "missing", "launcher.import": "missing", "guard.fired": "missing",
             "hook.payload": "shape"}.get(code, "timeout" if code.endswith(".watchdog") else "io")
    return {"code": code, "cause": cause, "class": cls, "event": event}


_EVENT_OF = {"user-prompt": "UserPromptSubmit", "pre-tool": "PreToolUse", "post-tool": "PostToolUse",
             "post-tool-failure": "PostToolUseFailure"}


# --- markers: flat empty directories in the home, one mkdir each (docs/DIAGNOSTICS.md section 3) ---

def write_marker(code: str) -> None:
    """For a place that cannot write the record. Only when the home exists and is no symlink; one mkdir, which
    fails on any object at the name and follows nothing. Never raises."""
    try:
        if code not in MARKER_CODES:
            return
        home = _home()
        if not home.is_dir() or home.is_symlink():
            return
        os.mkdir(home / (MARKER_PREFIX + code), 0o700)
    except Exception:  # noqa: BLE001
        pass


def write_marker_bounded(code: str, seconds: float = 0.3) -> None:
    """write_marker in a daemon thread, waited for at most `seconds`: a slow disk cannot hold the hook. Called after
    the answer, right before the process ends: a thread still alive then ends the process at once, as a thread
    alive at the shutdown of the interpreter can crash it (signal 11 on a macOS runner, 2026-09-27). Never raises."""
    try:
        import threading
        t = threading.Thread(target=write_marker, args=(code,), daemon=True)
        t.start()
        t.join(seconds)
        if t.is_alive():
            sys.stdout.flush()
            os._exit(0)
    except Exception:  # noqa: BLE001
        pass


def _launcher_marker() -> Path | None:
    """The marker run.cmd leaves in %LOCALAPPDATA%\\maisecrets-launcher: never in the home, as a detached child on
    Windows would inherit the hook's pipe handles (codex code review, round 3), and never in the plugin folder, as
    Codex binds a hook's approval to the plugin's contents (openai/codex#54619). None where the variable is not set."""
    base = os.environ.get("LOCALAPPDATA")
    return Path(base) / LAUNCHER_DIR / (MARKER_PREFIX + "launcher.no-python") if base else None


def _launcher_marker_is_there() -> bool:
    p = _launcher_marker()
    try:
        return p is not None and stat.S_ISDIR(os.lstat(p).st_mode)
    except OSError:
        return False


def _claim_launcher_marker() -> list[tuple[str, str]]:
    """The launcher's marker, counted only when its rmdir succeeded (at most once)."""
    p = _launcher_marker()
    if p is None:
        return []
    try:
        st = os.lstat(p)
        if not stat.S_ISDIR(st.st_mode) or os.listdir(p):
            return []
        os.rmdir(p)
    except OSError:
        return []
    return [("launcher.no-python", time.strftime("%Y-%m-%d", time.localtime(st.st_mtime)))]


def _takeable_markers(home: Path) -> bool:
    """A marker the fold can take: a real directory under a marker code's name, or a claimed name left by a crash."""
    for name in _marker_names(home):
        code = name[len(MARKER_PREFIX):]
        try:
            if (code in MARKER_CODES or _CLAIMED_RE.match(name)) and stat.S_ISDIR(os.lstat(home / name).st_mode):
                return True
        except OSError:
            pass
    return False


def _marker_names(home: Path) -> list[str]:
    try:
        return [n for n in os.listdir(home) if n.startswith(MARKER_PREFIX)]
    except OSError:
        return []


def _claim_markers(home: Path) -> list[tuple[str, str]]:
    """(code, day) for each marker this call took: rename to a unique claimed name, rmdir it, and count it only
    when the rmdir succeeded (at most once). A claimed name left by a crash is removed when it is an empty real
    directory and not counted. Nothing else is touched."""
    taken = []
    for name in _marker_names(home):
        p = home / name
        claimed = _CLAIMED_RE.match(name)
        if claimed:
            try:
                if stat.S_ISDIR(os.lstat(p).st_mode):
                    os.rmdir(p)
            except OSError:
                pass
            continue
        code = name[len(MARKER_PREFIX):]
        if code not in MARKER_CODES:
            continue
        try:
            st = os.lstat(p)
            if not stat.S_ISDIR(st.st_mode) or os.listdir(p):
                continue                             # a full folder is no marker: it stays where it is
            target = home / f"{name}.claimed-{os.getpid()}-{time.time_ns()}"
            os.rename(p, target)
            os.rmdir(target)
        except OSError:
            continue
        taken.append((code, time.strftime("%Y-%m-%d", time.localtime(st.st_mtime))))
    return taken


def unfolded_markers(home: Path | None = None) -> list[str]:
    """The codes of markers no hook folded yet, read only."""
    home = home or _home()
    out = ["launcher.no-python"] if _launcher_marker_is_there() else []
    for name in _marker_names(home):
        code = name[len(MARKER_PREFIX):]
        try:
            if code in MARKER_CODES and stat.S_ISDIR(os.lstat(home / name).st_mode):
                out.append(code)
        except OSError:
            pass
    return sorted(set(out))


def clear(home: Path | None = None) -> int:
    """Remove the record, its aside, its temp files and the markers, under the record's lock: rmdir only for markers,
    never recursive. The lock file stays: removed, a second hook would lock a new file while the first one holds the
    old one (codex code review, round 1). The number of objects removed, or -1 when the lock is busy."""
    home = home or _home()
    if not home.is_dir() or home.is_symlink():
        return 0
    with _OneTry(home / LOCK_NAME) as locked:
        if not locked:
            return -1
        return _clear_locked(home)


def _clear_locked(home: Path) -> int:
    n = len(_claim_launcher_marker())
    try:
        names = os.listdir(home)
    except OSError:
        return n
    for name in names:
        p = home / name
        try:
            st = os.lstat(p)
            if name.startswith(MARKER_PREFIX):
                if stat.S_ISDIR(st.st_mode):
                    os.rmdir(p)
                    n += 1
            elif name in ("incidents.json", "incidents.json.corrupt") or (
                    name.startswith("incidents.json.") and name.endswith(".tmp")):
                if not stat.S_ISDIR(st.st_mode):
                    os.unlink(p)
                    n += 1
        except OSError:
            pass
    return n


# --- the report form, shared by the CLI and the prompt hook ---

def words_of(text: str) -> list[str]:
    """The words as the CLI reads them (cli._stdin_words): shlex, else a plain split."""
    import shlex
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def form(words: list[str]) -> tuple[str, str | None] | None:
    """What a report command asks for, when it asks for an incident: ("show", None), ("show", "code/cause"),
    ("clear", None) or ("usage", None). None for every other report form."""
    words = [w for w in words if w.lower() != "--create"]
    if not words or words[0].lower() != "incident":
        return None
    rest = [w.lower() for w in words[1:]]
    if not rest:
        return "show", None
    if rest == ["clear"]:
        return "clear", None
    if len(rest) == 1:
        m = _SELECTOR_RE.match(rest[0])
        if m and m.group(1) in CODES and m.group(2) in CAUSES:
            return "show", rest[0]
    return "usage", None


def recognize(prompt, client: str) -> tuple[str, str | None] | None:
    """The incident form of a typed Claude Code prompt, or None. Pure: no config, no store, no file."""
    if client != "claude" or not isinstance(prompt, str):
        return None
    m = _COMMAND_RE.match(prompt)
    if not m:
        return None
    return form(words_of(prompt[m.end():]))


# --- the report ---

def _launcher() -> str:
    from .notices import launcher
    return launcher()


USAGE = ("maisecrets: /maisecrets:report incident shows the incident report; "
         "/maisecrets:report incident <code/cause> shows one group. "
         f"Clear the record in a terminal: {_launcher()} report incident clear")


def _platform() -> str:
    s = sys.platform
    return "Darwin" if s == "darwin" else "Windows" if s.startswith("win") else "Linux" if s.startswith(
        "linux") else "other"


def issue(g: dict) -> tuple[str, str]:
    """Title and body of one group, from closed values only."""
    title = f"[incident] {_key(g)}"
    lines = [
        "## Incident (recorded by maisecrets on this computer)",
        f"- code: `{g['code']}` · cause: `{g['cause']}`"
        + (f" · {g['number_kind']} {g['number']}" if "number_kind" in g else ""),
        f"- class: {g['class']} · event: {g['event']} · tool: {g['tool_class']} · client: {g['client']}",
        f"- seen: {seen(g['count'])} · on {len(g['days'])} day(s) in the last {WINDOW_DAYS}",
        f"- plugin version: {g['plugin_version']} · {_platform()} · "
        f"Python {sys.version_info.major}.{sys.version_info.minor}",
        "",
        "## Notes (optional)",
        "Do not paste a prompt, a command, a value, a path or a name here: the codes above are enough.",
        "",
        "_Prepared by `maisecrets report incident` from closed values only._",
    ]
    return title, "\n".join(lines)


def _link(title: str, body: str) -> str:
    try:
        from . import events
        url = events.link(title, body, "bug")
    except Exception:  # noqa: BLE001 - a broken config gives the report without a link, and no error text
        return "link: unavailable (configuration)"
    if not url:
        return "link: none (reporting is off in this configuration)"
    return "link: " + url if len(url) <= URL_LIMIT else "link: too long for one link; copy the text above"


def render(groups: dict, selector: str | None, markers: list[str] | None = None) -> str:
    """The report for a person: the list of groups, then the text and the link of one group."""
    from . import detect
    markers = markers or []
    shown, withheld = {}, 0
    for k, g in groups.items():
        title, body = issue(g)
        if detect.scan(title + "\n" + body):
            withheld += 1
            continue
        shown[k] = g
    head = ["maisecrets: your incident report (shown to you only; this is not an error).",
            "maisecrets sent nothing. Read the text, then open the link and decide in GitHub's form."]
    if not shown and not markers:
        return "\n".join(head + ["No internal failure is recorded on this computer."]
                         + ([f"{withheld} group(s) withheld."] if withheld else []))
    lines = list(head)
    if shown:
        lines += ["", "Recorded (code/cause · class · days · seen):"]
        for k, g in sorted(shown.items(), key=lambda kv: kv[1]["days"][-1], reverse=True):
            lines.append(f"- {k} · {g['class']} · {len(g['days'])} · {seen(g['count'])}")
    if markers:
        lines.append("Not yet counted: " + ", ".join(markers))
    if withheld:
        lines.append(f"{withheld} group(s) withheld.")
    if shown:
        if selector and selector in shown:
            g = shown[selector]
        else:
            g = max(shown.values(), key=lambda x: x["days"][-1])
        title, body = issue(g)
        lines += ["", f"Report for {_key(g)}:", "", title, "", body, "", _link(title, body)]
        others = [k for k in shown if k != _key(g)]
        if others:
            lines.append("Other groups: /maisecrets:report incident " + others[0]
                         + (f" (and {len(others) - 1} more)" if len(others) > 1 else ""))
    return "\n".join(lines)


def report_text(selector: str | None = None) -> str:
    """Load and render, read only. Never raises."""
    try:
        groups, damaged = load()
        text = render(groups, selector, unfolded_markers())
        return text + ("\nThe record was damaged; the next hook sets it aside." if damaged else "")
    except Exception:  # noqa: BLE001
        return "maisecrets: the incident report could not be read."

