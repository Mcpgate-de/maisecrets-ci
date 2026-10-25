"""Vault references (docs/PROTOCOL.md section 4): a token that an MCP server minted gets its value from that server.

An MCP server may replace a value in its tool result with a token of the server range, `⟦EMAIL_1⟧` or
`⟦EMAIL_1:display⟧` (no `c`; PROTOCOL.md section 1). When the model later writes that token into a Write,
Edit, MultiEdit, NotebookEdit or Bash call, the hook asks the server for the value and puts it in; the model
sees only the token. The server gives a value only to a key that this vault announced:

- K: 32 random bytes per MCP origin and client profile, kept in the store with no placeholder.
- The announcement: a static `Client-Vault: v=1, kid=:<base64 SHA-256(K)>:` header on the user-scope entry of
  that server in the client's config. The client sends it on its OAuth token request, where the server binds
  the kid to the person who logged in.
- The resolve: the endpoint that the server names in its protected resource metadata (RFC 9728), called with
  `Authorization: Bearer <K>`. All values, or one error for the whole batch.

The hook notes a token only from a result of an `mcp__*` tool whose server entry is user scope (`source: user`),
keyed by the origin of that entry's URL. A token that was never noted stays text. Standard library only.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

from .vault import _DEFAULT_HOME, HOME, LockTimeout, _lock_for, atomic_write

OPEN, CLOSE = "⟦", "⟧"
# the server range: no `c`, a counter from 1 (PROTOCOL.md section 1); the display part is for humans only
SERVER_REF_RE = re.compile(rf"{OPEN}(?P<type>[A-Z][A-Z0-9_]{{0,39}}?)_(?P<n>[1-9]\d{{0,8}})"
                           rf"(?::(?P<display>[^{OPEN}{CLOSE}]{{0,80}}))?{CLOSE}")
_SERVER_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{0,39}?_[1-9]\d{0,8}")
HEADER = "Client-Vault"
_HEADER_RE = re.compile(r"v=1, kid=:(?P<kid>[A-Za-z0-9+/]{43}=):")
# an ISO 8601 time as the server may send it; anything else is never shown (a server must not put text before the AI)
_TIME_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)")
MAX_REFS = 100
MAX_REQUEST_BYTES = 64 * 1024
MAX_ANSWER_BYTES = 1024 * 1024
METADATA_TTL = 3600                   # an answer of the metadata endpoint, either way, is kept this long
CONNECT_TIMEOUT = 2.0
SOCKET_TIMEOUT = 4.0
BUDGET = 5.5                          # both requests together, inside the hook's 7 s watchdog
MAX_NOTES_PER_ORIGIN = 5000
LOCK_STALE = 10.0                     # the client's own lock rule for its config file

DIR = HOME / "vault-refs"
NOTES = DIR / "notes.json"            # profile -> origin -> key -> {"type", "seen", "display", "sessions": by MCP URL}
SENT = DIR / "sent.json"              # profile -> origin -> key -> time: server keys the model sent in a call
RELEASED = DIR / "released.json"      # session -> [{"name", "t"}]: the values a server gave, kept in the store 1 h
NOTE_TTL = 24 * 3600                  # a token seen longer ago than this stays text
RELEASE_WINDOW = 3600                 # a value a server gave is hunted in tool output this long, as a stored one
MAX_SESSIONS_PER_NOTE = 20
KEYS = DIR / "keys.json"              # profile -> origin -> {"kid", "created", "entries": [[name, url]]}; never K
DISCOVERY_BUDGET = 4.0                # the one metadata request of the post-tool hook (watchdog 16 s, lock wait 5 s)
# the whole work of the post-tool hook here: every lock wait, the metadata request and the header write. Each lock
# waited up to its own 6 s before, one after the other: more than 16 s in the worst case, and then the watchdog
# withheld the output of the tool (L1, 2026-10-16). The rest of the hook (the redaction) keeps the other 8 s
NOTE_BUDGET = 8.0
ENDPOINTS = DIR / "endpoints.json"    # origin + path -> {"endpoint", "t"}


def _net_errors() -> tuple:
    """The errors of one request. http.client and ssl are imported only when a request runs: every hook call
    imports this module, and the two cost about 20 ms (hook time without a user-scope server stays as it was)."""
    import http.client
    import ssl
    return (OSError, http.client.HTTPException, ssl.SSLError)


class Refused(Exception):
    """No value: the reason names keys, the origin and the status, never a value."""


# ------------------------------------------------------------------ tokens --
def find(text: str) -> list[tuple[str, int, int]]:
    """(key, start, end) for every token of the server range in text."""
    return [(f"{m.group('type')}_{m.group('n')}", m.start(), m.end()) for m in SERVER_REF_RE.finditer(text)]


def is_server_key(key: str) -> bool:
    return bool(_SERVER_KEY_RE.fullmatch(key))


def _now_iso(t: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if t is None else t))


# ---------------------------------------------------------- client config --
_CLIENT = {"name": "claude"}


def use_client(client: str) -> None:
    """The client of this hook run: "codex" takes the client config of Codex (codex_vault.py), any other value the one
    of Claude Code. One hook process serves one payload, so this is set once at its start."""
    _CLIENT["name"] = "codex" if client == "codex" else "claude"


def is_codex() -> bool:
    return _CLIENT["name"] == "codex"


def global_file() -> Path:
    """`<CLAUDE_CONFIG_DIR or home>/.claude<suffix>.json`: the client's default global config (Claude Code 2.1.301,
    function `b`). The suffix is `-custom-oauth` when CLAUDE_CODE_CUSTOM_OAUTH_URL is set; a public build has no
    other."""
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    suffix = "-custom-oauth" if os.environ.get("CLAUDE_CODE_CUSTOM_OAUTH_URL") else ""
    return (Path(base) if base else Path.home()) / f".claude{suffix}.json"


def legacy_file() -> Path:
    """`<config home>/.config.json` (2.1.301, `legacyPath`). The config home is CLAUDE_CONFIG_DIR, also when it is
    empty (`??` in the client: then `.config.json` relative to the working folder), else ~/.claude; the client
    normalizes it to NFC, and so does this. hooks/guard.py _client_config has the same rule."""
    import unicodedata
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    home = base if base is not None else str(Path.home() / ".claude")
    return Path(unicodedata.normalize("NFC", home)) / ".config.json"


def claude_json() -> Path:
    """The config file the client reads and writes, with the user-scope MCP servers in it. The rule of Claude Code
    2.1.301 (function `v_`): `.config.json` in the config home when it is a regular file and it is not empty, or it
    is empty with a write bit set and the global file does not exist; else the global file. statSync and existsSync
    follow a link, as os.stat and os.path.exists do. The other file is then a stale copy: never read or written."""
    legacy, other = legacy_file(), global_file()
    try:
        st = os.stat(legacy)
        if stat.S_ISREG(st.st_mode) and (st.st_size > 0 or ((st.st_mode & 0o222) and not os.path.exists(other))):
            return legacy
    except (OSError, ValueError):
        pass
    return other


def config_files() -> list[str]:
    """Every file the client may read, the chosen one first: a Bash value that names one is refused (C27). The plain
    `.claude.json` stays in the list when a custom OAuth URL names another global file (Gate B review)."""
    chosen = claude_json()
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    plain = (Path(base) if base else Path.home()) / ".claude.json"
    out: list[str] = []
    for f in (chosen, legacy_file(), global_file(), plain):
        # a relative name (an empty CLAUDE_CONFIG_DIR) would refuse every value that holds `.config.json`
        if f.is_absolute() and str(f) not in out:
            out.append(str(f))
    return out


def profile() -> str:
    """The id of this client profile: the global file, also when the client uses `.config.json`. It stays the same
    when the client changes the file, so the key of an origin stays the same (with no custom OAuth URL, it is the id
    that 0.6.29 and 0.6.30 used)."""
    if is_codex():
        from . import codex_vault
        return codex_vault.profile()
    return str(global_file().resolve())


def origin_of(url: object) -> str | None:
    """`https://host[:port]` of an https URL with a host, in lower case and without the default port."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() != "https" or not parts.hostname or parts.username or parts.password:
        return None
    if port == 0:
        return None
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port and port != 443 else "")


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def user_servers(config: dict | None = None) -> dict[str, str]:
    """name -> URL of each user-scope server (top-level `mcpServers`) with an https URL. None with an empty
    CLAUDE_CONFIG_DIR: the client then reads `.config.json` in its own working folder, which a hook cannot know."""
    if is_codex():
        from . import codex_vault
        return codex_vault.user_servers(config)
    if config is None and os.environ.get("CLAUDE_CONFIG_DIR") == "":
        return {}
    data = config if config is not None else (_read_json(claude_json()) or {})
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return {}
    return {name: spec["url"] for name, spec in servers.items()
            if isinstance(spec, dict) and origin_of(spec.get("url"))}


# ------------------------------------------------------------------- the key --
@contextlib.contextmanager
def _bounded(lock, deadline: float | None):
    """`with lock`, with a wait that ends at the deadline (time.monotonic) of the step at the latest: the lock's own
    wait (6 s) is longer than the budget of a hook step. A lock this process holds already is entered at once.
    Raises LockTimeout as the lock does. Without a deadline, the lock as it is."""
    if deadline is None or lock.depth > 0:
        with lock:
            yield lock
        return
    lock.LOCK_DEADLINE = max(0.0, min(type(lock).LOCK_DEADLINE, deadline - time.monotonic()))
    try:
        lock.__enter__()
    finally:
        del lock.LOCK_DEADLINE               # the wait of every other step stays the lock's own
    try:
        yield lock
    finally:
        lock.__exit__(None, None, None)


def _own_lock(deadline: float | None = None):
    return _bounded(_lock_for(DIR / ".lock"), deadline)


def _store_lock(deadline: float | None):
    """The lock of the store (vault.py, `HOME/.lock`), taken first with the bounded wait: the store's own take of the
    same lock object is then a re-entry. Without a deadline nothing is taken here."""
    if deadline is None:
        return contextlib.nullcontext()
    return _bounded(_lock_for(HOME / ".lock"), deadline)


def _store_name(origin: str) -> str:
    return "_maisecrets_vref_" + hashlib.sha256(f"{profile()}\0{origin}".encode()).hexdigest()[:24]


def kid_of(k: bytes) -> str:
    return base64.b64encode(hashlib.sha256(k).digest()).decode()


def header_value(k: bytes) -> str:
    return f"v=1, kid=:{kid_of(k)}:"


def bearer_of(k: bytes) -> str:
    return base64.urlsafe_b64encode(k).decode().rstrip("=")


def _key(backend, origin: str, create: bool, deadline: float | None = None) -> bytes | None:
    with _store_lock(deadline):
        return _key_locked(backend, origin, create)


def _key_locked(backend, origin: str, create: bool) -> bytes | None:
    raw = backend.get(_store_name(origin))
    if raw:
        try:
            k = bytes.fromhex(raw.strip())
            if len(k) == 32:
                return k
        except ValueError:
            pass
    if not create:
        return None
    import secrets
    k = secrets.token_bytes(32)
    backend.put(_store_name(origin), k.hex(), label="maisecrets vault reference key",
                comment="maisecrets: the key that gets values back from a server; not a placeholder value.")
    return k


def _mine(path: Path) -> dict:
    """The part of this profile in a file of the vault-refs folder; {} when the file or its shape is damaged."""
    mine = (_read_json(path) or {}).get(profile())
    return mine if isinstance(mine, dict) else {}


def _known_keys() -> dict:
    return _mine(KEYS)


def _enabled() -> dict[str, list[tuple[str, str]]]:
    """origin -> the entries (name, URL) of this profile whose server sent a token and named a vault endpoint: only
    they get the header. A renamed entry, or one with another URL, is another entry (Gate A review of the trigger)."""
    out: dict[str, list[tuple[str, str]]] = {}
    for origin, rec in _known_keys().items():
        if isinstance(rec, dict) and isinstance(rec.get("entries"), list):
            out[origin] = [(e[0], e[1]) for e in rec["entries"]
                           if isinstance(e, list) and len(e) == 2 and all(isinstance(x, str) for x in e)]
    return out


def _is_enabled(name: str, url: str) -> bool:
    return (name, url) in _enabled().get(origin_of(url) or "", [])


def _remember_key(origin: str, kid: str, entry: tuple[str, str] | None = None, deadline: float | None = None) -> None:
    with _own_lock(deadline):
        data = _read_json(KEYS) or {}
        mine = data.setdefault(profile(), {})
        rec = mine.get(origin)
        changed = False
        if not isinstance(rec, dict) or rec.get("kid") != kid:
            rec = mine[origin] = {"kid": kid, "created": _now_iso(), "entries": []}
            changed = True
        if not isinstance(rec.get("entries"), list):
            rec["entries"], changed = [], True
        if entry and list(entry) not in rec["entries"]:
            rec["entries"].append(list(entry))
            changed = True
        if changed:
            atomic_write(KEYS, json.dumps(data, indent=1))


# ------------------------------------------------------ the header write --
class _ConfigLock:
    """The client's own lock on its config: a `<file>.lock` folder. A lock younger than 10 s is waited for; an older
    one is stale and taken over."""

    def __init__(self, path: Path, wait: float = 5.0) -> None:
        self.dir = path.with_name(path.name + ".lock")
        self.wait = wait

    def __enter__(self):
        deadline = time.time() + self.wait
        while True:
            try:
                os.mkdir(self.dir, 0o700)
                self.ino = os.stat(self.dir).st_ino
                return self
            except FileExistsError:
                try:
                    age = time.time() - os.stat(self.dir).st_mtime
                except OSError:
                    continue                    # it went away: try again
                if age > LOCK_STALE:
                    try:
                        os.rmdir(self.dir)
                    except OSError:
                        pass
                    continue
                if time.time() > deadline:
                    raise TimeoutError("the client holds its config lock")
                time.sleep(0.05)

    def __exit__(self, *exc) -> None:
        try:
            if os.stat(self.dir).st_ino == self.ino:     # another process took it over as stale: it is theirs
                os.rmdir(self.dir)
        except OSError:
            pass


def _write_config(path: Path, data: dict) -> None:
    """A temporary file in the same folder, renamed over the original; the mode of the original stays."""
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        mode = 0o600
    tmp = path.with_name(f"{path.name}.maisecrets.{os.getpid()}.tmp")
    try:
        os.unlink(tmp)                          # left by a process that died; never written through
    except OSError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _backup(path: Path, backup: Path) -> None:
    """A copy of the config with mode 0600 from its first byte; a link at the backup path is removed, not followed."""
    try:
        os.unlink(backup)
    except FileNotFoundError:
        pass
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(path.read_bytes())


def _header_key(headers: dict) -> str | None:
    return next((h for h in headers if isinstance(h, str) and h.lower() == HEADER.lower()), None)


def _kid_in(value: object) -> str | None:
    m = _HEADER_RE.fullmatch(value) if isinstance(value, str) else None
    return m.group("kid") if m else None


def _may_change_config() -> bool:
    """A test home never changes the client config of the person; a test sets CLAUDE_CONFIG_DIR to its own folder.
    Under the test suite (tests/_isolate.py) the config must also lie in the temp folder of the run: an inherited
    CLAUDE_CONFIG_DIR of a real profile is refused (Gate A review of the trigger). Both the file and its target must
    lie there: the lock and the backup go beside the file. An empty CLAUDE_CONFIG_DIR is refused: the client then
    takes `.config.json` relative to its working directory, which a hook cannot know."""
    if is_codex():
        from . import codex_vault
        return codex_vault.may_change_config()
    if os.environ.get("CLAUDE_CONFIG_DIR") == "":
        return False
    if os.environ.get("MAISECRETS_TEST_HOME_OWNED"):
        import tempfile
        tmp = os.path.realpath(tempfile.gettempdir())
        chosen = claude_json()
        return all(p.startswith(tmp + os.sep) for p in (os.path.realpath(str(chosen)),
                                                         os.path.realpath(str(chosen.parent))))
    return HOME == _DEFAULT_HOME or bool(os.environ.get("CLAUDE_CONFIG_DIR"))


def ensure_headers(cfg: dict, backend) -> str | None:
    """At session start (Claude Code). Nothing new: a header goes on an entry only after its server sent a token and
    named a vault endpoint (enable). Here the header of such an entry is put back when the client lost it, and a header
    of ours (a kid this profile made) goes from an entry that no longer qualifies (another URL, plain http, a removed
    server) and from every entry with `client_header` false; a header someone else wrote stays there. No network
    request. Returns one line for the session-start message, or None."""
    if not _may_change_config():
        return None
    # a key the server no longer accepts (quarantined or revoked) is never used again: a new one, and its header below
    renewed: list[str] = []
    if cfg.get("client_header", True) is not False:
        try:
            renewed = rotate_lost(backend, time.monotonic() + BUDGET)
        except Exception:  # noqa: BLE001 - a store backend has its own errors; the header repair below still runs
            renewed = []                        # tried again at the next start; the header repair below still runs
    added, removed, path, backup = _apply_config(cfg, backend)
    parts = []
    if renewed:
        hosts = ", ".join(urlsplit(o).hostname or o for o in renewed)
        # Codex keeps its helper line, so no notice follows there: the step goes here
        step = f". {reconnect_step('')}".rstrip(".") if is_codex() else ""
        parts.append(f"maisecrets: {hosts} no longer accepted the key of this computer (quarantined or revoked), so "
                     f"maisecrets made a new key{step}")
    told = set(renewed)
    if added:
        # a header that a busy client lock kept from the post-tool hook: its notice comes now (Gate B review)
        parts.extend(_notice(n).rstrip(".") for n in added)
        told |= {o for o, entries in _enabled().items() if any(n in added for n, _u in entries)}
    for origin in told:
        _mark_told(origin, "header")            # the line above tells it: no session-start hint for it
    if removed:
        parts.append(f"maisecrets removed its {HEADER} {'helper' if is_codex() else 'header'} from {len(removed)} "
                     f"MCP server(s) in {path}")
    if not parts:
        return None
    return "; ".join(parts) + (f" (a backup of the config is kept until the next start: {backup.name}. To turn "
                               "this off: /maisecrets:settings client_header off.)")


def _apply_config(cfg: dict, backend, lock_wait: float = 5.0,
                  deadline: float | None = None) -> tuple[list[str], list[str], Path, Path]:
    """The headers of the client config as they should be: ours on each enabled URL, none of ours elsewhere. Only
    `mcpServers.<name>.headers` changes, under the client's own lock, with a backup first; a file that is not valid JSON
    is not touched. Returns (added, removed, path, backup)."""
    if is_codex():
        return _apply_codex_config(cfg, backend, lock_wait, deadline)
    # the path as the client names it: its lock is `<that path>.lock` (proper-lockfile with an explicit lockfilePath,
    # 2.1.301), also when the file is a link; the backup lies beside it, not beside a link's target (a dotfiles folder)
    path = claude_json()
    backup = path.with_name(path.name + ".maisecrets-backup")
    first = _read_json(path) if path.is_file() else None
    if first is None:
        return [], [], path, backup
    keys: dict[str, bytes] = {}
    urls = _enabled() if cfg.get("client_header", True) is not False else {}
    for origin in urls:
        k = _key(backend, origin, create=False, deadline=deadline)
        if k is not None:
            keys[origin] = k
    ours = {v.get("kid") for v in _known_keys().values() if isinstance(v, dict)} | {kid_of(k) for k in keys.values()}
    if _apply_headers(copy.deepcopy(first), keys, urls, ours) == ([], []):
        # nothing to change: no lock, and the backup of the last change goes (it holds every server's credentials).
        # A backup that 0.6.29 or 0.6.30 left beside a link's target or beside a global file the client does not use
        # stays: maisecrets cannot prove it wrote a file of that name there (Gate A review, round 2)
        try:
            backup.unlink()
        except OSError:
            pass
        return [], [], path, backup
    if deadline is not None:
        lock_wait = max(0.0, min(lock_wait, deadline - time.monotonic()))
    with _ConfigLock(path, wait=lock_wait):
        # the client may have changed its file between the choice and the lock (a new .config.json): then nothing is
        # written now, and the next start writes the file the client uses then (Gate A and Gate B review)
        if claude_json() != path or not path.is_file():
            return [], [], path, backup
        data = _read_json(path)
        if data is None:
            return [], [], path, backup
        added, removed = _apply_headers(data, keys, urls, ours)
        if added or removed:
            _backup(path, backup)
            _write_config(path.resolve(), data)     # a link stays a link: the rename goes over its target
    return added, removed, path, backup


def _apply_codex_config(cfg: dict, backend, lock_wait: float,
                        deadline: float | None = None) -> tuple[list[str], list[str], Path, Path]:
    """Codex: one `http_headers_helper` line on each enabled user entry, and the helper's state file
    (codex_vault.py: a static header there would go to any URL a repository names for the entry)."""
    from . import codex_vault
    wanted: dict[str, tuple[str, str]] = {}
    if cfg.get("client_header", True) is not False:
        for origin, entries in _enabled().items():
            k = _key(backend, origin, create=False, deadline=deadline)
            if k is None:
                continue
            for name, url in entries:
                wanted[name] = (url, header_value(k))
        if wanted:
            codex_vault.place_helper()
    if deadline is not None:
        lock_wait = max(0.0, min(lock_wait, deadline - time.monotonic()))   # the post-tool budget (L1)
    return codex_vault.apply_config(wanted, lock_wait=lock_wait)


def enable(cfg: dict, backend, name: str, url: str, deadline: float | None = None) -> str | None:
    """The server of this user-scope entry sent a token and named a vault endpoint: a key for its origin, and the
    header on this entry only. Returns the notice for the person once, when the header was added, or None."""
    if not _may_change_config() or cfg.get("client_header", True) is False:
        return None
    origin = origin_of(url)
    if not origin:
        return None
    # one step under maisecrets' own lock: two calls at once made two keys, and the header could name the one the store
    # lost (Fable review, round 3)
    with _own_lock(deadline):
        k = _key(backend, origin, create=True, deadline=deadline)
        _remember_key(origin, kid_of(k), (name, url))
    try:
        # a short wait inside the post-tool hook: a busy client lock leaves the write to the next session start
        added, _removed, _path, _backup_path = _apply_config(cfg, backend, lock_wait=1.0, deadline=deadline)
    except TimeoutError:
        return None
    if name not in added:
        return None
    try:
        _mark_told(origin, "header", deadline)      # the notice tells it: no session-start hint for it again
    except (LockTimeout, OSError):
        pass
    return _notice(name)


def _notice(name: str) -> str:
    if is_codex():
        from . import codex_vault
        return codex_vault.notice(name)
    # measured on Claude Code 2.1.302: `/mcp reconnect <name>` reads the entry again, its headers included, and every
    # later request carries the new header; no restart is needed
    return (f"maisecrets: the MCP server {_say_name(name)} supports {HEADER}, and maisecrets wrote its header into "
            f"the client config. {reconnect_step(name)} Then maisecrets puts this server's values into your local "
            "files and commands; the AI still sees only placeholders. To turn it off: /maisecrets:settings "
            "client_header off. More: README, section \"Vault references\".")


def reconnect_step(name: str) -> str:
    """The one step after a header write: what makes the client send the new header."""
    if is_codex():
        return "Start Codex again (a new codex run sends it)."
    return f"Type /mcp reconnect {_say_name(name)} (or start Claude Code again)."


_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def _say_name(name: object, fallback: str = "<server name>") -> str:
    """A server name as the texts show it: the name of the entry when it is a plain name, else the fallback. The name
    comes from the person's own config, but a deny reason goes to the model, so only a plain name goes there."""
    return name if isinstance(name, str) and _NAME_RE.fullmatch(name) else fallback


def _apply_headers(data: dict, keys: dict, urls: dict, ours: set) -> tuple[list[str], list[str]]:
    """Change the headers in data (the parsed config) in place; returns (added, removed) server names."""
    added: list[str] = []
    removed: list[str] = []
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            headers = spec.get("headers")
            if headers is not None and not isinstance(headers, dict):
                continue                       # a shape we do not know: left as it is
            have = _header_key(headers or {})
            origin = origin_of(spec.get("url"))
            want = header_value(keys[origin]) if origin in keys and (name, spec.get("url")) in urls.get(origin, ()) \
                else None
            if want is None:
                if have and _kid_in(headers[have]) in ours:
                    del headers[have]
                    if not headers:
                        del spec["headers"]
                    removed.append(name)
                continue
            if have == HEADER and headers[have] == want:
                continue
            headers = spec.setdefault("headers", {})
            if have:
                del headers[have]
            headers[HEADER] = want
            added.append(name)
    return added, removed


# --------------------------------------------------------------- the notes --
def _off(cfg: dict | None) -> bool:
    return cfg is not None and cfg.get("client_header", True) is False


def note_result(payload: dict, cfg: dict, backend=None, deadline: float | None = None) -> tuple[int, str | None]:
    """PostToolUse: note each server-range token of an MCP result from a user-scope server. The first token of a server
    that is not enabled yet is the only trigger for a network request: one metadata request to that server, and the
    header on its entry when it names a vault endpoint (enable). The result stays as it is. Returns (the number of
    tokens noted, a notice for the person or None)."""
    count, notice = 0, None
    if cfg.get("client_header", True) is False:
        return count, notice
    tool = str(payload.get("tool_name") or "")
    server = payload.get("mcp_server") if isinstance(payload.get("mcp_server"), dict) else {}
    if not tool.startswith("mcp__") or server.get("source") != "user" or not isinstance(server.get("name"), str):
        return count, notice
    found: dict[str, tuple[str, set]] = {}        # key -> (type, the display parts of this result)
    asked: set = set()

    def walk(node, into_input: bool = False) -> None:
        if isinstance(node, str):
            for m in SERVER_REF_RE.finditer(node):
                key = f"{m.group('type')}_{m.group('n')}"
                if into_input:
                    asked.add(key)
                else:
                    found.setdefault(key, (m.group("type"), set()))[1].add(m.group("display") or "")
        elif isinstance(node, list):
            for x in node:
                walk(x, into_input)
        elif isinstance(node, dict):
            for x in node.values():
                walk(x, into_input)
    walk(payload.get("tool_response"))
    # a token that the call itself carried is no sighting: a server that repeats its query ("no match for
    # ⟦EMAIL_9⟧") would give the model a fresh seen_at for a key it never showed in this session (Gate B review)
    walk(payload.get("tool_input"), into_input=True)
    for key in asked:
        found.pop(key, None)
    if not found and not asked:
        return count, notice
    url = user_servers().get(server["name"])
    origin = origin_of(url)
    session = payload.get("session_id")
    if not origin or not isinstance(session, str) or not session:
        return count, notice
    now = time.time()
    seen = _now_iso(now)
    # every wait from here on ends at this deadline: a busy lock raises LockTimeout, and the post-tool hook then
    # leaves the token as text and redacts the output as it does without vault references
    deadline = deadline if deadline is not None else time.monotonic() + NOTE_BUDGET
    with _own_lock(deadline):
        # a key that the model sent to this origin, in any call of any session in the last NOTE_TTL, is never noted
        # later: a server that stores text and shows it again ("notes: ⟦EMAIL_9⟧") would give a planted key a new
        # sighting (Gate B review, round 2). Recorded for every user-scope entry, also one that is not enabled yet:
        # local state only, no request (Gate B review of the trigger). A key noted before stays noted
        sent_all = _read_json(SENT) or {}
        sent = sent_all.setdefault(profile(), {}).setdefault(origin, {})
        stale = [k for k, t in sent.items() if not (isinstance(t, (int, float)) and t > now - NOTE_TTL)]
        for k in stale:
            del sent[k]
        for k in asked:
            sent.pop(k, None)
            sent[k] = now
        while len(sent) > MAX_NOTES_PER_ORIGIN:
            del sent[next(iter(sent))]
        if asked or stale:
            atomic_write(SENT, json.dumps(sent_all, indent=1))
        for k in [k for k in found if k in sent]:
            found.pop(k)
    if not found:
        return count, notice
    if not _is_enabled(server["name"], url):
        # not enabled: a token of this result that the model did not send is the trigger
        if backend is None or not _may_change_config():
            return count, notice
        if not endpoint(cfg, url, min(deadline, time.monotonic() + DISCOVERY_BUDGET)):
            return count, notice            # no field: unsupported, cached; no answer: asked again next time
        notice = enable(cfg, backend, server["name"], url, deadline)
        if not _is_enabled(server["name"], url):
            return count, notice
    with _own_lock(deadline):
        data = _read_json(NOTES) or {}
        mine = data.setdefault(profile(), {}).setdefault(origin, {})
        for key, (type_, displays) in found.items():
            old = mine.pop(key, None)           # re-inserted last: the oldest notes are first
            old = old if isinstance(old, dict) else {}
            where = dict(old.get("seen")) if isinstance(old.get("seen"), dict) else {}
            shown = dict(old.get("display")) if isinstance(old.get("display"), dict) else {}
            conflict = [u for u in (old.get("conflict") or []) if isinstance(u, str)]
            by_url = old.get("sessions") if isinstance(old.get("sessions"), dict) else {}
            sessions = {u: [x for x in v if isinstance(x, str)] for u, v in by_url.items()
                        if isinstance(u, str) and isinstance(v, list)}
            if url in where and not (_seen_time(where[url]) or 0) > now - NOTE_TTL:
                # the sighting of this URL is older than NOTE_TTL: a new sighting starts it again, with this session
                # only. Kept, the old first sighting refused the key for good, also after the tool was called again
                where.pop(url)
                shown.pop(url, None)
                sessions.pop(url, None)
                conflict = [u for u in conflict if u != url]
            # one entry per server URL: two servers on one origin can both send EMAIL_1, for two people. The time is
            # the FIRST sighting: the server compares it with the time it minted the key, and a later sighting of a
            # key minted again for another person would pass that check with the other person's value (contract;
            # peer review H1). The sessions are per URL too: a session that saw the key from one URL must not get
            # the value of another URL on the same origin (Gate A review)
            named = sorted(d for d in displays if d)
            if url not in where:
                where[url], shown[url] = seen, (named[0] if named else "")
            if url not in conflict and (len(named) > 1 or (named and shown.get(url) and named[0] != shown[url])):
                conflict.append(url)            # the same key with another display: the server's mapping changed
            if not shown.get(url) and named:
                shown[url] = named[0]
            here = [x for x in sessions.get(url, []) if x != session]
            sessions[url] = (here + [session])[-MAX_SESSIONS_PER_NOTE:]
            mine[key] = {"type": type_, "seen": where, "display": shown, "conflict": conflict, "sessions": sessions}
        while len(mine) > MAX_NOTES_PER_ORIGIN:
            del mine[next(iter(mine))]
        atomic_write(NOTES, json.dumps(data, indent=1))
    return len(found), notice


def _seen_time(value: object) -> float | None:
    import calendar
    try:
        return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")) if isinstance(value, str) else None
    except ValueError:
        return None


def _notes(session: str | None) -> dict:
    """origin -> key -> {"type", "seen": {url: seen_at}}: the URLs that showed a key to this session of this client
    profile in the last NOTE_TTL. A token that another session saw stays text here, as a stored value of another
    session does (C4)."""
    mine = (_read_json(NOTES) or {}).get(profile())
    if not isinstance(mine, dict) or not session:
        return {}
    now = time.time()
    out: dict = {}
    for origin, notes in mine.items():
        if not isinstance(notes, dict):
            continue
        for key, note in notes.items():
            if not isinstance(note, dict):
                continue
            seen = note.get("seen") if isinstance(note.get("seen"), dict) else {}
            by_url = note.get("sessions") if isinstance(note.get("sessions"), dict) else {}
            fresh = {u: t for u, t in seen.items()
                     if isinstance(u, str) and (_seen_time(t) or 0) > now - NOTE_TTL
                     and isinstance(by_url.get(u), list) and session in by_url[u]}
            if fresh:
                out.setdefault(origin, {})[key] = {"type": note.get("type"), "seen": fresh,
                                                   "conflict": [u for u in (note.get("conflict") or []) if u in fresh]}
    return out


def noted(keys: list[str], session: str | None) -> dict[str, list[str]]:
    """key -> the origins that noted it for this session, for the keys that any origin noted."""
    out: dict[str, list[str]] = {}
    for origin, mine in _notes(session).items():
        if not isinstance(mine, dict):
            continue
        for key in keys:
            if isinstance(mine.get(key), dict):
                out.setdefault(key, []).append(origin)
    return out


def noted_elsewhere(text: str, cfg: dict | None, session: str | None) -> list[str]:
    """The server tokens of text that this profile noted, but not for this session or not in the last NOTE_TTL: they
    get a reason, as a stored value of another session does. A token never noted stays text."""
    refs = list(dict.fromkeys(k for k, _a, _b in find(text)))
    if _off(cfg) or not refs:
        return []
    here = noted(refs, session)
    mine = (_read_json(NOTES) or {}).get(profile())
    if not isinstance(mine, dict):
        return []
    return [k for k in refs if k not in here
            and any(isinstance(notes, dict) and isinstance(notes.get(k), dict) for notes in mine.values())]


def forget(keys: list[str], origin: str, url: str, deadline: float | None = None) -> None:
    """The notes of these keys from this server URL go: the server said they are older than its data."""
    with _own_lock(deadline):
        data = _read_json(NOTES) or {}
        mine = (data.get(profile()) or {}).get(origin)
        if not isinstance(mine, dict):
            return
        for k in keys:
            note = mine.get(k)
            if not isinstance(note, dict):
                continue
            for field in ("seen", "display", "sessions"):
                if isinstance(note.get(field), dict):
                    note[field].pop(url, None)
            note["conflict"] = [u for u in (note.get("conflict") or []) if u != url]
            if not note.get("seen"):
                del mine[k]
        atomic_write(NOTES, json.dumps(data, indent=1))


def find_noted(text: str, cfg: dict | None, session: str | None) -> list[tuple[str, int, int]]:
    """The server-range tokens in text that a server result noted for this session; any other one stays text, and
    every one does when client_header is off."""
    refs = find(text)
    if not refs or _off(cfg):
        return []
    known = noted(list(dict.fromkeys(k for k, _a, _b in refs)), session)
    return [r for r in refs if r[0] in known]


# --------------------------------------------------------------- transport --
def _cafile(cfg: dict) -> str | None:
    f = cfg.get("client_vault_cafile")
    return f if isinstance(f, str) and f else None


def _request(cfg: dict, method: str, url: str, headers: dict, body: bytes | None, deadline: float):
    """_send in a thread that the caller waits for until the deadline only: a socket timeout bounds one read, not a
    server that sends one header line every few seconds."""
    import threading
    box: dict = {}

    def run() -> None:
        try:
            box["ok"] = _send(cfg, method, url, headers, body, deadline)
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            box["err"] = exc
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(max(0.0, deadline - time.monotonic()) + 0.1)
    if "ok" in box:
        return box["ok"]
    if "err" in box:
        raise box["err"]
    raise TimeoutError("the server took too long")


def _send(cfg: dict, method: str, url: str, headers: dict, body: bytes | None, deadline: float):
    """One HTTPS request with no redirect and no proxy. Returns (status, headers, body) with the body cut above
    MAX_ANSWER_BYTES + 1, so a longer body is seen as too long."""
    import http.client
    import ssl
    parts = urlsplit(url)
    left = deadline - time.monotonic()
    if left <= 0.2:
        raise TimeoutError("no time left")
    ctx = ssl.create_default_context(cafile=_cafile(cfg))
    conn = http.client.HTTPSConnection(parts.hostname, 443 if parts.port is None else parts.port,
                                       timeout=min(CONNECT_TIMEOUT, left),
                                       context=ctx)
    try:
        conn.connect()
        conn.sock.settimeout(min(SOCKET_TIMEOUT, max(0.2, deadline - time.monotonic())))
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request(method, path, body=body, headers=headers)
        answer = conn.getresponse()
        chunks, size = [], 0
        while size <= MAX_ANSWER_BYTES:
            if time.monotonic() > deadline:
                raise TimeoutError("the answer took too long")
            chunk = answer.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return answer.status, {k.lower(): v for k, v in answer.getheaders()}, b"".join(chunks)
    finally:
        conn.close()


def _is_json(headers: dict) -> bool:
    return headers.get("content-type", "").split(";")[0].strip().lower() == "application/json"


def endpoint(cfg: dict, url: str, deadline: float) -> str | None:
    """The resolve endpoint that the server of this MCP URL names (RFC 9728 metadata, `client_vault_endpoint`): an
    https URL of the same origin, or None. Kept per origin and path for METADATA_TTL, either way."""
    origin = origin_of(url)
    if not origin:
        return None
    path = urlsplit(url).path
    path = "" if path == "/" else path          # RFC 9728: the resource path as it is, a trailing slash included
    cache_key = origin + path
    cache = _read_json(ENDPOINTS) or {}
    hit = cache.get(cache_key)
    try:
        age = time.time() - float(hit.get("t")) if isinstance(hit, dict) else -1.0
    except (TypeError, ValueError):
        age = -1.0
    if 0 <= age < METADATA_TTL:
        cached = hit.get("endpoint")
        if cached is None:
            return None
        if isinstance(cached, str) and origin_of(cached) == origin:
            return cached
    found = None
    try:
        status, headers, body = _request(cfg, "GET", f"{origin}/.well-known/oauth-protected-resource{path}",
                                         {"Accept": "application/json"}, None, deadline)
        if status != 200 or not _is_json(headers) or len(body) > MAX_ANSWER_BYTES:
            return None                         # a 404 or 5xx in a deploy is no answer: not cached (peer review M2)
        meta = json.loads(body.decode("utf-8"))
        if not isinstance(meta, dict):
            return None
        candidate = meta.get("client_vault_endpoint")
        if origin_of(candidate) == origin:
            found = candidate
    except (ValueError, RecursionError) + _net_errors():
        return None                             # not cached: the next call asks again (deep JSON: RecursionError)
    try:
        with _own_lock(deadline):
            cache = _read_json(ENDPOINTS) or {}
            cache[cache_key] = {"endpoint": found, "t": time.time()}
            atomic_write(ENDPOINTS, json.dumps(cache, indent=1))
    except LockTimeout:
        pass                                    # the answer holds; a busy lock only costs the next call one request
    return found


# ---------------------------------------------------------------- the resolve --
_CODES = {(401, "unknown_key"), (403, "pending"), (403, "clock_skew"), (404, "unknown_ref"), (410, "expired"),
          (429, "rate_limited"), (503, "disabled")}


def _safe_time(value: object) -> str | None:
    return value if isinstance(value, str) and _TIME_RE.fullmatch(value) else None


def _why(origin: str, status: int, code: str | None, body: dict, headers: dict, keys: list[str],
         url: str = "", deadline: float | None = None, kid: str | None = None) -> str:
    host = urlsplit(origin).hostname
    names = ", ".join(f"⟦{k}⟧" for k in keys)
    if code in ("unknown_key", "pending", "disabled"):
        # the state of the binding, in the words of /maisecrets:status, with the one step the person takes
        rec = _set_state(origin, code, body.get("activates_at") if code == "pending" else None,
                         deadline=deadline, kid=kid)
        name = _entry_name(origin, url)
        return (f"the state of the MCP server {_say_name(name, host)} ({host}) is: "
                f"{describe(rec['state'], name or host, rec.get('activates_at'))}")
    if code == "clock_skew":
        return f"the clock of this computer is off by more than 5 minutes for {host}; the person fixes the clock"
    if code == "unknown_ref":
        return f"{host} does not know one of {names}; use only tokens from a result of that server"
    if code == "expired":
        return f"{names} are older than {host}'s data; read the data again and use the new tokens"
    if code == "rate_limited":
        after = headers.get("retry-after", "")
        return f"{host} reached its limit" + (f"; try again in {after} s" if after.isdigit() else "; try later")
    return f"{host} gave no usable answer (HTTP {status})"


def resolve(cfg: dict, backend, keys: list[str], session: str | None,
            deadline: float | None = None) -> dict[str, tuple[str, str]]:
    """key -> (value, origin) for every key, or Refused. All or nothing, for every origin together."""
    if not keys:
        return {}
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET
    if _off(cfg):
        raise Refused("vault references are off (client_header false)")
    notes = _notes(session)
    where_from: dict[str, set] = {}
    for origin, mine in notes.items():
        for k in keys:
            note = mine.get(k) if isinstance(mine, dict) else None
            seen = note.get("seen") if isinstance(note, dict) else None
            for url in (seen if isinstance(seen, dict) else {}):
                where_from.setdefault(k, set()).add((origin, url))
    ambiguous = [k for k in keys if len(where_from.get(k, ())) > 1]
    if ambiguous:
        raise Refused(f"⟦{ambiguous[0]}⟧ came from more than one server, so maisecrets cannot tell which one to ask")
    groups: dict[tuple[str, str], list[str]] = {}
    for k in keys:
        if k not in where_from:
            raise Refused(f"⟦{k}⟧ was not seen in a result of an MCP server")
        origin, url = next(iter(where_from[k]))
        if url in (notes[origin][k].get("conflict") or []):
            forget([k], origin, url, deadline)
            raise Refused(f"the server sent ⟦{k}⟧ for two different values, so it may name another person now; "
                          "call the server's tool again and use the new tokens")
        groups.setdefault((origin, url), []).append(k)
    current = set(user_servers().values())
    out: dict[str, tuple[str, str]] = {}
    for (origin, url), mine in groups.items():
        host = urlsplit(origin).hostname
        if len(mine) > MAX_REFS:
            raise Refused(f"{len(mine)} tokens of {host} in one call; at most {MAX_REFS} go in one call")
        if url not in current or origin_of(url) != origin:
            raise Refused(f"{host} is no longer a user-scope MCP server of this client")
        k = _key(backend, origin, create=False, deadline=deadline)
        if k is None:
            raise Refused(f"this computer has no key for {host}; the next token of that server sets it up again")
        where = endpoint(cfg, url, deadline)
        if not where:
            raise Refused(f"{host} does not name a vault endpoint, or could not be reached")
        body = json.dumps({"now": _now_iso(),
                           "refs": [{"key": key, "seen_at": notes[origin][key]["seen"][url]} for key in mine]}).encode()
        if len(body) > MAX_REQUEST_BYTES:
            raise Refused(f"the request to {host} is larger than 64 KB")
        try:
            status, headers, raw = _request(cfg, "POST", where, {"Authorization": f"Bearer {bearer_of(k)}",
                                                                 "Content-Type": "application/json",
                                                                 "Accept": "application/json"}, body, deadline)
        except _net_errors() as exc:
            raise Refused(f"{host} could not be reached ({type(exc).__name__})") from None
        answer = None
        if len(raw) <= MAX_ANSWER_BYTES and _is_json(headers):
            try:
                answer = json.loads(raw.decode("utf-8"))
            except (ValueError, RecursionError):
                answer = None
        answer = answer if isinstance(answer, dict) else None
        if status == 200 and answer is not None:
            values = answer.get("values")
            if isinstance(values, dict) and all(isinstance(values.get(key), str) for key in mine):
                for key in mine:
                    out[key] = (values[key], origin)
                _set_state(origin, "active", deadline=deadline, kid=kid_of(k))
                continue
            raise Refused(f"{host} gave no usable answer (a value is missing or not text)")
        code = answer.get("error") if answer is not None else None
        code = code if (status, code) in _CODES else None
        if code == "expired":
            forget(mine, origin, url, deadline)     # a fresh sighting starts the time again (contract)
        raise Refused(_why(origin, status, code, answer or {}, headers, mine, url, deadline, kid_of(k)))
    return out


# ---------------------------------------------------------------- the state --
# The state of the binding of one origin, as the server last answered it, for the key this profile has now. The
# server answers `401 unknown_key` both before a binding and after a quarantine or a revoke (SPEC 8.4); only a record
# that this key was bound once (`bound`) tells the two apart. Never K, never a value: the kid, the state, the time.
STATES = DIR / "states.json"          # profile -> origin -> {"kid", "state", "t", "bound", "activates_at", "told"}
STATE_WORDS = ("header", "pending", "active", "lost", "disabled")


def _kid_now(origin: str) -> str | None:
    rec = _known_keys().get(origin)
    kid = rec.get("kid") if isinstance(rec, dict) else None
    return kid if isinstance(kid, str) else None


def state_of(origin: str) -> dict:
    """The record of this origin for the key of this profile now, or {} (no answer yet, or the key changed)."""
    return _current(_mine(STATES).get(origin), _kid_now(origin))


def _current(rec: object, kid: str | None) -> dict:
    if not isinstance(rec, dict) or not kid or rec.get("kid") != kid or rec.get("state") not in STATE_WORDS:
        return {}
    return rec


def _next_state(old: dict, kid: str | None, answer: str, activates_at: object, told: str | None) -> dict:
    bound = bool(old.get("bound"))
    state = ("lost" if bound else "header") if answer == "unknown_key" else answer
    if state in ("active", "pending"):
        bound = True                    # a 503 alone proves no binding: an allow list can answer it without one
    rec = {"kid": kid, "state": state, "t": time.time(), "bound": bound}
    # a server must not put text before the AI: the time is kept only when it is a time (SPEC 8.4)
    when = _safe_time(activates_at)
    if state == "pending" and when:
        rec["activates_at"] = when
    rec["told"] = told if told is not None else old.get("told")
    return rec


def _same(old: dict, rec: dict) -> bool:
    """The same answer within a minute: no write in a resolve."""
    return {k: old.get(k) for k in ("state", "activates_at")} == {k: rec.get(k) for k in ("state", "activates_at")} \
        and isinstance(old.get("t"), (int, float)) and 0 <= time.time() - old["t"] < 60


def _set_state(origin: str, answer: str, activates_at: str | None = None, told: str | None = None,
               deadline: float | None = None, kid: str | None = None) -> dict:
    """Record a server answer (`active`, `pending`, `disabled`, `unknown_key`) or a told state. Returns the record.
    `unknown_key` is `lost` when this key was bound once, else `header`. The old record is read again under the lock,
    so a parallel answer never takes `bound` back (Gate A review). A busy lock or a failed write keeps the old record
    on disk; the record is returned all the same, so the reason of a deny still names the state. `kid` is the kid
    of the key that got the answer: an answer for a key that a new key replaced meanwhile is not written (Gate A
    review, round 2), it would name the state of the new key."""
    now = _kid_now(origin)
    asked = kid or now
    old = _current(_mine(STATES).get(origin), asked)     # the record of the key that got the answer
    rec = _next_state(old, asked, answer, activates_at, told)
    if now and asked != now:
        return state_of(origin) or rec          # a new key came meanwhile: the reason names the state of that key
    if not now or (told is None and _same(old, rec)):
        return old if now and old else rec
    try:
        with _own_lock(deadline):
            if _kid_now(origin) != asked:
                return state_of(origin) or rec      # a new key came while the answer was on its way
            data = _read_json(STATES) or {}
            mine = data.get(profile())
            if not isinstance(mine, dict):
                mine = data[profile()] = {}         # a damaged part is written new, not a reason to fail
            rec = _next_state(_current(mine.get(origin), asked), asked, answer, activates_at, told)
            mine[origin] = rec
            atomic_write(STATES, json.dumps(data, indent=1))
    except (LockTimeout, OSError):
        pass
    return rec


def _mark_told(origin: str, state: str, deadline: float | None = None) -> None:
    """The person heard this state (a notice, a session-start hint, the status): no hint for it again."""
    rec = state_of(origin)
    if rec.get("state") == state:
        _set_state(origin, state, rec.get("activates_at"), told=state, deadline=deadline)
    elif state == "header" and not rec:
        _set_state(origin, "header", told="header", deadline=deadline)


def describe(state: str | None, name: object, activates_at: str | None = None) -> str:
    """The state of one server in the person's words, with the one next step. `state` None: not used yet."""
    who = _say_name(name)
    if state == "header":
        if is_codex():
            return "header written — start Codex again"
        return f"header written — type /mcp reconnect {who} (or start Claude Code again)"
    if state == "pending":
        when = activates_at or "a time the server did not give"
        return (f"waiting for activation until {when} — activate it on the server's connections page, or sign in to "
                f"{who} again in the browser")
    if state == "active":
        return "active"
    if state == "lost":
        return ("this key is quarantined (used by two accounts) or revoked — maisecrets makes a new key at the next "
                f"start of {'Codex' if is_codex() else 'Claude Code'}")
    if state == "disabled":
        return "the server's operator switch is off"
    return "not used yet (no server token seen, or the server names no vault endpoint)"


def _entry_name(origin: str, url: str) -> str | None:
    """The name of the enabled entry with this URL; the first one when two entries share it."""
    return next((n for n, u in _enabled().get(origin, []) if u == url), None)


def check_state(cfg: dict, backend, origin: str, url: str, deadline: float | None = None) -> tuple[dict, str | None]:
    """The status probe (SPEC 8.5): one resolve with no refs, so no value can come back and none is sent. Returns
    (the new record, None), or (the last record, why no answer came). Only for an origin with a key: a key exists only
    after a server token and a vault endpoint, so no request goes out before a server token."""
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET
    try:
        k = _key(backend, origin, create=False, deadline=deadline)
    except LockTimeout:
        return state_of(origin), "the store was busy"
    if k is None:
        return state_of(origin), "this computer has no key for it"
    where = endpoint(cfg, url, deadline)
    if not where:
        return state_of(origin), "it names no vault endpoint, or it could not be reached"
    try:
        status, headers, raw = _request(cfg, "POST", where, {"Authorization": f"Bearer {bearer_of(k)}",
                                                             "Content-Type": "application/json",
                                                             "Accept": "application/json"},
                                        json.dumps({"now": _now_iso(), "refs": []}).encode(), deadline)
    except _net_errors() as exc:
        return state_of(origin), f"it could not be reached ({type(exc).__name__})"
    try:
        answer = json.loads(raw.decode("utf-8")) if _is_json(headers) and len(raw) <= MAX_ANSWER_BYTES else None
    except (ValueError, RecursionError):
        answer = None
    answer = answer if isinstance(answer, dict) else None
    code = answer.get("error") if answer is not None else None
    if status == 200 and answer is not None and isinstance(answer.get("values"), dict):
        return _set_state(origin, "active", deadline=deadline, kid=kid_of(k)), None
    if (status, code) == (403, "pending"):
        return _set_state(origin, "pending", answer.get("activates_at"), deadline=deadline, kid=kid_of(k)), None
    if (status, code) == (401, "unknown_key"):
        return _set_state(origin, "unknown_key", deadline=deadline, kid=kid_of(k)), None
    if (status, code) == (503, "disabled"):
        return _set_state(origin, "disabled", deadline=deadline, kid=kid_of(k)), None
    if (status, code) == (403, "clock_skew"):
        return state_of(origin), "the clock of this computer is off by more than 5 minutes"
    return state_of(origin), f"no usable answer (HTTP {status})"


def _state_line(name: str, origin: str, rec: dict, why: str | None) -> str:
    text = describe(rec.get("state") or "header", name, rec.get("activates_at"))
    when = f"checked {_now_iso(rec['t'])}" if isinstance(rec.get("t"), (int, float)) else "no answer yet"
    if why:
        return f"vault references: {name} ({origin}): {text} ({when}; not checked now: {why})"
    return f"vault references: {name} ({origin}): {text} ({when})"


def session_check(cfg: dict, backend) -> str | None:
    """At a session start: one status probe per origin with a header, all inside one BUDGET, and one line for each
    server whose state changed since the person last heard it. A server that does not answer gives no line."""
    enabled = _enabled()
    if _off(cfg) or not enabled:
        return None                     # no server token seen yet: no config read, no request
    servers = user_servers()
    deadline = time.monotonic() + BUDGET
    lines = []
    for origin, entries in enabled.items():
        live = [(n, u) for n, u in entries if servers.get(n) == u]
        if not live or time.monotonic() >= deadline - 0.2:
            continue
        name, url = live[0]
        try:
            rec, why = check_state(cfg, backend, origin, url, deadline)
        except (LockTimeout, OSError):
            continue
        state = rec.get("state")
        if why or not state or state == rec.get("told"):
            continue
        lines.append(f"maisecrets: vault references of {_say_name(name)}: "
                     f"{describe(state, name, rec.get('activates_at'))}.")
        _mark_told(origin, state, deadline)
    return " ".join(lines) or None


def _put_key(backend, origin: str, k: bytes) -> None:
    backend.put(_store_name(origin), k.hex(), label="maisecrets vault reference key",
                comment="maisecrets: the key that gets values back from a server; not a placeholder value.")


def rotate_lost(backend, deadline: float | None = None) -> list[str]:
    """At a session start: a new K for each origin whose server no longer accepts its key (quarantined or revoked). A
    vault must not use that K again (SPEC 6.4). The entries stay enabled, so the header write that follows puts the
    new kid on them. Only a key this computer holds, whose kid keys.json and the `lost` record both name, and an entry
    that the client config still has: local files alone never make a key, so no request goes out before a server
    token (Gate B review). The check runs again under the locks: two starts at once make one new key (Gate A review).
    Returns the origins."""
    out = []
    servers = None
    for origin, entries in _enabled().items():
        if state_of(origin).get("state") != "lost":
            continue
        servers = user_servers() if servers is None else servers
        if not any(servers.get(n) == u for n, u in entries):
            continue
        import secrets
        with _own_lock(deadline):
            with _store_lock(deadline):
                old = _key_locked(backend, origin, create=False)
                kid = _kid_now(origin)
                if old is None or kid_of(old) != kid or state_of(origin).get("state") != "lost":
                    continue
                k = secrets.token_bytes(32)
                _put_key(backend, origin, k)
                try:
                    data = _read_json(KEYS) or {}
                    mine = data.get(profile()) if isinstance(data.get(profile()), dict) else {}
                    rec = mine.get(origin)
                    entries = rec.get("entries") if isinstance(rec, dict) and isinstance(rec.get("entries"), list) \
                        else []
                    mine[origin] = {"kid": kid_of(k), "created": _now_iso(), "entries": entries}
                    data[profile()] = mine
                    atomic_write(KEYS, json.dumps(data, indent=1))
                except BaseException:
                    # keys.json still names the old kid: the old key goes back, so the store and keys.json agree and
                    # the next start tries again. Kept, the new key would never match keys.json, and no start would
                    # replace it again (Gate A and Gate B review, round 2)
                    _put_key(backend, origin, old)
                    raise
        out.append(origin)
    return out


def remember_released(backend, session: str | None, values: dict[str, tuple[str, str]]) -> None:
    """The values a server gave for this session go into the store as one entry with no placeholder, for
    RELEASE_WINDOW: a command that prints one, or an Edit result that shows it, is redacted to the server's token
    like a value the session resolved (Fable review). Older entries leave the store here."""
    if not session or not values:
        return
    now = time.time()
    import secrets
    name = "_maisecrets_vrel_" + secrets.token_hex(12)
    try:
        backend.put(name, json.dumps([[v, f"{OPEN}{k}{CLOSE}"] for k, (v, _o) in values.items()]),
                    label="maisecrets server values", comment="maisecrets: values a server gave, for one hour; "
                                                              "not a placeholder value.")
        with _lock_for(DIR / ".lock"):
            data = _prune(backend, _read_json(RELEASED) or {}, now)
            data.setdefault(session, []).append({"name": name, "t": now})
            atomic_write(RELEASED, json.dumps(data, indent=1))
    except BaseException:
        # not in the list, the entry would never leave the store: it goes now (Gate A review)
        try:
            backend.delete(name)
        except (RuntimeError, OSError):
            pass
        raise


def _expired(item: object, now: float) -> bool:
    try:
        return not isinstance(item, dict) or not 0 <= now - float(item.get("t")) < RELEASE_WINDOW
    except (TypeError, ValueError):
        return True


def _prune(backend, data: dict, now: float) -> dict:
    """data without the entries older than RELEASE_WINDOW; their values leave the store."""
    out: dict = {}
    for sess, items in data.items():
        keep = []
        for item in items if isinstance(items, list) else []:
            if not _expired(item, now):
                keep.append(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                try:
                    backend.delete(item["name"])
                except (RuntimeError, OSError):
                    keep.append(item)            # tried again at the next prune
        if keep:
            out[sess] = keep
    return out


def prune_released(backend) -> None:
    """At session start and when an expired entry is seen: the values older than their hour leave the store."""
    data = _read_json(RELEASED)
    if not data:
        return
    now = time.time()
    if not any(_expired(i, now) for items in data.values() for i in (items if isinstance(items, list) else [None])):
        return
    with _lock_for(DIR / ".lock"):
        data = _prune(backend, _read_json(RELEASED) or {}, now)
        if data:
            atomic_write(RELEASED, json.dumps(data, indent=1))
        else:
            try:
                RELEASED.unlink()
            except OSError:
                pass


def released(backend, session: str | None) -> list[tuple[str, str]]:
    """(value, token) for every value a server gave this session in the last RELEASE_WINDOW."""
    items = (_read_json(RELEASED) or {}).get(session or "") if session else None
    out: list[tuple[str, str]] = []
    now = time.time()
    if any(_expired(i, now) for i in (items if isinstance(items, list) else [])):
        prune_released(backend)
    for item in items if isinstance(items, list) else []:
        if _expired(item, now):
            continue
        raw = backend.get(str(item.get("name")))
        try:
            pairs = json.loads(raw) if raw else []
        except ValueError:
            pairs = []
        out.extend((v, t) for v, t in pairs if isinstance(v, str) and isinstance(t, str))
    return out


def has_released() -> bool:
    """Any value a server gave in the last hour, in any session: then the output hook opens the store."""
    now = time.time()
    data = _read_json(RELEASED) or {}
    return any(not _expired(i, now) for items in data.values() for i in (items if isinstance(items, list) else []))


def status_lines(cfg: dict, backend, check: bool = True) -> list[str]:
    """One line per user-scope server of this profile."""
    if cfg.get("client_header", True) is False:
        return ["vault references: off (client_header false)"]
    if is_codex():
        from . import codex_vault
        if not codex_vault.available():
            return ["vault references in Codex: off (they need Python 3.11 or later, and Windows is not supported "
                    "yet)"]
        if HOME != _DEFAULT_HOME and not os.environ.get("CODEX_HOME"):
            return ["vault references: off, because this maisecrets home is not the default one and CODEX_HOME is "
                    "not set"]
        lines = [f"vault references: client config {codex_vault.profile()} (Codex)"]
    else:
        if HOME != _DEFAULT_HOME and not os.environ.get("CLAUDE_CONFIG_DIR"):
            return ["vault references: off, because this maisecrets home is not the default one and CLAUDE_CONFIG_DIR "
                    "is not set"]
        chosen = claude_json()
        others = [str(f) for f in (legacy_file(), global_file()) if f != chosen and f.exists()]
        if os.environ.get("CLAUDE_CONFIG_DIR") == "":
            return ["vault references: off, because CLAUDE_CONFIG_DIR is set but empty (the client then reads a file "
                    "in its working folder)"]
        lines = [f"vault references: client config {chosen}" + (f" ({others[0]} is not read)" if others else "")]
    servers = user_servers()
    if not servers:
        return lines + ["vault references: no user-scope MCP server with an https URL"]
    probed: dict[str, tuple[dict, str | None]] = {}
    for name, url in servers.items():
        origin = origin_of(url)
        if not _is_enabled(name, url):
            lines.append(f"vault references: {name} ({origin}): {describe(None, name)}")
            continue
        if not check:
            lines.append(_state_line(name, origin, state_of(origin), "not asked"))
            continue
        if origin not in probed:                # one probe per origin: one key, one binding
            probed[origin] = check_state(cfg, backend, origin, url)
            rec, why = probed[origin]
            if not why and rec.get("state"):
                _mark_told(origin, rec["state"])    # the person reads it here: no session-start hint for it
        rec, why = probed[origin]
        lines.append(_state_line(name, origin, rec, why))
    return lines
