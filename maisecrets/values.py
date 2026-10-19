"""Values from your own tools: imports of found values, masked wherever they appear (README "Values from your own
tools", C26, #19 part 3).

A tool the person runs (a NER, an export, a script) writes JSON lines:

    {"value": "Jan Kowalski", "type": "NAME"}
    {"value": "jan.kowalski@example.org", "type": "EMAIL"}
    {"value": "A value without a shape"}            # type SECRET when it is missing

`maisecrets values import FILE`, or a file of the setting `value_files` at session start, adds them to an import:
`~/.maisecrets/imports/<id>.jsonl`, written by maisecrets alone (value_files.py). The registry pass `imports`
(registry phase 5, after the terms) finds every imported value as a phrase of whole words, in any case, NFC and
without format characters, with the matcher of the terms (terms.Matcher): one index of every import, never a regex
per value. A hit is a detect.Match of kind `import:<import id>:<value id>`, so it names its import.

Mask only, as the terms: the store keeps `maisecrets-import:<ids>`, never the value, and the placeholder is never
put back into a command or a file. An imported value that a rule finds, or that the store holds already, keeps
that rule's or that entry's placeholder (detect._import_hits, hooks._longest_wins): an import only adds masking
where nothing else masks, and never changes how another value is masked or resolved.

The trust rule: the agent can only make detection stricter. An import only adds. Nothing in a line can loosen
anything: only `value` and `type` are read, and a type only names the placeholder. A new import of the same file
merges into its import and never drops a value; only the person removes an import, by a typed prompt
(/maisecrets:forget import:ID, hooks.user_prompt). What an agent can still do is mask too much, and these hold it:

- a floor per value (_reason): at least MIN_LEN characters, a number at least MIN_DIGITS digits, no ordinary word
  (one word of lower-case letters, or only words of the stop list of the team terms), no text of maisecrets itself.
- caps: MAX_PER_IMPORT values in one import, MAX_VALUES in all, of which the imports that no value file names hold
  at most MAX_RUN_VALUES, so the person's value files always have room; MAX_IMPORTS imports.
- each new import is named at the next session start, by id and count, and /maisecrets:list shows every import.
"""
from __future__ import annotations

import errno
import hashlib
import json
import marshal
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import terms, value_files
from .home import HOME, ConfigError

TYPES = terms.TYPES
IMPORTS = value_files.IMPORTS
SUFFIX = value_files.SUFFIX
CACHE_FILE = value_files.CACHE_FILE
STATE_FILE = value_files.STATE_FILE

MAX_FILE_BYTES = 8 << 20       # about 150,000 lines of a name and a type
MAX_PER_IMPORT = 100_000
MAX_VALUES = 150_000           # as terms.MAX_TEAM_ENTITIES: the index stays within one build of about 2 s
MAX_RUN_VALUES = 100_000       # of MAX_VALUES: the imports that no value file names
MAX_IMPORTS = 50
MAX_RUN_IMPORTS = 30           # of MAX_IMPORTS: the imports that no value file names; the value files keep 20 places
MAX_IMPORT_BYTES = 24 << 20    # one import file as maisecrets writes it; a merge past it stops (Gate A, round 2)
MAX_LINES = 200_000            # lines one import parses at most: 8 MB of `0` lines cost millions of JSON reads
MAX_REFUSED_SHOWN = 20         # refused lines kept with their reason; the rest is a count
MAX_FILES_PER_START = 20       # value files one session start reads
MIN_LEN = 4
MIN_DIGITS = 6                 # a value of digits only: 2024 or 10115 would mask years and postcodes everywhere
MAX_LEN = 200
MAX_WORDS = terms.MAX_WORDS
_FORMAT = 1
_CONTROL_TEXT = ("⟦", "⟧", "maisecrets", "import:")
_LOWER_WORD = re.compile(r"[a-zß-ÿ]+")
_WORD_RE = re.compile(r"\w+")
_KEY_WORD = re.compile(r"(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9_]{0,39}?_c\d{1,9}(?![0-9])", re.I)
_RESERVED: list = []


def _reserved() -> frozenset:
    """The setting keys (config.json and the settings cards), lower case."""
    if not _RESERVED:
        from . import settings
        from .home import DEFAULT_CONFIG
        keys = list(DEFAULT_CONFIG) + list(settings.TITLE) + list(settings.MEANING)
        _RESERVED.append(frozenset(k.lower() for k in keys if "_" in k))
    return _RESERVED[0]


class ValuesError(ConfigError):
    """A ConfigError: every hook fails closed on it. The message names the import, never a value."""


@dataclass
class Result:
    id: str = ""
    new: dict = field(default_factory=dict)          # type -> values added now
    known: int = 0                                    # values this import or another one held already
    duplicates: int = 0                               # the same value twice in the file
    refused: list = field(default_factory=list)       # (line number, reason), never the text; the first ones
    refused_count: int = 0                            # every refused line
    stopped: str = ""                                 # why the import stopped before the end, or ""
    merged: bool = False                              # the file had an import already

    @property
    def added(self) -> int:
        return sum(self.new.values())


# ----------------------------------------------------------------- parsing --
def _norm(value: str) -> str:
    """A value as the index holds it: NFC, without format characters, white space runs as one space."""
    return " ".join(terms._norm(value).split())


def _reason(value: str) -> str:
    """Why a value is refused, or "". Fixed text, never the value."""
    if len(value) < MIN_LEN:
        return f"too short (at least {MIN_LEN} characters)"
    if len(value) > MAX_LEN:
        return f"too long (at most {MAX_LEN} characters)"
    if any(ord(c) < 32 for c in value):
        return "holds a control character or a line break"
    words = _WORD_RE.findall(terms._lower(value))
    if not words:
        return "holds no letter or digit"
    if len(words) > MAX_WORDS:
        return f"more than {MAX_WORDS} words"
    folded = value.casefold()
    if any(t in folded for t in _CONTROL_TEXT):
        # a value with one of them would mask the person's own controls (/maisecrets:forget import:ID) and the
        # placeholders (review of block 3, Opus H1)
        return "holds text of maisecrets itself (a placeholder bracket, maisecrets or import:)"
    if _KEY_WORD.search(value):
        # a placeholder key (SECRET_c1): the import pass would find it inside the brackets of a placeholder, and the
        # stored value behind it would no longer resolve (Gate B, round 1)
        return "holds a placeholder key"
    if any(w in _reserved() for w in words):
        # a setting key (value_files, rule_dirs): masked, the person's own settings prompt no longer works (Gate A and
        # Gate B, round 1)
        return "holds the name of a maisecrets setting"
    if _LOWER_WORD.fullmatch(value):
        return "an ordinary word (one word of lower-case letters)"
    stop = terms.stoplist()
    if all(w in stop for w in words):
        return "only common words (the stop list of the team terms)"
    digits = sum(c.isdigit() for c in value)
    if not any(c.isalpha() for c in value) and digits < MIN_DIGITS:
        return f"a number of fewer than {MIN_DIGITS} digits"
    return ""


class _Refused(list):
    """The refused lines: the first MAX_REFUSED_SHOWN with their reason, and the count of all (`count`)."""
    count = 0

    def append(self, item) -> None:
        self.count += 1
        if len(self) < MAX_REFUSED_SHOWN:
            super().append(item)


def parse(text: str) -> tuple[list, list, int]:
    """(values as (value, type, line), refused lines as (line, reason), duplicates). Blank lines and lines that start
    with `#` are skipped. Only `value` and `type` are read; any other field is ignored, so no field can loosen. At most
    MAX_LINES lines are read; the refused list keeps its first entries and the count of all (_Refused.count)."""
    items: list = []
    refused = _Refused()
    seen: set = set()
    duplicates = 0
    lines = 0
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lines += 1
        if lines > MAX_LINES:
            refused.append((n, f"line {n} and later not read: at most {MAX_LINES:,} lines in one file"))
            break
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            refused.append((n, "not JSON (a line that a writer has not finished is one too)"))
            continue
        if not isinstance(obj, dict):
            refused.append((n, "not a JSON object"))
            continue
        value = obj.get("value")
        if not isinstance(value, str) or not value.strip():
            refused.append((n, "no \"value\" text"))
            continue
        type_ = obj.get("type", "SECRET")
        if not isinstance(type_, str) or type_.upper() not in TYPES:
            refused.append((n, f"unknown type (one of {', '.join(TYPES)})"))
            continue
        value = _norm(value)
        why = _reason(value)
        if why:
            refused.append((n, why))
            continue
        low = terms._lower(value)
        if low in seen:
            duplicates += 1
            continue
        seen.add(low)
        items.append((value, type_.upper(), n))
    return items, refused, duplicates


# ------------------------------------------------------------------ sources --
def read_source(path: Path) -> bytes:
    """The bytes of a file to import, or ValueError with a reason for the person (never the file name).

    One open without following a link at the end of the path and without blocking, then every check on the open
    descriptor: a regular file (a FIFO, a device or a folder is refused), owned by the person or root, not writable by
    every user; then one read with a byte bound. So a file swapped after a check (TOCTOU), a FIFO that would hold the
    session start, and a file that grows while it is read all fail or stop at the bound."""
    if not hasattr(os, "O_NOFOLLOW"):
        # Windows has no O_NOFOLLOW: the link is refused by its own lstat, one step before the open (CI, windows)
        try:
            if os.path.islink(path):
                raise ValueError("a symbolic link (name the file it points to)")
        except OSError:
            pass
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError("a symbolic link (name the file it points to)") from None
        raise ValueError(f"cannot be read ({type(exc).__name__})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("not a regular file")
        if os.name != "nt":
            if st.st_uid not in (0, os.getuid()):
                raise ValueError("owned by another user")
            if st.st_mode & stat.S_IWOTH:
                raise ValueError("every user can write it")
        chunks, size = [], 0
        while size <= MAX_FILE_BYTES:
            chunk = os.read(fd, min(1 << 20, MAX_FILE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError as exc:
        raise ValueError(f"cannot be read ({type(exc).__name__})") from None
    finally:
        os.close(fd)
    if size > MAX_FILE_BYTES:
        raise ValueError(f"larger than {MAX_FILE_BYTES >> 20} MB; split it")
    return b"".join(chunks)


def _path_key(path: Path) -> str:
    """The same file gives the same key, so a new import of it merges. A hash: the state names no file."""
    try:
        real = os.path.realpath(str(path))
    except (OSError, ValueError):
        real = str(path)
    return hashlib.sha256(os.path.normcase(real).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _lock():
    """One lock for every write of the imports and the state: two imports at once lost one (review of block 3)."""
    from .home import _lock_for
    return _lock_for(HOME / ".values.lock")


def _import_files() -> list:
    """(id, path) of every import, sorted by id. A folder that cannot be read raises ValuesError."""
    try:
        with os.scandir(IMPORTS) as entries:
            names = sorted(e.name for e in entries if e.name.endswith(SUFFIX))
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise ValuesError(f"{IMPORTS}: cannot be read ({type(exc).__name__})") from None
    bad = [n for n in names if not value_files.ID_RE.fullmatch(n[:-len(SUFFIX)])]
    if bad:
        # value_files.present() counts every *.jsonl: one that no import id names was renamed or put there, and its
        # values would pass unmasked (Gate A, round 1)
        raise ValuesError(f"{IMPORTS} holds a file that is no import ({len(bad)} file(s) not named v<8 hex>.jsonl), "
                          "so the imports cannot be trusted. Move it out of that folder in a terminal.")
    return [(n[:-len(SUFFIX)], IMPORTS / n) for n in names]


def _read_import(iid: str, path: Path) -> tuple[dict, list]:
    """(header, [(value, type)]) of one import. A damaged file raises ValuesError: the hooks fail closed, since the
    alternative is a silent leak of exactly the values the import lists."""
    try:
        raw = terms._read_bounded(path, MAX_IMPORT_BYTES + (64 << 10))
        if raw is None:
            raise ValueError
        lines = raw.decode("utf-8").splitlines()
        head = json.loads(lines[0])
        if not isinstance(head, dict) or head.get("import") != iid:
            raise ValueError
        items = []
        for line in lines[1:]:
            obj = json.loads(line)
            v, t = obj["v"], obj["t"]
            if not isinstance(v, str) or t not in TYPES:
                raise ValueError
            items.append((v, t))
    except (OSError, ValueError, KeyError, IndexError, TypeError, UnicodeDecodeError):
        raise ValuesError(f"import:{iid} is damaged, so its values cannot be masked. Your prompt /maisecrets:forget "
                          f"import:{iid} removes it.") from None
    return head, items


def _write_import(iid: str, head: dict, items: list) -> None:
    from .home import atomic_write
    IMPORTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = [json.dumps(head, sort_keys=True)] + [json.dumps({"v": v, "t": t}, ensure_ascii=False) for v, t in items]
    atomic_write(IMPORTS / f"{iid}{SUFFIX}", "\n".join(body) + "\n")


def _load_state() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    from .home import atomic_write
    try:
        atomic_write(STATE_FILE, json.dumps(state, sort_keys=True))
    except OSError:
        pass


# ------------------------------------------------------------------- import --
def _configured(key: str) -> bool:
    """The key is the one of a file in the person's setting `value_files`. Only such a file counts as a value file:
    `origin` is a caller's word, and a command that called this module with "file" took the places of the value
    files (Gate A, round 2)."""
    try:
        from .home import load_config
        files = load_config().get("value_files") or []
    except Exception:  # noqa: BLE001 - no config: no value file
        return False
    return any(isinstance(f, str) and f.strip() and _path_key(Path(os.path.expanduser(f.strip()))) == key
               for f in files)


def _line_bytes(value: str, type_: str) -> int:
    return len(json.dumps({"v": value, "t": type_}, ensure_ascii=False).encode("utf-8")) + 1


def import_bytes(raw: bytes, key: str, origin: str = "run", build: bool = True) -> Result:
    """Add the values of one file to an import of a command (the import of `key`, or a new one). Raises ValueError
    with a message for the person when the file itself cannot be used. Never removes a value. Only the session start
    imports a value file (_import_bytes from _sync): a caller's `origin` is ignored, so a program that calls this
    with the key of a value file and bytes of its own cannot take the places of the value files (Gate B, round 3)."""
    return _import_bytes(raw, key, "run", build)


def _import_bytes(raw: bytes, key: str, origin: str = "run", build: bool = True) -> Result:
    """import_bytes for _sync: origin "file" counts only for a file of the setting `value_files` (_configured), whose
    bytes _sync read itself. build: build the index now (a session start builds it once, after all value files)."""
    if origin == "file" and not _configured(key):
        origin = "run"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("not UTF-8 text") from None
    items, refused, duplicates = parse(text)
    result = Result(refused=list(refused), refused_count=getattr(refused, "count", len(refused)),
                    duplicates=duplicates)
    # a command's import and a value file's import of the same path are two imports: a command cannot fill the place
    # of the person's value file (Gate A, round 1)
    key = ("file:" if origin == "file" else "run:") + key
    with _lock():
        every = [(iid, path) + _read_import(iid, path) for iid, path in _import_files()]
        mine = next((x for x in every if x[2].get("key") == key), None)
        if mine is None:
            runs_n = sum(1 for x in every if x[2].get("origin") != "file")
            if origin != "file" and runs_n >= MAX_RUN_IMPORTS:
                raise ValueError(f"maisecrets holds {MAX_RUN_IMPORTS} imports of commands, their limit (the other "
                                 f"{MAX_IMPORTS - MAX_RUN_IMPORTS} places are kept for your value files); "
                                 "/maisecrets:list names them, and your prompt /maisecrets:forget import:ID "
                                 "removes one")
            if len(every) >= MAX_IMPORTS:
                raise ValueError(f"maisecrets holds {MAX_IMPORTS} imports, the limit; /maisecrets:list names them, and "
                                 "your prompt /maisecrets:forget import:ID removes one")
        # each import keeps every value it lists, also one that another import holds: a removal of that other import
        # then leaves this one whole (Gate A and Gate B, round 1). The index keeps one entry per value
        held = {terms._lower(v) for v, _t in (mine[3] if mine else [])}
        total = sum(len(x[3]) for x in every)
        runs = sum(len(x[3]) for x in every if x[2].get("origin") != "file")
        if mine is None:
            iid = "v" + secrets.token_hex(4)
            while any(x[0] == iid for x in every):
                iid = "v" + secrets.token_hex(4)
            head = {"import": iid, "key": key, "origin": origin, "at": time.time()}
            values: list = []
        else:
            iid, head, values = mine[0], dict(mine[2]), list(mine[3])
            result.merged = True
        result.id = iid
        file_origin = head.get("origin") == "file"
        size = sum(_line_bytes(v, t) for v, t in values) + 200
        for value, type_, n in items:
            if terms._lower(value) in held:
                result.known += 1
                continue
            if len(values) >= MAX_PER_IMPORT:
                why = f"at most {MAX_PER_IMPORT:,} values in one import"
            elif total >= MAX_VALUES:
                why = f"maisecrets holds {MAX_VALUES:,} imported values, the limit"
            elif size + _line_bytes(value, type_) > MAX_IMPORT_BYTES:
                why = f"one import holds at most {MAX_IMPORT_BYTES >> 20} MB"
            elif not file_origin and runs >= MAX_RUN_VALUES:
                why = (f"the imports that no value file names hold {MAX_RUN_VALUES:,} values, their limit (the rest "
                       "is kept for your value files)")
            else:
                why = ""
            if why:
                result.stopped = (f"line {n} and later not imported: {why}; /maisecrets:list names the imports, and "
                                  "your prompt /maisecrets:forget import:ID removes one")
                break
            values.append((value, type_))
            size += _line_bytes(value, type_)
            held.add(terms._lower(value))
            result.new[type_] = result.new.get(type_, 0) + 1
            total += 1
            runs += not file_origin
        if result.added or mine is None:
            if not values:
                result.id = ""        # nothing to keep: no empty import
                return result
            head["at"] = time.time()
            _write_import(iid, head, values)
    reset()
    if result.added:
        if build:
            prebuild()
        _log(result, origin)
    return result


def import_file(path, origin: str = "run") -> Result:
    path = Path(os.path.expanduser(str(path)))
    # origin "file" counts here: the bytes are the ones of that path, and _configured checks that the person set it
    return _import_bytes(read_source(path), _path_key(path), origin)


def _log(result: Result, origin: str) -> None:
    """One events.log line per import: its id, origin and counts per type, no value (review of block 3, Fable M2:
    an agent's import masked text and left no trace)."""
    from types import SimpleNamespace
    from . import events
    events.record("ValueImport", origin, [SimpleNamespace(key="import:" + result.id, type=t, kind=f"import:{n}")
                                          for t, n in sorted(result.new.items())],
                  outcome=f"added {result.added}, known {result.known}, refused {result.refused_count}")


def type_text(counts: dict) -> str:
    return ", ".join(f"{t} {counts[t]}" for t in TYPES if counts.get(t))


def summary(result: Result) -> str:
    """The line a person reads: counts, refused line numbers with reasons. No value, no file name."""
    if not result.id:
        head = "imported nothing"
    else:
        head = (f"import:{result.id}: {'added' if result.merged else 'imported'} {result.added} value(s)"
                + (f" ({type_text(result.new)})" if result.added else ""))
    parts = [head]
    if result.known:
        parts.append(f"{result.known} held already")
    if result.duplicates:
        parts.append(f"{result.duplicates} duplicate line(s) skipped")
    count = max(result.refused_count, len(result.refused))
    if count:
        shown = "; ".join(f"line {n} {why}" for n, why in result.refused[:5])
        more = f"; and {count - min(5, len(result.refused))} more" if count > 5 else ""
        parts.append(f"{count} line(s) refused: {shown}{more}")
    if result.stopped:
        parts.append(result.stopped)
    return ", ".join(parts) + "."


def rows() -> list:
    """Every import: id, count, counts per type, when, origin. Never a value."""
    out = []
    for iid, path in _import_files():
        try:
            head, items = _read_import(iid, path)
        except ValuesError:
            out.append({"id": iid, "count": 0, "types": {}, "at": 0.0, "origin": "damaged"})
            continue
        counts: dict = {}
        for _v, t in items:
            counts[t] = counts.get(t, 0) + 1
        at = head.get("at")
        out.append({"id": iid, "count": len(items), "types": counts,
                    "at": float(at) if isinstance(at, (int, float)) else 0.0, "origin": head.get("origin", "run")})
    return out


def remove_typed(ids: list) -> str:
    """Remove imports. Only the prompt hook calls this, for a prompt the person typed (hooks.user_prompt): the one way
    an import is removed. A value file's next import then reads the file as it is."""
    said = []
    with _lock():
        for iid in ids:
            if not value_files.ID_RE.fullmatch(iid):
                said.append(f"import:{iid[:20]} is no import id (/maisecrets:list shows them)")
                continue
            path = IMPORTS / f"{iid}{SUFFIX}"
            try:
                path.unlink()
            except FileNotFoundError:
                said.append(f"import:{iid} not found (/maisecrets:list shows the imports)")
                continue
            except OSError as exc:
                said.append(f"import:{iid} could not be removed ({type(exc).__name__}); nothing was changed")
                continue
            said.append(f"import:{iid} removed; its values are no longer masked")
            from . import events
            events.record_weakening("value-import", "import:" + iid, "typed prompt")
    reset()
    prebuild()
    return "maisecrets: " + "; ".join(said) + "."


# ---------------------------------------------------------------- matcher --
_CACHE: list = []    # [Matcher] or [ValuesError]


def _stat_key(files: list) -> str:
    """The key of the index: the format, the Python version and each import file's id, size, time and inode. Only
    maisecrets writes these files, each with an atomic rename, so a change gives a new key."""
    h = hashlib.sha256(f"{_FORMAT} {sys.version_info[0]}.{sys.version_info[1]}".encode())
    for iid, path in files:
        try:
            st = os.stat(path)
        except OSError as exc:
            raise ValuesError(f"import:{iid} cannot be read ({type(exc).__name__})") from None
        h.update(f"{iid}\0{st.st_size}\0{st.st_mtime_ns}\0{st.st_ino}\n".encode())
    return h.hexdigest()


def _entities(files: list) -> list:
    out = []
    seen: set = set()
    for iid, path in files:
        _head, items = _read_import(iid, path)
        for n, (value, type_) in enumerate(items, 2):
            low = terms._lower(value)
            if low in seen:
                continue          # the first import keeps a value two imports list
            seen.add(low)
            out.append(terms.Entity(type_, (terms.Variant(value, terms.WORD),), n, "import:" + iid))
    return out


def _cached(key: str):
    try:
        fmt, k, data = marshal.loads(CACHE_FILE.read_bytes())
        if fmt == _FORMAT and k == key and isinstance(data, tuple) and len(data) == 8:
            return terms.Matcher(data=data)
    except (OSError, ValueError, EOFError, TypeError):
        pass
    return None


def _store(key: str, m) -> None:
    tmp = CACHE_FILE.with_name(CACHE_FILE.name + f".{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(marshal.dumps((_FORMAT, key, m.data())))
        os.replace(tmp, CACHE_FILE)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _build():
    files = _import_files()
    if not files:
        return terms.Matcher()
    key = _stat_key(files)
    m = _cached(key)
    if m is None:
        m = terms.Matcher(_entities(files))
        _store(key, m)
    return m


def matcher():
    """The matcher of every import, built once per process. A damaged import raises at every call."""
    if not _CACHE:
        try:
            _CACHE.append(_build())
        except ValuesError as exc:
            _CACHE.append(exc)
    if isinstance(_CACHE[0], ValuesError):
        raise _CACHE[0]
    return _CACHE[0]


def reset() -> None:
    _CACHE.clear()
    value_files.forget()


def prebuild() -> None:
    """Build the index now and cache it (after an import, at session start), so a tool hook only loads it."""
    reset()
    try:
        matcher()
    except ValuesError:
        pass


def matches(text: str) -> list:
    """The hits of the imports pass (detect._import_hits, registry phase "imports"): one Match per run, of kind
    `import:<import id>:<value id>`."""
    from .detect import Match
    return [Match(f"{ent.source}:{ent.id}", ent.type, text[s:e], s, e) for s, e, ent in matcher().find(text)]


# ------------------------------------------------------------ session start --
def _record(slot: str, rec: dict) -> None:
    """Write one value file's record into the state at once, under the lock: a whole state written back at the end of
    a session start overwrote what another session did in between (Gate A, round 1)."""
    with _lock():
        state = _load_state()
        files = state.get("files") if isinstance(state.get("files"), dict) else {}
        files[slot] = rec
        state["files"] = files
        _save_state(state)


def _has_import(key: str) -> bool:
    try:
        return any(_read_import(iid, path)[0].get("key") == key for iid, path in _import_files())
    except ValuesError:
        return False


def _sync(cfg: dict, deadline: float) -> list:
    """Import each file of `value_files` whose content changed since its last import, or whose import is gone (the
    person removed it, or another session did meanwhile): the file is then imported as it is now. Notes for the
    person; a file is named by its place in the setting, never by its name."""
    files = [f for f in cfg.get("value_files") or [] if isinstance(f, str) and f.strip()]
    notes = []
    with _lock():
        state = _load_state()
    known = state.get("files") if isinstance(state.get("files"), dict) else {}
    for number, shown in enumerate(files[:MAX_FILES_PER_START], 1):
        label = f"value file {number}"
        if time.time() > deadline:
            notes.append(f"{label} and later follow at the next session start")
            break
        path = Path(os.path.expanduser(shown.strip()))
        slot = _path_key(path)
        rec = known.get(slot) if isinstance(known.get(slot), dict) else {}
        try:
            raw = read_source(path)
        except ValueError as exc:
            said = f"{label}: {exc}"
            if rec.get("said") != said:
                notes.append(said)
                _record(slot, {"said": said})
            continue
        digest = hashlib.sha256(raw).hexdigest()[:16]
        if rec.get("digest") == digest and (rec.get("empty") or _has_import("file:" + slot)):
            continue
        try:
            result = _import_bytes(raw, slot, "file", build=False)
        except ValueError as exc:
            notes.append(f"{label}: {exc}")
            continue
        _record(slot, {"digest": digest, "empty": not result.id})
        if result.added or result.refused_count or result.stopped:
            notes.append(f"{label}: " + summary(result).rstrip("."))
    if len(files) > MAX_FILES_PER_START:
        notes.append(f"only the first {MAX_FILES_PER_START} value files are read")
    return notes


def session_note(cfg: dict, started: float | None = None) -> str | None:
    """At session start: import the value files that changed, then name each import that is new since the last
    start (an import an agent ran is seen), and an import that is damaged. Unchanged, it says nothing."""
    deadline = (started if started is not None else time.time()) + 8.0
    notes = _sync(cfg, deadline)
    every = rows()
    ids = sorted(r["id"] for r in every)
    with _lock():
        state = _load_state()
        before = state.get("announced")
        state["announced"] = ids
        _save_state(state)
    new = [r for r in every if r["id"] not in set(before or [])]
    parts = []
    if notes:
        parts.append("value files: " + "; ".join(notes) + ".")
    if new:
        shown = ", ".join(f"import:{r['id']} ({r['count']} value(s))" for r in new[:5])
        more = f" and {len(new) - 5} more" if len(new) > 5 else ""
        parts.append(f"from now on maisecrets masks the values of {shown}{more}. /maisecrets:list shows each "
                     "import; your prompt /maisecrets:forget import:ID removes one.")
    damaged = [r["id"] for r in every if r["origin"] == "damaged"]
    if damaged:
        parts.append(f"import:{damaged[0]} is damaged, so maisecrets withholds every tool result until your prompt "
                     f"/maisecrets:forget import:{damaged[0]} removes it.")
    prebuild()
    return ("maisecrets: " + " ".join(parts)) if parts else None


def summary_line() -> str:
    """One line for /maisecrets:status and /maisecrets:rules: imports and values, no value."""
    try:
        every = rows()
    except ValuesError as exc:
        return f"imported values: unusable ({exc})"
    return f"imported values: {sum(r['count'] for r in every)} in {len(every)} import(s)"
