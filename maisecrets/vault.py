"""The local vault: put, get, list, expire.

Values live in a backend. Metadata (type, fingerprint, created, last used,
expiry, display) lives in an index file under ``~/.maisecrets/`` that never
holds a value. When an entry expires, the value is deleted and the metadata
stays as a record of what went through.

Backends:
  * ``JsonFileBackend`` -- Day-1 test mode. Plaintext JSON, mode 0600, under
    ``~/.maisecrets/``. Never in a project directory. Marked ``test_mode``.
  * ``KeychainBackend`` -- macOS ``security`` CLI, generic passwords under one
    service name, no ``synchronizable`` flag, so nothing reaches iCloud.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import platform
import subprocess
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from .lazy_regex import LazyRx
from .placeholder import display_for

# the home folder and the configuration live in home.py; these names stay importable from here
from .home import (  # noqa: F401
    CONFIG, CodedError, ConfigError, DEFAULT_CONFIG, HOME, LockTimeout, POLICY_PATHS, WrongHome, _CONFIG_CHOICES,
    _CONFIG_TYPES, _DEFAULT_HOME, _LOCKS, _Lock, _SAFETY_KEYS, _STRICTNESS, _check_home, _check_types,
    _keep_the_stricter, _lock_for, _looks_misspelled, _note_user_config, _old_region_key, _read_fallback,
    _within_default_home, atomic_write, load_config, read_text_retry, windows_user_mismatch
)
INDEX = HOME / "index.json"
# The keychain namespace is per service name, not per vault home. A second home
# (tests, the harness, a latency run) minted SECRET_c1 too and a cleanup deleted
# the real SECRET_c1 (2026-09-26). So every home other than the default gets its
# own service name.
SERVICE = "maisecrets" if HOME == _DEFAULT_HOME else "maisecrets@" + hashlib.sha256(str(HOME).encode()).hexdigest()[:8]


def describe_backend(backend) -> str:
    """One line for a human: which store, where, and how to change it."""
    name = type(backend).__name__
    where = {
        "KeychainBackend": f"macOS login keychain, service '{SERVICE}' (Keychain Access shows the entries)",
        "WindowsVaultBackend": f"Windows Credential Locker, resource '{SERVICE}' (Settings > Credential Manager)",
        "EncryptedFileBackend": f"encrypted file {HOME / 'vault.enc.json'} (openssl, key file {HOME / 'key'})",
        "JsonFileBackend": f"PLAINTEXT file {HOME / 'vault.json'} - TEST MODE, not for real secrets",
    }.get(name, name)
    return (f"Stored values: {where}. Metadata: {INDEX}. "
            f"To change it: write {{\"backend\": \"encrypted-file\"}} to {CONFIG} (takes effect on the next call). "
            "Free and open source, by mcpgate.de.")


def intro_line(backend) -> str:
    """The first session start, for a person: what maisecrets does and where values stay. The
    paths, the backend switch and the file names are in /maisecrets:status (UX review,
    2026-09-27: JSON and file paths at the first start told a non-developer to change a setting
    their IT owns)."""
    where = {
        "KeychainBackend": "in the macOS Keychain",
        "WindowsVaultBackend": "in the Windows Credential Locker",
        "EncryptedFileBackend": "in an encrypted file",
        "JsonFileBackend": "in a PLAIN TEXT test file (test mode, not for real secrets)",
    }.get(type(backend).__name__, "in the local store")
    return (f"It keeps passwords, keys and personal data out of the AI: a prompt that holds one is "
            f"stopped, and the value stays on this computer, {where}.")


FP_KEY_ENTRY = "_maisecrets_fpkey"   # backend key that holds the fingerprint key (32 random bytes, hex)


def fingerprint(value: str, key: bytes) -> str:
    """Keyed fingerprint. An unkeyed hash of a short value (a phone number, a PIN) can
    be reversed by trying every candidate against the index file; the key lives in the
    backend, so the index alone gives nothing to try against."""
    import hmac
    return hmac.new(key, value.encode(), "sha256").hexdigest()[:16]


@dataclass
class Entry:
    key: str            # EMAIL_c1
    type: str           # EMAIL
    kind: str           # pattern name that found it
    fingerprint: str
    display: str | None
    created: float
    last_used: float
    expires: float
    max_expires: float
    session: str | None = None          # the session that created the entry
    uses: int = 0
    purged: bool = False
    counters: dict = field(default_factory=dict)  # unused on entries; kept for schema stability
    sessions: list = field(default_factory=list)  # sessions allowed to resolve the entry (see Vault.get)
    # a word that only a label rule found (letters only): replaced where it was found, never hunted in other texts
    weak: bool = False
    # a word that a label rule took in a tool result or a file: hunted in later tool results, never in a typed prompt,
    # where it would block every prompt that uses the word (field report on 0.6.16). Only a new entry gets it
    quiet: bool = False
    # no purged_at field: from_meta drops it, so the proof below can remove the filter and
    # the owning test sees the TypeError of the field report again

    @classmethod
    def from_meta(cls, meta: dict) -> "Entry":
        """An Entry from an index record, ignoring fields this version does not know. expire wrote
        `purged_at` into the index while Entry had no such field, so every read of an expired
        entry raised TypeError: /maisecrets:status and list failed, and a value pasted again after
        it expired blocked the prompt (field report, 2026-09-27). A record written by a newer
        version must not break an older one either."""
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in meta.items() if k in names})

    @property
    def ref(self) -> str:
        from .placeholder import CLOSE, OPEN
        return f"{OPEN}{self.key}:{self.display}{CLOSE}" if self.display else f"{OPEN}{self.key}{CLOSE}"


# the default passwords of services and the words that follow a label in code and docs: hunting one of them in
# every later text redacted `docker ps` and blocked "add a postgres service" (review, 2026-09-29). Only these are
# weak: a random lower-case value such as xqzvbnmq is a secret wherever it shows up (Codex review, 2026-09-29)
DEFAULT_WORDS = frozenset({
    "postgres", "postgresql", "mysql", "mariadb", "redis", "mongo", "mongodb", "rabbitmq", "guest", "elastic",
    "kibana", "grafana", "minio", "minioadmin", "keycloak", "oracle", "admin", "administrator", "root", "user",
    "users", "test", "tester", "testing", "demo", "default", "secret", "password", "passwort", "changeme",
    "example", "sample", "docker", "ubuntu", "raspberry", "letmein", "welcome", "qwerty", "plaintext", "candidate",
    "unchanged", "sentinel", "credentials", "identifier", "whitespace", "previous", "lookahead", "encrypted",
    "forbidden", "refreshed", "temporary", "operator", "punctuation", "tokenizer", "nexttoken", "token", "tokens",
    "required", "optional", "database", "service", "server", "client", "local", "localhost", "development",
    "production", "staging", "mindestens", "unbedingt", "vergessen", "unbekannt", "abgelaufen", "erforderlich",
    "geheim", "kennwort",
    # the word for password in other languages, compared without accents (_folded): a list of label translations
    # in a tool result stored the word for password itself, and it was hunted in every later tool result
    # (field report, 2026-10-25)
    "senha", "heslo", "geslo", "lozinka", "sifre", "haslo", "parola", "parool", "salasana", "jelszo", "losenord",
    "passord", "adgangskode", "wachtwoord", "contrasena", "motdepasse", "sifra", "parole", "geheimnis"})


def _folded(value: str) -> str:
    """``value`` in lower case without accents: Contraseña gives contrasena, hasło gives haslo."""
    import unicodedata
    v = unicodedata.normalize("NFKD", value.strip().lower().replace("ł", "l").replace("ı", "i"))
    return "".join(c for c in v if not unicodedata.combining(c))


_DICT_PART_RE = LazyRx(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")


def is_dictionary_word(value: str) -> bool:
    """Whether every part of a value (split at _ - . and at a change to capitals) is an English word of the word list
    or of the developer words of rules/term_stoplist.txt, also with a plural s. credential, response and
    passwordLastChanged are; ppsmohsyeeub, Wartungsfenster and Kx7QpZr9 are not. A label rule that took such a word in
    a tool result stores it weak (is_weak): one session masked a few ordinary words thousands of times a day in
    code and prose, and a codex review prompt with one of them was refused (field report, 2026-10-17)."""
    from .detect import english_words, reads_as_word
    v = value.strip()
    if not v or len(v) > 60 or not v.isascii() or not reads_as_word(v):
        return False
    words = english_words()
    if not words:
        return False   # no word list: hunt the value, as before
    from .terms import stoplist
    known = words | stoplist()
    parts = [w.lower() for p in re.split(r"[_.-]+", v) if p for w in _DICT_PART_RE.findall(p)]
    if not parts or "".join(parts) != re.sub(r"[_.-]+", "", v).lower():
        return False
    return all(len(w) >= 2 and _known_word(w, known) for w in parts)


# English endings and what the base word ends with before them (comparing: compare, specifically: specific). The
# list holds base words of 4 to 8 letters, and a hunted value has 8 letters or more: without the endings 25 of 28
# common prose words were no dictionary words, and a label rule's hit on one was hunted in every later tool result
# (field report, 2026-10-25)
_ENDINGS = (("ically", ("ic",)), ("ally", ("", "al")), ("ily", ("y",)), ("ly", ("", "le")), ("ies", ("y",)),
            ("ied", ("y",)), ("ier", ("y",)), ("ing", ("", "e")), ("ed", ("", "e")), ("ers", ("", "e")),
            ("er", ("", "e")), ("est", ("", "e")), ("es", ("",)), ("s", ("",)), ("ations", ("e", "")),
            ("ation", ("e", "")), ("ions", ("", "e")), ("ion", ("", "e")), ("ness", ("",)), ("ments", ("",)),
            ("ment", ("",)), ("ful", ("",)), ("less", ("",)), ("ity", ("", "e")), ("ive", ("", "e")),
            ("able", ("", "e")), ("ible", ("", "e")), ("al", ("",)), ("ance", ("", "e")), ("ence", ("", "e")),
            ("ant", ("", "e")), ("ent", ("", "e")), ("ise", ("", "y")), ("ize", ("", "y")), ("ised", ("", "y")),
            ("ized", ("", "y")), ("ising", ("", "y")), ("izing", ("", "y")))


def _known_word(w: str, known, depth: int = 2) -> bool:
    """Whether ``w`` is a word of ``known``, a word of it with an English ending (two at most: configurations), or
    two words of at least 4 letters each (benchmark: bench + mark)."""
    if w in known:
        return True
    if depth:
        for end, bases in _ENDINGS:
            if w.endswith(end) and len(w) - len(end) >= 3:
                stem = w[:-len(end)]
                if any(_known_word(stem + b, known, depth - 1) for b in bases):
                    return True
                # a doubled last consonant: running, stopped
                if len(stem) >= 4 and stem[-1] == stem[-2] and stem[-1] not in "aeiou" and stem[:-1] in known:
                    return True
    return any(w[:i] in known and w[i:] in known for i in range(4, len(w) - 3))


def code_word_spellings() -> list[str]:
    """The spellings of a code word (detect.code_words) that a keyword rule stored before 0.5.15. The vault finds a
    stored one by its fingerprint and reads no value (Vault.quiet_code_words)."""
    from .detect import code_words
    return [s for w in sorted(code_words()) for b in (w, w.capitalize(), w.upper()) for s in (b, b + ";")]


def is_weak(kind: str, value: str, tool: bool = False) -> bool:
    """A value that only a label rule found and that is a known default word (DEFAULT_WORDS), or, in a tool result or
    a file (tool), an English word (is_dictionary_word): replaced where it was found, never hunted in other
    texts. A word the person gives in a prompt is a chosen password and stays hunted (is_quiet)."""
    from .registry import is_label
    if not is_label(kind):
        return False
    if _folded(value) in DEFAULT_WORDS:
        return True
    return tool and is_dictionary_word(value)


def is_quiet(kind: str, value: str, tool: bool) -> bool:
    """A word of some language (detect.reads_as_word) that a label rule took in a tool result or a file: hunted in
    later tool results as before (a weak default word is not hunted at all, as in 0.6.16), never in a typed prompt.
    A word the person gives in a prompt stays hunted everywhere: a chosen word is a password there (review,
    2026-09-29). A random value that reads like a word (about 3 in 100 of 8 small letters) is then not looked for in
    a prompt that types it bare; it is still masked in every tool result. Only a new entry gets the mark."""
    from .detect import reads_as_word
    from .registry import is_label
    return tool and is_label(kind) and reads_as_word(value.strip())


# ---------------------------------------------------------------- backends --
class JsonFileBackend:
    test_mode = True

    def __init__(self) -> None:
        self.path = HOME / "vault.json"

    def _load(self, for_write: bool = False) -> dict:
        try:
            return json.loads(read_text_retry(self.path))
        except OSError:
            return {}
        except ValueError:
            if for_write:
                raise CodedError("vault store file unreadable; not overwritten", "store.file-read", "parse")
            return {}

    def _save(self, data: dict) -> None:
        atomic_write(self.path, json.dumps(data))

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        d = self._load(for_write=True)
        d[key] = value
        self._save(d)

    def get(self, key: str) -> str | None:
        return self._load().get(key)

    def delete(self, key: str) -> None:
        d = self._load(for_write=True)
        d.pop(key, None)
        self._save(d)

    def keys(self) -> list[str]:
        return list(self._load())


def parse_keychain_dump(text: str, service: str) -> list[str]:
    """The account names of every item of ``service`` in a `security dump-keychain` listing
    (attributes only). An item starts at a `keychain:` line; inside it the attributes are
    alphabetical, so "acct" comes before "svce"."""
    out: list[str] = []
    acct = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("keychain:"):
            acct = None
        elif line.startswith('"acct"<blob>='):
            acct = line.split("=", 1)[1].strip('"')
        elif line.startswith('"svce"<blob>=') and line.split("=", 1)[1].strip('"') == service and acct:
            out.append(acct)
    return out


_TIMEOUT_CODES = {"keychain": "store.timeout-keychain", "openssl": "store.timeout-openssl",
                  "Credential Locker": "store.timeout-locker"}


def _run_store(what: str, args: list[str], **kw) -> subprocess.CompletedProcess:
    """subprocess.run for a store call. A call that hits its timeout raised TimeoutExpired, which
    passed every `except RuntimeError` of the sweep, forget and wipe, and whose text lists the
    argv, the value included on the keychain's long-value path (CLI test agent, 2026-09-27)."""
    if not kw.get("capture_output"):
        # a store tool must never write to the hook's own stdout or stderr: the client reads the hook's answer there,
        # and a child that keeps them open holds the client (Gate A of 0.6.15)
        kw.setdefault("stdout", subprocess.PIPE)
        kw.setdefault("stderr", subprocess.PIPE)
    try:
        return subprocess.run(args, **kw)
    except subprocess.TimeoutExpired:
        raise CodedError(f"{what} call timed out", _TIMEOUT_CODES.get(what, "store.timeout-keychain"),
                         "timeout") from None


class KeychainBackend:
    """macOS login keychain via the ``security`` CLI. No sync flag is set."""
    test_mode = False

    MAX_LINE = 3900   # `security -i` line limit is 4096 bytes; the rest would run as a command

    @staticmethod
    def _q(s: str) -> str:
        """Quote one argument for the `security -i` command reader (double quotes, backslash escapes)."""
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def _interactive(self, line: str) -> subprocess.CompletedProcess:
        # `security -i` reads commands from stdin, so the value never sits on a command line where
        # `ps` of any local user shows it during the call (review, 2026-09-26)
        return _run_store("keychain", ["security", "-i"], input=(line + "\n").encode("utf-8"),
                              capture_output=True, timeout=5)

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        # -l is the "Name" column in Keychain Access, -j the comment shown in the item's info.
        # The item's ACL trusts /usr/bin/security, the tool that created it, so ANY process of
        # this user that runs `security find-generic-password` reads the value without a dialog
        # (review 2026-09-26). The keychain protects the value at rest and from
        # other users, not from this user's other processes. The gates are in the hooks.
        # No synchronizable flag: the item never joins iCloud Keychain or the Passwords app.
        # the value is stored base64-encoded with a marker: `find-generic-password -w` prints a
        # non-ASCII value as hex, so an umlaut never came back equal (measured 2026-09-26)
        import base64
        stored = "b64:" + base64.b64encode(value.encode("utf-8")).decode("ascii")
        parts = ["add-generic-password", "-U", "-s", self._q(SERVICE), "-a", self._q(key),
                 "-l", self._q(label or f"maisecrets {key}"), "-D", self._q("maisecrets placeholder"),
                 "-w", self._q(stored)]
        if comment:
            parts += ["-j", self._q(comment)]
        # no check=True: CalledProcessError prints the argument list, and an error text can reach
        # the model as a block reason (Codex review, 2026-09-26)
        line = " ".join(parts)
        if len(line.encode("utf-8")) <= self.MAX_LINE:
            r = self._interactive(line)
        else:
            # `security -i` reads at most 4096 bytes per line and runs the rest as a second
            # command (review, 2026-09-26: a 4096-bit PEM key). A long value goes on the
            # command line instead: the value is then visible to `ps` of any local user for the
            # milliseconds of the call, the trade documented in the README
            r = _run_store("keychain", ["security", "add-generic-password", "-U", "-s", SERVICE, "-a", key,
                                "-l", label or f"maisecrets {key}", "-D", "maisecrets placeholder",
                                "-w", stored] + (["-j", comment] if comment else []),
                               capture_output=True, timeout=5)
        if r.returncode != 0:
            raise CodedError(f"keychain add failed (rc {r.returncode})", "store.keychain-add", "rc", r.returncode)
        if self.get(key) != value:
            raise CodedError("keychain add failed (read-back differs)", "store.keychain-readback", "shape")

    def get(self, key: str) -> str | None:
        r = _run_store(
            "keychain",
            ["security", "find-generic-password", "-s", SERVICE, "-a", key, "-w"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return None
        raw = r.stdout.rstrip("\n")
        if raw.startswith("b64:"):
            import base64
            try:
                return base64.b64decode(raw[4:]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return None
        return raw   # an entry written before 0.3.22

    def delete(self, key: str) -> None:
        r = _run_store(
            "keychain",
            ["security", "delete-generic-password", "-s", SERVICE, "-a", key],
            capture_output=True, timeout=5,
        )
        # rc 44: no such item, which is the wanted end state; anything else keeps the entry
        # unpurged so the next sweep tries again (review, 2026-09-26)
        if r.returncode not in (0, 44):
            raise RuntimeError(f"keychain delete failed (rc {r.returncode})")

    def keys(self) -> list[str]:
        """Every account of the service, from the attribute dump (no secrets are printed without
        -d), so a damaged index can be rebuilt and an orphan item found (review, 2026-09-26)."""
        r = _run_store("keychain", ["security", "dump-keychain"], capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return []
        return parse_keychain_dump(r.stdout, SERVICE)

    def wipe(self) -> int:
        """Delete every item of the service, one call per item until none is left: the store is
        enumerated by deleting, so an item whose index entry is gone goes too. Raises when an
        item refuses to go (a locked keychain), so the caller never reports a wipe that did not
        happen."""
        n = 0
        for _ in range(10000):
            r = _run_store("keychain", ["security", "delete-generic-password", "-s", SERVICE],
                               capture_output=True, timeout=5)
            if r.returncode == 44:
                break
            if r.returncode != 0:
                raise RuntimeError(f"keychain delete failed (rc {r.returncode})")
            n += 1
        return n


class EncryptedFileBackend:
    """Linux servers and anywhere without a keychain: values encrypted at rest with
    ``openssl enc`` (AES-256-CBC, PBKDF2) plus an HMAC-SHA256 tag, key in a 0600 file.

    The key file is ``~/.maisecrets/key`` or ``$MAISECRETS_KEY_FILE`` (a root-managed
    path on a server). Without the key the vault file is noise. This is not a
    hardware-backed store: a process running as the same user can read the key,
    exactly as it could read the keychain on a Mac.
    """
    test_mode = False

    def __init__(self) -> None:
        self.path = HOME / "vault.enc.json"
        self.key_file = Path(os.environ.get("MAISECRETS_KEY_FILE", HOME / "key"))

    def _key(self) -> bytes:
        if not self.key_file.exists():
            self.key_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(os.urandom(32).hex() + "\n")
        return self.key_file.read_bytes().strip()

    def _openssl(self, args: list[str], data: bytes) -> bytes:
        r = _run_store("openssl", ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000", "-salt",
                            "-pass", f"file:{self.key_file}", *args], input=data, capture_output=True, timeout=5)
        if r.returncode != 0:
            raise CodedError("openssl failed: " + r.stderr.decode(errors="ignore")[:200], "store.openssl", "rc",
                             r.returncode)
        return r.stdout

    def _tag(self, blob: bytes) -> str:
        import hmac
        return hmac.new(hashlib.sha256(b"maisecrets-mac:" + self._key()).digest(), blob, "sha256").hexdigest()

    def _load(self, for_write: bool = False) -> dict:
        try:
            return json.loads(read_text_retry(self.path))
        except OSError:
            return {}
        except ValueError:
            # a damaged vault file must not be replaced by one with a single new entry: every
            # other value would be lost without a message (review, 2026-09-26)
            if for_write:
                raise CodedError("vault store file unreadable; not overwritten", "store.file-read", "parse")
            return {}

    def _save(self, data: dict) -> None:
        atomic_write(self.path, json.dumps(data))

    def keys(self) -> list[str]:
        return list(self._load())

    def wipe(self) -> int:
        n = len(self._load())
        for f in (self.path, self.key_file):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                # a file that stays holds the values: never count it as wiped
                raise RuntimeError(f"{f.name} not deleted ({type(exc).__name__})") from exc
        return n

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        import base64
        self._key()
        blob = self._openssl([], value.encode())
        d = self._load(for_write=True)
        d[key] = {"c": base64.b64encode(blob).decode(), "t": self._tag(blob)}
        self._save(d)

    def get(self, key: str) -> str | None:
        import base64
        import hmac
        entry = self._load().get(key)
        if not entry:
            return None
        blob = base64.b64decode(entry["c"])
        if not hmac.compare_digest(self._tag(blob), entry.get("t", "")):
            return None   # tampered or foreign key: fail closed
        try:
            return self._openssl(["-d"], blob).decode()
        except RuntimeError as exc:
            from . import incidents
            incidents.note("store.decrypt", exc)
            return None

    def delete(self, key: str) -> None:
        d = self._load(for_write=True)
        d.pop(key, None)
        self._save(d)


class WindowsVaultBackend:
    """Windows: the per-user Credential Locker (``Windows.Security.Credentials.PasswordVault``),
    DPAPI-backed, reached through PowerShell. No module to install; the entries show up in
    Settings > Credential Manager under the resource name ``maisecrets``."""
    test_mode = False
    _PRELUDE = ("[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]"
                " | Out-Null; $v = New-Object Windows.Security.Credentials.PasswordVault; ")

    def _ps(self, script: str, stdin: str = "") -> subprocess.CompletedProcess:
        return _run_store("Credential Locker",
                          ["powershell", "-NoProfile", "-NonInteractive", "-Command", self._PRELUDE + script],
                          input=stdin, capture_output=True, text=True, timeout=15)

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        # the value travels via stdin as base64, never as a command-line argument and never as
        # text the console code page could re-encode (review, 2026-09-26: Windows PowerShell 5.1
        # reads a redirected stdin in the OEM code page)
        import base64
        b64 = base64.b64encode(value.encode("utf-8")).decode("ascii")
        r = self._ps("$b = [Console]::In.ReadToEnd().Trim(); "
                     "$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)); "
                     f"try {{ $old = $v.Retrieve('{SERVICE}', '{key}'); $v.Remove($old) }} catch {{}}; "
                     f"$v.Add((New-Object Windows.Security.Credentials.PasswordCredential('{SERVICE}', '{key}', $p)))",
                     stdin=b64)
        if r.returncode != 0:
            raise CodedError(f"PasswordVault add failed (rc {r.returncode})", "store.locker-add", "rc", r.returncode)

    def get(self, key: str) -> str | None:
        import base64
        r = self._ps(f"try {{ $c = $v.Retrieve('{SERVICE}', '{key}'); $c.RetrievePassword(); "
                     "[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($c.Password))) } "
                     "catch { exit 3 }")
        if r.returncode != 0:
            return None
        try:
            return base64.b64decode(r.stdout.strip()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    def delete(self, key: str) -> None:
        self._ps(f"try {{ $v.Remove($v.Retrieve('{SERVICE}', '{key}')) }} catch {{}}")

    def keys(self) -> list[str]:
        r = self._ps(f"try {{ $v.FindAllByResource('{SERVICE}') | ForEach-Object {{ $_.UserName }} }} catch {{}}")
        return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()] if r.returncode == 0 else []

    def get_many(self, keys: list[str]) -> dict[str, str]:
        """All values in one PowerShell start (each start costs hundreds of milliseconds; one
        per key on every tool result reached the watchdog; review, 2026-09-26)."""
        import base64
        if not keys:
            return {}
        wanted = ",".join("'" + k + "'" for k in keys if re.fullmatch(r"[A-Z][A-Z_]*_c\d{1,9}", k))
        r = self._ps("foreach ($k in @(" + wanted + ")) { try { "
                     f"$c = $v.Retrieve('{SERVICE}', $k); $c.RetrievePassword(); "
                     "[Console]::Out.WriteLine($k + ' ' + "
                     "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($c.Password))) "
                     "} catch {} }")
        out: dict[str, str] = {}
        if r.returncode != 0:
            return out
        for ln in r.stdout.splitlines():
            k, _sp, b = ln.strip().partition(" ")
            try:
                out[k] = base64.b64decode(b).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass
        return out

    def wipe(self) -> int:
        keys = self.keys()
        for k in keys:
            self.delete(k)
        return len(keys)


def make_backend(cfg: dict):
    """keychain on macOS; an openssl-encrypted file elsewhere; jsonfile only when asked (test mode)."""
    _check_home()
    backend = cfg.get("backend", "keychain")
    if backend == "jsonfile":
        return JsonFileBackend()
    if backend == "encrypted-file":
        return EncryptedFileBackend()
    if backend == "windows-vault":
        return WindowsVaultBackend()
    if platform.system() == "Darwin":
        return KeychainBackend()
    if platform.system() == "Windows":
        return WindowsVaultBackend()
    return EncryptedFileBackend()


def _mutating(fn):
    """Run the method as one read-modify-write under the vault lock."""
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._exclusive():
            return fn(self, *args, **kwargs)
    return wrapper


class _Mutation:
    def __init__(self, vault: "Vault") -> None:
        self.vault = vault

    def __enter__(self):
        self.vault._lock.__enter__()
        if self.vault._lock.depth == 1:
            try:
                self.vault._index = self.vault._load_index()
            except BaseException:
                # `with` calls __exit__ only after __enter__ returned: a damaged index kept the lock
                self.vault._lock.__exit__(None, None, None)
                raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None and self.vault._lock.depth == 1:
                self.vault._save_index()
        finally:
            self.vault._lock.__exit__(exc_type, exc, tb)


# ------------------------------------------------------------------- vault --
class Vault:
    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or load_config()
        self.last_refused = 0      # deletes the store refused in the last expire sweep
        self.backend = make_backend(self.cfg)
        self._lock = _lock_for(HOME / ".lock")
        self._index = self._load_index()

    def _exclusive(self):
        """Lock, re-read the index (another process may have written it), and save on exit:
        every mutation is a read-modify-write under the lock, so no update is lost."""
        return _Mutation(self)

    # index -----------------------------------------------------------------
    def _load_index(self) -> dict:
        if not INDEX.exists():
            return {"entries": {}, "counters": {}, "by_fingerprint": {}}
        try:
            data = json.loads(read_text_retry(INDEX))
        except ValueError as exc:
            # a damaged index must not become an empty one: the counters would restart and the
            # next put would overwrite SECRET_c1 in the store. The file stays in place, so every
            # later call raises too (moving it away made the guard last one call; review,
            # 2026-09-26). `maisecrets repair` rebuilds the counters from the store.
            from .notices import launcher
            raise CodedError(f"its list of stored values ({INDEX.name}) is damaged. Until it is repaired, nothing is "
                             f"stored or put into a command. To repair it, run {launcher()} repair in a terminal",
                             "store.index-read", "parse") from exc
        if not isinstance(data, dict) or "entries" not in data:
            raise CodedError("vault index has an unexpected shape", "store.index-shape", "shape")
        return data

    def _save_index(self) -> None:
        atomic_write(INDEX, json.dumps(self._index, indent=1))

    def _ttl_for(self, type_: str) -> int:
        ttls = self.cfg.get("ttl_seconds", {})
        return int(ttls.get(type_, ttls.get("default", 86400)))

    _fpkey_cache: bytes | None = None

    def fp_key(self) -> bytes:
        """The fingerprint key, created on first use and kept in the backend, never in the index."""
        if self._fpkey_cache is None:
            raw = self.backend.get(FP_KEY_ENTRY)
            if not raw:
                raw = os.urandom(32).hex()
                self.backend.put(FP_KEY_ENTRY, raw, label="maisecrets fingerprint key",
                                 comment="maisecrets: key for the fingerprints in index.json; not a placeholder value.")
            self._fpkey_cache = bytes.fromhex(raw.strip())
        return self._fpkey_cache

    def fingerprint(self, value: str) -> str:
        return fingerprint(value, self.fp_key())

    def live_fingerprints(self, prompt: bool = False) -> dict[str, str]:
        """fingerprint -> key for every entry whose value is still stored and may be hunted in any text. A weak entry
        is not: `DB_PASSWORD=postgres` stored `postgres`, and every later text with the word was redacted and every
        prompt with it blocked, in every session, for a day (review, 2026-09-29). In a typed prompt (prompt=True) a
        quiet entry is not hunted either (Entry.quiet)."""
        return {m["fingerprint"]: k for k, m in self._index["entries"].items()
                if not m.get("purged") and not m.get("weak") and not (prompt and m.get("quiet"))}

    @_mutating
    def weaken_quiet_words(self) -> int:
        """Mark weak the live quiet entries (a label rule took them in a tool result) that are English words
        (is_dictionary_word) or default words (DEFAULT_WORDS). Before 0.6.38 such a word was hunted in every later
        tool result for a day. Reads the value of each such entry once; a store that refuses the read leaves it as it
        is. Returns the count."""
        todo = [k for k, m in self._index["entries"].items()
                if m.get("quiet") and not m.get("weak") and not m.get("purged")]
        n = 0
        for key in todo:
            try:
                value = self.backend.get(key)
            except RuntimeError as exc:
                from . import incidents
                incidents.note("store.mark-weak", exc)
                continue
            if value is not None and (is_dictionary_word(value) or _folded(value) in DEFAULT_WORDS):
                self._index["entries"][key]["weak"] = True
                n += 1
        return n

    @_mutating
    def mark_weak_entries(self) -> int:
        """Mark the weak entries a version before 0.5.15 stored without the mark (see Entry.weak). Reads the value of
        each unmarked label-rule entry once; a store that refuses the read leaves the entry unmarked for the next
        start. Returns the count marked weak."""
        from .registry import is_label
        todo = [k for k, m in self._index["entries"].items()
                if "weak" not in m and not m.get("purged") and is_label(m.get("kind", ""))]
        n = 0
        for key in todo:
            try:
                value = self.backend.get(key)
            except RuntimeError as exc:
                from . import incidents
                incidents.note("store.mark-weak", exc)
                continue
            if value is None:
                continue
            weak = is_weak(self._index["entries"][key]["kind"], value)
            self._index["entries"][key]["weak"] = weak
            n += weak
        return n

    # api -------------------------------------------------------------------
    @_mutating
    def put(self, value: str, type_: str, kind: str, session: str | None = None,
            ttl: int | None = None) -> Entry:
        """Store a value; the same live value yields the same reference."""
        self.expire()
        fp = self.fingerprint(value)
        existing = self._index["by_fingerprint"].get(fp)
        if existing and not self._index["entries"][existing].get("purged"):
            e = Entry.from_meta(self._index["entries"][existing])
            if session and session not in e.sessions:
                e.sessions.append(session)
            e.quiet = False             # a value given outside a tool result: hunted in prompts again
            e.weak = e.weak and is_weak(kind, value)   # and in every text, unless it is a default word
            self._touch(e)
            return e
        e = self._put_new(value, type_, kind, session, ttl)
        self._save_index()
        return e

    def _put_new(self, value: str, type_: str, kind: str, session: str | None, ttl: int | None,
                 tool: bool = False) -> "Entry":
        fp = self.fingerprint(value)
        n = self._index["counters"].get(type_, 0) + 1
        self._index["counters"][type_] = n
        key = f"{type_}_c{n}"
        now = time.time()
        ttl = min(ttl or self._ttl_for(type_), int(self.cfg.get("max_ttl_seconds", 30 * 86400)))
        e = Entry(key=key, type=type_, kind=kind, fingerprint=fp,
                  # a term (terms.py) stores its entity id, not the term: a display of that would mean nothing
                  display=None if kind.startswith(("term:", "import:")) else display_for(type_, value),
                  created=now, last_used=now,
                  expires=now + ttl, max_expires=now + int(self.cfg.get("max_ttl_seconds", 30 * 86400)),
                  session=session, uses=0, sessions=[session] if session else [],
                  weak=is_weak(kind, value, tool), quiet=is_quiet(kind, value, tool))
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(now))
        self.backend.put(
            key, value,
            label=f"maisecrets {key} ({kind})",
            comment=f"maisecrets placeholder {e.ref}. type={type_} kind={kind} created={created} "
                    f"ttl={ttl}s fingerprint={fp}. Value is inserted only into the real call.",
        )
        self._index["entries"][key] = asdict(e)
        self._index["by_fingerprint"][fp] = key
        return e

    @_mutating
    def put_many(self, items: list[tuple[str, str, str]], session: str | None = None,
                 tool: bool = False) -> list["Entry | None"]:
        """Store many values in one lock, one sweep and one index save; a tool result with
        hundreds of addresses called put() per value and rewrote the growing index each time
        (measured: 1000 e-mails 8.7 s, above the watchdog; review, 2026-09-26). Above
        `max_new_entries_per_result` new values, the rest is not stored: None in the result,
        the caller masks the value without a key."""
        self.expire()
        cap = int(self.cfg.get("max_new_entries_per_result", 100))
        out: list[Entry | None] = []
        new = 0
        dirty = False
        for value, type_, kind in items:
            fp = self.fingerprint(value)
            existing = self._index["by_fingerprint"].get(fp)
            if existing and not self._index["entries"][existing].get("purged"):
                e = Entry.from_meta(self._index["entries"][existing])
                if session and session not in e.sessions:
                    e.sessions.append(session)
                if not tool:
                    e.quiet = False     # a value the person gives in a prompt is hunted in prompts again
                    # a word a tool result stored weak is a chosen password once the person gives it (field report,
                    # 2026-10-25: the weak words of the list grew from base words to words with endings)
                    e.weak = e.weak and is_weak(kind, value)
                # a tool result keeps the mark of an existing entry. An entry without one (stored by an older version,
                # or a mark an older process dropped) reads as quiet=False and stays hunted: its origin is unknown,
                # and only a new entry from a tool result is known to come from one (final codex review of 0.6.17)
                self._touch(e, save=False)
                dirty = True
                out.append(e)
                continue
            if new >= cap:
                out.append(None)
                continue
            out.append(self._put_new(value, type_, kind, session, None, tool))
            new += 1
            dirty = True
            if new % 10 == 0:
                self._save_index()   # a watchdog exit mid-way leaves at most ten unnamed store items
        if dirty:
            self._save_index()
        return out

    def status(self, key: str, session: str | None = None) -> str:
        """ok | unknown | expired | no-session | foreign-session, without reading the value.

        A reference resolves only in a session that saw it come in: the session that
        created the entry, or one where a human typed the reference into a prompt
        (``admit``). Keys are counters, so a reference an agent never saw is guessable;
        without this rule an injected instruction could name ``SECRET_c1`` and have it
        resolved (review of the agent channel, 2026-09-26).
        """
        meta = self._index["entries"].get(key)
        if meta is None:
            return "unknown"
        if meta.get("purged") or meta["expires"] < time.time():
            return "expired"
        if session is None:
            return "no-session"
        # the creating session always counts; entries written before 0.3.0 have `session` but no
        # `sessions` list (a 0.2.0 entry was refused in its own session after the update, 2026-09-26)
        allowed = set(meta.get("sessions") or [])
        if meta.get("session"):
            allowed.add(meta["session"])
        if session not in allowed:
            return "foreign-session"
        return "ok"

    @_mutating
    def admit(self, key: str, session: str | None) -> None:
        """A human brought the reference into this session (it was in a prompt)."""
        meta = self._index["entries"].get(key)
        if meta is None or not session or session in meta.get("sessions", []):
            return
        meta.setdefault("sessions", []).append(session)
        self._save_index()

    def admit_many(self, keys, session: str | None) -> None:
        """admit() for every key one text brought in, in one hold of the lock and one index write; nothing at all
        when the session holds each key already. A hit in a tool result admitted its key alone, and each admit
        re-read and rewrote the whole index: five stored names in one result cost 1.6 s on Python 3.9 with 6,000
        values in the vault (measured 2026-10-12)."""
        keys = [k for k in dict.fromkeys(keys) if k in self._index["entries"]]
        if not session or all(session in (self._index["entries"][k].get("sessions") or []) for k in keys):
            return
        with self._exclusive():
            for key in keys:
                meta = self._index["entries"].get(key)
                if meta is not None and session not in meta.get("sessions", []):
                    meta.setdefault("sessions", []).append(session)

    @_mutating
    def get(self, key: str, session: str | None = None, human: bool = False) -> tuple[str | None, str]:
        """Return (value, status). ``human=True`` is the CLI path: no session rule."""
        self.expire()
        meta = self._index["entries"].get(key)
        if meta is None:
            return None, "unknown"
        # past its expiry but not purged: the store refused the delete, or the sweep cap left it
        # for the next call; the human path skips `status`, so it printed the value (suite
        # review, 2026-09-27)
        if meta.get("purged") or meta["expires"] < time.time():
            return None, "expired"
        if not human:
            st = self.status(key, session)
            if st != "ok":
                return None, st
        value = self.backend.get(key)
        if value is None:
            return None, "expired"
        e = Entry.from_meta(meta)
        self._touch(e)
        return value, "ok"

    # grants: one-time permission for a command to read one value ----------
    GRANT_TTL = 120
    GRANT_USES = 3      # the value is read once in the main shell before the command runs; a retry
                        # of the read itself is the only reason for a second use

    @_mutating
    def grant(self, key: str, session: str | None, tool: str, context: str) -> tuple[str | None, str]:
        """Mint a one-time grant for ``key`` after the session rule and the limiter passed.

        Returns (nonce, status). The Bash hook puts ``resolve KEY --grant NONCE`` into the
        command instead of the value, so the command the user approves and the transcript
        never carry the value. The limiter caps distinct keys per session and resolves per
        hour so many values cannot leave in one automated sweep.
        """
        st = self.status(key, session)
        if st != "ok":
            return None, st
        st = self._limit(key, session)
        if st != "ok":
            return None, st
        import secrets as _secrets
        nonce = _secrets.token_urlsafe(16)
        now = time.time()
        grants = self._index.setdefault("grants", {})
        for n in [n for n, g in grants.items() if g["expires"] < now or g.get("uses", 0) >= self.GRANT_USES]:
            del grants[n]
        grants[nonce] = {"key": key, "session": session, "expires": now + self.GRANT_TTL, "uses": 0}
        if not self._record(key, session, tool, context):
            del grants[nonce]
            return None, "audit log not writable"
        self._save_index()
        return nonce, "ok"

    @_mutating
    def redeem(self, key: str, nonce: str) -> tuple[str | None, str]:
        g = self._index.get("grants", {}).get(nonce)
        if g is None or g["key"] != key:
            return None, "no-grant"
        if g.get("used") or g.get("uses", 0) >= self.GRANT_USES:
            return None, "grant-used"
        if g["expires"] < time.time():
            return None, "grant-expired"
        g["uses"] = g.get("uses", 0) + 1
        self._save_index()
        return self.get(key, human=True)

    def _limit(self, key: str, session: str | None) -> str:
        now = time.time()
        rec = [r for r in self._index.get("resolves", []) if r["ts"] > now - 3600]
        self._index["resolves"] = rec
        per_session = int(self.cfg.get("max_keys_per_session", DEFAULT_CONFIG["max_keys_per_session"]))
        per_hour = int(self.cfg.get("max_resolves_per_hour", DEFAULT_CONFIG["max_resolves_per_hour"]))
        keys_in_session = {r["key"] for r in rec if r["session"] == session}
        if key not in keys_in_session and len(keys_in_session) >= per_session:
            return f"limit: {per_session} different placeholders in this session this hour (max_keys_per_session)"
        if len(rec) >= per_hour:
            return f"limit: {per_hour} uses in the last hour (max_resolves_per_hour)"
        return "ok"

    def _limit_all(self, keys: list[str], session: str | None) -> list[str]:
        """The limiter for every key of one call together: two new keys at a cap of one passed one by
        one, and the first was recorded before the second was refused (review, 2026-09-29)."""
        keys = list(dict.fromkeys(keys))     # one resolve per key, whatever the caller passes
        if not keys:
            return []                         # nothing to resolve is under every cap, also a lowered one
        failed = [f"{k} ({st})" for k in keys for st in [self._limit(k, session)] if st != "ok"]
        if failed:
            return failed
        now = time.time()
        rec = [r for r in self._index.get("resolves", []) if r["ts"] > now - 3600]
        per_session = int(self.cfg.get("max_keys_per_session", DEFAULT_CONFIG["max_keys_per_session"]))
        per_hour = int(self.cfg.get("max_resolves_per_hour", DEFAULT_CONFIG["max_resolves_per_hour"]))
        known = {r["key"] for r in rec if r["session"] == session}
        new = [k for k in dict.fromkeys(keys) if k not in known]
        if new and len(known) + len(new) > per_session:
            # a cap lowered below the keys already known: the first new key is over it (review round 4:
            # IndexError when the call named only known keys)
            return [f"{new[max(0, per_session - len(known))]} (limit: {per_session} different placeholders in this "
                    "session this hour (max_keys_per_session))"]
        if len(rec) + len(keys) > per_hour:
            return [f"{keys[per_hour - len(rec)]} (limit: {per_hour} uses in the last hour "
                    "(max_resolves_per_hour))"]
        return []

    def _record(self, key: str, session: str | None, tool: str, context: str) -> bool:
        """One audit line per resolve. False when the line could not be written: the README
        promises the line, so a resolve without it does not happen (review, 2026-09-26)."""
        now = time.time()
        self._index.setdefault("resolves", []).append({"ts": now, "session": session, "key": key})
        try:
            HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
            path = HOME / "audit.log"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))
                ctx = context.replace("\n", " ").replace("\t", " ")[:160]
                f.write(f"{stamp}\t{(session or '-')[:8]}\t{key}\t{tool}\t{ctx}\n")
            self._rotate_audit(path)
            return True
        except OSError:
            return False

    def _rotate_audit(self, path: Path) -> None:
        """Keep the newest `audit_max_lines` lines (retention; operator review, 2026-09-26)."""
        cap = int(self.cfg.get("audit_max_lines", 2000))
        try:
            if path.stat().st_size < cap * 120:
                return
            lines = path.read_text(encoding="utf-8").splitlines()
            if len(lines) > cap:
                atomic_write(path, "\n".join(lines[-cap:]) + "\n")
        except OSError:
            pass

    @_mutating
    def record_server(self, keys: list[str], session: str | None, tool: str, context: str) -> str:
        """Values a server gave (vault_refs.py), named `KEY@host`: the limiter for all of them together, then one
        audit line each. They have no entry, so the session rule of the store does not apply; vault_refs does it."""
        failed = self._limit_all(keys, session)
        if failed:
            return failed[0]
        for key in dict.fromkeys(keys):
            if not self._record(key, session, tool, context):
                return "audit log not writable"
        self._save_index()
        return "ok"

    @_mutating
    def record_resolve(self, key: str, session: str | None, tool: str, context: str) -> str:
        """For tools that need the value inline (MCP arguments): session rule + limiter + audit."""
        st = self.status(key, session)
        if st != "ok":
            return st
        st = self._limit(key, session)
        if st != "ok":
            return st
        if not self._record(key, session, tool, context):
            return "audit log not writable"
        self._save_index()
        return "ok"

    @_mutating
    def _touch(self, e: Entry, save: bool = True) -> None:
        now = time.time()
        e.last_used = now
        e.uses += 1
        if self.cfg.get("renew_on_use", True):
            e.expires = min(now + self._ttl_for(e.type), e.max_expires)
        self._index["entries"][e.key] = asdict(e)
        if save:
            self._save_index()

    def list(self) -> list[Entry]:
        self.expire()
        return [Entry.from_meta(m) for m in self._index["entries"].values()]

    @_mutating
    def forget(self, key: str, route: str = "cli") -> str:
        """Delete one entry at the user's request: the value from the store and the metadata
        from the index, fingerprint included. "ok", "unknown", or "store" when the store refused
        (the entry then stays, so nothing looks deleted that is not). A deletion writes one
        events.log line with the route that asked for it; the next session start names it."""
        meta = self._index["entries"].get(key)
        if meta is None:
            from . import destinations
            self.destinations_kept = not destinations.forget([key])   # a record a failed forget left behind
            return "unknown"
        if not meta.get("purged"):
            try:
                self.backend.delete(key)
            except RuntimeError:
                return "store"
        fp = meta.get("fingerprint")
        del self._index["entries"][key]
        if fp and self._index["by_fingerprint"].get(fp) == key:
            del self._index["by_fingerprint"][fp]
        self._save_index()
        from . import events
        events.record_weakening("forget", key, route)      # the value is gone: a later text with it is not redacted
        from . import destinations
        # where a forgotten secret went is the person's to delete too; a record that could not be written is said
        self.destinations_kept = not destinations.forget([key])
        return "ok"

    @_mutating
    def expire(self, limit: int | None = 25) -> int:
        """Delete expired values; keep their metadata. Returns the count of values deleted;
        `last_refused` holds the count the store refused to delete.

        Runs on every put/get/list, so every hook call sweeps. A keychain
        delete costs ~10 ms (measured 2026-09-26), so a sweep is capped at
        `limit` deletes per call; the rest go on the next call. `limit=None`
        sweeps everything (SessionStart, `maisecrets expire`).
        """
        now = time.time()
        n = tried = 0
        self.last_refused = 0
        purged_now: list[str] = []
        for key, meta in self._index["entries"].items():
            if limit is not None and tried >= limit:
                break
            if not meta.get("purged") and meta["expires"] < now:
                tried += 1       # a refused delete costs time too, so it counts against the cap
                try:
                    self.backend.delete(key)
                except RuntimeError as exc:
                    from . import incidents
                    incidents.note("store.expire", exc)
                    # one item that refuses to go (a locked keychain over SSH) must not block
                    # every hook; the entry stays unpurged and the next sweep tries again. It is
                    # not counted as purged: the value is still in the store.
                    self.last_refused += 1
                    continue
                meta["purged"] = True
                meta["purged_at"] = now
                purged_now.append(key)
                n += 1
        # metadata of a purged entry (masked display, session ids) is retention too: gone after
        # keep_purged_days; the fingerprint map goes with it (operator review, 2026-09-26)
        keep = int(self.cfg.get("keep_purged_days", 30)) * 86400
        old = [k for k, m in self._index["entries"].items()
               if m.get("purged") and now - float(m.get("purged_at") or m.get("expires") or now) > keep]
        for k in old:
            fp = self._index["entries"][k].get("fingerprint")
            del self._index["entries"][k]
            if fp and self._index["by_fingerprint"].get(fp) == k:
                del self._index["by_fingerprint"][fp]
        if n or old:
            self._save_index()
        if old or purged_now:
            from . import destinations
            # where a value went goes with the value: the list shows no purged entry (codex review of 0.6.7)
            destinations.forget(old + purged_now)
        return n

    @_mutating
    @_mutating
    def quiet_code_words(self) -> list[str]:
        """Mark weak the statement keywords a keyword rule stored before 0.5.15. `if not token: <keyword>` stored the
        keyword, and maisecrets redacted it in every later text until the entry expired; the detector stores none
        now, but the old entries stayed (field report, 2026-09-29). A weak entry is not hunted in other texts, and
        its placeholder still resolves: nothing is deleted without the person (Codex review, 2026-09-29, of a
        version that deleted). The entries are found by fingerprint: no value is read. Returns the keys marked."""
        entries = self._index["entries"]
        if not any(str(m.get("kind", "")).startswith("ds-keyword") and not m.get("purged") and not m.get("weak")
                   for m in entries.values()):
            return []   # no fingerprint key is made for a store that has no such entry
        quieted = []
        for word in code_word_spellings():
            key = self._index["by_fingerprint"].get(self.fingerprint(word))
            meta = entries.get(key) if key else None
            if (not meta or meta.get("purged") or meta.get("weak")
                    or not str(meta.get("kind", "")).startswith("ds-keyword")):
                continue
            meta["weak"] = True
            quieted.append(key)
        return quieted

    def repair(self) -> dict:
        """Rebuild a damaged index from the store: every stored value is deleted (nothing
        resolves), and the counters are set past every key seen so no new entry can overwrite
        an old value. Refused on a backend that cannot enumerate itself."""
        if not hasattr(self.backend, "keys"):
            raise RuntimeError("this store cannot be enumerated; repair is not possible here")
        keys = self.backend.keys()
        counters: dict[str, int] = {}

        def seen(type_: str, num: int) -> None:
            counters[type_] = max(counters.get(type_, 0), num)
        for key in keys:
            type_, sep, num = key.rpartition("_c")
            if sep and num.isdigit():
                seen(type_, int(num))
        # the store holds only live values: a key whose value expired lives on in the index and in
        # old transcripts. Counters from the store alone went back below it, and the next value got
        # the old key, so an old placeholder resolved to the new value (review, 2026-09-27). Every
        # key the index names, readable or not, and its own counters count too.
        try:
            raw = INDEX.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw = ""
        for type_, num in re.findall(r"\b([A-Z][A-Z0-9_]*)_c(\d+)\b", raw):
            seen(type_, int(num))
        try:
            old = json.loads(raw).get("counters", {})
            for type_, num in (old.items() if isinstance(old, dict) else []):
                if isinstance(type_, str) and isinstance(num, int):
                    seen(type_, num)
        except (ValueError, AttributeError):
            pass
        deleted = 0
        for key in keys:
            # the fingerprint key and the vault reference keys (vault_refs.py) are no values: a new key would unlink
            # every server
            if key != FP_KEY_ENTRY and not key.startswith(("_maisecrets_vref_", "_maisecrets_vrel_")):
                try:
                    self.backend.delete(key)
                    deleted += 1
                except RuntimeError:
                    pass
        idx = {"entries": {}, "counters": counters, "by_fingerprint": {}}
        atomic_write(INDEX, json.dumps(idx, indent=1))
        return {"keys_seen": len(keys), "deleted": deleted, "counters": counters}


def wipe_everything(cfg: dict, run_dir: str | None = None) -> tuple[int, list[str]]:
    """Delete every stored value of this vault's service, the metadata, the logs and the waiting
    prompts: the offboarding step. Works without a readable index (a damaged index is the case
    where it is needed most). Returns (values deleted, problems); a problem means a value may
    still be in the store, and the caller must say so (review, 2026-09-26)."""
    backend = make_backend(cfg)
    problems: list[str] = []
    n = 0
    with _lock_for(HOME / ".lock"):
        # a file store raises OSError (a folder that is not writable), the platform stores
        # RuntimeError; either one is a problem to report, never a traceback (2026-09-27)
        try:
            n = backend.wipe() if hasattr(backend, "wipe") else 0
        except (RuntimeError, OSError) as exc:
            problems.append(f"store: {type(exc).__name__}")
        try:
            keys = backend.keys() if hasattr(backend, "keys") else []
        except (RuntimeError, OSError):
            keys = []
        for key in keys:
            try:
                backend.delete(key)
                n += 1
            except (RuntimeError, OSError):
                problems.append(f"store item {key} not deleted")
        from . import destinations
        if not destinations.wipe():        # under its lock: a writer holding it would write the record back
            problems.append("destinations.json not deleted")
        from . import incidents
        incidents.clear(HOME)              # the incident record, its aside, lock and temp files, the markers
        # the names marked with {{…}} and the term index (terms.py); terms.txt is the person's list and stays
        # under the terms lock too (order: this lock, then the terms lock; a terms writer never takes this one): a
        # proposal or a mark written at the same time came back after the wipe (codex verification of block 2)
        def unlink(names: tuple) -> None:
            for name in names:
                try:
                    (HOME / name).unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    problems.append(f"{name} not deleted")
        # the index of the imports (values.py) is built again from them; the imports are the person's, as terms.txt
        unlink(("index.json", "audit.log", "events.log", "hooks.log", ".announced", ".values-cache"))
        term_files = ("terms.marked.json", ".terms-cache", "terms.suggested.txt")
        try:
            with _lock_for(HOME / ".terms.lock"):
                unlink(term_files)
        except LockTimeout:
            # another maisecrets process held the terms lock: say what is left and how to finish, never success
            problems.append(f"{', '.join(term_files)} not deleted (another maisecrets process held the terms lock; "
                            "run the wipe again)")
        # vault-refs: the server tokens seen and sent, the key ids and the endpoints (vault_refs.py); its keys
        # are in the store
        dirs = [HOME / "pending", HOME / "run", HOME / "vault-refs"] + ([Path(run_dir)] if run_dir else [])
        for d in dirs:
            if d.is_dir():
                for f in d.iterdir():
                    try:
                        if f.name == "sealed" and f.is_dir() and not f.is_symlink():
                            # the ssh first-use FIFOs: mode 0300, readable only for the sweep
                            os.chmod(f, 0o700)
                            for g in f.iterdir():
                                g.unlink()
                            f.rmdir()
                        else:
                            f.unlink()
                    except OSError:
                        problems.append(f"{f.name} not deleted")
    return n, problems
