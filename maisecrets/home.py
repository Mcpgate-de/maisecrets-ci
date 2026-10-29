"""The home folder of maisecrets and its configuration: where the files live, how a file is written and read
safely, the file lock, and load_config().

These helpers lived in vault.py. The detector, the term lists, the imports and the rules of your own need them, and
reaching them through vault.py made every scan import the store. vault.py imports them from here, so `vault.HOME`,
`vault.load_config` and the others are the same objects as before.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

HOME = Path(os.environ.get("MAISECRETS_HOME") or Path.home() / ".maisecrets")   # empty: the default, as in run.sh
CONFIG = HOME / "config.json"
_DEFAULT_HOME = Path.home() / ".maisecrets"


class WrongHome(RuntimeError):
    """maisecrets.home, directly or through another maisecrets module, was imported before a test run chose its own
    home, and still names the user's own home."""


def _within_default_home(path: Path) -> bool:
    """The user's own home or a path inside it, also through `..` or a symbolic link, and the same directory by
    device and inode: a bind mount, or another case of the name on a case-insensitive disk (codex Gate A of the
    registry, rounds 1 and 2). Runs only under a test run's marker."""
    real, home = path.resolve(), _DEFAULT_HOME.resolve()
    if real == home or home in real.parents:
        return True
    if not home.exists():
        return False
    for p in (real, *real.parents):
        try:
            if p.exists() and os.path.samefile(p, home):
                return True
        except OSError:
            continue
    return False


def _check_home() -> None:
    """A test run owns a temp home (tests/_isolate.py sets MAISECRETS_TEST_HOME_OWNED). HOME is bound at import (in
    this module; vault takes it from here), so a runner that imported maisecrets.home before the isolation kept the
    real home, and the resets of the suite deleted the real index, vault file and key (a fork's runner, 2026-10-12).
    Under that marker the user's own ~/.maisecrets is refused before a read or a write. A second temp home that a test
    chooses on purpose stays allowed. Without the marker (every real hook) this is one environment lookup."""
    owned = os.environ.get("MAISECRETS_TEST_HOME_OWNED")
    if owned and _within_default_home(HOME):
        raise WrongHome(f"maisecrets names the user's own {HOME}, but this test run owns {owned}: import "
                        "tests/_isolate.py before anything that imports maisecrets")

DEFAULT_CONFIG = {
    "backend": "keychain",          # keychain (macOS) | windows-vault | encrypted-file (Linux) | jsonfile (test)
    "report_url": "https://github.com/Mcpgate-de/maisecrets/issues",   # shown in the block notice
    "ttl_seconds": {"default": 86400, "CARD": 3600},
    "max_ttl_seconds": 30 * 86400,
    "renew_on_use": True,
    "scrub_transcript": True,
    "block_at_mentions": True,
    # README "Invisible characters": tag characters, variation-selector runs and bidi controls leave tool results
    "strip_hidden_characters": True,
    # Claude Code with mods (the mod): a prompt with a value goes through with placeholders; false blocks it
    "rewrite_prompts": True,
    "gateway_servers": [],           # MCP servers that resolve placeholders themselves; read by nothing yet
    # country codes for the PII rules and the label languages; "auto" is the country of the system
    # setting (maisecrets/detection/regions.py). pii_regions is the old name and still read.
    "regions": ["auto"],
    "max_new_entries_per_result": 100,   # above this, a tool result is masked without storing more values
    "resolve_in_files": True,        # Write/Edit content resolves a placeholder like an MCP argument
    "shortcut": True,                # the first SessionStart names /maisecrets:shortcut once; it installs nothing
    "ssh_via_sandbox": True,         # a value may go to ssh on stdin inside the Claude Code sandbox
    "ssh_approval": "per-command",   # under rehydration "confirm": "per-session" is one confirm per value and session
    "ssh_consent": False,            # every ssh-family command: a read runs, a write asks once per host (#8)
    "ssh_host_groups": {},           # {"group": ["host", …]}: one ssh consent covers the whole group
    "ssh_autonomous_hosts": [],      # hosts (or group names) where the AI writes over ssh without asking, always
    "rule_dirs": [],                 # folders of detection rules of your own (user_rules.py); a typed prompt adds one
    "read_pdf": "allow",             # allow | ask | block | convert: a PDF that the AI reads (file_reads.py, C28)
    "read_image": "allow",           # allow | ask | block: an image that the AI reads
    "clean_dirs": [],                # folders whose PDFs and images pass as allow; a typed prompt adds one
    "value_files": [],               # files of values from your own tools (values.py); a typed prompt adds one
    "secret_destinations": "observe",  # note where each secret is sent (destinations.py); protect also asks; off
    "rehydration": "automatic",      # automatic | confirm | block: does maisecrets add a confirm (rehydration.py)
    "guard": True,                   # a synced install registers the guard outside its folder (hooks/guard.py)
    "client_header": True,           # vault references: a key header on user-scope MCP servers (vault_refs.py)
    "client_vault_cafile": "",       # vault references: a CA file for a server behind an own CA; empty: the system's
    "pass_agent_reports": True,      # the report of a subagent of this session is model text: not blocked (hooks.py)
    "tips": True,                    # a tip at session start, and a hint when a case for a setting first comes up
    # the limiter (C7): a brake for a session that sends its own values out in bulk; the session rule (C4) keeps the
    # rest of the store closed anyway. Replayed over five months of sessions, the busiest hour needed 67 values and
    # 118 resolves; 25 and 60 would have stopped 3 of 178 sessions that used values (0.6.9)
    "max_keys_per_session": 200,     # distinct values one session resolves in an hour
    "max_resolves_per_hour": 1000,   # resolves in an hour, all sessions
    "keep_purged_days": 30,          # metadata of an expired entry is deleted after this many days
    "audit_max_lines": 2000,
}

# a machine-wide policy the administrator writes; its keys win over the user file and the
# environment and cannot be changed from ~/.maisecrets (operator review, 2026-09-26)
POLICY_PATHS = {
    "Darwin": Path("/Library/Application Support/maisecrets/policy.json"),
    "Windows": Path(os.environ.get("ProgramData", r"C:\\ProgramData")) / "maisecrets" / "policy.json",
    "Linux": Path("/etc/maisecrets/policy.json"),
}
_CONFIG_TYPES = {
    "backend": str, "report_url": (str, type(None)), "ttl_seconds": dict, "max_ttl_seconds": int,
    "renew_on_use": bool, "scrub_transcript": bool, "block_at_mentions": bool, "rewrite_prompts": bool,
    "strip_hidden_characters": bool,
    "gateway_servers": list,
    "regions": list, "pii_regions": list, "max_keys_per_session": int, "max_resolves_per_hour": int, "tips": bool,
    "max_new_entries_per_result": int, "keep_purged_days": int, "audit_max_lines": int,
    "allow_plaintext_store": bool, "resolve_in_files": bool, "shortcut": bool, "ssh_via_sandbox": bool,
    "ssh_consent": bool, "ssh_host_groups": dict, "ssh_autonomous_hosts": list, "secret_destinations": str,
    "ssh_approval": str, "rehydration": str, "guard": bool, "client_header": bool, "client_vault_cafile": str,
    "pass_agent_reports": bool, "rule_dirs": list,
    "read_pdf": str, "read_image": str, "clean_dirs": list, "value_files": list,
}


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Write via a per-process temp file and an atomic rename. A shared temp name
    (``index.tmp``) let two hook processes running at once replace each other's file; the
    second one then failed with FileNotFoundError and the hook blocked the tool call
    (Codex with two plugin copies, 2026-09-26)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        # Windows refuses to replace a file another process has open for reading (WinError 5
        # in the 12-process test on windows-latest, 2026-09-26); a reader holds it for
        # milliseconds, so retry briefly instead of failing the hook
        for attempt in range(40):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 39:
                    raise
                time.sleep(0.05)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def read_text_retry(path: Path, attempts: int = 40) -> str:
    """Read a file that another hook process may be replacing right now. Windows raises
    PermissionError for the reader while os.replace runs on the same name (the 12-process test
    on windows-latest, 2026-09-27; the writer side got its retry on 2026-09-26). The window is
    milliseconds, so retry briefly; the last attempt raises."""
    for attempt in range(attempts):
        try:
            return path.read_text(encoding="utf-8")
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05)
    raise AssertionError("unreachable")


def windows_user_mismatch() -> tuple[str, str] | None:
    """(account the process runs as, account the environment names) when they differ on Windows, else None.

    The Codex app runs a slash command as its sandbox user with the person's environment, so the store path points
    into the person's profile. There such a command left the store folder with rights for the sandbox users and an
    index.json the person could no longer read, and every later hook of the person failed (2026-10-01..05). A run
    with an explicit MAISECRETS_HOME chose its store on purpose and is not checked."""
    if os.name != "nt" or os.environ.get("MAISECRETS_HOME"):
        return None
    named = os.environ.get("USERNAME") or ""
    try:
        import ctypes
        from ctypes import wintypes
        size = wintypes.DWORD(257)
        buf = ctypes.create_unicode_buffer(257)
        if not ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(size)):
            return None
        real = buf.value
    except (OSError, AttributeError, ImportError):
        return None
    if named and real and real.lower() != named.lower():
        return real, named
    return None


_LOCKS: dict = {}


def _lock_for(path: Path) -> "_Lock":
    """One lock object per path and process, shared by every Vault in the process: a second
    flock on a second descriptor would wait for the first (measured: two Vault objects in one
    process deadlocked)."""
    key = str(path)
    if key not in _LOCKS:
        _LOCKS[key] = _Lock(path)
    return _LOCKS[key]


def _note_user_config(exc: BaseException | None, cause: str = "other") -> None:
    from . import incidents
    incidents.note("config.user-ignored", exc, cause)


class CodedError(RuntimeError):
    """A store failure with its incident code (maisecrets/incidents.py). The message stays for the CLI; the hook's
    record takes only the code, the cause and the exit code (docs/DIAGNOSTICS.md, D2)."""

    def __init__(self, message: str, code: str, cause: str = "other", rc: int | None = None) -> None:
        super().__init__(message)
        self.incident_code, self.incident_cause, self.incident_rc = code, cause, rc


class LockTimeout(RuntimeError):
    incident_code, incident_cause, incident_rc = "store.lock", "lock", None


class _Lock:
    """An exclusive lock per vault home, taken around each read-modify-write of the index and
    released right after. Not held for a process's lifetime: a long-lived holder starved every
    hook, and a Codex hook that times out is fail-OPEN (measured 2026-09-26). Re-entrant within
    the process. A lock that cannot be taken within ``LOCK_DEADLINE`` raises, so the hook fails
    closed with a reason instead of hanging into the client's timeout, which fails open."""
    LOCK_DEADLINE = 6.0

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd = None
        self.depth = 0

    def __enter__(self):
        self.depth += 1
        if self.depth > 1:
            return self
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except BaseException:
            self.depth -= 1                  # no lock was taken: a later enter must try again (codex review)
            raise
        deadline = time.time() + self.LOCK_DEADLINE
        try:
            while True:
                try:
                    try:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except ImportError:
                        import msvcrt
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.time() > deadline:
                        raise LockTimeout(f"vault lock busy for {self.LOCK_DEADLINE:.0f}s ({self.path})")
                    time.sleep(0.02)
        except BaseException:
            os.close(fd)
            self.depth -= 1
            raise
        self.fd = fd
        return self

    def __exit__(self, *exc) -> None:
        self.depth -= 1
        if self.depth > 0 or self.fd is None:
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


class ConfigError(RuntimeError):
    """A config value of the wrong type; the message names the key, never a value."""


_CONFIG_CHOICES = {"secret_destinations": ("observe", "off", "protect")}


def _check_types(cfg: dict, source: str) -> None:
    for key, want in _CONFIG_TYPES.items():
        if key in cfg and (not isinstance(cfg[key], want) or (want is int and isinstance(cfg[key], bool))):
            raise ConfigError(f"{source}: {key} has the wrong type")
    for key, choices in _CONFIG_CHOICES.items():
        # "obesrve" read as "not observe" and silently stopped the record (codex review of 0.6.7)
        if key in cfg and cfg[key] not in choices:
            raise ConfigError(f"{source}: {key} must be one of {', '.join(choices)}")
    ttl = cfg.get("ttl_seconds")
    if isinstance(ttl, dict) and not all(isinstance(v, int) for v in ttl.values()):
        raise ConfigError(f"{source}: ttl_seconds values must be integers")


def _old_region_key(layer: dict) -> dict:
    """pii_regions (up to 0.4) named the Presidio regions with "generic" in the list. A layer that
    sets it and not `regions` sets `regions` to the same countries."""
    if "pii_regions" in layer and "regions" not in layer:
        layer = dict(layer)
        layer["regions"] = [r for r in layer["pii_regions"] if str(r).lower() != "generic"]
    layer = {k: v for k, v in layer.items() if k != "pii_regions"}
    return layer


_STRICTNESS = {"automatic": 0, "confirm": 1, "block": 2}
_SAFETY_KEYS = ("rehydration", "resolve_in_files", "ssh_via_sandbox", "ssh_consent")


def _looks_misspelled(key: str) -> bool:
    """A near miss of a safety key ("rehydraton"), not a longer key of a newer version that starts with
    one ("rehydration_mcp"): an older plugin reading a newer policy only warns about that (review round 4)."""
    import difflib
    if any(key.startswith(k + "_") for k in _SAFETY_KEYS):
        return False
    return bool(difflib.get_close_matches(key, list(_SAFETY_KEYS), n=1, cutoff=0.8))


def _keep_the_stricter(cfg: dict, parsed: dict) -> None:
    """A user file ignored for a wrong type still said what it wanted: a stricter rehydration policy,
    or a route switched off, stays; a looser one is the default anyway. A rehydration value that is
    no policy is block (review, 2026-09-29: the fallback turned block into confirm); a list or an
    object there raised TypeError and locked the client (review round 2)."""
    want = parsed.get("rehydration", cfg["rehydration"])
    if not isinstance(want, str) or want not in _STRICTNESS:
        want = "block"
        cfg["rehydration_fallback"] = True     # the setting is ours, not the file's: the refusal says so
    if _STRICTNESS[want] > _STRICTNESS.get(cfg["rehydration"], 2):
        cfg["rehydration"] = want
    for key in ("resolve_in_files", "ssh_via_sandbox"):
        if parsed.get(key) is False:
            cfg[key] = False
    if parsed.get("ssh_consent") is True:
        cfg["ssh_consent"] = True
    if isinstance(parsed.get("rule_dirs"), list):
        # more rules only make detection stricter: they run after every built-in rule, so none takes a span first
        cfg["rule_dirs"] = parsed["rule_dirs"]
    for key in ("read_pdf", "read_image"):
        if parsed.get(key) in ("ask", "block", "convert"):
            cfg[key] = parsed[key]                 # each stops more than the default allow; clean_dirs only loosens


def _read_fallback(cfg: dict) -> None:
    """A config.json that cannot be read may say read_pdf or read_image block: both count as block until it is fixed,
    the same rule as rehydration (review of block 4: bad JSON turned a block into allow)."""
    cfg["read_pdf"] = cfg["read_image"] = "block"
    cfg["read_fallback"] = True


def load_config() -> dict:
    """Defaults, then ~/.maisecrets/config.json, then CLAUDE_PLUGIN_OPTION_<KEY> if a client passes
    plugin options that way, then the machine policy file, whose keys win. The manifest declares
    no `userConfig`: Claude Code 2.1.223 rejects a manifest with that key as invalid and then
    loads NO hook at all (measured on Debian, 2026-09-26), and a guard that silently vanishes
    on an older client is worse than a guard without a settings dialog. A wrong type raises
    ConfigError with the key name: a silent AttributeError later locked the user out with no
    hint at the config (review, 2026-09-26)."""
    _check_home()
    import copy
    import platform as _platform
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["config_warning"] = ""
    try:
        user = json.loads(CONFIG.read_text(encoding="utf-8"))
        if not isinstance(user, dict):
            raise ConfigError(f"{CONFIG.name} must hold one JSON object")
        _check_types(user, CONFIG.name)
    except FileNotFoundError:
        user = {}
    except OSError as exc:
        # a file that exists and cannot be read may say block: it loosens nothing (review, 2026-09-29)
        user = {}
        cfg["config_warning"] = f"{CONFIG.name} cannot be read ({type(exc).__name__}) and was ignored"
        _note_user_config(exc)
        cfg["rehydration"] = "block"
        cfg["rehydration_fallback"] = True
        _read_fallback(cfg)
    except ValueError:
        # the user file is advisory: a typo must not lock the user out of the client (review,
        # 2026-09-26). The defaults are the strict values, so the fallback loosens nothing; the
        # warning is shown at session start and in the block notice.
        user = {}
        cfg["config_warning"] = f"{CONFIG.name} is not valid JSON and was ignored"
        _note_user_config(None, "parse")
        # the file may have set block: an ignored file loosens nothing, so nothing is rehydrated until it is fixed
        cfg["rehydration"] = "block"
        cfg["rehydration_fallback"] = True
        _read_fallback(cfg)
    except ConfigError as exc:
        cfg["config_warning"] = f"{exc}; the file was ignored"
        _note_user_config(None, "shape")
        if isinstance(user, dict):
            _keep_the_stricter(cfg, user)
            # an ignored file may have said block for a PDF or an image: both block until it is fixed (README)
            _read_fallback(cfg)
            # the file still says what the person decided: no hint asks about a key they wrote (settings.py)
            cfg["user_keys_ignored"] = sorted(k for k in user if k in _CONFIG_TYPES)
        else:
            # JSON that is no object cannot be read either (it may wrap a block): the same as invalid JSON
            cfg["rehydration"] = "block"
            cfg["rehydration_fallback"] = True
            _read_fallback(cfg)
        user = {}
    unknown = sorted(k for k in user if k not in _CONFIG_TYPES)
    if unknown:
        # a key is named only when it is a typo of a real one: a value pasted into the file as a
        # key went into the session-start message (invariant I1, 2026-09-28), and a value can have
        # the shape of a key name
        import difflib
        named = [k for k in unknown if difflib.get_close_matches(k, list(_CONFIG_TYPES), n=1, cutoff=0.8)]
        other = len(unknown) - len(named)
        what = ", ".join(named + ([f"{other} more that are not near a known key"] if other else []))
        cfg["config_warning"] = (cfg["config_warning"] + "; " if cfg["config_warning"] else "") + \
            f"{CONFIG.name}: unknown key(s) {what} ignored"
        user = {k: v for k, v in user.items() if k in _CONFIG_TYPES}
        if any(_looks_misspelled(k) for k in named):
            # "rehydraton": "block" is a stricter wish spelled wrong: dropping it would loosen. The file's
            # own rehydration key must not undo it (review round 3: "resolve_in_file": false next to it)
            user.pop("rehydration", None)
            cfg["rehydration"] = "block"
            cfg["rehydration_fallback"] = True
    user = _old_region_key(user)
    cfg.update(user)
    # a key the user wrote is a decision, a missing one is not (maisecrets/settings.py): both read the same value
    cfg["user_keys"] = sorted(set(user) | set(cfg.pop("user_keys_ignored", [])))
    cfg["regions_from"] = "config.json" if "regions" in user else "default"
    env = os.environ
    backend = env.get("CLAUDE_PLUGIN_OPTION_BACKEND", "").strip()
    if backend and backend != "auto":
        cfg["backend"] = backend
    regions = env.get("CLAUDE_PLUGIN_OPTION_PII_REGIONS", "").strip()
    if regions:
        cfg["regions"] = [r.strip().lower() for r in regions.split(",") if r.strip() and r.strip().lower() != "generic"]
        cfg["regions_from"] = "plugin option"
    ttl = env.get("CLAUDE_PLUGIN_OPTION_TTL_HOURS", "").strip()
    if ttl:
        try:
            cfg.setdefault("ttl_seconds", {})["default"] = int(float(ttl) * 3600)
        except ValueError:
            pass
    if env.get("CLAUDE_PLUGIN_OPTION_REPORT_URL", "").strip():
        cfg["report_url"] = env["CLAUDE_PLUGIN_OPTION_REPORT_URL"].strip()
    policy_path = POLICY_PATHS.get(_platform.system())
    cfg["policy_keys"] = []
    if policy_path is not None:
        try:
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            policy = {}
        except OSError as exc:
            # an administrator's file that exists and cannot be read is not "no policy": it fails closed
            # like a policy that is not valid JSON (review, 2026-09-29)
            raise ConfigError(f"{policy_path} cannot be read ({type(exc).__name__})") from exc
        except ValueError as exc:
            raise ConfigError(f"{policy_path} is not valid JSON") from exc
        if not isinstance(policy, dict):
            # valid JSON of another shape was skipped silently: no policy applied at all
            raise ConfigError(f"{policy_path} must hold one JSON object")
        _check_types(policy, policy_path.name)
        # the policy's rule folders and allow list add to the person's own (maisecrets/user_rules.py): they are no
        # setting the person changes, so they stay out of policy_keys and the person keeps their own rule_dirs
        for key in ("rule_dirs", "allow"):
            extra = policy.pop(key, [])
            if not isinstance(extra, list) or not all(isinstance(x, str) for x in extra):
                raise ConfigError(f"{policy_path.name}: {key} must be a list of strings")
            cfg["policy_" + key] = extra
        import difflib
        unknown_policy = sorted(k for k in policy if k not in _CONFIG_TYPES and not k.startswith(("_", "$")))
        policy = {k: v for k, v in policy.items() if k in _CONFIG_TYPES}
        typo = [k for k in unknown_policy if _looks_misspelled(k)]
        if unknown_policy:
            # a key of a newer version or a management tool is ignored with a warning; "_" and "$" keys
            # are comments and schema links
            cfg["config_warning"] = (cfg["config_warning"] + "; " if cfg["config_warning"] else "") + \
                f"{policy_path.name}: {len(unknown_policy)} unknown key(s) ignored" + \
                ("; a safety key looks misspelled, rehydration is blocked until fixed" if typo else "")
        if typo:
            # an administrator's "rehydraton": "block" dropped silently would loosen; its intent is unknown
            policy["rehydration"] = "block"
            cfg["rehydration_fallback"] = True
        elif "rehydration" in policy:
            cfg["rehydration_fallback"] = False   # the administrator's setting, not our fallback
        policy_keys = sorted(policy)
        policy = _old_region_key(policy)
        cfg.update(policy)
        cfg["policy_keys"] = policy_keys
        if "regions" in policy:
            cfg["regions_from"] = "machine policy"
    cfg["max_ttl_seconds"] = min(int(cfg.get("max_ttl_seconds", 30 * 86400)), 30 * 86400)
    if cfg.get("backend") == "jsonfile" and not cfg.get("allow_plaintext_store", False):
        # the plaintext store is for tests and the harness, which say so in their own config
        raise ConfigError("backend jsonfile is the TEST store; set allow_plaintext_store to use it")
    return cfg


def regions_from_config():
    """The regions and label languages that the config of this computer names (maisecrets/detection/regions.py). A
    config that
    cannot be read counts as none: a bad one is reported by the vault."""
    from . import regions
    try:
        cfg = load_config()
    except Exception:  # noqa: BLE001 - config is optional; a bad one is reported by the vault
        cfg = {}
    return regions.resolve(cfg)
