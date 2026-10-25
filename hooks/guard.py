#!/usr/bin/env python3
"""The maisecrets guard: a hook that lives outside the plugin folder.

A Claude Code update of a synced plugin rewrites its folder, and a session whose plugin was loaded
from it then runs none of its hooks, silently (anthropics/claude-code#97847; measured 2026-09-29:
the session that started the sync ran no maisecrets hook either, while /plugin showed the new
version). Nothing inside the plugin can see that. A synced maisecrets places this script at
~/.claude/maisecrets-guard.py and registers it with the plugin's matchers.

For each prompt and tool call it waits a moment for the heartbeat that every maisecrets hook writes
when it starts (~/.maisecrets/alive/<hash of session, event and id>). No heartbeat means maisecrets
did not run for this call: the prompt is blocked, the tool call denied, a tool result withheld. It
stays silent where maisecrets is not meant to run: another account, a plugin switched off in the
user, project, local or managed settings, Codex. The heartbeat stays where it is (a second guard
registration may wait for the same one); maisecrets sweeps old ones. Standard library only, and no
import from the plugin: the plugin folder is exactly what may be missing.

    python3 ~/.claude/maisecrets-guard.py --off    switch the guard off from a terminal
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

EVENTS = {"UserPromptSubmit": "user-prompt", "PreToolUse": "pre-tool", "PostToolUse": "post-tool"}
MESSAGE = ("maisecrets did not run for this call: a plugin update replaced its folder, or it started too slowly.\n\n"
           "    claude --resume {session}\n\n"
           "Exit this session and run the command above in the directory where you started it.{clip} "
           "/reload-plugins does not help after an update of a synced plugin. "
           "If maisecrets is off on purpose, switch the guard off in a terminal: python3 {script} --off")
# no sign of an update: a busy computer delayed maisecrets, and a second try works. The refusal said "exit this
# session" and an autonomous run stopped for a person, while the next call went through (measured 2026-09-29,
# load 7.7). The restart stays the second step, for an update older than the trash window.
RETRY = ("maisecrets did not answer in time for this call (the computer may be busy), so the call did not run. "
         "Run it again. If every call fails this way, a plugin update replaced the maisecrets folder:\n\n"
         "    claude --resume {session}\n\n"
         "Exit this session and run the command above in the directory where you started it.{clip} "
         "/reload-plugins does not help after an update of a synced plugin. "
         "If maisecrets is off on purpose, switch the guard off in a terminal: python3 {script} --off")
# maisecrets started for this call: its folder is there, so no restart helps
SLOW = ("maisecrets started for this call but did not answer in time (the computer may be busy), so the call did "
        "not run. Run it again.")
# a terminal with copy-on-select (Ghostty's default) replaces the clipboard as soon as text is selected
# (measured 2026-09-29: the command stayed 25 s until one word was selected), so the refusal says it was copied
CLIP = " It was copied to your clipboard; selecting text in the terminal can replace it."
MANAGED = {"darwin": "/Library/Application Support/ClaudeCode/managed-settings.json",
           "linux": "/etc/claude-code/managed-settings.json"}


def _home() -> str:
    return os.environ.get("MAISECRETS_HOME") or os.path.join(os.path.expanduser("~"), ".maisecrets")


def _marker(code: str) -> None:
    """An incident marker for /maisecrets:report incident (docs/DIAGNOSTICS.md, section 3): one empty folder made with
    one mkdir in a home that exists and is no link, after the answer, waited for at most 0.3 s. Never raises."""
    import threading

    def make() -> None:
        try:
            home = _home()
            if os.path.isdir(home) and not os.path.islink(home):
                os.mkdir(os.path.join(home, "incident-marker." + code), 0o700)
        except Exception:  # noqa: BLE001
            pass
    try:
        sys.stdout.flush()
        t = threading.Thread(target=make, daemon=True)
        t.start()
        t.join(0.3)
        if t.is_alive():
            os._exit(0)          # a thread alive at the shutdown of the interpreter can crash it (signal 11)
    except Exception:  # noqa: BLE001
        pass


def _claude_dir() -> str:
    return os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _settings_files(cwd: str) -> list:
    """The settings files that set enabledPlugins, lowest precedence first: user; each project .claude folder from
    the outermost ancestor (the repository root, or the home directory) to the working directory; the repository
    root's local settings again, which win over a local file an older Claude Code left in a subdirectory (codex
    review, 2026-10-07); managed. What the guard cannot read: --settings on the command line and managed
    settings that come from a server or MDM (docs/THREAT-MODEL.md C13)."""
    files = [os.path.join(_claude_dir(), "settings.json")]
    d = os.path.abspath(cwd) if cwd else ""
    chain, root, stop = [], "", os.path.expanduser("~")
    while d:
        chain.append(d)
        parent = os.path.dirname(d)
        # a submodule has a .git file, not a folder: its superproject's settings count too
        if os.path.isdir(os.path.join(d, ".git")):
            root = d
            break
        if parent == d or d == stop:
            break
        d = parent
    for d in reversed(chain):
        files += [os.path.join(d, ".claude", "settings.json"), os.path.join(d, ".claude", "settings.local.json")]
    if root:
        files.append(os.path.join(root, ".claude", "settings.local.json"))
    files.append(MANAGED.get(sys.platform, ""))
    return files


def _plugin_ids(claude: str, account: str) -> list:
    """The exact plugin ids of the maisecrets copies Claude Code can load: the synced one of this account, and the
    installed ones whose plugin is maisecrets (by its key or by the name in its manifest; a marketplace may list it
    under another name). A key of a copy that is not installed is no copy (codex review, 2026-10-07)."""
    ids = ["maisecrets@synced"] if account and _synced_copies(claude, account) else []
    installed = _load(os.path.join(claude, "plugins", "installed_plugins.json")).get("plugins") or {}
    for key, entries in installed.items() if isinstance(installed, dict) else []:
        named = key.split("@", 1)[0] == "maisecrets"
        for e in entries if isinstance(entries, list) else []:
            path = e.get("installPath") if isinstance(e, dict) else None
            if isinstance(path, str) and _load(os.path.join(path, ".claude-plugin", "plugin.json")).get("name") \
                    == "maisecrets":
                named = True
        if named and key not in ids:
            ids.append(key)
    return ids


def _switched_off(cwd: str, ids: list) -> bool:
    """maisecrets switched off for every copy that could run here. Each id takes the value of the settings that
    win; an id with no entry is on, as Claude Code enables a plugin by default. With no known copy, the
    maisecrets@ keys the settings name stand in. One copy off beside another on keeps the guard watching: the
    directory copy off and the synced copy on kept it silent while the synced copy did not load (field report,
    2026-10-07)."""
    effective: dict = {}
    for f in _settings_files(cwd):
        plugins = _load(f).get("enabledPlugins") if f else None
        if isinstance(plugins, dict):
            effective.update({k: v for k, v in plugins.items() if isinstance(v, bool)})
    ids = ids or [k for k in effective if k.split("@", 1)[0] == "maisecrets"]
    return bool(ids) and all(effective.get(i, True) is False for i in ids)


def _client_config() -> str:
    """The config file Claude Code uses (2.1.301, function `v_`; maisecrets/vault_refs.py claude_json has the same
    rule): `.config.json` in the config folder when it is a regular file and not empty, or empty with a write bit and
    no global file; else `.claude<suffix>.json` in CLAUDE_CONFIG_DIR or the home folder."""
    import unicodedata
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    suffix = "-custom-oauth" if os.environ.get("CLAUDE_CODE_CUSTOM_OAUTH_URL") else ""
    other = os.path.join(base or os.path.expanduser("~"), f".claude{suffix}.json")
    home = base if base is not None else os.path.join(os.path.expanduser("~"), ".claude")
    legacy = os.path.join(unicodedata.normalize("NFC", home), ".config.json")
    try:
        st = os.stat(legacy)
        if stat.S_ISREG(st.st_mode) and (st.st_size > 0 or ((st.st_mode & 0o222) and not os.path.exists(other))):
            return legacy
    except (OSError, ValueError):
        pass
    return other


def _account() -> str:
    """<organizationUuid>_<accountUuid> of the account Claude Code runs as, the name of its synced folder."""
    acc = _load(_client_config()).get("oauthAccount") or {}
    org, user = acc.get("organizationUuid"), acc.get("accountUuid")
    return f"{org}_{user}" if org and user else ""


TRASH_WINDOW = 15 * 60
# the folder names of a synced copy: an update writes the next generation beside the last one
# (maisecrets, then maisecrets~g2, ...; measured 2026-09-29) and moves the old one to the trash
_SYNCED_NAME = re.compile(r"maisecrets(~g\d+)?")


def _synced_copies(claude: str, account: str) -> list:
    """Every maisecrets copy the sync holds for this account, whichever generation it is."""
    base = os.path.join(claude, "plugins", "synced", account)
    try:
        names = os.listdir(base)
    except OSError:
        return []
    return [os.path.join(base, n) for n in names if _SYNCED_NAME.fullmatch(n)
            and os.path.isfile(os.path.join(base, n, ".claude-plugin", "plugin.json"))]
# after the start, how long an answer may take: maisecrets answers within its own watchdog (7 s for a
# prompt and a tool call, 16 s for a tool result; maisecrets/hooks.py WATCHDOG_SECONDS) plus a margin. The
# guard's hook timeout (GUARD_TIMEOUTS in maisecrets/cli.py) covers the start wait and this
ANSWER_WAIT = {"UserPromptSubmit": 8.0, "PreToolUse": 8.0, "PostToolUse": 17.0}


def _recently_trashed(claude: str) -> bool:
    """A maisecrets folder that Claude Code moved to plugins/.trash in the last minutes (an update)."""
    trash = os.path.join(claude, "plugins", ".trash")
    now = time.time()
    try:
        entries = os.listdir(trash)
    except OSError:
        return False
    for entry in entries:
        d = os.path.join(trash, entry)
        try:
            names = os.listdir(d)
            # a move keeps a folder's mtime on APFS; the change time, and the new trash entry, say when
            st = os.stat(d)
            moved = max(st.st_mtime, st.st_ctime)
        except OSError:
            continue            # a plain file or a folder we cannot read: the next entry
        if any(n.startswith("maisecrets") for n in names) and now - moved < TRASH_WINDOW:
            return True
    return False


def expected(cwd: str = "") -> bool:
    """Whether maisecrets is meant to run here, by the same rule under which it writes its heartbeat
    (guard.json present, or a synced copy)."""
    cfg = _load(os.path.join(_home(), "guard.json"))
    mode = cfg.get("expect")
    if mode == "off":
        return False
    claude = _claude_dir()
    account = _account()
    if _switched_off(cwd, _plugin_ids(claude, account)):
        return False
    if mode == "always":
        return True
    # the synced copy that registered the guard wrote the account it ran as. For that account maisecrets is
    # meant to run while its synced folder is there, and in the minutes after an update moved it to the
    # trash (a folder that is gone is the case the guard is for). A folder gone for longer means the
    # organisation took maisecrets out of the sync: the guard stops expecting it, or it would block every
    # session for good (reviews, 2026-09-29). Another account falls through to its own synced folder.
    registered = cfg.get("accounts") if isinstance(cfg.get("accounts"), list) else [cfg.get("account")]
    if account and account in registered:
        roots = cfg.get("roots") if isinstance(cfg.get("roots"), dict) else {}
        folders = [roots[account]] if isinstance(roots.get(account), str) else []
        # the folder this account's copy ran from (measured), then every copy the sync holds for it now
        folders += _synced_copies(claude, account)
        return (any(os.path.isfile(os.path.join(f, ".claude-plugin", "plugin.json")) for f in folders)
                or _recently_trashed(claude))
    if account and _synced_copies(claude, account):
        return True
    if mode is None:
        return False            # no guard.json and no synced copy: maisecrets writes no heartbeat here
    installed = _load(os.path.join(claude, "plugins", "installed_plugins.json")).get("plugins") or {}
    return any(k.startswith("maisecrets@") for k in installed)


def heartbeat_name(session: str, event: str, ident: str) -> str:
    """The same name maisecrets.hooks._heartbeat writes; the tests hold both to it."""
    return hashlib.sha256(f"{session}\0{event}\0{ident}".encode()).hexdigest()[:32]


def _clipboard_commands() -> list:
    """The clipboard writers of this platform that are on the PATH, first choice first."""
    if sys.platform == "darwin":
        names = [["pbcopy"]]
    elif os.name == "nt":
        names = [["clip"]]
    else:
        names = [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    return [n for n in names if shutil.which(n[0])]


def _copy_resume(session: str) -> bool:
    """Put the restart command on the clipboard, once per session: a refusal comes for every call, and the
    person may copy something else in between. MAISECRETS_GUARD_CLIPBOARD=off turns it off (tests, harness)."""
    if os.environ.get("MAISECRETS_GUARD_CLIPBOARD", "").lower() in ("off", "0", "false"):
        return False
    marker = os.path.join(_home(), "alive", heartbeat_name(session, "clipboard", "") + ".clip")
    if os.path.exists(marker):
        return True
    for cmd in _clipboard_commands():
        try:
            r = subprocess.run(cmd, input=f"claude --resume {session}".encode(), timeout=2,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:
            try:
                os.makedirs(os.path.dirname(marker), mode=0o700, exist_ok=True)
                open(marker, "w").close()
            except OSError:
                pass            # no marker: the next refusal copies again, which is harmless
            return True
    return False


def _refusal(hook_event: str, session: str, cause: str = "update") -> dict:
    """cause: "update" (a maisecrets folder went to the trash minutes ago), "slow" (maisecrets started and did not
    answer), "unknown" (no start and no sign of an update)."""
    if cause == "slow":
        message = SLOW
    else:
        # a synced update: /reload-plugins keeps the gone generation path (measured 2026-09-29); a new process
        # does not
        message = (MESSAGE if cause == "update" else RETRY).format(
            script=os.path.join(_claude_dir(), "maisecrets-guard.py"), session=session,
            clip=CLIP if _copy_resume(session) else "")
    if hook_event == "UserPromptSubmit":
        return {"decision": "block", "reason": message}
    if hook_event == "PreToolUse":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": message}}
    if cause != "update":
        # the tool ran: running it again repeats what it did. Its effect can be read in a new call
        message = message.replace("so the call did not run. Run it again.", "so its result is not shown.")
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                   "updatedToolOutput": f"[{message} The tool ran; its output is withheld.]"}}


def decide(payload: dict, wait: float) -> dict:
    hook_event = payload.get("hook_event_name", "")
    event = EVENTS.get(hook_event)
    if event is None or "turn_id" in payload or "prompt_id" not in payload:
        return {}               # not an event maisecrets guards, or not Claude Code (Codex sends turn_id)
    ident = payload.get("prompt_id") if event == "user-prompt" else payload.get("tool_use_id")
    session = payload.get("session_id")
    if not ident or not session or not expected(str(payload.get("cwd") or "")):
        return {}
    done = os.path.join(_home(), "alive", heartbeat_name(session, event, ident))
    started = done + ".s"
    begin = time.monotonic()
    while True:
        if os.path.exists(done):
            return {}           # maisecrets answered this call
        now = time.monotonic()
        # no start within `wait`: maisecrets does not run; started but no answer by its own watchdog: it died
        if now - begin >= wait and not os.path.exists(started):
            return _refusal(hook_event, session, "update" if _recently_trashed(_claude_dir()) else "unknown")
        if now - begin >= wait + ANSWER_WAIT[hook_event]:
            return _refusal(hook_event, session, "slow")
        time.sleep(0.05)


def switch_off() -> str:
    home = _home()
    os.makedirs(home, mode=0o700, exist_ok=True)
    cfg = _load(os.path.join(home, "guard.json"))
    with open(os.path.join(home, "guard.json"), "w", encoding="utf-8") as f:
        # the person's own off: without "by", so a policy that allows the guard again does not undo it
        json.dump({**{k: v for k, v in cfg.items() if k != "by"}, "expect": "off"}, f)
    return f"the maisecrets guard is off ({os.path.join(home, 'guard.json')}); /maisecrets:guard install turns it on"


def main() -> int:
    if sys.argv[1:] == ["--off"]:
        print(switch_off())
        return 0
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = {}
    try:
        wait = float(os.environ.get("MAISECRETS_GUARD_WAIT", "5"))
    except ValueError:
        wait = 5.0
    out = decide(payload if isinstance(payload, dict) else {}, wait)
    sys.stdout.write(json.dumps(out))
    if out:
        _marker("guard.fired")
    return 0


if __name__ == "__main__":
    sys.exit(main())
