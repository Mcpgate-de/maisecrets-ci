"""Whether a path names what the hooks guard: the maisecrets home and the value run directory (by any spelling, link
or file identity), an ssh config, and the config of a client. hooks.py imports every name again, so hooks.<name> is
the same object."""
from __future__ import annotations

import os
import platform
import re

from .shell_commands import _protected_dirs, _store_read_match


def _is_ssh_config_path(path: str, cwd: str) -> bool:
    if not path:
        return False
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    try:
        real = os.path.realpath(p)
    except OSError:
        real = p
    home_ssh = os.path.realpath(os.path.join(os.path.expanduser("~"), ".ssh"))
    if platform.system() in ("Darwin", "Windows"):
        # a case-insensitive file system: ~/.SSH/config is ~/.ssh/config (opus round 3)
        real, home_ssh = os.path.normcase(real).casefold(), os.path.normcase(home_ssh).casefold()
    return real == home_ssh or real.startswith(home_ssh + os.sep)


def _names_a_guarded_file(value: str, cwd: str) -> bool:
    """A value that, used as a path, names the maisecrets home, a store file, an ssh config, the client config or a
    file in the client's config folder (its settings hold the hooks). Each piece is a path too: `--config=PATH`,
    `@PATH`, `file://PATH` (Gate A review)."""
    if "\0" in value:
        return False                            # refused on its own below, with its own reason
    if len(value) > 4096 or _holds_a_guarded_folder(value):
        return True                             # too long to judge, or a guarded folder anywhere (a path with a space)
    pieces = {value.strip()}
    for part in re.split(r"[\s=,;]+", value):
        part = part.strip("'\"")
        for lead in ("file://", "@"):
            if part.startswith(lead):
                part = part[len(lead):]
        if part:
            pieces.add(part)
    return any(_a_guarded_path(v, cwd) for v in pieces if v)


def _holds_a_guarded_folder(value: str) -> bool:
    """The value holds the spelling of a guarded folder anywhere: a path with a space splits into pieces that each
    look harmless (Gate A review, round 2)."""
    from . import vault_refs
    from .vault import HOME
    home = os.path.expanduser("~")
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")
    spellings = {str(HOME), os.path.realpath(str(HOME)), config_dir, os.path.realpath(config_dir),
                 *vault_refs.config_files(), os.path.join(home, ".ssh"), "~/.ssh", "~/.claude", "~/.maisecrets",
                 "$HOME/.ssh", "${HOME}/.ssh", "$HOME/.claude", "${HOME}/.claude"}
    # the Codex config and its folder: the helper line and the hooks of Codex live there
    codex_home = os.environ.get("CODEX_HOME") or os.path.join(home, ".codex")
    spellings |= {codex_home, os.path.realpath(codex_home), "~/.codex", "$HOME/.codex", "${HOME}/.codex"}
    return any(sp and sp in value for sp in spellings)


def _a_guarded_path(v: str, cwd: str) -> bool:
    from . import vault_refs
    try:
        if _store_read_match(v) or _in_the_home(v, cwd) or _is_ssh_config_path(v, cwd):
            return True
        full = v if os.path.isabs(os.path.expanduser(v)) else os.path.join(cwd or os.getcwd(), v)
        real = os.path.realpath(os.path.expanduser(full))
        config_dir = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
        folder = os.path.realpath(config_dir)
        codex = os.path.realpath(os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex"))
        return real in {os.path.realpath(f) for f in vault_refs.config_files()} or real == folder \
            or real.startswith(folder + os.sep) or real == codex or real.startswith(codex + os.sep)
    except (OSError, ValueError):
        return True                             # a path we cannot judge is refused, not served


def _identity(path: str) -> tuple[int, int] | None:
    try:
        st = os.stat(path)
        return st.st_dev, st.st_ino
    except OSError:
        return None


def _abs(path: str, cwd: str) -> str:
    p = os.path.expanduser(path.strip())
    return os.path.realpath(p if os.path.isabs(p) else os.path.join(cwd or os.getcwd(), p))


def _touches_store(path: str, cwd: str = "", contains: bool = False) -> bool:
    """Whether the path lies in a protected directory, compared by file identity (device and inode) of the
    path and each of its parents: on a case-insensitive file system another spelling is the same directory
    (Codex review, 2026-09-28). With ``contains``, a protected directory below the path counts too: a
    recursive Grep over a parent reads the store."""
    if not isinstance(path, str) or not path.strip():
        return False
    real = _abs(path, cwd)
    protected = [d for d in _protected_dirs() if os.path.isdir(d)]
    ids = {_identity(d) for d in protected} - {None}
    probe = real
    while True:
        if _identity(probe) in ids or any(probe == d for d in protected):
            return True
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    if _hardlinked_into(real, protected):
        return True
    if contains and os.path.isdir(real):
        me = _identity(real)
        for d in protected:
            q = d
            while True:
                if _identity(q) == me:
                    return True
                parent = os.path.dirname(q)
                if parent == q:
                    break
                q = parent
    return False


def _hardlinked_into(real: str, protected: list[str]) -> bool:
    """A second name of a store file outside the store (`ln`) has no protected parent: the
    file's own identity decides (invariant I3, 2026-09-28). Only a file with more than one
    link is compared, so an ordinary read costs one stat."""
    try:
        st = os.stat(real)
    except OSError:
        return False
    if st.st_nlink < 2 or not os.path.isfile(real):
        return False
    me = (st.st_dev, st.st_ino)
    for d in protected:
        for top, dirs, files in os.walk(d):
            if top.count(os.sep) - d.count(os.sep) >= 2:
                dirs[:] = []
            for name in files:
                if _identity(os.path.join(top, name)) == me:
                    return True
    return False


def _in_the_home(path: str, cwd: str) -> bool:
    """A path under the maisecrets home or the value run directory, by any spelling or link."""
    from .vault import HOME
    if not path:
        return False
    try:
        expanded = os.path.expanduser(path)
        if expanded and not os.path.isabs(expanded) and cwd:
            expanded = os.path.join(cwd, expanded)   # the client's cwd, not the hook's
        real = os.path.realpath(expanded)
        home = os.path.realpath(str(HOME))
        if platform.system() in ("Darwin", "Windows"):   # case-insensitive file systems (APFS, NTFS)
            real, home = real.lower(), home.lower()
        inside = real == home or real.startswith(home + os.sep)
        # the run directory and a hard link are known by identity only (invariant I3, 2026-09-28)
        inside = inside or _touches_store(path, cwd)
        # the guard script outside the plugin folder: an agent that rewrites it switches the guard off
        guard = os.path.join(os.environ.get("CLAUDE_CONFIG_DIR", os.path.join(os.path.expanduser("~"), ".claude")),
                             "maisecrets-guard.py")
        inside = inside or os.path.realpath(expanded) == os.path.realpath(guard)
    except (OSError, ValueError):
        inside = False
    return inside or ".maisecrets" in path.lower() or "maisecrets-guard.py" in path.lower()
