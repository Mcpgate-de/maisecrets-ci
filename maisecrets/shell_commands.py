"""How the hooks read a shell command: the context of each character, the simple commands and their command words,
the reasons a command that carries a placeholder is refused, the ssh route, the backstop patterns of a store read and
the calls of a hook entry. hooks.py imports every name again, so hooks.<name> is the same object."""
from __future__ import annotations

import os
import re

from .lazy_regex import LazyRx as _LazyRx

# Reads of the store by the agent itself. The value is for the command a human approved,
# not for the agent's context. Text matching, so a backstop and not a boundary; the
# boundary is the grant (a reference resolves only through a nonce this hook minted).
# text matching is a backstop, never the boundary (docs/THREAT-MODEL.md C8); each pattern is
# named so a deny can say what it matched and the user can report a false positive
_STORE_READ_PATTERNS: list[tuple[str, str]] = [
    # the launchers route `get` to the CLI too (review, 2026-09-29: `run.sh get` and `run.cmd get` passed)
    ("maisecrets get", r"(?<![\w.-])maisecrets(?:\.cli)?(?:\.py)?\s+get\b|(?<![\w-])cli\.py\s+get\b"
                       r"|(?<![\w-])(?:dispatch\.py|run\.sh|run\.cmd)[\"']?\s+get\b"),
    ("keychain read of the maisecrets service",
     r"security\s+find-generic-password[^\n]*maisecrets|security\s+dump-keychain"),
    # listing every credential names no resource (review, 2026-09-29): the type itself is the read
    ("Credential Locker read", r"PasswordVault[^\n]*maisecrets|maisecrets[^\n]*PasswordVault"
                               r"|Windows\.Security\.Credentials\.PasswordVault"
                               r"|PasswordVault[^\n]*Retrieve(?:All|Password)"),
    ("the vault files", r"vault\.enc\.json|vault\.json[^\n]*maisecrets|maisecrets[^\n]*vault\.json"),
    # MAISEC~1: the 8.3 name Windows gives the default home (review, 2026-09-29)
    # a wildcard that opens it: ~/.maisec*/index.json (review, 2026-09-29)
    ("the maisecrets home directory", r"(?i:\.maisecrets|maisec~\d)(?![\w-])|(?i:\.mais\w*[*?])"
                                      r"|MAISECRETS_HOME"),
    ("the value resolver", r"(?<![\w-])hooks[/\\]resolve\.py\b|resolve\.py\s+\S+\s+--grant\b"
                           r"|(?<![\w-])resolve\s+\S+\s+--grant\b|cmd_resolve|\.redeem\("),
    ("the ssh approval store", r"ssh-approvals|ssh_approval|ssh-consent\.json"),
    # the mod's question stores values and scrubs a transcript by session id: for the mod, not the agent
    ("the mod's question", r"(?<![\w-])(?:dispatch\.py|run\.sh|run\.cmd)[\"']?\s+[\"']?mod-prompt\b"),
    # the guard outside the plugin folder: `--off` in its refusal is for the person, not the agent
    ("the maisecrets guard", r"maisecrets-guard\.py"),     # guard.json sits in the home, covered above
    ("a value delivery path", r"maisecrets[/\\]run[/\\]|maisecrets-\d+[/\\]|maisecrets[/\\](?:v-|sealed)|__ms_\d+\b"
                              r"|XDG_RUNTIME_DIR[^\n]*maisecrets"),
]
_STORE_READ_RE = _LazyRx("|".join(f"(?P<p{i}>{rx})" for i, (_n, rx) in enumerate(_STORE_READ_PATTERNS)))
# PowerShell on Windows: command names and file names in any case (Get-Content VAULT.ENC.JSON reads the file)
_STORE_READ_RE_I = _LazyRx(_STORE_READ_RE.pattern, re.IGNORECASE)


def _store_read_match(command: str, windows_paths: bool = False) -> str | None:
    """The name of the backstop pattern a command matches, or None. With windows_paths, a directory
    matches in any case and with / or \\ between its parts, as a Windows path does."""
    for d in _store_dir_spellings():
        # a home set by environment variable has no `.maisecrets` in its name (invariant I3, 2026-09-28)
        if windows_paths:
            # Win32 drops trailing dots of a path part: `<home>.\index.json` opens the home (review, 2026-09-29)
            rx = r"\.*[/\\]+".join(re.escape(p) for p in re.split(r"[/\\]+", d)) + r"\.*(?![\w.-])"
            if re.search(rx, command, re.IGNORECASE):
                return "the maisecrets home directory"
        elif re.search(re.escape(d) + r"(?![\w.-])", command):
            return "the maisecrets home directory"
    m = (_STORE_READ_RE_I if windows_paths else _STORE_READ_RE).search(command)
    if not m:
        return None
    for i, (name, _rx) in enumerate(_STORE_READ_PATTERNS):
        if m.group(f"p{i}") is not None:
            return name
    return "store read"


def _store_dir_spellings() -> list[str]:
    """The protected directories as the configured path and as the real path, longest first."""
    from .vault import HOME
    names = {str(HOME).rstrip(os.sep)} | set(_protected_dirs())
    return sorted((n for n in names if len(n) > 1), key=len, reverse=True)


def _protected_dirs() -> list[str]:
    """The vault home and the value run directory, as real paths: a tool that reads them bypasses every
    gate around a resolve (external review, 2026-09-28: Read was not checked at all)."""
    import tempfile
    from .vault import HOME
    dirs = [str(HOME)]
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    dirs.append(os.path.join(xdg, "maisecrets") if xdg else "")
    dirs.append(os.path.join(tempfile.gettempdir(), f"maisecrets-{os.getuid()}") if hasattr(os, "getuid") else "")
    return [os.path.realpath(os.path.expanduser(d)) for d in dirs if d]


_HEREDOC_RE = _LazyRx(r"<<(?P<dash>-?)[ \t]*(?P<tag>(?:'[^'\n]*'|\"[^\"\n]*\"|\\[^\s]|[^\s;&|<>()'\"\\])+)")
_REFUSED_CONTEXT = {
    "ansi": "inside $'…' the value would need ANSI-C escaping",
    "backtick": "inside `…` the value would be parsed a second time",
    "hdq": "inside a quoted heredoc nothing expands, the file would get the variable name",
    "hdx": "inside a heredoc that runs a command substitution the placement cannot be proven",
    "arith": "inside $((…)) a value is not a number",
}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "mksh"}
INLINE_INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua", "osascript",
                       "deno", "bun"}
INLINE_CODE_FLAGS = _LazyRx(r"^-(?:[A-Za-z]*[ceE][A-Za-z]*|-eval|-command|-exec)$")
REMOTE_OR_EVAL = {"ssh", "eval", "su", "expect", "script", "sshpass", "plink", "mosh", "screen", "tmux"}
# commands that run other commands with arguments they build from their input
ARG_RUNNERS = {"xargs", "parallel", "watch", "flock", "chroot", "nsenter", "unshare", "setsid", "runuser",
               "strace", "ltrace", "gdb", "script", "busybox", "systemd-run", "toybox"}
# variables that name the ssh command another tool runs
_SSH_VAR_RE = _LazyRx(r"(?<![\w])(?:GIT_SSH_COMMAND|GIT_SSH|RSYNC_RSH|CVS_RSH)=")
# a variable in front of a fixed path is a known command word: "$HOME/bin/tool", ${REPO}/bin/x
_FIXED_TAIL_RE = _LazyRx(r"^\$\{?[A-Za-z_][A-Za-z_0-9]*\}?(?:/[^/$`\s]+)+$")
# arguments that name stdin as the file to run
_STDIN_FILES = {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}
# clients that read statements from stdin when no statement is given
_SQL_CLIENTS = {"mysql", "mariadb", "psql", "sqlite3", "mongo", "mongosh", "redis-cli", "clickhouse-client"}
ENCODERS = {"base64", "base32", "xxd", "od", "hexdump", "uuencode", "rev", "b2sum", "cksum"}
SHELL_KEYWORDS = {"{", "}", "!", "if", "then", "else", "elif", "fi", "while", "until", "do", "done", "case",
                  "esac", "coproc", "function", "select", "in"}
# the options of a wrapper that take the next word as their argument; every other option takes none
# a part that feeds its input to a later shell, a group closer with a redirection, and trace settings
# from outside the shell's own words (reviews of 0.5.4, 2026-09-28)
_EXEC_RE = _LazyRx(r"^(?:(?:command|builtin)\s+)*exec\b")
_CLOSER_RE = _LazyRx(r"^(?:(?:\}|\)|done|fi|esac)(?![A-Za-z0-9_])|\d*<)")   # `( bash )<f` leaves `<f`
_TRACE_RE = _LazyRx(
    r"(?:^|[\s;&|(])(?:SHELLOPTS|BASHOPTS)="                                     # an assignment
    r"|(?:^|[\s;&|(])(?:export|declare|typeset|readonly)\b[^;&|\n]*\b(?:SHELLOPTS|BASHOPTS)\b"
    r"|(?:^|[\s;&|(])set\b[^;&|\n]*\s[-+]o\s+(?:xtrace|verbose)\b"             # set … -o xtrace
    r"|(?:^|[\s;&|(])set\b[^;&|\n]*\s-[A-Za-z]*[xv][A-Za-z]*(?=\s|$|[;&|])"      # set … -x / -v
    r"|(?:^|[\s;&|(])shopt\b[^;&|\n]*\b(?:xtrace|verbose)\b")
ENVS = {"env", "genv"}


def _env_splits(args: list[str]) -> bool:
    """Whether env, given these words after its name, builds its command from a string (-S,
    --split-string or a prefix of it such as --sp). -u, -C and -P take an argument: in `-uS` the S
    is a variable name. Real words, so `/usr/bin/env '-S'` and `\\env -S` count (review, 2026-09-28)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--" or not a.startswith("-") or a == "-":
            return False
        if a.startswith("--"):
            name = a.split("=", 1)[0]
            if len(name) > 2 and "--split-string".startswith(name):
                return True
            i += 2 if name in ("--unset", "--chdir") and "=" not in a else 1
            continue
        for j, letter in enumerate(a[1:], 1):
            if letter == "S":
                return True
            if letter in "uCP":
                i += 1 if a[j + 1:] else 2
                break
        else:
            i += 1
    return False


WRAPPER_ARG_OPTIONS = {
    "env": ("-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-P"),
    "sudo": ("-u", "-g", "-h", "-p", "-C", "-U", "-T", "-r", "-t", "-D", "--user", "--group", "--host"),
    "doas": ("-u", "-C"),
    "timeout": ("-s", "--signal", "-k", "--kill-after"),
    "nice": ("-n", "--adjustment"),
    "ionice": ("-c", "-n", "-p", "--class", "--classdata"),
    "stdbuf": ("-i", "-o", "-e"),
    "exec": ("-a",),
    "time": ("-f", "-o", "--format", "--output"),
    "caffeinate": ("-t", "-w"),
    "command": (),
}
WRAPPERS = {"env", "genv", "command", "exec", "nice", "time", "nohup", "sudo", "doas", "builtin", "timeout", "stdbuf",
            "caffeinate", "ionice", "chronic"}
_SLICE_RE = _LazyRx(r"\$\{[A-Za-z_][A-Za-z_0-9]*(?::\s*\d|:\s+-\d|\^|,|//|/|#|%)")


# before a comment or a heredoc body: the parser's reading is sure only when no bracket, brace, parenthesis,
# backslash or backtick comes first. Inside (( )), $[ ], [[ ]], ${ }, a zsh pattern or after an escape the shell
# reads no comment or heredoc there and runs what follows (reviews of 0.6.7, rounds 4 to 6). The parser itself is
# not changed: a misread comment would flip its quote state and hide the next line.
_UNSURE_BEFORE_COMMENT = _LazyRx(r"[()\[\]{}\\`]")
_UNSURE_BEFORE_HEREDOC = _LazyRx(r"[(){}\[\\`]")       # ((1<<TAG)) is a shift, no heredoc (codex round 7)


def comment_is_sure(command: str, ctxs: list[str], pos: int) -> bool:
    """The comment that holds pos is one for the shell too."""
    k = pos
    while k > 0 and ctxs[k - 1] == "comment":
        k -= 1
    return "\r" not in command and not _UNSURE_BEFORE_COMMENT.search(command, 0, k)


def heredoc_is_sure(command: str, ctxs: list[str], pos: int) -> bool:
    """The heredoc body that holds pos is one for the shell too: the plain text before it opens no ((, ${ or $[."""
    k = pos
    while k > 0 and ctxs[k - 1] in ("hd", "hdq", "hdx"):
        k -= 1
    if "\r" in command:         # the parser ends a heredoc at TAG\r, the shell does not, and the quotes move (Opus)
        return False
    return not _UNSURE_BEFORE_HEREDOC.search("".join(c for c, cx in zip(command[:k], ctxs[:k]) if cx == ""))


def _shell_contexts(command: str) -> list[str]:
    """One context per character position of a bash command line, as a small state machine
    reads it. Contexts: '' (plain word), 'sq' (inside '…'), 'dq' (inside "…"), 'hd' (body of
    an unquoted heredoc, expands like dq), 'comment', and the ones the rewrite refuses:
    'ansi' ($'…'), 'backtick', 'hdq' (body of a quoted heredoc), 'hdx' (an unquoted heredoc
    body with a command substitution in it), 'arith' ($((…))). A $(…) opens a fresh quoting
    scope on a stack with its own parenthesis depth, so a placeholder inside
    "$(printf '%s' ⟦X⟧)" is placed for the inner single quotes and a `)` of a subshell inside
    does not close the scope (reviews, 2026-09-26)."""
    n = len(command)
    out = [""] * n
    stack: list[str] = [""]          # quoting scope per $( ) level
    depth: list[int] = [0]           # open '(' inside the current $( ) scope
    pending: list[tuple[str, bool]] = []   # heredocs announced on the current line: (tag, quoted)
    i = 0
    while i < n:
        c = command[i]
        st = stack[-1]
        if st == "sq":
            out[i] = "sq"
            if c == "'":
                stack[-1] = ""
            i += 1
            continue
        if st in ("ansi", "backtick"):
            out[i] = st
            if c == "\\":
                if i + 1 < n:
                    out[i + 1] = st
                i += 2
                continue
            if (st == "ansi" and c == "'") or (st == "backtick" and c == "`"):
                if st == "backtick" and len(stack) > 1:
                    stack.pop()
                    depth.pop()
                else:
                    stack[-1] = ""
            i += 1
            continue
        if st == "arith":
            out[i] = "arith"
            if c == "(":
                depth[-1] += 1
            elif c == ")":
                depth[-1] -= 1
                if depth[-1] <= 0:
                    stack.pop()
                    depth.pop()
            i += 1
            continue
        if st == "dq":
            out[i] = "dq"
            if c == "\\":
                if i + 1 < n:
                    out[i + 1] = "dq"
                i += 2
                continue
            if c == '"':
                stack[-1] = ""
                i += 1
                continue
            if c == "$" and command.startswith("$((", i):
                out[i + 1] = out[i + 2] = "arith"
                stack.append("arith")
                depth.append(2)
                i += 3
                continue
            if c == "$" and i + 1 < n and command[i + 1] == "(":
                out[i + 1] = "dq"
                stack.append("")
                depth.append(0)
                i += 2
                continue
            if c == "`":
                out[i] = "backtick"     # a backtick inside "…" starts a substitution too
                stack.append("backtick")
                depth.append(0)
            i += 1
            continue
        # plain
        if c == "\\":
            out[i] = ""
            if i + 1 < n:
                out[i + 1] = ""
            i += 2
            continue
        if c == "\n":
            out[i] = ""
            i += 1
            if pending:
                # heredoc bodies follow, in announcement order, each up to its terminator line
                for tag, quoted, dash in pending:
                    ctx = "hdq" if quoted else "hd"
                    body_start = i
                    while i < n:
                        eol = command.find("\n", i)
                        eol = n if eol < 0 else eol
                        line = command[i:eol].rstrip("\r")
                        probe = line.lstrip("\t") if dash else line
                        if probe == tag:
                            for k in range(i, min(eol + 1, n)):
                                out[k] = ""
                            i = eol + 1
                            break
                        for k in range(i, min(eol + 1, n)):
                            out[k] = ctx
                        i = eol + 1
                    if not quoted:
                        body = command[body_start:i]
                        if "$(" in body or "`" in body:
                            for k in range(body_start, min(i, n)):
                                if out[k] == "hd":
                                    out[k] = "hdx"
                pending = []
            continue
        if c == "#" and (i == 0 or command[i - 1] in " \t\n;&|("):
            eol = command.find("\n", i)
            eol = n if eol < 0 else eol
            for k in range(i, eol):
                out[k] = "comment"
            i = eol
            continue
        if c == "'":
            out[i] = ""
            stack[-1] = "sq"
            i += 1
            continue
        if c == '"':
            out[i] = ""
            stack[-1] = "dq"
            i += 1
            continue
        if c == "$" and i + 1 < n and command[i + 1] == "'":
            out[i] = out[i + 1] = "ansi"
            stack[-1] = "ansi"
            i += 2
            continue
        if c == "$" and command.startswith("$((", i):
            out[i] = out[i + 1] = out[i + 2] = "arith"
            stack.append("arith")
            depth.append(2)
            i += 3
            continue
        if c == "$" and i + 1 < n and command[i + 1] == "(":
            out[i] = out[i + 1] = ""
            stack.append("")
            depth.append(0)
            i += 2
            continue
        if c == "(":
            out[i] = ""
            depth[-1] += 1
            i += 1
            continue
        if c == ")":
            out[i] = ""
            if depth[-1] > 0:
                depth[-1] -= 1
            elif len(stack) > 1:
                stack.pop()
                depth.pop()
            i += 1
            continue
        if c == "`":
            out[i] = "backtick"
            stack.append("backtick")
            depth.append(0)
            i += 1
            continue
        if c == "<" and command.startswith("<<<", i):
            out[i] = out[i + 1] = out[i + 2] = ""      # a here-string is a word, not a heredoc
            i += 3
            continue
        if c == "<" and command.startswith("<<", i):
            m = _HEREDOC_RE.match(command, i)
            if m:
                for k in range(i, m.end()):
                    out[k] = ""
                raw = m.group("tag")
                quoted = any(ch in raw for ch in "'\"\\")
                tag = raw.replace("'", "").replace('"', "").replace("\\", "")
                pending.append((tag, quoted, bool(m.group("dash"))))
                i = m.end()
                continue
        out[i] = ""
        i += 1
    return out


def _quote_state(command: str, pos: int) -> str:
    """Context of the placeholder at ``pos``; see _shell_contexts."""
    ctxs = _shell_contexts(command)
    return ctxs[pos] if pos < len(ctxs) else ""


_ASSIGN_RE = _LazyRx(r"^[A-Za-z_][A-Za-z_0-9]*=")
# a redirection word: group 1 is a target glued to the operator
_REDIR_RE = _LazyRx(r"^(?:\d+|&)?(?:<<<|<<-?|<>|<&|>&|>>|>\||<|>)(.*)$")


def _segments(command: str, ctxs: list[str]) -> list[dict]:
    """The simple commands of a command line, read only in the plain context: text inside
    quotes, comments and heredoc bodies is masked to 'Q' so it never forms a command word
    (`python3 script.py`, a word in a comment and `docker run -e` were taken for a nested
    shell by a substring regex; review, 2026-09-26). Each segment: its words with leading
    assignments and wrappers (env, sudo, nice, …) removed, its command word (basename),
    whether it is fed by a pipe and whether it announces a heredoc."""
    # a backslash before a newline continues the line: `bash \<newline>-c '…'` is `bash -c '…'`, and a
    # split there hid -c from every rule (review, 2026-09-28). Two spaces keep every offset.
    command = re.sub(r"(?<!\\)((?:\\\\)*)\\\n", lambda m: m.group(0) if ctxs[m.end() - 2] not in ("", "dq")
                     else m.group(1) + "  ", command)
    masked = "".join(ch if ctx == "" else ("\n" if ch == "\n" else "Q") for ch, ctx in zip(command, ctxs))
    segs: list[dict] = []
    piped = False
    cur: list[str] = []
    heredoc = False
    start = 0                       # offset of the first character of the current segment

    def flush(next_piped: bool) -> None:
        nonlocal cur, piped, heredoc
        text = "".join(cur).strip()
        if text:
            segs.append({"text": text, "piped": piped, "heredoc": heredoc, "start": start, "end": i})
        cur, piped, heredoc = [], next_piped, False

    i = 0
    while i < len(masked):
        ch = masked[i]
        if not cur:
            start = i
        if masked.startswith("<<", i) and not masked.startswith("<<<", i):
            heredoc = True
        if ch in ";\n()" :
            flush(False)
            i += 1
            continue
        if ch == "|":
            two = masked.startswith("||", i)
            flush(not two)
            # |& pipes stderr as well: still a pipe (final review, 2026-09-28)
            i += 2 if two or masked.startswith("|&", i) else 1
            continue
        if ch == "&" and not ((i and masked[i - 1] in "<>") or masked.startswith("&>", i)):
            # a redirection is no separator: 2>&1, <&3, &>file (the ask showed "2>" for 2>&1)
            flush(False)
            i += 2 if masked.startswith("&&", i) else 1
            continue
        cur.append(ch)
        i += 1
    flush(False)
    import shlex as _shlex
    for seg in segs:
        words = seg["text"].split()
        # the real words, with quotes and backslashes removed as the shell removes them: `\ssh`,
        # `s''sh` and `b''ash '-c'` were not recognised and passed every rule on command words
        # (review, 2026-09-27). A heredoc body line is all 'Q' in the masked text and keeps its mask.
        if set(seg["text"]) - set("Q \t"):
            try:
                words = _shlex.split(command[seg["start"]:seg["end"]]) or words
            except ValueError:
                pass
        # leading assignments, shell keywords and wrappers: the command word is behind them. `{ ssh …; }`,
        # `if …; then ssh …`, `! ssh` and `env -i ssh` hid ssh from every rule (security review, 2026-09-28)
        while words and (_ASSIGN_RE.match(words[0]) or words[0] in SHELL_KEYWORDS or _REDIR_RE.match(words[0])
                         or os.path.basename(words[0]) in WRAPPERS):
            m = _REDIR_RE.match(words[0])
            if m:
                # a redirection before the command word, with its target glued on or as the next word
                # (Codex review, 2026-09-28)
                words = words[1:] if m.group(1) else words[2:]
                continue
            w = os.path.basename(words[0])
            words = words[1:]
            if w in ENVS and _env_splits(words):
                seg["env_split"] = True
            if w == "case":
                # `case WORD in`: the word is matched, not run
                words = words[words.index("in") + 1:] if "in" in words else []
                continue
            if w == "function" and words:
                # `function f { base64; }`: the name is not the command word (review, 2026-09-28)
                words = words[1:]
                continue
            if w in SHELL_KEYWORDS or _ASSIGN_RE.match(w):
                continue
            takes = WRAPPER_ARG_OPTIONS.get(w, ())
            while words and words[0].startswith("-") and words[0] != "-":
                opt = words[0]
                words = words[2:] if opt in takes else words[1:]
            if w == "timeout" and words and re.fullmatch(r"[0-9.]+[smhd]?", words[0]):
                words = words[1:]
        seg["words"] = words
        seg["cmd"] = os.path.basename(words[0]) if words else ""
    return segs


_REF_RE = _LazyRx(r"⟦[^⟦⟧]*⟧")


def _value_reaches(command: str, ctxs: list[str], segs: list[dict]) -> list[bool]:
    """Which parts of the command can read the value: a part that holds it, and a part fed by a
    pipe after one that holds it. The encoder rule asks this, so that base64 on a remote script
    next to `printf ⟦K⟧ | ssh` is not refused (feedback on 0.5.2, 2026-09-28). A value that can come
    back anywhere else makes every part a reader: a variable, a file, a heredoc, a process
    substitution, a function, an alias, read or mapfile."""
    refs = [m.start() for m in _REF_RE.finditer(command)]
    held = [any(sg["start"] <= r < sg["end"] for r in refs) for sg in segs]
    masked = "".join(ch if ctx == "" else "Q" for ch, ctx in zip(command, ctxs))
    everywhere = bool(refs) and (
        any(sg["heredoc"] for sg in segs) or "<(" in masked or ">(" in masked
        or re.search(r"\(\s*\)|(?:^|[\s;&|({])(?:function|alias|read|mapfile|readarray|tee|source|\.)(?:\s|$)",
                     masked)
        or any(h and re.search(r"[<>]", masked[sg["start"]:sg["end"]]) for h, sg in zip(held, segs)))
    if not everywhere:
        # an assignment keeps the value for later parts: X=⟦K⟧, export X=⟦K⟧, X=$(printf ⟦K⟧)
        for m in re.finditer(r"(?:^|[\s;&|({])[A-Za-z_][A-Za-z_0-9]*\+?=", masked):
            end, depth = m.end(), 0
            while end < len(masked) and (depth or not masked[end].isspace()) and (depth or masked[end] not in ";&|"):
                depth += masked[end] == "("
                depth -= masked[end] == ")" and depth > 0
                end += 1
            if any(m.end() <= r < end for r in refs):
                everywhere = True
                break
    if everywhere:
        return [True] * len(segs)
    reach: list[bool] = []
    for k, sg in enumerate(segs):
        reach.append(held[k] or (sg["piped"] and any(held[:k])))
    return reach


def _refusal_for(command: str, ctxs: list[str]) -> str | None:
    """Why a command that carries placeholders is refused: a shell or an interpreter that would
    parse the value a second time, or a step that would encode, slice or trace it. Command
    words only, so `python3 script.py ⟦K⟧` and `docker run -e T=⟦K⟧ img` pass."""
    plain = "".join(ch if ctx in ("", "dq", "hd") else " " for ch, ctx in zip(command, ctxs))
    unquoted = "".join(ch if ctx == "" else " " for ch, ctx in zip(command, ctxs))
    if "ansi" in ctxs or any(ch == "$" and ctx == "" and command[i + 1:i + 2] == '"'
                             for i, (ch, ctx) in enumerate(zip(command, ctxs))):
        # the rewrite refuses a value inside $'…'; a command word in it is hidden as well (Codex review, 2026-09-28)
        return "$'…' quoting hides the command words from the check"
    segs = _segments(command, ctxs)
    reach = _value_reaches(command, ctxs, segs)
    for seg, reached in zip(segs, reach):
        words, cmd = seg["words"], seg["cmd"]
        if seg.get("env_split") or (cmd in ARG_RUNNERS and any(
                os.path.basename(w) in ENVS and _env_splits(words[k + 1:]) for k, w in enumerate(words))):
            # env -S builds its command from a string: the command word is hidden (final review, 2026-09-28)
            return "env -S builds the command from a string, so its command word cannot be checked"
        if not words:
            continue
        flags = [w for w in words[1:] if w.startswith("-")]
        if cmd in ("watch", "parallel") and not (cmd == "watch" and any(f in ("-x", "--exec") for f in flags)):
            return f"{cmd} runs its command through sh -c, which would parse the value a second time"
        if cmd in ARG_RUNNERS or (cmd == "find" and any(w in ("-exec", "-execdir", "-ok", "-okdir") for w in words)):
            inner = next((os.path.basename(w) for w in words[1:] if os.path.basename(w) in
                          SHELLS | REMOTE_OR_EVAL | INLINE_INTERPRETERS | {"scp", "sftp", "autossh", "rsync"}), None)
            if inner:
                return f"{cmd} would hand the value to {inner} as an argument"
        if cmd in SHELLS:
            # input that reaches the shell: a redirection in its own part, an `exec <…` before it, or a
            # redirection on a group around it (`{ bash; } <…`, `( bash ) <…`) (Codex review, 2026-09-28).
            # A `<` of another command, such as `mysql … < dump.sql && bash post.sh`, does not count
            # (final review of 0.5.4).
            redirected = "<" in unquoted[seg["start"]:seg["end"]] or any(
                "<" in unquoted[sg["start"]:sg["end"]] and (
                    (_EXEC_RE.match(sg["text"]) and sg["start"] < seg["start"])
                    or (sg["start"] > seg["start"] and (not sg["words"] or _CLOSER_RE.match(sg["text"]))))
                for sg in segs)
            if any(INLINE_CODE_FLAGS.match(f) and "c" in f for f in flags) or seg["heredoc"] or seg["piped"] \
                    or redirected:
                # input from a redirection or a process substitution is read as code too (Codex review, 2026-09-28)
                return f"{cmd} would parse the value a second time as shell code"
            if any(re.fullmatch(r"[-+][A-Za-z]*[xv][A-Za-z]*", f) for f in flags) or \
                    any(w in ("xtrace", "verbose", "--xtrace", "--verbose", "--debugger") for w in words[1:]) or \
                    _TRACE_RE.search(unquoted):
                # a trace from elsewhere: SHELLOPTS=… or BASHOPTS=…, or set -o xtrace / set -x before the
                # shell (Codex review, 2026-09-28). The word verbose in another command does not count
                # (final review of 0.5.4).
                return f"{cmd} with tracing would print the value"
        if cmd in REMOTE_OR_EVAL:
            return f"{cmd} hands the command line to another shell"
        if cmd in (".", "source") and (seg["piped"] or seg["heredoc"] or any(w in _STDIN_FILES for w in words[1:])):
            return f"{cmd} would run the value as shell code"
        if cmd in INLINE_INTERPRETERS and any(INLINE_CODE_FLAGS.match(f) for f in flags):
            return f"{cmd} with inline code would parse the value as program text"
        if cmd in ENCODERS and reached:
            return f"{cmd} would encode the value"
        if cmd in ("awk", "gawk", "mawk", "nawk") and "-v" in words:
            return "awk -v changes backslashes in the value; use V=⟦KEY⟧ awk '… ENVIRON[\"V\"] …' instead"
        if cmd == "openssl" and reached and len(words) > 1 and words[1] in ("enc", "base64", "dgst"):
            return f"openssl {words[1]} would encode the value"
        if cmd == "set" and any(re.fullmatch(r"-[a-wyz]*x[a-z]*", f) for f in flags):
            return "set -x would trace the value"
        if cmd == "set" and "xtrace" in words:
            return "set -o xtrace would trace the value"
        for w in words[1:]:
            # a shell named later in the segment with its own -c: docker run img sh -c "…"
            if os.path.basename(w) in SHELLS:
                rest = words[words.index(w) + 1:]
                if any(INLINE_CODE_FLAGS.match(r) and "c" in r for r in rest if r.startswith("-")):
                    return f"{os.path.basename(w)} -c would parse the value a second time as shell code"
    if re.search(r"(?<![\w-])PS4=", plain):
        return "a custom PS4 would trace the value"
    # ssh in another form, in the parts of the command that carry a value or are piped with one: scp, sftp,
    # autossh or mosh as the command; rsync with a remote shell and the value in its own arguments; a
    # variable that names an ssh command (GIT_SSH_COMMAND, RSYNC_RSH, …) or git -c core.sshCommand anywhere.
    # A word that only mentions ssh (ansible -c ssh, a path ending in /rsync) does not count (final
    # review and differential test against 0.5.2, 2026-09-28)
    segs = _segments(command, ctxs)
    # every token, a server's too (vault_refs.py): offsets of the stored-value form alone missed `scp f h:⟦NAME_2⟧`
    offsets = [m.start() for m in _REF_RE.finditer(command) if ctxs[m.start()] != "comment"]
    if offsets and _SSH_VAR_RE.search(plain):
        return "a variable that names an ssh command would hand the value to ssh in a form that cannot be checked"
    with_value = {n for n, sg in enumerate(segs) if any(sg["start"] <= a < sg["end"] for a in offsets)}
    related = set(with_value)
    for n in sorted(with_value):
        k = n
        while k > 0 and segs[k]["piped"]:
            k -= 1
            related.add(k)
        k = n + 1
        while k < len(segs) and segs[k]["piped"]:
            related.add(k)
            k += 1
    for n in sorted(related):
        sg = segs[n]
        words = sg["words"]
        if sg["cmd"] in ("scp", "sftp", "autossh", "mosh"):
            return (f"{sg['cmd']} hands its arguments to a remote shell; "
                    "a value reaches ssh only as printf '%s' ⟦KEY⟧ | ssh host '…'")
        if sg["cmd"] == "git" and any(w.lower().startswith("core.sshcommand=") for w in words):
            return "git -c core.sshCommand would hand the value to ssh in a form that cannot be checked"
        if sg["cmd"] == "rsync" and n in with_value:
            remote_spec = any(re.match(r"^(?:[^\s/@:]+@)?[\w.-]+:(?!//)", w) for w in words[1:])
            rsh = any(w in ("-e", "--rsh") or w.startswith(("--rsh=", "-e")) for w in words[1:])
            if remote_spec or rsh:
                return "rsync over ssh hands its arguments to a remote shell; pass the value another way"
    m = _SLICE_RE.search(plain)
    if m:
        return f"the parameter expansion {m.group(0)}… would slice or rewrite the value"
    return None


# ssh options that take an argument (OpenSSH 9)
_SSH_ARG_FLAGS = set("BbcDEeFIiJLlmOoPpQRSWw")
# flags and -o options that pick another route, share a connection, change the destination or run a
# local command: the route sets its own, and the user must read the real destination
_SSH_REFUSED_FLAGS = set("JWSMOF")
_SSH_REFUSED_OPTIONS = ("proxycommand", "proxyjump", "proxyusefdpass", "controlmaster", "controlpath",
                        "controlpersist", "hostname", "localcommand", "permitlocalcommand", "knownhostscommand",
                        "remotecommand", "include", "tunnel")


def _ssh_options(toks: list[str], i: int, opts: list) -> int:
    """Read ssh options from toks[i:] into opts as (flag, value); return the index after them."""
    while i < len(toks) and toks[i].startswith("-") and toks[i] != "--" and toks[i] != "-":
        letters, i, took_next = toks[i][1:], i + 1, False
        for n, c in enumerate(letters):
            if c in _SSH_ARG_FLAGS:
                val = letters[n + 1:]
                if not val and i < len(toks):
                    val, took_next = toks[i], True
                opts.append((c, val))
                break
            opts.append((c, None))
        if took_next:
            i += 1
    return i


def _ssh_way(why: str) -> str:
    """The form that works for what the refused remote command wanted to do. The answer names a way,
    not only the rule: an ops user needs root-only logs, and "the remote su would hand the value to
    another shell" left no way forward (field report on 0.5.8, 2026-09-28)."""
    base = ("To give a value to a remote host, pipe it on stdin to the command that reads it, inside the "
            "Claude Code sandbox, one host per command: printf '%s' ⟦KEY⟧ | ssh HOST 'zgrep -F -f - FILE'.")
    # the second hop first: its reason names "another shell or host" too
    if re.search(r"\bremote (?:ssh|sshpass|plink|mosh|autossh|scp|sftp|rsync)\b|\bjump\b|\bproxy\b", why):
        return "For a host behind another host, run one ssh command per host. " + base
    if re.search(r"\b(?:su|sudo|login shell|shell|wrapper)\b", why):
        return ("To read a file only root can read, put sudo in front of the command that reads it, not su "
                "or a shell: printf '%s' ⟦KEY⟧ | ssh HOST 'sudo zgrep -F -f - FILE'. " + base)
    if "encoded" in why:
        return ("Keep the encoder out of the remote command that gets the value; a script can go as the "
                "command's own text instead of through base64. " + base)
    return base


def _remote_refusal(remote: str) -> str | None:
    """Why the remote command would run the value as code, pass it on, or show it encoded. The
    value arrives on its stdin, so a command that reads data there is fine (grep -F -f -, cat > f,
    sh -c 'grep …'); one that reads its program there, or hands the value to another shell or
    host, is not (edge-case review, 2026-09-27: only the first word was checked)."""
    if not remote.strip():
        return "the remote login shell would run the value as shell code; name the command that reads it"
    rctx = _shell_contexts(remote)
    for seg in _segments(remote, rctx):
        words, cmd = seg["words"], seg["cmd"]
        if not words:
            if seg["text"].strip():
                # only a wrapper and its options: sudo -s, sudo -i, env starts a login shell on stdin
                return "the remote wrapper would start a shell that reads the value as shell code"
            continue
        # a redirection glued to the command word: bash</dev/stdin
        cmd = os.path.basename(re.split(r"[<>]", words[0])[0]) or cmd
        if re.search(r"<\s*/dev/(?:stdin|fd/0)", seg["text"]) and cmd in SHELLS | INLINE_INTERPRETERS:
            return f"the remote {cmd} would read the value as its program"
        flags = [w for w in words[1:] if w.startswith("-")]
        args = [w for w in words[1:] if not w.startswith("-") or w == "-"]
        if cmd in ("source", ".") and (not args or args[0] in _STDIN_FILES):
            return "the remote shell would run the value as shell code"
        if cmd in ("crontab", "at", "batch"):
            return f"the remote {cmd} would store the value as code that runs later"
        query_flags = ("-e", "-c", "--execute", "--command", "--eval", "-f", "--file")
        if cmd in _SQL_CLIENTS and not any(f.split("=", 1)[0] in query_flags for f in flags):
            return f"the remote {cmd} would read the value as statements; give the query with -e or -c"
        if cmd == "openssl" and args and args[0] in ("enc", "base64", "dgst"):
            return f"the remote openssl {args[0]} would send the value back encoded"
        if cmd in SHELLS | INLINE_INTERPRETERS and args and args[0] in _STDIN_FILES:
            return f"the remote {cmd} would read the value as its program"
        if "$" in words[0] or "`" in words[0]:
            return "the remote command word is built from a variable and is only known when it runs"
        if cmd in REMOTE_OR_EVAL:
            return f"the remote {cmd} would hand the value to another shell or host"
        if cmd in ENCODERS:
            return (f"the remote {cmd} could send the value back encoded, where the output redaction "
                    "cannot see it")
        if cmd in SHELLS and ("-s" in flags or not any(INLINE_CODE_FLAGS.match(f) and "c" in f for f in flags)):
            return f"the remote {cmd} would read the value as shell code"
        if cmd in SHELLS:
            code = next((words[n + 1] for n, w in enumerate(words[:-1]) if INLINE_CODE_FLAGS.match(w) and "c" in w), "")
            inner = _remote_refusal(code) if code else None
            if inner:
                return inner
        if cmd in INLINE_INTERPRETERS and not [w for w in words[1:] if w != "-" and not w.startswith("-")] \
                and not any(INLINE_CODE_FLAGS.match(f) for f in flags):
            return f"the remote {cmd} would read the value as its program"
        if cmd in ARG_RUNNERS or (cmd == "find" and any(w in ("-exec", "-execdir", "-ok", "-okdir") for w in words)):
            inner = next((os.path.basename(w) for w in words[1:] if os.path.basename(w) in
                          SHELLS | REMOTE_OR_EVAL | INLINE_INTERPRETERS | {"scp", "sftp", "autossh", "rsync"}),
                         None)
            if inner:
                return f"the remote {cmd} would hand the value to {inner}"
    return None


# remote commands that only read and print: the session approval covers these alone (ssh_approval.py)
READ_ONLY_REMOTE = {"grep", "egrep", "fgrep", "zgrep", "zegrep", "zfgrep", "xzgrep", "bzgrep", "rg", "cat", "zcat",
                    "xzcat", "bzcat", "head", "tail", "journalctl", "wc", "sort", "uniq", "cut", "tr", "jq",
                    "ls", "stat", "uptime", "df", "du", "true"}
# journalctl options that change state or write a file; getopt takes an unambiguous prefix, so a
# prefix of one of these counts too (Codex review, 2026-09-28: --rotate and --vacuum-time passed)
_JOURNALCTL_STATEFUL = ("--rotate", "--vacuum-size", "--vacuum-files", "--vacuum-time", "--flush", "--sync",
                        "--relinquish-var", "--smart-relinquish-var", "--setup-keys", "--update-catalog",
                        "--cursor-file", "--force", "--interval", "--verify-key", "--new-id128",
                        "--synchronize-on-exit")


# wrappers the session approval allows in front of a read-only command, with no option of their own
_READ_ONLY_WRAPPERS = {"sudo", "nice", "command"}
# the only options of sort and uniq the session approval allows: none of them writes a file or runs a
# program (Codex review, 2026-09-28: `sort --out=FILE`, an abbreviation, wrote the value to a file)
_SORT_OK = _LazyRx(r"^(?:-[bdfghinrsuMV]+|-k\S*|-t\S?|--(?:numeric-sort|reverse|unique|ignore-case|"
                      r"human-numeric-sort|version-sort|month-sort|general-numeric-sort|ignore-leading-blanks|"
                      r"dictionary-order|stable))$")
_UNIQ_OK = _LazyRx(r"^(?:-[cdiuz]+|-[fsw]\d*|\d+|--(?:count|repeated|unique|ignore-case))$")


def _remote_is_read_only(remote: str) -> bool:
    """Whether every part of the remote command only reads and prints. Each part is a bare command
    word from READ_ONLY_REMOTE, at most behind sudo (or sudo -n), nice or command without other options: no path, no
    assignment such as PATH=, since a command named grep in /tmp is not grep (Codex review,
    2026-09-28). No output redirection, tee, subshell or expansion, and none of the options with
    which a reader writes a file or runs a program."""
    import shlex
    rctx = _shell_contexts(remote)
    unquoted = "".join(ch if ctx == "" else " " for ch, ctx in zip(remote, rctx))
    if any(c in unquoted for c in "><()&") or "`" in remote or "$" in remote:
        return False
    segs = _segments(remote, rctx)
    if not segs:
        return False
    for sg in segs:
        try:
            raw = shlex.split(remote[sg["start"]:sg["end"]])
        except ValueError:
            return False
        while raw and raw[0] in _READ_ONLY_WRAPPERS:
            # sudo -n (never ask for a password) is how ops scripts call sudo, so a missing rule fails
            # instead of hanging; it changes who reads, not what the command does (field report on 0.5.8)
            raw = raw[2:] if raw[0] == "sudo" and raw[1:2] == ["-n"] else raw[1:]
        if not raw or raw[0] not in READ_ONLY_REMOTE:
            return False             # a path, an assignment, a wrapper option or another command
        cmd, args = raw[0], raw[1:]
        if cmd == "sort" and not all(_SORT_OK.match(a) for a in args):
            return False
        if cmd == "uniq" and not all(_UNIQ_OK.match(a) for a in args):
            return False
        if cmd == "rg" and any(a.startswith("--pre") or a.startswith("--se") for a in args):
            return False
        if cmd == "journalctl":
            for a in args:
                name = a.split("=", 1)[0]
                if name.startswith("--") and len(name) > 2 and \
                        any(o.startswith(name) for o in _JOURNALCTL_STATEFUL):
                    return False
    return True


def _ssh_route(command: str, ctxs: list[str], refs: list[tuple[str, int, int]]) -> dict | str:
    """The one way a value may reach ssh: on stdin, through the Claude Code sandbox. Returns the
    plan, or the reason the command is refused. Whether the user confirms is the rehydration
    policy's decision (rehydration.py), not the route's.

    Two review rounds broke a host allowlist that read the destination from the command text (a
    quoted -oProxyCommand after the host reached another host). The sandbox needs no such proof:
    no command reaches the network directly, and its proxy admits only the allowed hosts
    (measured 2026-09-27 on macOS and Debian 13: 200 for an allowed host, 403 for another). What
    the sandbox cannot see is the remote side, which may pass the value on; under "confirm" the
    user reads the remote command first. The value never sits in ssh's arguments, where the remote
    shell would parse it as code."""
    import shlex
    segs = _segments(command, ctxs)
    ssh_idx = [n for n, seg in enumerate(segs) if seg["cmd"] == "ssh"]
    if len(ssh_idx) != 1:
        return "only one ssh per command can take a value; run each ssh as its own command"
    j = ssh_idx[0]
    seg = segs[j]
    if any(seg["start"] <= a < seg["end"] for _k, a, _b in refs):
        if "<<" in command[seg["start"]:seg["end"]]:
            return "a heredoc or here-string into ssh is not supported; pipe it in: printf '%s' ⟦KEY⟧ | ssh host '…'"
        return ("ssh would put the value into the remote command line, where the remote shell parses it; "
                "pipe it in instead: printf '%s' ⟦KEY⟧ | ssh host 'grep -F -f - …'")
    k = j
    while k > 0 and segs[k]["piped"]:
        k -= 1
    if k == j:
        return "the value reaches ssh only on stdin: printf '%s' ⟦KEY⟧ | ssh host '…'"
    lo, hi = segs[k]["start"], segs[j - 1]["end"]
    if any(not lo <= a < hi for _k, a, _b in refs):
        return "every placeholder must sit in the commands that feed ssh on stdin"
    blanked = command[:seg["start"]] + " " * (seg["end"] - seg["start"]) + command[seg["end"]:]
    other = _refusal_for(blanked, _shell_contexts(blanked))
    if other:
        return other
    text = command[seg["start"]:seg["end"]]
    try:
        toks = shlex.split(text)
    except ValueError:
        return "the ssh command line cannot be read"
    at = next((n for n, t in enumerate(toks) if os.path.basename(t) == "ssh" and not _ASSIGN_RE.match(t)), None)
    if at is None:
        return "the ssh command line cannot be read"
    opts: list = []
    i = _ssh_options(toks, at + 1, opts)
    if i < len(toks) and toks[i] == "--":
        i += 1
    if i >= len(toks):
        return "the ssh command names no host"
    dest = toks[i]
    # OpenSSH reads options after the host too (edge-case review, 2026-09-27: -S after the host won)
    i = _ssh_options(toks, i + 1, opts)
    if i < len(toks) and toks[i] == "--":
        i += 1
    remote = toks[i:]
    for c, val in opts:
        if c == "o" and val and ("$" in val or "`" in val):
            return "an ssh option holds an expansion whose result is only known when it runs"
        key = re.split(r"[=\s]+", val.strip(" \t=\"'"), maxsplit=1)[0].strip("\"'").lower() if c == "o" and val else ""
        if c in _SSH_REFUSED_FLAGS or key in _SSH_REFUSED_OPTIONS or key.startswith("canonical"):
            return ("ssh with its own proxy, jump host, shared connection, config file, host name or local "
                    "command is refused; the sandbox route sets the connection itself")
    # ssh joins the remote words with spaces and the remote shell parses the result again, so the check
    # reads exactly that string (final review, 2026-09-28: quoting each word hid a `;` or a `|`)
    if any("$" in t or "`" in t for t in remote):
        return "the remote command holds an expansion ($ or a backtick) whose result is only known when it runs"
    why = _remote_refusal(" ".join(remote))
    if why:
        return why
    # the insertion point: the end of the ssh command word, found among the plain words of the masked
    # text, so it can never land inside a quoted word or an assignment (edge-case review, 2026-09-27)
    masked = "".join(ch if ctx == "" else "Q" for ch, ctx in zip(command[seg["start"]:seg["end"]],
                                                                  ctxs[seg["start"]:seg["end"]]))
    spans = [(m.start(), m.end(), m.group(0)) for m in re.finditer(r"\S+", masked)]
    # skip what _segments skips: assignments, keywords, wrappers with their options and option arguments
    w = 0
    while w < len(spans) and (_ASSIGN_RE.match(spans[w][2]) or spans[w][2] in SHELL_KEYWORDS
                              or os.path.basename(spans[w][2]) in WRAPPERS):
        wrapper = os.path.basename(spans[w][2])
        w += 1
        if wrapper in WRAPPERS:
            while w < len(spans) and spans[w][2].startswith("-") and spans[w][2] != "-":
                w += 2 if spans[w][2] in WRAPPER_ARG_OPTIONS.get(wrapper, ()) else 1
            if wrapper == "timeout" and w < len(spans) and re.fullmatch(r"[0-9.]+[smhd]?", spans[w][2]):
                w += 1
    ssh_span = spans[w] if w < len(spans) and os.path.basename(spans[w][2]) == "ssh" else None
    if ssh_span is None or "Q" in ssh_span[2]:
        return "write ssh as a plain word, not quoted or escaped: printf '%s' ⟦KEY⟧ | ssh host '…'"
    # the line as written, from the ssh word on: redirections such as 2>&1 stay whole
    line = command[seg["start"] + ssh_span[0]:seg["end"]].strip()
    return {"insert_at": seg["start"] + ssh_span[1], "dest": dest, "line": line, "remote": " ".join(remote)}


_HOOK_ENTRIES = {"session-start", "user-prompt", "pre-tool", "post-tool", "post-tool-failure", "mod-prompt"}


def _calls_a_hook_entry(command: str, broad: bool = False) -> bool:
    """A command word that runs a maisecrets hook entry with an event: the agent would hand the hook a payload it
    wrote, a forged PostToolUse or prompt (plan review of #8, 2026-10-06). Read from the parsed words, so a mention
    in quotes (`echo "… run.sh post-tool"`) is no call (Codex review)."""
    ctxs = _shell_contexts(command)
    segs = _segments(command, ctxs)
    for sg in segs:
        words = sg.get("words") or []
        for k, w in enumerate(words[:-1]):
            # an event in a variable counts only with consent on: `./run.sh $ENV` of another project (opus round 3)
            if os.path.basename(w) in ("run.sh", "run.cmd", "dispatch.py") and (
                    words[k + 1] in _HOOK_ENTRIES or (broad and words[k + 1].startswith("$"))):
                return True
    # inside a nested shell or an interpreter (`bash -c '…run.sh user-prompt …'`, `python3 -c 'os.system(…)'`,
    # `find -exec sh -c`) the words are one string: the text decides. Always for a shell; with ssh consent on
    # (`broad`), for any command that does not only print the text (Gate B of #8, two rounds): a Codex consent has
    # no second proof, so a forged prompt must not reach the hook. With consent off, `python3 -c 'print(…)'` passes.
    shells = {"bash", "sh", "zsh", "dash", "ksh", "fish", "eval", "su", "xargs", "parallel", "watch", "script"}
    printers = {"echo", "printf", "grep", "egrep", "rg", "cat", "head", "tail", "less", "git"}
    for m in re.finditer(r"(?:run\.sh|run\.cmd|dispatch\.py)[\"']?\s+[\"']?"
                         r"(?:session-start|user-prompt|pre-tool|post-tool(?:-failure)?|mod-prompt)\b", command):
        seg = next((sg for sg in segs if sg["start"] <= m.start() < sg["end"]), None)
        if seg and seg.get("cmd") in shells:
            return True
        if broad and not _only_prints(command, ctxs, segs, seg, printers):
            return True
    if broad and re.search(r"\b(?:session-start|user-prompt|pre-tool|post-tool(?:-failure)?|mod-prompt)\b", command):
        # the entry and the event in different words (R=…/run.sh; $R user-prompt): any mention of an entry outside
        # a command that only prints it counts
        for m in re.finditer(r"run\.sh|run\.cmd|dispatch\.py", command):
            seg = next((sg for sg in segs if sg["start"] <= m.start() < sg["end"]), None)
            if not _only_prints(command, ctxs, segs, seg, printers):
                return True
    return False


def _only_prints(command: str, ctxs: list[str], segs: list[dict], seg: dict | None, printers: set) -> bool:
    """The whole command is one printing command with no pipe and no redirect: its text reaches nobody's shell.
    `printf … > /tmp/x; bash /tmp/x` wrote it to a file a later part runs (codex review of the repair)."""
    if not seg or len(segs) != 1 or seg.get("cmd") not in printers:
        return False
    unquoted = "".join(ch if cx == "" else " " for ch, cx in zip(command, ctxs))
    return not re.search(r"[<>|]", unquoted)


def _parse_for_consent(text: str):
    ctxs = _shell_contexts(text)
    return _segments(text, ctxs), ctxs
