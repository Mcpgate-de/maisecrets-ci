#!/usr/bin/env python3
"""Find credentials in the approvals and settings that Claude Code and Codex keep outside the repository.

A command that a person approves is stored as text, and a token in that command stays in the file. The working
tree scan (scan_secrets.py) sees only the files of one repository; this script reads the files of this user:

  Claude Code  <claude config>/settings.json, settings.local.json        (the whole file: permissions, env ...)
               .claude.json, its backups, .config.json                 (projects[<path>].allowedTools)
               <project N>/.claude/settings.json, settings.local.json  (each project of .claude.json)
  Codex        <codex home>/config.toml                                (the whole file)
               <codex home>/rules/*.rules                              (prefix_rule lines, the approvals)
               <project N>/.codex/config.toml, .codex/rules/*.rules    (each [projects."<path>"] of config.toml)

<claude config> is CLAUDE_CONFIG_DIR or ~/.claude; .claude.json sits in CLAUDE_CONFIG_DIR, else in the home.
<codex home> is CODEX_HOME or ~/.codex.

Nothing this script prints is a value, a line of a file, a hash of a value, or a name that a person or a client
chose. A finding is a per-run id (S1, S2 ...; the same value keeps its id across files), the file, the place in
it, the type, the rule, how sure the match is and the length. Names print only from a fixed list: a project folder
prints as <project N>; a file name prints only when the client itself writes that name (rules/default.rules,
backups/.claude.json.backup N, without its digits), else as [file N]; a key prints only when it is a setting name
of a client (known_keys.txt) and not a child of mcpServers, mcp_servers, env or projects, else as [key N]; a rule
of the person's own prints as user rule N; a CLAUDE_CONFIG_DIR or CODEX_HOME that is set prints as <claude config> or
<codex home>. A label whose parts form a token once the separators are gone is withheld whole. The names are
still scanned: a token in a project path or a file name is a finding. The script never changes a file.

    python3 audit_approvals.py [--pii] [--out FILE] [--max-mb N]

--out must not name a file this script reads. --max-mb (default 50) skips a larger file; the report names it.

Exit code: 0 nothing found, 1 findings, 2 error (a file could not be read: not a regular file, too large, or not
parsable; so "nothing found" is not proven).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _detector  # noqa: E402

ROTATION = "references/rotation.md"
WITHHELD = "[withheld]"
MAX_MB = 50.0     # a settings file is kilobytes; a 100 MB file took 214 s and 511 MB (Gate A M3)


# ------------------------------------------------------------------------------------------- names --
HERE = Path(__file__).resolve().parent


def _known_keys() -> frozenset:
    """The setting names of both clients (known_keys.txt next to this script). Only these print by name: a name
    judged by its shape let 40 letters, 16 digits and tokens split across keys through (Gate A round 3)."""
    try:
        text = (HERE / "known_keys.txt").read_text(encoding="utf-8")
    except OSError:
        return frozenset()
    return frozenset(x.strip() for x in text.splitlines() if x.strip() and not x.startswith("#"))


KNOWN_KEYS = _known_keys()
# the file names the clients write themselves: Codex appends approvals to rules/default.rules
# (codex-rs/core/src/exec_policy.rs DEFAULT_POLICY_FILE); Claude Code copies .claude.json to
# backups/.claude.json.backup.<ms> and a file it cannot parse to backups/.claude.json.corrupted.<ms>
# (code.claude.com/docs/en/errors, "Configuration error in ~/.claude.json")
RULES_NAMES = frozenset({"default.rules"})
BACKUP_NAME = re.compile(r"\.claude\.json\.(backup|corrupted)\.\d{13}")
# the children of these keys are names a person chooses (an MCP server, an environment variable, a project): they
# print by number even when a setting has the same name (an MCP server called `filesystem`; Gate A round 4, F3)
CHOSEN_CHILDREN = frozenset({"mcpServers", "mcp_servers", "env", "projects"})


def shown(text: str) -> str:
    """Text as printed: a control character as \\xNN and a lone surrogate as \\uXXXX, so that no line can fail
    to encode (Gate A round 2, M1) or move the cursor of a terminal."""
    text = re.sub(r"[\x00-\x1f\x7f]", lambda m: f"\\x{ord(m.group()):02x}", text)
    return re.sub(r"[\ud800-\udfff]", lambda m: f"\\u{ord(m.group()):04x}", text)


class Source:
    """A file this script looks for. ``label`` is what the report prints for it, built only from fixed names and
    from the clients' own names (RULES_NAMES, BACKUP_NAME); ``path`` is never printed (Gate A round 2, H2;
    round 3)."""

    def __init__(self, path: Path, label: str, client: str, what: str) -> None:
        self.path, self.label, self.client, self.what = path, label, client, what


class Names:
    """The numbers of what prints by number: project folders, file names outside the clients' own names, and
    keys outside the vocabulary. The same name keeps its number within one report."""

    def __init__(self) -> None:
        self.projects: dict[str, int] = {}
        self.origin: dict[int, Source] = {}
        self.files: dict[str, int] = {}
        self.backups: dict[str, dict[str, int]] = {}
        self.keys: dict[str, int] = {}
        self.rules: dict[str, int] = {}

    def project(self, name: str, origin: Source) -> int:
        """The number of a project folder; ``origin`` is the Source that names it, kept as the object so that the
        report prints its checked label (Gate A round 4, F2)."""
        if name not in self.projects:
            self.projects[name] = len(self.projects) + 1
            self.origin[self.projects[name]] = origin
        return self.projects[name]

    def file(self, name: str, own: bool) -> str:
        if own:
            return name
        return f"[file {self.files.setdefault(name, len(self.files) + 1)}]"

    def backup(self, name: str) -> str:
        """A backup of the client config as `.claude.json.backup N` or `.claude.json.corrupted N`: the 13 digits of
        its name are not printed (Gate A round 4, F2); any other name as [file N]."""
        m = BACKUP_NAME.fullmatch(name)
        if not m:
            return self.file(name, False)
        seen = self.backups.setdefault(m.group(1), {})
        return f".claude.json.{m.group(1)} {seen.setdefault(name, len(seen) + 1)}"

    def key(self, name: str, parent: str | None = None) -> str:
        if name in KNOWN_KEYS and parent not in CHOSEN_CHILDREN:
            return name
        return f"[key {self.keys.setdefault(name, len(self.keys) + 1)}]"

    def rule(self, kind: str) -> str:
        """A rule id of the person's own (`user:<id>`, chosen up to 64 characters) or a term id prints by number
        (Gate A round 4, F1); a built-in rule id prints by name."""
        if ":" not in kind:
            return kind
        prefix = kind.split(":", 1)[0]
        word = {"user": "user rule", "term": "term"}.get(prefix, "rule")
        return f"{word} {self.rules.setdefault(kind, len(self.rules) + 1)}"


def _root(var: str, default: str, placeholder: str) -> tuple[Path, str]:
    """A folder the person chose prints as its placeholder; only the default prints, as ~/<default>."""
    value = os.environ.get(var)
    if not value:
        return Path.home() / default, f"~/{default}"
    return Path(value), placeholder


def claude_dir() -> tuple[Path, str]:
    return _root("CLAUDE_CONFIG_DIR", ".claude", "<claude config>")


def codex_home() -> tuple[Path, str]:
    return _root("CODEX_HOME", ".codex", "<codex home>")


# ------------------------------------------------------------------------------------------- files --
class Unreadable(OSError):
    """A file this script does not read: not a regular file, or larger than --max-mb."""


def _read(path: Path) -> str:
    """The text of a regular file, read only (this script never writes a source). Opened without blocking and
    checked on the open descriptor: a FIFO or a link to /dev/stdin made a plain open() wait forever (Gate A M2)."""
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Unreadable("not a regular file")
        if st.st_size > MAX_MB * 1_000_000:
            raise Unreadable(f"too large ({st.st_size // 1_000_000} MB, --max-mb {MAX_MB:g})")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            return fh.read().decode("utf-8", errors="replace")
    finally:
        if fd >= 0:
            os.close(fd)


def listed(folder: Path, keep) -> list[Path]:
    """The regular files of a folder that ``keep`` accepts, sorted. A folder that is absent, not a folder, or has
    a NUL in its name (a Codex project header can hold one) gives none."""
    try:
        return sorted(p for p in folder.iterdir() if keep(p.name) and p.is_file())
    except (OSError, ValueError):
        return []


def rules_in(folder: Path) -> list[Path]:
    """`*.rules` in a rules folder, as Codex loads them (codex-rs/core/src/exec_policy.rs collect_policy_files)."""
    return listed(folder, lambda n: n.endswith(".rules") and n != ".rules")


def _claude_projects(files: list[Source]) -> list[tuple[str, Source]]:
    out: list[tuple[str, Source]] = []
    for s in files:
        try:
            data = json.loads(_read(s.path))
        except Exception:   # main() reports the file; a deep nesting raised RecursionError here
            continue
        projects = data.get("projects") if isinstance(data, dict) else None
        if isinstance(projects, dict):
            out += [(p, s) for p in projects if isinstance(p, str)]
    return out


TOML_ESCAPES = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\", "e": "\x1b"}
TOML_HEX = {"x": 2, "u": 4, "U": 8}


def toml_basic(s: str) -> str:
    """A TOML basic string as Codex decodes it: \\b \\t \\n \\f \\r \\" \\\\ \\e, \\xHH, \\uXXXX, \\UXXXXXXXX. A
    header `[projects."/x/\\u0067hp_…"]` names a folder with a token that the raw text hides (Gate A round 2,
    H1)."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        n = s[i + 1:i + 2]
        if c != "\\" or not n:
            out.append(c)
            i += 1
        elif n in TOML_ESCAPES:
            out.append(TOML_ESCAPES[n])
            i += 2
        elif n in TOML_HEX:
            digits = s[i + 2:i + 2 + TOML_HEX[n]]
            try:
                if len(digits) != TOML_HEX[n]:
                    raise ValueError
                out.append(chr(int(digits, 16)))
                i += 2 + TOML_HEX[n]
            except ValueError:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


PROJECT_HEADER = re.compile(r"""^\s*\[\s*projects\s*\.\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)')\s*\]""")


def codex_project_names(text: str) -> list[str]:
    """The project folders of a Codex config.toml: with tomllib (3.11+) every form TOML allows, and the
    `[projects."…"]` headers decoded as above in any case (the 3.9 fallback, and a file tomllib refuses)."""
    out: list[str] = []
    try:
        import tomllib   # type: ignore[import-not-found]
        projects = tomllib.loads(text).get("projects")
        if isinstance(projects, dict):
            out += [k for k in projects if isinstance(k, str)]
    except Exception:   # 3.9 has no tomllib; a file Codex cannot parse either is still read by its headers
        pass
    for line in text.splitlines():
        m = PROJECT_HEADER.match(line)
        if m:
            name = toml_basic(m.group(1)) if m.group(1) is not None else m.group(2)
            if name not in out:
                out.append(name)
    return out


def sources(names: Names) -> list[Source]:
    """Every file this script looks for, present or not, with the label the report prints for it."""
    cdir, clabel = claude_dir()
    out = [Source(cdir / n, f"{clabel}/{n}", "Claude Code", "user settings")
           for n in ("settings.json", "settings.local.json")]
    # the client config: `.claude.json` in CLAUDE_CONFIG_DIR, else in the home (the rule of maisecrets/vault_refs.py
    # global_file, copied: the standalone skill zip has no vault_refs), its `-custom-oauth` form, the legacy
    # `.config.json` of the config dir, and the copies the client keeps in `backups/`
    if os.environ.get("CLAUDE_CONFIG_DIR"):
        home, hlabel = cdir, clabel
    else:
        home, hlabel = Path.home(), "~"
    client = [Source(home / ".claude.json", f"{hlabel}/.claude.json", "Claude Code", "client config")]
    if os.environ.get("CLAUDE_CODE_CUSTOM_OAUTH_URL"):
        client.append(Source(home / ".claude-custom-oauth.json", f"{hlabel}/.claude-custom-oauth.json",
                             "Claude Code", "client config"))
    if (cdir / ".config.json").is_file():
        client.append(Source(cdir / ".config.json", f"{clabel}/.config.json", "Claude Code", "client config"))
    for f in listed(cdir / "backups", lambda n: n.startswith(".claude") and ".json" in n):
        shown_name = names.backup(f.name)
        client.append(Source(f, f"{clabel}/backups/{shown_name}", "Claude Code", "client config"))
    out += client
    for name, origin in _claude_projects(client):
        n = names.project(name, origin)
        for f in ("settings.json", "settings.local.json"):
            out.append(Source(Path(name) / ".claude" / f, f"<project {n}>/.claude/{f}", "Claude Code",
                              "project settings"))
    chome, xlabel = codex_home()
    config = Source(chome / "config.toml", f"{xlabel}/config.toml", "Codex", "config")
    out.append(config)
    rules = rules_in(chome / "rules")
    out += [Source(f, f"{xlabel}/rules/{names.file(f.name, f.name in RULES_NAMES)}", "Codex", "approval rules")
            for f in rules] or [
        Source(chome / "rules" / "*.rules", f"{xlabel}/rules/*.rules", "Codex", "approval rules")]
    try:
        text = _read(config.path)
    except (OSError, ValueError):
        text = ""
    for name in codex_project_names(text):
        n = names.project(name, config)
        folder = Path(name) / ".codex"
        out.append(Source(folder / "config.toml", f"<project {n}>/.codex/config.toml", "Codex", "project config"))
        out += [Source(f, f"<project {n}>/.codex/rules/{names.file(f.name, f.name in RULES_NAMES)}", "Codex",
                       "project approval rules")
                for f in rules_in(folder / "rules")]
    seen, unique = set(), []
    for s in out:
        key = os.path.normcase(os.path.abspath(str(s.path))) if "\x00" not in str(s.path) else str(s.path)
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique


# ------------------------------------------------------------------------------------------ places --
def json_strings(node, path: tuple = ()):
    """(path, string) for each string in the document, keys included (a key can hold a command). The path is a
    tuple of keys (str) and list indexes (int); render() prints it."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, list):
        for i, x in enumerate(node):
            yield from json_strings(x, path + (i,))
    elif isinstance(node, dict):
        for k, v in node.items():
            yield path + (str(k), "(key)"), str(k)
            yield from json_strings(v, path + (str(k),))


def render(path: tuple, names: Names) -> str:
    out, parent = "", None
    for x in path:
        if isinstance(x, int):
            out += f"[{x}]"
        elif x == "(key)":
            out += " (key)"
        else:
            out += ("." if out else "") + names.key(x, parent)
            parent = x
    return out


def is_approval(what: str, place: str) -> bool:
    return (what.endswith("approval rules") or ".allowedTools[" in place
            or place.startswith(("permissions.allow[", "permissions.ask[", "permissions.deny[")))


def fix_for(what: str, place: str) -> str:
    if place == "(path)":
        return (f"a file or folder name holds the credential: rotate the credential ({ROTATION}), then rename "
                "the file or folder")
    if place.endswith("(project path)"):
        return (f"a project folder name holds the credential: rotate the credential ({ROTATION}), then remove "
                "that project entry")
    if what.endswith("approval rules"):
        return f"remove this prefix_rule from the file, then rotate the credential ({ROTATION})"
    if is_approval(what, place):
        return f"remove this approval entry from the file, then rotate the credential ({ROTATION})"
    return (f"take the value out of this setting (an environment variable or a placeholder), then rotate the "
            f"credential ({ROTATION})")


TOML_SECTION = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
TOML_KEY = re.compile(r"""^\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_.-]+)\s*=""")


def toml_parts(dotted: str) -> list[str]:
    """The names of a TOML table header or a dotted key, quotes removed (a basic string decoded)."""
    out = []
    for m in re.finditer(r"""\s*("(?:[^"\\]|\\.)*"|'[^']*'|[^.\s]+)\s*(?:\.|$)""", dotted):
        x = m.group(1)
        out.append(toml_basic(x[1:-1]) if x.startswith('"') else x[1:-1] if x.startswith("'") else x)
    return out


def line_parts(text: str, toml: bool) -> list[tuple[int, list[str]]]:
    """For each line (index 0 = line 1) its number and, in a TOML file, the names of the table and the key that
    the line belongs to. render_line() prints them."""
    out, section, key = [], [], []
    for n, line in enumerate(text.split("\n"), 1):
        if toml:
            s, k = TOML_SECTION.match(line), TOML_KEY.match(line)
            if s:
                section, key = toml_parts(s.group(1)), []
            elif k:
                key = toml_parts(k.group(1))
        out.append((n, section + key))
    return out


def render_line(n: int, parts: list[str], names: Names) -> str:
    shown = [names.key(x, parts[i - 1] if i else None) for i, x in enumerate(parts)]
    return f"line {n} ({'.'.join(shown)})" if parts else f"line {n}"


# -------------------------------------------------------------------------------------------- scan --
def scan_file(detect, enabled, src: Source, names: Names) -> list[tuple[str, object]]:
    """(place, match) for each hit. A JSON file is scanned string by string with its JSON path; the client
    config only in `projects.*.allowedTools` (the rest is account state and MCP servers, which the plugin
    handles elsewhere). A file that is not valid JSON, a rules file and a TOML file are scanned as text with
    line numbers."""
    text = _read(src.path)
    hits: list[tuple[str, object]] = []
    toml = src.path.name.endswith(".toml")
    if toml or src.what.endswith("approval rules"):
        doc = None
    else:
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
    if doc is not None:
        if src.what == "client config":
            items = []
            projects = doc.get("projects") if isinstance(doc, dict) else None
            for name, entry in (projects.items() if isinstance(projects, dict) else []):
                tools = entry.get("allowedTools") if isinstance(entry, dict) else None
                if isinstance(tools, list):
                    n = names.project(name, src)
                    items += [(f"projects[<project {n}>].allowedTools[{i}]", t)
                              for i, t in enumerate(tools) if isinstance(t, str)]
            for place, s in items:
                hits += [(place, m) for m in detect.scan(s, enabled, "tool")]
        else:
            for path, s in json_strings(doc):
                hits += [(render(path, names), m) for m in detect.scan(s, enabled, "tool")]
        return hits
    parts = line_parts(text, toml)
    starts = _detector.line_starts(text)
    for m in _detector.scan_text(detect, text, enabled, "tool"):
        n, names_of_line = parts[_detector.line_of(starts, m.start) - 1]
        hits.append((render_line(n, names_of_line, names), m))
    return hits


def inner_rule(detect, m) -> str | None:
    if m.type != "SECRET":
        return None
    for x in detect.scan(m.value):
        if x.type == "SECRET" and x.kind != m.kind:
            return x.kind
    return None


def classify(kind: str, inner: str | None) -> tuple[str, str]:
    def guess(k: str) -> bool:
        return k in ("generic-api-key", "url-query-secret") or k.startswith("ds-keyword")
    if not guess(kind):
        return kind, "shape"
    if inner and not guess(inner):
        return inner, "shape"
    return kind, "guess"


# a token keeps _ and - inside (ghp_, sk-): the label is joined once without the path and key separators, and
# once without any separator
SEPARATORS = (re.compile(r"[/.:\[\]\s]"), re.compile(r"[/.:_\-\[\]\s]"))


def joined_check(detect, rules, label: str) -> str:
    """The second layer behind the vocabulary: a label whose parts form a token once the separators are gone
    (a token split across folders or keys) is withheld whole (Gate A round 3)."""
    for sep in SEPARATORS:
        if any(m.type == "SECRET" for m in detect.scan(sep.sub("", label), rules, "tool")):
            return "[label withheld]"
    return label


def guard(lines: list[str], values) -> list[str]:
    """The last check before any output: a line that holds a found value loses that part, also in the forms a
    report could write it (JSON-escaped, control-escaped; Gate A M1). The labels hold no chosen name, so this
    is the second line of defence, not the first."""
    forms = set()
    for v in values:
        if v:
            forms |= {v, json.dumps(v)[1:-1], json.dumps(v, ensure_ascii=False)[1:-1], shown(v)}
    order = sorted((f for f in forms if f), key=len, reverse=True)
    out = []
    for line in lines:
        for v in order:
            if v in line:
                line = line.replace(v, WITHHELD)
        out.append(line)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Credentials in the approvals and settings of Claude Code and Codex, by place, never by value.")
    ap.add_argument("--pii", action="store_true", help="also list personal data (e-mail, IBAN, phone ...)")
    ap.add_argument("--out", help="write the full report to this file and print only the summary")
    ap.add_argument("--max-mb", type=float, default=MAX_MB,
                    help=f"do not read a file larger than this (default {MAX_MB:g}); the report names it")
    args = ap.parse_args(argv)
    try:
        return run(args)
    except Exception as exc:   # whatever a file holds, the answer is an error code, not a traceback (round 2, M1)
        print(f"secret-hygiene: the approvals check stopped: {exc.__class__.__name__}")
        return 2


def run(args) -> int:
    global MAX_MB
    MAX_MB = args.max_mb
    try:
        detect = _detector.load()
    except SystemExit as exc:
        print(exc)
        return 2
    enabled = None if args.pii else _detector.secret_rules(detect)
    names = Names()
    files = sources(names)
    if args.out:
        def real(f) -> str:
            try:
                return os.path.realpath(str(f))
            except ValueError:   # a NUL in a project path: no file can have that name
                return ""
        out_real = real(args.out)
        if out_real and any(real(s.path) == out_real for s in files):
            print("secret-hygiene: --out names a file this script reads; it writes no source file. "
                  "Choose another --out file.")
            return 2
    ids: dict[str, str] = {}
    findings, read, missing, failed = [], [], [], []

    def add(m, src: Source, place: str) -> None:
        if not args.pii and m.type != "SECRET":
            return
        sid = ids.setdefault(m.value, f"S{len(ids) + 1}")
        rule, sure = classify(m.kind, inner_rule(detect, m))
        rule = names.rule(rule)
        findings.append((sid, m.type, rule, sure, len(m.value), src.label, place, src.client, src.what))

    rules = _detector.secret_rules(detect)
    for src in files:
        src.label = joined_check(detect, rules, src.label)
    for src in files:
        label = f"{src.label} ({src.client} {src.what})"
        try:
            if src.path.name == "*.rules":
                raise FileNotFoundError
            os.stat(str(src.path))
        except (FileNotFoundError, NotADirectoryError, ValueError):   # ValueError: a NUL in a project path
            missing.append(label)
            continue
        except OSError as exc:
            failed.append(f"{label}: {exc.__class__.__name__}")
            continue
        try:
            hits = scan_file(detect, enabled, src, names)
        except Unreadable as exc:
            failed.append(f"{label}: {exc}")
            continue
        except Exception as exc:   # a deep nesting raised RecursionError and read as "findings" (Gate A M4)
            failed.append(f"{label}: {exc.__class__.__name__}")
            continue
        read.append(label)
        for place, m in hits:
            add(m, src, joined_check(detect, rules, place))
    # the names are scanned although they are never printed: a project folder (as its client decoded it) and
    # each path this script looked at can hold a token (Gate A B1, round 2 H1)
    for name, n in names.projects.items():
        origin = names.origin[n]      # the Source itself: a withheld label must not lose the finding (round 4, F2)
        for m in detect.scan(name, enabled, "tool"):
            if m.value not in ids:
                add(m, origin, f"<project {n}> (project path)")
    for src in files:
        for m in detect.scan(str(src.path), enabled, "tool"):
            if m.value not in ids:
                add(m, src, "(path)")
    lines = ["Approvals and settings that Claude Code and Codex keep outside the repository.",
             f"Read {len(read)} file(s); {len(missing)} known file(s) do not exist"
             + (f"; {len(failed)} could NOT be read" if failed else "") + "."]
    lines.append(f"Findings: {len(ids)} distinct value(s) in {len(findings)} place(s).")
    for sid, mtype, rule, sure, n, label, place, client, what in sorted(
            findings, key=lambda f: (f[3] != "shape", int(f[0][1:]), f[5], f[6])):
        lines.append(f"  {sid:<4} {mtype:<7} {rule:<24} {sure:<5} len {n:<4} {label}  {place}  ({client} {what})")
        lines.append(f"       fix: {fix_for(what, place)}")
    if failed:
        lines.append("Could NOT be read (nothing found there is not proven):")
        lines += [f"  {x}" for x in failed]
    lines.append("Files read:")
    lines += [f"  {x}" for x in read] or ["  (none)"]
    lines.append("Files that do not exist:")
    lines += [f"  {x}" for x in missing] or ["  (none)"]
    if names.projects:
        lines.append("Projects (their folder names are not printed; open the file named here to find one):")
        lines += [f"  project {n} (from {names.origin[n].label})" for n in sorted(names.origin)]
    shape = len({f[0] for f in findings if f[3] == "shape"})
    lines.append(f"Summary: {len(ids)} value(s); {shape} match a provider's token format (rotate first). "
                 "Removing an entry does not revoke the credential: the command ran with it, and copies of the "
                 f"file (backups, transcripts) can still hold it. Rotate it ({ROTATION}), then remove the entry.")
    lines.append("Values and names that a person or a client chose are not shown. The same id means the same "
                 "value. This script changed no file.")
    lines = [shown(x) for x in guard(lines, ids)]
    if args.out:
        try:
            Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"secret-hygiene: cannot write the --out file: {exc.__class__.__name__}")
            return 2
        print("Wrote the full report to the --out file.")
        print("\n".join(line for line in lines if not line.startswith("  ")))
    else:
        print("\n".join(lines))
    if findings:
        return 1
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
