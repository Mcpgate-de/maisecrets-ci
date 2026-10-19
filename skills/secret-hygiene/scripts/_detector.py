"""Find the maisecrets detector for the skill scripts.

Two layouts: inside the maisecrets plugin the package sits three levels up (plugin root);
in the standalone skill zip a copy sits next to this file. The copy wins when both exist.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load():
    if sys.version_info < (3, 9):
        raise SystemExit("secret-hygiene needs Python 3.9 or newer.")
    for base in (HERE, *list(HERE.parents)[:3]):
        if (base / "maisecrets" / "detection" / "core.py").is_file():
            if str(base) not in sys.path:
                sys.path.insert(0, str(base))
            from maisecrets import detect  # noqa: E402
            return detect
    raise SystemExit("secret-hygiene: the maisecrets detector was not found next to the skill or in the plugin.")


def line_starts(text: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def line_of(starts: list[int], offset: int) -> int:
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


CHUNK_LINES = 400
CHUNK_OVERLAP = 60     # longer than a PEM key block, so a match on a chunk border is seen whole
SMALL = 200_000


def scan_text(detect, text: str, enabled: set | None = None, channel: str = "tool") -> list:
    """detect.scan for text of any size. The detector runs a rule only when one of its keywords
    occurs in the text; in a 28 MB history nearly every keyword occurs somewhere, so nearly all
    267 rules ran over everything (71 s for 217 commits, 2026-09-27). Scanned in overlapping line
    chunks, a rule runs only where its keyword is near: three times faster, and on 6 MB of real
    history the same secrets (only three postcodes, whose context word sat outside the chunk,
    were lost; this skill reports secrets unless --pii is given). channel "tool": a file, a commit or a
    tool result, where a password of letters after a password label counts (detect.scan); "prompt" for a typed
    prompt."""
    if len(text) < SMALL:
        return detect.scan(text, enabled, channel)
    import dataclasses
    lines = text.split("\n")
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line) + 1)
    seen: dict = {}
    i = 0
    while i < len(lines):
        j = min(len(lines), i + CHUNK_LINES)
        a = starts[i]
        piece = text[a:starts[j] - 1] if j < len(lines) else text[a:]
        for m in detect.scan(piece, enabled, channel):
            key = (m.start + a, m.end + a)
            if key not in seen:
                seen[key] = dataclasses.replace(m, start=m.start + a, end=m.end + a)
        if j >= len(lines):
            break
        i = j - CHUNK_OVERLAP
    return [seen[k] for k in sorted(seen)]


def secret_rules(detect) -> set:
    """The ids of the rules that find secrets. Without --pii only these run: the personal-data
    rules (e-mail, phone, IBAN, German ids) have no keywords, so they ran over every chunk and
    their hits were thrown away afterwards (2026-09-27)."""
    return {r.id for r in detect.rules() if r.type == "SECRET"}


# --- parallel scanning: one process per core, each with its own detector -----------------------
_W: dict = {}


def _worker_init(enabled) -> None:
    _W["detect"] = load()
    _W["enabled"] = enabled


def worker_scan(job: tuple) -> tuple:
    """job = (tag, text): the matches as (start, end, type, kind, value) plus each keyword match
    re-scanned for a provider name. Runs in a child process; the values never leave this
    machine and never reach the output (the parent maps them to per-run ids)."""
    tag, text = job
    detect, enabled = _W["detect"], _W["enabled"]
    out = []
    for m in scan_text(detect, text, enabled):
        inner = None
        if m.type == "SECRET":
            for x in detect.scan(m.value):
                if x.type == "SECRET" and x.kind != m.kind:
                    inner = x.kind
                    break
        out.append((m.start, m.end, m.type, m.kind, m.value, inner))
    return tag, out


def pool(enabled):
    import concurrent.futures
    import os
    return concurrent.futures.ProcessPoolExecutor(max_workers=os.cpu_count() or 2,
                                                  initializer=_worker_init, initargs=(enabled,))


def parse_log(raw: str):
    """Units of `git log -p -U0 --format='commit %h %ad %an'`: (commit, date, author, path,
    [(line number, added text)]), in log order. A file's path is read only from its header
    block (after `diff --git`, before the first `@@`): an added line whose text starts with
    `++ ` shows up as `+++ …` and was taken for a header, which printed its text as a path
    (review, 2026-09-27)."""
    units = []
    commit, date, author, path, lines = "", "", "", "", []
    new_line = 0
    header = False

    def flush():
        nonlocal lines
        if lines:
            units.append((commit, date, author, path, lines))
        lines = []
    for row in raw.splitlines():
        if row.startswith("commit "):
            # only the --format line is unprefixed and starts so; diff content is prefixed
            flush()
            header = False
            parts = row.split(" ", 3)
            commit = parts[1]
            date = parts[2] if len(parts) > 2 else ""
            author = parts[3] if len(parts) > 3 else ""
            path = ""
        elif row.startswith("diff --git "):
            flush()
            header = True
            path = ""
        elif header and row.startswith("+++ "):
            path = row[6:] if row.startswith("+++ b/") else row[4:]
        elif row.startswith("@@"):
            header = False
            try:
                new_line = int(row.split("+", 1)[1].split(",")[0].split(" ")[0])
            except (IndexError, ValueError):
                new_line = 0
        elif not header and row.startswith("+"):
            lines.append((new_line, row[1:]))
            new_line += 1
    flush()
    return units


def worker_history(job: tuple) -> tuple:
    """job = (index, cwd, shas, max_bytes): run git log for these commits in this process, parse
    and scan it here. Only the hits travel back to the parent: sending 1.5 GB of history text
    through one parent process was the bottleneck (2026-09-27)."""
    import subprocess
    idx, cwd, shas, max_bytes = job
    detect, enabled = _W["detect"], _W["enabled"]
    r = subprocess.run(["git", "log", "--no-walk=unsorted", "-p", "--no-color", "--no-ext-diff", "-U0",
                        "--date=short", "--format=commit %h %ad %an", *shas],
                       cwd=cwd, capture_output=True, env=_git_env())
    rows, skipped = [], []
    for commit, date, author, path, lines in parse_log(r.stdout.decode("utf-8", errors="replace")):
        text = "\n".join(t for _, t in lines)
        if max_bytes and len(text) > max_bytes:
            skipped.append(f"{path} in commit {commit}")
            continue
        starts = line_starts(text)
        for m in scan_text(detect, text, enabled):
            inner = None
            if m.type == "SECRET":
                for x in detect.scan(m.value):
                    if x.type == "SECRET" and x.kind != m.kind:
                        inner = x.kind
                        break
            lineno = lines[line_of(starts, m.start) - 1][0]
            rows.append((commit, date, author, path, lineno, m.type, m.kind, m.value, inner))
    return idx, rows, skipped, r.returncode


def _git_env() -> dict:
    import os
    return {k: v for k, v in os.environ.items() if k not in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE")}
