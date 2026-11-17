#!/usr/bin/env python3
"""Find the secrets that already reached an AI provider through the local agent transcripts.

Claude Code keeps every session in ~/.claude/projects/**/*.jsonl, Codex in
~/.codex/sessions/**/*.jsonl. A value in a prompt, a tool result or a model answer there was
sent to the provider (Anthropic or OpenAI). Deleting the local file does not take it back:
the finding means "rotate it".

Nothing this script prints is a value, a line of a transcript or a hash of a value. A finding
is a per-run id (S1, S2 ...; the same value keeps its id across sessions), a type, the rule,
how sure the match is, where in the session it sat, and the sessions it appears in.

    python3 audit_transcripts.py [--claude] [--codex] [--pii] [--days N | --all] [--out FILE] [--workers N]
        [--estimate] [--full]
    python3 audit_transcripts.py --scrub [--yes] [--days N | --all]

The default is the sessions of the last 30 days and the fast scan (_fast.py); --full reads each record as one
text, as 0.9.13 did, with every rule.

It prints the size of the transcripts first, an estimate from the real speed of the scan after its
first 25 seconds, a progress line at least every 30 seconds with the time left at the current speed,
and the time it took, on stderr; a busy computer is named. --estimate runs the same pool on a sample
of files from all projects for 15 seconds, stops it and prints the estimate.

Each found value gets a class (verdict_of): REAL (rotate it: it is in your maisecrets store, or it has a provider's
token format and was sent in a prompt or a tool result), TEST (it names itself a test value, vendor docs publish it,
only the model wrote it, or a keyword guess stands only in test code), or UNKNOWN. stdout gets only the summary: the
verdict, at most 10 real tokens with the page to revoke each (rotation.json), and one line with the rest and the
path of the full report, which --out names (default: a new file in the temp folder).

--scrub lists which local transcript files hold a found value; with --yes it replaces each
value in them with ⟦TYPE_n⟧, keeping every line valid JSON. It skips files written to in the
last 10 minutes (a running session). It does not undo what the provider received.

Exit code: 0 nothing found, 1 findings, 2 error.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import threading
import time
import zlib
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _detector  # noqa: E402
import _fast  # noqa: E402

SENT = {"prompt", "tool result", "model output"}
ACTIVE_SECONDS = 600
JOB_BYTES = 512_000         # a job ends at this size too: a file of few long lines balanced badly over the pool, and
#                             the progress counts finished jobs only (2 MB jobs hid up to 2 MB per worker)
SAMPLE_JOB_BYTES = 256_000  # --estimate: smaller jobs, so the short sample counts what it scanned
SMALL = 512                 # the strings of a record shorter than this are joined and scanned as one text
PART = 1024                 # a long text is cut at a blank line, into parts of about this size or more
PART_MAX = 65536
MODE = "fast"               # "full" (--full): each record one text, every rule; "fast": _fast.py
SEEN_MAX = 300_000          # the texts a worker remembers by hash before it forgets them all
ESTIMATE_SECONDS = 25       # the scan estimates its time from what the pool did in its first 25 s
SAMPLE_SECONDS = 15         # --estimate: the pool scans spread files this long, then stops
SAMPLE_BYTES = 64_000_000   # --estimate: at most this much of them
PROGRESS_SECONDS = 30
BUSY_LOAD = 1.0             # a 1-minute load above the cores at the start: other work slows the scan (the load
#                             lags: a pool that just ran, an --estimate, adds to it for a minute)


def sources(claude: bool, codex: bool, days: int) -> list[tuple[str, Path]]:
    home = Path.home()
    roots = []
    if claude:
        base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or home / ".claude") / "projects"
        roots.append(("claude", base))
    if codex:
        roots.append(("codex", Path(os.environ.get("CODEX_HOME") or home / ".codex") / "sessions"))
    cutoff = time.time() - days * 86400 if days else 0
    out = []
    for client, root in roots:
        if not root.is_dir():
            continue
        for f in root.rglob("*.jsonl"):
            try:
                if f.stat().st_mtime >= cutoff:
                    out.append((client, f))
            except OSError:
                continue
    return spread(out)


def spread(files: list) -> list:
    """The files in an order that mixes the projects: one file of each project folder in turn, each folder in path
    order. The first seconds of the scan then show its speed on the whole history, not on the first project of the
    alphabet (#59: an estimate from the first 2 MB in path order was four times too fast)."""
    groups: dict = defaultdict(list)
    for item in sorted(files, key=lambda x: str(x[1])):
        groups[(item[0], str(item[1].parent))].append(item)
    queues = [groups[k] for k in sorted(groups)]
    out = []
    for i in range(max((len(q) for q in queues), default=0)):
        out.extend(q[i] for q in queues if i < len(q))
    return out


def kind_of(client: str, rec: dict) -> str:
    """Where in the session a record sits: prompt, tool result, model output, or local record
    (hook attachments, metadata: not proven to have reached the provider)."""
    if client == "claude":
        t = rec.get("type")
        if t == "user":
            content = (rec.get("message") or {}).get("content")
            if isinstance(content, list) and any(isinstance(x, dict) and x.get("type") == "tool_result"
                                                 for x in content):
                return "tool result"
            return "prompt"
        if t == "assistant":
            return "model output"
        return "local record"
    payload = rec.get("payload") or {}
    if rec.get("type") == "response_item":
        pt, role = payload.get("type"), payload.get("role")
        if pt == "message" and role == "user":
            return "prompt"
        if pt in ("function_call_output", "custom_tool_call_output", "local_shell_call_output"):
            return "tool result"
        return "model output"
    return "local record"


class Whole(str):
    """A text that the full detector scans whole in either mode: the base64 of a document has no anchor of the fast
    tier, and only the decoder of the full scan reads it."""


def strings_of(node, notes: dict | None = None):
    """The strings of a record that can hold a typed value, in record order. Left out, each only in its own schema:
    the data of an Anthropic base64 source of an image ({type: base64, media_type: image/*}), Claude Code's copy of a
    read image (`base64` next to type image/*), a Codex input_image data URL (`image_url` of type input_image), and
    the provider's opaque blobs (`signature` of a thinking block, `data` of a redacted_thinking block,
    `encrypted_content` of a Codex reasoning item). The same key anywhere else is scanned (Gate A of #59). A text/*
    document in base64 is decoded and its text is scanned. A PDF or another binary document is scanned in its base64
    as before, as a `Whole` text: the full detector decodes base64 in a tool result."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for x in node:
            yield from strings_of(x, notes)
    elif isinstance(node, dict):
        t = node.get("type")
        t = t if isinstance(t, str) else ""
        media = node.get("media_type")
        media = media if isinstance(media, str) else ""
        for k, v in node.items():
            if isinstance(v, str):
                if k == "data" and t == "base64" and "media_type" in node:
                    if media.startswith("text/"):
                        try:
                            yield base64.b64decode(v).decode("utf-8", errors="replace")
                        except ValueError:
                            yield v
                    elif not media.startswith("image/"):
                        yield Whole(v)
                    continue
                if ((k == "base64" and t.startswith("image/"))
                        or (k == "image_url" and t == "input_image" and v.startswith("data:image/"))
                        or (k == "signature" and t == "thinking") or (k == "data" and t == "redacted_thinking")
                        or (k == "encrypted_content" and t == "reasoning")):
                    continue
            yield from strings_of(v, notes)


CONTEXT_LINES = 3
CONTEXT_CHARS = 1000


def _tail(s: str, lines: int = CONTEXT_LINES, chars: int = CONTEXT_CHARS) -> str:
    """The last `lines` lines of s, at most `chars` characters."""
    a = len(s)
    for _ in range(lines):
        a = s.rfind("\n", 0, a)
        if a < 0:
            break
    return s[max(a + 1, len(s) - chars):]


def _head(s: str, lines: int = CONTEXT_LINES, chars: int = CONTEXT_CHARS) -> str:
    """The first `lines` lines of s, at most `chars` characters."""
    b = -1
    for _ in range(lines):
        b = s.find("\n", b + 1)
        if b < 0:
            break
    return s[:min(len(s) if b < 0 else b, chars)]


def _border(segs: list, i: int) -> list:
    """The pieces of the window around the border after text i: CONTEXT_LINES lines on each side, taken from as many
    texts as it needs (a text of two lines between a label and its value). Each piece is (text index or None for a
    separator, offset in that text, piece)."""
    sides = []
    for step, first in ((-1, i), (1, i + 1)):
        side, need, room, j = [], CONTEXT_LINES, CONTEXT_CHARS, first
        while 0 <= j < len(segs) and need > 0 and room > 0:
            body = segs[j][0]
            piece = _tail(body, need, room) if step < 0 else _head(body, need, room)
            side.append((j, len(body) - len(piece) if step < 0 else 0, piece))
            need -= piece.count("\n") + 1
            room -= len(piece)
            if len(piece) < len(body):
                break
            j += step
        sides.append(side)
    back, ahead = sides
    pieces: list = []
    for j, off, piece in reversed(back):
        pieces += [(j, off, piece), (None, 0, segs[j][1])]
    for k, (j, off, piece) in enumerate(ahead):
        pieces.append((j, off, piece))
        if k + 1 < len(ahead):
            pieces.append((None, 0, segs[j][1]))
    return pieces


def _cut(text: str) -> list:
    """A long text in pieces, cut at a blank line before a heading or a tag, or where a hash of the paragraph says
    so: the same section in two system prompts makes the same piece, also after a change before it."""
    if len(text) < 4 * PART:
        return [text]
    bodies, cur, size = [], [], 0
    for p in text.split("\n\n"):
        if size >= PART and (size >= PART_MAX or p[:1] in "#<"
                             or zlib.crc32(p[:64].encode("utf-8", "surrogatepass")) % 8 == 0):
            bodies.append("\n\n".join(cur))
            cur, size = [], 0
        cur.append(p)
        size += len(p) + 2
    bodies.append("\n\n".join(cur))
    return bodies


def _mode() -> str:
    return _detector._W.get("mode") or MODE


def units(rec, notes: dict | None = None) -> list:
    """The texts of a record in record order, each as (text, separator after it, whole). --full: one text, the
    strings joined as 0.9.13 joined them. The fast scan: a run of short strings, each long string cut at blank lines
    (#59: a long string recurs in the next snapshot, the next session, the toolUseResult copy), each document
    (`whole`: the full detector, Whole); record_hits scans each text alone and each border between two of them."""
    if _mode() == "full":
        # --full reads a record as 0.9.13 did: its strings joined in record order, one text, every rule (round 4 of
        # Gate A: a long field split from its neighbour lost a value four lines after its label)
        joined = "\n".join(strings_of(rec, notes))
        return [(joined, "\n", False)] if joined else []
    segs: list = []
    for x in strings_of(rec, notes):
        if isinstance(x, Whole):
            segs.append([str(x), "\n", True, False])
        elif len(x) < SMALL:
            if segs and segs[-1][3]:
                segs[-1][0] += "\n" + x
            else:
                segs.append([x, "\n", False, True])
        else:
            bodies = _cut(x)
            for j, body in enumerate(bodies):
                segs.append([body, "\n\n" if j + 1 < len(bodies) else "\n", False, False])
    return [(body, sep, whole) for body, sep, whole, _small in segs]


def record_hits(detect, segs: list, enabled, channel: str) -> list:
    """(type, rule, value, inner rule, in test code) per hit of a record. Each text is scanned alone, so it stays one
    cache entry when it recurs. Each border is scanned too: CONTEXT_LINES lines on each side of it, from as many texts
    as that takes (_border). A hit there counts once, where it starts, and only when that text did not find it alone: a
    label at the end of one string and its value in the next (Gate A of #59)."""
    found, starts = [], []
    for body, _sep, whole in segs:
        hits = scan_once(detect, body, enabled, channel, whole) if body else ()
        starts.append({h[0] for h in hits})
        found.extend(h[1:] for h in hits)
    counted: set = set()
    for i in range(len(segs) - 1):
        # an empty text is an empty line of the record, as 0.9.13 joined it: the window walks across it
        pieces = _border(segs, i)
        text = "".join(p for _j, _off, p in pieces)
        whole = any(segs[j][2] for j, _off, _p in pieces if j is not None)
        for start, typ, rule, value, inner, test in scan_once(detect, text, enabled, channel, whole):
            at, where = 0, None
            for j, off, piece in pieces:
                if at <= start < at + len(piece):
                    where = None if j is None else (j, off + start - at)
                    break
                at += len(piece)
            # a hit counts once, where it starts: not when its text found it alone, nor in a second window
            if where is not None and (where[1] in starts[where[0]] or where in counted):
                continue
            if where is not None:
                counted.add(where)
            found.append((typ, rule, value, inner, test))
    return found


_SEEN: dict = {}
_FINGERPRINT: list = [None, None]


def _fingerprint(enabled):
    """A stable fingerprint of the rule selection, for the cache key; worked out once per selection object."""
    if enabled is None:
        return None
    if _FINGERPRINT[0] is not enabled:
        _FINGERPRINT[0] = enabled
        _FINGERPRINT[1] = hashlib.sha256("\n".join(sorted(map(str, enabled))).encode()).digest()
    return _FINGERPRINT[1]


def _in_test_code(text: str, start: int) -> bool:
    """Whether a hit sits in test code by the detector's own test (a grep line that names a test file, or a test
    marker such as `def test_` or `assert` in its line or the 40 lines before it). False when the copy of the
    detector has no such test."""
    try:
        from maisecrets.detection.text_index import in_test_code
    except ImportError:
        return False
    try:
        return bool(in_test_code(text, start))
    except Exception:   # a test of context must never end the audit
        return False


def scan_once(detect, text: str, enabled, channel: str, whole: bool = False) -> tuple:
    """(start, type, rule, value, inner rule, in test code) per hit of a text, each distinct text scanned once per
    worker. The key is a sha256 of the text with the mode, the rule selection and the channel, kept in memory only."""
    mode = "full" if whole else _mode()
    key = (mode, _fingerprint(enabled), channel, hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest())
    got = _SEEN.get(key)
    if got is not None:
        return got
    hits = []
    found = (_detector.scan_text(detect, text, enabled, channel) if mode == "full"
             else _fast.scan(detect, text, enabled, channel, _detector.scan_text))
    for m in found:
        inner = None
        if m.type == "SECRET":
            for x in detect.scan(m.value):
                if x.type == "SECRET" and x.kind != m.kind:
                    inner = x.kind
                    break
        hits.append((m.start, m.type, m.kind, m.value, inner, _in_test_code(text, m.start)))
    if len(_SEEN) >= SEEN_MAX:
        _SEEN.clear()
    _SEEN[key] = got = tuple(hits)
    return got


def record_path(rec: dict) -> str:
    """The file a Claude Code tool result read or wrote, as the client notes it next to the result
    (`toolUseResult.file.filePath` of Read, `toolUseResult.filePath` of Write and Edit); empty for any other record."""
    res = rec.get("toolUseResult")
    if not isinstance(res, dict):
        return ""
    f = res.get("file")
    path = f.get("filePath") if isinstance(f, dict) else res.get("filePath")
    return path if isinstance(path, str) else ""


def _is_test_path(path: str) -> bool:
    if not path:
        return False
    try:
        from maisecrets.detection.text_index import is_test_path
    except ImportError:
        return False
    return bool(is_test_path(path))


def worker_jsonl(job: tuple) -> tuple:
    """job = (tag, client, lines): scan the texts of each JSON line (units); return the tag, the rows
    (line index, record kind, timestamp, type, rule, value, inner rule, in test code) per hit, and the notes: the
    records that could not be scanned. In test code: the record is the result of a Read, Write or Edit of a test file
    (record_path), or the detector's test-code check holds at the hit (_in_test_code)."""
    tag, client, lines = job
    detect, enabled = _detector._W["detect"], _detector._W["enabled"]
    rows: list = []
    notes: dict = {}
    if isinstance(lines, tuple):    # ("range", start, length): this worker reads it
        try:
            lines = _read_range(tag[0], lines[1], lines[2])
        except OSError:
            return tag, rows, {"unread": 1}
    for i, line in enumerate(lines):
        mark = len(rows)
        try:
            try:
                rec = json.loads(line)
            except ValueError:
                rec = None
            if isinstance(rec, dict):
                segs = units(rec, notes)
                kind = kind_of(client, rec)
                stamp = str(rec.get("timestamp") or "")[:10]
            else:
                # a cut or damaged line is still scanned: skipping it hid its value (review, 2026-09-27)
                segs, kind, stamp = [(line, "\n", False)], "local record", ""
            # a prompt is judged as the prompt hook judges it; a tool result or a record as a tool result
            channel = "prompt" if kind == "prompt" else "tool"
            in_test_file = _is_test_path(record_path(rec) if isinstance(rec, dict) else "")
            for typ, rule, value, inner, test in record_hits(detect, segs, enabled, channel):
                rows.append((i, kind, stamp, typ, rule, value, inner, in_test_file or test))
        except Exception:   # one record that breaks a step (a lone surrogate, Gate A) must not end the audit
            del rows[mark:]
            notes["unread"] = notes.get("unread", 0) + 1
    return tag, rows, notes


class _LineTooLong(Exception):
    """A line longer than the limit of the --estimate sample: its file leaves the sample."""


class _Deadline(Exception):
    """The --estimate sample ran out of time while it searched for line ends."""


def _ranges(f: Path, job_bytes: int, max_line: int = 0, stop=None):
    """(start, end) of each job of a file: up to job_bytes, ending after the last whole line in it. A line longer than
    job_bytes is a job of its own. The line ends are searched in blocks of 64 KB, so a long line is never held whole
    here. For the --estimate sample: a line longer than `max_line` raises _LineTooLong as soon as the search has passed
    that length, and `stop()` is asked before each block (_Deadline): a line of gigabytes has no end to wait for
    (round 3 of Gate A). The scan itself passes neither."""
    size = f.stat().st_size
    with open(f, "rb") as fh:

        def last_newline(lo: int, hi: int) -> int:
            pos = hi
            while pos > lo:
                if stop is not None and stop():
                    raise _Deadline
                at = max(lo, pos - 65536)
                fh.seek(at)
                k = fh.read(pos - at).rfind(b"\n")
                if k >= 0:
                    return at + k
                pos = at
            return -1

        def next_newline(pos: int, line_start: int) -> int:
            fh.seek(pos)
            while True:
                if stop is not None and stop():
                    raise _Deadline
                if max_line and pos - line_start > max_line:
                    raise _LineTooLong
                block = fh.read(65536)
                if not block:
                    return size - 1
                k = block.find(b"\n")
                if k >= 0:
                    return pos + k
                pos += len(block)
        start = 0
        while start < size:
            end = min(start + job_bytes, size)
            if end < size:
                k = last_newline(start, end)
                end = k + 1 if k >= 0 else next_newline(end, start) + 1   # the first line is longer than a job
            yield start, end
            start = end


def _jobs(files: list[tuple[str, Path]], job_bytes: int = 0, max_line: int = 0, stop=None, skipped=None):
    """(job, [its size in bytes]) per job. A job names a byte range of a file; the worker reads and decodes it, so the
    parent only finds line ends (round 2 of Gate A on the estimate: a huge line was read and decoded here, before the
    deadline). The progress counts what the files hold on disk, also a CRLF line end and a letter of several bytes
    (round 6 of #59)."""
    for client, f in files:
        try:
            for start, end in _ranges(f, job_bytes or JOB_BYTES, max_line, stop):
                yield ((str(f), start), client, ("range", start, end - start)), [end - start]
        except _LineTooLong:
            if skipped is not None:
                skipped.append(max_line)
        except _Deadline:
            return
        except OSError:
            continue


def _read_range(path: str, start: int, length: int) -> list:
    """The lines of a byte range, decoded; only a line feed ends a line (a CR stays at its end, as JSON allows)."""
    with open(path, "rb") as fh:
        fh.seek(start)
        data = fh.read(length)
    parts = data.split(b"\n")
    lines = [x + b"\n" for x in parts[:-1]] + ([parts[-1]] if parts[-1] else [])
    return [x.decode("utf-8", errors="replace") for x in lines]


def jobs_for(files: list[tuple[str, Path]]):
    for job, _sizes in _jobs(files):
        yield job


def default_workers() -> int:
    return max(1, (os.cpu_count() or 2) - 1)


def run(files, enabled, workers: int = 0, progress=None):
    """(tag, rows, notes, characters) per job, in the order of the jobs. The progress counts each job when it ends, in
    any order, and gets a tick at least every second while the scan waits for the next job in order: a slow first job
    held back the estimate and gave it only its own bytes (Gate A of #59)."""
    import concurrent.futures
    workers = workers or default_workers()
    total = sum(f.stat().st_size for _c, f in files if f.exists())
    if total < 1_000_000 or workers == 1:
        _detector._worker_init(enabled, MODE)
        for job, sizes in _jobs(files):
            res = worker_jsonl(job) + (sum(sizes),)
            if progress is not None:
                progress.finished(sum(sizes))
            yield res
        return
    ex = _detector.pool(enabled, workers, MODE)
    done = False
    try:
        window = 4 * workers
        pending: list = []

        def ready(fut, n):
            while progress is not None and not fut.done():
                concurrent.futures.wait([fut], timeout=1)
                progress.tick()
            return fut.result() + (n,)
        for job, sizes in _jobs(files):
            fut = ex.submit(worker_jsonl, job)
            if progress is not None:
                fut.add_done_callback(lambda f, n=sum(sizes): progress.finished(n) if not f.cancelled() else None)
            pending.append((fut, sum(sizes)))
            if len(pending) >= window:
                yield ready(*pending.pop(0))
        for fut, n in pending:
            yield ready(fut, n)
        done = True
    finally:
        # closed early: the jobs that wait are cancelled, and nothing waits for the running ones
        ex.shutdown(wait=done, cancel_futures=not done)


def _took(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f} s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


class Progress:
    """Size and file count first (stat only), a warning when other work keeps the cores busy, an estimate from the
    real speed of the scan after its first ESTIMATE_SECONDS (or at its end when it is shorter), a line at least
    every PROGRESS_SECONDS with the time left at the current speed, the time at the end. On stderr; it names no
    value, line or hash. `clock` is for the tests."""

    def __init__(self, files, workers: int, out=None, clock=time.monotonic):
        self.out, self.files, self.clock = out or sys.stderr, len(files), clock
        self.total = sum(_size(f) for _c, f in files)
        self.t0 = self.last = clock()
        self.done = self.files_done = 0
        self.lock = threading.Lock()
        self.rate = 0.0
        self.estimated = False
        self.say(f"Scanning {self.files} transcript file(s), {self.total / 1e6:,.0f} MB, with {workers} process(es).")
        busy = busy_load()
        if busy:
            self.say(f"Other work on this computer slows the scan (load {busy[0]:.0f} on {busy[1]} cores).")

    def say(self, text: str) -> None:
        print(text, file=self.out, flush=True)

    def finished(self, nbytes: int) -> None:
        """A job ended (from the pool's thread)."""
        with self.lock:
            self.done += nbytes

    def step(self, nbytes: int, files_done: int) -> None:
        self.finished(nbytes)
        self.tick(files_done)

    def tick(self, files_done: int | None = None) -> None:
        if files_done is not None:
            self.files_done = files_done
        now = self.clock()
        spent = max(now - self.t0, 1e-6)
        self.rate = self.done / spent
        if not self.estimated and spent >= ESTIMATE_SECONDS and self.done:   # no speed before any work ended
            self.estimated = True
            self.say(f"Estimate: about {_took(self.total / max(self.rate, 1.0))} for {self.total / 1e6:,.0f} MB, "
                     f"{_took(self.left())} left ({self.rate / 1e6:.2f} MB/s in the first {spent:.0f} s).")
            self.last = now
        elif now - self.last >= PROGRESS_SECONDS:
            self.last = now
            left = f"about {_took(self.left())} left" if self.done else "no part finished yet"
            self.say(f"Progress: {self.files_done}/{self.files} files, {100 * self.done / max(self.total, 1):.0f} %, "
                     f"{self.rate / 1e6:.2f} MB/s, {left}.")

    def left(self) -> float:
        return max(self.total - self.done, 0) / max(self.rate, 1.0)

    def end(self) -> None:
        spent = max(self.clock() - self.t0, 1e-6)
        if not self.estimated and self.done:   # a scan shorter than ESTIMATE_SECONDS: its whole speed
            self.estimated = True
            self.say(f"Estimate: about {_took(self.total / max(self.done / spent, 1.0))} for "
                     f"{self.total / 1e6:,.0f} MB ({self.done / spent / 1e6:.2f} MB/s).")
        self.say(f"Scanned {self.done / 1e6:,.0f} MB in {_took(spent)}.")


def busy_load():
    """(1-minute load, cores) when other work keeps more than BUSY_LOAD of the cores busy, else None. No load on
    Windows."""
    try:
        load = os.getloadavg()[0]
    except (AttributeError, OSError):
        return None
    cores = os.cpu_count() or 1
    return (load, cores) if load > BUSY_LOAD * cores else None


def _sample_jobs(files: list, skipped: list | None = None, stop=None):
    """The jobs of the --estimate sample, SAMPLE_JOB_BYTES each: one job of each project in turn, until SAMPLE_BYTES.
    One large file no longer fills the sample alone (Gate A of #59). A line larger than SAMPLE_BYTES leaves its file out
    of the sample, noted in `skipped`; the sample stays within SAMPLE_BYTES; the search for line ends stops at the
    deadline (`stop`)."""
    skipped = [] if skipped is None else skipped
    groups: dict = defaultdict(list)
    for item in files:
        groups[(item[0], str(item[1].parent))].append(item)
    queues = [_jobs(groups[k], SAMPLE_JOB_BYTES, SAMPLE_BYTES, stop, skipped) for k in sorted(groups)]
    size = 0
    while queues:
        for q in list(queues):
            item = next(q, None)
            if item is None:
                queues.remove(q)
                continue
            if size + sum(item[1]) > SAMPLE_BYTES:
                return   # the sample stays within SAMPLE_BYTES
            yield item
            size += sum(item[1])


def _stop(ex) -> None:
    """End a pool at once: cancel the jobs that wait and end the running ones. A worker that still runs keeps the
    process alive at its exit (Gate A of #59)."""
    procs = list((getattr(ex, "_processes", None) or {}).values())   # shutdown() forgets them
    ex.shutdown(wait=False, cancel_futures=True)
    for proc in procs:
        try:
            proc.terminate()
        except (OSError, AttributeError):
            pass
    ex.shutdown(wait=True)


def estimate(files, enabled, workers: int, progress: Progress) -> int:
    """--estimate: the pool that the scan would use (a pool of one with --workers 1) scans spread files for
    SAMPLE_SECONDS and stops at once, also in the middle of a slow record; the time for all comes from that real
    speed, its start included. What the sample finds is not shown. A job that fails ends it with exit code 2."""
    import concurrent.futures
    t0 = progress.clock()
    done, tags, failed, skipped = 0, set(), None, []
    ex = _detector.pool(enabled, max(1, workers), MODE)
    try:
        jobs = _sample_jobs(files, skipped, lambda: progress.clock() - t0 >= SAMPLE_SECONDS)
        pending: dict = {}
        while True:
            # a short queue: a job half written into the pipe of a stopped worker kept the process alive
            for job, sizes in jobs:
                pending[ex.submit(worker_jsonl, job)] = (sum(sizes), job[0][0])
                if len(pending) >= 2 * max(1, workers):
                    break
            left = SAMPLE_SECONDS - (progress.clock() - t0)
            if not pending or left <= 0:
                break
            finished, _rest = concurrent.futures.wait(pending, timeout=left,
                                                      return_when=concurrent.futures.FIRST_COMPLETED)
            for fut in finished:
                nbytes, tag = pending.pop(fut)
                try:
                    fut.result()
                except Exception as e:   # noqa: BLE001  a crashed worker: no estimate from it
                    failed = type(e).__name__
                    break
                done += nbytes
                tags.add(tag)
            if failed:
                break
        spent = max(progress.clock() - t0, 1e-6)   # before the stop: ending the workers is no part of the speed
    finally:
        _stop(ex)
    if skipped:
        progress.say(f"Left out of the sample: {len(skipped)} line(s) larger than {SAMPLE_BYTES / 1e6:.0f} MB.")
    if failed:
        progress.say(f"No estimate: a part of the sample could not be scanned ({failed}).")
        return 2
    if not done:
        progress.say(f"No estimate yet: no part of the sample finished in {SAMPLE_SECONDS} s. The scan itself "
                     "prints its estimate once its first parts are done.")
        return 2
    progress.say(estimate_line(progress.total, done, spent, workers, len(tags)))
    return 0


def estimate_line(total: int, done: int, spent: float, workers: int, files: int) -> str:
    """The --estimate line: the time for `total` bytes at the measured speed of the sample, whatever the number of
    processes."""
    rate = done / spent
    return (f"Estimate: about {_took(total / max(rate, 1.0))} for {total / 1e6:,.0f} MB with {workers} process(es) "
            f"({rate / 1e6:.2f} MB/s on a sample of {done / 1e6:.1f} MB from {files} file(s) in {spent:.0f} s).")


def _size(f: Path) -> int:
    try:
        return f.stat().st_size
    except OSError:
        return 0


_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# the whole file name: Claude Code's <uuid>.jsonl, or Codex's rollout-<date>T<time>-<uuid>.jsonl
_SESSION_ID_RE = re.compile(rf"(?:rollout-\d{{4}}-\d\d-\d\dT\d\d-\d\d-\d\d-)?({_UUID})")


_UNNAMED: dict = {}   # path -> number, per run: a file whose name is no session id


def session_label(client: str, path: Path) -> str:
    """The client and the first 8 characters of the session id, never text of a folder or a file name (a folder
    name can hold a token). Only a file name that is a session id in the client's own form counts; any other file
    is "session N", a number of this run that maps back to nothing (a hash of the path would let a guess at a token
    in the folder name be tested)."""
    name = "Claude" if client == "claude" else "Codex"
    m = _SESSION_ID_RE.fullmatch(path.stem)
    if m:
        return f"{name} {m.group(1)[:8]}"
    n = _UNNAMED.setdefault(str(path), len(_UNNAMED) + 1)
    return f"{name} session {n}"


def classify(kind: str, inner: str | None) -> tuple[str, str]:
    guess = kind in ("generic-api-key", "url-query-secret") or kind.startswith("ds-keyword")
    if not guess:
        return kind, "shape"
    if inner and not (inner in ("generic-api-key", "url-query-secret") or inner.startswith("ds-keyword")):
        return inner, "shape"
    return kind, "guess"


# --- what a finding is: REAL (rotate it), TEST, or UNKNOWN (shown on request) ------------------------------------
REAL, TEST, UNKNOWN = "REAL", "TEST", "UNKNOWN"
TEST_PATH_WHY = "provider format, only in test code"   # UNKNOWN, named on its own line of the summary
ROWS_MAX = 10
# a test word at the start of the value, after a character that is not a letter or a digit, or at its end: inside a
# run of letters and digits it is chance (a random token holds "Test" about once in a million; value_checks.py)
_TEST_WORDS = "test|testing|example|sample|dummy|fake|mock|fixture|placeholder|changeme|demo"
_TEST_WORD_RE = re.compile(rf"(?i)(?:^|[^a-z0-9])(?:{_TEST_WORDS})|(?:{_TEST_WORDS})$")


def names_itself(value: str, rule: str = "") -> bool:
    """A value that says it is a test value: `my-test-token`, `testpass`, `sk-fake-…`, `…EXAMPLE`, a placeholder. A
    value of a rule whose own format holds `test` (format_has_test) is judged by the detector's checks only."""
    if not format_has_test(rule) and _TEST_WORD_RE.search(value):
        return True
    try:
        from maisecrets.detection.value_checks import _names_itself, looks_like_placeholder
    except ImportError:
        return False
    return bool(looks_like_placeholder(value) or _names_itself(value))


def public_test_value(value: str, typ: str) -> bool:
    """A value that vendor documentation publishes for tests (rules/public_test_values.txt)."""
    try:
        from maisecrets.detection.core import is_public_test_value
    except ImportError:
        return False
    return bool(is_public_test_value(value, typ))


def store_matches(values) -> tuple[set, str]:
    """(the values your maisecrets store holds or held, how it was compared). The store is the person's own, and the
    audit runs as the person: Vault.held_among compares the keyed fingerprint of each value in this process. It reads
    the fingerprint key and the index through the vault API, never a stored value and never a store file directly,
    and writes nothing (THREAT-MODEL C17)."""
    try:
        from maisecrets import vault
    except ImportError:
        return set(), "not compared: this copy of the skill has no maisecrets store"
    if not vault.INDEX.exists():
        return set(), "not compared: maisecrets has stored nothing on this computer"
    try:
        held = vault.Vault().held_among(values)
    except Exception as exc:   # a store that cannot be read must not end the audit
        return set(), f"not compared: the store could not be read ({type(exc).__name__})"
    if held is None:
        return set(), "not compared: the store has no fingerprint key"
    return held, "compared in this process by keyed fingerprint; no stored value was read"


def strength(rule: str, sure: str) -> int:
    """2 a provider format, 1 a label rule, 0 a keyword guess."""
    if sure != "shape":
        return 0
    return 2 if provider_format({"sure": sure, "rule": rule}) else 1


_FORMAT_WITH_TEST: list = []


def format_has_test(rule: str) -> bool:
    """The rule's own format holds the word test (Stripe sk_test_, rk_test_, a sandbox key): there the word says
    test mode of a real account, not a made-up value."""
    if not _FORMAT_WITH_TEST:
        ids = set()
        try:
            from maisecrets import detect
            for r in detect.rules():
                rx = getattr(r, "regex", None)
                if rx is not None and re.search(r"(?i)test", str(getattr(rx, "pattern", "") or "")):
                    ids.add(r.id)
        except Exception:   # no rule list: nothing is exempt
            pass
        _FORMAT_WITH_TEST.append(frozenset(ids))
    return rule in _FORMAT_WITH_TEST[0]


def provider_format(e: dict) -> bool:
    """A provider's token format: a shape rule, not a keyword guess and not a label rule (letters after a password
    label are a guess too, whatever their rule is called)."""
    if e["sure"] != "shape":
        return False
    try:
        from maisecrets.detection.registry import is_label
    except ImportError:
        return True
    return not is_label(e["rule"])


def verdict_of(e: dict, value: str, held: bool) -> tuple[str, str]:
    """(class, reason) of one found value. The signals, in this order:
    in your store -> REAL; a keyword guess or a label rule that names itself -> TEST; a documented test value ->
    TEST; only in model output -> TEST (the model wrote it); every occurrence in test code -> TEST for a keyword
    guess, UNKNOWN for a provider format (a real token pasted into a test stays visible); a provider format sent in
    a prompt or a tool result -> REAL; the rest UNKNOWN."""
    sent = SENT & set(e["kinds"])
    if held:
        return REAL, "in your maisecrets store"
    if not provider_format(e) and names_itself(value, e.get("rule", "")):
        # a provider format is no self-named value: its body is random and holds a test word by chance (ghp_test…);
        # the detector already drops a placeholder of a provider format (ghp_fake…)
        return TEST, "names itself a test value"
    if public_test_value(value, e["type"]):
        return TEST, "a documented test value"
    if sent == {"model output"}:
        return TEST, "only in model output"
    shape = provider_format(e)
    if e["test_all"]:
        if not shape:
            return TEST, "only in test code"
        return UNKNOWN, TEST_PATH_WHY
    if shape and sent & {"prompt", "tool result"}:
        return REAL, "provider format, in your input or a tool result"
    if not sent:
        return UNKNOWN, "only in local records"
    return UNKNOWN, "keyword guess"


def load_rotation() -> dict:
    try:
        return json.loads((Path(__file__).resolve().parent / "rotation.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"providers": {}, "rules": []}


def rotation_for(rule: str, table: dict, sure: str = "shape") -> tuple[str, str]:
    """(label, where to revoke it) for a rule: the longest prefix in rotation.json, else the rule's own name (a
    keyword guess: "value after a password label")."""
    best = None
    for row in table.get("rules", []):
        prefix = row[0]
        if rule.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = row
    if best:
        p = table.get("providers", {}).get(best[1])
        if p:
            where = best[3] if len(best) > 3 else p["where"]
            return f"{p['name']} {best[2]}", ("see the provider's settings" if where == "settings" else where)
    return ("value after a password label" if sure == "guess" else rule), "see the provider's settings"


def _providers(clients) -> str:
    names = sorted({"Anthropic" if c == "claude" else "OpenAI" for c in clients})
    return " and ".join(names) or "the AI provider"


def summary(per_id: dict, n_files: int, days: int, report: str, store_note: str, table: dict,
            clients_scanned) -> list[str]:
    """The lines the skill shows as they are: the verdict, at most ROWS_MAX real tokens, one line on the rest."""
    period = f"last {days} days" if days else "all sessions"
    if not per_id:
        return [f"AI history, {period}: no secret found in {n_files} session file(s)."]
    real = [(sid, e) for sid, e in per_id.items() if e["class"] == REAL and SENT & set(e["kinds"])]
    real.sort(key=lambda kv: kv[1]["last"] or "", reverse=True)
    real.sort(key=lambda kv: len(kv[1]["sessions"]), reverse=True)   # most sessions first, then the latest
    lines = []
    if real:
        prov = _providers(set().union(*(e["clients"] for _s, e in real)))
        lines.append(f"AI history, {period}: {len(real)} real token(s) reached {prov}. Rotate them:")
        width = max(len(rotation_for(e["rule"], table, e["sure"])[0]) for _s, e in real[:ROWS_MAX])
        for n, (_sid, e) in enumerate(real[:ROWS_MAX], 1):
            label, where = rotation_for(e["rule"], table, e["sure"])
            when = f"last {e['last']}" if e["last"] else "date unknown"
            lines.append(f"  {n}. {label:<{width}}  {len(e['sessions'])} session(s), {when}  -> {where}")
    else:
        lines.append(f"AI history, {period}: no token that is surely real reached {_providers(clients_scanned)}.")
    # a provider format seen only in test files: no rotation row (fixtures would flood it), but not hidden either
    in_tests = Counter(rotation_for(e["rule"], table, e["sure"])[0] for e in per_id.values()
                       if e["why"] == TEST_PATH_WHY and SENT & set(e["kinds"]))
    if in_tests:
        top = ", ".join(f"{label} {n}" for label, n in in_tests.most_common(3))
        lines.append(f"Also check: {sum(in_tests.values()):,} provider-format token(s) seen only in test files "
                     f"({top}). The report lists them.")
    rest = Counter()
    for _sid, e in per_id.items():
        if e["why"] == TEST_PATH_WHY and SENT & set(e["kinds"]):
            continue
        if e["class"] == REAL and not SENT & set(e["kinds"]):
            rest["only on this computer"] += 1
        elif e["class"] == TEST:
            rest["test values"] += 1
        elif e["class"] == UNKNOWN:
            rest["only on this computer" if not SENT & set(e["kinds"]) else "unclear"] += 1
    parts = []
    if len(real) > ROWS_MAX:
        parts.append(f"{len(real) - ROWS_MAX:,} more real token(s)")
    for name in ("test values", "unclear", "only on this computer"):
        if rest[name]:
            parts.append(f"{rest[name]:,} {name}")
    shown = "Not shown: " + (", ".join(parts) if parts else "nothing") + f". Full report: {report}"
    if store_note.startswith("not compared"):
        shown += f" (your maisecrets store was {store_note})"
    lines.append(shown)
    return lines


def details(per_id: dict) -> list[str]:
    """The classes per rule, for "Show details": what each rule found that reached the provider, by class and
    reason."""
    by_rule: dict = defaultdict(Counter)
    for e in per_id.values():
        if SENT & set(e["kinds"]):
            by_rule[e["rule"]][(e["class"], e["why"])] += 1
    lines = ["BY RULE (values that reached the provider; class: reason count):"]
    for rule, c in sorted(by_rule.items(), key=lambda kv: -sum(kv[1].values())):
        parts = [f"{cls} {why} {n}" for (cls, why), n in sorted(c.items(), key=lambda kv: (kv[0][0], -kv[1]))]
        lines.append(f"  {rule:<28} {sum(c.values()):>5}: " + "; ".join(parts))
    return lines


def shown_path(out, report: Path) -> str:
    """The report as the summary names it, with no folder (a folder name can hold a token): a path the person gave
    (--out) is not echoed; for the temp file the script chose, its file name only."""
    return "the file you gave with --out" if out else f"{report.name} in your temp folder"


def save_report(path: Path, text: str, new: bool) -> bool:
    """write_report, or one line that names the error class and no path (the path can hold a token)."""
    try:
        write_report(path, text, new)
    except OSError as exc:
        print(f"The report file could not be written ({type(exc).__name__}).")
        return False
    return True


def default_report_path() -> Path:
    import tempfile
    return Path(tempfile.gettempdir()) / f"maisecrets-ai-history-{time.strftime('%Y%m%d-%H%M%S')}.txt"


def write_report(path: Path, text: str, new: bool = False) -> None:
    """The report holds no value: rule names, counts, dates and session labels. Readable by the person only: an
    existing --out file gets mode 0600 too (os.open sets the mode only when it creates the file), and the default
    report (new) is created exclusively, so a file or a link planted at its path is not followed."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if new else os.O_TRUNC) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Secrets that already reached an AI provider, by location, never by value.")
    ap.add_argument("--claude", action="store_true")
    ap.add_argument("--codex", action="store_true")
    ap.add_argument("--pii", action="store_true", help="also list personal data (e-mail, IBAN, phone ...)")
    ap.add_argument("--days", type=int, default=30,
                    help="only sessions written to in the last N days (default: 30; 0 for all)")
    ap.add_argument("--all", action="store_true", help="all sessions, of any age")
    ap.add_argument("--out", help="write the full report to this file (default: a new file in the temp folder); "
                                  "stdout gets only the summary")
    ap.add_argument("--scrub", action="store_true", help="list the local files that hold a found value")
    ap.add_argument("--yes", action="store_true", help="with --scrub: replace the values in those files")
    ap.add_argument("--workers", type=int, default=0,
                    help=f"processes that scan (default: the cores minus one, here {default_workers()})")
    ap.add_argument("--full", action="store_true",
                    help="read each record as one text with every rule, as before (slower; the default fast scan "
                         "runs the rules only near a line with a rule's prefix or keyword)")
    ap.add_argument("--estimate", action="store_true",
                    help="print the size and the estimated time, scan only a sample, and stop")
    args = ap.parse_args(argv)
    global MODE
    MODE = "full" if args.full else "fast"
    _UNNAMED.clear()
    if args.all:
        args.days = 0
    if not args.claude and not args.codex:
        args.claude = args.codex = True
    detect = _detector.load()
    enabled = None if args.pii else _detector.secret_rules(detect)
    files = sources(args.claude, args.codex, args.days)
    if not files and not args.estimate and not args.scrub:
        report = Path(args.out) if args.out else default_report_path()
        period = f"last {args.days} days" if args.days else "all sessions"
        head = [f"AI history, {period}: no transcripts found.", f"Full report: {shown_path(args.out, report)}"]
        if not save_report(report, "\n".join(head) + "\n", new=not args.out):
            return 2
        print("\n".join(head))
        return 0
    if not files:
        print("No agent transcripts found.")
        return 0
    ids: dict[str, str] = {}
    per_id: dict[str, dict] = {}
    per_file: dict[str, set] = defaultdict(set)
    client_of = {str(f): c for c, f in files}
    workers = max(1, args.workers) if args.workers else default_workers()
    progress = Progress(files, workers)
    if args.estimate:
        return estimate(files, enabled, workers, progress)
    order = {str(f): n for n, (_c, f) in enumerate(files)}
    notes: Counter = Counter()
    for (tag, _start), rows, job_notes, _nbytes in run(files, enabled, workers, progress):
        notes.update(job_notes)
        progress.tick(order.get(tag, 0))
        for _i, kind, stamp, mtype, rule, value, inner, in_test in rows:
            if not args.pii and mtype != "SECRET":
                continue
            sid = ids.setdefault(value, f"S{len(ids) + 1}")
            per_file[tag].add(value)
            name, sure = classify(rule, inner)
            e = per_id.setdefault(sid, {"type": mtype, "rule": name, "sure": sure, "len": len(value),
                                        "sessions": set(), "kinds": Counter(), "first": stamp, "last": stamp,
                                        "clients": set(), "test_all": True})
            if strength(name, sure) > strength(e["rule"], e["sure"]):
                # the strongest finding of the value counts, in any order: a provider format beats a label rule,
                # and a label rule beats a keyword guess
                e["rule"], e["sure"] = name, sure
            e["sessions"].add(session_label(client_of[tag], Path(tag)))
            e["kinds"][kind] += 1
            e["clients"].add(client_of[tag])
            e["test_all"] = e["test_all"] and bool(in_test)
            if stamp:
                e["first"] = min(e["first"] or stamp, stamp)
                e["last"] = max(e["last"] or stamp, stamp)
    progress.end()
    if args.scrub:
        return scrub(per_file, ids, args.yes)
    held, store_note = store_matches(list(ids)) if ids else (set(), "not needed")
    for value, sid in ids.items():
        per_id[sid]["class"], per_id[sid]["why"] = verdict_of(per_id[sid], value, value in held)
    report = Path(args.out) if args.out else default_report_path()
    table = load_rotation()
    head = summary(per_id, len(files), args.days, shown_path(args.out, report), store_note, table,
                   {c for c, _f in files})
    lines = head + ["", f"Scanned {len(files)} transcript file(s)."]
    if notes["unread"]:
        lines.append(f"Not scanned: {notes['unread']} record(s) that could not be read.")
    lines.append(f"Your maisecrets store: {store_note}.")
    sent = {k: v for k, v in per_id.items() if SENT & set(v["kinds"])}
    local = {k: v for k, v in per_id.items() if k not in sent}
    lines.append(f"Reached the AI provider: {len(sent)} distinct value(s). Only in local records: {len(local)}.")
    rank = {REAL: 0, UNKNOWN: 1, TEST: 2}
    for title, group in (("REACHED THE PROVIDER", sent), ("Only in local records", local)):
        if not group:
            continue
        lines.append(title + ":")
        for sid, e in sorted(group.items(), key=lambda kv: (rank[kv[1]["class"]], kv[1]["sure"] != "shape",
                                                            int(kv[0][1:]))):
            where = ", ".join(f"{n} {k}" for k, n in e["kinds"].most_common())
            prov = "/".join(sorted({"Anthropic" if c == "claude" else "OpenAI" for c in e["clients"]}))
            shown = "; ".join(sorted(e["sessions"])[:3]) + (f"; +{len(e['sessions']) - 3} more"
                                                             if len(e["sessions"]) > 3 else "")
            lines.append(f"  {sid:<5} {e['class']:<7} {e['type']:<7} {e['rule']:<24} {e['sure']:<5} len {e['len']:<4} "
                         f"to {prov:<16} {e['first']}..{e['last']} in {len(e['sessions'])} session(s) "
                         f"[{where}] ({e['why']}): {shown}")
    if per_id:
        lines += [""] + details(per_id)
        lines.append("REAL: rotate it (references/rotation.md). TEST: a test value. UNKNOWN: not sure either way; a "
                     "keyword guess can be noise, and a provider format in test code can still be real.")
    lines.append("Values are not shown. The same id means the same value. Deleting or scrubbing a local "
                 "transcript does not take back what the provider received.")
    if not save_report(report, "\n".join(lines) + "\n", new=not args.out):
        return 2
    print("\n".join(head))
    return 1 if per_id else 0


def scrub(per_file: dict[str, set], ids: dict[str, str], yes: bool) -> int:
    now = time.time()
    targets = []
    for tag, values in sorted(per_file.items()):
        path = Path(tag)
        try:
            active = now - path.stat().st_mtime < ACTIVE_SECONDS
        except OSError:
            continue
        targets.append((path, values, active))
    if not targets:
        print("No local transcript holds a found value.")
        return 0
    for path, values, active in targets:
        note = " (skipped: written to in the last 10 minutes)" if active else ""
        print(f"  {len(values)} value(s) in {path}{note}")
    if not yes:
        print(f"{sum(1 for t in targets if not t[2])} file(s) would be changed. Nothing was changed. Run again "
              "with --scrub --yes to replace the values in them. This cleans only this computer; the provider "
              "keeps what it received.")
        return 1
    changed, left, moved, missed = 0, 0, [], 0
    for path, values, active in targets:
        if active:
            continue
        result = _scrub_file(path, values, ids)
        if result is None:
            moved.append(path)
            continue
        n_left, n_missing, n_changed = result
        left += n_left
        missed += n_missing
        changed += n_changed > 0
        if n_missing:
            print(f"  not scrubbed in {path}: {n_missing} value(s) that do not stand there as text (encoded, or "
                  "split over fields)")
    for path in moved:
        print(f"  skipped {path}: it changed while this ran (a session is writing to it)")
    if left:
        print(f"{left} line(s) could not be cleaned (not valid JSON or not UTF-8) and still hold a value.")
    print(f"Replaced the values in {changed} file(s). The provider keeps what it received: rotate the values.")
    return 1 if left or missed else 0


def _is_text_document(node) -> bool:
    """An Anthropic base64 source of a text/* document: the audit reads its decoded text (strings_of)."""
    media = node.get("media_type")
    return (node.get("type") == "base64" and isinstance(node.get("data"), str) and isinstance(media, str)
            and media.startswith("text/"))


def _decoded(data: str):
    try:
        return base64.b64decode(data).decode("utf-8")
    except ValueError:
        return None


def _scrub_strings(node):
    """Every string the scrub can reach: the JSON strings, and the decoded text of a text/* document."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for x in node:
            yield from _scrub_strings(x)
    elif isinstance(node, dict):
        if _is_text_document(node):
            text = _decoded(node["data"])
            if text is not None:
                yield text
        for x in node.values():
            yield from _scrub_strings(x)


def _scrub_file(path: Path, values: set, ids: dict) -> tuple | None:
    """Replace the values in one transcript, line by line, in bytes: an unchanged line is copied
    byte for byte (CRLF, number spelling and invalid UTF-8 stay as they were), a changed line is
    written as compact JSON, a line that is not JSON gets a plain text replacement. The values are
    searched in the decoded JSON strings (a value with a line break is escaped in the raw line), and in
    the decoded text of a text/* document in base64, which is encoded again after the replacement. The
    file mode is kept. Returns (lines that still hold a value, values found nowhere as text, lines changed),
    or None when the file changed while it was read (a session wrote to it; review, 2026-09-27). The scrub
    never counts a value as replaced that it did not find (Gate A of #59)."""
    tags = {v: f"⟦SCRUBBED_{ids[v]}⟧" for v in values}
    order = sorted(tags, key=len, reverse=True)
    before = path.stat()
    raw = path.read_bytes()
    out: list[bytes] = []
    left, n_changed = 0, 0
    seen: set = set()

    def replace(text: str) -> str:
        for v in order:
            if v in text:
                seen.add(v)
                text = text.replace(v, tags[v])
        return text

    def clean(node):
        if isinstance(node, str):
            return replace(node)
        if isinstance(node, list):
            return [clean(x) for x in node]
        if isinstance(node, dict):
            new = {k: clean(x) for k, x in node.items()}
            if _is_text_document(node):
                text = _decoded(node["data"])
                if text is not None:
                    done = replace(text)
                    if done != text:
                        new["data"] = base64.b64encode(done.encode("utf-8")).decode("ascii")
            return new
        return node

    def holds(rec) -> bool:
        return any(v in x for x in _scrub_strings(rec) for v in order)
    for line in raw.splitlines(keepends=True):
        body = line.rstrip(b"\r\n")
        end = line[len(body):]
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            out.append(line)
            hit = [v for v in order if v.encode("utf-8") in body]
            seen.update(hit)
            left += bool(hit)
            continue
        try:
            rec = json.loads(text)
        except ValueError:
            rec = None
        if rec is not None:
            if not holds(rec):
                out.append(line)
                continue
            try:
                cleaned = clean(rec)
                new = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except UnicodeEncodeError:
                out.append(line)
                left += 1
                continue
            out.append(new + end)
            n_changed += 1
            left += holds(cleaned)
            continue
        if not any(v in text for v in order):
            out.append(line)
            continue
        plain = replace(text)
        try:
            new = plain.encode("utf-8")
        except UnicodeEncodeError:
            out.append(line)
            left += 1
            continue
        out.append(new + end)
        n_changed += 1
        left += any(v in plain for v in order)
    now = path.stat()
    if (now.st_size, now.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        return None
    missing = len(set(order) - seen)
    if n_changed:
        tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, before.st_mode & 0o777)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(b"".join(out))
            os.chmod(tmp, before.st_mode & 0o777)
            # Again just before the replace: an append while the copy was written would be lost.
            now = path.stat()
            if (now.st_size, now.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
                return None
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()
    return left, missing, n_changed


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
