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

It prints the size of the transcripts first, an estimate after the first few MB, a progress line at
least every 30 seconds and the time it took, on stderr. --estimate scans only a sample in one process
and prints the estimate.

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
import sys
import time
import zlib
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _detector  # noqa: E402
import _fast  # noqa: E402

SENT = {"prompt", "tool result", "model output"}
ACTIVE_SECONDS = 600
LINES_PER_JOB = 2000
JOB_BYTES = 2_000_000       # a job ends at this size too: a file of few long lines balanced badly over the pool
SMALL = 512                 # the strings of a record shorter than this are joined and scanned as one text
PART = 1024                 # a long text is cut at a blank line, into parts of about this size or more
PART_MAX = 65536
MODE = "fast"               # "full" (--full): each record one text, every rule; "fast": _fast.py
SEEN_MAX = 300_000          # the texts a worker remembers by hash before it forgets them all
SAMPLE_BYTES = 2_000_000    # the estimate is measured on the first ~2 MB
SAMPLE_SECONDS = 20         # or on what one process scans in this time
POOL_SHARE = 0.7            # a pool of N processes scans about 0.7 x N times one (netcup, 8 cores, #59)
PROGRESS_SECONDS = 30


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
    return sorted(out, key=lambda x: str(x[1]))


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
    """(type, rule, value, inner rule) per hit of a record. Each text is scanned alone, so it stays one cache entry
    when it recurs. Each border is scanned too: CONTEXT_LINES lines on each side of it, from as many texts as that
    takes (_border). A hit there counts once, where it starts, and only when that text did not find it alone: a
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
        for start, typ, rule, value, inner in scan_once(detect, text, enabled, channel, whole):
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
            found.append((typ, rule, value, inner))
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


def scan_once(detect, text: str, enabled, channel: str, whole: bool = False) -> tuple:
    """(start, type, rule, value, inner rule) per hit of a text, each distinct text scanned once per worker. The key
    is a sha256 of the text with the mode, the rule selection and the channel, kept in memory only."""
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
        hits.append((m.start, m.type, m.kind, m.value, inner))
    if len(_SEEN) >= SEEN_MAX:
        _SEEN.clear()
    _SEEN[key] = got = tuple(hits)
    return got


def worker_jsonl(job: tuple) -> tuple:
    """job = (tag, client, lines): scan the texts of each JSON line (units); return the tag, the rows
    (line index, record kind, timestamp, type, rule, value, inner rule) per hit, and the notes: the records that
    could not be scanned."""
    tag, client, lines = job
    detect, enabled = _detector._W["detect"], _detector._W["enabled"]
    rows: list = []
    notes: dict = {}
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
            for typ, rule, value, inner in record_hits(detect, segs, enabled, channel):
                rows.append((i, kind, stamp, typ, rule, value, inner))
        except Exception:   # one record that breaks a step (a lone surrogate, Gate A) must not end the audit
            del rows[mark:]
            notes["unread"] = notes.get("unread", 0) + 1
    return tag, rows, notes


def _jobs(files: list[tuple[str, Path]]):
    """(job, the size in bytes of each of its lines) per job. The file is read in bytes and each line decoded: the
    progress counts what the file holds on disk, also a CRLF line end (Windows) and a letter of several bytes; a count
    of the decoded characters never reached the file size there, and no estimate came (round 6 of #59)."""
    for client, f in files:
        try:
            with open(f, "rb") as fh:
                batch, sizes, start = [], [], 0
                for n, raw in enumerate(fh):
                    batch.append(raw.decode("utf-8", errors="replace"))
                    sizes.append(len(raw))
                    if len(batch) >= LINES_PER_JOB or sum(sizes) >= JOB_BYTES:
                        yield ((str(f), start), client, batch), sizes
                        batch, sizes, start = [], [], n + 1
                if batch:
                    yield ((str(f), start), client, batch), sizes
        except OSError:
            continue


def jobs_for(files: list[tuple[str, Path]]):
    for job, _sizes in _jobs(files):
        yield job


def default_workers() -> int:
    return max(1, (os.cpu_count() or 2) - 1)


def run(files, enabled, workers: int = 0):
    """(tag, rows, notes, characters) per job, in the order of the jobs."""
    workers = workers or default_workers()
    total = sum(f.stat().st_size for _c, f in files if f.exists())
    if total < 1_000_000 or workers == 1:
        _detector._worker_init(enabled, MODE)
        for job, sizes in _jobs(files):
            yield worker_jsonl(job) + (sum(sizes),)
        return
    ex = _detector.pool(enabled, workers, MODE)
    done = False
    try:
        window = 4 * workers
        pending = []
        for job, sizes in _jobs(files):
            pending.append((ex.submit(worker_jsonl, job), sum(sizes)))
            if len(pending) >= window:
                fut, n = pending.pop(0)
                yield fut.result() + (n,)
        for fut, n in pending:
            yield fut.result() + (n,)
        done = True
    finally:
        # closed early (--estimate): the jobs that wait are cancelled, and nothing waits for the running ones
        ex.shutdown(wait=done, cancel_futures=not done)


def _took(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f} s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


class Progress:
    """Size and file count first (stat only), an estimate after the first SAMPLE_BYTES, a line at least every
    PROGRESS_SECONDS, the time at the end. On stderr; it names no value, line or hash."""

    def __init__(self, files, workers: int, out=None):
        self.out, self.files = out or sys.stderr, len(files)
        self.total = sum(_size(f) for _c, f in files)
        self.t0 = self.last = time.monotonic()
        self.done = self.files_done = 0
        self.rate = 0.0
        self.estimated = False
        self.say(f"Scanning {self.files} transcript file(s), {self.total / 1e6:,.0f} MB, with {workers} process(es).")

    def say(self, text: str) -> None:
        print(text, file=self.out, flush=True)

    def step(self, nbytes: int, files_done: int) -> None:
        self.done += nbytes
        self.files_done = files_done
        now = time.monotonic()
        spent = max(now - self.t0, 1e-6)
        self.rate = self.done / spent
        if not self.estimated and (self.done >= min(SAMPLE_BYTES, self.total) or spent >= SAMPLE_SECONDS):
            self.estimated = True
            self.say(f"Estimate: about {_took(self.left())} for {self.total / 1e6:,.0f} MB "
                     f"({self.rate / 1e6:.2f} MB/s on the first {self.done / 1e6:.1f} MB).")
            self.last = now
        elif now - self.last >= PROGRESS_SECONDS:
            self.last = now
            self.say(f"Progress: {self.files_done}/{self.files} files, {100 * self.done / max(self.total, 1):.0f} %, "
                     f"{self.rate / 1e6:.2f} MB/s, about {_took(self.left())} left.")

    def left(self) -> float:
        return max(self.total - self.done, 0) / max(self.rate, 1.0)

    def end(self) -> None:
        if not self.estimated:   # a file that shrank or could not be read: the sample size was never reached
            self.estimated = True
            self.say(f"Estimate: about {_took(self.left())} for {self.total / 1e6:,.0f} MB "
                     f"({self.rate / 1e6:.2f} MB/s on {self.done / 1e6:.1f} MB).")
        self.say(f"Scanned {self.done / 1e6:,.0f} MB in {_took(time.monotonic() - self.t0)}.")


def estimate(files, enabled, workers: int, progress: Progress) -> int:
    """--estimate: one process scans the first records, up to SAMPLE_BYTES or SAMPLE_SECONDS, one record at a time,
    and the time for all is worked out from that rate. No pool starts, so nothing runs on after the estimate (Gate A
    of #59). What the sample finds is not shown."""
    _detector._worker_init(enabled, MODE)
    target = min(SAMPLE_BYTES, progress.total)
    t0 = time.monotonic()
    done = 0
    for (tag, client, lines), sizes in _jobs(files):
        for line, size in zip(lines, sizes):
            worker_jsonl((tag, client, [line]))
            done += size
            if done >= target or time.monotonic() - t0 >= SAMPLE_SECONDS:
                break
        else:
            continue
        break
    one = done / max(time.monotonic() - t0, 1e-6)
    rate = one if workers == 1 else one * workers * POOL_SHARE
    progress.say(f"Estimate: about {_took(progress.total / max(rate, 1.0))} for {progress.total / 1e6:,.0f} MB with "
                 f"{workers} process(es) ({one / 1e6:.2f} MB/s in one process on the first {done / 1e6:.1f} MB).")
    return 0


def _size(f: Path) -> int:
    try:
        return f.stat().st_size
    except OSError:
        return 0


def session_label(client: str, path: Path) -> str:
    if client == "claude":
        return f"Claude {path.parent.name.strip('-').replace('-', '/')[-40:]} {path.stem[:8]}"
    return f"Codex {path.stem[-36:][:8]}"


def classify(kind: str, inner: str | None) -> tuple[str, str]:
    guess = kind in ("generic-api-key", "url-query-secret") or kind.startswith("ds-keyword")
    if not guess:
        return kind, "shape"
    if inner and not (inner in ("generic-api-key", "url-query-secret") or inner.startswith("ds-keyword")):
        return inner, "shape"
    return kind, "guess"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Secrets that already reached an AI provider, by location, never by value.")
    ap.add_argument("--claude", action="store_true")
    ap.add_argument("--codex", action="store_true")
    ap.add_argument("--pii", action="store_true", help="also list personal data (e-mail, IBAN, phone ...)")
    ap.add_argument("--days", type=int, default=30,
                    help="only sessions written to in the last N days (default: 30; 0 for all)")
    ap.add_argument("--all", action="store_true", help="all sessions, of any age")
    ap.add_argument("--out", help="write the full report to this file and print only the summary")
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
    if args.all:
        args.days = 0
    if not args.claude and not args.codex:
        args.claude = args.codex = True
    detect = _detector.load()
    enabled = None if args.pii else _detector.secret_rules(detect)
    files = sources(args.claude, args.codex, args.days)
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
    for (tag, _start), rows, job_notes, nbytes in run(files, enabled, workers):
        notes.update(job_notes)
        progress.step(nbytes, order.get(tag, 0))
        for _i, kind, stamp, mtype, rule, value, inner in rows:
            if not args.pii and mtype != "SECRET":
                continue
            sid = ids.setdefault(value, f"S{len(ids) + 1}")
            per_file[tag].add(value)
            name, sure = classify(rule, inner)
            e = per_id.setdefault(sid, {"type": mtype, "rule": name, "sure": sure, "len": len(value),
                                        "sessions": set(), "kinds": Counter(), "first": stamp, "last": stamp,
                                        "clients": set()})
            e["sessions"].add(session_label(client_of[tag], Path(tag)))
            e["kinds"][kind] += 1
            e["clients"].add(client_of[tag])
            if stamp:
                e["first"] = min(e["first"] or stamp, stamp)
                e["last"] = max(e["last"] or stamp, stamp)
    progress.end()
    if args.scrub:
        return scrub(per_file, ids, args.yes)
    lines = [f"Scanned {len(files)} transcript file(s)."]
    if notes["unread"]:
        lines.append(f"Not scanned: {notes['unread']} record(s) that could not be read.")
    sent = {k: v for k, v in per_id.items() if SENT & set(v["kinds"])}
    local = {k: v for k, v in per_id.items() if k not in sent}
    lines.append(f"Reached the AI provider: {len(sent)} distinct value(s). Only in local records: {len(local)}.")
    for title, group in (("REACHED THE PROVIDER (rotate these)", sent), ("Only in local records", local)):
        if not group:
            continue
        lines.append(title + ":")
        for sid, e in sorted(group.items(), key=lambda kv: (kv[1]["sure"] != "shape", kv[0])):
            where = ", ".join(f"{n} {k}" for k, n in e["kinds"].most_common())
            prov = "/".join(sorted({"Anthropic" if c == "claude" else "OpenAI" for c in e["clients"]}))
            shown = "; ".join(sorted(e["sessions"])[:3]) + (f"; +{len(e['sessions']) - 3} more"
                                                             if len(e["sessions"]) > 3 else "")
            lines.append(f"  {sid:<5} {e['type']:<7} {e['rule']:<24} {e['sure']:<5} len {e['len']:<4} "
                         f"to {prov:<16} {e['first']}..{e['last']} in {len(e['sessions'])} session(s) "
                         f"[{where}]: {shown}")
    shape = sum(1 for e in sent.values() if e["sure"] == "shape")
    lines.append(f"Summary: {len(sent)} value(s) reached a provider, {shape} of them in a provider's token format "
                 f"(rotate first); {len(sent) - shape} are keyword guesses that can be noise.")
    lines.append("Values are not shown. The same id means the same value. Deleting or scrubbing a local "
                 "transcript does not take back what the provider received.")
    if args.out:
        Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Wrote the full report to {args.out}.")
        print("\n".join(line for line in lines if not line.startswith("  ")))
    else:
        print("\n".join(lines))
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
