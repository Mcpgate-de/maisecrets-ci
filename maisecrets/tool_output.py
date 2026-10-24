"""What the PostToolUse hook does to a tool result besides the scan: the exact match of the values a session
resolved or the store holds, in every derived form, the strip of hidden characters, the mask of their byte forms in
a transcript, and the places of a result that hold a file as base64. hooks.py imports every name again, so
hooks.<name> is the same object."""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from . import detect
from .debug_log import _debug
from .lazy_regex import LazyRx as _LazyRx
from .vault import Vault

_TOKEN_SPLIT_RE = _LazyRx(r"[\s\"'`<>()\[\]{},;]+")
_FINE_SPLIT_RE = _LazyRx(r"[/?&#=:@,;+|\\]")
_EXACT_MIN_LEN = 8


def _candidates(token: str):
    """The token and the pieces a value usually sits in: after KEY=, inside user:pass@host, in
    a URL path or query, without trailing punctuation, JSON-unescaped and URL-decoded. A base64
    value keeps its '=' padding because the split at '=' is a second candidate, not a
    replacement. A value in `?k=<v>&z=1` or `path/<v>/x` reached the model before the fine
    split (review, 2026-09-26)."""
    yield token
    stripped = token.rstrip(".,;:)")
    if stripped != token:
        yield stripped
    if "=" in token:
        yield token.split("=", 1)[1]
    for piece in _FINE_SPLIT_RE.split(token):
        if len(piece) >= _EXACT_MIN_LEN and piece != token:
            yield piece
    if "%" in token:
        from urllib.parse import unquote
        dec = unquote(token)
        if dec != token:
            yield dec
            for piece in _FINE_SPLIT_RE.split(dec):
                if len(piece) >= _EXACT_MIN_LEN and piece != dec:
                    yield piece
            # a value with an encoded separator (`?t=pa%40ss…`) splits apart once decoded
            for piece in _FINE_SPLIT_RE.split(token):
                if "%" in piece and unquote(piece) != piece:
                    yield unquote(piece)
    if "\\" in token:
        try:
            dec = json.loads('"' + token + '"')
        except ValueError:
            dec = None
        if dec and dec != token:
            yield dec
    yield from _decoded(token)


_HEX_RE = _LazyRx(r"(?:[0-9a-fA-F]{2}){6,}")
_B64_RE = _LazyRx(r"[A-Za-z0-9+/_-]{12,}={0,2}")


def _decoded(token: str):
    """The text a hex or base64 token decodes to. A stored value that another session put in
    and a command printed as `| base64` or `xxd -p` reached the model: the encoded forms were
    checked only for values this session resolved (invariant I1, 2026-09-28). Decoding needs
    no store read; the fingerprint decides."""
    import base64
    import binascii
    t = token.rstrip(".,;:)")
    out = []
    if _HEX_RE.fullmatch(t):
        try:
            out.append(bytes.fromhex(t))
        except ValueError:
            pass
    if _B64_RE.fullmatch(t):
        padded = t + "=" * (-len(t) % 4)
        for alt in (b"+/", b"-_"):
            try:
                out.append(base64.b64decode(padded, altchars=alt, validate=True))
            except (binascii.Error, ValueError):
                pass
    for raw in out:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(text) >= _EXACT_MIN_LEN and text.isprintable():
            yield text


def _derived_forms(value: str) -> list[str]:
    """The shapes a value takes after the encodings a command applies on the way out: base64
    (standard and URL-safe, with and without padding), hex, URL-encoded, JSON-escaped. Checked
    as plain substrings for the values this session resolved (review, 2026-09-26: `| base64`
    and `xxd -p` reached the model)."""
    import base64
    from urllib.parse import quote, quote_plus
    raw = value.encode("utf-8")
    forms = [value]
    for f in (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()):
        forms += [f, f.rstrip("=")]
    escaped = [json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]]
    # JSON inside a JSON string (an MCP result whose text is a JSON document) escapes twice
    forms += [raw.hex(), raw.hex().upper(), quote(value, safe=""), quote_plus(value), *escaped,
              *(json.dumps(e)[1:-1] for e in escaped)]
    return [f for f in dict.fromkeys(forms) if len(f) >= _EXACT_MIN_LEN]


def _resolved_values(vault: Vault, session: str | None, prompt: bool = False) -> list[tuple[str, str]]:
    """(value, reference) for every key this session resolved in the last hour: a value the hook
    itself inserted into a command or an MCP argument is expected back in the output, in any
    position and any encoding, so it is matched as a substring and not by whole token."""
    now = time.time()
    keys = [r["key"] for r in vault._index.get("resolves", []) if r.get("session") == session and r["ts"] > now - 3600]
    out: list[tuple[str, str]] = []
    from .vault import Entry
    # a weak entry is not hunted as a substring either, and in a typed prompt (prompt) a quiet one is not
    # (Vault.live_fingerprints): an agent that used the placeholder of a word made the word block the prompt (Gate A)
    live = [k for k in dict.fromkeys(keys) if vault._index["entries"].get(k)
            and not vault._index["entries"][k].get("purged") and not vault._index["entries"][k].get("weak")
            and not (prompt and vault._index["entries"][k].get("quiet"))]
    if hasattr(vault.backend, "get_many"):
        found = vault.backend.get_many(live)
    else:
        found = {k: v for k in live for v in [vault.backend.get(k)] if v}
    for key in live:
        value = found.get(key)
        if value:
            out.append((value, Entry.from_meta(vault._index["entries"][key]).ref))
    from . import vault_refs
    # the values a server gave this session; a short one or a word would rewrite every output that holds it
    # ("true" inside "construed"), so those are not hunted (Fable review, round 3)
    out.extend((v, t) for v, t in vault_refs.released(vault.backend, session)
               if len(v) >= _EXACT_MIN_LEN and not detect.reads_as_word(v))
    return out


def _inserted_values(text: str, vault: Vault, prompt: bool = False) -> list[tuple[str, str]]:
    """(value, reference) for every live vault value that appears in ``text``, found by keyed
    fingerprint of the tokens, so no value is read from the store. prompt: the text is a typed prompt
    (Vault.live_fingerprints)."""
    live = vault.live_fingerprints(prompt)
    if not live:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for token in _TOKEN_SPLIT_RE.split(text):
        for cand in _candidates(token):
            if len(cand) < _EXACT_MIN_LEN or cand in seen:
                continue
            seen.add(cand)
            key = live.get(vault.fingerprint(cand))
            if key is not None:
                from .vault import Entry
                out.append((cand, Entry.from_meta(vault._index["entries"][key]).ref))
    return out


def _exact_redact(text: str, vault: Vault, session: str | None, hit: dict, entries: list,
                  resolved: list[tuple[str, str]] | None = None, values: list[str] | None = None,
                  prompt: bool = False) -> str:
    """Values without a known shape (a password stored with `put`, a value from a prior
    prompt) come back from a command in plaintext unless they are matched exactly. The
    match is by keyed fingerprint of each token, so no value is read from the store; the
    values this session itself resolved are matched as substrings in every derived form."""
    out = text
    for value, ref in resolved or []:
        # a value this session itself put in is no guess: it goes at any length. The 8-character floor of
        # _derived_forms is for the encoded forms and the fingerprint search below; a 6-character password
        # stored with `put` came back to the model in plain text (external review, 2026-09-28)
        forms = _derived_forms(value)
        if value and 4 <= len(value) < _EXACT_MIN_LEN:
            forms.append(value)       # 4 to 7 characters: everywhere, also between letters
        if value and len(value) < 4:
            # under 4 characters only where no letter or digit stands next to it: a plain substring replace
            # of `a` broke every word of the output (Codex review, 2026-09-28)
            pattern = re.compile(r"(?<![^\W_])" + re.escape(value) + r"(?![^\W_])")   # any letter or digit
            out, n = pattern.subn(lambda _m: ref, out)
            if n:
                hit["n"] += n
                if values is not None and value not in values:
                    values.append(value)
        for form in sorted(forms, key=len, reverse=True):
            if form in out:
                n = out.count(form)
                out = out.replace(form, ref)
                hit["n"] += n
                if values is not None and form not in values:
                    values.append(form)
    live = vault.live_fingerprints(prompt)   # a typed prompt does not hunt a quiet entry (Entry.quiet)
    if not live:
        return out
    found: list[str] = []          # admitted together at the end: one index write, not one per hit
    seen: set[str] = set()
    tokens = list(_TOKEN_SPLIT_RE.split(out))
    # a value with spaces or quotes survives no tokenizer; the rest of a KEY=value line does
    for line in out.splitlines():
        line = line.strip()
        tokens.append(line)
        for sep in ("=", ":"):
            if sep in line:
                tokens.append(line.split(sep, 1)[1].strip())
    for token in tokens:
        if len(token) < _EXACT_MIN_LEN:
            continue
        for cand in _candidates(token):
            if len(cand) < _EXACT_MIN_LEN or cand in seen:
                continue
            seen.add(cand)
            key = live.get(vault.fingerprint(cand))
            if key is None:
                continue
            found.append(key)
            from .vault import Entry
            e = Entry.from_meta(vault._index["entries"][key])
            # a URL-decoded or JSON-unescaped candidate is not in the text; its encoded form is
            raw = cand if cand in out else _raw_form(token, cand)
            n = out.count(raw)
            out = out.replace(raw, e.ref)
            hit["n"] += n
            entries.append(e)
            if values is not None and raw not in values:
                values.append(raw)
    vault.admit_many(found, session)
    return out


def _raw_form(token: str, cand: str) -> str:
    """The piece of ``token`` that decodes to ``cand`` (URL-encoded or JSON-escaped), shortest
    first; the whole token when no piece does, so the encoded value never stays in the text."""
    from urllib.parse import unquote
    pieces = [token, token.rstrip(".,;:)")] + ([token.split("=", 1)[1]] if "=" in token else [])
    pieces += _FINE_SPLIT_RE.split(token)
    for p in sorted(dict.fromkeys(pieces), key=len):
        if "%" in p and unquote(p) == cand:
            return p
        if "\\" in p:
            try:
                if json.loads('"' + p + '"') == cand:
                    return p
            except ValueError:
                pass
    return token


# Text a model reads and a person does not see (README, "Invisible characters"): Unicode tag characters, each the
# twin of an ASCII character ("ASCII smuggling"), and variation selectors used as bytes. Bidi controls are not
# in it: they reorder what a person sees, the model reads the text in its logical order (Opus review, 2026-10-06).
_TAGS_RE = _LazyRx("[\U000E0000-\U000E007F]+")
# the three flags of the standard emoji set that are tag sequences: England, Scotland, Wales
_FLAG_TAGS = {"".join(chr(0xE0000 + ord(c)) for c in name) + "\U000E007F" for name in ("gbeng", "gbsct", "gbwls")}
_VS_RE = _LazyRx("[\uFE00-\uFE0F\U000E0100-\U000E01EF]")


def _cjk(ch: str) -> bool:
    """An assigned CJK ideograph, the base of an ideographic variation sequence."""
    import unicodedata
    return unicodedata.name(ch, "").startswith(("CJK UNIFIED IDEOGRAPH", "CJK COMPATIBILITY IDEOGRAPH"))


def _selector_kept(text: str, at: int) -> bool:
    """A variation selector a character may carry, by a rule of thumb and not the Unicode registry of variation
    sequences: one after a visible character, that is a letter, a digit, punctuation or a symbol (no control,
    format, private, unassigned, combining or space character). VS15 and VS16 (emoji or text presentation) after
    any such character; VS1 to VS14 not after ASCII; VS17 to VS256 (ideographic variants) only after an assigned
    CJK ideograph. A second selector, or one after another kind of character, goes (Opus review, 2026-10-06: a
    joiner between selectors passed a rule that looked at runs; codex, 2026-10-06: line separators, combining and
    private characters passed a list of five categories)."""
    import unicodedata
    if at == 0:
        return False
    prev, vs = text[at - 1], ord(text[at])
    if unicodedata.category(prev)[0] in "CMZ":      # a selector itself is Mn, so a second one in a row goes too
        return False
    if vs in (0xFE0E, 0xFE0F):
        return True
    if vs <= 0xFE0D:
        return ord(prev) > 0x7F
    return _cjk(prev)


def strip_hidden(text: str) -> tuple[str, int, list[str]]:
    """``text`` without tag characters (the three flags keep theirs) and without variation selectors that carry
    bytes, how many characters went, and the runs that went (for the Codex rollout)."""
    gone: list[str] = []
    out = text
    if _VS_RE.search(out):
        # selectors first, against the text as it came: one after a tag run follows an invisible character
        kept, run = [], []
        for i, ch in enumerate(out):
            if _VS_RE.match(ch) and not _selector_kept(out, i):
                run.append(ch)
                continue
            if run:
                gone.append("".join(run))
                run = []
            kept.append(ch)
        if run:
            gone.append("".join(run))
        out = "".join(kept)

    def tag(m: "re.Match") -> str:
        run = m.group(0)
        if m.start() > 0 and m.string[m.start() - 1] == "\U0001F3F4" and run in _FLAG_TAGS:
            return run
        gone.append(run)
        return ""
    out = _TAGS_RE.sub(tag, out)
    return out, sum(len(r) for r in gone), gone


# The byte forms, raw UTF-8 and JSON escape in any case, of what a transcript must not keep: a tag character
# (U+E0000-U+E007F), an ideographic selector (U+E0100-U+E01EF) and VS1 to VS14 (U+FE00-U+FE0D). VS15 and VS16 stay:
# emoji need them, and one of them carries one bit.
_HIDDEN_BYTES_RE = _LazyRx(
    rb"\xf3\xa0(?:[\x80\x81\x84-\x86][\x80-\xbf]|\x87[\x80-\xaf])|\xef\xb8[\x80-\x8d]"
    rb"|\\u[dD][bB]40\\u[dD](?:[cC][0-7]|[dD][0-9a-eA-E])[0-9a-fA-F]|\\u[fF][eE]0[0-9a-dA-D]")


def _escaped_backslash(data: bytes, at: int) -> bool:
    """Whether the backslash at ``at`` is itself escaped: an odd number of backslashes stands right before it."""
    n = 0
    while at - n - 1 >= 0 and data[at - n - 1] == 0x5C:
        n += 1
    return n % 2 == 1


def _mask_hidden_in_transcript(path: str, start: int = 0) -> int:
    """Overwrite every byte form above in a JSONL transcript with spaces, in place: no record is parsed or written
    again, every record keeps its length, and a space inside a JSON string is still a string (Opus review,
    2026-10-06: rewriting whole records failed on deep nesting, number forms and alike keys). An escape whose
    backslash is itself escaped is text ("\\" then letters) and stays (codex review). The rule is blunter than
    strip_hidden(): a flag of England, Scotland or Wales and an ideographic variant lose their selectors in the
    transcript, not in what the model reads. With ``start``, reading begins at the line that holds that byte, so
    a grown file is read from where it grew. Returns the forms masked; never raises."""
    try:
        if not path or not os.path.exists(path):
            return 0
        fd = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
        try:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            except ImportError:
                pass
            size, pos, hits, chunk = os.fstat(fd).st_size, 0, 0, 8 * 1024 * 1024
            if 0 < start <= size:
                back = max(0, start - 65536)
                os.lseek(fd, back, os.SEEK_SET)
                nl = os.read(fd, start - back).rfind(b"\n")
                # no newline in the 64 KB before it: the line may be longer, so the whole file is read
                pos = back + nl + 1 if nl >= 0 else 0
            while pos < size:
                os.lseek(fd, pos, os.SEEK_SET)
                data = os.read(fd, chunk + 16)
                if not data:
                    break
                if len(data) > chunk:
                    nl = data.rfind(b"\n", 0, chunk)
                    if nl > 0:
                        data = data[:nl + 1]    # a form never spans a newline
                    else:
                        # a line longer than the window: cut at an ASCII byte that is no backslash, so no form and
                        # no run of backslashes spans the edge (Opus review, 2026-10-06)
                        cut = chunk
                        while cut > chunk - 64 and (data[cut - 1] >= 0x80 or data[cut - 1] == 0x5C):
                            cut -= 1
                        data = data[:cut]
                found = [0]

                def one(m: "re.Match") -> bytes:
                    if m.group(0)[:1] == b"\\" and _escaped_backslash(data, m.start()):
                        return m.group(0)
                    found[0] += 1
                    return b" " * len(m.group(0))
                new = _HIDDEN_BYTES_RE.sub(one, data)
                if found[0]:
                    hits += found[0]
                    os.lseek(fd, pos, os.SEEK_SET)
                    os.write(fd, new)
                pos += len(data)
            if hits:
                os.fsync(fd)
        finally:
            os.close(fd)
        _debug(f"mask-hidden: {os.path.basename(path)} {hits} forms")
        return hits
    except Exception:  # noqa: BLE001 - a best-effort scrub must not withhold the tool output
        return 0


# A Read of an image or a PDF returns the file as base64: tool_response type "image" or "pdf" (file.base64) or
# "parts" (pages[].base64), and the client gives it to the model as an image or a document block, never as text
# (tests/client_payloads/claude-read-*-post.json, recorded from Claude Code 2.1.296). A scan of it as text cost
# 10.9 s for 1 MB and found only chance shapes, and a placeholder inside it would break the image.
_BINARY_READ_TYPES = ("image", "pdf", "parts")
_DATA_URI_RE = _LazyRx(r"data:image/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/=\s]*)")
_IMAGE_MAGIC = {"png": (b"\x89PNG\r\n\x1a\n",), "jpeg": (b"\xff\xd8\xff",), "gif": (b"GIF87a", b"GIF89a"),
                "webp": (b"RIFF",)}


_IMAGE_TRAILER = {"png": b"IEND\xaeB`\x82", "jpeg": b"\xff\xd9", "gif": b";"}


def _is_image_data_uri(s: Any) -> bool:
    """The whole text is a data URI whose whole body decodes as base64 to a file of its image type: the magic number
    at the start and the end of the format at the end (the IEND chunk of a PNG, the EOI marker of a JPEG, the trailer
    of a GIF, the RIFF length of a WebP). Claude Code sets `isImage` on a Bash output that starts with `data:image/`
    (recorded: `printf 'data:image/png;base64,'; base64 < tiny.png`), so the flag alone is a text the agent can print,
    and a prefix check let an agent switch off the redaction of a whole output (review of the 0.6.15 fixes). A check
    of the first bytes only let a key glued after the image (`…==AKIA…`, or on the next line) through (Gate A)."""
    if not isinstance(s, str):
        return False
    m = _DATA_URI_RE.fullmatch(s)
    if not m:
        return False
    import base64
    import binascii
    try:
        raw = base64.b64decode("".join(m.group(2).split()), validate=True)
    except (ValueError, binascii.Error):
        return False
    kind = m.group(1)
    if not raw.startswith(_IMAGE_MAGIC[kind]):
        return False
    if kind == "webp":
        return raw[8:12] == b"WEBP" and int.from_bytes(raw[4:8], "little") + 8 == len(raw)
    return raw.endswith(_IMAGE_TRAILER[kind])


def _binary_paths(payload: dict) -> set:
    """The places in tool_response that hold a file as base64 and are not scanned as text: the base64 of a Read of an
    image or a PDF, and the stdout of a Bash output that the client sends as an image (`isImage` true and the
    whole stdout an image data URI). Every other field is scanned as before; stderr always."""
    resp = payload.get("tool_response")
    if not isinstance(resp, dict):
        return set()
    tool = payload.get("tool_name")
    if tool == "Read" and resp.get("type") in _BINARY_READ_TYPES:
        out = set()
        if isinstance(resp.get("file"), dict) and isinstance(resp["file"].get("base64"), str):
            out.add(("file", "base64"))
        pages = resp.get("pages")
        for i, page in enumerate(pages if isinstance(pages, list) else []):
            if isinstance(page, dict) and isinstance(page.get("base64"), str):
                out.add(("pages", i, "base64"))
        return out
    if tool == "Bash" and resp.get("isImage") is True and _is_image_data_uri(resp.get("stdout")):
        return {("stdout",)}
    return set()
