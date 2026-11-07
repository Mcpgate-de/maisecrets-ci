"""Byte-level helpers for the JSON lines of a transcript (moved out of hooks.py, which is near its size limit)."""
from __future__ import annotations


def _json_string_spans(line: bytes) -> list[tuple[int, int]]:
    """The byte spans of the string contents in one JSON line, escapes skipped."""
    spans, i, n = [], 0, len(line)
    while i < n:
        if line[i] == 0x22:                       # a quote opens a string
            j = i + 1
            while j < n and line[j] != 0x22:
                j += 2 if line[j] == 0x5C else 1  # a backslash escapes the next byte
            spans.append((i + 1, min(j, n)))
            i = j + 1
        else:
            i += 1
    return spans


def _mask_digits_in_strings(data: bytes, digits: list[bytes]) -> tuple[bytes, int]:
    """Mask a value that is only digits where it sits inside a JSON string and no other digit stands next
    to it. A JSON number, a longer digit run and the four hex digits of a \\u escape stay untouched.
    Plain replacement skipped every all-digit value, so a detected tax ID stayed in the transcript
    (external review, 2026-09-28)."""
    buf, hits = bytearray(data), 0
    start = 0
    while start < len(buf):
        end = buf.find(b"\n", start)
        end = len(buf) if end < 0 else end
        line = bytes(buf[start:end])
        if any(d in line for d in digits):
            for a, b in _json_string_spans(line):
                for d in digits:
                    k = line.find(d, a, b)
                    while k >= 0:
                        before = line[k - 1:k]
                        after = line[k + len(d):k + len(d) + 1]
                        esc = line.rfind(b"\\u", max(a, k - 5), k)
                        if not before.isdigit() and not after.isdigit() and not (esc >= 0 and k - esc <= 5):
                            buf[start + k:start + k + len(d)] = b"*" * len(d)
                            hits += 1
                        k = line.find(d, k + len(d), b)
        start = end + 1
    return bytes(buf), hits
