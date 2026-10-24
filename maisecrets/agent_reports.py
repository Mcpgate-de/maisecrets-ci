"""How a subagent's report proves itself, so the prompt hook lets it pass (hooks.agent_report decides). hooks.py imports
every name again, so hooks.<name> is the same object."""
from __future__ import annotations

import html
import json
import os
import re

from . import detect
from .lazy_regex import LazyRx as _LazyRx

# A subagent's report reaches the session as a prompt (<task-notification>), and a prompt hook can only
# block or pass it: a report that quoted a value of the right shape stopped the session until the person
# pasted it again (2026-09-29, twice in one review). The text was written by a model of this session, so
# every value in it was in a model's context already, and blocking it protects nothing. The hook payload
# has no origin field (Claude Code 2.1.284), so the report proves itself: one notification block, a tool
# use id that this session's transcript gives to an Agent or SendMessage call, an output file in this
# session's subagents folder, and a result equal to that subagent's last answer. A typed or pasted text,
# a background command, a monitor event: none of them passes, and no value outside the result passes
# (docs/THREAT-MODEL.md C19).
_NOTIFICATION_RE = _LazyRx(r"<task-notification>\n(?P<body>.*?)\n</task-notification>", re.S)
_AGENT_TOOLS = ("Agent", "Task", "SendMessage")


def _notification_tag(body: str, name: str) -> str | None:
    # the short fields (id, path, status) never hold a tag of their own
    m = re.search(rf"<{name}>([^<]*)</{name}>", body)
    return m.group(1) if m else None


def _result_span(body: str) -> tuple[int, int] | None:
    """The span of the result text in a notification body: from the first <result> to the last </result>. The
    result is the subagent's own text, and a `<` in it (`Option<String>`, `a < b`) ended a match on `[^<]*` early,
    so a real report was blocked (review, 2026-09-29)."""
    a = body.find("<result>")
    b = body.rfind("</result>")
    return (a + len("<result>"), b) if 0 <= a and a + len("<result>") <= b else None


def _plain(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def _last_answer(path: str) -> str | None:
    """The text of the subagent's last message. Claude Code writes one record per content block of a message, all
    with the same message id: a final answer of two text blocks (text, thinking, text) is two records, and taking
    the last one alone blocked the report (review, 2026-09-29)."""
    text_id, parts = None, []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if '"assistant"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("type") != "assistant":
                    continue
                msg = rec.get("message") or {}
                texts = [b.get("text", "") for b in msg.get("content") or []
                         if isinstance(b, dict) and b.get("type") == "text"]
                if not texts:
                    continue
                mid = msg.get("id")
                if mid is None or mid != text_id:
                    text_id, parts = mid, []
                parts.extend(texts)
    except OSError:
        return None
    return "\n".join(parts) if parts else None


def _called_an_agent(transcript: str, tool_use_id: str) -> bool:
    try:
        with open(transcript, encoding="utf-8") as f:
            for line in f:
                if tool_use_id not in line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("type") != "assistant":
                    continue
                for b in (rec.get("message") or {}).get("content") or []:
                    if (isinstance(b, dict) and b.get("type") == "tool_use" and b.get("id") == tool_use_id
                            and b.get("name") in _AGENT_TOOLS):
                        return True
    except OSError:
        return False
    return False


def _one_report_proves_itself(body: str, transcript: str) -> bool:
    span = _result_span(body)
    tool_use_id = _notification_tag(body, "tool-use-id")
    out = _notification_tag(body, "output-file")
    if span is None or not tool_use_id or not out or _notification_tag(body, "status") != "completed":
        return False
    subagents = os.path.realpath(transcript[: -len(".jsonl")]) + os.sep + "subagents" + os.sep
    real = os.path.realpath(out)
    if not real.startswith(subagents) or not real.endswith(".jsonl"):
        # on Windows the output file under the temp folder is no link into the session (a link needs a right
        # there), so the report named a file outside it and was blocked (Windows e2e, 2026-09-30). The subagent's
        # own transcript is found by its task id, in this session's folder only
        task_id = _notification_tag(body, "task-id") or ""
        if not re.fullmatch(r"[A-Za-z0-9]{6,64}", task_id):
            return False
        real = subagents + f"agent-{task_id}.jsonl"
        if not os.path.isfile(real):
            return False
    answer = _last_answer(real)
    if answer is None or _plain(answer) != _plain(html.unescape(body[span[0]:span[1]])):
        return False
    return _called_an_agent(transcript, tool_use_id)


def _report_rest(payload: dict, prompt: str) -> str | None:
    """The text outside the results when the prompt is nothing but reports of subagents of this session, each
    proven as described above; None otherwise. Two agents that finish in the same turn may arrive in one prompt;
    each block proves itself."""
    transcript = str(payload.get("transcript_path") or "")
    if not transcript.endswith(".jsonl"):
        return None
    # one opening tag per closing tag, counted before any regex: a megabyte of opening tags kept the lazy match
    # scanning past the watchdog (Codex review, 2026-09-29)
    opened = prompt.count("<task-notification>")
    if not opened or opened != prompt.count("</task-notification>") or opened > 16:
        return None
    blocks = list(_NOTIFICATION_RE.finditer(prompt))
    if not blocks:
        return None
    # nothing but the blocks: a text typed before, between or after them is a person's
    pos = 0
    for m in blocks:
        if prompt[pos:m.start()].strip():
            return None
        pos = m.end()
    if prompt[pos:].strip() or opened != len(blocks):
        return None
    if not all(_one_report_proves_itself(m.group("body"), transcript) for m in blocks):
        return None
    # only a result is the subagent's text: a value in another field (a real report pasted again, with a value
    # added to its summary) was typed by a person and must be blocked (review, 2026-09-29)
    rest, pos = [], 0
    for m in blocks:
        body = m.group("body")
        a, b = _result_span(body)
        rest.append(prompt[pos:m.start("body") + a])
        pos = m.start("body") + b
    rest.append(prompt[pos:])
    text = "".join(rest)
    return None if detect.scan(text) else text
