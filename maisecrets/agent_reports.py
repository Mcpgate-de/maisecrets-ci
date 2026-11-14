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
# session's subagents folder, and a result equal to that subagent's last answer. A report with no tool use id
# proves itself by its task id: the file subagents/agent-<task id>.jsonl of this session, and a result equal to
# its last answer (Claude Code 2.1.322, 2026-11-14). A background command reports
# the same way, and its summary is the command (or its description) as the model wrote it: a block lost the
# notice, and the session waited for a command that had ended (2026-10-26). It passes when the summary equals
# that Bash call of this transcript and the output file is in this session's tasks folder. A typed or pasted
# text and a monitor event do not pass, and no value outside the model's text passes (docs/THREAT-MODEL.md C19).
_NOTIFICATION_RE = _LazyRx(r"<task-notification>\n(?P<body>.*?)\n</task-notification>", re.S)
_AGENT_TOOLS = ("Agent", "Task", "SendMessage")
_COMMAND_TOOLS = ("Bash",)
# the summary of a background command (Claude Code transcripts, 2026-10): `Background command "<description or
# command>" completed (exit code 0)`, also with `: No matches found` after the code, or `failed with exit code 1`
_COMMAND_END_RE = _LazyRx(r'" (?:(?P<completed>completed) \(exit code \d{1,3}(?:: [^()<"]{0,80})?\)'
                         r'|(?P<failed>failed) with exit code \d{1,3})\Z')
_COMMAND_START = 'Background command "'


def _notification_tag(body: str, name: str) -> str | None:
    """A short field (id, path, status) of the notice, read outside the result only and present once: a result that
    quotes `<tool-use-id>` changed how the report was read (codex review, 2026-11-14)."""
    span = _result_span(body)
    envelope = body[: span[0] - len("<result>")] + body[span[1]:] if span else body
    found = re.findall(rf"<{name}>([^<]*)</{name}>", envelope)
    return found[0] if len(found) == 1 else None


def _result_span(body: str) -> tuple[int, int] | None:
    """The span of the result text in a notification body: from the first <result> to the last </result>. The
    result is the subagent's own text, and a `<` in it (`Option<String>`, `a < b`) ended a match on `[^<]*` early,
    so a real report was blocked (review, 2026-09-29)."""
    a = body.find("<result>")
    b = body.rfind("</result>")
    return (a + len("<result>"), b) if 0 <= a and a + len("<result>") <= b else None


def _plain(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def _same_text(raw: str, said: str) -> bool:
    """Whether a notice carries `said` as the client writes it: the text itself or its escaped form. Decoding the
    notice would take any entity (`&CounterClockwiseContourIntegral;` is one sign), and a stored value written as
    an entity name left the check with the span (codex review, 2026-10-26)."""
    said = _plain(said)
    return bool(said) and _plain(raw) in (said, html.escape(said, quote=False), html.escape(said))


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
    return _tool_input(transcript, tool_use_id, _AGENT_TOOLS) is not None


def _tool_input(transcript: str, tool_use_id: str, names: tuple) -> dict | None:
    """The input of the call with this id in the transcript, when the call is one of `names`."""
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
                            and b.get("name") in names):
                        return b.get("input") if isinstance(b.get("input"), dict) else {}
    except OSError:
        return None
    return None


def _launched_task(transcript: str, task_id: str) -> bool:
    """Whether this transcript started or resumed the agent of this task id: the result of an Agent, Task or
    SendMessage call that names it (`agentId`, `resumedAgentId`). A file in the subagents folder alone is no proof:
    the session can write one (codex review, 2026-11-14)."""
    # one pass: the ids of the agent calls and the ids the results with this task id answer (codex review: a scan per
    # result read the transcript again for each one)
    calls, answered = set(), set()
    try:
        with open(transcript, encoding="utf-8") as f:
            for line in f:
                is_call = '"tool_use"' in line and any(f'"{n}"' in line for n in _AGENT_TOOLS)
                is_result = task_id in line and '"tool_result"' in line
                if not (is_call or is_result):
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                blocks = [b for b in (rec.get("message") or {}).get("content") or [] if isinstance(b, dict)]
                if rec.get("type") == "assistant":
                    calls.update(str(b.get("id")) for b in blocks
                                 if b.get("type") == "tool_use" and b.get("name") in _AGENT_TOOLS)
                res = rec.get("toolUseResult")
                if rec.get("type") == "user" and isinstance(res, dict) and \
                        task_id in (res.get("agentId"), res.get("resumedAgentId")):
                    answered.update(str(b.get("tool_use_id")) for b in blocks if b.get("type") == "tool_result")
    except OSError:
        return False
    return bool(calls & answered)


def _subagent_by_task_id(body: str, subagents: str) -> str | None:
    """The subagent's own transcript that the task id names, in this session's subagents folder only."""
    task_id = _notification_tag(body, "task-id") or ""
    if not re.fullmatch(r"[A-Za-z0-9]{6,64}", task_id):
        return None
    path = subagents + f"agent-{task_id}.jsonl"
    # a link that points out of the folder is no proof
    if not os.path.isfile(path) or not os.path.realpath(path).startswith(subagents):
        return None
    return path


def _one_report_proves_itself(body: str, transcript: str) -> bool:
    span = _result_span(body)
    tool_use_id = _notification_tag(body, "tool-use-id")
    if span is None or _notification_tag(body, "status") != "completed":
        return False
    subagents = os.path.realpath(transcript[: -len(".jsonl")]) + os.sep + "subagents" + os.sep
    if not tool_use_id:
        # Claude Code 2.1.322 sends a report with no tool use id each time a resumable agent stops (108 of 316
        # reports in one session, 2026-11-14), and its output file is in the tasks folder. The report proves
        # itself by its task id: the subagent's own transcript in this session's folder, and its last answer
        real = _subagent_by_task_id(body, subagents)
        if real is None or not _launched_task(transcript, _notification_tag(body, "task-id") or ""):
            return False
        answer = _last_answer(real)
        return answer is not None and _same_text(body[span[0]:span[1]], answer)
    out = _notification_tag(body, "output-file")
    if not out:
        return False
    real = os.path.realpath(out)
    if not real.startswith(subagents) or not real.endswith(".jsonl"):
        # on Windows the output file under the temp folder is no link into the session (a link needs a right
        # there), so the report named a file outside it and was blocked (Windows e2e, 2026-09-30). The subagent's
        # own transcript is found by its task id, in this session's folder only
        real = _subagent_by_task_id(body, subagents)
        if real is None:
            return False
    answer = _last_answer(real)
    if answer is None or not _same_text(body[span[0]:span[1]], answer):
        return False
    return _called_an_agent(transcript, tool_use_id)


def _command_span(body: str, transcript: str) -> tuple[int, int] | None:
    """The span of the model's text in the summary of a background command's notice, when the notice proves itself:
    the tool use id is a Bash call of this transcript, the summary holds its command or its description, and the
    output file is in this session's tasks folder. None otherwise."""
    tool_use_id = _notification_tag(body, "tool-use-id")
    out = _notification_tag(body, "output-file")
    if not tool_use_id or not out or _notification_tag(body, "status") not in ("completed", "failed"):
        return None
    session = os.path.basename(transcript[: -len(".jsonl")])
    parts = os.path.normpath(out).replace("\\", "/").split("/")
    if len(parts) < 3 or parts[-3] != session or parts[-2] != "tasks" or not parts[-1].endswith(".output"):
        return None
    a = body.find("<summary>")
    b = body.rfind("</summary>")
    if a < 0 or b < a:
        return None
    a += len("<summary>")
    end = _COMMAND_END_RE.search(body, a, b)
    # the status and the summary name the same outcome
    if not body.startswith(_COMMAND_START, a) or end is None or not end.group(_notification_tag(body, "status")):
        return None
    span = (a + len(_COMMAND_START), end.start())
    call = _tool_input(transcript, tool_use_id, _COMMAND_TOOLS)
    if call is None:
        return None
    said = (str(call.get(k) or "") for k in ("description", "command"))
    return span if any(_same_text(body[span[0]:span[1]], t) for t in said) else None


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
    # only a result is the subagent's text, and only the command in the summary is the model's: a value in another
    # field (a real report pasted again, with a value added to its summary) was typed by a person and must be
    # blocked (review, 2026-09-29)
    rest, pos = [], 0
    for m in blocks:
        body = m.group("body")
        if _one_report_proves_itself(body, transcript):
            a, b = _result_span(body)
        else:
            span = _command_span(body, transcript)
            if span is None:
                return None
            a, b = span
        rest.append(prompt[pos:m.start("body") + a])
        pos = m.start("body") + b
    rest.append(prompt[pos:])
    text = "".join(rest)
    return None if detect.scan(text) else text
