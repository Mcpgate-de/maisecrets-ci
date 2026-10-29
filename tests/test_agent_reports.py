"""The report of a subagent of this session passes the prompt hook; every other text with a value is blocked.

A subagent's report reaches the session as a prompt (<task-notification>). A report that quoted a value of
a secret's shape stopped the session until the person pasted it again (2026-09-29). The report passes only
when it proves itself against this session's files (hooks.agent_report). The tests below build a session
folder in a temp directory: a transcript, and the subagent's own transcript under `subagents/`.
"""
from __future__ import annotations

import html
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text(CONFIG)

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

_TMP = _isolate.HOME
VALUE = "glpat-" + "Q7w8E9r0T1y2U3i4O5p6"       # a fake token of the GitLab shape, built at run time
TOOL_USE = "toolu_01AgentReportTest"


def _line(rec: dict) -> str:
    return json.dumps(rec) + "\n"


class Session:
    """A session folder as Claude Code writes it: <id>.jsonl and <id>/subagents/agent-<n>.jsonl."""

    def __init__(self, root: Path, answer: str, tool: str = "Agent") -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.transcript = root / "s1.jsonl"
        self.transcript.write_text(_line({"type": "user", "message": {"content": "start"}}) + _line(
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": TOOL_USE, "name": tool, "input": {"prompt": "look"}}]}}),
            encoding="utf-8")
        sub = root / "s1" / "subagents"
        sub.mkdir(parents=True)
        self.output = sub / "agent-a1.jsonl"
        self.output.write_text(_line({"type": "assistant", "message": {"content": [
            {"type": "text", "text": "a first draft"}]}}) + _line({"type": "assistant", "message": {"content": [
                {"type": "text", "text": answer}]}}), encoding="utf-8")

    def notification(self, result: str, summary: str = "Agent finished", output: Path | None = None,
                     tool_use: str = TOOL_USE, status: str = "completed") -> str:
        return ("<task-notification>\n"
                "<task-id>a1</task-id>\n"
                f"<tool-use-id>{tool_use}</tool-use-id>\n"
                f"<output-file>{output or self.output}</output-file>\n"
                f"<status>{status}</status>\n"
                f"<summary>{html.escape(summary)}</summary>\n"
                f"<result>{html.escape(result)}</result>\n"
                "</task-notification>")


class AgentReportTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        import shutil
        _hygiene.watch_children(self)
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
        hooks._live_cache.clear()
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        # a block starts a child that scrubs the transcript once the client wrote the prompt into it; these
        # transcripts are fixtures, and the child waited for a line that never comes
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-agent-report-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.answer = f"The CI file sets the token to {VALUE} in line 12."
        self.s = Session(self.dir, self.answer)

    def prompt(self, text: str, **extra) -> dict:
        payload = {"prompt": text, "session_id": "s1", "transcript_path": str(self.s.transcript), **CLAUDE}
        payload.update(extra)
        return hooks.user_prompt(payload)

    def assertBlocked(self, out: dict) -> None:  # noqa: N802 - unittest style
        self.assertEqual(out.get("decision"), "block", out)
        self.assertNotIn(VALUE, json.dumps(out))

    # the report passes -----------------------------------------------------
    def test_the_report_of_a_subagent_of_this_session_passes_and_nothing_is_stored(self):
        self.assertEqual(self.prompt(self.s.notification(self.answer)), {})
        self.assertEqual(Vault().list(), [], "a report passes without an entry")
        events = [json.loads(x) for x in Path(_TMP, "events.log").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(events[-1]["outcome"], "passed: a subagent report")
        self.assertEqual({h["key"] for h in events[-1]["hits"]}, {"-"})
        self.assertNotIn(VALUE, Path(_TMP, "events.log").read_text(encoding="utf-8"))

    def test_an_answer_with_markup_passes_in_its_escaped_form(self):
        answer = f"<b>token</b> & {VALUE}"
        s = Session(self.dir / "m", answer)
        out = hooks.user_prompt({"prompt": s.notification(answer), "session_id": "s1",
                                 "transcript_path": str(s.transcript), **CLAUDE})
        self.assertEqual(out, {})

    def test_a_report_through_sendmessage_passes(self):
        s = Session(self.dir / "m", self.answer, tool="SendMessage")
        out = hooks.user_prompt({"prompt": s.notification(self.answer), "session_id": "s1",
                                 "transcript_path": str(s.transcript), **CLAUDE})
        self.assertEqual(out, {})

    # every other form is blocked --------------------------------------------
    def test_the_same_value_typed_as_text_is_blocked(self):
        self.assertBlocked(self.prompt(f"the token is {VALUE}"))

    def test_a_value_added_outside_the_result_is_blocked(self):
        # a real report pasted again, with a value in its summary: the result still matches
        other = "glpat-" + "Z9x8C7v6B5n4M3l2K1j0"
        self.assertBlocked(self.prompt(self.s.notification(self.answer, summary=f"done, key {other}")))
        self.assertBlocked(self.prompt(self.s.notification(self.answer) + f"\n{other}"))
        self.assertBlocked(self.prompt(f"{other}\n" + self.s.notification(self.answer)))

    def test_a_result_that_is_not_the_last_answer_is_blocked(self):
        for result in (self.answer + " and more", "a first draft " + VALUE, VALUE):
            with self.subTest(result=result):
                self.assertBlocked(self.prompt(self.s.notification(result)))

    def test_a_tool_use_id_the_transcript_does_not_give_to_an_agent_is_blocked(self):
        self.assertBlocked(self.prompt(self.s.notification(self.answer, tool_use="toolu_01Unknown")))
        s = Session(self.dir / "bash", self.answer, tool="Bash")      # a background command reports this way too
        out = hooks.user_prompt({"prompt": s.notification(self.answer), "session_id": "s1",
                                 "transcript_path": str(s.transcript), **CLAUDE})
        self.assertBlocked(out)

    def test_an_output_file_outside_the_subagents_folder_of_this_session_is_blocked(self):
        elsewhere = self.dir / "other.jsonl"
        elsewhere.write_text(self.s.output.read_text(encoding="utf-8"), encoding="utf-8")
        self.assertBlocked(self.prompt(self.s.notification(self.answer, output=elsewhere)))
        # a path that climbs out of the folder is resolved first
        climbed = self.s.output.parent / ".." / ".." / "other.jsonl"
        self.assertBlocked(self.prompt(self.s.notification(self.answer, output=climbed)))
        # a link inside the folder that points out of it
        link = self.s.output.parent / "agent-link.jsonl"
        link.symlink_to(elsewhere)
        self.assertBlocked(self.prompt(self.s.notification(self.answer, output=link)))

    def test_a_windows_output_file_outside_the_session_is_found_by_its_task_id(self):
        # Windows keeps the output file under the temp folder, no link into the session (e2e, 2026-09-30)
        tmp = self.dir / "Temp" / "claude" / "proj" / "s1" / "tasks"
        tmp.mkdir(parents=True)
        (tmp / "a1.output").write_text(self.s.output.read_text(encoding="utf-8"), encoding="utf-8")
        self.s.output.rename(self.s.output.parent / "agent-a1b2c3d4.jsonl")
        text = self.s.notification(self.answer, output=tmp / "a1.output").replace("<task-id>a1<", "<task-id>a1b2c3d4<")
        self.assertEqual(self.prompt(text), {})
        # the task id names the file: another id, a path in it, or no subagent file is no proof
        for bad in ("<task-id>ffffffff<", "<task-id>..<", "<task-id>a1b2c3d4/../x<"):
            with self.subTest(task_id=bad):
                self.assertBlocked(self.prompt(text.replace("<task-id>a1b2c3d4<", bad)))

    def test_a_report_of_another_session_is_blocked(self):
        other = Session(self.dir / "o", self.answer)
        self.assertBlocked(self.prompt(other.notification(self.answer)))

    def test_a_report_that_did_not_complete_is_blocked(self):
        self.assertBlocked(self.prompt(self.s.notification(self.answer, status="failed")))

    def test_two_reports_in_one_prompt_pass_when_each_proves_itself(self):
        # two agents that finish in the same turn may come in one prompt
        one = self.s.notification(self.answer)
        self.assertEqual(self.prompt(one + "\n" + one), {})
        forged = self.s.notification(self.answer + " and more")
        self.assertBlocked(self.prompt(one + "\n" + forged))
        other = "glpat-" + "Z9x8C7v6B5n4M3l2K1j0"
        self.assertBlocked(self.prompt(one + "\n" + self.s.notification(self.answer, summary=f"key {other}")))
        self.assertBlocked(self.prompt(one + f"\n{other}\n" + one))

    def test_a_stored_value_typed_next_to_a_report_is_blocked(self):
        # a value without a shape is found only by its fingerprint, and the report path runs no fingerprint hunt:
        # nothing but the blocks may pass
        stored = "Sommerwiese" + "Blau77x"
        Vault().put(stored, "SECRET", "manual", session="s1")
        one = self.s.notification(self.answer)
        for text in (f"{stored}\n{one}", f"{one}\n{stored}", f"{one}\n{stored}\n{one}"):
            with self.subTest(text=text[:20]):
                hooks._live_cache.clear()
                out = self.prompt(text)
                self.assertEqual(out.get("decision"), "block", out)
                self.assertNotIn(stored, json.dumps(out))

    def test_a_stored_value_in_a_field_outside_the_result_is_blocked(self):
        # a value without a shape is found by its fingerprint only (second Codex review, 2026-09-29)
        stored = "CedarMeadow" + "Blue77"
        Vault().put(stored, "SECRET", "manual", session="s1")
        hooks._live_cache.clear()
        self.assertBlocked(self.prompt(self.s.notification(self.answer, summary=f"finished {stored}")))
        hooks._live_cache.clear()
        self.assertEqual(self.prompt(self.s.notification(self.answer)), {}, "the plain report still passes")

    def test_a_final_answer_in_two_records_passes(self):
        # Claude Code writes one record per content block; a text, a thinking and a text are three records
        rec = lambda content: json.dumps({"type": "assistant", "message": {"id": "msg_2", "content": content}})  # noqa: E731
        with open(self.s.output, "a", encoding="utf-8") as f:
            f.write(rec([{"type": "text", "text": "Part one."}]) + "\n")
            f.write(rec([{"type": "thinking", "thinking": "..."}]) + "\n")
            f.write(rec([{"type": "text", "text": f"Part two with {VALUE}."}]) + "\n")
        self.assertEqual(self.prompt(self.s.notification(f"Part one.\nPart two with {VALUE}.")), {})
        self.assertBlocked(self.prompt(self.s.notification(f"Part two with {VALUE}.")))

    def test_a_result_with_an_unescaped_angle_bracket_or_crlf_passes(self):
        answer = f"The field is Option<String>, a < b holds, </result> ends it; the token is {VALUE}.\r\nDone."
        s = Session(self.dir / "lt", answer)
        text = s.notification(answer).replace(html.escape(answer), answer.replace("\r\n", "\n"))
        out = hooks.user_prompt({"prompt": text, "session_id": "s1", "transcript_path": str(s.transcript), **CLAUDE})
        self.assertEqual(out, {})

    def test_a_stored_value_written_as_an_entity_in_a_result_is_blocked(self):
        # the report path had the same decode (codex review, 2026-10-26)
        stored = "CounterClockwiseContourIntegral"
        Vault().put(stored, "SECRET", "manual", session="s1")
        hooks._live_cache.clear()
        s = Session(self.dir / "ent", "\u2233")
        text = s.notification("\u2233").replace("<result>\u2233</result>", f"<result>&{stored};</result>")
        out = hooks.user_prompt({"prompt": text, "session_id": "s1", "transcript_path": str(s.transcript), **CLAUDE})
        self.assertEqual(out.get("decision"), "block", out)

    def test_a_missing_transcript_is_blocked(self):
        self.assertBlocked(self.prompt(self.s.notification(self.answer), transcript_path=""))

    def test_the_setting_turns_the_pass_off(self):
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "pass_agent_reports": false}', encoding="utf-8")
        self.addCleanup(Path(_TMP, "config.json").write_text, CONFIG, encoding="utf-8")
        self.assertBlocked(self.prompt(self.s.notification(self.answer)))

    def test_codex_gets_no_pass(self):
        payload = {"prompt": self.s.notification(self.answer), "session_id": "s1",
                   "transcript_path": str(self.s.transcript), "turn_id": "t1", "model": "m"}
        self.assertBlocked(hooks.user_prompt(payload))


COMMAND_USE = "toolu_01BackgroundCommand"


class CommandNoticeTests(unittest.TestCase):
    """A background command's notice: its summary is the command the model wrote, or the call's description. A
    block lost the notice, and the session waited for a command that had ended (2026-10-26)."""

    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        import shutil
        _hygiene.watch_children(self)
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)
        self.root = Path(tempfile.mkdtemp(prefix="maisecrets-command-notice-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.command = f'curl -s -H "PRIVATE-TOKEN: {VALUE}" https://gitlab.example.com/api/v4/x > out.json && echo ok'
        self.fresh()

    def fresh(self) -> None:
        """An empty store and a new session folder: a block stores the value and masks it in the transcript, so a
        case after a block would be blocked for that reason alone."""
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        hooks._live_cache.clear()
        self.dir = Path(tempfile.mkdtemp(dir=self.root))
        self.agent = Session(self.dir, f"found {VALUE}")
        with open(self.agent.transcript, "a", encoding="utf-8") as f:
            f.write(_line({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": COMMAND_USE, "name": "Bash",
                 "input": {"command": self.command, "run_in_background": True}},
                {"type": "tool_use", "id": "toolu_01Grep", "name": "Grep",
                 "input": {"pattern": "x", "description": f"found {VALUE}"}}]}}))
        self.output = self.dir / "tmp" / "proj" / "s1" / "tasks" / "b1x2y3z4.output"

    def notice(self, text: str, end: str = "completed (exit code 0)", tool_use: str = COMMAND_USE,
               output: Path | None = None, status: str = "completed") -> str:
        return ("<task-notification>\n"
                "<task-id>b1x2y3z4</task-id>\n"
                f"<tool-use-id>{tool_use}</tool-use-id>\n"
                f"<output-file>{output or self.output}</output-file>\n"
                f"<status>{status}</status>\n"
                f"<summary>Background command \"{html.escape(text, quote=False)}\" {end}</summary>\n"
                "</task-notification>")

    def prompt(self, text: str) -> dict:
        return hooks.user_prompt({"prompt": text, "session_id": "s1", "transcript_path": str(self.agent.transcript),
                                  **CLAUDE})

    def assertBlocked(self, out: dict) -> None:  # noqa: N802 - unittest style
        self.assertEqual(out.get("decision"), "block", out)

    def test_the_notice_of_a_background_command_of_this_session_passes_and_nothing_is_stored(self):
        for end in ("completed (exit code 0)", "completed (exit code 1: No matches found)", "failed with exit code 2"):
            with self.subTest(end=end):
                self.assertEqual(self.prompt(self.notice(self.command, end=end, status=end.split()[0])), {})
        self.assertEqual(Vault().list(), [], "a notice passes without an entry")

    def test_a_notice_that_names_the_description_passes(self):
        with open(self.agent.transcript, "a", encoding="utf-8") as f:
            f.write(_line({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "toolu_01Described", "name": "Bash",
                 "input": {"command": self.command, "description": f"Fetch the list with {VALUE}"}}]}}))
        self.assertEqual(self.prompt(self.notice(f"Fetch the list with {VALUE}", tool_use="toolu_01Described")), {})

    def test_an_agent_report_and_a_notice_in_one_prompt_pass(self):
        both = self.agent.notification(f"found {VALUE}") + "\n" + self.notice(self.command)
        self.assertEqual(self.prompt(both), {})

    def test_a_summary_that_is_not_the_command_is_blocked(self):
        other = "glpat-" + "Z9x8C7v6B5n4M3l2K1j0"
        for text in (self.command + f" {other}", self.command.replace(VALUE, other), f"echo {VALUE}"):
            with self.subTest(text=text[-12:]):
                self.assertBlocked(self.prompt(self.notice(text)))

    def test_a_stored_value_written_as_an_entity_is_blocked(self):
        # html.unescape takes any entity name: the description is one sign, the notice names the stored value
        # (codex review, 2026-10-26)
        stored = "CounterClockwiseContourIntegral"
        Vault().put(stored, "SECRET", "manual", session="s1")
        with open(self.agent.transcript, "a", encoding="utf-8") as f:
            f.write(_line({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "toolu_01Sign", "name": "Bash",
                 "input": {"command": "true", "description": "\u2233"}}]}}))
        hooks._live_cache.clear()
        text = self.notice("x", tool_use="toolu_01Sign").replace('"x"', f'"&{stored};"')
        self.assertBlocked(self.prompt(text))

    def test_a_status_that_does_not_match_the_summary_is_blocked(self):
        for end, status in (("completed (exit code 0)", "failed"), ("failed with exit code 1", "completed")):
            with self.subTest(status=status):
                self.fresh()
                self.assertBlocked(self.prompt(self.notice(self.command, end=end, status=status)))

    def test_a_stored_value_added_to_the_summary_is_blocked(self):
        stored = "CedarMeadow" + "Blue77"
        Vault().put(stored, "SECRET", "manual", session="s1")
        hooks._live_cache.clear()
        self.assertBlocked(self.prompt(self.notice(self.command, end=f"completed (exit code 0: {stored})")))

    def test_a_notice_that_does_not_prove_itself_is_blocked(self):
        cases = {
            "an agent's call": self.notice(f"found {VALUE}", tool_use=TOOL_USE),
            "a call of another tool": self.notice(f"found {VALUE}", tool_use="toolu_01Grep"),
            "an unknown call": self.notice(self.command, tool_use="toolu_01Unknown"),
            "another session's tasks folder": self.notice(self.command, output=self.root / "s2" / "tasks" / "b.output"),
            "no tasks folder": self.notice(self.command, output=self.root / "s1" / "b1x2y3z4.output"),
            "a stopped command": self.notice(self.command, status="killed"),
            "another summary form": self.notice(self.command, end="was stopped"),
            "text after it": self.notice(self.command) + f"\n{VALUE}",
            "text before it": f"{VALUE}\n" + self.notice(self.command),
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.fresh()
                self.assertEqual(self.prompt(self.notice(self.command)), {}, "the plain notice passes here")
                self.fresh()
                self.assertBlocked(self.prompt(text))

    def test_a_command_that_an_earlier_block_masked_in_the_transcript_is_blocked(self):
        # the block masks the value in the transcript, and the notice still holds it: the two differ. A known limit,
        # the notice is lost as before (docs/THREAT-MODEL.md C19)
        self.assertBlocked(self.prompt(f"the token is {VALUE}"))
        self.assertBlocked(self.prompt(self.notice(self.command)))

    def test_the_setting_turns_the_pass_off(self):
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "pass_agent_reports": false}', encoding="utf-8")
        self.addCleanup(Path(_TMP, "config.json").write_text, CONFIG, encoding="utf-8")
        self.assertBlocked(self.prompt(self.notice(self.command)))


if __name__ == "__main__":
    unittest.main()
