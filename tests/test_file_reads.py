"""PDFs and images the AI reads (maisecrets/file_reads.py, C28): the settings read_pdf and read_image, clean_dirs, and
the convert mode that sends a PDF as masked text.

The payloads are the goldens that harness/probe_file_reads.py recorded from Claude Code 2.1.296 (research commit
a5c533d). The measured rule that every test here leans on: only a text-shaped updatedToolOutput takes an image or a
PDF out of the request. A string, or a PDF-shaped object with an empty base64, fails open.
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import file_reads, hooks, settings  # noqa: E402
from maisecrets.vault import HOME, load_config  # noqa: E402
import _hygiene  # noqa: E402

GOLDEN = ROOT / "harness" / "golden"
TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")
HINTS = Path(HOME, "hints.json")
TOKEN = "glpat-" + "Rk4tW9xQ2mZ7vB3nL8pY"          # a token shape, built at run time (scan_tree)
REAL_PDFTOTEXT = file_reads.pdftotext()       # the one maisecrets would run: fixed folders, no other writer


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({**TEST_CONFIG, **user}))
    # the values a converted PDF stored, too: a later module must not find a live store (test_hooks_paths does this)
    for f in (HINTS, Path(HOME, "index.json"), Path(HOME, "vault.json"), Path(HOME, "audit.log"),
              Path(HOME, "hooks.log")):
        try:
            os.unlink(f)
        except FileNotFoundError:
            pass
    shutil.rmtree(Path(HOME, "sessions-seen"), ignore_errors=True)    # the session S1 starts anew
    hooks._live_cache.clear()


def pdf_bytes(*lines: str) -> bytes:
    """A one-page PDF with these lines in Helvetica, standard library only (the builder of harness/probe_file_reads.py,
    with more than one line)."""
    ops = b" ".join(b"BT /F1 12 Tf 72 %d Td (%s) Tj ET" % (720 - 20 * i, ln.encode("latin-1"))
                    for i, ln in enumerate(lines))
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(ops) + ops + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out = b"%PDF-1.4\n"
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


def golden(name: str, cwd: str, **swap) -> dict:
    """A recorded payload with its placeholders filled in; `file_path` moves the read to another file."""
    text = (GOLDEN / f"{name}.json").read_text()
    # JSON-escaped: a Windows path has backslashes
    text = text.replace("{cwd}", json.dumps(cwd)[1:-1]).replace("{session_id}", "S1").replace("{prompt_id}", "p1")
    p = json.loads(text)
    fp = swap.pop("file_path", None)
    if fp:
        p["tool_input"]["file_path"] = fp
        if isinstance(p.get("tool_response"), dict) and isinstance(p["tool_response"].get("file"), dict) \
                and "filePath" in p["tool_response"]["file"]:
            p["tool_response"]["file"]["filePath"] = fp
    p.update(swap)
    # the client sends the file itself as base64 (measured: a PDF and a small image byte for byte); the goldens keep
    # a shortened copy, so a read of a file that exists gets its real bytes
    resp = p.get("tool_response")
    fpath = (p.get("tool_input") or {}).get("file_path")
    if isinstance(resp, dict) and isinstance(resp.get("file"), dict) and "base64" in resp["file"] \
            and isinstance(fpath, str) and os.path.isfile(fpath):
        resp["file"]["base64"] = base64.b64encode(Path(fpath).read_bytes()).decode()
    return p


def run_hook(event: str, payload: dict) -> dict:
    """The real entry point of the hooks, as dispatch.py calls it, with the JSON on stdin."""
    hooks._live_cache.clear()
    buf = io.StringIO()
    with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), redirect_stdout(buf):
        rc = hooks.main(["hook", event])
    assert rc == 0, rc
    return json.loads(buf.getvalue()) if buf.getvalue() else {}


def output(answer: dict):
    return (answer.get("hookSpecificOutput") or {}).get("updatedToolOutput")


def said(answer: dict) -> str:
    """What the person reads after a typed setting: a block reason (Codex form) or the context of a slash command,
    which runs on and shows the card."""
    return answer.get("reason") or (answer.get("hookSpecificOutput") or {}).get("additionalContext") or ""


def decision(answer: dict) -> str | None:
    return (answer.get("hookSpecificOutput") or {}).get("permissionDecision")


class _Work(unittest.TestCase):
    """A work folder with a PDF and a PNG, and a bin folder for a stub pdftotext."""

    def setUp(self):
        _reset()
        self.dir = Path(tempfile.mkdtemp(prefix="file-reads-", dir=_isolate.TMP)).resolve()
        self.cwd = str(self.dir / "work")
        os.makedirs(self.cwd)
        self.pdf = os.path.join(self.cwd, "hello.pdf")
        Path(self.pdf).write_bytes(pdf_bytes("Invoice 2026", f"deploy token {TOKEN}"))
        self.png = os.path.join(self.cwd, "tiny.png")
        Path(self.png).write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.calls = self.dir / "calls.txt"
        # no pdftotext of this machine, unless a test puts the stub or the real one there
        p = mock.patch.dict(os.environ, {"PATH": str(self.bin)})
        p.start()
        self.addCleanup(p.stop)
        p2 = mock.patch.object(file_reads, "_EXTRA_DIRS", (str(self.bin),))      # the fixed folder of the tests
        p2.start()
        self.addCleanup(p2.stop)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def stub(self, body: str = None) -> None:
        """A pdftotext that notes its arguments and prints a text with a token in it."""
        if os.name == "nt":
            self.skipTest("the stub pdftotext is a shell script; the same code runs on macOS and Linux")
        body = body if body is not None else f"printf 'Invoice 2026\\ndeploy token {TOKEN}\\n\\f'"
        tool = self.bin / "pdftotext"
        tool.write_text(f"#!/bin/sh\necho \"$@\" >> '{self.calls}'\n{body}\n")
        tool.chmod(0o755)

    def post(self, name: str = "PostToolUse_Read_pdf", **swap) -> dict:
        return run_hook("post-tool", golden(name, self.cwd, **swap))

    def pre(self, name: str = "PreToolUse_Read_pdf_pages", **swap) -> dict:
        return run_hook("pre-tool", golden(name, self.cwd, **swap))


# ------------------------------------------------------------ the shape --
class TheMeasuredShape(unittest.TestCase):
    def test_the_text_result_is_the_shape_the_probe_measured(self):
        # the replace_text branch of the probe is the shape that removed the PDF and the image (model view golden)
        probe = (ROOT / "harness" / "probe_file_reads.py").read_text()
        branch = probe[probe.index('mode == "replace_text"'):probe.index('mode == "replace_pdf_obj"')]
        measured = re.findall(r'"(\w+)":', branch[branch.index('"file": {') + 9:])
        self.assertEqual(tuple(measured), file_reads.TEXT_KEYS)
        r = file_reads.text_result("/x/a.pdf", "one\ntwo")
        self.assertEqual(r["type"], "text")
        self.assertEqual(set(r), {"type", "file"})
        self.assertEqual(tuple(r["file"]), file_reads.TEXT_KEYS)
        self.assertEqual((r["file"]["numLines"], r["file"]["startLine"], r["file"]["totalLines"]), (2, 1, 2))
        view = json.loads((GOLDEN / "file_reads_model_view.json").read_text())
        self.assertEqual(view["pdf_replace_text"][0]["content"], "1\tPROBE-REPLACED-TEXT: withheld",
                         "the text shape reaches the model as text, without the document")
        self.assertEqual(view["pdf_replace_obj"][0]["content"][1]["type"], "document",
                         "a PDF-shaped answer with an empty base64 still sends the PDF: never answer with it")
        self.assertEqual(view["png_replace"][0]["content"][0]["type"], "image",
                         "a string answer fails open: never answer with it")


class OnlyTheTextShapeLeaves(_Work):
    """Every answer that stands in for a PDF or an image, in every mode, with or without pdftotext, is the text
    shape (Read) or a text Bash result. A string or a PDF shape would fail open."""

    def test_every_mode_and_every_payload(self):
        cases = (("PostToolUse_Read_pdf", {}), ("PostToolUse_Read_pdf_pages", {}),
                 ("PostToolUse_Read_png", {"file_path": self.png}),
                 ("PostToolUse_Read_pdf", {"file_path": os.path.join(self.cwd, "noext")}))
        seen = 0
        for tool_present in (True, False):
            if tool_present:
                self.stub()
            else:
                (self.bin / "pdftotext").unlink()
            for pdf_mode in file_reads.MODES["read_pdf"]:
                for img_mode in file_reads.MODES["read_image"]:
                    for name, swap in cases:
                        with self.subTest(tool=tool_present, pdf=pdf_mode, img=img_mode, payload=name, **swap):
                            _reset(read_pdf=pdf_mode, read_image=img_mode, tips=False)
                            out = output(self.post(name, **dict(swap)))
                            if out is None:
                                continue
                            seen += 1
                            self.assertIsInstance(out, dict, "a string fails open")
                            self.assertEqual(out["type"], "text")
                            self.assertEqual(tuple(out["file"]), file_reads.TEXT_KEYS)
                            self.assertNotIn("base64", json.dumps(out))
                            self.assertNotIn(TOKEN, json.dumps(out))
        self.assertGreater(seen, 20)

    def test_a_failure_in_the_redaction_withholds_with_the_text_shape(self):
        _reset(read_pdf="convert")
        self.stub()
        with mock.patch.object(hooks, "post_tool", side_effect=RuntimeError("boom")):
            out = output(self.post())
        self.assertEqual(out["type"], "text", "the fail-closed answer of a Read must not be a string")
        self.assertIn("withheld", out["file"]["content"])

    def test_the_watchdog_answer_of_a_read_is_the_text_shape(self):
        p = golden("PostToolUse_Read_pdf", self.cwd)
        out = output(hooks._fail_closed("post-tool", p, "took longer than 16s."))
        self.assertEqual(out["type"], "text")
        # the golden joins the cwd and the name with "/", also on Windows (GitHub windows-latest)
        self.assertEqual(os.path.normpath(out["file"]["filePath"]), os.path.normpath(self.pdf))
        self.assertIsInstance(output(hooks._fail_closed("post-tool", {"tool_name": "Bash"}, "x")), str,
                              "other tools keep their answer")


# ------------------------------------------------------------ the modes --
class Allow(_Work):
    def test_allow_passes_unscanned_and_gives_the_hint_once(self):
        b64 = golden("PostToolUse_Read_pdf", self.cwd)["tool_response"]["file"]["base64"]
        real_scan = hooks.detect.scan

        def scan(text, *a, **kw):
            # the base64 gets the exact match of stored values only (_binary_paths of 0.6.17); the other fields of
            # the result are scanned as always
            self.assertNotEqual(text, b64, "base64 is no text to scan")
            return real_scan(text, *a, **kw)
        with mock.patch.object(hooks.detect, "scan", scan):
            first = self.post()
            second = self.post()
        self.assertIsNone(output(first), "the PDF passes as it is")
        ctx = first["hookSpecificOutput"]["additionalContext"]
        self.assertIn("/maisecrets:settings read_pdf MODE", ctx)
        self.assertIn("convert", ctx)
        self.assertNotIn("hello.pdf", ctx, "nothing of the file is in the hint")
        self.assertEqual(second, {}, "once")
        img = self.post("PostToolUse_Read_png", file_path=self.png)
        self.assertIn("read_image", img["hookSpecificOutput"]["additionalContext"], "the image has its own hint")

    def test_no_hint_when_decided_silenced_or_in_a_subagent(self):
        for user, extra in (({"read_pdf": "allow"}, {}), ({"tips": False}, {}), ({}, {"agent_id": "a1"})):
            with self.subTest(user=user, extra=extra):
                _reset(**user)
                self.assertEqual(self.post(**extra), {})

    def test_codex_hint_names_the_codex_form(self):
        p = golden("PostToolUse_Read_pdf", self.cwd)
        p.pop("prompt_id")
        p["turn_id"] = "t1"
        ctx = run_hook("post-tool", p)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("maisecrets: set read_pdf MODE", ctx)

    def test_pre_tool_lets_it_run(self):
        self.assertEqual(self.pre(), {})


class AskAndBlock(_Work):
    def test_block_denies_before_the_read(self):
        _reset(read_pdf="block", read_image="block")
        for name, swap, key in (("PreToolUse_Read_pdf_pages", {}, "read_pdf"),
                                ("PreToolUse_Read_png", {"file_path": self.png}, "read_image")):
            with self.subTest(name):
                out = self.pre(name, **swap)
                self.assertEqual(decision(out), "deny")
                self.assertIn(f"{key} is block", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_block_withholds_what_the_pre_tool_did_not_see(self):
        _reset(read_pdf="block")
        out = output(self.post(file_path=os.path.join(self.cwd, "report")))
        self.assertIn("read_pdf is block", out["file"]["content"])

    def test_ask_asks_in_claude_code_and_refuses_in_codex(self):
        _reset(read_pdf="ask")
        out = self.pre()
        self.assertEqual(decision(out), "ask")
        self.assertIn("cannot look inside it", out["hookSpecificOutput"]["permissionDecisionReason"])
        p = golden("PreToolUse_Read_pdf_pages", self.cwd)
        p.pop("prompt_id")
        p["turn_id"] = "t1"
        out = run_hook("pre-tool", p)
        self.assertEqual(decision(out), "deny")
        self.assertIn("maisecrets: set read_pdf allow", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_after_a_yes_the_file_passes_and_without_an_ask_it_is_withheld(self):
        _reset(read_pdf="ask")
        pre = golden("PreToolUse_Read_pdf_pages", self.cwd, file_path=self.pdf)
        self.assertEqual(decision(run_hook("pre-tool", pre)), "ask")
        self.assertEqual(self.post(), {}, "the person said yes to the ask of this call")
        self.assertEqual(output(self.post())["type"], "text", "the note of the ask is used once")
        out = output(self.post(file_path=os.path.join(self.cwd, "report")))
        self.assertEqual(out["type"], "text", "no ask came for a name without .pdf")

    def test_without_the_ask_of_this_call_a_pdf_is_withheld(self):
        # codex review of block 4: the extension alone passed; a file clean at the PreToolUse and not clean at the
        # PostToolUse (or another call's ask) went to the model without a dialog
        _reset(read_pdf="ask")
        self.assertEqual(output(self.post())["type"], "text", "no PreToolUse asked")
        pre = golden("PreToolUse_Read_pdf_pages", self.cwd, file_path=self.pdf)
        run_hook("pre-tool", pre)
        other = golden("PostToolUse_Read_pdf", self.cwd)
        other["tool_use_id"] = "another-call"
        self.assertEqual(output(run_hook("post-tool", other))["type"], "text", "the ask of another call")

    def _asked(self, name="PreToolUse_Read_pdf_pages", path=None):
        pre = golden(name, self.cwd, file_path=path or self.pdf)
        self.assertEqual(decision(run_hook("pre-tool", pre)), "ask")

    def test_bytes_swapped_in_and_back_during_the_read_are_withheld(self):
        # codex verification of block 4: a file swapped in for the read and restored before the PostToolUse passed;
        # the client's own copy of the bytes must be the file that was asked about
        _reset(read_pdf="ask")
        self._asked()
        post = golden("PostToolUse_Read_pdf", self.cwd)
        post["tool_response"]["file"]["base64"] = base64.b64encode(pdf_bytes("another file")).decode()
        self.assertEqual(output(run_hook("post-tool", post))["type"], "text")

    def test_the_note_is_keyed_by_the_file_whose_bytes_it_holds(self):
        # codex verification of block 4: the key came from a stat and the checksum from a second open; a stat that
        # saw the asked file A and an open that read B stored B's checksum under A's name, so B passed
        _reset(read_pdf="ask")
        asked = Path(self.cwd, "asked.pdf")
        asked.write_bytes(pdf_bytes("the file the person allowed"))
        Path(self.pdf).write_bytes(pdf_bytes("another file"))            # B sits under the name during the read
        real_stat = os.stat

        def stat_sees_a(path, *a, **k):
            return real_stat(asked if os.fspath(path) == self.pdf else path, *a, **k)
        pre = golden("PreToolUse_Read_pdf_pages", self.cwd, file_path=self.pdf)
        with mock.patch.object(os, "stat", stat_sees_a):
            self.assertEqual(decision(run_hook("pre-tool", pre)), "ask")
        b_bytes = Path(self.pdf).read_bytes()
        os.replace(asked, self.pdf)                                         # A is back before the PostToolUse
        post = golden("PostToolUse_Read_pdf", self.cwd)
        post["tool_response"]["file"]["base64"] = base64.b64encode(b_bytes).decode()
        self.assertEqual(output(run_hook("post-tool", post))["type"], "text")

    def test_a_file_that_changes_while_it_is_hashed_gets_no_note(self):
        _reset(read_pdf="ask")
        real_fstat = os.fstat
        calls = []

        def changed(fd):
            st = real_fstat(fd)
            calls.append(fd)
            if len(calls) % 2 == 0:                                         # the second look at the same file
                return os.stat_result(st[:8] + (st.st_mtime + 1, st.st_ctime))
            return st
        with mock.patch.object(os, "fstat", changed):
            self.assertIsNone(file_reads.file_digest(self.pdf))
        self.assertIsNotNone(file_reads.file_digest(self.pdf), "an unchanged file gets one")

    def test_a_reencoded_image_is_bound_by_its_size_and_the_file(self):
        _reset(read_image="ask")
        size = os.path.getsize(self.png)

        def post(**file):
            p = golden("PostToolUse_Read_png", self.cwd, file_path=self.png)
            p["tool_response"]["file"].update(base64=base64.b64encode(b"re-encoded by the client").decode(), **file)
            return run_hook("post-tool", p)
        self._asked("PreToolUse_Read_png", self.png)
        self.assertEqual(post(originalSize=size), {}, "a smaller copy of the asked file")
        self._asked("PreToolUse_Read_png", self.png)
        self.assertEqual(output(post(originalSize=size + 1))["type"], "text", "another size")
        self._asked("PreToolUse_Read_png", self.png)
        Path(self.png).write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x01" * 16)          # same size, other bytes
        self.assertEqual(output(post(originalSize=size))["type"], "text", "the file changed")

    def test_a_page_read_is_bound_by_the_file(self):
        _reset(read_pdf="ask")
        self._asked()
        post = golden("PostToolUse_Read_pdf_pages", self.cwd)
        post["tool_response"]["file"]["originalSize"] = os.path.getsize(self.pdf)
        self.assertEqual(run_hook("post-tool", post), {})
        self._asked()
        data = Path(self.pdf).read_bytes()
        Path(self.pdf).write_bytes(data.replace(b"Invoice 2026", b"Invoice 2027"))     # same size, other bytes
        self.assertEqual(output(run_hook("post-tool", post))["type"], "text")

    def test_a_file_above_the_cap_is_not_asked_about(self):
        _reset(read_pdf="ask")
        with mock.patch.object(file_reads, "BIND_MAX_BYTES", 10):
            out = self.pre()
        self.assertEqual(decision(out), "deny")
        self.assertIn("larger than", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_a_file_swapped_in_under_the_same_name_after_the_ask_is_withheld(self):
        # verification of block 4: the ask note named the path only; another file under the same name passed
        _reset(read_pdf="ask")
        pre = golden("PreToolUse_Read_pdf_pages", self.cwd, file_path=self.pdf)
        self.assertEqual(decision(run_hook("pre-tool", pre)), "ask")
        other = Path(self.cwd, "other.pdf")
        other.write_bytes(pdf_bytes("another file"))
        os.replace(other, self.pdf)                                   # a new inode under the asked name
        self.assertEqual(output(self.post())["type"], "text")

    @unittest.skipIf(os.name == "nt", "clean_dirs is for macOS and Linux")
    def test_clean_at_the_pre_tool_and_not_clean_at_the_post_tool_is_withheld(self):
        _reset(read_pdf="ask", clean_dirs=[self.cwd])
        time.sleep(0.02)
        with mock.patch.object(file_reads, "nested_client", return_value=False):
            file_reads.note_session_start({"session_id": "S1", "source": "startup"})
        pre = golden("PreToolUse_Read_pdf_pages", self.cwd, file_path=self.pdf)
        self.assertEqual(run_hook("pre-tool", pre), {}, "clean: no ask")
        shutil.rmtree(Path(HOME, "sessions-seen"))                   # no longer clean
        self.assertEqual(output(self.post())["type"], "text")

    def test_an_unknown_mode_blocks(self):
        _reset(read_pdf="convrt")
        self.assertEqual(decision(self.pre()), "deny")


class Convert(_Work):
    def test_the_pdf_goes_as_masked_text(self):
        _reset(read_pdf="convert")
        self.stub()
        self.assertEqual(self.pre(), {})
        answer = self.post()
        out = output(answer)
        self.assertEqual(out["type"], "text")
        self.assertEqual(tuple(out["file"]), file_reads.TEXT_KEYS)
        self.assertEqual(os.path.normpath(out["file"]["filePath"]), os.path.normpath(self.pdf))
        self.assertIn("Invoice 2026", out["file"]["content"])
        self.assertNotIn(TOKEN, json.dumps(answer), "the redaction ran on the text")
        self.assertRegex(out["file"]["content"], r"⟦SECRET_c\d+⟧")
        self.assertIn("as text only", answer["systemMessage"])

    def test_a_text_without_a_hit_still_replaces_the_pdf(self):
        _reset(read_pdf="convert")
        self.stub("printf 'just words, and some more words on the page\\n'")
        out = output(self.post())
        self.assertEqual(out["file"]["content"], "just words, and some more words on the page\n")

    def test_pages_go_to_pdftotext(self):
        _reset(read_pdf="convert")
        self.stub()
        p = golden("PostToolUse_Read_pdf_pages", self.cwd)
        p["tool_input"]["pages"] = "2-3"
        out = output(run_hook("post-tool", p))
        self.assertEqual(out["type"], "text")
        self.assertIn("-f 2 -l 3", self.calls.read_text())
        self.assertNotIn("base64", json.dumps(out))

    def test_a_page_range_that_is_no_range_is_refused(self):
        _reset(read_pdf="convert")
        self.stub()
        p = golden("PreToolUse_Read_pdf_pages", self.cwd)
        p["tool_input"]["pages"] = "1;rm"
        self.assertEqual(decision(run_hook("pre-tool", p)), "deny")
        p = golden("PostToolUse_Read_pdf_pages", self.cwd)
        p["tool_input"]["pages"] = "3-1"
        self.assertIn("not one page", output(run_hook("post-tool", p))["file"]["content"])

    def test_without_pdftotext_the_read_is_refused_and_the_message_says_how_to_install(self):
        _reset(read_pdf="convert")
        out = self.pre()
        self.assertEqual(decision(out), "deny")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("pdftotext", reason)
        self.assertIn("brew install poppler", reason)
        self.assertIn("poppler-utils", reason)
        self.assertIn("pdftotext", output(self.post())["file"]["content"], "the post-tool refuses it too")

    def test_a_short_path_of_a_desktop_client_still_finds_pdftotext(self):
        self.stub()
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            self.assertEqual(file_reads.pdftotext(), os.path.realpath(self.bin / "pdftotext"))

    def test_a_writable_folder_above_the_program_is_refused(self):
        # codex verification of block 4: only the program and its own folder were checked; a writer of a folder
        # above could rename the checked folder away and put another in its place
        self.stub()
        os.chmod(self.dir, 0o777)
        try:
            self.assertIsNone(file_reads.pdftotext(), "others can write a folder above the program")
        finally:
            os.chmod(self.dir, 0o700)
        os.chmod(self.dir, 0o770)
        try:
            with mock.patch.object(file_reads, "_group_has_other_writer", return_value=True):
                self.assertIsNone(file_reads.pdftotext(), "a group with another member can write it")
            with mock.patch.object(file_reads, "_group_has_other_writer", return_value=False):
                self.assertIsNotNone(file_reads.pdftotext(), "a group of root and this user only")
        finally:
            os.chmod(self.dir, 0o700)
        os.chmod(self.dir, 0o1777)
        try:
            self.assertIsNotNone(file_reads.pdftotext(), "a sticky folder like /tmp: entries keep their owner")
        finally:
            os.chmod(self.dir, 0o700)

    def test_an_untrusted_pdftotext_is_named_not_called_missing(self):
        _reset(read_pdf="convert")
        self.stub()
        with mock.patch.object(file_reads, "_group_has_other_writer", return_value=True):
            os.chmod(self.bin, 0o775)
            try:
                content = output(self.post())["file"]["content"]
            finally:
                os.chmod(self.bin, 0o755)
        self.assertIn("another account on this computer can change it", content)
        self.assertNotIn("not installed", content)

    def test_a_program_changed_after_the_lookup_is_not_started(self):
        _reset(read_pdf="convert")
        self.stub()
        real = file_reads._no_other_writer
        calls = []

        tool = str(self.bin / "pdftotext")

        def second_check_fails(path):
            calls.append(path)
            # the lookup checks link and target (one file here); the start checks the program again
            return real(path) and calls.count(tool) < 3
        with mock.patch.object(file_reads, "_no_other_writer", second_check_fails):
            out = output(self.post())
        self.assertIn("changed after it was checked", out["file"]["content"])
        self.assertFalse(self.calls.exists(), "the stub did not run")

    def test_a_pdftotext_on_the_path_only_is_never_run(self):
        # codex review of block 4: with no fixed copy, a PATH folder that the agent can write to won
        _reset(read_pdf="convert")
        work_bin = Path(self.cwd, "bin")
        work_bin.mkdir()
        tool = work_bin / "pdftotext"
        ran = Path(self.dir, "ran")
        tool.write_text(f"#!/bin/sh\ntouch '{ran}'\necho text\n")
        tool.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": str(work_bin)}):
            self.assertIsNone(file_reads.pdftotext())
            self.assertEqual(decision(self.pre()), "deny")
            self.assertIn("pdftotext", output(self.post())["file"]["content"])
        self.assertFalse(ran.exists(), "the program on the PATH did not run")

    def test_an_unsafe_place_or_the_working_folder_is_refused(self):
        self.stub()
        self.assertEqual(file_reads.pdftotext(self.cwd), os.path.realpath(self.bin / "pdftotext"))
        os.chmod(self.bin, 0o777)
        try:
            self.assertIsNone(file_reads.pdftotext(), "a folder that others can write to")
        finally:
            os.chmod(self.bin, 0o755)
        (self.bin / "pdftotext").chmod(0o757)
        self.assertIsNone(file_reads.pdftotext(), "a program that others can write to")
        (self.bin / "pdftotext").chmod(0o755)
        self.assertIsNone(file_reads.pdftotext(str(self.dir)), "a program in the working folder")

    def test_a_failing_or_slow_pdftotext_withholds(self):
        _reset(read_pdf="convert")
        for body, why in (("exit 3", "exit 3"), ("/bin/sleep 5", "longer than")):
            with self.subTest(body):
                self.stub(body)
                with mock.patch.object(file_reads, "EXTRACT_SECONDS", 0.5):
                    started = time.monotonic()
                    out = output(self.post())
                self.assertLess(time.monotonic() - started, 4)
                self.assertEqual(out["type"], "text")
                self.assertIn(why, out["file"]["content"])

    def test_an_exception_during_the_extraction_kills_the_child_and_fails_closed(self):
        # any exception in the main thread while pdftotext runs. This tree's watchdog is a thread and cannot raise
        # here; the finally block must still end the child for a watchdog that could
        _reset(read_pdf="convert")
        self.stub("/bin/sleep 30")
        children = []
        real_stop = file_reads._stop

        def stop(child):
            children.append(child)
            real_stop(child)

        def interrupted(thread, seconds):
            raise RuntimeError("an exception in the main thread")
        with mock.patch.object(file_reads, "_wait", interrupted), mock.patch.object(file_reads, "_stop", stop):
            out = output(self.post())
        self.assertEqual(out["type"], "text")
        self.assertIn("withheld", out["file"]["content"])
        self.assertIsNotNone(children[0].poll(), "the child ended with the hook")

    def test_a_long_text_is_cut(self):
        _reset(read_pdf="convert")
        self.stub("/usr/bin/yes 'some words in a line' | /usr/bin/head -c 400000")
        content = output(self.post())["file"]["content"]
        self.assertLess(len(content), file_reads.MAX_TEXT_CHARS + 300)
        self.assertIn("the text stops here", content)

    def test_the_worst_text_at_the_cap_is_redacted_inside_the_budget(self):
        # review of block 4: 256K of AWS key shapes held the hook 97 s, past the client's 20 s, and it failed open.
        # The cap is the bound; the budget here leaves room for the extraction (6 s) under the 16 s watchdog
        import random
        rnd = random.Random(7)
        abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        text = " ".join("AKIA" + "".join(rnd.choice(abc) for _ in range(16))
                        for _ in range(file_reads.MAX_TEXT_CHARS // 21 + 1))[:file_reads.MAX_TEXT_CHARS]
        from maisecrets import detect
        t0 = time.monotonic()
        detect.scan(text)
        self.assertLess(time.monotonic() - t0, 8.0)

    def test_a_pdf_larger_than_the_cap_is_refused_before_pdftotext(self):
        _reset(read_pdf="convert")
        self.stub()
        with mock.patch.object(file_reads, "MAX_PDF_BYTES", 10):
            out = output(self.post())
        self.assertIn("larger than", out["file"]["content"])
        self.assertFalse(self.calls.exists(), "pdftotext did not run")

    def test_an_endless_output_is_read_up_to_the_cap_and_the_child_ends(self):
        _reset(read_pdf="convert")
        self.stub("/usr/bin/yes 'some words in a line'")
        t0 = time.monotonic()
        content = output(self.post())["file"]["content"]
        self.assertLess(time.monotonic() - t0, file_reads.EXTRACT_SECONDS, "it stops at the cap, not at the timeout")
        self.assertIn("the text stops here", content)

    def test_the_module_loads_without_subprocess(self):
        # it loads on every PostToolUse: subprocess and shutil cost about 30 ms and load only for a conversion
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import maisecrets.file_reads; "
                "print(sorted(m for m in ('subprocess', 'shutil') if m in sys.modules))")
        r = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT)], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "[]", r.stderr)

    def test_a_pdf_without_text_says_so(self):
        _reset(read_pdf="convert")
        self.stub("printf '\\f'")
        self.assertIn("cannot read text in images", output(self.post())["file"]["content"])

    def test_read_image_has_no_convert(self):
        _reset(read_image="convert")      # a hand-edited file: no mode, so it blocks
        self.assertEqual(decision(self.pre("PreToolUse_Read_png", file_path=self.png)), "deny")


@unittest.skipIf(os.name == "nt", "clean_dirs is for macOS and Linux: st_ctime is the creation time on Windows")
class CleanDirs(_Work):
    def begin(self) -> None:
        """The session S1 starts now: every file that exists already is older than it."""
        time.sleep(0.02)
        with mock.patch.object(file_reads, "nested_client", return_value=False):
            file_reads.note_session_start({"session_id": "S1", "source": "startup"})
        time.sleep(0.02)

    @unittest.skipIf(os.name == "nt", "a symbolic link needs a privilege on Windows")
    def test_a_read_inside_passes_and_a_way_out_does_not(self):
        clean = self.dir / "clean"
        clean.mkdir()
        inside = clean / "a.pdf"
        inside.write_bytes(b"%PDF-1.4\n")
        os.symlink(self.pdf, clean / "link.pdf")                 # a link in the clean folder to a file outside
        os.symlink(clean, self.dir / "clean-link")               # the clean folder through a link
        (self.dir / "clean2").mkdir()
        (self.dir / "clean2" / "a.pdf").write_bytes(b"%PDF-1.4\n")   # older than the session, beside the folder
        _reset(read_pdf="block", clean_dirs=[str(clean)])
        self.begin()
        cases = ((str(inside), "pass"), (str(self.dir / "clean-link" / "a.pdf"), "pass"),
                 (str(clean / "link.pdf"), "deny"), (str(clean / ".." / "work" / "hello.pdf"), "deny"),
                 (str(self.dir / "clean2" / "a.pdf"), "deny"))
        for path, want in cases:
            with self.subTest(path):
                pre = self.pre(file_path=path)
                post = self.post(file_path=path)
                if want == "pass":
                    self.assertEqual((pre, post), ({}, {}))
                else:
                    self.assertEqual(decision(pre), "deny")
                    self.assertEqual(output(post)["type"], "text")

    def test_a_clean_file_must_be_the_bytes_the_client_read(self):
        _reset(read_pdf="block", clean_dirs=[self.cwd])
        self.begin()
        self.assertEqual(self.pre(file_path=self.pdf), {})
        post = golden("PostToolUse_Read_pdf", self.cwd)
        post["tool_response"]["file"]["base64"] = base64.b64encode(pdf_bytes("from another folder")).decode()
        self.assertEqual(output(run_hook("post-tool", post))["type"], "text", "a root swapped in and back")
        self.assertEqual(self.pre(file_path=self.pdf), {})
        self.assertEqual(self.post(), {}, "the same bytes pass")
        self.assertEqual(output(self.post())["type"], "text", "the note of the clean read is used once")
        with mock.patch.object(file_reads, "BIND_MAX_BYTES", 10):
            self.assertEqual(decision(self.pre(file_path=self.pdf)), "deny", "above the cap a file is never clean")

    def test_a_relative_path_resolves_from_the_cwd(self):
        _reset(read_pdf="block", clean_dirs=[self.cwd])
        self.begin()
        self.assertEqual(self.pre(file_path="hello.pdf"), {})

    def test_a_file_the_agent_puts_there_in_the_session_is_not_clean(self):
        # review of block 4: cp, mv or ln of a file from outside into the clean folder undid the block
        clean = self.dir / "clean"
        clean.mkdir()
        old = clean / "old.pdf"
        old.write_bytes(b"%PDF-1.4\n")
        moved = self.dir / "moved.pdf"
        moved.write_bytes(b"%PDF-1.4\n")                         # older than the session, outside the folder
        _reset(read_pdf="block", clean_dirs=[str(clean)])
        self.begin()
        shutil.copy2(self.pdf, clean / "copied.pdf")              # cp -p keeps the mtime, not the change time
        os.rename(moved, clean / "moved.pdf")
        os.link(self.pdf, clean / "hard.pdf")
        self.assertEqual(self.pre(file_path=str(old)), {}, "a file that was there before the session passes")
        for name in ("copied.pdf", "moved.pdf", "hard.pdf"):
            with self.subTest(name):
                self.assertEqual(decision(self.pre(file_path=str(clean / name))), "deny")
                self.assertEqual(output(self.post(file_path=str(clean / name)))["type"], "text")

    def test_a_link_to_a_file_that_also_has_a_name_outside_is_not_clean(self):
        clean = self.dir / "clean"
        clean.mkdir()
        os.link(self.pdf, clean / "hard.pdf")                     # made before the session: still two names
        _reset(read_pdf="block", clean_dirs=[str(clean)])
        self.begin()
        self.assertEqual(decision(self.pre(file_path=str(clean / "hard.pdf"))), "deny")

    def test_without_a_note_of_the_session_nothing_is_clean(self):
        _reset(read_pdf="block", clean_dirs=[self.cwd])
        self.assertEqual(decision(self.pre(file_path=self.pdf)), "deny")

    def _note(self) -> str:
        return os.path.join(str(HOME), "sessions-seen", "S1")

    def test_only_the_session_start_writes_the_note(self):
        # review round 2: a note deleted by the agent was made again by the next prompt, with a later time
        p = golden("UserPromptSubmit_pasted_image", self.cwd, prompt="hello")
        run_hook("user-prompt", p)
        self.assertIsNone(file_reads.session_start("S1"), "a prompt writes no note")
        file_reads.note_session_start({"session_id": "S1", "source": "compact"})
        self.assertIsNone(file_reads.session_start("S1"), "a compaction writes no note")
        self.begin()
        first = file_reads.session_start("S1")
        self.assertIsNotNone(first)
        time.sleep(0.02)
        self.begin()
        self.assertEqual(file_reads.session_start("S1"), first, "a second start keeps the first time")
        self.assertIsNone(file_reads.session_start("../x"), "a session id is no path")

    def test_a_later_time_on_the_note_does_not_move_the_start(self):
        self.begin()
        first = file_reads.session_start("S1")
        os.utime(self._note(), (time.time() + 10 ** 6, time.time() + 10 ** 6))
        # Linux stamps the note with a coarse clock that can lag time.time() by a few ms: the first start can be that
        # stamp, the later one the time in the note (CI, python:3.12-slim). The point is the 10**6 s, not the ms
        self.assertLess(file_reads.session_start("S1"), first + 0.05)

    def test_a_linked_note_or_folder_is_not_followed(self):
        other = self.dir / "agent"
        other.mkdir()
        (other / "S1").write_text(json.dumps({"t": time.time() - 10 ** 6, "roots": {}}))   # a valid note, elsewhere
        os.makedirs(os.path.dirname(self._note()), exist_ok=True)
        os.symlink(other / "S1", self._note())
        self.assertIsNone(file_reads.session_start("S1"), "a linked note")
        os.unlink(self._note())
        os.unlink(other / "S1")
        os.rmdir(os.path.dirname(self._note()))
        os.symlink(other, os.path.dirname(self._note()))
        try:
            self.begin()
            self.assertIsNone(file_reads.session_start("S1"), "a linked folder")
            self.assertEqual(os.listdir(other), [], "nothing written through the link")
        finally:
            os.unlink(os.path.dirname(self._note()))

    def test_a_nested_client_trusts_no_clean_folder(self):
        _reset(read_pdf="block", clean_dirs=[self.cwd])
        time.sleep(0.02)
        with mock.patch.object(file_reads, "nested_client", return_value=True):
            file_reads.note_session_start({"session_id": "S1", "source": "startup"})
        self.assertIsNone(file_reads.session_start("S1"))
        self.assertEqual(decision(self.pre(file_path=self.pdf)), "deny")

    def test_a_nested_client_is_seen_in_the_process_chain(self):
        me, parent = os.getpid(), os.getppid()

        def ps(chain):
            lines = [f"{pid} {ppid} {name}" for pid, ppid, name in chain]
            return mock.Mock(stdout="\n".join(lines) + "\n")
        top = [(me, parent, "python3"), (parent, 50, "bash"), (50, 40, "claude"), (40, 1, "-zsh")]
        nested = [(me, parent, "python3"), (parent, 50, "bash"), (50, 45, "/usr/local/bin/claude"), (45, 40, "bash"),
                  (40, 30, "claude"), (30, 1, "login")]
        with mock.patch.object(subprocess, "run", return_value=ps(top)):
            self.assertFalse(file_reads.nested_client())
        with mock.patch.object(subprocess, "run", return_value=ps(nested)):
            self.assertTrue(file_reads.nested_client())
        with mock.patch.object(subprocess, "run", side_effect=OSError("no ps")):
            self.assertTrue(file_reads.nested_client(), "a process list that cannot be read counts as nested")

    def _old_tree(self, name: str) -> Path:
        tree = self.dir / name
        (tree / "sub").mkdir(parents=True)
        (tree / "old.pdf").write_bytes(b"%PDF-1.4\n")
        (tree / "sub" / "old.pdf").write_bytes(b"%PDF-1.4\n")
        return tree

    def test_a_folder_swapped_in_under_the_name_of_the_root_is_not_clean(self):
        # codex review of block 4: the root was resolved again at each read; an old tree moved under its name passed
        clean = self._old_tree("clean")
        other = self._old_tree("other")                           # older than the session, never approved
        _reset(read_pdf="block", clean_dirs=[str(clean)])
        self.begin()
        self.assertEqual(self.pre(file_path=str(clean / "old.pdf")), {}, "the approved root")
        os.rename(clean, self.dir / "clean.away")
        os.rename(other, clean)
        self.assertEqual(decision(self.pre(file_path=str(clean / "old.pdf"))), "deny")

    @unittest.skipIf(os.name == "nt", "a symbolic link needs a privilege on Windows")
    def test_a_root_that_is_a_link_is_never_clean_and_cannot_be_added(self):
        real = self._old_tree("real")
        os.symlink(real, self.dir / "link")
        _reset(read_pdf="block", clean_dirs=[str(self.dir / "link")])    # a hand-edited file
        self.begin()
        self.assertEqual(decision(self.pre(file_path=str(self.dir / "link" / "old.pdf"))), "deny")
        p = golden("UserPromptSubmit_pasted_image", self.cwd,
                   prompt=f"/maisecrets:settings clean_dirs add {self.dir / 'link'}")
        self.assertIn("is a link", said(run_hook("user-prompt", p)))

    def test_an_old_folder_moved_into_the_root_is_not_clean(self):
        clean = self._old_tree("clean")
        moved = self._old_tree("moved")
        _reset(read_pdf="block", clean_dirs=[str(clean)])
        self.begin()
        self.assertEqual(self.pre(file_path=str(clean / "sub" / "old.pdf")), {}, "a subfolder that was there")
        os.rename(moved, clean / "moved")
        self.assertEqual(decision(self.pre(file_path=str(clean / "moved" / "old.pdf"))), "deny")

    def test_a_root_the_person_adds_in_the_session_counts_at_once(self):
        clean = self._old_tree("scans")
        _reset(read_pdf="block")
        self.begin()
        p = golden("UserPromptSubmit_pasted_image", self.cwd, prompt=f"/maisecrets:settings clean_dirs add {clean}")
        run_hook("user-prompt", p)
        self.assertEqual(load_config()["clean_dirs"], [str(clean)])
        self.assertEqual(self.pre(file_path=str(clean / "old.pdf")), {})

    @unittest.skipIf(os.name == "nt", "a symbolic link needs a privilege on Windows")
    def test_the_session_start_names_a_clean_folder_that_is_a_link(self):
        real = self._old_tree("real")
        os.symlink(real, self.dir / "link")
        self.assertEqual(file_reads.link_roots({"clean_dirs": [str(self.dir / "link"), str(real)]}),
                         [str(self.dir / "link")])
        home = self.dir / "home"
        (home / "store").mkdir(parents=True)
        (home / "store" / "config.json").write_text(json.dumps({**TEST_CONFIG, "clean_dirs": [str(self.dir / "link")]}))
        path = f"{os.path.dirname(sys.executable)}{os.pathsep}/usr/bin{os.pathsep}/bin"
        out = _launcher("session-start", {"session_id": "S2", "source": "startup", "cwd": self.cwd,
                                          "hook_event_name": "SessionStart"}, home, path)
        self.assertIn("1 clean folder(s) are a link or lie under one", out.get("systemMessage", ""))
        self.assertNotIn(str(self.dir), out["systemMessage"], "no local path in the text the model can read")
        with mock.patch.object(settings, "load_config", return_value={**load_config(),
                                                                       "clean_dirs": [str(self.dir / "link")]}):
            card = settings.render(only="clean_dirs")
        self.assertIn(f"add the real folder: {real}", card, "the person's own settings view names it")

    def test_a_folder_that_holds_the_work_is_refused(self):
        def add(folder):
            p = golden("UserPromptSubmit_pasted_image", self.cwd,
                       prompt=f"/maisecrets:settings clean_dirs add {folder}")
            return said(run_hook("user-prompt", p))
        for folder, why in (("/", "home folder"), ("~", "home folder"), (str(self.dir), "works in"),
                            (self.cwd, "works in")):
            with self.subTest(folder):
                self.assertIn(why, add(folder))
                self.assertEqual(load_config()["clean_dirs"], [])
        add(str(self.dir / "scans"))
        self.assertEqual(load_config()["clean_dirs"], [str(self.dir / "scans")], "a folder beside the work")


class BashDataUri(_Work):
    def test_a_data_uri_image_counts_as_an_image_read(self):
        _reset(read_image="block")
        out = output(self.post("PostToolUse_Bash_datauri"))
        self.assertIs(out["isImage"], False)
        self.assertIn("read_image is block", out["stdout"])
        self.assertNotIn("base64,", out["stdout"])
        _reset(read_image="ask")
        self.assertIn("read_image is ask", output(self.post("PostToolUse_Bash_datauri"))["stdout"],
                      "no ask came before a Bash call")

    def test_allow_passes_it_and_gives_the_image_hint(self):
        out = self.post("PostToolUse_Bash_datauri")
        self.assertIsNone(output(out))
        self.assertIn("read_image", out["hookSpecificOutput"]["additionalContext"])

    def test_plain_base64_text_is_no_image(self):
        p = golden("PostToolUse_Bash_base64", self.cwd)
        self.assertIsNone(file_reads.post_read(p, {**load_config(), "read_image": "block"}, False))
        p["tool_response"]["stdout"] = "  data:image/png;base64,iVBOR"
        self.assertIsNone(file_reads.kind_of_response("Bash", p["tool_response"]),
                          "only the client's isImage makes an image, never the text")

    def test_a_data_uri_prefix_without_is_image_is_scanned(self):
        # review of block 4: a stdout that starts like a data URI let the whole Bash result pass unscanned
        p = golden("PostToolUse_Bash_datauri", self.cwd)
        p["tool_response"].update(isImage=False, stdout=f"data:image/png;base64,x\nDB_TOKEN={TOKEN}\n")
        answer = run_hook("post-tool", p)
        self.assertNotIn(TOKEN, json.dumps(answer))
        self.assertRegex(output(answer)["stdout"], r"DB_TOKEN=⟦SECRET_c\d+⟧")

    def test_an_image_passes_but_its_stderr_is_scanned(self):
        p = golden("PostToolUse_Bash_datauri", self.cwd)
        image = p["tool_response"]["stdout"]
        p["tool_response"]["stderr"] = f"curl: Authorization: Bearer {TOKEN}\n"
        answer = run_hook("post-tool", p)
        out = output(answer)
        self.assertNotIn(TOKEN, json.dumps(answer))
        self.assertRegex(out["stderr"], r"Bearer ⟦SECRET_c\d+⟧")
        self.assertEqual((out["stdout"], out["isImage"]), (image, True), "the image itself goes on unchanged")

    def test_the_fail_closed_answer_of_a_bash_image_is_its_text_shape(self):
        p = golden("PostToolUse_Bash_datauri", self.cwd)
        out = output(hooks._fail_closed("post-tool", p, "took longer than 16s."))
        self.assertIsInstance(out, dict, "a string fails open: the image is sent")
        self.assertIs(out["isImage"], False)
        self.assertEqual(out["stderr"], "")
        self.assertIn("withheld", out["stdout"])
        self.assertNotIn("base64,", json.dumps(out))


class Notebook(_Work):
    """A notebook Read with an image output (harness/golden/PostToolUse_Read_notebook.json): its text is scanned as
    always; ask and block send it as text, without the image."""

    def _post(self, **cell_text):
        p = golden("PostToolUse_Read_notebook", self.cwd)
        p["tool_response"]["file"]["cells"][0]["source"] = f"key = '{TOKEN}'"
        return run_hook("post-tool", p)

    def test_block_sends_the_text_without_the_image(self):
        _reset(read_image="block")
        answer = self._post()
        out = output(answer)
        self.assertEqual(out["type"], "text")
        self.assertEqual(tuple(out["file"]), file_reads.TEXT_KEYS)
        content = out["file"]["content"]
        self.assertIn("<Figure>", content)
        self.assertIn("image output was withheld (setting read_image block)", content)
        self.assertNotIn("iVBOR", json.dumps(answer))
        self.assertNotIn(TOKEN, json.dumps(answer), "the cells are scanned too")

    def test_ask_asks_before_a_notebook_with_an_image_and_codex_withholds(self):
        _reset(read_image="ask")
        nb = Path(self.cwd, "plot.ipynb")
        nb.write_text(json.dumps({"cells": [{"outputs": [{"data": {"image/png": "iVBOR"}}]}]}))
        pre = golden("PreToolUse_Read_png", self.cwd, file_path=str(nb))
        self.assertEqual(decision(run_hook("pre-tool", pre)), "ask")
        self.assertIn("iVBOR", json.dumps(output(self._post())), "after the yes the image goes, the cells are masked")
        nb.write_text(json.dumps({"cells": [{"outputs": [{"text": "x"}]}]}))
        self.assertEqual(run_hook("pre-tool", pre), {}, "a notebook without an image is not asked about")
        self.assertNotIn("iVBOR", json.dumps(self._post()), "it got an image after the PreToolUse: withheld")
        p = golden("PostToolUse_Read_notebook", self.cwd, turn_id="t1")
        self.assertNotIn("iVBOR", json.dumps(run_hook("post-tool", p)), "Codex cannot ask: withheld")

    def test_the_image_data_is_not_scanned(self):
        # review round 2: under allow the base64 was scanned (300 KB took 7.5 s); a token shape inside it stays as it
        # is, because it is image data, while the cell is masked
        p = golden("PostToolUse_Read_notebook", self.cwd)
        p["tool_response"]["file"]["cells"][0]["source"] = f"key = '{TOKEN}'"
        img = p["tool_response"]["file"]["cells"][0]["outputs"][0]["image"]
        img["image_data"] = img["image_data"] + TOKEN
        out = output(run_hook("post-tool", p))
        self.assertEqual(out["file"]["cells"][0]["outputs"][0]["image"]["image_data"], img["image_data"])
        self.assertNotIn(TOKEN, out["file"]["cells"][0]["source"])

    def test_block_keeps_an_error_output_as_text(self):
        _reset(read_image="block")
        p = golden("PostToolUse_Read_notebook", self.cwd)
        p["tool_response"]["file"]["cells"][0]["outputs"].append(
            {"output_type": "error", "ename": "ZeroDivisionError", "evalue": f"token {TOKEN}",
             "traceback": ["line one", "line two"]})
        content = output(run_hook("post-tool", p))["file"]["content"]
        self.assertIn("ZeroDivisionError: token ⟦SECRET_c", content)
        self.assertIn("line two", content)

    def test_allow_keeps_the_image_and_still_scans_the_cells(self):
        answer = self._post()
        self.assertNotIn(TOKEN, json.dumps(answer))
        self.assertIn("iVBOR", json.dumps(output(answer)))

    def test_a_notebook_without_an_image_is_no_image_read(self):
        p = golden("PostToolUse_Read_notebook", self.cwd)
        del p["tool_response"]["file"]["cells"][0]["outputs"][0]["image"]
        self.assertIsNone(file_reads.kind_of_response("Read", p["tool_response"]))


# ------------------------------------------------------- typed settings --
class TypedSettings(_Work):
    def _prompt(self, text: str, **client) -> dict:
        p = golden("UserPromptSubmit_pasted_image", self.cwd, prompt=text)
        p.update(client)
        return run_hook("user-prompt", p)

    def test_one_typed_setting_changes_the_mode(self):
        out = self._prompt("/maisecrets:settings read_pdf convert")
        self.assertIn("PDFs the AI reads is convert (set by you)", said(out))
        self.assertIn("pdftotext is not installed", said(out), "the note comes at once, not at the first PDF")
        self.assertEqual(load_config()["read_pdf"], "convert")
        self.assertIn("pdftotext is not installed", settings.render(only="read_pdf"), "the card says it too")
        out = self._prompt("maisecrets: set read_pdf convert", turn_id="t1")
        self.assertEqual(out["decision"], "block", "Codex: the sentence never reaches the model")
        self.stub()
        self.assertNotIn("pdftotext", said(self._prompt("/maisecrets:settings read_pdf convert")))
        self.assertNotIn("pdftotext", said(self._prompt("/maisecrets:settings read_pdf block")))

    def test_read_image_refuses_convert(self):
        out = self._prompt("/maisecrets:settings read_image convert")
        self.assertIn("convert is for PDFs only", said(out))
        self.assertEqual(load_config()["read_image"], "allow")

    def test_clean_dirs_add_and_remove(self):
        out = self._prompt(f"/maisecrets:settings clean_dirs add {self.dir / 'my scans'}")
        self.assertIn("Folders with clean files is", said(out))
        self.assertEqual(load_config()["clean_dirs"], [str(self.dir / "my scans")])
        self._prompt(f"maisecrets: set clean_dirs remove {self.dir / 'my scans'}", turn_id="t1")
        self.assertEqual(load_config()["clean_dirs"], [])
        out = self._prompt("/maisecrets:settings clean_dirs add relative/dir")
        self.assertIn("not added", said(out))

    def test_a_tool_call_cannot_set_them(self):
        for cmd in ("echo '/maisecrets:settings read_pdf allow'", "echo 'maisecrets: set clean_dirs add /tmp'"):
            with self.subTest(cmd):
                out = run_hook("pre-tool", {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "S1",
                                            "prompt_id": "p1", "cwd": self.cwd})
                self.assertEqual(decision(out), "deny")

    def test_a_prompt_the_person_did_not_type_sets_nothing(self):
        self._prompt("/maisecrets:settings read_pdf allow", source="cron")
        _reset(read_pdf="block")
        self._prompt("/maisecrets:settings read_pdf allow", source="cron")
        self.assertEqual(load_config()["read_pdf"], "block")

    def test_a_file_ignored_for_a_wrong_type_keeps_the_stricter_mode(self):
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "read_pdf": "block", "clean_dirs": [self.cwd], "tips": "x"}))
        cfg = load_config()
        self.assertEqual(cfg["read_pdf"], "block")
        self.assertEqual(cfg["clean_dirs"], [], "a clean folder only loosens: it is not kept")

    def test_a_config_that_cannot_be_read_blocks_both(self):
        # review of block 4: bad JSON or a wrong type dropped a block the person had set
        cases = {"bad JSON": '{"backend": "jsonfile", "allow_plaintext_store": true, "read_pdf": "block",}',
                 "a list value": json.dumps({**TEST_CONFIG, "read_pdf": ["block"]}),
                 "no object": json.dumps([{"read_pdf": "block"}])}
        for name, text in cases.items():
            with self.subTest(name):
                CONFIG.write_text(text)
                cfg = load_config()
                self.assertEqual((cfg["read_pdf"], cfg["read_image"]), ("block", "block"))
                pre = self.pre(file_path=self.pdf)
                self.assertEqual(decision(pre), "deny")
                self.assertIn("config.json cannot be read", pre["hookSpecificOutput"]["permissionDecisionReason"])
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "tips": "x"}))
        cfg = load_config()
        self.assertEqual((cfg["read_pdf"], cfg["read_image"]), ("block", "block"),
                         "codex review of block 4: any wrong type in the file ignores it, so both block")

    def test_the_card_names_the_modes(self):
        text = settings.render()
        self.assertIn("PDFs the AI reads · allow · not decided", text)
        self.assertIn("convert     send only its text", text)
        self.assertIn("/maisecrets:settings read_pdf convert", text)


# ------------------------------------------------- end to end, real hooks --
def _launcher(event: str, payload: dict, home: Path, path: str) -> dict:
    """hooks/run.sh with the JSON on stdin, as Claude Code starts it: a temp HOME and a temp maisecrets home."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
    env.update({"HOME": str(home), "MAISECRETS_" + "HOME": str(home / "store"), "PATH": path,
                "PYTHONDONTWRITEBYTECODE": "1"})
    r = subprocess.run(["bash", str(ROOT / "hooks" / "run.sh"), event], input=json.dumps(payload),
                       capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout) if r.stdout.strip() else {}


class EndToEnd(_Work):
    """The person types one setting, then drags a PDF into the session; the model sees only the masked text."""

    def _run(self, path: str) -> None:
        home = self.dir / "home"
        (home / "store").mkdir(parents=True)
        (home / "store" / "config.json").write_text(json.dumps(TEST_CONFIG))
        py_dir = os.path.dirname(sys.executable)
        path = f"{path}{os.pathsep}{py_dir}{os.pathsep}/usr/bin{os.pathsep}/bin"
        typed = golden("UserPromptSubmit_pasted_image", self.cwd, prompt="/maisecrets:settings read_pdf convert")
        out = _launcher("user-prompt", typed, home, path)
        self.assertIn("is convert (set by you)", said(out))
        pre = golden("PreToolUse_Read_pdf_pages", self.cwd)
        del pre["tool_input"]["pages"]
        self.assertEqual(_launcher("pre-tool", pre, home, path), {}, "the read runs")
        post = golden("PostToolUse_Read_pdf", self.cwd)
        post["tool_response"]["file"]["base64"] = base64.b64encode(Path(self.pdf).read_bytes()).decode()
        answer = _launcher("post-tool", post, home, path)
        out = output(answer)
        self.assertEqual(out["type"], "text")
        self.assertEqual(tuple(out["file"]), file_reads.TEXT_KEYS)
        self.assertIn("Invoice 2026", out["file"]["content"])
        self.assertRegex(out["file"]["content"], r"deploy token ⟦SECRET_c\d+⟧")
        self.assertNotIn(TOKEN, json.dumps(answer))
        self.assertNotIn(post["tool_response"]["file"]["base64"][:40], json.dumps(answer))

    @unittest.skipUnless(REAL_PDFTOTEXT, "no pdftotext that maisecrets trusts (fixed folder, no other writer)")
    def test_with_the_real_pdftotext(self):
        self._run(os.path.dirname(REAL_PDFTOTEXT))


_PAD = bytes.fromhex("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a")


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def locked_pdf_bytes(user: str, *lines: str, perms: int = -4) -> bytes:
    """pdf_bytes encrypted by the standard security handler, revision 2 (RC4, 40 bits; PDF 1.7, 7.6.3), standard
    library only. An empty `user` password is a PDF that only its owner password restricts: any reader opens it. A
    user password locks it: pdftotext ends with `Incorrect password`, as for AES-128 and AES-256 (measured with qpdf's
    output on poppler 26.10.0, 2026-10-17)."""
    import hashlib
    plain = pdf_bytes(*lines)
    pad = lambda pw: (pw.encode("latin-1") + _PAD)[:32]  # noqa: E731
    owner = _rc4(hashlib.md5(pad("owner-test")).digest()[:5], pad(user))
    p_entry = perms
    perms = perms.to_bytes(4, "little", signed=True)
    file_id = hashlib.md5(b"a test pdf").digest()
    key = hashlib.md5(pad(user) + owner + perms + file_id).digest()[:5]
    check = _rc4(key, _PAD)
    # encrypt each stream with the key of its object (algorithm 1); the test PDF has no string outside a stream
    objs = re.findall(rb"(\d+) 0 obj\n(.*?)\nendobj\n", plain, re.S)
    out = b"%PDF-1.4\n"
    offs = []
    for num, body in objs:
        m = re.match(rb"(<< /Length )\d+( >>\nstream\n)(.*)(\nendstream)\Z", body, re.S)
        if m:
            okey = hashlib.md5(key + int(num).to_bytes(3, "little") + b"\0\0").digest()[:10]
            data = _rc4(okey, m.group(3))
            body = m.group(1) + b"%d" % len(data) + m.group(2) + data + m.group(4)
        offs.append(len(out))
        out += num + b" 0 obj\n" + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += (b"trailer\n<< /Size %d /Root 1 0 R /Encrypt << /Filter /Standard /V 1 /R 2 /O <%s> /U <%s> /P %d >> "
            b"/ID [<%s> <%s>] >>\nstartxref\n%d\n%%%%EOF\n") % (
        len(objs) + 1, owner.hex().encode(), check.hex().encode(), p_entry, file_id.hex().encode(),
        file_id.hex().encode(), xref)
    return out


class LockedOrDamaged(_Work):
    """A PDF locked by a password, one only its owner restricts, and a damaged one (2026-10-17): under convert the PDF
    never reaches the model as bytes, and the refusal names the cause."""

    def _convert(self, data: bytes) -> tuple:
        Path(self.pdf).write_bytes(data)
        answer = self.post()
        out = output(answer)
        self.assertEqual(out["type"], "text", "the PDF is replaced by text, never passed")
        self.assertNotIn(base64.b64encode(data).decode()[:40], json.dumps(answer))
        return out["file"]["content"], answer

    def test_the_cause_comes_from_pdftotext(self):
        _reset(read_pdf="convert")
        for body, cause in (
                ("echo 'Command Line Error: Incorrect password' >&2; exit 1", file_reads.LOCKED),
                ("echo \"Syntax Error: Couldn't find trailer dictionary\" >&2; exit 1",
                 "the file is damaged or no PDF"),
                ("exit 3", "does not allow its text to be copied"),
                # the message that ends the run comes after many warnings: the end of stderr is kept
                ("/usr/bin/yes 'Syntax Error: a damaged object' | /usr/bin/head -n 6000 >&2; "
                 "echo 'Command Line Error: Incorrect password' >&2; exit 1", file_reads.LOCKED),
                # the phrase in an earlier message, or with another exit code, is no lock
                ("echo 'Command Line Error: Incorrect password' >&2; echo 'Syntax Error: x' >&2; exit 1",
                 "the file is damaged or no PDF"),
                ("echo 'Command Line Error: Incorrect password' >&2; exit 2", "the file is damaged or no PDF")):
            with self.subTest(body):
                self.stub(body)
                self.calls.unlink(missing_ok=True)
                text, answer = self._convert(pdf_bytes("Invoice 2026"))
                self.assertIn(cause, text)
                self.assertIn("withheld", answer["systemMessage"])
                # the conversion runs with -q; only a failure brings the second run, of page 1, that reads the messages
                first, second = self.calls.read_text().splitlines()
                self.assertTrue(first.startswith("-q "), first)
                self.assertNotIn("-q", second.split())
                self.assertIn("-f 1 -l 1", second)

    def _second_run(self, second: str) -> tuple:
        """A conversion that fails (exit 1), and a second run of the stub given by `second`. (text, seconds, calls)."""
        _reset(read_pdf="convert")
        self.stub(f'if [ "$1" = "-q" ]; then exit 1; fi\n{second}')
        started = time.monotonic()
        text, _answer = self._convert(pdf_bytes("Invoice 2026"))
        return text, time.monotonic() - started, self.calls.read_text().splitlines()

    def test_a_second_run_that_hangs_is_stopped(self):
        # extract itself, not the hook: the hook's watchdog would end the test process with exit 0
        _reset(read_pdf="convert")
        self.stub('if [ "$1" = "-q" ]; then exit 1; fi\n'
                  "echo 'Command Line Error: Incorrect password' >&2; exec /bin/sleep 30")
        started = time.monotonic()
        with mock.patch.object(file_reads, "DIAGNOSE_SECONDS", 0.5):
            text, why = file_reads.extract(self.pdf, None, self.cwd)
        self.assertIsNone(text)
        self.assertIn("the file is damaged or no PDF", why, "no cause from a run that did not end")
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(len(self.calls.read_text().splitlines()), 2)

    def test_a_second_run_above_the_memory_limit_is_stopped(self):
        diag = []
        real_start = file_reads._start

        def start(args, stdout, stderr):
            child = real_start(args, stdout, stderr)
            if "-q" not in args:
                diag.append(child.pid)
            return child
        with mock.patch.object(file_reads, "_start", start), mock.patch.object(file_reads, "DIAGNOSE_SECONDS", 10.0), \
                mock.patch.object(file_reads, "_rss", lambda pid: file_reads.MAX_RSS_BYTES + 1 if pid in diag else 0):
            text, took, _calls = self._second_run("exec /bin/sleep 30")
        self.assertIn("the file is damaged or no PDF", text)
        self.assertLess(took, 4, "stopped by the memory check, not by the time limit")

    def test_a_program_changed_before_the_second_run_is_not_started(self):
        started = []
        real_start, real_check = file_reads._start, file_reads._no_other_writer

        def start(args, stdout, stderr):
            started.append(args)
            return real_start(args, stdout, stderr)
        with mock.patch.object(file_reads, "_start", start), mock.patch.object(
                file_reads, "_no_other_writer", lambda path: not started and real_check(path)):
            text, _took, calls = self._second_run("echo 'Command Line Error: Incorrect password' >&2; exit 1")
        self.assertEqual(len(calls), 1, "only the conversion ran")
        self.assertIn("the file is damaged or no PDF", text)

    def test_a_locked_pdf_tells_the_model_not_to_ask_for_the_password(self):
        _reset(read_pdf="convert")
        self.stub("echo 'Command Line Error: Incorrect password' >&2; exit 1")
        text, _answer = self._convert(pdf_bytes("Invoice 2026"))
        self.assertIn("do not ask the user for the password", text)

    def test_much_stderr_does_not_stop_pdftotext(self):
        # a damaged PDF can make pdftotext print a warning per object: the conversion never blocks on its messages
        _reset(read_pdf="convert")
        self.stub("/usr/bin/yes 'Syntax Error: a damaged object' | /usr/bin/head -c 2000000 >&2; "
                  "printf 'Invoice 2026, a text after the warnings\\n'")
        with mock.patch.object(file_reads, "EXTRACT_SECONDS", 3.0):
            text, _answer = self._convert(pdf_bytes("Invoice 2026"))
        self.assertIn("a text after the warnings", text)

    @unittest.skipUnless(REAL_PDFTOTEXT, "no pdftotext that maisecrets trusts (fixed folder, no other writer)")
    def test_with_the_real_pdftotext(self):
        p = mock.patch.object(file_reads, "_EXTRA_DIRS", (os.path.dirname(REAL_PDFTOTEXT),))
        p.start()
        self.addCleanup(p.stop)
        locked = locked_pdf_bytes("user-test", "Invoice 2026", f"deploy token {TOKEN}")
        # only an owner password, and printing (bit 3) and copying (bit 5) forbidden: poppler 26.10.0 converts it
        restricted = locked_pdf_bytes("", "Invoice 2026", f"deploy token {TOKEN}", perms=-4 - 4 - 16)
        plain = pdf_bytes("Invoice 2026", f"deploy token {TOKEN}")
        for mode in ("convert", "ask", "block"):
            _reset(read_pdf=mode)
            for name, data in (("locked", locked), ("restricted", restricted), ("damaged", plain[:len(plain) // 3])):
                with self.subTest(mode=mode, pdf=name):
                    Path(self.pdf).write_bytes(data)
                    pre = self.pre()
                    if mode == "block":
                        self.assertEqual(decision(pre), "deny")
                    if mode == "ask":
                        self.assertEqual(decision(pre), "ask", "the person decides, as for any PDF")
                        self.post()     # the answer of the call takes its ask note
                        continue
                    text, answer = self._convert(data)
                    self.assertNotIn(TOKEN, json.dumps(answer))
                    if mode == "block":
                        self.assertIn("the setting read_pdf is block", text)
                    elif name == "locked":
                        self.assertIn(file_reads.LOCKED, text)
                    elif name == "restricted":
                        # poppler 26.10.0 converts it; an older poppler may refuse with its exit 3 (Gate A, round 2)
                        self.assertTrue("Invoice 2026" in text or "does not allow its text to be copied" in text, text)
                    else:
                        self.assertIn("the file is damaged or no PDF", text)


def bomb_pdf(mib: int) -> bytes:
    """A one-page PDF whose content stream inflates to `mib` MiB of text operators, all at one place on the page: a
    few KB on disk. pdftotext took 4 MiB of them to 234 MB, 16 MiB past 900 MB (poppler 26.10.0, 2026-10-14)."""
    import zlib
    line = b"BT /F1 12 Tf 50 700 Td (AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA) Tj ET\n"
    block = line * (1 << 14)
    co = zlib.compressobj(9)
    data = b"".join(co.compress(block) for _ in range((mib << 20) // len(block))) + co.flush()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> "
            b"/Contents 4 0 R >>",
            b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out = b"%PDF-1.4\n"
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


def macho(*commands) -> bytes:
    """A 64-bit Mach-O header with these load commands: ("dylib", name) or ("rpath", path)."""
    import struct
    body = b""
    for kind, text in commands:
        raw = text.encode() + b"\0"
        raw += b"\0" * (-len(raw) % 8)
        if kind == "dylib":
            body += struct.pack("<IIIIII", 0xC, 24 + len(raw), 24, 2, 0x10000, 0x10000) + raw
        else:
            body += struct.pack("<III", 0x8000001C, 12 + len(raw) + 4, 16) + b"\0" * 4 + raw
    return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, len(commands), len(body), 0, 0) + body


class TheConverterIsBounded(_Work):
    """Review of 2026-10-14: memory, scans, the trust of the admin group and of the libraries pdftotext loads."""

    # ------------------------------------------------------------------ memory --
    def test_a_child_that_takes_too_much_memory_is_stopped_and_the_pdf_withheld(self):
        _reset(read_pdf="convert")
        self.stub(f"exec '{sys.executable}' -c \"b = b'x' * (200 << 20); import time; time.sleep(5)\"")
        with mock.patch.object(file_reads, "MAX_RSS_BYTES", 64 << 20):
            t0 = time.monotonic()
            content = output(self.post())["file"]["content"]
        self.assertIn("more than 64 MB of memory", content)
        self.assertLess(time.monotonic() - t0, 4.0, "stopped at the limit, not at the timeout")

    def test_a_child_whose_memory_cannot_be_read_is_stopped(self):
        _reset(read_pdf="convert")
        self.stub("/bin/sleep 5")
        with mock.patch.object(file_reads, "_rss", return_value=None):
            content = output(self.post())["file"]["content"]
        self.assertIn("cannot watch the memory", content)

    def test_a_child_ended_by_a_signal_is_refused(self):
        _reset(read_pdf="convert")
        self.stub("printf 'words enough to count as a page of text, more than 25\\n'; kill -SEGV $$")
        content = output(self.post())["file"]["content"]
        self.assertIn("signal", content)
        self.assertNotIn("words enough", content)

    @unittest.skipUnless(REAL_PDFTOTEXT, "no pdftotext that maisecrets trusts (fixed folder, no other writer)")
    def test_a_bomb_pdf_stops_the_real_pdftotext_at_the_limit(self):
        # 4 MiB of text operators, 15 KB on disk: unbounded, pdftotext peaks at about 234 MB and then prints text
        bomb = self.dir / "bomb.pdf"
        bomb.write_bytes(bomb_pdf(4))
        with mock.patch.object(file_reads, "_EXTRA_DIRS", (os.path.dirname(REAL_PDFTOTEXT),)), \
                mock.patch.object(file_reads, "MAX_RSS_BYTES", 48 << 20):
            text, why = file_reads.extract(str(bomb))
        self.assertIsNone(text)
        self.assertIn("more than 48 MB of memory", why)

    def test_the_child_gets_no_loader_variables(self):
        _reset(read_pdf="convert")
        self.stub("/usr/bin/env | /usr/bin/grep -E '^(LD_|DYLD_)' ; "
                  "printf 'and a line of text that is long enough for one page\\n'")
        loader = {"LD_PRELOAD": "/nowhere/x.so", "DYLD_INSERT_LIBRARIES": "/nowhere/x.dylib"}
        with mock.patch.dict(os.environ, loader):
            content = output(self.post())["file"]["content"]
        self.assertIn("long enough", content)
        self.assertNotIn("/nowhere", content)
        # SIP strips DYLD_* when /bin/sh starts on macOS, so the stub alone cannot see that half (round 2)
        with mock.patch.dict(os.environ, loader):
            self.assertFalse([k for k in file_reads._child_env() if k.startswith(("LD_", "DYLD_"))])

    # ------------------------------------------------------------------- scans --
    def test_a_scan_with_page_numbers_only_counts_as_scanned(self):
        _reset(read_pdf="convert")
        self.stub("printf '1\\n\\f2\\n\\f3\\n\\f'")
        content = output(self.post())["file"]["content"]
        self.assertIn("looks scanned", content)
        self.assertIn("3 page(s)", content)
        self.assertNotIn("2\n", content.replace("3 page", ""), "nothing of the scan")

    def test_a_short_text_on_each_page_still_passes(self):
        _reset(read_pdf="convert")
        line = "Seite mit dreissig Zeichen Text."
        self.stub(f"printf '{line}\\n\\f{line}\\n\\f'")
        content = output(self.post())["file"]["content"]
        self.assertNotIn("looks scanned", content)
        self.assertEqual(content.count(line), 2)

    def test_a_pdf_in_a_test_folder_is_no_test_code(self):
        # a label hit in test code is a fixture and stays; a converted PDF under tests/ is a document (Gate B, round 4)
        _reset(read_pdf="convert")
        folder = Path(self.cwd, "tests")
        folder.mkdir()
        pdf = folder / "contract.pdf"
        pdf.write_bytes(Path(self.pdf).read_bytes())
        value = "Kx7#mQ2v" + "Lp9wZr"
        self.stub(f"printf 'Vertrag 2026 mit allen Seiten\\nPasswort: {value}\\n\\f'")
        answer = self.post(file_path=str(pdf))
        self.assertNotIn(value, json.dumps(answer))
        # and not by its content either: a PDF that prints test code (codex, round 5). Another value: the first one
        # is stored now, and its exact match would mask it anyway
        _reset(read_pdf="convert")
        value = "Qw3-nB8x" + "Tz5vRk"
        self.stub(f"printf 'def test_login(self):\\n    password = \"{value}\"\\n"
                  "and some more words on this page\\n\\f'")
        answer = self.post()
        self.assertNotIn(value, json.dumps(answer))

    def test_a_typed_change_of_these_settings_is_weighed_like_the_others(self):
        self.assertTrue(settings.loosens("read_pdf", "convert", "ask"))
        self.assertFalse(settings.loosens("read_pdf", "ask", "convert"))
        self.assertTrue(settings.loosens("read_pdf", "bogus", "allow"), "a value that is no mode works as block")
        self.assertTrue(settings.loosens("read_image", "block", "ask"))
        home = os.path.expanduser("~")
        self.assertFalse(settings.loosens("clean_dirs", ["~/shots"], [os.path.join(home, "shots") + "/"]),
                         "the same folder in another spelling")
        self.assertTrue(settings.loosens("clean_dirs", ["~/shots"], ["~/shots", "~/scans"]))
        self.assertFalse(settings.loosens("clean_dirs", ["~/shots", "~/scans"], ["~/shots"]))

    @unittest.skipIf(os.name == "nt", "a symbolic link needs a privilege on Windows")
    def test_a_dangling_rpath_link_counts_by_its_target(self):
        target = self.dir / "open" / "lib"
        link = self.dir / "linked"
        os.symlink(target, link)
        (self.dir / "open").mkdir()
        self.assertEqual([os.path.realpath(x) for x in file_reads._nearest_folder(str(link))],
                         [os.path.realpath(self.dir), os.path.realpath(self.dir / "open")],
                         "the folder of the link's name and the folder it points to")

    def test_the_text_is_scanned_as_tool_channel_text(self):
        _reset(read_pdf="convert")
        self.stub()
        from maisecrets import detect
        real = detect.scan
        channels = []

        def scan(text, *a, **kw):
            if "Invoice 2026" in text:
                channels.append(kw.get("channel"))
            return real(text, *a, **kw)
        with mock.patch.object(hooks.detect, "scan", scan):
            output(self.post())
        self.assertEqual(channels, ["tool"])

    # ------------------------------------------------- the admin group (Option B) --
    @unittest.skipIf(os.name == "nt", "groups are for macOS and Linux")
    def test_an_admin_group_writes_as_root_does(self):
        import types
        other = types.SimpleNamespace(gr_name="admin", gr_mem=["root", "someone-else"])
        with mock.patch("grp.getgrgid", return_value=other), \
                mock.patch.object(file_reads, "admin_groups", return_value=frozenset({"admin", "wheel"})):
            self.assertFalse(file_reads._group_has_other_writer(80))
            other.gr_name = "staff"
            self.assertTrue(file_reads._group_has_other_writer(80), "any other group with another member")

    @unittest.skipIf(os.name == "nt", "groups are for macOS and Linux")
    def test_a_group_whose_members_are_not_listed_is_another_writer(self):
        # macOS everyone (12) and localaccounts (61) list no member and hold every account (Opus review)
        import types
        hidden = types.SimpleNamespace(gr_name="everyone", gr_mem=[])
        with mock.patch("grp.getgrgid", return_value=hidden):
            self.assertTrue(file_reads._group_has_other_writer(12))

    @unittest.skipIf(os.name == "nt", "links and modes are for macOS and Linux")
    def test_a_link_counts_by_its_owner_not_its_mode_bits(self):
        # Linux shows every link as 0777: /bin and /lib of a merged /usr are links (both reviews of block 4)
        self.stub()
        link = self.dir / "linkbin"
        os.symlink(self.bin, link)
        if hasattr(os, "lchmod"):
            os.lchmod(link, 0o777)
        if not os.lstat(link).st_mode & 0o002:
            self.skipTest("this system gives a link no write bit to test with")
        self.assertTrue(file_reads._no_other_writer(str(link / "pdftotext")))

    @unittest.skipUnless(sys.platform == "darwin", "chmod +a is macOS")
    def test_an_acl_that_lets_another_account_write_refuses(self):
        d = self.dir / "acl"
        d.mkdir()
        self.assertTrue(file_reads._no_other_writer(str(d)))
        subprocess.run(["/bin/chmod", "+a", "everyone deny delete", str(d)], check=True)
        self.assertTrue(file_reads._no_other_writer(str(d)), "a deny entry takes nothing away from the owner")
        subprocess.run(["/bin/chmod", "+a", "everyone allow add_file", str(d)], check=True)
        self.assertFalse(file_reads._no_other_writer(str(d)))
        subprocess.run(["/bin/chmod", "-N", str(d)], check=True)
        # the flags of inheritance share the allow field: allow,file_inherit,directory_inherit and, on a file made
        # inside, allow,inherited (both reviews of round 2)
        subprocess.run(["/bin/chmod", "+a", "everyone allow add_file,file_inherit,directory_inherit", str(d)],
                       check=True)
        (d / "inside").write_text("x")
        self.assertFalse(file_reads._no_other_writer(str(d)))
        self.assertTrue(file_reads._acl_lets_in(str(d / "inside")), "allow,inherited:write on a file made inside")
        sub = d / "sub"
        sub.mkdir()
        self.assertTrue(file_reads._acl_lets_in(str(sub)), "allow,inherited on the folder made inside")
        subprocess.run(["/bin/chmod", "-RN", str(d)], check=True)

    def test_the_text_of_a_macos_acl_is_read_with_its_flags(self):
        # the shapes acl_to_text gave on macOS (round 2): the flags of inheritance share the allow field
        uuid = "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C"
        for entry, grants in ((f"group:{uuid}:everyone:12:deny:delete", False),
                              (f"group:{uuid}:everyone:12:allow:read", False),
                              (f"group:{uuid}:everyone:12:allow:add_file", True),
                              (f"group:{uuid}:everyone:12:allow,file_inherit,directory_inherit:write", True),
                              (f"group:{uuid}:everyone:12:allow,inherited:write", True)):
            with self.subTest(entry):
                self.assertEqual(file_reads.acl_text_grants_write(f"!#acl 1\n{entry}\n"), grants)

    def test_a_posix_acl_on_linux_refuses(self):
        import errno
        with mock.patch.object(sys, "platform", "linux"):
            with mock.patch.object(os, "getxattr", return_value=b"\x02\x00", create=True):
                self.assertTrue(file_reads._acl_lets_in("/x"))
            with mock.patch.object(os, "getxattr", side_effect=OSError(errno.ENODATA, "no"), create=True):
                self.assertFalse(file_reads._acl_lets_in("/x"))
            with mock.patch.object(os, "getxattr", side_effect=OSError(errno.EACCES, "no"), create=True):
                self.assertTrue(file_reads._acl_lets_in("/x"), "a list that cannot be read counts")

    def test_a_script_whose_interpreter_the_path_chooses_is_not_run(self):
        tool = self.bin / "pdftotext"
        tool.write_text("#!/usr/bin/env sh\necho hi\n")
        tool.chmod(0o755)
        self.assertIsNone(file_reads.libraries(str(tool)))
        self.assertIsNone(file_reads.pdftotext())

    @unittest.skipIf(os.name == "nt", "process groups are for macOS and Linux")
    def test_the_watchdog_can_end_a_running_pdftotext(self):
        # os._exit of the watchdog skips the finally of extract(), and the child has its own session (both reviews)
        child = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        file_reads._RUNNING.add(child.pid)
        try:
            file_reads.kill_running()
            self.assertIsNotNone(child.wait(timeout=5))
        finally:
            file_reads._RUNNING.discard(child.pid)
        _reset(read_pdf="convert")
        self.stub("/bin/sleep 5")
        seen = []
        real_wait = file_reads._wait

        def wait(thread, seconds):
            seen.append(set(file_reads._RUNNING))
            raise RuntimeError("stop")
        with mock.patch.object(file_reads, "_wait", wait):
            output(self.post())
        self.assertTrue(seen and seen[0], "extract() names its child while it runs")
        self.assertEqual(file_reads._RUNNING, set(), "and forgets it after")
        self.assertIs(real_wait, file_reads._wait)
        from maisecrets import hooks as hooks_mod
        self.assertIn("reader.kill_running()", Path(hooks_mod.__file__).read_text())

    def test_a_cut_text_ends_at_a_line_and_never_inside_a_key(self):
        head = "word " * (file_reads.MAX_TEXT_CHARS // 5 - 40) + "\n"
        label = "PRIVATE" + " KEY-----\n"          # built at run time (scan_tree)
        key = "-----BEGIN " + label + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3\n" * 10 + "-----END " + label
        cut = file_reads._cut(head + key)
        self.assertNotIn("BEGIN", cut)
        self.assertNotIn("QUJD", cut)
        long_line = "a" * (file_reads.MAX_TEXT_CHARS - 10) + "\nsecond line that goes past the cap\n"
        self.assertTrue(file_reads._cut(long_line).endswith("\n"))
        self.assertNotIn("second", file_reads._cut(long_line))
        _reset(read_pdf="convert")
        self.stub("/usr/bin/head -c 200000 /dev/zero | /usr/bin/tr '\\\\0' 'a'")
        content = output(self.post())["file"]["content"]
        self.assertIn("are one line", content)
        self.assertNotIn("aaaa", content)

    @unittest.skipUnless(sys.platform.startswith("linux"), "ldd")
    def test_the_libraries_of_a_root_program_on_linux_are_trusted(self):
        # the merged /usr links failed every check before (both reviews): this is the check convert runs
        tool = os.path.realpath(sys.executable)
        if file_reads.libraries(tool) is None:
            self.skipTest("this python is no dynamic ELF program, or ldd is missing")
        if not file_reads._no_other_writer(tool):
            self.skipTest("this python is not installed where only root and this user can write")
        self.assertTrue(file_reads._trusted_libraries(tool))

    def test_the_admin_groups_of_each_system(self):
        cases = (("darwin", None, {"admin", "wheel"}),
                 ("linux", 'ID=ubuntu\nID_LIKE=debian\n', {"sudo", "admin"}),
                 ("linux", 'ID=debian\n', {"sudo"}),
                 ("linux", 'ID=fedora\n', {"wheel"}),
                 ("linux", 'ID="rocky"\nID_LIKE="rhel centos fedora"\n', {"wheel"}),
                 ("linux", 'ID=alpine\n', set()),
                 ("linux", 'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n', set()),
                 ("win32", None, set()))
        for platform, release, want in cases:
            with self.subTest(platform=platform, release=release):
                opener = mock.mock_open(read_data=release or "")
                with mock.patch.object(sys, "platform", platform), mock.patch("builtins.open", opener):
                    self.assertEqual(file_reads.admin_groups(), frozenset(want))

    # -------------------------------------------------------------- libraries --
    def test_a_script_loads_its_interpreter(self):
        self.stub()
        libs = file_reads.libraries(str(self.bin / "pdftotext"))
        self.assertEqual(libs[0], "/bin/sh", "the interpreter, then its own libraries")

    def test_a_library_that_another_account_can_write_refuses_the_program(self):
        _reset(read_pdf="convert")
        self.stub()
        libdir = self.dir / "lib"
        libdir.mkdir()
        lib = libdir / "libpoppler.dylib"
        lib.write_bytes(b"\0")
        with mock.patch.object(file_reads, "libraries", return_value=[str(lib)]):
            self.assertIsNotNone(file_reads.pdftotext())
            os.chmod(libdir, 0o777)
            try:
                self.assertIsNone(file_reads.pdftotext(), "others can write the folder of a library")
                content = output(self.post())["file"]["content"]
            finally:
                os.chmod(libdir, 0o755)
            self.assertIsNone(file_reads.pdftotext(str(libdir)), "a library in the working folder")
        self.assertIn("a library it loads", content)
        self.assertFalse(self.calls.exists(), "pdftotext did not run")
        with mock.patch.object(file_reads, "libraries", return_value=None):
            self.assertIsNone(file_reads.pdftotext(), "libraries that cannot be told")

    def test_the_mach_o_libraries_are_found_through_rpath_and_each_library(self):
        app = self.dir / "app"
        (app / "bin").mkdir(parents=True)
        (app / "lib").mkdir()
        exe = app / "bin" / "tool"
        (app / "early").mkdir()
        exe.write_bytes(macho(("rpath", "@loader_path/../early"), ("rpath", "@loader_path/../lib"),
                              ("dylib", "@rpath/liba.dylib"), ("dylib", "/usr/lib/libSystem.B.dylib")))
        (app / "lib" / "liba.dylib").write_bytes(macho(("dylib", "@loader_path/libb.dylib")))
        (app / "lib" / "libb.dylib").write_bytes(macho())
        found = file_reads._macho_libraries(str(exe))
        # the rpath folder searched first is checked too: a library planted there later would win (round 2)
        self.assertEqual([os.path.realpath(x) for x in found or ()],
                         [os.path.realpath(app / "early")]
                         + [os.path.realpath(app / "lib" / n) for n in ("liba.dylib", "libb.dylib")])
        # a missing rpath folder counts by the nearest folder above it: whoever writes there can make it (round 3)
        exe2 = app / "bin" / "tool2"
        exe2.write_bytes(macho(("rpath", "@loader_path/../missing/deeper"), ("rpath", "@loader_path/../lib"),
                               ("dylib", "@rpath/libb.dylib")))
        self.assertEqual(os.path.realpath(file_reads._macho_libraries(str(exe2))[0]), os.path.realpath(app))
        self.assertFalse(settings.loosens("clean_dirs", ["/safe/docs"], ["/safe/./docs"]))
        (app / "lib" / "libb.dylib").unlink()
        self.assertIsNone(file_reads._macho_libraries(str(exe)), "a library that is not there")
        exe.write_bytes(b"\0" * 64)
        self.assertIsNone(file_reads._macho_libraries(str(exe)), "no Mach-O")

    @unittest.skipUnless(sys.platform.startswith("linux"), "ldd")
    def test_ldd_names_the_libraries_of_an_elf_program(self):
        libs = file_reads.libraries(os.path.realpath(sys.executable))
        if libs is None:
            self.skipTest("this python is no dynamic ELF program, or ldd is missing")
        self.assertTrue(any("libc" in os.path.basename(x) or "ld-" in os.path.basename(x) for x in libs), libs)

    @unittest.skipUnless(sys.platform == "darwin" and REAL_PDFTOTEXT, "no pdftotext that maisecrets trusts on macOS")
    def test_the_real_pdftotext_and_its_libraries_are_checked(self):
        libs = file_reads.libraries(REAL_PDFTOTEXT)
        self.assertIsNotNone(libs)
        if REAL_PDFTOTEXT.startswith("/opt/homebrew/"):
            self.assertTrue(any("libpoppler" in x for x in libs), libs)


@unittest.skipUnless(REAL_PDFTOTEXT, "no pdftotext that maisecrets trusts (fixed folder, no other writer)")
class RealPdftotext(unittest.TestCase):
    def test_pages_and_text_of_a_synthetic_pdf(self):
        d = Path(tempfile.mkdtemp(dir=_isolate.TMP))
        f = d / "a.pdf"
        f.write_bytes(pdf_bytes("first line of the page", "second line of the page"))
        text, why = file_reads.extract(str(f), "1")
        self.assertEqual(why, "")
        self.assertIn("first line of the page", text)
        self.assertIn("second line of the page", text)
        self.assertEqual(file_reads.extract(str(d / "missing.pdf"))[0], None)
        (d / "bad.pdf").write_bytes(b"not a pdf")
        text, why = file_reads.extract(str(d / "bad.pdf"))
        self.assertIsNone(text)
        self.assertIn("the file is damaged or no PDF", why)
        shutil.rmtree(d, True)


if __name__ == "__main__":
    unittest.main()
