"""maisecrets/ner_health.py: a name source that is set and cannot be used is named to the person once, with the cause
and the step: at the session start, at the first unchecked tool result of a session (again when the cause changes),
and as a `names` note of /maisecrets:status and the panel, never a FAIL. Synthetic origins and names only.

Run: python3 -m unittest tests.test_ner_health -v
"""
from __future__ import annotations

import os
import socket
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from maisecrets import hub, ner_gateway, ner_health as H, sref_client as S, status_verdict as sv  # noqa: E402
from maisecrets.vault import JsonFileBackend  # noqa: E402

ORIGIN = "https://gw.example.test"
GATEWAY = {"url": ORIGIN, "gateway": ORIGIN, "gateway_url": ORIGIN + "/mcp", "allow_network": True}
def P(session: str, **extra) -> dict:
    """The payload of a hook of the person's own session."""
    return {"session_id": session, **extra}


SERVERS = {"team-gateway": ORIGIN + "/mcp", "other": "https://other.example.test/mcp"}


def _free_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                   # nothing listens there now
    return f"http://127.0.0.1:{port}/"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = JsonFileBackend()
        for f in (H.STATE, H._WARNED, S._ended_path(), ner_gateway.CACHE):
            f.unlink(missing_ok=True)
            self.addCleanup(f.unlink, missing_ok=True)
        self.addCleanup(S.forget, self.backend, ORIGIN)
        patcher = mock.patch("maisecrets.ner_setup._servers", return_value=SERVERS)
        patcher.start()
        self.addCleanup(patcher.stop)

    def cfg(self, conf: dict) -> dict:
        return {"backend": "jsonfile", "remote_detector": conf}

    def login(self) -> None:
        S._keep(self.backend, ORIGIN, {"refresh": "r-synthetic", "access": "a-synthetic", "scope": "x",
                                       "expires": time.time() + 3600})


class CauseTests(Base):
    def test_each_reason_has_its_cause(self):
        local, url = {"url": "http://127.0.0.1:8765/"}, {"url": "https://ner.example.test/"}
        cases = ((local, "refused", "local_down"), (url, "refused", "no_answer"), (url, "network", "no_answer"),
                 (url, "timeout", "slow"), (GATEWAY, "busy", "busy"), (GATEWAY, "rate_limited", "rate_limited"),
                 (GATEWAY, "forbidden", "no_scope"), (local, "not_ours", "not_ours"), (url, "too_long", None),
                 (url, "odd", "other"))
        for conf, reason, cause in cases:
            with self.subTest(reason=reason, conf=conf["url"]):
                self.assertEqual(H.cause_of(conf, reason), cause)

    def test_a_gateway_that_gave_no_detector_names_the_cause_it_recorded(self):
        with mock.patch.dict(ner_gateway.LAST, {"cause": "login_ended"}):
            self.assertEqual(H.cause_of(GATEWAY, "setup"), "login_ended")
        with mock.patch.dict(ner_gateway.LAST, {"cause": ""}):
            self.assertEqual(H.cause_of(GATEWAY, "setup"), "other")

    def test_the_step_names_the_server_of_the_gateway_and_codex_gets_its_prompt_form(self):
        self.assertEqual(H.line("login_ended", GATEWAY), "⚠️ maisecrets: names are NOT checked — the "
                         "gateway ended the login → /maisecrets:sref login team-gateway")
        self.assertTrue(H.line("no_login", GATEWAY, codex=True).endswith("→ maisecrets: sref login team-gateway"))
        self.assertTrue(H.line("local_down", {"url": "http://127.0.0.1:8765/"}).endswith("→ /maisecrets:ner local"))


class OnceTests(Base):
    def test_once_per_session_and_again_only_when_the_cause_changes(self):
        self.assertTrue(H.claim("s1", "busy"))
        self.assertFalse(H.claim("s1", "busy"))
        self.assertTrue(H.claim("s2", "busy"), "another session hears it too")
        self.assertTrue(H.claim("s1", "login_ended"), "a new cause")
        self.assertFalse(H.claim("s1", "login_ended"))
        self.assertFalse(H.claim("", "busy"), "no session: no line rather than one per result")

    def test_a_subagent_or_a_headless_run_neither_shows_nor_claims_the_line(self):
        cfg = self.cfg({"url": "https://ner.example.test/", "allow_network": True})
        self.assertIsNone(H.result_line(cfg, P("s1", agent_id="a1"), "network"))
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-py"}):
            self.assertIsNone(H.result_line(cfg, P("s1"), "network"))
            self.assertIsNone(H.start_line(self.cfg(GATEWAY), P("s1"), self.backend))
        self.assertEqual(H.recorded(GATEWAY), "no_login", "the status still learns the cause")
        self.assertIn("does not answer", H.result_line(cfg, P("s1"), "network"), "the person's own hook gets it")
        codex = {"session_id": "s2", "transcript_path": "/nonexistent/rollout.jsonl"}
        self.assertIsNone(H.result_line(cfg, codex, "network", codex=True), "codex exec or an unknown source")

    def test_the_line_is_claimed_per_session_and_source(self):
        a = self.cfg({"url": "https://ner-a.example.test/", "allow_network": True})
        b = self.cfg({"url": "https://ner-b.example.test/", "allow_network": True})
        self.assertIsNotNone(H.result_line(a, P("s1"), "network"))
        self.assertIsNotNone(H.result_line(b, P("s1"), "network"), "another source: its own line")
        self.assertIsNone(H.result_line(b, P("s1"), "network"))

    def test_a_result_line_records_the_cause_for_the_status_and_a_checked_result_clears_it(self):
        from maisecrets import remote_layer
        from maisecrets.detection import remote
        cfg = self.cfg({"url": "https://ner.example.test/", "allow_network": True})
        self.assertIn("does not answer", H.result_line(cfg, P("s1"), "network"))
        self.assertIsNone(H.result_line(cfg, P("s1"), "network"))
        self.assertEqual(H.recorded(cfg["remote_detector"]), "no_answer")
        with mock.patch.dict(remote_layer.LAST_CONF, {"v": cfg["remote_detector"]}):
            remote_layer.note_result(remote_layer.Layer({}, remote.RemoteStatus(state="ok")))
        self.assertIsNone(H.recorded(cfg["remote_detector"]))
        self.assertTrue(H.checked_recently(cfg["remote_detector"]))


class StartTests(Base):
    def test_a_gateway_login_the_gateway_ended_is_named_at_the_start_once(self):
        S._mark_ended(ORIGIN)
        cfg = self.cfg(GATEWAY)
        line = H.start_line(cfg, P("s1"), self.backend)
        self.assertEqual(line, "⚠️ maisecrets: names are NOT checked — the gateway ended the login "
                         "→ /maisecrets:sref login team-gateway")
        self.assertIsNone(H.start_line(cfg, P("s1"), self.backend), "the same session: not again")
        with mock.patch.dict(ner_gateway.LAST, {"cause": "login_ended"}):
            self.assertIsNone(H.result_line(cfg, P("s1"), "setup"), "no repeat at the first result")

    def test_a_renewal_that_did_not_finish_and_a_login_the_gateway_ended_have_their_own_lines(self):
        cfg = self.cfg(GATEWAY)
        S._mark_ended(ORIGIN, "uncertain")
        self.assertEqual(H.start_line(cfg, P("s1"), self.backend),
                         "\u26a0\ufe0f maisecrets: names are NOT checked \u2014 the last renewal did not finish; log "
                         "in again \u2192 /maisecrets:sref login team-gateway")
        self.assertEqual(H.verdict(cfg, self.backend).fact, "the last renewal did not finish; log in again")
        S._mark_ended(ORIGIN, "revoked")
        self.assertIn("the gateway ended the login \u2192", H.start_line(cfg, P("s2"), self.backend))
        self.assertEqual(H.ended_cause(ORIGIN), "login_ended")
        S._clear_ended(ORIGIN)
        self.assertEqual(H.ended_cause(ORIGIN), "no_login")

    def test_no_login_and_a_working_login(self):
        cfg = self.cfg(GATEWAY)
        self.assertIn("not logged in at the gateway", H.start_line(cfg, P("s1"), self.backend))
        self.login()
        self.assertIsNone(H.start_line(cfg, P("s2"), self.backend))

    def test_a_local_container_that_does_not_answer_and_one_that_is_starting(self):
        cfg = self.cfg({"url": "http://127.0.0.1:8765/"})
        with mock.patch("maisecrets.ner_setup.probe", return_value=(False, "")):
            self.assertTrue(H.start_line(cfg, P("s1"), self.backend).endswith("→ /maisecrets:ner local"))
            self.assertIsNone(H.start_line(cfg, P("s2"), self.backend, starting=True), "being started")
        with mock.patch("maisecrets.ner_setup.probe", return_value=(True, "")):
            self.assertIsNone(H.start_line(cfg, P("s3"), self.backend))

    def test_a_url_that_does_not_answer_within_a_second(self):
        cfg = self.cfg({"url": _free_url()})
        t0 = time.monotonic()
        self.assertIn("the name service does not answer → /maisecrets:ner", H.start_line(cfg, P("s1"), self.backend))
        self.assertLess(time.monotonic() - t0, 2.5)

    @unittest.skipIf(os.name == "nt", "run.sh: the session start of a POSIX launcher")
    def test_the_session_start_names_it_first_and_once(self):
        import json
        import subprocess
        import tempfile
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            store = home / "store"
            store.mkdir()
            (store / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                           "remote_detector": GATEWAY}))
            (store / "sref-ended.json").write_text(json.dumps({ORIGIN: time.time()}))
            (store / ".announced").write_text("x\n")          # not the first start: no welcome
            env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
            env.update({"HOME": str(home), "MAISECRETS_" + "HOME": str(store), "PYTHONDONTWRITEBYTECODE": "1",
                        "CLAUDECODE": "1"})

            def start() -> str:
                r = subprocess.run(["bash", str(root / "hooks" / "run.sh"), "session-" + "start"],
                                   input=json.dumps({"session_id": "S-start", "hook_event_name": "SessionStart"}),
                                   capture_output=True, text=True, env=env, timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                return json.loads(r.stdout).get("systemMessage", "")
            first = start()
            self.assertTrue(first.startswith("⚠️ maisecrets: names are NOT checked — the gateway ended "
                                             "the login → /maisecrets:sref login"), first)
            self.assertNotIn("names are NOT checked", start(), "once per session")

    @unittest.skipUnless(hasattr(__import__("socket"), "AF_UNIX"), "no Unix sockets here (Windows Python)")
    def test_a_unix_socket_is_probed_at_the_start(self):
        import socket
        import tempfile
        d = tempfile.mkdtemp(prefix="sock-")
        missing = self.cfg({"url": f"unix:{d}/none.sock"})
        self.assertIn("the name service does not answer", H.start_line(missing, P("s1"), self.backend))
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(f"{d}/ner.sock")
        srv.listen(1)
        self.addCleanup(srv.close)
        self.assertIsNone(H.start_line(self.cfg({"url": f"unix:{d}/ner.sock"}), P("s2"), self.backend))

    def test_no_source_no_line(self):
        self.assertIsNone(H.start_line({"backend": "jsonfile"}, P("s1"), self.backend))


class _Listener:
    """A local HTTP listener on a free port: /health answers 200, with the proof of `secret` when one is given."""

    def __init__(self, secret: str = "") -> None:
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from urllib.parse import parse_qs, urlsplit
        from maisecrets.detection.remote import _mac

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                q = parse_qs(urlsplit(self.path).query)
                body = {"status": "ok"}
                if secret and q.get("challenge"):
                    body["proof"] = _mac(secret, "health:" + q["challenge"][0])
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class LocalProofTests(Base):
    """The local container counts as checked only when it proves the secret `run.sh ner start` kept."""

    def local(self, listener: _Listener, secret: str = "") -> dict:
        from maisecrets import ner_secret
        self.addCleanup(listener.close)
        patcher = mock.patch("maisecrets.ner_setup.LOCAL_URL", listener.url)
        patcher.start()
        self.addCleanup(patcher.stop)
        ep = ner_secret.endpoint(listener.url)
        if secret:
            ner_secret.keep(self.backend, ep, secret, "container-synthetic")
            self.addCleanup(lambda: ner_secret._containers_path().unlink(missing_ok=True))
            self.addCleanup(self.backend.delete, ner_secret._entry(ep))
        return self.cfg({"url": listener.url})

    def test_a_foreign_listener_on_the_port_is_not_checked(self):
        secret = "s" * 40
        cfg = self.local(_Listener(), secret)                  # answers /health, cannot prove the secret
        check = H.verdict(cfg, self.backend)
        self.assertEqual((check.state, check.fact),
                         ("warn", "the local service is not the container maisecrets started"))
        self.assertIn("not the container", H.start_line(cfg, P("s1"), self.backend))

    def test_the_container_that_proves_the_secret_is_ready_and_checked_only_after_a_checked_result(self):
        secret = "p" * 40
        cfg = self.local(_Listener(secret), secret)
        check = H.verdict(cfg, self.backend)
        self.assertEqual((check.state, check.fact), ("n/a", "ready, not used yet in this session"))
        self.assertIsNone(H.start_line(cfg, P("s1"), self.backend), "no warning at the start")
        H.clear(cfg["remote_detector"])
        self.assertEqual(H.verdict(cfg, self.backend).state, "ok")

    def test_without_a_kept_secret_an_answer_proves_nothing(self):
        cfg = self.local(_Listener())
        check = H.verdict(cfg, self.backend)
        self.assertEqual((check.state, check.fact), ("n/a", "set, not proven yet"))
        H.clear(cfg["remote_detector"])                        # a tool result of this source was checked
        self.assertEqual(H.verdict(cfg, self.backend).state, "ok")


class FileLockThreadTests(unittest.TestCase):
    def test_another_thread_waits_and_the_holder_re_enters(self):
        import tempfile
        import threading
        from maisecrets.home import _lock_for
        lock = _lock_for(Path(tempfile.mkdtemp(prefix="lock-")) / ".t.lock")
        order: list = []
        with lock:
            with lock:                                     # the holding thread re-enters at once
                self.assertTrue(lock.held_here())

            def other() -> None:
                self.assertFalse(lock.held_here())
                with lock:
                    order.append("other")
            t = threading.Thread(target=other)
            t.start()
            time.sleep(0.3)
            order.append("holder")                         # the other thread is still waiting
        t.join(5)
        self.assertEqual(order, ["holder", "other"])


class LockWaitTests(unittest.TestCase):
    def test_a_holder_and_two_waiters_leave_the_lock_free(self):
        # the wait went through a shared attribute: the second waiter's `del` failed after it took the lock, which
        # then stayed held for good
        import tempfile
        import threading
        from maisecrets.home import _lock_for
        from maisecrets.vault_refs import _bounded
        lock = _lock_for(Path(tempfile.mkdtemp(prefix="lock-")) / ".w.lock")
        ran, errors = [], []
        holding = threading.Event()

        def holder() -> None:
            with lock:
                holding.set()
                time.sleep(0.5)

        def waiter(n: int) -> None:
            try:
                with _bounded(lock, time.monotonic() + 5):
                    ran.append(n)
            except Exception as exc:  # noqa: BLE001 - the failure under test
                errors.append(type(exc).__name__)
        h = threading.Thread(target=holder)
        h.start()
        holding.wait(5)
        ws = [threading.Thread(target=waiter, args=(n,)) for n in (1, 2)]
        for t in ws:
            t.start()
        for t in [h] + ws:
            t.join(10)
        self.assertEqual((sorted(ran), errors), ([1, 2], []))
        self.assertEqual((lock.depth, lock.fd), (0, None), "the lock is free again")
        self.assertEqual(lock.LOCK_DEADLINE, type(lock).LOCK_DEADLINE, "no wait was left on the shared lock")


class StatusTests(Base):
    def test_a_source_that_cannot_be_used_is_a_warn_and_the_head_line_says_names_are_not_checked(self):
        S._mark_ended(ORIGIN)
        check = H.verdict(self.cfg(GATEWAY), self.backend)
        self.assertEqual((check.state, check.name, check.fact, check.next),
                         ("warn", "names", "the gateway ended the login", "/maisecrets:sref login team-gateway"))
        ok = sv.Check("ok", "store", "answers", None, None)
        head = sv.head_line("9.9.9", [ok, check], "claude")
        self.assertIn("protects secrets in this session; names are not checked", head)
        fail = sv.Check("FAIL", "store", "no answer", "x", None)
        self.assertIn("is NOT protecting", sv.head_line("9.9.9", [fail, check], "claude"), "a FAIL still wins")
        self.assertIn("! names", "\n".join(sv.check_lines([check])))

    def test_checked_only_after_a_checked_result_of_the_same_source_and_no_source_is_no_check(self):
        self.login()
        unused = H.verdict(self.cfg(GATEWAY), self.backend)
        self.assertEqual((unused.state, unused.fact), ("n/a", "set, not used yet in this session"),
                         "a stored login proves no answer")
        H.clear({"url": "https://other.example.test/", "gateway": ""})
        self.assertEqual(H.verdict(self.cfg(GATEWAY), self.backend).state, "n/a", "another source was checked")
        H.clear(GATEWAY)
        self.assertEqual(H.verdict(self.cfg(GATEWAY), self.backend).state, "ok")
        with mock.patch.object(H.time, "time", return_value=time.time() + H.OK_FOR + 1):
            self.assertEqual(H.verdict(self.cfg(GATEWAY), self.backend).state, "n/a", "an hour ago is not recent")
        self.assertIsNone(H.verdict({"backend": "jsonfile"}, self.backend))
        for check in (unused, H.verdict(self.cfg(GATEWAY), self.backend)):
            head = sv.head_line("9.9.9", [check], "claude")
            self.assertNotIn("names are not checked", head)
            self.assertIn("protects this session", head)

    def test_a_cause_of_one_source_is_not_shown_for_another_after_a_switch(self):
        a = {"url": "https://ner-a.example.test/", "allow_network": True}
        b = {"url": "https://ner-b.example.test/", "allow_network": True}
        H.result_line(self.cfg(a), P("s1"), "network")
        self.assertEqual(H.verdict(self.cfg(a), self.backend).state, "warn")
        self.assertEqual(H.recorded(a), "no_answer")
        self.assertIsNone(H.recorded(b))
        self.assertEqual(H.verdict(self.cfg(b), self.backend).state, "n/a", "source B was never asked")

    def test_checked_is_a_past_fact_with_its_age_not_a_claim_about_now(self):
        conf = {"url": "https://ner.example.test/", "allow_network": True}
        H.clear(conf)
        self.assertEqual(H.verdict(self.cfg(conf), self.backend).fact, "checked under a minute ago")
        with mock.patch.object(H.time, "time", return_value=time.time() + 12 * 60 + 5):
            self.assertEqual(H.verdict(self.cfg(conf), self.backend).fact, "checked 12 min ago")

    def test_a_url_that_was_never_used_is_neutral_not_a_warn(self):
        conf = {"url": "https://ner.example.test/", "allow_network": True}
        self.assertEqual(H.verdict(self.cfg(conf), self.backend).state, "n/a")
        H.clear(conf)
        self.assertEqual(H.verdict(self.cfg(conf), self.backend).state, "ok")

    def test_a_login_cause_recorded_before_a_new_login_is_not_named(self):
        H.record("login_ended", GATEWAY)
        self.login()
        self.assertEqual(H.verdict(self.cfg(GATEWAY), self.backend).state, "n/a")
        H.record("busy", GATEWAY)
        self.assertEqual(H.verdict(self.cfg(GATEWAY), self.backend).fact, "the gateway's name service is busy")

    def test_the_panel_shows_the_names_note(self):
        note = sv.Check("warn", "names", "the gateway ended the login", "/maisecrets:sref login team-gateway", None)
        with mock.patch.object(sv, "names_verdict", return_value=note):
            got = hub.pane_status("s-panel")
        self.assertIn({"name": "names", "fact": "the gateway ended the login",
                       "next": "/maisecrets:sref login team-gateway"}, got["notes"])
        if "NOT protecting" not in got["line"]:
            self.assertIn("names are not checked", got["line"])


if __name__ == "__main__":
    unittest.main()
