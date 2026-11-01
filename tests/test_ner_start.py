"""`run.sh ner start` and the stored secret of the name service (#1699): the container gets a secret it must prove
before each text; the secret reaches docker in the environment, never on the command line, and lives in the store;
a container the person started by hand is left alone and runs unchecked. Docker is a fake here; the store is the
temp file store of tests/_isolate.py."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import ner_secret, ner_setup, remote_layer  # noqa: E402
from maisecrets.vault import HOME, make_backend  # noqa: E402

CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
EP = "127.0.0.1:8765"
CID = "c0ffee" * 10


class FakeDocker:
    """`container inspect`, `start`, `run`, `rm` as docker answers them; every call is kept."""

    def __init__(self, existing: str = "", image: str = "mcpgate/ner", run_rc: int = 0):
        self.existing, self.image, self.run_rc, self.calls = existing, image, run_rc, []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw.get("env")))
        verb = argv[1]
        if verb == "container":
            ok = bool(self.existing)
            return subprocess.CompletedProcess(argv, 0 if ok else 1, f"{self.existing} {self.image}\n" if ok else "",
                                               "" if ok else "no such container")
        if verb == "run":
            self.existing = CID
            return subprocess.CompletedProcess(argv, self.run_rc, CID + "\n" if self.run_rc == 0 else "", "boom")
        return subprocess.CompletedProcess(argv, 0, "", "")


def _clean() -> None:
    try:
        os.unlink(Path(HOME, "ner-containers.json"))
    except FileNotFoundError:
        pass
    backend = make_backend(CONFIG)
    try:
        backend.delete(ner_secret.PREFIX + EP.replace(":", "_"))
    except Exception:  # noqa: BLE001 - nothing stored
        pass


class StartTests(unittest.TestCase):
    def setUp(self):
        _clean()
        self.addCleanup(_clean)

    def start(self, docker: FakeDocker):
        with mock.patch.object(ner_setup, "container_tool", lambda: "/usr/bin/docker"), \
                mock.patch.object(ner_setup.subprocess, "run", docker):
            return ner_setup.start_local(CONFIG)

    def test_a_new_container_gets_a_secret_in_its_environment_and_the_store_keeps_it(self):
        docker = FakeDocker()
        code, lines = self.start(docker)
        self.assertEqual(code, 0, lines)
        run = [c for c in docker.calls if c[0][1] == "run"]
        self.assertEqual(len(run), 1)
        argv, env = run[0]
        secret = ner_secret.secret_of(make_backend(CONFIG), EP)
        self.assertEqual(len(secret), 43)
        self.assertEqual(env["NER_CLIENT_SECRET"], secret)
        self.assertIn("NER_CLIENT_SECRET", argv)
        self.assertNotIn(secret, " ".join(argv), "never on the command line, where ps shows it")
        self.assertNotIn(secret, "\n".join(lines))
        self.assertEqual(ner_secret.container_of(EP), CID)
        self.assertNotIn(secret, Path(HOME, "ner-containers.json").read_text(encoding="utf-8"))

    def test_the_container_maisecrets_set_up_is_started_again_and_checked(self):
        self.start(FakeDocker())
        before = ner_secret.secret_of(make_backend(CONFIG), EP)
        docker = FakeDocker(existing=CID)
        code, lines = self.start(docker)
        self.assertEqual((code, [c[0][1] for c in docker.calls]), (0, ["container", "start"]))
        self.assertIn("proves its secret", lines[0])
        self.assertEqual(ner_secret.secret_of(make_backend(CONFIG), EP), before, "the secret stays")

    def test_a_container_started_by_hand_is_left_alone_and_said_to_be_unchecked(self):
        docker = FakeDocker(existing="d00d" * 16)
        code, lines = self.start(docker)
        self.assertEqual([c[0][1] for c in docker.calls], ["container", "start"], "no rm, no run")
        self.assertIn("not checked", lines[0])
        self.assertEqual(ner_secret.secret_of(make_backend(CONFIG), EP), "")

    def test_a_container_ner_of_another_image_is_not_touched(self):
        docker = FakeDocker(existing="d00d" * 16, image="someone/else")
        code, _lines = self.start(docker)
        self.assertEqual((code, [c[0][1] for c in docker.calls]), (1, ["container"]))

    def test_a_secret_that_cannot_be_kept_removes_the_container_again(self):
        docker = FakeDocker()
        with mock.patch.object(ner_secret, "keep", side_effect=OSError("disk full")):
            code, lines = self.start(docker)
        self.assertEqual(code, 1)
        self.assertEqual([c[0][1:3] for c in docker.calls][-1], ["rm", "-f"])


class StoredSecretTests(unittest.TestCase):
    def setUp(self):
        _clean()
        self.addCleanup(_clean)

    def detector(self):
        cfg = dict(CONFIG, remote_detector={"url": "http://127.0.0.1:8765/", "format": "hf"})
        det, why = remote_layer.from_config(cfg)
        self.assertEqual(why, "")
        return det

    def test_without_a_recorded_start_the_store_is_not_asked_and_nothing_is_checked(self):
        with mock.patch.object(ner_secret, "secret_of", side_effect=AssertionError("the store was asked")):
            det = self.detector()
        self.assertEqual(det._RemoteDetector__secret, "")

    def test_after_a_start_the_detector_of_the_local_source_gets_the_secret(self):
        ner_secret.keep(make_backend(CONFIG), EP, "s" * 43, CID)
        self.assertEqual(self.detector()._RemoteDetector__secret, "s" * 43)

    def test_an_impostor_gets_its_own_note(self):
        status = remote_layer.remote.RemoteStatus("hf", "", "unavailable", "not_ours")
        remote_layer.note_result(remote_layer.Layer({}, status))
        with mock.patch.object(ner_setup, "claim_down_note", return_value=True):
            self.assertEqual(remote_layer.hint({"session_id": "S1"}), ner_setup.NOT_OURS_NOTE)
        remote_layer.note_result(remote_layer.Layer({}, remote_layer.remote.RemoteStatus("hf", "", "unavailable",
                                                                                         "timeout")))
        with mock.patch.object(ner_setup, "claim_down_note", return_value=True):
            self.assertEqual(remote_layer.hint({"session_id": "S1"}), ner_setup.DOWN_NOTE)


if __name__ == "__main__":
    unittest.main()
