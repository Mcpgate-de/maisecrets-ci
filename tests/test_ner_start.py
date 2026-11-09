"""`run.sh ner start` and the stored secret of the name service (#1699): the container gets a secret it must prove
before each text; the secret reaches docker in the environment, never on the command line, and lives in the store;
a container the person started by hand is left alone and runs unchecked. Docker is a fake here; the store is the
temp file store of tests/_isolate.py."""
from __future__ import annotations

import json
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
    # the file store of the tests: never the keychain, also for code that reads the config itself (ner_setup.report)
    Path(HOME, "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")
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
        self.assertEqual(argv[-1], ner_setup.SECRET_IMAGE, "a fixed tag that proves: an old latest would not")
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
        self.assertEqual(docker.calls[-1][0][1:], ["rm", "-f", CID], "by its id, not the name ner")


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

    def test_a_recorded_container_of_an_old_image_is_named_as_too_old(self):
        ner_secret.keep(make_backend(CONFIG), EP, "s" * 43, CID)
        conf = {"url": ner_setup.LOCAL_URL, "format": "hf"}
        with mock.patch.object(ner_setup, "probe", return_value=(True, "the service: answers")):
            with mock.patch.object(ner_setup, "_info", return_value={"model": "m"}):
                code, lines = ner_setup.report(conf)
            self.assertEqual(code, 1)
            self.assertIn("older than " + ner_setup.FIRST_SECRET_IMAGE, lines[-1])
            with mock.patch.object(ner_setup, "_info", return_value={"client_secret": True}):
                with mock.patch.object(ner_setup, "_proves", return_value=True), \
                        mock.patch.object(ner_setup, "container_tool", return_value=""):
                    code, lines = ner_setup.report(conf)
                self.assertEqual((code, lines[-1][:8]), (0, "checked:"))
                with mock.patch.object(ner_setup, "_proves", return_value=False):
                    code, lines = ner_setup.report(conf)
                self.assertEqual(code, 1)
                self.assertIn("is not the container that maisecrets started", lines[-1])

    def test_a_recorded_container_whose_secret_is_lost_gets_no_text(self):
        # the record without the secret: closed, not open (codex review of #1699)
        ner_secret.keep(make_backend(CONFIG), EP, "s" * 43, CID)
        make_backend(CONFIG).delete(ner_secret.PREFIX + EP.replace(":", "_"))
        det = self.detector()
        self.assertTrue(det._RemoteDetector__secret, "a check stays on")
        self.assertNotEqual(det._RemoteDetector__secret, "s" * 43)
        with mock.patch.object(ner_setup, "probe", return_value=(True, "the service: answers")):
            code, lines = ner_setup.report({"url": ner_setup.LOCAL_URL, "format": "hf"})
        self.assertEqual(code, 1)
        self.assertIn("cannot be read", lines[-1])

    def test_an_impostor_gets_its_own_note(self):
        status = remote_layer.remote.RemoteStatus("hf", "", "unavailable", "not_ours")
        remote_layer.note_result(remote_layer.Layer({}, status))
        with mock.patch.object(ner_setup, "claim_down_note", return_value=True):
            self.assertEqual(remote_layer.hint({"session_id": "S1"}), ner_setup.NOT_OURS_NOTE)
        remote_layer.note_result(remote_layer.Layer({}, remote_layer.remote.RemoteStatus("hf", "", "unavailable",
                                                                                         "timeout")))
        with mock.patch.object(ner_setup, "claim_down_note", return_value=True):
            note = remote_layer.hint({"session_id": "S1"})
        self.assertEqual(note, ner_setup.DOWN_NOTE.format(why="no answer in time"))
        self.assertIn("(no answer in time)", note)


OLD = "mcpgate/ner:v2.0.3584"
OLD_ID = "sha256:" + "a" * 64
PIN_ID = "sha256:" + "b" * 64
NEW_CID = "beef" * 16


class FollowDocker:
    """docker as follow_pin calls it, with containers by name: inspect, image inspect, pull, stop, rename, rm, run,
    rmi, start; every call is kept."""

    def __init__(self, image=OLD, running="true", pull_rc=0, run_rcs=(0,), image_id=OLD_ID):
        self.containers = {"ner": [CID, running, image_id, image]}
        self.pull_rc, self.run_rcs, self.calls = pull_rc, list(run_rcs), []

    def find(self, ref):
        for name, c in self.containers.items():
            if ref in (name, c[0]):
                return name
        return None

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw.get("env")))
        verb, ok = argv[1], subprocess.CompletedProcess
        if verb == "container":
            name = self.find(argv[-1])
            return ok(argv, 0, " ".join(self.containers[name]) + "\n", "") if name else ok(argv, 1, "", "no such")
        if verb == "image":
            return ok(argv, 0, PIN_ID + "\n", "") if argv[-1] == ner_setup.SECRET_IMAGE else ok(argv, 1, "", "")
        if verb == "pull":
            return ok(argv, self.pull_rc, "", "")
        if verb == "rename":
            name = self.find(argv[2])
            if name:
                self.containers[argv[3]] = self.containers.pop(name)
            return ok(argv, 0, "", "")
        if verb == "rm":
            name = self.find(argv[-1])
            if name:
                del self.containers[name]
            return ok(argv, 0, "", "")
        if verb in ("stop", "start"):
            name = self.find(argv[-1])
            if name:
                self.containers[name][1] = "false" if verb == "stop" else "true"
            return ok(argv, 0, "", "")
        if verb == "run":
            rc = self.run_rcs.pop(0) if self.run_rcs else 0
            if rc == 0:
                self.containers["ner"] = [NEW_CID, "true", PIN_ID, argv[-1]]
            return ok(argv, rc, NEW_CID + "\n" if rc == 0 else "", "boom")
        return ok(argv, 0, "", "")

    def verbs(self):
        return [c[0][1] for c in self.calls]


class FollowPinTests(unittest.TestCase):
    """The image of a container maisecrets set up follows the pin of the plugin version, at a session start, in the
    background: a release that moves SECRET_IMAGE reaches every person who runs the local service. Only forward, and
    the old container is removed only after the new one proved the secret."""

    def setUp(self):
        _clean()
        self.addCleanup(_clean)
        Path(HOME, "ner-update.json").unlink(missing_ok=True)
        self.addCleanup(Path(HOME, "ner-update.json").unlink, True)

    def follow(self, docker, conf=None, kept=True, proves=True):
        if kept:
            ner_secret.keep(make_backend(CONFIG), EP, "s" * 43, CID)
        with mock.patch.object(ner_setup.subprocess, "run", docker), \
                mock.patch.object(ner_setup, "_proves", return_value=proves), \
                mock.patch.object(ner_setup, "PROOF_WAIT_S", 0):
            return ner_setup.follow_pin("/usr/bin/docker", conf if conf is not None else {"url": ner_setup.LOCAL_URL})

    def test_an_old_image_gets_the_pinned_one_with_the_same_secret(self):
        docker = FollowDocker()
        self.assertEqual(self.follow(docker), "updated")
        self.assertEqual(docker.verbs(), ["container", "pull", "stop", "rename", "run", "rm", "image", "rmi"])
        calls = {c[0][1]: c for c in docker.calls}
        self.assertEqual(calls["pull"][0][-1], ner_setup.SECRET_IMAGE)
        self.assertEqual(calls["rename"][0][2:], [CID, ner_setup.PREV])
        self.assertEqual(calls["run"][0][-1], ner_setup.SECRET_IMAGE)
        self.assertEqual(calls["run"][1]["NER_CLIENT_SECRET"], "s" * 43, "the same secret, in the environment")
        self.assertNotIn("s" * 43, " ".join(calls["run"][0]))
        self.assertEqual(calls["rm"][0][-1], CID, "the old container goes only after the proof")
        self.assertEqual(calls["rmi"][0][-1], OLD_ID, "the old image goes")
        self.assertEqual(ner_secret.container_of(EP), NEW_CID)
        self.assertEqual(sorted(docker.containers), ["ner"])
        self.assertEqual(ner_secret.secret_of(make_backend(CONFIG), EP), "s" * 43)

    def test_a_failed_pull_leaves_the_container_as_it_is(self):
        docker = FollowDocker(pull_rc=1)
        self.assertEqual(self.follow(docker), "running")
        self.assertEqual(docker.verbs(), ["container", "pull"])
        self.assertEqual(ner_secret.container_of(EP), CID)

    def test_a_new_image_that_does_not_prove_the_secret_brings_the_old_one_back(self):
        for run_rcs, proves in (((1,), True), ((0,), False)):
            with self.subTest(run_rcs=run_rcs, proves=proves):
                _clean()
                Path(HOME, "ner-update.json").unlink(missing_ok=True)
                docker = FollowDocker(run_rcs=run_rcs)
                self.assertEqual(self.follow(docker, proves=proves), "kept")
                self.assertEqual(docker.containers, {"ner": [CID, "true", OLD_ID, OLD]}, "the old one, running")
                self.assertEqual(ner_secret.container_of(EP), CID)
                self.assertNotIn("rmi", docker.verbs(), "the old image stays")
                # this pin waits a day: the next session start does not try again
                again = FollowDocker()
                self.assertEqual(self.follow(again, kept=False), "running")
                self.assertNotIn("pull", again.verbs())

    def test_an_update_that_ended_halfway_is_put_back(self):
        docker = FollowDocker()
        docker.containers = {ner_setup.PREV: [CID, "false", OLD_ID, OLD]}
        self.assertEqual(self.follow(docker), "recovered")
        self.assertEqual(docker.containers, {"ner": [CID, "true", OLD_ID, OLD]})
        stray = FollowDocker()
        stray.containers = {ner_setup.PREV: ["0ther" * 12, "false", OLD_ID, OLD]}
        self.assertEqual(self.follow(stray), "none", "a ner-prev that is not ours stays as it is")

    def test_a_newer_image_is_never_taken_back(self):
        # an older plugin version in an open session pins an older image than the one that runs (Opus review)
        for image in ("mcpgate/ner:v2.0.9999@sha256:" + "c" * 64, "mcpgate/ner:v2.1.0", "mcpgate/ner",
                      "mcpgate/ner@sha256:" + "c" * 64):
            with self.subTest(image=image):
                _clean()
                docker = FollowDocker(image=image, image_id="sha256:" + "c" * 64)
                self.assertEqual(self.follow(docker), "running")
                self.assertNotIn("pull", docker.verbs())

    def test_the_same_tag_with_another_digest_is_updated_and_the_pinned_one_is_not(self):
        tag = ner_setup.SECRET_IMAGE.split("@")[0]
        for image, image_id, outcome in ((tag, OLD_ID, "updated"), (tag, PIN_ID, "running"),
                                         (ner_setup.SECRET_IMAGE, PIN_ID, "running"),
                                         ("docker.io/" + ner_setup.SECRET_IMAGE, PIN_ID, "running")):
            with self.subTest(image=image, image_id=image_id):
                _clean()
                docker = FollowDocker(image=image, image_id=image_id)
                self.assertEqual(self.follow(docker), outcome)

    def test_a_stopped_container_starts_before_any_download(self):
        docker = FollowDocker(running="false")
        self.assertEqual(self.follow(docker), "updated")
        self.assertEqual(docker.verbs()[:3], ["container", "start", "pull"])

    def test_updates_off_keeps_the_image_and_still_starts_a_stopped_container(self):
        docker = FollowDocker(running="false")
        self.assertEqual(self.follow(docker, {"url": ner_setup.LOCAL_URL, "auto_update": False}), "started")
        self.assertEqual(docker.verbs(), ["container", "start"])

    def test_a_container_started_by_hand_or_of_another_image_is_never_replaced(self):
        other = FollowDocker()
        other.containers["ner"][0] = "0ther" * 12      # a secret is kept, but for another container than this one
        for docker, kept, outcome in ((FollowDocker(), False, "running"), (other, True, "running"),
                                      (FollowDocker(image="evil/ner"), True, "foreign"),
                                      (FollowDocker(image="mcpgate/nerx"), True, "foreign")):
            with self.subTest(image=docker.containers["ner"][3], kept=kept):
                _clean()
                self.assertEqual(self.follow(docker, kept=kept), outcome)
                self.assertNotIn("pull", docker.verbs())
                self.assertNotIn("rm", docker.verbs())

    def test_no_container_and_a_session_that_holds_the_lock(self):
        docker = FollowDocker()
        docker.containers = {}
        self.assertEqual(self.follow(docker), "none")
        from maisecrets.home import _Lock
        with _Lock(Path(HOME, ".ner-update.lock")):
            fresh = FollowDocker()
            self.assertEqual(self.follow(fresh), "busy")
            self.assertEqual(fresh.calls, [])

    def test_run_sh_ner_start_waits_for_an_update_that_runs(self):
        from maisecrets.home import _Lock
        with _Lock(Path(HOME, ".ner-update.lock")), \
                mock.patch.object(ner_setup, "container_tool", lambda: "/usr/bin/docker"), \
                mock.patch.object(ner_setup.subprocess, "run", side_effect=AssertionError("docker was called")):
            with mock.patch.object(ner_setup, "START_WAIT_S", 0.1):
                code, lines = ner_setup.start_local(CONFIG)
        self.assertEqual(code, 1)
        self.assertIn("updating the image", lines[0])

    def test_the_status_names_the_image_against_the_pin(self):
        ner_secret.keep(make_backend(CONFIG), EP, "s" * 43, CID)
        pinned = ner_setup.SECRET_IMAGE.split("@")[0].rpartition(":")[2]
        cases = ((ner_setup.SECRET_IMAGE, CID, {}, f"image: {pinned}, the one this version pins"),
                 (OLD, CID, {}, f"image: v2.0.3584; this version pins {pinned}, and the next session start updates it"),
                 (OLD, CID, {"auto_update": False}, "updates off: /maisecrets:ner updates on"),
                 (OLD, NEW_CID, {}, "the container was not set up by maisecrets, so it is not updated"),
                 ("mcpgate/ner:v2.0.9999", CID, {}, "an older one, so it stays"),
                 ("evil/ner", CID, {}, ""))
        for image, cid, extra, want in cases:
            with self.subTest(image=image, cid=cid, extra=extra):
                docker = FollowDocker(image=image)
                docker.containers["ner"][0] = cid
                with mock.patch.object(ner_setup.subprocess, "run", docker):
                    line = ner_setup.image_line({"url": ner_setup.LOCAL_URL, **extra}, "/usr/bin/docker")
                if want:
                    self.assertIn(want, line)
                else:
                    self.assertEqual(line, "")
        ner_setup._note_update(failed=True)
        docker = FollowDocker()
        with mock.patch.object(ner_setup.subprocess, "run", docker):
            self.assertIn("did not start", ner_setup.image_line({"url": ner_setup.LOCAL_URL}, "/usr/bin/docker"))

    def test_updates_off_is_typed_and_recorded_as_a_weakening(self):
        from maisecrets import settings
        self.assertEqual(ner_setup.parse("/maisecrets:ner updates off"), "updates:off")
        self.assertEqual(ner_setup.parse("/maisecrets:ner updates on"), "updates:on")
        conf = {"url": ner_setup.LOCAL_URL, "format": "hf"}
        off = ner_setup.updated(conf, "updates:off")
        self.assertEqual(off["auto_update"], False)
        self.assertEqual(ner_setup.updated(off, "local")["auto_update"], False, "it stays when the source changes")
        self.assertNotIn("auto_update", ner_setup.updated(off, "updates:on"))
        self.assertTrue(settings.loosens("remote_detector", conf, off))
        self.assertFalse(settings.loosens("remote_detector", off, ner_setup.updated(off, "updates:on")))

if __name__ == "__main__":
    unittest.main()
