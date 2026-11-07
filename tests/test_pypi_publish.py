"""scripts/pypi_publish.py: a published version is never replaced, and the files to publish are the ones built.

Run: python3 -m unittest tests.test_pypi_publish -v
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pypi_publish as P  # noqa: E402


def dist(files: dict, sums: dict | None = None) -> Path:
    d = Path(tempfile.mkdtemp(prefix="pypi-dist-"))
    for name, body in files.items():
        (d / name).write_bytes(body)
    sums = sums if sums is not None else {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}
    (d / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sums.items()))
    return d


FILES = {"maisecrets-0.8.26-py3-none-any.whl": b"wheel", "maisecrets-0.8.26.tar.gz": b"sdist"}


class PublishTests(unittest.TestCase):
    def test_a_version_on_the_index_is_never_replaced(self):
        built = P.built_files(dist(FILES))
        self.assertEqual(P.decide(built, None), "upload")
        self.assertEqual(P.decide(built, dict(built)), "done", "a rerun of the same tag with the same files")
        self.assertEqual(P.decide(built, {**built, "maisecrets-0.8.26.tar.gz": "0" * 64}), "conflict")
        self.assertEqual(P.decide(built, {"maisecrets-0.8.26-py3-none-any.whl": "1" * 64}), "conflict")
        # a partial upload (the wheel went up, the sdist did not) is completed by a rerun, never replaced
        self.assertEqual(P.decide(built, {"maisecrets-0.8.26-py3-none-any.whl": built[
            "maisecrets-0.8.26-py3-none-any.whl"]}), "upload")
        self.assertEqual(P.version_of(built), "0.8.26")

    def test_files_that_are_not_the_build_are_refused(self):
        with self.assertRaises(SystemExit):
            P.built_files(dist(FILES, {n: "f" * 64 for n in FILES}))
        with self.assertRaises(SystemExit):
            P.built_files(dist({"maisecrets-0.8.26-py3-none-any.whl": b"wheel"}))   # no sdist
        with self.assertRaises(SystemExit):
            P.version_of(P.built_files(dist({"maisecrets-0.8.26-py3-none-any.whl": b"w",
                                             "maisecrets-0.8.25.tar.gz": b"s"})))


class TokenSourceTests(unittest.TestCase):
    def test_a_ci_run_that_is_no_tag_pipeline_publishes_nothing(self):
        cases = [({"CI_COMMIT_TAG": "v1.2.3"}, "v1.2.3"),
                 ({"GITHUB_ACTIONS": "true", "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.2.3"}, "v1.2.3"),
                 ({}, "")]
        for env, want in cases:
            with self.subTest(env=env), mock.patch.dict("os.environ", env, clear=True):
                self.assertEqual(P.ci_tag(), want)
        for env in ({"GITHUB_ACTIONS": "true", "GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main"},
                    {"CI": "true"}):
            with self.subTest(env=env), mock.patch.dict("os.environ", env, clear=True):
                with self.assertRaises(SystemExit):
                    P.ci_tag()

    def test_the_github_token_is_asked_with_the_audience_of_the_index(self):
        import io
        import json as _json
        seen = {}

        def fake_open(req, timeout):
            seen["url"], seen["auth"] = req.full_url, req.headers.get("Authorization")
            return io.BytesIO(_json.dumps({"value": "oidc-token-of-the-test"}).encode())
        env = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://gh.example/token?api-version=2.0",
               "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "bearer-of-the-test"}
        with mock.patch.dict("os.environ", env, clear=True), mock.patch.object(P.urllib.request, "urlopen", fake_open):
            self.assertEqual(P.github_id_token("testpypi"), "oidc-token-of-the-test")
        self.assertEqual(seen, {"url": "https://gh.example/token?api-version=2.0&audience=testpypi",
                                "auth": "bearer bearer-of-the-test"})
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(P.github_id_token("pypi"), "", "outside a GitHub job")



class AttestationTests(unittest.TestCase):
    """On GitHub Actions each file is signed and uploaded with its attestation (PEP 740 provenance)."""

    def run_main(self, env: dict) -> list:
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return mock.Mock(returncode=0)
        with mock.patch.dict("os.environ", env, clear=True), \
                mock.patch.object(P.subprocess, "run", fake_run), \
                mock.patch.object(P, "published", lambda *a: None), \
                mock.patch.object(P, "mint_token", lambda *a: "upload-token"), \
                mock.patch.object(P, "github_id_token", lambda *a: "id-token"), \
                mock.patch.object(P, "wait_listed", lambda *a: None), \
                mock.patch.object(P, "install_and_probe", lambda *a: None):
            self.assertEqual(P.main(["--index", "testpypi", str(dist(FILES))]), 0)
        return calls

    def test_github_signs_the_files_and_uploads_the_attestations(self):
        calls = self.run_main({"GITHUB_ACTIONS": "true", "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v0.8.26"})
        sign = [c for c in calls if "pypi_attestations" in c]
        upload = [c for c in calls if "twine" in c]
        self.assertEqual(len(sign), 1)
        self.assertEqual(sorted(Path(f).name for f in sign[0][4:]), sorted(FILES))
        self.assertIn("--attestations", upload[0])
        # twine takes an attestation only from its arguments, next to its file
        self.assertEqual(sorted(Path(f).name for f in upload[0] if f.endswith(".publish.attestation")),
                         sorted(n + ".publish.attestation" for n in FILES))
        self.assertLess(calls.index(sign[0]), calls.index(upload[0]), "signed before the upload")

    def test_gitlab_uploads_without_attestations(self):
        calls = self.run_main({"GITLAB_CI": "true", "CI_COMMIT_TAG": "v0.8.26", "TESTPYPI_ID_TOKEN": "id-token"})
        self.assertFalse([c for c in calls if "pypi_attestations" in c])
        self.assertNotIn("--attestations", [c for c in calls if "twine" in c][0])


if __name__ == "__main__":
    unittest.main()
