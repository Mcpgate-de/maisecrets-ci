"""scripts/notify_website.py: the website's data file gets the version, date and user notes of a release.

Run: python3 -m unittest tests.test_notify_website -v
"""
from __future__ import annotations

import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import notify_website as W  # noqa: E402

CHANGELOG = """# Changelog

## Unreleased

## [0.8.30] - 2026-11-08

### API

- Detector.label_names_a_number(label) -> bool (new) (c3363be)

### Features

- a caller can ask whether a field label can make a number personal data (c3363be)

### Fixes

- a content digest after a token label is no longer masked (c1d03fc)
- the user's 'own' rules load again. (abcdef1)
- leaves.label reads a list index as an index (5252f14)

## [0.8.29] - 2026-11-07

### Fixes

- an older fix (4f308ac)
"""

DATA = """/** Release status. */
export interface MsVersion { version: string; date: string }

/** The current release. */
export const msRelease: MsVersion = { version: '0.8.29', date: '2026-11-07' };

export const msReleaseNotes = {
  version: '0.8.29',
  points: [
    'An older fix.',
  ],
};

export const msDirectory = { version: '0.5.9', published: '2026-09-30' };
"""


class NotifyWebsiteTests(unittest.TestCase):
    def test_the_section_of_a_release_gives_its_date_and_user_points(self):
        date, points = W.release_section(CHANGELOG, "0.8.30")
        self.assertEqual(date, "2026-11-08")
        self.assertEqual(points, ["A caller can ask whether a field label can make a number personal data.",
                                  "A content digest after a token label is no longer masked.",
                                  "The user's 'own' rules load again.",
                                  "leaves.label reads a list index as an index."])
        with self.assertRaises(SystemExit):
            W.release_section(CHANGELOG, "0.9.0")

    def test_the_data_file_gets_the_version_and_date_and_keeps_every_other_line(self):
        date, _points = W.release_section(CHANGELOG, "0.8.30")
        new = W.rewrite(DATA, "0.8.30", date)
        self.assertEqual(W.current_version(new), "0.8.30")
        self.assertIn("export const msRelease: MsVersion = { version: '0.8.30', date: '2026-11-08' };", new)
        # the notes stay in the changelog: the job leaves the notes block as it is
        self.assertIn("    'An older fix.',\n", new)
        self.assertNotIn("A caller can ask", new)
        self.assertIn("export const msDirectory = { version: '0.5.9', published: '2026-09-30' };", new)
        self.assertTrue(new.startswith("/** Release status. */\nexport interface MsVersion"))

    def test_a_data_file_without_the_blocks_is_refused(self):
        with self.assertRaises(SystemExit):
            W.rewrite("export const other = 1;\n", "0.8.30", "2026-11-08")

    def test_without_the_deploy_key_nothing_is_done(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"MAISECRETS_WEBSITE_DEPLOY_KEY": "", "CI_COMMIT_TAG": "v0.7.2"}), \
                mock.patch.object(W.subprocess, "run", side_effect=AssertionError("no git without a key")), \
                redirect_stdout(out):
            self.assertEqual(W.main(), 0)
        self.assertIn("no website deploy key", out.getvalue())

    def test_ssh_gets_a_copy_of_the_key_that_only_the_owner_reads(self):
        # GitLab writes a file variable with mode 0644, and ssh refused the key (the 0.9.0 and 0.9.1 release jobs)
        import stat
        import subprocess
        import tempfile
        key = Path(tempfile.mkdtemp()) / "key"
        key.write_text("not a real key\n")
        key.chmod(0o644)
        seen = []

        def run(args, **kw):
            path = kw["env"]["GIT_SSH_COMMAND"].split()[2]
            seen.append((path, stat.S_IMODE(os.stat(path).st_mode), Path(path).read_text()))
            return subprocess.CompletedProcess(args, 1, "", "stopped by the test")
        with mock.patch.dict(os.environ, {"MAISECRETS_WEBSITE_DEPLOY_KEY": str(key), "CI_COMMIT_TAG": "v0.7.2"}), \
                mock.patch.object(W.subprocess, "run", side_effect=run), redirect_stdout(io.StringIO()):
            try:
                W.main()
            except SystemExit:
                pass
        self.assertTrue(seen, "git ran")
        path, mode, text = seen[0]
        self.assertNotEqual(path, str(key))
        if os.name != "nt":                   # Windows has no owner-only mode; the job runs on Linux
            self.assertEqual(mode, 0o600)
        self.assertEqual(text, "not a real key\n")


if __name__ == "__main__":
    unittest.main()
