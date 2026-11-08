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

    def test_the_data_file_gets_the_release_and_keeps_every_other_line(self):
        date, points = W.release_section(CHANGELOG, "0.8.30")
        new = W.rewrite(DATA, "0.8.30", date, points)
        self.assertEqual(W.current_version(new), "0.8.30")
        self.assertIn("export const msRelease: MsVersion = { version: '0.8.30', date: '2026-11-08' };", new)
        self.assertIn("  version: '0.8.30',\n  points: [\n    'A caller can ask", new)
        self.assertIn("    'The user\\'s \\'own\\' rules load again.',\n", new)
        self.assertNotIn("An older fix.", new)
        self.assertIn("export const msDirectory = { version: '0.5.9', published: '2026-09-30' };", new)
        self.assertTrue(new.startswith("/** Release status. */\nexport interface MsVersion"))

    def test_a_data_file_without_the_blocks_is_refused(self):
        with self.assertRaises(SystemExit):
            W.rewrite("export const other = 1;\n", "0.8.30", "2026-11-08", [])

    def test_without_the_deploy_key_nothing_is_done(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"MAISECRETS_WEBSITE_DEPLOY_KEY": "", "CI_COMMIT_TAG": "v0.8.30"}), \
                mock.patch.object(W.subprocess, "run", side_effect=AssertionError("no git without a key")), \
                redirect_stdout(out):
            self.assertEqual(W.main(), 0)
        self.assertIn("no website deploy key", out.getvalue())

    def test_a_key_file_readable_by_others_is_used_from_a_private_copy(self):
        # GitLab writes a file variable with mode 0644, and ssh refused it (the tag pipeline of 0.9.0)
        import stat
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            key = Path(d, "key")
            key.write_text("synthetic-key-text\n")
            key.chmod(0o644)
            work = Path(d, "work")
            work.mkdir()
            env = W._ssh_env(str(key), Path("/known"), str(work))
            used = env["GIT_SSH_COMMAND"].split("-i ", 1)[1].split(" ", 1)[0]
            self.assertNotEqual(used, str(key))
            self.assertEqual(stat.S_IMODE(os.stat(used).st_mode), 0o600)
            self.assertEqual(Path(used).read_text(), "synthetic-key-text\n")


if __name__ == "__main__":
    unittest.main()
