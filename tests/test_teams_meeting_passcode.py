"""The passcode of a Microsoft Teams meeting in its join link: https://teams.microsoft.com/meet/<id>?p=<passcode>. The
link alone lets anyone join, and the passcode reached the model in clear (field case, 2026-11-08).

Run: python3 -m unittest tests.test_teams_meeting_passcode -v
Every value is made up and built at run time, so no literal sits in the tree.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

RULE = "secret-teams-meeting-passcode"
MEETING = "1111" + "2222" + "3333" + "4444"
PASSCODE = "Demo" + "PassCode1234xy"
LINK = "https://teams.microsoft.com/meet/" + MEETING + "?p="


def hits(text: str, channel: str = "tool") -> list:
    return [(m.kind, text[m.start:m.end]) for m in detect.scan(text, channel=channel)]


class TeamsMeetingPasscodeTests(unittest.TestCase):
    def test_the_passcode_of_a_join_link_is_found_and_the_meeting_id_is_not(self):
        for text in ("Join the meeting: " + LINK + PASSCODE + "\n",
                     "<" + LINK + PASSCODE + ">",
                     "https://teams.microsoft.com/meet/" + MEETING + "?anon=true&p=" + PASSCODE + "&lang=de",
                     '{"joinUrl": "' + LINK + PASSCODE + '"}'):
            for channel in ("tool", "prompt"):
                with self.subTest(text=text[:30], channel=channel):
                    found = hits(text, channel)
                    self.assertIn((RULE, PASSCODE), found)
                    self.assertFalse([v for _, v in found if MEETING in v], found)

    def test_a_p_parameter_of_another_link_is_no_teams_passcode(self):
        for text in ("https://example.com/meet/" + MEETING + "?p=" + PASSCODE,
                     "https://teams.microsoft.com/l/meetup-join/19%3ameeting?p=" + PASSCODE,
                     "https://teams.microsoft.com/meet/" + MEETING + "?page=" + PASSCODE):
            with self.subTest(text=text[:40]):
                self.assertNotIn(RULE, [k for k, _ in hits(text)])


if __name__ == "__main__":
    unittest.main()
