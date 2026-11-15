"""#51: a user name in prose after a user cue (`for user`, `User … logged in`, `Welcome,`, `my username is`) and after a
user-id key, in the tool channel. Invented handles."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402


def scan(text: str, channel: str = "tool") -> list:
    active = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def users(text: str, channel: str = "tool") -> list:
    return [text[m.start:m.end] for m in scan(text, channel) if m.kind == "username-after-label"]


class UserNameAfterACueTests(unittest.TestCase):
    def test_each_cue_and_each_handle_shape(self):
        for text, value in (("a problem with the login process for user kalin.orbek. Additionally", "kalin.orbek"),
                            ("Login successful. Welcome, kalin_orb_42.\n", "kalin_orb_42"),
                            ("Details: User kalin.orbek successfully logged in from", "kalin.orbek"),
                            ("My username is korbek. I am", "korbek"),
                            ("including the user KOrbek7.\n", "KOrbek7"),
                            ("the user KalinOrbek has reported", "KalinOrbek"),
                            ("<userID>korbek7</userID>", "korbek7"),
                            ('{"login_name": "kalin.orbek"}', "kalin.orbek"),
                            ("[INFO] User plind88 logged in", "plind88"),
                            ("2026-11-15 10:00 user plind88 logged in", "plind88"),
                            ("Failed password for invalid user plind88 from", "plind88"),
                            ("Welcome back, kalin_orb_42!", "kalin_orb_42"),
                            ("Failed password for invalid user k.orbek from", "k.orbek"),
                            # #52: quoted values, key=value, systemd, sshd, sudo, pam, a plain word after a strong cue
                            ('auth failed for user "lhartmann7"', "lhartmann7"),
                            ("Access denied for user 'lhartmann7'@'10.0.0.5'", "lhartmann7"),
                            ("Login failed for user 'lhartmann7'.", "lhartmann7"),
                            ('User "lena.hartmann" cannot list resource "pods"', "lena.hartmann"),
                            ("ts=1 user=lhartmann7 action=login", "lhartmann7"),
                            ('User "KalinOrbek" logged in', "KalinOrbek"),
                            ("Started Session 3 of User kmorgan42.", "kmorgan42"),
                            ("Accepted password for kmorgan42 from 192.0.2.4 port 22", "kmorgan42"),
                            ("Failed publickey for k.morgan from 192.0.2.4 port 22", "k.morgan"),
                            ("sudo: kmorgan42 : TTY=pts/0 ; PWD=/home", "kmorgan42"),
                            ("GET /api?user=kmorgan42&page=2", "kmorgan42"),
                            ("Accepted publickey for jlindqvist from 192.0.2.4 port 22 ssh2", "jlindqvist"),
                            ("Accepted keyboard-interactive/pam for tvoss42 from 192.0.2.4", "tvoss42"),
                            ("Invalid user jlindqvist from 192.0.2.4 port 50122", "jlindqvist"),
                            ("Failed password for invalid user jlindqvist from 192.0.2.4", "jlindqvist"),
                            ("sudo: jlindqvist : TTY=pts/0 ; PWD=/home", "jlindqvist"),
                            ("sudo: jlindqvist : 3 incorrect password attempts ; TTY=pts/1", "jlindqvist"),
                            ("session opened for user kmorgan42(uid=1001) by (uid=0)", "kmorgan42"),
                            ("session opened for user root(uid=0) by kmorgan42(uid=1001)", "kmorgan42")):
            with self.subTest(text=text):
                self.assertIn(value, users(text))

    def test_code_roles_versions_and_placeholders_stay_text(self):
        for text in ("for user in users:", "for user.name in names", "the user_id column", "by user root",
                     "the user admin1", "Welcome, Admin.", "Welcome, user.", "User profile updated",
                     "User main_thread failed", "for user john.doe", "the user test_user", "for user api-service",
                     "<userID>12345</userID>", '{"handle": "true"}', "from user data.json", "the user user.email",
                     "My username is admin.", "for user service_account", "by user ci-runner",
                     "the user default_reader01", "for user x86_64", "Welcome, Python3.", "for user v1.2.3",
                     "the user my_app", "User KOrbek7 Settings", "My username is visible.",
                     '{"handle": "summer-collection"}', '{"handle": "zalto-glas"}', '{"screenName": "HomeScreen"}',
                     '{"userId": "usr_4f2a9c"}', "FATAL: password authentication failed for user analytics_ro",
                     "the user eu-west-2 region",
                     "Raises PermissionError for user AccessDenied", "// lookup by user UserRepository",
                     "Permission denied for user django_app", "the user utf-8 data", "for user sda1",
                     "the user eth0 interface", "by user pod-7f9c", "Welcome, JetBrains.",
                     "login for user SAML2 provider",
                     "My user name is in the config.", "the user eslint-plugin-react", '{"userId": "jenkins2"}',
                     '{"userId": "ftpuser2"}',
                     "session closed for user postgres2", "User ConfigManager failed", '{"userId": "kalinorbek"}',
                     '{"branch": "fix-orbek7"}', '{"handle": "kalin_orb_42"}', "for user e.g", "the user a.out",
                     "for user x.y", "session closed for user kibana8", "Requested by user codecov-commenter",
                     '{"userLogin": "jira-integration2"}', "user pgbouncer2 failed to authenticate",
                     "the user dashboard", "a user agent string", "for user preferences", 'user "admin" created',
                     "user=root", "user=$USER", "Failed password for root from 192.0.2.4", "sudo: deploy : TTY=pts/0",
                     "session opened for user root(uid=0) by (uid=0)", "Started Session 3 of User root.",
                     "the user interface of user settings", "user='postgres'", "by user system",
                     "from user input.", "Approved by user tkowalczyk", "Failed password for kmorgan42 to",
                     "sudo: kmorgan42 ran", "Started Session 3 of User kmorganx.",
                     "User=caddy", "GET /admin?user=dashboard HTTP/1.1", "Set the user 'profile' field",
                     "Access denied for user 'magento'@'localhost'", "Reset the password for profile42 from the page",
                     "sudo: kmorgan42 : command not found",
                     "Accepted publickey for ubuntu from 192.0.2.4", "Accepted publickey for borgbackup from 192.0.2.4",
                     "Invalid user admin from 192.0.2.4", "Failed password for root from 192.0.2.4",
                     "sudo: deploy : TTY=pts/0", "Accepted publickey for Jdoe from 192.0.2.4",
                     "Accepted publickey for git from 192.0.2.4", "accepted the password for review from the team",
                     "owned by polkitd(uid=998)", "nearby kmorgan42(uid=1)",
                     "for user 'magento2'@'localhost'",
                     "session closed for user telegraf1",
                     "by kmorgan42 for sshd(uid=0)"):
            with self.subTest(text=text):
                self.assertEqual([], users(text))

    def test_a_typed_prompt_keeps_its_rules(self):
        self.assertEqual([], users("for user kalin.orbek today", "prompt"))


if __name__ == "__main__":
    unittest.main()
