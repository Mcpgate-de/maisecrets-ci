"""Fields of an API answer that a label rule read as a secret (gateway field report, 2026-10-29): a paging cursor or
a file key after a label with `token` or `key` in it, a time or a state after a label with a secret word, and a
version in four parts read as an address. Each class keeps its true hits: a credential label still masks.

Run: python3 -m unittest tests.test_api_answer_fields -v
Every value is generated at run time from a seeded generator, so no literal sits in the tree.
"""
from __future__ import annotations

import base64
import os
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

RNG = random.Random(29)
B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def opaque() -> list:
    """Three shapes of an opaque handle: hex, base62 and base64url; the same three on each call, and each one a hit
    after `api_key: ` (the premise of every test below that expects a hit)."""
    rng = random.Random(30)
    return ["".join(rng.choice("0123456789abcdef") for _ in range(40)),
            "".join(rng.choice(B62) for _ in range(22)),
            base64.urlsafe_b64encode(bytes(rng.getrandbits(8) for _ in range(32))).decode().rstrip("=")]


def kinds_after(label: str, value: str) -> set:
    text = f"{label}: {value}"
    return {m.kind for m in detect.scan(text, channel="tool") if m.end > len(label) + 2}


class CursorAndFileKeyTests(unittest.TestCase):
    def test_the_values_are_hits_after_a_credential_label(self):
        for value in opaque():
            with self.subTest(shape=len(value)):
                self.assertTrue(kinds_after("api_key", value))

    def test_a_cursor_or_a_file_key_is_no_secret(self):
        for label in ("nextPageToken", "pageToken", "syncToken", "purchaseToken",
                      "nextSequenceToken", "NextContinuationToken", "cursorToken", "paginationToken",
                      "APIContinuationToken", "continueToken", "rewriteToken", '"next_page_token"', "fileKey",
                      '"file_key"',
                      '"node_key"'):
            for value in opaque():
                with self.subTest(label=label, shape=len(value)):
                    self.assertEqual(kinds_after(label, value), set())

    def test_a_credential_label_still_masks(self):
        for label in ("token", "secret", "api_key", "apiKey", "access_token", "secret_key", "private_key",
                      "client_secret", "auth_token", "refresh_token", "session_token", "PrevAuthToken",
                      "nextAuthToken", "profile_key", "private_file_key", "token_candidate", "password_update",
                      "secret_at", "api_key_on", "purchaseAccessToken", "assetAuthToken", "syncRefreshToken",
                      "nextAuthToken", "NextToken", "GITHUB_SYNC_TOKEN", "repo_sync_token", "CDN_ASSET_TOKEN",
                      "PAGE_TOKEN", "file_key", "Key rotated", "Secret updated", "Primary key"):
            for value in opaque()[1:]:    # a hex value also needs the entropy floor of its alphabet
                with self.subTest(label=label, shape=len(value)):
                    self.assertTrue(kinds_after(label, value))


class FieldsArgumentTests(unittest.TestCase):
    """A host that passes the field name with `fields=` (the gateway) gets the same answer as with a label prefix."""

    def test_a_cursor_a_file_key_a_time_and_a_version_given_as_fields_are_no_finding(self):
        det = detect.Detector()
        for name, value in (("file_key", opaque()[1]), ("purchaseToken", opaque()[2]), ("NextToken", opaque()[1]),
                            ("lastPasswordChangeDateTime", "2026-10-28T09:14:03Z")):
            with self.subTest(name=name):
                self.assertEqual(det.findings(value, channel="tool", fields=[(0, len(value), (name,))]), [])

    def test_a_field_takes_no_hit_of_the_bare_value_away(self):
        # docs/DETECTION.md: fields= adds hits and never takes one away, so a version under a field `version` that the
        # bare value reads as an address stays a hit; a host puts the label before the value for that
        det = detect.Detector()
        value = ".".join(str(n) for n in (85, 214, 17, 3))
        self.assertTrue(det.findings(value, channel="tool", fields=[(0, len(value), ("version",))]))
        self.assertEqual([m for m in detect.scan(f"version: {value}", channel="tool") if m.type == "IP"], [])

    def test_a_credential_given_as_a_field_is_found(self):
        det = detect.Detector()
        value = opaque()[1]
        self.assertTrue(det.findings(value, channel="tool", fields=[(0, len(value), ("api_key",))]))


class FieldLabelTests(unittest.TestCase):
    def test_the_label_of_a_field_follows_its_words(self):
        from maisecrets.detection import fields
        for name, label in ((("customer", "telefon"), "telefon"), (("items", 3), "items"), (("key",), ""),
                            (("data", "nextPageToken"), ""), (("file", "purchaseToken"), ""),
                            (("PrevAuthToken",), "PrevAuthToken"), (("token",), "token"), (("a:b",), "")):
            with self.subTest(name=name):
                got = fields.checked("v", [(0, 1, name)])
                self.assertEqual(got[0][2] if got else "", label)

    def test_a_credential_under_a_bare_token_field_is_found(self):
        det = detect.Detector()
        value = "".join(RNG.choice("0123456789abcdef") for _ in range(64))
        self.assertEqual(detect.scan(value, channel="tool"), [], "the premise: the bare value is no hit")
        self.assertTrue(det.findings(value, channel="tool", fields=[(0, len(value), ("token",))]))

    def test_findings_with_a_whole_text_field_is_the_two_scan_result(self):
        det = detect.Detector()
        for name, value in (("api_key", opaque()[1]), ("telefon", "0171 4829173"), ("version", "4.2.17.3")):
            with self.subTest(name=name):
                spans = [(0, len(value), (name,))]
                one = det.findings(value, channel="tool", fields=spans)
                from maisecrets.detection import fields
                two = fields.added(value, detect.scan(value, channel="tool"), fields.checked(value, spans),
                                   lambda t: detect.scan(t, channel="tool"))
                self.assertEqual([(m.kind, m.start, m.end) for m in one], [(m.kind, m.start, m.end) for m in two])

    def test_a_field_over_the_whole_text_scans_once(self):
        from maisecrets.detection import fields
        calls = []

        def scan(t):
            calls.append(t)
            return detect.scan(t, channel="tool")
        value = opaque()[1]
        hits = detect.scan(value, channel="tool")
        out = fields.added(value, hits, fields.checked(value, [(0, len(value), ("api_key",))]), scan, same_scan=True)
        self.assertEqual(calls, [f"api_key: {value}"])
        self.assertTrue(out)


class TimeAndStateTests(unittest.TestCase):
    def test_a_time_or_a_state_after_a_secret_word_is_no_value(self):
        for label in ("lastPasswordChangeDateTime", "passwordExpiresAt", "token_expires_at", "secretCreatedAt",
                      "password_set", "token_last_used_at", "secret_updated_on", "password-change-date",
                      "token-expiration-time", "secret-created-at", "token_state",
                      "token-revoked", "key_not_before", "keyValidUntil", "APIKeyCreatedAt",
                      "privateKeyMetadataId", "accessReviewId", "authenticationContextId", "vppTokenAppleId"):
            for value in ("2026-10-28T09:14:03Z", "2026-10-28", "DisableStrongPassword"):
                with self.subTest(label=label, value=value):
                    self.assertEqual(kinds_after(label, value), set())

    def test_a_password_in_the_shape_of_a_date_stays_a_hit(self):
        for label in ("password", "PASSWORD", "db_password"):
            with self.subTest(label=label):
                self.assertTrue(kinds_after(label, "1990-05-23"))

    def test_a_time_or_a_state_in_json_text_is_no_value(self):
        digits = lambda n: "".join(RNG.choice("0123456789") for _ in range(n))  # noqa: E731
        n10, n18, stamp = digits(10), "6" + digits(17), "2026" + "1028T091403Z"
        for key, value in (("password_set", f'"{n10}"'), ("password_status", f'"{n18}"'),
                           ("lastPasswordChangeDateTime", f'"{stamp}"'), ("password_last_changed", n10)):
            text = f'  "{key}": {value}'    # the last line of an object in pretty-printed JSON
            with self.subTest(key=key):
                self.assertEqual([m.kind for m in detect.scan(text, channel="tool")], [])

    def test_a_date_that_is_no_day_stays_a_value(self):
        for value in ("2026-99-99", "2026-02-30"):
            with self.subTest(value=value):
                self.assertTrue(kinds_after("api_key", value))

    def test_a_url_after_a_plural_secret_word_is_no_value(self):
        url = "https://api.github.com/app/installations/1/access_tokens"
        self.assertTrue(kinds_after("access_tokens", url))    # the premise: the bare plural label takes the URL
        self.assertEqual(kinds_after("access_tokens_url", url), set())

    def test_a_password_after_its_label_stays_a_hit(self):
        value = "".join(RNG.choice(B62) for _ in range(14)) + "!7"
        for label in ("password", "secret", "db_password"):
            with self.subTest(label=label):
                self.assertTrue(kinds_after(label, value))


class VersionQuadTests(unittest.TestCase):
    def ips(self, text: str) -> list:
        return [text[m.start:m.end] for m in detect.scan(text, channel="tool") if m.type == "IP"]

    def test_a_version_in_four_parts_is_no_address(self):
        for text in ("version: 1.3.0.0", "AssemblyVersion 4.2.17.3", "Upgrade MyPkg to 1.3.0.0",
                     "os_version: 4.12.0.1", "versionName: 4.12.0.1", '"product_version": "5.2.17.3"',
                     "packages/mypkg/1.3.0.0/mypkg.1.3.0.0.nupkg", "build 5.2.17.3", "lib.5.2.17.3.dll",
                     "see 5.2.17.3.nupkg", "nuget/metadata/mypkg/5.2.17.3.json"):
            with self.subTest(text=text):
                self.assertEqual(self.ips(text), [])

    def test_an_address_stays_a_hit(self):
        a = ".".join(str(n) for n in (85, 214, RNG.randrange(1, 250), RNG.randrange(1, 250)))
        for text in (f"client {a} blocked", f"from {a}.", f"ip: {a}", f"host {a}, port 22", f"lower: {a}",
                     f"connect v {a}", f"from {a}.Next request", f"server.{a}", f"conversion: {a}"):
            with self.subTest(text=text):
                self.assertEqual(self.ips(text), [a])
        b = ".".join(str(n) for n in (9, 8, 7, 0))
        for text in (f"ip: {b}", f"client {b} blocked", f"allow_ips: {b}", f"from {b} port 22", f"SSH to {b}",
                     f"Observed {b}", f"endpoint={b}", f"conversion: {b}"):
            with self.subTest(text=text):
                self.assertEqual(self.ips(text), [b])
        for text in (f"Your profile was updated. The IPv4 address is {a}.", f"Install done, connect from {a} now",
                     f"We updated the login made from the IP address {a}"):
            with self.subTest(text=text):
                self.assertEqual(self.ips(text), [a])


if __name__ == "__main__":
    unittest.main()
