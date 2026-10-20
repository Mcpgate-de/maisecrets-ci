"""Personal data after a label or in a fixed form (maisecrets/detection/personal.py), and three token forms with a
shorter tail
(0.6.21). Each rule is checked on a hit, on the ordinary developer text next to it, and on its channel and region.

Run: python3 -m unittest tests.test_personal_data -v
Every value is synthetic. A token is built at run time from parts, so the tree scan stays clean.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, personal, regions  # noqa: E402
import fp_corpus_pii  # noqa: E402

J = "".join
ALL_REGIONS = ("us", "uk", "in", "de", "fr", "es", "it", "pt", "ca", "au")


def scan(text: str, channel: str = "tool", region: tuple = ALL_REGIONS):
    active = regions.Active(regions=("generic", *region), languages=("en",), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def masked(text: str, value: str, channel: str = "tool", region: tuple = ALL_REGIONS) -> bool:
    out = text
    for m in sorted(scan(text, channel, region), key=lambda m: -m.start):
        out = out[:m.start] + "\u2022" + out[m.end:]
    return value not in out


def values(text: str, channel: str = "tool", region: tuple = ALL_REGIONS) -> list:
    return [(m.kind, m.value) for m in scan(text, channel, region) if m.kind in personal.RULE_IDS]


class DoubleNameTests(unittest.TestCase):
    """A double name with a hyphen is masked whole after its label (Benchmark V1, Gretel dev: names found in part
    811 to 55): the part after the hyphen may start with a capital."""

    def test_the_whole_double_name(self):
        for text, v in (("Customer name: " + J(["Maria Garcia", "-Lopez"]), J(["Maria Garcia", "-Lopez"])),
                        ("Name: " + J(["Omar Al", "-Rashid"]), J(["Omar Al", "-Rashid"])),
                        ("Name: " + J(["Jan Müller", "-Lüdenscheidt"]), J(["Jan Müller", "-Lüdenscheidt"]))):
            with self.subTest(v=v[:6]):
                self.assertIn(("name-after-label", v), values(text))

    def test_a_role_with_a_hyphen_stays_text(self):
        self.assertEqual([k for k, _v in values("Name: Front-Desk Team") if k == "name-after-label"], [])


class NameTests(unittest.TestCase):
    def test_a_name_after_a_person_label_is_masked(self):
        for text, name in (("patient: Dorian K. Ashby", "Dorian K. Ashby"),
                           ("tenant: Tobias Kellermann\nunit: 4B", "Tobias Kellermann"),
                           ('{"full_name": "Lena Brückner"}', "Lena Brückner"),
                           ("Ansprechpartner: Jonas Wendler", "Jonas Wendler"),
                           ("FN:Nora Whitfield", "Nora Whitfield")):
            with self.subTest(text=text):
                self.assertEqual(values(text), [("name-after-label", name)])

    def test_a_product_or_a_team_after_a_weak_label_stays_text(self):
        for text in ("app.kubernetes.io/name: Customer Portal", "  - name: Streaming Guild", "owner: Platform Team",
                     "Display name: Adobe Acrobat Reader", "name: Redis Cache", "Name: Wörterbuch Englisch",
                     "SELECT id FROM products WHERE name = 'Redis Cache'", "      - name: Run Pytest",
                     "Requested by: Product Owner", "oncall: Primary Rotation", "Kunde: Stadtwerke Nord",
                     "Ansprechpartner: Vertrieb Nord", "owner: Mgmt Vpc", "Approved by: Change Advisory Board"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])

    def test_a_surname_that_is_a_word_after_a_person_label(self):
        for text, name in (("customer_name: Sarah Park", "Sarah Park"), ("tenant: Michael King", "Michael King")):
            with self.subTest(text=text):
                self.assertEqual(values(text), [("name-after-label", name)])

    def test_a_closing_quote_is_no_part_of_the_name(self):
        self.assertEqual(values("tenant: 'Jonas Wendler'"), [("name-after-label", "Jonas Wendler")])

    def test_a_name_without_a_label_stays_text(self):
        self.assertEqual(values("Lena Brückner and Tobias Kellermann fixed the build."), [])

    def test_a_documentation_name_is_no_person(self):
        self.assertEqual(values("patient: Erika Mustermann"), [])



class NameBeforeAddressTests(unittest.TestCase):
    def test_a_name_before_an_address_but_not_before_a_bot(self):
        self.assertEqual(values("Reported by Tobias Kellermann <tobias.kellermann@example.org>"),
                         [("name-before-email", "Tobias Kellermann")])
        self.assertEqual(values("Author: GitHub Actions <noreply@github.com>"), [])
        self.assertEqual(values("Co-authored-by: Renovate Bot <bot@renovateapp.com>"), [])
        self.assertEqual(values("Heroku Status <status-page@heroku.example>"), [])
        self.assertEqual(values("Embark Studios <opensource@embark.example>"), [])


class BirthDateTests(unittest.TestCase):
    def test_a_date_after_a_birth_label(self):
        for text, v in (("DOB: 1987-04-12", "1987-04-12"), ("Geburtsdatum: 03.11.1979", "03.11.1979"),
                        ("née le 4 mars 1985", "4 mars 1985"), ("fecha de nacimiento: 12/05/1990", "12/05/1990")):
            with self.subTest(text=text):
                self.assertEqual(values(text), [("birth-date-after-label", v)])

    def test_a_date_after_born_on_or_a_birth_label_with_a_copula(self):
        # Benchmark V1, Nemotron dev split: birth dates found whole 4,736 to 9,609, no new false positive
        d = J(["1984", "-03-", "12"])
        for text in ("The patient was born on " + d + ".", "Her date of birth is " + d + ".", "Ivanov born on " + d,
                     "DateOfBirth=" + d, "date_of_birth: " + d, "Date of birth was " + d):
            with self.subTest(text=text[:16]):
                self.assertEqual(values(text), [("birth-date-after-label", d)])
                self.assertEqual(values(text, "prompt"), [], "a typed prompt is not blocked by it")

    def test_born_on_with_a_future_or_no_date_stays_text(self):
        for text in ("was born on " + J(["2091", "-03-", "12"]), "the idea was born on a Tuesday",
                     "build was created on " + J(["1984", "-03-", "12"])):
            with self.subTest(text=text[:16]):
                self.assertEqual(values(text), [])

    def test_other_dates_and_the_word_born_stay_text(self):
        for text in ("created: 2024-03-11", "released: 12.03.2024", "born 23 June 1912 in London",
                     "DOB 01/01/1970 is the placeholder for unknown records"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])



class IdNumberTests(unittest.TestCase):
    def test_an_id_number_after_an_id_label(self):
        for text, v in (("MRN: 00482913", "00482913"), ("passport no: K4829173", "K4829173"),
                        ("DL: D4812736", "D4812736"), ("tax id: 912-48-3017", "912-48-3017")):
            with self.subTest(text=text):
                # a passport or a tax id of a region rule is masked by that rule, which comes first
                self.assertTrue(masked(text, v))

    def test_a_specimen_a_snowflake_and_a_count_stay_text(self):
        for text in ("Specimen passport X0000000 (ICAO 9303 example)", "member id: 123456789012345678",
                     "account number of retries: 3", "x = sin(12345)", "<dl>12345</dl>",
                     "HPE ProLiant DL360 Gen10 Plus", "WHERE member_id = 20231115 LIMIT 10", "SELECT SIN(31415);"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])


class UrlUserTests(unittest.TestCase):
    def test_the_user_of_a_url(self):
        self.assertEqual(values("postgres://lbrueckner:pw4@db.internal:5432/app"),
                         [("user-in-url", "lbrueckner")])

    def test_service_accounts_templates_and_key_ids_stay_text(self):
        for text in ("postgres://postgres:postgres@localhost/db",
                     J(["https://__to", "ken__:x@upload.pypi.org/legacy/"]),
                     "ftp://anonymous:anonymous@ftp.example.org/pub/", "redis://${REDIS_USER}:${REDIS_PASS}@cache:6379",
                     "https://app4k29x1m8:x@api.example.net/", "amqp://rabbitmq:x@mq:5672/",
                     "https://gitlab-ci-token:x@gitlab.example.net/g/p.git", "postgres://app_user:x@db/app",
                     "postgresql://readonly:${DB_PASSWORD}@postgres/app", "https://reader:x@docs.internal/api"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])


class HomeUserTests(unittest.TestCase):
    def test_the_user_of_a_home_path(self):
        self.assertEqual(values("Traceback: /home/tkellermann/src/app.py"),
                         [("user-in-home-path", "tkellermann")])
        self.assertEqual(values("C:\\Users\\nwhitfield\\Desktop\\notes.txt"), [("user-in-home-path", "nwhitfield")])

    def test_a_user_name_with_capitals(self):
        self.assertEqual(values("C:\\Users\\SarahMiller\\project\\main.py"), [("user-in-home-path", "SarahMiller")])
        self.assertEqual(values("/Users/Shared/data"), [])

    def test_service_accounts_templates_and_the_own_home_stay_text(self):
        for text in ("/home/runner/work/app/app", "/Users/Shared/data", "C:\\Users\\Public\\Documents\\x",
                     "/home/appuser/app/main.py", "/home/nonroot/.cache", "/home/seluser/Downloads/x",
                     "/home/user1/x", "/home/airflow/dags/x.py", "File /home/oai/share/project/main.py, line 42"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])
        with mock.patch("getpass.getuser", return_value="tkellermann"):
            self.assertEqual(values("/home/tkellermann/src/app.py"), [])


class AddressTests(unittest.TestCase):
    def test_a_street_address_of_each_region(self):
        for text, v, region in (
                ("ship to 1618 Wexford Lane, Raleigh, NC 27601 now", "1618 Wexford Lane, Raleigh, NC 27601", ("us",)),
                ("Lieferadresse: Musterweg 7, 12345 Musterstadt", "Musterweg 7, 12345 Musterstadt", ("de",)),
                ("adresse : 14 rue des Lilas, 75011 Paris", "14 rue des Lilas, 75011 Paris", ("fr",)),
                ("Morada: Rua das Flores, 12, 4050-262 Porto", "Rua das Flores, 12, 4050-262 Porto", ("pt",))):
            with self.subTest(text=text):
                self.assertEqual(values(text, region=region), [("street-address", v)])
                # the form runs in its region only (an address after an address label is address-after-label, generic)
                self.assertEqual([x for x in values(text, region=("generic",)) if x[0] == "street-address"], [])

    def test_a_documentation_address_keeps_the_postcode_hit_of_its_region_rule(self):
        hits = [m.kind for m in scan("Adresse: Examplestraße 12, 10115 Berlin", region=("de",))]
        self.assertEqual(hits, [k for k in hits if k not in personal.RULE_IDS])
        self.assertTrue(hits)

    def test_a_field_on_the_line_before_is_no_company(self):
        text = "branch: main\nAdresse: Lindenstraße 12, 10115 Berlin"
        self.assertEqual(values(text, region=("de",)), [("street-address", "Lindenstraße 12, 10115 Berlin")])

    def test_a_company_or_a_landmark_address_stays_text(self):
        for text in ("Impressum: Muster GmbH, Hauptstraße 1, 10115 Berlin",
                     "Acme Corp Niederlassung München\nLeopoldstraße 250, 80807 München",
                     "The Empire State Building, 350 Fifth Avenue, New York, NY 10118",
                     "Our office: 1600 Amphitheatre Parkway, Mountain View, CA 94043",
                     "1 Shared Drive, quota 10240", "Filtering 2, 10000 Rows", "Scoring 4, 1200 Punkte",
                     "Access Via Bastion, 2 hops, port 30022", "3 place holders, 65536 Bytes"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])


class PhoneTests(unittest.TestCase):
    def test_a_number_with_one_digit_groups_in_both_channels(self):
        text = "call me on +1 4 1 5 223 3344"
        for ch in ("tool", "prompt"):
            with self.subTest(channel=ch):
                self.assertEqual(values(text, ch), [("phone-one-digit-groups", "+1 4 1 5 223 3344")])

    def test_a_typed_prompt_needs_a_phone_word_and_takes_no_us_form(self):
        self.assertEqual(values("Fix the parser for this matrix row: +1 2 3 4 56 7 89", "prompt"), [])
        self.assertEqual(values("Why does the phone parser reject (212) 867-5309 here?", "prompt", ("us",)), [])

    def test_a_us_number_needs_its_label_its_region_and_no_555(self):
        self.assertEqual(values("Tel: (312) 846-2291", region=("us",)), [("phone-us-national", "(312) 846-2291")])
        self.assertEqual(values("Tel: (312) 846-2291", region=("de",)), [])
        self.assertEqual(values("f(312) 846-2291", region=("us",)), [])
        self.assertEqual(values("phone: (312) 555-0100", region=("us",)), [])
        self.assertEqual(values("call (100) 250-1000", region=("us",)), [])   # no area code starts with 0 or 1

    def test_version_and_offset_runs_stay_text(self):
        for text in ("UTC +05 30", "a + 1 2 3", "score +1 0 0 0 0 0 0 0"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])


class CsvTests(unittest.TestCase):
    def test_the_cells_of_personal_columns(self):
        text = "name,email,dob\nLena Brückner,lena@example.org,1980-01-02\n"
        self.assertEqual(values(text), [("csv-personal-column", "Lena Brückner"),
                                        ("csv-personal-column", "1980-01-02")])

    def test_a_product_list_and_a_desk_list_stay_text(self):
        for text in ("name,price,qty\nWidget Pro,9.99,3\n", "name,phone\nFront Desk,ext. 100\nIT Helpdesk,ext. 200\n",
                     "id,name,address,dob,phone\n", "x,sin,cos\n0.5,0.479,0.877\n"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])


class ChannelTests(unittest.TestCase):
    def test_a_typed_prompt_takes_only_the_phone_rules(self):
        text = "patient: Dorian K. Ashby, DOB: 1987-04-12, MRN: 00482913, /home/tkellermann/x"
        self.assertEqual(values(text, "prompt"), [])
        self.assertEqual(len(values(text, "tool")), 4)

    def test_another_rule_keeps_its_span(self):
        # the e-mail rule takes the address; the name rule takes only the name before it
        kinds = [m.kind for m in scan("Tobias Kellermann <tobias.kellermann@mail.test-firma.de>")]
        self.assertIn("name-before-email", kinds)
        self.assertIn("email", kinds)


class CorpusTests(unittest.TestCase):
    def test_the_personal_data_corpus_has_no_false_hit_in_either_channel(self):
        for ch in ("tool", "prompt"):
            wrong = [(i, values(t, ch)) for i, t in fp_corpus_pii.PII_NO_HIT if values(t, ch)]
            self.assertEqual(wrong, [], f"{ch}: {len(wrong)} of {len(fp_corpus_pii.PII_NO_HIT)} texts")

    def test_every_positive_value_is_masked_in_a_tool_result(self):
        missed = []
        for i, text, vals in fp_corpus_pii.POSITIVE:
            out = text
            for m in sorted(scan(text), key=lambda m: -m.start):
                out = out[:m.start] + "\u2022" + out[m.end:]
            missed += [i for v in vals if v in out]
        self.assertEqual(missed, [])

    def test_the_corpus_is_large_enough(self):
        self.assertGreaterEqual(len(fp_corpus_pii.PII_NO_HIT), 300)
        self.assertGreaterEqual(len(fp_corpus_pii.POSITIVE), 40)


class OpenAiAnthropicKeyTests(unittest.TestCase):
    def test_a_short_openai_and_anthropic_key(self):
        for tok, kind in ((J(["sk-", "proj-", "Ab3dEf6hIj9kLm2nOp5qRs8t"]), "openai-anthropic-key-relaxed"),
                          (J(["sk-", "ant-", "ap" + "i03", "-",
                              "Zx8cVb7nMq6w", "Er5tYu4iOp3a"]), "openai-anthropic-key-relaxed")):
            with self.subTest(kind=kind):
                hits = [(m.kind, m.value) for m in scan("key " + tok, "prompt")]
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0][1], tok)

    def test_a_word_after_the_prefix_is_no_key(self):
        for text in ("rename sk-admin-sidebar-navigation-item", "the sk-proj-overview-header-container-large class",
                     "rename sk-admin-sidebar-navigation-item2X", "stack sk-admin-ApiGateway-Stack-2026"):
            with self.subTest(text=text):
                self.assertEqual(scan(text, "prompt"), [])

    def test_a_stripe_dash_test_key_is_no_openai_key(self):
        self.assertEqual([m for m in scan(J(["sk-", "test-", "Ab3dEf6hIj9kLm2nOp5qRs8t"]), "prompt")
                          if m.kind == "openai-anthropic-key-relaxed"], [])



class SlackTokenTests(unittest.TestCase):
    def test_a_short_slack_token(self):
        tok = J(["xox", "b-", "48213-", "Qw7eRt6yUi5oPa4sDf3gHj"])
        self.assertEqual([(m.kind, m.value) for m in scan("key " + tok, "prompt")], [("slack-token-relaxed", tok)])
        for text in ("xoxo-hugs-and-kisses-to-everyone!", "Investigate xoxb-background-worker-release-2024",
                     "xoxb-Team-Notifications-2026-Q4"):
            with self.subTest(text=text):
                self.assertEqual(scan(text, "prompt"), [])


class TwilioTests(unittest.TestCase):
    def test_a_twilio_account_sid_needs_its_name(self):
        sid = J(["AC", "3f9a1c0e7b52d8461e9fa0c37b5d2e84"])
        self.assertEqual([m.kind for m in scan("TWILIO_ACCOUNT_SID=" + sid, "prompt")],
                         ["twilio-account-sid-labelled"])
        self.assertEqual([m.kind for m in scan("digest " + sid, "prompt")], [])
        counted = J(["AC", "0123456789abcdef", "0123456789abcdef"])
        self.assertEqual(scan("account_sid " + counted, "prompt"), [])


class IdAfterLabelWholeTests(unittest.TestCase):
    """An id after its label is masked whole: after `of`, after a certificate or license number label, and with a letter
    prefix that a digit rule (us-license, us-bank) used to cut off (Benchmark V1, Nemotron dev: national ids whole
    15,713 to 17,123, partial 1,213 to 220)."""
    MRN = J(["MRN", "-48", "2913", "7"])
    CERT = J(["CL", "-48820", "19"])
    ACCT = J(["ACC", "-4071", "8653", "29"])
    SUFFIX = J(["4071", "8653", "-XY"])                     # a letter suffix after the digits

    def test_the_whole_id_after_its_label(self):
        for text, v in (("a medical record number of " + self.MRN, self.MRN),
                        ("The certificate license number is " + self.CERT + ".", self.CERT),
                        ("certificate license number " + self.CERT, self.CERT),
                        ("account number " + self.ACCT, self.ACCT)):
            with self.subTest(text=text[:20]):
                self.assertIn(("id-number-after-label", v), [(m.kind, m.value) for m in scan(text)])

    def test_a_digit_rule_takes_no_part_of_a_hyphenated_id(self):
        for text in ("The certificate license number is " + self.CERT, "account number " + self.ACCT,
                     "account number " + self.SUFFIX):
            with self.subTest(text=text[:20]):
                kinds = {m.kind for m in scan(text)}
                self.assertFalse(kinds & {"us-license#1", "us-bank"}, kinds)

    def test_words_after_the_labels_stay_text(self):
        for text in ("record number of rows: 12", "license number 2 applies (MIT)", "driver's license is required"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])


if __name__ == "__main__":
    unittest.main()
