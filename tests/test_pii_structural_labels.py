"""Names and ids under the field names of structured text (the structural label gaps of 2026-10-25).

Each class here is one change: a first or last name that is also a word, a key that names a person's role, a
compound key of a role and a name, an XML element named by a person label, an HTML table of fields and values, a SQL
dump's INSERT under its CREATE TABLE, a row with a first and a last name column, a title before a name, the bare
`student` label, and an id that starts with its own label. Every value is invented; each negative is developer text
in the same shape.

Run: python3 -m unittest tests.test_pii_structural_labels -v
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

from maisecrets import detect, regions  # noqa: E402

ALL = ("us", "uk", "de")
FIRST = "Ada" + "eze"
LAST = "Oko" + "nkwo"
NAME = FIRST + " " + LAST


def scan(text: str, channel: str = "tool", region: tuple = ALL) -> list:
    active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def masked(text: str, channel: str = "tool", region: tuple = ALL) -> str:
    for m in sorted(scan(text, channel, region), key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class Base(unittest.TestCase):
    def assertMasked(self, text: str, value: str, channel: str = "tool") -> None:
        self.assertIn(value, text)
        self.assertNotIn(value, masked(text, channel), text)

    def assertNoName(self, text: str, channel: str = "tool") -> None:
        self.assertNotIn("NAME", {m.type for m in scan(text, channel)}, text)


class WordAsSingleNameTests(Base):
    WORD = "Hun" + "ter"

    def test_a_name_that_is_a_word_is_masked_next_to_a_name_part_that_is_none(self):
        for text in ("first_name: " + self.WORD + "\nlast_name: " + LAST + "\n",
                     '{"last_name": "' + self.WORD + '", "first_name": "' + FIRST + '"}',
                     "first_name: " + self.WORD + "\nnotes: x\nlast_name: " + LAST + "\n"):
            with self.subTest(text=text):
                self.assertMasked(text, self.WORD)

    def test_a_word_alone_or_in_a_schema_of_words_stays_text(self):
        for text in ("first_name: " + self.WORD + "\n",
                     "first_name: Unique\nlast_name: Index\n",
                     "first_name: Mason\nlast_name: Carter\n",
                     # an e-mail address alone is no second name part
                     "first_name: " + self.WORD + "\ncontact: someone@example.org\n",
                     # the value goes on in a sentence: no field
                     "first_name: " + self.WORD + " said hello\nlast_name: " + LAST + "\n"):
            with self.subTest(text=text):
                self.assertNotIn(self.WORD, {m.value for m in scan(text)})

    def test_a_name_part_far_away_does_not_count(self):
        text = "first_name: " + self.WORD + "\n" + "x" * 400 + "\nlast_name: " + LAST + "\n"
        self.assertNotIn(self.WORD, {m.value for m in scan(text)})


class RoleKeyTests(Base):
    def test_a_name_after_a_key_that_names_a_persons_role_is_masked(self):
        for key in ("payer", "payee", "policyholder", "policy_holder", "borrower", "insured", "physician", "recipient",
                    "consignee", "shipper", "buyer", "seller", "sender", "guarantor"):
            for text in (key + ": " + NAME + "\n", '{"' + key + '": "' + NAME + '"}', key + " = " + NAME):
                with self.subTest(text=text):
                    self.assertMasked(text, NAME)

    def test_words_a_team_and_the_keys_of_the_broad_set_stay_text(self):
        for text in ("sender: Release Desk\n", "recipient: Platform Team\n", '{"buyer": "Build Bot"}',
                     # roles a company or a system has as often as a person: not in the set
                     "lender: " + NAME + "\n", "agent: " + NAME + "\n", "client: " + NAME + "\n",
                     "user: " + NAME + "\n", "contact: " + NAME + "\n", "customer: " + NAME + "\n",
                     # the role word inside a longer key
                     "message_sender: " + NAME + "\n"):
            with self.subTest(text=text):
                self.assertNotIn("name-after-label", {m.kind for m in scan(text)})


class CompoundNameKeyTests(Base):
    def test_a_name_after_a_key_of_a_role_and_name_is_masked(self):
        for key in ("account_holder_name", "investorName", "cardHolderName", "card-holder-name", "beneficiary_name",
                    "primary_investor_name", "policyholderFullName", "full__name"):
            for text in (key + ": " + NAME + "\n", '{"' + key + '": "' + NAME + '"}'):
                with self.subTest(text=text):
                    self.assertMasked(text, NAME)

    def test_the_name_of_an_account_a_company_a_fund_or_a_program_stays_text(self):
        for key in ("account_name", "company_name", "issuer_name", "fund_name", "agent_name", "accountName",
                    "instrument_name"):
            with self.subTest(key=key):
                self.assertNotIn("name-after-label", {m.kind for m in scan(key + ": " + NAME + "\n")})
        # a role key before words or a team stays text
        for text in ("owner_name: Platform Team\n", '{"investorName": "Global Equity Fund"}'):
            with self.subTest(text=text):
                self.assertNoName(text)


class XmlElementLabelTests(Base):
    def test_a_name_inside_an_element_named_by_a_person_label_is_masked(self):
        for text in ("<payment>\n  <card_holder>" + NAME + "</card_holder>\n</payment>\n",
                     "<ns:fullName>" + NAME + "</ns:fullName>",
                     '<customerName xml:lang="en">' + NAME + "</customerName>",
                     "<person><name>" + NAME + "</name></person>",
                     "<project><developers><developer><name>" + NAME + "</name></developer></developers></project>"):
            with self.subTest(text=text):
                self.assertMasked(text, NAME)

    def test_the_name_of_a_project_or_a_product_and_words_stay_text(self):
        for text in ("<project>\n  <name>Kogito Quarkify</name>\n</project>\n",
                     '<product id="7"><name>Zentrix Lumo</name></product>',
                     "<item><name>Garden Hose</name></item>",
                     "<security><fullName>Zentrix Lumo</fullName></security>",
                     "<counterparty><name>Zentrix Lumo</name></counterparty>",
                     "<owner>Platform Team</owner>",
                     "<card_holder>Not Provided</card_holder>"):
            with self.subTest(text=text):
                self.assertNoName(text)


BIRTH = "1984-03-" + "12"


class HtmlFieldValueTableTests(Base):
    def test_a_table_of_fields_and_values_is_one_record(self):
        text = ("<table>\n<tr><th>Full name</th><td>" + NAME + "</td></tr>\n"
                "<tr><th>Date of birth</th><td>" + BIRTH + "</td></tr>\n</table>\n")
        out = masked(text)
        for v in (NAME, BIRTH):
            with self.subTest(v=len(v)):
                self.assertNotIn(v, out)
        self.assertIn("html-table-personal-column", {m.kind for m in scan(text)})

    def test_a_table_of_a_thing_or_a_place_stays_text(self):
        for text in ("<table><tr><th>Name</th><td>Desk Lamp</td></tr><tr><th>Price</th><td>12.50</td></tr></table>",
                     "<table><tr><th>Name</th><td>North Depot</td></tr><tr><th>Address</th>"
                     "<td>12 Oak Lane, Springfield</td></tr></table>",
                     # one personal field alone is no record
                     "<table><tr><th>Full name</th><td>" + NAME + "</td></tr></table>"):
            with self.subTest(text=text[:40]):
                self.assertNotIn("html-table-personal-column", {m.kind for m in scan(text)})


class SqlDumpCreateTableTests(Base):
    OTHER = "Bram " + "Tellenbosch"
    CREATE = ("CREATE TABLE `users` (\n  `id` int NOT NULL,\n  `full_name` varchar(100),\n  `dob` date,\n"
              "  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n")

    def test_an_insert_without_columns_takes_them_from_its_create_table(self):
        text = (self.CREATE + "INSERT INTO `users` VALUES (1,'" + NAME + "','" + BIRTH + "'),(2,'" + self.OTHER
                + "','1990-07-" + "21');\n")
        out = masked(text)
        for v in (NAME, self.OTHER, BIRTH):
            with self.subTest(v=len(v)):
                self.assertNotIn(v, out)

    def test_another_table_a_table_of_things_or_no_create_table_names_no_cell(self):
        for text in (self.CREATE + "INSERT INTO `orders` VALUES (1,'" + NAME + "','" + BIRTH + "');\n",
                     "CREATE TABLE products (id int, name varchar(50), released date);\n"
                     "INSERT INTO products VALUES (1,'Garden Hose','2024-05-01');\n",
                     "INSERT INTO users VALUES (1,'" + NAME + "','" + BIRTH + "');\n"):
            with self.subTest(text=text[-40:]):
                self.assertNotIn("sql-insert-personal-column", {m.kind for m in scan(text)})


class FirstAndLastNameColumnTests(Base):
    """The one exception to "a name part alone is no person": a record with a first-name and a last-name column."""

    def test_a_row_with_a_first_and_a_last_name_is_a_person(self):
        for text in ("INSERT INTO customers (first_name, last_name, email) VALUES ('" + FIRST + "', '" + LAST
                     + "', 'someone@example.org');",
                     "<table><tr><th>First name</th><th>Last name</th></tr><tr><td>" + FIRST + "</td><td>" + LAST
                     + "</td></tr></table>",
                     "| First Name | Last Name |\n|---|---|\n| " + FIRST + " | " + LAST + " |\n",
                     # the case that tests/test_personal_after_its_label.py kept as text before this exception
                     "| Field | Value |\n|---|---|\n| First Name | " + FIRST + " |\n| Last Name | " + LAST + " |\n"):
            out = masked(text)
            for v in (FIRST, LAST):
                with self.subTest(text=text[:30], v=len(v)):
                    self.assertNotIn(v, out)

    def test_one_name_part_a_fixture_or_form_words_stay_text(self):
        for text in ("| First Name | Plan |\n|---|---|\n| " + FIRST + " | basic |\n",
                     "INSERT INTO t (first_name, last_name) VALUES ('Foo', 'Bar');",
                     "INSERT INTO t (first_name, last_name) VALUES ('Jane', 'Doe');",
                     "| First Name | Last Name |\n|---|---|\n| Required | Optional |\n",
                     "| Field | Value |\n|---|---|\n| First Name | Required |\n| Last Name | Optional |\n"):
            with self.subTest(text=text[:40]):
                self.assertNoName(text)


class BareStudentLabelTests(Base):
    COURSE = "Informatik " + "Bachelor"

    def test_a_name_after_student_that_ends_its_field_is_masked(self):
        for text in ("Student: " + NAME + "\n", "Student: " + NAME + " (ID 4711)\n",
                     "Student: " + NAME + ", Class 7B\n", "student_name: " + NAME + ", enrolled\n"):
            with self.subTest(text=text):
                self.assertMasked(text, NAME)

    def test_a_course_of_study_that_a_sentence_goes_on_from_stays_text(self):
        for text in ("Student: " + self.COURSE + " an der Hochschule\n",
                     "Student: " + self.COURSE + ", zweites Semester\n"):
            with self.subTest(text=text):
                self.assertNoName(text)


class IdWithItsLabelAsPrefixTests(Base):
    DIGITS = "4829" + "173"

    def test_an_id_that_starts_with_its_label_is_masked_whole(self):
        for token in ("MRN" + self.DIGITS, "mrn" + self.DIGITS):
            for text in (token + "\n", "Cartella clinica " + token + " del paziente\n", "record " + token + ", seen"):
                with self.subTest(text=text):
                    hit = [m for m in scan(text) if m.type == "ID_NUMBER"]
                    self.assertEqual([token], [m.value for m in hit])

    def test_an_id_after_its_label_keeps_its_span(self):
        for text, value in (("MRN: AB" + self.DIGITS + "\n", "AB" + self.DIGITS),
                            ("MRN " + self.DIGITS + "\n", self.DIGITS)):
            with self.subTest(text=text):
                self.assertEqual([value], [m.value for m in scan(text) if m.type == "ID_NUMBER"])
        # a placeholder number stays text, with or without the glued label
        self.assertNotIn("ID_NUMBER", {m.type for m in scan("MRN" + "1234567\n")})


if __name__ == "__main__":
    unittest.main()
