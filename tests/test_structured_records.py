"""Personal data and passwords in structured text: the field names of a record in more languages and short forms, a
password column in a table, and the records of the line formats (YAML, .env, a log line, SQL UPDATE and WHERE, PHP
print_r) and of JSON inside a string or a Python dict (the structured corpus, set A dev, 2026-10-25).

Each class is one change. Each positive is an invented value in a record that names a person; each negative is the
same shape with no person in it, or a value that is no password.

Run: python3 -m unittest tests.test_structured_records -v
"""
from __future__ import annotations

import os
import random
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402

ALL = ("us", "de", "fr", "es", "it", "nl", "se", "pl", "pt")
FIRST, LAST = "Dana", "Okafor"
BIRTH = "1984-03-" + "12"
STREET = "Kerkstraat " + "12"
PHONE = "+31 6 " + "4829 1735"
USER = "dokafor" + "84"


def _password(seed: int = 7) -> str:
    rnd = random.Random(seed)
    return "".join(rnd.choice(string.ascii_letters) for _ in range(8)) + "".join(rnd.choice(string.digits)
                                                                              for _ in range(3)) + "!"


PASSWORD = _password()


_DETECTOR = []


def scan(text: str, channel: str = "tool") -> list:
    if not _DETECTOR:
        _DETECTOR.append(detect.Detector(regions=regions.Active(
            regions=("generic", *ALL), languages=tuple(regions.label_languages_available()), source="test")))
    with _DETECTOR[0].activate():
        return detect.scan(text, channel=channel)


def masked(text: str, channel: str = "tool") -> str:
    for m in sorted(scan(text, channel), key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class Base(unittest.TestCase):
    def assertMasked(self, text: str, *values: str, channel: str = "tool") -> None:
        out = masked(text, channel)
        for v in values:
            self.assertIn(v, text)
            self.assertNotIn(v, out, text)

    def assertText(self, text: str, *values: str) -> None:
        out = masked(text)
        for v in values:
            self.assertIn(v, out, text)

    def kinds(self, text: str) -> set:
        return {m.kind for m in scan(text)}


# --------------------------------------------------------------------------------------- the column vocabulary --
class ColumnVocabularyTests(Base):
    def test_a_field_name_in_another_language_names_its_column(self):
        for head in ("nazwisko,imie,data_urodzenia,adres", "achternaam,voornaam,geboortedatum,straatnaam",
                     "efternamn,förnamn,födelsedatum,gatuadress", "apellido,nombre,fecha_nacimiento,domicilio"):
            with self.subTest(head):
                self.assertMasked(f"{head}\n{LAST},{FIRST},{BIRTH},{STREET}\n", LAST, BIRTH, STREET)

    def test_a_name_without_its_diacritics_and_a_short_form_name_their_column(self):
        self.assertMasked("| lname | fname | dob | tel |\n|---|---|---|---|\n"
                          f"| {LAST} | {FIRST} | {BIRTH} | {PHONE} |\n",
                          LAST, FIRST, BIRTH, PHONE)
        self.assertMasked(f"haslo_reset;data_urodzenia;nazwisko\nx;{BIRTH};{LAST}\n", BIRTH, LAST)
        self.assertMasked(f'{{"gebruikersnaam": "{USER}", "geb_dat": "{BIRTH}", "achternaam": "{LAST}"}}',
                          USER, BIRTH, LAST)

    def test_a_persons_entity_before_the_field_and_a_doubled_separator_are_read(self):
        self.assertMasked(f'{{"customer__surname": "{LAST}", "customer__date__of__birth": "{BIRTH}"}}', LAST, BIRTH)
        self.assertMasked(f"klient__nazwisko,klient__adres\n{LAST},{STREET}\n", LAST, STREET)

    def test_a_field_of_a_company_or_an_account_stays_text(self):
        # company_name and account_name are no person: their record has no person in it
        self.assertText(f'{{"company_name": "{LAST} Logistics", "company__address": "{STREET}"}}', STREET)
        self.assertText(f"account_name,adres\n{LAST} Holding,{STREET}\n", STREET)
        # a person's field alone, beside no strong column, stays text as before
        self.assertText(f"imie,nazwisko,status\n{FIRST},{LAST},active\n", LAST)

    def test_the_folding_is_one_mapping(self):
        from maisecrets import personal
        for raw, want in (("klient__nazwisko", "last_name"), ("Hasło", "hasło"), ("customer__date__of__birth",
                          "date_of_birth"), ("company_name", "company_name"), ("FirstNm", "first_name"),
                          ("födelsedag", "date_of_birth"), ("user_name", "user_name")):
            with self.subTest(raw):
                self.assertEqual(personal._md_column(raw), want)


# ------------------------------------------------------------------------------------------ a password column --
class PasswordColumnTests(Base):
    def test_a_password_under_its_column_in_a_table_is_masked(self):
        for text in (f"| login | wachtwoord |\n|---|---|\n| {USER} | {PASSWORD} |\n",
                     f"<table><tr><th>user</th><th>hasło</th></tr><tr><td>{USER}</td><td>{PASSWORD}</td></tr>"
                     "</table>",
                     f"INSERT INTO accounts (login, db_password) VALUES ('{USER}', '{PASSWORD}');\n",
                     f"| Field | Value |\n|---|---|\n| lösenord | {PASSWORD} |\n"):
            with self.subTest(text[:20]):
                self.assertMasked(text, PASSWORD)
                self.assertIn("secret-under-password-column", self.kinds(text))

    def test_a_typed_prompt_is_not_blocked_by_the_column(self):
        text = f"| login | wachtwoord |\n|---|---|\n| {USER} | {PASSWORD} |\n"
        self.assertNotIn("secret-under-password-column", {m.kind for m in scan(text, "prompt")})

    def test_a_value_that_is_no_password_stays_text(self):
        bcrypt = "$2b$12$" + "".join(random.Random(3).choice(string.ascii_letters + "./") for _ in range(53))
        for cell in ("required", "string", "varchar(255)", "********", "${DB_PASSWORD}", "<secret>", "true",
                     "Departure:", "rgb/top12",
                     "ENC(" + "abc123def" + ")", bcrypt):
            text = f"| field | password |\n|---|---|\n| admin | {cell} |\n"
            with self.subTest(cell[:10]):
                self.assertNotIn("secret-under-password-column", self.kinds(text))
        # a column that holds the hash of a password, and a column of a password rule
        for head in ("password_hash", "hashed_password", "password_policy", "passport", "pass", "boarding_pass"):
            text = f"| user | {head} |\n|---|---|\n| {USER} | {PASSWORD} |\n"
            with self.subTest(head):
                self.assertNotIn("secret-under-password-column", self.kinds(text))

    def test_a_record_of_json_or_lines_is_left_to_the_keyword_rules(self):
        # the keyword rules read `password: value` with their own filters; the column rule reads tables only
        text = f'{{"user": "{USER}", "password": "test1234"}}'
        self.assertNotIn("secret-under-password-column", self.kinds(text))


# ------------------------------------------------------------------------------------- the line formats --
class LineRecordTests(Base):
    def test_a_yaml_record_and_a_list_of_records_are_read(self):
        self.assertMasked(f"customer:\n  nachname: {LAST}\n  vorname: {FIRST}\n  geburtsdatum: '{BIRTH}'\n",
                          LAST, BIRTH)
        self.assertMasked(f"people:\n  - lname: \"{LAST}\"\n    dob: {BIRTH}\n  - lname: {LAST}x\n    dob: {BIRTH}\n",
                          LAST, BIRTH)

    def test_an_env_file_and_a_compose_environment_list_are_read(self):
        self.assertMasked(f"CUSTOMER_NAME={FIRST} {LAST}\nPHONE={PHONE}\nAPP_PORT=8080\n", f"{FIRST} {LAST}")
        self.assertMasked(f"environment:\n  - CONTACT_NAME={FIRST} {LAST}\n  - TELEFON={PHONE}\n", f"{FIRST} {LAST}")

    def test_a_log_line_with_two_pairs_or_more_is_one_record(self):
        self.assertMasked(f"2026-10-25T10:00:00Z INFO [api] signup nachname={LAST} geb_datum={BIRTH} plan=pro\n",
                          LAST, BIRTH)
        self.assertMasked(f'level=info msg="user created" full_name="{FIRST} {LAST}" phone="{PHONE}"\n',
                          f"{FIRST} {LAST}", PHONE)

    def test_a_sql_update_and_a_where_clause_are_one_record(self):
        self.assertMasked(f"UPDATE customers SET apellido = '{LAST}', fecha_nacimiento = '{BIRTH}' WHERE id = 42;",
                          LAST, BIRTH)
        self.assertMasked(f"SELECT * FROM users WHERE last_name = '{LAST}' AND dob = '{BIRTH}';", LAST, BIRTH)

    def test_a_php_print_r_is_read(self):
        self.assertMasked(f"Array\n(\n    [nachname] => {LAST}\n    [geburtsdatum] => {BIRTH}\n)\n", LAST, BIRTH)

    def test_a_record_without_a_person_stays_text(self):
        # a company's config: an address and a phone, no person (a phone after its label is the phone rule's)
        for text in (f"company_name: {LAST} Logistics\naddress: {STREET}\nphone: {PHONE}\n",
                     # a service list: a name and a host address
                     "services:\n  - name: billing\n    address: 10.0.0.12:8080\n    port: 8080\n",
                     # a log line with one person field and no strong one
                     f"INFO login ok user={USER} took_ms=12 status=200\n",
                     # two blocks apart: the name of one and the birth date of the other are no record
                     f"[owner]\nnachname = {LAST}\n\n[release]\ngeburtsdatum = 2024-05-01\n"):
            with self.subTest(text[:20]):
                self.assertNotIn("kv-personal-field", self.kinds(text))

    def test_a_long_text_of_pairs_stays_linear(self):
        from _timing import assert_linear
        assert_linear(self, lambda t: scan(t, "tool"),
                      lambda n: "".join(f"key{i}: value{i}\nk{i}=v{i} a{i}=b{i}\n" for i in range(n)), 1500)


# ------------------------------------------------------------------------------- JSON inside a string or a dict --
class QuotedJsonTests(Base):
    def test_json_inside_a_json_string_is_read(self):
        text = ('{"event": "signup", "payload": "{\\"nazwisko\\": \\"' + LAST + '\\", \\"data_urodzenia\\": \\"'
                + BIRTH + '\\"}"}')
        self.assertMasked(text, LAST, BIRTH)

    def test_a_python_dict_repr_is_read(self):
        self.assertMasked(f"DEBUG payload={{'last_name': '{LAST}', 'dob': '{BIRTH}', 'plan': 'pro'}}", LAST, BIRTH)

    def test_a_quoted_record_without_a_person_stays_text(self):
        text = '{"payload": "{\\"company_name\\": \\"' + LAST + ' Logistics\\", \\"street\\": \\"' + STREET + '\\"}"}'
        self.assertNotIn("json-personal-field", self.kinds(text))
        self.assertNotIn("json-personal-field", self.kinds(f"{{'name': 'billing', 'address': '{STREET}', 'kind': "
                                                           "'depot'}"))


if __name__ == "__main__":
    unittest.main()
