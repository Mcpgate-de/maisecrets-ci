"""Personal data after its label in more forms (the gap analysis of 2026-10-16 on Nemotron-PII and Gretel).

Each class here is one change: a label in Markdown bold, a phone number after a phone word, an ID number after a
health, tax or national label, one name word after a first or last name label, a street line after an address label,
the person columns of a Markdown table, and the passport and driving licence labels of the EU languages. Each
positive is an invented value in the shape of the datasets; each negative is developer text in the same shape.

Run: python3 -m unittest tests.test_personal_after_its_label -v
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

from maisecrets import detect, normalise, regions  # noqa: E402

ALL = ("us", "uk", "in", "de", "fr", "es", "it", "pt", "ca", "au", "nl", "se")


def scan(text: str, channel: str = "tool", region: tuple = ALL) -> list:
    active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def masked(text: str, channel: str = "tool", region: tuple = ALL) -> str:
    for m in sorted(scan(text, channel, region), key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class Base(unittest.TestCase):
    def assertMasked(self, text: str, value: str, channel: str = "tool", region: tuple = ALL) -> None:
        self.assertIn(value, text)
        self.assertNotIn(value, masked(text, channel, region), text)

    def assertText(self, text: str, channel: str = "tool", region: tuple = ALL) -> None:
        self.assertEqual(text, masked(text, channel, region))


# ------------------------------------------------------------------------------------------------- Markdown bold --
BIRTH = "1984-03-" + "12"
NAME = "Dana " + "Okafor"
PASSWORD = "Qz8k" + "Lm2pR7xw"


class BoldLabelTests(Base):
    def test_a_value_after_a_bold_label_is_masked_like_after_the_plain_label(self):
        for text, value in (
                ("**Date of birth:** " + BIRTH, BIRTH),
                ("**Date of birth**: " + BIRTH, BIRTH),
                ("- **Full name:** " + NAME + "\n- **Role:** reviewer", NAME),
                ("__Date of birth:__ " + BIRTH, BIRTH),
                ("**Password:** " + PASSWORD, PASSWORD),
                ("| **Password:** " + PASSWORD + " |", PASSWORD)):
            with self.subTest(text=text):
                self.assertMasked(text, value)

    def test_the_offsets_of_the_value_stay_those_of_the_original(self):
        text = "**Date of birth:** " + BIRTH + " and more"
        hits = [m for m in scan(text) if m.type == "BIRTH_DATE"]
        self.assertEqual([(text[m.start:m.end]) for m in hits], [BIRTH])
        # a hit never takes the stars of the next bold label with it
        text = "**Full name:** " + NAME + " **Role:** reviewer"
        self.assertEqual([text[m.start:m.end] for m in scan(text) if m.type == "NAME"], [NAME])

    def test_the_emphasis_stage_drops_only_the_stars_around_a_label(self):
        self.assertEqual(normalise.normalise("**Date of birth:** x").text, "Date of birth: x")
        self.assertEqual(normalise.normalise("**Date of birth**: x").text, "Date of birth: x")
        self.assertEqual(normalise.normalise("__Name:__ x").text, "Name: x")
        for text in ("a **bold** word", "__version__ = 1", "__all__: list = []", "f(**kwargs)", "**Note**",
                     "x ** 2: y", "__init__ : x"):
            with self.subTest(text=text):
                self.assertIs(normalise.normalise(text).text, text)

    def test_a_typed_prompt_keeps_its_decisions(self):
        self.assertText("**Date of birth:** " + BIRTH, "prompt")

    def test_a_bold_label_without_a_value_stays_text(self):
        for text in ("**Note:** see below", "**Password:** must be 12 characters", "**First name:** String, required",
                     "**Date of birth**: required, format YYYY-MM-DD", "**Version:** 1.2.3"):
            with self.subTest(text=text):
                self.assertText(text)

    def test_a_long_line_of_bold_labels_stays_linear(self):
        import time
        line = ("**Note:** x " * 20000) + ("**" * 40000)
        t0 = time.process_time()
        scan(line)
        self.assertLess(time.process_time() - t0, 20)


# ---------------------------------------------------------------------------------- phone after a phone word --
US = "415-382-" + "9174"


class PhoneAfterWordTests(Base):
    def test_a_north_american_number_after_calling_dial_or_contact_is_masked_whole(self):
        for text in ("Please contact the report coordinator at " + US + " or visit the site.",
                     "You can reach us by calling " + US + ".", "Please contact " + US + " for help.",
                     "Dial " + US + " now."):
            with self.subTest(text=text):
                self.assertEqual(text.replace(US, "•"), masked(text, region=("us",)))

    def test_a_number_found_before_the_wider_call_words_stays_found(self):
        # the span ratchet found these (2026-10-20): a first try matched from `contact` and swallowed the later cue
        mail = "dana.ok" + "afor@posteo.de"
        for text in ("Please contact " + NAME + " at " + mail + " or " + US + ".",
                     "**Contact Roadside Assistance**: Call " + US + " for immediate help.",
                     "Or contact support at " + mail + " or " + US + "."):
            with self.subTest(text=text):
                self.assertIn("phone-after-phone-word", {m.kind for m in scan(text, region=("us",))})
                self.assertNotIn(US, masked(text, region=("us",)))

    def test_no_phone_shape_after_contact_stays_text(self):
        for text in ("contact us about ticket 415-382-9174-2 later", "contact version 2.415.382 build",
                     "Build 415-382-9174 of the contact list"):
            with self.subTest(text=text):
                self.assertNotIn("phone-after-phone-word", {m.kind for m in scan(text, region=("us",))})

    def test_a_number_after_a_contact_label_or_a_phone_word_with_its_purpose_is_masked(self):
        # Benchmark V3, dev, 2026-10-22: a contact label before its colon and "Fax number for notice:" left the number
        for pre in ("Contact: ", "- Contact information: ", "- Primary contact: ", "Emergency contact details: ",
                    "Fax number for notice: ", "Phone number for payment: ", "Please contact the following number: "):
            with self.subTest(pre=pre):
                self.assertMasked("Details\n" + pre + US + ". More text.\n", US, region=("us",))
        # the contact label takes only the strict North American form
        for text in ("Contact: 2024-10-16", "Contact information: build 4.15.382", "Contact: 12 people"):
            with self.subTest(text=text):
                self.assertNotIn("phone-after-phone-word", {m.kind for m in scan(text, region=("us",))})

    def test_a_persons_own_number_in_a_sentence_is_masked_and_a_companys_stays_text(self):
        # a person's number needs no phone word: reach out to me at, my number is (2026-10-22); a company's line in the
        # same sentence stays text, as in a table of depots
        for text in ("Feel free to reach out to me at " + US + ".", "You can reach him directly at " + US + ".",
                     "Send it to her at " + US + ".", "My number is " + US + ".", "My direct line is " + US + ".",
                     "Get me directly on " + US + ".", "Contact: **" + US + "**"):
            with self.subTest(text=text):
                self.assertMasked(text, US, region=("us",))
        for text in ("Feel free to reach out to us at " + US + ".", "Our support team is available at " + US + ".",
                     "The line is " + US + " long", "We can help you at " + US + ".", "Contact: build " + US,
                     "Contact information: ticket " + US):
            with self.subTest(text=text):
                self.assertNotIn("phone-after-phone-word", {m.kind for m in scan(text, region=("us",))})

    def test_four_counting_digits_at_the_end_are_no_placeholder_and_a_long_count_is(self):
        # a real number ends in …4567 once in about 400; a run of six digits or more is a specimen (2026-10-22)
        # a North American number went to its own rule before too; a national one of another country did not
        self.assertMasked("Phone number: 312-846-" + "4567", "312-846-" + "4567", region=("us",))
        for value in ("0221 482 " + "4567", "06-" + "4829" + "6543", "0412 739 " + "6789"):
            with self.subTest(value=value):
                self.assertMasked("Telefon: " + value, value, region=("de",))
        # 0123 456 789 is a valid national form whose only fault is that it counts
        for text in ("Telefon: 030 " + "12345678", "Mobile: 0151 " + "987654", "Telefon: 0123 456 " + "789"):
            with self.subTest(text=text):
                self.assertNotIn("phone-after-phone-word", {m.kind for m in scan(text, region=("de", "us"))})

    def test_a_national_number_after_a_phone_word_is_masked(self):
        for text, value in (
                ("Phone number: " + US, US),
                ("You can reach me at " + US + " or by mail.", US),
                ("Please call " + US.replace("-", ".") + " tomorrow.", US.replace("-", ".")),
                ('{"phone": "' + US + '", "name": "x"}', US),
                ("Telefoonnummer: 06 " + "4829 1735", "06 " + "4829 1735"),
                ("Telefon: 030 " + "4829" + "1735", "030 " + "4829" + "1735"),
                ("contact number is 07700 " + "900123", "07700 " + "900123"),
                ("Handy: 0151/" + "4829" + "1735", "0151/" + "4829" + "1735"),
                ("Phone (work): " + US, US),
                ("Tel.: 030 482917-" + "0", "030 482917-" + "0"), ("Tel: 030 482917 " + "0", "030 482917 " + "0")):
            with self.subTest(text=text):
                self.assertMasked(text, value)
                self.assertIn("phone-after-phone-word", {m.kind for m in scan(text)})

    def test_a_number_that_is_no_phone_number_stays_text(self):
        for text in ("Fax: (212) 555-" + "0147", "Phone: 415-555-" + "0123", "phone: 123-456-" + "7890",
                     "mobile: 1.2.3", "Mobile build 2024.10.16.1 shipped", "phone_verified_at: 1712345678",
                     "Phone: 2019-2024", "call took 1712345678 ms", "contact: 2024-10-16", "cell [2]: 3.14159",
                     "phone_number = models.CharField(max_length=20)", "Called 3 times in 2024-10-16 12:00:01",
                     "Mobile: 0151 1111111", "text 1234567 bytes", "Phone: 12:30 to 14:00",
                     "Phone: 2024-10-16 14:30", "mobile 2024-10-16 14:30:01 INFO app started",
                     "mobile: 3 412 908 users", "Fax: 1 500 000", "phone 4 8 15 16 23 42",
                     "Mobile build artifact: 938-274-" + "6157 completed",
                     "Mobile build artifact = 938-274-" + "6157", "Mobile build artifact - 938-274-" + "6157"):
            with self.subTest(text=text):
                self.assertNotIn("phone-after-phone-word", {m.kind for m in scan(text)})

    def test_a_national_number_written_as_one_run_is_masked_after_a_phone_word(self):
        # a German mobile number is often written without a space (a report from the gateway, 2026-10-21); one run
        # counts only when it starts with the trunk 0 or with +
        run = "0171" + "4829" + "173"
        for text in ("Telefon: " + run, '{"telefon": "' + run + '"}', '{"phone": "' + run + '"}', "Tel. " + run,
                     "Handy 0151" + "4829" + "1735"):
            with self.subTest(text=text):
                self.assertIn("phone-after-phone-word", {m.kind for m in scan(text, region=("de",))})
        self.assertMasked("Telefon: " + run, run, region=("de",))
        for text in ("Phone: 1712" + "345678", "phone: 0171" + "1111111", "Tel: 0123" + "4567" + "8901",
                     "fax: 2026" + "1021" + "120000", "Telefon: 4829" + "173"):
            with self.subTest(text=text):
                self.assertNotIn("phone-after-phone-word", {m.kind for m in scan(text, region=("de",))})

    def test_a_typed_prompt_is_not_blocked_by_it(self):
        self.assertNotIn("phone-after-phone-word", {m.kind for m in scan("Phone number: " + US, "prompt")})

    def test_a_north_american_number_needs_region_us_or_ca(self):
        self.assertNotIn("phone-after-phone-word", {m.kind for m in scan("Phone number: " + US, region=("de",))})
        self.assertIn("phone-after-phone-word", {m.kind for m in scan("Phone number: " + US, region=("ca",))})
        self.assertMasked("Telefon: 030 " + "4829" + "1735", "030 " + "4829" + "1735", region=("de",))
        # the (312) form stays with phone-us-national
        self.assertEqual({m.kind for m in scan("Tel: (312) 846-" + "2291", region=("us",))}, {"phone-us-national"})


# ------------------------------------------------------------------- one name word after a first or last name --
GIVEN, FAMILY = "Da" + "na", "Oka" + "for"


class SingleNameTests(Base):
    def test_one_name_word_after_a_first_or_last_name_label_is_masked(self):
        for text, value in (
                ("First name: " + GIVEN, GIVEN),
                ("last name: " + FAMILY, FAMILY),
                ('{"first_name": "' + GIVEN + '", "last_name": "' + FAMILY + '"}', FAMILY),
                ("Vorname: Jürgen\nNachname: " + FAMILY, FAMILY),
                ("Prénom : Amélie", "Amélie"),
                ("Last name: Nguy" + "ễn", "Nguy" + "ễn"),
                ("First name: Nguye\u0302" + "n", "Nguye\u0302" + "n"),
                ("First name: \u1ea0" + "nh", "\u1ea0" + "nh"),
                ("First name: Mark", "Mark")):
            with self.subTest(text=text):
                self.assertMasked(text, value)
                self.assertIn("name-single-after-label", {m.kind for m in scan(text)})

    def test_a_word_a_type_a_state_or_a_documentation_name_stays_text(self):
        for text in ("first_name: String", "last name: Required", 'first_name = "John"', "last_name: Doe",
                     "surname: Text", "last name: Baker", "first_name: Optional[str] = None", "first name: <name>",
                     "given_name: Unknown", "first_name = models.CharField(max_length=30)", "lastName: Mustermann",
                     "first name: Max Mustermann", "last_name: Nullable", "first_name: Hashed",
                     '{"first_name": "Vorname", "last_name": "Nachname", "surname": "Familienname"}',
                     "first_name: Prénom\nlast_name: Nom", "first_name=Imię\nlast_name=Nazwisko",
                     '"firstName": "Firstname"', "last_name: Deprecated", "first_name: Unicode",
                     '{"first_name":"Texte"}', '{"first_name":"Zeichenfolge"}', "first_name: Prenume\nlast_name: Nume",
                     '{"first_name": "Vardas", "last_name": "Pavard\u0117"}', "first_name: Input"):
            with self.subTest(text=text):
                self.assertNotIn("name-single-after-label", {m.kind for m in scan(text)})

    def test_two_words_are_left_to_the_name_rule(self):
        kinds = {m.kind for m in scan("Last name: " + FAMILY + " Smith")}
        self.assertEqual(kinds, {"name-after-label"})

    def test_a_double_surname_with_two_capitals_is_masked_whole(self):
        double = "Okafor-" + "Brandt"
        for text in ("Last Name: " + double + "\nDate of Birth: none", "- **Last Name:** " + double + "\n- **City:** x",
                     "Nachname: " + double + ", Vorname: none"):
            with self.subTest(text=text):
                self.assertEqual(text.replace(double, "•"), masked(text))

    def test_a_name_after_first_or_last_name_is_in_a_sentence_is_masked(self):
        for text in ("My last name is " + FAMILY + ".", "The patient's last name is " + FAMILY + ".",
                     "Your first name is " + GIVEN + ", and your date of birth follows."):
            with self.subTest(text=text):
                value = FAMILY if FAMILY in text else GIVEN
                self.assertEqual(text.replace(value, "•"), masked(text))

    def test_a_state_or_a_type_after_name_is_stays_text(self):
        for text in ("The first name is required.", "First name is Required", "The last name is Optional here",
                     "first name is String", "The last name is Unknown."):
            with self.subTest(text=text):
                self.assertNotIn("name-single-after-label", {m.kind for m in scan(text)})

    def test_a_hyphenated_value_of_words_stays_text(self):
        for text in ("Last Name: Self-Employed\n", "Last Name: Non-Applicable\n",
                     "last_name: Auto-Generated\n"):
            with self.subTest(text=text):
                self.assertNotIn("name-single-after-label", {m.kind for m in scan(text)})


class DutchAndSwedishNameLabelTests(Base):
    def test_a_name_after_naam_or_namn_is_masked_whole(self):
        name = "Daan " + "Bakker"
        for text in ("Naam: " + name + "\nAdres: Kerkstraat 1", "Namn: " + name + "\n"):
            with self.subTest(text=text):
                self.assertEqual(text.replace(name, "•"), masked(text))

    def test_words_after_naam_stay_text(self):
        for text in ("Naam: Product Owner\n", "naam: Build Pipeline"):
            with self.subTest(text=text):
                self.assertNotIn("name-after-label", {m.kind for m in scan(text)})


class AddressLabelsInMoreLanguagesTests(Base):
    def test_an_address_after_adres_adress_indirizzo_anschrift_or_street_address_is_masked_whole(self):
        for text, value in (("Adres: Kerkstraat 12, 1012 AB Amsterdam\n", "Kerkstraat 12, 1012 AB Amsterdam"),
                            ("Adress: Storgatan 5, 111 22 Stockholm\n", "Storgatan 5, 111 22 Stockholm"),
                            ("Indirizzo: Via Roma 12, 00184 Roma\n", "Via Roma 12, 00184 Roma"),
                            ("Anschrift: Lindenweg 4, 80333 München\n", "Lindenweg 4, 80333 München"),
                            ("street_address: 12 Oak Street, Springfield\n", "12 Oak Street, Springfield")):
            with self.subTest(text=text):
                self.assertEqual(text.replace(value, "•"), masked(text))

    def test_a_value_that_is_no_address_after_the_new_labels_stays_text(self):
        for text in ("Adres: zie hieronder, versie 1.2.3\n", "Indirizzo: vedi sotto\n", "Anschrift: siehe oben\n"):
            with self.subTest(text=text):
                self.assertText(text)


class UsAddressOnTwoLinesTests(Base):
    STREET = "4821 Harbor " + "Mission Apt. 5\nSpringfield, IL 62704"
    MILITARY = "PSC 1234, Box " + "5678\nAPO AE 09876"

    def test_a_us_address_on_two_lines_is_masked_whole(self):
        for text, value in (("I live at " + self.STREET + " and work nearby.", self.STREET),
                            ("Mail it to:\n" + self.MILITARY + "\n", self.MILITARY),
                            (self.STREET + "\n", self.STREET),
                            ("your home address (" + self.STREET + "), email", self.STREET),
                            ("update my home address " + self.STREET + " please", self.STREET)):
            with self.subTest(text=text):
                self.assertEqual(text.replace(value, "•"), masked(text, region=("us",)))

    def test_a_heading_or_a_company_over_a_city_line_stays_text(self):
        for text in ("Release 2 Notes\nAustin, TX 78701 office", "Chapter 12 Summary\nSee Page, IL 60601",
                     "Acme Corporation\nHeadquarters\n" + self.STREET + "\n"):
            with self.subTest(text=text):
                self.assertNotIn("address-us-two-lines", {m.kind for m in scan(text, region=("us",))})


class NameNextToAPersonCueTests(Base):
    def test_a_name_in_a_declaration_a_self_introduction_or_before_its_birth_is_masked_whole(self):
        for text in ("I, " + NAME + ", hereby declare that the above is true.",
                     "Hello, my name is " + NAME + " and I am writing about my claim.",
                     "Patient " + NAME + ", born on " + BIRTH + ", was seen today.",
                     "The policyholder, " + NAME + ", a resident of Springfield, signed."):
            with self.subTest(text=text):
                # the birth date has its own rule
                self.assertEqual(text.replace(NAME, "•", 1).replace(BIRTH, "•"), masked(text).replace(BIRTH, "•"))

    def test_a_full_name_after_a_title_is_masked_whole(self):
        for text in ("Dear Mr " + NAME + ", we have received your application.",
                     "The claim was initiated by Mrs. " + NAME + " for her son."):
            with self.subTest(text=text):
                self.assertEqual(text.replace(NAME, "•"), masked(text))

    def test_a_full_name_after_a_salutation_is_masked_whole(self):
        for text in ("Dear " + NAME + ",\nThank you for your application.", "Hello " + NAME + "! Welcome aboard."):
            with self.subTest(text=text):
                self.assertEqual(text.replace(NAME, "•"), masked(text))

    def test_the_role_words_of_a_salutation_do_not_touch_the_other_cues(self):
        # the span ratchet found it (2026-10-20): `Participant <name>, born on` was found before the role list
        text = "Participant Okafor, born on " + BIRTH + ", was seen today."
        self.assertIn("name-next-to-a-person-cue", {m.kind for m in scan(text)})

    def test_a_role_or_a_placeholder_after_a_salutation_stays_text(self):
        for text in ("Dear Valued Policyholder,\n", "Dear Hiring Manager,\n", "Dear Customer,\n", "Dear John Doe,\n",
                     "Hi Team Leads,\n"):
            with self.subTest(text=text):
                self.assertNotIn("name-next-to-a-person-cue", {m.kind for m in scan(text)})

    def test_a_title_before_words_one_word_or_a_street_stays_text(self):
        for text in ("Open the Ms Word Document first.", "Mr Product Owner will decide.", "Mr John Doe is a sample.",
                     "Visit us at 12 Oak Dr. We are open daily."):
            with self.subTest(text=text):
                self.assertNotIn("name-next-to-a-person-cue", {m.kind for m in scan(text)})

    def test_one_word_words_a_role_or_a_placeholder_next_to_a_cue_stay_text(self):
        for text in ("The Applicant, born on the date given above, signs here.", "Texas, born on paper, grew.",
                     "my name is Required Field in this schema", "I, John Doe, hereby confirm the template.",
                     "I, Product Owner, am responsible for the backlog."):
            with self.subTest(text=text):
                self.assertNotIn("name-next-to-a-person-cue", {m.kind for m in scan(text)})


# ------------------------------------------------------------------- a street line after an address label --
STREET = "4821 Maple " + "Ridge Drive"


class StreetLineTests(Base):
    def test_a_street_line_after_an_address_label_or_a_verb_of_residence_is_masked(self):
        for text, value in (
                ("Street address: " + STREET, STREET),
                ("The tenant resides at 77 Harbour " + "Lane, Apt 4B.", "77 Harbour " + "Lane, Apt 4B"),
                ('{"address": "' + STREET + '", "city": "Springfield"}', STREET),
                ("Anschrift: Linden" + "straße 42", "Linden" + "straße 42"),
                ("Frau Okafor wohnt in der Garten" + "straße 3a.", "Garten" + "straße 3a"),
                ("Indirizzo: Via Roma " + "12", "Via Roma " + "12"),
                ("Street address: 123 5th " + "Avenue", "123 5th " + "Avenue"),
                ("Bank account status: active\nAddress: 100 Harbour " + "Lane", "100 Harbour " + "Lane"),
                ("The patient lives at " + STREET + " with her son.", STREET),
                ("Dana, our office manager, lives at 12 Oak " + "Street", "12 Oak " + "Street"),
                ("Her daughter works at the store and lives at 12 Oak " + "Street", "12 Oak " + "Street"),
                ("Return address: 12 Oak " + "Street", "12 Oak " + "Street")):
            with self.subTest(text=text):
                self.assertMasked(text, value)
                self.assertIn("address-street-after-label", {m.kind for m in scan(text)})

    def test_a_company_or_public_address_and_a_street_shape_in_code_stay_text(self):
        for text in ("Our office address: 100 Main Street", "Beispiel GmbH, Address: 100 Main Street",
                     "The Empire State Building is located at 350 Fifth Avenue", "Listen address: 8080 Rack Row",
                     "address: 0x7fff Main Street", "Hotel address: 1 Harbour Lane",
                     "address: see the 2 Main Street docs", "lives at: the 3 Root Path",
                     "IP address: 10 Network " + "Drive", "address: 0 Main " + "Street",
                     "The server lives at 10 Downing " + "Street", "Our store lives on 5 Market " + "Street",
                     "Warehouse address: 9 Industrial " + "Road", "The API lives at 10 Data " + "Drive"):
            with self.subTest(text=text):
                self.assertNotIn("address-street-after-label", {m.kind for m in scan(text)})

    def test_a_company_on_the_line_before_keeps_the_address_text_and_a_home_label_keeps_it_masked(self):
        for text in ("Acme Inc.\nAddress: 100 Harbour Lane", "Employer address: 100 Harbour Lane",
                     "Northwind Industries\nStreet Address: " + STREET,
                     "First Harbour Bank\nAddress: 100 Harbour Lane"):
            with self.subTest(text=text):
                self.assertNotIn("address-street-after-label", {m.kind for m in scan(text)})
        self.assertMasked("Employer: Acme Inc.\nHome address: 12 Harbour Lane", "12 Harbour Lane")
        self.assertMasked("Name: " + NAME + "\nAddress: " + STREET, STREET)

    def test_a_direction_and_a_unit_after_the_street_type_are_masked_with_the_street(self):
        # masked() puts one mark where a hit was: the whole value goes, and nothing after it
        for text, value in (
                ("Street Address: 12 Oak " + "Street SW\nCity: Springfield", "12 Oak " + "Street SW"),
                ("I live at 12 Oak " + "Street 99, in Springfield.", "12 Oak " + "Street 99"),
                ("Address: 12 Oak " + "Street N Ste A | Phone: none", "12 Oak " + "Street N Ste A"),
                ("She resides at 12 Oak " + "Avenue 9E, in Springfield", "12 Oak " + "Avenue 9E"),
                ("- **Street Address:** 12 Oak " + "Road NE C\n- **City:** Springfield", "12 Oak " + "Road NE C"),
                ("He lives at 12 Oak " + "Street B999.", "12 Oak " + "Street B999"),
                ("I reside at 12 Oak " + "Lane Southwest and work from home.", "12 Oak " + "Lane Southwest")):
            with self.subTest(text=text):
                self.assertEqual(text.replace(value, "•"), masked(text))

    def test_a_number_or_a_direction_that_goes_on_in_the_sentence_stays_text(self):
        for text, value, rest in (
                ("I live at 12 Oak " + "Street 3 days a week.", "12 Oak " + "Street", " 3 days"),
                ("Address: 12 Oak " + "Street West of the river", "12 Oak " + "Street", " West of"),
                ("He lives at 12 Oak " + "Street 5 more", "12 Oak " + "Street", " 5 more")):
            with self.subTest(text=text):
                self.assertEqual(text.replace(value, "•"), masked(text))
                self.assertIn(rest, masked(text))

    def test_a_companys_address_takes_the_company_decision(self):
        company: list = []
        from maisecrets import personal
        personal.hits("Beispiel GmbH, Address: 100 Main Street", "tool", ("us",), company)
        self.assertIn("address-street-after-label", {c[4] for c in company})


# ----------------------------------------------------------------------- person columns of a Markdown table --
class MarkdownTableTests(Base):
    def test_a_table_of_fields_and_values_is_one_record(self):
        street = "12 Oak Lane, Springfield"
        for text in ("| Field | Value |\n|---|---|\n| Full Name | " + NAME + " |\n| Date of Birth | " + BIRTH
                     + " |\n| Street Address | " + street + " |\n",
                     "| **Full Name** | " + NAME + " |\n|---|---|\n| **Date of Birth** | " + BIRTH + " |\n"):
            with self.subTest(text=text):
                expected = text.replace(NAME, "•").replace(BIRTH, "•").replace(street, "•")
                self.assertEqual(expected, masked(text))

    def test_a_first_or_last_name_field_of_a_record_is_a_name(self):
        first, last = NAME.split()
        for text in ("| Field | Value |\n|---|---|\n| First Name | " + first + " |\n| Last Name | " + last
                     + " |\n| Date of Birth | " + BIRTH + " |\n",
                     "first_name,last_name,dob\n" + first + "," + last + "," + BIRTH + "\n"):
            with self.subTest(text=text):
                self.assertMasked(text, first)
                self.assertMasked(text, last)

    def test_a_name_part_field_without_a_person_or_with_a_form_word_stays_text(self):
        first, last = NAME.split()
        # a first and a last name alone make no record; a form word is no name
        self.assertText("| Field | Value |\n|---|---|\n| First Name | " + first + " |\n| Last Name | " + last + " |\n")
        self.assertText("| Field | Value |\n|---|---|\n| First Name | Required |\n| Last Name | Optional |\n"
                        "| Date of Birth | " + BIRTH + " |\n")

    def test_the_names_of_a_fixture_in_name_part_fields_stay_text(self):
        # seed data and API examples: fixture words, and a first and a last name that make a placeholder together
        for text in ("first_name,last_name,dob\nFoo,Bar,1999-12-31\nTest,User,2000-01-01\n",
                     '{"first_name": "Jane", "last_name": "Doe", "date_of_birth": "1990-01-01"}',
                     "| Field | Value |\n|---|---|\n| First Name | John |\n| Last Name | Doe |\n"
                     "| Date of Birth | " + BIRTH + " |\n"):
            with self.subTest(text=text):
                self.assertNotIn("NAME", {m.type for m in scan(text)})

    def test_the_name_column_of_a_person_in_a_role_counts_beside_a_strong_column(self):
        for head in ("Candidate Name", "Client Name", "Player Name", "Recipient Name", "Applicant Name", "Student Name",
                     "Member Name", "Contact Name", "Passenger Name", "Beneficiary Name", "Tenant Name"):
            with self.subTest(head=head):
                self.assertMasked("| " + head + " | Date of Birth |\n|---|---|\n| " + NAME + " | " + BIRTH + " |\n",
                                  NAME)
                # without a strong column a list of names is no record (a score board)
                self.assertText("| " + head + " | Score |\n|---|---|\n| " + NAME + " | 88 |\n")
                # the same field in camel case in a JSON record
                key = head.split()[0].lower() + "Name"
                self.assertMasked('{"' + key + '": "' + NAME + '", "dateOfBirth": "' + BIRTH + '"}', NAME)

    def test_a_table_of_fields_without_a_person_stays_text(self):
        for text in ("| Name | Value |\n|---|---|\n| Product Name | Widget Pro |\n| Version | 2.1 |\n",
                     "| Setting | Value |\n|---|---|\n| Name | build-runner |\n"
                     "| Address | 10 Oak Lane, Springfield |\n"):
            with self.subTest(text=text):
                self.assertNotIn("md-table-personal-column", {m.kind for m in scan(text)})

    TABLE = ("| Name | Date of Birth | Phone Number |\n|------|---------------|--------------|\n"
             "| " + NAME + " | " + BIRTH + " | " + US + " |\n")

    def test_the_person_columns_of_a_markdown_table_mask_their_cells(self):
        for value in (NAME, BIRTH, US):
            self.assertMasked(self.TABLE, value)
        self.assertIn("md-table-personal-column", {m.kind for m in scan(self.TABLE)})
        # a table without the outer bars
        self.assertMasked("Name | Phone\n--- | ---\n" + NAME + " | 030 846 " + "2291 |", NAME)
        self.assertMasked("| Patient Name | MRN |\n|:---|---:|\n| " + NAME + " | " + "4821" + "3977 |", "4821" + "3977")

    def test_a_table_without_a_person_stays_text(self):
        for text in ("| Name | Version | Phone |\n|---|---|---|\n| maisecrets | 0.6.31 | n/a |",
                     "| Depot | Address | Phone |\n|---|---|---|\n| North | 12 Harbour Lane, Dunmore | " + US + " |",
                     "| Field | Type | Description |\n|---|---|---|\n| name | string | Full Name |",
                     "| Name | Phone |\n|---|---|\n| Front Desk | " + US + " |",
                     "| Name | Address |\n|---|---|\n| Zorvia Quent | 127.0.0.1:8080 |",
                     "| Name | Address | DOB |\n|---|---|---|\n| Zorvia Quent | db.internal:5432 | n/a |",
                     "| Name | Date of Birth |\n|---|---|\n| Release Candidate | 2024-05-01 |",
                     "| Name | Address | DOB |\n| --- | --- | --- |\n| Orion Vega | node1.acme.dev | n/a |"):
            with self.subTest(text=text):
                self.assertText(text)
        self.assertText("name,address\nZorvia Quent,127.0.0.1:8080\n")

    def test_a_long_separator_line_stays_linear(self):
        import time
        for sep in ("|---|---" + " " * 1990 + "x", "|" + "---|" * 490 + "x", " " * 1990 + "x"):
            t0 = time.process_time()
            scan("| Name | DOB |\n" + sep + "\n| " + NAME + " | " + BIRTH + " |")
            self.assertLess(time.process_time() - t0, 5)


# ------------------------------------------------------------------------------- health, tax and national IDs --
class HealthIdLabelTests(Base):
    def test_an_id_after_its_label_and_a_comma_is_masked_whole(self):
        value = "AB-" + "4821930217"
        for text in ("Provide your health plan beneficiary number, " + value + ", to medical professionals.",
                     "Have a medical record number, " + value + ", that can be verified."):
            with self.subTest(text=text):
                self.assertEqual(text.replace(value, "•"), masked(text))

    def test_a_comma_after_an_id_label_and_no_id_stays_text(self):
        for text in ("Passport, 12 copies attached", "account number, see page 4",
                     "medical record number, 2024 edition"):
            with self.subTest(text=text):
                self.assertNotIn("id-number-after-label", {m.kind for m in scan(text)})

    def test_an_id_after_a_health_tax_or_national_label_is_masked(self):
        for text, value in (
                ("Health plan beneficiary number: " + "4821" + "39771", "4821" + "39771"),
                ("The patient's medical record number is MRX-" + "4821" + "3977.", "MRX-" + "4821" + "3977"),
                ("National ID: " + "7741 2290 " + "5531", "7741 2290 " + "5531"),
                ("Tax ID number: " + "48-21" + "39771", "48-21" + "39771"),
                ('beneficiary_id = "BNF-' + "4821" + '397"', "BNF-" + "4821" + "397")):
            with self.subTest(text=text):
                self.assertMasked(text, value)
                self.assertIn("id-number-after-label", {m.kind for m in scan(text)})

    def test_the_label_without_a_number_stays_text(self):
        for text in ("Medical record: see the chart (no number yet)", "national_id: str = Field(..., max_length=12)",
                     "TIN format: 9 digits", "Tax ID: ${TAX_ID}", "national id card 123456789",
                     "beneficiary: the person who receives the payout", "Beneficiary: VENDOR " + "00042",
                     "Social Security: 2024 COLA " + "3.2"):
            with self.subTest(text=text):
                self.assertText(text)


# --------------------------------------------------------------- passport and driving licence, EU languages --
class TravelIdLabelTests(Base):
    def test_a_passport_or_licence_number_after_its_label_in_an_eu_language_is_masked(self):
        for label in ("Führerscheinnummer:", "Pass-Nr.", "permis de conduire n°", "Número de pasaporte:",
                      "carnet de conducir:", "numero di passaporto", "patente di guida:", "Paspoortnummer:",
                      "rijbewijsnummer", "Passaporte n.º", "körkortsnummer", "numer paszportu:", "Numer prawa jazdy:",
                      "driving licence number:"):
            value = "XC" + "4821" + "3977"
            with self.subTest(label=label):
                self.assertMasked(label + " " + value, value)
                self.assertIn("id-number-after-label", {m.kind for m in scan(label + " " + value)})

    def test_a_patent_a_password_and_a_label_without_a_number_stay_text(self):
        for text in ("Patente: EP" + "1234567", "pass: " + "48213977", "Reisepass: abgelaufen, neu beantragen",
                     "permis de conduire: catégorie B", "numero di passaporto: vedi allegato"):
            with self.subTest(text=text):
                self.assertNotIn("id-number-after-label", {m.kind for m in scan(text)})



# ------------------------------------------------------------- a unit or a short street name before its number --
class AddressUnitAfterADotTests(Base):
    def assertMaskedExactly(self, text: str, value: str) -> None:
        """the whole value is masked, and nothing after it"""
        s = text.index(value)
        out = masked(text)
        self.assertTrue(out.startswith(text[:s]) and out.endswith(text[s + len(value):]), "masked too much")
        self.assertFalse(any(c.isalnum() for c in out[s:len(out) - len(text) + s + len(value)]), "a part stays")

    def test_the_number_after_ste_apt_or_a_short_street_name_is_part_of_the_address(self):
        for text, value in (
                ("Address: 1200 Harbor " + "Road, Ste. 300\n", "1200 Harbor " + "Road, Ste. 300"),
                ("Address: 48 Maple " + "Drive, Apt. 12\n", "48 Maple " + "Drive, Apt. 12"),
                ("Adresse: Linden" + "str. 5, 10115 Berlin\n", "Linden" + "str. 5, 10115 Berlin")):
            with self.subTest(text=text):
                self.assertMaskedExactly(text, value)

    def test_a_dot_that_ends_a_sentence_still_ends_the_address(self):
        for text, value in (
                ("Address: 12 Oak " + "Lane, Springfield. 3 people live there.", "12 Oak " + "Lane, Springfield"),
                ("Address: 12 Paste " + "Road, Main. 300 more", "12 Paste " + "Road, Main")):
            with self.subTest(text=text):
                self.assertMaskedExactly(text, value)



# ------------------------------------------------------------------------------- a phone extension after the number --
class PhoneExtensionTests(Base):
    US = "(212) 846-" + "2291"
    INTL = "+1 212 846 " + "2291"

    def assertWholeAndNoMore(self, text: str, value: str) -> None:
        s = text.index(value)
        out = masked(text, region=("us",))
        self.assertTrue(out.startswith(text[:s]) and out.endswith(text[s + len(value):]), "masked too much")
        self.assertFalse(any(c.isalnum() for c in out[s:len(out) - len(text) + s + len(value)]), "a part stays")

    def test_the_extension_is_masked_with_the_number(self):
        for text, value in (("Phone: " + self.US + "x204 today", self.US + "x204"),
                            ("Phone: " + self.INTL + " ext. 31 today", self.INTL + " ext. 31"),
                            ("phone: 212.846." + "2291 x1234 done", "212.846." + "2291 x1234")):
            with self.subTest(text=len(text)):
                self.assertWholeAndNoMore(text, value)

    def test_a_word_after_the_number_and_a_hex_like_token_stay_text(self):
        self.assertWholeAndNoMore("Phone: " + self.US + " extra", self.US)
        self.assertText("build 1234x5678", region=("us",))



# ------------------------------------------------------------------- personal columns of SQL and HTML tables --
class SqlAndHtmlTableTests(Base):
    LEE = "Lee " + "Kim"
    OAK = "12 Oak " + "Lane"
    SQL = ("INSERT INTO customers (order_id, full_name, street, dob) VALUES\n"
           "  ('1234', '" + NAME + "', '" + STREET + "', '" + BIRTH + "'),\n"
           "  ('99', '" + LEE + "', '" + OAK + "', '1990-01-" + "02');\n")
    HTML = ("<table>\n  <tr><th>order_id</th><th>full_name</th><th>street</th></tr>\n"
            "  <tr><td>1234</td><td>" + NAME + "</td><td>" + STREET + "</td></tr>\n</table>\n")

    def test_the_personal_columns_of_each_row_are_masked(self):
        for text, values in ((self.SQL, (NAME, STREET, BIRTH, self.LEE, self.OAK)), (self.HTML, (NAME, STREET))):
            out = masked(text, region=("us",))
            for v in values:
                with self.subTest(v=len(v)):
                    self.assertNotIn(v, out)
            self.assertIn("1234", out, "an order number stays text")

    def test_a_table_without_a_person_stays_text(self):
        for text in ("INSERT INTO depots (code, street) VALUES ('A1', '" + STREET + "');",
                     "<table><tr><th>name</th><th>price</th></tr><tr><td>Desk Lamp</td><td>12.50</td></tr></table>",
                     "INSERT INTO products (name, sku) VALUES ('Desk Lamp', 'DL-1');"):
            with self.subTest(text=text[:20]):
                self.assertText(text, region=("us",))


    def test_inline_tags_a_head_and_a_body_and_quoted_column_names_still_name_the_cells(self):
        for text, values in (
                ("<table class='x'><thead><tr><th scope='col'>full_name</th><th>street</th></tr></thead><tbody>"
                 "<tr><td><a href='/c/7'>" + NAME + "</a></td><td><span>" + STREET + "</span></td></tr></tbody>"
                 "</table>", (NAME, STREET)),
                ('INSERT INTO "customers" ("full_name", "street", "dob") VALUES (\'' + NAME + "', '" + STREET
                 + "', NULL);", (NAME, STREET))):
            out = masked(text, region=("us",))
            for v in values:
                with self.subTest(v=len(v)):
                    self.assertNotIn(v, out)

    def test_a_business_table_stays_text(self):
        phone = "(415) 382-" + "9174"
        for text in ("INSERT INTO offices (name, street, phone) VALUES ('Berlin Office', '" + STREET + "', '"
                     + phone + "');",
                     "INSERT INTO companies (name, address) VALUES ('Acme Logistics GmbH', '" + STREET + "');",
                     "INSERT INTO venues (venue_name, street) VALUES ('Harbor Hall', '" + STREET + "');",
                     "INSERT INTO depots (name, street, phone) VALUES ('North Depot', '" + STREET + "', '" + phone
                     + "');",
                     "INSERT INTO branches (branch, street) VALUES ('Downtown Branch', '" + STREET + "');",
                     "INSERT INTO warehouses (name, address) VALUES ('Warehouse 7', '" + STREET + "'), "
                     "('Central Warehouse', '" + self.OAK + "');",
                     "<table><tr><th>name</th><th>street</th><th>phone</th></tr><tr><td>Berlin Office</td><td>"
                     + STREET + "</td><td>" + phone + "</td></tr></table>",
                     "<table><tr><th>company</th><th>address</th></tr><tr><td>Acme Inc.</td><td>" + STREET
                     + "</td></tr></table>",
                     "<table><tr><th>name</th><th>address</th></tr><tr><td>Riverside Arena</td><td>" + STREET
                     + "</td></tr></table>"):
            with self.subTest(text=text[:30]):
                self.assertIn(STREET, masked(text, region=("us",)))

    def test_a_malformed_statement_or_table_names_no_cell(self):
        for text in ("INSERT INTO customers (full_name, street) VALUES ('" + NAME + "', '" + STREET + "'",
                     "INSERT INTO customers (full_name, street, dob) VALUES ('" + NAME + "', '" + STREET + "');",
                     "INSERT INTO customers VALUES ('" + NAME + "', '" + STREET + "');",
                     "<table><tr><td>full_name</td><td>street</td></tr><tr><td>" + NAME + "</td><td>" + STREET
                     + "</td></tr></table>",
                     "<table><tr><th>full_name</th><th>street</th></tr><tr><td>" + NAME + "</td><td>" + STREET
                     + "</td></tr>",
                     "<table><tr><th>full_name</th><th>street</th></tr><tr><td colspan=2>" + NAME + " " + STREET
                     + "</td></tr></table>",
                     "<table><tr><th>full_name</th><th>street</th></tr><tr><td>" + NAME + " <i>VIP</i></td><td>"
                     + STREET + "</td></tr></table>"):
            with self.subTest(text=text[:30]):
                self.assertNotIn("-personal-column", " ".join(m.kind for m in scan(text, region=("us",))))


# --------------------------------------------------------------- personal fields of JSON objects and XML records --
class JsonAndXmlRecordTests(Base):
    LEE = "Lee " + "Kim"
    OAK = "12 Oak " + "Lane"

    def test_the_personal_fields_of_a_record_are_masked(self):
        for text, values in (
                ('{"order_id": 1234, "full_name": "' + NAME + '", "address_line1": "' + STREET + '"}', (NAME, STREET)),
                ('{"data": [{"customer_name": "' + NAME + '", "street": "' + STREET + '"}, {"customer_name": "'
                 + self.LEE + '", "street": "' + self.OAK + '"}]}', (NAME, STREET, self.LEE, self.OAK)),
                ('{"fullName": "' + NAME + '", "streetAddress": "' + STREET + '"}', (NAME, STREET)),
                ('<?xml version="1.0"?><records><record><full_name>' + NAME + "</full_name><street>" + STREET
                 + "</street></record></records>", (NAME, STREET))):
            out = masked(text, region=("us",))
            for v in values:
                with self.subTest(v=len(v), text=text[:12]):
                    self.assertNotIn(v, out)

    def test_a_record_of_a_place_or_text_with_markup_stays_text(self):
        for text in ('{"name": "Berlin Office", "street": "' + STREET + '"}',
                     "<venues><venue><name>Riverside Arena</name><address>" + STREET + "</address></venue></venues>",
                     "<p>Hello <full_name>" + NAME + "</full_name> at <street>" + STREET + "</street></p>",
                     '{"warehouse": "Warehouse 7", "address": "' + STREET + '"}'):
            with self.subTest(text=text[:20]):
                self.assertIn(STREET, masked(text, region=("us",)))

    def test_a_broken_record_names_no_field(self):
        for text in ('{"full_name": "' + NAME + '", "street": "' + STREET,
                     "<record><full_name>" + NAME + "</full_name><street>" + STREET + "</record>"):
            with self.subTest(text=text[:20]):
                self.assertNotIn("-personal-field", " ".join(m.kind for m in scan(text, region=("us",))))



# ------------------------------------------- one field policy: names folded, attributes, one level of nesting --
class RecordFieldNameTests(Base):
    def assertBothMasked(self, text: str) -> None:
        out = masked(text, region=("us",))
        for v in (NAME, STREET):
            with self.subTest(v=len(v), text=text[:24]):
                self.assertNotIn(v, out)

    def test_a_namespace_an_escape_or_another_language_names_the_column(self):
        for text in ("<fpml:party><fpml:full_name>" + NAME + "</fpml:full_name><fpml:street>" + STREET
                     + "</fpml:street></fpml:party>",
                     '"order",first\\_name\\_full,"full\\_name","street\\_address"\n"1","x","' + NAME + '","'
                     + STREET + '"\n',
                     "<kund><namn>" + NAME + "</namn><adress>" + STREET + "</adress></kund>",
                     '{"cognome": "x", "nome": "' + NAME + '", "indirizzo": "' + STREET + '"}'):
            self.assertBothMasked(text)

    def test_the_attributes_of_an_element_are_a_record(self):
        # address_line1 is a field name the column policy knows and no label rule does: only the record reads it
        self.assertBothMasked('<Customer customer_name="' + NAME + '" address_line1="' + STREET + '" tier="gold"/>')
        self.assertIn(STREET, masked('<Office name="Berlin Office" street="' + STREET + '"/>', region=("us",)))

    def test_a_record_nested_right_in_a_person_record_joins_it(self):
        self.assertBothMasked("<party id='p1'><name>" + NAME + "</name><postalAddress><streetAddress>" + STREET
                              + "</streetAddress><city>Springfield</city></postalAddress></party>")
        self.assertBothMasked('{"customer": {"full_name": "' + NAME + '", "address": {"street": "' + STREET
                              + '", "city": "Springfield"}}}')

    def test_a_company_with_a_branch_and_a_record_two_levels_down_stay_text(self):
        for text in ("<company><name>Acme Logistics GmbH</name><branch><street>" + STREET
                     + "</street></branch></company>",
                     "<p><name>" + NAME + "</name><contact><postal><street>" + STREET
                     + "</street></postal></contact></p>"):
            with self.subTest(text=text[:20]):
                self.assertIn(STREET, masked(text, region=("us",)))


# ------------------------------------------------------------ the place after a street belongs to the address --
class AddressWithItsPlaceTests(Base):
    def assertWhole(self, text: str, value: str) -> None:
        s = text.index(value)
        out = masked(text, region=("us", "de"))
        self.assertTrue(out.startswith(text[:s]) and out.endswith(text[s + len(value):]), "masked too much")
        self.assertFalse(any(c.isalnum() for c in out[s:len(out) - len(text) + s + len(value)]), "a part stays")

    def test_the_postcode_the_city_and_the_country_after_a_street_are_masked_with_it(self):
        for text, value in (
                ("Address: 12 Via " + "Roma, 00184 Roma\n", "12 Via " + "Roma, 00184 Roma"),
                ("Street address: " + STREET + ", Springfield, IL 62704, USA\n",
                 STREET + ", Springfield, IL 62704, USA"),
                ("Kunde: Max-Planck-Straße " + "12, 80333 München, Deutschland\n",
                 "Max-Planck-Straße " + "12, 80333 München, Deutschland"),
                ("Lieferadresse 99 Rue de " + "Rivoli, 75001 Paris\n", "99 Rue de " + "Rivoli, 75001 Paris")):
            with self.subTest(text=text[:16]):
                self.assertWhole(text, value)

    def test_a_street_line_that_no_other_rule_found_stays_text(self):
        # the European form only widens a hit of another rule: a company seat or a hospital alone is no person's
        for text in ("Siège social : 99 Rue de " + "Rivoli, 75001 Paris\n",
                     "Lieu de destination : Hôpital Saint-Antoine, 184 Rue du " + "Faubourg, 75012 Paris\n"):
            with self.subTest(text=text[:16]):
                self.assertText(text, region=("us",))

    def test_a_number_and_a_postcode_without_a_street_word_stay_text(self):
        for text in ("Release notes version 12, 2024 Edition\n", "Order 12, 80333 Units shipped\n",
                     "Chapter 4, 1999 Edition\n"):
            with self.subTest(text=text[:16]):
                self.assertText(text, region=("us", "de"))



# ------------------------------------------------- no value found in part before 0.6.42 is found no more since --
class NoValueLostAgainTests(Base):
    """Found by the per-span ratchet of scripts/compare_bench.py over the releases 0.6.41 to 0.7.0: spans that a
    release made worse. Each value here was masked at least in part before and was in the clear after."""

    def test_a_double_name_whose_second_part_is_a_word_is_masked(self):
        # a second surname with the ending of a noun (Fleming, Waters) made the whole value read as words
        for text, value in (("Name: Jasmijn Bakker-" + "Fleming, Passport Number: X\n", "Jasmijn Bakker-" + "Fleming"),
                            ("- Name: Dana Okafor-" + "Waters\n- Street Address: x\n", "Dana Okafor-" + "Waters"),
                            # and the other way round: a first surname that is a word alone (llano)
                            ("Name: Leonor Llanos-" + "Pacheco\n", "Leonor Llanos-" + "Pacheco")):
            with self.subTest(text=text[:12]):
                self.assertMasked(text, value)

    def test_a_double_name_that_runs_on_into_the_next_label_is_masked_up_to_its_surname(self):
        text = "Name: Ana Ruiz-" + "Diaz Address: 12 Oak Lane\n"
        out = masked(text, region=("us",))
        self.assertNotIn("Ruiz", out)
        self.assertNotIn("Diaz", out)
        self.assertText("Name: Product Owner-Lead Meeting\n", region=("us",))

    def test_an_address_with_a_template_after_its_unit_keeps_the_street_masked(self):
        # street names without a street word (Pine Ridge): only the value after the label finds them
        for text in ("Address: 12345 Pine " + "Ridge, Apt. 999, [City], [State], [Zip Code]\n",
                     "Home Address: 999 Oak " + "Hollow, Apt. 12 (as an example only)\n",
                     "Mailing Address: 4821 Maple " + "Crest, Apt. 77, and the property is leased until May.\n"):
            with self.subTest(text=text[:14]):
                out = masked(text, region=("us",))
                self.assertNotIn(text.split(": ")[1].split(",")[0], out)


if __name__ == "__main__":
    unittest.main()


class ReviewOfTheDatasetRulesTests(Base):
    """The Opus review of 2026-10-17: developer text that the first version masked."""

    def test_placeholder_streets_stay_text(self):
        for text in ("address: 123 Main Street", "Shipping address: 123 Main St", "Adresse: Musterstraße 1",
                     "Anschrift: Beispielweg 12", "server:\n  address: 25 Main Street",
                     "The default address is 1 Infinite Loop for the test fixture."):
            with self.subTest(text):
                self.assertText(text)

    def test_a_sentence_after_a_name_label_stays_text(self):
        for text in ("first_name: Too long (maximum is 50 characters)", "first_name: May not be null",
                     "first_name: Was", "surname: Renamed to family_name in v2",
                     "- **first_name:** Renamed to given_name"):
            with self.subTest(text):
                self.assertText(text)

    def test_a_type_word_in_one_field_keeps_the_other_names_masked(self):
        for text in ("first_name: Dana\nlast_name: Okafor\nmiddle_name: Unknown",
                     '{"first_name": "Dana", "surname": "Okafor", "middle_name": "Default"}'):
            with self.subTest(text):
                out = masked(text)
                self.assertNotIn("Dana", out)
                self.assertNotIn("Okafor", out)

    def test_four_digit_groups_after_a_phone_word_stay_text(self):
        for text in ("Telefon 2024 2025 2026", "Cell 1024 2048 4096 overflow", "Fax: 8080 9090 7070"):
            with self.subTest(text):
                self.assertText(text)

    def test_a_thing_that_resides_at_a_place_stays_text(self):
        for text in ("Each shard resides at 2 Primary Road", "The handler lives in 4 Core Lane module."):
            with self.subTest(text):
                self.assertText(text)
