"""Street addresses that the gap analysis of 0.9.11 found missed (Mendeley, Gretel val samples): the US territories FM,
MH and PW, a residence cue that keeps a person's address masked after a company is named, the USPS street suffixes
after an address label, and residence cues in more languages. Invented addresses."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402

REGIONS = ("generic", "de", "us", "fr", "it", "es", "nl", "se")
LANGS = ("en", "de", "fr", "it", "es", "nl", "sv")


def addresses(text: str) -> list:
    act = regions.Active(regions=REGIONS, languages=LANGS, source="test")
    with detect.Detector(regions=act).activate():
        return [text[m.start:m.end] for m in detect.scan(text, channel="tool") if m.type == "ADDRESS"]


class AddressesInProseTests(unittest.TestCase):
    def test_found(self):
        for text in ("Ship to:\n4881 Orbek Radial Suite 072\nEast Emily, PW 83256",
                     "the address 4458 Lopez Dale\nSharpmouth, FM 19019",
                     "the address 77483 Varga Square Apt. 713\nNorth Amy, MH 09467",
                     "Jane Roe from Cook Inc, residing at 5169 Hill Walk Suite 982\nNorth Amy, NC 30271",
                     "Jane Roe from Cook Inc, residing at 5169 Orbek Varga\nNorth Amy, NC 30271",
                     "She lives at 77 Oak Lane\nDover, DE 19901",
                     "- Street Address: 62238 Kristen Haven Suite 305", "Street Address: 900 Rivera Lakes",
                     "a resident of 12 Hatfield Road", "domiciliado en Calle Mayor 5, Madrid",
                     "residente in Via Roma 12, Torino", "woonachtig op Kerkstraat 12"):
            with self.subTest(text=text):
                self.assertTrue(addresses(text))

    def test_stays_text(self):
        for text in ("Jane Roe from Cook Inc, located at 5169 Hill Walk Suite 982\nNorth Amy, NC 30271",
                     "Our office is at 12 Main Street\nSpringfield, IL 62704", "We went to 12 Hills yesterday",
                     "There are 3 Ways to do it", "Address: 5 Point", "the 4 Walks of life",
                     "con sede legale in Via della Pace 12, Roma", "a resident of the city for 20 years",
                     "resident in 3 countries", "the resident 3 Bears", "The cache lives at 1 Shared Point",
                     "The data is located in 3 Isolated Islands", "the key lives in 2 Vault Ways",
                     "The bug resides in 2 Hidden Fields", "the file is located in 4 Config Bridge",
                     '{"venue": "north", "note": "x", "street": "42 Mill Lane", "city": "Dover"}'):
            with self.subTest(text=text):
                self.assertEqual([], addresses(text))


if __name__ == "__main__":
    unittest.main()
