"""#49 step 2: the setting business_addresses. keep (the default) leaves the address of a company, an office or a
public place as text, as before; mask masks it as any address. Invented addresses."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions, settings  # noqa: E402
from maisecrets.home import ConfigError, _check_types  # noqa: E402

TEXTS = ("Our office: Acme Robotics Inc., 1200 Harbor Blvd, Springfield, IL 62704",
         "Visit us at the Harbor View Inn, 12 Seaside Road, Newport, RI 02840",
         "Warehouse: 900 Industrial Pkwy, Columbus, OH 43215",
         "Hotel Seeblick, Lindenweg 14, 10115 Berlin", "Office address: Lindenweg 14, 10115 Berlin",
         "Firmensitz: Musterweg 7, 80331 München")


def addresses(text: str, business: bool | None) -> list:
    kw = {} if business is None else {"business_addresses": business}
    act = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test", **kw)
    with detect.Detector(regions=act).activate():
        return [text[m.start:m.end] for m in detect.scan(text, channel="tool") if m.type == "ADDRESS"]


class BusinessAddressTests(unittest.TestCase):
    def test_keep_is_the_default_and_leaves_a_business_address_as_text(self):
        for text in TEXTS:
            with self.subTest(text=text):
                self.assertEqual(addresses(text, None), [])
                self.assertEqual(addresses(text, False), [])

    def test_mask_masks_a_business_address(self):
        for text in TEXTS:
            with self.subTest(text=text):
                self.assertTrue(addresses(text, True), "the street of the business is masked")

    def test_a_home_address_is_masked_either_way(self):
        text = "Ship to: 42 Elm Street, Springfield, IL 62704"
        self.assertTrue(addresses(text, False))
        self.assertEqual(addresses(text, False), addresses(text, True))

    def test_the_config_reads_it_and_refuses_another_word(self):
        self.assertFalse(regions.resolve({}, "en_US").business_addresses)
        self.assertTrue(regions.resolve({"business_addresses": "mask"}, "en_US").business_addresses)
        _check_types({"business_addresses": "keep"}, "test")
        with self.assertRaises(ConfigError):
            _check_types({"business_addresses": "yes"}, "test")

    def test_mask_to_keep_is_a_weakening(self):
        self.assertTrue(settings.loosens("business_addresses", "mask", "keep"))
        self.assertFalse(settings.loosens("business_addresses", "keep", "mask"))


if __name__ == "__main__":
    unittest.main()
