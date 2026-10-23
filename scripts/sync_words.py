#!/usr/bin/env python3
"""Build maisecrets/detection/rules/words_en.txt from a pinned SCOWL release (the English word list of the password
rule).

The list holds the base words of SCOWL's en_US Hunspell dictionary (size 60) with 4 to 8 lower-case ASCII
letters, one per line: about 21,000 words, about 140 KB. The password rule (label-pw-literal in
maisecrets/detection/value_checks.py) reads it once, and only when a password label stands in the text. A longer word
is still covered by its parts (basketball: basket + ball).

Offline by design: download the release asset yourself and pass its path. The digest is pinned, so a changed
asset fails here.

    gh release download rel-2026.02.25 -R en-wl/wordlist -p 'hunspell-en_US-2026.02.25.zip' -D <dir>
    python3 scripts/sync_words.py <dir>/hunspell-en_US-2026.02.25.zip

Writes maisecrets/detection/rules/words_en.txt, LICENSE-scowl (the copyright part of the dictionary's README) and
SCOWL_VERSION.
"""
import hashlib
import io
import sys
import zipfile
from pathlib import Path

TAG = "rel-2026.02.25"
ASSET = "hunspell-en_US-2026.02.25.zip"
SHA256 = "ac8e73310e951d88c52c2cf2ba54ceaca34f8486a81630ac8a75dc5f931179f9"
SOURCE = f"https://github.com/en-wl/wordlist/releases/download/{TAG}/{ASSET}"
MIN_LEN, MAX_LEN = 4, 8


def words_of(dic: str) -> list:
    out = set()
    for line in dic.splitlines()[1:]:          # the first line is the entry count
        w = line.split("/", 1)[0].strip()
        if w.isascii() and w.isalpha() and w.islower() and MIN_LEN <= len(w) <= MAX_LEN:
            out.add(w)
    return sorted(out)


def license_of(readme: str) -> str:
    """The copyright and permission notice of SCOWL and the paragraph on its sources. The credits after it (names
    and mail addresses of contributors, the Australian list and the affix file, neither of which is used) are left
    out; the README in the pinned asset has them."""
    start = readme.index("Copyright 2000-")
    end = readme.index("The primary source of words for SCOWL")
    return readme[start:end].rstrip() + "\n"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    raw = Path(sys.argv[1]).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SHA256:
        print(f"refused: sha256 {digest} is not the pinned {SHA256} of {ASSET}")
        return 1
    z = zipfile.ZipFile(io.BytesIO(raw))
    words = words_of(z.read("en_US.dic").decode("utf-8"))
    lic = license_of(z.read("README_en_US.txt").decode("utf-8"))
    dst = Path(__file__).resolve().parent.parent / "maisecrets" / "detection" / "rules"
    (dst / "words_en.txt").write_text("\n".join(words) + "\n", encoding="utf-8")
    (dst / "LICENSE-scowl").write_text(
        f"maisecrets/detection/rules/words_en.txt is a word list created from SCOWL: the base words of 4 to 8 "
        f"letters of\n"
        f"the en_US Hunspell dictionary (SCOWL size 60), release {TAG},\n{SOURCE}\n"
        f"(sha256 {SHA256}).\n"
        f"The English dictionaries come directly from SCOWL and are under the same copyright terms\n"
        f"as SCOWL. The text below is the copyright notice, the permission notice and the sources paragraph\n"
        f"of that dictionary's README_en_US.txt.\n\n"
        + lic, encoding="utf-8")
    (dst / "SCOWL_VERSION").write_text(TAG + "\n", encoding="utf-8")
    print(f"words_en.txt: {len(words)} words, {sum(len(w) + 1 for w in words)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
