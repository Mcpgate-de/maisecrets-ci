"""Which regions and label languages the detector uses.

A region is a country code. It selects the Presidio PII rules of that country (a German tax ID, a
US social security number). A label language selects the words that name a credential in that
language (`passwort:`, `kennwort:`). English labels are always on, because the vendored rulesets
are English and people write English labels in every language.

The config key `regions` is a list of country codes. The entry "auto" is the country of the system
setting. The label languages are all languages with a label file, whatever the system setting and the
regions: a person writes a label in another language than the one of the system, and a tool result
holds the field names of a foreign system. English comes first, then the language of the system setting
and of each region, then the others. A machine without a system setting (a CI container with the C
locale) gets the generic PII rules only.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

LABELS_DIR = Path(__file__).parent / "rules" / "labels"
DEFAULT_REGIONS = ["auto"]

# Presidio names the United Kingdom "uk"; a locale names it "GB"
_COUNTRY_ALIAS = {"gb": "uk"}
# the language of a region, for the label files; a region not listed adds PII rules only.
# A region with two label languages lists both (Belgium: Dutch and French).
REGION_LANGUAGE = {
    "de": "de", "at": "de", "ch": "de", "li": "de",
    "us": "en", "uk": "en", "au": "en", "ca": "en", "in": "en", "ng": "en", "ph": "en", "sg": "en",
    "za": "en", "ie": "en", "nz": "en",
    "es": "es", "it": "it", "fi": "fi", "se": "sv", "pl": "pl", "tr": "tr", "kr": "ko", "th": "th",
    "fr": "fr", "lu": "fr", "be": ("nl", "fr"), "nl": "nl", "pt": "pt", "br": "pt", "dk": "da", "no": "nb",
    "cz": "cs", "ru": "ru", "cn": "zh", "tw": "zh", "hk": "zh", "mo": "zh", "jp": "ja",
}
# a system language whose label file has another name: "no" (Norwegian) is written as Bokmål, nb.txt
_LANGUAGE_ALIAS = {"no": "nb"}


def _region_languages(region: str) -> tuple[str, ...]:
    langs = REGION_LANGUAGE.get(region, ())
    return (langs,) if isinstance(langs, str) else tuple(langs)


@dataclass(frozen=True)
class Active:
    regions: tuple[str, ...]      # country codes, "generic" first
    languages: tuple[str, ...]    # label languages, "en" first
    source: str                   # where the regions came from, for /maisecrets:status


def _macos_locale() -> str | None:
    import plistlib
    try:
        with open(Path.home() / "Library" / "Preferences" / ".GlobalPreferences.plist", "rb") as f:
            prefs = plistlib.load(f)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    loc = prefs.get("AppleLocale")
    return loc if isinstance(loc, str) else None


def _windows_locale() -> str | None:
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(85)
        if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, 85):
            return buf.value
    except (AttributeError, OSError):
        pass
    return None


def system_locale() -> str | None:
    """The locale of the person's system setting, for example "de_DE" or "en-US".

    MAISECRETS_LOCALE wins, for a server with no setting and for the tests. On macOS and Windows
    the system setting comes before LANG: a terminal often has LANG=en_US.UTF-8 on a German
    system (measured on the development Mac, 2026-09-27: LANG en_US.UTF-8, AppleLocale de_DE).
    """
    env = os.environ.get("MAISECRETS_LOCALE", "").strip()
    if env:
        return env
    native = _macos_locale() if sys.platform == "darwin" else _windows_locale() if sys.platform == "win32" else None
    if native:
        return native
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def parse_locale(loc: str | None) -> tuple[str | None, str | None]:
    """(language, country) of a locale: "de_DE.UTF-8" gives ("de", "de"), "en-GB" ("en", "uk")."""
    if not loc:
        return None, None
    base = loc.split(".", 1)[0].split("@", 1)[0].replace("-", "_")
    if base.upper() in ("C", "POSIX"):
        return None, None
    parts = base.split("_")
    lang = parts[0].lower() if parts[0].isalpha() and 2 <= len(parts[0]) <= 3 else None
    country = None
    for p in parts[1:]:
        if p.isalpha() and len(p) == 2:
            country = _COUNTRY_ALIAS.get(p.lower(), p.lower())
            break
    return lang, country


def label_languages_available() -> list[str]:
    return sorted(p.stem for p in LABELS_DIR.glob("*.txt"))


def resolve(cfg: dict, locale: str | None = None) -> Active:
    """The regions and label languages of a config. `auto` and the label language of the system come from `locale`
    ("de_DE"), else from this computer's setting (system_locale)."""
    raw = cfg.get("regions")
    source = cfg.get("regions_from", "config")
    if raw is None:
        raw, source = list(DEFAULT_REGIONS), "default"
    lang, country = parse_locale(system_locale() if locale is None else locale)
    regions: list[str] = []
    for r in raw:
        r = str(r).strip().lower()
        r = _COUNTRY_ALIAS.get(r, r)
        if r == "auto":
            if country:
                regions.append(country)
                source += f", auto = {country} from the system setting"
            else:
                source += ", auto = none (no system setting)"
        elif r and r != "generic":
            regions.append(r)
    regions = list(dict.fromkeys(regions))
    lang = _LANGUAGE_ALIAS.get(lang, lang) if lang else None
    # every label file is on (since 0.8.2): a label word of one language in a text of another is common
    available = label_languages_available()
    languages = ["en"] + ([lang] if lang else []) + [x for r in regions for x in _region_languages(r)] + available
    return Active(regions=("generic", *regions),
                  languages=tuple(x for x in dict.fromkeys(languages) if x in set(available)),
                  source=source)


@dataclass(frozen=True)
class Label:
    prefilter: str     # a lowercase literal that every match of the regex contains
    regex: str
    examples: tuple[str, ...]


def load_labels(language: str) -> list[Label]:
    """rules/labels/<language>.txt: one label per line, three tab-separated fields: the prefilter
    literal, the regex (case-insensitive, matched where detect-secrets matches its own denylist),
    and example words separated by commas. The examples are documentation and test input."""
    out = []
    for n, line in enumerate((LABELS_DIR / f"{language}.txt").read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError(f"{language}.txt line {n}: expected 3 tab-separated fields, got {len(fields)}")
        pre, regex, ex = (f.strip() for f in fields)
        out.append(Label(pre, regex, tuple(e.strip() for e in ex.split(",") if e.strip())))
    return out
