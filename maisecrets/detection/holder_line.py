"""A name on the line directly above a bank block names the account holder (#40, part 3), apart from personal.py,
which the plugin directory reads only up to 200,000 bytes per file. core._personal_hits calls names_above_bank for
the name-after-label check of a tool result, and company_follows for a name after an account holder label."""
from __future__ import annotations

import re

# a line of a bank block: its label, then a colon (Bank: …, IBAN: …, Kontonummer: …, Sort code: …)
_BANK_LINE = (r"[ \t]*(?i:bank(?:[ \t]*name)?|kreditinstitut|iban|bic|swift(?:[ \t]*code)?|blz|bankleitzahl"
              r"|konto(?:[ \t]*nr\.?|nummer)|account[ \t]*(?:number|no\.?|nr\.?)|sort[ \t]*code|routing[ \t]*number"
              r"|kontoinhaber(?:in)?|account[ \t]*holder)[ \t]*:[^\n]*")
# a block holds an account: an IBAN or an account number line, not a bank name alone
_ACCOUNT_LINE_RE = re.compile(r"(?im)^[ \t]*(?:iban|konto(?:[ \t]*nr\.?|nummer)|account[ \t]*(?:number|no\.?|nr\.?))"
                              r"[ \t]*:")
# a word of a heading above a bank block, not of a name (Bank Details, Zahlungsdaten, Spendenkonto): the word list
# lacks many of them. Banks stays a surname
_HEADING_WORD_RE = re.compile(
    r"(?i)(?:bank|konto|account|payment|zahlung|rechnung|invoice|details?|daten|data|angaben|info|information|summary"
    r"|total|betrag|amount|transfer|wire|remittance|empf(?:ä|ae)nger|recipient|beneficiary|verwendungszweck|reference"
    r"|abrechnung|buchhaltung|projekt|project|spenden?|kasse|verein|stiftung|förderverein|foerderverein|donations?"
    r"|hallo|hello|hey|moin|servus|zusammen|danke|thanks|gr(?:ü|ue)(?:ß|ss)e"
    r"|(?:bank|konto|zahlungs?|payment|(?:ü|ue)berweisung|spenden)\w{3,}"
    r"|\w{3,}(?:daten|details?|angaben|verbindung|info|konto|kasse|verein|stiftung))")
# a legal form that ends the line or the JSON value right after the name, in its usual spelling (GmbH, KG, Ltd,
# & Co. KG): after an account holder label it marks a company as the holder (Kontoinhaber: Musterbau Schmidt GmbH).
# Case-sensitive, so a surname such as Sa or Se stays a name
_COMPANY_AFTER_RE = re.compile(r"[ \t]+(?:&[ \t]*Co\.?[ \t]+)?(?:GmbH|mbH|AG|UG|KG|OHG|GbR|SE|e\.[ \t]?V\.|SAS|SARL"
                               r"|S\.A\.|S\.r\.l\.|B\.V\.|N\.V\.|Inc\.?|Corp\.?|LLC|Ltd\.?|Limited|PLC|plc)"
                               r"[ \t]*[,;.]?[\"']?[ \t]*(?:[,}\]]|\r?\n|$)")   # a line end or a JSON value end
_HOLDER_LABEL_RE = re.compile(r"(?i)(?:kontoinhaber(?:in)?|account[ _-]?holder|card[ _-]?holder|cardholder)"
                              r"[\"']?[ \t]*[:=][ \t\"']*$")
_RX: list = []


def _above_bank_re():
    """Two to four name words alone on a line (a particle may stand between them, a comma may end the line), then the
    bank block right below it (no blank line between). Windows line ends count."""
    if not _RX:
        from .personal import _NAME_PARTICLE, _NAME_STEM
        _RX.append(re.compile(r"(?m)^[ \t]*(" + _NAME_STEM + r"(?:[ \t]+(?:" + _NAME_PARTICLE + r"[ \t]+){0,2}"
                              + _NAME_STEM + r"){1,3}),?[ \t]*\r?\n"
                              r"((?:" + _BANK_LINE + r"(?:\n|$)){1,8})"))
    return _RX[0]


def company_follows(text: str, start: int, end: int) -> bool:
    """After an account holder label, a legal form ends the line right after the name: the holder is likely a
    company, not a person."""
    line = text.rfind("\n", 0, start) + 1
    return bool(_HOLDER_LABEL_RE.search(text, line, start) and _COMPANY_AFTER_RE.match(text, end))


def names_above_bank(text: str) -> list:
    """The spans of a person's name on the line directly above a bank block that holds an account: the line names the
    account holder, as a Slack message or a mail writes it. Not a word of a heading (Bankverbindung, Bank Details),
    not words that read as English words, not a value that _name_ok refuses, not a block of a bank name alone. One
    word alone is no name here: a brand reads the same. Two words of an unknown brand stay a limit, as after any
    name label."""
    from .personal import _name_ok, _reads_as_words
    out = []
    for m in _above_bank_re().finditer(text):
        if not _ACCOUNT_LINE_RE.search(m.group(2)):
            continue
        v = m.group(1)
        if any(_HEADING_WORD_RE.fullmatch(w) for w in v.split()):
            continue
        plain = re.sub(r"-[^\s]*", "", v)
        if _name_ok(v) and not (_reads_as_words(v, every=True) and _reads_as_words(plain, every=True)):
            out.append((m.start(1), m.end(1)))
    return out
