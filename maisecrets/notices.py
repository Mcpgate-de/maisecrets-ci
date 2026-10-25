"""What a person reads when the prompt hook blocks a prompt: the words of a block notice and the notice itself.
hooks.py imports every name again, so hooks.<name> is the same object."""
from __future__ import annotations

import platform

# one word per thing the AI does not get, for every text a person reads (the block notice, the ms:( check). By type
# first: a type of pii.national_id that is no ID of a person (a postal code, a licence plate, a VAT number) has its own
TYPE_WORDS = {"SECRET": ("secret", "secrets"), "EMAIL": ("e-mail address", "e-mail addresses"),
              "IBAN": ("IBAN", "IBANs"), "CARD": ("card number", "card numbers"),
              "PHONE": ("phone number", "phone numbers"), "IP": ("IP address", "IP addresses"),
              "NAME": ("name", "names"),
              "DE_PLZ": ("postal code", "postal codes"),
              "DE_KFZ": ("licence plate", "licence plates"),
              "UK_VEHICLE_REGISTRATION": ("licence plate", "licence plates"),
              "TR_LICENSE_PLATE": ("licence plate", "licence plates"),
              "IN_VEHICLE_REGISTRATION": ("licence plate", "licence plates"),
              "NG_VEHICLE_REGISTRATION": ("licence plate", "licence plates"),
              "DE_VAT_ID": ("VAT number", "VAT numbers"), "IT_VAT_CODE": ("VAT number", "VAT numbers"),
              "IN_GSTIN": ("VAT number", "VAT numbers"),
              "MEDICAL_LICENSE": ("medical licence number", "medical licence numbers")}
# then by the class of the type (maisecrets/detection/types.json): 13 classes, one word each
CLASS_WORDS = {"secret": ("secret", "secrets"), "pii.email": TYPE_WORDS["EMAIL"], "pii.phone": TYPE_WORDS["PHONE"],
               "pii.iban": TYPE_WORDS["IBAN"], "pii.card": TYPE_WORDS["CARD"], "pii.ip": TYPE_WORDS["IP"],
               "pii.name": TYPE_WORDS["NAME"], "pii.address": ("postal address", "postal addresses"),
               "pii.birth_date": ("date of birth", "dates of birth"), "pii.username": ("user name", "user names"),
               "pii.bank_account": ("bank account number", "bank account numbers"),
               "pii.tax_id": ("tax number", "tax numbers"),
               "pii.national_id": ("official ID number", "official ID numbers")}


def type_word(type_: str) -> str:
    """The word of a placeholder type with its article (`a secret`, `an e-mail address`); a type of a rule of your
    own, which no class names, as itself."""
    words = TYPE_WORDS.get(type_)
    if words is None:
        from .detection.vocabulary import TYPES
        words = CLASS_WORDS.get((TYPES.get(type_) or {}).get("class", ""))
    if words is None:
        return f"a value of the type {type_}"
    word = words[0]
    return ("an " if word[0] in "aeioAEIO" or word.startswith(("IBAN", "IP ")) else "a ") + word
STORE_NAMES = {"KeychainBackend": "the macOS Keychain", "WindowsVaultBackend": "the Windows Credential Locker",
               "EncryptedFileBackend": "an encrypted file in ~/.maisecrets",
               "JsonFileBackend": "a PLAIN TEXT test file"}
NOTICE_PREVIEW = 400


def _hours(seconds: int) -> str:
    if seconds % 86400 == 0 and seconds >= 86400:
        n = seconds // 86400
        return f"{n} day" + ("s" if n != 1 else "")
    n = max(1, round(seconds / 3600))
    return f"{n} hour" + ("s" if n != 1 else "")


def send_command() -> str:
    """The command that sends the blocked prompt: `/ms` only when the person installed the shortcut (its command file
    calls the maisecrets wrapper, cli.install_shortcut), else `/maisecrets:send`. The plugin ships no `/ms`: without
    the shortcut it is an unknown command."""
    import os
    from pathlib import Path
    commands = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "commands"
    try:
        if "maisecrets/bin/ms.sh" in (commands / "ms.md").read_text(encoding="utf-8"):
            return "/ms"
    except (OSError, UnicodeDecodeError):
        pass
    return "/maisecrets:send"


def launcher() -> str:
    """The absolute path of this plugin's launcher for this OS, for a line the person runs in a terminal (run.sh does
    not run in cmd or PowerShell)."""
    import os
    name = "run.cmd" if os.name == "nt" else "run.sh"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks", name)


def _paste_key() -> str:
    return "⌘V" if platform.system() == "Darwin" else "Ctrl+V"


def block_notice(entries: list, rewritten: str, copied: bool, codex: bool, cfg: dict, vault) -> list[str]:
    """What a person reads when a prompt is blocked, and nothing more: what kind of thing was
    found, that the AI did not get it, and the one next step, set apart by blank lines because
    the clients show plain text. The count, the masked forms and the retention are in
    /maisecrets:list; the report link is built by /maisecrets:report (review with the product
    owner, 2026-09-27: the user does not need to know whether it was 1 e-mail or 13)."""
    kinds = {e.type for e in entries}
    # a value this session resolved matches without an entry of its own; it was stored as a secret
    secret = "SECRET" in kinds or not kinds
    personal = bool(kinds - {"SECRET"})
    a_secret = type_word("SECRET")      # the word the ms:( check uses for the same thing
    what = (f"{a_secret} and personal data were" if secret and personal
            else f"{a_secret} was" if secret else "personal data was")
    lines = [f"maisecrets: {what} found and kept from the AI.", ""]
    if copied:
        tail = " Then send it." if codex else f" Then send it, or type {send_command()} to send it at once."
        lines.append(f"    {_paste_key()}  pastes the cleaned prompt.{tail}")
    elif codex:
        lines += ["    Copy the cleaned prompt from here and send it:", "", "    " + rewritten]
    else:
        lines += [f"    Type {send_command()} to send the cleaned prompt, or copy it from here:", "",
                  "    " + rewritten]
    lines.append("")
    if codex:
        lines.append("maisecrets by mcpgate.de")
    else:
        lines.append("Something wrong? /maisecrets:report · maisecrets by mcpgate.de")
    return lines


def peer_notice(entries: list, sender: str) -> list[str]:
    """What the person reads when a message of another Claude session was blocked (the mod rewrites it where it runs):
    who sent it, that the model did not get it, and what helps. Nothing to paste: the person did not write it."""
    kinds = {e.type for e in entries}
    secret = "SECRET" in kinds or not kinds
    personal = bool(kinds - {"SECRET"})
    what = ("a secret and personal data" if secret and personal else "a secret" if secret else "personal data")
    return [f"maisecrets: a message from the Claude session {sender} held {what}. It was kept from the AI here, and "
            "the AI did not get the message.", "",
            "    The values are stored. Ask that session to send placeholders (⟦…⟧) instead of the values.", "",
            "Something wrong? /maisecrets:report · maisecrets by mcpgate.de"]
