"""What a person reads when the prompt hook blocks a prompt: the words of a block notice and the notice itself.
hooks.py imports every name again, so hooks.<name> is the same object."""
from __future__ import annotations

import platform

TYPE_WORDS = {"SECRET": ("secret", "secrets"), "EMAIL": ("e-mail address", "e-mail addresses"),
              "IBAN": ("IBAN", "IBANs"), "CARD": ("card number", "card numbers"),
              "PHONE": ("phone number", "phone numbers"), "IP": ("IP address", "IP addresses"),
              "NAME": ("name", "names")}
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
    what = ("a secret and personal data were" if secret and personal
            else "a secret was" if secret else "personal data was")
    lines = [f"maisecrets: {what} found and kept from the AI.", ""]
    if copied:
        tail = " Then send it." if codex else " Then send it, or type /ms to send it at once."
        lines.append(f"    {_paste_key()}  pastes the cleaned prompt.{tail}")
    elif codex:
        lines += ["    Copy the cleaned prompt from here and send it:", "", "    " + rewritten]
    else:
        lines += ["    Type /ms to send the cleaned prompt, or copy it from here:", "", "    " + rewritten]
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
            "    The values are stored. Ask that session to send them as placeholders (⟦…⟧) or as shapes.", "",
            "Something wrong? /maisecrets:report · maisecrets by mcpgate.de"]
