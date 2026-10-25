"""One short tip per day at session start, rotating. Off with {"tips": false} in config.json."""
from __future__ import annotations

import time

from .vault import HOME, load_config

TIPS = [
    "maisecrets: write `password: <value>` (or passwort:, api_key=; 8+ characters) and the value is stored on "
    "this computer; the AI gets a placeholder and can still use it in commands.",
    "maisecrets: copy a value, then /maisecrets:put stores it and puts its placeholder in your clipboard.",
    "maisecrets: /maisecrets:list shows what is stored, masked; /maisecrets:forget <key> deletes one.",
    "maisecrets: a placeholder works only in a session where you typed or pasted it. Paste it into a prompt to use "
    "it here.",
    "maisecrets: /maisecrets:report prepares a report from the last detection, without the value.",
    "maisecrets: /maisecrets:audit lists every use of a stored value: when, which placeholder, which command.",
    "maisecrets: a bare password in a normal sentence is not detected. Write password: in front of it, test it "
    "with ms:(…), or use /maisecrets:put.",
    "maisecrets: add detection rules for the tokens of your own services in ~/.maisecrets/rules.d or a team "
    "folder; /maisecrets:rules shows them, README \"Rules of your own\" says how.",
]
# Codex has no slash commands for plugins: its tips name only what works there
TIPS_CODEX = [
    "maisecrets: write `password: <value>` (or passwort:, api_key=; 8+ characters) and the value is stored on "
    "this computer; the AI gets a placeholder and can still use it in commands.",
    "maisecrets: a placeholder works only in a session where you typed or pasted it. Paste it into a prompt to use "
    "it here.",
    "maisecrets: a bare password in a normal sentence is not detected. Write password: in front of it, or test it "
    "with ms:(…) alone as your prompt.",
    "maisecrets: add detection rules for the tokens of your own services in ~/.maisecrets/rules.d or a team "
    "folder (`maisecrets: set rule_dirs add DIR` as your own prompt); README \"Rules of your own\" says how.",
]


def tip_of_the_day(codex: bool = False) -> str | None:
    if load_config().get("tips", True) is False:
        return None
    state = HOME / ".tip"
    today = time.strftime("%Y-%m-%d")
    try:
        last_day, idx = state.read_text(encoding="utf-8").split()
        idx = int(idx)
    except (OSError, ValueError):
        last_day, idx = "", -1
    if last_day == today:
        return None
    pool = TIPS_CODEX if codex else TIPS
    idx = (idx + 1) % len(pool)
    try:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        state.write_text(f"{today} {idx}\n", encoding="utf-8")
    except OSError:
        pass
    return pool[idx]


# the first session start says how to see maisecrets work. The example must be one the detector
# finds (a@b.c is not: its top-level domain is one letter); a test holds it to that
TRY_IT_EXAMPLE = "max.muster@firma-xyz.de"   # not example.com: a reserved domain is no hit


def try_it_line() -> str:
    return f"Try it: send ms:({TRY_IT_EXAMPLE}) alone. maisecrets says what it would mask, and nothing reaches the AI."
