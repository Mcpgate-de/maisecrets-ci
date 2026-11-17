"""The session start's words for the person: the welcome of the first start, and one short tip per day at most.
Off with {"tips": false} in config.json. Each line fits one terminal row."""
from __future__ import annotations

import time

from .vault import HOME, load_config

TIPS = [
    "Tip: write password: before a value, and maisecrets stores it.",
    "Tip: /maisecrets:put stores the value in your clipboard.",
    "Tip: /maisecrets opens your settings, stored values and the name service.",
    "Tip: /maisecrets:list uses shows where stored values went.",
    "Tip: /maisecrets:report sends a false alarm to the maintainers, without the value.",
    "Tip: /maisecrets:term add NAME masks a word of your own.",
    "Tip: /maisecrets:shortcut adds /ms for /maisecrets:send.",
    'Tip: rules for the tokens of your own services: /maisecrets:rules (README "Rules of your own").',
    "Tip: secrets that leaked before stay valid until you rotate them: /maisecrets:secret-hygiene.",
]
# Codex has no slash commands for plugins: its tips name only what works there
TIPS_CODEX = [
    "Tip: write password: before a value, and maisecrets stores it.",
    "Tip: maisecrets: term add NAME (alone as your prompt) masks a word of your own.",
    'Tip: rules for the tokens of your own services: maisecrets: set rule_dirs add DIR (README "Rules of your own").',
    "Tip: secrets that leaked before stay valid until you rotate them: ask for the secret-hygiene skill.",
]
SHORTCUT = "/maisecrets:shortcut"


def tip_of_the_day(codex: bool = False) -> str | None:
    """The next tip of the client's pool, once per calendar day; None on a day that had one. `shortcut: false` keeps
    the /ms tip out."""
    cfg = load_config()
    if cfg.get("tips", True) is False:
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
    if cfg.get("shortcut", True) is False and SHORTCUT in pool[idx]:
        idx = (idx + 1) % len(pool)
    try:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        state.write_text(f"{today} {idx}\n", encoding="utf-8")
    except OSError:
        pass
    return pool[idx]


def welcome_lines(codex: bool = False, lock: bool = False) -> list[str]:
    """The first start in a home: what maisecrets does, how to try and check it, and the two next steps (names, old
    leaks). `lock`: the values show on the screen with a lock (show_values, Claude Code only)."""
    first = ("maisecrets is on: passwords, keys and personal data reach the AI only as \u27e6\u2026\u27e7; the value "
             "stays on this computer.")
    if codex:
        return [first,
                "Try it: maisecrets: demo on (alone as your prompt, in a new session) \u00b7 Check: maisecrets: status",
                "Names too: maisecrets: ner local \u00b7 Old leaks: ask for the secret-hygiene skill"]
    return [first + (" \U0001F512 marks such a value." if lock else ""),
            "Try it: /maisecrets:demo on in a new session \u00b7 Check: /maisecrets:status",
            "Names too: /maisecrets:ner local \u00b7 Old leaks: /maisecrets:secret-hygiene"]


NOT_PROTECTED = "\u26a0\ufe0f maisecrets is NOT protecting this session \u2192 {cmd}"
TEST_STORE = "\u26a0\ufe0f maisecrets: test store, values are kept as plain text (backend in config.json)."
