"""The settings a person sees and changes, and the hint that names one at the moment it matters.

A setting changes only from a prompt the person typed, which the UserPromptSubmit hook reads
(`/maisecrets:settings KEY VALUE`, or `maisecrets: set KEY VALUE` alone as the prompt): a tool call of
the model never writes one, also not a stricter value (a prompt injection could set it for good). The
CLI only shows them. A key the user wrote is a decision; a missing key is "not decided" and reads the
default. A hint goes to the model once, when the case it is about first happens.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from . import ner_setup
from .home import (CONFIG, DEFAULT_CONFIG, HOME, ConfigError, LockTimeout, _check_types, _lock_for, atomic_write,
                   load_config)

# Every key of the config is in exactly one class (a test holds it): a new key without one is a test failure.
DISCOVERABLE = ("ssh_consent", "ssh_autonomous_hosts", "secret_destinations", "rehydration", "read_pdf",
                "read_image", "show_values")
ADVANCED = ("ssh_host_groups", "ssh_approval", "resolve_in_files", "ssh_via_sandbox", "block_at_mentions",
            "rewrite_prompts", "scrub_transcript", "strip_hidden_characters", "regions", "ttl_seconds",
            "renew_on_use", "tips", "shortcut", "guard", "pass_agent_reports", "gateway_servers", "client_header",
            "max_keys_per_session", "max_resolves_per_hour", "rule_dirs", "clean_dirs", "value_files",
            "remote_detector", "business_addresses")
INTERNAL = ("backend", "allow_plaintext_store", "report_url", "max_ttl_seconds", "max_new_entries_per_result",
            "keep_purged_days", "audit_max_lines", "pii_regions", "client_vault_cafile")

TITLE = {
    "ssh_consent": "SSH consent", "ssh_autonomous_hosts": "Autonomous hosts",
    "secret_destinations": "Where secrets were sent",
    "rehydration": "Stored values in tool calls", "ssh_host_groups": "SSH host groups",
    "ssh_approval": "SSH approval", "resolve_in_files": "Values in files", "ssh_via_sandbox": "Values over ssh",
    "block_at_mentions": "Block @file mentions", "rewrite_prompts": "Rewrite prompts",
    "scrub_transcript": "Clean the transcript", "strip_hidden_characters": "Remove invisible characters",
    "regions": "Countries for personal data", "ttl_seconds": "How long a stored value lives",
    "renew_on_use": "Renew on use",
    "tips": "Tips and hints",
    "shortcut": "/ms shortcut", "guard": "Update guard", "pass_agent_reports": "Subagent reports",
    "gateway_servers": "Gateway servers", "client_header": "Values back from your MCP servers",
    "rule_dirs": "Rule folders",
    "read_pdf": "PDFs the AI reads", "read_image": "Images the AI reads", "clean_dirs": "Folders with clean files",
    "value_files": "Value files", "remote_detector": "Names from a service", "show_values": "Values on your screen",
    "max_keys_per_session": "Values per session and hour", "max_resolves_per_hour": "Uses per hour",
    "business_addresses": "Business addresses",
}
MEANING = {
    "ssh_consent": "Ask before each ssh command that changes something on a host.",
    "ssh_autonomous_hosts": "Hosts where the AI may change things over ssh without asking, in every session.",
    "secret_destinations": "Notes where each stored secret is sent, on this computer only. With protect, asks "
                           "before a secret goes to a host it never went to.",
    "rehydration": "How a stored value goes into a tool call.",
    "ssh_host_groups": "Hosts that one typed ssh window covers together.",
    "ssh_approval": "When stored values in tool calls is confirm: for ssh, ask for each command, or once per value "
                    "and session.",
    "resolve_in_files": "A placeholder in Write or Edit content gets its value.",
    "ssh_via_sandbox": "A value may go to ssh on stdin inside the Claude Code sandbox.",
    "block_at_mentions": "Block an @file mention in a prompt; the file would skip the scan.",
    "rewrite_prompts": "Claude Code with mods: send a prompt with placeholders instead of blocking it.",
    "scrub_transcript": "Remove a value from the session transcript on disk.",
    "strip_hidden_characters": "Remove invisible characters from tool results.",
    "regions": "Countries for the personal-data rules.",
    "business_addresses": "The address of a company, an office, a shop or a public place: kept as text by default, "
                          "as it is public and an agent works with it; mask treats it as personal data.",
    "read_pdf": "maisecrets cannot look inside a PDF. What happens when the AI reads one.",
    "read_image": "maisecrets cannot look inside an image. What happens when the AI reads one.",
    "show_values": "Claude Code with mods, in the fullscreen terminal and the desktop app: the value behind a "
                   "placeholder on your screen, never for the AI.",
    "clean_dirs": "Folders of clean PDFs and images: a file that was there before the session is allowed.",
    "rule_dirs": "Folders with detection rules of your own or of your team, read with ~/.maisecrets/rules.d.",
    "value_files": "Files of values from your own tools (JSON lines), imported at session start when they change. "
                   "An import only adds; your prompt /maisecrets:forget import:ID removes one.",
    "remote_detector": "A named-entity service that adds names in tool results after the rules. Off unless you "
                       "choose a source: /maisecrets:ner local, url URL or off.",
    "ttl_seconds": "How long a stored value lives.",
    "renew_on_use": "A use of a value extends its life.",
    "tips": "A short tip at session start, and a hint when a setting first matters.",
    "shortcut": "The first session start names /maisecrets:shortcut once.",
    "guard": "A synced install registers the guard outside its folder.",
    "pass_agent_reports": "A subagent's report or a background command's notice is not blocked.",
    "gateway_servers": "MCP servers that resolve placeholders themselves.",
    "client_header": "A key header on your own MCP server once it sends a masked value and supports it, so it "
                     "can give its masked values back into your files and commands, never to the AI.",
    "max_keys_per_session": "How many different stored values one session may use in an hour. A brake against "
                            "sending all values out at once; normal work stays far below it.",
    "max_resolves_per_hour": "How often stored values may go into tool calls in an hour, all sessions together.",
}
CHOICE_TEXT = {
    "secret_destinations": (("observe", "note where each secret goes; never stops a call"),
                            ("protect", "also ask before a secret goes to a host it never went to"),
                            ("off", "note nothing")),
    "rehydration": (("automatic", "use a stored value in a tool call"), ("confirm", "ask before each use"),
                    ("block", "never put a stored value into a tool call")),
    "ssh_approval": (("per-command", "ask for each command"), ("per-session", "ask once per value and session")),
    "read_pdf": (("allow", "the PDF goes to the AI as it is"), ("ask", "ask you before each PDF"),
                 ("block", "the Read tool does not open a PDF"),
                 ("convert", "send only its text, with secrets and personal data masked (needs pdftotext)")),
    "read_image": (("allow", "the image goes to the AI as it is"), ("ask", "ask you before each image"),
                   ("block", "the Read tool does not open an image")),
    "business_addresses": (("keep", "the address of a company or a public place stays text"),
                           ("mask", "mask it as any address")),
    "show_values": (("always", "each value stands in the text with a lock; a click copies it"),
                    ("click", "a click on a placeholder shows the values of that reply for 10 seconds"),
                    ("off", "placeholders only")),
}
# what a prompt may set; any other key is edited in config.json by hand
_BOOL_WORDS = {"on": True, "true": True, "off": False, "false": False}
_CHOICES = {"rehydration": ("automatic", "confirm", "block"), "ssh_approval": ("per-command", "per-session"),
            "secret_destinations": ("observe", "protect", "off"), "read_pdf": ("allow", "ask", "block", "convert"),
            "read_image": ("allow", "ask", "block"), "show_values": ("always", "click", "off"),
            "business_addresses": ("keep", "mask"), "ttl_seconds": ("1h", "24h", "7d")}
# ttl_seconds: the words a prompt types, the seconds config.json holds. A card number keeps 1 h, as the default does
TTL_WORDS = {"1h": 3600, "24h": 86400, "7d": 7 * 86400}
TTL_LABELS = {"1h": "1 h", "24h": "24 h", "7d": "7 days"}
_CARD_TTL = 3600
_BOOL_KEYS = tuple(k for k in DISCOVERABLE + ADVANCED if isinstance(DEFAULT_CONFIG.get(k), bool))
# a whole number in this range: the limiter (C7). 0 would stop every use; a person who wants that sets rehydration block
_INT_KEYS = {"max_keys_per_session": (1, 1_000_000), "max_resolves_per_hour": (1, 1_000_000)}

# the whole prompt, nothing else: a sentence inside a longer prompt is text for the model, not an order
_PROMPT_RE = re.compile(r"\A\s*(?:/maisecrets:settings|maisecrets:\s*set)\s+([a-z_]+)\s+([a-z0-9-]+)\s*\Z", re.I)
# the list of autonomous hosts: add or remove one host (as the ssh call writes it: user@host:port) or group name
_HOST = r"([\w.@:\[\]-]+)"
_AUTONOMOUS_RE = re.compile(r"\A\s*(?:/maisecrets:settings\s+ssh_autonomous_hosts\s+(add|remove)|maisecrets:\s*ssh\s+"
                            r"(autonomous|ask))\s+" + _HOST + r"\s*\Z", re.I)
# the rule folders: add or remove one folder, the rest of the prompt as typed (a path can hold spaces)
_RULE_DIRS_RE = re.compile(r"\A\s*(?:/maisecrets:settings|maisecrets:\s*set)\s+rule_dirs\s+(add|remove)\s+(\S(?:.*\S)?)"
                           r"\s*\Z", re.I)
# the clean folders: the same form (file_reads.py)
_CLEAN_DIRS_RE = re.compile(r"\A\s*(?:/maisecrets:settings|maisecrets:\s*set)\s+clean_dirs\s+(add|remove)\s+"
                            r"(\S(?:.*\S)?)\s*\Z", re.I)
# the value files (maisecrets/values.py): the same form, one file per prompt
_VALUE_FILES_RE = re.compile(r"\A\s*(?:/maisecrets:settings|maisecrets:\s*set)\s+value_files\s+(add|remove)\s+"
                             r"(\S(?:.*\S)?)\s*\Z", re.I)
_LIST_KEYS = ("ssh_autonomous_hosts", "rule_dirs", "clean_dirs", "value_files")
_FOLDER_KEYS = ("rule_dirs", "clean_dirs")
_PATH_KEYS = _FOLDER_KEYS + ("value_files",)
_HINTS_RESET_RE = re.compile(r"\A\s*(?:/maisecrets:settings\s+hints\s+reset|maisecrets:\s*reset\s+hints)\s*\Z", re.I)
# the same sentence anywhere in a tool call: a nested client (`codex exec 'maisecrets: set …'`, `claude -p`) would
# type it for the model, and the writer called by name would skip the prompt (review of C22). A text match: a
# sentence or a name built at run time is not seen
IN_A_COMMAND_RE = re.compile(r"(?:/maisecrets:settings|maisecrets:\s*set)\s+[a-z_]+\s+[a-z0-9-]+|"
                             r"maisecrets:\s*ssh\s+(?:autonomous|ask)\s|"
                             r"maisecrets:\s*reset\s+hints|\b(?:apply_typed|grant_typed|grant_by_code)\b", re.I)
# a term removal makes detection weaker: only the person types it (terms.py)
IN_A_COMMAND_RE = re.compile(IN_A_COMMAND_RE.pattern + r"|(?:/maisecrets:term|maisecrets:\s*term)\s+remove\s|"
                             r"\bterm_remove_typed\b", re.I)
# the source of names (ner_setup.py): a tool call must not send the text of tool results somewhere new
IN_A_COMMAND_RE = re.compile(IN_A_COMMAND_RE.pattern + "|" + ner_setup.IN_A_COMMAND, re.I)
# who wrote the prompt (Claude Code 2.1.292 UserPromptSubmit `source`): only the person at the composer. A scheduled
# task, a loop wakeup, a system or poll prompt can carry text the model chose (CronCreate, ScheduleWakeup), and an
# `sdk` prompt can come from a program a tool started (codex review round 2), so none of them changes anything. A
# prompt without the field is taken as the person, unless a program started the client (NESTED_ENTRYPOINTS)
TYPED_SOURCES = (None, "user")
# A prompt without `source` is not the person's when a program started the client through the Agent SDK: `claude -p`
# runs its hooks with CLAUDE_CODE_ENTRYPOINT=sdk-cli, the SDKs with sdk-ts or sdk-py. The client sets it itself:
# `env -u` and a `cli` set before the start do not change it (measured on Claude Code 2.1.300). The terminal client
# sends no `source` either and has `cli`; the desktop app sets claude-desktop (read from its bundle). Codex sets
# nothing, so a Codex hook sees the entry point of the program that started Codex: none from a terminal
NESTED_ENTRYPOINTS = ("sdk-",)
_LOCK = HOME / ".settings.lock"


def nested_program(payload: dict) -> str | None:
    """The entry point when this prompt, with no `source`, came from a client that a program started; else None."""
    entry = os.environ.get("CLAUDE_CODE_ENTRYPOINT", "")
    return entry if payload.get("source") is None and entry.startswith(NESTED_ENTRYPOINTS) else None


# a message of another Claude session (SendMessage) reaches a session as a prompt, wrapped by the client, and the hook
# input names no origin (2.1.302: `source` is in the schema and not sent). A person can type the wrapper too, so it
# only takes rights away: such a prompt is never the person's, and a block never touches the clipboard (2026-10-21).
# The hook gets the wrapper without the line "Another Claude session sent a message:" that the transcript shows
# (2.1.307, measured 2026-10-22 with a probe hook), so the line is optional
_PEER_RE = re.compile(r"\A\s*(?:Another Claude session sent a message:\s*)?<cross-session-message\b([^>\n]{0,400})>")
_PEER_NAME_RE = re.compile(r'\bfrom-name="([A-Za-z0-9 ._-]{1,40})"')


def peer_sender(prompt) -> str | None:
    """The name of the session that sent this prompt with SendMessage, \"another session\" when it gives none; None
    for any other prompt."""
    m = _PEER_RE.match(prompt) if isinstance(prompt, str) else None
    if not m:
        return None
    name = _PEER_NAME_RE.search(m.group(1))
    return name.group(1) if name else "another session"


def typed_by_the_person(payload: dict) -> bool:
    """The prompt counts as typed by the person: a `source` the person has, no program started the client, no other
    session sent it, and no subagent (came_from names it; codex review of /maisecrets:ner)."""
    return (payload.get("source") in TYPED_SOURCES and nested_program(payload) is None
            and peer_sender(payload.get("prompt")) is None and not payload.get("agent_id"))


def not_typed_reason(payload: dict) -> str:
    """One sentence for a settings change that did not count, and what the person can do."""
    entry = nested_program(payload)
    if entry:
        shown = re.sub(r"[^a-z0-9-]", "", entry.lower())[:20]     # a variable is no text for the model
        return ("maisecrets: a settings change counts only when you type it as your prompt; this one came from a "
                f"client that a program started (entry point {shown}, as `claude -p` has), so nothing was changed. "
                "Type it in your own Claude Code or Codex session.")
    return ("maisecrets: a settings change counts only when you type it as your prompt; this one came from "
            f"{came_from(payload)}, so nothing was changed.")


def came_from(payload: dict) -> str:
    """Who sent a prompt that the person did not type, in words: the client's `source` is a raw value (`cron`, a
    missing field), which said nothing to the person."""
    if peer_sender(payload.get("prompt")) is not None:
        return "another Claude session"
    if payload.get("agent_id"):
        return "a subagent"
    source = str(payload.get("source") or "").lower()
    if "sdk" in source or nested_program(payload):
        return "a program"
    if any(w in source for w in ("loop", "wake")):
        return "a loop that wakes the session"
    if any(w in source for w in ("cron", "schedul", "task")):
        return "a scheduled task"
    return "the client, not from you"


def state(key: str, cfg: dict) -> str:
    if key in (cfg.get("policy_keys") or []):
        return "set by a policy"
    if key not in (cfg.get("user_keys") or []):
        return "default"
    return "set by you"


# ---------------------------------------------------------------- the overview --
MAIN_GROUPS = (("Protection", ("ssh_consent", "secret_destinations")),
               ("Stored values", ("rehydration",)),
               ("Files the AI reads", ("read_pdf", "read_image")),
               ("Your screen", ("show_values", "tips")))
MORE_GROUPS = (("ssh", ("ssh_autonomous_hosts", "ssh_approval")),
               ("More on stored values", ("ttl_seconds", "renew_on_use", "resolve_in_files")),
               ("Prompts and files", ("rewrite_prompts", "business_addresses", "rule_dirs", "clean_dirs",
                                      "value_files")),
               ("Help and updates", ("shortcut", "guard")),
               ("Personal data", ("regions",)))
# not in the views: each one only weakens protection when changed, or it is set in config.json only
# (docs/ADMIN.md); config.json and a policy still set it
NOT_LISTED = ("strip_hidden_characters", "scrub_transcript", "block_at_mentions", "client_header", "ssh_via_sandbox",
              "pass_agent_reports", "max_keys_per_session", "max_resolves_per_hour", "remote_detector",
              # set in config.json only (docs/ADMIN.md)
              "gateway_servers", "ssh_host_groups")


def _mark(key: str, cfg: dict) -> str:
    if key in (cfg.get("policy_keys") or []):
        return "⚙"
    if key in (cfg.get("user_keys") or []):
        return "✎"
    return ""


LABEL = {
    "ssh_consent": "Ask before ssh changes a host", "secret_destinations": "Track where each secret goes",
    "rehydration": "Put values into tool calls", "read_pdf": "PDFs", "read_image": "Images",
    "show_values": "Values with a lock", "tips": "Tips and hints",
    "ssh_autonomous_hosts": "Hosts ssh may change freely", "ssh_approval": "With confirm, ssh asks",
    "renew_on_use": "A use extends a value's life", "resolve_in_files": "Values in Write and Edit",
    "rewrite_prompts": "Rewrite prompts", "business_addresses": "Company addresses",
    "rule_dirs": "Folders with your own rules", "clean_dirs": "Folders of clean files",
    "value_files": "Value files of your own tools", "shortcut": "Offer the /ms shortcut",
    "guard": "Register the update guard", "ttl_seconds": "Value lifetime",
    "regions": "Countries for personal data",
}


def ttl_word(value) -> str | None:
    """The word of a ttl_seconds value the pane offers, or None for a value written by hand."""
    d = value.get("default") if isinstance(value, dict) else None
    return next((w for w, sec in TTL_WORDS.items() if sec == d), None)


def region_codes() -> list:
    from .detection.regions import known_regions
    return sorted(r for r in known_regions() if r != "generic")


def _regions_of(value) -> list:
    return [str(r).lower() for r in value] if isinstance(value, list) and value else ["auto"]
_LIST_CHOICES = {"ssh_autonomous_hosts": "add HOST · remove HOST", "rule_dirs": "add DIR · remove DIR",
                 "clean_dirs": "add DIR · remove DIR", "value_files": "add FILE · remove FILE"}


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _row(key: str, cfg: dict) -> str:
    value = cfg.get(key)
    shown = _shown(value, key)
    if len(shown) > 30:
        shown = shown[:29] + "…"
    mark = _mark(key, cfg)
    now = f"**{_cell(shown)}**" + (f" {mark}" if mark else "")
    if mark == "⚙":
        other = "set by your admin"
    elif key in _LIST_CHOICES:
        other = _LIST_CHOICES[key]
    elif key == "ttl_seconds":
        word = ttl_word(value)
        now = f"**{TTL_LABELS.get(word, _cell(shown))}**" + (f" {mark}" if mark else "")
        other = " · ".join(TTL_LABELS[w] for w in TTL_WORDS if w != word) + " (cards: 1 h)"
    elif key == "regions":
        now = f"**{', '.join(_regions_of(value))}**" + (f" {mark}" if mark else "")
        other = "auto · or country codes, e.g. de · us · fr"
    elif key in _CHOICES:
        other = " · ".join(m for m in _CHOICES[key] if m != value)
    elif isinstance(value, bool):
        other = "off" if value else "on"
    else:
        other = ""
    return f"| {_cell(LABEL.get(key, TITLE.get(key, key)))} | {now} | {other} | `{key}` |"


def render_table(show_all: bool = False, cfg: dict | None = None, codex: bool = False) -> str:
    """The settings as a Markdown table, the groups in bold (`all`: the advanced ones too)."""
    cfg = cfg if cfg is not None else load_config()
    lines = ["| Setting | Now | Other choices | Key |", "|---|---|---|---|"]
    for title, keys in MAIN_GROUPS + (MORE_GROUPS if show_all else ()):
        lines.append(f"| **{title}** | | | |")
        lines += [_row(k, cfg) for k in keys]
    lines.append("")
    cmd = "maisecrets: set" if codex else "/maisecrets:settings"
    tail = (f"Undo: `{cmd} KEY default`" if show_all
            else "More: `" + ("maisecrets: settings all" if codex else "/maisecrets:settings all") + "`")
    lines.append(f"Change: `{cmd} KEY VALUE` · Details: `" + ("maisecrets: settings KEY" if codex
                 else "/maisecrets:settings KEY") + "` · " + tail)
    if any(_mark(k, cfg) for k in TITLE):
        lines.append("✎ = you changed it · ⚙ = set by your admin")
    if cfg.get("config_warning"):
        lines.append(f"WARNING: {cfg['config_warning']}")
    return "\n".join(lines)


def _shown(value, key: str = "") -> str:
    if key == "ttl_seconds" and isinstance(value, dict):
        hours = {k: f"{v / 3600:g} h" for k, v in value.items() if isinstance(v, (int, float))}
        rest = ", ".join(f"{k} {h}" for k, h in hours.items() if k != "default")
        return hours.get("default", "?") + (f" ({rest})" if rest else "")
    if key == "regions" and isinstance(value, list):
        return ", ".join(str(r) for r in value) or "auto"
    if isinstance(value, bool):
        return "on" if value else "off"
    if key in _LIST_KEYS and isinstance(value, list):
        return ", ".join(str(h) for h in value) if value else "none"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))[:40] if value else "none"
    return str(value)


def _card(key: str, cfg: dict) -> list[str]:
    value = cfg.get(key)
    st = state(key, cfg)
    lines = [f"  {TITLE[key]} ({key}) · {_shown(value, key)} · {'(default)' if st == 'default' else st}",
             f"    {MEANING[key]}"]
    for mode, text in CHOICE_TEXT.get(key, ()):
        lines.append(f"    {mode:<12}{text}")
    if key in (cfg.get("policy_keys") or []):
        lines.append("    An administrator's policy sets it; it cannot be changed here.")
    elif key == "secret_destinations":
        from . import destinations
        n, total, multi = destinations.summary()
        lines.append(f"    Seen so far: {n} secret(s), {total} destination(s), {multi} with more than one. "
                     "/maisecrets:list shows them.")
        asks, secrets, days = destinations.would_have_asked()
        if days:
            # from the record, not from the questions: a record from observe counts as if protect had been on
            lines.append(f"    protect would have asked about {asks} time(s) in the last {days} day(s), for {secrets} "
                         "secret(s): an estimate from the record, which holds no declined call.")
        if value == "observe":
            lines.append("    Ask before a new host: /maisecrets:settings secret_destinations protect")
        if value == "off":
            lines.append("    Turn on: /maisecrets:settings secret_destinations observe")
    elif key == "ssh_autonomous_hosts":
        lines.append("    Add: /maisecrets:settings ssh_autonomous_hosts add HOST   (as the ssh call writes it, "
                     "user@host:port)")
        if value:
            lines.append(f"    Remove: /maisecrets:settings ssh_autonomous_hosts remove {value[0]}")
        if not cfg.get("ssh_consent"):
            lines.append("    It matters only while SSH consent is on.")
    elif key == "rule_dirs":
        lines.append("    Add: /maisecrets:settings rule_dirs add DIR   (a full path or ~/…; "
                     "/maisecrets:rules shows what each folder loaded)")
        if value:
            lines.append(f"    Remove: /maisecrets:settings rule_dirs remove {value[0]}")
        if cfg.get("policy_rule_dirs"):
            lines.append(f"    From the machine policy, always read: {', '.join(cfg['policy_rule_dirs'])}")
    elif key == "value_files":
        lines.append("    Add: /maisecrets:settings value_files add FILE   (a full path or ~/…)")
        if value:
            lines.append(f"    Remove: /maisecrets:settings value_files remove {value[0]}   (its import stays; "
                         "/maisecrets:forget import:ID removes that)")
    elif key == "clean_dirs":
        lines.append("    Add: /maisecrets:settings clean_dirs add DIR   (a full path or ~/…)")
        if value:
            lines.append(f"    Remove: /maisecrets:settings clean_dirs remove {value[0]}")
        from .file_reads import link_roots
        for d in link_roots(cfg):
            # named here, in the person's own view; the session start gives only a count
            lines.append(f"    {d} is a link or lies under one, so nothing in it counts as clean. Remove it and "
                         f"add the real folder: {os.path.realpath(os.path.expanduser(d))}")
    elif key == "ttl_seconds":
        word = ttl_word(value)
        lines.append("    1h · 24h (default) · 7d. A card number stays 1 h.")
        lines.append(f"    Change: /maisecrets:settings ttl_seconds {'7d' if word != '7d' else '24h'}")
    elif key == "regions":
        lines.append(f"    auto (the country of this computer) or a code: {', '.join(region_codes())}")
        lines.append("    Change: /maisecrets:settings regions de   (one country; the pane takes several)")
    elif key in ("read_pdf", "read_image"):
        suggest = "convert" if key == "read_pdf" else "ask"
        lines.append(f"    Change: /maisecrets:settings {key} {suggest if value != suggest else 'allow'}")
        if key == "read_pdf" and value == "convert":
            from .file_reads import INSTALL, pdftotext
            if not pdftotext():
                lines.append(f"    pdftotext is not installed, so every PDF is refused until it is. {INSTALL}.")
    elif key in _BOOL_KEYS:
        lines.append(f"    Turn {'off' if value else 'on'}: /maisecrets:settings {key} {'off' if value else 'on'}")
    elif key in _CHOICES:
        other = next(m for m in _CHOICES[key] if m != value) if value in _CHOICES[key] else _CHOICES[key][0]
        lines.append(f"    Change: /maisecrets:settings {key} {other}")
    elif key in _INT_KEYS:
        n = value if isinstance(value, int) and not isinstance(value, bool) else DEFAULT_CONFIG[key]
        lines.append(f"    Raise: /maisecrets:settings {key} {min(n * 2, _INT_KEYS[key][1])}   (any whole number "
                     f"from {_INT_KEYS[key][0]})")
    else:
        lines.append(f"    Change it in {str(CONFIG).replace(str(Path.home()), '~', 1)}.")
    return lines


def _hint_lines() -> list[str]:
    given = _given()
    lines = ["Feature hints"]
    for feature in HINTS:
        seen = given.get(feature)
        when = f"shown {seen.get('given')}" if _given_this_revision(feature, given) else "not shown yet"
        lines.append(f"  {TITLE.get(feature) or HINTS[feature]['title']} · {when}")
    lines.append("  Reset: /maisecrets:settings hints reset")
    return lines


def render(show_all: bool = False, cfg: dict | None = None, only: str | None = None, codex: bool = False) -> str:
    """The text view (claude -p, Codex, a client without the mod): the card of one setting, or the table."""
    cfg = cfg if cfg is not None else load_config()
    if only not in TITLE:
        return render_table(show_all, cfg, codex)
    lines = ["maisecrets settings", ""] + _card(only, cfg)
    undo = f"maisecrets: set {only} default" if codex else f"/maisecrets:settings {only} default"
    lines += ["", f"Undo: {undo}    All settings: " + ("maisecrets: settings" if codex else "/maisecrets:settings")]
    if cfg.get("config_warning"):
        lines.append(f"WARNING: {cfg['config_warning']}")
    return "\n".join(lines)


def parse_prompt(prompt) -> tuple[str, str] | None:
    """(key, value word) when the whole prompt is a settings change, ("hints", "reset") for a reset of the
    hints, else None."""
    if not isinstance(prompt, str):
        return None
    if _HINTS_RESET_RE.match(prompt):
        return ("hints", "reset")
    m = _AUTONOMOUS_RE.match(prompt)
    if m:
        add = (m.group(1) or m.group(2)).lower() in ("add", "autonomous")
        return ("ssh_autonomous_hosts", ("add:" if add else "remove:") + m.group(3))
    m = _RULE_DIRS_RE.match(prompt)
    if m:
        return ("rule_dirs", m.group(1).lower() + ":" + m.group(2))
    m = _CLEAN_DIRS_RE.match(prompt)
    if m:
        return ("clean_dirs", m.group(1).lower() + ":" + m.group(2))
    m = _VALUE_FILES_RE.match(prompt)
    if m:
        return ("value_files", m.group(1).lower() + ":" + m.group(2))
    ner = ner_setup.parse(prompt)
    if ner:
        return ("remote_detector", "ner:" + ner)
    m = _PROMPT_RE.match(prompt)
    return (m.group(1).lower(), m.group(2).lower()) if m else None


def _too_wide(folder, cwd: str) -> str:
    """A clean folder must not hold the work of the agent: not /, not the home folder, not a folder that holds the
    folder the session works in (the agent writes there)."""
    real = os.path.realpath(str(folder))
    home = os.path.realpath(os.path.expanduser("~"))
    if real == os.path.dirname(real) or real == home:
        return "it is / or your home folder; choose the folder that holds only the clean files"
    if real != os.path.normpath(os.path.abspath(str(folder))):
        # a link can be pointed at another folder later; the real folder is what the person checked
        return f"it is a link or lies under one; add the real folder {real}"
    if cwd:
        work = os.path.realpath(cwd)
        try:
            if os.path.commonpath([work, real]) == real:
                return "it holds the folder this session works in, where the AI writes files"
        except ValueError:
            pass
    return ""


# The direction of each setting a prompt changes. A change loosens a protection when it gives the AI or a value more
# room: a protective switch turned away from its protective value, a policy that asks or refuses less, a higher cap,
# a new autonomous host. A key in NEUTRAL changes no protection (a test holds that every key is in one of them).
PROTECTIVE_BOOL = {"ssh_consent": True, "block_at_mentions": True, "scrub_transcript": True,
                   "strip_hidden_characters": True, "guard": True, "resolve_in_files": False,
                   "ssh_via_sandbox": False, "renew_on_use": False, "pass_agent_reports": False,
                   "client_header": False}
STRICTER_LAST = {"rehydration": ("automatic", "confirm", "block"), "ssh_approval": ("per-session", "per-command"),
                 "secret_destinations": ("off", "observe", "protect"),
                 # convert sends masked text only; ask can send the whole file
                 "read_pdf": ("allow", "ask", "convert", "block"), "read_image": ("allow", "ask", "block"),
                 # always shows each value on the screen; click shows them for a moment
                 "show_values": ("always", "click", "off"),
                 # mask treats a business address as personal data
                 "business_addresses": ("keep", "mask")}
NEUTRAL = ("tips", "shortcut", "rewrite_prompts")
# a direction of their own in loosens(): a longer life, a country taken out
OWN_DIRECTION = ("ttl_seconds", "regions")


def loosens(key: str, before, after) -> bool:
    """The change of key from before to after (both the values in effect) loosens a protection."""
    if key in PROTECTIVE_BOOL:
        return before == PROTECTIVE_BOOL[key] and after != PROTECTIVE_BOOL[key]
    if key in STRICTER_LAST:
        order = STRICTER_LAST[key]
        if key in ("read_pdf", "read_image") and before not in order:
            before = order[-1]       # a value that is no mode works as block (file_reads.mode)
        return before in order and after in order and order.index(after) < order.index(before)
    if key in _INT_KEYS:
        return isinstance(before, int) and isinstance(after, int) and after > before
    if key == "regions":
        # a country taken out: its personal-data rules stop (auto counts as one)
        return bool(set(_regions_of(before)) - set(_regions_of(after)))
    if key == "ttl_seconds":
        b = before.get("default") if isinstance(before, dict) else None
        a = after.get("default") if isinstance(after, dict) else None
        return isinstance(a, int) and isinstance(b, int) and a > b
    if key == "ssh_autonomous_hosts":
        return bool(set(after or []) - set(before or []))
    if key == "remote_detector":
        # off masks fewer names; a service on the network gets the text of tool results
        old = (before or {}).get("url") if isinstance(before, dict) else None
        new = (after or {}).get("url") if isinstance(after, dict) else None
        old_fb = ((before or {}).get("fallback") or {}).get("url") if isinstance(before, dict) else None
        new_fb = ((after or {}).get("fallback") or {}).get("url") if isinstance(after, dict) else None
        # a withheld tool result is the rules' result again: names that only the service finds reach the AI
        withhold_off = (isinstance(before, dict) and before.get("unavailable") == "withhold"
                        and not (isinstance(after, dict) and after.get("unavailable") == "withhold"))
        # an image that no longer follows the plugin keeps its old fixes and misses the new ones
        updates_off = (isinstance(after, dict) and after.get("auto_update") is False
                       and not (isinstance(before, dict) and before.get("auto_update") is False))
        return (withhold_off or updates_off or bool(old and not new)
                or bool(new and new != old and not ner_setup.remote.is_local(str(new)))
                or bool(new_fb and new_fb != old_fb and not ner_setup.remote.is_local(str(new_fb))))

    def same(dirs) -> set:     # ~/team, /home/me/team/ and /home/me/./team are one folder
        return {os.path.normcase(os.path.normpath(os.path.expanduser(d.strip()))) for d in dirs or []
                if isinstance(d, str) and d.strip()}
    if key == "clean_dirs":
        return bool(same(after) - same(before))     # a new clean folder: its files pass
    if key == "rule_dirs":
        return bool(same(before) - same(after))     # a folder taken off: its rules no longer run
    # value_files: neither way loosens. A file added imports more values; a file taken off keeps its import, which
    # only the person's prompt /maisecrets:forget import:ID removes (values.remove_typed records that)
    return False


def apply_typed(key: str, word: str, route: str = "typed prompt", cwd: str = "") -> tuple[bool, str]:
    """Write one change the person typed into config.json, keep every other key, and say what happened: (changed,
    text). Only the prompt hook calls this, for a prompt whose source is the person (TYPED_SOURCES). It is the
    only writer, under one name that a tool call is refused for (IN_A_COMMAND_RE)."""
    if (key, word) == ("hints", "reset"):
        try:
            with _lock_for(_LOCK):
                if _HINTS_FILE.exists():
                    _HINTS_FILE.unlink()
        except (OSError, LockTimeout) as exc:
            return False, f"maisecrets: the hints cannot be reset ({type(exc).__name__})."
        return True, "maisecrets: feature hints reset. No protection setting was changed."
    cfg = load_config()
    if key in (cfg.get("policy_keys") or []):
        return False, (f"maisecrets: {TITLE.get(key, key)} is set by your administrator's policy. It cannot be "
                       "changed here.")
    hosts_change = key in _LIST_KEYS and (word == "default" or word.startswith(("add:", "remove:")))
    if key == "regions":
        codes = region_codes()
        bare = word[len("toggle:"):] if word.startswith("toggle:") else word
        if word != "default" and bare != "auto" and bare not in codes:
            return False, f"maisecrets: regions takes auto or a country code ({', '.join(codes)}), or default."
    ner_change = key == "remote_detector" and word.startswith("ner:")
    if key not in _BOOL_KEYS and key not in _CHOICES and key not in _INT_KEYS and not hosts_change and not ner_change \
            and key != "regions":
        if key == "remote_detector":
            return False, ("maisecrets: send /maisecrets:ner local (or url URL, or off), or in Codex: "
                           "maisecrets: ner local.")
        if key == "ssh_autonomous_hosts":
            return False, ("maisecrets: send /maisecrets:settings ssh_autonomous_hosts add HOST (or remove HOST), "
                           "or in Codex: maisecrets: ssh autonomous HOST (or ask HOST).")
        if key == "rule_dirs":
            return False, ("maisecrets: send /maisecrets:settings rule_dirs add DIR (or remove DIR), "
                           "or in Codex: maisecrets: set rule_dirs add DIR.")
        if key == "clean_dirs":
            return False, ("maisecrets: send /maisecrets:settings clean_dirs add DIR (or remove DIR), "
                           "or in Codex: maisecrets: set clean_dirs add DIR.")
        if key == "value_files":
            return False, ("maisecrets: send /maisecrets:settings value_files add FILE (or remove FILE), "
                           "or in Codex: maisecrets: set value_files add FILE.")
        if key in MEANING:
            return False, f"maisecrets: {key} is not changed by a prompt; edit {CONFIG} by hand."
        return False, f"maisecrets: {key} is no setting this command changes. /maisecrets:settings --all lists them."
    if word != "default" and not hosts_change and not ner_change and key != "regions":
        if key in _BOOL_KEYS and word not in _BOOL_WORDS:
            return False, f"maisecrets: {key} takes on, off or default."
        if key == "read_image" and word == "convert":
            return False, ("maisecrets: convert is for PDFs only; maisecrets cannot read text in images. read_image "
                           "takes allow, ask, block or default.")
        if key in _CHOICES and word not in _CHOICES[key]:
            return False, f"maisecrets: {key} takes {', '.join(_CHOICES[key])} or default."
        if key in _INT_KEYS:
            low, high = _INT_KEYS[key]
            # the length first: int() of thousands of digits raises instead of answering (codex review of 0.6.9)
            if not (word.isdigit() and len(word) <= 8 and low <= int(word) <= high):
                return False, f"maisecrets: {key} takes a whole number from {low} to {high:,}, or default."
    note = ""
    if ner_change:
        # a server name becomes its URL; an argument the command does not know is answered, never ignored
        resolved, answer = ner_setup.typed_word(word[4:], slash=route in ("slash command", "settings pane"))
        if resolved is None:
            return False, answer
        word = "ner:" + resolved
    if ner_change and word.startswith("ner:fallback:url:") and not (cfg.get("remote_detector") or {}).get("url"):
        return False, ("maisecrets: a fallback needs a source first: send /maisecrets:ner on, then the fallback. "
                       "Nothing was changed.")
    if ner_change and word.startswith(("ner:url:", "ner:fallback:url:")):
        word_url = word.split("url:", 1)[1]
        why = ner_setup.check_url(word_url)
        if why:
            return False, f"maisecrets: the address is not used ({why}). Nothing was changed."
        if word.startswith("ner:fallback:"):
            note = (" The fallback gets the tool results only while the service of this computer does not answer, "
                    "and never a prompt you type. The service has no sign-in: use one on a private network only.")
        elif not ner_setup.remote.is_local(word_url):
            note = " " + ner_setup.SENT_NOTE.format(where="that service") + (
                " The service has no sign-in: use one on a private network only.")
        else:
            note = " " + ner_setup.LOCAL_NOTE
    if ner_change and word.startswith("ner:gateway:"):
        gw = word[len("ner:gateway:"):]
        why = ner_setup.check_url(gw) or ("" if gw.lower().startswith("https://") else "a gateway is https only")
        if why:
            return False, f"maisecrets: the address is not used ({why}). Nothing was changed."
        note = (" " + ner_setup.SENT_NOTE.format(where="this gateway")
                + " Log in once more with /maisecrets:sref login: it asks for the name scope.")
    if key == "read_pdf" and word == "convert":
        from .file_reads import INSTALL, pdftotext
        if not pdftotext():
            note = f" pdftotext is not installed, so maisecrets refuses every PDF until it is. Install it: {INSTALL}."
    if key == "value_files" and word.startswith("add:"):
        from .user_rules import expand
        path = expand(word[4:])
        if not path.is_absolute():
            return False, "maisecrets: the file is not added (not an absolute path). Nothing was changed."
        if not os.path.lexists(path):
            note = " The file does not exist yet; maisecrets imports it at a session start once it does."
        else:
            from .values import read_source
            try:
                read_source(path)
            except ValueError as exc:
                return False, f"maisecrets: the file is not added ({exc}). Nothing was changed."
            note = " maisecrets imports it at the next session start."
    if key in _FOLDER_KEYS and word.startswith("add:"):
        from .user_rules import expand, refused_folder
        why = refused_folder(expand(word[4:]))
        if why:
            return False, f"maisecrets: the folder is not added ({why.split(': ', 1)[-1]}). Nothing was changed."
        if key == "clean_dirs":
            why = _too_wide(expand(word[4:]), cwd)
            if why:
                return False, f"maisecrets: the folder is not added ({why}). Nothing was changed."
        if not expand(word[4:]).is_dir():
            note = (" The folder does not exist yet; maisecrets reads it once it does." if key == "rule_dirs"
                    else " The folder does not exist yet.")
        elif key == "rule_dirs":
            from .user_rules import rule_folder, _rule_files
            if not _rule_files(rule_folder(expand(word[4:]))):
                note = (" It holds no *.json or *.prefixes file, neither at its top nor in rules/, so it adds no rule"
                        " yet; /maisecrets:rules shows what each folder loads.")
    # a symlinked config.json (dotfiles) keeps its link: the new file replaces the target
    target = CONFIG.resolve() if CONFIG.is_symlink() else CONFIG
    try:
        # read, change and write under one lock: two prompts at once must not drop each other's change
        with _lock_for(_LOCK):
            try:
                text = target.read_text(encoding="utf-8")
            except FileNotFoundError:
                text = "{}"
            try:
                user = json.loads(text)
            except ValueError:
                user = None
            if not isinstance(user, dict):
                # rewriting a file that does not parse would drop what the person wrote in it
                return False, f"maisecrets: {CONFIG} is not one valid JSON object; fix it first. Nothing was changed."
            try:
                _check_types(user, CONFIG.name)
            except ConfigError as exc:
                # load_config ignores the whole file then: the change would be written and still not count
                return False, f"maisecrets: {exc}; fix it first. Nothing was changed."
            # before and after under the same lock: two changes at once record a weakening once, not 0 or 2 times
            before = load_config().get(key)
            if ner_change:
                user[key] = ner_setup.updated(user.get(key), word[4:])
            elif word == "default":
                user.pop(key, None)
                if key == "regions":
                    user.pop("pii_regions", None)     # the old name of the same setting would read again
            elif hosts_change:
                verb, host = word.split(":", 1)
                if key in _PATH_KEYS:
                    # ~/team and the same folder written in full are one folder
                    from .user_rules import expand
                    hosts = [h for h in user.get(key, []) if not isinstance(h, str) or expand(h) != expand(host)]
                else:
                    hosts = [h for h in user.get(key, []) if h != host]
                user[key] = hosts + [host] if verb == "add" else hosts
            elif key == "ttl_seconds":
                # only the default lifetime: a card's hour and a lifetime per type the file holds stay
                had = user.get(key) if isinstance(user.get(key), dict) else DEFAULT_CONFIG["ttl_seconds"]
                user[key] = {**had, "default": TTL_WORDS[word]}
            elif key == "regions":
                from .home import _old_region_key
                # the value in effect: a file of 0.4 and older names the countries pii_regions
                effective = _old_region_key(user).get(key)
                user.pop("pii_regions", None)
                if word.startswith("toggle:"):
                    code = word[len("toggle:"):]
                    now = [r for r in _regions_of(effective) if r != "auto"]
                    if code == "auto":
                        now = []
                    elif code in now:
                        now.remove(code)
                    else:
                        now.append(code)
                    user[key] = now or ["auto"]
                else:
                    user[key] = [word]
            else:
                user[key] = (_BOOL_WORDS[word] if key in _BOOL_KEYS else int(word) if key in _INT_KEYS
                             else word)
            atomic_write(target, json.dumps(user, indent=2) + "\n")
            after = load_config()
    except (OSError, LockTimeout) as exc:
        return False, f"maisecrets: {CONFIG} cannot be written ({type(exc).__name__}); nothing was changed."
    if loosens(key, before, after.get(key)):
        from . import events
        events.record_weakening("setting", key, route)      # the next session start names it to the person
    if ner_change and word.startswith(("ner:url:", "ner:gateway:", "ner:local")):
        ner_setup.claim_prompts_note()      # the answer says it: the session start need not say it again
    if ner_change and word == "ner:local":
        note = " " + ner_setup.LOCAL_NOTE
        # the person's typed choice starts the service at once, with no question first (start_typed checks the route)
        if ner_setup.start_typed(route):
            note += " " + ner_setup.START_NOTE
    if ner_change and word == "ner:off" and ner_setup.start_running():
        note = " " + ner_setup.STILL_RUNS
    if ner_change and word.startswith("ner:unavailable:"):
        return True, f"maisecrets: {ner_setup.unavailable_line(after.get(key) or {})}"
    if ner_change and word.startswith("ner:updates:"):
        return True, f"maisecrets: {ner_setup.updates_line(after.get(key) or {})}"
    if ner_change:
        return True, f"maisecrets: {ner_setup.describe(after.get(key))}.{note}"
    shown = (TTL_LABELS.get(ttl_word(after.get(key)) or "", _shown(after.get(key), key)) if key == "ttl_seconds"
             else ", ".join(_regions_of(after.get(key))) if key == "regions" else _shown(after.get(key), key))
    return True, f"maisecrets: {TITLE.get(key, key)} is {shown} ({state(key, after)}).{note}"


# ------------------------------------------------------------------ hints --
# A hint is one fixed line for the person, once per home: the hook's systemMessage, which the client shows to the
# person and not to the model. The model gets nothing about it, so it cannot word it again or repeat it (field
# report 2026-11-17: the model said the image hint twice, in its own words, and added the ssh hint to an unrelated
# answer). REVISION goes up only when the feature changes in a way that matters: then the hint comes once more. A
# hint never comes again because time passed, and a new wording of the line is no reason for a new revision.
HINTS = {
    "ssh_consent": {
        "revision": 2,
        "claude": ("maisecrets: the AI just ran an ssh command that changes a host. "
                   "/maisecrets:settings ssh_consent on asks you before each one; off keeps it as it is."),
        "codex": ("maisecrets: the AI just ran an ssh command that changes a host. "
                  "Send `maisecrets: set ssh_consent on` alone as your prompt to be asked before each one; "
                  "off keeps it as it is."),
    },
}
# no destination and no secret name in the line: the list, rendered by maisecrets, names the destination
HINTS["secret_destinations"] = {
    "revision": 1,
    "claude": ("maisecrets: a stored secret just went to a host it was not used with before; maisecrets only notes "
               "this. /maisecrets:list shows where each secret went; /maisecrets:settings secret_destinations protect "
               "asks you before a new host."),
    "codex": ("maisecrets: a stored secret just went to a host it was not used with before; maisecrets only notes "
              "this. Send `maisecrets: set secret_destinations protect` alone as your prompt to be asked before a new "
              "host."),
}
for _key, _noun, _first, _does, _rest in (
        ("read_pdf", "PDFs", "convert", "sends only their text, masked", "ask asks you each time, block stops them"),
        ("read_image", "images", "ask", "asks you each time", "block stops them")):
    # the same line for every file: nothing of the file or its name is in it (C28)
    HINTS[_key] = {
        "revision": 1,
        "claude": (f"maisecrets: {_noun} go to the AI as they are; maisecrets cannot mask inside them. "
                   f"/maisecrets:settings {_key} {_first} {_does}; {_rest}."),
        "codex": (f"maisecrets: {_noun} go to the AI as they are; maisecrets cannot mask inside them. "
                  f"`maisecrets: set {_key} {_first}`, alone as your prompt, {_does}; {_rest}."),
    }
# ms:(…) is no setting: its hint is a line for the person, once (maisecrets/check_value.py). Claude Code shows it under
# the first blocked or rewritten prompt that carried a value, Codex at the session start
HINTS["check_value"] = {"revision": 1, "title": "Check a value with ms:(…)"}
_HINTS_FILE = HOME / "hints.json"


def _given() -> dict:
    try:
        given = json.loads(_HINTS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return given if isinstance(given, dict) else {}


def _given_this_revision(feature: str, given: dict) -> bool:
    seen = given.get(feature)
    return isinstance(seen, dict) and isinstance(seen.get("revision"), int) and \
        seen["revision"] >= HINTS[feature]["revision"]


def hint_due(feature: str, cfg: dict) -> bool:
    """The setting is undecided (not in config.json, not in a policy, still the default) and this revision
    of its hint was never given. `tips: false` silences every hint."""
    if cfg.get("tips", True) is False:
        return False
    if feature in (cfg.get("policy_keys") or []) or feature in (cfg.get("user_keys") or []):
        return False
    if cfg.get(feature) != DEFAULT_CONFIG.get(feature):
        return False      # a file that was ignored as a whole still turned it on (vault._keep_the_stricter)
    return not _given_this_revision(feature, _given())


# A hint is claimed only where a person sees the line: a headless run would use it up unseen (Gate A of 30fb8d30).
# Claude Code: not under an Agent SDK entry point (`claude -p` is sdk-cli). Codex sets no entry point, but the first
# line of its rollout (the payload's transcript_path) is session_meta with the session source, serialized lowercase
# (codex-rs protocol SessionSource): cli is the terminal UI and vscode the app server (IDE extension, desktop app),
# which show a hook's systemMessage; exec prints none; mcp, a subagent and an unknown source get no hint either
_SHOWN_SOURCES = ("cli", "vscode")
_META_MAX = 4 << 20        # session_meta carries the base instructions: one line of some KB


def person_sees_hook_lines(payload: dict, codex: bool) -> bool:
    if not codex:
        return not os.environ.get("CLAUDE_CODE_ENTRYPOINT", "").startswith(NESTED_ENTRYPOINTS)
    return codex_session_source(payload.get("transcript_path")) in _SHOWN_SOURCES


def codex_session_source(path) -> str | None:
    """The `source` of a Codex rollout's session_meta line; None when the file or the line cannot tell."""
    if not isinstance(path, str) or not path:
        return None
    try:
        with open(path, "rb") as f:
            meta = json.loads(f.readline(_META_MAX))
    except (OSError, ValueError):
        return None
    body = meta.get("payload") if isinstance(meta, dict) and meta.get("type") == "session_meta" else None
    source = body.get("source") if isinstance(body, dict) else None
    return source if isinstance(source, str) else None


def claim_hint(feature: str) -> bool:
    """Record this revision of the hint as given, and say whether this process may give it: only the one that
    wrote the record. Two hooks at once give it once; a record that cannot be written gives no hint, so an
    unwritable home never makes it nag."""
    try:
        with _lock_for(_LOCK):
            given = _given()
            if _given_this_revision(feature, given):
                return False
            given[feature] = {"revision": HINTS[feature]["revision"], "given": time.strftime("%Y-%m-%d")}
            atomic_write(_HINTS_FILE, json.dumps(given, indent=2) + "\n")
            return True
    except (OSError, LockTimeout):
        return False
