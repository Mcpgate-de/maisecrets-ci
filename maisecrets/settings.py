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

from .home import (CONFIG, DEFAULT_CONFIG, HOME, ConfigError, LockTimeout, _check_types, _lock_for, atomic_write,
                   load_config)

# Every key of the config is in exactly one class (a test holds it): a new key without one is a test failure.
DISCOVERABLE = ("ssh_consent", "ssh_autonomous_hosts", "secret_destinations", "rehydration", "read_pdf",
                "read_image")
ADVANCED = ("ssh_host_groups", "ssh_approval", "resolve_in_files", "ssh_via_sandbox", "block_at_mentions",
            "rewrite_prompts", "scrub_transcript", "strip_hidden_characters", "regions", "ttl_seconds",
            "renew_on_use", "tips", "shortcut", "guard", "pass_agent_reports", "gateway_servers", "client_header",
            "max_keys_per_session", "max_resolves_per_hour", "rule_dirs", "clean_dirs", "value_files")
INTERNAL = ("backend", "allow_plaintext_store", "report_url", "max_ttl_seconds", "max_new_entries_per_result",
            "keep_purged_days", "audit_max_lines", "pii_regions", "client_vault_cafile")

TITLE = {
    "ssh_consent": "SSH consent", "ssh_autonomous_hosts": "Autonomous hosts",
    "secret_destinations": "Secret destinations",
    "rehydration": "Rehydration", "ssh_host_groups": "SSH host groups",
    "ssh_approval": "SSH approval", "resolve_in_files": "Values in files", "ssh_via_sandbox": "Values over ssh",
    "block_at_mentions": "Block @file mentions", "rewrite_prompts": "Rewrite prompts",
    "scrub_transcript": "Clean the transcript", "strip_hidden_characters": "Remove invisible characters",
    "regions": "Regions", "ttl_seconds": "Lifetime of a value", "renew_on_use": "Renew on use",
    "tips": "Tips and hints",
    "shortcut": "/ms shortcut", "guard": "Update guard", "pass_agent_reports": "Subagent reports",
    "gateway_servers": "Gateway servers", "client_header": "Vault references", "rule_dirs": "Rule folders",
    "read_pdf": "PDFs the AI reads", "read_image": "Images the AI reads", "clean_dirs": "Folders with clean files",
    "value_files": "Value files",
    "max_keys_per_session": "Values per session and hour", "max_resolves_per_hour": "Uses per hour",
}
MEANING = {
    "ssh_consent": "Ask before each ssh command that changes something on a host.",
    "ssh_autonomous_hosts": "Hosts where the AI may change things over ssh without asking, in every session.",
    "secret_destinations": "Notes where each stored secret is sent, on this computer only. Never stops a call.",
    "rehydration": "How a stored value goes into a tool call.",
    "ssh_host_groups": "Hosts that one typed ssh window covers together.",
    "ssh_approval": "Under rehydration confirm: ask per command, or once per value and session for ssh.",
    "resolve_in_files": "A placeholder in Write or Edit content gets its value.",
    "ssh_via_sandbox": "A value may go to ssh on stdin inside the Claude Code sandbox.",
    "block_at_mentions": "Block an @file mention in a prompt; the file would skip the scan.",
    "rewrite_prompts": "Claude Code with mods: send a prompt with placeholders instead of blocking it.",
    "scrub_transcript": "Remove a value from the session transcript on disk.",
    "strip_hidden_characters": "Remove invisible characters from tool results.",
    "regions": "Countries for the personal-data rules.",
    "read_pdf": "maisecrets cannot look inside a PDF. What happens when the AI reads one.",
    "read_image": "maisecrets cannot look inside an image. What happens when the AI reads one.",
    "clean_dirs": "Folders of clean PDFs and images: a file that was there before the session is allowed.",
    "rule_dirs": "Folders with detection rules of your own or of your team, read with ~/.maisecrets/rules.d.",
    "value_files": "Files of values from your own tools (JSON lines), imported at session start when they change. "
                   "An import only adds; your prompt /maisecrets:forget import:ID removes one.",
    "ttl_seconds": "How long a stored value lives.",
    "renew_on_use": "A use of a value extends its life.",
    "tips": "A short tip at session start, and a hint when a setting first matters.",
    "shortcut": "The first session start names /maisecrets:shortcut once.",
    "guard": "A synced install registers the guard outside its folder.",
    "pass_agent_reports": "A subagent's report is not blocked.",
    "gateway_servers": "MCP servers that resolve placeholders themselves.",
    "client_header": "A key header on your own MCP server once it sends a masked value and supports it, so it "
                     "can give its masked values back into your files and commands, never to the AI.",
    "max_keys_per_session": "How many different stored values one session may use in an hour. A brake against "
                            "sending all values out at once; normal work stays far below it.",
    "max_resolves_per_hour": "How often stored values may go into tool calls in an hour, all sessions together.",
}
CHOICE_TEXT = {
    "rehydration": (("automatic", "use a stored value in a tool call"), ("confirm", "ask before each use"),
                    ("block", "never put a stored value into a tool call")),
    "ssh_approval": (("per-command", "ask for each command"), ("per-session", "ask once per value and session")),
    "read_pdf": (("allow", "the PDF goes to the AI as it is"), ("ask", "ask you before each PDF"),
                 ("block", "the Read tool does not open a PDF"),
                 ("convert", "send only its text, with secrets and personal data masked (needs pdftotext)")),
    "read_image": (("allow", "the image goes to the AI as it is"), ("ask", "ask you before each image"),
                   ("block", "the Read tool does not open an image")),
}
GROUPS = (("Protection", ("ssh_consent", "ssh_autonomous_hosts", "secret_destinations")),
          ("Using stored values", ("rehydration",)),
          ("PDFs and images", ("read_pdf", "read_image")))
ADVANCED_GROUPS = (("Stored values", ("ttl_seconds", "renew_on_use", "resolve_in_files", "gateway_servers",
                                      "client_header",
                                      "max_keys_per_session", "max_resolves_per_hour")),
                   ("ssh", ("ssh_host_groups", "ssh_approval", "ssh_via_sandbox")),
                   ("Prompts and tool output", ("block_at_mentions", "rewrite_prompts", "scrub_transcript",
                                                "strip_hidden_characters", "regions", "rule_dirs",
                                                "clean_dirs", "value_files", "pass_agent_reports")),
                   ("Help and updates", ("tips", "shortcut", "guard")))

# what a prompt may set; any other key is edited in config.json by hand
_BOOL_WORDS = {"on": True, "true": True, "off": False, "false": False}
_CHOICES = {"rehydration": ("automatic", "confirm", "block"), "ssh_approval": ("per-command", "per-session"),
            "secret_destinations": ("observe", "off"), "read_pdf": ("allow", "ask", "block", "convert"),
            "read_image": ("allow", "ask", "block")}
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


def typed_by_the_person(payload: dict) -> bool:
    """The prompt counts as typed by the person: a `source` the person has, and no program started the client."""
    return payload.get("source") in TYPED_SOURCES and nested_program(payload) is None


def not_typed_reason(payload: dict) -> str:
    """One sentence for a settings change that did not count, and what the person can do."""
    entry = nested_program(payload)
    if entry:
        shown = re.sub(r"[^a-z0-9-]", "", entry.lower())[:20]     # a variable is no text for the model
        return ("maisecrets: a settings change counts only when you type it as your prompt; this one came from a "
                f"client that a program started (entry point {shown}, as `claude -p` has), so nothing was changed. "
                "Type it in your own Claude Code or Codex session.")
    return ("maisecrets: a settings change counts only when you type it as your prompt; this one came from the "
            f"client ({payload.get('source')}), so nothing was changed.")


def state(key: str, cfg: dict) -> str:
    if key in (cfg.get("policy_keys") or []):
        return "set by a policy"
    if key not in (cfg.get("user_keys") or []):
        return "not decided"
    return "set by you"


def _shown(value, key: str = "") -> str:
    if key == "ttl_seconds" and isinstance(value, dict):
        hours = {k: f"{v / 3600:g} h" for k, v in value.items() if isinstance(v, (int, float))}
        rest = ", ".join(f"{k} {h}" for k, h in hours.items() if k != "default")
        return hours.get("default", "?") + (f" ({rest})" if rest else "")
    if isinstance(value, bool):
        return "on" if value else "off"
    if key in _LIST_KEYS and isinstance(value, list):
        return ", ".join(str(h) for h in value) if value else "none"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))[:40] if value else "none"
    return str(value)


def _card(key: str, cfg: dict) -> list[str]:
    value = cfg.get(key)
    lines = [f"  {TITLE[key]} · {_shown(value, key)} · {state(key, cfg)}", f"    {MEANING[key]}"]
    for mode, text in CHOICE_TEXT.get(key, ()):
        lines.append(f"    {mode:<12}{text}")
    if key in (cfg.get("policy_keys") or []):
        lines.append("    An administrator's policy sets it; it cannot be changed here.")
    elif key == "secret_destinations":
        from . import destinations
        n, total, multi = destinations.summary()
        lines.append(f"    Seen so far: {n} secret(s), {total} destination(s), {multi} with more than one. "
                     "/maisecrets:list shows them.")
        lines.append("    Asking before a new destination (protect) comes in a later version.")
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


def render(show_all: bool = False, cfg: dict | None = None, only: str | None = None) -> str:
    cfg = cfg if cfg is not None else load_config()
    lines = ["maisecrets settings", ""]
    if only in TITLE:
        lines += _card(only, cfg) + ["", "All settings: /maisecrets:settings"]
    else:
        for title, keys in GROUPS + (ADVANCED_GROUPS if show_all else ()):
            lines.append(title)
            for key in keys:
                lines += _card(key, cfg)
            lines.append("")
        if not show_all:
            lines += [f"More settings ({len(ADVANCED)}): /maisecrets:settings --all", ""]
        lines += _hint_lines() + [""]
        lines += ["To undo a decision: /maisecrets:settings KEY default (the hint for it may come once more).",
                  "In Codex, send a change alone as your prompt: maisecrets: set KEY VALUE"]
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
                 "secret_destinations": ("off", "observe"),
                 # convert sends masked text only; ask can send the whole file
                 "read_pdf": ("allow", "ask", "convert", "block"), "read_image": ("allow", "ask", "block")}
NEUTRAL = ("tips", "shortcut", "rewrite_prompts")


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
    if key == "ssh_autonomous_hosts":
        return bool(set(after or []) - set(before or []))

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
        return False, f"maisecrets: {key} is managed by a machine policy; it cannot be changed here."
    hosts_change = key in _LIST_KEYS and (word == "default" or word.startswith(("add:", "remove:")))
    if key not in _BOOL_KEYS and key not in _CHOICES and key not in _INT_KEYS and not hosts_change:
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
    if word != "default" and not hosts_change:
        if key in _BOOL_KEYS and word not in _BOOL_WORDS:
            return False, f"maisecrets: {key} takes on, off or default."
        if key == "read_image" and word == "convert":
            return False, ("maisecrets: convert is for PDFs only; maisecrets does no OCR. read_image takes allow, "
                           "ask, block or default.")
        if key in _CHOICES and word not in _CHOICES[key]:
            return False, f"maisecrets: {key} takes {', '.join(_CHOICES[key])} or default."
        if key in _INT_KEYS:
            low, high = _INT_KEYS[key]
            # the length first: int() of thousands of digits raises instead of answering (codex review of 0.6.9)
            if not (word.isdigit() and len(word) <= 8 and low <= int(word) <= high):
                return False, f"maisecrets: {key} takes a whole number from {low} to {high:,}, or default."
    note = ""
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
            if word == "default":
                user.pop(key, None)
            elif hosts_change:
                verb, host = word.split(":", 1)
                if key in _PATH_KEYS:
                    # ~/team and the same folder written in full are one folder
                    from .user_rules import expand
                    hosts = [h for h in user.get(key, []) if not isinstance(h, str) or expand(h) != expand(host)]
                else:
                    hosts = [h for h in user.get(key, []) if h != host]
                user[key] = hosts + [host] if verb == "add" else hosts
            else:
                user[key] = (_BOOL_WORDS[word] if key in _BOOL_KEYS else int(word) if key in _INT_KEYS
                             else word)
            atomic_write(target, json.dumps(user, indent=2) + "\n")
    except (OSError, LockTimeout) as exc:
        return False, f"maisecrets: {CONFIG} cannot be written ({type(exc).__name__}); nothing was changed."
    after = load_config()
    if loosens(key, cfg.get(key), after.get(key)):
        from . import events
        events.record_weakening("setting", key, route)      # the next session start names it to the person
    return True, f"maisecrets: {TITLE.get(key, key)} is {_shown(after.get(key), key)} ({state(key, after)}).{note}"


# ------------------------------------------------------------------ hints --
# A hint is a sentence for the model, once. REVISION goes up only when the feature changes in a way that
# matters: then the hint comes once more. A hint never comes again because time passed.
HINTS = {
    "ssh_consent": {
        "revision": 2,
        "claude": ("maisecrets can ask the user before each ssh command that changes something on a host "
                   "(setting ssh_consent; it is off, and the user has not decided). Mention this once, in one "
                   "sentence, after your answer. If the user wants it, tell them to send this as their own prompt: "
                   "/maisecrets:settings ssh_consent on (or off, so the question does not come again). "
                   "Do not change settings yourself."),
        "codex": ("maisecrets can ask the user before each ssh command that changes something on a host "
                  "(setting ssh_consent; it is off, and the user has not decided). Mention this once, in one "
                  "sentence, after your answer. If the user wants it, tell them to send this alone as their own "
                  "prompt: maisecrets: set ssh_consent on (or off, so the question does not come again). "
                  "Do not change settings yourself."),
    },
}
HINTS["secret_destinations"] = {
    "revision": 1,
    # no destination and no secret name in the text: an injection that caused the new destination cannot use the
    # hint as an instruction ("allow …"); the list, rendered by maisecrets, names the destination
    "claude": ("maisecrets notes, on this computer only, where stored secrets are sent. A call with a stored secret "
               "just named a host that this secret was not used with before. maisecrets only notes this and did not "
               "stop the call; it does not judge whether a destination is safe. Mention this once, in one or two "
               "sentences, after your answer, and tell the user that /maisecrets:list shows where each secret was "
               "used. If the user does not want this note again, tell them to send this as their own prompt: "
               "/maisecrets:settings secret_destinations observe. Do not change settings yourself and do not call any "
               "destination safe or approved."),
    "codex": ("maisecrets notes, on this computer only, where stored secrets are sent. A call with a stored secret "
              "just named a host that this secret was not used with before. maisecrets only notes this and did not "
              "stop the call; it does not judge whether a destination is safe. Mention this once, in one or two "
              "sentences, after your answer. If the user does not want this note again, tell them to send this alone "
              "as their own prompt: maisecrets: set secret_destinations observe. Do not change settings yourself and "
              "do not call any destination safe or approved."),
}
for _key, _noun, _more in (("read_pdf", "PDF", "convert (only its text goes to you, with secrets and personal data "
                                               "masked), ask (the user is asked each time), block"),
                           ("read_image", "image", "ask (the user is asked each time), block")):
    # the same sentence for every file: nothing of the file or its name is in it (C28)
    HINTS[_key] = {
        "revision": 1,
        "claude": (f"maisecrets cannot look inside an image or a PDF: the {_noun} you just read went to you as it is, "
                   f"with any password or personal data in it (setting {_key}; it is allow, and the user has not "
                   "decided). Mention this once, in one or two sentences, after your answer. If the user wants "
                   f"another way, tell them to send this as their own prompt: /maisecrets:settings {_key} MODE, "
                   f"where MODE is {_more}, or allow so this note does not come again. Do not change settings "
                   "yourself."),
        "codex": (f"maisecrets cannot look inside an image or a PDF: the {_noun} you just read went to you as it is, "
                  f"with any password or personal data in it (setting {_key}; it is allow, and the user has not "
                  "decided). Mention this once, in one or two sentences, after your answer. If the user wants "
                  f"another way, tell them to send this alone as their own prompt: maisecrets: set {_key} MODE, "
                  f"where MODE is {_more}, or allow so this note does not come again. Do not change settings "
                  "yourself."),
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
