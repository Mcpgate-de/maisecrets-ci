"""Detection events for bug reports: what was found (kind, type, length), where (hook,
client), under which version. Never a value, never a display. ``maisecrets report`` turns
the last event into a prefilled GitHub issue URL. The same file holds one line per protection
that was loosened, which the next session start names to the person."""
from __future__ import annotations

import json
import os
import platform
import re
import sys
import time
import urllib.parse
from pathlib import Path

from .home import HOME

EVENTS = HOME / "events.log"
KEEP = 200
ISSUES_URL = "https://github.com/Mcpgate-de/maisecrets/issues/new"


def plugin_version() -> str:
    try:
        manifest = Path(__file__).resolve().parent.parent / ".claude-plugin" / "plugin.json"
        return json.loads(manifest.read_text(encoding="utf-8")).get("version", "?")
    except (OSError, ValueError):
        return "?"


def record(hook: str, client: str, entries: list, outcome: str = "") -> None:
    """One line per detection event; the last KEEP lines are kept."""
    if not entries:
        return
    try:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        line = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            "hook": hook, "client": client, "version": plugin_version(),
            "hits": [{"key": e.key, "type": e.type, "kind": e.kind} for e in entries],
            **({"outcome": outcome} if outcome else {}),
        })
        _append(line)
    except OSError:
        pass


def _parsed(text: str) -> dict:
    try:
        obj = json.loads(text)
    except ValueError:
        return {}
    return obj if isinstance(obj, dict) else {}


def _append(line: str) -> None:
    old: list[str] = []
    if EVENTS.exists():
        # a broken byte in the log must not stop the record (Gate B of 0.6.21)
        old = EVENTS.read_text(encoding="utf-8", errors="replace").splitlines()
    lines = old + [line]

    def removal_only(text: str) -> bool:
        hits = _parsed(text).get("hits")
        # a line of another shape is kept and never breaks the record (Opus review, 2026-10-06)
        return (isinstance(hits, list) and bool(hits)
                and all(isinstance(h, dict) and h.get("type") == "HIDDEN" for h in hits))
    # removals of invisible characters go first, the new one too, so they never push a detection out; a loosened
    # protection goes last, so the next session start can still name it
    while len(lines) > KEEP:
        drop = next((i for i, x in enumerate(lines) if removal_only(x)), None)
        if drop is None:
            drop = next((i for i, x in enumerate(lines) if "weakened" not in _parsed(x)), 0)
        del lines[drop]
    fd = os.open(EVENTS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def load(n: int = 20) -> list[dict]:
    """The last n detection events; a line about a loosened protection is not one."""
    try:
        lines = EVENTS.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            obj = json.loads(ln)
        except ValueError:
            continue
        if isinstance(obj, dict) and "weakened" not in obj:
            out.append(obj)
    return out[-n:] if n > 0 else []


# ------------------------------------------------------------ weakenings --
# Each action that loosens a protection writes one line: a setting changed in the looser direction, a value
# forgotten. A wipe deletes events.log with the rest (offboarding). The line names the time, the kind, the key or
# setting (never a value) and the route that asked for it. The next session start names them to the person in one
# sentence and marks them as shown. Any
# process of the user can change the file too (docs/THREAT-MODEL.md, C22): it makes an ordinary agent's action
# visible, it does not stop one that evades.
ROUTES = ("typed prompt", "slash command", "cli")
_SHOWN = HOME / ".weakenings-shown"
_NAME_RE = re.compile(r"[^A-Za-z0-9_.:@-]")


def record_weakening(kind: str, name: str, route: str) -> None:
    """One events.log line for an action that loosened a protection. Never raises: the action is done already."""
    try:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            old = [_parsed(x) for x in EVENTS.read_text(encoding="utf-8", errors="replace").splitlines()]
        except FileNotFoundError:
            old = []
        last = max((e["t"] for e in old if "weakened" in e and isinstance(e.get("t"), int)), default=0)
        _append(json.dumps({
            # a number that only grows: two lines in one clock tick must not share it, or the mark of the first
            # hides the second
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()), "t": max(time.time_ns(), last + 1),
            "weakened": kind, "name": _NAME_RE.sub("", str(name))[:64],
            "route": route if route in ROUTES else "other", "version": plugin_version(),
        }))
    except (OSError, ValueError):
        pass


def _label(e: dict) -> str:
    kind, name = e.get("weakened"), e.get("name", "?")
    if kind == "setting":
        return f"setting {name}"
    if kind == "forget":
        return f"forget {name}"
    return f"{kind} {name}"


def weakenings_since_last_start() -> str | None:
    """One sentence for the person that lists the protections loosened since the last session start, or None.
    The lines it names are marked as shown; a mark that cannot be written names them again next time."""
    try:
        shown = int(_SHOWN.read_text(encoding="utf-8").strip() or 0)
    except (OSError, ValueError):
        shown = 0
    try:
        lines = EVENTS.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    new = [e for e in map(_parsed, lines) if e.get("weakened") and isinstance(e.get("t"), int) and e["t"] > shown]
    if not new:
        return None
    try:
        atomic = _SHOWN.with_name(_SHOWN.name + ".tmp")
        atomic.write_text(repr(max(e["t"] for e in new)) + "\n", encoding="utf-8")
        os.replace(atomic, _SHOWN)
    except OSError:
        pass
    named = ", ".join(f"{_label(e)} ({e.get('route', 'other')})" for e in new[:5])
    more = f", and {len(new) - 5} more in {EVENTS.name}" if len(new) > 5 else ""
    was = "protection was" if len(new) == 1 else "protections were"
    return (f"maisecrets: since the last session start, {len(new)} {was} loosened: {named}{more}. If you did not "
            "do this, check /maisecrets:settings and /maisecrets:list.")


def issue_url(event: dict, note: str = "") -> str:
    return link(*issue_parts(event, note))


def generic_issue_url(kind: str, text: str) -> str:
    return link(*generic_issue_parts(kind, text))


def tracker() -> str | None:
    """The configured `report_url`: a policy can point it to its own tracker, or set null to turn
    reporting off. The report ignored it and always used ISSUES_URL (found 2026-09-28)."""
    from .home import load_config
    url = load_config().get("report_url", ISSUES_URL)
    return url.strip() or None if isinstance(url, str) else None


def tracker_or_error() -> tuple[str | None, str | None]:
    """The tracker, or the reason it cannot be known: a broken config must not stop a report of
    that same problem, but it must not send one past a policy either."""
    try:
        return tracker(), None
    except Exception as exc:  # noqa: BLE001 - ConfigError and RuntimeError both name the file
        return None, str(exc)


def github_repo(url: str | None) -> str | None:
    """owner/repo when the tracker is a GitHub repository, else None."""
    parts = urllib.parse.urlsplit(url or "")
    path = [x for x in parts.path.split("/") if x]
    if parts.scheme == "https" and parts.hostname == "github.com" and len(path) >= 2 and path[2:3] in ([], ["issues"]):
        return f"{path[0]}/{path[1]}"
    return None


def link(title: str, body: str, label: str) -> str | None:
    """A prefilled new-issue link on a GitHub tracker, the tracker itself on another one, or None
    when reporting is off."""
    url = tracker()
    repo = github_repo(url)
    if repo:
        q = urllib.parse.urlencode({"title": title, "body": body, "labels": label})
        return f"https://github.com/{repo}/issues/new?{q}"
    return url


def issue_parts(event: dict, note: str = "") -> tuple[str, str, str]:
    """Title, body and label of a false-positive issue with the event's facts. The value is not in
    the event, so it cannot be in the issue; the reporter describes the shape in words."""
    hits = ", ".join(f"{h['type']} via `{h['kind']}`" for h in event.get("hits", []))
    first = event.get("hits", [{}])[0]
    title = f"False positive: {first.get('kind', '?')} ({first.get('type', '?')})"
    body = "\n".join([
        "## What maisecrets detected",
        f"- hits: {hits}",
        f"- hook: `{event.get('hook')}` · client: `{event.get('client')}` · at {event.get('ts')}",
        f"- plugin version: {event.get('version')} · {platform.system()} {platform.release()} · "
        f"Python {sys.version_info.major}.{sys.version_info.minor}",
        "",
        "## Why it is wrong",
        note or "(describe the shape of the text, not the value itself: e.g. 'a build id of 20 hex chars "
                "after the word token')",
        "",
        "## What should happen instead",
        "",
        "_This report was prepared by `maisecrets report`. It carries no value; please keep it that way._",
    ])
    return title, body, "false-positive"


def generic_issue_parts(kind: str, text: str) -> tuple[str, str, str]:
    """A bug or a feature request straight from the session: title from the user's words,
    environment facts in the body, no event and no value."""
    label = "enhancement" if kind == "feature" else "bug"
    title = ("Feature: " if kind == "feature" else "Bug: ") + (text.strip()[:70] or "(describe it)")
    body = "\n".join([
        f"## {'What should maisecrets do' if kind == 'feature' else 'What happened'}",
        text.strip() or "(describe it here)",
        "",
        "## Environment",
        f"- plugin version: {plugin_version()} · {platform.system()} {platform.release()} · "
        f"Python {sys.version_info.major}.{sys.version_info.minor}",
        "",
        "_Prepared by `maisecrets report`; it carries no value._",
    ])
    return title, body, label
