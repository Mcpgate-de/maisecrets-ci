"""maisecrets command line: list, get, expire, scan, hook."""
from __future__ import annotations

import json
import re
import os
import sys
import time

from . import detect
from .hooks import main as hook_main
from .vault import ConfigError, Vault, load_config


def _age(ts: float) -> str:
    d = time.time() - ts
    if d < 3600:
        return f"{int(d // 60)}m"
    if d < 86400:
        return f"{int(d // 3600)}h"
    return f"{int(d // 86400)}d"


def cmd_list(_: list[str]) -> int:
    """What is stored, masked: the same view a person gets from /maisecrets:list. No value."""
    rc = _list_values()
    from . import value_files
    if value_files.present():
        from . import values
        try:
            _print_imports(values.rows())
        except values.ValuesError as exc:
            print(f"\nImported values: {exc}")
    return rc


def _list_values() -> int:
    v = Vault()
    rows = v.list()
    if not rows:
        print("Nothing is stored.")
        return 0
    live = [e for e in rows if not e.purged]
    print(f"{len(live)} value(s) stored, {len(rows) - len(live)} expired (only the masked form is kept).")
    print(f"{'placeholder':<14} {'type':<7} {'found by':<9} {'age':>5} {'uses':>4} {'expires in':>10}  shown as")
    from . import destinations
    shown_before = time.time() - destinations.NEW_SECONDS
    protect = v.cfg.get("secret_destinations", "observe") == "protect"
    for e in sorted(rows, key=lambda x: x.created):
        exp = "expired" if e.purged else f"{int(max(0, e.expires - time.time()) // 3600)}h"
        print(f"{e.key:<14} {e.type:<7} {_found_by(e.kind):<9} {_age(e.created):>5} {e.uses:>4} {exp:>10}  "
              f"{e.display or '-'}")
        if not e.purged:
            for line in _destination_lines(destinations.of(e.key), shown_before, protect):
                print(line)
    if v.backend.test_mode:
        print("\nbackend: jsonfile (TEST MODE, plaintext under ~/.maisecrets/)")
    launcher = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks",
                            "run.cmd" if os.name == "nt" else "run.sh")
    print(f"\nTo delete one: /maisecrets:forget <placeholder>. To delete everything, run in a terminal: {launcher} "
          "wipe --yes")
    return 0


def _found_by(kind: str) -> str:
    """How a stored value was found, in the words of the ms:( check (maisecrets/verdict.py): the rule id meant
    nothing to the person."""
    if kind == "manual":
        return "you"
    for prefix, word in (("term:", "term"), ("import:", "import"), ("user:", "your-rule")):
        if kind.startswith(prefix):
            return word
    from .verdict import EXPORT_RULE, how_found
    return "label" if kind == EXPORT_RULE else how_found(kind)


def _destination_lines(rec: dict, shown_before: float, protect: bool = False) -> list[str]:
    """Where a secret was sent (secret_destinations). With observe a record, never a permission: the heading says
    so. With protect these hosts ask no more, and the heading says that. The count is coarse, and a local use is
    listed apart because nothing protects it."""
    from . import destinations
    seen = sorted(rec.get("seen", {}).values(), key=lambda d: -d.get("last", 0))
    network = [d for d in seen if d.get("kind") == "network"]
    local = [d for d in seen if d.get("kind") != "network"]
    width = max([len(d.get("label", "")) for d in seen] + [20])
    out = []

    def row(d: dict) -> str:
        new = "   new" if d.get("first", 0) > shown_before else ""
        return (f"      {destinations.clean_label(d.get('label', '?')):<{width}}  "
                f"{destinations.uses_text(d.get('uses', 0)):<6} "
                f"last {destinations.when_text(d.get('last', 0))}{new}")
    if network:
        out.append("    Sent to (protect asks before a host not listed, or one cut with ...)" if protect
                   else "    Sent to (a record only; it allows nothing)")
        out += [row(d) for d in network]
    if local:
        out.append("    Used on this computer")
        out += [row(d) for d in local]
    return out


_ROUTE = {"v": "cli"}


def cmd_forget(args: list[str]) -> int:
    if not args:
        print("usage: maisecrets forget <KEY> [KEY ...]   (keys as /maisecrets:list shows them)", file=sys.stderr)
        return 2
    v, rc = Vault(), 0
    for raw in args:
        key = raw.strip("⟦⟧").split(":", 1)[0]
        status = v.forget(key, route=_ROUTE["v"])
        if getattr(v, "destinations_kept", False):
            print(f"{key}: its destination record could not be deleted now; /maisecrets:forget {key} again later.")
        if status == "ok":
            print(f"{key}: deleted. A placeholder for it no longer works anywhere.")
        elif status == "unknown":
            print(f"{key}: not found (see /maisecrets:list)")
            rc = 1
        else:
            print(f"{key}: the store refused to delete it; nothing was changed")
            rc = 1
    return rc


def cmd_get(args: list[str]) -> int:
    if not args:
        print("usage: maisecrets get <KEY>", file=sys.stderr)
        return 2
    value, status = Vault().get(args[0], human=True)
    if status != "ok":
        print(f"{args[0]}: {status}", file=sys.stderr)
        return 1
    print(value)
    return 0


def cmd_resolve(args: list[str]) -> int:
    """Read one value under a one-time grant. The Bash hook writes this call into the command
    in place of the placeholder; nothing else has a valid nonce. Prints the value without a
    trailing newline so a command substitution gets it byte for byte."""
    if len(args) != 3 or args[1] != "--grant":
        print("usage: maisecrets resolve <KEY> --grant <NONCE>", file=sys.stderr)
        return 2
    value, status = Vault().redeem(args[0], args[2])
    if status != "ok":
        print(f"maisecrets resolve {args[0]}: {status}", file=sys.stderr)
        return 1
    sys.stdout.write(value)
    sys.stdout.flush()
    return 0


def cmd_audit(args: list[str]) -> int:
    """The last resolves: when, which session, which key, which tool, the command with its
    placeholders. Values are never written here."""
    from .vault import HOME
    try:
        n = int(args[0]) if args else 20
    except ValueError:
        print("usage: audit [n]", file=sys.stderr)
        return 2
    path = HOME / "audit.log"
    if not path.exists():
        print("(no stored value was used yet)")
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()[-n:]
    print("time                 session  placeholder    tool            command")
    for line in lines:
        parts = line.split("\t")
        if len(parts) == 5:
            print(f"{parts[0]:<20} {parts[1]:<8} {parts[2]:<14} {parts[3][:15]:<15} {parts[4]}")
    return 0


def cmd_put(args: list[str]) -> int:
    """Store a value you choose (a password, a key without a known shape) and get a reference.

    The value comes from the clipboard (--clipboard) or from stdin, never from an
    argument: an argument lands in the shell history and in the transcript.
    """
    type_ = "SECRET"
    source = "stdin"
    for a in args:
        if a in ("-c", "--clipboard"):
            source = "clipboard"
        elif a.startswith("--type="):
            type_ = a.split("=", 1)[1].upper()
    if source == "clipboard":
        from .hooks import _clipboard_read
        value = _clipboard_read()
    else:
        value = sys.stdin.read()
    value = value.strip()
    if not value:
        print("maisecrets: the clipboard is empty. Copy the value first, then run /maisecrets:put again."
              if source == "clipboard" else "maisecrets: no value came on stdin; nothing was stored.", file=sys.stderr)
        return 2
    e = Vault().put(value, type_, "manual")
    from .hooks import _clipboard
    copied = _clipboard(e.ref)
    print(f"Stored. Its placeholder {e.ref} is in your clipboard: paste it where the value is needed." if copied
          else f"Stored. Its placeholder is {e.ref}: paste it where the value is needed.")
    return 0


def cmd_report(args: list[str]) -> int:
    """`report` lists the last detections; `report last [note]` or `report <n> [note]` prepares a
    false-positive issue for one of them; `report bug <text>` and `report feature <text>` prepare
    one without an event; `report incident [code/cause | clear]` shows the incident record. It prints the
    text and a prefilled link, and the person opens the link and decides in GitHub's form: it opens no
    browser and runs no program (docs/DIAGNOSTICS.md, D1). Nothing in it is a value."""
    from . import events, incidents
    if any(a.lower() == "--create" for a in args):
        print("--create is gone: maisecrets files nothing itself. Open the link and decide in GitHub's form.")
    args = [a for a in args if a.lower() != "--create"]
    asked = incidents.form(args)
    if asked:
        return _report_incident(*asked)
    if args and args[0] in ("bug", "feature"):
        return _report_out(events, *events.generic_issue_parts(args[0], " ".join(args[1:])))
    evs = events.load(20)
    if not evs:
        print("(no detection recorded yet)")
        return 0
    if not args or args[0] not in ("last", *map(str, range(1, len(evs) + 1))):
        print("n   time                 hook              client  hits")
        for i, e in enumerate(evs, 1):
            hits = ", ".join(f"{h['type']}/{h['kind']}" for h in e.get("hits", []))
            print(f"{i:<3} {e.get('ts', ''):<20} {e.get('hook', ''):<17} {e.get('client', ''):<7} {hits}")
        print("\n/maisecrets:report last <why it is wrong> | /maisecrets:report <n> <why> | /maisecrets:report bug "
              "<text> | /maisecrets:report feature <text> | /maisecrets:report incident")
        return 0
    if args[0] == "last":
        # a removal of invisible characters is no detection to report as a false alarm; the list shows it. The
        # whole log is searched: twenty removals pushed a detection out of the last twenty (codex review)
        # a quarantined rule of your own (RULE) is no detection either
        real = [e for e in events.load(events.KEEP)
                if any(h.get("type") not in ("HIDDEN", "RULE") for h in e.get("hits", []))]
        if not real:
            print("(no detection recorded yet)")
            return 0
        ev = real[-1]
    else:
        ev = evs[int(args[0]) - 1]
        if not any(h.get("type") not in ("HIDDEN", "RULE") for h in ev.get("hits", [])):
            what = ("only left out a rule of your own (/maisecrets:rules says why)"
                    if any(h.get("type") == "RULE" for h in ev.get("hits", []))
                    else "only removed invisible characters")
            print(f"that event {what}; there is no detection to report as a false alarm")
            return 0
    rc = _report_out(events, *events.issue_parts(ev, " ".join(args[1:])))
    _forget_the_false_positive(ev)
    return rc


TEST_DATA_URL = "https://github.com/Mcpgate-de/maisecrets#test-data-that-maisecrets-leaves-alone"


def _forget_the_false_positive(ev: dict) -> None:
    """A false positive stays in the store after the report: its fingerprint redacts the same text in
    every later tool result and, since 0.5.8, blocks every prompt that holds it; a detector fix does
    not clean it up (field report, 2026-09-28). The report names the stored value and the command
    that deletes it, and deletes nothing itself: the events are shared by all sessions, so "last" can
    be another session's real value, and a model can run this command too (Codex review, 2026-09-28)."""
    # most false alarms are test data: the forms that are never a hit, for the next fixture (README)
    print(f"Test data that maisecrets leaves alone: {TEST_DATA_URL}")
    keys = list(dict.fromkeys(h.get("key") for h in ev.get("hits", []) if h.get("key")))
    if keys:
        print("If this is not a secret, delete its stored value so it is not masked or blocked again: "
              + " ".join(f"/maisecrets:forget {k}" for k in keys))


def _report_incident(kind: str, selector: str | None) -> int:
    """The incident report in a terminal. Only to a terminal: through a pipe (a model's Bash call) it prints one
    line, so the report does not end up in the model's context by accident. That is no check of a person: a model
    with a shell can get a pseudo-terminal (docs/DIAGNOSTICS.md, D3)."""
    from . import incidents
    if kind == "usage":
        print(incidents.USAGE)
        return 0
    if not sys.stdout.isatty():
        print("maisecrets: the incident report is shown to a person only: type /maisecrets:report incident in "
              "Claude Code, or run this command in a terminal.")
        return 0
    if kind == "clear":
        n = incidents.clear()
        print("the incident record is busy; try again" if n < 0 else f"cleared: {n} incident file(s)")
        return 0
    print(incidents.report_text(selector))
    return 0


def _report_out(events, title: str, body: str, label: str) -> int:
    url, broken = events.tracker_or_error()
    if url is None and not broken:
        print("reporting is turned off here (report_url is null in the policy or the config)")
        return 0
    # the text itself first: over ssh or Remote Control a link is the same copy problem as before
    print(f"Title: {title}\nLabel: {label}\n\n{body}\n")
    if broken:
        print(f"no link and no issue: the configuration cannot be read ({broken}). Copy the text above.")
        return 0
    url = events.link(title, body, label)
    print(("prefilled link: " if events.github_repo(url) else "tracker: ") + url)
    print("maisecrets sent nothing: open the link, check the text in the form, and decide there.")
    return 0


def cmd_expire(_: list[str]) -> int:
    v = Vault()
    n = v.expire(limit=None)
    print(f"purged {n} expired value(s)")
    if v.last_refused:
        print(f"{v.last_refused} expired value(s) are still in the store: the store refused the delete. "
              "The next sweep tries again.", file=sys.stderr)
        return 1
    return 0


def cmd_scan(args: list[str]) -> int:
    # bytes, decoded with replacement: the CI scan of the repo pipes every file in, a PNG among
    # them, and a strict decode crashed without output, which read as "nothing found" (2026-09-27)
    text = " ".join(args) if args else sys.stdin.buffer.read().decode("utf-8", errors="replace")
    for m in detect.scan(text):
        print(f"{m.type:<7} {m.kind:<18} at {m.start}-{m.end} (len {len(m.value)})")
    return 0


def cmd_rules(args: list[str]) -> int:
    """The rules of your own (maisecrets/rules_cli.py): show, check, test, init, import."""
    from . import rules_cli
    return rules_cli.main(args)


def cmd_values(args: list[str]) -> int:
    """Values from your own tools (maisecrets/values.py): `values import FILE` and `values` (the imports). Prints
    counts, ids and line numbers, never a value and never the file name: the output reaches the model when the agent
    runs it. No command removes an import: only the person's typed prompt does."""
    from . import values
    if not args or args[0] in ("list", "show"):
        _print_imports(values.rows(), always=True)
        return 0
    if args[0] == "import" and len(args) == 2:
        try:
            result = values.import_file(args[1])
        except ValueError as exc:
            print(f"maisecrets: the file is not imported: {exc}. Nothing was changed.")
            return 1
        print("maisecrets: " + values.summary(result))
        if result.added:
            print("From now on these values are masked in every prompt and tool result. Mask only: a placeholder of "
                  "an imported value is never put back into a command or a file.")
        return 0
    if args[0] in ("remove", "forget", "delete"):
        print("maisecrets: no command removes an import; only the person does, as their own prompt: "
              "/maisecrets:forget import:ID (in Codex: maisecrets: forget import:ID).")
        return 1
    print("usage: maisecrets values [import FILE]", file=sys.stderr)
    return 2


def _print_imports(rows: list, always: bool = False) -> None:
    """The imports: id, count, types, age, origin. Never a value."""
    if not rows:
        if always:
            print("No values are imported. A tool of yours writes JSON lines ({\"value\": ..., \"type\": ...}); "
                  "/maisecrets:settings value_files add FILE adds them.")
        return
    from .values import type_text
    print(f"\nImported values (mask only): {sum(r['count'] for r in rows)} in {len(rows)} import(s)")
    for r in rows:
        origin = {"file": "a value file", "run": "a command", "damaged": "DAMAGED"}.get(r["origin"], r["origin"])
        age = _age(r["at"]) if r["at"] else "?"
        print(f"  import:{r['id']} · {r['count']} value(s) ({type_text(r['types']) or '-'}) · {age} · from {origin}")
    print("  To remove one: type /maisecrets:forget import:ID as your own prompt.")


def cmd_terms(args: list[str]) -> int:
    """The term lists (maisecrets/terms_cli.py): counts, and `suggest FILE`."""
    from . import terms_cli
    return terms_cli.main(args)


def cmd_config(_: list[str]) -> int:
    print(json.dumps(load_config(), indent=2))
    return 0


def cmd_settings(args: list[str]) -> int:
    """Show the settings a person decides, with their state. It changes nothing: a setting changes only from a
    prompt the person typed (maisecrets/settings.py), never from a command the model runs."""
    from . import settings
    rest = [a for a in args if a != "--all"]
    # KEY, KEY VALUE, or for the host list KEY add|remove HOST (field report on 0.6.6: the list's own form exited 1)
    folder = rest[0].lower() in ("rule_dirs", "clean_dirs", "value_files") if rest else False   # a path holds spaces
    list_form = (len(rest) >= 3 and (folder or rest[0].lower() == "ssh_autonomous_hosts")
                 and rest[1].lower() in ("add", "remove") and (len(rest) == 3 or folder))
    if rest and (len(rest) <= 2 or list_form) and rest[0].lower() in settings.TITLE:
        # after a typed change the prompt hook already wrote it: show the card with the new state
        print(settings.render(only=rest[0].lower()))
        return 0
    if rest and rest[0].lower() == "hints":
        print("\n".join(settings._hint_lines()))
        return 0
    if rest:
        print(f"maisecrets settings: {rest[0]!r} is no setting this command shows.\n")
    print(settings.render(show_all="--all" in args))
    return 1 if rest else 0


def cmd_status(_: list[str]) -> int:
    """What support needs first: version, where the plugin runs from, which Python, which
    store, which settings come from a policy, and what the logs counted."""
    import platform
    from pathlib import Path as _P
    from .vault import HOME, describe_backend
    root = _P(__file__).resolve().parent.parent
    version = "?"
    try:
        version = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")).get("version", "?")
    except (OSError, ValueError):
        pass
    print(f"maisecrets {version} at {root}")
    cfg_warning = load_config().get("config_warning")
    if cfg_warning:
        print(f"WARNING: {cfg_warning}")
    print(f"python {platform.python_version()} at {sys.executable}; {platform.system()} {platform.release()}")
    v = Vault()
    live = [e for e in v.list() if not e.purged]
    print(describe_backend(v.backend))
    kept = v.cfg.get("keep_purged_days")
    print(f"stored values: {len(live)}, {len(v.list()) - len(live)} expired (metadata kept {kept} days)")
    policy = v.cfg.get("policy_keys") or []
    print("settings from a machine policy: " + (", ".join(policy) if policy else "none"))
    from . import rehydration
    pol = {path: rehydration.policy(v.cfg, path) for path in rehydration.PATHS}
    what = {"automatic": "no ask of maisecrets; the client's permission rules decide",
            "confirm": "every call that gets a value asks first (Claude Code); Codex refuses it",
            "block": "no value goes into a tool call"}
    main = pol["bash"]
    other = [f"{path} {p}" for path, p in pol.items() if p != main]
    print(f"stored values in tool calls: {main} ({what[main]})" + (f"; except {', '.join(other)}" if other else ""))
    from . import detect
    def version(name: str) -> str:
        return (detect.RULES_DIR / f"{name}_VERSION").read_text(encoding="utf-8").strip()
    print(f"rules: {len(detect.rules())} (betterleaks {version('BETTERLEAKS')}, presidio {version('PRESIDIO')}, "
          f"detect-secrets {version('DETECT_SECRETS')})")
    from . import user_rules
    own = user_rules.load()
    print(f"rules of your own: {len(own.rules)} from {sum(f.state == 'ok' for f in own.folders)} folder(s), "
          f"{sum(not q.kept for q in own.quarantined)} left out; /maisecrets:rules shows them")
    from . import terms
    print(terms.summary())
    from . import value_files
    if value_files.present():
        from . import values
        print(values.summary_line())
    active = detect.active_regions()
    print(f"regions: {', '.join(active.regions)} ({active.source}); "
          f"label languages: {', '.join(active.languages)}")
    for name in ("events.log", "audit.log", "hooks.log"):
        p = HOME / name
        try:
            with open(p, "rb") as f:
                n = sum(1 for _ in f)
        except OSError:
            n = 0
        print(f"{name}: {n} lines")
    from . import codex_vault, vault_refs
    for line in vault_refs.status_lines(v.cfg, v.backend):
        print(line)
    if codex_vault.config_path().is_file():
        # the command does not know which client started it: the Codex profile gets its own lines when it exists
        vault_refs.use_client("codex")
        try:
            for line in vault_refs.status_lines(v.cfg, v.backend):
                print(line)
        finally:
            vault_refs.use_client("claude")
    from . import codex_trust
    for line in codex_trust.status_lines(root, codex_vault.codex_home()):
        print(line)
    from . import incidents
    groups, damaged = incidents.load()
    markers = incidents.unfolded_markers()
    print(f"incidents: {len(groups)} group(s)" + (f", {len(markers)} not yet folded" if markers else "")
          + (", the record is damaged" if damaged else "") + "; /maisecrets:report incident shows them")
    return 0


def cmd_wipe(args: list[str]) -> int:
    """Delete every stored value, the metadata and the logs of this vault: offboarding."""
    if "--yes" not in args:
        print("maisecrets wipe deletes every stored value, the index, the audit, event and hook logs and the "
              "pending prompts of this user. Run `wipe --yes` to do it.")
        return 2
    from .hooks import _run_dir
    from .vault import wipe_everything
    try:
        run_dir = _run_dir()
    except (OSError, RuntimeError):
        run_dir = None
    n, problems = wipe_everything(load_config(), run_dir)
    print(f"wiped: {n} stored value(s), index, logs. The config file stays.")
    if problems:
        print("NOT complete: " + "; ".join(problems) + ". A value may still be in the store; check it by hand.")
        return 1
    return 0


SHORTCUT_COMMAND = """---
description: Send the last blocked prompt as maisecrets rewrote it (short for /maisecrets:send).
allowed-tools: Bash(bash ~/.maisecrets/bin/ms.sh*)
---

!`bash ~/.maisecrets/bin/ms.sh`

The text above is the prompt the user sent through maisecrets, with placeholders instead of
values. Begin your reply with one line `Sent: ` followed by that text as it is (clients such as
Remote Control show neither the blocked prompt nor a slash command's expansion), then answer it.
"""


def install_shortcut(name: str = "ms", only_if_absent: bool = False) -> "tuple[str, str] | None":
    """Write the personal `/ms` command (`~/.claude/commands/ms.md`) and the stable wrapper
    `~/.maisecrets/bin/ms.sh`, which finds the newest installed plugin copy at run time (the
    plugin folder moves with every version). With ``only_if_absent`` an existing command file
    of that name is left alone (it may be the user's own). Returns (command file, wrapper) or
    None when nothing was written. Field request, 2026-09-26."""
    from pathlib import Path as _P
    from .vault import HOME
    root = _P(__file__).resolve().parent.parent
    commands = _P(os.environ.get("CLAUDE_CONFIG_DIR", _P.home() / ".claude")) / "commands"
    target = commands / f"{name}.md"
    if only_if_absent and target.exists():
        return None
    bin_dir = HOME / "bin"
    bin_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    wrapper = bin_dir / "ms.sh"
    wrapper.write_text((root / "hooks" / "ms.sh").read_text(encoding="utf-8"), encoding="utf-8")
    wrapper.chmod(0o700)
    commands.mkdir(parents=True, exist_ok=True)
    target.write_text(SHORTCUT_COMMAND, encoding="utf-8")
    return str(target), str(wrapper)


def remove_shortcut(name: str = "ms") -> list[str]:
    """Undo install_shortcut: delete the command file (only when it is ours), the wrapper, and
    leave a marker so the next session start does not install it again."""
    from pathlib import Path as _P
    from .vault import HOME
    removed: list[str] = []
    commands = _P(os.environ.get("CLAUDE_CONFIG_DIR", _P.home() / ".claude")) / "commands"
    target = commands / f"{name}.md"
    try:
        if target.exists() and "maisecrets/bin/ms.sh" in target.read_text(encoding="utf-8"):
            target.unlink()
            removed.append(str(target))
    except OSError:
        pass
    wrapper = HOME / "bin" / "ms.sh"
    if wrapper.exists():
        wrapper.unlink()
        removed.append(str(wrapper))
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    (HOME / ".shortcut").write_text("removed\n", encoding="utf-8")
    return removed


def cmd_shortcut(args: list[str]) -> int:
    if "--remove" in args:
        removed = remove_shortcut(next((a for a in args if a != "--remove" and a.isalnum()), "ms"))
        print("removed: " + (", ".join(removed) if removed else "nothing (no maisecrets shortcut found)"))
        print("The session start will not install it again; type /maisecrets:shortcut to get it back.")
        return 0
    name = (args[0] if args and args[0].isalnum() else "ms")
    target, wrapper = install_shortcut(name)
    from .vault import HOME
    (HOME / ".shortcut").write_text("installed\n", encoding="utf-8")
    print(f"Installed /{name}. Start a new session (or /reload-plugins) to use it. ({target} -> {wrapper})")
    return 0


GUARD_MARK = "maisecrets-guard.py"
# one command for the user settings and the managed settings: Claude Code runs an identical command
# once, and a machine where maisecrets never ran (no script) or has no python3 answers {} (review:
# two different registrations each waited for the heartbeat, and one of them refused)
GUARD_COMMAND = ('G="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/maisecrets-guard.py"; '
                 'if [ -f "$G" ] && command -v python3 >/dev/null 2>&1; then python3 "$G" || printf \'{}\'; '
                 "else printf '{}'; fi")
MANAGED_GUARD_COMMAND = GUARD_COMMAND
# the start wait (5 s), the answer wait of hooks/guard.py ANSWER_WAIT, and a margin
GUARD_TIMEOUTS = {"UserPromptSubmit": 15, "PreToolUse": 15, "PostToolUse": 25}


def _guard_paths() -> tuple:
    """The guard script and the settings file it is registered in, both under ~/.claude
    (CLAUDE_CONFIG_DIR when set): outside the plugin folder, which is what the guard watches."""
    from pathlib import Path as _P
    claude = _P(os.environ.get("CLAUDE_CONFIG_DIR", _P.home() / ".claude"))
    return claude / GUARD_MARK, claude / "settings.json"


# the command an older registration wrote: "<python>" "<dir>/maisecrets-guard.py"
_OLD_GUARD_COMMAND = re.compile(r'"[^"]*[/\\]python[0-9.]*" "[^"]*[/\\]maisecrets-guard\.py"')


def _is_our_hook(h) -> bool:
    """Our hook object and only ours: the exact command we register (or an older one of ours), not any
    command that happens to name the file (Codex review, 2026-09-29: a user's wrapper went with it)."""
    command = str(h.get("command", "")) if isinstance(h, dict) else ""
    return command == GUARD_COMMAND or bool(_OLD_GUARD_COMMAND.fullmatch(command))


def _is_guard(entry) -> bool:
    """An entry that holds our hook and nothing else."""
    hooks = entry.get("hooks") if isinstance(entry, dict) else None
    return bool(hooks) and all(_is_our_hook(h) for h in hooks)


def _without_guard(hooks: dict) -> dict:
    """The hooks block with our hook objects taken out; an entry keeps the user's own hooks beside ours,
    and an entry or event left empty is removed."""
    out = {}
    for event, entries in hooks.items():
        kept = []
        for e in entries if isinstance(entries, list) else []:
            inner = [h for h in (e.get("hooks") or []) if not _is_our_hook(h)] if isinstance(e, dict) else None
            if inner is None:
                kept.append(e)
            elif inner:
                kept.append({**e, "hooks": inner})
        if kept:
            out[event] = kept
    return out


# hook groups only Codex has a tool for: the guard watches Claude Code, which has no apply_patch
CODEX_ONLY_MATCHERS = {"apply_patch"}


def _guard_entries() -> dict:
    """The entries the guard needs now: the plugin's own events and matchers, with GUARD_COMMAND."""
    from pathlib import Path as _P
    plugin_hooks = json.loads((_P(__file__).resolve().parent.parent / "hooks" / "hooks.json")
                              .read_text(encoding="utf-8"))["hooks"]
    hooks: dict = {}
    for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse"):
        for entry in plugin_hooks.get(event, []):
            if entry.get("matcher") in CODEX_ONLY_MATCHERS:
                continue
            new = {"hooks": [{"type": "command", "command": GUARD_COMMAND, "timeout": GUARD_TIMEOUTS[event]}]}
            hooks.setdefault(event, []).append({"matcher": entry["matcher"], **new} if entry.get("matcher") else new)
    return hooks


def managed_guard_settings() -> dict:
    return {"hooks": _guard_entries()}


def _read_settings(settings) -> dict:
    """The settings as an object; a file that is not JSON, or JSON that is no object, is refused."""
    if not settings.exists():
        return {}
    current = json.loads(settings.read_text(encoding="utf-8"))
    if not isinstance(current, dict) or not isinstance(current.get("hooks", {}), dict):
        raise ValueError("not a settings object")
    for entries in (current.get("hooks") or {}).values():
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            raise ValueError("hooks of another shape")        # Claude Code refuses it too: not ours to fix
    return current


def _write_settings(settings, current: dict) -> None:
    """Write through a symlink (a dotfiles setup) and keep the file's mode (review: 0600 became 0644)."""
    import stat as _stat
    from pathlib import Path as _P
    from .vault import atomic_write
    target = _P(os.path.realpath(settings)) if settings.exists() or settings.is_symlink() else settings
    mode = _stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o600
    atomic_write(target, json.dumps(current, indent=2) + "\n", mode=mode)


def place_guard_script() -> bool:
    """Copy hooks/guard.py beside the Claude Code settings when it is missing or differs. Never raises:
    the session start must not fail on it. True when the file was written."""
    import shutil
    from pathlib import Path as _P
    try:
        src = _P(__file__).resolve().parent.parent / "hooks" / "guard.py"
        script, _settings = _guard_paths()
        if script.exists() and script.read_bytes() == src.read_bytes():
            return False
        script.parent.mkdir(parents=True, exist_ok=True)
        tmp = script.with_name(script.name + ".tmp")
        shutil.copyfile(src, tmp)
        os.replace(tmp, script)
        return True
    except OSError:
        return False


def _active_account() -> str:
    """<organizationUuid>_<accountUuid> of the account this Claude Code runs as (the guard compares it)."""
    from .vault_refs import claude_json
    path = claude_json()                        # the file the client uses, as the guard reads it
    try:
        acc = json.loads(path.read_text(encoding="utf-8")).get("oauthAccount") or {}
    except (OSError, ValueError, AttributeError):
        return ""
    org, user = acc.get("organizationUuid"), acc.get("accountUuid")
    return f"{org}_{user}" if org and user else ""


def install_guard(expect: str = "synced", root: str = "", keep_mode: bool = False) -> list[str]:
    """Copy the guard next to the Claude Code settings and register it for the events and matchers
    maisecrets itself uses. The settings file is backed up first and changed only in its hooks."""
    import time as _t
    from .vault import HOME
    script, settings = _guard_paths()
    try:
        current = _read_settings(settings)
    except ValueError as exc:
        raise SystemExit(f"{settings} is not a valid settings file; fix it first, nothing was changed") from exc
    place_guard_script()
    done = [f"placed the guard at {script}"]
    wanted = _guard_entries()
    hooks = _without_guard(current.get("hooks") or {})
    ours = {e: [x for x in v if _is_guard(x)] for e, v in (current.get("hooks") or {}).items()}
    if {e: v for e, v in ours.items() if v} != wanted:
        if settings.exists():
            backup = settings.with_name(f"settings.json.bak-maisecrets-{_t.strftime('%Y%m%d-%H%M%S')}")
            # 0600 from the start: the settings may hold tokens, and a copy under the umask was 0644
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(settings.read_bytes())
            done.append(f"backed up {settings.name} to {backup.name}")
        for event, entries in wanted.items():
            hooks.setdefault(event, []).extend(entries)
        current["hooks"] = hooks
        _write_settings(settings, current)
        done.append(f"registered it in {settings} for UserPromptSubmit, PreToolUse and PostToolUse")
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    # a synced copy names its real folder: the guard then expects maisecrets for that account only. The
    # session start keeps a mode the person chose (`--off`, `--always`; review: it silently undid `--off`)
    if keep_mode:
        try:
            prev = json.loads((HOME / "guard.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prev = {}
        prev = prev if isinstance(prev, dict) else {}
        # a mode the person chose stays; an "off" that the policy set ends when the policy allows the guard
        if prev.get("expect") in ("off", "always") and prev.get("by") != "policy":
            expect = prev["expect"]
    # every account that registered from a synced copy: two claude.ai profiles on one maisecrets home each
    # keep theirs (review, 2026-09-29: the last session start overwrote the other one)
    try:
        before = json.loads((HOME / "guard.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        before = {}
    before = before if isinstance(before, dict) else {}
    accounts = [a for a in before.get("accounts") or [] if isinstance(a, str)]
    roots = {k: v for k, v in (before.get("roots") or {}).items() if isinstance(v, str)} \
        if isinstance(before.get("roots"), dict) else {}
    account = _active_account() if root else ""
    if account and account not in accounts:
        accounts.append(account)
    if account:
        roots[account] = root               # the measured folder of this account's synced copy
    data = {"expect": expect, **({"root": root} if root else {}), **({"accounts": accounts} if accounts else {}),
            **({"roots": roots} if roots else {})}
    (HOME / "guard.json").write_text(json.dumps(data) + "\n", encoding="utf-8")
    (HOME / ".guard-removed").unlink(missing_ok=True)
    done.append(f"maisecrets now writes the heartbeat the guard waits for ({HOME / 'alive'})")
    return done


def guard_registered() -> bool:
    _script, settings = _guard_paths()
    try:
        return GUARD_MARK in settings.read_text(encoding="utf-8")
    except OSError:
        return False


def register_guard_for_a_synced_install() -> "str | None":
    """The session start of a synced install registers the guard itself (maintainer decision,
    2026-09-29: a step nobody takes protects nobody), and brings its matchers up to the plugin's
    after an update. Not after `guard remove`, not when `guard` is false, not when settings.json
    cannot be read as a settings object. Returns the line for the session-start message, or None.
    Never raises: the session start must not fail on it."""
    from .vault import HOME
    try:
        if (HOME / ".guard-removed").exists():
            return None
        _script, settings = _guard_paths()
        first = not guard_registered()
        from pathlib import Path as _P
        done = install_guard("synced", str(_P(__file__).resolve().parent.parent), keep_mode=True)
    except (Exception, SystemExit):  # noqa: BLE001 - a settings file of any shape must not break the start
        return None
    if first and any(d.startswith("registered it") for d in done):
        return (f"maisecrets registered its guard in {settings}: it blocks a session in which a plugin update left "
                "maisecrets not running. /maisecrets:guard remove takes it away.")
    return None


def guard_off_by_policy() -> None:
    """`"guard": false` in the config or the machine policy: a guard registered earlier stops expecting
    maisecrets (Codex review, 2026-09-29: it kept refusing). Never raises."""
    from .vault import HOME
    try:
        path = HOME / "guard.json"
        # also without a guard.json: a guard in the managed settings, or one registered earlier, reads it
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cfg = {}
        cfg = cfg if isinstance(cfg, dict) else {}
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        if cfg.get("expect") != "off":
            path.write_text(json.dumps({**cfg, "expect": "off", "by": "policy"}) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        pass


def remove_guard() -> list[str]:
    from .vault import HOME
    script, settings = _guard_paths()
    done = []
    if settings.exists():
        try:
            current = _read_settings(settings)
        except ValueError as exc:
            raise SystemExit(f"{settings} is not a valid settings file; remove the guard entries by hand") from exc
        hooks = _without_guard(current.get("hooks") or {})
        if hooks != (current.get("hooks") or {}):
            if hooks:
                current["hooks"] = hooks
            else:
                current.pop("hooks", None)
            _write_settings(settings, current)
            done.append(f"removed the guard entries from {settings}")
    for path in (script, HOME / "guard.json"):
        if path.exists():
            path.unlink()
            done.append(f"deleted {path}")
    # a synced install registers the guard at its session start; `guard remove` keeps it away
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    (HOME / ".guard-removed").write_text("removed\n", encoding="utf-8")
    return done


def cmd_guard(args: list[str]) -> int:
    """`guard install [--always]`, `guard remove`, `guard status`, `guard managed`."""
    what = args[0] if args else "status"
    if what == "install":
        if os.name == "nt":
            print("The guard is not built for Windows yet.", file=sys.stderr)
            return 1
        for line in install_guard("always" if "--always" in args else "synced"):
            print(line)
        print("Start a new session (or /reload-plugins) to use it. `guard remove` takes it away again.")
        return 0
    if what == "managed":
        print("For an organisation admin who prefers central settings: add this to the Claude Code managed")
        print("settings. The command is the one a synced maisecrets registers, so Claude Code runs it once.")
        print(json.dumps(managed_guard_settings(), indent=2))
        return 0
    if what == "remove":
        done = remove_guard()
        print("\n".join(done) if done else "nothing to remove (no maisecrets guard found)")
        return 0
    script, settings = _guard_paths()
    from .vault import HOME
    print(f"guard script: {script} ({'present' if script.exists() else 'missing'})")
    print(f"registered in {settings}: {'yes' if guard_registered() else 'no'}")
    print(f"heartbeat: {'on' if (HOME / 'guard.json').exists() else 'off'}")
    try:
        import importlib.util
        from pathlib import Path as _P
        spec = importlib.util.spec_from_file_location("maisecrets_guard", _P(__file__).resolve().parent.parent
                                                      / "hooks" / "guard.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        print(f"maisecrets expected for this account: {'yes' if mod.expected(os.getcwd()) else 'no'}")
    except Exception as exc:  # noqa: BLE001 - status must print what it can
        print(f"maisecrets expected for this account: unknown ({type(exc).__name__})")
    return 0


def cmd_repair(_: list[str]) -> int:
    """Rebuild a damaged index from the store; every stored value is deleted, the counters
    continue past the highest key seen, so no new value overwrites an old one."""
    from .vault import make_backend
    from .vault import HOME, _lock_for
    v = Vault.__new__(Vault)
    v.cfg = load_config()
    v.backend = make_backend(v.cfg)
    try:
        with _lock_for(HOME / ".lock"):
            info = v.repair()
    except RuntimeError as exc:
        print(f"repair refused: {exc}", file=sys.stderr)
        return 1
    last = ", ".join(f"{t}_c{n}" for t, n in sorted(info["counters"].items()))
    print(f"Repaired. {info['deleted']} stored value(s) were deleted; new placeholders continue after the old "
          f"numbers" + (f" (last: {last})." if last else "."))
    return 0


def cmd_consent_report(args: list[str]) -> int:
    from . import consent_report
    return consent_report.run(args)


COMMANDS = {"list": cmd_list, "get": cmd_get, "put": cmd_put, "resolve": cmd_resolve, "audit": cmd_audit,
            "report": cmd_report, "expire": cmd_expire, "scan": cmd_scan, "config": cmd_config,
            "status": cmd_status, "wipe": cmd_wipe, "repair": cmd_repair, "shortcut": cmd_shortcut,
            "forget": cmd_forget, "guard": cmd_guard, "settings": cmd_settings,
            "consent-report": cmd_consent_report, "rules": cmd_rules, "terms": cmd_terms, "values": cmd_values}


def _stdin_words() -> list[str]:
    """The words of the slash-command arguments on stdin. shlex only splits; a text that it
    cannot split (an apostrophe in a report) falls back to plain whitespace words."""
    import shlex
    text = sys.stdin.read() if not sys.stdin.isatty() else ""
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in {"-h", "--help"}:
        print("maisecrets status | list | get <KEY> | put [--clipboard] [--type=EMAIL] | audit [n]\n"
              "           | report [last|n|bug|feature|incident] [text] | expire | scan [text] | config\n"
              "           | settings [--all]"
              " | wipe --yes | repair | shortcut [name] | resolve <KEY> --grant <NONCE> | hook <event>\n"
              "           | consent-report ssh [--last 30d|N] [--json] [--excerpts FILE]\n"
              "           | rules [check [DIR] | test [text] | init DIR | import FILE.toml]\n"
              "           | terms [suggest FILE] | values [import FILE]")
        return 0
    if argv[0] == "hook":
        return hook_main(["hook"] + argv[1:])
    # the route of an action that loosens a protection (events.record_weakening): a slash command passes its
    # arguments on stdin, a command line is the CLI. Any program can do either, so it is a name, not a proof
    _ROUTE["v"] = "slash command" if "--args-stdin" in argv[1:] else "cli"
    if "--args-stdin" in argv[1:]:
        # a slash command passes its arguments in a quoted heredoc: spliced into the bash line,
        # `$(…)` or a pipe in a report text ran as code (feedback on 0.5.2, 2026-09-28)
        argv = [a for a in argv if a != "--args-stdin"] + _stdin_words()
    fn = COMMANDS.get(argv[0])
    if fn is None:
        print(f"unknown command {argv[0]}", file=sys.stderr)
        return 2
    from .vault import windows_user_mismatch
    mismatch = windows_user_mismatch()
    if mismatch:
        # a command that ran as the Codex sandbox user changed the rights of the person's store, and every hook of
        # the person failed after it (2026-10-01..05); so it does not touch the store at all
        real, named = mismatch
        print(f"maisecrets {argv[0]}: this command runs as the Windows account {real!r}, not as {named!r} whose "
              "maisecrets store this is (the Codex app runs commands in its sandbox like this). It does not touch the "
              "store, so the store keeps its rights. Run it again outside the sandbox (Codex asks you to approve "
              "that), or in a terminal of your own.", file=sys.stderr)
        return 1
    # a damaged index or a wrong policy printed a Python traceback to the person who ran
    # /maisecrets:list; the message of these two errors names the file and the fix, never a value
    try:
        return fn(argv[1:])
    except ConfigError as exc:
        print(f"maisecrets {argv[0]}: configuration error: {exc}. Fix the file named there.", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"maisecrets {argv[0]}: {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        # Codex on Windows runs a slash command as a sandbox user that may read the person's profile but not
        # write it (measured 2026-09-30); the traceback told the person nothing. The path is the store folder,
        # never a value.
        print(f"maisecrets {argv[0]}: no write access to {exc.filename or 'the store folder'}. The command runs as "
              "a different user than the one maisecrets protects, as the Codex sandbox on Windows does. Run it "
              "again outside the sandbox (Codex asks you to approve that).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
