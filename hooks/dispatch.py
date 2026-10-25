#!/usr/bin/env python3
"""Single entry point for every hook event; the launcher run.sh picks the interpreter."""
import os
import sys

if len(sys.argv) == 2 and sys.argv[1] == "mod-prompt" and sys.version_info < (3, 9):
    sys.exit(3)   # the mod then tries its next Python (claude-mod/maisecrets-mod.mjs); run.sh checks 3.9 for the hooks

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HOOK_EVENTS = ("user-prompt", "pre-tool", "post-tool", "post-tool-failure", "session-start")


def _marker(code: str) -> None:
    """An incident marker for /maisecrets:report incident (docs/DIAGNOSTICS.md, section 3): one empty folder made with
    one mkdir in a home that exists and is no link, after the answer, waited for at most 0.3 s. Never raises."""
    import threading

    def make() -> None:
        try:
            home = os.environ.get("MAISECRETS_HOME") or os.path.join(os.path.expanduser("~"), ".maisecrets")
            if os.path.isdir(home) and not os.path.islink(home):
                os.mkdir(os.path.join(home, "incident-marker." + code), 0o700)
        except Exception:  # noqa: BLE001
            pass
    try:
        sys.stdout.flush()
        t = threading.Thread(target=make, daemon=True)
        t.start()
        t.join(0.3)
        if t.is_alive():
            os._exit(0)          # a thread alive at the shutdown of the interpreter can crash it (signal 11)
    except Exception:  # noqa: BLE001
        pass


def _refuse_without_the_code(why: str) -> None:
    """The plugin's own code cannot be loaded (a half-synced folder, a missing module): answer as the
    launcher does without Python. A failed import ended the process with exit 1, which the client
    reads as no objection, so every prompt and tool went through (ops review, 2026-09-28). Nothing of
    maisecrets is imported here, and the text carries the exception type only."""
    event = sys.argv[1] if len(sys.argv) == 2 else ""
    msg = (f"maisecrets cannot load its own code ({why}); the plugin folder may be half updated. "
           "Start a new session (in Claude Code: claude --resume to keep this one).")
    if event == "post-tool-failure":
        import json
        print(json.dumps({"systemMessage": msg}))    # a failed output cannot be withheld: only the reason is named
        _marker("launcher.import")
        sys.exit(0)
    if event == "post-tool":
        import json
        text = f"[{msg} The tool ran and finished; its output is withheld, do not run it again.]"
        # one shape per client: Codex's strict schema drops an answer with Claude's updatedToolOutput
        codex = '"turn_id"' in sys.stdin.read()
        print(json.dumps({"decision": "block", "reason": text} if codex else
                         {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": text}}))
        _marker("launcher.import")
        sys.exit(0)
    if event == "session-start":
        import json
        print(json.dumps({"systemMessage": msg + " Until then every prompt and tool call is blocked."}))
        _marker("launcher.import")
        sys.exit(0)
    import json
    text = msg + " Until then every prompt and tool call is blocked."
    # JSON, not exit 2: Codex runs the tool when a hook exits 2 (harness/codex.py); both clients read this
    if event == "pre-tool":
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": text}}))
    else:
        print(json.dumps({"decision": "block", "reason": text}))
    _marker("launcher.import")
    sys.exit(0)


try:
    from maisecrets.hooks import main  # noqa: E402
except Exception as exc:  # noqa: BLE001 - a guard that fails open is no guard
    if len(sys.argv) == 2 and sys.argv[1] in HOOK_EVENTS:
        _refuse_without_the_code(type(exc).__name__)
    if len(sys.argv) == 2 and sys.argv[1] == "mod-prompt":
        sys.exit(1)       # no traceback: the mod passes the prompt on and the hook decides (above: it blocks)
    raise

if len(sys.argv) == 2 and sys.argv[1] == "mod-prompt":
    # the mod's question (claude-mod/maisecrets-mod.mjs). Any failure answers nothing: the mod then passes the prompt on
    # unchanged and the settings hook decides it, so a broken rewrite blocks and never lets a value through
    # unauthenticated like every hook entry (user-prompt takes any transcript_path too): a call by the agent
    # names any session id, so it can store values it already knows under that session and mask them in that
    # session's transcript. It learns nothing it did not give. The PreToolUse backstop names the command
    import json
    try:
        if os.environ.get("MAISECRETS_TEST_FAULT") == "mod-prompt":   # harness: prompt_secret_mod_fails
            raise RuntimeError("fault injected for the harness")
        from maisecrets.hooks import rewrite_prompt  # noqa: E402
        payload = json.load(sys.stdin)
        payload = payload if isinstance(payload, dict) else {}
        # the mod starts this in the plugin folder (a fixed command line); an @mention is relative to the session
        if isinstance(payload.get("cwd"), str) and os.path.isdir(payload["cwd"]):
            os.chdir(payload["cwd"])
        answer = rewrite_prompt(payload)
    except Exception:  # noqa: BLE001 - no traceback: what passes back goes through other mods
        sys.exit(1)
    # ASCII JSON: ⟦ as \u27e6. A Windows console code page cannot write ⟦, and the answer was a traceback
    # (GitHub windows-latest, 2026-10-06); JSON.parse in the mod reads the escape as the same text
    print(json.dumps({"maisecrets": "mod-prompt", **answer}))
    sys.exit(0)

if len(sys.argv) >= 2 and sys.argv[1] == "pending":
    from maisecrets.hooks import take_pending  # noqa: E402
    # Claude Code gives a command the id of its session, the same id its hooks get (measured with the
    # harness, 2026-09-28): with two blocked prompts waiting, /ms found neither and pointed to the
    # clipboard, which does not exist over SSH or in Remote Control (field report on 0.5.8)
    text = take_pending(os.environ.get("CLAUDE_CODE_SESSION_ID") or None)
    print(text if text is not None else "(maisecrets: no blocked prompt is waiting. A blocked prompt waits 15 "
          "minutes.)")
    sys.exit(0)

if len(sys.argv) >= 2 and sys.argv[1] in ("report", "put", "status", "list", "audit", "expire", "config",
                                          "wipe", "repair", "scan", "get", "shortcut", "forget", "guard",
                                          "settings", "consent-report", "rules", "terms", "values"):
    from maisecrets.cli import main as cli_main  # noqa: E402
    sys.exit(cli_main(sys.argv[1:]))

if len(sys.argv) == 2 and sys.argv[1] == "session-start":
    import json
    from maisecrets.vault import HOME, Vault  # noqa: E402
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = {}
    payload = payload if isinstance(payload, dict) else {}

    def _is_codex() -> bool:
        """SessionStart has no prompt_id or turn_id, and Claude Code may send `model`, so the
        payload rule of client_of does not decide here. The transcript path decides first (a
        Codex rollout lives under CODEX_HOME, default ~/.codex, also when Codex was started
        from a Claude Code shell that exports CLAUDECODE); then Claude Code's CLAUDECODE=1;
        then any CODEX_ variable (review, 2026-09-27)."""
        path = str(payload.get("transcript_path") or "")
        home = os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")
        if path:
            # Codex resolves CODEX_HOME (a canonical path), so compare resolved paths: /var against /private/var on
            # macOS took a Codex start for Claude Code, and the folder of the session was never recorded
            return any(a.startswith(b + os.sep) for a in (os.path.abspath(path), os.path.realpath(path))
                       for b in (os.path.abspath(home), os.path.realpath(home)))
        if os.environ.get("CLAUDECODE") == "1":
            return False
        return any(k.startswith("CODEX_") for k in os.environ)
    codex = _is_codex()
    from maisecrets.vault import intro_line  # noqa: E402
    import time
    from maisecrets.hooks import primer  # noqa: E402
    from maisecrets.vault import ConfigError, load_config  # noqa: E402
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        cfg = load_config()
    except ConfigError as exc:
        print(json.dumps({"systemMessage": f"maisecrets: configuration error: {exc}. Every prompt is blocked "
                                           "until the file is fixed."}))
        _marker("hook.session-start")
        sys.exit(0)
    try:
        v = Vault(cfg)
        v.expire(limit=None)
        quieted = v.quiet_code_words()
        v.mark_weak_entries()
        v.weaken_quiet_words()
    except RuntimeError as exc:
        # a damaged index: the message names `maisecrets repair`; a traceback here gave the
        # client no JSON and the person no hint
        print(json.dumps({"systemMessage": f"maisecrets: {exc}."}))
        _marker("hook.session-start")
        sys.exit(0)
    _clean_note = None
    try:
        from maisecrets import file_reads  # noqa: E402
        file_reads.note_session_start(payload, cfg)    # the anchor of a clean folder: only here, never later (C28)
        _links = file_reads.link_roots(cfg)
        if _links:
            # a count only: this text can reach the model, and a folder name can say who or what it is about. The
            # person's own settings card names the folders (codex verification of block 4)
            _clean_note = (f"maisecrets: {len(_links)} clean folder(s) are a link or lie under one, so nothing in "
                           "them counts as clean. /maisecrets:settings clean_dirs shows which, and the real folder "
                           "to add.")
        file_reads.prune_sessions()
    except Exception:  # noqa: BLE001 - the note never stops a session start; without it no folder is clean
        pass
    # a blocked prompt older than 15 minutes is never sent; the file goes too (retention)
    pending = HOME / "pending"
    if pending.is_dir():
        for f in pending.glob("*.txt"):
            try:
                if time.time() - f.stat().st_mtime > 15 * 60:
                    f.unlink()
            except OSError:
                pass
    out = {}
    version = "?"
    try:
        manifest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                ".claude-plugin", "plugin.json")
        with open(manifest, encoding="utf-8") as f:
            version = json.load(f).get("version", "?")
    except (OSError, ValueError):
        pass
    # the start line names the active rules of your own, and a folder of rule_dirs that does not load
    try:
        from maisecrets.user_rules import active_phrase, broken_folders_note  # noqa: E402
        own_rules, broken = active_phrase(), broken_folders_note()
    except Exception:  # noqa: BLE001 - rules of your own never stop a session start
        own_rules, broken = "", None
    marker = HOME / ".announced"
    tried = False
    if v.backend.test_mode or not marker.exists():
        tried = True        # the try-it line names ms:(…): the Codex tip below would say it twice
        from maisecrets.tips import try_it_line  # noqa: E402
        more = "" if codex else " /maisecrets:status shows the details, /maisecrets:list what is stored."
        out["systemMessage"] = (f"maisecrets {version} is on{own_rules}. " + intro_line(v.backend) + more + " "
                                + try_it_line())
        try:
            marker.write_text(type(v.backend).__name__ + "\n")
        except OSError:
            pass
    else:
        from maisecrets.tips import tip_of_the_day  # noqa: E402
        tip = tip_of_the_day(codex=codex)
        # one short line every session, so a lost hook registration is visible by its absence
        # (operator review, 2026-09-26); the tip rotates, the version does not
        out["systemMessage"] = f"maisecrets {version} is on{own_rules}." + (f" {tip}" if tip else "")
    if quieted:
        out["systemMessage"] = (out.get("systemMessage", "") +
                                f" {len(quieted)} stored word(s) are program code, not secrets "
                                f"({', '.join(quieted)}): maisecrets no longer masks them in other texts. "
                                "/maisecrets:forget deletes them.")
    if cfg.get("config_warning"):
        out["systemMessage"] = (out.get("systemMessage", "") + f" Warning: {cfg['config_warning']}."
                                + (" Until it is fixed, no stored value goes into a tool call."
                                   if cfg.get("rehydration_fallback") else ""))
    # each protection loosened since the last start (a setting, a forget), once, to the person (C22)
    try:
        from maisecrets.events import weakenings_since_last_start  # noqa: E402
        loosened = weakenings_since_last_start()
    except Exception:  # noqa: BLE001 - the session start must not fail on it
        loosened = None
    if loosened:
        out["systemMessage"] = (out.get("systemMessage", "") + " " + loosened).strip()
    if broken:
        out["systemMessage"] = out.get("systemMessage", "") + " " + broken
    if _clean_note:
        out["systemMessage"] = out.get("systemMessage", "") + " " + _clean_note
    # a rule of your own that fails a check is left out; the person hears it once, when the set changes
    try:
        from maisecrets.user_rules import session_note  # noqa: E402
        note = session_note()
    except Exception:  # noqa: BLE001 - rules of your own never stop a session start
        note = None
    if note:
        out["systemMessage"] = out.get("systemMessage", "") + " " + note
    # the terms (maisecrets/terms.py): a changed team list, or a terms.txt that stops the hooks
    try:
        from maisecrets import term_files  # noqa: E402
        note = None
        if term_files.start_note_due(cfg):    # without a list the terms module is not loaded at all
            from maisecrets.terms import session_note as terms_note  # noqa: E402
            note = terms_note()
    except Exception:  # noqa: BLE001 - terms never stop a session start; a bad terms.txt stops the next hook
        note = None
    if note:
        out["systemMessage"] = out.get("systemMessage", "") + " " + note
    # the imported values (maisecrets/values.py): the value files that changed are imported, and a new import is named
    try:
        from maisecrets import value_files  # noqa: E402
        note = None
        if value_files.start_note_due(cfg):   # without an import or a value file the values module is not loaded
            from maisecrets.values import session_note as values_note  # noqa: E402
            note = values_note(cfg)
    except Exception:  # noqa: BLE001 - an import never stops a session start; a damaged one stops the next hook
        note = None
    if note:
        out["systemMessage"] = out.get("systemMessage", "") + " " + note
    # ms:(…) in Codex: named once here, not in a block notice, where the person must only read paste and send
    # (Claude Code names it under the first blocked or rewritten prompt with a value, hooks._check_tip)
    if codex:
        try:
            from maisecrets import settings as _settings  # noqa: E402
            from maisecrets.check_value import TIP_CODEX  # noqa: E402
            if _settings.hint_due("check_value", cfg) and _settings.claim_hint("check_value") and not tried:
                out["systemMessage"] = out.get("systemMessage", "") + " " + TIP_CODEX
        except Exception:  # noqa: BLE001 - a tip never stops a session start
            pass
    # /ms is offered once, not installed: writing ~/.claude/commands without a question was a
    # change behind the user's back, and Codex cannot use it (UX review, 2026-09-27)
    if not codex and cfg.get("shortcut", True) and not (HOME / ".shortcut").exists():
        out["systemMessage"] = (out.get("systemMessage", "") +
                                " Tip: /maisecrets:shortcut adds /ms as a short form of /maisecrets:send.")
        try:
            (HOME / ".shortcut").write_text("offered\n", encoding="utf-8")
        except OSError:
            pass
    # a synced install: keep the guard script outside the plugin folder current and register it once
    # (the guard of README "Updates and open sessions"); "guard": false or `guard remove` keep it off,
    # an entry deleted from settings.json by hand comes back
    if not codex and os.name != "nt" and not (HOME / ".guard-removed").exists():
        from maisecrets.hooks import _from_a_synced_folder  # noqa: E402
        if _from_a_synced_folder():
            from maisecrets.cli import (guard_off_by_policy, place_guard_script,  # noqa: E402
                                        register_guard_for_a_synced_install)
            place_guard_script()
            if cfg.get("guard", True):
                note = register_guard_for_a_synced_install()
                if note:
                    out["systemMessage"] = out.get("systemMessage", "") + " " + note
            else:
                guard_off_by_policy()
    # vault references: the key header on the user-scope MCP servers of this profile (maisecrets/vault_refs.py); in
    # Codex the helper line of codex_vault.py
    try:
        from maisecrets import vault_refs  # noqa: E402
        vault_refs.use_client("codex" if codex else "claude")
        vault_refs.prune_released(v.backend)   # the values a server gave leave the store after their hour
        if codex:
            from maisecrets import codex_vault  # noqa: E402
            if codex_vault.available():
                codex_vault.note_session(payload)  # the folder whose project layers Codex uses for this session
                if codex_vault.STATE.exists():
                    codex_vault.place_helper()     # an update of the plugin brings a new helper
        note = vault_refs.ensure_headers(cfg, v.backend)
    except Exception:  # noqa: BLE001 - never stops a session start; without the header no value comes back
        note = None
    if note:
        out["systemMessage"] = out.get("systemMessage", "") + " " + note
    # the state of each server with a header: one status probe per origin (no value, no token), all inside one
    # budget, and a line once when the state changed since the person last heard it
    try:
        from maisecrets import vault_refs  # noqa: E402
        note = vault_refs.session_check(cfg, v.backend)
    except Exception:  # noqa: BLE001 - a state check never stops a session start
        note = None
    if note:
        out["systemMessage"] = out.get("systemMessage", "") + " " + note
    # the model reads what a placeholder is once per session, before it meets one
    out["hookSpecificOutput"] = {"hookEventName": "SessionStart",
                                 "additionalContext": primer(cfg, "codex" if codex else "claude")}
    print(json.dumps(out))
    sys.exit(0)
sys.exit(main(["hook", sys.argv[1] if len(sys.argv) == 2 else ""]))
