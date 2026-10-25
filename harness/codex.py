"""Codex harness: the same scenarios as run.py, driven through `codex exec`.

Isolation: a temporary CODEX_HOME with its own hooks.json (absolute paths into
this repo), a config.toml that disables approvals, and a dummy API-key login
so that ``openai_base_url`` points Codex at harness/fake_openai.py. No real
model call, no credits. With --real, the user's auth.json is copied instead
and a cheap real model answers.

Assertions: the marker secret never appears in any request body, in the
rollout transcript under CODEX_HOME/sessions, or in the final message; the
placeholders do.

With --tree=codex the plugin comes from the tree of the GitHub branch `release-codex` as
scripts/build_release_tree.py builds it from HEAD: a Git marketplace in `.agents/plugins/marketplace.json`
that names the branch and its `plugin/` folder, as a Codex user installs it. Without `.codex-plugin/` in that
folder Codex loads none of the hooks, and every scenario fails.

Usage: python3 harness/codex.py [--real] [--tree=codex] [scenario ...]
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

from run import MAIL   # the harness address: masked by maisecrets, not a reserved domain

ROOT = Path(__file__).resolve().parent.parent
MARK = "glpat-" + "CodexHarnessXyz123456789"
UNSEEN = "Cx7-" + "hRn4wQp8Zv"     # no detector shape: a check stores it
MODEL = os.environ.get("MAISECRETS_CODEX_MODEL", "gpt-5.6-sol")
PORT = 8792
REAL = "--real" in sys.argv
TREE = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--tree=")), None)
_MARKETPLACE: list = []
REF_MAIL = "\u27e6EMAIL_c1\u27e7"
MAKE_DOC = "import sys\nopen('account.html', 'w').write('<p>' + sys.argv[1] + '</p>')\n"
DOCUMENTS = {".pdf", ".docx", ".odt", ".rtf", ".html", ".htm"}


def value_in_file(path: Path, value: str) -> bool:
    """The value in a file a model produced: plain text, a zip container (.docx, .odt) or a PDF stream."""
    data = path.read_bytes()
    want = value.encode()
    if want in data or value.encode("utf-16-le") in data or value.encode("utf-16-be") in data:
        return True
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            return any(want in z.read(n) for n in z.namelist())
    if data.startswith(b"%PDF"):
        for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
            try:
                if want in zlib.decompress(m.group(1)):
                    return True
            except zlib.error:
                pass
        if shutil.which("pdftotext"):
            return want in subprocess.run(["pdftotext", str(path), "-"], capture_output=True).stdout
    return False


def _patch_js(line: str, fname: str) -> str:
    """Code mode: one tools.apply_patch call that adds fname with one line."""
    patch = f"*** Begin Patch\n*** Add File: {fname}\n+{line}\n*** End Patch\n"
    return (f"const r = await tools.apply_patch({json.dumps(patch)}); "
            "text(typeof r === 'string' ? r : JSON.stringify(r));")


def _js(cmd: str) -> str:
    return (f"const r = await tools.exec_command({{cmd: {json.dumps(cmd)}}}); "
            "text(typeof r === 'string' ? r : JSON.stringify(r));")

SCENARIOS = {
    "prompt_secret": {
        "prompt": f"Please check the token {MARK} in CI",
        "expect_blocked": True,
    },
    # ms:(…): Codex blocks it in UserPromptSubmit and shows the verdict; the value reaches neither the model nor the
    # rollout (C29). Without a closing bracket too
    "check_value_caught": {
        "prompt": f"ms:({MARK})",
        "expect_blocked": True,
        # codex exec prints no block reason (0.162.0: "UserPromptSubmit Blocked" only), so the verdict is read from
        # the detection record in the maisecrets home: the rule, no value
        "expect_home_text": [("events.log", '"kind": "gitlab-pat"}], "outcome": "ms:( check"')],
    },
    "check_value_not_caught": {
        "prompt": f"ms:( {UNSEEN}",
        "expect_blocked": True,
        # not caught, so stored as /maisecrets:put stores it (Codex sends no `source`: the person typed it)
        "expect_home_text": [("index.json", '"kind": "manual"')],
        "expect_absent": [UNSEEN],
    },
    "bash_echo": {
        # a real model refuses "print .env verbatim" on its own (2026-09-26); asking for the
        # variable names makes it run the command, and the redacted output is what it reads
        "prompt": "Run the shell command `cat .env` and tell me which variable names it defines.",
        "files": {".env": f"TOKEN={MARK}\n"},
        "turns": [{"exec": _js("cat .env")}, {"text": "done"}],
        "expect_placeholder": "⟦SECRET_c",
    },
    "bash_rehydrate": {
        "prompt": ("Run exactly this shell command, do not change it: "
                   "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"),
        "preload": True,
        "turns": [{"exec": _js("printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt")}, {"text": "done"}],
        "expect_placeholder": "⟦SECRET_c1⟧",
        "expect_file": ("used.txt", f"got:{MARK}"),
    },
    # rehydration "automatic" on an MCP text field (`message`): Codex gets "allow" with the value in the
    # argument, the server echoes it, and the echo comes back to the model redacted. Needs a real model:
    # the fake upstream has no MCP tool call (--real only)
    "mcp_text_field_rehydrate": {
        "prompt": "Call the echo tool of the everything MCP server once with the message ⟦SECRET_c1⟧ and "
                  "tell me what it answered.",
        "preload": True,
        "real_only": True,
        "mcp": {"everything": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-everything@2025.9.25"]}},
        "expect_placeholder": "⟦SECRET_c1⟧",
        "expect_text": "Echo: \u27e6SECRET_c1\u27e7",
        # the echo alone would also read so if the placeholder had stayed text: the proof is hooks.log,
        # a pre-tool "rewrite" and a post-tool "block" (it found the real value in the answer and replaced it)
        "value_goes_to": "mcp__everything__echo",
    },
    # the hook's "allow" carries the rewritten command, not more: Codex's own sandbox still holds. In a
    # read-only sandbox the write is refused although the hook rewrote the command (codex-cli 0.158.0,
    # 2026-09-29). Whether "allow" skips an escalation approval cannot be seen here: codex exec offers none.
    "allow_keeps_the_codex_sandbox": {
        "prompt": ("Run exactly this shell command once, do not change it: "
                   "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"),
        "preload": True,
        "real_only": True,
        "sandbox": "read-only",
        "approval": "on-request",
        "expect_file": ("used.txt", "<missing>"),
        "expect_hook": ("pre-tool", "Bash", "rewrite"),
        # the command ran and the sandbox refused the write; a call Codex rejected before it ran, or a
        # model that stopped, would leave the file missing too (review round 2)
        "expect_ran_and_refused": ("used.txt: Operation not permitted", "used.txt: Read-only file system",
                                   "used.txt: Permission denied"),
    },
    # Codex edits files with apply_patch (the matcher aliases Write and Edit; the payload says apply_patch,
    # measured on 0.158.0). A placeholder in the patch content becomes the value in the file
    "apply_patch_rehydrate": {
        "prompt": "Use the apply_patch tool (not a shell command) to create the file notes.txt with the single "
                  "line: key=⟦SECRET_c1⟧",
        "preload": True,
        "real_only": True,
        "expect_placeholder": "⟦SECRET_c1⟧",
        "expect_file": ("notes.txt", f"key={MARK}\n"),
        "expect_hook": ("pre-tool", "apply_patch", "rewrite"),
    },
    # apply_patch nested in code mode (functions.exec -> tools.apply_patch) reaches the hook by its own name: Codex
    # 0.163.0-alpha on Windows did not map it to the aliases Write and Edit, and a placeholder went into the file
    # unchecked (field report, 2026-10-19). A known placeholder gets its value; an unknown one is refused. The known
    # one stands in the prompt, so the session saw it (else the hook answers foreign-session)
    "exec_apply_patch_known": {
        "prompt": "Write the file notes.txt with ⟦SECRET_c1⟧",
        "preload": True,
        "turns": [{"exec": _patch_js("⟦SECRET_c1⟧", "notes.txt")}, {"text": "done"}],
        "expect_file": ("notes.txt", f"{MARK}\n"),
        "expect_hook": ("pre-tool", "apply_patch", "rewrite"),
    },
    "exec_apply_patch_unknown": {
        "prompt": "write the file",
        "preload": True,
        "turns": [{"exec": _patch_js("⟦SECRET_c999⟧", "bad.txt")}, {"text": "done"}],
        "expect_file": ("bad.txt", "<missing>"),
        "expect_hook": ("pre-tool", "apply_patch", "deny"),
    },
    # a patch against the maisecrets home is refused before Codex applies it (invariant I3, C14)
    "apply_patch_store_refused": {
        "prompt": "Use the apply_patch tool (not a shell command) to create the file {home}/notes.txt with the "
                  "single line: hello",
        "real_only": True,
        "expect_home_file_missing": "notes.txt",
        "expect_hook": ("pre-tool", "apply_patch", "deny"),
    },
    # a value for a document (field report, 2026-10-16: the model asked the user to type the address into the PDF by
    # hand). Inline code is refused and the refusal names the route; the route puts the value into the file on disk,
    # and no request, rollout or final message holds it
    "document_gets_the_value": {
        "prompt": "Create a page with our trade-fair account, e-mail address " + REF_MAIL + ".",
        "preload_mail": True,
        "files": {"make_doc.py": MAKE_DOC},
        "turns": [{"exec": _js("python3 -c \"open('account.html', 'w').write('<p>" + REF_MAIL + "</p>')\"")},
                  {"exec": _js("python3 make_doc.py '" + REF_MAIL + "'")}, {"text": "done"}],
        "expect_text": "run it with the placeholder as its argument: python3 make_doc.py " + REF_MAIL,
        "expect_file": ("account.html", f"<p>{MAIL}</p>"),
    },
    # the same request to a real model, in its own words: the address must reach a document it makes (a PDF, a
    # .docx or a page). A PDF whose font maps text to glyph ids can show red although the address is in it: look at
    # the file before you call it a regression (--real only)
    "document_gets_the_value_real": {
        "prompt": "Create a PDF file (or, if no PDF library is installed, a .docx or .html file) with our trade-fair "
                  "account: company Example Fairs Ltd, user name fair-team, e-mail address " + REF_MAIL + ".",
        "preload_mail": True,
        "real_only": True,
        "expect_value_in_a_file": True,
    },
    # rehydration "confirm": Codex cannot ask with a rewritten input, so the hook refuses the command
    # and it does not run; the model reads the reason, which names the key, not the value
    "bash_rehydrate_confirm": {
        "prompt": ("Run exactly this shell command, do not change it: "
                   "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"),
        "preload": True,
        "config": {"rehydration": "confirm"},
        "turns": [{"exec": _js("printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt")}, {"text": "done"}],
        "expect_file": ("used.txt", "<missing>"),
        "expect_text": "Codex cannot ask",
    },
    # vault references in Codex, three sessions against harness/vault_server.py (run_vault_refs)
    "vault_refs": {
        "custom": True,
    },
}


def marketplace() -> str:
    """What `codex plugin marketplace add` gets: this checkout, or with --tree=codex a marketplace folder whose
    `.agents/plugins/marketplace.json` names the built `release-codex` commit in a local Git repository."""
    if TREE is None:
        return str(ROOT)
    if TREE != "codex":
        raise SystemExit(f"--tree={TREE}: only codex")
    if not _MARKETPLACE:
        work = Path(tempfile.mkdtemp(prefix="maisecrets-codex-tree-"))
        sys.path.insert(0, str(ROOT / "scripts"))
        import build_release_tree
        # the tree is built inside a bare repository that holds HEAD alone: a push from this checkout would run its
        # pre-push hook, and the bare repository is what Codex clones
        # the tree is built in a bare repository that holds HEAD alone (a push from this checkout would run its
        # pre-push hook). That repository is shallow, and git 2.39 (the CI image) serving a filtered clone from a
        # shallow repository grows pack-objects until the kernel kills it (CI job 17447748452, exit 137): Codex
        # clones from a second, complete repository that holds the parentless release-codex commit alone
        build = work / "build.git"
        subprocess.run(["git", "init", "-q", "--bare", str(build)], check=True)
        subprocess.run(["git", "-C", str(build), "fetch", "-q", "--depth", "1", ROOT.as_uri(), "HEAD:refs/heads/src"],
                       check=True)
        cwd = os.getcwd()
        os.chdir(build)
        try:
            commit = build_release_tree.commit("src", None, "harness: release-codex of HEAD", "codex")
            subprocess.run(["git", "update-ref", "refs/heads/release-codex", commit], check=True)
        finally:
            os.chdir(cwd)
        repo = work / "repo.git"
        subprocess.run(["git", "init", "-q", "--bare", str(repo)], check=True)
        # Codex clones a Git source with a `path` as `--filter=blob:none --sparse`; a local repository serves that
        # only with the filter allowed (GitHub does), and without it the clone hangs (codex-cli 0.164.0)
        subprocess.run(["git", "-C", str(repo), "config", "uploadpack.allowFilter", "true"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "uploadpack.allowAnySHA1InWant", "true"], check=True)
        subprocess.run(["git", "-C", str(repo), "fetch", "-q", str(build),
                        "refs/heads/release-codex:refs/heads/release-codex"], check=True)
        if subprocess.run(["git", "-C", str(repo), "rev-parse", "--is-shallow-repository"], capture_output=True,
                          text=True, check=True).stdout.strip() != "false":
            raise SystemExit("the repository Codex clones from is shallow")
        mkt = work / "marketplace" / ".agents" / "plugins"
        mkt.mkdir(parents=True)
        (mkt / "marketplace.json").write_text(json.dumps({
            "name": "maisecrets", "interface": {"displayName": "maisecrets"},
            "plugins": [{"name": "maisecrets", "category": "Security",
                         "source": {"source": "url", "url": (work / "repo.git").as_uri(), "ref": "release-codex",
                                    "path": "plugin"}}]}, indent=2))
        print(f"     the plugin comes from release-codex {commit[:12]} (plugin/), not from this checkout")
        _MARKETPLACE.append(str(work / "marketplace"))
    return _MARKETPLACE[0]


def run_scenario(name: str, sc: dict) -> list[str]:
    fails: list[str] = []
    if sc.get("real_only") and not REAL:
        print(f"[SKIP] {name}  needs --real")
        return []
    work = Path(tempfile.mkdtemp(prefix=f"maisecrets-codex-{name}-"))
    cwd = work / "proj"
    cwd.mkdir()
    home = work / "vaulthome"
    home.mkdir()
    (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                  **sc.get("config", {})}))
    codex_home = work / "codex_home"
    codex_home.mkdir()
    out = work / "out"
    out.mkdir()
    env = dict(os.environ, CODEX_HOME=str(codex_home), MAISECRETS_HOME=str(home))
    # CI containers have no bubblewrap/landlock for Codex's Linux sandbox; the container is disposable,
    # so the job sets MAISECRETS_CODEX_SANDBOX to danger-full-access there
    sandbox = sc.get("sandbox") or os.environ.get("MAISECRETS_CODEX_SANDBOX", "workspace-write")
    cfg = (f'model = "{MODEL}"\nmodel_reasoning_effort = "low"\napproval_policy = "{sc.get("approval", "never")}"\n'
           f'sandbox_mode = "{sandbox}"\n')
    if REAL:
        shutil.copy(Path.home() / ".codex" / "auth.json", codex_home / "auth.json")
    else:
        # a custom provider: no WebSocket attempts, no login needed, a dummy key from the environment
        cfg += ('model_provider = "fake"\n[model_providers.fake]\nname = "maisecrets fake"\n'
                f'base_url = "http://127.0.0.1:{PORT}/v1"\nwire_api = "responses"\nenv_key = "FAKE_OPENAI_KEY"\n'
                'supports_websockets = false\n')
        env["FAKE_OPENAI_KEY"] = "sk-dummy-maisecrets-harness-key-0000000000"
    for server, spec in sc.get("mcp", {}).items():
        # the user's own approval for the tool: a hook's "allow" does not skip Codex's MCP approval
        # (codex-cli 0.158.0, measured 2026-09-28: "MCP tool call requires approval")
        cfg += (f'[mcp_servers.{server}]\ncommand = {json.dumps(spec["command"])}\nargs = {json.dumps(spec["args"])}\n'
                'default_tools_approval_mode = "approve"\n')
    (codex_home / "config.toml").write_text(cfg)
    if sc.get("dump"):
        # record every tool payload the real client sends (values masked by the shared detector): the
        # contract corpus under tests/client_payloads comes from these files, not from a guess
        dump_cmd = f"{sys.executable} \"{ROOT / 'harness' / 'dump_hook.py'}\""
        (codex_home / "hooks.json").write_text(json.dumps({"hooks": {
            ev: [{"matcher": ".*", "hooks": [{"type": "command", "command": dump_cmd}]}] if ev.endswith("ToolUse")
            else [{"hooks": [{"type": "command", "command": dump_cmd}]}]
            for ev in ("PreToolUse", "PostToolUse")}}))
        env["MAISECRETS_DUMP"] = str(out)
    # The plugin is installed the way a user gets it, from this checkout as a local marketplace,
    # so Codex's own plugin and hook discovery is under test. Writing hooks.json into CODEX_HOME
    # (the first version of this harness) hid a discovery failure: with a root plugin.json in the
    # package Codex found 0 of the 4 hooks (measured by a peer session on 0.157.1, 2026-09-26).
    for cmd in (["codex", "plugin", "marketplace", "add", marketplace()],
                ["codex", "plugin", "add", "maisecrets@maisecrets"]):
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            print(f"[FAIL] {name}  plugin install: {' '.join(cmd[2:])}: {(r.stderr or r.stdout).strip()[:300]}")
            return ["plugin install failed"]
    for fname, content in sc.get("files", {}).items():
        (cwd / fname).write_text(content)
    if sc.get("preload"):
        # in a subprocess: a Vault held in this process would hold the vault lock while codex
        # runs the hooks, and a Codex hook that times out is fail-open (measured 2026-09-26)
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets.vault import Vault; "
                "Vault().put(sys.stdin.read(), 'SECRET', 'gitlab-pat')")
        subprocess.run([sys.executable, "-c", code, str(ROOT)], input=MARK, text=True, check=True, env=env)
    if sc.get("preload_mail"):
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets.vault import Vault; "
                "Vault().put(sys.stdin.read(), 'EMAIL', 'email')")
        subprocess.run([sys.executable, "-c", code, str(ROOT)], input=MAIL, text=True, check=True, env=env)
    last = work / "last.txt"
    srv = None
    if not REAL:
        (out / "scenario.json").write_text(json.dumps({"turns": sc.get("turns", [{"text": "unreachable"}])}))
        srv = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_openai.py"),
                                str(out / "scenario.json"), str(out), str(PORT)])
        import time
        import urllib.request
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=0.2)
                break
            except Exception:
                time.sleep(0.1)
    # the plugin must not write into its own folder: Codex 0.164 and newer bind the approval of its hooks to the
    # contents (openai/codex#54619), and a written file switched them off (measured, 2026-10-19)
    sys.path.insert(0, str(ROOT))
    from maisecrets.codex_trust import content_hash
    plugin_roots = [p.parent.parent for p in (codex_home / "plugins" / "cache").rglob("hooks/hooks.json")]
    if TREE and plugin_roots and not all((p / ".codex-plugin" / "plugin.json").exists() for p in plugin_roots):
        fails.append("the installed plugin folder has no .codex-plugin/plugin.json: not the release-codex tree")
    contents_before = [content_hash(p) for p in plugin_roots]
    try:
        r = subprocess.run(
            ["codex", "exec", "--dangerously-bypass-hook-trust", "--skip-git-repo-check",
             "-C", str(cwd), "-o", str(last), sc["prompt"].replace("{home}", str(home))],
            env=env, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL,
        )
    finally:
        (codex_home / "auth.json").unlink(missing_ok=True)
        if srv:
            srv.terminate()
    if not plugin_roots:
        fails.append("no installed plugin folder found under CODEX_HOME/plugins/cache")
    elif [content_hash(p) for p in plugin_roots] != contents_before:
        fails.append("the plugin wrote into its own folder: Codex 0.164 and newer switch its hooks off")
    bodies = "".join(p.read_text(errors="ignore") for p in out.glob("request_*.json"))
    # every built-in tool Codex offered must be classified (harness/inventory.py)
    from inventory import offered, unclassified
    if sorted(out.glob("request_*.json")) and "exec" not in offered(sorted(out.glob("request_*.json"))):
        fails.append("no tool list found in the request bodies: the inventory check read nothing")
    for tool in unclassified("codex", sorted(out.glob("request_*.json"))):
        fails.append(f"UNCLASSIFIED TOOL {tool}: add it to tests/client_tools.json with its class")
    if MARK in bodies or MARK[-8:] in bodies:
        fails.append("LEAK: the marker (or its tail) reached the upstream request body")
    if MAIL in bodies:
        fails.append("LEAK: the address reached the upstream request body")
    out = r.stdout + "\n--- stderr ---\n" + r.stderr
    (work / "codex_out.txt").write_text(out)
    final = last.read_text() if last.exists() else ""
    rollouts = "".join(p.read_text(errors="ignore") for p in codex_home.rglob("*.jsonl"))
    if MARK in rollouts or MARK[-8:] in rollouts:
        fails.append("LOCAL: the marker is in the rollout transcript on disk (upstream requests were clean)"
                     if MARK not in bodies else "LEAK: the marker is in the rollout transcript")
    if MARK in final or MARK[-8:] in final:
        fails.append("LEAK: the marker (or its tail) is in the final message")
    if MAIL in rollouts or MAIL in final:
        fails.append("LEAK: the address is in the rollout transcript or the final message")
    for fname, text in sc.get("expect_home_text", []):
        got = (home / fname).read_text(errors="ignore") if (home / fname).exists() else ""
        if text not in got:
            fails.append(f"{fname} in the maisecrets home has no {text!r}")
    for value in sc.get("expect_absent", []):
        # a value of the scenario that must reach neither the model nor the rollout
        if value in bodies or value in rollouts or value in final:
            fails.append("LEAK: a value of the scenario is in a request, the rollout or the final message")
    lines = [ln.strip() for ln in out.splitlines()]
    failed_hooks = [ln for ln in lines if ln.startswith("hook: ") and ln.endswith("Failed")]
    if failed_hooks:
        # Codex runs the tool anyway when a hook fails (fail-open); a failed hook is never acceptable
        fails.append("hook failed in codex (fail-open): " + ", ".join(sorted(set(failed_hooks))))
    if sc.get("expect_blocked"):
        if "blocked" not in out.lower() and "maisecrets" not in out:
            fails.append("prompt was not blocked (no notice in output)")
        if rollouts and "SECRET_c" not in rollouts and "maisecrets" not in rollouts:
            pass  # a blocked prompt may leave no rollout at all
    ph = sc.get("expect_placeholder")
    ran_command = '"CommandExecution"' in rollouts or "exec_command" in rollouts
    # with --real there are no recorded request bodies; the tools-router line in codex's own
    # output is the redacted result as the model received it
    if ph and ph not in bodies and ph not in rollouts and ph not in final and not (REAL and ph in out):
        if REAL and not ran_command:
            print(f"     ~ {name}: the real model declined to run the command; nothing to check (not a failure)")
        else:
            fails.append(f"placeholder {ph} missing in upstream requests, rollout and final message")
    if sc.get("expect_file"):
        fname, content = sc["expect_file"]
        got = (cwd / fname).read_text() if (cwd / fname).exists() else "<missing>"
        if got != content:
            shown = got.replace(MAIL, "<MAIL>").replace(MARK, "<MARK>")
            fails.append(f"rehydration: {fname} holds {shown!r}")
    if sc.get("expect_value_in_a_file"):
        # a document, not the generator: a script that apply_patch wrote holds the value too, also when it never ran
        made = sorted(p for p in cwd.rglob("*") if p.is_file() and p.suffix.lower() in DOCUMENTS)
        if not any(value_in_file(p, MAIL) for p in made):
            fails.append("no document the model made holds the address (documents: "
                         f"{[p.name for p in made]}, all files: {sorted(p.name for p in cwd.rglob('*'))})"
                         .replace(MAIL, "<MAIL>"))
    if sc.get("expect_home_file_missing") and (home / sc["expect_home_file_missing"]).exists():
        fails.append(f"{sc['expect_home_file_missing']} was written into the maisecrets home")
    if sc.get("expect_hook"):
        log = (home / "hooks.log").read_text(errors="ignore") if (home / "hooks.log").exists() else ""
        event, tool, outcome = sc["expect_hook"]
        rows = [ln.split("\t") for ln in log.splitlines()]
        if not any(r[1:2] == [event] and tool in r and outcome in r for r in rows):
            fails.append(f"hooks.log has no {event} {outcome} for {tool}: the scenario did not reach the rewrite")
    if sc.get("expect_ran_and_refused"):
        seen = rollouts + out
        if not any(t in seen for t in sc["expect_ran_and_refused"]) or "cat: used.txt" not in seen:
            fails.append("no sign that the command ran and the sandbox refused the write")
    if sc.get("value_goes_to"):
        log = (home / "hooks.log").read_text(errors="ignore") if (home / "hooks.log").exists() else ""
        rows = [ln.split("\t") for ln in log.splitlines()]
        tool = sc["value_goes_to"]
        if not any(r[1:2] == ["pre-tool"] and tool in r and "rewrite" in r for r in rows) or \
                not any(r[1:2] == ["post-tool"] and tool in r and "block" in r for r in rows):
            fails.append(f"rehydration: {tool} did not get the real value (hooks.log has no rewrite and redaction)")
    if sc.get("expect_text") and not any(sc["expect_text"] in t for t in (bodies, rollouts, out)):
        if REAL and not ran_command and "maisecrets" not in rollouts:
            print(f"     ~ {name}: the real model declined to run the command; nothing to check (not a failure)")
        else:
            fails.append(f"expected {sc['expect_text']!r} in the requests, the rollout or the codex output")
    print(f"[{'OK ' if not fails else 'FAIL'}] {name}  rc={r.returncode}  work={work}")
    for f in fails:
        print("     -", f)
    if fails:
        # what codex itself said, marker redacted: the work dir is gone once a CI job ends
        tail = out.replace(MARK, "<MARK>").replace(MAIL, "<MAIL>").splitlines()[-25:]
        print("     codex output (tail):")
        for line in tail:
            print("       |", line[:200])
    return fails


VAULT_VALUES = ("vault-codex-person@example.com", "Vault Codex Person")


def _codex_vault_session(work: Path, env: dict, cwd: Path, turns: list, tag: str,
                         json_events: bool = False) -> tuple[str, str, str]:
    """One `codex exec` against the fake upstream: (codex output, request bodies, rollouts)."""
    import time
    import urllib.request
    out = work / f"out-{tag}"
    out.mkdir()
    (out / "scenario.json").write_text(json.dumps({"turns": turns}))
    srv = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_openai.py"), str(out / "scenario.json"),
                            str(out), str(PORT)])
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=0.2)
            break
        except Exception:
            time.sleep(0.1)
    try:
        # --json for the measure of the notice: codex-cli 0.162.0 puts a hook's systemMessage in neither output
        r = subprocess.run(["codex", "exec", "--dangerously-bypass-hook-trust", "--skip-git-repo-check", "-C",
                            str(cwd), *(["--json"] if json_events else []), "List the customers."], env=env,
                           capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
    finally:
        srv.terminate()
    text = r.stdout + "\n--- stderr ---\n" + r.stderr
    (work / f"codex_out-{tag}.txt").write_text(text)
    bodies = "".join(p.read_text(errors="ignore") for p in out.glob("request_*.json"))
    rollouts = "".join(p.read_text(errors="ignore") for p in (Path(env["CODEX_HOME"]) / "sessions").rglob("*.jsonl"))
    return text, bodies, rollouts


def run_vault_refs() -> list[str]:
    """Vault references in Codex, end to end (maisecrets/codex_vault.py; docs/PROTOCOL.md section 4).

    1. A first session calls the MCP tool of a user entry; its token makes maisecrets read the metadata and write
       ONE line on that entry, `http_headers_helper`, with a notice. No header goes out in this session.
    2. A second session: Codex runs the helper, the header reaches the server, the server binds the kid. The model
       writes the tokens with apply_patch and with a shell command: the files hold the values; no request body,
       rollout or final message does.
    3. A third session in a repository whose `.codex/config.toml` moves the entry to another server: that server gets
       no header, and its token stays text in the file.
    """
    sys.path.insert(0, str(ROOT / "harness"))
    from vault_server import VaultServer, kid_from_header
    if shutil.which("openssl") is None:
        print("[SKIP] vault_refs  needs openssl")
        return []
    fails: list[str] = []
    work = Path(tempfile.mkdtemp(prefix="maisecrets-codex-vault_refs-"))
    proj, repo, home, codex_home = work / "proj", work / "repo", work / "vaulthome", work / "codex_home"
    for d in (proj, repo / ".codex", home, codex_home):
        d.mkdir(parents=True)
    email, name = VAULT_VALUES
    with VaultServer() as srv, VaultServer(cert=None) as other:
        srv.auto_bind = True
        other.auto_bind = True
        srv.mint("EMAIL_1", email)
        srv.mint("NAME_2", name)
        other.mint("EMAIL_1", "other-server@example.com")
        bundle = work / "ca.pem"
        bundle.write_text(Path(srv.cert).read_text() + Path(other.cert).read_text())
        (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                      "client_vault_cafile": str(bundle)}))
        env = dict(os.environ, CODEX_HOME=str(codex_home), MAISECRETS_HOME=str(home), CODEX_CA_CERTIFICATE=str(bundle),
                   FAKE_OPENAI_KEY="sk-dummy-maisecrets-harness-key-0000000000")
        sandbox = os.environ.get("MAISECRETS_CODEX_SANDBOX", "workspace-write")
        cfg = (f'model = "{MODEL}"\nmodel_reasoning_effort = "low"\napproval_policy = "never"\n'
               f'sandbox_mode = "{sandbox}"\nmcp_oauth_credentials_store = "file"\nmodel_provider = "fake"\n'
               '# the person\'s own comment: it stays\n'
               f'[mcp_servers.demo]\nurl = "{srv.url}/mcp"\ndefault_tools_approval_mode = "approve"\n\n'
               f'[model_providers.fake]\nname = "maisecrets fake"\nbase_url = "http://127.0.0.1:{PORT}/v1"\n'
               'wire_api = "responses"\nenv_key = "FAKE_OPENAI_KEY"\nsupports_websockets = false\n')
        (codex_home / "config.toml").write_text(cfg)
        for cmd in (["codex", "plugin", "marketplace", "add", marketplace()],
                    ["codex", "plugin", "add", "maisecrets@maisecrets"]):
            r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                return [f"plugin install: {(r.stderr or r.stdout).strip()[:300]}"]
        before = (codex_home / "config.toml").read_text()
        call = {"exec": "const r = await tools.mcp__demo__customers({}); text(JSON.stringify(r));"}

        # 1: the trigger
        out1, _b, _r = _codex_vault_session(work, env, proj, [call, {"text": "done"}], "1", json_events=True)
        after = (codex_home / "config.toml").read_text()
        # Codex writes the trust of the session folder into the same file itself (`[projects."…"]` and its
        # `trust_level`, codex-cli 0.155.1): only the other new lines are the work of maisecrets
        added = [ln for ln in after.splitlines() if ln not in before.splitlines()
                 and not ln.startswith("[projects.") and not ln.startswith("trust_level = ") and ln.strip()]
        if len(added) != 1 or not added[0].startswith("http_headers_helper = "):
            fails.append(f"session 1 changed config.toml in {len(added)} line(s), not one helper line")
        if any(ln not in after.splitlines() for ln in before.splitlines()):
            fails.append("session 1 removed or changed a line of config.toml")
        if any(e.get("client_vault") for e in srv.log):
            fails.append("a header went out before the helper existed")
        # the notice is the hook's systemMessage; codex exec shows it in neither its text nor its --json output
        # (codex-cli 0.162.0: a warning entry of the hook run, shown by the TUI). tests/test_vault_refs.py checks the
        # answer of the hook itself
        print("[MEASURE] vault_refs: the notice reaches the codex exec output: "
              f"{'From the next start of Codex' in out1}")

        # 2: the header, the binding, the values in the files
        tokens = "⟦EMAIL_1⟧,⟦NAME_2⟧"
        patch = f"*** Begin Patch\n*** Add File: customers.csv\n+email,name\n+{tokens}\n*** End Patch\n"
        turns = [call, {"exec": f"const r = await tools.apply_patch({json.dumps(patch)}); text(JSON.stringify(r));"},
                 {"exec": _js("printf '%s\\n' '⟦NAME_2⟧' > name.txt")}, {"text": "done"}]
        n = len(srv.log)
        _out2, bodies, rollouts = _codex_vault_session(work, env, proj, turns, "2")
        sent = [e["client_vault"] for e in srv.log[n:] if e["path"] == "/mcp" and e.get("client_vault")]
        kid = kid_from_header(sent[0]) if sent else None
        if not sent:
            fails.append("session 2 sent no Client-Vault header")
        elif kid not in srv.bindings:
            fails.append("the server did not bind the kid of the header")
        want = {"customers.csv": f"email,name\n{email},{name}\n", "name.txt": f"{name}\n"}
        for fname, content in want.items():
            got = (proj / fname).read_text() if (proj / fname).exists() else "<missing>"
            if got != content:
                fails.append(f"{fname} holds {got.replace(email, '<EMAIL>').replace(name, '<NAME>')!r}")
        if "⟦EMAIL_1" not in bodies + rollouts:
            fails.append("the token never reached the model (did the MCP tool run?)")
        # the request bodies and the rollout are what the model reads and what stays on disk. The text output of
        # `codex exec` shows the person the diff of the patch it applied, values included, as for a stored value
        for value in (email, name):
            if value in bodies + rollouts:
                fails.append(f"LEAK: {value[:6]}… is in a request body or the rollout")

        # 3: a repository moves the entry to another server: no header there, and its token stays text
        (repo / ".codex" / "config.toml").write_text(f'[mcp_servers.demo]\nurl = "{other.url}/mcp"\n')
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        patch3 = "*** Begin Patch\n*** Add File: other.txt\n+⟦EMAIL_1⟧\n*** End Patch\n"
        turns3 = [call, {"exec": f"const r = await tools.apply_patch({json.dumps(patch3)}); text(JSON.stringify(r));"},
                  {"text": "done"}]
        _out3, _b3, _r3 = _codex_vault_session(work, env, repo, turns3, "3")
        if not any(e["path"] == "/mcp" for e in other.log):
            fails.append("session 3 did not reach the repository's server (the measurement no longer holds)")
        if any(e.get("client_vault") for e in other.log):
            fails.append("LEAK: the repository's server got the Client-Vault header")
        got = (repo / "other.txt").read_text() if (repo / "other.txt").exists() else "<missing>"
        if "other-server@example.com" in got or email in got:
            fails.append("a token from the repository's server was resolved")
    print(f"[{'OK ' if not fails else 'FAIL'}] vault_refs  work={work}")
    for f in fails:
        print("     -", f)
    return fails


def main() -> int:
    if shutil.which("codex") is None:
        print("codex not on PATH")
        return 2
    names = [a for a in sys.argv[1:] if not a.startswith("--")] or list(SCENARIOS)
    total = sum(len(run_vault_refs() if SCENARIOS[n].get("custom") else run_scenario(n, SCENARIOS[n])) for n in names)
    print("\nfailures:", total)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
