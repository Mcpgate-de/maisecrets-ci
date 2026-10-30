# maisecrets

[![version](https://img.shields.io/github/v/tag/Mcpgate-de/maisecrets?label=version&sort=semver)](CHANGELOG.md)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-d97757)](#install)
[![Codex](https://img.shields.io/badge/Codex-plugin-10a37f)](#install)
[![Python](https://img.shields.io/badge/python-3.9%2B%2C%20stdlib%20only-3776ab)](#requirements)
[![telemetry](https://img.shields.io/badge/telemetry-none-brightgreen)](PRIVACY.md)

Keeps passwords, tokens and personal data out of Claude Code and Codex. A value becomes a placeholder before the
model sees it, and goes back in on your machine only where a command or a file needs it.

## What it does

- **Blocks or rewrites a prompt** that carries a secret: the model gets a placeholder such as `⟦SECRET_c1⟧`, never
  the value.
- **Masks tool output** (files, commands, MCP results) before the model reads it.
- **Puts the value back locally** when the agent uses the placeholder in a command or a file.
- **Checks a value first:** `ms:(your value)` tells you whether it would be caught, without sending it.
- **Your own rules, terms and imports:** team rule folders, `/maisecrets:term add Jan Kowalski`, values from your
  own NER.
- **PDFs and images:** a PDF goes to the model as masked text only, or you are asked first.
- **Local and deterministic:** no model, no network request of its own unless a server you added offers
  [vault references](#vault-references), no telemetry.

## Quick start

```bash
claude plugin marketplace add Mcpgate-de/maisecrets
claude plugin install maisecrets@maisecrets     # then start a new session
```

```text
/maisecrets:status        what runs, which version
ms:(your value)           would this value be caught?
/maisecrets:settings      the choices you make
```

Codex and other installs: [Install](#install). More: [How it works](#how-it-works) ·
[Threat model](docs/THREAT-MODEL.md) · [Benchmarks](docs/BENCHMARKS.md) · [Known gaps](#known-gaps-measured-or-documented).

## How it works

An AI agent sees what you type and what its tools print: passwords, tokens, a
customer's e-mail address. maisecrets intercepts detected secrets and personal
data before they reach the cloud model. The real value goes back in only where
the call happens, and the model never sees it there either. By default
maisecrets adds no approval of its own: in Claude Code your permission rules
decide, as before; in Codex maisecrets answers `allow`, and Codex's sandbox and
its approval of MCP tools still apply. maisecrets itself sends no
prompt, value or telemetry to a server.

**What it is for:** maisecrets keeps values out of the model and out of the
session transcript. It guards against an agent that does not try to evade it.
It does not contain an agent that deliberately runs code with your rights to
switch it off ([threat model](docs/THREAT-MODEL.md), C22).

```bash
claude plugin marketplace add Mcpgate-de/maisecrets
claude plugin install maisecrets@maisecrets     # then start a new session
```

It works as a plugin for Claude Code (and Cowork) and for Codex, from the same
`hooks/hooks.json`. Codex and the other install paths: see [Install](#install).

**What it does, deterministically and locally:**

1. **You type a secret or a personal value** (a token, a password after a
   label, an e-mail address, a phone number with a country code, an IBAN, a
   card number, a public IP, and German identifiers by default; test data such
   as `example.com` stays alone, see "Test data that maisecrets leaves alone"). A
   `UserPromptSubmit` hook
   detects it, stores it in a local vault, blocks the prompt, and keeps the
   rewritten prompt with a placeholder such as `⟦SECRET_c1⟧` or
   `⟦EMAIL_c1:ma•••@•••.de⟧`. Type `/maisecrets:send` to send it as is,
   or paste it from the clipboard where one exists. The value never reached
   the model. Measured: zero API requests for a blocked prompt.
   **On Claude Code 2.1.287 and later (in the desktop app's Code tab from
   2.1.286), as a rule, there is no block and no resend:** a mod (`claude-mod/maisecrets-mod.mjs`) replaces the values with placeholders and
   the prompt goes on at once (the hook still blocks a prompt with an `@file`
   mention, a timeout of the mod, and a session where mods are off); your message on screen shows the placeholders, and the
   record of the prompt as typed in the transcript file is masked in place. The
   hook stays the gate: when the mod does not run or fails, the hook blocks as
   above. `"rewrite_prompts": false` keeps the block. See "The mod".
2. **The model reads a file or runs a command that outputs a secret.** A
   `PostToolUse` hook redacts the result before the model sees it.
3. **The model uses a placeholder in a Bash command or a tool argument.** A
   `PreToolUse` hook lets the command read the value once under a one-time
   grant, or inserts it into the tool argument, right before execution. The
   output is redacted again on the way back. See "Gates around a resolve".
   A form where the value could turn into code is refused; every other form
   runs without a maisecrets prompt, unless you set a stricter
   [rehydration policy](#rehydration-policy-optional).
4. **The model sends a message to another Claude session.** That session's
   prompt hook would block a message with a value, and the sender would not
   learn it. A `PreToolUse` hook on `SendMessage` replaces each value with a
   placeholder before the message leaves, stores the value, and tells the
   sending model. The receiving session's prompt hook then lets the message
   through; that session cannot use the placeholder in its own tool calls.

Everything a hook runs is readable source in this folder. No download, no
package install, no dependency outside the Python standard library and the
system tools it names (`security`, PowerShell, `openssl`, a clipboard tool).

What it does not do: detect a name without a label (it masks the names on your term list), follow a value through an encoding a
command applies, or protect against a process that runs as you. "Known gaps"
below lists every limit that was measured.

## What it looks like

You ask Claude to set up a deploy script and it reads your `.env`:

```
$ cat .env                          # what the command printed
DB_PASSWORD=<the real password>
STRIPE_KEY=<the real Stripe key>

                                    # what the model received
DB_PASSWORD=⟦SECRET_c1⟧
STRIPE_KEY=⟦SECRET_c2⟧
```

Claude writes the deploy command with the placeholder. Claude Code's permission
prompt, if your rules ask for one, shows this, and only this:

```
printf '%s' ⟦SECRET_c1⟧ | ./migrate --password-stdin --host db.example.internal
```

At execution the placeholder is read once from your keychain, the request
carries the real password, and the command's output comes back with any
value replaced again. The password was never in the prompt, the transcript,
or the model's context.

You paste a token into the prompt by accident:

```
> please check why my GitLab token glpat-… fails in CI
maisecrets: a secret was found and kept from the AI.

    ⌘V  pastes the cleaned prompt. Then send it, or type /maisecrets:send to send it at once.

Something wrong? /maisecrets:report · maisecrets by mcpgate.de
```

With `/maisecrets:shortcut` installed, the line names the short `/ms`.
Zero requests left the machine for that prompt. The rewritten prompt reads
`please check why ⟦SECRET_c3⟧ fails in CI`, and Claude can use the
placeholder in a command as above.

## Status

Released from `main` on every merge (`CHANGELOG.md`, tags `vX.Y.Z`). A release
moves only the last number; a higher one needs the owner's approval. Vault backend per platform:

| platform | backend | where the values live |
|---|---|---|
| macOS | `keychain` | login keychain via `security`, no iCloud sync flag |
| Windows | `windows-vault` | Credential Locker (`PasswordVault`, DPAPI) via PowerShell |
| Linux | `encrypted-file` | `openssl` AES-256-CBC + PBKDF2 + HMAC tag, key file 0600 |
| any | `jsonfile` | plaintext 0600, TEST MODE only |

Hooks run through `hooks/run.sh` (bash), which looks for a Python 3.9+ as
`python3`, `python`, `py -3`, a versioned name, or the Homebrew, `/usr/local`
and python.org paths. Claude Code on Windows runs a hook command in Git Bash
when Git for Windows is installed, and in PowerShell when it is not (pwsh 7,
else Windows PowerShell 5.1; read from Claude Code 2.1.284). So each command
in `hooks/hooks.json` is one text that both shells read: bash runs
`hooks/run.sh` and stops there, and PowerShell, which sees that part as a
comment, runs `hooks/run.cmd`. Codex on Windows runs the `commandWindows`
entry of each hook through `cmd.exe`, which starts `hooks/run.cmd` too. Both
launchers run the same `dispatch.py`. Without a Python
3.9+ the launcher blocks every prompt and every tool call and withholds every
tool result, and its message names what to install: fail closed, with a cause.

Proven with the harness on macOS (Claude Code 2.1.283) and on Debian 13
(2.1.223), the scenarios of `harness/run.py`, on every push in CI; Windows through the GitHub
Actions matrix (unit tests, both launchers, Credential Locker round trip), not
yet with a live Claude Code session. Codex (codex-cli 0.155.1): the same
`hooks/hooks.json`, Codex sets `CLAUDE_PLUGIN_ROOT` itself; `harness/codex.py`
proves the three tool scenarios against a fake Responses upstream on every
push and, with `--real`, against the real model. `docs/TESTING.md` has the
record. GitHub is a read-only mirror of the primary repository; issues and
pull requests are welcome there.

## Client support

✅ proven by the harness in this repo or seen live · ☑️ same runtime or possible per the
vendor's hook docs, not measured · ⚠️ partly · ❌ no hook

| client | prompt | rehydrate | redact | adapter |
|---|:---:|:---:|:---:|---|
| Claude Code CLI | ✅ | ✅ | ✅ | built; from 0.6.0 with mods (2.1.287+) a prompt with a value is rewritten with placeholders instead of blocked, measured live and in the harness; on Windows without Git Bash the shell tool is PowerShell, and a placeholder in a PowerShell command is refused (no PowerShell rewrite) |
| Claude desktop app, Code tab | ✅ | ✅ | ✅ | same hooks and manifest; a blocked prompt, an MCP call that resolves (with the ask and warning of 0.5.9, now `rehydration: confirm`), and a redacted Bash output seen live (2026-09-28); the mod (mods from 2.1.286) rewrites the prompt, seen live with Claude Code 2.1.288 (2026-10-06): the model got the placeholder, and your own message bubble shows the text as typed (a local display); not in the harness |
| Cowork | ✅ | ✅ | ✅ | same hooks as the desktop app; whether the mod loads there is not measured, so count on the block |
| Codex CLI | ✅ | ✅ | ✅ | built; hooks need one trust review per user (`/hooks`) unless an admin ships them as managed hooks; on Windows a shell placeholder is denied (PowerShell rewrite not built) |
| Codex in the ChatGPT desktop app | ✅ | ✅ | ✅ | same plugin runtime; block, rewrite and redaction seen live (2026-09-27), not in the harness |
| Codex IDE extension | ☑️ | ☑️ | ☑️ | same plugin runtime; not measured |
| Gemini CLI | ☑️ | ☑️ | ☑️ | not planned |
| Cursor | ☑️ | ☑️ | ⚠️ MCP only | waits for a shell-output hook |
| Copilot CLI | ⚠️ SDK only | ☑️ | ☑️ | waits for a prompt hook |
| OpenCode | ❌ | ☑️ | ☑️ | waits for a prompt hook |
| Antigravity | ❌ | ☑️ | ❌ | not supportable |
| Chat apps, web, mobile | ❌ | ❌ | ❌ | no hooks |

The three columns are the three guards: block a prompt that carries a
value, resolve a placeholder at execution, redact tool output before the
model sees it. A client with ❌ or ⚠️ under prompt or redact cannot be made
safe by this plugin; it would look protected and leak. The hook names
behind each mark are in `docs/CLIENTS.md`.

## Requirements

Python 3.9 or newer on the PATH the client gives its hooks (`python3 --version`).
The stock `python3` of macOS (3.9) is enough; nothing to install on a Mac.
Windows: install Python for all users, as an administrator:
`winget install --id Python.Python.3.12 --exact --scope machine`. Codex on Windows
runs commands as a sandbox user, and that user cannot start a Python installed for one
person only (`docs/CLIENTS.md`, "Codex on Windows: the sandbox user"). Linux: your package manager, plus
`openssl` for the vault and `xclip` if you want the clipboard. Without it the
plugin blocks every prompt and names the missing piece.

## Install

```bash
claude plugin marketplace add Mcpgate-de/maisecrets     # the GitHub repo is its own marketplace
claude plugin install maisecrets@maisecrets             # user scope; new session or /reload-plugins
claude plugin update maisecrets@maisecrets              # later versions
```

**Updates and open sessions.** A hook runs from the plugin folder of its version.
When Claude Code cannot find that folder, it shows `Plugin directory does not
exist` and runs the tool without the hook: every protection of that session is
off until `/reload-plugins` or a new session. No code of the plugin runs then, so
maisecrets cannot warn you itself. The harness measures this on every run
(scenario `plugin_folder_moved`, Claude Code 2.1.283: no hook runs, the tool
runs; anthropics/claude-code#97847). A client that runs the hook command anyway
gets a refusal: the command tests for the launcher first and blocks without it,
in bash, in PowerShell and, for Codex on Windows (`commandWindows`), in
`cmd.exe`. Codex needs this most: it removes the folder of the old version as
soon as it installs a new one, and an open Codex session then runs the command
of a folder that is gone (codex-cli 0.159.0, measured 2026-09-29). Exit that
session and run `codex resume`.

The install from the Claude plugin directory does not have this refusal. The
directory accepts only a hook command that names one program, so its copy (the
GitHub branch `release`) runs `run.sh` or `run.cmd` directly. If that folder is
gone, the hook does not run. Claude Code on Windows then also needs Git Bash. A
directory install keeps the old version folder for 14 days, so an open session
keeps its hooks. The install from this repository (`main`) keeps the refusal.

- Installed from this GitHub marketplace (the commands above), a previous version
  stays for 14 days, "so a session that already loaded the old version keeps
  running" ([Claude Code docs](https://code.claude.com/docs/en/plugins/loading#cleanup-of-previous-versions)).
  This is the install path we recommend.
- Synced from claude.ai, the previous folder moved to `~/.claude/plugins/.trash`
  when another Claude Code session started and synced (observed with Claude Code
  2.1.283 on 2026-09-28; not documented). A session that was open then lost its
  hooks. After an update, run `/reload-plugins` in every open session. That is
  not always enough: on 2026-09-29 (Claude Code 2.1.284) `/reload-plugins` kept
  the path of the gone folder (`/plugin` showed `commands path not found …
  maisecrets~g2`), and only a new process loaded maisecrets again: exit, then
  `claude --resume <session id>` in the directory where the session started (the
  guard puts this command on your clipboard, once per session). The
  session that started the sync can lose them too: on 2026-09-29 (Claude Code
  2.1.284) the folder was rewritten one second after a session started, and that
  session ran no maisecrets hook while `/plugin` showed the new version.
- **The guard closes this for a synced install.** It is a small hook outside the
  plugin folder (`~/.claude/maisecrets-guard.py`). Every maisecrets hook writes a
  heartbeat for its call once it has answered; when none comes (maisecrets did not
  run, or started and died), the guard blocks the prompt, denies
  the tool call or withholds the result. Without a sign of an update it asks to
  run the call again first, so an agent that works alone goes on; after an update
  it names `/reload-plugins` and the restart command. It stays
  silent for an account without maisecrets, for a plugin you switched off, and
  for Codex. Measured with the real client: `plugin_folder_moved_guarded` (the
  command does not run) and `bash_rehydrate_guarded` (a healthy session passes).
  - A synced maisecrets sets it up by itself: its session start places the script
    and, once, registers it in `~/.claude/settings.json` (a backup first, only the
    hooks change, one line in the session-start message says so). It protects the
    sessions after that one. `/maisecrets:guard remove` takes it away and it stays
    away; `"guard": false` in `~/.maisecrets/config.json` or in the machine policy
    keeps it off. A `settings.json` that is not valid JSON is left alone.
  - An admin who prefers central settings can register it in the Claude Code
    managed settings instead (`python3 -m maisecrets.cli guard managed` prints the
    entries); on a machine where maisecrets never ran that command answers `{}`.
  - Installed another way: `/maisecrets:guard install` does the same by hand.
  - Its cost: each prompt and tool call waits for the heartbeat, which the
    maisecrets hook of the same call writes as it starts (both run in parallel);
    without maisecrets it waits 5 s and then refuses. The refusal names
    `/reload-plugins`, then `claude --resume` with the id of this session for the
    case that the reload does not help, and, for a maisecrets that is off on purpose, the way out
    from a terminal: `python3 ~/.claude/maisecrets-guard.py --off` (it stays off;
    the agent cannot run it). A plugin switched off in the user, project, local or
    managed settings is left alone. The guard expects maisecrets for the account
    the synced copy registered under, so a second Claude profile is not blocked.
    On a Mac without the Command Line Tools there is no `python3`, and the guard
    answers nothing. It needs a claude.ai login: with an API key there is no
    account to compare, and `/maisecrets:guard status` says "expected: no".
    After an organisation takes maisecrets out of its sync the guard stops
    expecting it within 15 minutes; until then `--off` lets you work.
- For a team, an admin can roll out this marketplace with managed settings
  (`extraKnownMarketplaces` with `autoUpdate: true`, and `enabledPlugins`), so
  nobody has to type a command ([Claude Code docs](https://code.claude.com/docs/en/plugins/org)).

Codex (CLI, IDE extension, and the Codex agent inside the ChatGPT desktop app):

```bash
codex plugin marketplace add https://github.com/Mcpgate-de/maisecrets.git
codex plugin add maisecrets@maisecrets
```

Codex reads `.codex-plugin/plugin.json` (listing texts, icon) and the hooks from
`hooks/hooks.json`.

Codex skips a plugin's hooks until you review and trust them: open `/hooks`
in Codex and trust the maisecrets entries. Until then nothing is protected and
the plugin cannot tell you so, because no hook of it runs. From Codex 0.164 the
trust also covers the contents of the plugin folder (openai/codex#54619): after
each maisecrets update, Codex shows the hooks as failed and lets every prompt and
tool call through until you trust them again in `/hooks`. `/maisecrets:status`
reads Codex's `config.toml` and says whether Codex runs the hooks of the
installed version, and whether a second maisecrets is installed. A workspace admin
can ship the hooks as managed hooks (`requirements.toml`, MDM), which are
trusted by policy and cannot be disabled. The plain ChatGPT chat, web and
mobile have no local runtime and no hooks.

**Codex gets fewer versions.** Codex asks you to trust the hooks again for
each version, so Codex will install from the GitHub branch `release-codex`,
which can move more slowly than the releases, and moves at once for a security
fix; Claude Code gets every release.

For development:

```bash
claude --plugin-dir /path/to/maisecrets                 # one session, straight from the checkout
python3 -m unittest discover -s tests -v               # about 30 seconds
python3 harness/run.py                                 # 40 scenarios against a fake upstream (4 for the PowerShell tool of Windows)
python3 harness/codex.py [--real]                      # 15 scenarios through codex exec (five need --real)
python3 scripts/replay_can_fail.py                     # 387 proofs: each control's test, and each path of the seven invariants, goes red without its guard
python3 scripts/derived_counts.py                      # the numbers in the docs, measured again
python3 scripts/lint_plugin.py                         # frontmatter YAML, manifests, hook paths (pre-commit, CI)
scripts/install-hooks.sh                               # git pre-commit / pre-push
```

## Update and uninstall

```bash
claude plugin update maisecrets@maisecrets             # or a new session with an org-synced plugin
claude plugin uninstall maisecrets@maisecrets
codex plugin remove maisecrets@maisecrets
```

Uninstalling keeps the stored values until their TTL ends. To delete them,
the metadata and the logs at once, run `maisecrets wipe --yes` from the plugin
folder (`/maisecrets:status` prints the folder):

```bash
bash <plugin folder>/hooks/run.sh wipe --yes
```

or delete the `maisecrets` items in Keychain Access or Credential Manager and
the `~/.maisecrets` folder by hand. `wipe` reports when an item refused to go.

## For administrators

**Rollout.** claude.ai: an organisation admin adds a private or internal
marketplace repository under organisation settings and sets the availability
(available, installed by default, required). The sync accepts no public
repository, so create a private one with a `.claude-plugin/marketplace.json`
that lists maisecrets with this repository as its source, or mirror this
repository into a namespace you control and review each release there before
your members get it. ChatGPT workspace: Admin > Plugins > Add > Import
marketplace, with the same `marketplace.json`; the sync runs daily or on
"Sync now". Codex CLI users trust the hooks in `/hooks`; a change to
`hooks/hooks.json`, and from Codex 0.164 every maisecrets update, asks again, and
until then Codex runs no maisecrets hook and lets prompts and tool calls through. Managed hooks (`requirements.toml` through MDM) are trusted by
policy.

**Updates.** A new version reaches a member when `version` in
`.claude-plugin/plugin.json` changes: at the next session start for an
org-synced plugin, with `claude plugin update` otherwise. Every session starts
with one line `maisecrets X.Y.Z active`; its absence means the plugin did not
load. A rollback is a `git revert` on `main`: the pipeline releases it as the
next patch version.

**The guard for synced installs.** An update of an org-synced plugin can leave a
session without its hooks. maisecrets registers a guard against that by itself
(`"guard": false` in the policy turns it off); the managed settings can carry it
instead (`python3 -m maisecrets.cli guard managed`). See "Updates and open sessions".

**Settings you can enforce.** A machine policy file wins over the user's
`~/.maisecrets/config.json` and cannot be changed from there:
`/Library/Application Support/maisecrets/policy.json` (macOS),
`%ProgramData%\maisecrets\policy.json` (Windows), `/etc/maisecrets/policy.json`
(Linux). Any key from "Options" goes in it; typical: `backend`,
`scrub_transcript`, `max_ttl_seconds`, `regions`, `report_url`,
`resolve_in_files`, `rehydration`.
Every user must be able to read the file and its folder (for example 0644 and
0755): a policy maisecrets cannot read makes every hook fail closed, because it
cannot tell what the policy says. A key it does not know is ignored with a
warning; a key that starts with `_` or `$` is a comment or a schema link. A key
that looks like a misspelled `rehydration`, `resolve_in_files` or
`ssh_via_sandbox` blocks rehydration until it is fixed.
Two keys add to what the user has instead of replacing it: `rule_dirs`, rule
folders that every user reads and cannot remove, and `allow`, lines of the
allow list (both lists of strings; see "Rules of your own").
`/maisecrets:status` names the keys that come from the policy. The plaintext
`jsonfile` store is refused unless the policy or the user sets
`allow_plaintext_store`.

**What is written where.** `~/.maisecrets/index.json` holds metadata and keyed
fingerprints, a masked display for PII, and session ids; metadata of an expired
value is deleted after `keep_purged_days` (30). `audit.log` holds one line per
resolve (time, session, key, tool, the command with placeholders; capped at
`audit_max_lines`). `events.log` holds the last 200 detections (rule name and
type). `pending/` holds a blocked prompt with placeholders for 15 minutes.
`incidents.json` holds maisecrets' own internal failures as closed codes (at most
50 groups; see "Reporting an internal failure").
`hooks.log` holds one line per hook run (capped at 2000); the client column names
the entry point, `claude/local-agent` for a Cowork session. The FIFOs a value
is delivered through live in `$XDG_RUNTIME_DIR/maisecrets` or
`maisecrets-<uid>` in the temp directory, for up to 120 s. The values live in
the store of the platform; on macOS a value longer than about 2.8 KB (a private
key) is passed to `security` on its command line, visible to `ps` for the
milliseconds of the call, because the stdin form has a line limit. maisecrets itself sends nothing to a
server: no hook opens a network connection. Two exceptions to state to a data-protection
officer: the Windows Credential Locker can roam through a Microsoft account on
a machine that is not domain-joined (set `backend` to `encrypted-file` by
policy if that matters), and `/maisecrets:report` prints an issue text and a
link to `report_url`. It opens no browser and files nothing: you open the link
and decide in GitHub's form. Set `report_url` to your tracker, or set it to
`null` to turn reporting off.

**Diagnosis.** `/maisecrets:status` prints version, plugin folder, Python,
store, policy keys and log counts. `/maisecrets:audit` prints the last
resolves. `MAISECRETS_DEBUG_LOG=<file>` in the client's environment records one
line per hook call (event, client, duration, answer; never a value).
`bash <plugin folder>/hooks/run.sh wipe --yes` is the offboarding step; a
damaged `index.json` is rebuilt with `… run.sh repair` (stored values are
deleted, the counters continue). `hooks.log` in `~/.maisecrets` records every
hook run (time, event, client, session, tool, decision, duration; no value and
no command), so "the plugin did nothing" can be told from "the hook did not
run".

## What the plugin runs, sends and fetches

- Runs: `bash hooks/run.sh <event>` (or `hooks/run.cmd` for Codex on Windows)
  → `hooks/dispatch.py` on the matching hook events. Each reads one JSON
  payload from stdin and prints one JSON object. A Bash command with a
  placeholder reads the value from a FIFO in the per-user runtime or temp
  directory (POSIX) or through `hooks/resolve.py` under a one-time grant
  (Windows Git Bash).
- The mod (Claude Code 2.1.287 and later) runs this computer's Python with the
  plugin's own `hooks/dispatch.py mod-prompt`, with fixed arguments and no shell,
  and hands it the prompt on stdin; "The mod" below lists each call.
- Writes: under `~/.maisecrets`: `index.json` (metadata and keyed
  fingerprints, never a value), `audit.log`, `events.log`, `hooks.log`,
  `pending/`, `.announced`, `destinations.json` (where each value went, never a
  value), `incidents.json` and `incident-marker.*` folders (maisecrets' own
  failures as closed codes), `vault-refs/` (the server tokens seen, the key ids
  and the endpoint of each server; never a value or a key; the values a server
  gave stay in the store for one hour, so their echo in a tool result is
  redacted); one
  `Client-Vault` header per user-scope MCP server in the config file the
  client uses (`~/.claude/.config.json` when it is not empty, else
  `~/.claude.json`), with a backup beside it ("Vault references"); in Codex one `http_headers_helper` line per such server in
  `~/.codex/config.toml` instead, with the helper `~/.maisecrets/bin/codex-vault-helper.py` and its state file
  `vault-refs/codex-helper.json`; the value FIFOs in the per-user runtime or temp
  directory; the vault backend; on a blocked prompt the clipboard. With
  `scrub_transcript` on, it masks the raw value inside the client's transcript
  file named in the hook payload, in place, because the client writes the
  prompt to disk before or after the hook runs. "For administrators" has the
  retention of each file.
- The skill runs `skills/secret-hygiene/scripts/scan_secrets.py` (reads files and
  `git log`) and `redact_copy.py` (writes a new file) when the model follows it; neither
  opens a network connection.
- Sends and fetches: no telemetry and no download. These connections start from
  a command you run or a call that needs a value, and nothing else in the plugin
  opens one:
  - a Write, Edit or Bash call with a token that one of your own MCP servers
    sent: one metadata request and one resolve request to that server's own
    origin, over https, with this computer's key for that server ("Vault
    references"); `/maisecrets:status` makes the same request with no token;
  - the ssh route of your own ssh command inside the Claude Code sandbox
    (`hooks/proxy_connect.py`, the `ProxyCommand` of that ssh call): one
    CONNECT through Claude Code's local sandbox proxy (localhost only) to the
    host you named, with the proxy login that Claude Code puts in
    `HTTPS_PROXY` for that sandbox;
  - before an ssh command that carries a value, `hooks/sandbox_probe.py` checks
    that it runs inside that sandbox: it tries direct connections to 1.1.1.1:443,
    8.8.8.8:53 and 9.9.9.9:443 (the sandbox must refuse them) and one CONNECT with
    a wrong login to the local sandbox proxy. It sends no data, and it runs only
    when `SANDBOX_RUNTIME=1` and a local sandbox proxy are set;
  - `/maisecrets:report`: it prints the issue text and a prefilled link to
    `report_url` (the address carries the issue text, the plugin version, your
    platform and a rule name, never a value). It opens no browser and runs no
    program: the connection starts when you open the link.
- Credentials: the hooks and the mod fetch no credential for a request of
  their own. They read the values you stored, from your operating system's
  store, only to put each one into the tool call you allow, which then goes
  where that call goes. The two commands above use the login that belongs to
  them: the ssh route sends the sandbox proxy login from `HTTPS_PROXY` to the
  local sandbox proxy, and `gh` uses its own GitHub login. The Windows
  Credential Locker may roam through a Microsoft account (the operating system
  does that, not the plugin).

## Secret hygiene skill

The hooks stop a new value from reaching the model. The `secret-hygiene` skill deals with
values that already leaked. The model loads it when a task fits; in Claude Code it is also
`/maisecrets:secret-hygiene`. It does three things:

- **Check a repository.** `scan_secrets.py` lists the secrets in the working tree and, with
  `--history`, in every commit on every ref. A finding is a file, a line, a type, the rule, a
  length and a per-run id. The same id means the same value; the output never holds a value,
  a line of the file or a hash of the value, because the model reads it.
- **Install the protection.** A conversation starts with `protection_status.py`. It says ACTIVE
  only when a hook of the same agent ran for the call that started it. Otherwise the answer
  opens with an offer that names the source and the step the user must do, and the install
  commands run only after a yes. There is no offer in a web or mobile chat, and none without a
  Python 3.9 for the hooks. This is how the skill, which a store can list alone, brings the
  hooks along.
- **Check what the agents already received.** `audit_transcripts.py` reads the local Claude Code
  and Codex sessions and lists every secret that sat in a prompt, a tool result or a model answer,
  so it reached Anthropic or OpenAI: by type, rule, dates and sessions, never by value. On request
  it replaces the values in the local files (`--scrub`, then `--scrub --yes`), which does not
  take back what the provider received.
- **Contain a leak.** For a value that reached a chat, a commit, a log or a ticket, the skill
  gives the rotation steps per service from `references/rotation.md`: rotate first, clean up
  second. This part needs no shell, so it also works in a chat.
- **Make a file safe to share.** `redact_copy.py` writes `<name>.redacted<ext>` with every
  value replaced by `⟦TYPE_n⟧` and prints only the counts. The original is never changed.

The skill is not a guard. It works only when the model follows it, and it does not stop a
prompt. The history scan reads what each commit added; a value that entered only while a merge
conflict was resolved is not seen (`git log -p` shows no merge diff), and a file path that is
itself a secret is printed as it is. `python3 scripts/build_skill_zip.py` builds `dist/secret-hygiene.zip`, the
standalone skill with its own copy of the detector, for a skill upload without the plugin.

## Options

All options live in `~/.maisecrets/config.json` (next section) and take
effect on the next hook call. The manifest declares no `userConfig` on
purpose: Claude Code 2.1.223 rejects a manifest with that key and then loads
no hook at all, silently. A guard that vanishes on an older client is worse
than one without a settings dialog. At the first session start, and at every
start in test mode, a notice names the active store, its path and where to
change it. `python3 -m maisecrets.cli status` prints the same at any time.

### Settings you decide

`/maisecrets:settings` shows the settings that are yours to decide, grouped
(Protection, Using stored values, PDFs and images), one card each: the value, its state (`not
decided`, `set by you`, `set by a policy`), what it does, and the command for
the next step:

```
Protection
  SSH consent · off · not decided
    Ask before each ssh command that changes something on a host.
    Turn on: /maisecrets:settings ssh_consent on
```

A key that is missing from `config.json` is not decided; `false` written there
is a decision, with the same effect. `--all` shows the advanced settings too.

To change one, send the change as your own prompt, alone:

```
/maisecrets:settings ssh_consent on
maisecrets: set ssh_consent on          (the same, and the form for Codex)
```

`on`, `off`, a choice the card names (`rehydration confirm`), or `default`,
which removes your decision so that the setting reads the default again.
The prompt hook writes `config.json`. After the slash command it lets the
command run on, which shows the new card; the sentence form is stopped and
does not reach the model. maisecrets changes a setting for nothing else: not
for a prompt the client injected (a scheduled task, a loop wakeup, an SDK
prompt), not for a prompt of a client that a program started (`claude -p`
and the Agent SDKs: its hook sees `CLAUDE_CODE_ENTRYPOINT=sdk-…`), not for a
subagent's report, and a Bash or PowerShell command that carries the change
(a nested `codex exec` or `claude -p` that would type it) is refused. The AI
can tell you about a setting and the prompt to send. A setting from a machine
policy cannot be changed here. The limit: a program that runs as you can
write the file itself, and maisecrets sees a command only as text (C22 in the
threat model).

**You see each loosened protection.** A change that loosens a protection (a
setting in the looser direction, such as `rehydration automatic`, a higher
cap or a new autonomous host) and each `/maisecrets:forget` write one line
in `~/.maisecrets/events.log`: the time, the kind, the key or setting (never
a value) and the route (typed prompt, slash command, cli). The next session
start shows you one sentence that lists them, once:

```
maisecrets: since the last session start, 2 protections were loosened: setting rehydration (typed prompt),
forget SECRET_c3 (cli). If you did not do this, check /maisecrets:settings and /maisecrets:list.
```

A program that runs as you can also change that file; the line makes an
ordinary agent's action visible, it does not stop one that evades.

**Hints.** maisecrets stays quiet until a case comes up that one of these
settings is about. Then the AI gets one sentence about it, and mentions it
once. For `ssh_consent` that case is the first ssh command that changes
something on a host (`ssh web1 'sudo systemctl restart nginx'`; not `ssh web1
uptime`; and only when the command succeeds: Claude Code reports a failed one
through another event). A hint comes once, also when hooks run at the same
time; if maisecrets cannot record it, it does not come at all. It does not come again after you decided, and
it does not come again because time passed: only a real change of the
feature brings it back, once. `"tips": false` turns hints off with the tips.
The settings list shows each hint as `not shown yet` or `shown` with its date;
`/maisecrets:settings hints reset` (or `maisecrets: reset hints`) lets them
come once more and changes no protection setting.

### Where your secrets went

maisecrets notes, on this computer only, where each stored secret was handed
to a tool call: a host named in the call (from a URL, also one in quoted text,
not one in a shell comment), an ssh host, or an MCP server and tool. In a Bash
command every host it names counts for each secret in it, also a second URL
that the value does not reach. A file or a command without a host is listed
apart, as a local use. `/maisecrets:list`
shows it under each secret:

```
SECRET_c7      SECRET  format       3d   14        21h  -
    Sent to (a record only; it allows nothing)
      other.example.net     1×     last less than an hour ago   new
      api.github.com        10+×   last 2 hours ago
    Used on this computer
      a file in ~/proj/     2–9×   last 3 days ago
```

With the default `observe` this is a record, not a permission, and it stops nothing. The value is handed
out before the client asks you, so a call waits until the client reports that
it ran (also when it failed), and only then is it listed. A call you decline in
Claude Code's dialog is not listed (measured with the real client, whose
headless mode refuses the question). Codex sends
the same report for a command that ran or failed; a call it declines by its
approval policy never reaches the hooks. A call without a call id is not
listed: nothing could show that it ran. `new` marks a destination first seen in the
last 24 hours. When a secret that you used at one destination
(3 times on one day) goes to a new one for the first time, the AI tells you
once, in a sentence; this note does not come again. maisecrets does not
judge whether a destination is safe.

To be asked before a secret goes to a host it never went to, send
`/maisecrets:settings secret_destinations protect` as your own prompt. The hosts
of a secret's first call are its own; a first call that only writes a file
has none, and a second call that starts before the first one ran gets no
first call of its own. If you decline that first call, it holds the secret's
first call until it would have expired (24 hours), so until then every host
asks; a first call that maisecrets refuses for another reason holds it for 30
seconds only. After that, a call to a new host asks you first in
Claude Code, and the question names the new host. A host whose name the
record cannot hold one to one (more than 80 characters, a secret shape in it)
asks each time. When you allow
it and the call runs, the host is known and asks no more; a call you decline
leaves it new. Codex cannot ask with a rewritten input, so there the call is
refused before any value is resolved; run that step yourself, or switch back
to `observe` for it. A file or a command without a host never asks. What the
record already holds when you switch counts as known. `/maisecrets:settings`
shows about how often protect would have asked in your own last 30 days:
once per call that took a secret to a host it never went to. It is an
estimate from the record: a call you declined is not in it. Protect binds
only what the call shows: a URL with `http://` or `https://`, an ssh host, an
MCP server and tool. A host without a scheme (`curl host/api`), a host after a
flag (`psql -h host`), a host built at run time, a variable, a script or a
proxy shows none, and the port of a URL does not count, so for a hard limit
use the sandbox's allowed hosts too. If the destination record cannot be
read, the call asks, and the question says so; if the first use of a secret
cannot be recorded, it is refused, and you try once more.
`/maisecrets:settings secret_destinations off` stops the
record; nothing leaves the computer either way. When a value expires, its
record goes with it (if the record is busy at that moment, it goes 30 days
later with the metadata); forget and wipe delete it too.

## Vault

`~/.maisecrets/config.json` (all optional):

```json
{
  "backend": "keychain",
  "ttl_seconds": {"default": 86400, "CARD": 3600},
  "max_ttl_seconds": 2592000,
  "renew_on_use": true,
  "scrub_transcript": true,
  "block_at_mentions": true,
  "rewrite_prompts": true,
  "strip_hidden_characters": true,
  "regions": ["auto"],
  "max_keys_per_session": 200,
  "max_resolves_per_hour": 1000,
  "report_url": "https://github.com/Mcpgate-de/maisecrets/issues"
}
```

`backend`: `keychain` (macOS), `windows-vault`, `encrypted-file` (Linux and
any other), `jsonfile` (test mode, plaintext). `tips`: `false` turns off the
one-line tip that appears once a day at session start.

`regions`: country codes, for example `["de", "us"]`. Each country adds its
Presidio rules for personal data, such as a German tax ID or a US social
security number. `ch` and `at` add maisecrets' own rules for Switzerland (AHV
number, company UID) and Austria (social insurance number, UID), for which
Presidio has none. The entry `auto` is the country of your system setting (on
macOS and Windows the system setting, not `LANG`). The default is `["auto"]`.
An empty list keeps the generic rules only. The old key `pii_regions` still
works.

Credential labels come in languages. The labels of every language below are
on, whatever your system language and regions: `password:`, `passwort:`,
`wachtwoord:`, `hasło:` and the others (since 0.8.2; before, only English and the
labels of your system language and of each region). The
labels are data files in `maisecrets/detection/rules/labels/`, one file per language.
A new language is one new file. Files exist for Chinese, Czech, Danish, Dutch,
English, Finnish, French, German, Italian, Japanese, Korean, Norwegian (Bokmål),
Polish, Portuguese, Russian, Spanish, Swedish, Thai and Turkish. With Chinese or
Japanese on, the fullwidth colon (`密码：`, `パスワード：`) and a sentence with no
space (`密码是…`, `パスワードは…`) count as a label too. Each word comes from
a reviewed translation of an open-source project, and
`docs/label-sources.md` names the source of each word. `/maisecrets:status` shows the regions, where
they came from, and the label languages.

Every entry has a TTL. Each use renews it, up to `max_ttl_seconds`. On
expiry the value is deleted and the metadata stays as a record. Commands:
`python3 -m maisecrets.cli list | get <KEY> | put | audit | expire | scan | config`.

**What the store does and does not do.** The keychain, the Credential Locker
and the encrypted file keep the value off the disk in plaintext and away from
other users. None of them stops a process that runs as you: `security`,
PowerShell or openssl hand the value to any such process without a dialog
(`docs/THREAT-MODEL.md`). The gates below stand in front of the agent, not in
front of you.

## Check a value first: ms:(…)

Not sure whether maisecrets knows a password or a token? Send it in brackets
after `ms:` as your whole prompt:

```
> ms:(the-value-you-want-to-check)
✓ maisecrets masks this as a secret (⟦SECRET_…⟧). maisecrets knows this format, so it masks it wherever it appears, also alone.

This prompt was not sent. The value did not reach the AI.
```

```
> ms:(Kx7#another-value)
⚠ maisecrets did not catch this value. maisecrets stored it as ⟦SECRET_c4⟧. For 1 day after each use it is masked wherever it stands as a word of its own.

This prompt was not sent. The value did not reach the AI.
```

```
> ms:(two words)
⚠ maisecrets did not catch this value. It looks like ordinary text, so it was not stored. If it is a secret, store it with /maisecrets:put.

This prompt was not sent. The value did not reach the AI.
```

- **Report an unknown format.** When maisecrets did not catch a value with a fixed start (such as `sb_pat_`, before a
  random rest of 16 characters and more) and stores it, the answer offers a short issue link on a line of its own.
  It holds the value's shape only, as a pattern such as `sb_pat_[A-Za-z0-9]{32}`; the issue form asks which service
  issues the token. A value without a fixed start gets no link: no format rule can follow from it. You read the
  shape before you open the link; if the start is part of your secret, do not send it. The value is never in the
  link. With `report_url` set to `null` there is no link (docs/DETECTION-COVERAGE.md, loop 4).
- **Never sent.** A prompt that starts with `ms:(` (any case, blanks before it
  allowed) is always stopped, in Claude Code with and without the mod and in
  Codex, also when the closing `)` is missing. The mod never rewrites it: it
  drops the prompt and shows the verdict, and when maisecrets gives no verdict
  in time it drops the prompt all the same. Without the mod (Codex, an older
  Claude Code) the prompt hook blocks it and shows the verdict. Only you see
  the verdict. The prompt as you typed it is removed from the session
  transcript on disk (unless you turned `scrub_transcript` off), also when
  the prompt hook fails on it. Without the mod, a hook that cannot start at
  all (a half-updated plugin folder) blocks the prompt but does not clean the
  transcript. Blanks around the colon (`ms: (`) and the full-width `：（` of an
  input method count as the same start but store nothing; `ms:` without the
  bracket is an ordinary prompt.
- **The value** is the text between `ms:(` and the last `)`, or up to the end.
  One blank on each side is dropped, so `ms:( value )` and a key on its own
  lines between `ms:(` and `)` both work.
- **Several values** in one prompt: `ms:(first) ms:(second)`. Each value
  ends at its last `)` before the next `ms:(` (text after that `)` is not
  part of it), and each gets its own line (`Value 1: …`, `Value 2: …`). Each
  verdict is the one that value gets alone: a value is stored only after
  every value has its verdict. The prompt is not sent.
- **The verdict** is the one a normal prompt with that value gets: the
  detection rules, your rules of your own, your terms, the values already
  stored, the allow list and your regions. The answer names the type and the
  rule of each hit, never the value; a value that is caught is stored, as for
  a normal prompt.
- **Not caught:** when the value looks like a credential (no blanks, 8
  characters or more, a mix of letters, digits and signs or the randomness
  of a key; no word, no hex value, no id in capitals and digits, no date,
  version, file name or `name=value`), maisecrets stores it as
  `/maisecrets:put` does (type SECRET) and names its placeholder, so it is masked from then on wherever it
  stands as a word of its own (glued to other letters, it is not found). A
  passphrase with spaces is stored only when each word has a letter and a
  digit or a sign; it is found again alone on a line or after `:` or `=`, not
  inside a sentence, and the answer says so. It is not stored when the allow list
  allows it (the answer names the line), when it is shorter than 8
  characters or has more than one line (maisecrets could not find it again),
  when it looks like ordinary text (words, a sentence, a hash, an id, a
  command: the answer says so; store such a password with `/maisecrets:put`),
  when it holds a placeholder, or when the prompt did not come from you (a
  scheduled prompt, a subagent, `claude -p`). The client's own list of earlier
  prompts (the up arrow) may keep the prompt as typed; that is not measured.
- **Finding it.** Claude Code names `ms:(…)` once, under the first prompt that
  was blocked or rewritten because it carried a value; Codex names it once at
  a session start. `/maisecrets:settings` lists it under "Feature hints", and
  `/maisecrets:settings hints reset` shows it again.

In Remote Control the block notice is not shown (see "Sending a blocked
prompt" below), so the verdict is not visible there; the value is still not
sent.

## Handing a value to Claude on purpose

Paste it. A value with a known shape (a token, a key, an IBAN) is blocked,
stored, and comes back as a placeholder in your clipboard. A password without
a shape needs a label or the vault command:

- label it: `password: …`, `passwort: …`, `api_key=…` (English, Spanish and
  German labels are recognised; the value counts from 8 characters, so
  `password: yes` is not a hit);
- or copy the value and run `/maisecrets:put` in Claude Code; the placeholder
  replaces the value in your clipboard. Paste the placeholder into your next
  message, and Claude uses it in commands and tool calls. Over SSH and in a
  headless session there is no clipboard: type the value after a label
  (`passwort: …`) instead; the block stores it and names the placeholder.

A bare password in prose, such as "use Sommer2026 for the login", is not
detected. That is a limit of pattern detection, not a setting.

**The mod.** Claude Code 2.1.287 and later loads JavaScript middleware from a
plugin ("mods"). maisecrets ships one in its own folder: `claude-mod/maisecrets-mod.mjs`,
named by the manifest (`"hooks": "./claude-mod/maisecrets-mod.json"`). Nothing else in
the plugin points into that folder.

- **The one event it handles:** `prompt.submit`, which fires when a prompt is about
  to be sent. The mod handles the event; it never calls `$.prompt.submit` itself,
  so it submits no prompt and changes no prompt of other code. It acts on a
  person's own prompt only (typed or queued at the terminal, sent through Remote
  Control, or the turn of `claude -p`). A subagent's report, another session's or
  a channel's message goes on unchanged to the settings hook.
- **What it reads:** the text of that prompt, the session id and the session's
  working directory. It reads no environment variable and no file.
- **What it runs:** this computer's Python with the plugin's own
  `hooks/dispatch.py mod-prompt`, the same code the settings hooks run, in the
  plugin folder. Each call is fixed text, with no shell: `python3 hooks/dispatch.py
  mod-prompt`; when that cannot start or ends with an error (on Windows `python3`
  is often a store stub, and `dispatch.py` refuses a Python older than 3.9),
  `py -3 …`, then `python …`. All tries share one limit of 8 seconds. It sets
  `PYTHONUTF8=1` for that process (over the environment it inherits), so that
  Windows reads the pipe as UTF-8. When no Python answers, the mod passes the
  prompt on unchanged and the settings hook blocks it.
- **What it sends, and where:** the prompt, the session id and the working
  directory go to that local process on stdin. The process detects the values,
  stores them in the local store, and answers with the prompt with placeholders.
  The mod passes that text on to Claude Code in place of the prompt. Nothing goes
  to a network address: the mod makes no network call, and the launcher has none.
  The process also starts the local transcript scrub, which masks the values in
  this session's transcript file on disk.

The settings hook in `hooks/hooks.json` runs after the mod and stays the gate.
When the mod does not load, fails, times out or gets an answer of another shape,
the prompt reaches the hook unchanged and the hook blocks it. `hooks/hooks.json`
is unchanged, so Codex and an older Claude Code keep the block. Measured on
2.1.291: the request holds the placeholder and not the value, also for a prompt
typed while a tool runs; the settings hook sees the placeholder; on 2.1.274 the
mod does not load and the hook blocks. Seen live in the desktop app's Code tab
with Claude Code 2.1.288: the prompt is rewritten and the model gets the
placeholder; your own message bubble there shows the text as you typed it, which
is the app's local display. Cowork is not measured. Mods are a rollout switch of the client:
where they are off (a saved switch, some third-party setups), the hook blocks.

**Sending a blocked prompt.** `/maisecrets:send` sends the rewritten prompt as
it is, without the clipboard. A plugin cannot register a command without its
namespace, so `/maisecrets:shortcut [name]` writes a personal `/ms` for it
into `~/.claude/commands` when you ask for it (a fixed wrapper in
`~/.maisecrets/bin` finds the installed plugin at run time, so it survives
updates); an existing `/ms` is left alone, `--remove` takes it away. The first
session start only names the command, once; `"shortcut": false` turns that
off. Codex gets no offer, because it has no plugin slash commands. The answer starts with `Sent: ` and the
text that went out, because Remote Control shows neither a blocked prompt nor
a slash command's expansion; the block notice itself is not shown there
either (reported to the vendor).

## Invisible characters

A tool result can carry text that the model reads and a person does not see. maisecrets removes two
kinds of such characters from every tool result (a file read, a command's output, a web page, an MCP
result, the keys of its JSON too) before the model reads it:

- **Unicode tag characters** (U+E0000 to U+E007F). Each one is the twin of an ASCII character, so a
  web page can hold a whole hidden instruction ("ASCII smuggling"). A value spelled in them goes
  away with them. Only the flags of England, Scotland and Wales keep their tags.
- **Variation selectors used as bytes** (U+FE00 to U+FE0F, U+E0100 to U+E01EF). By a rule of
  thumb, not the Unicode registry of variation sequences, a selector stays after a letter, a digit,
  punctuation or a symbol: VS15 or VS16 (text or emoji style) after any of them, VS1 to VS14 after
  one that is not ASCII, an ideographic selector after an assigned CJK ideograph. A second selector
  in a row, or one after a space, a control, a format, a combining, private or unassigned character,
  goes. "Assigned" means known to the Unicode version of the Python that runs the hook.

The zero-width joiner of emoji and the marks U+200E and U+200F stay. Bidi controls (U+202A to
U+202E, U+2066 to U+2069) stay too: they reorder what a person sees, but the model reads the text in
its logical order, and translation files need them. The file on disk does not change, only what
the model reads. In Codex, the session's rollout file holds the raw output, and a resumed session
reads it again: maisecrets overwrites each tag character, ideographic selector and VS1 to VS14 there
with spaces, at once and again whenever the file changes in the next 15 seconds. That rule is
blunter: in the rollout, the three flags and ideographic variants lose their selectors too. You get no question: one line says how many characters went, the model reads that they can
carry an instruction, and the audit log records the count, never the text.
`"strip_hidden_characters": false` turns it off.

This is not a detector of prompt injection. It takes away one way to hide one. A selector that the
rule keeps still holds something: one of three states (VS15, VS16, none) after any letter or
symbol, up to four bits after a character that is not ASCII, and up to one byte after a CJK
ideograph, where the rule keeps the ideographic selectors that Chinese and Japanese text use.

## Disguised values in tool results

A value can also hide from the shape rules behind what a terminal or a renderer does not show. In a
tool result or a file (not in a typed prompt), the detector also scans a cleaned copy: without ANSI
colour codes, without zero-width and direction characters (U+00AD, U+200B to U+200F, U+202A to
U+202E, U+2060 to U+2064, U+2066 to U+2069, U+FEFF), with HTML entities and fullwidth letters
written out, and with each base64 or hex run decoded that holds text (gzip inside base64 is opened,
a run inside the text is decoded once more). A hit in the copy redacts the original span, the hidden
characters with it; a value in a decoded run takes the whole run, as in a Kubernetes Secret or a
docker `auth` field. The copy is only scanned around the lines that changed. Bounds: a text over 1
MB is not cleaned, a run over 16,384 characters (an image) is not decoded, and at most 64 runs,
64 KB of decoded bytes per text. The bounds count work, not time, so a busy machine decodes the
same. A text whose every line changes (a log in colour) is scanned twice, which about doubles its
time. The typed prompt is scanned as it is, so a block there needs the value in the clear.

## Password exports in tool results

A password export holds bare passwords in a column, and no shape or label rule finds a bare password
in a cell. In a tool result or a file, maisecrets masks every cell of the password, TOTP and secret
columns of a CSV or TSV table (comma, semicolon or tab) whose header row also names an entry column
(`url`, `username`, `login`, `name`, `title`, ...) and holds plain column names at the start of its line (a function
signature, SQL or a sentence is no header: a name of several words counts only quoted,
and with two columns only names without a space such as `user_name,password`): the exports of Chrome, Edge, Firefox, Safari,
Bitwarden, 1Password, KeePass(XC) and LastPass have such a header. A table with a password column
and no entry column counts when the file read (or grepped) is named like an export (`passwords.csv`, `bitwarden_export.csv`,
`1PasswordExport.csv`, a LastPass or KeePass export). The table ends at an empty line or at a row of
another width. A column `password_hash` or a flag such as `has_password` is no secret column. A typed
prompt is scanned as before. Limits, chosen
against false hits on code and documents: a header name of several words counts only in quotes (an
unquoted `Login Name` in a TSV is no header); a two-column table without an export file name keeps a
cell with a space (a passphrase there reaches the model); a test table with a `password` column next
to a `name` column is masked like an export. The secret-hygiene skill scans a file over 200 KB in
parts, and a part without the header row is not recognised as an export.

## Reporting a wrong detection

Every block and every redaction leaves an event in `~/.maisecrets/events.log`
(hook, client, rule name, type, plugin version; never a value). In Claude Code,
`/maisecrets:report last <why it is wrong>` prepares an issue from the last
event; `/maisecrets:report bug <what happened>` and
`/maisecrets:report feature <what it should do>` prepare one without an event.
The command prints the text and a prefilled link, so it also works over ssh and
in Remote Control. It opens no browser and files nothing: you open the link,
check the text in GitHub's form and decide there (`--create` is gone; to file
from a terminal, use `gh issue create` yourself). The arguments reach the CLI in
a quoted heredoc, so a shell never reads a reported command as code.
The CLI form is `python3 -m maisecrets.cli report …`. The value is not in the
event, so it cannot be in the issue; describe its shape in words.

## Reporting an internal failure

When maisecrets itself fails (a locked store, a store call that times out, no
Python for the hooks), it notes a closed code in `~/.maisecrets/incidents.json`
on this computer: the code, a cause, the client, the tool class (`Bash`, `MCP`,
…, never a tool's name), a count, the number of days in the last 30 and the
plugin version. It never holds an error text, a path, a prompt, a command, a
tool's input or output, a session id or a value; a field outside its closed
form drops the entry. Nothing is sent.

In Claude Code, type `/maisecrets:report incident`. The prompt hook shows the
report to you only; the model sees neither the report nor the link, and it works
also while the store is damaged. Open the link, check the text in GitHub's form
and decide there. In Codex and in a terminal, run
`<plugin folder>/hooks/run.sh report incident` (`hooks\run.cmd` on Windows; a
refusal names the full path); `report incident clear` deletes the record, and
`wipe` deletes it too. A refusal caused by maisecrets' own
failure names this command. The design is in `docs/DIAGNOSTICS.md` of the
repository.

## Gates around a resolve

A placeholder turns back into its value only here:

- **In the session where the value came in.** A reference resolves in the
  session where a human typed or pasted it, where the value was detected in a
  prompt, or where the value appeared in a tool result. A reference minted in
  session A resolves in session B only after you paste it into a prompt there.
  Keys are counters, so an injected text could otherwise name one it never saw.
- **Read up front in Bash.** The hook prefixes the command with
  `__ms_1="$(cat <fifo>)" || exit 97;` and turns `⟦SECRET_c1⟧` into
  `$__ms_1` in its quoting context. A detached process serves the value once
  through a FIFO in a directory only you can enter (`$XDG_RUNTIME_DIR/maisecrets`
  where the system has one, else `maisecrets-<uid>` in the temp directory; owner
  and mode are checked, a symlink is refused). It is readable from inside Codex's
  sandbox, which can neither write the vault nor read the keychain, and from a
  Claude Code sandbox that denies `~/.maisecrets`. On POSIX no grant is minted,
  so nothing is redeemable afterwards; on Windows Git Bash the resolver script
  reads the value under a one-time grant. The command you approve, the transcript and the tool record carry no
  value. A missing delivery ends the whole command with exit 97 before
  anything runs, also for references inside pipelines and subshells; nothing
  ever runs with an empty value. Every key is checked before anything is
  served, so a refused command leaves no value waiting. A value with quotes or
  `$(` arrives byte for byte in the contexts the rewrite can prove: plain,
  `'…'`, `"…"`, inside `$(…)`, an unquoted heredoc. A placeholder inside
  another shell (`bash -c`, `ssh`, `eval`, `su -c`), a quoted heredoc, `$'…'`
  or backticks, an interpreter with inline code (`python3 -c`, `perl -e`),
  `awk -v`, and a command that would encode, slice or trace the value
  (`base64`, `xxd`, `${x:0:4}`, `set -x`, `PS4=`) are refused with the
  reason, because there the value would be parsed a second time or leave in a
  shape the redaction cannot see. The check reads command words, so
  `python3 script.py ⟦KEY⟧`, `docker run -e T=⟦KEY⟧ img` and a word inside
  quotes or a comment pass. A refused command is refused as a whole: split off
  the step that needs the value and run it on its own. For a value that goes
  into a document or a generated file (a PDF, a .docx, a page), the refusal of
  inline code and of a quoted heredoc names the route that works: save the
  generator as a script file and run it with the placeholder as its argument
  (`python3 make_pdf.py ⟦KEY⟧`), or put the placeholder into the file content
  with Write, Edit or apply_patch. The file on disk gets the value; the model
  keeps the placeholder (harness scenario `document_gets_the_value`, Claude Code
  and Codex). Where the rehydration setting refuses these routes too, the
  refusal names none of them. On Windows the argument route does not work
  where a shell placeholder is refused (Codex, and the PowerShell tool of
  Claude Code). There the refusal and the primer name the file route only:
  a text file with the placeholder alone on a line (apply_patch, Write or
  Edit), which the script reads; then the script runs with no placeholder in
  the command.
- **ssh through the Claude Code sandbox.** A value may go to your own servers
  over ssh on one condition: the command runs in Claude Code's Bash sandbox,
  where the operating system forces every connection through Claude Code's
  proxy and the proxy admits only the hosts you allow. Then the value goes
  on stdin. maisecrets adds no ask of its own by default: Claude Code's permission
  rules decide, as for any Bash command. With `"rehydration": "confirm"` Claude Code
  asks you first, showing the host and the remote command:

  ```
  printf '%s' ⟦EMAIL_c3⟧ | ssh aux01 'grep -F -f - /var/log/mail.log'
  ```

  Enable the sandbox in `~/.claude/settings.json`:

  ```json
  {"sandbox": {"enabled": true, "allowUnsandboxedCommands": false,
               "network": {"allowedDomains": ["aux01.example.com"], "strictAllowlist": true}}}
  ```

  maisecrets puts its own options first on the ssh line: a `ProxyCommand`
  (`hooks/proxy_connect.py`, because plain ssh has no network in the
  sandbox) and `ControlMaster=no`, `ControlPath=none`. Outside the sandbox the
  command stops before the value is read. Refused, with the reason:

  - a value inside ssh's arguments, a here-string or a heredoc into ssh;
  - a remote side that reads its program from stdin or passes the value on:
    no remote command, `bash`, `sh -s`, `python3` alone, `| sh`, `$SHELL`,
    `eval`, another `ssh`, `xargs sh -c`, and encoders such as `base64`;
  - an own proxy, jump host, shared connection, config file, host name or
    local command (`-J`, `-W`, `-S`, `-M`, `-F`, `-o ProxyCommand`,
    `-o HostName`, `-o LocalCommand`, …);
  - ssh on Codex, which has no host allowlist.

  What to know before you set it up:

  - The allowlist needs the host name ssh connects to, not the alias:
    `ssh -G aux01 | grep ^hostname` shows it.
  - Jump hosts (`ProxyJump` in `~/.ssh/config`) and connection sharing are
    off on this route: the sandbox proxy is the only way out.
  - The sandbox has no terminal and limits writes. Use a key without a
    passphrase prompt or an agent, and connect once outside the sandbox so
    the host key is in `~/.ssh/known_hosts`. `sudo ssh` drops the proxy
    variables and fails.
  - The remote command itself can pass the value on. The sandbox limits
    where the connection goes, not what the remote side does with the value.

  `"ssh_via_sandbox": false` switches the route off. Measured on macOS and
  Debian 13 with Claude Code 2.1.283.

  **One approval per session (opt-in, under `rehydration: confirm`).** With
  confirm, a search over many hosts asks for every command. Set
  `"ssh_approval": "per-session"` in
  `~/.maisecrets/config.json`: the first ssh use of a value asks once, and
  names this scope. After you allow it, the same value goes on stdin to ssh
  without a prompt for the rest of the session, at most 8 hours. The session
  approval covers only remote commands that read and print (`grep`, `zgrep`,
  `cat`, `tail`, `journalctl`, `sort`, `uniq -c` and the like), with no `>`,
  no `tee` and no `sort -o`. Any other remote command asks every time. The
  sandbox, the stdin rule and `allowedDomains` stay as they are: a host
  outside the list still gets a 403. The approval is recorded when the
  command you allowed reads the value, not when the prompt appears, so a
  declined prompt approves nothing. Measured in the macOS and the Linux
  (bubblewrap) sandbox against a real host with Claude Code 2.1.283
  (`harness/sandbox/ssh_e2e.py`). The default is `"per-command"`.
- **Inline for Write and Edit, and for a Codex patch.** In Codex a placeholder in the content
  lines of `apply_patch` resolves the same way, and a patch against the maisecrets home is
  refused (measured on codex-cli 0.158.0). A placeholder in the content of Write, Edit,
  MultiEdit or NotebookEdit is resolved like an MCP argument, under the same
  session rule, cap and audit line (the line names the file). When your
  permission rules ask (or with `rehydration: confirm`), the prompt shows the
  diff with the value: that is the moment you see what goes on disk. `"resolve_in_files": false` (a policy can set it)
  turns this off; then the file tools refuse a placeholder and the way to a
  file is a Bash command you approve (`printf '%s' ⟦KEY⟧ > file`). The
  maisecrets home itself is never written by the agent.
- **Codex gets "allow".** Codex accepts a rewritten input only together with
  `allow`. Measured with codex-cli 0.158.0 (`harness/codex.py --real`): the call
  of an MCP tool still needs the tool's approval in Codex
  (`mcp_text_field_rehydrate`), and a shell command still runs in Codex's
  sandbox: in a read-only sandbox the write is refused although the hook
  rewrote it (`allow_keeps_the_codex_sandbox`). Whether `allow` skips Codex's
  approval of an escalated shell command is not measured: `codex exec` offers
  no escalation. Codex 0.155.1 documented that it does, so on Codex treat the
  rewrite of a shell command as approved by maisecrets. On Claude Code the hook
  gives no decision, so the normal permission rules apply to the rewritten call.
- **Inline for MCP tools.** An argument has no shell to read from, so the value
  is inserted after the same session rule, cap and audit line, into every field
  that holds the placeholder. A field that carries published text (`text`,
  `message`, `body`, `comment`, `subject` …) is no exception: when you ask the
  agent to send a password over Slack, it goes out, and the model still sees
  only the placeholder. The client's permission rules decide whether the call
  runs.

## SSH consent (optional)

An agent with your SSH keys can run any command on any host it reaches, also
when no secret is in the command. Claude Code's own `permissions.ask:
["Bash(ssh:*)"]` matches only the start of a command, so `cd x && ssh …`,
`bash -c "ssh …"` and `timeout 30 ssh …` pass it. With `ssh_consent` on (send
`/maisecrets:settings ssh_consent on` as your prompt, see "Settings you decide";
a policy can set it; it is off by default),
maisecrets reads every ssh-family call (`ssh`, `scp`, `sftp`, `rsync` to a
host, `sshfs`, `ssh-copy-id`, `mosh`, `autossh`), also behind `cd …&&`,
`timeout`, `nohup`, `env`, `sudo` and `perl -e 'alarm N; exec @ARGV'`:

- **A read runs.** A remote command that prints only metadata about the host,
  from a short list with named options (`uptime`, `df -h`, `free`, `uname`,
  `ls`, `du`, `wc` of a literal absolute path, `systemctl is-active`), with no
  expansion and no redirect except `2>&1` and `>/dev/null` (any other
  redirect asks, also a local one: the hook cannot tell a quoted `">"` that
  ssh hands to the remote shell from a local one). The content of a
  file, a log or a process list (`cat`, `grep`, `journalctl`, `ps`,
  `systemctl status`) is a write: it can carry a credential. Paths like
  `/etc/shadow`, `.env`, `id_*`, `*.pem`, `/proc` or `/root` are never a read;
  that check is a heuristic, not a guarantee.
- **Every write asks.** Any other remote command, a login shell, `sudo`,
  `docker`, a copy, a port forward or tunnel (`-L`, `-R`, `-D`, `-w`), or local
  data on stdin. A yes allows that one command; the next write asks again.
- **A host you trust for a while: type it.** Send `maisecrets: allow ssh web1`
  as your own prompt (the question names the exact sentence). Writes to that
  host, and to the hosts of its group in `"ssh_host_groups": {"web": ["web1",
  "web2"]}`, then run without a question for 8 hours, in that session, for the
  main thread only: a subagent asks for itself. The host is as written, with
  its user and port (`-l`, `-p`, `-o User`, `-o Port`, `user@`, `scp://…:port`):
  `root@web1` and `web1:2222` are other hosts than `web1`. Only a prompt you
  type counts: not a scheduled or SDK prompt, and a Bash or PowerShell command
  that carries the sentence is refused.
- **Hosts where the AI may work on its own.** Your own lab or ops servers can
  be autonomous: writes there never ask, in any session, while every other
  host asks for each write. Send `/maisecrets:settings ssh_autonomous_hosts add
  ops1` (or `maisecrets: ssh autonomous ops1`), and `remove ops1` (or
  `maisecrets: ssh ask ops1`) to take one off. The host is as the ssh call
  writes it (`root@lab:2323` is not `lab`), or the name of a group in
  `ssh_host_groups` (then its members, not a host of that name); every host
  of a call must be on the list. The list changes from your own prompt, and
  the deny list holds there too. Limit: maisecrets reads commands as text, so
  a program that builds the sentence at run time and feeds it to a nested
  client (Codex does not say who wrote a prompt) can add a host; check the
  list in `/maisecrets:settings`.
- **A form maisecrets cannot read asks every time.** A host built at run
  time (`ssh $HOST`), two users or
  ports for one connection, `sudo -u` (another user's ssh config), an option that sends the
  connection elsewhere (`-J`, `-W`, `-S`, `-F`, `-o ProxyCommand`, `-o
  HostName`, `-o RemoteCommand`), `GIT_SSH_COMMAND`, `git -c core.sshCommand`,
  `RSYNC_RSH`, `DOCKER_HOST=ssh://`, the own ssh options of `sshfs` (also
  `-F`), `mosh` (also abbreviated) and `rsync -e`, `ssh -P` (a tag that
  selects a block of your ssh config), and any mention of `.ss…` outside an
  ssh call in a command that does not only read: a change to `~/.ssh` can send
  an approved alias elsewhere, and a list of writers is never complete
  (`rsync`, `tar -C`, `ln -s` …), so only reads are listed (`cat`, `ls`,
  `grep`, `head`, `diff` …), and a redirect into `.ss…` asks too. Write and
  Edit on `~/.ssh` ask as well.
- **An ssh word asks only where a command starts it** (#15): as the command
  word; after a launcher (`env`, `xargs`, `timeout`, `setsid`, `sshpass`,
  `tmux` …) or as an argument of its own of any other program, unless it
  follows an option (`pytest -k ssh`) or the program only searches, shows or
  looks up (`grep`, `which`, `git`, `gh` …): `uv run ssh`, `gcloud compute
  ssh`; in quoted code after `-c`, `--run` or `--`; in `find -exec`, `docker exec` or `git rebase --exec`; in the
  code of `bash -c`, `fish -C` or `eval`, in a shell's heredoc and in the
  shell code of AppleScript's `do shell script`; as a path (`/usr/bin/ssh`)
  or after an escape in a string (`printf '…\nssh …'`); in a command
  substitution, also inside double quotes; in a pipe into a shell; in a file
  the line writes and then runs; as a URL that `curl` or `docker -H` connects
  to; as the program of an option (`rg --pre`); in a variable before a
  command (`BROWSER="ssh …"`); in a write to a startup file (`~/.bashrc`,
  `.envrc`, `.git/hooks/…`); and in
  any line that runs a command word it builds at run time (`S=ssh; $S web1`,
  `…; $_`, `eval`), since no parser can tell which text that runs. A mention
  that starts nothing does not ask: `grep ssh README.md`, a path such as
  `~/work/ms-ssh`, a comment, a commit message, a `git clone ssh://…` URL,
  or the word in Python code. A comment or heredoc whose end the parser cannot
  be sure of still asks.
- **A short deny list is always refused:** `mkfs` or `wipefs` on a device,
  `dd` to a device, `rm -rf /`, a fork bomb, anywhere in a command that names
  an ssh-family call (quotes removed; as a command word, not as a file name;
  not in plain text that a lone `echo` only prints).
  It is an airbag, not the protection.
- **Codex** cannot ask. It refuses and names a sentence with a code, for
  example `maisecrets: allow ssh web1 123456`. Typed alone as your very next
  prompt within 10 minutes, it allows writes to that host for 8 hours; the
  prompt does not reach the model. Any other prompt ends the code. Codex sends
  no sign of who wrote a prompt, so there the code is the proof.

Measured on the maintainer's transcripts with `scripts/measure_ssh_consent.py
--skip-cwd maisecrets` (2026-10-07, the sessions that work on maisecrets itself
left out): real ops commands use `sudo` or `docker` on the remote side almost
always, so most are writes (88 %), and the consent per host carries them. 112
sessions with ssh, a median of 2 questions per session, 7 at the 90th
percentile, 48 at most. The script ignores groups and the 8-hour expiry.

The mention rule, on the newest 600 sessions without the maisecrets ones
(2026-10-10): 0.6.10 asked 69 times, about 10 of them for a real reason;
0.6.11 asks 10 times, 8 of them for a real reason (labelled by hand).

**Check it on your own sessions.** `python3 -m maisecrets.cli consent-report
ssh` reads the Claude Code transcripts of the last 30 days on this computer
(`--last 7d`, or `--last 200` for the newest 200), classifies each command
that names an ssh-family word, and prints counts per verdict and per reason,
with no host, command or value. `--json` prints the same as JSON.
`--excerpts FILE` writes a short window around each question into a new
file of yours, to look at by hand: the values the detectors find are masked,
hosts and commands stay in it, so share only what you may share. It runs
nothing, changes no setting or consent, and sends nothing. Codex sessions are
not read.

A command name in another case (`SSH`, `Scp`) is the same program on macOS
and in PowerShell, so it counts too. A command line over 8,192 characters
that names ssh is not read at all: it asks (on Codex it is refused), so that
the answer always comes before the client's timeout.

Limits: maisecrets sees only the command text, and checks the ssh-family
starts that it shows. A program the line starts that starts ssh itself (a
script, `make`, `npm run`, `python3 -c`, `node -e`), an alias or a variable
set in an earlier command or in your profile, or a word built without the
letters `ssh` in the text is not seen. The check is built against an agent
that starts ssh openly without asking, not against one that tries to evade
it; consent before any connection needs a network layer (a sandbox with a host
allowlist). A program that git or gh starts
from its own configuration (a hook, an editor, a signing program, a browser)
is not checked; it gets the quoted text only as data. maisecrets reads the
command with its own small shell parser; other shell syntax that it reads
differently from bash or zsh can still hide a call (the reviews of 0.6.7 found
such forms only after one of the characters above). A mount (`sshfs`) or a tunnel
(`ssh -f -N -L`) that one consent started stays after the 8 hours, and the
local commands that use it ask nothing. On Codex the model sees the consent
code; maisecrets refuses a command that carries the sentence, but not one that
builds it at run time. The
`Monitor` tool of Claude Code runs a shell command outside the maisecrets
matcher (adding it would change the hook hash that Codex trusts). A program
that runs as you outside the sandbox can write the consent store. A hard
boundary needs host-side controls (restricted keys, `ForceCommand`, sudo
rules). Git over ssh (`git push`) is out of scope.

## Rehydration policy (optional)

The core does not change with this setting: a value stays out of the model on
every path, and a form where the value could become code is refused on every
path. The setting decides only whether maisecrets adds its own confirm where a
value is put into a call. `~/.maisecrets/config.json`, or the machine policy:

| `rehydration` | Claude Code | Codex |
|---|---|---|
| `"automatic"` (default) | no ask of ours; your permission rules decide | `allow` with the rewritten input |
| `"confirm"` | every call that gets a value asks, also in auto and bypass mode; the prompt names the fields and warns for a published-text field | refused before anything is resolved: Codex cannot ask with a rewritten input |
| `"block"` | refused before anything is resolved | refused |

It covers Bash, ssh, MCP tools and Write/Edit alike. `"resolve_in_files": false`
blocks the file tools alone; `"ssh_approval": "per-session"` works under
`confirm`. A value that is none of the three blocks. A `config.json` that is not
valid JSON, or holds no JSON object, blocks rehydration until it is fixed (it may
have said `block`), and
one ignored for a wrong type keeps what it made stricter (`rehydration`,
`resolve_in_files: false`, `ssh_via_sandbox: false`), so a typo never loosens
a setting. The refusal and `/maisecrets:status` name the file. In an unattended run (`claude -p`) nobody can answer a confirm, so the
call is refused and the model reads the reason, never the value. The whole
matrix, path by path: `tests/test_rehydration_matrix.py`.
- **Under a cap.** `max_keys_per_session` (200) distinct values per session and
  hour, and `max_resolves_per_hour` (1000) in total; above that the call is
  denied, and the reason names the command that raises the cap, for example
  `/maisecrets:settings max_resolves_per_hour 2000` (in Codex
  `maisecrets: set max_resolves_per_hour 2000`), typed as your own prompt. The cap
  is a brake for a session that would send all of its values out at once; the
  session rule above keeps every other value closed anyway. Replayed over five
  months of the maintainer's sessions, the busiest hour needed 67 values and 118
  uses; the old caps of 25 and 60 would have stopped 3 of 178 sessions that used
  values. Every resolve writes one line to `~/.maisecrets/audit.log`
  (time, session, key, tool, command with placeholders; never a value):
  `python3 -m maisecrets.cli audit`.
- **Not by the agent reading or changing the store.** A Bash command that
  calls `maisecrets get`, `security … maisecrets`, names `~/.maisecrets` or a
  delivery path, and a Write/Edit under `~/.maisecrets`, are denied and the
  reason names the pattern. This is text matching, a backstop; the boundary
  is the gates above, and a process that runs as you is not stopped by it.

Recommended in your Claude Code settings, outside the plugin: the sandbox with
`sandbox.credentials` deny for `.env` files and `~/.maisecrets`, and
`injectHosts` for the hosts a value may go to. That closes the paths no hook
sees: a command that sends `.env` or `printenv` somewhere without printing it
(a command that pipes `.env` into an upload). The hook redacts only what comes back.

## Test data that maisecrets leaves alone

maisecrets steps in only when a value that it can detect goes to the AI. Test data
does not need to look like a real secret, and these forms are never a hit:

- **In test code** (a file under `tests/`, `test_*.py`, `*_test.go`, `*.spec.ts`,
  `conftest.py`, or code after `def test_`, `assert`, `describe(`), a password that
  maisecrets finds only by its label (`password = "<value>"`) is a fixture.
  A token shape (`glpat-…`, `AKIA…`, a private key) and personal data are still found
  there: a real token in a test is a leak.
- **Anywhere:** a value that names itself (`testpass`, `secret123`, `Passw0rd!`,
  `my-test-token`), a placeholder (`<your-token>`, `${API_KEY}`, `{password}`,
  `changeme`, `xxxxxxxx`, `***`), and a default equal to its label or user
  (`POSTGRES_PASSWORD: postgres`, `admin:admin`).
- **Addresses:** e-mail at `example.com`, `example.org`, `example.net` and the domains
  `.test`, `.example`, `.invalid`, `.localhost`, a system mailbox such as `alerts@` or `noreply@`
  at `.local` or `.internal` (a person's mailbox there is found); IP addresses in
  the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and
  `2001:db8::/32`, private and loopback addresses.
- **A test value that vendor documentation publishes,** for its own type only: the payment
  test cards (Stripe, Braintree), the Stripe API reference keys, the jwt.io example token and
  the Twilio test numbers (`maisecrets/detection/rules/public_test_values.txt`, as sha256 digests). The
  same digits under another type stay a hit: an IBAN or a bank account that holds a test
  card's digits is found. A published key that a label assigns (`PROD_PASSWORD=…`,
  `api_key: …`, `?token=…`) is used as a credential there and stays a hit.
- **An AWS key id in a SigV4 credential scope:** `X-Amz-Credential=AKIA…` in a presigned
  URL, `Credential=AKIA…` in an `Authorization` header. The id names the key; it is not
  the secret half. The same id anywhere else is still found.

If maisecrets stops something that is not a secret, `/maisecrets:report last <why>`
sends the rule name, never the value.

## Detection rules

Four sources, one scanner (`maisecrets/detection/core.py`):

- **betterleaks** ruleset, vendored as data under `maisecrets/detection/rules/` (MIT,
  version in `BETTERLEAKS_VERSION`, refresh with `scripts/sync_betterleaks.py vX.Y.Z`):
  463 rules, 416 of them loaded. No betterleaks binary is used. betterleaks is the
  successor of gitleaks by the same maintainers; gitleaks takes security patches
  only since v8.30.1. Each rule's filter (an Expr expression: entropy limits,
  pattern lists) is read by `maisecrets/detection/rule_filter.py`; a rule whose filter is a
  program that module cannot read is left out (`generic-password`,
  `generic-username`, `generic-credential-uri`), and so are the 43 components that
  betterleaks never reports alone (`skipReport`). The BPE token ratio filter needs
  a tokenizer the standard library does not have; maisecrets answers 0 there, as
  betterleaks does without a tokenizer.
- **Own secret rules** (`maisecrets/detection/rules/own_secret_rules.json`, patterns
  derived from gitleaks v8.30.1, MIT): `generic-api-key`, to which the label
  filters of the detector are tuned, and nine token forms the betterleaks rules
  miss (Alibaba `LTAI`, Etsy, JFrog twice, a bare Fly.io token, an Atlassian
  token after a product name, a legacy Vault token, Twilio `SK`, Codecov). They
  run after betterleaks and only fill its gaps; a test drops each one that a
  later betterleaks finds itself. gitleaks itself is no longer vendored.
  Samsung CredData, line by line, without the test-vector repository, regions
  `de`: v0.6.17 has precision 0.929, recall 0.578 and F1 0.713 on tool results
  and files. On typed prompts it has 0.924, 0.527 and 0.671. With regions `us`,
  the US bank-account rule adds 546 false alarms (F1 0.690 and 0.649).
  `docs/BENCHMARKS.md` has the method, each release, a comparison with other
  tools and the commands to repeat it.
- **Presidio** pattern recognizers, vendored as data under `maisecrets/detection/rules/`
  (MIT, version in `PRESIDIO_VERSION`, refresh with `scripts/sync_presidio.py`):
  country-specific PII with scores and context words. The config key
  `regions` selects them (default: the country of the system setting; `de`
  gives Steuer-ID,
  Sozialversicherungsnummer, Personalausweis, Reisepass, USt-ID,
  Krankenversicherung, PLZ, Kfz, LANR, BSNR). Checksums for
  the German types, PESEL, the Spanish DNI and NIE, the NHS number, the ABA
  routing number and the codice fiscale are ported and checked against Presidio
  (`scripts/check_validators_against_presidio.py`). A digit-only shape such as
  a Steuer-ID is reported only with a context word nearby, even when the
  checksum passes. A USt-ID written `DE` and nine digits also needs a word
  such as `USt-IdNr` or `VAT` nearby: alone, that shape is often a FIX tag or
  an XML id. A Handelsregister number is not reported: it names a company, is
  public and is no personal data. Own rules (`REGIONAL_RULES` in
  `maisecrets/detection/core.py`) add what Presidio lacks: the Personalausweis and
  Reisepass number in the 9 characters the card prints (Presidio read the 9th
  as a check digit, which only the machine-readable zone carries), the
  Steuer-ID and the Rentenversicherungsnummer with the spaces of their printed
  form, and the Swiss and Austrian numbers. The Steuer-ID check follows the
  repeat rule of its issuer (exactly one digit twice or three times, never three
  in a row; ITZBund, "KONZEPT Steueridentifikationsnummer", version 2.3, 2016).
- **Crypto wallet secrets**: a BIP39 seed phrase (12 to 24 words of the
  English list, `maisecrets/detection/rules/bip39_english.txt`, MIT, whose checksum
  holds), a Bitcoin private key in Wallet Import Format and a BIP32 extended
  private key (`xprv`, `yprv`, `zprv`, `tprv`, …) are secrets by their checksum,
  with no label. A phrase of 12 words (a checksum of 4 bits) needs a word such
  as seed, wallet, recovery or password near it; 15 to 24 words stand alone.
  Addresses, extended public keys, the BIP39 reference vectors and a run of
  more than 48 list words (a word list) stay text. Not found yet: a phrase in
  a numbered list, a JSON array, or capitalised.
- **detect-secrets** (Yelp, Apache-2.0, version in `DETECT_SECRETS_VERSION`,
  refresh with `scripts/sync_detect_secrets.py vX.Y.Z`): credentials
  recognised by position (`password = …`, `api_key: "…"`, `user:pass@host`),
  with its heuristic filters ported (templated, indirect, sequential values
  are not secrets).
- **Own rules** for what none of the three covers: email (a
  bounded regex; the unbounded one took 11 s on an 80 KB dotted run), an email with its
  `@` written `%40` where an address is expected (after `=`, `mailto:`, `users/` or a mail
  word such as `To:`, or in a CSV column whose header names a mail address or its owner, such as
  `email`, `contact`, `login` or `courriel`), phone
  with a country code, `Bearer …` outside curl, `?api_key=…` in a URL, a
  password with no user in a URL (`redis://:…@host`), the secret half of an AWS
  key pair within a few lines after its `AKIA…` id (at most 4 lines on, and at most
  400 characters into its line, so a long line scans in linear time; the `-p` of mysql and
  the `-a` of redis-cli count only within 400 characters after the command word, for the same
  reason), and full-length GitLab
  runner and deploy tokens.
- Keys that a label names in a form the label rules do not read (0.6.16): each key in a list
  after a label that names secrets and nothing else (`"api_keys": ["…", "…"]`, `passwords =
  ['…']`, Go `Secrets: []string{"…"}`), to the end of the list; a value there must look like
  a key, so a name, a word-shaped identifier, a path, a password hash, a typed id (`pm_…`),
  an address (`0x…`) or a digest stays text, and a list after `tokens`, `code_tokens` or
  `keys` is not read (tokenizer output, cache keys); the value of an Elasticsearch
  `Authorization: ApiKey …` header (a header line, `curl -H`, a header object) that decodes
  from base64 to `id:key`; the scheme in prose stays text. A hex value after any other name
  stays text: a nonce, a checksum, an etag, a commit id and a key that a hex literal decodes
  into (`key = unhexlify('…')`, mostly published test vectors) are left out, as developer
  text is full of them (`tests/fp_corpus.py`).
- A password label and a literal value that is no word (0.6.16, `label-pw-literal`):
  `db_password = "…"`, `<password>…</password>`, `IDENTIFIED BY '…'`,
  `ConvertTo-SecureString '…'`, a value of 4 to 7 characters. The label comes from a frozen
  list of password words (`password`, `passwd`, `pwd`, `passphrase`, `kennwort`, …) and a list
  of words that make it name something else (`password_hint`, `passwordPolicy`, `bypass`). The
  value must be no word after undoing leet (`P4ssw0rd` is a word), no fixture (`testpass`),
  no mask, template or reference (`${DB_PASSWORD}`, `{{ … }}`, `settings.DB_PASSWORD`). The
  words come from `maisecrets/detection/rules/words_en.txt`, about 21,000 English words of 4 to 8
  letters from SCOWL (see `NOTICE`), read only when a password label is in the text. A miss in
  an English list is no evidence alone: the value needs a letter and a digit or a sign beside
  it (`_`, `-` and `.` join the words of a name and count as no sign), or (letters only) a
  mix of cases that no word boundary explains, letters of two scripts with case, or a
  lowercase run of 9 letters and more with fewer than 15 % vowels. So a word of another
  language (`senhaAtual`, `senha_atual`, `Pflicht`), a developer abbreviation (`ctxPtr`), a
  word in another script or with accents (a translated UI string), a path or a reference
  (`/run/secrets/db`, `./secrets/pw.txt`, `C:\keys\db.pw`, `vault:secret/db#pw`) and a
  value that is a whole regular expression after a secret label stay text. So do a
  number, a ratio, a time, a duration and a section (`95.2%`, `118/124`, `12:30`, `~30d`,
  `P90D`, `§3.2`), a dotted abbreviation and a word with a number (`Seite#3`). After the weak label `pass` (a boarding pass, a test pass) the
  value needs 8 characters of three classes. A comparison (`==`, `!=`), a label that is the tail
  of a path or a flag value, and an unquoted label before a comma (`f(password, "…")`) are no
  label and value. A word
  with a number and a sign (`Sommer2024!`, `Welcome1!`) is a password too; a word with a number
  alone (`Winter2023`) is left to the keyword rules. A passphrase of words
  (`passphrase: correct-horse-battery-staple`) stays text: the rule cannot tell it from a
  reference such as a Kubernetes secret name. A string that `+` continues, a version and a
  format template (`{pw}`) stay text too. Word-likeness and the label word classes follow Dan
  Szymkowiak's backlog ideas.
- A tool result or a file takes more (0.6.17): there, a value of ASCII letters after a password
  label is a password when no English word covers it, also without a digit, a sign or a mix of
  cases (`password = Some("pozkemva")`). A typed prompt keeps the rule above, because a false
  hit blocks a prompt; in a tool result it masks one value. Measures, durations, abbreviations
  and words in another script or with accents stay text in both. The secret-hygiene skill scans
  files, commits and tool results the same way.
- A word that a label rule takes in a tool result or a file blocks no later prompt (0.6.17): a
  value of letters only, with no evidence of chance and, in ASCII, at most one rare letter pair in
  ten (pairs counted in the word list). maisecrets stores it with a quiet mark: it still masks the
  word in every later tool result (a default word such as `postgres`, and since 0.6.38 an English
  word of the word list such as `fallback`, only where it was found; since 0.8.2 also an English word
  with an ending or of two words of the list, such as `directly` or `benchmarking`, and the word for
  password in another language, such as `contraseña`), but does not look for it in a
  typed prompt, also when this
  session used its placeholder in a command. A random value (`xqzvbnmq`) is looked for in prompts
  too, and so is a word the person gives in a prompt after a label, also when a tool result held
  it first. Only a value stored new from a tool result gets the mark; a value stored before 0.6.17
  has no mark and stays looked for. So a word that 0.6.16 stored from a file (field report) blocks
  prompts until it expires or `/maisecrets:forget` deletes it. A quiet English word that an older
  version stored is marked weak at the next session start.
  Limit, a trade for no blocked prompt: a password that is a word, or a random value of small
  letters that reads like one (about 3 in 100 of 8 letters, 1 in 200 of 12), and that a file or a
  tool result held first, is not looked for in a later prompt that has it without a label. It is
  still masked in every tool result.
  Limit of the word list: only English words count as words that are masked only where they were
  found. A common word of another language (`Wartungsfenster`), a name, a project term or an
  invented word that a label rule takes in a tool result is masked in every later tool result of
  every session until it expires or `/maisecrets:forget` deletes it. The word list makes this rare
  for English prose; it cannot remove it. A random value that reads like a word and is split into
  two words of the list or a word with an ending counts as a word too (measured: 369 of 190,508
  random values of 8 to 14 letters, 0.19 %); it is masked where it was found and not hunted in
  other texts. A word that a tool result stored and the person then gives as a password (with
  `/maisecrets:put` or after a label in a prompt) is hunted everywhere again. Since 0.8.2 a
  further place where the same tool result holds such a word without a label stays text, as for
  `fallback` since 0.6.38; before, the hunt masked it there too.
- A key after a label that names a secret, in a form the keyword rules do not read (0.6.16):
  `<clientSecret>…</clientSecret>`, `<AccessToken>…</AccessToken>`, a short value
  (`label-secret-literal`, 8 characters and more); and a quoted key of 12 characters and more
  after a weak label (`hmac`, `session`, `cookie`, `psk`, `salt`, `seed`, `otp`, `key`,
  `appKey("…")`, `<key>…</key>`; `label-weak-key`). The value must have few word letters and a
  high entropy for its alphabet (a charset-normalised entropy, after Dan Szymkowiak's backlog
  idea). A key is ASCII. A label that names something else stays text: `public_key`,
  `cache_key`, `primary_key`, `object_key`, `idempotency_key`, `csrf_token`, a hex value after
  `key` and any value after `nonce`, `x-amz-signature` or `x-amz-credential` (but not after
  `x-amz-security-token`).
- A TOTP or HOTP seed after a one-time-password label (0.6.16, `label-otp-seed`): 16 to 64
  base32 capitals after a label with `totp`, `hotp`, `otp`, `mfa`, `2fa` or `authenticator`
  (`TOTP_SEED=…`, `otp_seed: …`). A code of digits, a word, a constant name and a mask stay
  text.
- The STS session token of temporary AWS credentials (0.6.16, `label-aws-session-token`): the
  value of `X-Amz-Security-Token` in a presigned URL (percent-encoded) or a header, 100 to 4096
  characters. The other `X-Amz-` parameters stay text: the key id in `X-Amz-Credential`, the
  signature, the date.
- Four token formats with a public prefix that the vendored rulesets lack (0.6.16): the third
  NTLMSSP message in base64 (`Authorization: NTLM TlRMTVNTUAAD…`; the negotiate and challenge
  messages carry no password-derived response and stay text), a NATS nkey seed (`SU…`, 58
  characters of base32), a PASERK secret, local or wrapped key (`k4.local.…`, `k4.secret.…`)
  and a PASETO token (`v4.local.…`, `v4.public.…`). A public nkey and a PASERK public key or
  key id stay text. A PASERK key ends at its last base64url character, never on a period of the
  sentence around it.
- Order: the rules that read a label and a literal value (`label-pw-literal`,
  `label-secret-literal`, `label-weak-key`, `label-otp-seed`) run after every other rule and
  take only a span no other rule took. The list rule, the four token formats, the
  Elasticsearch `ApiKey` rule and the AWS session token rule are own secret rules: they take
  their spans in the secret stage, before detect-secrets and betterleaks.
- Prefixes newer than the vendored rulesets live in
  `maisecrets/detection/rules/prefixes.txt`, one line each, extended by pull request
  (`CONTRIBUTING.md`): `glrt-`, `gldt-`, `whsec_`, `cfut_`, the last two
  found bare in real prompts on 2026-09-26, and since 0.6.19 Google OAuth
  access tokens (`ya29.`), Tailscale keys, Discord webhook URLs, Salesforce
  refresh tokens, Cloudflare `cfk_` and `cfat_`, HubSpot private app tokens,
  New Relic `NRAK-`, `NRII-`, `NRRA-`, `NRAA-`, `NRIQ-` and `px-api-`, Claude
  Code OAuth tokens (`sk-ant-oat01-`, `sk-ant-ort01-`), Flutterwave, Doppler,
  Square `sq0csp-`, Contentful, Mapbox `sk.`, Kong Konnect, SonarQube Cloud
  `sqco_`, Adafruit IO and TestPyPI tokens. A Telegram bot token, a Mailchimp key and a Discord bot
  token (its first part must decode to a user id) have no fixed prefix and are
  own rules. A client id such as Salesforce `3MVG9` or Square `sq0idp-` is
  public and stays text.
- A secret shape with a fixed length (betterleaks: `glpat-[\w-]{20}`) is
  extended to the end of the token characters, so a longer token does not
  leave its tail in the clear (found with a 24-char token, 2026-09-26).
  The extension stops at a line break: a token that a line break splits
  (a hard-wrapped terminal line) keeps the part after the break in the clear.
  Joining the next line was measured on five months of session logs and left
  out: nearly every candidate was the next `.env` line, not the rest of a key.

- Personal data after a label or in a fixed form (0.6.21, `maisecrets/detection/personal.py`), in a tool
  result or a file only: a name after a name label (`patient:`, `tenant:`, `full_name:`, `FN:`,
  `Ansprechpartner:`; after the weak labels `name`, `owner` and `author` only a value that does not
  read as English words or nouns, so `name: Customer Portal` stays text), a name before an e-mail
  address (`First Last <mail>`, not before a bot or a service mailbox), a date after a birth label
  (`DOB`, `Geburtsdatum`, `né le`, `fecha de nacimiento`; not after `born`), an ID number of five
  digits and more after an ID label (`MRN`, `passport no`, `DL`, `SIN`, `TFN`, `NIR`, `tax id`,
  `account number`), the user in `user:password@host` and in another person's home path
  (`/home/<user>/`, `C:\Users\<user>\`; service accounts and your own user name stay text), a
  street address with its postcode in the form of an active region (US, UK, IN; DE, AT, CH; FR,
  BE, LU; PT, BR, ES, IT; an address next to a company, office or landmark word stays text; when a
  legal form such as `GmbH`, `AG`, `Ltd` or `Inc` ends the company's name right before the address,
  its German postcode and a German VAT ID right after it stay text too; a person's name or record
  key nearby, an employer or job label, a second address, a sender's VAT label or a blank line keeps
  them masked, and so does a sole trader, who has no legal form), and
  the cells of a CSV column for personal data (`address`, `dob`, `phone`, `ssn`, and a name or user
  column beside one of them; an address or a phone cell only in a row that also names a person). A
  typed prompt takes none of them: a hit blocks a prompt, and a
  person who types a name means to send it. Documentation names (`Erika Mustermann`, `John Doe`)
  stay text. `tests/fp_corpus_pii.py` holds 367 developer texts in these shapes that are no
  personal data (Kubernetes YAML, package authors that are teams, company addresses, dates that
  are no birth dates); the rules leave all of them alone.
- A phone number with one-digit groups after the country code (`+1 4 1 5 …`, 0.6.21): in a tool
  result, and in a typed prompt after a phone word; a US number in the national form
  `(312) 846-2291` after a phone word with region `us` or `ca`, in a tool result only (an area code
  and an exchange start with 2 to 9; the fictional 555 exchange stays text).
- Three token forms with a tail shorter than the vendored rules want (0.6.21): an OpenAI or
  Anthropic key (`sk-proj-`, `sk-ant-`, `sk-svcacct-`, `sk-admin-`; the tail needs a digit, a capital
  and a run of 16 letters and digits, so a CSS class such as `sk-admin-` and a long name stays text),
  a Slack token (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-` with digits and a hyphen first), and a Twilio
  Account SID (`AC` and 32 hex digits) next to its name; a counted fixture (`AC0123456789abcdef…`)
  stays text.

IBAN, credit card and IP come from Presidio's regexes with our validators
(mod-97, Luhn, public-range check). An IBAN may have spaces or hyphens
between its groups; an IBAN in lower case also needs the length of its
country. A card number without a word like "card", "Karte", "Kreditkarte",
"carte", "carta" or "tarjeta" nearby is not reported: Presidio scores the bare
shape low, and a 16-digit number passes Luhn one time in ten.

Measure what the rules would catch on your own recordings, values never
printed: `scripts/replay_sessions.py --claude --codex`.

## Rules of your own

**For administrators.** To give each machine of a team the same rules:

1. Run `maisecrets rules init DIR` (in the plugin folder: `bash hooks/run.sh
   rules init DIR`). It makes a team folder with `rules/`, `samples.txt`, a
   README and CI files for GitHub and GitLab.
2. Keep the folder in a repository of the company. Its CI runs `maisecrets
   rules check` on each change.
3. Put the folder on each machine. A git checkout that a scheduled job updates
   is one way.
4. Add the local path to `rule_dirs` in the machine policy ("Settings you can
   enforce"). A user cannot remove a folder of the policy.
5. On a machine, run `maisecrets rules check` to see that each folder loads.

maisecrets reads local folders only. It does not fetch or update a folder: how
the files get to each machine is the company's choice. When a folder of
`rule_dirs` is missing or cannot be read, each session start says so in one
sentence. When rules of your own run, the start line counts them: `maisecrets
0.6.N is on, with 12 rules of your own from 2 folders.`

You can add detection rules for the tokens of your own services, and you can
let single values through. maisecrets reads the rules from three places:

- `~/.maisecrets/rules.d`, your own folder. The AI cannot write there.
- each folder of the setting `rule_dirs`, for example a checkout of your
  team's rule repository. Type the change as your own prompt:

  ```
  /maisecrets:settings rule_dirs add ~/src/team-rules
  maisecrets: set rule_dirs add ~/src/team-rules     (the same, and the form for Codex)
  ```

  `remove` takes a folder off the list. Like every setting, only your typed
  prompt changes it (C22). When the folder has a subfolder `rules/`, as a
  team repository from `maisecrets rules init` has, maisecrets reads that
  subfolder; else it reads the folder itself. A folder with no rule file
  gets a note when you add it and in `/maisecrets:rules`.
- each folder of `rule_dirs` in the machine policy. You cannot remove those.

A folder holds three kinds of file, and maisecrets reads nothing else from it
(no symbolic link, no git metadata):

- `*.json` in the gitleaks form: `{"rules": [{"id": …, "regex": …,
  "keywords": […], "entropy": …, "secretGroup": …, "allowlists": [{"regexes":
  […], "regexTarget": "secret|match|line", "stopwords": […]}]}]}`. An optional
  `"type"` (`SECRET`, the default, or `NAME`, `EMAIL`, `PHONE`, `IBAN`, `CARD`,
  `IP`) sets the placeholder type. An allowlist with `"condition": "AND"`
  and more than one part is dropped (the stricter side), and
  `/maisecrets:rules` says so.
- `*.prefixes`, one rule per line, `id  regex`, as in
  `maisecrets/detection/rules/prefixes.txt`. The whole match is the secret.
- `*.terms`, a team term list with a floor against common words (Terms). Not
  in `rules.d`: your own list is `~/.maisecrets/terms.txt`.

A hook reads these files in every call, so each rule passes checks when it is
loaded: a keyword or a literal of at least 4 characters, at most 300
characters of regex, at most 500 rules, 200 files and 1 MB per folder (the
first 2000 entries and 2000 rules of a folder are looked at, refused ones
included), 64 KB per file, and an id that no earlier rule of the same folder
has. A rule whose id a rule of an earlier folder has runs as `<id>#2`, so one
folder cannot take a rule of another folder out by its id; `rule: user:<id>`
in the allow list switches both off. The regex must not backtrack: no repeat
inside a repeat (`(a+)+`), no repeat of something that can be empty
(`(a?){25}`), no branches that start alike inside a repeat (`(a|aa)+`), no two
repeats in a row that take the same characters (`.*.*`, `\w+\d+`), no
backreference, and no quantifier of variable length at the start (`\w+…`,
`x?[a-z]+…`). Then maisecrets times each new rule once on test texts that make
a backtracking regex slow, also on runs of the characters its own repeats take
and on its literals, those of each branch too, repeated before long runs; a
rule slower than 50 ms on the texts of one start is left out. A new rule runs
only after this timed test: when a hook call has no time left for the test,
the rule waits for the next call, and `maisecrets rules check` times every
rule at once and keeps the result for the hooks. A rule that is still slow in
a real scan (more than half a second inside its regex in one hook call) is
left out from the next call on. When a hook runs out of time, the rule of your
own with the most regex time is left out, if that time is more than half of
the call. Each verdict is kept by a hash of the rule in
`~/.maisecrets/.rules-state`, so a hook pays for the checks once. A changed
rule is checked again; a rule that a real scan found slow stays out until you
change it, and `maisecrets rules check DIR` shows it.

A rule that fails a check is left out, with its reason; the rest of the file
still loads. A refused rule is named by its place (`rule 3`, `line 7`), never
by its text: a refused line can be a pasted value. A broken file or folder
never stops a hook and never costs the rules of another folder. The session
start names a new failure once, and `/maisecrets:rules` shows each folder,
its rule count, a hash of its files, and each rule that was left out. Your
rules run after every built-in rule, the personal-data rules too, so a rule
of your own never cuts a part out of an e-mail address or an IBAN; a hit
carries the id with `user:` in front (`user:acme-token`).

`maisecrets rules` (in the plugin folder: `bash hooks/run.sh rules …`) does
the rest:

```
maisecrets rules list [--json]      every rule in scan order: key, id, origin, rank, channel, region, class, upstream, patches
maisecrets rules check [DIR]        each rule: ok with its time, slow, or refused with the reason; exit 1 on a problem
maisecrets rules test [text]        what the rules find in the text or stdin: type, rule, place, length
maisecrets rules init DIR           a team folder: README.md, rules/, samples.txt, CI for GitHub and GitLab
maisecrets rules import FILE.toml   a gitleaks or betterleaks config in the JSON form (Python 3.11+)
```

`rules check` also reads `samples.txt`: a line `hit <rule-id> <text>` must be
found by that rule, a line `miss <text>` by no rule of the folder. A failure
names the line, never its text. Without a folder, `rules check` checks every
folder the hooks read, and a missing folder of the setting or the policy is a
failure too. The CI files of `rules init` take maisecrets from its newest
release, so CI runs the checks that the hooks of your team run; for a fixed
version, write `--branch v0.6.N` there. `rules import` leaves out a rule with a
filter it cannot read and a rule that fails a check, and says which.

**The allow list.** `~/.maisecrets/allow.txt` lists what is not a hit, one
entry per line, `#` for a comment:

```
# my own address in every git log
name@my-company.example
rule: phone
```

A line is one exact value: the value with nothing before or after it is not
reported, a longer value that contains it still is. An allowed domain does
not let through the e-mail address that ends in it. `rule: <id>` switches a
rule off (`rule: user:acme-token`, or a built-in id from
`maisecrets scan`). An entry is never a pattern. An administrator puts the
same lines in `allow` of the machine policy. A folder of `rule_dirs` carries
no allow list: the AI can write a shared checkout, and the AI may only make
detection stricter. A value that is already stored stays redacted by its
exact match; `/maisecrets:forget` deletes it.

## PDFs and images

maisecrets cannot look inside an image or a PDF. When the AI reads one, the
client sends its bytes to the model, and a password or an address in it goes
along. You decide what happens, per type:

| Setting | `allow` (default) | `ask` | `block` | `convert` |
|---|---|---|---|---|
| `read_pdf` | the PDF goes as it is | Claude Code asks you first | refused | only its text goes, masked |
| `read_image` | the image goes as it is | Claude Code asks you first | refused | (no: maisecrets does no OCR) |

Send one setting as your own prompt, for example:

```
/maisecrets:settings read_pdf convert
maisecrets: set read_pdf convert          (the same, and the form for Codex)
```

Then ask the AI to read a PDF (measured with the Claude Code CLI). With
`convert`, the program `pdftotext` extracts the text on your computer, the
normal redaction masks it (as a tool result, so also a password after a
label and a value in a disguise), and the model gets that text in place of
the PDF, with placeholders of the form `⟦SECRET_cN⟧`. The PDF itself never
reaches the model and does not stay in the session transcript. A page range
(`pages`) works; Claude Code then also writes the pages as JPG files into a
folder of its own on your disk, and maisecrets does not clean those.
`convert` needs `pdftotext`: macOS `brew install poppler`, Debian or Ubuntu
`sudo apt install poppler-utils`.

maisecrets runs `pdftotext` only from the fixed install folders
(`/opt/homebrew/bin`, `/usr/local/bin`, `/opt/local/bin`, `/usr/bin`), never
from the PATH: a program the AI puts on the PATH must not run inside the
hook. Every folder from `/` down to the program, and down to each library
the program loads, must belong to root or to you. No other account may be
able to write it (also not through an access control list), except a group
whose members can become root anyway:
`admin` and `wheel` on macOS, `sudo` on Debian, `sudo` and `admin` on
Ubuntu, `wheel` on Fedora and its relatives (the default sudoers of each,
measured 2026-10-14). So a second admin account on a Mac no longer stops
`convert`. maisecrets reads the libraries itself (33 for Homebrew's
pdftotext of poppler 26.10.0; `ldd` on Linux), and it does not run a program
whose libraries it cannot name. It starts pdftotext without `LD_*` and
`DYLD_*` variables. The Homebrew folder belongs to you, and the AI runs as
you: it could still replace the pdftotext there or a library, and maisecrets
cannot tell. maisecrets keeps values out of the model and the transcript; it
does not contain an agent that works against it on purpose. On Windows there
is no such folder, so `convert` refuses there. Without pdftotext, maisecrets
refuses every PDF and says so; it never lets the PDF through.

A PDF that pdftotext cannot read in 6 seconds, that makes pdftotext use more
than 512 MB of memory, or that is damaged, is refused. A PDF locked by a
password is refused too, and the AI is told that cause and not to ask you
for the password; save a copy without the password and give the AI that
copy. A PDF with only an owner password (it opens without one and limits
printing or copying) converts, AES-256 included (measured with poppler
26.10.0). A crafted PDF of a few
MB can make pdftotext take 1.5 GB in 2.4 seconds: maisecrets watches the
memory of pdftotext every 50 ms while it waits and stops it there (macOS does not
enforce a memory limit on a process, measured; on Linux the kernel limits
it to 1 GB as well). Text after 32K characters is cut, and the AI is told to
read a smaller page range. A scanned PDF has no text, or only page numbers
or a header line: below 25 characters of text per page, maisecrets says that
the PDF looks scanned, and the AI gets nothing of it.

**Measured on 2026-10-14** (Claude Code 2.1.300, poppler 26.10.0, a corpus
of 24 generated PDFs with 168 planted values): pdftotext found 151 of the
values, pypdf 136. pypdf failed on text written one character at a time and
on form fields, has no time limit (one page took 14 s on Python 3.14, 47 s on
3.9) and needs `typing_extensions` on 3.9, so maisecrets keeps pdftotext; a
bundled pypdf stays an option for Windows later. pdftotext missed a page
rotated by 90 degrees (that page counts as scanned) and two values whose
label stood in the table cell beside them. How a PDF reaches the model: "read x.pdf" and a pasted path go
through the Read tool, and the hooks see the file; `@x.pdf` gives the model
only the name and the size, and the model then calls Read itself. No route
that was measured passes around the hooks. The interactive terminal UI was
not measured.

Until you decide, the first PDF and the first image the AI reads bring one
sentence about the setting (`"tips": false` silences it). If `config.json`
cannot be read (bad JSON, a value of the wrong type), both settings count as
`block` until you fix the file.

**What `block` stops, and what it does not.** The settings act on the Read
tool of Claude Code: `block` means "the Read tool does not open this PDF or
image". They do not stop a shell command that reads the file: `pdftotext
x.pdf -`, `strings x.pdf` or `cat` give the AI text, and maisecrets redacts
that text like any other command output (a secret with a known form is
masked, the rest of the text is not). maisecrets is no file cleaner and does
not refuse such commands.

**Codex.** Codex has no Read tool, and it gives a hook a command's output as
plain text without an image flag (measured on codex-cli 0.159.2). So on
Codex these settings change nothing that was measured: its `view_image` tool
is not measured, and a command output there is scanned as text, like every
other output. The typed form `maisecrets: set read_pdf …` still works and
holds for a later Claude Code session.

`clean_dirs` lists folders whose PDFs and images you know are clean (your own
screenshots, for example). A read there is allowed:
`/maisecrets:settings clean_dirs add ~/Pictures/Screenshots`, and `remove` the
same way. maisecrets resolves links and `..` first, so a link inside a clean
folder that points out of it does not count. A file counts only if it was in
the folder before the session began and has no second name (hard link): a
file that arrives during the session, also one that the AI copies, moves or
links there, waits for the next session. maisecrets refuses `/`, your home
folder, a folder that holds the folder the session works in, and a folder
that is a link or lies under one (add the real folder). The folder itself is
noted with the session: another folder moved or linked in under its name does
not count, and neither does a subfolder moved in during the session. The start of
the session is a note that maisecrets writes at the session start, never
later; without the note nothing in the folder is clean. A client that the AI
starts inside its own session (`claude -p` from its shell) trusts no clean
folder. `clean_dirs` works on macOS and Linux; on Windows no file in it counts
as clean, because there a moved file keeps its creation time.

With `ask`, a file goes to the AI only after you said yes to that very read: a
file that was not asked about (it was in a clean folder a moment before, or a
notebook got an image after the question) is withheld. maisecrets also keeps a
checksum of the file you allowed (and of a file in a clean folder) and checks
that the AI gets those very bytes. A file above 64 MB cannot be checked: it is
never clean, and with `ask` maisecrets refuses it before it asks you. For a
large image that Claude Code shrinks, a page range of a PDF and a notebook,
the client sends no copy of the file itself; maisecrets then checks the size
and the file as it is after the read, which leaves a short window.

A Bash command whose output starts with `data:image/…;base64,` sends an image
to the model too (Claude Code shows it as one and marks it `isImage`);
`read_image` decides about it. Only the image itself skips the scan: the
error output of the same command is redacted as usual. `ask` cannot ask
after the command ran, so it withholds the output, like `block`.

A notebook (`.ipynb`) whose output cells hold an image: with `ask` Claude
Code asks you first, and with `block` the AI gets the cells as text and each
image as a note that it was withheld. The cells are always redacted; the image
data is not scanned. Claude Code itself drops the outputs of a notebook when
they are large (measured on 2.1.296: an image of about 8 KB or more): the AI
then reads only a note to run `cat <notebook> | jq '.cells[0].outputs'` in
Bash, and that output is text, which maisecrets redacts like any output.

**Not covered:** an image you paste into the prompt (Ctrl+V or drag of an
image into Claude Code) reaches the model without passing any hook; the
prompt hook sees only your typed text. maisecrets cannot stop or mask it. An
image in the result of an MCP tool is not covered either.

## Terms: names, case numbers, customer names

A name has no shape, so no rule finds it. Tell maisecrets the names you keep
from the AI, and it masks them like a secret. The design is based on the
personal-terms design by [@danszymkowiak](https://github.com/danszymkowiak):
his file form, his match modes, and his rule that no message shows a term.

**Add a name.** Type it as your own prompt:

```
/maisecrets:term add Jan Kowalski
maisecrets: term add Jan Kowalski          (the same, and the form for Codex)
```

maisecrets writes the name to `~/.maisecrets/terms.txt` and does not send the
prompt to the model. From the next tool result on, `Jan Kowalski` becomes a
placeholder such as `⟦NAME_c3⟧`.

When you add a name of two or more words, maisecrets also adds the last word
alone and its genitive (`Kowalski | Kowalskis`), if it has 4 letters or more
and is not a common word. So `Herr Kowalski`, `Kowalskis Bericht`,
`Kowalski, Jan` and `J. Kowalski` are masked too. It adds them as whole words,
never as a stem with `*`: `Koch*` would mask `Kochen`, `Lang*` would mask
`language`. Type a stem yourself when you want one (`Kowalsk*`). A surname that
is also a word (`Jobs`, `Wolf`) is masked where it stands alone as that word. The joined forms `jan.kowalski`,
`Jan-Kowalski` and `jan_kowalski` (also in `jan_kowalski.pdf`) are masked as
one word. The first name alone stays visible: `Jan` is a common word, and
masking it would hide every other Jan. To mask it anyway, add it as a term
of its own. The answer to the command says what maisecrets added. A typing
error such as `/maisecrets:terms add …` or `maisecrets term add …` is not
sent to the model either: maisecrets shows the correct form.

A name inside a value that maisecrets stores never splits it. A password such
as `Kowalski#Lato2024` stays one value: it is masked whole, in the prompt and
in every later tool result, and never as a name with the rest in clear.

`/maisecrets:term remove Jan Kowalski` (or
`remove ⟦NAME_c3⟧`, the placeholder copied from a result) takes it off.
`/maisecrets:term` alone shows your lists. Only your typed prompt changes the
list, as with a setting (C22): a removal in a tool call is refused.

**Mark a name once.** Write `{{Jan Kowalski}}` in a prompt. maisecrets masks
the name in that prompt and in every tool result until the lifetime of a
name value ends (`ttl_seconds`, one day by default); it does not write
`terms.txt`. A marker is 1 to 5 words of letters (a hyphen or an apostrophe
inside a word), and one word starts with a capital letter. So
`{{ .Values.image.tag }}` and `{{ item }}` stay text, and so do one letter
and one common word alone (`{{A}}`, `{{The}}`). One word alone with a space
inside the braces or with a capital inside it (`{{ Title }}`,
`{{FirstName}}`) is the form of a template and stays text; mark a one-word
name such as `{{McDonald}}` with `/maisecrets:term add`. A name of two or
more words is marked in any of these forms (`{{Ronald McDonald}}`,
`{{ Jan Kowalski }}`). A marker counts only in a
prompt that you typed at the composer or over Remote Control, not in one that
a program or a subagent sent.

**The file.** `~/.maisecrets/terms.txt` holds one entity per line: a label,
then the variants, separated by `|`. `#` starts a comment.

```
# label      variants
PERSON_A     Jan Kowalski | Kowalsk* | Jan
CLIENT_B     Acme Holding | *acme-0042*
EMAIL_BOSS   boss at work
```

| variant | matches | does not match |
|---|---|---|
| `Jan` | the whole word: `Jan`, `Jan,`, `(Jan)`, `Jan's` | `January`, `Jan2`, `jan_report` |
| `Kowalsk*` | a word that starts so: `Kowalski`, `Kowalskiego`, `Kowalski_report` | `Nowakowalski` |
| `*kowalski` | a word that ends so: `Kowalski`, `JanKowalski` | `Kowalskiego` |
| `*acme-0042*` | the text and the letters, digits and `_` around it: `xacme-0042b` whole; in `x-acme-0042-b` and `acme-0042@example.com` the part `acme-0042` | none |

- Case does not matter (`ŁÓDŹ` matches `łódź`). A space in a variant matches
  any run of whitespace, also a line break. Other characters are literal.
- Composed and decomposed letters match alike (a macOS file name holds
  `Mu` plus a combining diaeresis for `Mü`), and a soft hyphen or a
  zero-width character inside a name does not hide it. A spelling with other
  letters does not match: `MUELLER` is not `Müller`, `GROSSMANN` is not
  `Großmann`, and fullwidth letters (`Ｍüller`) are not `Müller`. List such a
  spelling as a variant of its own.
- Two names that overlap (`Anna Maria` and `Maria Kowalski` in
  `Anna Maria Kowalski`) become one placeholder.
- A word is a run of letters, digits and `_`. So `Kowalski_report.pdf` is one
  word: `Kowalski` does not mask a part of it. Write `*kowalski*` to mask
  file names too.
- The longest variant wins: `Jan Kowalski` is one hit, not two.
- All variants of an entity get the same placeholder. The type is `NAME`,
  or the type in the label (`EMAIL_BOSS` gives `EMAIL`).
- A stem before or after a `*` needs 3 letters or digits, a `*…*` variant 4
  characters. maisecrets uses at most 50 `*…*` variants in all the lists: the
  51st stops your own list with its line, and a team list leaves it out and
  names it.
- The file must be private. If others can read it, maisecrets sets it to
  `0600`. If a line is wrong, every hook fails closed and the message names
  the line, never its text. Fix the line, and the next hook works. Only you
  write this file, so a silent skip would let through exactly the names you
  listed.

**A team list.** Put a `*.terms` file in a folder of `rule_dirs` (Rules of
your own; in its subfolder `rules/` when it has one, as for the rules). The AI can write a shared checkout, so a team list has a floor: an
entry of fewer than 3 characters, an entry of only words of
`maisecrets/rules/term_stoplist.txt` (1,134 words: the 521 words of the closed
word classes of English and German, and the words that 8 or more files of
this repository use, as the common words of a developer session; a small
list on purpose, not a dictionary), a `*` with a stem of
fewer than 5 letters (`ret*`, `*ing`), and a stem that 3 or more words of
that list share (`*ation*`), are left out. A line
that fails is left out with its reason; the rest of the file loads, and a bad
team file never stops a hook. The session start says when a team list
changed. `/maisecrets:rules` and `maisecrets terms` show the counts, the
files and each line left out, never a term. All the team lists together
can be up to 4 MB and 150,000 entries. A variant that an earlier entry holds
(your own list first) is left out, and at most 16 team variants share one
stem or first word: a list cannot make each word of a text walk thousands
of entries. These caps count the team lists together, in the order of
`rule_dirs` (the folders of the machine policy first): a list that the AI
can write can use them up and push out a list after it, as it can also
delete lines of its own folder. The lines pushed out are named in
`/maisecrets:rules`. A `*.terms` file that is a symbolic link is not read.

**Where the terms run.** The terms are a pass of the rule registry, after
the built-in rules and the rules of your own; `maisecrets rules list` shows
the pass as `terms:term`, with its own origin and class (`term`). It is one
index of every list, not a rule per term: its cost does not grow with the
number of terms. A hit says where it came from: its kind is `term:<id>` in
`maisecrets scan` and in the store, never the term. So an email address or an IBAN keeps the span its
rule found. A listed term that a rule finds too (an email address on your
list) gets the rule's type, but it stays a term: mask only. An exact value on
your allow list (`~/.maisecrets/allow.txt`) stays allowed, also when a term
list names it: both are yours, and the allow list is the narrower one.

**Not in a PDF or an image.** The matcher reads text. A name inside a PDF, an
image or another binary file that a tool reads reaches the model as it is.

**Mask only.** maisecrets never puts a name back. A term placeholder in a
command, an MCP argument or a file that the AI writes stays as it is: a
letter that the AI drafts holds `⟦NAME_c3⟧`, and you put in the name. The
store holds no term: one entry per entity, with an id, so the placeholder
stays the same across documents and sessions while the entry lives.

**Find the names in a document.** `maisecrets terms suggest FILE` (in the
plugin folder: `bash hooks/run.sh terms suggest FILE`) proposes lines for
`terms.txt` from a text or CSV file: names after a salutation, after
`Name:`, in a name column of a CSV file, and pairs of capitalised words. If
a surname comes in two or more endings, it proposes the stem
(`Kowalski | Kowalski*`). It never prints a name, not in a terminal either:
an AI can open a pseudo-terminal and read it. It writes the proposal to
`terms.suggested.txt` in the maisecrets folder (mode `0600`; the AI cannot
read that folder) and prints the count and the path. Open the file yourself,
and copy the lines you want into `terms.txt`. Nothing is added to your terms.

**Cost.** Without any list, maisecrets does not load the terms code: a hook
costs what it cost before (measured, `docs/BENCHMARKS.md`, "Terms"). With a
list, a hook pays a fixed amount for the module and the index, and the cost
does not grow with the number of terms. maisecrets keeps an index of the
lists in `~/.maisecrets/.terms-cache`.
With 100,000 entries a new hook process loads it in about 30 ms and scans
10 KB in 3 to 10 ms (measured on Python 3.9 and 3.14).
After you change a list, maisecrets builds the index again at the next
session start, or right after `/maisecrets:term add` or `remove`, so a tool
hook only loads it. Measured for 100,000 two-word entries (3.8 MB): 1.4 s on
Python 3.14, 2.2 s on Python 3.9. If a team list changes while a session
runs, the next hook builds the index.

## Values from your own tools

Your own tools often know values that maisecrets cannot find by their
shape: a NER finds the names in your case files, an export lists your
customers, a script knows the internal account ids. Give maisecrets those
values, and it masks them wherever they appear.

**The file.** Your tool writes one JSON object per line:

```
{"value": "Jan Kowalski", "type": "NAME"}
{"value": "jan.kowalski@example.org", "type": "EMAIL"}
{"value": "a value without a shape"}
```

`type` is one of `SECRET`, `NAME`, `EMAIL`, `PHONE`, `IBAN`, `CARD`, `IP`
(`SECRET` when it is missing). It names the placeholder, nothing else.
maisecrets reads only `value` and `type`; it ignores every other field.

**Import it.** Two ways:

- In a terminal: `bash hooks/run.sh values import FILE` (in the plugin
  folder). It prints the id of the import and its counts, and the number and
  reason of each line it refused. It never prints a value or the file name.
- As a setting: `/maisecrets:settings value_files add ~/work/ner-out.jsonl`
  (type it as your own prompt). maisecrets imports the file at each session
  start when its content changed.

maisecrets copies the accepted values to
`~/.maisecrets/imports/<id>.jsonl` (mode `0600`; the AI cannot read that
folder, C8). Each import has an opaque id such as `import:v1a2b3c4d`, never
the name of the file: a file named like one of its values would show that
value.

**What is masked.** From the next prompt and tool result on, each value is
masked in any case and with any spacing, also as a phrase of several words
across a line break (`Jan\n  KOWALSKI`), in composed or decomposed Unicode,
and with a soft hyphen or a zero-width character inside it. The match is on
whole words, as for a term (Terms, above): `Kowalski` does not mask a part of
`Kowalskiego`. The placeholder has the type of the line, for example `⟦NAME_c3⟧`.

**Where the imports run.** The imports are a pass of the rule registry,
after the terms (`maisecrets rules list` shows it as `imports:import`, origin
and class `import`). It is one index of all imports, not one rule per value.
A hit names its import: its kind is `import:<id>:<value id>` in
`maisecrets scan` and in the store. The store keeps these ids, never the
value.

**Mask only.** maisecrets never puts an imported value back. An import
placeholder in a command, an MCP argument or a file that the AI writes stays
as it is.

**An import only adds.** maisecrets follows the rule of this epic: the AI can
make detection stricter, never weaker.

- A new import of the same file adds its new values to the same import. A
  value that the file no longer lists stays. An edit of a value file that
  removes lines removes no value. Each import keeps every value it lists,
  also one that another import holds: the removal of one import leaves a
  value masked while another import lists it.
- An import of a file by a command and the import of the same file as a
  value file are two imports. A command cannot fill the import of your
  value file.
- A value that a rule finds (an email address, an IBAN) keeps the span, the
  type and the placeholder of that rule. A value that the store holds
  already (a password from `/maisecrets:put`) keeps its own placeholder,
  its type and its lifetime, and it still resolves into your commands. An
  import never turns a resolvable value into a masked-only one. Only the
  parts of an imported phrase outside such a value get the import's
  placeholder.
- No field of a line can switch a rule off, allow a value or change a
  lifetime: maisecrets reads `value` and `type` only.

**Only you remove an import.** Type `/maisecrets:forget import:ID` as your
own prompt (in Codex: `maisecrets: forget import:ID`). maisecrets does not
send that prompt to the model. A prompt from a scheduled task, a subagent or
a program that started the client removes nothing. A tool call that carries
the removal is refused, also when quotes, escapes, line continuations or a
PowerShell `+` split it. A removal that a program builds at run time (brace
expansion, an empty variable or `$()` inside a word, a character code,
PowerShell `-join`) is not seen:
the same text-match limit as for a setting (C22), and `values remove` in a terminal only names the
prompt. If you remove the import of a value file, the next session start
imports the file again as it is now (also when you removed it in another
session). So to drop a few values from a value file, edit the file, then
remove its import.

**What you see.** `/maisecrets:list` shows each import: its id, the number of
values per type, its age, and whether it came from a value file or a
command. It never shows a value. The session start names each new import
once, with its id and count, also an import that the AI ran.

**Who may write the file.** The AI may run `values import`, and it may write
a value file that lies in a folder it can write (a repository checkout).
That is allowed, because an import can only add masking. The worst an import
can do is to mask too much. These limits hold that:

- A value needs at least 4 characters. A value of only digits needs at
  least 6. maisecrets refuses one word of lower-case letters, a value of only
  common words (the stop list of the team terms,
  `maisecrets/rules/term_stoplist.txt`), and a value that holds a placeholder
  bracket, a placeholder key (`SECRET_c1`), `maisecrets`, `import:` or the
  name of a setting (`value_files`). So no import can break a placeholder
  or mask your own controls. Also, maisecrets never rewrites a settings
  prompt or the ssh grant sentence: the hook reads them first.
- The floor does not know every ordinary word. A capitalised word such as
  `Pipeline` passes, and the match ignores case, so an import can mask such
  a word in every text. That masks too much, never too little; the session
  start names each new import, and you remove it.
- One import holds at most 100,000 values, and all imports together at most
  150,000. The imports that no value file names (the imports of a command,
  which the AI can run) hold at most 100,000 of them, so your value files
  always have room. maisecrets holds at most 50 imports, of which at most 30
  are imports of commands: 20 places stay for your value files. Only a file
  in your setting `value_files` counts as a value file. One file is read to
  at most 200,000 lines, and one import file holds at most 24 MB. Past a cap, the import stops, says at which
  line, and names the prompt that removes an import. A value file in a
  folder that the AI can write counts as your value file: the AI can fill
  the caps through it, and push out a value file after it.
- maisecrets opens the file once, without following a symbolic link and
  without waiting on it, and checks the opened file: it must be a regular
  file (not a FIFO or a device), owned by you (or root), and not writable by
  every user. Then it reads it once, up to 8 MB. So a file that is swapped
  between a check and the read, a FIFO, and a file that grows while it is
  read all fail or stop at the limit. Windows has no open without a link:
  there maisecrets refuses a link one step before the open. A line that a writer has not finished
  is not valid JSON, so maisecrets refuses that line by its number and
  imports the rest.
- A damaged import in the maisecrets folder stops every hook (fail closed),
  and the message names the prompt that removes it. So does a `*.jsonl`
  file in `~/.maisecrets/imports` that no import id names.

**Not in a failed tool call.** When a command fails (a non-zero exit code),
Claude Code sends its output to the model before maisecrets sees it, as for
every other value (C2). An imported value in that output reaches the model.
maisecrets masks it in the transcript afterwards. A PDF or an image is not
read either, as for the terms.

**Cost.** Without an import, maisecrets does not load the import code: a hook
costs what it cost before (measured, `docs/BENCHMARKS.md`, "Values from your
own tools"). With an import, a hook loads one index from
`~/.maisecrets/.values-cache`. maisecrets builds the index after each import
and at session start, so a tool hook only loads it.

## Vault references

An MCP server can mask a value in its result, for example a customer's e-mail
address, with a token such as `⟦EMAIL_1:ma•••@example.org⟧` (no `c`: the server
made it). Without maisecrets, a file that the AI writes from that result holds
the token. With maisecrets and a server that supports vault references, the
file holds the real value, and the AI still sees only the token.

How it works (`docs/PROTOCOL.md` section 4):

1. Until an MCP server that you added yourself (user scope, an `https` URL)
   sends such a token, maisecrets asks no server and writes nothing into
   the client's config file. Tokens in a Bash output, a file, a web page or from a
   server in a project's `.mcp.json` start nothing.
2. With the first token of that server, maisecrets asks it once for its
   metadata (RFC 9728). Only if the server names a vault endpoint there does
   maisecrets make a random key for it and write a `Client-Vault` header with
   a hash of that key into that server's entry in the config file that
   Claude Code itself uses: `~/.claude/.config.json` when that file is not
   empty, else `~/.claude.json` (both in `CLAUDE_CONFIG_DIR` when it is set;
   the rule of 2.1.301). The other file is then an old copy, and maisecrets
   never reads or writes it. `/maisecrets:status` names the file. It
   changes nothing else in the file and keeps a backup beside it. You see a
   notice once, with one step: type `/mcp reconnect <server name>` (or start
   Claude Code again). The reconnect reads the server entry again, its
   headers included, and every later request carries the header (measured
   with 2.1.302). A server without the field gets no header, and maisecrets
   asks it again at the earliest after an hour.
3. The server links the hash to you when you log in to it. A link that comes
   from an existing login waits a day. The server tells you on its own
   channel; Claude Code does not show a server's notice in the chat
   (measured with 2.1.302). To use it earlier, activate it on the server's
   connections page, or sign in to the server again in the browser. You can
   revoke it there too. After a tool result of that server, maisecrets notes
   the tokens in it. The result does not change.
4. When the AI writes such a token into a file or a Bash command, maisecrets
   asks the server for the values, with the key, and puts them in. It gets all
   values or none. If the server refuses, the call is denied, and the reason
   names the state of the server and your next step (the table below).

`/maisecrets:status` shows the state of each server, with the time of the
last answer. It asks once per server origin that has a key on this
computer (an empty request that can return no value); two entries on one
origin share the key and the answer. At a session start maisecrets asks the
same question once per such origin, within 5.5 s for all, and tells you in
one line when a state changed since you last saw it. The deny reason of a Write, Edit or Bash call uses the same words:

| State | What you do (Claude Code) | In Codex |
|---|---|---|
| not used yet (no server token seen, or the server names no vault endpoint) | nothing | nothing |
| header written | type `/mcp reconnect <server name>` (or start Claude Code again) | start Codex again |
| waiting for activation until `<time>` | activate it on the server's connections page, or sign in to the server again in the browser | the same |
| active | nothing | nothing |
| this key is quarantined (used by two accounts) or revoked | nothing: maisecrets makes a new key at the next start, and you see the header step again | the same, then start Codex again |
| the server's operator switch is off | ask the server's operator | the same |

The server gives the same answer for a quarantined key, a revoked key and a
key it never saw. maisecrets tells them apart only by its own record: a key
that the server once answered as active or waiting is "quarantined or
revoked" now, any other key is "header written". A key that a server bound
and quarantined before maisecrets asked it once reads as "header written".
A revoke alone makes maisecrets make a new key at the next start. To stop
the link for good, turn the feature off: `client_header:
false` (`/maisecrets:settings client_header false`) turns it off (in Codex at
the next connection to the server) and removes
the header again. A server behind a
certificate authority of your own needs `client_vault_cafile`. On Windows a
Bash command gets no server value.

**In Codex** (measured with codex-cli 0.162.0 and 0.155.1) the same steps
hold, with three differences:

- maisecrets writes no header into `~/.codex/config.toml` (or
  `$CODEX_HOME/config.toml`). A repository's `.codex/config.toml` can give
  your server entry another URL: Codex merges it over your file, and it trusts
  a project on its own when its sandbox may write there. A fixed header would
  then go to that URL. So maisecrets adds one line, `http_headers_helper`, to
  that one entry. Codex runs this command when it connects to the server. It
  prints the header only when no `.codex/config.toml` of the folder you work
  in, or of a folder above it, names MCP servers, and only in the first folder
  of that Codex process, within two minutes of its start; else it prints
  nothing. The server needs the header only once, to link your key, so this
  limit costs little: in the desktop app a later chat in another folder sends
  no header until the app starts again.
  maisecrets changes no other byte of the file, does not touch a file that
  does not parse or that lies in a git repository, and keeps a backup in its
  own folder (`~/.maisecrets/vault-refs/`) until the next start that changes
  nothing.
- The values come from the next start of Codex: a new `codex` run sends the
  header, an open session does not (measured with codex-cli 0.162.0). Codex
  shows the notice as a warning of the hook in its terminal UI; `codex exec`
  does not print it.
- In a repository that brings its own MCP servers, maisecrets notes no token
  and sends no header. Codex vault references need Python 3.11 or later
  (`tomllib`), and they are off on Windows in this version. `apply_patch` and
  Bash (macOS, Linux) get the values.

The limit: an AI agent that runs as your user can read the key from the
store, as it can read any stored value. The server's cap, its audit and the
revoke bound that. A value written into a file is plain text there.

## Names from a local service (optional)

The rules find few names: a name has no shape (docs/NER-EXPERIMENT.md). A
named-entity service on your computer can add them in tool results. It is off
until `~/.maisecrets/config.json` names it:

```json
{
  "remote_detector": {
    "url": "http://127.0.0.1:8765/",
    "format": "hf",
    "model": "d3-onnx-fp32@d421f57d",
    "timeout_ms": 300,
    "max_chars": 20000
  }
}
```

- `format`: `hf` (Hugging Face token classification) or `presidio` (Presidio
  Analyzer, `POST /analyze`; `language` sets its language, `en` by default).
- Only names by default (`PER`, `PERSON`). `classes` maps more classes of the
  service to a type, for example `{"PER": "NAME", "LOC": "ADDRESS"}`, and
  `min_score` sets the least score per type. No threshold is set for you.
- `url` must be a loopback address or a Unix socket (`unix:/path/to.sock`).
  Another host needs `"allow_network": true` in the setting, and then your tool
  results go there (PRIVACY.md).
- Tool results only, one request per tool call, within `timeout_ms` (at most
  5000; the name lookup and a slow answer count too). Each value
  the rules found goes out as `_` filler of the same length. The filler costs
  the model a few names (21 of 2,482 on the benchmark samples), so a service on
  loopback or a Unix socket may read those values as they are with
  `"mask": false`; any other host always gets the filler. A slow, dead or
  confused service changes nothing: the rules' result stays as it is. A result
  longer than `max_chars` is not sent.
- A name the service finds is masked and stored, so its placeholder resolves,
  but it is never searched for in other texts: a wrong name such as `Build`
  costs one mask, where the service saw it. If a rule finds the same value
  later and would search for its own finding, the name is searched for from
  then on; a common word after a label stays where it was found.
- `model` is what you state; the answer of either format names no model.
  `examples/ner_service.py` is a reference service with the model of the NER
  experiment and reports its model at `GET /info`. It is an example, not part
  of the plugin.

## Known gaps (measured or documented)

What the plugin does not protect. Each item is a limit of the mechanism, not
a to-do.

- **The output of a command that fails reaches the model as it is (Claude
  Code).** Claude Code reports a failed call through another hook event,
  whose answer cannot replace the output. A value that a failing command
  prints (`grep TOKEN .env` with exit 1, a script that prints its config and
  stops) is not redacted, and it stays in the transcript. Measured over one
  user's transcripts: 14 such outputs with a hit in 105,241 Bash calls over 90
  days, 1 of them a secret. A command that ends in a pipe (`… | tail`) is
  redacted as usual. maisecrets then stores the value (a repeat is redacted),
  cleans the transcript on disk, tells the AI not to use it, and shows you a
  line about it. See the threat model, "What is knowingly not defended".
- **No hook, no protection.** Claude Chat, ChatGPT Chat, the web and the
  mobile apps run no plugin hooks. Cowork does, Claude Code does, Codex does.
- **A client that rejects the manifest loads nothing and says nothing.**
  Claude Code 2.1.223 did so for a manifest key it did not know. Check with
  `/hooks` that maisecrets is listed; the harness checks the debug log.
- **A hook that exceeds the client's timeout fails open** (10 s for the
  prompt hook, 20 s for tool output, set in `hooks/hooks.json`). The plugin's
  own watchdog answers fail-closed before that (7 s, 16 s for tool output:
  block, deny, or withheld output), and a hook that crashes answers the same
  way; Claude Code ignores exit 2 from `PostToolUse`, so the raw output would
  otherwise reach the model. Codex runs the tool anyway when a hook fails, so
  there the watchdog is the only net. On Windows the watchdog can come too
  late: Python has no SIGALRM there, and a detector regex that runs long
  holds the interpreter until it ends, so a hook past the client's timeout
  fails open. A tool result with more than 100 new
  values is masked without storing the rest.
- **Tool output above 50K characters** is spilled to a file by Claude Code
  and is not rewritten.
- **An image or a PDF that Claude reads** goes to the model as a picture or a
  document, not as text. maisecrets does not look for shapes in it: a secret
  in the text of a PDF or in a screenshot reaches the model. Only the exact
  match of your stored values checks its base64 form, and it finds a value
  only where the file holds its bytes uncompressed at an offset that is a
  multiple of 3 (no OCR, no decompression, by design). The same holds for a
  Bash output that Claude Code sends as an image.
- **`@file` mentions** inline a file outside the hook pipeline. The prompt
  hook blocks them when the path exists; ask Claude to read the file instead.
- **A name without a label is not detected, unless it is on a term list** (Terms). Regex only, by design: "Emma Johansson" alone looks like any two
  capitalised words. A name after a name label, before an e-mail address or in a CSV name column is masked
  in a tool result (0.6.21); in a typed prompt no name is detected. A name in a non-Latin script is masked only after
  a person label (`full name`, `native name`, `patient_name`, vCard `FN:`, also with parameters such as
  `FN;CHARSET=UTF-8:`; 0.6.24), not after `name:` or `owner:`,
  which also name products and languages. A street address without a postcode or an address label, or in a form of a
  region that is not active, passes too. Inside a vCard (after `BEGIN:VCARD`), an `ADR` in its fields, an `N`
  and a `BDAY` of eight digits are masked in a tool result, with or without parameters (0.6.25), also when the property
  is folded over two lines. A vCard line without its `BEGIN:VCARD` is masked after a `.vcf` file name (grep output) or
  in the structure of its property: `ADR` in capitals with a parameter of a card (`TYPE=home`, `PREF`) and an empty box
  and extended field, `N` in capitals with its five fields, `BDAY` with a parameter of a card. `adr:`, `n:`, a `BDAY:`
  date alone, a grep context line (`file.vcf-12-`) and a property in lower case folded more than 2,048 characters after
  its `BEGIN:VCARD` are not. The check for a
  company before an address label reads 120 characters of the line: in minified JSON a company address with its
  company word farther back is masked, and a person's address with an employer or a hotel within that reach passes.
  Its postcode stays masked when an employer label, a person's name or a key of a person's record stands near the
  company's name. The other way round, a company's postcode and VAT ID stay masked when a department line stands
  between the company's name and a street and postcode on one line (the address rule then masks the whole address),
  when the department is not a word of the list (Einkauf, Buchhaltung, Accounts Payable), and, in the street and
  postcode on two lines or after `Kunde:`, when the company's name has more than two words: a person's name glued to
  it (`Lena Brückner Lindner GmbH`) reads the same. On one line, after a company word, such a name frees the values
  as in 0.6.26.
  A wider reach was measured and left out, because it lets more home addresses pass (0.6.25).
- **The forms of 0.6.24 act on tool results only.** An ID after `member`, `record` or `account`, an address after
  `Address:`, a FHIR identifier, a `::add-mask::` value, a `SharedAccessKey=`, a Postman variable with a secret name and
  the other forms in `maisecrets rules list` (column "needs": label or form) are masked in a tool result or a file. A
  typed prompt with the same text is not blocked by them. A card number without a card word is masked in a tool
  result only when it is written in groups of four with the prefix of a card network; one run of digits needs the
  word (a float, a timestamp and an IMEI pass the Luhn check as often).
- **A pasted image is invisible to the hooks.** Claude Code gives the prompt
  hook only the typed text (measured on 2.1.296). An image or a PDF that the
  AI reads is in your hands ("PDFs and images"); maisecrets does not scan or
  clean an image, and does no OCR.
- **An image in an MCP tool result passes as it is.** `read_image` acts on
  the Read tool, on a Bash output that Claude Code marks as an image, and on
  the images of a notebook; not on an MCP result.
- **`block` stops the Read tool, not a shell read.** `pdftotext x.pdf -` or
  `strings` give the AI the text of the file; only secrets of a known form in
  it are masked. On Codex the PDF and image settings act on nothing measured.
- **A clean folder trusts the files that were there when the session
  began.** A file you put there yourself during the session waits for the
  next one. The start of a session is a note that maisecrets writes at the
  session start (the client sends no start time). The AI's tools may not
  touch the maisecrets folder, but that guard reads the command text: a
  command that hides the path (built from pieces, `find … -exec`) can still
  move the note and make a copied file count as clean. A client started
  under another program name (an npm install runs as `node`) is not seen as
  nested. Windows: no file counts as clean.
- **A term placeholder is never resolved** (Terms, mask only): a command or a
  file the AI writes keeps the placeholder.
- **A transformed value can pass.** For a value this session resolved, the
  output is checked as a substring in plain, base64, hex, URL-encoded and
  JSON-escaped form, and a resolving command may not encode it in the first
  place. Every other live value is matched by whole token, by the pieces of a
  URL or a `KEY=value` line, and by the rest of the line; a value split across
  lines, or encoded by a command that carried no placeholder, comes back
  unredacted. Values shorter than 8 characters are matched by shape only.
- **Every store hands a value to any process of the same user**, and so does
  a FIFO that waits for a granted command: another process of yours can read
  it during the up to 120 s the command takes to start. The gates stand in
  front of the agent, not in front of you; a Touch ID gate needs a signed
  helper and is not built. See "Vault" and `docs/THREAT-MODEL.md`.
- **Every e-mail address, phone number with a country code and public IP
  counts**, also your own and your colleagues'. `git log`, `dig` and `ip addr`
  come back with placeholders. Set `"regions": []` to drop the country
  identifiers, and list your own values in `~/.maisecrets/allow.txt` (see
  "Rules of your own").
- **Placeholders resolve in Bash, MCP tool arguments and the file tools.** In
  WebFetch or a subagent prompt they stay text. A subagent shares its parent's session; a
  headless run (`codex exec`, `claude -p`) is a session of its own, so a
  reference from an earlier run is foreign there.
- **A reference in a prompt is admitted as typed by a human**, also when the
  prompt was built from an issue body or a log in a headless run.
- **A slow rule of your own on Windows can outrun the hook's time limit**
  (see "A hook that exceeds the client's timeout fails open" above). The
  checks of "Rules of your own" keep a backtracking rule out, and a rule that
  is slow in one scan is left out from the next one on.
- **Claude Code on Windows without Git Bash** offers a `PowerShell` tool in
  place of Bash. maisecrets checks it like Bash for the store, in any case
  and with either slash, and refuses a placeholder in it with the reason:
  the rewrite knows POSIX quoting only. A placeholder in a file tool or an
  MCP argument works as on the other systems. The `/maisecrets:*` commands
  run through Bash and need Git Bash.
- **Codex on Windows** runs commands in PowerShell, where the bash quoting
  contexts of the grant rewrite do not apply. The prompt block, the output
  redaction and the inline MCP resolve run through `hooks/run.cmd`; a
  placeholder in a shell command is denied with a reason, and the reason
  names the route that works: apply_patch puts the value into a text file
  that the script reads, and the script then runs with no placeholder in the
  command. The launcher is
  proven in the GitHub Actions Windows job in the exact form Codex uses
  (`cmd.exe /C`, block and pass with a UTF-8 payload), not yet in a live
  Codex session.

## Licence

Apache-2.0. `docs/PROTOCOL.md` is the specification a gateway implements,
`docs/THREAT-MODEL.md` says what is defended, `docs/TESTING.md` what was measured.
The licensor is named in `NOTICE`; the vendored rule sets carry their own licences.
