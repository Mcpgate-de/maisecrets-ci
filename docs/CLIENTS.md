# Client coverage: which hook carries which guard

For the reader who wants to know which client maisecrets protects, how well, and why a client is not
supported yet. The short table is in the [README](../README.md#where-you-can-use-it-today).

## Client support

✅ proven by the harness in this repo or seen live · ☑️ same runtime or possible per the
vendor's hook docs, not measured · ⚠️ partly · ❌ no hook

| client | prompt | rehydrate | redact | adapter |
|---|:---:|:---:|:---:|---|
| Claude Code CLI | ✅ | ✅ | ✅ | built; from 0.6.0 with mods (2.1.287+) a prompt with a value is rewritten with placeholders instead of blocked, measured live and in the harness; on Windows without Git Bash the shell tool is PowerShell, and a placeholder in a PowerShell command is refused (no PowerShell rewrite) |
| Claude Code CLI, Code Mode | ✅ | ✅ | ✅ | 2.1.330 with `CLAUDE_CODE_EXPERIMENTAL_CODE_MODE=1`: the model's one tool is `REPL`, and each call its script makes (`$` as Bash, `file()` and `tools.Read` as Read, `write()` as Write) passes PreToolUse and PostToolUse under its own tool name; the script's own output passes PostToolUse as `REPL`. Measured 2026-11-23 in the harness (`code_mode_*`): an output, a file read and a value the script builds itself reach the model as placeholders; a given placeholder resolves in `$` and `write()`, a foreign one is refused; a crashing PreToolUse with `onFailure: block` refuses the script's call (without it, the call runs) |
| Claude desktop app, Code tab | ✅ | ✅ | ✅ | same hooks and manifest; a blocked prompt, an MCP call that resolves (with the ask and warning of 0.5.9, now `rehydration: confirm`), and a redacted Bash output seen live (2026-09-28); the mod (mods from 2.1.286) rewrites the prompt, seen live with Claude Code 2.1.288 (2026-10-06): the model got the placeholder, and your own message bubble shows the text as typed (a local display); not in the harness |
| Cowork | ✅ | ✅ | ✅ | Claude Code in a Linux VM of the desktop app, with its own copy of the plugin; the mod rewrites the prompt (2026-11-21, Claude Code 2.1.330); Cowork knows the commands by their short name (`/status`) and draws no panel, no dropped-prompt line and no lock, so a typed command runs through its command file there |
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
behind each mark are in [Hook names per guard](#hook-names-per-guard).

## Hook names per guard

Companion to the "Client support" table above. Read from the vendors' hook
documentation on 2026-09-26 unless marked measured.

One core (detector, vault, placeholder), one adapter per provider (manifest,
hook names, block/rewrite fields). Proven by the harness: Claude Code CLI
(hooks: block prompt, rewrite tool I/O; with mods, from 2.1.287, a prompt is rewritten instead of blocked, see the
"The mod" in [USING.md](USING.md#handing-a-value-to-claude-on-purpose)) and Codex CLI (same format; output via
block feedback). Same runtime, seen live but not in the harness: the Claude desktop app
(a blocked prompt, an MCP resolve with its ask and a redacted Bash output, 2026-09-28; in the Code tab with
Claude Code 2.1.288 the mod rewrites the prompt, 2026-10-06; Cowork: the mod rewrites, 2026-11-21) and Codex in the
ChatGPT app (2026-09-27). Same runtime, not measured: the Codex IDE extension. Docs, untested: ChatGPT
Work mode runs plugin hooks in the Codex runtime. OpenCode: own npm plugin, can
rewrite the prompt (correction 2026-09-26: the current plugin API lists
`tool.execute.before/after` as modifiable, no prompt hook). Checked in the
vendor docs on 2026-09-26 ("Client support" above has the marks), hook
names per guard:

| client | block a prompt | rehydrate | redact output |
|---|---|---|---|
| Gemini CLI | `BeforeModel` may rewrite | `BeforeTool` may rewrite | `AfterTool` may redact |
| Cursor | `beforeSubmitPrompt` blocks | `beforeShellExecution` | `postToolUse` for MCP results only; `afterShellExecution` cannot rewrite |
| Copilot CLI | `userPromptSubmitted` → `modifiedPrompt`, SDK hooks only | `preToolUse` → `modifiedArgs` | `postToolUse` → `modifiedResult` |
| OpenCode | none | `tool.execute.before` | `tool.execute.after` |
| Antigravity CLI | none (`PreInvocation` injects only) | `PreToolUse` → `overwrite` | none (`PostToolUse` expects `{}`) |

Unchecked: Kiro. No adapter: Claude Chat, ChatGPT Chat, web, mobile.

Antigravity CLI (`agy` 1.2.11, checked 2026-09-26 from the hook doc embedded
in the binary): own `hooks.json` contract, named hooks in `plugins/<name>/hooks.json`
or `.agents/hooks.json`, camelCase payloads. `PreToolUse` on `run_command` gets
`toolCall.args.CommandLine` and may answer `decision` allow/deny/ask plus
`overwrite` for the arguments, so rehydration and a deny are possible.
`PostToolUse` expects `{}` back: a tool result cannot be rewritten. There is no
prompt hook; `PreInvocation` carries no prompt and can only inject messages.
Two of the three guards (block a prompt, redact a result) have no hook to live
in, so an adapter would only rehydrate and deny. Not built; `agy plugin
validate` accepts the plugin layout but finds no hooks in it.

## Codex on Windows: the sandbox user

Measured on 2026-09-30 in Codex in the ChatGPT desktop app, Windows 11, maisecrets 0.5.15 to 0.5.19. Each
finding below broke `/maisecrets:status` on one machine, one after the other.

- **PowerShell, no bash.** The model runs a command in PowerShell. A command that calls `bash` fails with
  "The term 'bash' is not recognized". Each file in `commands/` names a PowerShell form (`run.cmd`) since 0.5.17.
- **No plugin root.** Codex leaves `${CLAUDE_PLUGIN_ROOT}` in a command file as written, and
  `$env:CLAUDE_PLUGIN_ROOT` is empty. Since 0.5.18 the command names the newest folder in
  `%USERPROFILE%\.codex\plugins\cache\*\maisecrets\*` instead.
- **A sandbox user.** Codex runs the command as a separate local user (`whoami`: `<host>\codexsandboxoffline`).
  That user gets the environment of the person (`USERNAME`, `LOCALAPPDATA`, the profile paths), so `run.cmd`
  finds the files, and `Test-Path` on the per-user Python is `True`.
- **No program from the profile.** The sandbox user may not start a program from the person's profile.
  `python.exe` under `%LOCALAPPDATA%\Programs\Python\Python312` fails with "Zugriff verweigert" (access
  denied). The python.org installer puts Python there by default, and so does
  `winget install Python.Python.3.12` (maisecrets 0.5.19 and older named that command). A Python bundled in the plugin folder would fail the same way, because
  that folder is in the profile too.
- **PATH.** The python.org installer changes PATH only when it is asked to. Since 0.5.19 `run.cmd` also looks in
  the install folders: the `py` launcher, and `Python3*` under `%LOCALAPPDATA%\Programs\Python` and
  `%ProgramFiles%`.

What works: Python installed for all users, in `C:\Program Files`. This needs an administrator once:

    winget install --id Python.Python.3.12 --exact --scope machine

Remove a per-user install of the same version first, in a terminal that is *not* elevated
(`winget uninstall --id Python.Python.3.12 --exact`). An elevated winget refuses it ("The package installed for
user scope cannot be uninstalled when running with administrator privileges"), and while it is there the
installer for all users stops with exit code 1603 (measured 2026-09-30). In an organisation, ship it through the software
distribution (Intune, MDM). Not yet measured: whether the sandbox user may start Python from
`C:\Program Files`, and whether Codex runs the hooks themselves as the person or as the sandbox user.

## Codex file edits: `apply_patch`

Measured on codex-cli 0.158.0 with a real model (2026-09-29): Codex edits files with one tool,
`apply_patch`. A PreToolUse matcher of `Write` or `Edit` reaches it (aliases), but the payload says
`tool_name: "apply_patch"` and holds the whole patch in `tool_input.command`. Codex 0.163.0-alpha on Windows maps it
to no alias (field report, 2026-10-19), so a PreToolUse group of its own names `apply_patch` (0.6.40). Where Codex
maps the aliases, both groups run on one patch: two equal answers, two audit lines (measured on codex-cli 0.163.0):

```
*** Begin Patch
*** Add File: notes.txt
+key=⟦SECRET_c1⟧
*** End Patch
```

The headers `Add File`, `Update File`, `Delete File` and `Move to` name the paths; Codex also applies
a header indented by spaces or tabs, so the hook reads it as a header too. A call without the patch
text in `command` is refused. maisecrets
refuses a patch that names the maisecrets home, refuses a placeholder in a header, and resolves one
in the content lines, context and removed lines included (the model read the file redacted, so the
patch must match the real text). Each further line of a multi-line value gets the prefix of its line,
so a PEM key lands in the file as it is and never starts a patch operation; the rewritten patch must
name exactly the files the checked one named. A context line that reads like a header is refused
(the safe side), and a value with a carriage return is refused (the format cannot carry it). Codex applies the rewritten patch when the hook answers `allow`.
The captured payload is `tests/client_payloads/codex-apply-patch.json`; the rehydration matrix
builds its Codex file row from it.

## A hook that fails: `onFailure`

Claude Code 2.1.330 and Codex 0.173 (openai/codex#62831) read `"onFailure": "block"` on a command hook. The default
is `continue`: a hook that cannot start, crashes or runs past its timeout lets the call through. `hooks/hooks.json`
sets `block` on `UserPromptSubmit`, on the three `PreToolUse` groups and on `PostToolUse`. Measured on 2026-11-23 with
a copy of the plugin whose launcher exits with 1, or sleeps past the timeout:

| hook that fails | Codex 0.173.0-alpha.4 | Claude Code 2.1.330 | Codex 0.171.0, or no `block` |
|---|---|---|---|
| `UserPromptSubmit` | `Blocked`, no request goes to the model | blocked, no request goes to the model | `Failed`, the prompt goes to the model |
| `PreToolUse` | `Blocked`, the command does not run | refused, the command does not run | `Failed`, the command runs |
| `PostToolUse` | `Blocked`, the model gets an empty output and the reason | the model gets the output and the reason | `Failed`, the model gets the output |

Codex tells the model `<event> hook failed. This hook is configured to block continuation on failure.` Claude Code
tells it `failed; blocking because onFailure is "block"` (or `timed out; …`), with the hook's stderr. Claude Code's
schema says: "'block': the failure counts as exit code 2, so the action the event guards (a tool call, a permission
request, a prompt) is blocked. Ignored for async hooks and on Stop, SubagentStop, TaskCompleted and TeammateIdle."
Exit code 2 holds back no output of `PostToolUse`, so there the watchdog of maisecrets stays the net.

A moved plugin folder (anthropics/claude-code#97847) is such a failure: the hook cannot start. Claude Code 2.1.330
then refuses the tool call (harness scenario `plugin_folder_moved`). The guard (`/maisecrets:guard`) still serves
older clients and the output of a call that started before the move.

`SessionStart` and `SessionEnd` keep the default. In Codex a failed start with `block` stops the session, and Codex
refuses `block` on `SessionEnd` and on an async hook and drops that hook. Codex 0.171.0 reads the plugin with the field
and runs its hooks as before.

The field is part of the hook's declaration hash in Codex 0.173 and newer, and not in older versions.
`maisecrets/codex_trust.py` accepts a trust from either version.

## Codex: vault references

Measured on codex-cli 0.162.0, and the helper also on 0.155.1 (2026-10-16), with a temp `CODEX_HOME`, a local
https MCP server with its own CA, and the fake upstream. The harness scenario `vault_refs` of `harness/codex.py`
repeats it on each pipeline.

- **Config.** `$CODEX_HOME/config.toml` (default `~/.codex`), `[mcp_servers.<name>] url = …`. A streamable-HTTP
  entry takes `http_headers`, `env_http_headers` and `http_headers_helper` (a command that prints a JSON object of
  headers). The headers of an entry go to every request to the origin of its URL: initialize, tools/list,
  tools/call, the OAuth metadata, the client registration and the `authorization_code` token request. The browser
  leg of the login gets none (the browser makes it), and another origin gets none.
- **A project moves a user entry.** Codex merges `<dir>/.codex/config.toml` of each folder from the project root
  down to the session folder over the user's file, deeply. A project file with only `[mcp_servers.demo] url = B`
  sent the user's `demo` entry, its static header included, to B. "Untrusted" would stop it, but the app server
  trusts a project on its own when the sandbox may write the folder (the default `workspace-write`) and writes the
  trust into the user's file. So maisecrets writes no static header in Codex.
- **The helper.** Codex runs `http_headers_helper` once per connection, in the session folder, with a cleared
  environment (`HOME`, `PATH`, `USER`, `TMPDIR` and a few more; no `CODEX_HOME`). `{}` gives no header and the
  server works; a helper that exits with an error stops the connection. maisecrets writes one helper line on the
  entry; the helper (`maisecrets/codex_helper.py`, copied to `~/.maisecrets/bin/`) prints the header only when no
  project layer of the folder has `mcp_servers`, and the command ends in `|| echo '{}'`.
- **When Codex reads the file.** At its start: a header written during a `codex exec` run did not reach the later
  requests of that run. In the app server (the terminal UI and the desktop app) a new thread loads the config again
  (`thread/start`); not measured.
- **The PostToolUse payload** of an MCP call: `session_id, turn_id, cwd, model, permission_mode, tool_name,
  tool_input, tool_response, tool_use_id, transcript_path`. `tool_name` is `mcp__<server>__<tool>`, with every
  character outside `[A-Za-z0-9_]` as `_`; there is no server name, URL or scope. maisecrets maps the name to a user
  entry and notes nothing when two entries could make it.
- **A hook's `systemMessage`** becomes a warning of the hook run. `codex exec` prints neither it nor the start line
  of maisecrets, in its text or its `--json` output. The terminal UI shows it under the hook run
  (`tui/src/history_cell/hook_cell.rs`), and Codex does not send it to the model: `core/src/hook_runtime.rs` sends
  it as a warning event, and only `additionalContext` goes to the model (read on `openai/codex` main on 2026-11-17,
  not measured; the ChatGPT app is not measured). The PostToolUse output schema allows it next to `decision` and
  `reason`. The one-time hints of maisecrets go there.
- **One answer per process.** Codex keeps the server URLs of the folder a session began in and runs the helper
  again after a change of the folder or a 401 or 403 (`core/src/session/turn_context.rs`,
  `rmcp-client/src/http_headers.rs`). So the first run of a Codex process decides for each entry, and only within
  two minutes of the process start; later runs elsewhere print `{}`. The desktop app runs one app server for all its
  chats, so a later chat in another folder sends no header until the app restarts (not measured). The plugin servers
  are read from every place codex-rs 0.162.0 reads them (four manifest places, `mcpServers` inline or as a path,
  `.mcp.json`, `mcp.json`).
- **Windows** (not measured): the file is `%USERPROFILE%\.codex\config.toml`, and the helper would run under
  `cmd.exe /C`. Codex vault references are off on Windows in this version.

## Claude Code: which MCP server a tool call goes to

The hook payload of an `mcp__*` tool (PreToolUse, PostToolUse, PostToolUseFailure, PermissionRequest) carries
`mcp_server: {name, source}`. In the schema of Claude Code 2.1.330 `source` is an open set (`sdk`, `plugin`,
`user`, `project`, `local`, `dynamic`, `managed`, `enterprise`, `claudeai`, `agent`), the config scope of the
server. A claude.ai connector is a server of type `claudeai-proxy` with the scope `claudeai`, or `dynamic` where
no plugin brought it; its name is its display name (`claude.ai Slack`), so its tools are `mcp__claude_ai_Slack__…`.
Its calls go through Anthropic's connector proxy, not from the client to the server. maisecrets therefore puts no
stored value into such a call (THREAT-MODEL C14, #99): the source `claudeai` names a connector, and so does the
prefix `mcp__claude_ai_` with any source that is no scope of the client's own config. Read from the binary and its
hook schema, and used by the tests of the connector binding (C31). In Cowork a connector can arrive as an `sdk`
server (`capabilities.experimental["anthropic/claudeAiConnector"]`) with a tool name the host chooses, and the
Cowork payload's source is not measured: there every source that is no own-config scope counts as a connector.
For this refusal the entry points are `remote_cowork` (measured in the Cowork VM, 2026-11-21),
`remote_cowork_trigger` (Claude Code's own list of Cowork cloud entry points) and `local-agent` (the desktop
app's local agent session, app.asar 6.28899.6, which may run on the computer itself). `cowork.active()`, which
changes the texts and turns names off, knows only the first two. In a remote session (`CLAUDE_CODE_REMOTE`) a
connector can have the source `dynamic` and no prefix, so that source counts there too. A server named `claude.ai X` from a plugin,
agent or dynamic source is refused as well, an over-refusal. Codex sends no `mcp_server`; its `codex_apps`
connectors (behind OpenAI's apps gateway) relay a call the same way, and maisecrets does not detect them
(KNOWN-GAPS).

## Sessions, subagents and headless runs

A reference resolves in the session that created it or admitted it. A Claude
Code subagent (Task) sends its parent's `session_id`, so it resolves what the
parent may resolve; it receives the same primer at session start. A headless
run (`claude -p`, `codex exec`) is a new session each time: a reference from
an earlier run is `foreign-session` there, and the deny says so. A prompt
built from untrusted text (an issue body, a log) admits every reference in it
as typed by a human; keep such runs on a machine without a vault.

## Status and self-test: what the commands see

Measured on 2026-11-15 with Claude Code 2.1.325 and codex-cli 0.169.0 (harness scenarios `selftest_tool_path` and
`selftest_hooks_not_running` of `harness/run.py`, `selftest_passes` of `harness/codex.py`, `maisecrets/selftest.py`,
`maisecrets/status_verdict.py`).

- **What the harness proves.** In Codex, the whole self-test: the tool path, and the value typed into the resumed
  session (`codex exec resume <id>`) gets "Self-test passed". In Claude Code, the tool path, and that the value sent
  by `claude -p --resume <id>` (the same session id, measured) is blocked without a pass: a prompt of `claude -p` is a
  program's (C22). The "passed" answer to a typed prompt of Claude Code is held by `tests/test_selftest.py` only.

- **The session of a command.** Claude Code gives a command `CLAUDE_CODE_SESSION_ID`, Codex gives it
  `CODEX_THREAD_ID`; each equals the `session_id` of the hook payloads. Codex passes on the Claude Code variable of
  the shell that started it, so a command checks both.
- **Codex drops a variable whose name holds `SECRET`** from a command's environment (`shell_environment_policy`,
  default excludes): a maisecrets command in Codex reads the default home, not a `MAISECRETS_HOME` the hooks get.
  The Codex harness sets it with `shell_environment_policy.set` for the self-test.
- **The marketplace copies.** Claude Code clones a marketplace to the `installLocation` that
  `plugins/known_marketplaces.json` names (`plugins/marketplaces/<name>`), with `lastUpdated`. Codex clones a Git
  marketplace to `$CODEX_HOME/.tmp/marketplaces/<name>` and reads `.agents/plugins/marketplace.json` or, without it,
  `.claude-plugin/marketplace.json`; `codex plugin add maisecrets@<name>` installs a newer version next to the old
  one. Each copy is as new as the client's last fetch: `/maisecrets:status` says "newest unknown" without one.
- **A `systemMessage` of PostToolUse** reaches the person in Claude Code and not the model (no request body held
  the test value). The one-time hints of maisecrets use it: `harness/hint_screen.py` (a pseudo-terminal) shows
  the line on the screen once and in no request body. `claude -p` shows no `systemMessage`; its hooks run under the
  entry point `sdk-cli`, and maisecrets gives no hint there and does not record one as given (harness scenarios
  `ssh_consent_hint_not_in_a_headless_run` and `read_pdf_hint_not_in_a_headless_run`). A Codex hook reads the session
  source from the first line of the rollout (`session_meta`, `source`): `cli` (terminal UI) and `vscode` (app
  server) get the hint, `exec`, `mcp`, a subagent and an unreadable rollout do not. Claude Code writes it into its local transcript (a `hook_system_message` record), so the test
  value stands there.
