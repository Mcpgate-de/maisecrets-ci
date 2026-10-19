# Client coverage: which hook carries which guard

Companion to the "Client support" table in the README. Read from the vendors' hook
documentation on 2026-09-26 unless marked measured.

One core (detector, vault, placeholder), one adapter per provider (manifest,
hook names, block/rewrite fields). Proven by the harness: Claude Code CLI
(hooks: block prompt, rewrite tool I/O; with mods, from 2.1.287, a prompt is rewritten instead of blocked, see the
README "The mod") and Codex CLI (same format; output via
block feedback). Same runtime, seen live but not in the harness: the Claude desktop app
(a blocked prompt, an MCP resolve with its ask and a redacted Bash output, 2026-09-28; in the Code tab with
Claude Code 2.1.288 the mod rewrites the prompt, 2026-10-06; Cowork: the mod not measured) and Codex in the
ChatGPT app (2026-09-27). Same runtime, not measured: the Codex IDE extension. Docs, untested: ChatGPT
Work mode runs plugin hooks in the Codex runtime. OpenCode: own npm plugin, can
rewrite the prompt (correction 2026-09-26: the current plugin API lists
`tool.execute.before/after` as modifiable, no prompt hook). Checked in the
vendor docs on 2026-09-26 (README "Client support" has the marks), hook
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
  of maisecrets, in its text or its `--json` output.
- **One answer per process.** Codex keeps the server URLs of the folder a session began in and runs the helper
  again after a change of the folder or a 401 or 403 (`core/src/session/turn_context.rs`,
  `rmcp-client/src/http_headers.rs`). So the first run of a Codex process decides for each entry, and only within
  two minutes of the process start; later runs elsewhere print `{}`. The desktop app runs one app server for all its
  chats, so a later chat in another folder sends no header until the app restarts (not measured). The plugin servers
  are read from every place codex-rs 0.162.0 reads them (four manifest places, `mcpServers` inline or as a path,
  `.mcp.json`, `mcp.json`).
- **Windows** (not measured): the file is `%USERPROFILE%\.codex\config.toml`, and the helper would run under
  `cmd.exe /C`. Codex vault references are off on Windows in this version.

## Sessions, subagents and headless runs

A reference resolves in the session that created it or admitted it. A Claude
Code subagent (Task) sends its parent's `session_id`, so it resolves what the
parent may resolve; it receives the same primer at session start. A headless
run (`claude -p`, `codex exec`) is a new session each time: a reference from
an earlier run is `foreign-session` there, and the deny says so. A prompt
built from untrusted text (an issue body, a log) admits every reference in it
as typed by a human; keep such runs on a machine without a vault.
