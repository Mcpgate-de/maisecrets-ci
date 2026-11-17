---
description: "Show and change the maisecrets settings, one line each"
argument-hint: "[all | KEY | KEY VALUE | KEY default]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" settings *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" settings *)
---

Run exactly this command, then stop. Show the user its output AS IS, as your whole answer: it is Markdown (a table) and must render as one. Do not put it in a code block, do not reword, shorten or summarise it, and add nothing before or after it:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" settings --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" settings --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not write this user's maisecrets folder or read its vault. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the settings of this user". The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes. With no argument it shows the settings you decide; with `--all` also the advanced ones.

With `KEY VALUE` the maisecrets prompt hook has already made the change the user typed; the command then shows
the new state of that setting. The command itself never changes a setting. Do not change a setting in another
way, and do not write maisecrets files: if the user wants a change, tell them the prompt to send.
