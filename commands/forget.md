---
description: "Delete stored values by key. Type it yourself, e.g. SECRET_c3"
argument-hint: "KEY [KEY ...] | import:ID"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" forget:*), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" forget:*)
---

The user wants to delete these stored values: $ARGUMENTS

An `import:ID` argument (an import of values from the user's own tools) is handled by maisecrets itself when the person types the prompt; no command removes an import. If the user asks for that here, tell them to type /maisecrets:forget import:ID as their own prompt, then stop.

If no key is given, tell the user to run /maisecrets:list and name the keys, then stop.
Otherwise run exactly this command with the keys the user gave, and show its output as is:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" forget --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" forget --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not write this user's maisecrets folder or read its vault. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the store of this user". The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.
