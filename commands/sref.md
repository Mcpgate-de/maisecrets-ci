---
description: Sensitive References of your gateway - status (the default) shows which MCP server offers them and whether maisecrets is logged in, login [NAME] logs in once in the browser, logout [NAME] forgets the login. No value is printed.
argument-hint: "[status | login [NAME] | logout [NAME]]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" sref:*), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" sref:*)
---

Run exactly this command with the arguments the user gave (none for the status), and show the user its output as is:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" sref --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" sref --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not read this user's maisecrets store. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the store of this user". The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.

`login` opens the browser and waits up to 110 seconds: the user logs in there and gives the consent. If no browser opens, the output names the URL; tell the user to open it. Start a login only when the user asked for it with this command. Do not open the URL yourself, and do not run the command again on your own if it ends without a login.
