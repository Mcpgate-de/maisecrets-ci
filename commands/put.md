---
description: Store the value in your clipboard and get a placeholder back (for a password maisecrets does not find by itself). The value never reaches the AI.
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" put *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" put *)
---

The user has copied a secret to the clipboard. Run exactly this command and show the user its
output, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" put --clipboard --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" put --clipboard --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not write this user's maisecrets folder or read its vault. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the store of this user". The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.

The output names the placeholder (such as ⟦SECRET_c4⟧) and tells the user it is now in the
clipboard in place of the value. Ask the user to paste that placeholder into their next message
where the value is needed; a placeholder resolves only after a human typed it into this session.
Never ask for the value itself. If the output says the clipboard is unavailable (SSH, a headless
session), tell the user to type the value after a label in a prompt instead, for example
`passwort: <value>`: maisecrets blocks that prompt, stores the value and answers with the placeholder.
