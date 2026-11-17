---
description: "Show whether maisecrets protects this session now"
argument-hint: "[all | test]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status), Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status all), Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status test), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status all), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status test)
---

The arguments are: `$ARGUMENTS`

If the arguments are `test`, run exactly this command, show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status test
```

Its output holds a self-test value that maisecrets replaces with ⟦SELFTEST⟧ before you read it. The value is no secret; do not try to get it. The user sees it and sends it as the next prompt.

If the arguments are `all`, run exactly this command, show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status all
```

Otherwise run exactly this command and show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash; for the self-test, `test` goes after `status`), run this instead:

```
& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status
```

For the details, `all` goes after `status` in the same way: `& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status all`.

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not write this user's maisecrets folder or read its vault. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the store of this user".
