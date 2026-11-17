---
description: "Show your own detection rules and what each loaded"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" rules), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" rules)
---

Run exactly this command and show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" rules
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" rules
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not read this user's maisecrets folder. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the rule folders of this user".

A folder is added or removed only by the user's own prompt (`/maisecrets:settings rule_dirs add DIR`). Do not add a folder in another way, and do not write maisecrets files: if the user wants a folder, tell them the prompt to send. You may write rules into a team folder the user names; `maisecrets rules check DIR` checks them.
