---
description: "Try maisecrets on real data; nothing reaches the AI until /clear"
argument-hint: "on"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status)
---

The maisecrets prompt hook answers `/maisecrets:demo on` itself, before this command runs, and only when the person types it as their own prompt in a session with no answer yet. The demo ends only with `/clear`. Do not switch the demo in another way, and do not write maisecrets files: if the user wants this, tell them the prompt to send (in Codex: `maisecrets: demo on`).

If this command runs anyway, the hook did not answer it. Run exactly this command and show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not write this user's maisecrets folder or read its vault. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the store of this user".
