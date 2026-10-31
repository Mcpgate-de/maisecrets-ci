---
description: Names in tool results from a named-entity service - local (a container on this computer), url URL (a service of your team) or off. Without an argument it shows the source and whether it answers.
argument-hint: "[local | url URL | off]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" ner *), Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" ner), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" ner *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" ner)
---

The maisecrets prompt hook has already made the change the user typed (`$ARGUMENTS`), if there was one. Do not change the setting in another way, and do not write maisecrets files.

Run exactly this command and show the user its output:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" ner
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" ner
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`.

If the output has a line that starts with `start: `, the local service is not running and docker or podman is installed. Then:

1. Run the command after `start: ` as it is. It downloads the image `mcpgate/ner` the first time and starts the service on 127.0.0.1:8765 only. If a container named `ner` exists already, run `docker start ner` (or `podman start ner`) instead.
2. Run the command above again with `--wait 120` after `ner`, and show the user its output.

If it still does not answer, show the user the output of `docker logs --tail 20 ner` and stop. Do not start a service on another port or address, and do not change the setting.
