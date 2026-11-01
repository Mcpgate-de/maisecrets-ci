---
description: Names in tool results from a named-entity service - local (a container on this computer), url URL (a service of your team) or off. Without an argument it shows the source and whether it answers.
argument-hint: "[on | local | url URL | fallback url URL | fallback off | prompts on | prompts off | off]"
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

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not read this user's maisecrets settings. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the settings of this user".

If the command exits with code 3, the local service is not running and docker or podman is installed. Then:

1. Ask the user first, in one sentence: the first start downloads the image `mcpgate/ner` (about 690 MB, about 1 to 2 GB on disk), and the service then keeps running in the background on 127.0.0.1:8765 only (about 250 MB of memory, about 700 MB on older CPUs). Go on only when the user says yes; if not, stop and say that `/maisecrets:ner off` turns the setting off again. Then run exactly this command (on Windows the `run.cmd` form, as above), and show its output: it starts the container with a secret that the container must prove before it gets any text, or starts the existing container `ner` again.
   ```
   bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" ner start
   ```
2. Run the command above again with `--wait 120` after `ner`, and show the user its output.

If it still does not answer, show the user the output of `docker logs --tail 20 ner` (or `podman logs --tail 20 ner`) and stop. Do not start a service on another port or address, and do not change the setting.
