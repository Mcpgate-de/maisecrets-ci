---
description: "Setup: mask names with a named-entity service"
argument-hint: "[local | url URL | gateway NAME | off | all]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" ner *), Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" ner), Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" sref login *), Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" sref login), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" ner *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" ner), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" sref login *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" sref login)
---

The maisecrets prompt hook has already made the change the user typed (`$ARGUMENTS`), if there was one, and it answers an argument it does not know itself. Do not change the setting in another way, and do not write maisecrets files.

Run exactly this command and show the user its output as it is. If `$ARGUMENTS` is `all`, put `all` after `ner` (in both forms below).

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" ner
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" ner
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not read this user's maisecrets settings. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the settings of this user".

When the user typed `local` (or `on`), the prompt hook has already started the local service in the background, and the output says `starting`. Do not ask the user anything about the download, and do not start it a second time. Show the output, then stop.

If the command exits with code 3, the local service is not running, no start runs, and docker or podman is installed. Then:

1. If `$ARGUMENTS` is `local` or `on`, do not ask first. Tell the user this note: "maisecrets: I am loading the name service mcpgate/ner (about 690 MB, 1 to 2 GB on disk) and starting it on 127.0.0.1:8765 only. That takes a few minutes. To turn it off: /maisecrets:ner off (a download that runs ends by itself first)." Then run exactly this command (on Windows the `run.cmd` form, as above), and show its output: it starts the container with a secret that the container must prove before it gets any text, or starts the existing container `ner` again.
   ```
   bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" ner start
   ```
   Then run the command above again with `--wait 120` after `ner`, and show the user its output.
2. Otherwise do not start it: tell the user that `/maisecrets:ner local`, sent as their own prompt, starts it. A setting alone never starts a download.

If it still does not answer, show the user the output of `docker logs --tail 20 ner` (or `podman logs --tail 20 ner`) and stop. Do not start a service on another port or address, and do not change the setting.

If the command exits with code 4, the gateway source needs a login with the name scope. Only if `$ARGUMENTS` starts with `gateway` or is one server name alone (the user just chose this source, which asks for that login), run `run.sh sref login` with the server name that the `login` line names after the arrow (or the `run.cmd` form on Windows), and show its output: it opens the browser and waits up to 110 seconds for the user's consent. Then run `run.sh ner` again and show its output. Otherwise do not start a login: tell the user to send `/maisecrets:sref login` as their own prompt.
