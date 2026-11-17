---
description: "Report a false alarm, a bug or an idea"
argument-hint: "[last | bug <text> | feature <text> | incident [code/cause]]"
disable-model-invocation: true
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" report *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" report *)
---

Run exactly this command and show the user its output (the issue text and the link), then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" report --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" report --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not write this user's maisecrets folder or read its vault. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the store of this user". The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.

Forms: `/maisecrets:report` lists the last detections; `/maisecrets:report last <why it is wrong>`
prepares a false-positive issue from the last one and names the `/maisecrets:forget` command that
deletes its stored value, so the text is not redacted or blocked again; `/maisecrets:report bug <what happened>` and
`/maisecrets:report feature <what it should do>` prepare an issue without a detection.
`/maisecrets:report incident` shows the incident record: maisecrets' own internal failures, as
closed codes. In Claude Code the prompt hook answers it to the user before this command runs, and
the model does not see it. In Codex, run the terminal form that a refusal names. maisecrets opens no browser and files nothing: the user opens the link and decides in
GitHub's form.

The link opens a GitHub issue prefilled with the plugin version and platform, plus the rule name
and type for a false positive. It carries no value. Do not add detected text to the issue; the
user describes its shape in words.
