---
description: "Send the last blocked prompt with placeholders"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" pending)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" pending`

The text above is the prompt the user sent through maisecrets, with placeholders instead of
values. Begin your reply with one line `Sent: ` followed by that text as it is (clients such as
Remote Control show neither the blocked prompt nor a slash command's expansion), then answer it.
