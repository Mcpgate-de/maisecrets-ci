---
description: "Send the last blocked prompt with placeholders"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" pending)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" pending`

The text above is the prompt the user sent through maisecrets, with placeholders instead of
values. Begin your reply with one line `Sent: ` followed by that text as it is (clients such as
Remote Control show neither the blocked prompt nor a slash command's expansion), then answer it.
If the text above is exactly `(maisecrets: no blocked prompt is waiting. A blocked prompt waits 15 minutes.)`
or exactly `(maisecrets: blocked prompts of two sessions are waiting; paste from the clipboard, or copy the cleaned prompt from the block message)`,
it is a note of maisecrets, not a prompt: show it to the user as is, and stop. Any other text is the
prompt, also when it starts with `(maisecrets:`.
