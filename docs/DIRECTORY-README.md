# maisecrets

Keeps passwords, tokens and personal data out of Claude Code. A value in a prompt or in a tool result becomes a
placeholder such as `⟦SECRET_c1⟧` before the model sees it. The value stays in your operating system's store, and it goes
back into a command or a tool argument only at execution, where your rules allow it.

This is the short README of the plugin as the directory ships it. The full documentation, the threat model and the
benchmarks are at https://github.com/Mcpgate-de/maisecrets.

## Security summary

- The mod reads the prompt you send, the session id, the working directory and the origin of the prompt.
- It gives them only to the plugin's own `hooks/dispatch.py`, on standard input of a local Python child process.
- It starts only one of three fixed local commands, with no shell: `python3 hooks/dispatch.py mod-prompt`,
  `py -3 hooks/dispatch.py mod-prompt` or `python hooks/dispatch.py mod-prompt`.
- No program name and no argument comes from the prompt, the model, the environment or a setting.
- The mod opens no network connection. It sends no prompt, no session data and no local data to the publisher or to
  any other server.

## Install

In Claude Code 2.1.275 or later, one line installs it from its marketplace on GitHub:

```
/plugin install maisecrets --marketplace Mcpgate-de/maisecrets
```

Then start a new session.

## What the hooks do

All hooks run `hooks/run.sh` (or `hooks/run.cmd` on Windows), which starts this computer's Python 3 with
`hooks/dispatch.py` from the plugin folder. Everything they run is readable source in the plugin folder: no
download, no package install, no dependency outside the Python standard library.

| Event | What it does |
|---|---|
| `SessionStart` | Prints the version and the protections that are on. Notes the start of the session. |
| `UserPromptSubmit` | Scans your prompt. When it holds a password, a token or personal data, the hook stops it and offers you the cleaned prompt with placeholders. |
| `PreToolUse` | Scans the input of a tool call. Puts a stored value into a command or a tool argument right before execution, when your rules allow it, and refuses a form where the value could run as code. |
| `PostToolUse`, `PostToolUseFailure` | Scans the result of a tool call and replaces each value with its placeholder before the model sees it. |

## What the mod does

`claude-mod/maisecrets-mod.mjs` is a mod for Claude Code 2.1.287 and later. It lets a prompt with a value go through
with placeholders instead of the block of the `UserPromptSubmit` hook, shows you your values on your screen (never to
the model), masks a tool result that the result hook missed, and serves the `/maisecrets` menu. Everything it does
goes through the Claude Code mod API; it opens no socket, no URL and no HTTP request itself.

### The programs it starts (`$.process.run`, `$.process.spawn`)

Only the plugin's own `hooks/dispatch.py`, in the plugin folder, with Python 3, as a fixed argument list (no shell):

```
python3 hooks/dispatch.py mod-prompt     (or: py -3 ..., python ...: the name of Python differs per system)
python3 hooks/dispatch.py mod-values     (the values of placeholders, to draw them on your screen)
python3 hooks/dispatch.py mod-reveal     (one value you clicked, to show or copy it)
python3 hooks/dispatch.py mod-demo       (whether this session is in the demo)
python3 hooks/dispatch.py mod-settings   (the /maisecrets menu and its panel)
python3 hooks/dispatch.py mod-result     (the second check of a tool result)
```

The menu also runs the commands you choose in it (`hooks/dispatch.py` with that command's words, for example a login
at your gateway); that Python process may start your browser for a login, or Docker or Podman for the local name
service, only when you chose that command. Each run gets `PYTHONUTF8=1` and a time limit.

### What it sends, and where

The text of the question (a prompt, a tool result, the keys to show, a menu action), with the session id and, for a
prompt, the working directory and where the prompt came from, goes as JSON on standard input to that local Python
process. Nothing goes over the network from the mod. The Python process sends text off this computer only to a
service you set up: the name service of `/maisecrets ner`, or a gateway you logged in at (`/maisecrets sref login`).

### The one MCP call (`$.mcp.call`)

When a claude.ai connector showed Sensitive References this session, the mod calls that connector's own tool
`sensitive_references_resource` once at the end of a turn, with no argument (to learn its gateway) or with a one-time
nonce of the mod (to prove that the connector reaches your gateway with your account). It calls no other tool.

### What it sets

- `$.env.set('CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION', ...)`: off while a session is in the demo (`/maisecrets demo
  on`), back to Claude Code's default after it.
- `$.env.set('MAISECRETS_MOD_NET', ...)`: a random value of this mod process (32 hex characters, made at its start),
  only while the maisecrets result hooks of a tool call run, and `''` again after them. The hooks write it into their
  answer as a proof that they checked the result; it is no credential and leaves this computer in no request.
- `$.store`: one counter, how often it showed its hint about values on the screen.
- `$.prompt.fill`: only the login command of a gateway, into an empty input box; your Enter starts it.

### The events it hooks, and what each does

| Event | What the hook does |
|---|---|
| `prompt.submit`, `classic.UserPromptSubmit` | Replaces values in your prompt with placeholders before it is sent; shows one line when the prompt hook did not run. |
| `tool.call` | Notes that a call started (for the second check); refuses a call that carries the mod's own pairing nonce. |
| `tool.run` | Notes which placeholders and references a call used; changes nothing. |
| `classic.PostToolUse`, `classic.PostToolUseFailure` | Give the result hook a one-time code of this mod and take the hook's proof line out of the output. |
| `session.append` (tool results) | Masks a tool result the result hook did not check, before Claude Code keeps or sends it; if that fails, withholds the output. |
| `session.append` (hook context) | Takes the proof lines of the result hook out of the context. |
| `http.fetch` | Only in the demo: refuses every request Claude Code itself sends. Outside the demo, it changes nothing. |
| `session.compact` | Only in the demo: skips a compaction, because it is a model request of its own. |
| `turn.step` | Only in the demo: answers each model step with one line instead of a request. |
| `turn.complete` | Refreshes the status line; offers a gateway login when one is due. |
| `command.run`, `$.command.register` | The `/maisecrets` menu and the commands typed as `/maisecrets:NAME`. |
| `$.command.run` (a call, not a hook) | Runs the plugin's own entry command `/maisecrets` with the words you chose in the menu, after the hook that asked has returned. It runs no other command. |
| `ui.render`, `ui.close`, `session.start` | Draws your values (with a lock) and the menu panel on your screen, and one line above the prompt when the name service checked a tool result of this turn only in part or not at all (the worst share, and where the rest went), until your next prompt; nothing of it goes to the model. |

### When it fails

The prompt goes on unchanged, and the `UserPromptSubmit` hook blocks it as without the mod. A tool result whose second
check fails is withheld. In the demo, a hook that gets no answer from Python refuses the request.

## Programs the plugin starts

- Python 3 (`python3`, `py -3` or `python`) with the plugin's own scripts.
- The store of your operating system: `security` on macOS (the login keychain), PowerShell on Windows (the
  Credential Locker), and `openssl` for the encrypted file on Linux.
- A clipboard tool to put the cleaned prompt on your clipboard.
- `pdftotext`, only when you turn on `read_pdf convert`, from the fixed install folders of the system.

## Credentials and network

maisecrets has no server, no account, no API key and no telemetry. It needs no credential for itself.

- It does use credentials of yours: the values it took out of your prompts and tool results. It keeps them in the
  store above and reads one back only to put it into a tool call on this machine where your rules allow it. They are
  your values, not a login to maisecrets, and they never go to the publisher.
- The values it finds stay on your machine, in the store above, and expire (24 hours by default).
- It reads no credential of yours to send it anywhere. Where the source reads a token, an environment variable or a
  header, it does so to detect a value and mask it, or to recognise a server token that one of your own MCP servers
  sent.
- Vault references (optional, off until such a server sends a token): for an MCP server that you added yourself
  (user scope, an `https` URL) and that names a vault endpoint, maisecrets makes a random key per server and asks
  that same server over HTTPS for the values behind its own tokens. No request goes to any other host.
  `client_header: false` turns this off.
- `/maisecrets report` prints an issue text and a prefilled link. It opens no browser and sends nothing.

Details: `PRIVACY.md` and `SECURITY.md` in this folder.

## Commands

```
/maisecrets status        does it protect this session? one line per check (all: the details)
/maisecrets list          the stored values (placeholders and masked displays, never a secret)
/maisecrets settings      the choices you make
/maisecrets forget        delete a stored value
/maisecrets not-a-secret  a wrong hit: delete it and never mask that exact value again
/maisecrets demo          try it with real data, in a new session: no prompt goes to the AI until /clear
/maisecrets report        an issue text for a problem
```

## License

Apache-2.0. The vendored rule sets keep their own licenses (`NOTICE`, `maisecrets/detection/rules/LICENSE-*`).
