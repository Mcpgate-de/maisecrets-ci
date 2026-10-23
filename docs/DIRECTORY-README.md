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
with placeholders, instead of the block of the `UserPromptSubmit` hook.

- **What it reads, and why:** it does not read other messages, files or settings.

  | Data | Why `hooks/dispatch.py` needs it |
  |---|---|
  | the prompt you typed (or sent with Remote Control or `claude -p`) | to find the values and write the prompt with placeholders |
  | the session id | a placeholder resolves only in the session that made it, and the transcript clean-up finds the session by it |
  | the working directory (`session.cwd`) | to judge an `@file` mention or a relative path in the prompt |
  | the origin of the prompt | a `{{Name}}` marker counts only in a prompt that a person typed (`composer`, `bridge`) |

- **What it runs:** exactly one of these three commands. Each one is a fixed argument list in the source
  (`claude-mod/maisecrets-mod.mjs`, the functions `runPython3`, `runPyLauncher` and `runPython`), not built at run
  time and not run through a shell:

  ```
  python3 hooks/dispatch.py mod-prompt
  py -3 hooks/dispatch.py mod-prompt
  python hooks/dispatch.py mod-prompt
  ```

  It tries them in this order, because the name of Python differs between macOS, Linux and Windows, and stops at the
  first that answers. Each one runs in the plugin folder, with `PYTHONUTF8=1` so that Windows reads the prompt as
  UTF-8, and all three together get at most 8 seconds. `hooks/dispatch.py` is readable source in the plugin folder and
  uses the same detection as the hooks.
- **What it sends, and where:** `$.process.run` starts a local child process on the same machine; it is not a network
  call. The mod writes the four values above as JSON to the standard input of that process and reads the prompt with
  placeholders from its standard output. It opens no socket, no URL and no HTTP request, and it starts no remote
  process.
- **When it fails:** the prompt goes on unchanged, and the `UserPromptSubmit` hook blocks it as without the mod.

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
- `/maisecrets:report` prints an issue text and a prefilled link. It opens no browser and sends nothing.

Details: `PRIVACY.md` and `SECURITY.md` in this folder.

## Commands

```
/maisecrets:status        what runs, which version
/maisecrets:list          the stored values (placeholders and masked displays, never a secret)
/maisecrets:settings      the choices you make
/maisecrets:forget        delete a stored value
/maisecrets:report        an issue text for a problem
```

## License

Apache-2.0. The vendored rule sets keep their own licenses (`NOTICE`, `maisecrets/detection/rules/LICENSE-*`).
