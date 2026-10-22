# maisecrets

Keeps passwords, tokens and personal data out of Claude Code. A value in a prompt or in a tool result becomes a
placeholder such as `⟦SECRET_c1⟧` before the model sees it. The value stays in your operating system's store, and it goes
back into a command or a tool argument only at execution, where your rules allow it.

This is the short README of the plugin as the directory ships it. The full documentation, the threat model and the
benchmarks are at https://github.com/Mcpgate-de/maisecrets.

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

- **What it reads:** the text of a prompt that you typed (or sent with Remote Control or `claude -p`), the session
  id, the working directory (`session.cwd`) and the origin of the prompt. It does not read other messages, files or
  settings.
- **What it runs:** one program, written as fixed text at the call: this computer's Python 3 with the plugin's own
  `hooks/dispatch.py` and the argument `mod-prompt`, in the plugin folder. It tries `python3`, then `py -3`, then
  `python`, because the name of Python differs between macOS, Linux and Windows. It passes the prompt on standard
  input and gets the prompt with placeholders back. That is the same detection the hooks use.
- **What it sends, and where:** nothing leaves the machine. The prompt goes only to that local Python process on
  standard input, and the rewritten prompt goes back to Claude Code. The mod opens no network connection.
- **When it fails:** the prompt goes on unchanged, and the `UserPromptSubmit` hook blocks it as without the mod.

## Programs the plugin starts

- Python 3 (`python3`, `py -3` or `python`) with the plugin's own scripts.
- The store of your operating system: `security` on macOS (the login keychain), PowerShell on Windows (the
  Credential Locker), and `openssl` for the encrypted file on Linux.
- A clipboard tool to put the cleaned prompt on your clipboard.
- `pdftotext`, only when you turn on `read_pdf convert`, from the fixed install folders of the system.

## Credentials and network

maisecrets has no server, no account and no telemetry. It asks you for no credential and needs none.

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
