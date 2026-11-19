# How maisecrets works

For the reader who wants to know what maisecrets does inside: the hooks and when they run, what the plugin
runs, sends and fetches, the gates in front of each resolve, and the detection rules. What maisecrets defends
and where that ends is in [THREAT-MODEL.md](THREAT-MODEL.md). The limits that were measured are in
[KNOWN-GAPS.md](KNOWN-GAPS.md).

Contents:

- [How it works](#how-it-works)
- [Status](#status)
- [What the plugin runs, sends and fetches](#what-the-plugin-runs-sends-and-fetches)
- [Invisible characters](#invisible-characters)
- [Disguised values in tool results](#disguised-values-in-tool-results)
- [Password exports in tool results](#password-exports-in-tool-results)
- [Gates around a resolve](#gates-around-a-resolve)
- [Detection rules](#detection-rules)

## How it works

An AI agent sees what you type and what its tools print: passwords, tokens, a
customer's e-mail address. maisecrets intercepts detected secrets and personal
data before they reach the cloud model. The real value goes back in only where
the call happens, and the model never sees it there either. By default
maisecrets adds no approval of its own: in Claude Code your permission rules
decide, as before; in Codex maisecrets answers `allow`, and Codex's sandbox and
its approval of MCP tools still apply. maisecrets itself sends no
prompt, value or telemetry to a server.

**What it is for:** maisecrets keeps values out of the model and out of the
session transcript. It guards against an agent that does not try to evade it.
It does not contain an agent that deliberately runs code with your rights to
switch it off ([threat model](THREAT-MODEL.md), C22).

```bash
claude plugin marketplace add Mcpgate-de/maisecrets
claude plugin install maisecrets@maisecrets     # then start a new session
```

It works as a plugin for Claude Code (and Cowork) and for Codex, from the same
`hooks/hooks.json`. Codex and the other install paths: see [Install](ADMIN.md#install).

**What it does, deterministically and locally:**

1. **You type a secret or a personal value** (a token, a password after a
   label, an e-mail address, a phone number with a country code, an IBAN, a
   card number, a public IP, and the identifiers of your region (`regions`, by default the country of the system); test data such
   as `example.com` stays alone, see ["Test data that maisecrets leaves alone"](USING.md#test-data-that-maisecrets-leaves-alone)). A
   `UserPromptSubmit` hook
   detects it, stores it in a local vault, blocks the prompt, and keeps the
   rewritten prompt with a placeholder such as `⟦SECRET_c1⟧` or
   `⟦EMAIL_c1:ma•••@•••.de⟧`. Type `/maisecrets:send` to send it as is,
   or paste it from the clipboard where one exists. The value never reached
   the model. Measured: zero API requests for a blocked prompt.
   **On Claude Code 2.1.287 and later (in the desktop app's Code tab from
   2.1.286), as a rule, there is no block and no resend:** a mod (`claude-mod/maisecrets-mod.mjs`) replaces the values with placeholders and
   the prompt goes on at once (the hook still blocks a prompt with an `@file`
   mention, a timeout of the mod, and a session where mods are off); your message on screen shows the placeholders, and the
   record of the prompt as typed in the transcript file is masked in place. The
   hook stays the gate: when the mod does not run or fails, the hook blocks as
   above. `"rewrite_prompts": false` keeps the block. See ["The mod"](USING.md#handing-a-value-to-claude-on-purpose).
2. **The model reads a file or runs a command that outputs a secret.** A
   `PostToolUse` hook redacts the result before the model sees it.
3. **The model uses a placeholder in a Bash command or a tool argument.** A
   `PreToolUse` hook lets the command read the value once under a one-time
   grant, or inserts it into the tool argument, right before execution. The
   output is redacted again on the way back. See "Gates around a resolve".
   A form where the value could turn into code is refused; every other form
   runs without a maisecrets prompt, unless you set a stricter
   [rehydration policy](ADMIN.md#rehydration-policy-optional).
4. **The model sends a message to another Claude session.** That session's
   prompt hook would block a message with a value, and the sender would not
   learn it. A `PreToolUse` hook on `SendMessage` replaces each value with a
   placeholder before the message leaves, stores the value, and tells the
   sending model. The receiving session's prompt hook then lets the message
   through; that session cannot use the placeholder in its own tool calls.

Everything a hook runs is readable source in this folder. No download, no
package install, no dependency outside the Python standard library and the
system tools it names (`security`, PowerShell, `openssl`, a clipboard tool).

What it does not do: detect a name without a label (it masks the names on your term list), follow a value through an encoding a
command applies, or protect against a process that runs as you. [Known gaps](KNOWN-GAPS.md#known-gaps-measured-or-documented)
lists every limit that was measured.

## Status

Released from `main` on every merge (`CHANGELOG.md`, tags `vX.Y.Z`). A release
moves only the last number; a higher one needs the owner's approval. Vault backend per platform:

| platform | backend | where the values live |
|---|---|---|
| macOS | `keychain` | login keychain via `security`, no iCloud sync flag |
| Windows | `windows-vault` | Credential Locker (`PasswordVault`, DPAPI) via PowerShell |
| Linux | `encrypted-file` | `openssl` AES-256-CBC + PBKDF2 + HMAC tag, key file 0600 |
| any | `jsonfile` | plaintext 0600, TEST MODE only |

Hooks run through `hooks/run.sh` (bash), which looks for a Python 3.9+ as
`python3`, `python`, `py -3`, a versioned name, or the Homebrew, `/usr/local`
and python.org paths. Claude Code on Windows runs a hook command in Git Bash
when Git for Windows is installed, and in PowerShell when it is not (pwsh 7,
else Windows PowerShell 5.1; read from Claude Code 2.1.284). So each command
in `hooks/hooks.json` is one text that both shells read: bash runs
`hooks/run.sh` and stops there, and PowerShell, which sees that part as a
comment, runs `hooks/run.cmd`. Codex on Windows runs the `commandWindows`
entry of each hook through `cmd.exe`, which starts `hooks/run.cmd` too. Both
launchers run the same `dispatch.py`. Without a Python
3.9+ the launcher blocks every prompt and every tool call and withholds every
tool result, and its message names what to install: fail closed, with a cause.

Proven with the harness on macOS (Claude Code 2.1.283) and on Debian 13
(2.1.223), the scenarios of `harness/run.py`, on every push in CI; Windows through the GitHub
Actions matrix (unit tests, both launchers, Credential Locker round trip), not
yet with a live Claude Code session. Codex (codex-cli 0.155.1): the same
`hooks/hooks.json`, Codex sets `CLAUDE_PLUGIN_ROOT` itself; `harness/codex.py`
proves the three tool scenarios against a fake Responses upstream on every
push and, with `--real`, against the real model. `docs/TESTING.md` has the
record. GitHub is a read-only mirror of the primary repository; issues and
pull requests are welcome there.

### What `/maisecrets:status` says

The command fits on one screen. The head line says whether this session is
protected: `🔒` when no check failed, `⚠️ … is NOT protecting this session`
when one did. Outside a client session (a terminal) no session can be judged,
so the head line makes no claim. One line follows per check: `✓` ok, `!` warn,
`✗` FAIL, `–` does not apply. A warn or FAIL line names the next command after
`→`. In Codex the commands are typed: `maisecrets: status all`. Each fact
claims only what the check saw. `/maisecrets:status all` prints the longer
facts of each check and the details that support needs.

**hooks.** The tool-call hook of this session must have run in the last 2
minutes, because the command itself is a tool call. The prompt hook must have
run at all, because each session starts with a prompt. The line names the
hooks that ran and when (`hooks.log`). If no hook ran, the client does not
run maisecrets: in Claude Code, run `/reload-plugins` or start a new session;
in Codex, trust the maisecrets hooks in `/hooks`.

**version.** maisecrets compares its version with the marketplace copy that the
client fetched itself. It makes no network request. So "the newest" is only as
new as the last fetch, and without a copy the line says "newest unknown". After
an update, start a new session; Codex also asks you to trust the hooks again.

**codex.** Codex runs a hook only when you trusted its current contents
(openai/codex#54619). Each update ends that trust. The line recomputes the
hashes and says whether Codex runs the hooks of the installed version. `–`
means Codex did not install maisecrets on this computer.

**store.** maisecrets reads a key that does not exist, and the store must
answer. If it does not answer, every prompt with a value is blocked until it
does. The plaintext test file (`jsonfile`) is for tests only. To use another
store, write `{"backend": "encrypted-file"}` (or `keychain`, `windows-vault`)
to `config.json` in the maisecrets folder; it takes effect on the next call.

**incidents.** These are faults of maisecrets itself in the last 30 days. A
fail-closed incident means maisecrets refused a call it could not check: safe,
but it stopped work. A best-effort incident means a side step failed (a cleanup
or a record). Act when they repeat or stop your work; `/maisecrets:report
incident` shows them and makes a report.

**self-test.** `/maisecrets:status test` proves both protection paths in the
real client. The tool-result hook must mask a test value in the output of the
command, and the prompt hook must stop it when you send it. A pass counts for
this version, in this session or for 4 hours. If the AI wrote the test value
into a tool call, it had the value: start a new session and test again.

**older.** This line shows when an older maisecrets ran in the last day,
after this version first started, and a gateway login was used on this
computer. maisecrets cannot see whether that session is still open, so the
line says it may be. A session keeps the version it
started with until it restarts, and an old renewal logic can end the login (a
version before 0.9.16 did). Each session start and each gateway renewal write
their version and a time to `versions.json`. A version up to 0.9.17 writes no
such time, so its lines in `events.log` (one per detection, each with its
version) show it. An old session that finds nothing and only renews a login is
not seen. The session start says the same once a day. Restart the sessions
that started before the time it names.

**The line of facts.** It names the source of names (off, a local service with
its answer time, a gateway, or one that does not answer), the number of
rules, the regions and the number of label languages.

## What the plugin runs, sends and fetches

- Runs: `bash hooks/run.sh <event>` (or `hooks/run.cmd` for Codex on Windows)
  → `hooks/dispatch.py` on the matching hook events. Each reads one JSON
  payload from stdin and prints one JSON object. A Bash command with a
  placeholder reads the value from a FIFO in the per-user runtime or temp
  directory (POSIX) or through `hooks/resolve.py` under a one-time grant
  (Windows Git Bash).
- The mod (Claude Code 2.1.287 and later) runs this computer's Python with the
  plugin's own `hooks/dispatch.py mod-prompt`, with fixed arguments and no shell,
  and hands it the prompt on stdin; ["The mod"](USING.md#handing-a-value-to-claude-on-purpose) lists each call.
- Writes: under `~/.maisecrets`: `index.json` (metadata and keyed
  fingerprints, never a value), `audit.log`, `events.log`, `hooks.log`,
  `pending/`, `.announced`, `destinations.json` (where each value went, never a
  value), `incidents.json` and `incident-marker.*` folders (maisecrets' own
  failures as closed codes), `vault-refs/` (the server tokens seen, the key ids
  and the endpoint of each server; never a value or a key; the values a server
  gave stay in the store while the session works, so their echo in a tool
  result is redacted: one hour after the session's last tool result, at most
  24 hours, and they go when the session ends); one
  `Client-Vault` header per user-scope MCP server in the config file the
  client uses (`~/.claude/.config.json` when it is not empty, else
  `~/.claude.json`), with a backup beside it ("Vault references"); in Codex one `http_headers_helper` line per such server in
  `~/.codex/config.toml` instead, with the helper `~/.maisecrets/bin/codex-vault-helper.py` and its state file
  `vault-refs/codex-helper.json`; the value FIFOs in the per-user runtime or temp
  directory; the vault backend; on a blocked prompt the clipboard. With
  `scrub_transcript` on, it masks the raw value inside the client's transcript
  file named in the hook payload, in place, because the client writes the
  prompt to disk before or after the hook runs. "For administrators" has the
  retention of each file.
- The skill runs `skills/secret-hygiene/scripts/scan_secrets.py` (reads files and
  `git log`) and `redact_copy.py` (writes a new file) when the model follows it; neither
  opens a network connection.
- Sends and fetches: no telemetry. The plugin downloads nothing, except the image of the optional local name
  service, which follows the plugin at a session start (`/maisecrets:ner updates off` keeps it). The other
  connections start from a command you run or a call that needs a value, and nothing else in the plugin opens one:
  - a Write, Edit or Bash call with a token that one of your own MCP servers
    sent: one metadata request and one resolve request to that server's own
    origin, over https, with this computer's key for that server ("Vault
    references"); `/maisecrets:status` makes the same request with no token;
  - the ssh route of your own ssh command inside the Claude Code sandbox
    (`hooks/proxy_connect.py`, the `ProxyCommand` of that ssh call): one
    CONNECT through Claude Code's local sandbox proxy (localhost only) to the
    host you named, with the proxy login that Claude Code puts in
    `HTTPS_PROXY` for that sandbox;
  - before an ssh command that carries a value, `hooks/sandbox_probe.py` checks
    that it runs inside that sandbox: it tries direct connections to 1.1.1.1:443,
    8.8.8.8:53 and 9.9.9.9:443 (the sandbox must refuse them) and one CONNECT with
    a wrong login to the local sandbox proxy. It sends no data, and it runs only
    when `SANDBOX_RUNTIME=1` and a local sandbox proxy are set;
  - `/maisecrets:report`: it prints the issue text and a prefilled link to
    `report_url` (the address carries the issue text, the plugin version, your
    platform and a rule name, never a value). It opens no browser and runs no
    program: the connection starts when you open the link.
- Credentials: the hooks and the mod fetch no credential for a request of
  their own. They read the values you stored, from your operating system's
  store, only to put each one into the tool call you allow, which then goes
  where that call goes. The two commands above use the login that belongs to
  them: the ssh route sends the sandbox proxy login from `HTTPS_PROXY` to the
  local sandbox proxy, and `gh` uses its own GitHub login. The Windows
  Credential Locker may roam through a Microsoft account (the operating system
  does that, not the plugin).

## Invisible characters

A tool result can carry text that the model reads and a person does not see. maisecrets removes two
kinds of such characters from every tool result (a file read, a command's output, a web page, an MCP
result, the keys of its JSON too) before the model reads it:

- **Unicode tag characters** (U+E0000 to U+E007F). Each one is the twin of an ASCII character, so a
  web page can hold a whole hidden instruction ("ASCII smuggling"). A value spelled in them goes
  away with them. Only the flags of England, Scotland and Wales keep their tags.
- **Variation selectors used as bytes** (U+FE00 to U+FE0F, U+E0100 to U+E01EF). By a rule of
  thumb, not the Unicode registry of variation sequences, a selector stays after a letter, a digit,
  punctuation or a symbol: VS15 or VS16 (text or emoji style) after any of them, VS1 to VS14 after
  one that is not ASCII, an ideographic selector after an assigned CJK ideograph. A second selector
  in a row, or one after a space, a control, a format, a combining, private or unassigned character,
  goes. "Assigned" means known to the Unicode version of the Python that runs the hook.

The zero-width joiner of emoji and the marks U+200E and U+200F stay. Bidi controls (U+202A to
U+202E, U+2066 to U+2069) stay too: they reorder what a person sees, but the model reads the text in
its logical order, and translation files need them. The file on disk does not change, only what
the model reads. In Codex, the session's rollout file holds the raw output, and a resumed session
reads it again: maisecrets overwrites each tag character, ideographic selector and VS1 to VS14 there
with spaces, at once and again whenever the file changes in the next 15 seconds. That rule is
blunter: in the rollout, the three flags and ideographic variants lose their selectors too. You get no question: one line says how many characters went, the model reads that they can
carry an instruction, and the audit log records the count, never the text.
`"strip_hidden_characters": false` turns it off.

This is not a detector of prompt injection. It takes away one way to hide one. A selector that the
rule keeps still holds something: one of three states (VS15, VS16, none) after any letter or
symbol, up to four bits after a character that is not ASCII, and up to one byte after a CJK
ideograph, where the rule keeps the ideographic selectors that Chinese and Japanese text use.

## Disguised values in tool results

A value can also hide from the shape rules behind what a terminal or a renderer does not show. In a
tool result or a file (not in a typed prompt), the detector also scans a cleaned copy: without ANSI
colour codes, without zero-width and direction characters (U+00AD, U+200B to U+200F, U+202A to
U+202E, U+2060 to U+2064, U+2066 to U+2069, U+FEFF), with HTML entities and fullwidth letters
written out, and with each base64 or hex run decoded that holds text (gzip inside base64 is opened,
a run inside the text is decoded once more). A hit in the copy redacts the original span, the hidden
characters with it; a value in a decoded run takes the whole run, as in a Kubernetes Secret or a
docker `auth` field. The copy is only scanned around the lines that changed. Bounds: a text over 1
MB is not cleaned, a run over 16,384 characters (an image) is not decoded, and at most 64 runs,
64 KB of decoded bytes per text. The bounds count work, not time, so a busy machine decodes the
same. A text whose every line changes (a log in colour) is scanned twice, which about doubles its
time. The typed prompt is scanned as it is, so a block there needs the value in the clear.

## Password exports in tool results

A password export holds bare passwords in a column, and no shape or label rule finds a bare password
in a cell. In a tool result or a file, maisecrets masks every cell of the password, TOTP and secret
columns of a CSV or TSV table (comma, semicolon or tab) whose header row also names an entry column
(`url`, `username`, `login`, `name`, `title`, ...) and holds plain column names at the start of its line (a function
signature, SQL or a sentence is no header: a name of several words counts only quoted,
and with two columns only names without a space such as `user_name,password`): the exports of Chrome, Edge, Firefox, Safari,
Bitwarden, 1Password, KeePass(XC) and LastPass have such a header. A table with a password column
and no entry column counts when the file read (or grepped) is named like an export (`passwords.csv`, `bitwarden_export.csv`,
`1PasswordExport.csv`, a LastPass or KeePass export). The table ends at an empty line or at a row of
another width. A column `password_hash` or a flag such as `has_password` is no secret column. A typed
prompt is scanned as before. Limits, chosen
against false hits on code and documents: a header name of several words counts only in quotes (an
unquoted `Login Name` in a TSV is no header); a two-column table without an export file name keeps a
cell with a space (a passphrase there reaches the model); a test table with a `password` column next
to a `name` column is masked like an export. The secret-hygiene skill scans a file over 200 KB in
parts, and a part without the header row is not recognised as an export.

## Gates around a resolve

A placeholder turns back into its value only here:

- **In the session where the value came in.** A reference resolves in the
  session where a human typed or pasted it, where the value was detected in a
  prompt, or where the value appeared in a tool result. A reference minted in
  session A resolves in session B only after you paste it into a prompt there.
  Keys are counters, so an injected text could otherwise name one it never saw.
- **Read up front in Bash.** The hook prefixes the command with
  `if __ms_1="$(cat <fifo>)" && [ -n "${__ms_1}" ]; then :; else …; exit 97; fi;` and turns `⟦SECRET_c1⟧` into
  `${__ms_1}` in its quoting context. A detached process serves the value once
  through a FIFO in a directory only you can enter (`$XDG_RUNTIME_DIR/maisecrets`
  where the system has one, else `maisecrets-<uid>` in the temp directory; owner
  and mode are checked, a symlink is refused). It is readable from inside Codex's
  sandbox, which can neither write the vault nor read the keychain, and from a
  Claude Code sandbox that denies `~/.maisecrets`. On POSIX no grant is minted,
  so nothing is redeemable afterwards; on Windows Git Bash the resolver script
  reads the value under a one-time grant. The command you approve, the transcript and the tool record carry no
  value. A missing delivery ends the whole command with exit 97 before
  anything runs, also for references inside pipelines and subshells; nothing
  ever runs with an empty value. Every key is checked before anything is
  served, so a refused command leaves no value waiting. A value with quotes or
  `$(` arrives byte for byte in the contexts the rewrite can prove: plain,
  `'…'`, `"…"`, inside `$(…)`, an unquoted heredoc. A placeholder inside
  another shell (`bash -c`, `ssh`, `eval`, `su -c`), a quoted heredoc, `$'…'`
  or backticks, an interpreter with inline code (`python3 -c`, `perl -e`),
  `awk -v`, and a command that would encode, slice or trace the value
  (`base64`, `xxd`, `${x:0:4}`, `set -x`, `PS4=`) are refused with the
  reason, because there the value would be parsed a second time or leave in a
  shape the redaction cannot see. The check reads command words, so
  `python3 script.py ⟦KEY⟧`, `docker run -e T=⟦KEY⟧ img` and a word inside
  quotes or a comment pass. A refused command is refused as a whole: split off
  the step that needs the value and run it on its own. For a value that goes
  into a document or a generated file (a PDF, a .docx, a page), the refusal of
  inline code and of a quoted heredoc names the route that works: save the
  generator as a script file and run it with the placeholder as its argument
  (`python3 make_pdf.py ⟦KEY⟧`), or put the placeholder into the file content
  with Write, Edit or apply_patch. The file on disk gets the value; the model
  keeps the placeholder (harness scenario `document_gets_the_value`, Claude Code
  and Codex). Where the rehydration setting refuses these routes too, the
  refusal names none of them. On Windows the argument route does not work
  where a shell placeholder is refused (Codex, and the PowerShell tool of
  Claude Code). There the refusal and the primer name the file route only:
  a text file with the placeholder alone on a line (apply_patch, Write or
  Edit), which the script reads; then the script runs with no placeholder in
  the command.
- **ssh through the Claude Code sandbox.** A value may go to your own servers
  over ssh on one condition: the command runs in Claude Code's Bash sandbox,
  where the operating system forces every connection through Claude Code's
  proxy and the proxy admits only the hosts you allow. Then the value goes
  on stdin. maisecrets adds no ask of its own by default: Claude Code's permission
  rules decide, as for any Bash command. With `"rehydration": "confirm"` Claude Code
  asks you first, showing the host and the remote command:

  ```
  printf '%s' ⟦EMAIL_c3⟧ | ssh aux01 'grep -F -f - /var/log/mail.log'
  ```

  Enable the sandbox in `~/.claude/settings.json`:

  ```json
  {"sandbox": {"enabled": true, "allowUnsandboxedCommands": false,
               "network": {"allowedDomains": ["aux01.example.com"], "strictAllowlist": true}}}
  ```

  maisecrets puts its own options first on the ssh line: a `ProxyCommand`
  (`hooks/proxy_connect.py`, because plain ssh has no network in the
  sandbox) and `ControlMaster=no`, `ControlPath=none`. Outside the sandbox the
  command stops before the value is read. Refused, with the reason:

  - a value inside ssh's arguments, a here-string or a heredoc into ssh;
  - a remote side that reads its program from stdin or passes the value on:
    no remote command, `bash`, `sh -s`, `python3` alone, `| sh`, `$SHELL`,
    `eval`, another `ssh`, `xargs sh -c`, and encoders such as `base64`;
  - an own proxy, jump host, shared connection, config file, host name or
    local command (`-J`, `-W`, `-S`, `-M`, `-F`, `-o ProxyCommand`,
    `-o HostName`, `-o LocalCommand`, …);
  - ssh on Codex, which has no host allowlist.

  What to know before you set it up:

  - The allowlist needs the host name ssh connects to, not the alias:
    `ssh -G aux01 | grep ^hostname` shows it.
  - Jump hosts (`ProxyJump` in `~/.ssh/config`) and connection sharing are
    off on this route: the sandbox proxy is the only way out.
  - The sandbox has no terminal and limits writes. Use a key without a
    passphrase prompt or an agent, and connect once outside the sandbox so
    the host key is in `~/.ssh/known_hosts`. `sudo ssh` drops the proxy
    variables and fails.
  - The remote command itself can pass the value on. The sandbox limits
    where the connection goes, not what the remote side does with the value.

  `"ssh_via_sandbox": false` switches the route off. Measured on macOS and
  Debian 13 with Claude Code 2.1.283.

  **One approval per session (opt-in, under `rehydration: confirm`).** With
  confirm, a search over many hosts asks for every command. Set
  `"ssh_approval": "per-session"` in
  `~/.maisecrets/config.json`: the first ssh use of a value asks once, and
  names this scope. After you allow it, the same value goes on stdin to ssh
  without a prompt for the rest of the session, at most 8 hours. The session
  approval covers only remote commands that read and print (`grep`, `zgrep`,
  `cat`, `tail`, `journalctl`, `sort`, `uniq -c` and the like), with no `>`,
  no `tee` and no `sort -o`. Any other remote command asks every time. The
  sandbox, the stdin rule and `allowedDomains` stay as they are: a host
  outside the list still gets a 403. The approval is recorded when the
  command you allowed reads the value, not when the prompt appears, so a
  declined prompt approves nothing. Measured in the macOS and the Linux
  (bubblewrap) sandbox against a real host with Claude Code 2.1.283
  (`harness/sandbox/ssh_e2e.py`). The default is `"per-command"`.
- **Inline for Write and Edit, and for a Codex patch.** In Codex a placeholder in the content
  lines of `apply_patch` resolves the same way, and a patch against the maisecrets home is
  refused (measured on codex-cli 0.158.0). A placeholder in the content of Write, Edit,
  MultiEdit or NotebookEdit is resolved like an MCP argument, under the same
  session rule, cap and audit line (the line names the file). When your
  permission rules ask (or with `rehydration: confirm`), the prompt shows the
  diff with the value: that is the moment you see what goes on disk. `"resolve_in_files": false` (a policy can set it)
  turns this off; then the file tools refuse a placeholder and the way to a
  file is a Bash command you approve (`printf '%s' ⟦KEY⟧ > file`). The
  maisecrets home itself is never written by the agent.
- **Codex gets "allow".** Codex accepts a rewritten input only together with
  `allow`. Measured with codex-cli 0.158.0 (`harness/codex.py --real`): the call
  of an MCP tool still needs the tool's approval in Codex
  (`mcp_text_field_rehydrate`), and a shell command still runs in Codex's
  sandbox: in a read-only sandbox the write is refused although the hook
  rewrote it (`allow_keeps_the_codex_sandbox`). Whether `allow` skips Codex's
  approval of an escalated shell command is not measured: `codex exec` offers
  no escalation. Codex 0.155.1 documented that it does, so on Codex treat the
  rewrite of a shell command as approved by maisecrets. On Claude Code the hook
  gives no decision, so the normal permission rules apply to the rewritten call.
- **Inline for MCP tools.** An argument has no shell to read from, so the value
  is inserted after the same session rule, cap and audit line, into every field
  that holds the placeholder. A field that carries published text (`text`,
  `message`, `body`, `comment`, `subject` …) is no exception: when you ask the
  agent to send a password over Slack, it goes out, and the model still sees
  only the placeholder. The client's permission rules decide whether the call
  runs.

## Detection rules

Four sources, one scanner (`maisecrets/detection/core.py`):

- **betterleaks** ruleset, vendored as data under `maisecrets/detection/rules/` (MIT,
  version in `BETTERLEAKS_VERSION`, refresh with `scripts/sync_betterleaks.py vX.Y.Z`):
  463 rules, 416 of them loaded. No betterleaks binary is used. betterleaks is the
  successor of gitleaks by the same maintainers; gitleaks takes security patches
  only since v8.30.1. Each rule's filter (an Expr expression: entropy limits,
  pattern lists) is read by `maisecrets/detection/rule_filter.py`; a rule whose filter is a
  program that module cannot read is left out (`generic-password`,
  `generic-username`, `generic-credential-uri`), and so are the 43 components that
  betterleaks never reports alone (`skipReport`). The BPE token ratio filter needs
  a tokenizer the standard library does not have; maisecrets answers 0 there, as
  betterleaks does without a tokenizer.
- **Own secret rules** (`maisecrets/detection/rules/own_secret_rules.json`, patterns
  derived from gitleaks v8.30.1, MIT): `generic-api-key`, to which the label
  filters of the detector are tuned, and nine token forms the betterleaks rules
  miss (Alibaba `LTAI`, Etsy, JFrog twice, a bare Fly.io token, an Atlassian
  token after a product name, a legacy Vault token, Twilio `SK`, Codecov). They
  run after betterleaks and only fill its gaps; a test drops each one that a
  later betterleaks finds itself. gitleaks itself is no longer vendored.
  Samsung CredData, line by line, without the test-vector repository, regions
  `de`: v0.6.17 has precision 0.929, recall 0.578 and F1 0.713 on tool results
  and files. On typed prompts it has 0.924, 0.527 and 0.671. With regions `us`,
  the US bank-account rule adds 546 false alarms (F1 0.690 and 0.649).
  `docs/BENCHMARKS.md` has the method, each release, a comparison with other
  tools and the commands to repeat it.
- **Presidio** pattern recognizers, vendored as data under `maisecrets/detection/rules/`
  (MIT, version in `PRESIDIO_VERSION`, refresh with `scripts/sync_presidio.py`):
  country-specific PII with scores and context words. The config key
  `regions` selects them (default: the country of the system setting; `de`
  gives Steuer-ID,
  Sozialversicherungsnummer, Personalausweis, Reisepass, USt-ID,
  Krankenversicherung, PLZ, Kfz, LANR, BSNR). Checksums for
  the German types, PESEL, the Spanish DNI and NIE, the NHS number, the ABA
  routing number and the codice fiscale are ported and checked against Presidio
  (`scripts/check_validators_against_presidio.py`). A digit-only shape such as
  a Steuer-ID is reported only with a context word nearby, even when the
  checksum passes. A USt-ID written `DE` and nine digits also needs a word
  such as `USt-IdNr` or `VAT` nearby: alone, that shape is often a FIX tag or
  an XML id. A Handelsregister number is not reported: it names a company, is
  public and is no personal data. Own rules (`REGIONAL_RULES` in
  `maisecrets/detection/core.py`) add what Presidio lacks: the Personalausweis and
  Reisepass number in the 9 characters the card prints (Presidio read the 9th
  as a check digit, which only the machine-readable zone carries), the
  Steuer-ID and the Rentenversicherungsnummer with the spaces of their printed
  form, and the Swiss and Austrian numbers. The Steuer-ID check follows the
  repeat rule of its issuer (exactly one digit twice or three times, never three
  in a row; ITZBund, "KONZEPT Steueridentifikationsnummer", version 2.3, 2016).
- **Crypto wallet secrets**: a BIP39 seed phrase (12 to 24 words of the
  English list, `maisecrets/detection/rules/bip39_english.txt`, MIT, whose checksum
  holds), a Bitcoin private key in Wallet Import Format and a BIP32 extended
  private key (`xprv`, `yprv`, `zprv`, `tprv`, …) are secrets by their checksum,
  with no label. A phrase of 12 words (a checksum of 4 bits) needs a word such
  as seed, wallet, recovery or password near it; 15 to 24 words stand alone.
  Addresses, extended public keys, the BIP39 reference vectors and a run of
  more than 48 list words (a word list) stay text. Not found yet: a phrase in
  a numbered list, a JSON array, or capitalised.
- **detect-secrets** (Yelp, Apache-2.0, version in `DETECT_SECRETS_VERSION`,
  refresh with `scripts/sync_detect_secrets.py vX.Y.Z`): credentials
  recognised by position (`password = …`, `api_key: "…"`, `user:pass@host`),
  with its heuristic filters ported (templated, indirect, sequential values
  are not secrets).
- **Own rules** for what none of the three covers: email (a
  bounded regex; the unbounded one took 11 s on an 80 KB dotted run), an email with its
  `@` written `%40` where an address is expected (after `=`, `mailto:`, `users/` or a mail
  word such as `To:`, or in a CSV column whose header names a mail address or its owner, such as
  `email`, `contact`, `login` or `courriel`), phone
  with a country code, `Bearer …` outside curl, `?api_key=…` in a URL, a
  password with no user in a URL (`redis://:…@host`), the secret half of an AWS
  key pair within a few lines after its `AKIA…` id (at most 4 lines on, and at most
  400 characters into its line, so a long line scans in linear time; the `-p` of mysql and
  the `-a` of redis-cli count only within 400 characters after the command word, for the same
  reason), and full-length GitLab
  runner and deploy tokens.
- Keys that a label names in a form the label rules do not read (0.6.16): each key in a list
  after a label that names secrets and nothing else (`"api_keys": ["…", "…"]`, `passwords =
  ['…']`, Go `Secrets: []string{"…"}`), to the end of the list; a value there must look like
  a key, so a name, a word-shaped identifier, a path, a password hash, a typed id (`pm_…`),
  an address (`0x…`) or a digest stays text, and a list after `tokens`, `code_tokens` or
  `keys` is not read (tokenizer output, cache keys); the value of an Elasticsearch
  `Authorization: ApiKey …` header (a header line, `curl -H`, a header object) that decodes
  from base64 to `id:key`; the scheme in prose stays text. A hex value after any other name
  stays text: a nonce, a checksum, an etag, a commit id and a key that a hex literal decodes
  into (`key = unhexlify('…')`, mostly published test vectors) are left out, as developer
  text is full of them (`tests/fp_corpus.py`).
- A password label and a literal value that is no word (0.6.16, `label-pw-literal`):
  `db_password = "…"`, `<password>…</password>`, `IDENTIFIED BY '…'`,
  `ConvertTo-SecureString '…'`, a value of 4 to 7 characters. The label comes from a frozen
  list of password words (`password`, `passwd`, `pwd`, `passphrase`, `kennwort`, …) and a list
  of words that make it name something else (`password_hint`, `passwordPolicy`, `bypass`). The
  value must be no word after undoing leet (`P4ssw0rd` is a word), no fixture (`testpass`),
  no mask, template or reference (`${DB_PASSWORD}`, `{{ … }}`, `settings.DB_PASSWORD`). The
  words come from `maisecrets/detection/rules/words_en.txt`, about 21,000 English words of 4 to 8
  letters from SCOWL (see `NOTICE`), read only when a password label is in the text. A miss in
  an English list is no evidence alone: the value needs a letter and a digit or a sign beside
  it (`_`, `-` and `.` join the words of a name and count as no sign), or (letters only) a
  mix of cases that no word boundary explains, letters of two scripts with case, or a
  lowercase run of 9 letters and more with fewer than 15 % vowels. So a word of another
  language (`senhaAtual`, `senha_atual`, `Pflicht`), a developer abbreviation (`ctxPtr`), a
  word in another script or with accents (a translated UI string), a path or a reference
  (`/run/secrets/db`, `./secrets/pw.txt`, `C:\keys\db.pw`, `vault:secret/db#pw`) and a
  value that is a whole regular expression after a secret label stay text. So do a
  number, a ratio, a time, a duration and a section (`95.2%`, `118/124`, `12:30`, `~30d`,
  `P90D`, `§3.2`), a dotted abbreviation and a word with a number (`Seite#3`). After the weak label `pass` (a boarding pass, a test pass) the
  value needs 8 characters of three classes. A comparison (`==`, `!=`), a label that is the tail
  of a path or a flag value, and an unquoted label before a comma (`f(password, "…")`) are no
  label and value. A word
  with a number and a sign (`Sommer2024!`, `Welcome1!`) is a password too; a word with a number
  alone (`Winter2023`) is left to the keyword rules. A passphrase of words
  (`passphrase: correct-horse-battery-staple`) stays text: the rule cannot tell it from a
  reference such as a Kubernetes secret name. A string that `+` continues, a version and a
  format template (`{pw}`) stay text too. Word-likeness and the label word classes follow Dan
  Szymkowiak's backlog ideas.
- A tool result or a file takes more (0.6.17): there, a value of ASCII letters after a password
  label is a password when no English word covers it, also without a digit, a sign or a mix of
  cases (`password = Some("pozkemva")`). A typed prompt keeps the rule above, because a false
  hit blocks a prompt; in a tool result it masks one value. Measures, durations, abbreviations
  and words in another script or with accents stay text in both. The secret-hygiene skill scans
  files, commits and tool results the same way.
- A word that a label rule takes in a tool result or a file blocks no later prompt (0.6.17): a
  value of letters only, with no evidence of chance and, in ASCII, at most one rare letter pair in
  ten (pairs counted in the word list). maisecrets stores it with a quiet mark: it still masks the
  word in every later tool result (a default word such as `postgres`, and since 0.6.38 an English
  word of the word list such as `fallback`, only where it was found; since 0.8.2 also an English word
  with an ending or of two words of the list, such as `directly` or `benchmarking`, and the word for
  password in another language, such as `contraseña`), but does not look for it in a
  typed prompt, also when this
  session used its placeholder in a command. A random value (`xqzvbnmq`) is looked for in prompts
  too, and so is a word the person gives in a prompt after a label, also when a tool result held
  it first. Only a value stored new from a tool result gets the mark; a value stored before 0.6.17
  has no mark and stays looked for. So a word that 0.6.16 stored from a file (field report) blocks
  prompts until it expires or `/maisecrets:forget` deletes it. A quiet English word that an older
  version stored is marked weak at the next session start.
  Limit, a trade for no blocked prompt: a password that is a word, or a random value of small
  letters that reads like one (about 3 in 100 of 8 letters, 1 in 200 of 12), and that a file or a
  tool result held first, is not looked for in a later prompt that has it without a label. It is
  still masked in every tool result.
  Limit of the word list: only English words count as words that are masked only where they were
  found. A common word of another language (`Wartungsfenster`), a name, a project term or an
  invented word that a label rule takes in a tool result is masked in every later tool result of
  every session until it expires or `/maisecrets:forget` deletes it. The word list makes this rare
  for English prose; it cannot remove it. A random value that reads like a word and is split into
  two words of the list or a word with an ending counts as a word too (measured: 369 of 190,508
  random values of 8 to 14 letters, 0.19 %); it is masked where it was found and not hunted in
  other texts. A word that a tool result stored and the person then gives as a password (with
  `/maisecrets:put` or after a label in a prompt) is hunted everywhere again. Since 0.8.2 a
  further place where the same tool result holds such a word without a label stays text, as for
  `fallback` since 0.6.38; before, the hunt masked it there too.
  Since 0.9.7 the same holds for a hit of a name or shape rule that is an English or developer word
  (a product name such as `Claude`, a JSON key such as `confidential`): it is masked where it was
  found and not hunted in other texts, also when this session used its placeholder in a command
  (#23). An entry that an older version stored is checked once at the next session start. A value
  stored with `/maisecrets:put`, a term and an imported value stay hunted.
- A key after a label that names a secret, in a form the keyword rules do not read (0.6.16):
  `<clientSecret>…</clientSecret>`, `<AccessToken>…</AccessToken>`, a short value
  (`label-secret-literal`, 8 characters and more); and a quoted key of 12 characters and more
  after a weak label (`hmac`, `session`, `cookie`, `psk`, `salt`, `seed`, `otp`, `key`,
  `appKey("…")`, `<key>…</key>`; `label-weak-key`). The value must have few word letters and a
  high entropy for its alphabet (a charset-normalised entropy, after Dan Szymkowiak's backlog
  idea). A key is ASCII. A label that names something else stays text: `public_key`,
  `cache_key`, `primary_key`, `object_key`, `idempotency_key`, `csrf_token`, a hex value after
  `key` and any value after `nonce`, `x-amz-signature` or `x-amz-credential` (but not after
  `x-amz-security-token`).
- A TOTP or HOTP seed after a one-time-password label (0.6.16, `label-otp-seed`): 16 to 64
  base32 capitals after a label with `totp`, `hotp`, `otp`, `mfa`, `2fa` or `authenticator`
  (`TOTP_SEED=…`, `otp_seed: …`). A code of digits, a word, a constant name and a mask stay
  text.
- The STS session token of temporary AWS credentials (0.6.16, `label-aws-session-token`): the
  value of `X-Amz-Security-Token` in a presigned URL (percent-encoded) or a header, 100 to 4096
  characters. The other `X-Amz-` parameters stay text: the key id in `X-Amz-Credential`, the
  signature, the date.
- Four token formats with a public prefix that the vendored rulesets lack (0.6.16): the third
  NTLMSSP message in base64 (`Authorization: NTLM TlRMTVNTUAAD…`; the negotiate and challenge
  messages carry no password-derived response and stay text), a NATS nkey seed (`SU…`, 58
  characters of base32), a PASERK secret, local or wrapped key (`k4.local.…`, `k4.secret.…`)
  and a PASETO token (`v4.local.…`, `v4.public.…`). A public nkey and a PASERK public key or
  key id stay text. A PASERK key ends at its last base64url character, never on a period of the
  sentence around it.
- Order: the rules that read a label and a literal value (`label-pw-literal`,
  `label-secret-literal`, `label-weak-key`, `label-otp-seed`) run after every other rule and
  take only a span no other rule took. The list rule, the four token formats, the
  Elasticsearch `ApiKey` rule and the AWS session token rule are own secret rules: they take
  their spans in the secret stage, before detect-secrets and betterleaks.
- Prefixes newer than the vendored rulesets live in
  `maisecrets/detection/rules/prefixes.txt`, one line each, extended by pull request
  (`CONTRIBUTING.md`): `glrt-`, `gldt-`, `whsec_`, `cfut_`, the last two
  found bare in real prompts on 2026-09-26, and since 0.6.19 Google OAuth
  access tokens (`ya29.`), Tailscale keys, Discord webhook URLs, Salesforce
  refresh tokens, Cloudflare `cfk_` and `cfat_`, HubSpot private app tokens,
  New Relic `NRAK-`, `NRII-`, `NRRA-`, `NRAA-`, `NRIQ-` and `px-api-`, Claude
  Code OAuth tokens (`sk-ant-oat01-`, `sk-ant-ort01-`), Flutterwave, Doppler,
  Square `sq0csp-`, Contentful, Mapbox `sk.`, Kong Konnect, SonarQube Cloud
  `sqco_`, Adafruit IO and TestPyPI tokens. A Telegram bot token, a Mailchimp key and a Discord bot
  token (its first part must decode to a user id) have no fixed prefix and are
  own rules. A client id such as Salesforce `3MVG9` or Square `sq0idp-` is
  public and stays text.
- A secret shape with a fixed length (betterleaks: `glpat-[\w-]{20}`) is
  extended to the end of the token characters, so a longer token does not
  leave its tail in the clear (found with a 24-char token, 2026-09-26).
  The extension stops at a line break: a token that a line break splits
  (a hard-wrapped terminal line) keeps the part after the break in the clear.
  Joining the next line was measured on five months of session logs and left
  out: nearly every candidate was the next `.env` line, not the rest of a key.

- Personal data after a label or in a fixed form (0.6.21, `maisecrets/detection/personal.py`), in a tool
  result or a file only: a name after a name label (`patient:`, `tenant:`, `full_name:`, `FN:`,
  `Ansprechpartner:`; after the weak labels `name`, `owner` and `author` only a value that does not
  read as English words or nouns, so `name: Customer Portal` stays text), a name before an e-mail
  address (`First Last <mail>`, not before a bot or a service mailbox), a date after a birth label
  (`DOB`, `Geburtsdatum`, `né le`, `fecha de nacimiento`; not after `born`), an ID number of five
  digits and more after an ID label (`MRN`, `passport no`, `DL`, `SIN`, `TFN`, `NIR`, `tax id`,
  `account number`), the user in `user:password@host` and in another person's home path
  (`/home/<user>/`, `C:\Users\<user>\`; service accounts and your own user name stay text), a
  street address with its postcode in the form of an active region (US, UK, IN; DE, AT, CH; FR,
  BE, LU; PT, BR, ES, IT; an address next to a company, office or landmark word stays text; when a
  legal form such as `GmbH`, `AG`, `Ltd` or `Inc` ends the company's name right before the address,
  its German postcode and a German VAT ID right after it stay text too; a person's name or record
  key nearby, an employer or job label, a second address, a sender's VAT label or a blank line keeps
  them masked, and so does a sole trader, who has no legal form; the setting `business_addresses`
  `mask` masks such an address as any address), and
  the cells of a CSV column for personal data (`address`, `dob`, `phone`, `ssn`, and a name or user
  column beside one of them; an address or a phone cell only in a row that also names a person). A
  typed prompt takes none of them: a hit blocks a prompt, and a
  person who types a name means to send it. Documentation names (`Erika Mustermann`, `John Doe`)
  stay text. `tests/fp_corpus_pii.py` holds 367 developer texts in these shapes that are no
  personal data (Kubernetes YAML, package authors that are teams, company addresses, dates that
  are no birth dates); the rules leave all of them alone.
- A phone number with one-digit groups after the country code (`+1 4 1 5 …`, 0.6.21): in a tool
  result, and in a typed prompt after a phone word; a US number in the national form
  `(312) 846-2291` after a phone word with region `us` or `ca`, in a tool result only (an area code
  and an exchange start with 2 to 9; the fictional 555 exchange stays text).
- Three token forms with a tail shorter than the vendored rules want (0.6.21): an OpenAI or
  Anthropic key (`sk-proj-`, `sk-ant-`, `sk-svcacct-`, `sk-admin-`; the tail needs a digit, a capital
  and a run of 16 letters and digits, so a CSS class such as `sk-admin-` and a long name stays text),
  a Slack token (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-` with digits and a hyphen first), and a Twilio
  Account SID (`AC` and 32 hex digits) next to its name; a counted fixture (`AC0123456789abcdef…`)
  stays text.

IBAN, credit card and IP come from Presidio's regexes with our validators
(mod-97, Luhn, public-range check). An IBAN may have spaces or hyphens
between its groups; an IBAN in lower case also needs the length of its
country. A card number without a word like "card", "Karte", "Kreditkarte",
"carte", "carta" or "tarjeta" nearby is not reported: Presidio scores the bare
shape low, and a 16-digit number passes Luhn one time in ten.

Measure what the rules would catch on your own recordings, values never
printed: `scripts/replay_sessions.py --claude --codex`.
