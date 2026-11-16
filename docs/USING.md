# Using maisecrets

For the person who works with maisecrets every day in Claude Code or Codex. This document says what you see,
which settings you choose, where the values go, how you check a value first, how you hand a value to the AI
on purpose, and what you do about a wrong hit. The install and the first steps are in the
[README](../README.md). The rules and settings for a team are in [ADMIN.md](ADMIN.md).

Contents:

- [Quick start](#quick-start)
- [What it looks like](#what-it-looks-like)
- [Secret hygiene skill](#secret-hygiene-skill)
- [Options](#options)
- [Vault](#vault)
- [Check a value first: ms:(…)](#check-a-value-first-ms)
- [Try it with real data: the demo mode](#try-it-with-real-data-the-demo-mode)
- [Handing a value to Claude on purpose](#handing-a-value-to-claude-on-purpose)
- [Reporting a wrong detection](#reporting-a-wrong-detection)
- [Reporting an internal failure](#reporting-an-internal-failure)
- [Test data that maisecrets leaves alone](#test-data-that-maisecrets-leaves-alone)
- [PDFs and images](#pdfs-and-images)
- [Terms: names, case numbers, customer names](#terms-names-case-numbers-customer-names)

## Quick start

```bash
claude plugin marketplace add Mcpgate-de/maisecrets
claude plugin install maisecrets@maisecrets     # then start a new session
```

```text
/maisecrets:status        what runs, which version
ms:(your value)           would this value be caught?
/maisecrets:settings      the choices you make
/maisecrets:not-a-secret KEY   a wrong hit: never mask this exact value again
/maisecrets:secret-hygiene   secrets that leaked before you installed it
```

Codex and other installs: [Install](ADMIN.md#install). More: [How it works](HOW-IT-WORKS.md#how-it-works) ·
[Threat model](THREAT-MODEL.md) · [Benchmarks](BENCHMARKS.md) · [Known gaps](KNOWN-GAPS.md#known-gaps-measured-or-documented).

## What it looks like

You ask Claude to set up a deploy script and it reads your `.env`:

```
$ cat .env                          # what the command printed
DB_PASSWORD=<the real password>
STRIPE_KEY=<the real Stripe key>

                                    # what the model received
DB_PASSWORD=⟦SECRET_c1⟧
STRIPE_KEY=⟦SECRET_c2⟧
```

Claude writes the deploy command with the placeholder. Claude Code's permission
prompt, if your rules ask for one, shows this, and only this:

```
printf '%s' ⟦SECRET_c1⟧ | ./migrate --password-stdin --host db.example.internal
```

At execution the placeholder is read once from your keychain, the request
carries the real password, and the command's output comes back with any
value replaced again. The password was never in the prompt, the transcript,
or the model's context.

You paste a token into the prompt by accident:

```
> please check why my GitLab token glpat-… fails in CI
maisecrets kept a secret from the AI.

  /maisecrets:send   send the cleaned prompt now
  ⌘V                 paste it to edit it first

A wrong hit? /maisecrets:not-a-secret SECRET_c3
```

With `/maisecrets:shortcut` installed, the first step names the short `/ms`.
Where no clipboard exists (Remote Control, SSH), the notice shows the cleaned
prompt under the `/ms` line instead of the paste line. The last line names the
stored value when there is one, else `KEY`; Codex has no `/ms` and names
`maisecrets: not a secret KEY`. When a subagent's report or a background
command's notice is blocked, the notice says so, and `/ms` passes it on with
placeholders.
Zero requests left the machine for that prompt. The rewritten prompt reads
`please check why ⟦SECRET_c3⟧ fails in CI`, and Claude can use the
placeholder in a command as above.

## Secret hygiene skill

The hooks stop a new value from reaching the model. The `secret-hygiene` skill deals with
values that already leaked. The model loads it when a task fits; in Claude Code it is also
`/maisecrets:secret-hygiene`. It does three things:

- **Check a repository.** `scan_secrets.py` lists the secrets in the working tree and, with
  `--history`, in every commit on every ref. A finding is a file, a line, a type, the rule, a
  length and a per-run id. The same id means the same value; the output never holds a value,
  a line of the file or a hash of the value, because the model reads it.
- **Install the protection.** A conversation starts with `protection_status.py`. It says ACTIVE
  only when a hook of the same agent ran for the call that started it. Otherwise the answer
  opens with an offer that names the source and the step the user must do, and the install
  commands run only after a yes. There is no offer in a web or mobile chat, and none without a
  Python 3.9 for the hooks. This is how the skill, which a store can list alone, brings the
  hooks along.
- **Check what the agents already received.** `audit_transcripts.py` reads the local Claude Code
  and Codex sessions and lists the secrets it finds in a prompt, a tool result or a model answer,
  so it reached Anthropic or OpenAI: by type, rule, dates and sessions, never by value. It reads the
  last 30 days by default (`--all` for all), tells the size and an estimate first (`--estimate` stops
  there), and shows its progress. The default fast scan runs the rules only near a line with a rule's
  prefix or label, so it can miss a value whose label stands more than three lines away; `--full`
  reads each record as one text with every rule, as before, and finds those too. On request
  it replaces the values in the local files (`--scrub`, then `--scrub --yes`), which does not
  take back what the provider received.
- **Check the saved approvals.** `audit_approvals.py` reads what the agents keep outside the
  repository: the user and project settings and the `allowedTools` of Claude Code, and the
  `rules/*.rules` and `config.toml` of Codex (it honours `CLAUDE_CONFIG_DIR` and `CODEX_HOME`).
  A command that you approved stays there as text, with any token in it. The report names the
  file and the place (`permissions.allow[3]`, `rules/default.rules line 12`), never the value,
  and it changes no file.
- **Contain a leak.** For a value that reached a chat, a commit, a log or a ticket, the skill
  gives the rotation steps per service from `references/rotation.md`: rotate first, clean up
  second. This part needs no shell, so it also works in a chat.
- **Make a file safe to share.** `redact_copy.py` writes `<name>.redacted<ext>` with every
  value replaced by `⟦TYPE_n⟧` and prints only the counts. The original is never changed.

The skill is not a guard. It works only when the model follows it, and it does not stop a
prompt. The history scan reads what each commit added; a value that entered only while a merge
conflict was resolved is not seen (`git log -p` shows no merge diff), and a file path that is
itself a secret is printed as it is. `python3 scripts/build_skill_zip.py` builds `dist/secret-hygiene.zip`, the
standalone skill with its own copy of the detector, for a skill upload without the plugin.

## Options

All options live in `~/.maisecrets/config.json` (next section) and take
effect on the next hook call. The manifest declares no `userConfig` on
purpose: Claude Code 2.1.223 rejects a manifest with that key and then loads
no hook at all, silently. A guard that vanishes on an older client is worse
than one without a settings dialog. At the first session start, and at every
start in test mode, a notice names the active store, its path and where to
change it. `python3 -m maisecrets.cli status` prints the same at any time.

### Settings you decide

`/maisecrets:settings` shows the settings that are yours to decide, grouped
(Protection, Using stored values, PDFs and images, Your screen), one card each: the value, its state (`not
decided`, `set by you`, `set by a policy`), what it does, and the command for
the next step:

```
Protection
  SSH consent · off · not decided
    Ask before each ssh command that changes something on a host.
    Turn on: /maisecrets:settings ssh_consent on
```

A key that is missing from `config.json` is not decided; `false` written there
is a decision, with the same effect. `--all` shows the advanced settings too.

To change one, send the change as your own prompt, alone:

```
/maisecrets:settings ssh_consent on
maisecrets: set ssh_consent on          (the same, and the form for Codex)
```

`on`, `off`, a choice the card names (`rehydration confirm`), or `default`,
which removes your decision so that the setting reads the default again.
The prompt hook writes `config.json`. After the slash command it lets the
command run on, which shows the new card; the sentence form is stopped and
does not reach the model. maisecrets changes a setting for nothing else: not
for a prompt the client injected (a scheduled task, a loop wakeup, an SDK
prompt), not for a prompt of a client that a program started (`claude -p`
and the Agent SDKs: its hook sees `CLAUDE_CODE_ENTRYPOINT=sdk-…`), not for a
subagent's report, and a Bash or PowerShell command that carries the change
(a nested `codex exec` or `claude -p` that would type it) is refused. The AI
can tell you about a setting and the prompt to send. A setting from a machine
policy cannot be changed here. The limit: a program that runs as you can
write the file itself, and maisecrets sees a command only as text (C22 in the
threat model).

**You see each loosened protection.** A change that loosens a protection (a
setting in the looser direction, such as `rehydration automatic`, a higher
cap or a new autonomous host) and each `/maisecrets:forget` write one line
in `~/.maisecrets/events.log`: the time, the kind, the key or setting (never
a value) and the route (typed prompt, slash command, cli). The next session
start shows you one sentence that lists them, once:

```
maisecrets: since the last session start, 2 protections were loosened: setting rehydration (typed prompt),
forget SECRET_c3 (cli). If you did not do this, check /maisecrets:settings and /maisecrets:list.
```

A program that runs as you can also change that file; the line makes an
ordinary agent's action visible, it does not stop one that evades.

**Hints.** maisecrets stays quiet until a case comes up that one of these
settings is about. Then the AI gets one sentence about it, and mentions it
once. For `ssh_consent` that case is the first ssh command that changes
something on a host (`ssh web1 'sudo systemctl restart nginx'`; not `ssh web1
uptime`; and only when the command succeeds: Claude Code reports a failed one
through another event). A hint comes once, also when hooks run at the same
time; if maisecrets cannot record it, it does not come at all. It does not come again after you decided, and
it does not come again because time passed: only a real change of the
feature brings it back, once. `"tips": false` turns hints off with the tips.
The settings list shows each hint as `not shown yet` or `shown` with its date;
`/maisecrets:settings hints reset` (or `maisecrets: reset hints`) lets them
come once more and changes no protection setting.

### Where your secrets went

maisecrets notes, on this computer only, where each stored secret was handed
to a tool call: a host named in the call (from a URL, also one in quoted text,
not one in a shell comment), an ssh host, or an MCP server and tool. In a Bash
command every host it names counts for each secret in it, also a second URL
that the value does not reach. A file or a command without a host is listed
apart, as a local use. `/maisecrets:list`
shows it under each secret:

```
SECRET_c7      SECRET  format       3d   14        21h  -
    Sent to (a record only; it allows nothing)
      other.example.net     1×     last less than an hour ago   new
      api.github.com        10+×   last 2 hours ago
    Used on this computer
      a file in ~/proj/     2–9×   last 3 days ago
```

With the default `observe` this is a record, not a permission, and it stops nothing. The value is handed
out before the client asks you, so a call waits until the client reports that
it ran (also when it failed), and only then is it listed. A call you decline in
Claude Code's dialog is not listed (measured with the real client, whose
headless mode refuses the question). Codex sends
the same report for a command that ran or failed; a call it declines by its
approval policy never reaches the hooks. A call without a call id is not
listed: nothing could show that it ran. `new` marks a destination first seen in the
last 24 hours. When a secret that you used at one destination
(3 times on one day) goes to a new one for the first time, the AI tells you
once, in a sentence; this note does not come again. maisecrets does not
judge whether a destination is safe.

To be asked before a secret goes to a host it never went to, send
`/maisecrets:settings secret_destinations protect` as your own prompt. The hosts
of a secret's first call are its own; a first call that only writes a file
has none, and a second call that starts before the first one ran gets no
first call of its own. If you decline that first call, it holds the secret's
first call until it would have expired (24 hours), so until then every host
asks; a first call that maisecrets refuses for another reason holds it for 30
seconds only. After that, a call to a new host asks you first in
Claude Code, and the question names the new host. A host whose name the
record cannot hold one to one (more than 80 characters, a secret shape in it)
asks each time. When you allow
it and the call runs, the host is known and asks no more; a call you decline
leaves it new. Codex cannot ask with a rewritten input, so there the call is
refused before any value is resolved; run that step yourself, or switch back
to `observe` for it. A file or a command without a host never asks. What the
record already holds when you switch counts as known. `/maisecrets:settings`
shows about how often protect would have asked in your own last 30 days:
once per call that took a secret to a host it never went to. It is an
estimate from the record: a call you declined is not in it. Protect binds
only what the call shows: a URL with `http://` or `https://`, an ssh host, an
MCP server and tool. A host without a scheme (`curl host/api`), a host after a
flag (`psql -h host`), a host built at run time, a variable, a script or a
proxy shows none, and the port of a URL does not count, so for a hard limit
use the sandbox's allowed hosts too. If the destination record cannot be
read, the call asks, and the question says so; if the first use of a secret
cannot be recorded, it is refused, and you try once more.
`/maisecrets:settings secret_destinations off` stops the
record; nothing leaves the computer either way. When a value expires, its
record goes with it (if the record is busy at that moment, it goes 30 days
later with the metadata); forget and wipe delete it too.

## Vault

`~/.maisecrets/config.json` (all optional):

```json
{
  "backend": "keychain",
  "ttl_seconds": {"default": 86400, "CARD": 3600},
  "max_ttl_seconds": 2592000,
  "renew_on_use": true,
  "scrub_transcript": true,
  "block_at_mentions": true,
  "rewrite_prompts": true,
  "strip_hidden_characters": true,
  "regions": ["auto"],
  "max_keys_per_session": 200,
  "max_resolves_per_hour": 1000,
  "report_url": "https://github.com/Mcpgate-de/maisecrets/issues"
}
```

`backend`: `keychain` (macOS), `windows-vault`, `encrypted-file` (Linux and
any other), `jsonfile` (test mode, plaintext). `tips`: `false` turns off the
one-line tip that appears once a day at session start.

`regions`: country codes, for example `["de", "us"]`. Each country adds its
Presidio rules for personal data, such as a German tax ID or a US social
security number. `ch` and `at` add maisecrets' own rules for Switzerland (AHV
number, company UID) and Austria (social insurance number, UID), for which
Presidio has none. The entry `auto` is the country of your system setting (on
macOS and Windows the system setting, not `LANG`). The default is `["auto"]`.
An empty list keeps the generic rules only. The old key `pii_regions` still
works.

Credential labels come in languages. The labels of every language below are
on, whatever your system language and regions: `password:`, `passwort:`,
`wachtwoord:`, `hasło:` and the others (since 0.8.2; before, only English and the
labels of your system language and of each region). The
labels are data files in `maisecrets/detection/rules/labels/`, one file per language.
A new language is one new file. Files exist for Chinese, Czech, Danish, Dutch,
English, Finnish, French, German, Italian, Japanese, Korean, Norwegian (Bokmål),
Polish, Portuguese, Russian, Spanish, Swedish, Thai and Turkish. With Chinese or
Japanese on, the fullwidth colon (`密码：`, `パスワード：`) and a sentence with no
space (`密码是…`, `パスワードは…`) count as a label too. Each word comes from
a reviewed translation of an open-source project, and
`docs/label-sources.md` names the source of each word. `/maisecrets:status` shows the regions and
the number of label languages; `/maisecrets:status all` also shows where they came from and each language.

Every entry has a TTL. Each use renews it, up to `max_ttl_seconds`. On
expiry the value is deleted and the metadata stays as a record. Commands:
`python3 -m maisecrets.cli list | get <KEY> | put | audit | expire | scan | config`.

**What the store does and does not do.** The keychain, the Credential Locker
and the encrypted file keep the value off the disk in plaintext and away from
other users. None of them stops a process that runs as you: `security`,
PowerShell or openssl hand the value to any such process without a dialog
(`docs/THREAT-MODEL.md`). The [gates around a resolve](HOW-IT-WORKS.md#gates-around-a-resolve) stand in front of the agent, not in
front of you.

## Check a value first: ms:(…)

Not sure whether maisecrets knows a password or a token? Send it in brackets
after `ms:` as your whole prompt:

```
> ms:(the-value-you-want-to-check)
✓ maisecrets masks this as a secret (⟦SECRET_…⟧). maisecrets knows this format, so it masks it wherever it appears, also alone.

This prompt was not sent. The value did not reach the AI.
```

```
> ms:(Kx7#another-value)
⚠ maisecrets did not catch this value. maisecrets stored it as ⟦SECRET_c4⟧. For 1 day after each use it is masked wherever it stands as a word of its own.

This prompt was not sent. The value did not reach the AI.
```

```
> ms:(two words)
⚠ maisecrets did not catch this value. It looks like ordinary text, so it was not stored. If it is a secret, store it with /maisecrets:put.

This prompt was not sent. The value did not reach the AI.
```

- **Report an unknown format.** When maisecrets did not catch a value with a fixed start (such as `sb_pat_`, before a
  random rest of 16 characters and more) and stores it, the answer offers a short issue link on a line of its own.
  It holds the value's shape only, as a pattern such as `sb_pat_[A-Za-z0-9]{32}`; the issue form asks which service
  issues the token. A value without a fixed start gets no link: no format rule can follow from it. You read the
  shape before you open the link; if the start is part of your secret, do not send it. The value is never in the
  link. With `report_url` set to `null` there is no link (docs/DETECTION-COVERAGE.md, loop 4).
- **Never sent.** A prompt that starts with `ms:(` (any case, blanks before it
  allowed) is always stopped, in Claude Code with and without the mod and in
  Codex, also when the closing `)` is missing. The mod never rewrites it: it
  drops the prompt and shows the verdict, and when maisecrets gives no verdict
  in time it drops the prompt all the same. Without the mod (Codex, an older
  Claude Code) the prompt hook blocks it and shows the verdict. Only you see
  the verdict. The prompt as you typed it is removed from the session
  transcript on disk (unless you turned `scrub_transcript` off), also when
  the prompt hook fails on it. Without the mod, a hook that cannot start at
  all (a half-updated plugin folder) blocks the prompt but does not clean the
  transcript. Blanks around the colon (`ms: (`) and the full-width `：（` of an
  input method count as the same start but store nothing; `ms:` without the
  bracket is an ordinary prompt.
- **The value** is the text between `ms:(` and the last `)`, or up to the end.
  One blank on each side is dropped, so `ms:( value )` and a key on its own
  lines between `ms:(` and `)` both work.
- **Several values** in one prompt: `ms:(first) ms:(second)`. Each value
  ends at its last `)` before the next `ms:(` (text after that `)` is not
  part of it), and each gets its own line (`Value 1: …`, `Value 2: …`). Each
  verdict is the one that value gets alone: a value is stored only after
  every value has its verdict. The prompt is not sent.
- **The verdict** is the one a normal prompt with that value gets: the
  detection rules, your rules of your own, your terms, the values already
  stored, the allow list and your regions. The answer names the type and the
  rule of each hit, never the value; a value that is caught is stored, as for
  a normal prompt.
- **Not caught:** when the value looks like a credential (no blanks, 8
  characters or more, a mix of letters, digits and signs or the randomness
  of a key; no word, no hex value, no id in capitals and digits, no date,
  version, file name or `name=value`), maisecrets stores it as
  `/maisecrets:put` does (type SECRET) and names its placeholder, so it is masked from then on wherever it
  stands as a word of its own (glued to other letters, it is not found). A
  passphrase with spaces is stored only when each word has a letter and a
  digit or a sign; it is found again alone on a line or after `:` or `=`, not
  inside a sentence, and the answer says so. It is not stored when the allow list
  allows it (the answer names the line), when it is shorter than 8
  characters or has more than one line (maisecrets could not find it again),
  when it looks like ordinary text (words, a sentence, a hash, an id, a
  command: the answer says so; store such a password with `/maisecrets:put`),
  when it looks like a test value (only words such as super, secret, geheim
  or test, and digits, also after a label: `passwort: supergeheim123`; the
  rules leave such a value alone on purpose, and the answer says so),
  when it holds a placeholder, or when the prompt did not come from you (a
  scheduled prompt, a subagent, `claude -p`). The client's own list of earlier
  prompts (the up arrow) may keep the prompt as typed; that is not measured.
- **Finding it.** Claude Code names `ms:(…)` once, under the first prompt that
  was blocked or rewritten because it carried a value; Codex names it once at
  a session start. `/maisecrets:settings` lists it under "Feature hints", and
  `/maisecrets:settings hints reset` shows it again.

In Remote Control the block notice is not shown (see "Sending a blocked
prompt" below), so the verdict is not visible there; the value is still not
sent.

## Try it with real data: the demo mode

`ms:(…)` checks one value. To see what maisecrets does with a whole text, such
as a real customer mail, switch the demo mode on. Type it as your own prompt:

```
/maisecrets:demo on          (Codex: maisecrets: demo on)
```

While the demo is on, maisecrets answers each prompt of this session itself,
and no prompt reaches the AI:

```
maisecrets demo: nothing was sent to the AI.
It masks 1 secret, 1 e-mail address.

Please check the token ⟦SECRET_c1⟧ and write to ⟦EMAIL_c1:jo•••@•••.de⟧ today

/maisecrets:demo off to send again
```

- **The values are stored** as when you send a prompt, so the placeholders are
  the normal ones. Only the sending is replaced by this answer.
- **A long text** shows its first 20 lines and the count of the rest. When
  maisecrets masked something, the full masked text goes to the clipboard,
  where one exists.
- **Names.** In Claude Code a name service (`/maisecrets:ner`) takes part as
  for a normal prompt. A service on the network reads a prompt only when you
  turn its prompts on (`/maisecrets:ner prompts on`).
- **Only your own commands pass, in their exact form:** `/maisecrets:demo off`,
  the settings, `ms:(…)`, `/maisecrets:term`, `/maisecrets:not-a-secret`, and
  for example `/maisecrets:status`, `/maisecrets:status all` or
  `/maisecrets:list`. A command with other text after it gets the demo answer.
  `/ms` and `/maisecrets:send` send nothing during the demo.
  `/maisecrets:status` shows a `!` line while the demo is on.
- **A pasted image** goes nowhere during the demo: the demo blocks the whole
  prompt, also an image alone (measured on Claude Code 2.1.325). It does not
  read the image.
- **If the demo state cannot be read** (a damaged file), maisecrets sends no
  prompt of any session until you type `/maisecrets:demo off`, which resets it.
- **It ends** with `/maisecrets:demo off` or with the session. A new session or
  `/clear` ends it: `/clear` starts a new session (measured on Claude Code
  2.1.325). Only your own typed prompt switches it: a subagent, a program
  (`claude -p`), a scheduled prompt or a tool call changes nothing.
- In Claude Code the answer comes as one line ("Prompt dropped by a hook"),
  and a line break of the prompt shows as ↵. The screen shows the placeholders
  there, also with `show_values` on. In Codex the block shows the answer.

## Handing a value to Claude on purpose

Paste it. A value with a known shape (a token, a key, an IBAN) is blocked,
stored, and comes back as a placeholder in your clipboard. A password without
a shape needs a label or the vault command:

- label it: `password: …`, `passwort: …`, `api_key=…` (labels in 19 languages are
  recognised; a value that is no word counts from 4 characters, after the weak label `pass`
  from 8, so `password: yes` is not a hit);
- or copy the value and run `/maisecrets:put` in Claude Code; the placeholder
  replaces the value in your clipboard. Paste the placeholder into your next
  message, and Claude uses it in commands and tool calls. Over SSH and in a
  headless session there is no clipboard: type the value after a label
  (`passwort: …`) instead; the block stores it and names the placeholder.

A bare password in prose, such as "use Sommer2026 for the login", is not
detected. That is a limit of pattern detection, not a setting.

**The mod.** Claude Code 2.1.287 and later loads JavaScript middleware from a
plugin ("mods"). maisecrets ships one in its own folder: `claude-mod/maisecrets-mod.mjs`,
named by the manifest (`"hooks": "./claude-mod/maisecrets-mod.json"`). Nothing else in
the plugin points into that folder.

- **The events it handles:** `prompt.submit`, which fires when a prompt is about
  to be sent, and for the values on your screen (below) `ui.render` of a reply
  (`AssistantMessage`), of your own prompt (`UserMessage`), of a tool call and its
  result (`ToolUse`, `ToolResult`) and `session.start`. The mod handles the event; it never calls `$.prompt.submit` itself,
  so it submits no prompt and changes no prompt of other code. It acts on a
  person's own prompt only (typed or queued at the terminal, sent through Remote
  Control, or the turn of `claude -p`). A subagent's report, another session's or
  a channel's message goes on unchanged to the settings hook.
- **What it reads:** the text of that prompt, the session id and the session's
  working directory. It reads no environment variable and no file.
- **What it runs:** this computer's Python with the plugin's own
  `hooks/dispatch.py mod-prompt`, the same code the settings hooks run, in the
  plugin folder. Each call is fixed text, with no shell: `python3 hooks/dispatch.py
  mod-prompt`; when that cannot start or ends with an error (on Windows `python3`
  is often a store stub, and `dispatch.py` refuses a Python older than 3.9),
  `py -3 …`, then `python …`. All tries share one limit of 8 seconds. It sets
  `PYTHONUTF8=1` for that process (over the environment it inherits), so that
  Windows reads the pipe as UTF-8. When no Python answers, the mod passes the
  prompt on unchanged and the settings hook blocks it.
  For the screen it runs the same way `hooks/dispatch.py mod-values` (the
  values of the placeholders in view) and, on your click on a gateway
  reference, `hooks/dispatch.py mod-reveal`.
- **What it sends, and where:** the prompt, the session id and the working
  directory go to that local process on stdin. The process detects the values,
  stores them in the local store, and answers with the prompt with placeholders.
  The mod passes that text on to Claude Code in place of the prompt. Nothing goes
  to a network address: the mod makes no network call, and the launcher has none.
  The process also starts the local transcript scrub, which masks the values in
  this session's transcript file on disk.

The settings hook in `hooks/hooks.json` runs after the mod and stays the gate.
When the mod does not load, fails, times out or gets an answer of another shape,
the prompt reaches the hook unchanged and the hook blocks it. `hooks/hooks.json`
is unchanged, so Codex and an older Claude Code keep the block. Measured on
2.1.291: the request holds the placeholder and not the value, also for a prompt
typed while a tool runs; the settings hook sees the placeholder; on 2.1.274 the
mod does not load and the hook blocks. Seen live in the desktop app's Code tab
with Claude Code 2.1.288: the prompt is rewritten and the model gets the
placeholder; your own message bubble there shows the text as you typed it, which
is the app's local display. Cowork is not measured. Mods are a rollout switch of the client:
where they are off (a saved switch, some third-party setups), the hook blocks.

**Values on your screen (`show_values`).** In Claude Code with mods, the mod
draws a reply or a tool result again with each value of your store in place
of its placeholder, as inline code with a lock: `Max Mustermann 🔒`. Claude
and the transcript keep the placeholder. Only the drawing on your screen
changes, and it reaches no model request, no transcript, no debug log and no
`/export` file (measured on Claude Code 2.1.319, `harness/screen.py`).

| `show_values` | What you see |
|---|---|
| `always` (default) | Each value stands in the text. A click copies it, and a toast says that Claude knows only the placeholder. |
| `click` | Placeholders. A click on one shows every value of that reply for 10 seconds; a sent prompt hides them. |
| `off` | Placeholders only, as before. |

A secret (a password, a key, a token: `⟦SECRET_c1⟧`, `⟦sref:secret:…⟧`) never
shows on the screen in any mode, so a screenshot or a shared screen does not
carry it. Its placeholder stays, with a 🔒 where the value is at hand, and a
click copies it.

Change it with `/maisecrets:settings show_values click` as your own prompt. A
policy can set `click` or `off` for everyone. A change towards `always` is
logged as a loosened protection.

- **Where:** the fullscreen terminal of Claude Code (its default layout) and
  the Code tab of the desktop app. On the terminal's main screen
  (`CLAUDE_CODE_NO_FLICKER=0`) the drawing would stay in the scrollback and in
  `/export`, so the mod draws nothing there. VS Code and the phone also keep
  the placeholders.
- **Which values:** only values of this computer's store that this session may
  use (the session rule of every resolve). A display of these is no use of a
  value: no audit line, no limiter, no renewal.
- **Sensitive References of a gateway** resolve for the screen only on your
  click, through the gateway's display sink and its own scope: the first click
  shows the value, a second click copies it. Each click costs the gateway's
  quota and writes its audit. A secret is never drawn: one click copies it.
- **How:** the mod asks `python3 hooks/dispatch.py mod-values` (the same
  fixed command lines as the prompt path) for the keys of the replies in view.
  A reply outside the view asks for nothing until you scroll to it. The values
  live only in the mod's memory, at most 500, and are gone with the session.
  The AI cannot ask the same question: a Bash command that names this entry is
  refused, and a value in a tool output is masked again.
- **Terminal.app** shows no embedded links: Claude Code writes the URL after
  the text. There the values have no link, and you copy one by selecting it.
- **Screen sharing:** `always` shows every value in view. Use `click` or `off`
  when others can see your screen.
- **Other plugins** get the tool output before maisecrets masks it for the
  model, because Claude Code gives every hook the same payload. A plugin that
  logs tool output can store a value in clear text (#29). Measured on
  2026-11-08: a memory plugin wrote the search text of its recall, built from
  tool output, into its own event log. Check what your other plugins log.

**Sending a blocked prompt.** `/maisecrets:send` sends the rewritten prompt as
it is, without the clipboard. A plugin cannot register a command without its
namespace, so `/maisecrets:shortcut [name]` writes a personal `/ms` for it
into `~/.claude/commands` when you ask for it (a fixed wrapper in
`~/.maisecrets/bin` finds the installed plugin at run time, so it survives
updates); an existing `/ms` is left alone, `--remove` takes it away. The first
session start only names the command, once; `"shortcut": false` turns that
off. Codex gets no offer, because it has no plugin slash commands. The answer starts with `Sent: ` and the
text that went out, because Remote Control shows neither a blocked prompt nor
a slash command's expansion; the block notice itself is not shown there
either (reported to the vendor).

## Reporting a wrong detection

Every block and every redaction leaves an event in `~/.maisecrets/events.log`
(hook, client, rule name, type, plugin version; never a value). In Claude Code,
`/maisecrets:report last <why it is wrong>` prepares an issue from the last
event; `/maisecrets:report bug <what happened>` and
`/maisecrets:report feature <what it should do>` prepare one without an event.
The command prints the text and a prefilled link, so it also works over ssh and
in Remote Control. It opens no browser and files nothing: you open the link,
check the text in GitHub's form and decide there (`--create` is gone; to file
from a terminal, use `gh issue create` yourself). The arguments reach the CLI in
a quoted heredoc, so a shell never reads a reported command as code.
The CLI form is `python3 -m maisecrets.cli report …`. The value is not in the
event, so it cannot be in the issue; describe its shape in words.

A wrong hit that should stay unmasked from now on: type `/maisecrets:not-a-secret KEY` as your own prompt
(Codex: `maisecrets: not a secret KEY`). ["A wrong hit in one step"](ADMIN.md#rules-of-your-own) says what
it does and how `undo` takes it back.

## Reporting an internal failure

When maisecrets itself fails (a locked store, a store call that times out, no
Python for the hooks), it notes a closed code in `~/.maisecrets/incidents.json`
on this computer: the code, a cause, the client, the tool class (`Bash`, `MCP`,
…, never a tool's name), a count, the number of days in the last 30 and the
plugin version. It never holds an error text, a path, a prompt, a command, a
tool's input or output, a session id or a value; a field outside its closed
form drops the entry. Nothing is sent.

In Claude Code, type `/maisecrets:report incident`. The prompt hook shows the
report to you only; the model sees neither the report nor the link, and it works
also while the store is damaged. Open the link, check the text in GitHub's form
and decide there. In Codex and in a terminal, run
`<plugin folder>/hooks/run.sh report incident` (`hooks\run.cmd` on Windows; a
refusal names the full path); `report incident clear` deletes the record, and
`wipe` deletes it too. A refusal caused by maisecrets' own
failure names this command. The design is in `docs/DIAGNOSTICS.md` of the
repository.

## Test data that maisecrets leaves alone

maisecrets steps in only when a value that it can detect goes to the AI. Test data
does not need to look like a real secret, and these forms are never a hit:

- **In test code** (a file under `tests/`, `test_*.py`, `*_test.go`, `*.spec.ts`,
  `conftest.py`, or code after `def test_`, `assert`, `describe(`), a password that
  maisecrets finds only by its label (`password = "<value>"`) is a fixture.
  A token shape (`glpat-…`, `AKIA…`, a private key) and personal data are still found
  there: a real token in a test is a leak.
- **Anywhere:** a value that names itself (`testpass`, `secret123`, `Passw0rd!`,
  `my-test-token`), a placeholder (`<your-token>`, `${API_KEY}`, `{password}`,
  `changeme`, `xxxxxxxx`, `***`), and a default equal to its label or user
  (`POSTGRES_PASSWORD: postgres`, `admin:admin`).
- **Addresses:** e-mail at `example.com`, `example.org`, `example.net` and the domains
  `.test`, `.example`, `.invalid`, `.localhost`, a system mailbox such as `alerts@` or `noreply@`
  at `.local` or `.internal` (a person's mailbox there is found); IP addresses in
  the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and
  `2001:db8::/32`, private and loopback addresses, the public resolvers (`8.8.8.8`,
  `1.1.1.1` and their IPv6 forms). An IPv6 address that wraps an IPv4 (6to4, Teredo, NAT64
  `64:ff9b::/96`) is judged by the IPv4 it carries.
- **A test value that vendor documentation publishes,** for its own type only: the payment
  test cards (Stripe, Braintree), the Stripe API reference keys, the jwt.io example token and
  the Twilio test numbers (`maisecrets/detection/rules/public_test_values.txt`, as sha256 digests). The
  same digits under another type stay a hit: an IBAN or a bank account that holds a test
  card's digits is found. A published key that a label assigns (`PROD_PASSWORD=…`,
  `api_key: …`, `?token=…`) is used as a credential there and stays a hit.
- **An AWS key id in a SigV4 credential scope:** `X-Amz-Credential=AKIA…` in a presigned
  URL, `Credential=AKIA…` in an `Authorization` header. The id names the key; it is not
  the secret half. The same id anywhere else is still found.

If maisecrets stops something that is not a secret, `/maisecrets:report last <why>`
sends the rule name, never the value.

## PDFs and images

maisecrets cannot look inside an image or a PDF. When the AI reads one, the
client sends its bytes to the model, and a password or an address in it goes
along. You decide what happens, per type:

| Setting | `allow` (default) | `ask` | `block` | `convert` |
|---|---|---|---|---|
| `read_pdf` | the PDF goes as it is | Claude Code asks you first | refused | only its text goes, masked |
| `read_image` | the image goes as it is | Claude Code asks you first | refused | (no: maisecrets does no OCR) |

Send one setting as your own prompt, for example:

```
/maisecrets:settings read_pdf convert
maisecrets: set read_pdf convert          (the same, and the form for Codex)
```

Then ask the AI to read a PDF (measured with the Claude Code CLI). With
`convert`, the program `pdftotext` extracts the text on your computer, the
normal redaction masks it (as a tool result, so also a password after a
label and a value in a disguise), and the model gets that text in place of
the PDF, with placeholders of the form `⟦SECRET_cN⟧`. The PDF itself never
reaches the model and does not stay in the session transcript. A page range
(`pages`) works; Claude Code then also writes the pages as JPG files into a
folder of its own on your disk, and maisecrets does not clean those.
`convert` needs `pdftotext`: macOS `brew install poppler`, Debian or Ubuntu
`sudo apt install poppler-utils`.

maisecrets runs `pdftotext` only from the fixed install folders
(`/opt/homebrew/bin`, `/usr/local/bin`, `/opt/local/bin`, `/usr/bin`), never
from the PATH: a program the AI puts on the PATH must not run inside the
hook. Every folder from `/` down to the program, and down to each library
the program loads, must belong to root or to you. No other account may be
able to write it (also not through an access control list), except a group
whose members can become root anyway:
`admin` and `wheel` on macOS, `sudo` on Debian, `sudo` and `admin` on
Ubuntu, `wheel` on Fedora and its relatives (the default sudoers of each,
measured 2026-10-14). So a second admin account on a Mac no longer stops
`convert`. maisecrets reads the libraries itself (33 for Homebrew's
pdftotext of poppler 26.10.0; `ldd` on Linux), and it does not run a program
whose libraries it cannot name. It starts pdftotext without `LD_*` and
`DYLD_*` variables. The Homebrew folder belongs to you, and the AI runs as
you: it could still replace the pdftotext there or a library, and maisecrets
cannot tell. maisecrets keeps values out of the model and the transcript; it
does not contain an agent that works against it on purpose. On Windows there
is no such folder, so `convert` refuses there. Without pdftotext, maisecrets
refuses every PDF and says so; it never lets the PDF through.

A PDF that pdftotext cannot read in 6 seconds, that makes pdftotext use more
than 512 MB of memory, or that is damaged, is refused. A PDF locked by a
password is refused too, and the AI is told that cause and not to ask you
for the password; save a copy without the password and give the AI that
copy. A PDF with only an owner password (it opens without one and limits
printing or copying) converts, AES-256 included (measured with poppler
26.10.0). A crafted PDF of a few
MB can make pdftotext take 1.5 GB in 2.4 seconds: maisecrets watches the
memory of pdftotext every 50 ms while it waits and stops it there (macOS does not
enforce a memory limit on a process, measured; on Linux the kernel limits
it to 1 GB as well). Text after 32K characters is cut, and the AI is told to
read a smaller page range. A scanned PDF has no text, or only page numbers
or a header line: below 25 characters of text per page, maisecrets says that
the PDF looks scanned, and the AI gets nothing of it.

**Measured on 2026-10-14** (Claude Code 2.1.300, poppler 26.10.0, a corpus
of 24 generated PDFs with 168 planted values): pdftotext found 151 of the
values, pypdf 136. pypdf failed on text written one character at a time and
on form fields, has no time limit (one page took 14 s on Python 3.14, 47 s on
3.9) and needs `typing_extensions` on 3.9, so maisecrets keeps pdftotext; a
bundled pypdf stays an option for Windows later. pdftotext missed a page
rotated by 90 degrees (that page counts as scanned) and two values whose
label stood in the table cell beside them. How a PDF reaches the model: "read x.pdf" and a pasted path go
through the Read tool, and the hooks see the file; `@x.pdf` gives the model
only the name and the size, and the model then calls Read itself. No route
that was measured passes around the hooks. The interactive terminal UI was
not measured.

Until you decide, the first PDF and the first image the AI reads bring one
sentence about the setting (`"tips": false` silences it). If `config.json`
cannot be read (bad JSON, a value of the wrong type), both settings count as
`block` until you fix the file.

**What `block` stops, and what it does not.** The settings act on the Read
tool of Claude Code: `block` means "the Read tool does not open this PDF or
image". They do not stop a shell command that reads the file: `pdftotext
x.pdf -`, `strings x.pdf` or `cat` give the AI text, and maisecrets redacts
that text like any other command output (a secret with a known form is
masked, the rest of the text is not). maisecrets is no file cleaner and does
not refuse such commands.

**Codex.** Codex has no Read tool, and it gives a hook a command's output as
plain text without an image flag (measured on codex-cli 0.159.2). So on
Codex these settings change nothing that was measured: its `view_image` tool
is not measured, and a command output there is scanned as text, like every
other output. The typed form `maisecrets: set read_pdf …` still works and
holds for a later Claude Code session.

`clean_dirs` lists folders whose PDFs and images you know are clean (your own
screenshots, for example). A read there is allowed:
`/maisecrets:settings clean_dirs add ~/Pictures/Screenshots`, and `remove` the
same way. maisecrets resolves links and `..` first, so a link inside a clean
folder that points out of it does not count. A file counts only if it was in
the folder before the session began and has no second name (hard link): a
file that arrives during the session, also one that the AI copies, moves or
links there, waits for the next session. maisecrets refuses `/`, your home
folder, a folder that holds the folder the session works in, and a folder
that is a link or lies under one (add the real folder). The folder itself is
noted with the session: another folder moved or linked in under its name does
not count, and neither does a subfolder moved in during the session. The start of
the session is a note that maisecrets writes at the session start, never
later; without the note nothing in the folder is clean. A client that the AI
starts inside its own session (`claude -p` from its shell) trusts no clean
folder. `clean_dirs` works on macOS and Linux; on Windows no file in it counts
as clean, because there a moved file keeps its creation time.

With `ask`, a file goes to the AI only after you said yes to that very read: a
file that was not asked about (it was in a clean folder a moment before, or a
notebook got an image after the question) is withheld. maisecrets also keeps a
checksum of the file you allowed (and of a file in a clean folder) and checks
that the AI gets those very bytes. A file above 64 MB cannot be checked: it is
never clean, and with `ask` maisecrets refuses it before it asks you. For a
large image that Claude Code shrinks, a page range of a PDF and a notebook,
the client sends no copy of the file itself; maisecrets then checks the size
and the file as it is after the read, which leaves a short window.

A Bash command whose output starts with `data:image/…;base64,` sends an image
to the model too (Claude Code shows it as one and marks it `isImage`);
`read_image` decides about it. Only the image itself skips the scan: the
error output of the same command is redacted as usual. `ask` cannot ask
after the command ran, so it withholds the output, like `block`.

A notebook (`.ipynb`) whose output cells hold an image: with `ask` Claude
Code asks you first, and with `block` the AI gets the cells as text and each
image as a note that it was withheld. The cells are always redacted; the image
data is not scanned. Claude Code itself drops the outputs of a notebook when
they are large (measured on 2.1.296: an image of about 8 KB or more): the AI
then reads only a note to run `cat <notebook> | jq '.cells[0].outputs'` in
Bash, and that output is text, which maisecrets redacts like any output.

**Not covered:** maisecrets cannot read or mask an image you paste into the
prompt (Ctrl+V or drag of an image into Claude Code). The prompt hook runs for
that prompt, but it gets only the text: `[Image #1]` in the terminal, an empty
text for an image alone in `claude -p` (measured on 2.1.325). When the hook
blocks the prompt, the image does not go either; in the demo mode that is each
prompt. An image in the result of an MCP tool is not covered either.

## Terms: names, case numbers, customer names

A name has no shape, so no rule finds it. Tell maisecrets the names you keep
from the AI, and it masks them like a secret. The design is based on the
personal-terms design by [@danszymkowiak](https://github.com/danszymkowiak):
his file form, his match modes, and his rule that no message shows a term.

**Add a name.** Type it as your own prompt:

```
/maisecrets:term add Jan Kowalski
maisecrets: term add Jan Kowalski          (the same, and the form for Codex)
```

maisecrets writes the name to `~/.maisecrets/terms.txt` and does not send the
prompt to the model. From the next tool result on, `Jan Kowalski` becomes a
placeholder such as `⟦NAME_c3⟧`.

When you add a name of two or more words, maisecrets also adds the last word
alone and its genitive (`Kowalski | Kowalskis`), if it has 4 letters or more
and is not a common word. So `Herr Kowalski`, `Kowalskis Bericht`,
`Kowalski, Jan` and `J. Kowalski` are masked too. It adds them as whole words,
never as a stem with `*`: `Koch*` would mask `Kochen`, `Lang*` would mask
`language`. Type a stem yourself when you want one (`Kowalsk*`). A surname that
is also a word (`Jobs`, `Wolf`) is masked where it stands alone as that word. The joined forms `jan.kowalski`,
`Jan-Kowalski` and `jan_kowalski` (also in `jan_kowalski.pdf`) are masked as
one word. The first name alone stays visible: `Jan` is a common word, and
masking it would hide every other Jan. To mask it anyway, add it as a term
of its own. The answer to the command says what maisecrets added. A typing
error such as `/maisecrets:terms add …` or `maisecrets term add …` is not
sent to the model either: maisecrets shows the correct form.

A name inside a value that maisecrets stores never splits it. A password such
as `Kowalski#Lato2024` stays one value: it is masked whole, in the prompt and
in every later tool result, and never as a name with the rest in clear.

`/maisecrets:term remove Jan Kowalski` (or
`remove ⟦NAME_c3⟧`, the placeholder copied from a result) takes it off.
`/maisecrets:term` alone shows your lists. Only your typed prompt changes the
list, as with a setting (C22): a removal in a tool call is refused.

**Mark a name once.** Write `{{Jan Kowalski}}` in a prompt. maisecrets masks
the name in that prompt and in every tool result until the lifetime of a
name value ends (`ttl_seconds`, one day by default); it does not write
`terms.txt`. A marker is 1 to 5 words of letters (a hyphen or an apostrophe
inside a word), and one word starts with a capital letter. So
`{{ .Values.image.tag }}` and `{{ item }}` stay text, and so do one letter
and one common word alone (`{{A}}`, `{{The}}`). One word alone with a space
inside the braces or with a capital inside it (`{{ Title }}`,
`{{FirstName}}`) is the form of a template and stays text; mark a one-word
name such as `{{McDonald}}` with `/maisecrets:term add`. A name of two or
more words is marked in any of these forms (`{{Ronald McDonald}}`,
`{{ Jan Kowalski }}`). A marker counts only in a
prompt that you typed at the composer or over Remote Control, not in one that
a program or a subagent sent.

**The file.** `~/.maisecrets/terms.txt` holds one entity per line: a label,
then the variants, separated by `|`. `#` starts a comment.

```
# label      variants
PERSON_A     Jan Kowalski | Kowalsk* | Jan
CLIENT_B     Acme Holding | *acme-0042*
EMAIL_BOSS   boss at work
```

| variant | matches | does not match |
|---|---|---|
| `Jan` | the whole word: `Jan`, `Jan,`, `(Jan)`, `Jan's` | `January`, `Jan2`, `jan_report` |
| `Kowalsk*` | a word that starts so: `Kowalski`, `Kowalskiego`, `Kowalski_report` | `Nowakowalski` |
| `*kowalski` | a word that ends so: `Kowalski`, `JanKowalski` | `Kowalskiego` |
| `*acme-0042*` | the text and the letters, digits and `_` around it: `xacme-0042b` whole; in `x-acme-0042-b` and `acme-0042@example.com` the part `acme-0042` | none |

- Case does not matter (`ŁÓDŹ` matches `łódź`). A space in a variant matches
  any run of whitespace, also a line break. Other characters are literal.
- Composed and decomposed letters match alike (a macOS file name holds
  `Mu` plus a combining diaeresis for `Mü`), and a soft hyphen or a
  zero-width character inside a name does not hide it. A spelling with other
  letters does not match: `MUELLER` is not `Müller`, `GROSSMANN` is not
  `Großmann`, and fullwidth letters (`Ｍüller`) are not `Müller`. List such a
  spelling as a variant of its own.
- Two names that overlap (`Anna Maria` and `Maria Kowalski` in
  `Anna Maria Kowalski`) become one placeholder.
- A word is a run of letters, digits and `_`. So `Kowalski_report.pdf` is one
  word: `Kowalski` does not mask a part of it. Write `*kowalski*` to mask
  file names too.
- The longest variant wins: `Jan Kowalski` is one hit, not two.
- All variants of an entity get the same placeholder. The type is `NAME`,
  or the type in the label (`EMAIL_BOSS` gives `EMAIL`).
- A stem before or after a `*` needs 3 letters or digits, a `*…*` variant 4
  characters. maisecrets uses at most 50 `*…*` variants in all the lists: the
  51st stops your own list with its line, and a team list leaves it out and
  names it.
- The file must be private. If others can read it, maisecrets sets it to
  `0600`. If a line is wrong, every hook fails closed and the message names
  the line, never its text. Fix the line, and the next hook works. Only you
  write this file, so a silent skip would let through exactly the names you
  listed.

**A team list.** Put a `*.terms` file in a folder of `rule_dirs` (Rules of
your own; in its subfolder `rules/` when it has one, as for the rules). The AI can write a shared checkout, so a team list has a floor: an
entry of fewer than 3 characters, an entry of only words of
`maisecrets/rules/term_stoplist.txt` (1,134 words: the 521 words of the closed
word classes of English and German, and the words that 8 or more files of
this repository use, as the common words of a developer session; a small
list on purpose, not a dictionary), a `*` with a stem of
fewer than 5 letters (`ret*`, `*ing`), and a stem that 3 or more words of
that list share (`*ation*`), are left out. A line
that fails is left out with its reason; the rest of the file loads, and a bad
team file never stops a hook. The session start says when a team list
changed. `/maisecrets:rules` and `maisecrets terms` show the counts, the
files and each line left out, never a term. All the team lists together
can be up to 4 MB and 150,000 entries. A variant that an earlier entry holds
(your own list first) is left out, and at most 16 team variants share one
stem or first word: a list cannot make each word of a text walk thousands
of entries. These caps count the team lists together, in the order of
`rule_dirs` (the folders of the machine policy first): a list that the AI
can write can use them up and push out a list after it, as it can also
delete lines of its own folder. The lines pushed out are named in
`/maisecrets:rules`. A `*.terms` file that is a symbolic link is not read.

**Where the terms run.** The terms are a pass of the rule registry, after
the built-in rules and the rules of your own; `maisecrets rules list` shows
the pass as `terms:term`, with its own origin and class (`term`). It is one
index of every list, not a rule per term: its cost does not grow with the
number of terms. A hit says where it came from: its kind is `term:<id>` in
`maisecrets scan` and in the store, never the term. So an email address or an IBAN keeps the span its
rule found. A listed term that a rule finds too (an email address on your
list) gets the rule's type, but it stays a term: mask only. An exact value on
your allow list (`~/.maisecrets/allow.txt`) stays allowed, also when a term
list names it: both are yours, and the allow list is the narrower one.

**Not in a PDF or an image.** The matcher reads text. A name inside a PDF, an
image or another binary file that a tool reads reaches the model as it is.

**Mask only.** maisecrets never puts a name back. A term placeholder in a
command, an MCP argument or a file that the AI writes stays as it is: a
letter that the AI drafts holds `⟦NAME_c3⟧`, and you put in the name. The
store holds no term: one entry per entity, with an id, so the placeholder
stays the same across documents and sessions while the entry lives.

**Find the names in a document.** `maisecrets terms suggest FILE` (in the
plugin folder: `bash hooks/run.sh terms suggest FILE`) proposes lines for
`terms.txt` from a text or CSV file: names after a salutation, after
`Name:`, in a name column of a CSV file, and pairs of capitalised words. If
a surname comes in two or more endings, it proposes the stem
(`Kowalski | Kowalski*`). It never prints a name, not in a terminal either:
an AI can open a pseudo-terminal and read it. It writes the proposal to
`terms.suggested.txt` in the maisecrets folder (mode `0600`; the AI cannot
read that folder) and prints the count and the path. Open the file yourself,
and copy the lines you want into `terms.txt`. Nothing is added to your terms.

**Cost.** Without any list, maisecrets does not load the terms code: a hook
costs what it cost before (measured, `docs/BENCHMARKS.md`, "Terms"). With a
list, a hook pays a fixed amount for the module and the index, and the cost
does not grow with the number of terms. maisecrets keeps an index of the
lists in `~/.maisecrets/.terms-cache`.
With 100,000 entries a new hook process loads it in about 30 ms and scans
10 KB in 3 to 10 ms (measured on Python 3.9 and 3.14).
After you change a list, maisecrets builds the index again at the next
session start, or right after `/maisecrets:term add` or `remove`, so a tool
hook only loads it. Measured for 100,000 two-word entries (3.8 MB): 1.4 s on
Python 3.14, 2.2 s on Python 3.9. If a team list changes while a session
runs, the next hook builds the index.
