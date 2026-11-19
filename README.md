# maisecrets

[![version](https://img.shields.io/github/v/tag/Mcpgate-de/maisecrets?label=version&sort=semver)](CHANGELOG.md)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-d97757)](#install)
[![Codex](https://img.shields.io/badge/Codex-plugin-10a37f)](#install)
[![Python](https://img.shields.io/badge/python-3.9%2B%2C%20stdlib%20only-3776ab)](#requirements)
[![telemetry](https://img.shields.io/badge/telemetry-none-brightgreen)](PRIVACY.md)

Keeps passwords, tokens and personal data out of Claude Code and Codex. A value becomes a placeholder before the
model sees it, and goes back in on your machine only where a command or a file needs it. No model, no download, no
package: Python's standard library only. Install takes two commands.

You ask Claude to set up a deploy script and it reads your `.env`:

```
$ cat .env                          # what the command printed
DB_PASSWORD=<the real password>
STRIPE_KEY=<the real Stripe key>

                                    # what the model received
DB_PASSWORD=⟦SECRET_c1⟧
STRIPE_KEY=⟦SECRET_c2⟧
```

Claude writes the next command with the placeholder. The real value goes back in only when that command runs on your
machine, and the output comes back masked again. More examples: [What it looks like](docs/USING.md#what-it-looks-like).

## What it does

- **Blocks or rewrites a prompt** that carries a secret: the model gets a placeholder such as `⟦SECRET_c1⟧`, never
  the value.
- **Masks tool output** (files, commands, MCP results) before the model reads it.
- **Puts the value back locally** when the agent uses the placeholder in a command or a file.
- **Checks a value first:** `ms:(your value)` tells you whether it would be caught, without sending it.
- **Finds what leaked before:** maisecrets protects from the moment it runs. `/maisecrets:secret-hygiene` checks a
  repository, its git history and your earlier sessions for secrets that got out before; rotate what it finds.
- **Your own rules, terms and imports:** team rule folders, `/maisecrets:term add Jan Kowalski`, values from your
  own NER.
- **PDFs and images:** a PDF goes to the model as masked text only, or you are asked first.
- **Local and deterministic:** no model, no network request of its own unless a server you added offers
  [vault references](docs/ADMIN.md#vault-references), no telemetry.

## Install

No model, no download, no package: Python's standard library only. Install takes two commands.

Claude Code (CLI, desktop app, Cowork):

```bash
claude plugin marketplace add Mcpgate-de/maisecrets
claude plugin install maisecrets@maisecrets     # then start a new session
```

Codex (CLI, IDE extension, and the Codex agent inside the ChatGPT desktop app):

```bash
codex plugin marketplace add https://github.com/Mcpgate-de/maisecrets.git
codex plugin add maisecrets@maisecrets
```

Then open `/hooks` in Codex and trust the maisecrets entries. Codex runs no hook of a plugin until you trust it, and it
asks again after each update.

Updates, the install for a team, and what an update does to an open session: [docs/ADMIN.md](docs/ADMIN.md#install).

## Requirements

Python 3.9 or newer on the PATH the client gives its hooks (`python3 --version`).
The stock `python3` of macOS (3.9) is enough; nothing to install on a Mac.
Windows: install Python for all users, as an administrator:
`winget install --id Python.Python.3.12 --exact --scope machine`. Codex on Windows
runs commands as a sandbox user, and that user cannot start a Python installed for one
person only (`docs/CLIENTS.md`, "Codex on Windows: the sandbox user"). Linux: your package manager, plus
`openssl` for the vault and `xclip` if you want the clipboard. Without it the
plugin blocks every prompt and names the missing piece.

## Update and uninstall

```bash
claude plugin update maisecrets@maisecrets             # or a new session with an org-synced plugin
claude plugin uninstall maisecrets@maisecrets
codex plugin remove maisecrets@maisecrets
```

Uninstalling keeps the stored values until their TTL ends. To delete them,
the metadata and the logs at once, run `maisecrets wipe --yes` from the plugin
folder (`/maisecrets:status` prints the folder):

```bash
bash <plugin folder>/hooks/run.sh wipe --yes
```

or delete the `maisecrets` items in Keychain Access or Credential Manager and
the `~/.maisecrets` folder by hand. `wipe` reports when an item refused to go.

## Check that it works

Start a new session and run `/maisecrets:status test` (in Codex, send `maisecrets: status test`). It prints a test
value that the AI only sees as `⟦SELFTEST⟧`; type that value as your next prompt, and maisecrets answers "Self-test
passed" without sending it. `/maisecrets:status` alone fits on one screen: a lock in the head line says whether this
session is protected, then one short line per check (`✓`, `!` or `✗`, with the next step); `/maisecrets:status all`
adds the details.

## Where you can use it today

Only the clients that are built and measured (in the harness of this repository, or seen live):

| Client | Prompt | Values back in commands and files | Tool output |
|---|---|---|---|
| Claude Code (CLI, desktop app, Cowork) | ✓ replaced (from Claude Code 2.1.287; before that blocked; in Cowork not measured, count on the block) | ✓ | ✓ |
| Codex (CLI, ChatGPT desktop app) | ✓ blocked; you send the cleaned prompt again | ✓ | ✓ |

Not yet: Gemini CLI, Cursor, Copilot CLI, OpenCode. Why: [docs/CLIENTS.md](docs/CLIENTS.md#client-support).

## Everyday commands

In Claude Code (Codex has no plugin slash commands; [docs/USING.md](docs/USING.md) names its forms):

- `/maisecrets:status`: does it protect this session? One short line per check; `/maisecrets:status all` adds the details.
- `ms:(your value)`: would this value be caught? Nothing is sent. [More](docs/USING.md#check-a-value-first-ms).
- `/maisecrets:demo on`, in a new session: try it with real data. Your messages show with their values locked,
  and no prompt goes to the AI until `/clear` (a managed Claude Code may still send `/compact`, with placeholders).
  [More](docs/USING.md#try-it-with-real-data-the-demo-mode).
- `/maisecrets`: one panel in Claude Code for your settings, stored values and the name service, with no model turn. [More](docs/USING.md#the-maisecrets-panel-claude-code).
- `/maisecrets:settings`: the choices you make. [More](docs/USING.md#options).
- `/maisecrets:list`: the stored values in masked form, never a secret. [More](docs/USING.md#vault).
- `/maisecrets:not-a-secret KEY`: a wrong hit; never mask this exact value again.
  [More](docs/USING.md#reporting-a-wrong-detection).
- `/maisecrets:secret-hygiene`: the secrets that leaked before you installed maisecrets.
  [More](docs/USING.md#secret-hygiene-skill).

## What the Claude Code mod does

In Claude Code, maisecrets also loads a mod, `claude-mod/maisecrets-mod.mjs`. These are the facts of its code:

- **What it reads:** the prompts you send (to put placeholders in place of values), and the messages and tool rows
  that Claude Code draws on your screen (to show you the values there). What it draws on the screen never goes to
  the model. It also reads the session id and the working directory of the session, and the kind of screen and
  whether a message is in view (to draw values only there). It keeps one counter of its own in the Claude Code
  store of the plugin: how often it showed its hint about values on the screen. The screen facts and the counter
  stay on this computer and go to no program.
- **What it starts:** the mod itself starts only the plugin's `hooks/dispatch.py`, in the plugin folder, with a
  fixed command line: `python3 hooks/dispatch.py mod-prompt` (or `mod-values`, `mod-reveal`, `mod-demo`,
  `mod-settings`). On Windows it tries `py -3 hooks/dispatch.py …` and then `python hooks/dispatch.py …` with the
  same last word, because Windows often has no `python3`. It does not start a shell. One panel action starts more:
  when you choose the local name service in the `/maisecrets` panel, that Python starts another Python, which starts
  the name service container with Docker or Podman.
- **What it sends:** the text of the question (a prompt, the keys or references to show, a panel action), with the
  session id and, for a prompt, the working directory and where the prompt came from (for example the prompt box or
  Remote Control), goes to that local Python process on stdin, as JSON. The mod itself makes no network request.
  The Python process sends text off this computer only to a service you set up: the name service of
  `/maisecrets:ner`, or a server you added that offers vault references or Sensitive References
  (`/maisecrets:sref login`). The details:
  [What the plugin runs, sends and fetches](docs/HOW-IT-WORKS.md#what-the-plugin-runs-sends-and-fetches).
- **The demo** (`/maisecrets:demo on`): in a session in the demo, the `http.fetch` hook refuses every request that
  Claude Code itself sends (the turns, and side requests such as the title or the next-prompt guess), and each model
  step gets one line from the mod instead of a request. The `session.compact` hook skips a compaction in that
  session, because a compaction is a model request of its own; the conversation stays as it is. When the plugin's
  Python says that a session is not in the demo, these hooks let its requests and compactions go on unchanged. When
  the Python gives no answer, they refuse, so nothing goes out by mistake.
- **Prompt suggestions in the demo:** the mod switches `CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION` off for the demo.
  After the demo, it sets the default of Claude Code. A value that you set before the demo is not kept. If that
  reset fails, suggestions stay off until the next session.

## What it does not protect

- A process that runs as you, or an agent that deliberately runs code to switch maisecrets off
  ([threat model](docs/THREAT-MODEL.md), C22).
- A name without a label. maisecrets masks the names on your term list, and more with the optional name service.
- A value that a command changes with an encoding before it prints it.
- A client without hooks: the chat apps, the web and the mobile apps.
- The output of a failed command in Claude Code, a secret inside a PDF or an image, and the other measured limits:
  [docs/KNOWN-GAPS.md](docs/KNOWN-GAPS.md).

## Documentation by reader

- **Using it:** [docs/USING.md](docs/USING.md): settings, the vault, `ms:(…)`, handing a value to the AI, a wrong
  detection, terms, test data, PDFs and images.
- **Administering it:** [docs/ADMIN.md](docs/ADMIN.md): install and updates, a team rollout, rules of your own, the
  rehydration policy, the SSH consent, values from your own tools, vault references, a name service.
- **How it works:** [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md), and what is defended:
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- **Known gaps:** [docs/KNOWN-GAPS.md](docs/KNOWN-GAPS.md).
- **Clients:** [docs/CLIENTS.md](docs/CLIENTS.md).
- **Benchmarks:** [docs/BENCHMARKS.md](docs/BENCHMARKS.md).
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md), [docs/TESTING.md](docs/TESTING.md),
  [docs/REPO-STANDARDS.md](docs/REPO-STANDARDS.md).
- **Changes, privacy, security:** [CHANGELOG.md](CHANGELOG.md), [PRIVACY.md](PRIVACY.md),
  [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. `docs/PROTOCOL.md` is the specification a gateway implements,
`docs/THREAT-MODEL.md` says what is defended, `docs/TESTING.md` what was measured.
The licensor is named in `NOTICE`; the vendored rule sets carry their own licences.

## Moved sections

The sections below moved to the documents by reader. Each heading keeps the old link to its section.

### Quick start

Moved to [docs/USING.md](docs/USING.md#quick-start).

### How it works

Moved to [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#how-it-works).

### What it looks like

Moved to [docs/USING.md](docs/USING.md#what-it-looks-like).

### Status

Moved to [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#status).

### Client support

Moved to [docs/CLIENTS.md](docs/CLIENTS.md#client-support).

### For administrators

Moved to [docs/ADMIN.md](docs/ADMIN.md#for-administrators).

### What the plugin runs, sends and fetches

Moved to [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#what-the-plugin-runs-sends-and-fetches).

### Secret hygiene skill

Moved to [docs/USING.md](docs/USING.md#secret-hygiene-skill).

### Options

Moved to [docs/USING.md](docs/USING.md#options).

### Settings you decide

Moved to [docs/USING.md](docs/USING.md#settings-you-decide).

### Where your secrets went

Moved to [docs/USING.md](docs/USING.md#where-your-secrets-went).

### Vault

Moved to [docs/USING.md](docs/USING.md#vault).

### Check a value first: ms:(…)

Moved to [docs/USING.md](docs/USING.md#check-a-value-first-ms).

### Handing a value to Claude on purpose

Moved to [docs/USING.md](docs/USING.md#handing-a-value-to-claude-on-purpose).

### Invisible characters

Moved to [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#invisible-characters).

### Disguised values in tool results

Moved to [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#disguised-values-in-tool-results).

### Password exports in tool results

Moved to [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#password-exports-in-tool-results).

### Reporting a wrong detection

Moved to [docs/USING.md](docs/USING.md#reporting-a-wrong-detection).

### Reporting an internal failure

Moved to [docs/USING.md](docs/USING.md#reporting-an-internal-failure).

### Gates around a resolve

Moved to [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#gates-around-a-resolve).

### SSH consent (optional)

Moved to [docs/ADMIN.md](docs/ADMIN.md#ssh-consent-optional).

### Rehydration policy (optional)

Moved to [docs/ADMIN.md](docs/ADMIN.md#rehydration-policy-optional).

### Test data that maisecrets leaves alone

Moved to [docs/USING.md](docs/USING.md#test-data-that-maisecrets-leaves-alone).

### Detection rules

Moved to [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#detection-rules).

### Rules of your own

Moved to [docs/ADMIN.md](docs/ADMIN.md#rules-of-your-own).

### PDFs and images

Moved to [docs/USING.md](docs/USING.md#pdfs-and-images).

### Terms: names, case numbers, customer names

Moved to [docs/USING.md](docs/USING.md#terms-names-case-numbers-customer-names).

### Values from your own tools

Moved to [docs/ADMIN.md](docs/ADMIN.md#values-from-your-own-tools).

### Vault references

Moved to [docs/ADMIN.md](docs/ADMIN.md#vault-references).

### Sensitive References

Moved to [docs/ADMIN.md](docs/ADMIN.md#sensitive-references).

### Names from a service (optional)

Moved to [docs/ADMIN.md](docs/ADMIN.md#names-from-a-service-optional).

### Known gaps (measured or documented)

Moved to [docs/KNOWN-GAPS.md](docs/KNOWN-GAPS.md#known-gaps-measured-or-documented).
