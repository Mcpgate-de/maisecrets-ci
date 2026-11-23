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

[![maisecrets demo: values with a lock on your screen, placeholders for the AI](https://mcpgate.de/media/maisecrets-demo.gif)](https://mcpgate.de/maisecrets/)

Claude works with the placeholders. The real value goes back in only when a command or a tool call runs on your
machine, and the output comes back masked again. More examples: [What it looks like](docs/USING.md#what-it-looks-like).

## What it does

- **Blocks or rewrites a prompt** that carries a secret: the model gets a placeholder such as `⟦SECRET_c1⟧`, never
  the value.
- **Masks tool output** (files, commands, MCP results) before the model reads it.
- **Puts the value back locally** when the agent uses the placeholder in a command or a file.
- **Checks a value first:** `ms:(your value)` tells you whether it would be caught, without sending it.
- **Finds what leaked before:** maisecrets protects from the moment it runs. `/maisecrets:secret-hygiene` checks a
  repository, its git history and your earlier sessions for secrets that got out before; rotate what it finds.
- **Your own rules, terms and imports:** team rule folders, `/maisecrets term add Jan Kowalski`, values from your
  own NER.
- **PDFs and images:** a PDF goes to the model as masked text only, or you are asked first.
- **Local and deterministic:** no model, no telemetry, no network request except for a service you set
  up: a name service, a gateway, or a server with [vault references](docs/ADMIN.md#vault-references).

The hooks block or mask a prompt that carries a value, mask tool output, and put the value into a command or a file
only when the call runs. In Claude Code, maisecrets also loads a mod: it puts the placeholders into your prompt before
it goes out, and shows the values on your screen with a lock. What the mod reads, starts and sends:
[What the Claude Code mod does](docs/HOW-IT-WORKS.md#what-the-claude-code-mod-does).

## Install

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
folder (`/maisecrets status` prints the folder):

```bash
bash <plugin folder>/hooks/run.sh wipe --yes
```

or delete the `maisecrets` items in Keychain Access or Credential Manager and
the `~/.maisecrets` folder by hand. `wipe` reports when an item refused to go.

## Check that it works

Start a new session and run `/maisecrets status test` (in Codex, send `maisecrets: status test`). It prints a test
value that the AI only sees as `⟦SELFTEST⟧`; type that value as your next prompt, and maisecrets answers "Self-test
passed" without sending it.

To try it with real data, send `maisecrets: demo on` in a new session. Your messages show with their values locked,
and no prompt goes to the AI until `/clear`. [More](docs/USING.md#try-it-with-real-data-the-demo-mode).

## Where you can use it today

Only the clients that are built and measured (in the harness of this repository, or seen live):

| Client | Prompt | Values back in commands and files | Tool output |
|---|---|---|---|
| Claude Code (CLI, desktop app, Cowork) | ✓ replaced (from Claude Code 2.1.287; before that blocked; in Cowork too, measured 2026-11-21) | ✓ | ✓ |
| Codex (CLI, ChatGPT desktop app) | ✓ blocked; you send the cleaned prompt again | ✓ | ✓ |

Not yet: Gemini CLI, Cursor, Copilot CLI, OpenCode. Why: [docs/CLIENTS.md](docs/CLIENTS.md#client-support).

## How well it detects

Measured on data that no rule was written from. Method and all numbers:
[mcpgate.de/maisecrets/built-to-be-checked](https://mcpgate.de/maisecrets/built-to-be-checked/).

- Personal data in four public datasets (0.9.12): precision 0.92 to 0.997, and the best F1 of four tools on three of
  them (against Presidio, Preserve, pii-anon). Names are the weak point; the optional name service masks more.
- Secrets in GitHub issues (3,761 values, 0.8.2): recall 0.72; Betterleaks 0.55, gitleaks 0.53.
- A sealed holdout of 872 texts (0.9.12): 2 false alarms, precision 0.997.

## Everyday commands

In Claude Code (`/ms NAME` is the same; `/maisecrets:NAME` needs the mod; a change is the text you type; Codex:
[docs/USING.md](docs/USING.md)):

- `/maisecrets status`: does it protect this session? One short line per check; `/maisecrets status all` adds the details.
- `ms:(your value)`: would this value be caught? Nothing is sent. [More](docs/USING.md#check-a-value-first-ms).
- `/maisecrets`: one panel in Claude Code for your settings, stored values and the name service, with no model turn. [More](docs/USING.md#the-maisecrets-panel-claude-code).
- `/maisecrets settings`: the choices you make. [More](docs/USING.md#options).
- `/maisecrets list`: the stored values, masked, never a secret. [More](docs/USING.md#vault).
- `maisecrets: not a secret KEY`: a wrong hit; never mask this exact value again.
  [More](docs/USING.md#reporting-a-wrong-detection).
- `/maisecrets:secret-hygiene`: the secrets that leaked before you installed maisecrets.
  [More](docs/USING.md#secret-hygiene-skill).

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
- **Benchmarks:** [mcpgate.de/maisecrets/built-to-be-checked](https://mcpgate.de/maisecrets/built-to-be-checked/);
  [docs/BENCHMARKS.md](docs/BENCHMARKS.md) is an older snapshot (October 2026).
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md), [docs/TESTING.md](docs/TESTING.md),
  [docs/REPO-STANDARDS.md](docs/REPO-STANDARDS.md).
- **Changes, privacy, security:** [CHANGELOG.md](CHANGELOG.md), [PRIVACY.md](PRIVACY.md),
  [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. `docs/PROTOCOL.md` is the specification a gateway implements,
`docs/THREAT-MODEL.md` says what is defended, `docs/TESTING.md` what was measured.
The licensor is named in `NOTICE`; the vendored rule sets carry their own licences.

## Moved sections

These sections moved to the documents by reader. An old link to one of them lands here.

**docs/USING.md:** <a name="quick-start"></a>[Quick start](docs/USING.md#quick-start) · <a name="what-it-looks-like"></a>[What it looks like](docs/USING.md#what-it-looks-like) · <a name="secret-hygiene-skill"></a>[Secret hygiene skill](docs/USING.md#secret-hygiene-skill) · <a name="options"></a>[Options](docs/USING.md#options) · <a name="settings-you-decide"></a>[Settings you decide](docs/USING.md#settings-you-decide) · <a name="where-your-secrets-went"></a>[Where your secrets went](docs/USING.md#where-your-secrets-went) · <a name="vault"></a>[Vault](docs/USING.md#vault) · <a name="check-a-value-first-ms"></a>[Check a value first: ms:(…)](docs/USING.md#check-a-value-first-ms) · <a name="handing-a-value-to-claude-on-purpose"></a>[Handing a value to Claude on purpose](docs/USING.md#handing-a-value-to-claude-on-purpose) · <a name="reporting-a-wrong-detection"></a>[Reporting a wrong detection](docs/USING.md#reporting-a-wrong-detection) · <a name="reporting-an-internal-failure"></a>[Reporting an internal failure](docs/USING.md#reporting-an-internal-failure) · <a name="test-data-that-maisecrets-leaves-alone"></a>[Test data that maisecrets leaves alone](docs/USING.md#test-data-that-maisecrets-leaves-alone) · <a name="pdfs-and-images"></a>[PDFs and images](docs/USING.md#pdfs-and-images) · <a name="terms-names-case-numbers-customer-names"></a>[Terms: names, case numbers, customer names](docs/USING.md#terms-names-case-numbers-customer-names)

**docs/HOW-IT-WORKS.md:** <a name="how-it-works"></a>[How it works](docs/HOW-IT-WORKS.md#how-it-works) · <a name="status"></a>[Status](docs/HOW-IT-WORKS.md#status) · <a name="what-the-plugin-runs-sends-and-fetches"></a>[What the plugin runs, sends and fetches](docs/HOW-IT-WORKS.md#what-the-plugin-runs-sends-and-fetches) · <a name="invisible-characters"></a>[Invisible characters](docs/HOW-IT-WORKS.md#invisible-characters) · <a name="disguised-values-in-tool-results"></a>[Disguised values in tool results](docs/HOW-IT-WORKS.md#disguised-values-in-tool-results) · <a name="password-exports-in-tool-results"></a>[Password exports in tool results](docs/HOW-IT-WORKS.md#password-exports-in-tool-results) · <a name="gates-around-a-resolve"></a>[Gates around a resolve](docs/HOW-IT-WORKS.md#gates-around-a-resolve) · <a name="detection-rules"></a>[Detection rules](docs/HOW-IT-WORKS.md#detection-rules) · <a name="what-the-claude-code-mod-does"></a>[What the Claude Code mod does](docs/HOW-IT-WORKS.md#what-the-claude-code-mod-does)

**docs/CLIENTS.md:** <a name="client-support"></a>[Client support](docs/CLIENTS.md#client-support)

**docs/ADMIN.md:** <a name="for-administrators"></a>[For administrators](docs/ADMIN.md#for-administrators) · <a name="ssh-consent-optional"></a>[SSH consent (optional)](docs/ADMIN.md#ssh-consent-optional) · <a name="rehydration-policy-optional"></a>[Rehydration policy (optional)](docs/ADMIN.md#rehydration-policy-optional) · <a name="rules-of-your-own"></a>[Rules of your own](docs/ADMIN.md#rules-of-your-own) · <a name="values-from-your-own-tools"></a>[Values from your own tools](docs/ADMIN.md#values-from-your-own-tools) · <a name="vault-references"></a>[Vault references](docs/ADMIN.md#vault-references) · <a name="sensitive-references"></a>[Sensitive References](docs/ADMIN.md#sensitive-references) · <a name="names-from-a-service-optional"></a>[Names from a service (optional)](docs/ADMIN.md#names-from-a-service-optional)

**docs/KNOWN-GAPS.md:** <a name="known-gaps-measured-or-documented"></a>[Known gaps (measured or documented)](docs/KNOWN-GAPS.md#known-gaps-measured-or-documented)
