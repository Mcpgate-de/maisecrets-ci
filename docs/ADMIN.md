# Administering maisecrets

For the person who installs maisecrets for a team or a machine, or who connects it to other tools. This
document says how to install and update it, what happens to open sessions, which settings a policy enforces,
and how you add rules of your own, the SSH consent, the rehydration policy, values from your own tools, vault
references, Sensitive References and a name service. The everyday use is in [USING.md](USING.md).

Contents:

- [Install](#install)
- [For administrators](#for-administrators)
- [SSH consent (optional)](#ssh-consent-optional)
- [Rehydration policy (optional)](#rehydration-policy-optional)
- [Rules of your own](#rules-of-your-own)
- [Values from your own tools](#values-from-your-own-tools)
- [Vault references](#vault-references)
- [Sensitive References](#sensitive-references)
- [Names from a service (optional)](#names-from-a-service-optional)

## Install

```bash
claude plugin marketplace add Mcpgate-de/maisecrets     # the GitHub repo is its own marketplace
claude plugin install maisecrets@maisecrets             # user scope; new session or /reload-plugins
claude plugin update maisecrets@maisecrets              # later versions
```

**Updates and open sessions.** A hook runs from the plugin folder of its version.
When Claude Code cannot find that folder, it shows `Plugin directory does not
exist` and runs the tool without the hook: every protection of that session is
off until `/reload-plugins` or a new session. No code of the plugin runs then, so
maisecrets cannot warn you itself. The harness measures this on every run
(scenario `plugin_folder_moved`, Claude Code 2.1.283: no hook runs, the tool
runs; anthropics/claude-code#97847). A client that runs the hook command anyway
gets a refusal: the command tests for the launcher first and blocks without it,
in bash, in PowerShell and, for Codex on Windows (`commandWindows`), in
`cmd.exe`. Codex needs this most: it removes the folder of the old version as
soon as it installs a new one, and an open Codex session then runs the command
of a folder that is gone (codex-cli 0.159.0, measured 2026-09-29). Exit that
session and run `codex resume`.

The install from the Claude plugin directory does not have this refusal. The
directory accepts only a hook command that names one program, so its copy (the
GitHub branch `release`) runs `run.sh` or `run.cmd` directly. If that folder is
gone, the hook does not run. Claude Code on Windows then also needs Git Bash. A
directory install keeps the old version folder for 14 days, so an open session
keeps its hooks. The install from this repository (`main`) keeps the refusal.

- Installed from this GitHub marketplace (the commands above), a previous version
  stays for 14 days, "so a session that already loaded the old version keeps
  running" ([Claude Code docs](https://code.claude.com/docs/en/plugins/loading#cleanup-of-previous-versions)).
  This is the install path we recommend.
- Synced from claude.ai, the previous folder moved to `~/.claude/plugins/.trash`
  when another Claude Code session started and synced (observed with Claude Code
  2.1.283 on 2026-09-28; not documented). A session that was open then lost its
  hooks. After an update, run `/reload-plugins` in every open session. That is
  not always enough: on 2026-09-29 (Claude Code 2.1.284) `/reload-plugins` kept
  the path of the gone folder (`/plugin` showed `commands path not found …
  maisecrets~g2`), and only a new process loaded maisecrets again: exit, then
  `claude --resume <session id>` in the directory where the session started (the
  guard puts this command on your clipboard, once per session). The
  session that started the sync can lose them too: on 2026-09-29 (Claude Code
  2.1.284) the folder was rewritten one second after a session started, and that
  session ran no maisecrets hook while `/plugin` showed the new version.
- **The guard closes this for a synced install.** It is a small hook outside the
  plugin folder (`~/.claude/maisecrets-guard.py`). Every maisecrets hook writes a
  heartbeat for its call once it has answered; when none comes (maisecrets did not
  run, or started and died), the guard blocks the prompt, denies
  the tool call or withholds the result. Without a sign of an update it asks to
  run the call again first, so an agent that works alone goes on; after an update
  it names `/reload-plugins` and the restart command. It stays
  silent for an account without maisecrets, for a plugin you switched off, and
  for Codex. Measured with the real client: `plugin_folder_moved_guarded` (the
  command does not run) and `bash_rehydrate_guarded` (a healthy session passes).
  - A synced maisecrets sets it up by itself: its session start places the script
    and, once, registers it in `~/.claude/settings.json` (a backup first, only the
    hooks change, one line in the session-start message says so). It protects the
    sessions after that one. `/maisecrets:guard remove` takes it away and it stays
    away; `"guard": false` in `~/.maisecrets/config.json` or in the machine policy
    keeps it off. A `settings.json` that is not valid JSON is left alone.
  - An admin who prefers central settings can register it in the Claude Code
    managed settings instead (`python3 -m maisecrets.cli guard managed` prints the
    entries); on a machine where maisecrets never ran that command answers `{}`.
  - Installed another way: `/maisecrets:guard install` does the same by hand.
  - Its cost: each prompt and tool call waits for the heartbeat, which the
    maisecrets hook of the same call writes as it starts (both run in parallel);
    without maisecrets it waits 5 s and then refuses. The refusal names
    `/reload-plugins`, then `claude --resume` with the id of this session for the
    case that the reload does not help, and, for a maisecrets that is off on purpose, the way out
    from a terminal: `python3 ~/.claude/maisecrets-guard.py --off` (it stays off;
    the agent cannot run it). A plugin switched off in the user, project, local or
    managed settings is left alone. The guard expects maisecrets for the account
    the synced copy registered under, so a second Claude profile is not blocked.
    On a Mac without the Command Line Tools there is no `python3`, and the guard
    answers nothing. It needs a claude.ai login: with an API key there is no
    account to compare, and `/maisecrets:guard status` says "expected: no".
    After an organisation takes maisecrets out of its sync the guard stops
    expecting it within 15 minutes; until then `--off` lets you work.
- For a team, an admin can roll out this marketplace with managed settings
  (`extraKnownMarketplaces` with `autoUpdate: true`, and `enabledPlugins`), so
  nobody has to type a command ([Claude Code docs](https://code.claude.com/docs/en/plugins/org)).

Codex (CLI, IDE extension, and the Codex agent inside the ChatGPT desktop app):

```bash
codex plugin marketplace add https://github.com/Mcpgate-de/maisecrets.git
codex plugin add maisecrets@maisecrets
```

Codex reads `.codex-plugin/plugin.json` (listing texts, icon) and the hooks from
`hooks/hooks.json`.

Codex skips a plugin's hooks until you review and trust them: open `/hooks`
in Codex and trust the maisecrets entries. Until then nothing is protected and
the plugin cannot tell you so, because no hook of it runs. From Codex 0.164 the
trust also covers the contents of the plugin folder (openai/codex#54619): after
each maisecrets update, Codex shows the hooks as failed and lets every prompt and
tool call through until you trust them again in `/hooks`. `/maisecrets:status`
reads Codex's `config.toml` and says whether Codex runs the hooks of the
installed version, and whether a second maisecrets is installed. A workspace admin
can ship the hooks as managed hooks (`requirements.toml`, MDM), which are
trusted by policy and cannot be disabled. The plain ChatGPT chat, web and
mobile have no local runtime and no hooks.

**Codex gets fewer versions.** Codex asks you to trust the hooks again for
each version, so Codex will install from the GitHub branch `release-codex`,
which can move more slowly than the releases, and moves at once for a security
fix; Claude Code gets every release.

For development:

```bash
claude --plugin-dir /path/to/maisecrets                 # one session, straight from the checkout
python3 -m unittest discover -s tests -v               # about 30 seconds
python3 harness/run.py                                 # 60 scenarios against a fake upstream (4 for the PowerShell tool of Windows)
python3 harness/codex.py [--real]                      # 19 scenarios through codex exec (five need --real)
python3 scripts/replay_can_fail.py                     # 438 proofs: each control's test, and each path of the 17 invariant beliefs, goes red without its guard
python3 scripts/derived_counts.py                      # the numbers in the docs, measured again
python3 scripts/lint_plugin.py                         # frontmatter YAML, manifests, hook paths (pre-commit, CI)
scripts/install-hooks.sh                               # git pre-commit / pre-push
```

## For administrators

**Rollout.** claude.ai: an organisation admin adds a private or internal
marketplace repository under organisation settings and sets the availability
(available, installed by default, required). The sync accepts no public
repository, so create a private one with a `.claude-plugin/marketplace.json`
that lists maisecrets with this repository as its source, or mirror this
repository into a namespace you control and review each release there before
your members get it. ChatGPT workspace: Admin > Plugins > Add > Import
marketplace, with the same `marketplace.json`; the sync runs daily or on
"Sync now". An import in 2026-10 delivered maisecrets with `hooks: []`, which protects
nothing; an import of 0.9.13 on 2026-11-16 delivered the hooks. Check that Settings > Hooks
lists the source maisecrets, trust the hooks there, and run `maisecrets: status test`; if
the hooks are missing, each person installs maisecrets locally (see [Install](#install)). Codex CLI users trust the hooks in `/hooks`; a change to
`hooks/hooks.json`, and from Codex 0.164 every maisecrets update, asks again, and
until then Codex runs no maisecrets hook and lets prompts and tool calls through. Managed hooks (`requirements.toml` through MDM) are trusted by
policy.

**Updates.** A new version reaches a member when `version` in
`.claude-plugin/plugin.json` changes: at the next session start for an
org-synced plugin, with `claude plugin update` otherwise. A session start says
nothing while all is well (only the first start in a maisecrets folder shows a
welcome), so its silence proves nothing. To check that the plugin loaded, run
`/maisecrets:status` (Codex: `maisecrets: status`) in the session, or look for
the `session-start` row of that session in `~/.maisecrets/hooks.log`. A rollback is a `git revert` on `main`: the pipeline releases it as the
next patch version.

**The guard for synced installs.** An update of an org-synced plugin can leave a
session without its hooks. maisecrets registers a guard against that by itself
(`"guard": false` in the policy turns it off); the managed settings can carry it
instead (`python3 -m maisecrets.cli guard managed`). See "Updates and open sessions".

**Settings you can enforce.** A machine policy file wins over the user's
`~/.maisecrets/config.json` and cannot be changed from there:
`/Library/Application Support/maisecrets/policy.json` (macOS),
`%ProgramData%\maisecrets\policy.json` (Windows), `/etc/maisecrets/policy.json`
(Linux). Any key from "Options" goes in it; typical: `backend`,
`scrub_transcript`, `max_ttl_seconds`, `regions`, `report_url`,
`resolve_in_files`, `rehydration`.
Every user must be able to read the file and its folder (for example 0644 and
0755): a policy maisecrets cannot read makes every hook fail closed, because it
cannot tell what the policy says. A key it does not know is ignored with a
warning; a key that starts with `_` or `$` is a comment or a schema link. A key
that looks like a misspelled `rehydration`, `resolve_in_files` or
`ssh_via_sandbox` blocks rehydration until it is fixed.
Two keys add to what the user has instead of replacing it: `rule_dirs`, rule
folders that every user reads and cannot remove, and `allow`, lines of the
allow list (both lists of strings; see "Rules of your own").
`/maisecrets:status all` names the keys that come from the policy. The plaintext
`jsonfile` store is refused unless the policy or the user sets
`allow_plaintext_store`.

**What is written where.** `~/.maisecrets/index.json` holds metadata and keyed
fingerprints, a masked display for PII, and session ids; metadata of an expired
value is deleted after `keep_purged_days` (30). `audit.log` holds one line per
resolve (time, session, key, tool, the command with placeholders; capped at
`audit_max_lines`). `events.log` holds the last 200 detections (rule name and
type). `pending/` holds a blocked prompt with placeholders for 15 minutes.
`incidents.json` holds maisecrets' own internal failures as closed codes (at most
50 groups; see ["Reporting an internal failure"](USING.md#reporting-an-internal-failure)).
`versions.json` holds, per plugin version, the time of its first and last session start and of its last gateway
renewal (no value, no session id): the newest version warns when an older one ran in the last day and may still be open.
`hooks.log` holds one line per hook run (capped at 2000); the client column names
the entry point, `claude/local-agent` for a Cowork session. The FIFOs a value
is delivered through live in `$XDG_RUNTIME_DIR/maisecrets` or
`maisecrets-<uid>` in the temp directory, for up to 120 s. The values live in
the store of the platform; on macOS every value goes to `security` on stdin, never
on its command line. A value longer than one stdin line (about 2.8 KB, a private
key) is split over several keychain items, and a value above about 160 KB is
refused. maisecrets itself sends nothing to a
server: no hook opens a network connection. Two exceptions to state to a data-protection
officer: the Windows Credential Locker can roam through a Microsoft account on
a machine that is not domain-joined (set `backend` to `encrypted-file` by
policy if that matters), and `/maisecrets:report` prints an issue text and a
link to `report_url`. It opens no browser and files nothing: you open the link
and decide in GitHub's form. Set `report_url` to your tracker, or set it to
`null` to turn reporting off.

**Diagnosis.** `/maisecrets:status` fits on one screen: a head line that says
whether this session is protected, one short line per check (`✓` ok, `!` warn,
`✗` FAIL, with the next command) and one line of key facts.
`/maisecrets:status all` adds version, plugin folder, Python, store, policy keys
and log counts (docs/HOW-IT-WORKS.md, "Status", says what each check means). `/maisecrets:audit` prints the last
resolves. `MAISECRETS_DEBUG_LOG=<file>` in the client's environment records one
line per hook call (event, client, duration, answer; never a value).
`bash <plugin folder>/hooks/run.sh wipe --yes` is the offboarding step; a
damaged `index.json` is rebuilt with `… run.sh repair` (stored values are
deleted, the counters continue). `hooks.log` in `~/.maisecrets` records every
hook run (time, event, client, session, tool, decision, duration; no value and
no command), so "the plugin did nothing" can be told from "the hook did not
run".

### The demo where an organization manages Claude Code

Claude Code 2.1.327 and later run a built-in security plugin (`sec-default`) on a machine with managed
settings and for Team and Enterprise organizations. It lets the hooks of a plugin that a person installed
run on most events, but not on two of them. For maisecrets, the plugin page (`/plugin`) says:

> Its hooks on session.compact, http.fetch{origin=engine} do not run here: where an organization manages
> Claude Code, these events pass over the plugins you install. Only a plugin that counts as your
> organization's own runs hooks on these events. An administrator sets that up in managed settings.

maisecrets has these two hooks only for the demo mode (`/maisecrets:demo on`). In the demo they stop
`/compact` and the requests Claude Code makes on its own (`/rename`, `/btw`, `/recap`, the next-prompt
suggestion). Where they do not run, these requests go to the AI. They carry the conversation as it is: the
prompts with placeholders and the demo lines, never a stored value. The turns of the demo stay local,
because the `turn.step` hook still runs. The prompt rewrite (`prompt.submit`) and all other protection do
not change. A plugin cannot see that its hooks are passed over, so the demo start says it as a condition.

To make maisecrets the organization's own plugin, so that these hooks run:

1. In the managed settings, enable it: `"enabledPlugins": {"maisecrets@<your marketplace>": true}`.
2. In the managed settings, declare that marketplace under `extraKnownMarketplaces` with the source the
   machines install from. Use a local directory whose `marketplace.json` lists maisecrets by a relative
   path, or a remote source. Claude Code takes a copy from a remote source as the organization's only when
   the copy matches a recorded hash.
3. Start a new session and open `/plugin`. The note above is gone for maisecrets. If it is still there,
   the debug log (`claude --debug`) names the reason in a line that starts with
   `maisecrets@<your marketplace> is enabled by managed settings, but`.

Read from the Claude Code 2.1.327 and 2.1.328 binaries (the text of the plugin page and the code that selects
the plugins). Not yet tested in a managed organization.

### Settings in config.json only

- `gateway_servers`: the MCP servers that resolve placeholders themselves (a list of server names).
- `ssh_host_groups`: hosts that one typed ssh window covers together (`{"web": ["web1", "web2"]}`).

### Settings the panel does not offer

The `/maisecrets` panel and the `/maisecrets:settings` table leave out the settings that only weaken a protection
when a person changes them: `strip_hidden_characters`, `scrub_transcript`, `block_at_mentions`, `client_header`,
`ssh_via_sandbox`, `pass_agent_reports`, `max_keys_per_session`, `max_resolves_per_hour`. Set them in
`config.json` or in the machine policy; a policy value cannot be changed by the person. The typed command still
changes one, with the checks of C22, so that a person who meets the limiter can raise it.

## SSH consent (optional)

An agent with your SSH keys can run any command on any host it reaches, also
when no secret is in the command. Claude Code's own `permissions.ask:
["Bash(ssh:*)"]` matches only the start of a command, so `cd x && ssh …`,
`bash -c "ssh …"` and `timeout 30 ssh …` pass it. With `ssh_consent` on (send
`/maisecrets:settings ssh_consent on` as your prompt, see ["Settings you decide"](USING.md#settings-you-decide);
a policy can set it; it is off by default),
maisecrets reads every ssh-family call (`ssh`, `scp`, `sftp`, `rsync` to a
host, `sshfs`, `ssh-copy-id`, `mosh`, `autossh`), also behind `cd …&&`,
`timeout`, `nohup`, `env`, `sudo` and `perl -e 'alarm N; exec @ARGV'`:

- **A read runs.** A remote command that prints only metadata about the host,
  from a short list with named options (`uptime`, `df -h`, `free`, `uname`,
  `ls`, `du`, `wc` of a literal absolute path, `systemctl is-active`), with no
  expansion and no redirect except `2>&1` and `>/dev/null` (any other
  redirect asks, also a local one: the hook cannot tell a quoted `">"` that
  ssh hands to the remote shell from a local one). The content of a
  file, a log or a process list (`cat`, `grep`, `journalctl`, `ps`,
  `systemctl status`) is a write: it can carry a credential. Paths like
  `/etc/shadow`, `.env`, `id_*`, `*.pem`, `/proc` or `/root` are never a read;
  that check is a heuristic, not a guarantee.
- **Every write asks.** Any other remote command, a login shell, `sudo`,
  `docker`, a copy, a port forward or tunnel (`-L`, `-R`, `-D`, `-w`), or local
  data on stdin. A yes allows that one command; the next write asks again.
- **A host you trust for a while: type it.** Send `maisecrets: allow ssh web1`
  as your own prompt (the question names the exact sentence). Writes to that
  host, and to the hosts of its group in `"ssh_host_groups": {"web": ["web1",
  "web2"]}`, then run without a question for 8 hours, in that session, for the
  main thread only: a subagent asks for itself. The host is as written, with
  its user and port (`-l`, `-p`, `-o User`, `-o Port`, `user@`, `scp://…:port`):
  `root@web1` and `web1:2222` are other hosts than `web1`. Only a prompt you
  type counts: not a scheduled or SDK prompt, and a Bash or PowerShell command
  that carries the sentence is refused.
- **Hosts where the AI may work on its own.** Your own lab or ops servers can
  be autonomous: writes there never ask, in any session, while every other
  host asks for each write. Send `/maisecrets:settings ssh_autonomous_hosts add
  ops1` (or `maisecrets: ssh autonomous ops1`), and `remove ops1` (or
  `maisecrets: ssh ask ops1`) to take one off. The host is as the ssh call
  writes it (`root@lab:2323` is not `lab`), or the name of a group in
  `ssh_host_groups` (then its members, not a host of that name); every host
  of a call must be on the list. The list changes from your own prompt, and
  the deny list holds there too. Limit: maisecrets reads commands as text, so
  a program that builds the sentence at run time and feeds it to a nested
  client (Codex does not say who wrote a prompt) can add a host; check the
  list in `/maisecrets:settings`.
- **A form maisecrets cannot read asks every time.** A host built at run
  time (`ssh $HOST`), two users or
  ports for one connection, `sudo -u` (another user's ssh config), an option that sends the
  connection elsewhere (`-J`, `-W`, `-S`, `-F`, `-o ProxyCommand`, `-o
  HostName`, `-o RemoteCommand`), `GIT_SSH_COMMAND`, `git -c core.sshCommand`,
  `RSYNC_RSH`, `DOCKER_HOST=ssh://`, the own ssh options of `sshfs` (also
  `-F`), `mosh` (also abbreviated) and `rsync -e`, `ssh -P` (a tag that
  selects a block of your ssh config), and any mention of `.ss…` outside an
  ssh call in a command that does not only read: a change to `~/.ssh` can send
  an approved alias elsewhere, and a list of writers is never complete
  (`rsync`, `tar -C`, `ln -s` …), so only reads are listed (`cat`, `ls`,
  `grep`, `head`, `diff` …), and a redirect into `.ss…` asks too. Write and
  Edit on `~/.ssh` ask as well.
- **An ssh word asks only where a command starts it** (#15): as the command
  word; after a launcher (`env`, `xargs`, `timeout`, `setsid`, `sshpass`,
  `tmux` …) or as an argument of its own of any other program, unless it
  follows an option (`pytest -k ssh`) or the program only searches, shows or
  looks up (`grep`, `which`, `git`, `gh` …): `uv run ssh`, `gcloud compute
  ssh`; in quoted code after `-c`, `--run` or `--`; in `find -exec`, `docker exec` or `git rebase --exec`; in the
  code of `bash -c`, `fish -C` or `eval`, in a shell's heredoc and in the
  shell code of AppleScript's `do shell script`; as a path (`/usr/bin/ssh`)
  or after an escape in a string (`printf '…\nssh …'`); in a command
  substitution, also inside double quotes; in a pipe into a shell; in a file
  the line writes and then runs; as a URL that `curl` or `docker -H` connects
  to; as the program of an option (`rg --pre`); in a variable before a
  command (`BROWSER="ssh …"`); in a write to a startup file (`~/.bashrc`,
  `.envrc`, `.git/hooks/…`); and in
  any line that runs a command word it builds at run time (`S=ssh; $S web1`,
  `…; $_`, `eval`), since no parser can tell which text that runs. A mention
  that starts nothing does not ask: `grep ssh README.md`, a path such as
  `~/work/ms-ssh`, a comment, a commit message, a `git clone ssh://…` URL,
  or the word in Python code. A comment or heredoc whose end the parser cannot
  be sure of still asks.
- **A short deny list is always refused:** `mkfs` or `wipefs` on a device,
  `dd` to a device, `rm -rf /`, a fork bomb, anywhere in a command that names
  an ssh-family call (quotes removed; as a command word, not as a file name;
  not in plain text that a lone `echo` only prints).
  It is an airbag, not the protection.
- **Codex** cannot ask. It refuses and names a sentence with a code, for
  example `maisecrets: allow ssh web1 123456`. Typed alone as your very next
  prompt within 10 minutes, it allows writes to that host for 8 hours; the
  prompt does not reach the model. Any other prompt ends the code. Codex sends
  no sign of who wrote a prompt, so there the code is the proof.

Measured on the maintainer's transcripts with `scripts/measure_ssh_consent.py
--skip-cwd maisecrets` (2026-10-07, the sessions that work on maisecrets itself
left out): real ops commands use `sudo` or `docker` on the remote side almost
always, so most are writes (88 %), and the consent per host carries them. 112
sessions with ssh, a median of 2 questions per session, 7 at the 90th
percentile, 48 at most. The script ignores groups and the 8-hour expiry.

The mention rule, on the newest 600 sessions without the maisecrets ones
(2026-10-10): 0.6.10 asked 69 times, about 10 of them for a real reason;
0.6.11 asks 10 times, 8 of them for a real reason (labelled by hand).

**Check it on your own sessions.** `python3 -m maisecrets.cli consent-report
ssh` reads the Claude Code transcripts of the last 30 days on this computer
(`--last 7d`, or `--last 200` for the newest 200), classifies each command
that names an ssh-family word, and prints counts per verdict and per reason,
with no host, command or value. `--json` prints the same as JSON.
`--excerpts FILE` writes a short window around each question into a new
file of yours, to look at by hand: the values the detectors find are masked,
hosts and commands stay in it, so share only what you may share. It runs
nothing, changes no setting or consent, and sends nothing. Codex sessions are
not read.

A command name in another case (`SSH`, `Scp`) is the same program on macOS
and in PowerShell, so it counts too. A command line over 8,192 characters
that names ssh is not read at all: it asks (on Codex it is refused), so that
the answer always comes before the client's timeout.

Limits: maisecrets sees only the command text, and checks the ssh-family
starts that it shows. A program the line starts that starts ssh itself (a
script, `make`, `npm run`, `python3 -c`, `node -e`), an alias or a variable
set in an earlier command or in your profile, or a word built without the
letters `ssh` in the text is not seen. The check is built against an agent
that starts ssh openly without asking, not against one that tries to evade
it; consent before any connection needs a network layer (a sandbox with a host
allowlist). A program that git or gh starts
from its own configuration (a hook, an editor, a signing program, a browser)
is not checked; it gets the quoted text only as data. maisecrets reads the
command with its own small shell parser; other shell syntax that it reads
differently from bash or zsh can still hide a call (the reviews of 0.6.7 found
such forms only after one of the characters above). A mount (`sshfs`) or a tunnel
(`ssh -f -N -L`) that one consent started stays after the 8 hours, and the
local commands that use it ask nothing. On Codex the model sees the consent
code; maisecrets refuses a command that carries the sentence, but not one that
builds it at run time. The
`Monitor` tool of Claude Code runs a shell command outside the maisecrets
matcher (adding it would change the hook hash that Codex trusts). A program
that runs as you outside the sandbox can write the consent store. A hard
boundary needs host-side controls (restricted keys, `ForceCommand`, sudo
rules). Git over ssh (`git push`) is out of scope.

## Rehydration policy (optional)

The core does not change with this setting: a value stays out of the model on
every path, and a form where the value could become code is refused on every
path. The setting decides only whether maisecrets adds its own confirm where a
value is put into a call. `~/.maisecrets/config.json`, or the machine policy:

| `rehydration` | Claude Code | Codex |
|---|---|---|
| `"automatic"` (default) | no ask of ours; your permission rules decide. In auto mode an MCP call that gets a value asks you: auto mode checks the call before maisecrets puts the value in, then refuses it and shows the model the changed input | `allow` with the rewritten input |
| `"confirm"` | every call that gets a value asks, also in auto and bypass mode; the prompt names the fields and warns for a published-text field | refused before anything is resolved: Codex cannot ask with a rewritten input |
| `"block"` | refused before anything is resolved | refused |

It covers Bash, ssh, MCP tools and Write/Edit alike. `"resolve_in_files": false`
blocks the file tools alone; `"ssh_approval": "per-session"` works under
`confirm`. A value that is none of the three blocks. A `config.json` that is not
valid JSON, or holds no JSON object, blocks rehydration until it is fixed (it may
have said `block`), and
one ignored for a wrong type keeps what it made stricter (`rehydration`,
`resolve_in_files: false`, `ssh_via_sandbox: false`), so a typo never loosens
a setting. The refusal and `/maisecrets:status` name the file. In an unattended run (`claude -p`) nobody can answer a confirm, so the
call is refused and the model reads the reason, never the value. The whole
matrix, path by path: `tests/test_rehydration_matrix.py`.
- **Under a cap.** `max_keys_per_session` (200) distinct values per session and
  hour, and `max_resolves_per_hour` (1000) in total; above that the call is
  denied, and the reason names the command that raises the cap, for example
  `/maisecrets:settings max_resolves_per_hour 2000` (in Codex
  `maisecrets: set max_resolves_per_hour 2000`), typed as your own prompt. The cap
  is a brake for a session that would send all of its values out at once; the
  session rule above keeps every other value closed anyway. Replayed over five
  months of the maintainer's sessions, the busiest hour needed 67 values and 118
  uses; the old caps of 25 and 60 would have stopped 3 of 178 sessions that used
  values. Every resolve writes one line to `~/.maisecrets/audit.log`
  (time, session, key, tool, command with placeholders; never a value):
  `python3 -m maisecrets.cli audit`.
- **Not by the agent reading or changing the store.** A Bash command that
  calls `maisecrets get`, `security … maisecrets`, names `~/.maisecrets` or a
  delivery path, and a Write/Edit under `~/.maisecrets`, are denied and the
  reason names the pattern. This is text matching, a backstop; the boundary
  is the [gates around a resolve](HOW-IT-WORKS.md#gates-around-a-resolve), and a process that runs as you is not stopped by it.

Recommended in your Claude Code settings, outside the plugin: the sandbox with
`sandbox.credentials` deny for `.env` files and `~/.maisecrets`, and
`injectHosts` for the hosts a value may go to. That closes the paths no hook
sees: a command that sends `.env` or `printenv` somewhere without printing it
(a command that pipes `.env` into an upload). The hook redacts only what comes back.

## Rules of your own

**For administrators.** To give each machine of a team the same rules:

1. Run `maisecrets rules init DIR` (in the plugin folder: `bash hooks/run.sh
   rules init DIR`). It makes a team folder with `rules/`, `samples.txt`, a
   README and CI files for GitHub and GitLab.
2. Keep the folder in a repository of the company. Its CI runs `maisecrets
   rules check` on each change.
3. Put the folder on each machine. A git checkout that a scheduled job updates
   is one way.
4. Add the local path to `rule_dirs` in the machine policy ("Settings you can
   enforce"). A user cannot remove a folder of the policy.
5. On a machine, run `maisecrets rules check` to see that each folder loads.

maisecrets reads local folders only. It does not fetch or update a folder: how
the files get to each machine is the company's choice. When a folder of
`rule_dirs` is missing or cannot be read, each session start says so in one
sentence. When rules of your own run, the start line counts them: `maisecrets
0.6.N is on, with 12 rules of your own from 2 folders.`

You can add detection rules for the tokens of your own services, and you can
let single values through. maisecrets reads the rules from three places:

- `~/.maisecrets/rules.d`, your own folder. The AI cannot write there.
- each folder of the setting `rule_dirs`, for example a checkout of your
  team's rule repository. Type the change as your own prompt:

  ```
  /maisecrets:settings rule_dirs add ~/src/team-rules
  maisecrets: set rule_dirs add ~/src/team-rules     (the same, and the form for Codex)
  ```

  `remove` takes a folder off the list. Like every setting, only your typed
  prompt changes it (C22). When the folder has a subfolder `rules/`, as a
  team repository from `maisecrets rules init` has, maisecrets reads that
  subfolder; else it reads the folder itself. A folder with no rule file
  gets a note when you add it and in `/maisecrets:rules`.
- each folder of `rule_dirs` in the machine policy. You cannot remove those.

A folder holds three kinds of file, and maisecrets reads nothing else from it
(no symbolic link, no git metadata):

- `*.json` in the gitleaks form: `{"rules": [{"id": …, "regex": …,
  "keywords": […], "entropy": …, "secretGroup": …, "allowlists": [{"regexes":
  […], "regexTarget": "secret|match|line", "stopwords": […]}]}]}`. An optional
  `"type"` (`SECRET`, the default, or `NAME`, `EMAIL`, `PHONE`, `IBAN`, `CARD`,
  `IP`) sets the placeholder type. An allowlist with `"condition": "AND"`
  and more than one part is dropped (the stricter side), and
  `/maisecrets:rules` says so.
- `*.prefixes`, one rule per line, as in
  `maisecrets/detection/rules/prefixes.txt`: `id  PREFIX  REST`, where
  maisecrets adds the edges to the literal prefix, or `id  regex`. The whole
  match is the secret.
- `*.terms`, a team term list with a floor against common words (Terms). Not
  in `rules.d`: your own list is `~/.maisecrets/terms.txt`.

A hook reads these files in every call, so each rule passes checks when it is
loaded: a keyword or a literal of at least 4 characters, at most 300
characters of regex, at most 500 rules, 200 files and 1 MB per folder (the
first 2000 entries and 2000 rules of a folder are looked at, refused ones
included), 64 KB per file, and an id that no earlier rule of the same folder
has. A rule whose id a rule of an earlier folder has runs as `<id>#2`, so one
folder cannot take a rule of another folder out by its id; `rule: user:<id>`
in the allow list switches both off. The regex must not backtrack: no repeat
inside a repeat (`(a+)+`), no repeat of something that can be empty
(`(a?){25}`), no branches that start alike inside a repeat (`(a|aa)+`), no two
repeats in a row that take the same characters (`.*.*`, `\w+\d+`), no
backreference, and no quantifier of variable length at the start (`\w+…`,
`x?[a-z]+…`). Then maisecrets times each new rule once on test texts that make
a backtracking regex slow, also on runs of the characters its own repeats take
and on its literals, those of each branch too, repeated before long runs; a
rule slower than 50 ms on the texts of one start is left out. A new rule runs
only after this timed test: when a hook call has no time left for the test,
the rule waits for the next call, and `maisecrets rules check` times every
rule at once and keeps the result for the hooks. A rule that is still slow in
a real scan (more than half a second inside its regex in one hook call) is
left out from the next call on. When a hook runs out of time, the rule of your
own with the most regex time is left out, if that time is more than half of
the call. Each verdict is kept by a hash of the rule in
`~/.maisecrets/.rules-state`, so a hook pays for the checks once. A changed
rule is checked again; a rule that a real scan found slow stays out until you
change it, and `maisecrets rules check DIR` shows it.

A rule that fails a check is left out, with its reason; the rest of the file
still loads. A refused rule is named by its place (`rule 3`, `line 7`), never
by its text: a refused line can be a pasted value. A broken file or folder
never stops a hook and never costs the rules of another folder. The session
start names a new failure once, and `/maisecrets:rules` shows each folder,
its rule count, a hash of its files, and each rule that was left out. Your
rules run after every built-in rule, the personal-data rules too, so a rule
of your own never cuts a part out of an e-mail address or an IBAN; a hit
carries the id with `user:` in front (`user:acme-token`).

`maisecrets rules` (in the plugin folder: `bash hooks/run.sh rules …`) does
the rest:

```
maisecrets rules list [--json]      every rule in scan order: key, id, origin, rank, channel, region, class, upstream, patches
maisecrets rules check [DIR]        each rule: ok with its time, slow, or refused with the reason; exit 1 on a problem
maisecrets rules test [text]        what the rules find in the text or stdin: type, rule, place, length
maisecrets rules init DIR           a team folder: README.md, rules/, samples.txt, CI for GitHub and GitLab
maisecrets rules import FILE.toml   a gitleaks or betterleaks config in the JSON form (Python 3.11+)
```

`rules check` also reads `samples.txt`: a line `hit <rule-id> <text>` must be
found by that rule, a line `miss <text>` by no rule of the folder. A failure
names the line, never its text. Without a folder, `rules check` checks every
folder the hooks read, and a missing folder of the setting or the policy is a
failure too. The CI files of `rules init` take maisecrets from its newest
release, so CI runs the checks that the hooks of your team run; for a fixed
version, write `--branch v0.6.N` there. `rules import` leaves out a rule with a
filter it cannot read and a rule that fails a check, and says which.

**The allow list.** `~/.maisecrets/allow.txt` lists what is not a hit, one
entry per line, `#` for a comment:

```
# my own address in every git log
name@my-company.example
rule: phone
```

A line is one exact value: the value with nothing before or after it is not
reported, a longer value that contains it still is. An allowed domain does
not let through the e-mail address that ends in it. `rule: <id>` switches a
rule off (`rule: user:acme-token`, or a built-in id from
`maisecrets scan`). An entry is never a pattern. An administrator puts the
same lines in `allow` of the machine policy. A folder of `rule_dirs` carries
no allow list: the AI can write a shared checkout, and the AI may only make
detection stricter. A value that is already stored stays redacted by its
exact match; `/maisecrets:forget` deletes it. The list holds for the name
service too (`/maisecrets:ner`).

**A wrong hit in one step.** Type `/maisecrets:not-a-secret KEY` as your own
prompt (Codex: `maisecrets: not a secret KEY`), with the key from
`/maisecrets:list` or the placeholder you copied. It deletes the stored value
and adds its exact value to `allow.txt`, under a comment line with the key. The
answer names the key and the masked form, never the value. A secret, a card
number, an IBAN or an official, tax or bank number needs the same command
twice within 2 minutes. Only your typed prompt counts: a subagent, a program,
a scheduled prompt, another session or a tool call changes nothing.
`/maisecrets:list` shows each such allowance with its key, type, date and
masked form; `/maisecrets:not-a-secret undo KEY` (Codex: `maisecrets: undo
not a secret KEY`) takes it back. Undo deletes only the line it wrote, directly under its
comment line; a line you wrote yourself stays, and the answer says so when it
cannot tell the two apart. The line that tells you what was masked
ends with this hint.

## Values from your own tools

Your own tools often know values that maisecrets cannot find by their
shape: a NER finds the names in your case files, an export lists your
customers, a script knows the internal account ids. Give maisecrets those
values, and it masks them wherever they appear.

**The file.** Your tool writes one JSON object per line:

```
{"value": "Jan Kowalski", "type": "NAME"}
{"value": "jan.kowalski@example.org", "type": "EMAIL"}
{"value": "a value without a shape"}
```

`type` is one of `SECRET`, `NAME`, `EMAIL`, `PHONE`, `IBAN`, `CARD`, `IP`
(`SECRET` when it is missing). It names the placeholder, nothing else.
maisecrets reads only `value` and `type`; it ignores every other field.

**Import it.** Two ways:

- In a terminal: `bash hooks/run.sh values import FILE` (in the plugin
  folder). It prints the id of the import and its counts, and the number and
  reason of each line it refused. It never prints a value or the file name.
- As a setting: `/maisecrets:settings value_files add ~/work/ner-out.jsonl`
  (type it as your own prompt). maisecrets imports the file at each session
  start when its content changed.

maisecrets copies the accepted values to
`~/.maisecrets/imports/<id>.jsonl` (mode `0600`; the AI cannot read that
folder, C8). Each import has an opaque id such as `import:v1a2b3c4d`, never
the name of the file: a file named like one of its values would show that
value.

**What is masked.** From the next prompt and tool result on, each value is
masked in any case and with any spacing, also as a phrase of several words
across a line break (`Jan\n  KOWALSKI`), in composed or decomposed Unicode,
and with a soft hyphen or a zero-width character inside it. The match is on
whole words, as for a term ([Terms](USING.md#terms-names-case-numbers-customer-names)): `Kowalski` does not mask a part of
`Kowalskiego`. The placeholder has the type of the line, for example `⟦NAME_c3⟧`.

**Where the imports run.** The imports are a pass of the rule registry,
after the terms (`maisecrets rules list` shows it as `imports:import`, origin
and class `import`). It is one index of all imports, not one rule per value.
A hit names its import: its kind is `import:<id>:<value id>` in
`maisecrets scan` and in the store. The store keeps these ids, never the
value.

**Mask only.** maisecrets never puts an imported value back. An import
placeholder in a command, an MCP argument or a file that the AI writes stays
as it is.

**An import only adds.** maisecrets follows the rule of this epic: the AI can
make detection stricter, never weaker.

- A new import of the same file adds its new values to the same import. A
  value that the file no longer lists stays. An edit of a value file that
  removes lines removes no value. Each import keeps every value it lists,
  also one that another import holds: the removal of one import leaves a
  value masked while another import lists it.
- An import of a file by a command and the import of the same file as a
  value file are two imports. A command cannot fill the import of your
  value file.
- A value that a rule finds (an email address, an IBAN) keeps the span, the
  type and the placeholder of that rule. A value that the store holds
  already (a password from `/maisecrets:put`) keeps its own placeholder,
  its type and its lifetime, and it still resolves into your commands. An
  import never turns a resolvable value into a masked-only one. Only the
  parts of an imported phrase outside such a value get the import's
  placeholder.
- No field of a line can switch a rule off, allow a value or change a
  lifetime: maisecrets reads `value` and `type` only.

**Only you remove an import.** Type `/maisecrets:forget import:ID` as your
own prompt (in Codex: `maisecrets: forget import:ID`). maisecrets does not
send that prompt to the model. A prompt from a scheduled task, a subagent or
a program that started the client removes nothing. A tool call that carries
the removal is refused, also when quotes, escapes, line continuations or a
PowerShell `+` split it. A removal that a program builds at run time (brace
expansion, an empty variable or `$()` inside a word, a character code,
PowerShell `-join`) is not seen:
the same text-match limit as for a setting (C22), and `values remove` in a terminal only names the
prompt. If you remove the import of a value file, the next session start
imports the file again as it is now (also when you removed it in another
session). So to drop a few values from a value file, edit the file, then
remove its import.

**What you see.** `/maisecrets:list` shows each import: its id, the number of
values per type, its age, and whether it came from a value file or a
command. It never shows a value. The session start names each new import
once, with its id and count, also an import that the AI ran.

**Who may write the file.** The AI may run `values import`, and it may write
a value file that lies in a folder it can write (a repository checkout).
That is allowed, because an import can only add masking. The worst an import
can do is to mask too much. These limits hold that:

- A value needs at least 4 characters. A value of only digits needs at
  least 6. maisecrets refuses one word of lower-case letters, a value of only
  common words (the stop list of the team terms,
  `maisecrets/rules/term_stoplist.txt`), and a value that holds a placeholder
  bracket, a placeholder key (`SECRET_c1`), `maisecrets`, `import:` or the
  name of a setting (`value_files`). So no import can break a placeholder
  or mask your own controls. Also, maisecrets never rewrites a settings
  prompt or the ssh grant sentence: the hook reads them first.
- The floor does not know every ordinary word. A capitalised word such as
  `Pipeline` passes, and the match ignores case, so an import can mask such
  a word in every text. That masks too much, never too little; the session
  start names each new import, and you remove it.
- One import holds at most 100,000 values, and all imports together at most
  150,000. The imports that no value file names (the imports of a command,
  which the AI can run) hold at most 100,000 of them, so your value files
  always have room. maisecrets holds at most 50 imports, of which at most 30
  are imports of commands: 20 places stay for your value files. Only a file
  in your setting `value_files` counts as a value file. One file is read to
  at most 200,000 lines, and one import file holds at most 24 MB. Past a cap, the import stops, says at which
  line, and names the prompt that removes an import. A value file in a
  folder that the AI can write counts as your value file: the AI can fill
  the caps through it, and push out a value file after it.
- maisecrets opens the file once, without following a symbolic link and
  without waiting on it, and checks the opened file: it must be a regular
  file (not a FIFO or a device), owned by you (or root), and not writable by
  every user. Then it reads it once, up to 8 MB. So a file that is swapped
  between a check and the read, a FIFO, and a file that grows while it is
  read all fail or stop at the limit. Windows has no open without a link:
  there maisecrets refuses a link one step before the open. A line that a writer has not finished
  is not valid JSON, so maisecrets refuses that line by its number and
  imports the rest.
- A damaged import in the maisecrets folder stops every hook (fail closed),
  and the message names the prompt that removes it. So does a `*.jsonl`
  file in `~/.maisecrets/imports` that no import id names.

**Not in a failed tool call.** When a command fails (a non-zero exit code),
Claude Code sends its output to the model before maisecrets sees it, as for
every other value (C2). An imported value in that output reaches the model.
maisecrets masks it in the transcript afterwards. A PDF or an image is not
read either, as for the terms.

**Cost.** Without an import, maisecrets does not load the import code: a hook
costs what it cost before (measured, `docs/BENCHMARKS.md`, "Values from your
own tools"). With an import, a hook loads one index from
`~/.maisecrets/.values-cache`. maisecrets builds the index after each import
and at session start, so a tool hook only loads it.

## Vault references

An MCP server can mask a value in its result, for example a customer's e-mail
address, with a token such as `⟦EMAIL_1:ma•••@example.org⟧` (no `c`: the server
made it). Without maisecrets, a file that the AI writes from that result holds
the token. With maisecrets and a server that supports vault references, the
file holds the real value, and the AI still sees only the token.

How it works (`docs/PROTOCOL.md` section 4):

1. Until an MCP server that you added yourself (user scope, an `https` URL)
   sends such a token, maisecrets asks no server and writes nothing into
   the client's config file. Tokens in a Bash output, a file, a web page or from a
   server in a project's `.mcp.json` start nothing.
2. With the first token of that server, maisecrets asks it once for its
   metadata (RFC 9728). Only if the server names a vault endpoint there does
   maisecrets make a random key for it and write a `Client-Vault` header with
   a hash of that key into that server's entry in the config file that
   Claude Code itself uses: `~/.claude/.config.json` when that file is not
   empty, else `~/.claude.json` (both in `CLAUDE_CONFIG_DIR` when it is set;
   the rule of 2.1.301). The other file is then an old copy, and maisecrets
   never reads or writes it. `/maisecrets:status all` names the file. It
   changes nothing else in the file and keeps a backup beside it. You see a
   notice once, with one step: type `/mcp reconnect <server name>` (or start
   Claude Code again). The reconnect reads the server entry again, its
   headers included, and every later request carries the header (measured
   with 2.1.302). A server without the field gets no header, and maisecrets
   asks it again at the earliest after an hour.
3. The server links the hash to you when you log in to it. A link that comes
   from an existing login waits a day. The server tells you on its own
   channel; Claude Code does not show a server's notice in the chat
   (measured with 2.1.302). To use it earlier, activate it on the server's
   connections page, or sign in to the server again in the browser. You can
   revoke it there too. After a tool result of that server, maisecrets notes
   the tokens in it. The result does not change.
4. When the AI writes such a token into a file or a Bash command, maisecrets
   asks the server for the values, with the key, and puts them in. It gets all
   values or none. If the server refuses, the call is denied, and the reason
   names the state of the server and your next step (the table below).

`/maisecrets:status all` groups the servers by state ("active: …", "not used
yet: …"); a server in a state that needs a step of yours keeps its own line,
with the time of the last answer. It asks once per server origin that has a key on this
computer (an empty request that can return no value); two entries on one
origin share the key and the answer. At a session start maisecrets asks the
same question once per such origin, within 5.5 s for all, and tells you in
one line when a state changed since you last saw it. The deny reason of a Write, Edit or Bash call uses the same words:

| State | What you do (Claude Code) | In Codex |
|---|---|---|
| not used yet (no server token seen, or the server names no vault endpoint) | nothing | nothing |
| header written | type `/mcp reconnect <server name>` (or start Claude Code again) | start Codex again |
| waiting for activation until `<time>` | activate it on the server's connections page, or sign in to the server again in the browser | the same |
| active | nothing | nothing |
| this key is quarantined (used by two accounts) or revoked | nothing: maisecrets makes a new key at the next start, and you see the header step again | the same, then start Codex again |
| the server's operator switch is off | ask the server's operator | the same |

The server gives the same answer for a quarantined key, a revoked key and a
key it never saw. maisecrets tells them apart only by its own record: a key
that the server once answered as active or waiting is "quarantined or
revoked" now, any other key is "header written". A key that a server bound
and quarantined before maisecrets asked it once reads as "header written".
A revoke alone makes maisecrets make a new key at the next start. To stop
the link for good, turn the feature off: `client_header:
false` (`/maisecrets:settings client_header false`) turns it off (in Codex at
the next connection to the server) and removes
the header again. A server behind a
certificate authority of your own needs `client_vault_cafile`. On Windows a
Bash command gets no server value.

**In Codex** (measured with codex-cli 0.162.0 and 0.155.1) the same steps
hold, with three differences:

- maisecrets writes no header into `~/.codex/config.toml` (or
  `$CODEX_HOME/config.toml`). A repository's `.codex/config.toml` can give
  your server entry another URL: Codex merges it over your file, and it trusts
  a project on its own when its sandbox may write there. A fixed header would
  then go to that URL. So maisecrets adds one line, `http_headers_helper`, to
  that one entry. Codex runs this command when it connects to the server. It
  prints the header only when no `.codex/config.toml` of the folder you work
  in, or of a folder above it, names MCP servers, and only in the first folder
  of that Codex process, within two minutes of its start; else it prints
  nothing. The server needs the header only once, to link your key, so this
  limit costs little: in the desktop app a later chat in another folder sends
  no header until the app starts again.
  maisecrets changes no other byte of the file, does not touch a file that
  does not parse or that lies in a git repository, and keeps a backup in its
  own folder (`~/.maisecrets/vault-refs/`) until the next start that changes
  nothing.
- The values come from the next start of Codex: a new `codex` run sends the
  header, an open session does not (measured with codex-cli 0.162.0). Codex
  shows the notice as a warning of the hook in its terminal UI; `codex exec`
  does not print it.
- In a repository that brings its own MCP servers, maisecrets notes no token
  and sends no header. Codex vault references need Python 3.11 or later
  (`tomllib`), and they are off on Windows in this version. `apply_patch` and
  Bash (macOS, Linux) get the values.

The limit: an AI agent that runs as your user can read the key from the
store, as it can read any stored value. The server's cap, its audit and the
revoke bound that. A value written into a file is plain text there.

## Sensitive References

A gateway with Sensitive References (for example mcpgate, where the resolver is
where every person with an account may use it, unless an administrator blocks them) can mask a value in
its tool results with a reference such as `⟦sref:email:<id>:ma•••@example.org⟧`.
The AI sees the reference and its display part, not the value in the call.
With maisecrets, a command or a file that needs the value gets it on your
computer, at the moment of the call, from the gateway's resolver. A file keeps
the value, so the AI sees it if it reads that file later; for one hour after a
resolve, output that prints the value shows the reference instead.

1. Log in once: `/maisecrets:sref login` (in Codex: `run.sh sref login` in a
   terminal). Your browser opens; you log in to the gateway and give the
   consent there. Nothing logs in by itself. When a server of your own
   configuration first sends this session references and this computer has
   no login at its gateway, a line says so, once per session and gateway, with
   the command. In Claude Code the command `/maisecrets:sref login NAME` also
   goes into the input box at the end of the AI's turn, when the box is empty
   (else at the end of a later turn): your Enter starts the login. `/maisecrets:sref` shows the
   state, `/maisecrets:sref logout` forgets the login. The gateway gives a
   new refresh token at each renewal and ends the login when a spent one comes
   back. When a renewal ends without a usable answer (a crash, a killed
   process, a broken connection, an error of the gateway) and the gateway
   names a reuse window (`sensitive_references.refresh_reuse_interval`),
   maisecrets sends the same token once more and gets the same new pair: the
   login stays. The retry goes out 3 s after the first request and 3 s after
   its failure at the earliest, and only when it can end inside the window. A
   gateway that needs more than about 7 s for one renewal still sees it as a
   second use and ends the login. Without the window,
   after that one retry, or when the window has ended, maisecrets never sends
   that token again: on the next use or renewal it tells you that the last
   renewal did not finish and that you log in again. A login the gateway
   refused is named as "the gateway ended the login".
2. A reference counts only when a tool result of a gateway that you added
   yourself (user scope), or of a claude.ai connector, showed it in the same
   session in the last 24 hours. A claude.ai connector has no URL in the
   client's config, and a result's text cannot say which server spoke. So in
   Claude Code, after a connector showed a reference, the mod asks that
   connector's tool `sensitive_references_resource` for its gateway at the end
   of the turn. Its answer is only a proposal (for an hour): the input box
   gets `/maisecrets:sref login NAME` and a line that names the connector and
   the host, and only a login you type (or press in the panel) binds the
   connector to that gateway; the AI cannot run `/maisecrets:sref`. What stays:
   a connector you added that is not your gateway can name your gateway's URL.
   Log in only when the named connector is your gateway (a check by the
   gateway itself is planned). Before that, its
   references do not count; ask for them again after the login. A binding is
   never re-pointed, never takes a gateway that a server of your
   configuration or another connector holds, and never a name of your own
   configuration (also `claude_ai_…` names); `/maisecrets:sref logout NAME`
   undoes it. A reference that two gateways showed in a session resolves at
   neither. The connector's name in commands is its tool-name spelling
   without `claude_ai_` (`claude.ai Team GW` is `Team_GW`). Codex has no
   claude.ai connectors in its hooks, so this applies to Claude Code only. A
   reference from another session, or one the AI typed itself, gets a reason
   and no value.
3. In a Bash command the value is fetched only when the command starts and
   reads it; a command that never runs costs no resolve. maisecrets sends the
   program's name as the target (sink `process`). A command needs a login
   that allows it: on macOS and Linux the login asks for the gateway's
   command scope too, and the consent page names it ("may also put real
   values into commands"). A login from before 0.9.0, or one on Windows, fills
   files only: the command then prints the gateway's reason and ends with exit
   code 97, without the value; `/maisecrets:sref login` again allows
   commands. In the content of Write,
   Edit, MultiEdit, NotebookEdit or a Codex patch the file gets the value, and
   maisecrets sends the path as the target (sink `local_file`); mcpgate checks
   the kind of target, not the path. The value of a file write is fetched
   before the client asks you about the write, so a write you refuse has
   already cost a resolve (counted in the gateway's daily quota and audit) and
   the AI still gets nothing. A reference in a path is refused. Anywhere else
   (another MCP server, WebFetch, a subagent) it stays text.
4. For an hour after a resolve, output that prints the value shows the
   reference instead. An error names the reason and a count, never a value. The
   audit (`/maisecrets:audit`) names each resolve with the kind of the
   reference and 4 characters of its id.

The gateway decides who may resolve and which sinks it allows; maisecrets
adds the session rule on your computer (`docs/THREAT-MODEL.md`, C31).

## Names from a service (optional)

The rules find few names: a name has no shape (docs/NER-EXPERIMENT.md). A
named-entity service can add them, in tool results and, in Claude Code, in your prompts. It is off until you choose
a source, with one command typed as your own prompt:

| Command | Source |
|---|---|
| `/maisecrets:ner local` | the service on this computer, `http://127.0.0.1:8765/` (`on` is the same) |
| `/maisecrets:ner url URL` | a service of your team on a private network |
| `/maisecrets:ner gateway URL` | the gateway of your `/maisecrets:sref login`, when it offers name detection (log in once more after the switch) |
| `/maisecrets:ner gateway NAME` | the same, by the name of an MCP server of your configuration (the list of `/maisecrets:sref`); the name alone, `/maisecrets:ner NAME`, is the same when it is no word of the command |
| `/maisecrets:ner off` | the rules alone (the default) |
| `/maisecrets:ner fallback url URL` | a second service for tool results while the local one is not running (`fallback off` removes it) |
| `/maisecrets:ner unavailable withhold` | while the service gives no answer, a tool result is kept from the AI; by default (`unavailable rules`) the rules alone mask it |
| `/maisecrets:ner updates off` | the image of the local service stays as it is; by default it follows the plugin (`updates on` turns that back on) |
| `/maisecrets:ner` | one screen: a head line (the source and whether it answers), then one line per check, marked as in `/maisecrets:status` (✓ ok, ! warn, ✗ FAIL, – n/a), with the next command after → for a warn or a FAIL. The checks: the source and what it reads; for `local` the service (and its secret), the image and the load; for `url` whether it is reachable; for `gateway` the login with the name scope and your quota; and today's count from `ner.log` (a warn when the rules alone took at least 10 texts and at least a fifth of all) |
| `/maisecrets:ner all` | the same, then the details: what the service reads, what a tool result gets while it does not answer, the model and types, the image against the pin, the load from `GET /metrics` (workers in use, requests that wait, CPU and memory of its container; numbers only) and today's counts per service |

In Codex, send `maisecrets: ner local` (or `url URL`, `off`) alone as your
prompt. An argument the command does not know gets an answer with the valid
forms, and nothing changes. One source at a time: a new one replaces the old one. A fallback only
when you add one. Only a prompt you type changes it, with the limits of every
setting (threat model, C22). `local` means whatever listens on 127.0.0.1:8765;
maisecrets does not verify that it is `mcpgate/ner`.

- **local**: the service is the container `mcpgate/ner` (the model D3 of the
  NER experiment as ONNX; AFL-3.0 and Apache-2.0, its notices are in the
  image). When the person types `/maisecrets:ner local` (in Codex `maisecrets: ner local`) or presses
  `local` in the panel, maisecrets starts it at once in the background with docker or podman, with no
  question first, and says so (about 690 MB to download, 1 to 2 GB on disk, about 250 MB of memory
  while it runs, at most 1.5 GB and half the cores, 2 to 4). No second download or container start runs at
  the same time: a start holds the lock of the start, and a second one that comes while it runs waits for
  it or ends with a note. `/maisecrets:ner off` turns the source off, as before; it
  does not stop a download or a start that runs. While one runs, the answer says that the start ends by itself
  and to send `/maisecrets:ner off` again after it. Only that typed choice starts a
  download: a source set by a policy or in an earlier session does not, and the session start then says that
  the service is not running and names `/maisecrets:ner local`. The start is
  `run.sh ner start`, which runs the container `ner` with a secret of its own
  (in its environment, never on a command line) and keeps that secret in your
  store. Before each text the container must prove the secret (a fresh
  challenge each time); a process that holds the port without it gets no text,
  and maisecrets tells you once. A container you started by hand keeps working,
  unchecked; `/maisecrets:ner` says which one runs. The proof and the text use
  two connections, so a process that takes the port in the moment between them
  is not stopped; only one that can stop the container can do that.
  If the kept secret is lost or cannot be read, the container gets no text
  until you run `/maisecrets:ner` again. Each tool result reads the secret from
  your store (on macOS the keychain), which costs a little time. A process of
  your own user that deletes maisecrets' files can switch the check off, as it
  can change any setting; the check stops a listener that holds the port, not
  your own account.
  Without docker or podman, install one of them (Docker Desktop, OrbStack,
  Podman), use a service of your team, or keep the rules alone. After a
  restart, maisecrets starts the container again at the next session start
  (`docker start ner`, only for a container whose image is `mcpgate/ner`);
  until it answers, the rules work alone.
  **Updates:** each plugin version pins one image of `mcpgate/ner` by its
  digest. When a plugin update pins a newer one, the next session start updates
  the container in the background. A stopped container starts first; then the
  new image downloads while the old container runs (if the download fails,
  nothing changes). The old container stops and waits as `ner-prev`, and a new
  one starts with the same secret. Only when the new one proves the secret is
  the old one removed, with its image. If the new one does not prove it within
  90 seconds, it goes, the old one runs again, and maisecrets tries that image
  again after a day, not at each session start. For the seconds of the change
  the rules work alone. The image only moves forward: a session that still
  runs an older plugin version never takes a newer image back. This applies
  only to a container that `run.sh ner start` set up; a container you started
  by hand is never replaced, and `/maisecrets:ner` says which image runs and
  which one the plugin pins. `/maisecrets:ner updates off` keeps the image as
  it is; it counts as a weaker setting, because the old image keeps its old
  fixes.
- **url**: the text of each tool result goes to that service, with each value
  the rules found as filler. The service has no sign-in: run it only on a
  network that only its users reach. It must use https or a private address
  (RFC 1918, ULA, link-local, 100.64.0.0/10): plain http to a public address is
  refused. An administrator can set the source for everyone in the machine
  policy.
- **fallback**: used only while nothing listens for the local service (it is
  not running), for tool results only. A slow or broken local service, and a
  team service as the first source, never hand text to the fallback, and a
  prompt never goes there. The AI says once per session when it is used.
  On Windows a stopped local service answers a connection only after about
  2 s (Windows retries it), so with the default `timeout_ms` of 300 it counts
  as slow and the fallback does not take over; a `timeout_ms` of 3000 lets the
  refusal arrive in time.
- **Which service read what**: `/maisecrets:ner` and `/maisecrets:status all`
  count today's requests per service, from `ner.log` (time, service, tool
  result or prompt, characters, names, plugin version; never text). The counts
  are those of all your sessions on this computer, not of one session, as far
  as the log keeps them (above 1 MB its older half goes). A session keeps the
  plugin version it started with: the counts say how many requests came from
  sessions of another version, and name a result of the rules alone from a
  version before 0.8.29, which wrote no reason, `older version`.
- **Names in lower case**: the model of `mcpgate/ner` is cased, and a capital
  letter is its main sign of a name. `Peter Pan` becomes a placeholder,
  `peter pan` mostly stays text. A name that must always be masked belongs in
  your term list (`/maisecrets:term add NAME`).
- **Product names**: the model takes some product and model names for a
  person. A product word that stands alone (Claude, Copilot, GitHub, Jenkins,
  Jira and a few more) is never masked as a name; a full name that holds one
  is. It can still mark another product name as a person.
- **When the service does not answer**, the rules mask the tool result alone,
  as without it, and the AI tells you once per session. `/maisecrets:status`
  shows the source and whether it answers.

The command writes the setting `remote_detector` in `~/.maisecrets/config.json`
and keeps its other keys. Written by hand, the setting looks like this:

```json
{
  "remote_detector": {
    "url": "http://127.0.0.1:8765/",
    "format": "hf",
    "model": "d3-onnx-fp32@d421f57d",
    "timeout_ms": 300,
    "max_chars": 20000
  }
}
```

- `format`: `hf` (Hugging Face token classification) or `presidio` (Presidio
  Analyzer, `POST /analyze`; `language` sets its language, `en` by default).
- Only names by default (`PER`, `PERSON`). `classes` maps more classes of the
  service to a type, for example `{"PER": "NAME", "LOC": "ADDRESS"}`, and
  `min_score` sets the least score per type. No threshold is set for you.
  With a class beyond names and `"ask_labels": true` (the command sets it),
  the `hf` request asks for those classes
  (`"parameters": {"labels": [...]}`); `mcpgate/ner` answers `PER`, `ORG`,
  `LOC` and `DATE` (its `GET /info` lists them).
- `url` must be a loopback address or a Unix socket (`unix:/path/to.sock`).
  Another host needs `"allow_network": true` in the setting, and then your tool
  results go there (PRIVACY.md).
- Tool results, and the prompts you type in Claude Code (with the mod), for every source: a
  name in a prompt becomes a placeholder and never blocks it. A service on the network (`url`, `gateway`) gets
  the prompt with the rules' findings and your stored values as filler (threat model, C30a). Codex prompts keep
  the rules alone (Codex cannot rewrite a prompt, so it can only block one). A prompt of a program (`claude -p`,
  the Agent SDK) never goes to a service on the network, and a fallback never gets a prompt. Until 0.9.14,
  `/maisecrets:ner prompts on|off` turned the prompt part on or off; that form now gets the list of valid forms,
  and a `"prompts"` key in `~/.maisecrets/config.json` is ignored. Only an administrator can keep prompts from
  the service: a `remote_detector` in the machine policy with `"prompts": false` (the whole setting then comes
  from the policy). `/maisecrets:ner` shows `prompts: policy` then. A person who had a `url` or `gateway` source before this
  change sees one note at the next session start in Claude Code: the name service now checks prompts too.
  One request per tool call or prompt. A tool result waits `timeout_ms`
  (300 by default, at most 5000; the name lookup and a slow answer count too), plus a share
  that grows with its length: 1.5 times the rate of this computer (ms per 1,000 characters,
  from its last answers; 60 until it has five, the rate of the reference setup) per 1,000
  characters, at most `max_timeout_ms` (3000 by default, at most 5000). `"timeout_scales": false`
  keeps the fixed `timeout_ms`. `ner.log` names the reason of each result that the rules took
  alone (timeout, too_long, refused …), and `/maisecrets:ner` counts the reasons. A prompt waits
  `prompt_timeout_ms` (1000 by default for a service on this computer, never less than its `timeout_ms`;
  2000 in total for a service on the network, the gateway's discovery and token included, plus at most about 0.1 s that a thread needs to end; at most 5000): you wait for
  your prompt anyway. If the service gives no answer in time, the prompt goes on with the rules alone,
  and maisecrets says once per session that its names were not checked, and why. On the reference setup
  (`mcpgate/ner` with the production limits of 4 cores and 1.5 GB, an AMD EPYC 9645, 4 requests at
  once; `bench/results/2026-11-01-v3-0.8.7-prompt-ner/`) a text of 1,000 characters takes 100 ms
  (median) and 164 ms (p95). Each value
  the rules found goes out as `_` filler of the same length. The filler costs
  the model a few names (21 of 2,482 on the benchmark samples), so a service on
  loopback or a Unix socket may read those values as they are with
  `"mask": false`; any other host always gets the filler. A slow, dead or
  confused service changes nothing: the rules' result stays as it is. A result
  longer than `max_chars` is not sent.
- When a source is set and cannot be used, you see one line with the cause and the step, for example
  `⚠️ maisecrets: names are NOT checked — the gateway ended the login → /maisecrets:sref login NAME`. The session
  start checks the source (the gateway: a login in the store; a url or the local container: an answer within a
  second; a Unix socket: a connection within a second), and a tool result names it once per session, again only when the cause changes. `/maisecrets:status`
  and the panel show it as a `names` note, and the head line then says "protects secrets in this session; names
  are not checked". The AI is told at each such result that names may stand in clear text; a name it then
  writes in clear text came through that result; it is not made up. A text longer than the service takes still
  gets its own line under that result. With `/maisecrets:ner unavailable withhold`
  such a result does not reach the AI at all (a text longer than the service takes is named, not withheld). The
  output of a failed command (Bash with an exit code other than 0) is neither checked by the service nor
  withheld: Claude Code does not let a hook replace it (threat model, PostToolUseFailure).
- **gateway**: the gateway of your `/maisecrets:sref login` finds the names, when its protected resource metadata
  names `ner_endpoint` and `ner_scope`. The login asks for that scope only while this source is set, so you log in
  once more after the switch. The text goes over https with your access token, the rules' findings as filler.
  A tool result waits 3,000 ms by default (`timeout_ms`); measured from a laptop against the reference gateway:
  p50 160 ms for 200 characters and 740 ms for 10,000; with 8 sessions at once p95 600 ms. The gateway's wait
  does not grow with the length of the text, and its answers do not change the rate of this computer
  (`ner-rate.json`). A prompt waits 2,000 ms by default; only a prompt you type goes there, never one of
  `claude -p` or the Agent SDK.
- A name the service finds is masked and stored, so its placeholder resolves,
  but it is never searched for in other texts: a wrong name such as `Build`
  costs one mask, where the service saw it. If a rule finds the same value
  later and would search for its own finding, the name is searched for from
  then on; a common word after a label stays where it was found.
- `model` is what you state; the answer of either format names no model.
  `examples/ner_service.py` is a reference service with the model of the NER
  experiment and reports its model at `GET /info`. It is an example, not part
  of the plugin.
