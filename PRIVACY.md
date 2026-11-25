# Privacy

maisecrets has no service of the publisher, no telemetry and no network connection that
you did not set up. Its hooks and its mod process your data on your machine. Network
communication happens only in the cases listed under "What leaves the machine": a
command that you or the agent runs, and a service that you set up yourself (a name
service, a gateway of references, or an MCP server you added). This page
states what it reads, what it stores, for how long, and what leaves the machine, so that
a person or a data-protection officer can check it against the source.

## What it reads

- **For detection:** only the text that the client hands the hooks and the mod: your
  prompts, the input of tool calls and the results of tool calls. The hooks scan that text
  for secrets and personal data (e-mail addresses, phone numbers, IBANs, card numbers, IP
  addresses and national identifiers where enabled).
- **Its own files:** its configuration (`~/.maisecrets/config.json` and, if an
  administrator wrote one, the machine policy file), its state and logs under
  `~/.maisecrets/`, and the stored values in the store of your operating system.
- **Files you named in a setting:** the folders of your own detection rules
  (`rule_dirs`) and the files of values from your own tools (`value_files`).
- **The client's transcript:** with `scrub_transcript` on (the default), it reads the
  transcript file of the current session on your disk and masks a detected value in it.
  When the client does not name that file, it looks for it by the session id in the
  client's `projects/` folder.
- **The client's configuration:** the client's config file (`~/.claude.json` in Claude Code,
  or the file the client uses: the MCP servers you added, and the account ids the guard
  compares), its settings files (user, project and managed: the guard checks whether
  maisecrets is switched on), its plugin list, its `commands/` folder, and the marketplace
  copy that the client fetched or a local marketplace folder you added (for the version
  that `/maisecrets status` shows). In Codex: `config.toml` with its profile files, the hook
  trust and the marketplace copy.
- **The language setting of the system:** on macOS, the language and region of your account
  (`~/Library/Preferences/.GlobalPreferences.plist`), to choose the label languages and the
  national identifiers. The environment variable `MAISECRETS_LOCALE` replaces this read.

It reads no other file of yours, except through a tool call that you or the agent makes.

## What it stores, and where

- Detected values go into the store of your operating system: the macOS login keychain,
  the Windows Credential Locker, or an encrypted file with a 0600 key file on Linux.
- `~/.maisecrets/index.json` holds metadata: a keyed fingerprint of each value, a masked
  display for personal data (never for a secret), timestamps, and the session ids that may
  resolve it. It never holds a value.
- `~/.maisecrets/audit.log` holds one line per resolve (time, session, key, tool, the
  command with placeholders; for a Sensitive Reference also the gateway's audit id of the release, when the
  gateway sends one of 1 to 128 characters of `A-Z a-z 0-9 . _ -` that holds none of the values this gateway released). `events.log` holds the last detections (rule and type).
  `hooks.log` holds one line per hook run. `pending/` holds a blocked prompt with
  placeholders for 15 minutes. `withheld/` holds, for an hour, the task id and the server and tool
  name of an MCP result the prompt hook blocked, so the AI learns of it once. `incidents.json` and the `incident-marker.*` folders hold
  maisecrets' own internal failures as closed codes (code, cause, client, tool class, a
  count, the number of days, the plugin version); never an error text, a path, a prompt, a
  command, a session id or a value. None of them holds a value.
- With `scrub_transcript` on (the default), the plugin masks a detected value inside the
  client's own transcript file on your disk, in place.
- Vault references (only after an MCP server you added yourself sent a server token and
  names a vault endpoint): a random key K per server origin in the store above;
  `~/.maisecrets/vault-refs/` holds the server tokens seen, the key ids and endpoints,
  each server's link state and the copy of the Codex profile file (below), never a value or
  a key of maisecrets; a value a server gave stays in the store
  for one hour so its echo in later output is masked. In the client's configuration the
  plugin adds one `Client-Vault` header (a hash of K, never K) to that server's entry, in
  Claude Code, or a header helper line, in Codex.
- Before it changes a file of the client's configuration, the plugin keeps a copy beside it,
  mode 0600: `<config>.maisecrets-backup` before it adds or removes that header, and
  `settings.json.bak-maisecrets-<time>` for each `/maisecrets guard install`. A copy holds
  what the file holds, also its tokens. A link at a copy's name is removed, not followed.
  The copy of the config file goes when maisecrets next finds that no header needs a
  change. For a Codex profile file, the copy lies in `~/.maisecrets/vault-refs/` instead.

## For how long

A value expires after its TTL (24 hours by default, one hour for card numbers, at most 30
days; renewed on use up to the cap) and is then deleted from the store. Metadata of an
expired value is deleted 30 days later. The logs are capped (2 000 lines). `wipe` deletes
the stored values, the metadata, the logs, the waiting prompts, `vault-refs/` and the
copies of the client's configuration it made, at once. It does not delete your settings
and your own lists in `~/.maisecrets/` (`config.json`, your terms, the imported value
files, the list of values that are no secret) and some state files of its own.

## What leaves the machine

No telemetry. The hooks and the mod send nothing to a server of their own. The one download
is the image of a name service on this computer that you set up (`/maisecrets ner local` or
`run.sh ner start` pulls it first): at a session start, the plugin gives that container the image
its version pins, with the docker or podman on your PATH (`/maisecrets ner updates off` keeps the
image). Connections start only from a command you run, or go to a service you set up yourself:

- Your own ssh command inside the Claude Code sandbox goes through Claude Code's local
  sandbox proxy to the host you named, with the proxy login Claude Code sets for that
  sandbox. Before an ssh command that carries a value, a check tries a few direct
  connections that the sandbox must refuse; it sends no data.
- In Claude Code, after a claude.ai connector of yours showed a gateway reference, the mod asks
  that connector once per session which gateway it belongs to (its tool
  `sensitive_references_resource`, with no argument). It sends no text of yours; the answer is a
  proposal that only a login you type takes. After that login, for a gateway that gives a pairing
  proof, the mod calls the same tool once more with a random nonce as its only argument, and
  maisecrets sends the same nonce with your login token to that gateway to check the
  connector's proof. Neither holds text of yours.
- A stored value can go to your gateway as a deposit, over maisecrets' own connection with your
  login token, when the AI uses it in a call of a claude.ai connector that is bound to that gateway;
  the call then carries a one-time handle in place of the value.
- `/maisecrets report` prints the issue text and a prefilled link to the configured
  `report_url`. It opens no browser and files nothing: the connection starts when you open
  the link, and you decide in GitHub's form. A prefilled GitHub link carries the issue text,
  the plugin version, your platform and the rule name of a detection or the closed codes of an
  internal failure, never a value. Another tracker set in `report_url` is printed as it is
  configured, with no text in it. Set `report_url` to your own tracker or to `null`.
- Vault references: after an MCP server that you added yourself (user scope, an `https`
  URL) sent a server token, the plugin reads that server's public metadata once. If the
  server names a vault endpoint, it asks that same server, over HTTPS and with K, for the
  values behind the tokens the AI writes into a file or command, and for the state of the
  link (no token in that request). No request goes to any other host, and nothing goes out
  before such a server sent a token. `client_header: false` turns this off and removes the
  header.
- A named-entity service (`remote_detector`, off by default): only when you chose a source
  (`/maisecrets ner local`, `url URL` or `gateway URL`, or `config.json` names its `url`), the text of a tool result goes to that service after the rules ran, with
  every value the rules found replaced by filler of the same length (a service on this
  computer gets them as they are only when the setting says `"mask": false`). A typed prompt goes
  there too, with the same filler, but only in Claude Code with the mod (which rewrites the prompt),
  and not when a machine policy sets `"prompts": false`. A prompt of a program (`claude -p`, the
  Agent SDK) never goes to a service on the network. The gateway source sends the text with the access token of your own `/maisecrets sref login`.
  That login holds the name scope whenever the gateway offers it, but the gateway gets text only while you chose it
  as the source.
  A fallback you add (`/maisecrets ner fallback url URL`) gets tool results only while the
  service on this computer is not running, and never a prompt. `ner.log` in the store folder
  records per request the time, the service, the kind, the length and the count of names, never text. The plugin accepts only a loopback address (127.0.0.0/8, `::1`, `localhost`)
  or a Unix socket, so the text stays on this computer, unless you set `allow_network: true`
  in that setting (`/maisecrets ner url URL` sets it for a host that is not on this
  computer); then it goes to the host you named. What the service finds is stored like
  any other value and masked only where the service found it, unless a rule that searches for
  its own findings finds the same value later.
- The Windows Credential Locker may roam through a Microsoft account on a machine that is
  not domain-joined. Choose the `encrypted-file` store there if that matters.

A tool result of a claude.ai connector passes Anthropic's connector proxy before maisecrets masks it, so there
only the gateway's own scrubber protects it; a stored value never goes into a connector's tool call.

## Who processes what

The plugin has no server and no telemetry. mcpgate (the publisher) receives no data from
it. The source is public on GitHub, in the repository `Mcpgate-de/maisecrets`, under Apache-2.0.
