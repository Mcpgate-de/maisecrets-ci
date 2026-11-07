# maisecrets protocol (draft 0)

This document is the specification that a client (hook plugin) and an
execution point (a gateway) share. The plugin repo owns it; a gateway
implements it.

## 1. Placeholder

`⟦TYPE_cN⟧` or `⟦TYPE_cN:display⟧` (brackets U+27E6/U+27E7, mask character
U+2022 in the display). Chosen by measurement against real parsers: `<…>` vanishes in HTML and is a shell redirection, `[…]`
is a Jira link and a regex class, `***` is a regex quantifier; `⟦…⟧` with
`•` survives CommonMark, HTML, XHTML, URL query, regex and SQL LIKE.

- `TYPE` is one of `SECRET`, `EMAIL`, `IBAN`, `CARD`, `IP`, `PHONE`.
- `c` marks a client-minted reference. A server mints `⟦TYPE_N⟧` or `⟦TYPE_N:display⟧` without `c`
  and never mints the `c` range, so the two never collide.
- `N` is a per-client, per-type counter. It is never derived from the value.
- Resolution matches the key `TYPE_cN` only. The display part is for humans
  and may be dropped or altered by a model.
- The gateway treats a `⟦…⟧` token as its own only when the display part is
  empty or is itself a display (a fixed point of the mask transformation); a
  real value in token form is still scanned.
- The earlier `<TYPE_cN>` form is recognised for rehydration, never minted.
- The display rules (`maisecrets/pii_display.py`): e-mail shows at most two
  characters of the local part and, for a non-freemail domain, only the
  top-level label; phone shows the first two digits and the last two; card the
  last four; IBAN the first and last four; IPv4 the first two octets; IPv6 the
  first two hextets before `::`. A display hides at least three characters and
  always carries a bullet; a value the rules cannot mask gets no display.
- A gateway that resolves placeholders itself answers a client reference it
  cannot resolve with an error instead of calling the API with the literal
  text.

## 2. Vault entry

| field | meaning |
|---|---|
| key | `TYPE_cN` |
| type, kind | placeholder type; detector pattern name |
| fingerprint | HMAC-SHA256(store key, value)[:16], for "same value, same reference", exact-match redaction and records |
| display | human hint, never for secrets |
| created, last_used, uses | audit |
| expires, max_expires | TTL, renewed on use up to the cap |
| purged | value deleted; metadata kept |

A value never leaves the backend except into (a) a tool's arguments at
execution time, (b) `maisecrets get` for a human.

## 3. Rehydration at the client

`PreToolUse` on `Bash`: the command is prefixed with one read per key into a
shell variable (`__ms_1="$(cat <fifo>)" || exit 97;` on POSIX, a resolver call
under a one-time grant on Windows Git Bash), and every `⟦TYPE_cN⟧` becomes that
variable in its quoting context. The value is never in the command text. A
context the rewrite cannot place (a nested shell, a quoted heredoc, `$'…'`,
backticks) and a command that would encode, slice or trace the value are
refused with the reason. Unknown, expired, foreign-session or capped
references deny the call with a reason that names the key and the status.
Partial resolution never happens.

`PreToolUse` on an MCP tool: every string argument is walked; references are
resolved inline under the same session rule and cap. A server-range token (§4) in an MCP argument stays as it is.

Session rule: a reference resolves only in the session that minted it or in
one where a human typed it into a prompt (`UserPromptSubmit` admits it).

`PostToolUse`: every string in `tool_response` is scanned by shape, and every
token (and the rest of a `KEY=value` line) is compared by keyed fingerprint
with the live entries; hits become references (existing reference when the
fingerprint is known). The response keeps its shape.

## 4. Vault references

Status: draft. Built in the client (`maisecrets/vault_refs.py`); the field and header names are
provisional until the IANA registries are checked.

A server can keep a value away from the model: it puts a token of the server
range (§1, `⟦TYPE_N⟧` or `⟦TYPE_N:display⟧`) into its tool result and keeps the
value. This section lets a vault on the person's computer get that value back
for a local Write, Edit or Bash call, so that the model still sees only the
token. A client without a vault sees what it saw before. The server gives a
value only to a key that the vault announced when the person logged in.

### 4.1 The key and the header

- The vault makes a random 32-byte key `K` per server origin and per client
  profile. It stores `K` like a vault entry, but no placeholder names it, so no
  tool call can resolve it. Two profiles, or two origins, never share a `K`;
  two servers on one origin share it.
- The vault announces `kid = SHA-256(K)` in a static header on the server's
  entry in the client configuration. The header is an RFC 9651 Dictionary:

  ```
  Client-Vault: v=1, kid=:<standard base64 of the 32 bytes, with padding>:
  ```

- The vault writes the header only on an entry of user scope, never on a
  project file that a repository carries and never on an entry that it cannot
  edit. The URL of the entry must be `https`.
- The vault writes the header only on demand: when a tool result of that
  entry's server carries a server-range token, and the server's metadata
  (§4.3) names `client_vault_endpoint`. Until then it makes no request and
  changes no file. It writes the header on that one entry, and it tells the
  person once, with the one step that makes the client send it. Claude Code
  reads the entry again, its headers included, on `/mcp reconnect <name>`
  (measured on 2.1.302); a new start does the same. A new Codex run sends it,
  an open session does not (measured on codex-cli 0.162.0). The binding begins
  after that step. At a start, the vault puts back a header of such an entry that the
  client lost, and removes its own header from an entry that no longer
  qualifies.
- The write changes one key of the configuration file. The vault takes the
  client's own lock (a `<file>.lock` folder; a lock older than 10 s is stale),
  reads the file again, writes a temporary file in the same folder and renames
  it over the original. It does not change a file that is not valid JSON, and
  it keeps a backup. The person can turn this off (`client_header: false`).
  The vault then removes its own header.
- Codex (measured on codex-cli 0.162.0): a project layer (`<dir>/.codex/config.toml`)
  merges deeply over the user's `config.toml` and can set another `url` on a
  user entry. A static `http_headers` header of that entry then goes to the
  project's URL, also for a project that Codex trusted on its own. So the vault
  writes no static header there. It writes `http_headers_helper` on the user
  entry: a command that Codex runs at connect time in the session folder. Its
  JSON output becomes headers on every request to the origin of the URL, the
  `authorization_code` token request included, never the browser leg. The
  helper prints the header only when its state file names this entry and URL,
  the user's file still has them, no profile can change them, and no project
  layer of the session folder has `mcp_servers`; else `{}`. Codex keeps the
  server URLs of the folder a session began in and runs the helper again after
  a change of the folder or a 401, so a later run of one Codex process gives
  the header only when the first run gave it, in the same folder; a run with no
  record counts as the first only while the process is younger than two minutes
  (deny by default). The hook notes a result only in the folder that SessionStart
  recorded for its session, and only when that start saw no project layer or
  profile file with servers (a layer deleted later does not move the server
  back). A project layer that sets `features.non_prefixed_mcp_tool_names` counts
  as one with servers. The helper reads `client_header` itself at each run (the
  policy file wins), so the opt-out works at the next connection. Its command ends in
  `|| echo '{}'`, because a helper that fails stops Codex from connecting. The
  PostToolUse payload of Codex names the tool only (`mcp__<server>__<tool>`,
  each character outside `[A-Za-z0-9_]` as `_`). The vault maps it to a user
  entry by that rule, and notes nothing when another server (a stdio or
  switched-off entry, a plugin server) could make the name, when the tool part
  holds `__`, when a project layer has servers, or when the session began in
  another folder. The vault never writes a `config.toml` that lies
  in a git work tree.
- `K` never travels on the MCP connection. It goes only to the resolve
  endpoint (§4.4).

### 4.2 The binding on the server

1. **At login.** The client sends its static headers on the OAuth token
   request too (measured with one client; a client that does not is bound by
   path 2). The server reads `Client-Vault` on the request with
   `grant_type=authorization_code` and binds the `kid` to the subject at once.
   That request needs the PKCE verifier of the login that the person did, so a
   stolen access or refresh token cannot use this path.
2. **On an MCP request.** A `kid` that is not yet bound and arrives on an MCP
   request becomes `pending`. The server tells the subject on a channel that
   the agent does not control. The binding becomes active after a cool-down
   (24 hours in the first server) or earlier when the person confirms. The
   notice lets the person revoke it.

Rules for every binding:

- One `kid` belongs to one subject, ever. If a bound or pending `kid` arrives
  with a second subject, the server binds nothing, revokes both records and
  tells both subjects.
- The server stores `kid` only, never `K`. It compares `SHA-256(K)` with the
  stored `kid` in constant time, and it never logs `K`.
- The server limits the number of active `kid`s per subject and the number
  of values per day, writes one audit line per value released, and makes a
  revoke take effect at once.

### 4.3 Finding the endpoint

The vault reads the protected resource metadata of the MCP URL (RFC 9728)
the first time a result of that server carries a server-range token, and
again before a resolve when its kept answer is older than an hour:
`GET <origin>/.well-known/oauth-protected-resource<path of the MCP URL>`, and
takes the field `client_vault_endpoint`: an absolute URL. If the field is
missing from a 200 answer, the server does not support vault references.
Any other status is a failure, not an answer, and the vault does not keep it.
If the URL is not `https` or its origin differs from the origin of the MCP
URL, the vault does not resolve. The vault may keep the answer per origin for
a time (an hour in maisecrets). The path keeps a trailing slash.

### 4.4 The resolve request

```
POST <client_vault_endpoint>
Authorization: Bearer <K, base64url without padding: 43 characters>
Content-Type: application/json

{"now": "2026-10-16T09:00:00Z",
 "refs": [{"key": "EMAIL_1", "seen_at": "2026-10-16T08:58:12Z"}]}
```

- `key` is the token's key without its display part.
- `now` is the client's clock; `seen_at` is when the vault FIRST saw the key
  in a result of that server. Both are ISO 8601 in UTC. A later sighting does
  not move it: when the server mints the key again for another person, a
  later time would pass the server's check with that person's value.
- `TYPE` is `[A-Z][A-Z0-9_]*`, at most 40 characters (`IPV6_1`).
- At most 100 refs and 64 KB per request.
- The endpoint accepts `K` only. It refuses the client's OAuth token.

The server corrects each `seen_at` by the difference between its own clock
and `now`. If that difference is above 5 minutes, it answers `clock_skew`. A
key whose value the server minted after the corrected `seen_at` is `expired`:
the same key can name another value after the server's mapping restarts.

### 4.5 The answer

All values, or one error for the whole request. Partial resolution never
happens.

| status | body | meaning |
|---|---|---|
| 200 | `{"values": {"EMAIL_1": "…"}}` | one string for each requested key |
| 401 | `{"error": "unknown_key"}` | no active `kid` for this `K`, or revoked |
| 403 | `{"error": "pending", "activates_at": "<ISO 8601>"}` | the binding waits for its cool-down |
| 403 | `{"error": "clock_skew"}` | the client's clock is off by more than 5 minutes |
| 404 | `{"error": "unknown_ref"}` | a key is not in the subject's mapping |
| 410 | `{"error": "expired"}` | a key is newer than its `seen_at` |
| 429 | `{"error": "rate_limited"}` and `Retry-After` | the cap is reached |
| 503 | `{"error": "disabled"}` | the server has the feature off |

Every other answer is a deny: any 3xx (the client follows no redirect), any
other status, a body that is not JSON, a `Content-Type` other than
`application/json`, a body above 1 MB, a value that is not a string, a key
missing from a 200 answer.

### 4.6 The client

- **Noting.** After a tool result of an MCP server of user scope, the vault
  notes each server-range token with the origin and the URL of that server,
  the time and the session, per client profile. A token that two servers sent
  is refused, also when the two share an origin. A token resolves only in a
  session that saw it from that server URL, and only for 24 hours after that
  URL first showed it; in any other case the call is denied with that reason.
  An `expired` answer deletes the note of its keys, so the next sighting
  starts the time again. A sighting after the 24 hours starts a new note too,
  for its session only. A key that one server showed with two different
  display parts, in one result or in two, is refused and its note goes: the
  server's mapping changed, and the token may name another person. A token
  that the model sent to that server, in this call or in any call of the
  last 24 hours (also before the server was in use), is no sighting and no
  trigger: a server that repeats or stores text would otherwise give it a new
  time. The result does not change. A
  token in any other result (a file read, a web page, a project-scope server)
  is not noted.
- **Resolving.** Before a Write, Edit, MultiEdit, NotebookEdit or Bash call,
  the vault looks for noted tokens. It sends one request per origin and puts
  the values in only when every request succeeds; otherwise it denies the call
  and names the reason. A token that was never noted stays text, so a client
  that never noted a token behaves as before. A token noted from two origins
  is refused, because the vault cannot tell which server to ask.
- **Where a value goes.** In Write and Edit content, inline; in Bash, through
  the same shell variable and FIFO as a stored value (§3), so the command
  text holds no value. An MCP argument keeps the token: it goes back to the
  server that minted it.
- **Transport.** TLS with the system's trust store (or a configured CA file),
  host name check, no redirects, no proxy. The whole fetch, metadata and
  resolve, ends within 5.5 s, inside the hook's 7 s watchdog.
- **Limits and audit.** A server value counts in the vault's own limits per
  session and per hour, as `KEY@host`, before the request. One local audit
  line per value: the key with the server's host, the tool and the call.
  Never the value. A value that a later check refuses gets no audit line.
- **Echo.** While the session works, the vault looks for each value a server
  gave in the later tool results of that session, as it does for a stored
  value, and puts the server's token back in its place. To do that it keeps
  the values in its store: a tool result of the session keeps them for about
  one more hour (the renewal runs at most once a minute), never longer than 24 hours after the server gave them, and the
  SessionEnd hook deletes them when the session ends. A session that crashes
  sends no SessionEnd; its values go at their expiry, at the latest at the
  next session start. A session that ends and is resumed (`claude --resume`)
  starts without them: an echo is then masked by its shape only, until the
  next value comes from the server. The SessionEnd entry is not
  authenticated, as no hook entry is: an agent that calls the launcher with
  its own session id ends its own window early, as it could run `wipe`. A value under 8 characters or one that reads
  as a word is not looked for: it would change every text that holds it.
- **Paths.** A server value goes into the content of a file tool, never into
  its path. In Bash, a value that names the vault's own folder, a store file,
  an ssh configuration, the client configuration or a file in the client's
  configuration folder is refused, also as a piece of the value
  (`--config=PATH`, `@PATH`, `file://PATH`).
- **State.** The vault keeps the last answer of the server per origin and
  key: `header` (the header is written, and the server knows no binding yet),
  `pending` (with `activates_at`), `active`, `lost` or `disabled`. A
  `401 unknown_key` is `lost` only when the same key got `pending` or `active`
  before; the server gives the same answer for a quarantine, a revoke and a key
  it never saw. The status and the session start ask with the status probe: a
  resolve with `"refs": []`, which carries no key of a token and can return no
  value. One probe per origin, only for an origin with a key (so never before a
  server token), at most once per session start, all origins inside one 5.5 s
  budget. The session start tells the person a state once, when it differs
  from the state the person last saw (a notice, a hint, the status). A deny
  of a resolve names the state and the next step of the person in the same
  words. At the next start after `lost` the vault makes a new `K` and writes
  its header; it never uses the old `K` again.
- **Off.** With the opt-out, no token is noted and no noted token resolves.

### 4.7 What this does not stop

An agent that runs as the same user as the vault can read the store and use
`K` (the store backstop is a backstop, not a boundary). The defence against it
is on the server: the cap, the audit line per value, the notice and the
revoke. A token that the model plants, or that a server echoes, still resolves
only to the subject's own current mapping on that server.

### 4.8 Conformance

A server conforms when a client gets these answers:

1. A login with the header binds the `kid`; a resolve with `K` returns the values.
2. An MCP request with a new `kid` gives `pending` with `activates_at`.
3. The client's OAuth token on the endpoint gives `unknown_key`.
4. One `kid` with two subjects gives no value to either.
5. A `seen_at` older than the value gives `expired`; a `now` one day off gives `clock_skew`.
6. A request with one unknown key among known ones gives `unknown_ref` and no value.

The client side is tested against a fake server with both endpoints
(`harness/vault_server.py`, `tests/test_vault_refs.py`).

## 5. Failure rules

- A hook that cannot decide fails closed and says why.
- A timeout is fail-open in Claude Code and in Codex: the prompt goes to the model, the tool runs, the
  output goes to the model as it is (Claude Code 2.1.302 and codex-cli 0.162.0, measured 2026-10-17). The
  detector must stay a regex in milliseconds.
- Codex reads a hook until its stdout closes; Claude Code reads it when the process ends. A child process
  that keeps the hook's stdout open makes the hook time out in Codex after it answered. The launcher
  (`hooks/run.sh`) gives its Python probes no descriptor of the hook and 2 s in total.
- Nothing a hook prints contains a value. Reasons name keys and counts.
