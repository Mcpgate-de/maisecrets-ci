# Known gaps

For the reader who must know what maisecrets does not protect before relying on it. Each item is a limit that
was measured or documented. The controls and where each one ends are in [THREAT-MODEL.md](THREAT-MODEL.md).

## Known gaps (measured or documented)

What the plugin does not protect. Each item is a limit of the mechanism, not
a to-do.

- **Code that the agent runs as the person can call maisecrets (#98).** A shell
  command that imports a module of maisecrets is refused, in its own text and in a
  Python script it starts by path. A script that builds the module name at run
  time, loads another file, or lies inside a maisecrets checkout is not read. Such
  code runs with the person's rights and can reach the store and bind a connector
  directly; only a sandbox of the client stops it (C22). The pairing nonce that
  Python makes for each login is depth, not a boundary.
- **The status knows the mod only from its rows in `hooks.log`.** The mod
  writes one at the session start, for each prompt it checks, and once per new
  session id one second after its first prompt (after `/clear` or a resume).
  A status in that first second, or one after the mod's Python failed, can show
  `mod off` while the mod runs. The next prompt writes the row. An older login without the name
  scope (maisecrets 0.9.24 or older) needs one new consent before the gateway
  can check names.
- **The ids in the result of an Agent or Task call are not masked (#31).**
  Claude Code writes the agent id, the task id and the output file into that
  result, and it shows the AI the pointer it makes from the result that the
  hook returns. maisecrets keeps the ids and the name of the output file as
  they are, also when a rule, the name service or a stored value finds them: a
  placeholder there stopped the AI from continuing the agent and blocked its
  report. Only an id of the client's shape is kept, and of a SendMessage result
  only its resumedAgentId. The folder of the output file, the task text and the
  report are masked as usual. In the
  cloud runtime (Cowork, Claude Code on the web) this is not measured: there a
  blocked report shows no notice, so a report that maisecrets blocks for
  another reason is still lost without a word.
- **The output of a command that fails reaches the model as it is (Claude
  Code without the mod).** With the mod, the mod masks it before Claude Code keeps it. Claude Code reports a failed call through another hook event,
  whose answer cannot replace the output. A value that a failing command
  prints (`grep TOKEN .env` with exit 1, a script that prints its config and
  stops) is not redacted, and it stays in the transcript. Measured over one
  user's transcripts: 14 such outputs with a hit in 105,241 Bash calls over 90
  days, 1 of them a secret. A command that ends in a pipe (`… | tail`) is
  redacted as usual. maisecrets then stores the value (a repeat is redacted),
  cleans the transcript on disk, tells the AI not to use it, and shows you a
  line about it. See the threat model, "What is knowingly not defended".
- **No hook, no protection.** Claude Chat, ChatGPT Chat, the claude.ai chat on the web and the
  mobile apps run no plugin hooks. Cowork does, Claude Code does, Codex does.
- **In Cowork and in a cloud session, the prompt you type reaches Anthropic in clear text before maisecrets
  sees it.** The desktop app or the browser sends the text to Anthropic's session service, which passes it to
  Claude Code in the cloud VM. Anthropic stores the session transcript; whether it keeps your original text is not
  measured. maisecrets runs in that VM: it keeps the value from the model, not from
  Anthropic's servers. The same holds for a prompt that you type on another device in Remote Control. In Claude
  Code on your own computer the hook rewrites the prompt before it leaves the computer. See the threat model,
  "Network paths".
- **The note "Its hooks on session.compact, http.fetch{origin=engine} do not
  run here" on the plugin page (`/plugin`) concerns only the demo.** Claude
  Code shows it where an organization manages Claude Code (managed settings,
  or a Team or Enterprise organization). maisecrets uses these two hooks only
  in the demo mode, to keep `/compact` and the requests that Claude Code
  makes on its own (`/rename`, `/btw`, `/recap`, the next-prompt suggestion)
  away from the AI. Outside the demo, no protection changes. In the demo,
  these requests can still go to the AI, with placeholders only. You cannot
  change this yourself; an administrator can
  ([ADMIN.md](ADMIN.md#the-demo-where-an-organization-manages-claude-code)).
- **Text without a placeholder is text the AI knows.** maisecrets masks what
  reaches the AI through a prompt, a tool call or a tool result. It does not
  see these channels: the AI's own reply, the instruction and memory files
  that the client loads, an image you paste, and masks of other systems. A name in clear
  text in a reply can come from any of them, and from an earlier prompt that
  maisecrets did not mask: when maisecrets stores a value later, it replaces
  the value in the transcript files on disk with `*` of the same length, but
  the AI saw it in clear text before. If maisecrets missed a name, add it with
  `/maisecrets term add NAME`. Without
  NER (`/maisecrets ner local`) maisecrets finds a name only after a label
  (such as `Kontaktperson:` or a
  salutation) or on your term list, and a stored name of one word only in
  the same case.
- **The mod's second net for tool results has limits.** It masks no image or PDF
  in a result. When the mod's own Python fails too, the AI gets no output, but
  the tool's own record of it stays in the transcript on disk. The second net
  does not keep a value in a test file as a fixture, as the hook does. Each
  result that the hook did not check costs one Python start (about 0.05 to
  0.1 s, measured on one Mac). In Code Mode the mod does not see the answer
  of the REPL's own result hook, so each REPL result costs that start. An
  error that another mod answers itself, without the tool, passes as a
  refusal. While a result hook runs, a command that another tool call
  starts at the same time inherits the variable `MAISECRETS_MOD_NET=on`; it is a flag, the proof is a keyed
  hash, and its key stays in the maisecrets home. maisecrets refuses the
  commands that name the key and masks it in tool output, and the mod
  makes it new at each session start. An agent that hides the name of
  the command on purpose can still read it and then write a proof line.
- **The hooks watch tells, it does not block.** It needs the mod. When the
  hook cannot write `hooks.log` (a full disk, a home it cannot write), the
  line says that the hooks did not run although they did. Any program of yours
  can write a row into `hooks.log` and so silence the watch. It cannot switch
  off the second net: that reads the hook's own answer.
- **A client that rejects the manifest loads nothing and says nothing.**
  Claude Code 2.1.223 did so for a manifest key it did not know. Check with
  `/hooks` that maisecrets is listed; the harness checks the debug log.
- **A hook that exceeds the client's timeout fails open** (10 s for the
  prompt hook, 20 s for tool output, set in `hooks/hooks.json`). The plugin's
  own watchdog answers fail-closed before that (7 s, 16 s for tool output:
  block, deny, or withheld output), and a hook that crashes answers the same
  way; Claude Code ignores exit 2 from `PostToolUse`, so the raw output would
  otherwise reach the model. Codex 0.172 and older run the tool anyway when a
  hook fails, so there the watchdog is the only net. The prompt, tool-call and
  tool-result hooks set `onFailure: block`. From Claude Code 2.1.330 and Codex
  0.173 on, the client itself blocks the prompt and the tool call when such a
  hook cannot start, crashes or times out. Codex also withholds the tool
  result. Claude Code does not: a failed tool-result hook lets the output
  through. The mod masks that output before Claude Code keeps it; without
  the mod it reaches the model. The price: when maisecrets itself fails on every call, that session
  can send no prompt and run no tool until maisecrets runs again. The session
  start hook does not set it, so a failed start does not stop the session. On Windows the watchdog can come too
  late: Python has no SIGALRM there, and a detector regex that runs long
  holds the interpreter until it ends, so a hook past the client's timeout
  fails open. A tool result with more than 100 new
  values is masked without storing the rest.
- **Tool output above 50K characters** is spilled to a file by Claude Code
  and is not rewritten.
- **An image or a PDF that Claude reads** goes to the model as a picture or a
  document, not as text. maisecrets does not look for shapes in it: a secret
  in the text of a PDF or in a screenshot reaches the model. Only the exact
  match of your stored values checks its base64 form, and it finds a value
  only where the file holds its bytes uncompressed at an offset that is a
  multiple of 3 (no OCR, no decompression, by design). The same holds for a
  Bash output that Claude Code sends as an image.
- **`@file` mentions** inline a file outside the hook pipeline. The prompt
  hook blocks them when the path exists; ask Claude to read the file instead.
  An `@` before slashes alone, as in the sed expression `s/=.*@/x/`, names no
  file and is no mention.
- **A name without a label is not detected, unless it is on a term list** (Terms). Regex only, by design: "Emma Johansson" alone looks like any two
  capitalised words. A name after a name label, before an e-mail address or in a CSV name column is masked
  in a tool result (0.6.21); in a typed prompt the rules detect no name (a name service you set checks it in
  Claude Code with the mod). A name in a non-Latin script is masked only after
  a person label (`full name`, `native name`, `patient_name`, vCard `FN:`, also with parameters such as
  `FN;CHARSET=UTF-8:`; 0.6.24), not after `name:` or `owner:`,
  which also name products and languages. A street address without a postcode or an address label, or in a form of a
  region that is not active, passes too. Inside a vCard (after `BEGIN:VCARD`), an `ADR` in its fields, an `N`
  and a `BDAY` of eight digits are masked in a tool result, with or without parameters (0.6.25), also when the property
  is folded over two lines. A vCard line without its `BEGIN:VCARD` is masked after a `.vcf` file name (grep output) or
  in the structure of its property: `ADR` in capitals with a parameter of a card (`TYPE=home`, `PREF`) and an empty box
  and extended field, `N` in capitals with its five fields, `BDAY` with a parameter of a card. `adr:`, `n:`, a `BDAY:`
  date alone, a grep context line (`file.vcf-12-`) and a property in lower case folded more than 2,048 characters after
  its `BEGIN:VCARD` are not. The check for a
  company before an address label reads 120 characters of the line: in minified JSON a company address with its
  company word farther back is masked, and a person's address with an employer or a hotel within that reach passes.
  Its postcode stays masked when an employer label, a person's name or a key of a person's record stands near the
  company's name. The other way round, a company's postcode and VAT ID stay masked when a department line stands
  between the company's name and a street and postcode on one line (the address rule then masks the whole address),
  when the department is not a word of the list (Einkauf, Buchhaltung, Accounts Payable), and, in the street and
  postcode on two lines or after `Kunde:`, when the company's name has more than two words: a person's name glued to
  it (`Lena Brückner Lindner GmbH`) reads the same. On one line, after a company word, such a name frees the values
  as in 0.6.26.
  A wider reach was measured and left out, because it lets more home addresses pass (0.6.25).
- **The forms of 0.6.24 act on tool results only.** An ID after `member`, `record` or `account`, an address after
  `Address:`, a FHIR identifier, a `::add-mask::` value, a `SharedAccessKey=`, a Postman variable with a secret name and
  the other forms in `maisecrets rules list` (column "needs": label or form) are masked in a tool result or a file. A
  typed prompt with the same text is not blocked by them. A card number without a card word is masked in a tool
  result only when it is written in groups of four with the prefix of a card network; one run of digits needs the
  word (a float, a timestamp and an IMEI pass the Luhn check as often).
- **A pasted image is invisible to the hooks.** Claude Code gives the prompt
  hook only the text: `[Image #1]` in the terminal, an empty text for an image
  alone in `claude -p` (measured on 2.1.325; 2.1.296 gave the typed text). A
  block of the prompt stops the image too, so the demo mode stops it. An image or a PDF that the
  AI reads is in your hands ("PDFs and images"); maisecrets does not scan or
  clean an image, and does no OCR.
- **An image in an MCP tool result passes as it is.** `read_image` acts on
  the Read tool, on a Bash output that Claude Code marks as an image, and on
  the images of a notebook; not on an MCP result.
- **`block` stops the Read tool, not a shell read.** `pdftotext x.pdf -` or
  `strings` give the AI the text of the file; only secrets of a known form in
  it are masked. On Codex the PDF and image settings act on nothing measured.
- **A clean folder trusts the files that were there when the session
  began.** A file you put there yourself during the session waits for the
  next one. The start of a session is a note that maisecrets writes at the
  session start (the client sends no start time). The AI's tools may not
  touch the maisecrets folder, but that guard reads the command text: a
  command that hides the path (built from pieces, `find … -exec`) can still
  move the note and make a copied file count as clean. A client started
  under another program name (an npm install runs as `node`) is not seen as
  nested. Windows: no file counts as clean.
- **A term placeholder is never resolved** (Terms, mask only): a command or a
  file the AI writes keeps the placeholder.
- **A transformed value can pass.** For a value this session resolved, the
  output is checked as a substring in plain, base64, hex, URL-encoded and
  JSON-escaped form, and a resolving command may not encode it in the first
  place. Every other live value is matched by whole token, by the pieces of a
  URL or a `KEY=value` line, and by the rest of the line; a value split across
  lines, or encoded by a command that carried no placeholder, comes back
  unredacted. Values shorter than 8 characters are matched by shape only.
- **Every store hands a value to any process of the same user**, and so does
  a FIFO that waits for a granted command: another process of yours can read
  it during the up to 120 s the command takes to start. The gates stand in
  front of the agent, not in front of you; a Touch ID gate needs a signed
  helper and is not built. See "Vault" and `docs/THREAT-MODEL.md`.
- **Every e-mail address, phone number with a country code and public IP
  counts**, also your own and your colleagues'. `git log`, `dig` and `ip addr`
  come back with placeholders. Set `"regions": []` to drop the country
  identifiers, and list your own values in `~/.maisecrets/allow.txt` (see
  "Rules of your own").
- **Placeholders resolve in Bash, MCP tool arguments and the file tools.** In
  WebFetch or a subagent prompt they stay text. A subagent shares its parent's session; a
  headless run (`codex exec`, `claude -p`) is a session of its own, so a
  reference from an earlier run is foreign there.
- **A claude.ai connector gets no stored value, and its results pass Anthropic first.** The call of a
  claude.ai connector (in Claude Code `mcp__claude_ai_<connector>__<tool>`; in Cowork `mcp__<display name>__<tool>`,
  without `claude_ai_`) goes through Anthropic's connector proxy, where TLS ends. So maisecrets refuses a call of
  such a tool that would carry a stored value; add the server directly (`claude mcp add`), or, if the connector is
  your gateway, use its own references. The one exception is a deposit (`docs/PROTOCOL.md` section 6): for a
  connector that is bound to your gateway by a pairing proof, and a call that the gateway names as a deposit
  target, maisecrets sends the value to the gateway over its own connection, and the call carries a one-time
  handle. When the gateway also names `deposit_any_field`, a name, an e-mail address, a phone number, a postal
  address, a birth date, an IBAN, an IP address or a user name can go in this way into any text field of a tool that
  the gateway lists, and only in the actions that the gateway lists for that tool. Today these are the GitLab and
  Jira actions that create an issue, add a comment and update an issue; the gateway adds more actions one by one.
  maisecrets refuses every other action before the value leaves, with the line that this action of the connector
  does not take a stored value and that it was not sent. A secret, a card number, an ID number, a value of your own rule or of your term list, and every
  other type go only to a deposit target. The result of a connector passes the proxy before maisecrets masks it: there only the gateway's own
  scrubber protects it. In Cowork every MCP server outside your own config counts as a connector, and in a remote
  session a server of the source `dynamic` does. A server of a plugin or an agent named `claude.ai X` is refused
  too.
- **Your own rule makes a stored personal value strict only when it finds that value.** maisecrets keeps the first
  kind that stored a value. If a built-in rule stored an e-mail address and your own rule or an import matches the
  same value later, maisecrets marks the entry strict at that match; the address then goes only to a deposit
  target. Until your rule sees the value again (for example, a rule that you add after the value was stored), the
  entry can still go into any text field of a listed action.
- **A changed copy of the gateway's metadata on your computer.** maisecrets keeps the gateway's metadata for at
  most an hour in its home folder, with a MAC made with the binding key in the store. A copy that a process changed
  without that key, for example with `all_types` switched on, fails the MAC, and maisecrets reads the metadata again
  from the gateway. A process of your own user that reads the store key can still sign a changed copy (A3). Then an
  added type still fails the check against maisecrets' own list, but an added tool, action or `all_types` passes.
  The AI cannot write the maisecrets home folder (C14), and the gateway checks each call again and refuses an action
  that it does not list (`binding_mismatch`).
- **A declined call leaves the value at your gateway for up to 300 s (accepted risk).** A deposit sends the value to
  your gateway in PreToolUse, before the question comes: the question and the handles are one answer, and no hook
  runs between your answer and the call. When you decline (rehydration `confirm`, Claude Code's auto mode, or a
  permission rule of your own), the deposit stays unused at your own gateway, bound to that call and usable once,
  until it expires (at most 300 s). No third party gets it.
- **A prompt injection can put a stored value into a public issue (known risk).** With rehydration `automatic`, a
  listed action takes a deposit without a question from maisecrets, as every MCP call takes a value in 0.9.22. A
  text that the AI reads can make it write a stored value into an issue or a comment, and with `all_types` a
  secret too. This is a design decision: a value in a ticket must not work worse than in 0.9.22. Set rehydration
  to `confirm` if you want to answer each call; the value then waits unused at your gateway until you answer.
- **With `all_types`, a secret can come back through Anthropic's proxy (open point).** When your gateway sets
  `all_types` to true, every stored value, a secret, a card number and an ID number too, goes as a deposit into
  any text field of a listed action, such as the text of a ticket. A later read of that ticket through the
  connector returns the value through the proxy, and the gateway's result scrub finds only known secret formats.
  maisecrets has no answer for this read-back of its own. Since gateway v2.0.4132 (ai-gateway #2048), the gateway
  returns a SECRET that it took into a listed action as a Sensitive Reference when the same person reads it
  again, and maisecrets treats that reference as any other (C31). The gateway refuses a SECRET that is too weak to
  find again (`weak_secret`): such a value does not go into the action. Any other read-back depends on the
  gateway's result scrub.
- **Detection can take a secret for a personal value.** If maisecrets types a secret as a phone number or a
  name, the gateway's `deposit_any_field` lets that value go into any text field of a listed tool. A later read
  of that field through the connector passes Anthropic's proxy, and only the gateway's own result scrub masks it.
- **The gateway checks a listed action again at call time.** maisecrets refuses an action that `actions` does not
  list. The gateway also checks each call: an action takes a personal value only when it sends a JSON body (POST,
  PUT or PATCH) and every hook that it runs is on the gateway's audited list, and no handle may stand in a field that
  goes into a URL (such as a project or an issue key of a lookup). Examples that do not take one: an action that
  encodes its body (a Gmail send), a dispatcher. For such a call the gateway answers `binding_mismatch` before it
  uses the deposit, so the value is not sent upstream; the deposit expires unused. The AI gets one line that says so.
- **The deposit does not work in Cowork.** maisecrets finds the binding of a connector by the tool-name prefix
  `mcp__claude_ai_<connector>__`. Cowork drops `claude_ai_` from the tool names (measured 2026-11-22), and the
  sref login has no way into the VM yet. So in Cowork (and in the desktop app's local agent session) a connector
  call with a stored value stays refused.
- **A gateway's refusal of a deposit reaches the AI as raw text, next to its line.** When the gateway refuses a
  call that carried a deposit handle, its tool result is `deposit_refused: <code>` with `isError: true`. Claude
  Code 2.1.330 reports such a call as failed (PostToolUseFailure, seen in the live probe of 2026-11-22), and that
  answer cannot replace the output (anthropics/claude-code#97278). So the AI sees the code itself, which holds no
  value and no handle, and maisecrets adds its one line as context. A code that maisecrets does not know reaches
  the AI with no line. The `error` field that maisecrets reads is the text of the result's blocks, joined by a
  line break and trimmed, with no prefix. That form is read from the 2.1.330 bundle; it is not measured against a
  live payload of a refusal.
- **Codex has connectors too, and maisecrets does not detect them.** Codex's `codex_apps` server (ChatGPT app
  connectors behind OpenAI's apps gateway) relays a call like a claude.ai connector. Codex sends no server source,
  so maisecrets cannot tell such a call from a direct server, and it puts the stored value in.
- **A value resolved into a Bash command can reach a connector through that command.** The connector rule reads
  only the MCP call itself. A command that sends the value on is the destination the person allowed (C16).
- **A reference in a prompt is admitted as typed by a human**, also when the
  prompt was built from an issue body or a log in a headless run.
- **A slow rule of your own on Windows can outrun the hook's time limit**
  (see "A hook that exceeds the client's timeout fails open" above). The
  checks of "Rules of your own" keep a backtracking rule out, and a rule that
  is slow in one scan is left out from the next one on.
- **Claude Code on Windows without Git Bash** offers a `PowerShell` tool in
  place of Bash. maisecrets checks it like Bash for the store, in any case
  and with either slash, and refuses a placeholder in it with the reason:
  the rewrite knows POSIX quoting only. A placeholder in a file tool or an
  MCP argument works as on the other systems. The `/maisecrets:*` commands
  run through Bash and need Git Bash.
- **Codex on Windows** runs commands in PowerShell, where the bash quoting
  contexts of the grant rewrite do not apply. The prompt block, the output
  redaction and the inline MCP resolve run through `hooks/run.cmd`; a
  placeholder in a shell command is denied with a reason, and the reason
  names the route that works: apply_patch puts the value into a text file
  that the script reads, and the script then runs with no placeholder in the
  command. The launcher is
  proven in the GitHub Actions Windows job in the exact form Codex uses
  (`cmd.exe /C`, block and pass with a UTF-8 payload), not yet in a live
  Codex session.
