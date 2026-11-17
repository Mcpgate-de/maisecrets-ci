# Known gaps

For the reader who must know what maisecrets does not protect before relying on it. Each item is a limit that
was measured or documented. The controls and where each one ends are in [THREAT-MODEL.md](THREAT-MODEL.md).

## Known gaps (measured or documented)

What the plugin does not protect. Each item is a limit of the mechanism, not
a to-do.

- **The output of a command that fails reaches the model as it is (Claude
  Code).** Claude Code reports a failed call through another hook event,
  whose answer cannot replace the output. A value that a failing command
  prints (`grep TOKEN .env` with exit 1, a script that prints its config and
  stops) is not redacted, and it stays in the transcript. Measured over one
  user's transcripts: 14 such outputs with a hit in 105,241 Bash calls over 90
  days, 1 of them a secret. A command that ends in a pipe (`… | tail`) is
  redacted as usual. maisecrets then stores the value (a repeat is redacted),
  cleans the transcript on disk, tells the AI not to use it, and shows you a
  line about it. See the threat model, "What is knowingly not defended".
- **No hook, no protection.** Claude Chat, ChatGPT Chat, the web and the
  mobile apps run no plugin hooks. Cowork does, Claude Code does, Codex does.
- **Text without a placeholder is text the AI knows.** maisecrets masks what
  reaches the AI through a prompt, a tool call or a tool result. It does not
  see these channels: the AI's own reply, the instruction and memory files
  that the client loads, an image you paste, and masks of other systems. A name in clear
  text in a reply can come from any of them, and from an earlier prompt that
  maisecrets did not mask: when maisecrets stores a value later, it replaces
  the value in the transcript files on disk with `*` of the same length, but
  the AI saw it in clear text before. If maisecrets missed a name, add it with
  `/maisecrets:term add NAME`. Without
  NER (`/maisecrets:ner local`) maisecrets finds a name only after a label
  (such as `Kontaktperson:` or a
  salutation) or on your term list, and a stored name of one word only in
  the same case.
- **A client that rejects the manifest loads nothing and says nothing.**
  Claude Code 2.1.223 did so for a manifest key it did not know. Check with
  `/hooks` that maisecrets is listed; the harness checks the debug log.
- **A hook that exceeds the client's timeout fails open** (10 s for the
  prompt hook, 20 s for tool output, set in `hooks/hooks.json`). The plugin's
  own watchdog answers fail-closed before that (7 s, 16 s for tool output:
  block, deny, or withheld output), and a hook that crashes answers the same
  way; Claude Code ignores exit 2 from `PostToolUse`, so the raw output would
  otherwise reach the model. Codex runs the tool anyway when a hook fails, so
  there the watchdog is the only net. On Windows the watchdog can come too
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
