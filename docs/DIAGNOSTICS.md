# Local diagnostics and reporting (design v6, 0.6.10)

Status: built on branch `feat/local-diagnostics-build` (sections 3 to 11); the design to build from, after six
review rounds (round 6: codex and Opus, build with changes; the changes are in section 10). Issue: Mcpgate-de/maisecrets#14.

maisecrets has no telemetry, no server and no automatic error upload, and it keeps it that way. This design
adds a way to learn about real problems: maisecrets records its own internal failures **on this computer**, as
closed codes. When the person types the report command in Claude Code, the prompt hook shows the report and a
prefilled link **to the person only**; the prompt does not reach the model. The person clicks the link, checks
the text in GitHub's own issue form and decides there. maisecrets itself sends nothing.

Section 13 lists the changes after the reviews (codex gpt-5.6-sol, Opus, ChatGPT; rounds 1 to 5).

## 1. Rules (the invariants)

- **D1 maisecrets sends nothing.** No report or incident code opens a network connection, starts a browser or
  runs `gh`; the helpers for both are deleted. No telemetry, no id, no ping.
- **D2 An incident record and an incident report hold only closed values.** Every field is a value from a closed
  list or a bounded number. The record never holds an exception message, a path, a command, an MCP tool name, a
  prompt, a tool input or output, a session id, a user or host name, a key or a value. The report adds no
  platform release string and no error text (a config that does not load is the fixed word `unavailable`). What
  the report does show about use: the client family, the tool class, the number of days in the last 30 on which a
  failure was seen, and a coarse count. The detection, bug and feature reports carry text the person typed; D2
  does not cover them (section 7).
- **D3 maisecrets never files a report.** It shows the text and a link; the intended step is that the person
  clicks the link, checks the text in GitHub's form and presses Submit. Limits, stated in the threat model (C24):
  the click on the link already sends the prefilled text to GitHub in the URL; an agent with its own browser,
  shell or GitHub tools can file an issue, which maisecrets cannot tell from a person; a model with a shell can
  get the report through a pseudo-terminal (`script`, `pty`) and can clear the record, as it can already run
  `wipe --yes`. maisecrets does not hand the incident report or its link to the model on its own paths (section 7).
- **D4 Recording never changes an answer, and never keeps the hook alive.** Codes are queued while the hook works.
  Only the code path whose answer won writes its queue, after the answer. All file work after an answer runs in
  one daemon thread, and the process ends by `os._exit(0)` at the watchdog deadline at the latest, whoever won
  (measured, round 5: a hook that answers and does not exit before the client's timeout lets the prompt
  through). A failure of the recorder is never recorded. No diagnostics write happens before an answer.
- **D5 Bounded and removable.** At most 50 groups, one aside copy of a damaged record, at most one marker per code;
  `wipe` and the terminal `report incident clear` delete them.

## 2. What happens today (and changes)

- `/maisecrets:report last` (a false positive) **opens the browser at once** on a desktop, so the text reaches
  GitHub before the person read it; `--create` files it with `gh` under the person's login, and
  `commands/report.md:4` pre-approves `run.sh report *`, so a model can run it without a question. **Both go.**
  `report`, `report last [why]`, `report bug|feature <text>` keep their meaning and print the text and the link.
  A person who still types `--create` gets the line "--create is gone; open the link".
- `vault.py` and `hooks.py` raise `RuntimeError` (or a subclass) with no code; `destinations.pend` and `commit`
  swallow their errors; 15 `_debug` calls keep nothing unless a debug variable is set; 7 places answer
  fail-closed.
- A damaged store or config makes the prompt hook fail closed before it reads the prompt, and a report run as a
  Bash call is withheld again by PostToolUse (`hooks.py:3318`), so today no report about a damaged store reaches
  the person.

`events.log` and `hooks.log` stay as they are. Found on the way and fixed on its own branch
(`fix/a-heartbeat-that-cannot-stat-the-home-does-not-fail-open`): the guard heartbeat raised before the hook's
`try` on Python 3.9 with a home that cannot be searched, and the prompt went through.

## 3. Data model

`~/.maisecrets/incidents.json`, written only by a hook:

```json
{
  "version": 1,
  "groups": {
    "store.locker-add/rc": {
      "code": "store.locker-add", "cause": "rc", "number_kind": "exit", "number": 1,
      "class": "fail-closed", "event": "UserPromptSubmit", "tool_class": "-", "client": "codex",
      "days": ["2026-10-08", "2026-10-09"], "count": 3, "plugin_version": "0.6.10"
    }
  }
}
```

| Field | Closed form |
|---|---|
| `code` | one of `incidents.CODES` (section 4) |
| `cause` | `permission`, `timeout`, `lock`, `parse`, `io`, `missing`, `rc`, `shape`, `other`, mapped at the outcome site |
| `number_kind`, `number` | absent, or `errno` 0–4095, `winerror` 0–65535, `exit` −255–255 |
| `class` | `best-effort`, `fail-closed` |
| `event` | a hook event name, `launcher`, `guard` |
| `tool_class` | `Bash`, `PowerShell`, `MCP`, `File`, `Other`, `-` |
| `client` | `claude`, `codex`, `-` |
| `days` | real dates within the last 30 days, at most 7 (the report shows only their number) |
| `count` | 1–9999 (the report shows only the level `1`, `2`, `3+` or `10+`) |
| `plugin_version` | three numbers of at most 3 digits each, no leading zero, or `unknown` |

- **Key and selector:** `code/cause`. No hash.
- **One schema function** builds a group, loads the file and renders a report: a field outside its form drops the
  whole group. The rendered report is scanned by the detector; a group with a hit is left out and the report says
  "1 group withheld".
- **Reading the record:** `O_NOFOLLOW|O_NONBLOCK` where the platform has them, then `fstat`: a regular file of at
  most 64 KB, else it counts as damaged (section 8). A FIFO or a symlink cannot make a hook wait.
- **Markers** for places that cannot write the record: **flat empty directories in the home**,
  `~/.maisecrets/incident-marker.<code>`, each made with one single `mkdir`. There is no marker root to replace: a
  symlink or any other object at the final name makes `mkdir` fail, and nothing is followed. The home itself is
  the store's own folder, which every other part of maisecrets already trusts.
  - **Writers** (each after its own answer is out, each ignoring every error): `run.sh` (`launcher.no-python`,
    only when `[ -d "$HOME_DIR" ] && [ ! -L "$HOME_DIR" ]`, `umask 077`, in the background with no output),
    `run.cmd` (`launcher.no-python` in `%LOCALAPPDATA%\maisecrets-launcher`, where it writes `last-start.txt` on
    every start: a detached child on Windows inherits the hook's pipe handles, and the home is another, configured
    folder, code review round 3; not in the plugin folder, because Codex 0.164 binds the approval of the hooks to
    its contents, openai/codex#54619), `dispatch.py` (`launcher.import`), `guard.py`
    (`guard.fired`), the watchdog (`hook.<event>.watchdog`), the scrub child (`scrub.write`). An empty home
    variable resolves the same way in all of them: `vault.py`, `guard.py` and `run.sh` use the default home for an
    empty value (today `vault.py:28` differs).
  - **The fold** runs in the post-answer thread of a hook, under the record's lock. It lists the home, takes only
    names of the strict form `incident-marker.<code>` with `<code>` in `CODES`, and for each: `rename` to
    `incident-marker.<code>.claimed-<pid>-<ns>`, `rmdir` the claimed name, and only when `rmdir` succeeded count
    the occurrence (its `lstat` mtime is the day) and write the record. **At most once:** a crash between the
    steps loses the occurrence and never counts it twice. A marker made while one exists coalesces with it (the
    day of the second is lost), on purpose.
  - **Never `unlink`, never recursive.** A claimed name left by a crash is removed with `rmdir` when it is an
    empty real directory and is not counted; every other object (a symlink, a file, a full folder) is left alone.
  - **Windows** has no `dir_fd`: a race between the check and the `rename` stays, for an attacker who already
    runs as the same user. It is written down in C24.
- **The report lists unfolded markers** (read only, with the same name rule; the fold stays with the hooks), so the
  terminal form shows a launcher failure before any hook ran again.

## 4. Where failures are recorded

Codes sit at the **outcome site**: the place where a failure ends a hook path or is swallowed, where the context is
known. A raise that several callers share (`_check_types` for the user file and for the policy) gets its code
from the catch, not from the raise.

A test walks the AST of `maisecrets/` and checks two things against an explicit registry (function name and code,
not line numbers): every `raise` of `RuntimeError` and its subclasses (`LockTimeout`, `ConfigError`) is
catalogued with the outcome site it reaches; and every outcome site records exactly one code. A code with no
site fails. `scrub.write` is a string of code in the child and is checked by its own test, not by the walker.

| Code | Outcome site (`vault.py` unless named) | Class |
|---|---|---|
| `store.file-read` | 551 (jsonfile), 749 (openssl file), as they reach the hook's `_failure` | fail-closed |
| `store.keychain-add`, `store.keychain-readback` | 649, 651 | fail-closed |
| `store.openssl` | 733 | fail-closed |
| `store.locker-add` | 823 | fail-closed |
| `store.index-read`, `store.index-shape` | 949, 952 | fail-closed |
| `store.lock` | 220 (`LockTimeout` after `LOCK_DEADLINE`) | fail-closed |
| `store.timeout-keychain`, `store.timeout-openssl`, `store.timeout-locker` | 598; `_run_store` gets a closed backend id instead of display text. A store timeout longer than the watchdog shows up as `hook.<event>.watchdog` | fail-closed |
| `store.decrypt` | the swallowed decrypt failure at 789 (the value is then "not available") | best-effort |
| `store.mark-weak` | 997 | best-effort |
| `store.expire` | the `except` at 1327 (also a keychain delete that fails there, 679) | best-effort |
| `config.policy-invalid` | a policy that does not read, parse or type-check (402, 404, 407, and `_check_types` 257/261/264 through the policy call at 408), and the jsonfile rule at 434, at the hook's `config-error` answer | fail-closed |
| `config.user-ignored` | the `except ConfigError` at 342 (it catches 323 and `_check_types` for the user file) | best-effort |
| `hook.run-dir`, `hook.sealed-dir` | `hooks.py` 1874 (`_run_dir`), 1892 (`_sealed_dir`), as they reach `_failure` | fail-closed |
| `hook.payload` | the non-object payload answer (`hooks.py:3846`); it answers before the timer, so it writes a marker in a 0.3 s thread | fail-closed |
| `hook.<event>.unexpected` | the call of `_failure` (`hooks.py:3893`), and the inner catch of `_post_tool_guarded` (`hooks.py:3560`) | fail-closed |
| `hook.<event>.watchdog` | the watchdog's answer won (a marker) | fail-closed |
| `hook.session-start` | the SessionStart path in `dispatch.py:96` (no watchdog there: its recording has its own 0.3 s limit) | best-effort |
| `destinations.pend`, `destinations.commit` | `pend` and `commit` (`destinations.py` 233, 253) return a closed result instead of swallowing it | best-effort |
| `destinations.protect` | `_protect_fresh` (`hooks.py`): the record could not be read for a protect check, so every network host of the call asks | fail closed |
| `scrub.start` | the catch after `Popen` in `_scrub_transcript_later` (`hooks.py:224`) and the catch in `_scrub_failed_prompt_now` (`hooks.py:3787`), queued in process | best-effort |
| `scrub.write` | the scrub child (a marker) | best-effort |
| `prompt.pending` | the catch at `hooks.py:402` | best-effort |
| `prompt.tip` | the catch in `_check_tip` (`hooks.py`): the ms:(…) tip could not be read or recorded; the prompt goes on without it | best-effort |
| `prompt.check-store` | the catch in `_store_unseen` (`hooks.py`): a value that an ms:(…) check did not catch could not be stored; the answer says so and the prompt stays blocked | best-effort |
| `prompt.clipboard` | `_clipboard` (`hooks.py:85`) returns a reason: a missing tool and an SSH session record nothing; a timeout, a non-zero exit and any other failure record this code | best-effort |
| `launcher.no-python`, `launcher.import` | `run.sh`/`run.cmd` found no Python; `dispatch.py` could not import the plugin (markers) | fail-closed |
| `guard.fired` | the guard refused (a marker; `guard.py` has its own `_home()`) | fail-closed |

**Not recorded, on purpose:** the sites that only the CLI reaches (`wipe` 701 and 767, `repair` 1384 and 1417,
`forget` 1294): the CLI prints its own error, and a CLI run never writes the record. The Python side of the mod
(`rewrite_prompt`): its failure ends in the hook, which records it there. **Not observable** (in the docs): a
manifest the client rejects, a client timeout that fails open, the "plugin folder is gone" answers in
`hooks/hooks.json` (a change there changes the hook hash that Codex trusts), a failure in the mod's JavaScript, a
failure of the recorder itself, and the stdin read in `main()` (`hooks.py:3843`), which runs before the timer.

## 5. Who sees what

- **best-effort:** recorded only. The person finds it with the report command; there is no hint in 0.6.10
  (section 12).
- **fail-closed:** the refusal gets one fixed line, whether or not the record could be written. Claude Code:
  `maisecrets sent no report. Type /maisecrets:report incident to see one you can read and send yourself.`
  Codex: `maisecrets sent no report. Run <the hook's own absolute folder>/run.sh report incident in a terminal to
  see one you can read and send yourself.` (a local path, never part of a report; Codex shows it where it shows the
  refusal). The refusals for `launcher.*` and `guard.fired` keep their own text: no Python or no plugin folder can
  show a report.

## 6. (removed: the hint)

The hint to the model moved to a later version (section 12). It was the only diagnostics write before an answer,
and it needed the typed-session mark in every mode.

## 7. Reading and sending

| Step | Claude Code | Codex | Own terminal |
|---|---|---|---|
| read the incident report | type `/maisecrets:report incident [code/cause]` | the terminal form (a typed form only after the display is measured) | `run.sh report incident [code/cause]` |
| send | click the link, check the text in GitHub's form, Submit | the same | the same |
| clear the record | the terminal form | the terminal form | `run.sh report incident clear` |
| detections, bugs, features | `/maisecrets:report [last [why] \| bug \| feature …]` as today, without browser and `gh` | as today | as today |

- **One form function decides the report form from the words**, and both the CLI and the recognizer call it: the
  words come from `shlex` (with the fallback to a plain split, as `_stdin_words` does today), `--create` is
  dropped, and the comparison ignores case. So the CLI and the recognizer can never disagree on what is an
  incident report.
- **The recognizer** is a pure function, the **first statement** of `user_prompt` and of `rewrite_prompt` (before
  the test fault, the imports, `load_config()` and the store). It applies only to a Claude Code payload whose
  prompt matches `^/maisecrets:report(\s|$)` (ASCII, as the client writes the command name; a leading space or
  another spelling is not expanded by the client and reaches the model as plain text, measured in round 5). When
  the form function says `incident`, the recognizer owns the prompt: a closed form (`incident`,
  `incident <code/cause>`) gets the report, any other text gets a fixed usage line. In the mod path it returns `{}`
  (no rewrite), so the prompt reaches the hook unchanged. The tests take the six forms that Claude Code expands and
  that a plain prefix missed (a tab, two spaces, a newline, `"incident"` in quotes, `Incident`,
  `--create incident`). What runs before the recognizer, in `main()`: the stdin read, the payload check and the
  start heartbeat (after the timer, section 10).
- The answer is a block whose reason is the report and the link, with `suppressOriginalPrompt`. Its first line says
  it is no error: `maisecrets: your incident report (shown to you only; this is not an error).` The model sees
  neither the prompt nor the report, and no Bash call, PreToolUse or PostToolUse runs, so a damaged store or config
  cannot withhold it. Measured in round 4 (`claude -p` 2.1.295): the 20 lines and the whole URL are shown.
- `commands/report.md` gets `disable-model-invocation: true`. Measured in round 5: the model's `Skill` call on it
  fails, and the person's own `/maisecrets:report bug …` still expands and runs.
- **The CLI form** (`run.sh report incident`) prints the report only when stdout is a terminal, else one line that
  names the typed form and the terminal form. This check stops an accidental echo into the model's context and
  nothing more: a model with a shell can get a pseudo-terminal (D3, C24). The check applies to `incident` and
  `incident clear` only, never to the detection, bug and feature reports.
- **Codex:** `codex exec` 0.159.2 shows only `hook: UserPromptSubmit Blocked`, without the reason (round 4). Before
  Codex gets a typed form, the TUI and the ChatGPT app are measured with the report in `systemMessage` and a short
  fixed `reason`; the measurement also checks that `systemMessage` does not reach the model. Until then the
  terminal form is the Codex path, and the recognizer returns no match for a Codex payload.
- **`clear`** is a terminal form, for the person's convenience; it is no protected step (D3).
- **One group per link.** Without a selector the report lists the groups (code/cause, class, days, seen) and gives
  the link for the newest one; each other group names its own command. The URL is tested to stay under 4,000
  characters (measured in round 3: 1 group 410, 50 groups 15,845).
- **The link** comes from `events.link` with the configured `report_url`, called inside `try` after the text is
  rendered. When the config does not load, the report comes without a link and says
  `link: unavailable (configuration)`; no error text. A GitHub tracker gets the record in the query and a fixed
  title prefix `[incident]` (GitHub applies URL labels only for users with triage access); a policy's non-GitHub
  tracker URL is printed as configured, with no body, and is the administrator's text, outside D2.
- The rendered platform is `Darwin`, `Windows`, `Linux` or `other`, and Python is `major.minor`; the incident report
  does not reuse `generic_issue_parts` (`events.py:158` adds `platform.release()`).

## 8. Damaged record, wipe, clear

- A record that does not parse, is not a regular file or is over 64 KB is replaced by an empty one; the old file is
  kept as the one aside copy `incidents.json.corrupt` (an older aside is overwritten: the record holds nothing of
  the person). A symlink is removed, not followed and not kept.
- Only a hook writes the record and folds markers. A CLI read never writes; `clear` removes the files.
- `wipe` (`wipe_everything`, `vault.py:1424`) and `clear` remove `incidents.json`, its aside, its lock file, any
  `incidents.json.*.tmp` (`os._exit` can leave one) and the marker directories, with the same name rule and `rmdir`
  as the fold, never recursive; `/maisecrets:status` shows the number of groups.

## 9. What changes with the removal of the browser and `gh`

- Code: `events.open_in_browser`, `has_local_browser`, `create_with_gh` deleted; `cli.cmd_report` and
  `_report_out` print text and link only; `cli.py` docstring and help (174-177, 192-193) and the top-level help
  (788, which also adds `incident`); the texts "records it" in `hooks.py` (1995, 2714).
- Command: `commands/report.md` description, `argument-hint` (adds `incident [code/cause]`, keeps the YAML
  quoting), the paragraph about `--create`, and `disable-model-invocation: true`; `allowed-tools` keeps
  `run.sh report *` for the other forms.
- Tests: `test_cli_matrix.py` 783, 1416-1450, 1454-1478, 1480-1499; `test_hidden_characters.py` 77, 430;
  `test_frontmatter.py` 4 (docstring), 38, 44, 66-67; a test of `cli.main(["--help"])`; the comment in
  `harness/run.py` 362-375 (`report_args_stay_text`).
- Beliefs and scripts: `c6-a-report-files-only-to-report-url` becomes "no report form runs a subprocess or opens a
  browser", with a new mutation (a `subprocess.run` call added to `_report_out`), because its old `find` targets
  the deleted `gh` code; the `find` string of `manifest-every-frontmatter-parses-as-yaml` follows the new
  `argument-hint`; `scripts/lint_plugin.py:5`.
- Docs: README (364-367, 415-419, 722-725), PRIVACY.md (45-50), THREAT-MODEL row C24. The changelog history and the
  SSH parser tests that contain `gh issue create` stay.

## 10. Watchdog and recording

In pseudocode, for `main()` (`hooks.py:3837`), after review round 6 (both: build with changes):

```
timer = start(on_timeout, WATCHDOG_SECONDS[event])   # first, before any file work
heartbeat(start)                                     # guarded by the timer
try:    won = answer(handler(payload), "ok")
except: won = answer(fail_closed(...), ...)          # as today, incl. the config-error answer and the scrub
finally:
    if won:
        run_log; write queue, fold markers           # inline, still under the timer: if it hangs, the timer's
                                                     # losing watchdog ends the process at the deadline
        timer.cancel(); timer.join(1)                # as today (hooks.py:3896-3901)
    else:
        discard the queue
        timer.join()                                 # the watchdog's thread ends the process

answer(obj, how):                                    # as today, plus a bounded lock and a return value
    serialize obj                                    # an object that cannot be written claims nothing
    if not lock.acquire(timeout=1): return False     # a handler stuck in its own write cannot hold the watchdog
    if answered: release; return False
    answered = True; write and flush JSON
    if how != "watchdog": heartbeat(done)            # the guard needs it; the watchdog writes it in its thread
    release; return True

on_timeout():
    won = answer(fail_closed("took longer than …"), "watchdog")
    if won: one daemon thread: heartbeat(done), scrub_failed_prompt, the marker; join it for at most 1.5 s
    os._exit(0)                                      # always: a hook that answered must still end in time
```

- The answers stay the same as today, apart from the fixed line of section 5. "The same answers" in the tests
  means: identical with the recorder on, off, raising, slow and holding its lock.
- The done heartbeat is written on both paths, as today: the guard waits for it, and without it the guard adds its
  own refusal after 13 s (Opus round 6). The handler writes it inside `answer()`; the winning watchdog writes it
  in its bounded thread, so a stalled home cannot hold the process past the client's timeout (code review round 1,
  measured with FIFOs: alive at 25 s before, ended at 8.6 s after).
- The work after a won answer runs inline, not in a thread of its own: the timer still runs, and a losing watchdog
  ends the process at the deadline (code review round 1: the design named a thread; the inline form is as safe and
  simpler).
- The process ends at the latest about 1.5 s after the watchdog deadline (7 s, 16 s after a tool), below the
  client's timeout (10 s, 20 s). When the watchdog cannot take the answer lock within 1 s, the handler is in the
  middle of its own answer, and the watchdog still exits.
- A regex search holds the GIL, so the timer thread cannot run while one backtracks. Where the platform has
  SIGALRM, `main()` also arms a timer in the main thread 0.25 s before the thread watchdog (`_arm_alarm`); its
  handler runs `on_timeout()` inside the search. Both share `on_timeout()` and `answer()`, so one answer leaves
  the process; the handler does nothing while an answer is in writing. A non-blocking lock lets only the first of
  the two run `on_timeout()`, so the second cannot end the process before the first finishes its work. That work
  also leaves out the rule of your own that held the hook (`_quarantine_running_rule`, C25). Measured on 0.6.14 with a real PostToolUse
  process and a 256K line of AWS key ids: no answer within 25 s (3.14) and 23.3 s (3.9), past the client's 20 s;
  with the alarm, the fail-closed answer after 15.9 s on both. Windows has no SIGALRM: there the thread watchdog
  stays alone (`tests/test_hook_time.py`).

## 11. Tests that must exist

- schema: every field rejects hostile forms (newline, Unicode, a number out of range, a boolean as a number, a
  non-finite number, a deep object, an unknown code, an impossible date, a date out of the window, a poisoned
  version); a group with one bad field is dropped; a detector hit drops the group; a FIFO, a symlink and a 65 KB
  file at `incidents.json` do not make a hook wait;
- the AST walker against the site registry, both ways; the `_check_types` raises map to `config.user-ignored`
  through the user file and to `config.policy-invalid` through the policy;
- the rendered report of every code holds no detector hit, also when the exception message held a synthetic
  secret and a path; a config error that names a path does not appear;
- the form function: the six measured forms, a leading space, an upper-case command name, `incidentally`,
  `incident please`, multi-line text; the CLI and the recognizer give the same result for each;
- the prompt-hook report: a damaged index, a broken config and a broken policy each still give the report as a
  block reason with `suppressOriginalPrompt`; the store is patched to raise and is not called; `load_config` is
  called only inside `try`, after the text is rendered; a Codex payload gets no match; free text after `report`
  (`last <why>`, `bug`) does not take the path;
- the mod path: `rewrite_prompt` returns `{}` for every incident form with `load_config`, `_has_live` and `Vault`
  patched to raise, none of them called;
- the CLI form prints the incident report to a terminal only; through a pipe it prints the one line; the detection,
  bug and feature reports print through a pipe as today;
- recording and the watchdog: the same answers with the recorder on, off, raising, slow and holding its lock; a
  handler paused after it queued a code, a watchdog that wins, then the handler resumes: only the watchdog marker
  survives; post-answer work that hangs (heartbeat, `_run_log`, the queue, the fold) still ends the process at the
  watchdog deadline, without a scrub and without a marker from the losing watchdog; a winning watchdog with a
  blocked disk still exits within its deadline;
- markers: a symlink, a file and a full folder at a marker name and at a claimed name are not followed, not
  counted and left alone; a marker made during a fold survives as the next occurrence; a crash after the claim
  counts the occurrence at most once; `pending/` and every name outside the strict form are never touched; the
  `run.sh` writer makes no marker when the home is missing or a symlink;
- no report form calls a browser or `gh` (both patched to raise), also `report last`, `bug` and `--create`;
- the URL of the largest valid group stays under the limit;
- `wipe` and `clear` remove every file and marker; a CLI read writes nothing.

## 12. In 0.6.10, and later

In 0.6.10: sections 3 to 11, a threat-model row C24 with beliefs for D1 to D5, README and PRIVACY.md.

Later, on purpose: the hint to the model after a repeated best-effort failure (needs a write before the answer and
the typed-session mark in every mode); the typed incident form for Codex (after the display measurement); the
recognizer on `UserPromptExpansion`, which gives `command_name` and the parsed arguments (after a measurement that
its block reason reaches the person only); failures in the mod's JavaScript; the client's own version; any
telemetry (not planned).

## 13. Changes against v5 (review round 5: codex rework, Opus build with changes)

- **Watchdog (Opus BLOCKER, measured):** the process always ends at the watchdog deadline; a losing watchdog skips
  the scrub and the marker but still exits; all post-answer work runs in one thread; the winning watchdog runs no
  heartbeat and no log (codex HIGH-2). Pseudocode in section 10.
- **Recognizer (Opus HIGH-1, measured; codex HIGH-3):** one form function shared with the CLI (`shlex`, no case,
  `--create` dropped); `^/maisecrets:report(\s|$)` for Claude Code payloads only; the first statement of both
  functions; what precedes it in `main()` is stated.
- **Markers (codex BLOCKER, Opus MEDIUM-1/2):** flat `incident-marker.<code>` directories in the home, one `mkdir`
  each, no root to swap; count only after a successful `rmdir`; every other object is left alone; the Windows race
  is stated.
- **isatty (both):** an accidental-echo guard only; a model can get a pty, read the report and clear the record, as
  it can run `wipe --yes`; stated in D3 and C24.
- **Sites (codex MEDIUM-1/2, Opus LOW-1/2/3):** codes at outcome sites; `_check_types` by its caller;
  `store.keychain-delete` folded into `store.expire`; `hook.payload` at 3846 with its own marker; `_failure` at
  3893; both scrub starters; the pending catch at 402; a clipboard reason; `wipe_everything` at 1424.
- **Smaller:** the Codex line names the absolute hook folder; section 9 adds `test_frontmatter.py:4` and
  `harness/run.py:362-375`; the stdin read before the timer is stated as not observable.
