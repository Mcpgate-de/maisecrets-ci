# Testing

What runs, where, and what makes it fail. The history of each finding is in the commit messages.

## Suites

| suite | command | where it runs |
|---|---|---|
| unit tests | `python3 -m unittest discover -s tests` | GitLab `unit` (Linux, 3.12 and 3.9), GitHub on Windows and macOS (merge request: GitLab `windows_macos`; release: branch `ci`); locally `scripts/check_all.sh` |
| beliefs | `python3 scripts/replay_can_fail.py` (one worker per CPU, each in a copy of the tree; `--jobs 1` for serial) | GitLab `beliefs_can_fail_replay`; locally `scripts/check_all.sh` |
| stated numbers | `python3 scripts/derived_counts.py` | pre-push hook, GitLab `manifests` |
| repository scan | `python3 scripts/scan_tree.py` | GitLab `no_secrets_in_tree` |
| Claude Code harness | `python3 harness/run.py` | GitLab `harness_claude`; locally `scripts/check_all.sh` (needs `claude`) |
| Codex harness | `python3 harness/codex.py` | GitLab `harness_codex` |
| Codex harness on the `release-codex` tree | `python3 harness/codex.py --tree=codex` (the tree that `scripts/build_release_tree.py --flavor codex` builds from HEAD, installed as a Git source with `path: plugin`) | GitLab `harness_codex` |
| vault references, end to end | `python3 harness/vault_refs_e2e.py` | by hand before a release that touches `maisecrets/vault_refs.py` (needs `claude` and `openssl`): the real client, a client profile of its own and the fake server of `harness/vault_server.py`; the resolve and the `client_header: false` run |
| native store and clipboard | `MAISECRETS_NATIVE_BACKEND_TEST=1`, `MAISECRETS_NATIVE_CLIPBOARD_TEST=1` | GitHub runners only: they use the real keychain and clipboard |
| Codex with a real model | `python3 harness/codex.py --real` | by hand: `mcp_text_field_rehydrate`, `allow_keeps_the_codex_sandbox`, `apply_patch_rehydrate` and `apply_patch_store_refused` need a real model (an MCP call, a sandbox and a patch the fake upstream cannot script) |
| ssh through the sandbox | `MAISECRETS_E2E_HOST=<ssh alias> MAISECRETS_E2E_IP=<address> python3 harness/sandbox/ssh_e2e.py` | by hand before a release that touches the ssh route, on macOS and on Linux: the real Claude Code sandbox against a real host, under `rehydration: automatic` (cases 0a to 0f) and `confirm` |
| false alarms in a real tree | `python3 scripts/measure_false_alarms.py <dir> [--samples]` | by hand after a detector change: the hits a Read would act on, per rule, with the shape of each value and never the value; the regression corpus of normal work is `tests/fp_corpus.py` (`tests/test_fp_corpus.py`), a night of autonomous work is `tests/test_night_run.py` |
| false alarms in seven public trees | `python3 scripts/measure_fp_bank.py fetch <cache>`, then `measure <cache> --json <out>` before and after, then `compare <before> <after>` | by hand after a detector change: the Python standard library, detect-secrets, ferret-scan, Preserve, GitHub's starter workflows, Docker's compose samples and the tldr pages on fixed commits; `compare` names each rule whose acted count changed; it exits 2 when a tree is missing or at another commit and 1 when the total of acted hits rose. `fetch` makes each clone new; in a directory it did not make, it only reads refs and objects and compares each file with the commit. The fetch needs the network, so it is not a CI job |
| Benchmark V1 | `python3 bench/run.py --scanner S --source X --split dev --out <file>`, then `python3 bench/report.py <files>`; `python3 bench/bank/make_bank.py --check` | by hand before and after a detector change and for each release: maisecrets and four other scanners on the same cases, scored by span (full, partial, missed), per class and family, with the false alarms per 1,000 negative cases. `tests/test_bench.py` checks the case format and the metric in the suite. `docs/BENCHMARK-V1.md` has the method and the commands |
| Holdout V2 | `python3 bench/holdout_v2.py check\|generate\|seal\|verify …`, then `bench/run.py --source holdout-v2 --release-candidate` | by hand, on a release candidate only, after the seal (docs/BENCHMARK-V2.md, "Holdout V2"). No template exists yet |
| library outside the plugin | `python3 scripts/library_smoke.py [<checkout>]` | by hand before a change of the library API, with the newest Python and with `/usr/bin/python3` (3.9): copies only `maisecrets/__init__.py` and `maisecrets/detection/` into a new virtual environment with no site packages and a home folder that does not exist, builds a `Detector` with all four arguments, and scans a text. It fails when a module of the plugin is imported, the home folder is created, or the token, the e-mail address or the IBAN is not found |
| the library as a wheel | `python3 scripts/wheel_smoke.py [--python PY] [--wheel FILE]` | GitLab `unit` (3.12) and `unit_python39`: builds the wheel of `pyproject.toml`, installs it into a fresh venv and imports it from there with an empty home folder. It fails when the version is not the plugin's, a file of `maisecrets/detection/` is missing or a module of the plugin is in the wheel, a detector or the JSON entry point (`python -m maisecrets.detection`) misses the token or the SSN, a module of the plugin is imported, or the home folder gets a file |
| detector identity | `python3 scripts/detection_fingerprint.py --out FILE [--creddata DIR]` | by hand before and after a refactor of the rules: the full hit list on fixed inputs, compared with `cmp` (section "A refactor of the rules") |
| rule provenance | `python3 scripts/rule_provenance.py --out FILE [--coverage]` | by hand: one row per rule with its source, origin, upstream and licence, region, class, form, validator, context words and the limits of `docs/rule-limits.json`; `--coverage` adds hits, labelled hits and false positives per rule on the development splits. `tests/test_rule_provenance.py` checks that every rule has one row and every limit names a rule |
| release comparison | `python3 scripts/release_compare.py PREV NEW OUT [--reuse-prev DIR] [--reuse-new DIR]` | by hand for each release: both tags on the dev and val splits of the development sources and Privy totals, the change per source, split and class, the five largest gains and regressions, and the findings of `scripts/compare_bench.py`; time is reported, not judged |
| Windows end to end | `GITLAB_COM_TOKEN=… python3 scripts/windows_e2e.py [--rev REV]` | by hand before a release that touches the hooks, the launchers or the harness: GitLab-hosted Windows runners of a separate project, in three shapes (PowerShell 7, Windows PowerShell 5.1, Git Bash). Each job runs `harness/windows/shell_probe.py` (which shell runs a hook, and the `hooks.json` command in each shell) and `harness/run.py` with the shell tool the client offers (`MAISECRETS_HARNESS_SHELL_TOOL`) |

2974 tests (`tests/test_*.py`), about 35 seconds on an M-series laptop. Without PyYAML, two tests of
`tests/test_measure_catalog_coverage.py` fail and the belief `manifest-every-frontmatter-parses-as-yaml` is
skipped; CI installs it. A virtual environment with `pip install pyyaml` gives the full run locally. The GitHub matrix runs on
Windows and macOS in two places. In a merge request into `main`, and into `next` unless it changes documentation
alone (`.gitlab-ci.yml`, label `public-ci` for any other), the GitLab job `windows_macos` pushes the commit
that `main` would get to the CI repository `Mcpgate-de/maisecrets-ci` and fails with the names of the
failing tests. On `main`, it runs on the tested commit of a release (branch `ci`), unless a green run
on the same git tree exists (the release then reuses it). A merge without a release runs no matrix on
`main`: its merge request ran it.
`scripts/github_matrix.py` has the details.

## What makes a test count

- **A belief per control.** `beliefs/*.toml` names, per control of `docs/THREAT-MODEL.md`,
  the tests that own it and one mutation of the guarded code. The replay runs the tests green,
  applies the mutation, demands red, and restores the file. A skipped test is no evidence.
- **An invariant over every path.** A mechanism belief proves one guard; an invariant belief
  (`beliefs/inv-*.toml`, `kind = "invariant"`) proves one goal over every path to it. It names
  several tests and a mutation per path (`[[proof]]`, each with a `path`). The replay runs the
  tests green once, then each mutation, and demands that every mutation turns at least one test
  red and that every test is red under at least one mutation; a test that no mutation reaches is
  named as ballast. The four invariants:

  | invariant | module | the population it covers |
  |---|---|---|
  | I1 a stored value never reaches output the model or the person reads | `test_invariant_model_output.py` | every hook event, both clients, six tool-response shapes, the encodings of an own oracle for a resolved value and for another session's value as its own token, every refusal, the fail-closed answers, the prompt that goes on, the session-start message; every output field is classified |
  | I2 a rewrite never grants more than the call (Claude Code; Codex is the named exception) | `test_invariant_rewrite_grants_no_more.py` | 20 Bash command shapes (quotes, heredoc, assignments, loops, subshells, ssh with sudo), MCP inputs nested and as JSON text, Write and Edit; an own checker that knows the delivery forms as text; a call without a placeholder gets no grant |
  | I3 no agent tool reads vault material | `test_invariant_store_reads.py` | every tool that reads a path, from `tests/client_tools.json` (the harness checks that list against the real client's tool list on every run; checked against the matcher), twelve spellings of a store path, searches over a parent, MCP paths and file URIs, Bash with the default and the configured home; and the other side, a path next to the store passes |
  | I4 every detected value can be scrubbed from a transcript | `test_invariant_transcript_scrub.py` | every value the detector returns on the matrix, the token corpus and one PII value per type, in ten record shapes and two JSON writers, across the read window, and through the hooks |

  Each oracle is the test's own: it builds the encodings and escapes without the product's
  helpers, so a form the product forgets stays red.
- **No unexpected skip.** `scripts/no_unexpected_skips.py` fails the CI job on any skip except
  the two native tests.
- **The rehydration matrix.** `tests/test_rehydration_matrix.py` holds one hand-written table:
  path (Bash, ssh, MCP, an MCP published-text field, file tools) × client (Claude Code, Codex) ×
  policy (`automatic`, `confirm`, `block`) → defer, allow, ask or deny, and a second table for the
  Windows capabilities. Each cell drives the real `pre_tool` with a stored value and checks the
  decision, where the value went (a real bash for Bash on POSIX; on Windows the decision only), that
  no reason names it, and that a refusal left nothing behind that a test can see: no audit line, no
  approval token, no value waiting in the run directory (the sealed first-use directory cannot be
  listed; the approval store names its token). An ssh rewrite is not run here: its bytes are proven
  in the real sandbox by `harness/sandbox/ssh_e2e.py`. The precheck and the record are not one
  transaction: a hook of a parallel call can take the last slot of a cap in between, and then the
  refused call has written the audit line of its first key. No value leaves and no cap is passed. It also checks the default, a setting that is no policy, the
  shapes refused under every policy, a good key next to a refused one, and, by the syntax tree of
  `hooks.py`, every call site that returns a rewrite and every function that builds one. The code's own table (`rehydration.outcome`) is never read by the test. Five C16 beliefs
  mutate the policy and its call sites. The harness proves the same on the real clients: `mcp_rehydrate`,
  `mcp_rehydrate_confirm`, `bash_ssh_automatic`, `bash_ssh_asks` (Claude Code) and
  `bash_rehydrate_confirm`, `mcp_text_field_rehydrate`, `allow_keeps_the_codex_sandbox`,
  `apply_patch_rehydrate`, `apply_patch_store_refused` (Codex).
- **The guard.** `tests/test_guard.py` runs the guard and the maisecrets hook as two processes of
  one event: with maisecrets every event passes, without it every event is stopped. It also holds
  the name both sides compute, the account check, and the synced install that places the script.
  The harness proves it with the real client: `plugin_folder_moved_guarded` (the folder goes away
  mid-session and the command does not run) and `bash_rehydrate_guarded` (a healthy session passes).
- **Payloads from the real client.** A client-specific row of a matrix uses a payload captured from
  that client (`tests/client_payloads/`, recorded with `harness/codex.py` and the `dump` option,
  ids replaced). The Codex file row first used Claude Code's `Write`; Codex sends `apply_patch`, and
  every cell was green while real Codex edits resolved nothing.
- **Generated inputs with known answers.** `tests/detection_matrix.py` builds 2,500 cases from
  labels (the denylist and `maisecrets/detection/rules/labels/*.txt`), separators, value shapes and
  context; the gate compares the full result per case. The matrix takes the label files of the
  active languages (English and German under the pinned test locale). `tests/test_label_languages.py`
  runs each other label file the same way with its language on, and checks prose with each word.
- **Real bytes.** The gate tests run the rewritten command through a real bash and compare the
  bytes that arrive.

## Isolation

Every test module imports `tests/_isolate.py` first. It gives the process a temp vault home and
a temp dir, pins `MAISECRETS_LOCALE=de_DE`, and removes the variables of the client that
started the run (`CODEX_*`, `CLAUDE_CODE_*`, `CLAUDE_PLUGIN_OPTION_*`, `CLAUDECODE`). Tripwires
for `pbcopy`, `open`, `security` and `powershell` come first on `PATH`. Windows finds
`clip.exe` and `powershell.exe` in System32 before `PATH`, so a sitecustomize installs
`tests/_platform_fakes.py` in every Python child on every platform. `tests/_hygiene.py` checks
that no test left the process state changed or a value-serving child alive.

A runner of your own (a script that switches a detector setting and then discovers the tests, a
bench script) imports `tests/_isolate.py` before anything that imports `maisecrets`. The vault
binds its home at import, and `detect.rules()` imports the vault to read the config. A runner that
loaded the rules first kept the user's own store home, and the resets of the suite deleted the
index, the vault file and the key there (a fork's runner, 2026-10-12). Two guards stop that
(`tests/test_isolation_order.py`): `_isolate` refuses to start when the vault already names another
home, and while a test run owns a home, the vault refuses the user's own home.

## A refactor of the rules

A change that only moves the rules (a new data model, a loader rewritten, a filter renamed) must not change a hit.
`scripts/detection_fingerprint.py` shows that. It scans fixed inputs in both channels (`prompt`, `tool`) and in
five region sets (`none`, `de`, `us`, `all`, and `de+own`: `de` with rules of your own and an allow list). It
writes one sorted line per input with the full hit list: rule id, type, start, end, and the flags `is_fixture` (no
path and a test path) and `is_public_test_value`. The first line names the rule count and a digest of the rule ids
in their order, per region set. The file holds ids and offsets, never a value.

The inputs:

- CredData (`--creddata`): every unique labelled line.
- `tests/fp_corpus.py`, and `tests/fp_corpus_pii.py` when the tree has it.
- The token lists of `tests/test_rules_from_the_catalogs.py` and `tests/test_rules_from_other_detectors.py`.
- Probes: one or more texts for each matcher and each named filter of `maisecrets/detection/registry.py`, and a password
  export with its file name.
- The recorded scans of the detector tests: the script runs those test modules with `detect.scan` wrapped, and
  replays each call with its path and its `enabled` set (`--no-recorded` leaves them out, `--record FILE` and
  `--recorded FILE` keep one recording for several runs).

A mutation run on the registry (2026-10-15) switched off each named filter, each matcher and each band in turn. The
fingerprint without CredData changed for every one of them (34 mutants, two review rounds) except five: the window of
`generic-api-key` on a long text gives the same hits by design (it is a speed-up), the form fallback for a rule that
`rules()` did not mark has no caller, and the `enabled` keys of a rule, the export pass and the filter fallback are
held by unit tests in `tests/test_registry.py`. A recording keeps no text that holds the value of an environment
variable, and only its owner can read the file.

1. Before the change, write the reference: `python3 scripts/detection_fingerprint.py --creddata <CredData> --out ref.jsonl`.
2. After each step, write the file again to `new.jsonl` with the same arguments.
3. Run `cmp ref.jsonl new.jsonl`. If the files differ, the step changed the detector. `diff` names the corpus, the
   input, the channel and the region set of each changed hit list.

With CredData and 6 workers a run takes about 4 minutes on an M-series laptop, the recording included.
`tests/test_detection_fingerprint.py` checks that two runs give the same bytes and that a moved hit changes them.

## Coverage

```
COVERAGE_PROCESS_START=<rc> COVERAGE_RCFILE=<rc> python3 -m coverage run -m unittest discover -s tests
```

The rc needs `parallel = True` and absolute `source` paths: the skill scripts run with a temp
repository as their working directory. 2026-09-27: 95 % of the lines in `maisecrets/`,
`hooks/` and the skill scripts.
