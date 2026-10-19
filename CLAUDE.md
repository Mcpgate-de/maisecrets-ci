# maisecrets: notes for an agent working in this repository

maisecrets is a Claude Code and Codex plugin. Its hooks keep secrets and personal data out of the
model: they block a prompt that carries one, replace values with placeholders such as
`⟦SECRET_c1⟧`, put the real value into a tool call only where the user allows it, and redact tool
output. `README.md` says what it does for users; `docs/` holds the design.

## Read first

- `docs/THREAT-MODEL.md`: the controls C1 to C23, what each one blocks and where it ends.
- `docs/REPO-STANDARDS.md`: layout, git hooks, CI, versions and releases, remotes, directory rules.
- `docs/TESTING.md`: the test layers and how to run them.
- `docs/PROTOCOL.md` and `docs/CLIENTS.md`: the hook payloads of each client.
- `docs/DETECTION.md`: the detection core (`maisecrets/detection/`), its library API and its old names.

## Rules

- **Never touch the real store.** Tests and probes use a temp home: `MAISECRETS_HOME` set to a new
  directory with `config.json` `{"backend": "jsonfile", "allow_plaintext_store": true}`
  (`tests/_isolate.py` does this). Never read `~/.maisecrets`, a keychain or a Credential Locker.
- **Never read session transcripts** to find test data. Use synthetic values.
- **No personal names, private hosts or real email addresses** in the repository. It is public.
- **Versions:** a release moves only the last number (`scripts/release.py`). A minor or major bump
  needs the maintainer's approval (`MAISECRETS_RELEASE_BUMP`).
- **Commit subjects** follow `type(scope): text`; `feat fix perf security deps` become the
  changelog line, so write them for the user.
- **Commit often, push rarely.** Each push runs the GitLab pipeline and two GitHub runners. Collect
  commits and push them together.
- **C21 is frozen since 0.6.12.** A new syntax rule in `maisecrets/ssh_consent.py` needs a field example
  (a command an ordinary agent really ran) or a demonstrated ordinary-agent pattern, not a form that a
  reviewer constructed. #15 took nine review rounds because each round found new long-tail forms; C21
  guards the ssh starts the command line shows to an agent that does not try to evade it
  (`docs/THREAT-MODEL.md`).
- **Commit subjects are release notes.** Write them for a user ("detects secrets in 245 more formats"),
  not for a developer ("a test value hides only its own type").

## Where the code lives

- GitLab (`gitlab.com/Sprinterli/maisecrets`) is the primary repository and runs the CI. A merge
  to `main` there releases: the release job tags it, and the mirror job pushes `main`, the tag and a
  `release` branch (runtime files only, `scripts/build_release_tree.py`) to GitHub.
- GitHub (`Mcpgate-de/maisecrets`) is the public mirror, the install marketplace and the issue
  tracker. Never merge on GitHub: the next mirror push would fail as not a fast-forward. Take a
  GitHub pull request into GitLab (`git fetch <github> pull/<n>/head:pr-<n>`, merge request there);
  a commit with `Fixes Mcpgate-de/maisecrets#<n>` closes the issue when the mirror pushes it.

## Checks before a push

```bash
python3 -m unittest discover -s tests          # also with /usr/bin/python3 (3.9, the oldest supported)
python3 scripts/replay_can_fail.py             # each belief's test must go red under its mutation
python3 scripts/scan_tree.py                   # no secret shape in the tree, test literals included
python3 scripts/derived_counts.py              # the numbers stated in the docs
python3 scripts/lint_plugin.py                 # frontmatter YAML, manifests, hook paths, command names
ruff check --select E,F,W --line-length 120 maisecrets hooks harness tests scripts skills
python3 harness/run.py                         # the real claude client against a fake upstream
```

`scripts/check_all.sh` runs all of these. The git hooks (`scripts/install-hooks.sh`) run only the checks of seconds (a commit: secret scan of the staged diff, manifests, plugin lint; a push: also lint, repository scan, derived counts); the tests, the replay and the harness run in the merge request pipeline, and a red pipeline blocks the merge. CI runs as root in
`python:3.12-slim` and `python:3.9-slim`: a test that depends on file permissions must allow for
root.

## Known traps

- A unit test cannot show what the real Claude Code sandbox allows. The ssh route and the session
  approval were measured end to end in the sandbox against a real host; a design that passed every
  unit test failed there (the sandbox denies writes outside the working directory).
- `claude plugin validate --strict` does not parse the frontmatter strictly; the directory check
  does. `scripts/lint_plugin.py` covers that gap.
- A plugin update removes the plugin folder of an open session (synced plugins) and its hooks then
  fail open until the session restarts. `/reload-plugins` does not help there: it keeps the old
  `~gN` path (anthropics/claude-code#97847, measured on 2.1.284). A marketplace install keeps the old
  version folder for 14 days, so its open sessions keep working. Nothing in the plugin can prevent
  it (README, "Updates and open sessions").

## Watch list: changes upstream that change the design

Check these at the start of a work session here, and at least once a week. A change in one of
them is a reason for an issue. After each check, update the last column (date and result).

| What to watch | Why it matters | How to check | Last checked |
|---|---|---|---|
| Codex can replace a prompt (a `UserPromptSubmit` answer that rewrites the text, or middleware like the Claude Code mods) | Codex still blocks a prompt with a value, and the person sends it again with `/maisecrets:send`. With a rewrite, `rewrite_prompt()` (the path of `claude-mod/maisecrets-mod.mjs`) can serve Codex too. | `codex-rs/hooks/src/events/user_prompt_submit.rs` on `openai/codex` main: does `UserPromptSubmitOutcome` get a prompt field? Read the notes of the newest release (`gh release list -R openai/codex`). | 2026-10-06, codex 0.160.1: no. The outcome has `should_stop`, `stop_reason`, `additional_contexts`. |
| anthropics/claude-code#97847: a synced plugin update moves the plugin folder of an open session, and its hooks fail open | The guard (C13) and README "Updates and open sessions" exist because of it. | `gh issue view 97847 -R anthropics/claude-code`. The harness scenario `plugin_folder_moved` prints `[GAP]` while the gap is open and fails when a client closes it. | 2026-10-06: open. |
| A ChatGPT workspace delivers a plugin's hooks | A workspace that imported the marketplace delivered the plugin with `hooks: []`, so a plugin with hooks and no MCP server protects nothing there. Each person needs the local marketplace install. | Sync the marketplace in a test workspace (Admin > Plugins), install it, and look for the maisecrets hooks in Settings > Hooks (with a project open), or run a probe hook. Read OpenAI's plugin docs on hooks. | 2026-10 (field report, ChatGPT app on Windows, OpenAI.Codex 26.928.2636.0): `hooks: []`. |
| Cowork loads the mod | Measured: the CLI and the desktop app's Code tab rewrite. Cowork shares the hooks of the desktop app; whether it loads the mod is unknown, so the README counts on the block there. | In Cowork, type a fake token such as `glpat-` and 20 letters: a placeholder in the reply and no block means the mod runs. | 2026-10-06: not measured. |
| The Claude Code mods API (`prompt.submit`, `$.process.run`, the rollout switch) | `claude-mod/maisecrets-mod.mjs` depends on it. The settings hook catches every failure, but a silent change would bring back the block. | On each new Claude Code version: `claude plugin test .` and `python3 harness/run.py prompt_secret`. The harness fails when a client that has mods does not load the mod. The types of the running version are in `.claude-plugin/types/` after a run. | 2026-10-06, Claude Code 2.1.291: works. |
