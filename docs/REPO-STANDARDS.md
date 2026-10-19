# Repo standards and requirements

What this repository must satisfy, and why. Items marked **now** are in place
as of 2026-09-26. Items marked **before public** gate the first public
release. Items marked **before directory** gate the submission to the Claude
and OpenAI plugin directories.

## Layout and hygiene (now)

- `maisecrets/` core, `hooks/` entry points, `harness/` live hook harness,
  `tests/` unit tests, `docs/` concept and decisions, `scripts/` tooling.
- Everything a hook runs lives inside the plugin folder. No symlink, no
  submodule, no binary, no package install at runtime (Claude directory
  checklist).
- `.gitignore` excludes caches and harness output. Nothing under
  `~/.maisecrets/` is ever committed.
- `LICENSE` Apache-2.0, `README.md` describes what the plugin runs, writes,
  sends and fetches (the directory reviewer reads it), `CHANGELOG.md`.

## Git hooks (now)

- `.githooks/pre-commit`: staged diff through our own detector, manifests
  parse, plugin lint. It runs in seconds; the unit tests run once per push. Installed by `scripts/install-hooks.sh`, which pins
  `core.hooksPath` for this repo because the global `~/.git-hooks` would
  otherwise bypass it.
- `.githooks/pre-push`: refuses tag pushes, runs lint, the repository scan, the plugin lint and
  the derived counts (seconds). The unit tests, the belief replay and the harness run in the merge
  request pipeline; `scripts/check_all.sh` runs all of them locally.

## CI on gitlab.com (now)

- `.gitlab-ci.yml`: workflow rules for MR pipelines, `main`, tags, schedules.
  Stages validate (manifests, `claude plugin validate --strict`, commit
  subject format, no secrets in tree, ruff), test (unittest, the Claude Code
  harness and the Codex harness against their fake upstreams, with an empty
  HOME and a dummy key, versions pinned), mirror, release. Runner capability
  tag `docker` on the netcup host.
- Release gate: the `release` job waits until the GitHub Actions matrix
  (Windows, macOS; Linux runs on GitLab) is green for the tested SHA on the public mirror
  (`scripts/wait_for_github_checks.py`, public API, no token). Windows was
  red across four releases on 2026-09-26 because nothing waited for it.
- Matrix in a merge request: the job `windows_macos` runs in every merge request pipeline, beside the
  Linux tests (`scripts/github_matrix.py mr`). The git hooks run no tests, so these jobs together are
  the test gate of a merge request: Linux on GitLab, Windows and macOS on GitHub. It merges the MR head into the current target branch (the
  head alone on a conflict), pushes that commit to the branch `ci-mr/<iid>-<sha12>` of the public CI
  repository `Mcpgate-de/maisecrets-ci`, waits for `.github/workflows/ci.yml` there and prints each
  failing test with the exception line. The workflow writes the failures as annotations
  (`github_matrix.py unit`), because the public API serves annotations without a token and the job log
  needs one. Each commit gets a new branch name, so no push needs force. The job deletes the older
  branches of the same MR and every `ci-mr/*` branch older than 14 days, so the branch of a merged MR
  goes with the first MR pipeline after 14 days. The label `no-public-ci` keeps an MR off GitHub (a
  fix that must stay private until its release). Every change runs the job: the tests read nearly every
  file of the tree, the docs included.
- Why a separate CI repository: an MR branch is no protected ref, so the key of this job is no
  protected variable. `MAISECRETS_GITHUB_MR_CI_KEY` (file variable, environment `mr-ci`, not
  protected) is a write deploy key of `Mcpgate-de/maisecrets-ci` alone. A leak writes that repository
  only. The mirror's key can push `main` and the tags of the install source, and stays protected. The
  workflow token is read-only in both repositories (`permissions: contents: read`).
- Release reuse: before the mirror job pushes a release candidate to `ci`, it looks for a green push run
  of the matrix whose commit has exactly the git tree of the candidate (`github_matrix.py reuse`, in
  the CI repository and in the mirror). A run counts only when every job ran and passed; a
  `pull_request` run tested GitHub's merge commit, another tree, and never counts. With a match, the
  mirror job does not push, and the release job logs the reused run (`MATRIX_REUSED_RUN`) instead of
  waiting. The tree matches when the MR was up to date with `main` at its last pipeline and nothing
  else merged before it. No match, or no answer from GitHub, is the wait as before.
- Matrix by hand: push the commit to the GitHub branch `ci-check` (pushed over each time; the rulesets
  protect only `main`, `release` and the tags `v*`). `.github/workflows/ci.yml` runs on it. No draft pull request
  and no new branch name: GitHub keeps listing a deleted pull-request branch.
- Vendored rulesets: Renovate keeps `maisecrets/detection/rules/` current (`renovate.json`). The job `renovate`
  runs self-hosted on a pipeline schedule with `RENOVATE_RUN=true`; on a schedule no other job runs.
  It reads the three `*_VERSION` files. For an upstream release at least 7 days old it runs the sync
  script of that ruleset (`postUpgradeTasks`), so the MR carries the version and the regenerated
  JSON together. The MR pipeline tests the new rules, and a person merges; it becomes a
  `deps(rules)` patch release. A version of detect-secrets or Presidio moved without its JSON is red
  (`scripts/check_vendored_rules.py`, `tests/test_vendored_rules.py`).

  The sync scripts execute no upstream code: betterleaks ships TOML, and the detect-secrets and Presidio
  regexes are read from their Python source as data (`scripts/_static_python.py` knows literals,
  f-strings, `+`, `.format`, `join`, `re.compile` and `Pattern(...)`, and refuses the rest; the
  Presidio wheel is checked against the sha256 PyPI lists, which proves only that the download is the
  file PyPI lists). A value built larger than 200,000 characters, a source file over 2 MB or a
  download over 20 MB is refused. A Presidio class the reading cannot take whole (another base form,
  two bases, a computed default, a duplicate name, patterns that are no literal list) stops the sync:
  Renovate then shows an artifact error on the MR instead of a ruleset with a rule missing. For
  detect-secrets v1.3.0 to v1.5.0 and Presidio 2.2.355 to 2.2.364 (five versions) this gives the same
  JSON byte for byte as executing the upstream code did. Three designs before this one were refused
  in review (2026-10-06): upstream code ran next to the Renovate token, next to the CI job token of
  the schedule's owner, or handed an artifact to a job with a push token.

  `RENOVATE_TOKEN` is the project access token `renovate-bot`, Developer, `api` and
  `write_repository`: it can open an MR and push an unprotected branch, also a branch of another
  open MR, and it cannot push to `main`, merge, create a `v*` tag or read a CI variable (with the
  project's protection: `main` and `v*` tags for Maintainers only). It is protected (only protected
  branches and tags get it) and scoped to the environment `renovate` (on gitlab.com Free that names which
  job of this file gets it; it is no access control).

  What review of the MR is for: a vendored ruleset is data the detector trusts. A new release can
  weaken or drop a rule, or bring a regex
  that backtracks; the tests catch only what they cover. Read the diff of the rule ids. The 7-day wait
  is weaker for detect-secrets: a GitHub tag's date is set by its author, and a tag can move.
  `LICENSE-presidio` comes from the main branch, not from the release.

  Set in the GitLab project, not in this repository: the schedule and its variable, the token and its
  expiry (2027-10-05).

## Versions and releases (now)

- Claude Code fetches a plugin update only when the `version` string in
  `.claude-plugin/plugin.json` changes (manifest reference, "version"). The
  bump is therefore the release, and it is never typed by hand.
- Commit subjects follow `type(scope): text`, types `feat fix perf security
  deps docs ci test chore build style refactor`, `!` or `BREAKING CHANGE` for
  a breaking change. CI job `commit_format` refuses anything else; the
  `.githooks/commit-msg` hook catches it before the commit.
- **The subject is the changelog line.** `feat fix perf security deps` are
  rendered into `CHANGELOG.md` under the next version, so write them for the
  user: what changed for them. `docs ci test chore build style refactor` are
  not rendered: a repository move, a CI change or a wording fix is not a
  release note. What operators need to know goes into this file, not into
  the changelog.
- `scripts/release.py` decides from the commits since the last `v*` tag
  whether there is a release (`feat fix perf security deps`, a breaking
  change, an untyped subject). A release moves only the last number. The
  middle or first number moves only with the owner's approval: the CI variable
  `MAISECRETS_RELEASE_BUMP=minor` or `=major` on that one pipeline. A breaking
  change is the `!` or a footer line `BREAKING CHANGE: …`, never the words in
  a sentence. It writes
  the version into the three manifests and a generated section into
  `CHANGELOG.md`.
- The GitHub branch `release` holds only the runtime files of each release
  (`scripts/build_release_tree.py`, one commit per release, pushed by `mirror_tag`). The
  tests, CI files, release scripts and developer docs are left out: the plugin never runs
  them, and the Anthropic directory blocked two versions on literals in the tests.
  `tests/test_release_tree.py` names the developer-only files; every other tracked file
  ships.
- The directory hold: with `MAISECRETS_DIRECTORY_HOLD: "1"` in `.gitlab-ci.yml`, `mirror_tag`
  pushes GitHub `main` and the tag but not `release`, so the Anthropic directory sees no new
  version while one is in its review. The organisation marketplace (GitLab `main`,
  `notify_marketplace`) and a Codex install from GitHub `main` get every release. Set it to `"0"`
  to publish again; the next release carries every change since.
- The `release` job runs on every push to `main` after the tests, commits
  `chore(release): vX.Y.Z` with `ci.skip`, and pushes the tag `vX.Y.Z`. The tag
  pipeline validates again and mirrors. Nobody pushes a tag by hand: the
  pre-push hook refuses it.
- No changelog fragments and no build counter: the commit subjects are the changelog.
  A plugin version is read by users and by the updater, so it is real semver,
  derived from the commit types instead of claimed in a fragment.
- Credentials: `MAISECRETS_CI_PUSH_TOKEN` (project access token
  `maisecrets-ci-release`, `write_repository`, expires 2027-09-25) and
  `MAISECRETS_GITHUB_DEPLOY_KEY` (file variable, deploy key with write access
  on the GitHub repo only). Both protected, so only protected refs see them:
  `main` and the tags `v*` (protected tags, create level Maintainer). The
  first tag pipeline ran before the tags were protected and got an empty
  key variable; the mirror job now fails loudly on an empty key.

- claude.ai organisation marketplace: synced from the private GitLab project
  through a read-only project token (`claude-ai-org-sync`, Reporter,
  `read_api` + `read_repository`). "Sync automatically" wants a Standard
  Webhooks signature that gitlab.com does not send (403 on every delivery),
  so the tag pipeline's `notify_marketplace` job sends the signed push event
  itself (`scripts/notify_marketplace.py`, variables
  `MAISECRETS_CLAUDE_MARKETPLACE_URL` and `MAISECRETS_CLAUDE_WEBHOOK_SECRET`).
  Each further organisation adds the same pair with the suffix `_2`, `_3` and so
  on, and its own read-only project token; every pair gets the event.

## Remotes (now)

- Primary: `gitlab.com/Sprinterli/maisecrets`, private; it is also the source
  the claude.ai organisation marketplace syncs from. Mirror:
  `github.com/Mcpgate-de/maisecrets`, public, the marketplace for everyone,
  written only by the CI `mirror` job (`origin/main` and tags, deploy key,
  host keys pinned in `.ci-known-hosts-github`). Nobody pushes to GitHub by
  hand. `github.com/Mcpgate-de/maisecrets-ci`, public, holds only the `ci-mr/*` branches of the merge
  request job and is no install source.
  A second private GitHub mirror for the organisation sync existed for
  two hours on 2026-09-26 and was removed once the GitLab source worked.
- GitLab stays under the personal namespace on purpose: a project inside a
  gitlab.com group on the Free tier cannot mint project access tokens, and
  a transfer drops the existing ones (measured 2026-09-26: the release token
  and the org-sync token were gone after the move and had to be recreated).
  The brand lives on GitHub (`Mcpgate-de`) and on the homepage, not in the
  GitLab path.

## Licensing (before public)

- Apache-2.0 for the plugin. A gateway-side implementation lives in its
  own repository under its own licence; this repo owns the protocol spec.
- Detection rules: betterleaks (MIT), Presidio (MIT) and detect-secrets
  (Apache-2.0) are vendored as data under `maisecrets/detection/rules/`, each with its
  licence file, version file and sync script. The six own rules in
  `detect.py` are plain regular expressions; `NOTICE` records every origin.

## Security and privacy (before public)

- `SECURITY.md` with a contact and a disclosure window.
- Threat model in `docs/`: what the vault protects against (values in cloud
  transcripts, plaintext on disk) and what it does not (another process of
  the same user, a compromised machine).
- Privacy statement for the directories: the plugin collects nothing and
  sends nothing. If an opt-in install counter is added, it needs its own
  paragraph and a URL.

## Directory submission (before directory)

- Claude: public GitHub repo, `.claude-plugin/plugin.json`, README ≥ 40 words,
  LICENSE, validation in the developer portal, security scan reads the source.
  The icon rule is stated only by the portal's `ICON_MISSING` finding, not in the
  manifest reference: `icon` in plugin.json, or `.claude-plugin/icon.svg|png`, or
  `assets/icon.*`, square, at least 128 px; without one the publisher's GitHub
  avatar is shown. The plugin sets `icon` and `assets/icon.*` but no
  `.claude-plugin/icon.*`, which the portal showed ahead of the field; `icon` is the raw GitHub URL of
  `assets/icon.png` on `main`, because the portal's listing preview renders a URL
  and shows only a letter for a path inside the plugin. An upload of a zip to a
  claude.ai account shows a generic tile.
- Codex: `.codex-plugin/plugin.json` is the compatibility manifest (a root
  `plugin.json` made Codex 0.157 find none of the hooks). Its `interface` block
  carries `composerIcon` and `logo` (square PNG, 512 px, like the examples in
  github.com/openai/plugins), the listing texts and the URLs. Codex reads
  `hooks/hooks.json` only while the manifest defines no `hooks` key. The release
  script bumps this manifest with the other two; `test_release_tools` checks it.
- OpenAI: verified identity, published privacy policy; for MCP plugins also
  website, support and terms URLs plus 5 positive and 3 negative test cases.
- Domain: `maisecrets.dev` is registered (2026-09-26) and is the
  `homepage` in the manifests; it points at the product page under
  mcpgate.de. `maisecrets.io` is not registered. The OpenAI route needs a
  website with privacy and support pages behind that domain.

## Testing discipline (now)

- Unit tests: `python3 -m unittest discover -s tests`.
- Harness: `python3 harness/run.py`, fake upstream, every request body scanned.
- Every new guard gets a mutation probe: remove it, the harness or a test must
  go red. Probe results are recorded in `docs/TESTING.md` with the count.
