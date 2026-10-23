# Detection coverage: how maisecrets stays current

maisecrets should find the newest token formats soon after a provider ships them, and it should have no blind spot
that nobody measures. Until 0.7.8 it kept three vendored rule sets current (Renovate) and measured recall on
benchmark datasets, but it never measured which formats the other public sources know and it misses. One question
about a Storyblok token (2026-10-22) found 206 such formats in an afternoon, and raised the share of catalog
examples found without a label by 4 to 10 points per catalog. This document turns that afternoon into a process.

## The five loops

| Loop | What it does | How often | Automated | Output |
|---|---|---|---|---|
| 1. Coverage as a number | Measure every catalog's examples: bare, after a label, in the catalog's own text | weekly, and in the release gate | yes | `docs/coverage.json`; the gate stops when a number falls |
| 2. New formats as rule drafts | Turn each new entry of the watched sources into a draft rule with a test | daily watch, draft on demand | the draft; a person merges | a merge request with rules, tests and measurements |
| 3. Research sweep | Read the providers' own documentation for token formats | weekly queue (`format_intake`), research on demand | the queue yes; the research by an agent, on request | `format-intake/queue.md`, then `bench/formats/research-<date>.jsonl` |
| 4. Field reports | A person reports a format that `ms:(…)` did not catch: shape only, never the value | when it happens | the issue text | an issue, then a draft (loop 2) |
| 5. Families | Measure each family of formats separately and close one family at a time | per block | measurement yes | a number per family in loop 1 |

### 1. Coverage as a number

`scripts/measure_catalog_coverage.py` runs over the newest commit of each catalog (noseyparker, kingfisher,
gitleaks, betterleaks, trufflehog, GitLab) and counts, per catalog, the rules whose examples maisecrets finds whole:
bare, after a label, and in the example's own text. The numbers go to `docs/coverage.json` with the catalog commits.

- **Ratchet:** the release gate measures the candidate on the catalog commits of `docs/coverage.json`. A number that
  falls stops the release, as a span masked worse does.
- **Drift:** a weekly scheduled job measures `main` on the newest catalog commits. A new catalog rule that maisecrets
  misses shows as a lower share there before anyone asks.

### 2. New formats as rule drafts

`format_watch` (daily, `scripts/watch_formats.py`) compares the GitHub secret scanning types, trufflehog's detectors,
betterleaks on `main`, Google's Veles plugins, gitleaks on `master`, Trivy's built-in secret rules, Nosey Parker's
rule ids and the key templates of nuclei-templates with `docs/format-watch.txt` and turns red on a new entry. It
also keeps a fingerprint of each entry's rule text (`docs/format-watch-fp.txt`) and turns red when a provider
changes a known format, a new length or a second prefix under the same id.

A draft comes from `scripts/draft_format_rules.py` (in the weekly `coverage_drift` job, as the artifact
`format-drafts/`): it takes the
catalog's regex, keeps the fixed prefix first (the form of `rules/prefixes.txt`), checks the rule against every
example of the catalog rule, and writes a test whose oracle is kept apart from the rule (a class template of the
catalog example). The draft merge request carries the FP bank, the time measurement and the gate. Nothing merges by
itself: each rule can raise false positives.

### 3. Research sweep

The weekly job `format_intake` (`scripts/format_intake.py`, Mondays) puts every signal into one queue, the artifact
`format-intake/queue.md` and `queue.jsonl`: new and changed entries of the watched lists, the open "Token format:"
reports that the answer of `ms:(…)` links (loop 4), and the posts of the last 14 days about token formats in the
provider changelogs of `docs/format-feeds.txt`. An item turns the job red. Its first run over 60 days found
Cloudflare's scannable Access service token secrets (2026-08-26). A person or an agent works the queue: research,
then the drafts below.

Agents read, per provider that GitHub secret scanning names (and per new provider of loop 2), the provider's
documentation, changelog or source for its token formats, and write one line per format with its source:
`type, provider, variant, prefix, regex, shape, source, evidence`. A line without a source has no regex. The lines
go to `bench/formats/research-<date>.jsonl` (without the free-text `shape`), and
`scripts/draft_researched_rules.py <file>` turns them into drafts: it generates five tokens per format, drops a
format that an existing rule already finds, a generic or public one and one without a first-party source, and keeps
a rule only when it takes every token whole, also before `.`, `,` and `)`. The sweep of 2026-10-22 covered 529
types and gave 108 rules; two sweeps over the providers' own code gave 72 (0.7.10) and 47 (0.7.11).

### 4. Field reports

When `ms:(…)` says that maisecrets would not catch a value, the answer offers to report the format. The report holds
the fixed prefix (only a short run of letters before a separator, such as `sb_pat_`), the length of the rest and its
character classes, never the value. It prints an issue text and a prefilled link, as `/maisecrets:report` does; the
person opens the link (built in 0.7.10: `check_value.format_report`). The Storyblok token of 2026-10-22 is the case
this loop is for: it was in no catalog.

### 5. Families

Each family has its own number in loop 1 and is closed as one block, with its own false-positive measurement.

| Family | Example | State |
|---|---|---|
| Fixed prefix | `hvs.`, `sb_pat_`, `glpat-` | closed 2026-10-22 for the catalogs and the GitHub types |
| Signature inside the key | Azure identifiable keys, CASK `JQQJ99` | closed 2026-10-22 for Microsoft's published signatures |
| Provider word and shape | `datadog … 32 hex` | 0.7.10: 16 rules. Of 61 candidates, 45 added nothing: a realistic value after the same words was already a hit; kingfisher's own examples were missed for their low-entropy values, not for a missing rule |
| Checksum without a prefix | formats whose last characters are a CRC | open |
| Structured tokens | JWT, PASETO, signed URLs | partly |
| Encoded values | base64, percent-encoding | partly (the tool channel decodes) |
| Connection strings | `postgres://user:…@host` | partial masking by policy (docs/BENCHMARK-V3.md) |

## Guards for every new rule

- An oracle kept apart from the rule, and a mutation that turns its test red (length, character set, boundary).
- A sweep over the FP bank and the developer text: no acted hit outside test code.
- The release gate: no span worse in V3, Holdout V2 recall not lower, the coverage numbers not lower.
- Time: CPU time of a fixed 1 MB text and of a short prompt, base and candidate measured in turns; the gate stops at
  more than 20 % and reports the load average.
- Out by design: short generic prefixes (`sk_`, `key_`), public ids and publishable keys, connection strings.
- No new rule takes a part of a longer token that another rule took whole (a Fly.io token of several macaroons, a
  hook URL with its scheme, the tail of a commit id): compare the catalog coverage rule by rule with
  `docs/coverage-rules.txt` before the push, not only in the gate.
