# Benchmark V2

Status: **frozen** (2026-10-20), scoring code `bench/score.py` at commit `e19ef7a78f83133410e1804178f63d1cdb938d23`.
V2 keeps everything of `docs/BENCHMARK-V1.md` that is not named here. A change to a frozen part needs a V3.

## What V2 freezes from V1

- **Scoring** (`bench/score.py`): a span is `full`, `partial` or `missed`; precision counts a finding as right when it
  lies on sensitive text; `too wide`; a rate is "-" under 30 spans.
- **The case format, the classes and the scope of each scanner** (V1 "Classes", "Scope of a scanner").
- **The split rule:** `sha256(source + "/" + record)`, the first 8 hex digits modulo 10: 0 to 5 `dev`, 6 to 7 `val`,
  8 to 9 `holdout`.
- **The sources and their pins**, with the label cleaning of `scripts/measure_datasets.py`.

## Which data is what

| Data | Role in V2 | Why |
|---|---|---|
| Nemotron-PII, Gretel, Mendeley, PIILO, all splits | **development** | The rule round of 2026-10-19 read their cases on `--split all`, the public holdout split included. A new salt would not make them unseen again. The split names stay in the files; for these four sets they mean dev and val only. |
| The public bank `bench/bank/` (dev, val) | development | written by the maintainer, public |
| The secret catalogs (six) | development | the rule examples of other tools, read during coverage work |
| **Privy** (`beki/privy`, test-small, all splits) | **independent evaluation** | added 2026-10-20; nobody had read it for tuning. Its mapping was fixed from the dataset card and the label inventory before the first run of any scanner. Its cases are never read for a rule: only totals and per-class counts are looked at. |
| **Holdout V2** (private) | **independent evaluation** | see below; the honest number for a release |
| Holdout V1 (private, 80 cases) | development (`val`) | its last run was on the 0.6.41 candidate; it is no test any more |

A rule round reads cases only from the development data, decides on its `val` split and the false-alarm bank, and
reports `dev` and `val` apart. `bench/run.py --split all` writes the case ids of every split; an analysis run uses
`--split dev`.

## Scanners and their configurations

Each scanner runs with the configuration its result file names and nothing tuned per source. Every distribution is
pinned in `bench/adapters/requirements/` (a test checks that each foreign adapter has such a file).

| Scanner | Configuration |
|---|---|
| maisecrets | regions `generic,de,us`, sources and references off; tool channel |
| detect-secrets | its default plugins (V1) |
| secret-scan | V1 |
| pii-anon | the README profile (V1) |
| preserve | V1 |
| **Presidio** 2.2.364 | `AnalyzerEngine().analyze(text, language="en")`, the default recognizers and spaCy `en_core_web_lg` 3.8.0, no score threshold. DATE_TIME, NRP, URL and CRYPTO are left out: they have no class here and would count against every birth date and address. The version is the one maisecrets vendors its recognizers from (`maisecrets/detection/rules/PRESIDIO_VERSION`). |

## The report

`bench/report.py` writes, per source and split, one table per family (spans, full, partial, missed, recall strict and
lenient, char recall, false positives, precision, F1, too wide, false positives per 1,000 negative cases, median time)
and one table per class (full / partial / missed per scanner). A comparison is read per class first: a gain in one
class and a loss in another must both be visible. Aggregate F1 is a secondary number.

## Repeat a run

From the root of a checkout, with the commands of `docs/BENCHMARK-V1.md` ("Repeat a measurement") for the four V1
scanners, the datasets and the catalogs, plus Presidio and Privy:

```bash
python3.11 -m venv /tmp/venv-presidio && /tmp/venv-presidio/bin/pip install --no-deps -r bench/adapters/requirements/presidio.txt
export BENCH_PRESIDIO_PYTHON=/tmp/venv-presidio/bin/python
python3 scripts/measure_datasets.py fetch --only privy          # the pinned archive and its test-small.json
git worktree add --detach /tmp/maisecrets-0.6.41 v0.6.41         # the maisecrets release to measure
BENCH_PYTHON=/tmp/venv-yaml/bin/python BENCH_CATALOGS=/tmp/catalogs bench/run_all.sh results /tmp/maisecrets-0.6.41
```

`results/` then holds one JSON file per scanner, source and split (the raw data), `report.md` (the tables of
`bench/report.py`), `report.csv` (the same numbers, one row per run and family or class) and `environment.json`
(`bench/manifest.py`: the operating system, the benchmark commit and the maisecrets checkout with their state, each
scanner's Python with every installed distribution, the pinned datasets and the commits of the catalogs). The
report refuses a result from a modified tree. The run of 2026-10-20 took 41 minutes on an Apple M5, beside other measurements.

## Limitations

- The datasets are synthetic and mostly English. Their labels are not always ours: Nemotron labels some policy and
  loan numbers as bank accounts, and documentation example passwords as passwords.
- Privy's label names are Presidio's entity types, and its test split has no e-mail, phone, IP, IBAN or SSN labels.
  Its classes are names, national ids, passwords, cards and bank numbers; a comparison with Presidio on Privy may
  favour Presidio's taxonomy.
- **Privy's precision for maisecrets measures mostly this gap** (counted 2026-10-20 on `next` at 40e638ef, totals by
  class and rule only, no case read): of 3,443 false positives on 28,843 cases, 3,282 (95 %) are values of the
  classes Privy does not label: `us-ssn` 796, `iban` 820, `ip` 760, `email` 738, phone 136. About 160 remain
  (`us-license` 57, `ds-keyword-colon` 51, others below 25). The V2 number stays as frozen; a V3 should score Privy
  only on the classes it labels (as the scope of a scanner leaves out what it cannot find) and report the rest apart.
- Names and addresses are most of the missed spans. maisecrets has no named-entity model; Presidio has one.
- maisecrets runs in the tool channel on every case; a typed prompt is a stricter channel.
- PIILO is small (1,496 spans). A rate under 30 spans is not printed.

## Development sources after the freeze

`traces` (`bench/traces.py`, 2026-10-20) is development data and no part of a V2 comparison. A seeded generator makes
3,000 protocol traces at run time (JSON, SQL, HTML, XML, CSV, log lines, query strings): a few personal fields among
fields that only look like them. It was written to test whether the protocol formats cause Privy's false positives;
the formats come from common practice of these protocols, not from Privy. On it, maisecrets has a precision of 0.993
on `dev` and 0.986 on `val` (38 and 23 false positives), so the formats are not the cause: the count above is. Its
misses (addresses, user names, names and birth dates in a field of their own) are recall work on development data.

## Holdout V2

1. **The templates are written before any case is generated, and not from maisecrets' misses.** Their source is a
   list of real-world formats per class (public format specifications, issuer ranges, documented label words),
   committed first. Nobody who writes the templates looks at a list of maisecrets misses for them.
2. A seeded generator writes the cases into a private directory. The manifest (`bench/holdout.manifest`: number of
   cases, sha256 of each file) is committed before the first run.
3. The holdout runs only on a release candidate. Each run writes one line to `bench/HOLDOUT-LOG.md`, totals only.
4. No rule is changed because of a holdout result. **Whoever sees the totals of a holdout run does not derive a new
   case form or a new rule from them.** A set that was read for tuning becomes development data, and the log says so.

## Decisions taken at the freeze (2026-10-20)

1. The public holdout split of the four read datasets is development data (no new salt).
2. Privy is the second independent number, chosen and mapped before any result.
3. The scanners are the four of V1 and Presidio.
