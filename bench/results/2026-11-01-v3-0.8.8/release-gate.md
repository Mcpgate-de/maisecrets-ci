## Release gate

Hooks or other runtime files changed (claude-mod/maisecrets-mod.mjs, maisecrets/hooks.py, maisecrets/ner_setup.py, maisecrets/remote_layer.py, maisecrets/settings.py): run the harness and a live test between two sessions with --plugin-dir before the release.

Detection changed (maisecrets/detection/personal.py, maisecrets/detection/remote.py): Benchmark V3 against the last release, span by span:

| Result | Spans worse | Changes | False positives |
|---|---:|---|---|
| aparte-dev-maisecrets-full | 0 | none | 91 → 91 |
| aparte-holdout-maisecrets-full | 0 | none | 183 → 183 |
| aparte-val-maisecrets-full | 0 | none | 69 → 69 |
| bank-dev-maisecrets | 0 | none | 0 → 0 |
| bank-val-maisecrets | 0 | none | 0 → 0 |
| credsweeper-dev-maisecrets-full | 0 | none | 123 → 123 |
| credsweeper-holdout-maisecrets-full | 0 | none | 14 → 14 |
| credsweeper-val-maisecrets-full | 0 | none | 23 → 23 |
| gretel-dev-maisecrets-full | 0 | none | 2816 → 2816 |
| gretel-holdout-every25-maisecrets | 0 | none | 30 → 30 |
| gretel-holdout-maisecrets-full | 0 | none | 904 → 904 |
| gretel-val-every25-maisecrets | 0 | none | 40 → 40 |
| gretel-val-maisecrets-full | 0 | none | 972 → 972 |
| llmredactor-dev-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-holdout-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-val-maisecrets-full | 0 | none | 0 → 0 |
| mendeley-dev-maisecrets-full | 0 | none | 1310 → 1310 |
| mendeley-holdout-every25-maisecrets | 0 | none | 20 → 20 |
| mendeley-holdout-maisecrets-full | 0 | none | 421 → 421 |
| mendeley-val-every25-maisecrets | 0 | none | 18 → 18 |
| mendeley-val-maisecrets-full | 0 | none | 391 → 391 |
| nemotron-dev-maisecrets-full | 0 | none | 522 → 522 |
| nemotron-holdout-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-holdout-maisecrets-full | 0 | none | 205 → 205 |
| nemotron-val-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-val-maisecrets-full | 0 | none | 193 → 193 |
| piilo-dev-maisecrets-full | 0 | none | 8 → 8 |
| piilo-holdout-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-holdout-maisecrets-full | 0 | none | 1 → 1 |
| piilo-val-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-val-maisecrets-full | 0 | none | 3 → 3 |
| privy-all-every10-maisecrets | 0 | none | 345 → 345 |
| privy-all-maisecrets-full | 0 | none | 3481 → 3481 |

Catalog coverage (rules whose examples are found whole), against docs/coverage.json:

| Catalog | Bare | After a label |
|---|---|---|
| noseyparker | 88 → 88 | 171 → 171 |
| kingfisher | 352 → 352 | 995 → 995 |
| gitleaks | 80 → 80 | 154 → 154 |
| betterleaks | 168 → 168 | 347 → 347 |
| trufflehog | 83 → 83 | 840 → 840 |
| gitlab | 119 → 119 | 162 → 162 |

CPU time, base v0.8.7 and candidate in turns (3 rounds, median; load average 0.6 before, 1.0 after, 8 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 12.41 s | 12.061 s | 0.97 |
| short prompt | 1.315 ms | 1.505 ms | 1.14 |

**Gate: passed**
