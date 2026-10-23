## Release gate

Hooks or other runtime files changed (maisecrets/check_value.py, maisecrets/hooks.py): run the harness and a live test between two sessions with --plugin-dir before the release.

Detection changed (maisecrets/detection/core.py, maisecrets/detection/registry.py, maisecrets/detection/rules/own_secret_rules.json, maisecrets/detection/rules/prefixes.txt): Benchmark V3 against the last release, span by span:

| Result | Spans worse | Changes | False positives |
|---|---:|---|---|
| aparte-dev-maisecrets-full | – | not comparable (other cases or no baseline) | – |
| aparte-holdout-maisecrets-full | – | not comparable (other cases or no baseline) | – |
| aparte-val-maisecrets-full | – | not comparable (other cases or no baseline) | – |
| bank-dev-maisecrets | 0 | none | 0 → 0 |
| bank-val-maisecrets | 0 | none | 0 → 0 |
| credsweeper-dev-maisecrets-full | – | not comparable (other cases or no baseline) | – |
| credsweeper-holdout-maisecrets-full | – | not comparable (other cases or no baseline) | – |
| credsweeper-val-maisecrets-full | – | not comparable (other cases or no baseline) | – |
| gretel-dev-maisecrets-full | 0 | {'missed->full': 8} | 2550 → 2550 |
| gretel-holdout-every25-maisecrets | 0 | none | 28 → 28 |
| gretel-holdout-maisecrets-full | 0 | {'missed->full': 1} | 811 → 811 |
| gretel-val-every25-maisecrets | 0 | none | 34 → 34 |
| gretel-val-maisecrets-full | 0 | {'missed->full': 4} | 870 → 870 |
| llmredactor-dev-maisecrets-full | – | not comparable (other cases or no baseline) | – |
| llmredactor-holdout-maisecrets-full | – | not comparable (other cases or no baseline) | – |
| llmredactor-val-maisecrets-full | – | not comparable (other cases or no baseline) | – |
| mendeley-dev-maisecrets-full | 0 | none | 1150 → 1150 |
| mendeley-holdout-every25-maisecrets | 0 | none | 18 → 18 |
| mendeley-holdout-maisecrets-full | 0 | none | 371 → 371 |
| mendeley-val-every25-maisecrets | 0 | none | 15 → 15 |
| mendeley-val-maisecrets-full | 0 | none | 338 → 338 |
| nemotron-dev-maisecrets-full | 0 | {'missed->full': 68, 'partial->full': 26} | 515 → 515 |
| nemotron-holdout-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-holdout-maisecrets-full | 0 | {'missed->full': 25, 'partial->full': 7} | 203 → 203 |
| nemotron-val-every25-maisecrets | 0 | {'missed->full': 3} | 7 → 7 |
| nemotron-val-maisecrets-full | 0 | {'missed->full': 23, 'partial->full': 6} | 190 → 190 |
| piilo-dev-maisecrets-full | 0 | none | 8 → 8 |
| piilo-holdout-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-holdout-maisecrets-full | 0 | none | 1 → 1 |
| piilo-val-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-val-maisecrets-full | 0 | none | 3 → 3 |
| privy-all-every10-maisecrets | 0 | none | 339 → 339 |
| privy-all-maisecrets-full | 0 | none | 3447 → 3447 |

Holdout V2 recall: 0.6329 → 0.6329

Catalog coverage (rules whose examples are found whole), against docs/coverage.json:

| Catalog | Bare | After a label |
|---|---|---|
| noseyparker | 88 → 88 | 171 → 171 |
| kingfisher | 344 → 351 | 994 → 994 |
| gitleaks | 80 → 80 | 153 → 153 |
| betterleaks | 168 → 168 | 346 → 346 |
| trufflehog | 80 → 83 | 839 → 839 |
| gitlab | 119 → 119 | 162 → 162 |

CPU time, base v0.7.9 and candidate in turns (3 rounds, median; load average 1.8 before, 1.7 after, 10 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 4.361 s | 4.593 s | 1.05 |
| short prompt | 0.512 ms | 0.588 ms | 1.15 |

**Gate: passed**
