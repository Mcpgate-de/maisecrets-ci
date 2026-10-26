## Release gate

Hooks or other runtime files changed (maisecrets/vault.py): run the harness and a live test between two sessions with --plugin-dir before the release.

Detection changed (maisecrets/detection/core.py, maisecrets/detection/personal.py, maisecrets/detection/regions.py, maisecrets/detection/rulespec.py): Benchmark V3 against the last release, span by span:

| Result | Spans worse | Changes | False positives |
|---|---:|---|---|
| aparte-dev-maisecrets-full | 0 | none | 91 → 91 |
| aparte-holdout-maisecrets-full | 0 | none | 181 → 183 |
| aparte-val-maisecrets-full | 0 | {'missed->full': 1} | 69 → 69 |
| bank-dev-maisecrets | – | not comparable (other cases or no baseline) | – |
| bank-val-maisecrets | 0 | none | 0 → 0 |
| credsweeper-dev-maisecrets-full | 0 | none | 121 → 123 |
| credsweeper-holdout-maisecrets-full | 0 | none | 14 → 14 |
| credsweeper-val-maisecrets-full | 0 | none | 21 → 23 |
| gretel-dev-maisecrets-full | 0 | {'missed->full': 1984, 'missed->partial': 84, 'partial->full': 12} | 2550 → 2814 |
| gretel-holdout-every25-maisecrets | 0 | {'missed->full': 24, 'partial->full': 1} | 28 → 30 |
| gretel-holdout-maisecrets-full | 0 | {'missed->full': 673, 'missed->partial': 19, 'partial->full': 9} | 811 → 903 |
| gretel-val-every25-maisecrets | 0 | {'missed->full': 18, 'missed->partial': 1} | 34 → 39 |
| gretel-val-maisecrets-full | 0 | {'missed->partial': 34, 'missed->full': 606, 'partial->full': 2} | 870 → 970 |
| llmredactor-dev-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-holdout-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-val-maisecrets-full | 0 | none | 0 → 0 |
| mendeley-dev-maisecrets-full | 0 | {'missed->full': 2507, 'missed->partial': 37} | 1150 → 1310 |
| mendeley-holdout-every25-maisecrets | 0 | {'missed->full': 31} | 18 → 20 |
| mendeley-holdout-maisecrets-full | 0 | {'missed->full': 820, 'missed->partial': 4} | 371 → 421 |
| mendeley-val-every25-maisecrets | 0 | {'missed->full': 34, 'missed->partial': 1} | 15 → 18 |
| mendeley-val-maisecrets-full | 0 | {'missed->full': 813, 'missed->partial': 7} | 338 → 391 |
| nemotron-dev-maisecrets-full | 0 | {'missed->full': 3413, 'partial->full': 4, 'missed->partial': 15} | 515 → 520 |
| nemotron-holdout-every25-maisecrets | 0 | {'missed->full': 49} | 7 → 7 |
| nemotron-holdout-maisecrets-full | 0 | {'missed->full': 1165, 'partial->full': 2, 'missed->partial': 7} | 203 → 205 |
| nemotron-val-every25-maisecrets | 0 | {'missed->full': 48} | 7 → 7 |
| nemotron-val-maisecrets-full | 0 | {'missed->full': 1129, 'partial->full': 4, 'missed->partial': 11} | 190 → 193 |
| piilo-dev-maisecrets-full | 0 | none | 8 → 8 |
| piilo-holdout-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-holdout-maisecrets-full | 0 | none | 1 → 1 |
| piilo-val-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-val-maisecrets-full | 0 | none | 3 → 3 |
| privy-all-every10-maisecrets | 0 | {'missed->full': 12} | 339 → 345 |
| privy-all-maisecrets-full | 0 | {'missed->full': 96} | 3447 → 3482 |

Holdout V2 recall: 0.6473 → 0.6473

Catalog coverage (rules whose examples are found whole), against docs/coverage.json:

| Catalog | Bare | After a label |
|---|---|---|
| noseyparker | 88 → 88 | 171 → 171 |
| kingfisher | 352 → 352 | 995 → 995 |
| gitleaks | 80 → 80 | 154 → 154 |
| betterleaks | 168 → 168 | 347 → 347 |
| trufflehog | 83 → 83 | 841 → 841 |
| gitlab | 119 → 119 | 162 → 162 |

CPU time, base v0.8.1 and candidate in turns (3 rounds, median; load average 2.7 before, 2.8 after, 10 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 4.634 s | 5.269 s | 1.14 |
| short prompt | 0.598 ms | 0.642 ms | 1.07 |

**Gate: passed**
