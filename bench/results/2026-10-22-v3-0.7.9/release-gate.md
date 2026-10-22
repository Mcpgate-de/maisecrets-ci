## Release gate


Detection changed (maisecrets/detection/core.py, maisecrets/detection/rules/own_secret_rules.json, maisecrets/detection/rules/prefixes.txt): Benchmark V3 against the last release, span by span:

| Result | Spans worse | Changes | False positives |
|---|---:|---|---|
| bank-dev-maisecrets | 0 | none | 0 → 0 |
| bank-val-maisecrets | 0 | none | 0 → 0 |
| gretel-dev-maisecrets-full | 0 | none | 2550 → 2550 |
| gretel-holdout-every25-maisecrets | 0 | none | 28 → 28 |
| gretel-holdout-maisecrets-full | 0 | none | 811 → 811 |
| gretel-val-every25-maisecrets | 0 | none | 34 → 34 |
| gretel-val-maisecrets-full | 0 | none | 869 → 870 |
| mendeley-dev-maisecrets-full | 0 | none | 1150 → 1150 |
| mendeley-holdout-every25-maisecrets | 0 | none | 18 → 18 |
| mendeley-holdout-maisecrets-full | 0 | none | 371 → 371 |
| mendeley-val-every25-maisecrets | 0 | none | 15 → 15 |
| mendeley-val-maisecrets-full | 0 | none | 338 → 338 |
| nemotron-dev-maisecrets-full | 0 | none | 515 → 515 |
| nemotron-holdout-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-holdout-maisecrets-full | 0 | none | 203 → 203 |
| nemotron-val-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-val-maisecrets-full | 0 | none | 190 → 190 |
| piilo-dev-maisecrets-full | 0 | none | 8 → 8 |
| piilo-holdout-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-holdout-maisecrets-full | 0 | none | 1 → 1 |
| piilo-val-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-val-maisecrets-full | 0 | none | 3 → 3 |
| privy-all-every10-maisecrets | 0 | none | 339 → 339 |
| privy-all-maisecrets-full | 0 | none | 3447 → 3447 |

Holdout V2 recall: 0.6256 → 0.6256

**Gate: passed**
