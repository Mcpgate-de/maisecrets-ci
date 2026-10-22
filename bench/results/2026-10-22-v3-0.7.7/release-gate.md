## Release gate


Detection changed (maisecrets/detection/core.py, maisecrets/detection/personal.py): Benchmark V3 against the last release, span by span:

| Result | Spans worse | Changes | False positives |
|---|---:|---|---|
| bank-dev-maisecrets | 0 | {'missed->full': 3} | 0 → 0 |
| bank-val-maisecrets | 0 | none | 0 → 0 |
| gretel-dev-maisecrets-full | 0 | {'missed->full': 85} | 2535 → 2550 |
| gretel-holdout-every25-maisecrets | 0 | none | 28 → 28 |
| gretel-holdout-maisecrets-full | 0 | {'missed->full': 37} | 809 → 811 |
| gretel-val-every25-maisecrets | 0 | {'missed->full': 4} | 34 → 34 |
| gretel-val-maisecrets-full | 0 | {'missed->full': 34} | 869 → 869 |
| mendeley-dev-maisecrets-full | 0 | none | 1150 → 1150 |
| mendeley-holdout-every25-maisecrets | 0 | none | 18 → 18 |
| mendeley-holdout-maisecrets-full | 0 | none | 371 → 371 |
| mendeley-val-every25-maisecrets | 0 | none | 15 → 15 |
| mendeley-val-maisecrets-full | 0 | none | 338 → 338 |
| nemotron-dev-maisecrets-full | 0 | {'missed->full': 2082, 'partial->full': 5} | 512 → 515 |
| nemotron-holdout-every25-maisecrets | 0 | {'missed->full': 24} | 7 → 7 |
| nemotron-holdout-maisecrets-full | 0 | {'missed->full': 616} | 203 → 203 |
| nemotron-val-every25-maisecrets | 0 | {'missed->full': 42} | 7 → 7 |
| nemotron-val-maisecrets-full | 0 | {'missed->full': 671, 'partial->full': 2} | 188 → 190 |
| piilo-dev-maisecrets-full | 0 | none | 8 → 8 |
| piilo-holdout-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-holdout-maisecrets-full | 0 | none | 1 → 1 |
| piilo-val-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-val-maisecrets-full | 0 | none | 3 → 3 |
| privy-all-every10-maisecrets | 0 | {'missed->full': 1} | 339 → 339 |
| privy-all-maisecrets-full | 0 | {'missed->full': 9} | 3445 → 3447 |

Holdout V2 recall: 0.6256 → 0.6256

**Gate: passed**
