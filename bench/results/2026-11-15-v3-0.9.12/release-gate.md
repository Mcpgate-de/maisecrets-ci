## Release gate


Detection changed (maisecrets/detection/core.py, maisecrets/detection/encoded_mail.py, maisecrets/detection/fields.py, maisecrets/detection/id_labels.py, maisecrets/detection/key_values.py, maisecrets/detection/leaves.py, maisecrets/detection/personal.py, maisecrets/detection/public_values.py): Benchmark V3 against the last release, span by span:

| Result | Spans worse | Changes | False positives |
|---|---:|---|---|
| aparte-dev-maisecrets-full | 0 | none | 92 → 92 |
| aparte-holdout-maisecrets-full | 0 | none | 183 → 183 |
| aparte-val-maisecrets-full | 0 | none | 69 → 69 |
| bank-dev-maisecrets | 0 | none | 0 → 0 |
| bank-val-maisecrets | 0 | none | 0 → 0 |
| credsweeper-dev-maisecrets-full | 0 | none | 123 → 123 |
| credsweeper-holdout-maisecrets-full | 0 | none | 14 → 14 |
| credsweeper-val-maisecrets-full | 0 | none | 23 → 23 |
| gretel-dev-maisecrets-full | 135 | {'missed->partial': 24, 'full->missed': 135, 'missed->full': 408} | 2890 → 2259 |
| gretel-holdout-every25-maisecrets | 1 | {'missed->full': 2, 'full->missed': 1} | 30 → 23 |
| gretel-holdout-maisecrets-full | 39 | {'missed->full': 126, 'full->missed': 39, 'partial->full': 4, 'missed->partial': 13} | 915 → 735 |
| gretel-val-every25-maisecrets | 1 | {'missed->full': 8, 'full->missed': 1} | 40 → 36 |
| gretel-val-maisecrets-full | 52 | {'missed->full': 154, 'missed->partial': 10, 'full->missed': 52} | 999 → 799 |
| llmredactor-dev-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-holdout-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-val-maisecrets-full | 0 | none | 0 → 0 |
| mendeley-dev-maisecrets-full | 0 | {'missed->full': 1589, 'partial->full': 132} | 1310 → 1396 |
| mendeley-holdout-every25-maisecrets | 0 | {'missed->full': 14, 'partial->full': 1} | 20 → 20 |
| mendeley-holdout-maisecrets-full | 0 | {'missed->full': 524, 'partial->full': 27} | 421 → 457 |
| mendeley-val-every25-maisecrets | 0 | {'missed->full': 20, 'partial->full': 3} | 18 → 21 |
| mendeley-val-maisecrets-full | 0 | {'missed->full': 529, 'partial->full': 33} | 391 → 420 |
| nemotron-dev-maisecrets-full | 69 | {'full->missed': 68, 'missed->full': 55, 'missed->partial': 5, 'partial->missed': 1} | 526 → 496 |
| nemotron-holdout-every25-maisecrets | 0 | none | 7 → 6 |
| nemotron-holdout-maisecrets-full | 25 | {'full->missed': 25, 'missed->full': 21, 'missed->partial': 1} | 206 → 193 |
| nemotron-val-every25-maisecrets | 0 | {'missed->full': 1} | 7 → 7 |
| nemotron-val-maisecrets-full | 15 | {'partial->missed': 1, 'missed->full': 17, 'full->missed': 14} | 193 → 172 |
| piilo-dev-maisecrets-full | 0 | none | 39 → 39 |
| piilo-holdout-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-holdout-maisecrets-full | 0 | none | 15 → 15 |
| piilo-val-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-val-maisecrets-full | 0 | none | 9 → 9 |
| privy-all-every10-maisecrets | 0 | none | 346 → 346 |
| privy-all-maisecrets-full | 0 | none | 3493 → 3493 |

Holdout V2 recall: 0.6594 → 0.6594

Catalog coverage (rules whose examples are found whole), against docs/coverage.json:

| Catalog | Bare | After a label |
|---|---|---|
| noseyparker | 89 → 89 | 171 → 171 |
| kingfisher | 356 → 356 | 995 → 995 |
| gitleaks | 80 → 80 | 154 → 154 |
| betterleaks | 170 → 170 | 347 → 347 |
| trufflehog | 83 → 83 | 840 → 840 |
| gitlab | 122 → 122 | 162 → 162 |

CPU time, base v0.9.11 and candidate in turns (3 rounds, median; load average 0.6 before, 1.1 after, 8 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 10.234 s | 10.547 s | 1.03 |
| short prompt | 0.408 ms | 0.44 ms | 1.08 |
| 62 KB one-line JSON with a field label | 0.652 s | 0.649 s | 1.00 |

**Gate: stopped**
