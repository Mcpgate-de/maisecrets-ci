## Release gate

Hooks or other runtime files changed (claude-mod/maisecrets-mod.mjs, commands/audit.md, commands/put.md, hooks/dispatch.py, hooks/guard.py, hooks/hooks.json, hooks/run.cmd, hooks/run.sh): run the harness and a live test between two sessions with --plugin-dir before the release.

Detection changed (maisecrets/detection/rulespec.py): Benchmark V3 against the last release, span by span:

| Result | Spans worse | Changes | False positives |
|---|---:|---|---|
| aparte-dev-maisecrets-full | 0 | none | 91 → 91 |
| aparte-holdout-maisecrets-full | 0 | none | 181 → 181 |
| aparte-val-maisecrets-full | 0 | none | 69 → 69 |
| bank-dev-maisecrets | 0 | none | 0 → 0 |
| bank-val-maisecrets | 0 | none | 0 → 0 |
| credsweeper-dev-maisecrets-full | 0 | none | 121 → 121 |
| credsweeper-holdout-maisecrets-full | 0 | none | 14 → 14 |
| credsweeper-val-maisecrets-full | 0 | none | 21 → 21 |
| gretel-dev-maisecrets-full | 0 | none | 2550 → 2550 |
| gretel-holdout-every25-maisecrets | 0 | none | 28 → 28 |
| gretel-holdout-maisecrets-full | 0 | none | 811 → 811 |
| gretel-val-every25-maisecrets | 0 | none | 34 → 34 |
| gretel-val-maisecrets-full | 0 | none | 870 → 870 |
| llmredactor-dev-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-holdout-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-val-maisecrets-full | 0 | none | 0 → 0 |
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

Holdout V2 recall: 0.6329 → 0.6329

Catalog coverage (rules whose examples are found whole), against docs/coverage.json:

| Catalog | Bare | After a label |
|---|---|---|
| noseyparker | 88 → 88 | 171 → 171 |
| kingfisher | 352 → 352 | 995 → 995 |
| gitleaks | 80 → 80 | 154 → 154 |
| betterleaks | 168 → 168 | 347 → 347 |
| trufflehog | 83 → 83 | 841 → 841 |
| gitlab | 119 → 119 | 162 → 162 |

CPU time, base v0.8.0 and candidate in turns (3 rounds, median; load average 6.7 before, 6.6 after, 10 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 9.162 s | 8.378 s | 0.91 |
| short prompt | 1.054 ms | 1.409 ms | 1.34 |

**Gate: passed**
