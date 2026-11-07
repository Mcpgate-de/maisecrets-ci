## Release gate

Hooks or other runtime files changed (hooks/dispatch.py, hooks/hooks.json, hooks/run.cmd, hooks/run.sh, maisecrets/check_value.py, maisecrets/codex_trust.py, maisecrets/exit_wrap.py, maisecrets/hooks.py): run the harness and a live test between two sessions with --plugin-dir before the release.

Detection changed (maisecrets/detection/core.py, maisecrets/detection/fields.py, maisecrets/detection/leaves.py, maisecrets/detection/own_rules.py, maisecrets/detection/personal.py, maisecrets/detection/rules/leading_literals.json, maisecrets/detection/value_checks.py): Benchmark V3 against the last release, span by span:

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
| gretel-dev-maisecrets-full | 0 | {'missed->partial': 96, 'missed->full': 196, 'partial->full': 1} | 2824 → 2867 |
| gretel-holdout-every25-maisecrets | 0 | none | 30 → 30 |
| gretel-holdout-maisecrets-full | 0 | {'missed->partial': 38, 'missed->full': 54} | 906 → 909 |
| gretel-val-every25-maisecrets | 0 | {'missed->full': 4} | 40 → 40 |
| gretel-val-maisecrets-full | 0 | {'missed->partial': 32, 'missed->full': 47} | 975 → 988 |
| llmredactor-dev-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-holdout-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-val-maisecrets-full | 0 | none | 0 → 0 |
| mendeley-dev-maisecrets-full | 0 | none | 1310 → 1310 |
| mendeley-holdout-every25-maisecrets | 0 | none | 20 → 20 |
| mendeley-holdout-maisecrets-full | 0 | none | 421 → 421 |
| mendeley-val-every25-maisecrets | 0 | none | 18 → 18 |
| mendeley-val-maisecrets-full | 0 | none | 391 → 391 |
| nemotron-dev-maisecrets-full | 0 | {'missed->full': 220} | 522 → 525 |
| nemotron-holdout-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-holdout-maisecrets-full | 0 | {'missed->full': 66} | 205 → 205 |
| nemotron-val-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-val-maisecrets-full | 0 | {'missed->full': 61} | 193 → 193 |
| piilo-dev-maisecrets-full | 0 | none | 8 → 39 |
| piilo-holdout-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-holdout-maisecrets-full | 0 | none | 1 → 14 |
| piilo-val-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-val-maisecrets-full | 0 | none | 3 → 9 |
| privy-all-every10-maisecrets | 0 | none | 345 → 345 |
| privy-all-maisecrets-full | 0 | none | 3480 → 3480 |

Holdout V2 recall: 0.6473 → 0.6473

Catalog coverage (rules whose examples are found whole), against docs/coverage.json:

| Catalog | Bare | After a label |
|---|---|---|
| noseyparker | 88 → 88 | 171 → 171 |
| kingfisher | 352 → 352 | 995 → 995 |
| gitleaks | 80 → 80 | 154 → 154 |
| betterleaks | 168 → 168 | 347 → 347 |
| trufflehog | 83 → 83 | 840 → 840 |
| gitlab | 119 → 119 | 162 → 162 |

CPU time, base v0.8.25 and candidate in turns (3 rounds, median; load average 0.6 before, 1.0 after, 8 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 10.317 s | 10.857 s | 1.05 |
| short prompt | 0.677 ms | 0.752 ms | 1.11 |

**Gate: passed**
