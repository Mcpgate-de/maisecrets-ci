## Release gate

Hooks or other runtime files changed (claude-mod/show-values.mjs, maisecrets/hooks.py, maisecrets/show_values.py, maisecrets/sref_client.py, maisecrets/sref_notes.py, maisecrets/tool_output.py, maisecrets/vault.py): run the harness and a live test between two sessions with --plugin-dir before the release.

Detection changed (maisecrets/detection/contract.py, maisecrets/detection/core.py, maisecrets/detection/encoded_mail.py, maisecrets/detection/own_rules.py, maisecrets/detection/personal.py, maisecrets/detection/regions.py, maisecrets/detection/registry.py, maisecrets/detection/remote.py): Benchmark V3 against the last release, span by span:

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
| gretel-dev-maisecrets-full | 0 | {'partial->full': 16, 'missed->full': 38} | 2867 → 2868 |
| gretel-holdout-every25-maisecrets | 0 | {'missed->full': 1} | 30 → 30 |
| gretel-holdout-maisecrets-full | 0 | {'missed->full': 13, 'partial->full': 3} | 909 → 909 |
| gretel-val-every25-maisecrets | 0 | none | 40 → 40 |
| gretel-val-maisecrets-full | 0 | {'missed->full': 8, 'missed->partial': 1, 'partial->full': 3} | 988 → 988 |
| llmredactor-dev-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-holdout-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-val-maisecrets-full | 0 | none | 0 → 0 |
| mendeley-dev-maisecrets-full | 0 | none | 1310 → 1310 |
| mendeley-holdout-every25-maisecrets | 0 | none | 20 → 20 |
| mendeley-holdout-maisecrets-full | 0 | none | 421 → 421 |
| mendeley-val-every25-maisecrets | 0 | none | 18 → 18 |
| mendeley-val-maisecrets-full | 0 | none | 391 → 391 |
| nemotron-dev-maisecrets-full | 0 | none | 525 → 525 |
| nemotron-holdout-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-holdout-maisecrets-full | 0 | none | 205 → 205 |
| nemotron-val-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-val-maisecrets-full | 0 | none | 193 → 193 |
| piilo-dev-maisecrets-full | 0 | none | 39 → 39 |
| piilo-holdout-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-holdout-maisecrets-full | 0 | none | 14 → 14 |
| piilo-val-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-val-maisecrets-full | 0 | none | 9 → 9 |
| privy-all-every10-maisecrets | 0 | none | 345 → 345 |
| privy-all-maisecrets-full | 0 | none | 3480 → 3480 |

Holdout V2 recall: 0.6522 → 0.6522

Catalog coverage (rules whose examples are found whole), against docs/coverage.json:

| Catalog | Bare | After a label |
|---|---|---|
| noseyparker | 88 → 88 | 171 → 171 |
| kingfisher | 352 → 352 | 995 → 995 |
| gitleaks | 80 → 80 | 154 → 154 |
| betterleaks | 168 → 168 | 347 → 347 |
| trufflehog | 83 → 83 | 840 → 840 |
| gitlab | 119 → 119 | 162 → 162 |

CPU time, base v0.9.3 and candidate in turns (3 rounds, median; load average 0.6 before, 1.0 after, 8 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 10.262 s | 10.099 s | 0.98 |
| short prompt | 0.696 ms | 0.646 ms | 0.93 |

**Gate: passed**
