## Release gate

Hooks or other runtime files changed (claude-mod/maisecrets-mod.mjs, commands/demo.md, hooks/dispatch.py, maisecrets/cli.py, maisecrets/demo.py, maisecrets/hooks.py, maisecrets/ner_gateway.py, maisecrets/older_versions.py): run the harness and a live test between two sessions with --plugin-dir before the release.

Detection changed (maisecrets/detection/core.py, maisecrets/detection/key_values.py, maisecrets/detection/rules/words/README.md, maisecrets/detection/rules/words/passwords/reserved-words.txt, maisecrets/detection/value_checks.py): Benchmark V3 against the last release, span by span:

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
| gretel-dev-maisecrets-full | 0 | none | 2259 → 2258 |
| gretel-holdout-every25-maisecrets | 0 | none | 23 → 23 |
| gretel-holdout-maisecrets-full | 0 | none | 735 → 735 |
| gretel-val-every25-maisecrets | 0 | none | 36 → 36 |
| gretel-val-maisecrets-full | 0 | none | 799 → 799 |
| llmredactor-dev-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-holdout-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-val-maisecrets-full | 0 | none | 0 → 0 |
| mendeley-dev-maisecrets-full | 0 | none | 1396 → 1396 |
| mendeley-holdout-every25-maisecrets | 0 | none | 20 → 20 |
| mendeley-holdout-maisecrets-full | 0 | none | 457 → 457 |
| mendeley-val-every25-maisecrets | 0 | none | 21 → 21 |
| mendeley-val-maisecrets-full | 0 | none | 420 → 420 |
| nemotron-dev-maisecrets-full | 0 | none | 496 → 496 |
| nemotron-holdout-every25-maisecrets | 0 | none | 6 → 6 |
| nemotron-holdout-maisecrets-full | 0 | none | 193 → 193 |
| nemotron-val-every25-maisecrets | 0 | none | 7 → 7 |
| nemotron-val-maisecrets-full | 0 | none | 172 → 172 |
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
| kingfisher | 357 → 357 | 995 → 995 |
| gitleaks | 80 → 80 | 154 → 154 |
| betterleaks | 170 → 170 | 347 → 347 |
| trufflehog | 83 → 83 | 840 → 840 |
| gitlab | 122 → 122 | 162 → 162 |

CPU time, base v0.9.17 and candidate in turns (3 rounds, median; load average 0.6 before, 1.0 after, 8 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 12.058 s | 12.581 s | 1.04 |
| short prompt | 0.482 ms | 0.542 ms | 1.12 |
| 62 KB one-line JSON with a field label | 0.676 s | 0.74 s | 1.09 |

**Gate: passed**
