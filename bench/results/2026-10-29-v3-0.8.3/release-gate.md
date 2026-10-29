## Release gate

Hooks or other runtime files changed (maisecrets/agent_reports.py, maisecrets/cli.py, maisecrets/destinations.py, maisecrets/home.py, maisecrets/hooks.py, maisecrets/incidents.py, maisecrets/settings.py): run the harness and a live test between two sessions with --plugin-dir before the release.

Detection changed (maisecrets/detection/core.py, maisecrets/detection/own_rules.py, maisecrets/detection/personal.py, maisecrets/detection/registry.py, maisecrets/detection/rules/prefixes.txt, maisecrets/detection/value_checks.py): Benchmark V3 against the last release, span by span:

| Result | Spans worse | Changes | False positives |
|---|---:|---|---|
| aparte-dev-maisecrets-full | 0 | none | 91 → 91 |
| aparte-holdout-maisecrets-full | 0 | {'missed->full': 2} | 183 → 183 |
| aparte-val-maisecrets-full | 0 | {'missed->full': 1} | 69 → 69 |
| bank-dev-maisecrets | 0 | none | 0 → 0 |
| bank-val-maisecrets | 0 | none | 0 → 0 |
| credsweeper-dev-maisecrets-full | 0 | none | 123 → 123 |
| credsweeper-holdout-maisecrets-full | 0 | none | 14 → 14 |
| credsweeper-val-maisecrets-full | 0 | none | 23 → 23 |
| gretel-dev-maisecrets-full | 0 | none | 2814 → 2814 |
| gretel-holdout-every25-maisecrets | 0 | none | 30 → 30 |
| gretel-holdout-maisecrets-full | 0 | none | 903 → 903 |
| gretel-val-every25-maisecrets | 0 | none | 39 → 39 |
| gretel-val-maisecrets-full | 0 | none | 970 → 970 |
| llmredactor-dev-maisecrets-full | 0 | {'partial->full': 2} | 0 → 0 |
| llmredactor-holdout-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-val-maisecrets-full | 0 | none | 0 → 0 |
| mendeley-dev-maisecrets-full | 0 | none | 1310 → 1310 |
| mendeley-holdout-every25-maisecrets | 0 | none | 20 → 20 |
| mendeley-holdout-maisecrets-full | 0 | none | 421 → 421 |
| mendeley-val-every25-maisecrets | 0 | none | 18 → 18 |
| mendeley-val-maisecrets-full | 0 | none | 391 → 391 |
| nemotron-dev-maisecrets-full | 0 | none | 520 → 520 |
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
| privy-all-maisecrets-full | 0 | none | 3482 → 3482 |

Holdout V2 recall: 0.6473 → 0.6473

Catalog coverage (rules whose examples are found whole), against docs/coverage.json:

| Catalog | Bare | After a label |
|---|---|---|
| noseyparker | 88 → 88 | 171 → 171 |
| kingfisher | 352 → 352 | 995 → 995 |
| gitleaks | 80 → 80 | 154 → 154 |
| betterleaks | not compared: catalog at another commit | |
| trufflehog | not compared: catalog at another commit | |
| gitlab | not compared: catalog at another commit | |

CPU time, base v0.8.2 and candidate in turns (3 rounds, median; load average 3.6 before, 3.8 after, 10 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 6.021 s | 5.925 s | 0.98 |
| short prompt | 0.714 ms | 0.779 ms | 1.09 |

**Gate: passed**
