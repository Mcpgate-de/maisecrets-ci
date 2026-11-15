## Release gate

Hooks or other runtime files changed (hooks/dispatch.py, maisecrets/home.py, maisecrets/ner_setup.py, maisecrets/settings.py, maisecrets/terms.py, maisecrets/vault.py): run the harness and a live test between two sessions with --plugin-dir before the release.

Detection changed (maisecrets/detection/business.py, maisecrets/detection/key_values.py, maisecrets/detection/personal.py, maisecrets/detection/phone_forms.py, maisecrets/detection/regions.py, maisecrets/detection/remote.py, maisecrets/detection/street_forms.py, maisecrets/detection/user_forms.py): Benchmark V3 against the last release, span by span:

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
| gretel-dev-maisecrets-full | 0 | {'missed->full': 71} | 2878 → 2890 |
| gretel-holdout-every25-maisecrets | 0 | none | 30 → 30 |
| gretel-holdout-maisecrets-full | 0 | {'missed->full': 18} | 912 → 915 |
| gretel-val-every25-maisecrets | 0 | {'missed->full': 1} | 40 → 40 |
| gretel-val-maisecrets-full | 0 | {'missed->full': 19} | 995 → 999 |
| llmredactor-dev-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-holdout-maisecrets-full | 0 | none | 0 → 0 |
| llmredactor-val-maisecrets-full | 0 | none | 0 → 0 |
| mendeley-dev-maisecrets-full | 0 | none | 1310 → 1310 |
| mendeley-holdout-every25-maisecrets | 0 | none | 20 → 20 |
| mendeley-holdout-maisecrets-full | 0 | none | 421 → 421 |
| mendeley-val-every25-maisecrets | 0 | none | 18 → 18 |
| mendeley-val-maisecrets-full | 0 | none | 391 → 391 |
| nemotron-dev-maisecrets-full | 0 | {'missed->full': 1435, 'partial->full': 1} | 526 → 526 |
| nemotron-holdout-every25-maisecrets | 0 | {'missed->full': 23} | 7 → 7 |
| nemotron-holdout-maisecrets-full | 0 | {'missed->full': 479} | 205 → 206 |
| nemotron-val-every25-maisecrets | 0 | {'missed->full': 39} | 7 → 7 |
| nemotron-val-maisecrets-full | 0 | {'missed->full': 495} | 193 → 193 |
| piilo-dev-maisecrets-full | 0 | none | 39 → 39 |
| piilo-holdout-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-holdout-maisecrets-full | 0 | none | 14 → 15 |
| piilo-val-every25-maisecrets | 0 | none | 0 → 0 |
| piilo-val-maisecrets-full | 0 | none | 9 → 9 |
| privy-all-every10-maisecrets | 0 | none | 346 → 346 |
| privy-all-maisecrets-full | 0 | none | 3493 → 3493 |

Holdout V2 recall: 0.6522 → 0.6594

Catalog coverage (rules whose examples are found whole), against docs/coverage.json:

| Catalog | Bare | After a label |
|---|---|---|
| noseyparker | 89 → 89 | 171 → 171 |
| kingfisher | 356 → 356 | 995 → 995 |
| gitleaks | 80 → 80 | 154 → 154 |
| betterleaks | 170 → 170 | 347 → 347 |
| trufflehog | 83 → 83 | 840 → 840 |
| gitlab | 122 → 122 | 162 → 162 |

CPU time, base v0.9.10 and candidate in turns (3 rounds, median; load average 0.6 before, 1.0 after, 8 CPUs):

| Text | Base | Candidate | Ratio |
|---|---:|---:|---:|
| 1 MB tool text | 10.937 s | 10.76 s | 0.98 |
| short prompt | 0.426 ms | 0.409 ms | 0.96 |
| 62 KB one-line JSON with a field label | 0.767 s | 0.713 s | 0.93 |

**Gate: passed**
