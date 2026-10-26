# Extended baseline

The version column says 0.7.2 for maisecrets: that is the version in .claude-plugin/plugin.json on `next` before the release moves it. The measured code is the 0.8.2 release candidate, commit `097e68dd`.

Counts only. Holdout rows are totals. Each section stands alone: the new sets are not in the V3 tables or their denominators.

## Benchmark V3: maisecrets against earlier releases

### Against the last release (2026-10-25-v3-0.8.1)

Baseline: `bench/results/2026-10-25-v3-0.8.1`.

| Result | Recall strict | Precision | FP | Spans worse |
|---|---|---|---|---:|
| aparte-dev-maisecrets-full | 0.8152 → 0.8152 | 0.9591 → 0.9591 | 16 → 16 | 0 |
| aparte-holdout-maisecrets-full | 0.3308 → 0.3308 | 1.0 → 0.9924 | 0 → 2 | 0 |
| aparte-val-maisecrets-full | 0.7973 → 0.8007 | 0.9672 → 0.9673 | 8 → 8 | 0 |
| bank-dev-maisecrets | 0.9677 → 0.9598 | 1.0 → 1.0 | 0 → 0 | not comparable |
| bank-val-maisecrets | 0.7059 → 0.7059 | 1.0 → 1.0 | 0 → 0 | 0 |
| credsweeper-dev-maisecrets-full | 0.7159 → 0.7159 | 0.7925 → 0.7875 | 66 → 68 | 0 |
| credsweeper-holdout-maisecrets-full | 0.6709 → 0.6709 | 0.8462 → 0.8462 | 10 → 10 | 0 |
| credsweeper-val-maisecrets-full | 0.8846 → 0.8846 | 0.8915 → 0.8779 | 14 → 16 | 0 |
| gretel-dev-maisecrets-full | 0.2925 → 0.3176 | 0.9025 → 0.9011 | 2550 → 2814 | 0 |
| gretel-holdout-every25-maisecrets | 0.2957 → 0.3202 | 0.9164 → 0.9169 | 28 → 30 | 0 |
| gretel-holdout-maisecrets-full | 0.2801 → 0.3054 | 0.9047 → 0.9028 | 811 → 903 | 0 |
| gretel-val-every25-maisecrets | 0.2966 → 0.3122 | 0.9124 → 0.9053 | 34 → 39 | 0 |
| gretel-val-maisecrets-full | 0.2827 → 0.3059 | 0.8959 → 0.8933 | 870 → 970 | 0 |
| llmredactor-dev-maisecrets-full | 0.9103 → 0.9103 | 1.0 → 1.0 | 0 → 0 | 0 |
| llmredactor-holdout-maisecrets-full | 0.9076 → 0.9076 | 1.0 → 1.0 | 0 → 0 | 0 |
| llmredactor-val-maisecrets-full | 0.9222 → 0.9222 | 1.0 → 1.0 | 0 → 0 | 0 |
| mendeley-dev-maisecrets-full | 0.6857 → 0.7019 | 0.9893 → 0.9881 | 1150 → 1310 | 0 |
| mendeley-holdout-every25-maisecrets | 0.6758 → 0.689 | 0.9889 → 0.9879 | 18 → 20 | 0 |
| mendeley-holdout-maisecrets-full | 0.6831 → 0.6988 | 0.9898 → 0.9887 | 371 → 421 | 0 |
| mendeley-val-every25-maisecrets | 0.69 → 0.7063 | 0.9897 → 0.988 | 15 → 18 | 0 |
| mendeley-val-maisecrets-full | 0.6867 → 0.7024 | 0.9906 → 0.9894 | 338 → 391 | 0 |
| nemotron-dev-maisecrets-full | 0.6086 → 0.625 | 0.9957 → 0.9958 | 511 → 516 | 0 |
| nemotron-holdout-every25-maisecrets | 0.5931 → 0.6095 | 0.9958 → 0.996 | 7 → 7 | 0 |
| nemotron-holdout-maisecrets-full | 0.6044 → 0.621 | 0.995 → 0.9951 | 203 → 205 | 0 |
| nemotron-val-every25-maisecrets | 0.6043 → 0.6209 | 0.9958 → 0.9959 | 7 → 7 | 0 |
| nemotron-val-maisecrets-full | 0.6116 → 0.6281 | 0.9952 → 0.9953 | 190 → 193 | 0 |
| piilo-dev-maisecrets-full | 0.0985 → 0.0985 | 0.9247 → 0.9247 | 7 → 7 | 0 |
| piilo-holdout-every25-maisecrets | – → – | – → – | 0 → 0 | 0 |
| piilo-holdout-maisecrets-full | 0.087 → 0.087 | 0.9655 → 0.9655 | 1 → 1 | 0 |
| piilo-val-every25-maisecrets | – → – | 1.0 → 1.0 | 0 → 0 | 0 |
| piilo-val-maisecrets-full | 0.0897 → 0.0897 | 0.9 → 0.9 | 3 → 3 | 0 |
| privy-all-every10-maisecrets | 0.2358 → 0.2461 | 0.9753 → 0.9763 | 7 → 7 | 0 |
| privy-all-maisecrets-full | 0.2496 → 0.2576 | 0.9477 → 0.9489 | 166 → 167 | 0 |

### Against the published 0.7.3 baseline (2026-10-21-v3)

Baseline: `bench/results/2026-10-21-v3/run`.

| Result | Recall strict | Precision | FP | Spans worse |
|---|---|---|---|---:|
| bank-dev-maisecrets | 0.9355 → 0.9598 | 1.0 → 1.0 | 0 → 0 | not comparable |
| bank-val-maisecrets | 0.7059 → 0.7059 | 1.0 → 1.0 | 0 → 0 | 0 |
| gretel-dev-maisecrets-full | 0.2884 → 0.3176 | 0.9098 → 0.9011 | 2307 → 2814 | 0 |
| gretel-holdout-every25-maisecrets | 0.2937 → 0.3202 | 0.9159 → 0.9169 | 28 → 30 | 0 |
| gretel-holdout-maisecrets-full | 0.2753 → 0.3054 | 0.9103 → 0.9028 | 746 → 903 | 0 |
| gretel-val-every25-maisecrets | 0.2931 → 0.3122 | 0.9115 → 0.9053 | 34 → 39 | 0 |
| gretel-val-maisecrets-full | 0.2781 → 0.3059 | 0.9011 → 0.8933 | 809 → 970 | 0 |
| mendeley-dev-maisecrets-full | 0.6857 → 0.7019 | 0.9893 → 0.9881 | 1150 → 1310 | 0 |
| mendeley-holdout-every25-maisecrets | 0.6758 → 0.689 | 0.9889 → 0.9879 | 18 → 20 | 0 |
| mendeley-holdout-maisecrets-full | 0.6831 → 0.6988 | 0.9898 → 0.9887 | 371 → 421 | 0 |
| mendeley-val-every25-maisecrets | 0.69 → 0.7063 | 0.9897 → 0.988 | 15 → 18 | 0 |
| mendeley-val-maisecrets-full | 0.6867 → 0.7024 | 0.9906 → 0.9894 | 338 → 391 | 0 |
| nemotron-dev-maisecrets-full | 0.5878 → 0.625 | 0.9957 → 0.9958 | 504 → 516 | 0 |
| nemotron-holdout-every25-maisecrets | 0.5731 → 0.6095 | 0.9957 → 0.996 | 7 → 7 | 0 |
| nemotron-holdout-maisecrets-full | 0.5856 → 0.621 | 0.9948 → 0.9951 | 203 → 205 | 0 |
| nemotron-val-every25-maisecrets | 0.5792 → 0.6209 | 0.9956 → 0.9959 | 7 → 7 | 0 |
| nemotron-val-maisecrets-full | 0.5917 → 0.6281 | 0.9952 → 0.9953 | 187 → 193 | 0 |
| piilo-dev-maisecrets-full | 0.0985 → 0.0985 | 0.9247 → 0.9247 | 7 → 7 | 0 |
| piilo-holdout-every25-maisecrets | – → – | – → – | 0 → 0 | 0 |
| piilo-holdout-maisecrets-full | 0.087 → 0.087 | 0.9655 → 0.9655 | 1 → 1 | 0 |
| piilo-val-every25-maisecrets | – → – | 1.0 → 1.0 | 0 → 0 | 0 |
| piilo-val-maisecrets-full | 0.0897 → 0.0897 | 0.9 → 0.9 | 3 → 3 | 0 |
| privy-all-every10-maisecrets | 0.235 → 0.2461 | 0.9752 → 0.9763 | 7 → 7 | 0 |
| privy-all-maisecrets-full | 0.2485 → 0.2576 | 0.9474 → 0.9489 | 166 → 167 | 0 |

## Benchmark V3: the other scanners (reused only when unchanged)

| Result | Scanner | Status | Level | Cases | Spans | Recall strict | Precision | FP | Snippet level |
|---|---|---|---|---:|---:|---|---|---:|---|
| bank-dev-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| bank-dev-detect_secrets.json | detect-secrets 1.5.0 | measured | span | 120 | 54 | 0.3889 | 1.0 | 0 | – |
| bank-dev-pii_anon.json | pii-anon 1.7.0rc1 | measured | span | 120 | 120 | 0.625 | 0.6062 | 63 | – |
| bank-dev-preserve.json | preserve 0.6.1 | measured | span | 120 | 174 | 0.6897 | 0.8089 | 30 | – |
| bank-dev-presidio.json | presidio 2.2.364 | measured | span | 120 | 120 | 0.7333 | 0.8211 | 22 | – |
| bank-dev-secret_scan.json | secret-scan 0.4.2 | measured | span | 120 | 54 | 0.7222 | 0.8636 | 9 | – |
| bank-val-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| bank-val-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/bank-val-detect_secrets.json.gz | span | 33 | 27 | – | 1.0 | 0 | – |
| bank-val-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/bank-val-pii_anon.json.gz | span | 33 | 24 | – | 0.625 | 12 | – |
| bank-val-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/bank-val-preserve.json.gz | span | 33 | 51 | 0.5882 | 0.7692 | 9 | – |
| bank-val-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/bank-val-presidio.json.gz | span | 33 | 24 | – | 0.617 | 18 | – |
| bank-val-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/bank-val-secret_scan.json.gz | span | 33 | 27 | – | 1.0 | 0 | – |
| catalogs-all-every1-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| catalogs-all-every1-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/catalogs-all-every1-detect_secrets.json.gz | span | 11902 | 11902 | 0.2354 | 1.0 | 0 | – |
| catalogs-all-every1-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/catalogs-all-every1-pii_anon.json.gz | span | 11902 | – | – | – | 0 | – |
| catalogs-all-every1-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/catalogs-all-every1-preserve.json.gz | span | 11902 | 11902 | 0.0571 | 1.0 | 0 | – |
| catalogs-all-every1-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/catalogs-all-every1-presidio.json.gz | span | 11902 | – | – | 0.0 | 177 | – |
| catalogs-all-every1-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/catalogs-all-every1-secret_scan.json.gz | span | 11902 | 11902 | 0.0729 | 1.0 | 0 | – |
| gretel-holdout-every25-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| gretel-holdout-every25-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/gretel-holdout-every25-detect_secrets.json.gz | span | 336 | 9 | – | 1.0 | 0 | – |
| gretel-holdout-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/gretel-holdout-every25-pii_anon.json.gz | span | 336 | 1009 | 0.4024 | 0.256 | 2092 | – |
| gretel-holdout-every25-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/gretel-holdout-every25-preserve.json.gz | span | 336 | 1018 | 0.4253 | 0.2117 | 2547 | – |
| gretel-holdout-every25-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/gretel-holdout-every25-presidio.json.gz | span | 336 | 1009 | 0.4609 | 0.2705 | 2225 | – |
| gretel-holdout-every25-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/gretel-holdout-every25-secret_scan.json.gz | span | 336 | 9 | – | 1.0 | 0 | – |
| gretel-val-every25-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| gretel-val-every25-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/gretel-val-every25-detect_secrets.json.gz | span | 334 | 12 | – | 0.0 | 2 | – |
| gretel-val-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/gretel-val-every25-pii_anon.json.gz | span | 334 | 1141 | 0.4294 | 0.2768 | 2012 | – |
| gretel-val-every25-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/gretel-val-every25-preserve.json.gz | span | 334 | 1153 | 0.412 | 0.2465 | 2461 | – |
| gretel-val-every25-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/gretel-val-every25-presidio.json.gz | span | 334 | 1141 | 0.4531 | 0.2727 | 2398 | – |
| gretel-val-every25-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/gretel-val-every25-secret_scan.json.gz | span | 334 | 12 | – | 1.0 | 0 | – |
| mendeley-holdout-every25-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| mendeley-holdout-every25-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/mendeley-holdout-every25-detect_secrets.json.gz | span | 398 | – | – | – | 0 | – |
| mendeley-holdout-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/mendeley-holdout-every25-pii_anon.json.gz | span | 398 | 2360 | 0.6008 | 0.6421 | 1320 | – |
| mendeley-holdout-every25-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/mendeley-holdout-every25-preserve.json.gz | span | 398 | 2360 | 0.6665 | 0.8213 | 411 | – |
| mendeley-holdout-every25-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/mendeley-holdout-every25-presidio.json.gz | span | 398 | 2360 | 0.6644 | 0.8997 | 430 | – |
| mendeley-holdout-every25-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/mendeley-holdout-every25-secret_scan.json.gz | span | 398 | – | – | – | 0 | – |
| mendeley-val-every25-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| mendeley-val-every25-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/mendeley-val-every25-detect_secrets.json.gz | span | 362 | – | – | – | 0 | – |
| mendeley-val-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/mendeley-val-every25-pii_anon.json.gz | span | 362 | 2084 | 0.6099 | 0.658 | 1089 | – |
| mendeley-val-every25-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/mendeley-val-every25-preserve.json.gz | span | 362 | 2084 | 0.666 | 0.8127 | 380 | – |
| mendeley-val-every25-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/mendeley-val-every25-presidio.json.gz | span | 362 | 2084 | 0.6766 | 0.8952 | 397 | – |
| mendeley-val-every25-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/mendeley-val-every25-secret_scan.json.gz | span | 362 | – | – | – | 0 | – |
| nemotron-holdout-every25-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| nemotron-holdout-every25-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/nemotron-holdout-every25-detect_secrets.json.gz | span | 816 | 92 | 0.0217 | 1.0 | 0 | – |
| nemotron-holdout-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/nemotron-holdout-every25-pii_anon.json.gz | span | 816 | 2909 | 0.7439 | 0.3263 | 3905 | – |
| nemotron-holdout-every25-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/nemotron-holdout-every25-preserve.json.gz | span | 816 | 3001 | 0.6475 | 0.8543 | 290 | – |
| nemotron-holdout-every25-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/nemotron-holdout-every25-presidio.json.gz | span | 816 | 2909 | 0.7384 | 0.929 | 172 | – |
| nemotron-holdout-every25-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/nemotron-holdout-every25-secret_scan.json.gz | span | 816 | 92 | 0.1413 | 0.9286 | 1 | – |
| nemotron-val-every25-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| nemotron-val-every25-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/nemotron-val-every25-detect_secrets.json.gz | span | 834 | 118 | 0.0847 | 1.0 | 0 | – |
| nemotron-val-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/nemotron-val-every25-pii_anon.json.gz | span | 834 | 2781 | 0.7659 | 0.2966 | 4440 | – |
| nemotron-val-every25-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/nemotron-val-every25-preserve.json.gz | span | 834 | 2899 | 0.6368 | 0.825 | 358 | – |
| nemotron-val-every25-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/nemotron-val-every25-presidio.json.gz | span | 834 | 2781 | 0.7224 | 0.9277 | 173 | – |
| nemotron-val-every25-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/nemotron-val-every25-secret_scan.json.gz | span | 834 | 118 | 0.1186 | 1.0 | 0 | – |
| piilo-holdout-every25-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| piilo-holdout-every25-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/piilo-holdout-every25-detect_secrets.json.gz | span | 46 | – | – | – | 0 | – |
| piilo-holdout-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/piilo-holdout-every25-pii_anon.json.gz | span | 46 | 8 | – | 0.024 | 203 | – |
| piilo-holdout-every25-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/piilo-holdout-every25-preserve.json.gz | span | 46 | 8 | – | 0.2188 | 25 | – |
| piilo-holdout-every25-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/piilo-holdout-every25-presidio.json.gz | span | 46 | 8 | – | 0.1739 | 38 | – |
| piilo-holdout-every25-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/piilo-holdout-every25-secret_scan.json.gz | span | 46 | – | – | – | 0 | – |
| piilo-val-every25-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| piilo-val-every25-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/piilo-val-every25-detect_secrets.json.gz | span | 55 | – | – | – | 0 | – |
| piilo-val-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/piilo-val-every25-pii_anon.json.gz | span | 55 | 8 | – | 0.0285 | 239 | – |
| piilo-val-every25-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/piilo-val-every25-preserve.json.gz | span | 55 | 8 | – | 0.2 | 24 | – |
| piilo-val-every25-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/piilo-val-every25-presidio.json.gz | span | 55 | 8 | – | 0.14 | 43 | – |
| piilo-val-every25-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/piilo-val-every25-secret_scan.json.gz | span | 55 | – | – | – | 0 | – |
| privy-all-every10-ai_gateway.json | ai_gateway – | not run: BENCH_GATEWAY_PYTHON is not set | span | – | – | – | – | – | – |
| privy-all-every10-detect_secrets.json | detect-secrets 1.5.0 | reused from bench/results/2026-10-21-v3/run/privy-all-every10-detect_secrets.json.gz | span | 2816 | 90 | 0.2778 | 0.3788 | 41 | – |
| privy-all-every10-pii_anon.json | pii-anon 1.7.0rc1 | reused from bench/results/2026-10-21-v3/run/privy-all-every10-pii_anon.json.gz | span | 2816 | 1076 | 0.2862 | 0.9359 | 22 | – |
| privy-all-every10-preserve.json | preserve 0.6.1 | reused from bench/results/2026-10-21-v3/run/privy-all-every10-preserve.json.gz | span | 2816 | 1166 | 0.1921 | 0.4176 | 350 | – |
| privy-all-every10-presidio.json | presidio 2.2.364 | reused from bench/results/2026-10-21-v3/run/privy-all-every10-presidio.json.gz | span | 2816 | 1076 | 0.473 | 0.5266 | 1060 | – |
| privy-all-every10-secret_scan.json | secret-scan 0.4.2 | reused from bench/results/2026-10-21-v3/run/privy-all-every10-secret_scan.json.gz | span | 2816 | 90 | 0.0 | – | 0 | – |

## New PII sets: nym and DialogPII

| Result | Scanner | Status | Level | Cases | Spans | Recall strict | Precision | FP | Snippet level |
|---|---|---|---|---:|---:|---|---|---:|---|
| nym-dev-every5-maisecrets.json | maisecrets 0.7.2 | measured | span | 99727 | 301008 | 0.1872 | 0.994 | 339 | – |
| nym-dev-every25-maisecrets.json | maisecrets 0.7.2 | measured | span | 20001 | 60064 | 0.1869 | 0.9949 | 57 | – |
| nym-dev-every25-presidio.json | presidio 2.2.364 | reused from <scratch>/xb-stage/results/nym-dev-every25-presidio.json | span | 20001 | 58575 | 0.5324 | 0.5971 | 30447 | – |
| nym-dev-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from <scratch>/xb-stage/results/nym-dev-every25-pii_anon.json | span | 20001 | 58575 | 0.424 | 0.8936 | 2733 | – |
| dialogpii-dev-full-maisecrets.json | maisecrets 0.7.2 | measured | span | 1980 | 24733 | 0.0343 | 1.0 | 0 | – |
| dialogpii-dev-full-presidio.json | presidio 2.2.364 | reused from <scratch>/xb-stage/results/dialogpii-dev-full-presidio.json | span | 1980 | 24733 | 0.5811 | 0.1227 | 116891 | – |
| dialogpii-dev-full-pii_anon.json | pii-anon 1.7.0rc1 | reused from <scratch>/xb-stage/results/dialogpii-dev-full-pii_anon.json | span | 1980 | 24733 | 0.3457 | 0.6503 | 5087 | – |
| nym-val-every5-maisecrets.json | maisecrets 0.7.2 | measured | span | 30288 | 101550 | 0.1862 | 0.9941 | 111 | – |
| nym-val-every25-maisecrets.json | maisecrets 0.7.2 | measured | span | 6192 | 20784 | 0.1846 | 0.9963 | 14 | – |
| nym-val-every25-presidio.json | presidio 2.2.364 | reused from <scratch>/xb-stage/results/nym-val-every25-presidio.json | span | 6192 | 20300 | 0.5366 | 0.5876 | 10770 | – |
| nym-val-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from <scratch>/xb-stage/results/nym-val-every25-pii_anon.json | span | 6192 | 20300 | 0.4183 | 0.887 | 999 | – |
| dialogpii-val-full-maisecrets.json | maisecrets 0.7.2 | measured | span | 616 | 7180 | 0.0311 | 1.0 | 0 | – |
| dialogpii-val-full-presidio.json | presidio 2.2.364 | reused from <scratch>/xb-stage/results/dialogpii-val-full-presidio.json | span | 616 | 7180 | 0.5811 | 0.1258 | 33242 | – |
| dialogpii-val-full-pii_anon.json | pii-anon 1.7.0rc1 | reused from <scratch>/xb-stage/results/dialogpii-val-full-pii_anon.json | span | 616 | 7180 | 0.3677 | 0.6399 | 1618 | – |
| nym-holdout-every5-maisecrets.json | maisecrets 0.7.2 | measured | span | 31294 | 114963 | 0.1863 | 0.9954 | 97 | – |
| nym-holdout-every25-maisecrets.json | maisecrets 0.7.2 | measured | span | 6211 | 22850 | 0.1859 | 0.996 | 17 | – |
| nym-holdout-every25-presidio.json | presidio 2.2.364 | reused from <scratch>/xb-stage/results/nym-holdout-every25-presidio.json | span | 6211 | 22383 | 0.521 | 0.59 | 11649 | – |
| nym-holdout-every25-pii_anon.json | pii-anon 1.7.0rc1 | reused from <scratch>/xb-stage/results/nym-holdout-every25-pii_anon.json | span | 6211 | 22383 | 0.4158 | 0.8569 | 1439 | – |
| dialogpii-holdout-full-maisecrets.json | maisecrets 0.7.2 | measured | span | 638 | 7993 | 0.04 | 1.0 | 0 | – |
| dialogpii-holdout-full-presidio.json | presidio 2.2.364 | reused from <scratch>/xb-stage/results/dialogpii-holdout-full-presidio.json | span | 638 | 7993 | 0.5995 | 0.1304 | 36994 | – |
| dialogpii-holdout-full-pii_anon.json | pii-anon 1.7.0rc1 | reused from <scratch>/xb-stage/results/dialogpii-holdout-full-pii_anon.json | span | 638 | 7993 | 0.4235 | 0.6466 | 2010 | – |
| nym-dev-every125-maisecrets.json | maisecrets 0.7.2 | measured | span | 3894 | 11677 | 0.1877 | 0.9959 | 9 | – |
| nym-dev-every125-preserve.json | preserve 0.6.1 | reused from <scratch>/xb-stage/results/nym-dev-every125-preserve.json | span | 3894 | 11677 | 0.4678 | 0.5094 | 5750 | – |
| nym-val-every125-maisecrets.json | maisecrets 0.7.2 | measured | span | 1225 | 4162 | 0.1884 | 0.9961 | 3 | – |
| nym-val-every125-preserve.json | preserve 0.6.1 | reused from <scratch>/xb-stage/results/nym-val-every125-preserve.json | span | 1225 | 4162 | 0.4563 | 0.5307 | 1865 | – |
| nym-holdout-every125-maisecrets.json | maisecrets 0.7.2 | measured | span | 1239 | 4583 | 0.1859 | 0.9976 | 2 | – |
| nym-holdout-every125-preserve.json | preserve 0.6.1 | reused from <scratch>/xb-stage/results/nym-holdout-every125-preserve.json | span | 1239 | 4583 | 0.4615 | 0.4904 | 2329 | – |
| dialogpii-dev-every5-maisecrets.json | maisecrets 0.7.2 | measured | span | 366 | 4638 | 0.0375 | 1.0 | 0 | – |
| dialogpii-dev-every5-preserve.json | preserve 0.6.1 | reused from <scratch>/xb-stage/results/dialogpii-dev-every5-preserve.json | span | 366 | 4638 | 0.5017 | 0.1046 | 22454 | – |
| dialogpii-val-every5-maisecrets.json | maisecrets 0.7.2 | measured | span | 106 | 1288 | 0.0287 | 1.0 | 0 | – |
| dialogpii-val-every5-preserve.json | preserve 0.6.1 | reused from <scratch>/xb-stage/results/dialogpii-val-every5-preserve.json | span | 106 | 1288 | 0.5256 | 0.1111 | 6154 | – |
| dialogpii-holdout-every5-maisecrets.json | maisecrets 0.7.2 | measured | span | 124 | 1460 | 0.0507 | 1.0 | 0 | – |
| dialogpii-holdout-every5-preserve.json | preserve 0.6.1 | reused from <scratch>/xb-stage/results/dialogpii-holdout-every5-preserve.json | span | 124 | 1460 | 0.5658 | 0.1072 | 7759 | – |

## Structured corpus (targeted regression benchmark: written for the known gaps of maisecrets, not independent evidence of competitive superiority (docs/BENCHMARK-STRUCTURED.md))

| Result | Scanner | Status | Level | Cases | Spans | Recall strict | Precision | FP | Snippet level |
|---|---|---|---|---:|---:|---|---|---:|---|
| structured-dev-full-maisecrets.json | maisecrets 0.7.2 | measured | span | 2201 | 11490 | 0.6348 | 0.9526 | 370 | – |
| structured-dev-full-presidio.json | presidio 2.2.364 | reused from <scratch>/xb-stage/results/structured-dev-full-presidio.json | span | 2201 | 10071 | 0.5235 | 0.6217 | 5192 | – |
| structured-dev-full-preserve.json | preserve 0.6.1 | reused from <scratch>/xb-stage/results/structured-dev-full-preserve.json | span | 2201 | 11490 | 0.445 | 0.6589 | 3073 | – |
| structured-dev-full-pii_anon.json | pii-anon 1.7.0rc1 | reused from <scratch>/xb-stage/results/structured-dev-full-pii_anon.json | span | 2201 | 10071 | 0.4485 | 0.6351 | 2957 | – |
| structured-val-full-maisecrets.json | maisecrets 0.7.2 | measured | span | 1543 | 8758 | 0.619 | 0.962 | 218 | – |
| structured-val-full-presidio.json | presidio 2.2.364 | reused from <scratch>/xb-stage/results/structured-val-full-presidio.json | span | 1543 | 7753 | 0.5217 | 0.6598 | 3451 | – |
| structured-val-full-preserve.json | preserve 0.6.1 | reused from <scratch>/xb-stage/results/structured-val-full-preserve.json | span | 1543 | 8758 | 0.4404 | 0.6731 | 2189 | – |
| structured-val-full-pii_anon.json | pii-anon 1.7.0rc1 | reused from <scratch>/xb-stage/results/structured-val-full-pii_anon.json | span | 1543 | 7753 | 0.4474 | 0.663 | 2020 | – |
| structured-b-holdout-full-maisecrets.json | maisecrets 0.7.2 | measured | span | 2000 | 8034 | 0.5286 | 0.9797 | 92 | – |
| structured-b-holdout-full-presidio.json | presidio 2.2.364 | reused from <scratch>/xb-stage/results/structured-b-holdout-full-presidio.json | span | 2000 | 6139 | 0.555 | 0.6991 | 2796 | – |
| structured-b-holdout-full-preserve.json | preserve 0.6.1 | reused from <scratch>/xb-stage/results/structured-b-holdout-full-preserve.json | span | 2000 | 8034 | 0.5307 | 0.7414 | 1783 | – |
| structured-b-holdout-full-pii_anon.json | pii-anon 1.7.0rc1 | reused from <scratch>/xb-stage/results/structured-b-holdout-full-pii_anon.json | span | 2000 | 6139 | 0.4787 | 0.5336 | 3003 | – |

Label: targeted regression benchmark: written for the known gaps of maisecrets, not independent evidence of competitive superiority (docs/BENCHMARK-STRUCTURED.md).

## New secret sets: GitHub issues and the catalog examples

| Result | Scanner | Status | Level | Cases | Spans | Recall strict | Precision | FP | Snippet level |
|---|---|---|---|---:|---:|---|---|---:|---|
| ghissues-dev-full-maisecrets.json | maisecrets 0.7.2 | measured | snippet + span | 25387 | 3944 | 0.714 | 0.0728 | 36498 | precision 0.6682, precision_secret_findings 0.734 |
| ghissues-dev-full-detect_secrets.json | detect-secrets 1.5.0 | reused from <scratch>/xb-stage/results/ghissues-dev-full-detect_secrets.json | snippet + span | 25387 | 3944 | 0.2936 | 0.123 | 10348 | precision 0.4956, precision_secret_findings 0.4956 |
| ghissues-dev-full-gitleaks.json | gitleaks 8.30.1 | reused from <scratch>/xb-stage/results/ghissues-dev-full-gitleaks.json | snippet + span | 25387 | 3944 | 0.5274 | 0.4414 | 2613 | precision 0.9065, precision_secret_findings 0.9065 |
| ghissues-dev-full-betterleaks.json | betterleaks 1.9.0 | reused from <scratch>/xb-stage/results/ghissues-dev-full-betterleaks.json | snippet + span | 25387 | 3944 | 0.5454 | 0.2456 | 6650 | precision 0.6547, precision_secret_findings 0.6547 |
| ghissues-dev-full-trufflehog.json | trufflehog 3.99.2 | reused from <scratch>/xb-stage/results/ghissues-dev-full-trufflehog.json | snippet + span | 25387 | 3944 | 0.1164 | 0.2815 | 1205 | precision 0.6851, precision_secret_findings 0.6851 |
| ghissues-dev-full-kingfisher.json | kingfisher 2.11.1 | reused from <scratch>/xb-stage/results/ghissues-dev-full-kingfisher.json | snippet + span | 25387 | 3944 | 0.2028 | 0.2875 | 1965 | precision 0.81, precision_secret_findings 0.81 |
| ghissues-dev-full-kingfisher1.json | kingfisher 1.113.0 | reused from <scratch>/xb-stage/results/ghissues-dev-full-kingfisher1.json | snippet + span | 25387 | 3944 | 0.2896 | 0.2992 | 3033 | precision 0.8176, precision_secret_findings 0.8176 |
| ghissues-dev-full-noseyparker.json | noseyparker 0.24.0 | reused from <scratch>/xb-stage/results/ghissues-dev-full-noseyparker.json | snippet + span | 25387 | 3944 | 0.2944 | 0.2041 | 4760 | precision 0.6075, precision_secret_findings 0.6075 |
| ghissues-holdout-full-maisecrets.json | maisecrets 0.7.2 | measured | snippet + span | 25401 | 3761 | 0.7198 | 0.0674 | 37956 | precision 0.6514, precision_secret_findings 0.7123 |
| ghissues-holdout-full-detect_secrets.json | detect-secrets 1.5.0 | reused from <scratch>/xb-stage/results/ghissues-holdout-full-detect_secrets.json | snippet + span | 25401 | 3761 | 0.2943 | 0.1201 | 10480 | precision 0.4834, precision_secret_findings 0.4834 |
| ghissues-holdout-full-gitleaks.json | gitleaks 8.30.1 | reused from <scratch>/xb-stage/results/ghissues-holdout-full-gitleaks.json | snippet + span | 25401 | 3761 | 0.5323 | 0.4061 | 2886 | precision 0.8895, precision_secret_findings 0.8895 |
| ghissues-holdout-full-betterleaks.json | betterleaks 1.9.0 | reused from <scratch>/xb-stage/results/ghissues-holdout-full-betterleaks.json | snippet + span | 25401 | 3761 | 0.5456 | 0.2293 | 6890 | precision 0.6321, precision_secret_findings 0.6321 |
| ghissues-holdout-full-trufflehog.json | trufflehog 3.99.2 | reused from <scratch>/xb-stage/results/ghissues-holdout-full-trufflehog.json | snippet + span | 25401 | 3761 | 0.1231 | 0.2263 | 1586 | precision 0.66, precision_secret_findings 0.66 |
| ghissues-holdout-full-kingfisher.json | kingfisher 2.11.1 | reused from <scratch>/xb-stage/results/ghissues-holdout-full-kingfisher.json | snippet + span | 25401 | 3761 | 0.2175 | 0.3481 | 1485 | precision 0.7891, precision_secret_findings 0.7891 |
| ghissues-holdout-full-kingfisher1.json | kingfisher 1.113.0 | reused from <scratch>/xb-stage/results/ghissues-holdout-full-kingfisher1.json | snippet + span | 25401 | 3761 | 0.2965 | 0.3231 | 2719 | precision 0.7833, precision_secret_findings 0.7833 |
| ghissues-holdout-full-noseyparker.json | noseyparker 0.24.0 | reused from <scratch>/xb-stage/results/ghissues-holdout-full-noseyparker.json | snippet + span | 25401 | 3761 | 0.3111 | 0.206 | 4819 | precision 0.5905, precision_secret_findings 0.5905 |
| catalogs-all-full-maisecrets.json | maisecrets 0.7.2 | measured | span | 11902 | 11902 | 0.6174 | 1.0 | 0 | – |
| catalogs-all-full-detect_secrets.json | detect-secrets 1.5.0 | reused from <scratch>/xb-stage/results/catalogs-all-full-detect_secrets.json | span | 11902 | 11902 | 0.2354 | 1.0 | 0 | – |
| catalogs-all-full-gitleaks.json | gitleaks 8.30.1 | reused from <scratch>/xb-stage/results/catalogs-all-full-gitleaks.json | span | 11902 | 11902 | 0.451 | 1.0 | 0 | – |
| catalogs-all-full-betterleaks.json | betterleaks 1.9.0 | reused from <scratch>/xb-stage/results/catalogs-all-full-betterleaks.json | span | 11902 | 11902 | 0.4613 | 1.0 | 0 | – |
| catalogs-all-full-trufflehog.json | trufflehog 3.99.2 | reused from <scratch>/xb-stage/results/catalogs-all-full-trufflehog.json | span | 11902 | 11902 | 0.1233 | 1.0 | 0 | – |
| catalogs-all-full-kingfisher.json | kingfisher 2.11.1 | reused from <scratch>/xb-stage/results/catalogs-all-full-kingfisher.json | span | 11902 | 11902 | 0.219 | 1.0 | 0 | – |
| catalogs-all-full-kingfisher1.json | kingfisher 1.113.0 | reused from <scratch>/xb-stage/results/catalogs-all-full-kingfisher1.json | span | 11902 | 11902 | 0.2776 | 1.0 | 0 | – |
| catalogs-all-full-noseyparker.json | noseyparker 0.24.0 | reused from <scratch>/xb-stage/results/catalogs-all-full-noseyparker.json | span | 11902 | 11902 | 0.0981 | 1.0 | 0 | – |
| catalogs-example-all-full-maisecrets.json | maisecrets 0.7.2 | measured | span | 5951 | 5951 | 0.638 | 0.9675 | 135 | – |
| catalogs-example-all-full-detect_secrets.json | detect-secrets 1.5.0 | reused from <scratch>/xb-stage/results/catalogs-example-all-full-detect_secrets.json | span | 5951 | 5951 | 0.2769 | 0.9543 | 120 | – |
| catalogs-example-all-full-gitleaks.json | gitleaks 8.30.1 | reused from <scratch>/xb-stage/results/catalogs-example-all-full-gitleaks.json | span | 5951 | 5951 | 0.4841 | 0.9763 | 73 | – |
| catalogs-example-all-full-betterleaks.json | betterleaks 1.9.0 | reused from <scratch>/xb-stage/results/catalogs-example-all-full-betterleaks.json | span | 5951 | 5951 | 0.5108 | 0.9688 | 103 | – |
| catalogs-example-all-full-trufflehog.json | trufflehog 3.99.2 | reused from <scratch>/xb-stage/results/catalogs-example-all-full-trufflehog.json | span | 5951 | 5951 | 0.1875 | 0.9754 | 31 | – |
| catalogs-example-all-full-kingfisher.json | kingfisher 2.11.1 | reused from <scratch>/xb-stage/results/catalogs-example-all-full-kingfisher.json | span | 5951 | 5951 | 0.3697 | 0.988 | 28 | – |
| catalogs-example-all-full-kingfisher1.json | kingfisher 1.113.0 | reused from <scratch>/xb-stage/results/catalogs-example-all-full-kingfisher1.json | span | 5951 | 5951 | 0.5034 | 0.9753 | 79 | – |
| catalogs-example-all-full-noseyparker.json | noseyparker 0.24.0 | reused from <scratch>/xb-stage/results/catalogs-example-all-full-noseyparker.json | span | 5951 | 5951 | 0.2349 | 0.8802 | 221 | – |

## Speed and resources

Machine: Apple M5, 10 CPUs, 32.0 GB RAM, macOS 27.2. Load average 2.8 at the start, 2.7 at the end. One scanner after the other; peak RSS of the scanner's process tree.

| Scanner | Text | Mode | Cold start ms | Warm median ms | Warm p95 ms | Peak RSS MB |
|---|---|---|---:|---:|---:|---:|
| maisecrets | prompt | warm process | 58.2 | 0.734 | 0.767 | 28.6 |
| maisecrets | tool_10kb | warm process | 156.3 | 46.564 | 47.088 | 30.4 |
| maisecrets | tool_1mb | warm process | 8424.5 | 5246.898 | 5246.898 | 739.6 |
| maisecrets_ner | – | not installed here (its environment variable is not set) | | | | |
| betterleaks | prompt | process per run | 213.4 | 174.197 | 177.879 | 49.7 |
| betterleaks | tool_10kb | process per run | 169.9 | 172.922 | 173.306 | 49.8 |
| betterleaks | tool_1mb | process per run | 332.3 | 321.898 | 320.597 | 65.2 |
| detect_secrets | prompt | warm process | 131.8 | 2.182 | 2.457 | 38.1 |
| detect_secrets | tool_10kb | warm process | 118.0 | 25.418 | 30.917 | 38.4 |
| detect_secrets | tool_1mb | warm process | 2740.4 | 2222.457 | 2222.457 | 61.5 |
| gitleaks | prompt | process per run | 248.5 | 221.712 | 227.653 | 69.2 |
| gitleaks | tool_10kb | process per run | 224.8 | 219.344 | 219.815 | 66.8 |
| gitleaks | tool_1mb | process per run | 317.7 | 323.424 | 315.944 | 71.8 |
| kingfisher | prompt | process per run | 2492.3 | 2161.892 | 2410.523 | 144.1 |
| kingfisher | tool_10kb | process per run | 2064.4 | 2087.458 | 2099.436 | 144.6 |
| kingfisher | tool_1mb | process per run | 2094.5 | 2102.234 | 2085.76 | 158.1 |
| noseyparker | prompt | process per run | 274.4 | 316.161 | 323.897 | 242.1 |
| noseyparker | tool_10kb | process per run | 337.8 | 391.893 | 422.78 | 242.7 |
| noseyparker | tool_1mb | process per run | 429.6 | 421.127 | 419.431 | 253.6 |
| pii_anon | prompt | warm process | 216.0 | 0.876 | 0.898 | 56.7 |
| pii_anon | tool_10kb | warm process | 196.0 | 26.688 | 29.542 | 57.2 |
| pii_anon | tool_1mb | warm process | 3621.2 | 3473.552 | 3473.552 | 183.6 |
| preserve | prompt | warm process | 4968.6 | 475.821 | 504.333 | 2038.8 |
| preserve | tool_10kb | warm process | 7141.5 | 2464.189 | 2749.593 | 2038.5 |
| preserve | tool_1mb | warm process | 29541.8 | 25746.645 | 25746.645 | 2121.9 |
| presidio | prompt | warm process | 1254.5 | 8.311 | 9.136 | 788.0 |
| presidio | tool_10kb | warm process | 1150.3 | 281.6 | 291.995 | 816.2 |
| presidio | tool_1mb | warm process | 131137.3 | 121861.826 | 121861.826 | 6286.0 |
| trufflehog | prompt | process per run | 688.3 | 543.503 | 583.198 | 163.1 |
| trufflehog | tool_10kb | process per run | 1010.0 | 613.784 | 735.175 | 165.0 |
| trufflehog | tool_1mb | process per run | 686.2 | 744.387 | 727.142 | 201.0 |

| Scanner | Install footprint | Disk MB | Model files MB | torch | Network at run time | GPU |
|---|---|---:|---:|---|---|---|
| maisecrets | maisecrets/ of the candidate (Python standard library only) | 3.5 | 0 | no | no (standard library, no network code in the detector) | not used (CPU only) |
| betterleaks | the release binary | 22.1 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |
| detect_secrets | its virtual environment | 15.8 | 0.0 | no | not blocked, not observed | not used (CPU only) |
| gitleaks | the release binary | 20.3 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |
| kingfisher | the release binary | 26.4 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |
| noseyparker | the release binary | 29.1 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |
| pii_anon | its virtual environment | 57.4 | 0.0 | no | not blocked, not observed | not used (CPU only) |
| preserve | its virtual environment | 264.2 | 0.0 | no | not blocked, not observed | not used (CPU only) |
| presidio | its virtual environment | 597.1 | 424.5 | no | not blocked, not observed | not used (CPU only) |
| trufflehog | the release binary | 162.6 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |

maisecrets with the local NER layer: not measured here (BENCH_NER_PYTHON, BENCH_NER not set). The figures of docs/NER-EXPERIMENT.md: D3 (the support-copilot setting): 33 / 88 ms per document, memory + 0.7 GB; GLiNER multi v2.1: 152 / 411 ms per document, memory + 3.5 GB; spacy en_core_web_sm: 12 / 38 (median / p95) ms per document, memory 137 after load, 168 after the documents.

The rows of the other scanners come from the staging run of 2026-10-25 on the same machine (load average 3.2 at its start, 3.9 at its end).
