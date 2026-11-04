# Speed and resources of 0.8.18 and the other scanners, on the reference host

`scripts/measure_resources.py` on maisecrets 0.8.18 (ee5efeed) and every other scanner of Benchmark V3, one scanner
after the other on a quiet host: cold start, warm latency for a short prompt, a 10 KB and a 1 MB tool result (cut from
the candidate's own source and docs), peak RSS of the process tree, install footprint. Table: `resources.md`; raw
values: `resources.json`.

Host: netcup RS 2000 G12, AMD EPYC 9645 (Zen 5), 8 vCPU, 15.6 GB RAM, Debian 13 (Linux 6.12), Python 3.13.5 for
maisecrets. No CI build at the start or the end; load average 0.1 at the start, 1.3 at the end. Run on 2026-11-04.

The scanners at the versions of `bench/adapters/requirements/`: Presidio 2.2.364 on Python 3.11.17 with
en_core_web_lg 3.8.0; Preserve 0.6.1, pii-anon 1.7.0rc1 and detect-secrets 1.5.0 on Python 3.15.0rc3 (the published run of 0.8.2 used 3.15.0 on a Mac); the release binaries gitleaks 8.30.1, Betterleaks 1.9.0,
TruffleHog 3.99.2, Kingfisher 2.11.1 and Nosey Parker 0.24.0 as their Linux x86_64 archives. On Linux no sandbox
denies the binaries the network; each runs with its offline flag (validation off), as the table says. The
network column of the binaries was written as on macOS by the script of that day and is corrected to Linux here.
secret-scan is not part of this measurement (as in 0.8.2's table).

The earlier table (`2026-10-26-v3-0.8.2/extended/resources.md`) was measured on an Apple M5; the two hosts differ, so
compare rows within one table, not across the two.

Command (GNU time from the Debian package `time`, unpacked without root, as BENCH_TIME):

```bash
BENCH_TIME=… BENCH_PRESIDIO_PYTHON=… BENCH_PRESERVE_PYTHON=… BENCH_PII_ANON_PYTHON=… BENCH_DETECT_SECRETS_PYTHON=… \
BENCH_GITLEAKS=… BENCH_BETTERLEAKS=… BENCH_TRUFFLEHOG=… BENCH_KINGFISHER=… BENCH_NOSEYPARKER=… \
python3 scripts/measure_resources.py <worktree of v0.8.18> OUT
```
