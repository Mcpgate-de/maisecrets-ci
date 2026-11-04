# JSON benchmark, maisecrets 0.8.19

`bench/json_bench.py` (docs/BENCHMARK-JSON.md) at 3a5e4a31 (= v0.8.19 plus the benchmark), 160 responses, 241.9 KB of
JSON, seed 7. Host: netcup RS 2000 G12, AMD EPYC 9645, Debian 13, quiet host (load 0.50 at the start, no CI build).
2026-11-04. Raw result: `json-bench.json`.

| Tool | Recall | Precision | Found | Missed | False alarms | CPU ms per KB |
|---|---:|---:|---:|---:|---:|---:|
| maisecrets record | 0.837 | 0.996 | 1,986 | 387 | 9 | 5.2 |
| maisecrets text | 0.807 | 0.995 | 1,915 | 458 | 9 | 6.7 |
| Presidio text | 0.786 | 0.566 | 1,866 | 507 | 1,434 | 89.0 |
| Presidio structured | 0.693 | 0.517 | 1,644 | 729 | 1,537 | 149.6 |
| pii-anon text | 0.742 | 0.790 | 1,760 | 613 | 468 | 5.0 |
| detect-secrets text | 0.030 | 0.356 | 72 | 2,301 | 130 | 2.9 |

detect-secrets looks for secrets only: on the secret class it finds 72 of 154 with 130 false alarms (maisecrets record:
123 of 154, 9 false alarms). Presidio and pii-anon have no secret class here. The shapes, fields and values were chosen
by this project (docs/BENCHMARK-JSON.md); read the table as a measurement of these shapes.
