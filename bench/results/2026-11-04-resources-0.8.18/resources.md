## Speed and resources

Machine: AMD EPYC 9645 96-Core Processor, 8 CPUs, 15.6 GB RAM, Linux 6.12.115+deb13.1-amd64. Load average 0.1 at the start, 1.3 at the end. One scanner after the other; peak RSS of the scanner's process tree.

| Scanner | Text | Mode | Cold start ms | Warm median ms | Warm p95 ms | Peak RSS MB |
|---|---|---|---:|---:|---:|---:|
| maisecrets | prompt | warm process | 67.5 | 0.691 | 0.817 | 23.7 |
| maisecrets | tool_10kb | warm process | 219.0 | 59.583 | 65.011 | 25.6 |
| maisecrets | tool_1mb | warm process | 17235.3 | 9928.515 | 9928.515 | 329.6 |
| presidio | prompt | warm process | 3448.3 | 18.204 | 23.539 | 767.4 |
| presidio | tool_10kb | warm process | 2821.5 | 524.382 | 556.062 | 794.5 |
| presidio | tool_1mb | warm process | 167797.4 | 184665.186 | 184665.186 | 4794.6 |
| preserve | prompt | warm process | 12972.6 | 762.915 | 994.006 | 1931.0 |
| preserve | tool_10kb | warm process | 13768.6 | 2133.681 | 2509.002 | 1930.5 |
| preserve | tool_1mb | warm process | 68671.7 | 63231.179 | 63231.179 | 1951.4 |
| pii_anon | prompt | warm process | 532.0 | 2.122 | 2.404 | 57.8 |
| pii_anon | tool_10kb | warm process | 356.9 | 34.83 | 41.472 | 57.9 |
| pii_anon | tool_1mb | warm process | 5859.9 | 5408.561 | 5408.561 | 140.9 |
| gitleaks | prompt | process per run | 510.7 | 482.237 | 648.151 | 64.3 |
| gitleaks | tool_10kb | process per run | 746.1 | 563.375 | 601.079 | 65.4 |
| gitleaks | tool_1mb | process per run | 895.7 | 773.993 | 753.254 | 68.6 |
| betterleaks | prompt | process per run | 403.6 | 350.307 | 396.709 | 46.2 |
| betterleaks | tool_10kb | process per run | 409.5 | 351.601 | 375.953 | 48.3 |
| betterleaks | tool_1mb | process per run | 678.6 | 636.244 | 627.499 | 61.2 |
| trufflehog | prompt | process per run | 2082.2 | 1952.823 | 2002.306 | 202.5 |
| trufflehog | tool_10kb | process per run | 2016.7 | 1903.217 | 1930.22 | 205.2 |
| trufflehog | tool_1mb | process per run | 2035.8 | 1943.157 | 1916.768 | 258.3 |
| detect_secrets | prompt | warm process | 217.0 | 2.249 | 4.101 | 33.5 |
| detect_secrets | tool_10kb | warm process | 174.7 | 34.066 | 43.238 | 34.1 |
| detect_secrets | tool_1mb | warm process | 3419.6 | 3215.387 | 3215.387 | 52.4 |
| kingfisher | prompt | process per run | 5406.4 | 5482.312 | 5962.293 | 104.8 |
| kingfisher | tool_10kb | process per run | 5785.9 | 5576.673 | 5680.109 | 102.4 |
| kingfisher | tool_1mb | process per run | 6445.5 | 5986.98 | 5569.242 | 152.3 |
| noseyparker | prompt | process per run | 739.2 | 594.816 | 636.614 | 267.1 |
| noseyparker | tool_10kb | process per run | 732.4 | 635.378 | 716.236 | 265.8 |
| noseyparker | tool_1mb | process per run | 600.0 | 605.485 | 596.918 | 284.3 |
| maisecrets_ner | – | not installed here (its environment variable is not set) | | | | |

| Scanner | Install footprint | Disk MB | Model files MB | torch | Network at run time | GPU |
|---|---|---:|---:|---|---|---|
| maisecrets | maisecrets/ of the candidate (Python standard library only) | 3.7 | 0 | no | no (standard library, no network code in the detector) | not used (CPU only) |
| presidio | its virtual environment | 783.3 | 424.5 | no | not blocked, not observed | not used (CPU only) |
| preserve | its virtual environment | 302.0 | 0.0 | no | not blocked, not observed | not used (CPU only) |
| pii_anon | its virtual environment | 91.9 | 0.0 | no | not blocked, not observed | not used (CPU only) |
| gitleaks | the release binary | 20.9 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |
| betterleaks | the release binary | 23.1 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |
| trufflehog | the release binary | 34.8 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |
| detect_secrets | its virtual environment | 15.4 | 0.0 | no | not blocked, not observed | not used (CPU only) |
| kingfisher | the release binary | 34.9 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |
| noseyparker | the release binary | 40.7 | 0 | no | denied by the sandbox on macOS (validation off by flag) | not used (CPU only) |

maisecrets with the local NER layer: not measured here (BENCH_NER_PYTHON, BENCH_NER not set). The figures of docs/NER-EXPERIMENT.md: spacy en_core_web_sm: 12 / 38 (median / p95) ms per document, memory 137 after load, 168 after the documents; D3 (the support-copilot setting): 33 / 88 ms per document, memory + 0.7 GB; GLiNER multi v2.1: 152 / 411 ms per document, memory + 3.5 GB.
