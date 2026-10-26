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
