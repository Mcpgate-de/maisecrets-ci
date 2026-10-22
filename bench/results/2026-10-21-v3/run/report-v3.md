# Benchmark V3 report

Recall as in V1 and V2 (strict: the span masked whole). P(V2): a finding on no labelled span is wrong. P(V3): only a finding of a class the source labels counts (`bench/v3_scope.json`); the rest is listed as out of scope. A class in `lower bound` has labels a read sample showed not exhaustive: its precision is a lower bound. Privy is never read: its precision is observed under incomplete annotation.

## bank, split dev (75 cases)

Cases sha256 `172bdf2e2118`, benchmark commit `a5fd1ff3`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| detect-secrets | 1.5.0 | 51 | 0.353 | 0 | 1.000 | 0 | 1.000 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 51 | 0.941 | 0 | 1.000 | 0 | 1.000 | - |
| preserve | 0.6.1 (01dbd771) | 51 | 0.706 | 6 | 0.870 | 6 | 0.870 | - |
| secret-scan | 0.4.2 (7d8b5c18) | 51 | 0.765 | 9 | 0.864 | 9 | 0.864 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| ai_gateway | 2.0.3392 (984787cd) | 33 | 0.909 | 6 | 0.833 | 6 | 0.833 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 42 | 0.929 | 0 | 1.000 | 0 | 1.000 | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 42 | 0.714 | 18 | 0.690 | 18 | 0.690 | - |
| preserve | 0.6.1 (01dbd771) | 42 | 0.857 | 18 | 0.684 | 18 | 0.684 | - |
| presidio | 2.2.364 | 42 | 0.881 | 19 | 0.698 | 19 | 0.698 | - |

## bank, split val (33 cases)

Cases sha256 `7d350302c12c`, benchmark commit `a5fd1ff3`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| detect-secrets | 1.5.0 | 27 | - | 0 | 1.000 | 0 | 1.000 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 27 | - | 0 | 1.000 | 0 | 1.000 | - |
| preserve | 0.6.1 (01dbd771) | 27 | - | 0 | 1.000 | 0 | 1.000 | - |
| secret-scan | 0.4.2 (7d8b5c18) | 27 | - | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| ai_gateway | 2.0.3392 (984787cd) | 12 | - | 3 | 0.800 | 3 | 0.800 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 24 | - | 0 | 1.000 | 0 | 1.000 | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 24 | - | 12 | 0.625 | 12 | 0.625 | - |
| preserve | 0.6.1 (01dbd771) | 24 | - | 9 | 0.667 | 9 | 0.667 | - |
| presidio | 2.2.364 | 24 | - | 18 | 0.617 | 18 | 0.617 | - |

## catalogs, split all (11902 cases)

Cases sha256 `6c3b05a075ce`, benchmark commit `a5fd1ff3`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| detect-secrets | 1.5.0 | 11902 | 0.235 | 0 | 1.000 | 0 | 1.000 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 11902 | 0.586 | 0 | 1.000 | 0 | 1.000 | - |
| preserve | 0.6.1 (01dbd771) | 11902 | 0.057 | 0 | 1.000 | 0 | 1.000 | - |
| secret-scan | 0.4.2 (7d8b5c18) | 11902 | 0.073 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| presidio | 2.2.364 | 0 | - | 177 | 0.000 | 177 | 0.000 | - |

## gretel, split dev (25066 cases)

Cases sha256 `59f13e70d759`, benchmark commit `a5fd1ff3`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 855 | 0.401 | 64 | 0.844 | 64 | 0.844 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 78610 | 0.287 | 2243 | 0.911 | 2243 | 0.911 | - |

## gretel, split holdout (8507 cases)

Cases sha256 `9a19609497fe`, benchmark commit `a5fd1ff3`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 287 | 0.352 | 17 | 0.857 | 17 | 0.857 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 26718 | 0.275 | 729 | 0.911 | 729 | 0.911 | - |

## gretel, split holdout, sample 1 in 25 (336 cases)

Cases sha256 `212270da7f07`, benchmark commit `a5fd1ff3`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| detect-secrets | 1.5.0 | 9 | - | 0 | 1.000 | 0 | 1.000 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 9 | - | 0 | 1.000 | 0 | 1.000 | - |
| preserve | 0.6.1 (01dbd771) | 9 | - | 0 | 1.000 | 0 | 1.000 | - |
| secret-scan | 0.4.2 (7d8b5c18) | 9 | - | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| ai_gateway | 2.0.3392 (984787cd) | 160 | 0.694 | 36 | 0.755 | 36 | 0.755 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 1009 | 0.294 | 28 | 0.915 | 28 | 0.915 | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 1009 | 0.402 | 2558 | 0.220 | 2092 | 0.256 | pii.other 466 |
| preserve | 0.6.1 (01dbd771) | 1009 | 0.427 | 2575 | 0.209 | 2547 | 0.211 | pii.other 28 |
| presidio | 2.2.364 | 1009 | 0.461 | 2225 | 0.271 | 2225 | 0.271 | - |

## gretel, split val (8359 cases)

Cases sha256 `631b8af7fe5e`, benchmark commit `a5fd1ff3`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 269 | 0.379 | 14 | 0.881 | 14 | 0.881 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 25894 | 0.277 | 795 | 0.901 | 795 | 0.901 | - |

## gretel, split val, sample 1 in 25 (334 cases)

Cases sha256 `689791d6f120`, benchmark commit `a5fd1ff3`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| detect-secrets | 1.5.0 | 12 | - | 2 | 0.000 | 2 | 0.000 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 12 | - | 1 | 0.750 | 1 | 0.750 | - |
| preserve | 0.6.1 (01dbd771) | 12 | - | 0 | 1.000 | 0 | 1.000 | - |
| secret-scan | 0.4.2 (7d8b5c18) | 12 | - | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| ai_gateway | 2.0.3392 (984787cd) | 178 | 0.736 | 50 | 0.724 | 50 | 0.724 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 1141 | 0.294 | 33 | 0.913 | 33 | 0.913 | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 1141 | 0.429 | 2300 | 0.251 | 2012 | 0.277 | pii.other 288 |
| preserve | 0.6.1 (01dbd771) | 1141 | 0.416 | 2475 | 0.245 | 2461 | 0.246 | pii.other 14 |
| presidio | 2.2.364 | 1141 | 0.453 | 2398 | 0.273 | 2398 | 0.273 | - |

## mendeley, split dev (26945 cases)

Cases sha256 `a837d51d142b`, benchmark commit `a5fd1ff3`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 154793 | 0.686 | 1150 | 0.989 | 1150 | 0.989 | - |

## mendeley, split holdout (9084 cases)

Cases sha256 `b6188553c5a7`, benchmark commit `a5fd1ff3`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 52450 | 0.683 | 371 | 0.990 | 371 | 0.990 | - |

## mendeley, split holdout, sample 1 in 25 (398 cases)

Cases sha256 `3dc654b710e9`, benchmark commit `a5fd1ff3`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| ai_gateway | 2.0.3392 (984787cd) | 1222 | 0.493 | 0 | 1.000 | 0 | 1.000 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 2360 | 0.676 | 18 | 0.989 | 18 | 0.989 | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 2360 | 0.601 | 2319 | 0.505 | 1320 | 0.642 | pii.other 999 |
| preserve | 0.6.1 (01dbd771) | 2360 | 0.666 | 563 | 0.770 | 411 | 0.821 | pii.other 122, pii.birth_date 30 |
| presidio | 2.2.364 | 2360 | 0.664 | 441 | 0.897 | 430 | 0.900 | pii.bank_account 11 |

## mendeley, split val (9001 cases)

Cases sha256 `3a19407f7433`, benchmark commit `a5fd1ff3`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 51592 | 0.687 | 338 | 0.991 | 338 | 0.991 | - |

## mendeley, split val, sample 1 in 25 (362 cases)

Cases sha256 `9bae655af341`, benchmark commit `a5fd1ff3`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| ai_gateway | 2.0.3392 (984787cd) | 1099 | 0.490 | 0 | 1.000 | 0 | 1.000 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 2084 | 0.690 | 15 | 0.990 | 15 | 0.990 | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 2084 | 0.610 | 2006 | 0.511 | 1089 | 0.658 | pii.other 917 |
| preserve | 0.6.1 (01dbd771) | 2084 | 0.666 | 521 | 0.760 | 380 | 0.813 | pii.other 115, pii.birth_date 26 |
| presidio | 2.2.364 | 2084 | 0.677 | 407 | 0.893 | 397 | 0.895 | pii.bank_account 10 |

## nemotron, split dev (59965 cases)

Cases sha256 `4572e95c9a86`, benchmark commit `a5fd1ff3`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 6998 | 0.448 | 18 | 0.994 | 18 | 0.994 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 200710 | 0.593 | 490 | 0.996 | 486 | 0.996 | pii.iban 4 |

## nemotron, split holdout (20229 cases)

Cases sha256 `b8d859efa101`, benchmark commit `a5fd1ff3`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 2257 | 0.467 | 7 | 0.994 | 7 | 0.994 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 68086 | 0.590 | 196 | 0.995 | 196 | 0.995 | - |

## nemotron, split holdout, sample 1 in 25 (816 cases)

Cases sha256 `bd52e8a68548`, benchmark commit `a5fd1ff3`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| detect-secrets | 1.5.0 | 92 | 0.022 | 0 | 1.000 | 0 | 1.000 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 92 | 0.500 | 0 | 1.000 | 0 | 1.000 | - |
| preserve | 0.6.1 (01dbd771) | 92 | 0.065 | 1 | 0.875 | 1 | 0.875 | - |
| secret-scan | 0.4.2 (7d8b5c18) | 92 | 0.141 | 1 | 0.929 | 1 | 0.929 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| ai_gateway | 2.0.3392 (984787cd) | 1102 | 0.566 | 5 | 0.992 | 5 | 0.992 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 2909 | 0.576 | 7 | 0.996 | 7 | 0.996 | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 2909 | 0.744 | 4193 | 0.311 | 3905 | 0.326 | pii.other 288 |
| preserve | 0.6.1 (01dbd771) | 2909 | 0.666 | 296 | 0.851 | 289 | 0.854 | pii.other 7 |
| presidio | 2.2.364 | 2909 | 0.738 | 172 | 0.929 | 172 | 0.929 | - |

## nemotron, split val (19806 cases)

Cases sha256 `26eb1c2513f5`, benchmark commit `a5fd1ff3`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 2397 | 0.454 | 8 | 0.993 | 8 | 0.993 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 66240 | 0.597 | 179 | 0.995 | 179 | 0.995 | - |

## nemotron, split val, sample 1 in 25 (834 cases)

Cases sha256 `92999e7d794a`, benchmark commit `a5fd1ff3`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| detect-secrets | 1.5.0 | 118 | 0.085 | 0 | 1.000 | 0 | 1.000 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 118 | 0.390 | 0 | 1.000 | 0 | 1.000 | - |
| preserve | 0.6.1 (01dbd771) | 118 | 0.085 | 2 | 0.833 | 2 | 0.833 | - |
| secret-scan | 0.4.2 (7d8b5c18) | 118 | 0.119 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| ai_gateway | 2.0.3392 (984787cd) | 1081 | 0.553 | 3 | 0.995 | 3 | 0.995 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 2781 | 0.587 | 7 | 0.996 | 7 | 0.996 | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 2781 | 0.766 | 4750 | 0.283 | 4437 | 0.297 | pii.other 313 |
| preserve | 0.6.1 (01dbd771) | 2781 | 0.660 | 358 | 0.824 | 356 | 0.825 | pii.other 2 |
| presidio | 2.2.364 | 2781 | 0.722 | 173 | 0.928 | 173 | 0.928 | - |

## piilo, split dev (4024 cases)

Cases sha256 `5470a9df5eb6`, benchmark commit `a5fd1ff3`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 873 | 0.099 | 8 | 0.915 | 7 | 0.925 | pii.ip 1 |

## piilo, split holdout (1405 cases)

Cases sha256 `7385f3f4158b`, benchmark commit `a5fd1ff3`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 322 | 0.087 | 1 | 0.966 | 1 | 0.966 | - |

## piilo, split holdout, sample 1 in 25 (46 cases)

Cases sha256 `c14a711017e1`, benchmark commit `a5fd1ff3`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 8 | - | 0 | - | 0 | - | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 8 | - | 218 | 0.022 | 203 | 0.024 | pii.other 15 |
| preserve | 0.6.1 (01dbd771) | 8 | - | 29 | 0.194 | 25 | 0.219 | pii.birth_date 3, pii.other 1 |
| presidio | 2.2.364 | 8 | - | 38 | 0.174 | 38 | 0.174 | - |

## piilo, split val (1378 cases)

Cases sha256 `7b3a5684813e`, benchmark commit `a5fd1ff3`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 301 | 0.090 | 3 | 0.900 | 3 | 0.900 | - |

## piilo, split val, sample 1 in 25 (55 cases)

Cases sha256 `17bbba8573a1`, benchmark commit `a5fd1ff3`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| secret-scan | 0.4.2 (7d8b5c18) | 0 | - | 1 | 0.000 | 0 | - | secret 1 |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 8 | - | 0 | 1.000 | 0 | 1.000 | - |
| pii-anon | 1.7.0rc1 (2171ace5) | 8 | - | 252 | 0.027 | 239 | 0.029 | pii.other 13 |
| preserve | 0.6.1 (01dbd771) | 8 | - | 26 | 0.188 | 24 | 0.200 | pii.birth_date 1, pii.other 1 |
| presidio | 2.2.364 | 8 | - | 43 | 0.140 | 43 | 0.140 | - |

## privy, split all (28843 cases)

Cases sha256 `3d471990ca13`, benchmark commit `a5fd1ff3`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 756 | 0.373 | 101 | 0.736 | 101 | 0.736 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.3 (eee4b2e0) | 11247 | 0.240 | 3344 | 0.448 | 65 | 0.977 | pii.national_id 825, pii.iban 820, pii.ip 760, pii.email 738 |

## privy, split all, sample 1 in 10 (2816 cases)

Cases sha256 `092dd3e63d0f`, benchmark commit `a5fd1ff3`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| detect-secrets | 1.5.0 | 90 | 0.278 | 41 | 0.379 | 41 | 0.379 | - |
| maisecrets | 0.7.3 (eee4b2e0) | 90 | 0.356 | 5 | 0.865 | 5 | 0.865 | - |
| preserve | 0.6.1 (01dbd771) | 90 | 0.033 | 0 | 1.000 | 0 | 1.000 | - |
| secret-scan | 0.4.2 (7d8b5c18) | 90 | 0.000 | 0 | - | 0 | - | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| ai_gateway | 2.0.3392 (984787cd) | 280 | 0.132 | 227 | 0.140 | 0 | 1.000 | pii.email 88, pii.iban 76, pii.ip 62, pii.phone 1 |
| maisecrets | 0.7.3 (eee4b2e0) | 1076 | 0.225 | 334 | 0.421 | 2 | 0.992 | pii.email 88, pii.national_id 79, pii.iban 76, pii.ip 66 |
| pii-anon | 1.7.0rc1 (2171ace5) | 1076 | 0.286 | 643 | 0.333 | 22 | 0.936 | pii.national_id 174, pii.email 88, pii.phone 81, pii.other 80 |
| preserve | 0.6.1 (01dbd771) | 1076 | 0.205 | 741 | 0.251 | 350 | 0.415 | pii.email 88, pii.phone 88, pii.national_id 76, pii.iban 73 |
| presidio | 2.2.364 | 1076 | 0.473 | 1946 | 0.377 | 1060 | 0.527 | pii.national_id 390, pii.address 152, pii.phone 114, pii.email 88 |

