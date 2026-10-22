# Benchmark V3 report

Recall as in V1 and V2 (strict: the span masked whole). P(V2): a finding on no labelled span is wrong. P(V3): only a finding of a class the source labels counts (`bench/v3_scope.json`); the rest is listed as out of scope. A class in `lower bound` has labels a read sample showed not exhaustive: its precision is a lower bound. Privy is never read: its precision is observed under incomplete annotation.

## bank, split dev (75 cases)

Cases sha256 `172bdf2e2118`, benchmark commit `777858aa`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 51 | 0.941 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 42 | 0.929 | 0 | 1.000 | 0 | 1.000 | - |

## bank, split val (33 cases)

Cases sha256 `7d350302c12c`, benchmark commit `777858aa`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 27 | - | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 24 | - | 0 | 1.000 | 0 | 1.000 | - |

## catalogs, split all (11902 cases)

Cases sha256 `6c3b05a075ce`, benchmark commit `777858aa`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 11902 | 0.586 | 0 | 1.000 | 0 | 1.000 | - |

## gretel, split dev (25066 cases)

Cases sha256 `59f13e70d759`, benchmark commit `777858aa`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 855 | 0.401 | 64 | 0.844 | 64 | 0.844 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 78610 | 0.290 | 2471 | 0.904 | 2471 | 0.904 | - |

## gretel, split holdout (8507 cases)

Cases sha256 `9a19609497fe`, benchmark commit `777858aa`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 287 | 0.352 | 17 | 0.857 | 17 | 0.857 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 26718 | 0.278 | 792 | 0.905 | 792 | 0.905 | - |

## gretel, split holdout, sample 1 in 25 (salt `v3/`) (336 cases)

Cases sha256 `212270da7f07`, benchmark commit `777858aa`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 9 | - | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 1009 | 0.296 | 28 | 0.916 | 28 | 0.916 | - |

## gretel, split val (8359 cases)

Cases sha256 `631b8af7fe5e`, benchmark commit `777858aa`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 269 | 0.379 | 14 | 0.881 | 14 | 0.881 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 25894 | 0.280 | 855 | 0.896 | 855 | 0.896 | - |

## gretel, split val, sample 1 in 25 (salt `v3/`) (334 cases)

Cases sha256 `689791d6f120`, benchmark commit `777858aa`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 12 | - | 1 | 0.750 | 1 | 0.750 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 1141 | 0.294 | 33 | 0.913 | 33 | 0.913 | - |

## mendeley, split dev (26945 cases)

Cases sha256 `a837d51d142b`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 154793 | 0.686 | 1150 | 0.989 | 1150 | 0.989 | - |

## mendeley, split holdout (9084 cases)

Cases sha256 `b6188553c5a7`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 52450 | 0.683 | 371 | 0.990 | 371 | 0.990 | - |

## mendeley, split holdout, sample 1 in 25 (salt `v3/`) (398 cases)

Cases sha256 `3dc654b710e9`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 2360 | 0.676 | 18 | 0.989 | 18 | 0.989 | - |

## mendeley, split val (9001 cases)

Cases sha256 `3a19407f7433`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 51592 | 0.687 | 338 | 0.991 | 338 | 0.991 | - |

## mendeley, split val, sample 1 in 25 (salt `v3/`) (362 cases)

Cases sha256 `9bae655af341`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 2084 | 0.690 | 15 | 0.990 | 15 | 0.990 | - |

## nemotron, split dev (59965 cases)

Cases sha256 `4572e95c9a86`, benchmark commit `777858aa`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 6998 | 0.448 | 18 | 0.994 | 18 | 0.994 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 200710 | 0.603 | 494 | 0.996 | 490 | 0.996 | pii.iban 4 |

## nemotron, split holdout (20229 cases)

Cases sha256 `b8d859efa101`, benchmark commit `777858aa`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 2257 | 0.467 | 7 | 0.994 | 7 | 0.994 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 68086 | 0.599 | 196 | 0.995 | 196 | 0.995 | - |

## nemotron, split holdout, sample 1 in 25 (salt `v3/`) (816 cases)

Cases sha256 `bd52e8a68548`, benchmark commit `777858aa`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 92 | 0.500 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 2909 | 0.588 | 7 | 0.996 | 7 | 0.996 | - |

## nemotron, split val (19806 cases)

Cases sha256 `26eb1c2513f5`, benchmark commit `777858aa`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 2397 | 0.454 | 8 | 0.993 | 8 | 0.993 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 66240 | 0.607 | 180 | 0.995 | 180 | 0.995 | - |

## nemotron, split val, sample 1 in 25 (salt `v3/`) (834 cases)

Cases sha256 `92999e7d794a`, benchmark commit `777858aa`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 118 | 0.390 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 2781 | 0.597 | 7 | 0.996 | 7 | 0.996 | - |

## piilo, split dev (4024 cases)

Cases sha256 `5470a9df5eb6`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 873 | 0.099 | 8 | 0.915 | 7 | 0.925 | pii.ip 1 |

## piilo, split holdout (1405 cases)

Cases sha256 `7385f3f4158b`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 322 | 0.087 | 1 | 0.966 | 1 | 0.966 | - |

## piilo, split holdout, sample 1 in 25 (salt `v3/`) (46 cases)

Cases sha256 `c14a711017e1`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 8 | - | 0 | - | 0 | - | - |

## piilo, split val (1378 cases)

Cases sha256 `7b3a5684813e`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 301 | 0.090 | 3 | 0.900 | 3 | 0.900 | - |

## piilo, split val, sample 1 in 25 (salt `v3/`) (55 cases)

Cases sha256 `17bbba8573a1`, benchmark commit `777858aa`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 8 | - | 0 | 1.000 | 0 | 1.000 | - |

## privy, split all (28843 cases)

Cases sha256 `3d471990ca13`, benchmark commit `777858aa`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 756 | 0.373 | 101 | 0.736 | 101 | 0.736 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 11247 | 0.240 | 3344 | 0.448 | 65 | 0.977 | pii.national_id 825, pii.iban 820, pii.ip 760, pii.email 738 |

## privy, split all, sample 1 in 10 (salt `v3/`) (2816 cases)

Cases sha256 `092dd3e63d0f`, benchmark commit `777858aa`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 90 | 0.356 | 5 | 0.865 | 5 | 0.865 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.6 (bef132cf) | 1076 | 0.225 | 334 | 0.421 | 2 | 0.992 | pii.email 88, pii.national_id 79, pii.iban 76, pii.ip 66 |

