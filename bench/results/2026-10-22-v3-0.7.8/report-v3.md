# Benchmark V3 report

Recall as in V1 and V2 (strict: the span masked whole). P(V2): a finding on no labelled span is wrong. P(V3): only a finding of a class the source labels counts (`bench/v3_scope.json`); the rest is listed as out of scope. A class in `lower bound` has labels a read sample showed not exhaustive: its precision is a lower bound. Privy is never read: its precision is observed under incomplete annotation.

## bank, split dev (75 cases)

Cases sha256 `172bdf2e2118`, benchmark commit `008abf2b`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 51 | 1.000 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 42 | 0.929 | 0 | 1.000 | 0 | 1.000 | - |

## bank, split val (33 cases)

Cases sha256 `7d350302c12c`, benchmark commit `008abf2b`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 27 | - | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 24 | - | 0 | 1.000 | 0 | 1.000 | - |

## gretel, split dev (25066 cases)

Cases sha256 `59f13e70d759`, benchmark commit `008abf2b`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 855 | 0.428 | 66 | 0.848 | 66 | 0.848 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 78610 | 0.291 | 2484 | 0.903 | 2484 | 0.903 | - |

## gretel, split holdout (8507 cases)

Cases sha256 `9a19609497fe`, benchmark commit `008abf2b`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 287 | 0.380 | 18 | 0.859 | 18 | 0.859 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 26718 | 0.279 | 793 | 0.905 | 793 | 0.905 | - |

## gretel, split holdout, sample 1 in 25 (salt `v3/`) (336 cases)

Cases sha256 `212270da7f07`, benchmark commit `008abf2b`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 9 | - | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 1009 | 0.296 | 28 | 0.916 | 28 | 0.916 | - |

## gretel, split val (8359 cases)

Cases sha256 `631b8af7fe5e`, benchmark commit `008abf2b`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 269 | 0.416 | 14 | 0.891 | 14 | 0.891 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 25894 | 0.281 | 855 | 0.896 | 855 | 0.896 | - |

## gretel, split val, sample 1 in 25 (salt `v3/`) (334 cases)

Cases sha256 `689791d6f120`, benchmark commit `008abf2b`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 12 | - | 1 | 0.800 | 1 | 0.800 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 1141 | 0.296 | 33 | 0.914 | 33 | 0.914 | - |

## mendeley, split dev (26945 cases)

Cases sha256 `a837d51d142b`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 154793 | 0.686 | 1150 | 0.989 | 1150 | 0.989 | - |

## mendeley, split holdout (9084 cases)

Cases sha256 `b6188553c5a7`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 52450 | 0.683 | 371 | 0.990 | 371 | 0.990 | - |

## mendeley, split holdout, sample 1 in 25 (salt `v3/`) (398 cases)

Cases sha256 `3dc654b710e9`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 2360 | 0.676 | 18 | 0.989 | 18 | 0.989 | - |

## mendeley, split val (9001 cases)

Cases sha256 `3a19407f7433`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 51592 | 0.687 | 338 | 0.991 | 338 | 0.991 | - |

## mendeley, split val, sample 1 in 25 (salt `v3/`) (362 cases)

Cases sha256 `9bae655af341`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 2084 | 0.690 | 15 | 0.990 | 15 | 0.990 | - |

## nemotron, split dev (59965 cases)

Cases sha256 `4572e95c9a86`, benchmark commit `008abf2b`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 6998 | 0.664 | 20 | 0.996 | 20 | 0.996 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 200710 | 0.606 | 495 | 0.996 | 491 | 0.996 | pii.iban 4 |

## nemotron, split holdout (20229 cases)

Cases sha256 `b8d859efa101`, benchmark commit `008abf2b`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 2257 | 0.665 | 7 | 0.995 | 7 | 0.995 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 68086 | 0.602 | 196 | 0.995 | 196 | 0.995 | - |

## nemotron, split holdout, sample 1 in 25 (salt `v3/`) (816 cases)

Cases sha256 `bd52e8a68548`, benchmark commit `008abf2b`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 92 | 0.663 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 2909 | 0.591 | 7 | 0.996 | 7 | 0.996 | - |

## nemotron, split val (19806 cases)

Cases sha256 `26eb1c2513f5`, benchmark commit `008abf2b`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 2397 | 0.669 | 10 | 0.994 | 10 | 0.994 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 66240 | 0.609 | 180 | 0.995 | 180 | 0.995 | - |

## nemotron, split val, sample 1 in 25 (salt `v3/`) (834 cases)

Cases sha256 `92999e7d794a`, benchmark commit `008abf2b`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 118 | 0.678 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 2781 | 0.600 | 7 | 0.996 | 7 | 0.996 | - |

## piilo, split dev (4024 cases)

Cases sha256 `5470a9df5eb6`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 873 | 0.099 | 8 | 0.915 | 7 | 0.925 | pii.ip 1 |

## piilo, split holdout (1405 cases)

Cases sha256 `7385f3f4158b`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 322 | 0.087 | 1 | 0.966 | 1 | 0.966 | - |

## piilo, split holdout, sample 1 in 25 (salt `v3/`) (46 cases)

Cases sha256 `c14a711017e1`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 8 | - | 0 | - | 0 | - | - |

## piilo, split val (1378 cases)

Cases sha256 `7b3a5684813e`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 301 | 0.090 | 3 | 0.900 | 3 | 0.900 | - |

## piilo, split val, sample 1 in 25 (salt `v3/`) (55 cases)

Cases sha256 `17bbba8573a1`, benchmark commit `008abf2b`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 8 | - | 0 | 1.000 | 0 | 1.000 | - |

## privy, split all (28843 cases)

Cases sha256 `3d471990ca13`, benchmark commit `008abf2b`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 756 | 0.373 | 101 | 0.736 | 101 | 0.736 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 11247 | 0.241 | 3346 | 0.449 | 65 | 0.977 | pii.national_id 825, pii.iban 820, pii.ip 760, pii.email 738 |

## privy, split all, sample 1 in 10 (salt `v3/`) (2816 cases)

Cases sha256 `092dd3e63d0f`, benchmark commit `008abf2b`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 90 | 0.356 | 5 | 0.865 | 5 | 0.865 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.7.2 (008abf2b) | 1076 | 0.226 | 334 | 0.422 | 2 | 0.992 | pii.email 88, pii.national_id 79, pii.iban 76, pii.ip 66 |

