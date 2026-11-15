# Benchmark V3 report

Recall as in V1 and V2 (strict: the span masked whole). P(V2): a finding on no labelled span is wrong. P(V3): only a finding of a class the source labels counts (`bench/v3_scope.json`); the rest is listed as out of scope. A class in `lower bound` has labels a read sample showed not exhaustive: its precision is a lower bound. Privy is never read: its precision is observed under incomplete annotation.

## aparte, split dev (465 cases)

Cases sha256 `07720cd6ee27`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 460 | 0.815 | 16 | 0.959 | 16 | 0.959 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 0 | - | 76 | 0.000 | 0 | - | pii.email 33, pii.iban 29, pii.phone 14 |

## aparte, split holdout (880 cases)

Cases sha256 `6505185380ef`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 792 | 0.333 | 2 | 0.993 | 2 | 0.993 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 0 | - | 181 | 0.000 | 0 | - | pii.email 100, pii.iban 76, pii.bank_account 3, pii.ip 2 |

## aparte, split val (310 cases)

Cases sha256 `42afc41014af`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 296 | 0.804 | 8 | 0.968 | 8 | 0.968 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 0 | - | 61 | 0.000 | 0 | - | pii.iban 27, pii.email 22, pii.phone 12 |

## bank, split dev (120 cases)

Cases sha256 `6f8fcea6ab3f`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 54 | 1.000 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 120 | 0.942 | 0 | 1.000 | 0 | 1.000 | - |

## bank, split val (33 cases)

Cases sha256 `7d350302c12c`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 27 | - | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 24 | - | 0 | 1.000 | 0 | 1.000 | - |

## credsweeper, split dev (114 cases)

Cases sha256 `8ce64f62567a`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 352 | 0.727 | 68 | 0.790 | 68 | 0.790 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 0 | - | 55 | 0.000 | 0 | - | pii.ip 52, pii.email 2, pii.username 1 |

## credsweeper, split holdout (50 cases)

Cases sha256 `095ec645edb7`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 79 | 0.671 | 10 | 0.846 | 10 | 0.846 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 0 | - | 4 | 0.000 | 0 | - | pii.name 2, pii.email 1, pii.username 1 |

## credsweeper, split val (35 cases)

Cases sha256 `648d2b73a6eb`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 130 | 0.885 | 16 | 0.878 | 16 | 0.878 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 0 | - | 7 | 0.000 | 0 | - | pii.ip 6, pii.email 1 |

## gretel, split dev (25066 cases)

Cases sha256 `59f13e70d759`, benchmark commit `916fda2f`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 855 | 0.471 | 82 | 0.833 | 82 | 0.833 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 78610 | 0.325 | 2177 | 0.923 | 2177 | 0.923 | - |

## gretel, split holdout (8507 cases)

Cases sha256 `9a19609497fe`, benchmark commit `916fda2f`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 287 | 0.408 | 24 | 0.832 | 24 | 0.832 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 26718 | 0.312 | 711 | 0.923 | 711 | 0.923 | - |

## gretel, split holdout, sample 1 in 25 (salt `v3/`) (336 cases)

Cases sha256 `212270da7f07`, benchmark commit `916fda2f`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 9 | - | 1 | 0.750 | 1 | 0.750 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 1009 | 0.325 | 22 | 0.938 | 22 | 0.938 | - |

## gretel, split val (8359 cases)

Cases sha256 `631b8af7fe5e`, benchmark commit `916fda2f`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 269 | 0.476 | 21 | 0.862 | 21 | 0.862 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 25894 | 0.312 | 778 | 0.914 | 778 | 0.914 | - |

## gretel, split val, sample 1 in 25 (salt `v3/`) (334 cases)

Cases sha256 `689791d6f120`, benchmark commit `916fda2f`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 12 | - | 1 | 0.833 | 1 | 0.833 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 1141 | 0.323 | 35 | 0.916 | 35 | 0.916 | - |

## llmredactor, split dev (187 cases)

Cases sha256 `c2bad5452d0b`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 329 | 0.909 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 50 | 0.960 | 0 | 1.000 | 0 | 1.000 | - |

## llmredactor, split holdout (61 cases)

Cases sha256 `6c769e3866b3`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 107 | 0.916 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 12 | - | 0 | 1.000 | 0 | 1.000 | - |

## llmredactor, split val (52 cases)

Cases sha256 `15165265781f`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 80 | 0.912 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 10 | - | 0 | 1.000 | 0 | 1.000 | - |

## mendeley, split dev (26945 cases)

Cases sha256 `a837d51d142b`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 154793 | 0.713 | 1396 | 0.988 | 1396 | 0.988 | - |

## mendeley, split holdout (9084 cases)

Cases sha256 `b6188553c5a7`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 52450 | 0.709 | 457 | 0.988 | 457 | 0.988 | - |

## mendeley, split holdout, sample 1 in 25 (salt `v3/`) (398 cases)

Cases sha256 `3dc654b710e9`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 2360 | 0.695 | 20 | 0.988 | 20 | 0.988 | - |

## mendeley, split val (9001 cases)

Cases sha256 `3a19407f7433`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 51592 | 0.713 | 420 | 0.989 | 420 | 0.989 | - |

## mendeley, split val, sample 1 in 25 (salt `v3/`) (362 cases)

Cases sha256 `9bae655af341`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 2084 | 0.717 | 21 | 0.986 | 21 | 0.986 | - |

## nemotron, split dev (59965 cases)

Cases sha256 `4572e95c9a86`, benchmark commit `916fda2f`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 6998 | 0.685 | 20 | 0.996 | 20 | 0.996 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 200710 | 0.632 | 476 | 0.996 | 472 | 0.996 | pii.iban 4 |

## nemotron, split holdout (20229 cases)

Cases sha256 `b8d859efa101`, benchmark commit `916fda2f`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 2257 | 0.687 | 7 | 0.996 | 7 | 0.996 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 68086 | 0.628 | 186 | 0.995 | 186 | 0.995 | - |

## nemotron, split holdout, sample 1 in 25 (salt `v3/`) (816 cases)

Cases sha256 `bd52e8a68548`, benchmark commit `916fda2f`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 92 | 0.663 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 2909 | 0.616 | 6 | 0.997 | 6 | 0.997 | - |

## nemotron, split val (19806 cases)

Cases sha256 `26eb1c2513f5`, benchmark commit `916fda2f`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 2397 | 0.689 | 10 | 0.994 | 10 | 0.994 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 66240 | 0.635 | 162 | 0.996 | 162 | 0.996 | - |

## nemotron, split val, sample 1 in 25 (salt `v3/`) (834 cases)

Cases sha256 `92999e7d794a`, benchmark commit `916fda2f`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 118 | 0.712 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 2781 | 0.635 | 7 | 0.996 | 7 | 0.996 | - |

## piilo, split dev (4024 cases)

Cases sha256 `5470a9df5eb6`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 873 | 0.099 | 39 | 0.688 | 38 | 0.694 | pii.ip 1 |

## piilo, split holdout (1405 cases)

Cases sha256 `7385f3f4158b`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 322 | 0.087 | 15 | 0.651 | 15 | 0.651 | - |

## piilo, split holdout, sample 1 in 25 (salt `v3/`) (46 cases)

Cases sha256 `c14a711017e1`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 8 | - | 0 | - | 0 | - | - |

## piilo, split val (1378 cases)

Cases sha256 `7b3a5684813e`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 301 | 0.090 | 9 | 0.750 | 9 | 0.750 | - |

## piilo, split val, sample 1 in 25 (salt `v3/`) (55 cases)

Cases sha256 `17bbba8573a1`, benchmark commit `916fda2f`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 8 | - | 0 | 1.000 | 0 | 1.000 | - |

## privy, split all (28843 cases)

Cases sha256 `3d471990ca13`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 756 | 0.815 | 111 | 0.848 | 111 | 0.848 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 11247 | 0.725 | 3382 | 0.707 | 67 | 0.992 | pii.national_id 826, pii.iban 820, pii.ip 760, pii.email 738 |

## privy, split all, sample 1 in 10 (salt `v3/`) (2816 cases)

Cases sha256 `092dd3e63d0f`, benchmark commit `916fda2f`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 90 | 0.856 | 6 | 0.928 | 6 | 0.928 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.11+916fda2f (916fda2f) | 1076 | 0.716 | 340 | 0.694 | 2 | 0.997 | pii.email 88, pii.national_id 79, pii.iban 76, pii.ip 66 |

