# Benchmark V3 report

Recall as in V1 and V2 (strict: the span masked whole). P(V2): a finding on no labelled span is wrong. P(V3): only a finding of a class the source labels counts (`bench/v3_scope.json`); the rest is listed as out of scope. A class in `lower bound` has labels a read sample showed not exhaustive: its precision is a lower bound. Privy is never read: its precision is observed under incomplete annotation.

## aparte, split dev (465 cases)

Cases sha256 `07720cd6ee27`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 460 | 0.815 | 16 | 0.959 | 16 | 0.959 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 0 | - | 76 | 0.000 | 0 | - | pii.email 33, pii.iban 29, pii.phone 14 |

## aparte, split holdout (880 cases)

Cases sha256 `6505185380ef`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 792 | 0.333 | 2 | 0.993 | 2 | 0.993 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 0 | - | 181 | 0.000 | 0 | - | pii.email 100, pii.iban 76, pii.bank_account 3, pii.ip 2 |

## aparte, split val (310 cases)

Cases sha256 `42afc41014af`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 296 | 0.804 | 8 | 0.968 | 8 | 0.968 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 0 | - | 61 | 0.000 | 0 | - | pii.iban 27, pii.email 22, pii.phone 12 |

## bank, split dev (120 cases)

Cases sha256 `6f8fcea6ab3f`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 54 | 1.000 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 120 | 0.942 | 0 | 1.000 | 0 | 1.000 | - |

## bank, split val (33 cases)

Cases sha256 `7d350302c12c`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 27 | - | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 24 | - | 0 | 1.000 | 0 | 1.000 | - |

## credsweeper, split dev (114 cases)

Cases sha256 `8ce64f62567a`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 352 | 0.727 | 68 | 0.790 | 68 | 0.790 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 0 | - | 55 | 0.000 | 0 | - | pii.ip 52, pii.email 2, pii.username 1 |

## credsweeper, split holdout (50 cases)

Cases sha256 `095ec645edb7`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 79 | 0.671 | 10 | 0.846 | 10 | 0.846 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 0 | - | 4 | 0.000 | 0 | - | pii.name 2, pii.email 1, pii.username 1 |

## credsweeper, split val (35 cases)

Cases sha256 `648d2b73a6eb`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 130 | 0.885 | 16 | 0.878 | 16 | 0.878 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 0 | - | 7 | 0.000 | 0 | - | pii.ip 6, pii.email 1 |

## gretel, split dev (25066 cases)

Cases sha256 `59f13e70d759`, benchmark commit `cc52a362`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 855 | 0.471 | 82 | 0.833 | 82 | 0.833 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 78610 | 0.321 | 2796 | 0.902 | 2796 | 0.902 | - |

## gretel, split holdout (8507 cases)

Cases sha256 `9a19609497fe`, benchmark commit `cc52a362`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 287 | 0.408 | 24 | 0.832 | 24 | 0.832 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 26718 | 0.308 | 888 | 0.905 | 888 | 0.905 | - |

## gretel, split holdout, sample 1 in 25 (salt `v3/`) (336 cases)

Cases sha256 `212270da7f07`, benchmark commit `cc52a362`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 9 | - | 1 | 0.750 | 1 | 0.750 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 1009 | 0.324 | 29 | 0.920 | 29 | 0.920 | - |

## gretel, split val (8359 cases)

Cases sha256 `631b8af7fe5e`, benchmark commit `cc52a362`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 269 | 0.476 | 21 | 0.862 | 21 | 0.862 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 25894 | 0.308 | 974 | 0.894 | 974 | 0.894 | - |

## gretel, split val, sample 1 in 25 (salt `v3/`) (334 cases)

Cases sha256 `689791d6f120`, benchmark commit `cc52a362`. Lower bound: pii.bank_account.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 12 | - | 1 | 0.833 | 1 | 0.833 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 1141 | 0.316 | 39 | 0.906 | 39 | 0.906 | - |

## llmredactor, split dev (187 cases)

Cases sha256 `c2bad5452d0b`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 329 | 0.909 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 50 | 0.960 | 0 | 1.000 | 0 | 1.000 | - |

## llmredactor, split holdout (61 cases)

Cases sha256 `6c769e3866b3`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 107 | 0.916 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 12 | - | 0 | 1.000 | 0 | 1.000 | - |

## llmredactor, split val (52 cases)

Cases sha256 `15165265781f`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 80 | 0.912 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 10 | - | 0 | 1.000 | 0 | 1.000 | - |

## mendeley, split dev (26945 cases)

Cases sha256 `a837d51d142b`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 154793 | 0.702 | 1310 | 0.988 | 1310 | 0.988 | - |

## mendeley, split holdout (9084 cases)

Cases sha256 `b6188553c5a7`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 52450 | 0.699 | 421 | 0.989 | 421 | 0.989 | - |

## mendeley, split holdout, sample 1 in 25 (salt `v3/`) (398 cases)

Cases sha256 `3dc654b710e9`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 2360 | 0.689 | 20 | 0.988 | 20 | 0.988 | - |

## mendeley, split val (9001 cases)

Cases sha256 `3a19407f7433`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 51592 | 0.702 | 391 | 0.989 | 391 | 0.989 | - |

## mendeley, split val, sample 1 in 25 (salt `v3/`) (362 cases)

Cases sha256 `9bae655af341`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 2084 | 0.706 | 18 | 0.988 | 18 | 0.988 | - |

## nemotron, split dev (59965 cases)

Cases sha256 `4572e95c9a86`, benchmark commit `cc52a362`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 6998 | 0.685 | 20 | 0.996 | 20 | 0.996 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 200710 | 0.625 | 506 | 0.996 | 502 | 0.996 | pii.iban 4 |

## nemotron, split holdout (20229 cases)

Cases sha256 `b8d859efa101`, benchmark commit `cc52a362`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 2257 | 0.687 | 7 | 0.996 | 7 | 0.996 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 68086 | 0.621 | 198 | 0.995 | 198 | 0.995 | - |

## nemotron, split holdout, sample 1 in 25 (salt `v3/`) (816 cases)

Cases sha256 `bd52e8a68548`, benchmark commit `cc52a362`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 92 | 0.663 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 2909 | 0.609 | 7 | 0.996 | 7 | 0.996 | - |

## nemotron, split val (19806 cases)

Cases sha256 `26eb1c2513f5`, benchmark commit `cc52a362`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 2397 | 0.689 | 10 | 0.994 | 10 | 0.994 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 66240 | 0.628 | 183 | 0.995 | 183 | 0.995 | - |

## nemotron, split val, sample 1 in 25 (salt `v3/`) (834 cases)

Cases sha256 `92999e7d794a`, benchmark commit `cc52a362`. Lower bound: pii.national_id.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 118 | 0.712 | 0 | 1.000 | 0 | 1.000 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 2781 | 0.621 | 7 | 0.996 | 7 | 0.996 | - |

## piilo, split dev (4024 cases)

Cases sha256 `5470a9df5eb6`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 873 | 0.099 | 39 | 0.688 | 38 | 0.694 | pii.ip 1 |

## piilo, split holdout (1405 cases)

Cases sha256 `7385f3f4158b`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 322 | 0.087 | 14 | 0.667 | 14 | 0.667 | - |

## piilo, split holdout, sample 1 in 25 (salt `v3/`) (46 cases)

Cases sha256 `c14a711017e1`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 8 | - | 0 | - | 0 | - | - |

## piilo, split val (1378 cases)

Cases sha256 `7b3a5684813e`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 301 | 0.090 | 9 | 0.750 | 9 | 0.750 | - |

## piilo, split val, sample 1 in 25 (salt `v3/`) (55 cases)

Cases sha256 `17bbba8573a1`, benchmark commit `cc52a362`. Lower bound: none.

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 8 | - | 0 | 1.000 | 0 | 1.000 | - |

## privy, split all (28843 cases)

Cases sha256 `3d471990ca13`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 756 | 0.815 | 111 | 0.848 | 111 | 0.848 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 11247 | 0.725 | 3382 | 0.707 | 67 | 0.992 | pii.national_id 826, pii.iban 820, pii.ip 760, pii.email 738 |

## privy, split all, sample 1 in 10 (salt `v3/`) (2816 cases)

Cases sha256 `092dd3e63d0f`, benchmark commit `cc52a362`. Lower bound: none.

### secret

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 90 | 0.856 | 6 | 0.928 | 6 | 0.928 | - |

### pii

| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope (V3) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| maisecrets | 0.9.9+cc52a362 (cc52a362) | 1076 | 0.716 | 340 | 0.694 | 2 | 0.997 | pii.email 88, pii.national_id 79, pii.iban 76, pii.ip 66 |

