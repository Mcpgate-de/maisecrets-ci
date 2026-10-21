## bank, split dev (75 cases)

Cases sha256 `6fe1029ba80e`, benchmark commit `93e46e05`.

### secret

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| detect-secrets | 1.5.0 | 51 | 18 | 9 | 24 | 0.353 | 0.529 | 0.217 | 1.000 | 0 | 1.000 | 0.522 | 0 | 0.0 | 0.46 |
| maisecrets | 0.7.3 (eee4b2e0) | 51 | 48 | 0 | 3 | 0.941 | 0.941 | 0.990 | 1.000 | 0 | 1.000 | 0.970 | 0 | 0.0 | 0.49 |
| preserve | 0.6.1 (01dbd771) | 51 | 36 | 4 | 11 | 0.706 | 0.784 | 0.647 | 1.000 | 6 | 0.870 | 0.779 | 3 | 666.7 | 38.73 |
| secret-scan | 0.4.2 (7d8b5c18) | 51 | 39 | 3 | 9 | 0.765 | 0.824 | 0.563 | 1.000 | 9 | 0.864 | 0.811 | 6 | 272.7 | 0.17 |

| Class | detect-secrets | maisecrets | preserve | secret-scan |
|---|---|---|---|---|
| secret.generic | 3 / 0 / 0 | 3 / 0 / 0 | 0 / 0 / 3 | 3 / 0 / 0 |
| secret.password | 3 / 0 / 9 | 9 / 0 / 3 | 9 / 0 / 3 | 9 / 0 / 3 |
| secret.private_key | 0 / 3 / 0 | 3 / 0 / 0 | 3 / 0 / 0 | 0 / 3 / 0 |
| secret.token | 12 / 6 / 9 | 27 / 0 / 0 | 24 / 0 / 3 | 27 / 0 / 0 |
| secret.webhook | 0 / 0 / 6 | 6 / 0 / 0 | 0 / 4 / 2 | 0 / 0 / 6 |

Cells: full / partial / missed spans.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 42 | 36 | 0 | 6 | 0.857 | 0.857 | 0.910 | 1.000 | 0 | 1.000 | 0.923 | 0 | 0.0 | 0.49 |
| pii-anon | 1.7.0rc1 (2171ace5) | 42 | 30 | 7 | 5 | 0.714 | 0.881 | 0.870 | 1.000 | 18 | 0.690 | 0.702 | 0 | 210.5 | 0.40 |
| preserve | 0.6.1 (01dbd771) | 42 | 36 | 3 | 3 | 0.857 | 0.929 | 0.954 | 1.000 | 18 | 0.684 | 0.761 | 3 | 666.7 | 38.73 |

| Class | maisecrets | pii-anon | preserve |
|---|---|---|---|
| pii.email | 12 / 0 / 0 | 12 / 0 / 0 | 12 / 0 / 0 |
| pii.iban | 6 / 0 / 0 | 3 / 1 / 2 | 6 / 0 / 0 |
| pii.ip | 3 / 0 / 0 | 3 / 0 / 0 | 3 / 0 / 0 |
| pii.name | 3 / 0 / 3 | 6 / 0 / 0 | 6 / 0 / 0 |
| pii.phone | 9 / 0 / 0 | 3 / 6 / 0 | 9 / 0 / 0 |
| pii.tax_id | 0 / 0 / 3 | 0 / 0 / 3 | 0 / 3 / 0 |
| pii.username | 3 / 0 / 0 | 3 / 0 / 0 | 0 / 0 / 3 |

Cells: full / partial / missed spans.

## bank, split val (33 cases)

Cases sha256 `7d350302c12c`, benchmark commit `93e46e05`.

### secret

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| detect-secrets | 1.5.0 | 27 | 11 | 3 | 13 | - | - | - | - | 0 | 1.000 | - | 0 | 0.0 | 0.38 |
| maisecrets | 0.7.3 (eee4b2e0) | 27 | 24 | 0 | 3 | - | - | - | - | 0 | 1.000 | - | 0 | 0.0 | 0.52 |
| preserve | 0.6.1 (01dbd771) | 27 | 12 | 0 | 15 | - | - | - | - | 0 | 1.000 | - | 0 | 1000.0 | 58.49 |
| secret-scan | 0.4.2 (7d8b5c18) | 27 | 12 | 0 | 15 | - | - | - | - | 0 | 1.000 | - | 0 | 0.0 | 0.16 |

| Class | detect-secrets | maisecrets | preserve | secret-scan |
|---|---|---|---|---|
| secret.generic | 0 / 0 / 3 | 3 / 0 / 0 | 3 / 0 / 0 | 3 / 0 / 0 |
| secret.password | 0 / 0 / 3 | 0 / 0 / 3 | 0 / 0 / 3 | 0 / 0 / 3 |
| secret.token | 8 / 3 / 4 | 15 / 0 / 0 | 9 / 0 / 6 | 9 / 0 / 6 |
| secret.webhook | 3 / 0 / 3 | 6 / 0 / 0 | 0 / 0 / 6 | 0 / 0 / 6 |

Cells: full / partial / missed spans.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 24 | 12 | 0 | 12 | - | - | - | - | 0 | 1.000 | - | 0 | 0.0 | 0.52 |
| pii-anon | 1.7.0rc1 (2171ace5) | 24 | 20 | 0 | 4 | - | - | - | - | 12 | 0.625 | - | 0 | 500.0 | 0.32 |
| preserve | 0.6.1 (01dbd771) | 24 | 18 | 1 | 5 | - | - | - | - | 9 | 0.667 | - | 0 | 1000.0 | 58.49 |

| Class | maisecrets | pii-anon | preserve |
|---|---|---|---|
| pii.address | 0 / 0 / 3 | 0 / 0 / 3 | 0 / 1 / 2 |
| pii.birth_date | 0 / 0 / 3 | 3 / 0 / 0 | 0 / 0 / 3 |
| pii.card | 3 / 0 / 0 | 3 / 0 / 0 | 3 / 0 / 0 |
| pii.email | 6 / 0 / 0 | 6 / 0 / 0 | 6 / 0 / 0 |
| pii.name | 0 / 0 / 6 | 6 / 0 / 0 | 6 / 0 / 0 |
| pii.phone | 3 / 0 / 0 | 2 / 0 / 1 | 3 / 0 / 0 |

Cells: full / partial / missed spans.

## catalogs, split all (11902 cases)

Cases sha256 `6c3b05a075ce`, benchmark commit `93e46e05`.

### secret

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| detect-secrets | 1.5.0 | 11902 | 2802 | 750 | 8350 | 0.235 | 0.298 | 0.308 | 1.000 | 0 | 1.000 | 0.381 | 0 | - | 0.32 |
| maisecrets | 0.7.3 (eee4b2e0) | 11902 | 6976 | 301 | 4625 | 0.586 | 0.611 | 0.607 | 0.997 | 0 | 1.000 | 0.739 | 0 | - | 0.25 |
| preserve | 0.6.1 (01dbd771) | 11902 | 680 | 1256 | 9966 | 0.057 | 0.163 | 0.146 | 0.900 | 0 | 1.000 | 0.108 | 0 | - | 22.84 |
| secret-scan | 0.4.2 (7d8b5c18) | 11902 | 868 | 128 | 10906 | 0.073 | 0.084 | 0.142 | 1.000 | 0 | 1.000 | 0.136 | 0 | - | 0.10 |

| Class | detect-secrets | maisecrets | preserve | secret-scan |
|---|---|---|---|---|
| secret.token | 2776 / 738 / 8112 | 6876 / 266 / 4484 | 680 / 1216 / 9730 | 868 / 126 / 10632 |
| secret.webhook | 26 / 12 / 238 | 100 / 35 / 141 | 0 / 40 / 236 | 0 / 2 / 274 |

Cells: full / partial / missed spans.

## gretel, split all (41932 cases)

Cases sha256 `f99130f699cd`, benchmark commit `93e46e05`.

### secret

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 1411 | 546 | 5 | 860 | 0.387 | 0.391 | 0.482 | 1.000 | 95 | 0.853 | 0.532 | 326 | 53.0 | 2.92 |

| Class | maisecrets |
|---|---|
| secret.generic | 378 / 0 / 370 |
| secret.password | 168 / 5 / 490 |

Cells: full / partial / missed spans.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 131222 | 37080 | 722 | 93420 | 0.283 | 0.288 | 0.340 | 0.996 | 3767 | 0.909 | 0.431 | 326 | 53.0 | 2.92 |

| Class | maisecrets |
|---|---|
| pii.address | 8585 / 360 / 22469 |
| pii.bank_account | 55 / 0 / 74 |
| pii.birth_date | 1307 / 0 / 605 |
| pii.card | 438 / 0 / 63 |
| pii.email | 8508 / 43 / 5 |
| pii.iban | 1160 / 0 / 25 |
| pii.ip | 1929 / 0 / 144 |
| pii.name | 9801 / 235 / 67081 |
| pii.national_id | 1981 / 4 / 1062 |
| pii.phone | 3172 / 78 / 1313 |
| pii.username | 144 / 2 / 579 |

Cells: full / partial / missed spans.

## gretel, split all, sample 1 in 50 (837 cases)

Cases sha256 `d45ec8200a8b`, benchmark commit `93e46e05`.

### secret

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| detect-secrets | 1.5.0 | 25 | 7 | 0 | 18 | - | - | - | - | 12 | 0.429 | - | 0 | 13.5 | 3.93 |
| maisecrets | 0.7.3 (eee4b2e0) | 25 | 10 | 0 | 15 | - | - | - | - | 2 | 0.833 | - | 7 | 22.6 | 2.88 |
| preserve | 0.6.1 (01dbd771) | 25 | 5 | 0 | 20 | - | - | - | - | 2 | 0.714 | - | 62 | 6525.4 | 179.78 |
| secret-scan | 0.4.2 (7d8b5c18) | 25 | 7 | 1 | 17 | - | - | - | - | 2 | 0.818 | - | 0 | 2.5 | 0.34 |

| Class | detect-secrets | maisecrets | preserve | secret-scan |
|---|---|---|---|---|
| secret.generic | 7 / 0 / 10 | 9 / 0 / 8 | 5 / 0 / 12 | 5 / 1 / 11 |
| secret.password | 0 / 0 / 8 | 1 / 0 / 7 | 0 / 0 / 8 | 2 / 0 / 6 |

Cells: full / partial / missed spans.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 2510 | 759 | 12 | 1739 | 0.302 | 0.307 | 0.349 | 0.995 | 60 | 0.927 | 0.456 | 7 | 22.6 | 2.88 |
| pii-anon | 1.7.0rc1 (2171ace5) | 2510 | 1056 | 607 | 847 | 0.421 | 0.662 | 0.584 | 1.000 | 6500 | 0.221 | 0.289 | 25 | 8113.0 | 4.69 |
| preserve | 0.6.1 (01dbd771) | 2510 | 1109 | 618 | 783 | 0.442 | 0.688 | 0.591 | 1.000 | 6322 | 0.222 | 0.296 | 62 | 6525.4 | 179.78 |

| Class | maisecrets | pii-anon | preserve |
|---|---|---|---|
| pii.address | 177 / 7 / 461 | 39 / 350 / 256 | 3 / 366 / 276 |
| pii.bank_account | 0 / 0 / 1 | 1 / 0 / 0 | 0 / 0 / 1 |
| pii.birth_date | 28 / 0 / 17 | 37 / 0 / 8 | 35 / 1 / 9 |
| pii.card | 11 / 0 / 1 | 12 / 0 / 0 | 12 / 0 / 0 |
| pii.email | 163 / 0 / 0 | 163 / 0 / 0 | 163 / 0 / 0 |
| pii.iban | 21 / 0 / 0 | 20 / 1 / 0 | 20 / 1 / 0 |
| pii.ip | 50 / 0 / 0 | 50 / 0 / 0 | 50 / 0 / 0 |
| pii.name | 189 / 2 / 1218 | 650 / 252 / 507 | 713 / 244 / 452 |
| pii.national_id | 47 / 0 / 14 | 39 / 0 / 22 | 29 / 2 / 30 |
| pii.phone | 67 / 3 / 21 | 38 / 4 / 49 | 81 / 4 / 6 |
| pii.username | 6 / 0 / 6 | 7 / 0 / 5 | 3 / 0 / 9 |

Cells: full / partial / missed spans.

## mendeley, split all (45030 cases)

Cases sha256 `3740c7589dfe`, benchmark commit `93e46e05`.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 258835 | 177394 | 742 | 80699 | 0.685 | 0.688 | 0.678 | 1.000 | 1859 | 0.990 | 0.810 | 0 | 0.0 | 1.48 |

| Class | maisecrets |
|---|---|
| pii.address | 30121 / 144 / 15999 |
| pii.card | 39060 / 0 / 0 |
| pii.name | 14748 / 598 / 61854 |
| pii.national_id | 51283 / 0 / 0 |
| pii.phone | 42182 / 0 / 2846 |

Cells: full / partial / missed spans.

## mendeley, split all, sample 1 in 50 (872 cases)

Cases sha256 `02eeb7c5280f`, benchmark commit `93e46e05`.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 5011 | 3429 | 16 | 1566 | 0.684 | 0.688 | 0.677 | 1.000 | 46 | 0.987 | 0.808 | 0 | - | 1.50 |
| pii-anon | 1.7.0rc1 (2171ace5) | 5011 | 2965 | 1351 | 695 | 0.592 | 0.861 | 0.659 | 1.000 | 5020 | 0.500 | 0.542 | 0 | - | 6.44 |
| preserve | 0.6.1 (01dbd771) | 5011 | 3274 | 671 | 1066 | 0.653 | 0.787 | 0.577 | 1.000 | 1233 | 0.762 | 0.704 | 0 | - | 156.93 |

| Class | maisecrets | pii-anon | preserve |
|---|---|---|---|
| pii.address | 574 / 1 / 319 | 0 / 663 / 231 | 0 / 407 / 487 |
| pii.card | 769 / 0 / 0 | 524 / 0 / 245 | 769 / 0 / 0 |
| pii.name | 273 / 15 / 1197 | 1450 / 33 / 2 | 642 / 264 / 579 |
| pii.national_id | 991 / 0 / 0 | 991 / 0 / 0 | 991 / 0 / 0 |
| pii.phone | 822 / 0 / 50 | 0 / 655 / 217 | 872 / 0 / 0 |

Cells: full / partial / missed spans.

## nemotron, split all (100000 cases)

Cases sha256 `868ca339d17f`, benchmark commit `93e46e05`.

### secret

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 11652 | 5280 | 62 | 6310 | 0.453 | 0.459 | 0.352 | 0.997 | 33 | 0.994 | 0.622 | 46 | 12.0 | 1.88 |

| Class | maisecrets |
|---|---|
| secret.generic | 1362 / 11 / 3294 |
| secret.password | 3918 / 51 / 3016 |

Cells: full / partial / missed spans.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 335036 | 198625 | 320 | 136091 | 0.593 | 0.594 | 0.734 | 1.000 | 865 | 0.995 | 0.743 | 46 | 12.0 | 1.88 |

| Class | maisecrets |
|---|---|
| pii.address | 6252 / 69 / 10558 |
| pii.bank_account | 11521 / 2 / 980 |
| pii.birth_date | 16410 / 0 / 1669 |
| pii.card | 1516 / 0 / 11 |
| pii.email | 53549 / 1 / 0 |
| pii.iban | 3 / 2 / 1 |
| pii.ip | 7958 / 0 / 13 |
| pii.name | 41959 / 9 / 101671 |
| pii.national_id | 29979 / 183 / 4680 |
| pii.phone | 24000 / 54 / 6186 |
| pii.username | 5478 / 0 / 10322 |

Cells: full / partial / missed spans.

## nemotron, split all, sample 1 in 50 (1921 cases)

Cases sha256 `68724bde91ce`, benchmark commit `93e46e05`.

### secret

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| detect-secrets | 1.5.0 | 229 | 8 | 12 | 209 | 0.035 | 0.087 | 0.246 | 1.000 | 2 | 0.917 | 0.067 | 1 | 0.6 | 3.16 |
| maisecrets | 0.7.3 (eee4b2e0) | 229 | 101 | 1 | 127 | 0.441 | 0.445 | 0.318 | 1.000 | 0 | 1.000 | 0.612 | 0 | 4.4 | 1.96 |
| preserve | 0.6.1 (01dbd771) | 229 | 22 | 4 | 203 | 0.096 | 0.114 | 0.353 | 1.000 | 4 | 0.867 | 0.173 | 23 | 502.2 | 149.18 |
| secret-scan | 0.4.2 (7d8b5c18) | 229 | 39 | 1 | 189 | 0.170 | 0.175 | 0.372 | 1.000 | 0 | 1.000 | 0.291 | 0 | 0.0 | 0.21 |

| Class | detect-secrets | maisecrets | preserve | secret-scan |
|---|---|---|---|---|
| secret.generic | 4 / 12 / 84 | 27 / 0 / 73 | 20 / 0 / 80 | 18 / 0 / 82 |
| secret.password | 4 / 0 / 125 | 74 / 1 / 54 | 2 / 4 / 123 | 21 / 1 / 107 |

Cells: full / partial / missed spans.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 6471 | 3787 | 12 | 2672 | 0.585 | 0.587 | 0.724 | 1.000 | 13 | 0.996 | 0.737 | 0 | 4.4 | 1.96 |
| pii-anon | 1.7.0rc1 (2171ace5) | 6471 | 4861 | 176 | 1434 | 0.751 | 0.778 | 0.802 | 1.000 | 10356 | 0.293 | 0.422 | 4 | 5393.4 | 4.25 |
| preserve | 0.6.1 (01dbd771) | 6471 | 4323 | 334 | 1814 | 0.668 | 0.720 | 0.768 | 1.000 | 763 | 0.838 | 0.744 | 23 | 502.2 | 149.18 |

| Class | maisecrets | pii-anon | preserve |
|---|---|---|---|
| pii.address | 136 / 4 / 204 | 169 / 89 / 86 | 0 / 187 / 157 |
| pii.bank_account | 238 / 0 / 26 | 158 / 2 / 104 | 197 / 38 / 29 |
| pii.birth_date | 307 / 0 / 36 | 343 / 0 / 0 | 310 / 0 / 33 |
| pii.card | 16 / 0 / 0 | 16 / 0 / 0 | 16 / 0 / 0 |
| pii.email | 1007 / 0 / 0 | 1007 / 0 / 0 | 1007 / 0 / 0 |
| pii.ip | 189 / 0 / 0 | 177 / 2 / 10 | 189 / 0 / 0 |
| pii.name | 743 / 0 / 1953 | 2080 / 32 / 584 | 1777 / 1 / 918 |
| pii.national_id | 610 / 8 / 107 | 348 / 41 / 336 | 285 / 95 / 345 |
| pii.phone | 459 / 0 / 108 | 457 / 5 / 105 | 530 / 7 / 30 |
| pii.username | 82 / 0 / 238 | 106 / 5 / 209 | 12 / 6 / 302 |

Cells: full / partial / missed spans.

## piilo, split all (6807 cases)

Cases sha256 `9b72a8d24f11`, benchmark commit `93e46e05`.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 1496 | 141 | 0 | 1355 | 0.094 | 0.094 | 0.123 | 1.000 | 12 | 0.922 | 0.171 | 0 | 1.7 | 10.67 |

| Class | maisecrets |
|---|---|
| pii.address | 0 / 0 / 2 |
| pii.email | 39 / 0 / 0 |
| pii.name | 98 / 0 / 1267 |
| pii.national_id | 0 / 0 / 78 |
| pii.phone | 4 / 0 / 2 |
| pii.username | 0 / 0 / 6 |

Cells: full / partial / missed spans.

## piilo, split all, sample 1 in 50 (132 cases)

Cases sha256 `96c45ffa113c`, benchmark commit `93e46e05`.

### pii

| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | Median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| maisecrets | 0.7.3 (eee4b2e0) | 15 | 2 | 0 | 13 | - | - | - | - | 0 | 1.000 | - | 0 | 0.0 | 9.81 |
| pii-anon | 1.7.0rc1 (2171ace5) | 15 | 14 | 0 | 1 | - | - | - | - | 674 | 0.020 | - | 0 | 4926.2 | 11.02 |
| preserve | 0.6.1 (01dbd771) | 15 | 15 | 0 | 0 | - | - | - | - | 89 | 0.144 | - | 2 | 565.6 | 361.21 |

| Class | maisecrets | pii-anon | preserve |
|---|---|---|---|
| pii.email | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 |
| pii.name | 1 / 0 / 13 | 13 / 0 / 1 | 14 / 0 / 0 |

Cells: full / partial / missed spans.

