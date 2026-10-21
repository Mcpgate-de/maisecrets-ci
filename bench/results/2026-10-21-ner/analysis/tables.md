
### Samples of 1 in 50 (all `dev`)

| Variant | nemotron: names whole / added FP / PII precision | gretel: names whole / added FP / PII precision | mendeley: names whole / added FP / PII precision | piilo: names whole / added FP / PII precision |
|---|---|---|---|---|
| maisecrets 0.7.3 | 743 of 2696 (27.6 %) / – / 0.9964 | 189 of 1409 (13.4 %) / – / 0.9274 | 273 of 1485 (18.4 %) / – / 0.9868 | 1 of 14 (7.1 %) / – / 1.0 |
| + spaCy sm | 2245 (83.3 %) / 730 / 0.8619 | 764 (54.2 %) / 2731 / 0.3696 | 1350 (90.9 %) / 763 / 0.8535 | 11 (78.6 %) / 150 / 0.0741 |
| + spaCy lg | 2434 (90.3 %) / 96 / 0.9777 | 802 (56.9 %) / 2264 / 0.4194 | 1404 (94.5 %) / 715 / 0.8619 | 13 (92.9 %) / 48 / 0.2258 |
| + GLiNER 0.5 | 2518 (93.4 %) / 1468 / 0.7694 | 971 (68.9 %) / 1392 / 0.5258 | 1465 (98.7 %) / 1102 / 0.8018 | 13 (92.9 %) / 2160 / 0.0064 |
| + GLiNER 0.3 | 2540 (94.2 %) / 2010 / 0.7108 | 991 (70.3 %) / 1889 / 0.4577 | 1466 (98.7 %) / 1272 / 0.7792 | 13 (92.9 %) / 2766 / 0.005 |
| + DistilBERT | 2521 (93.5 %) / 329 / 0.9436 | 702 (49.8 %) / 1681 / 0.567 | 1426 (96.0 %) / 749 / 0.8562 | 6 (42.9 %) / 91 / 0.099 |
| + DistilBERT, whole words | 2531 (93.9 %) / 140 / 0.9696 | 713 (50.6 %) / 570 / 0.7276 | 1426 (96.0 %) / 575 / 0.8821 | 6 (42.9 %) / 50 / 0.1379 |
| + multilingual DistilBERT, whole words | 2486 (92.2 %) / 38 / 0.9895 | 674 (47.8 %) / 81 / 0.918 | 1410 (94.9 %) / 746 / 0.8557 | 8 (57.1 %) / 48 / 0.1724 |

### Full datasets (all splits)

| Variant | nemotron: names whole / added FP / PII precision | gretel: names whole / added FP / PII precision | mendeley: names whole / added FP / PII precision | piilo: names whole / added FP / PII precision |
|---|---|---|---|---|
| maisecrets 0.7.3 | 41959 of 143639 (29.2 %) / – / 0.9954 | 9801 of 77117 (12.7 %) / – / 0.909 | 14748 of 77200 (19.1 %) / – / 0.9897 | 98 of 1365 (7.2 %) / – / 0.9216 |
| + spaCy sm | 120827 (84.1 %) / 39908 / 0.8545 | 40706 (52.8 %) / 130444 / 0.3839 | 70608 (91.5 %) / 38573 / 0.8576 | 902 (66.1 %) / 8877 / 0.0977 |
| + spaCy lg | 131404 (91.5 %) / 5863 / 0.9736 | 45042 (58.4 %) / 108953 / 0.4381 | 73385 (95.1 %) / 37420 / 0.8622 | 1094 (80.1 %) / 4039 / 0.2217 |
| + GLiNER 0.5 | not run | not run | not run | not run |
| + GLiNER 0.3 | not run | not run | not run | not run |
| + DistilBERT | not run | not run | not run | not run |
| + DistilBERT, whole words | not run | not run | not run | not run |
| + multilingual DistilBERT, whole words | not run | not run | not run | not run |

### Spans made worse, and PERSON spans dropped on a deterministic finding

| Variant | spans made worse (all files) | dropped on a finding (all files), by its type |
|---|---:|---|
| spaCy sm | 0 | 65252: pii.name 36071, pii.address 22036, pii.card 3982, pii.email 1199, pii.username 701 |
| spaCy lg | 0 | 71551: pii.name 47860, pii.address 20647, pii.username 1040, pii.card 728, pii.email 495 |
| GLiNER 0.5 | 0 | 1637: pii.name 960, pii.email 572, pii.username 81, secret 12, pii.national_id 10 |
| GLiNER 0.3 | 0 | 1822: pii.name 981, pii.email 693, pii.username 84, pii.national_id 35, secret 21 |
| DistilBERT | 0 | 1959: pii.name 1301, pii.email 359, pii.address 192, pii.username 105, pii.national_id 1 |
| DistilBERT, whole words | 0 | 1058: pii.name 883, pii.address 122, pii.email 32, pii.username 19, pii.national_id 1 |
| multilingual DistilBERT, whole words | 0 | 1069: pii.name 866, pii.address 179, pii.username 9, secret 8, pii.email 7 |

### Names in running text and in record fields (samples)

| Variant | prose: whole before → after (of spans) | person-cue: whole before → after (of spans) | label-same: whole before → after (of spans) | record-field: whole before → after (of spans) |
|---|---|---|---|---|
| spaCy sm | 498 → 2540 (3349) | 315 → 1017 (1134) | 369 → 426 (489) | 14 → 144 (295) |
| spaCy lg | 498 → 2712 (3349) | 315 → 1069 (1134) | 369 → 453 (489) | 14 → 162 (295) |
| GLiNER 0.5 | 498 → 2931 (3349) | 315 → 1087 (1134) | 369 → 459 (489) | 14 → 207 (295) |
| GLiNER 0.3 | 498 → 2958 (3349) | 315 → 1095 (1134) | 369 → 463 (489) | 14 → 208 (295) |
| DistilBERT | 498 → 2786 (3349) | 315 → 1059 (1134) | 369 → 434 (489) | 14 → 140 (295) |
| DistilBERT, whole words | 498 → 2800 (3349) | 315 → 1059 (1134) | 369 → 436 (489) | 14 → 142 (295) |
| multilingual DistilBERT, whole words | 498 → 2737 (3349) | 315 → 1053 (1134) | 369 → 413 (489) | 14 → 144 (295) |

### Gretel by language (samples): whole names before → after (of spans), added false positives

| Variant | us | de | es | fr | it | nl | se |
|---|---|---|---|---|---|---|---|
| spaCy sm | 109 → 382 (547), FP 329 | 11 → 99 (170), FP 587 | 21 → 58 (139), FP 530 | 7 → 32 (65), FP 211 | 17 → 64 (132), FP 306 | 18 → 57 (169), FP 442 | 6 → 72 (187), FP 326 |
| spaCy lg | 109 → 394 (547), FP 161 | 11 → 101 (170), FP 554 | 21 → 57 (139), FP 318 | 7 → 34 (65), FP 133 | 17 → 72 (132), FP 381 | 18 → 67 (169), FP 407 | 6 → 77 (187), FP 310 |
| GLiNER 0.5 | 109 → 472 (547), FP 885 | 11 → 110 (170), FP 104 | 21 → 91 (139), FP 104 | 7 → 49 (65), FP 63 | 17 → 96 (132), FP 68 | 18 → 74 (169), FP 94 | 6 → 79 (187), FP 74 |
| GLiNER 0.3 | 109 → 481 (547), FP 1171 | 11 → 112 (170), FP 138 | 21 → 96 (139), FP 150 | 7 → 50 (65), FP 100 | 17 → 97 (132), FP 91 | 18 → 75 (169), FP 129 | 6 → 80 (187), FP 110 |
| DistilBERT | 109 → 379 (547), FP 471 | 11 → 72 (170), FP 232 | 21 → 55 (139), FP 110 | 7 → 24 (65), FP 142 | 17 → 57 (132), FP 102 | 18 → 52 (169), FP 413 | 6 → 63 (187), FP 211 |
| DistilBERT, whole words | 109 → 383 (547), FP 209 | 11 → 74 (170), FP 82 | 21 → 55 (139), FP 38 | 7 → 24 (65), FP 45 | 17 → 61 (132), FP 33 | 18 → 53 (169), FP 106 | 6 → 63 (187), FP 57 |
| multilingual DistilBERT, whole words | 109 → 360 (547), FP 37 | 11 → 62 (170), FP 11 | 21 → 67 (139), FP 6 | 7 → 24 (65), FP 10 | 17 → 60 (132), FP 5 | 18 → 46 (169), FP 9 | 6 → 55 (187), FP 3 |

### Full datasets by split (A and B): whole names before → after (of spans)

- spaCy sm: dev 39726 → 139269 of 178624; val 13463 → 46276 of 59339; holdout 13417 → 47498 of 61358
- spaCy lg: dev 39726 → 149952 of 178624; val 13463 → 49724 of 59339; holdout 13417 → 51249 of 61358

### False positives the layer adds, by family (samples, `dev`)

| Variant | record field | technical identifier | company word | one word at a sentence start | role or title words | rest | on a gold span of another class (not a false positive) |
|---|---|---|---|---|---|---|---|
| spaCy sm | 498 | 246 | 2 | 431 | 3 | 3194 | 478 |
| spaCy lg | 115 | 138 | 0 | 209 | 0 | 2661 | 458 |
| GLiNER 0.5 | 90 | 44 | 39 | 954 | 570 | 4425 | 260 |
| GLiNER 0.3 | 145 | 77 | 62 | 1137 | 687 | 5829 | 293 |
| DistilBERT | 65 | 3 | 3 | 320 | 0 | 2459 | 616 |
| DistilBERT, whole words | 38 | 1 | 0 | 278 | 10 | 1008 | 272 |
| multilingual DistilBERT, whole words | 3 | 0 | 0 | 34 | 8 | 868 | 207 |
