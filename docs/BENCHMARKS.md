# Benchmarks

This file is a snapshot. Each table names what was measured, how, the source and the date. The method and its
limits are in their own section. "Repeat this measurement" has the commands.

| Snapshot | |
|---|---|
| Date | 2026-10-14; the 0.6.24, 0.6.25 and 0.6.26 rows and sections: 2026-10-16; "Personal data after its label in more forms" and "vCard lines and company addresses in more forms": 2026-10-17 |
| maisecrets | v0.6.17 (tag `v0.6.17`); earlier releases from their tags; the CredData rows of 0.6.18 to 0.6.21 and the holdout section: 2026-10-15; 0.6.24, 0.6.25 and 0.6.26 from their release branches, 2026-10-16 |
| Data | Samsung CredData, commit `0b1940e171725ad8937311120b191602608a4801` (2026-09-29); four labelled PII datasets, pinned in "Labelled PII datasets" (2026-10-15) |
| Machine | Apple M5, 10 cores, macOS 27.0 |
| Python | 3.14.8 (CredData runs); 3.14.8 and 3.9.6 (timing) |
| Scripts | `scripts/measure_creddata.py`, `scripts/measure_scan_time.py`, `scripts/measure_datasets.py`, `tests/test_fp_corpus.py` |

## Benchmark V1 baseline, 0.6.39 (2026-10-19)

`docs/BENCHMARK-V1.md` defines the method; `bench/results/2026-10-19-v0.6.39.md` holds every table. maisecrets
`v0.6.39` against detect-secrets 1.5.0, secret-scan 0.4.2 (7d8b5c1), pii-anon 1.7.0rc1 (2171ace) and Preserve 0.6.1
(01dbd77), each only on the classes it claims. Strict recall counts a span only when it is masked whole; precision
counts a finding as right when it lies on sensitive text.

| Source | Family | maisecrets 0.6.39 | Others (same cases) | What it says |
|---|---|---|---|---|
| Bank, dev (75 cases) | secret | R 0.94, P 1.00, 0 FP | secret-scan R 0.77, P 0.86; Preserve R 0.71, P 0.87; detect-secrets R 0.35, P 1.00 | the forms maisecrets sees: written by this project, so a regression check, not a fair ranking |
| Rule examples of six catalogs (11,902 cases) | secret | R 0.59 | detect-secrets 0.24, secret-scan 0.07, Preserve 0.06 | provider token formats bare and after `token = `; no negatives, so no precision |
| Nemotron-PII, 1 in 50 (1,921 documents) | pii | R 0.48, P 0.996 | Preserve R 0.67, P 0.84; pii-anon R 0.75, P 0.29 | maisecrets finds no names or street addresses by design (README); the others find more and mask much ordinary text |
| Nemotron-PII, 1 in 50 | secret | R 0.32, P 1.00 | secret-scan 0.17, Preserve 0.10, detect-secrets 0.03 | passwords and keys in prose, mostly after a label |
| Gretel finance, 1 in 50 (837 documents) | pii | R 0.23, P 0.85 | Preserve R 0.44, P 0.22; pii-anon R 0.42, P 0.22 | the precision of maisecrets is lowest here; its false alarms are the next thing to read (dev split only) |
| Mendeley financial, 1 in 50 (872 documents) | pii | R 0.48, P 1.00 | Preserve R 0.65, P 0.76; pii-anon R 0.59, P 0.50 | |
| PIILO, full (6,807 essays) | pii | R 0.08, P 0.96 | – (the sample of 1 in 50 has 15 spans: too few for a rate) | names of students: maisecrets does not detect names |
| Private frozen holdout (80 cases) | both | R 0.83, P 1.00, 0 FP | not run for the others | `bench/HOLDOUT-LOG.md` |

Time per case, median: maisecrets 0.25 to 6.8 ms, detect-secrets 0.3 to 3.7 ms, secret-scan 0.1 to 0.4 ms, pii-anon 0.3
to 9.5 ms, Preserve 25 to 390 ms (the same machine, one process each). The false-alarm bank (seven trees,
`scripts/measure_fp_bank.py`) gives 0.6.39: 1,325 / 85 / 1,143 / 119 / 4 / 25 / 24 acted hits on CPython `Lib/`,
detect-secrets, ferret-scan, Preserve, starter-workflows, awesome-compose and tldr pages.

Not shown here: an overall rank. The tools have different aims (a secret scanner, a PII anonymiser, a guard of model
input), and the classes with fewer than 30 spans have no rate.
## Rule changes measured with Benchmark V1

### A user name after its label, and a tax id under `steuer_id`, 2026-10-19

The first rule change measured with Benchmark V1 (`docs/BENCHMARK-V1.md`) against the baseline of 0.6.39 (tag
`v0.6.39`); the same cases (the same case hash) on both sides.

- **Gap seen:** the bank's dev split (`bank/tool/user-record`, `bank/tool/csv-customers`): a user name after
  `"username":` and a German tax id under a CSV column `steuer_id` were missed. Nemotron-PII labels 15,800 user names;
  0.6.39 found 51 of them whole.
- **Cause:** user names had rules only in a URL, a home path and a table column; the tax id rule (`de-tax-id`, with
  its checksum) knew `steuer-id` and `steuerid` as context words, not `steuer_id`.
- **Fix:** the tool-channel rule `username-after-label` (`maisecrets/detection/personal.py`) reads the whole value after
  a label that names a user name and masks it whole or not at all; a service account, a placeholder, a schema word, a
  Kubernetes principal, a field or role name of dictionary words, code, and a value inside an `example:` stay. The
  tax id rule takes `steuer_id` and close spellings as context words; the checksum still decides. A CSV column for
  the social insurance, identity card or tax identification number (long names only) makes a table personal.
- **Inspiration:** the label bridge of pii-anon (the label gives the type); Presidio has no user name recognizer.

| Measure | 0.6.39 | This change |
|---|---|---|
| Bank, dev: full spans / false positives | 81 / 0 | 87 / 0 (tax id 0 → 3, user name 0 → 3) |
| Bank, val | 36 / 0 | 36 / 0 |
| Nemotron-PII (100,000 documents): user names found whole | 51 of 15,800 | 2,849 |
| Nemotron-PII: false positives, precision | 910, 0.9946 | 919, 0.9946 |
| Gretel (41,932 documents): user names found whole | 57 of 725 | 125 |
| Gretel: false positives, precision | 7,016, 0.8213 | 7,040, 0.8212 |
| Mendeley, PIILO, rule examples of six catalogs | – | no change in full spans or false positives |
| Private frozen holdout (80 cases) | R 0.875, 0 FP | no change (`bench/HOLDOUT-LOG.md`) |
| False-alarm bank, seven trees (`compare`) | – | +0 acted hits |
| Recorded test inputs (`scripts/detection_fingerprint.py` calls, 21,656) | – | 0 changed |
| Time per Nemotron document (1 in 10, three alternating runs) | 1.83 / 2.06 / 2.30 ms median | 1.93 / 2.23 / 2.60 ms median: −0.5 % and +2.6 % against the neighbouring runs of 0.6.39, within the drift of the machine during the runs |

Limits kept on purpose: prose that names a user name (`Use username: octavia77 in the walkthrough`) is masked like a
record; a value that is an e-mail address plus more (`a@b.net/tenant`) goes to the e-mail rule; a user name that is one
dictionary word (`porter2026`) stays unmasked; an `example:` key more than 40 lines above the label is not seen.
Review: codex Gate A (gpt-5.6-sol) rounds 1 to 3, each finding fixed; round 4 could not run (the workspace had no
credits), so the last reading is the author's own probes.

### An 8-digit date is no US bank account number, 2026-10-19

- **Gap seen:** Gretel, dev split, maisecrets with `us`: 2,730 of 4,148 false alarms came from `us-bank` (Presidio's
  `\b[0-9]{8,17}\b` with `account`, `bank`, `debit` … anywhere in 120 characters). In English text: 1,935 false alarms
  against 145 account numbers. The most frequent lengths were 8 and 10 digits.
- **Two fixes measured:** (A) the context word in the 30 characters before the number on its line, and no 8-digit
  date; (B) no 8-digit date only. Against the user-name change above, same cases:

| Measure | Before | A: label window and date | B: date only (merged) |
|---|---|---|---|
| Gretel: false positives, precision | 7,040, 0.821 | 3,593, 0.900 | 5,605, 0.852 |
| Gretel: full spans | 28,901 | 28,843 (bank −11, card −11, id −11, name −19) | 28,900 (birth date −1) |
| Nemotron: account numbers found whole | 9,051 of 12,503 | 8,800 | 9,051 |
| Mendeley: card numbers found whole | 31,687 of 39,060 | 31,006 | 31,687 |
| Nemotron, Mendeley: false positives | 919, 24 | 861, 24 | 913, 24 |

  A takes real card and account numbers that only `us-bank` finds today (no card word near them), so B is the change.
  The next step is a card rule that finds those numbers; then the window of A costs no card.
- **The birth date that B lost** (Gretel dev split, `Date of Birth: YYYYMMDD`) was masked only by chance, by
  `us-bank`. `birth-date-after-label` now reads the compact form after its label when it is a real past day: Gretel
  birth dates 1,196 (0.6.39) → 1,195 (B) → 1,199, false positives 5,605 → 5,606; nothing else changes.
- **All sources, all changes of this section against 0.6.39:** bank dev 81 → 87 full, 0 false positives; Nemotron
  166,039 → 168,846 full, 910 → 913 false positives; Gretel 28,820 → 28,904 full, 7,016 → 5,606 false positives;
  Mendeley, PIILO, catalogs, bank val unchanged; holdout unchanged before the birth date change (84 of 96, 0 false
  positives; not run after it, see "Splits"); false-alarm bank +0; recorded test inputs unchanged.

### Mastercard of the 2-series, 15-digit JCB, and the label window of `us-bank`, 2026-10-19

- **Gap seen:** the label window of A above lost 681 Mendeley card numbers. All 681 pass Luhn and start with 2:
  388 Mastercard numbers of the 2-series (2221 to 2720, 16 digits) and 293 JCB numbers of 15 digits (2131).
- **Cause:** Presidio's card pattern takes the first digits 1, 3, 4, 5 and 6, so these numbers never reached the Luhn
  check. Only `us-bank` covered them, by chance.
- **Fix 1, cards:** the first group of the card pattern takes both ranges (`PRESIDIO_CARD_FIRST`, applied only to the
  upstream text it expects), and the issuer table knows the 15-digit JCB.
- **Fix 2, `us-bank`:** the label must stand before the number on its own line, within 60 characters
  (`PRESIDIO_LABEL_BEFORE`). Presidio's window is 80 characters before and 40 after, across lines. 30 characters lost
  251 Nemotron account numbers ("the account number associated with this loan is ..."); across lines took 948 false
  alarms back for 25 numbers.

| Measure | Before (`next`, 31e1676e) | Fix 1: cards | Fix 1 and 2 |
|---|---|---|---|
| Mendeley: full spans, F1 | 123,987, 0.6477 | 127,725, 0.6608 (cards 31,687 → 35,425) | 128,890, 0.6648 (phone +1,165) |
| Gretel: false positives, precision, F1 | 5,606, 0.852, 0.3471 | 5,607, 0.853, 0.3477 (cards 238 → 305) | 3,687, 0.898, 0.3509 |
| Gretel: full spans lost by fix 2 | – | – | account −6, card −6, id −10, name −19, phone −3, birth date −1 |
| Nemotron: account numbers found whole, F1 | 9,051, 0.6538 | 9,051, 0.6538 | 8,978, 0.6537 |
| Nemotron: false positives | 913 | 913 | 873 |
| PIILO: full spans, false positives | 127, 5 | 127, 5 | 125, 4 |
| Bank dev, bank val | 87 / 0, 36 / 0 | no change | no change |
| False-alarm bank, seven trees (`compare`) | – | +2 (card test values of a card scanner's tests) | +0 against fix 1 |
| Recorded test inputs (`scripts/detection_fingerprint.py` calls, 21,656) | – | – | 0 changed |

### Account numbers whole: a hyphen, and a column named account number, 2026-10-19

- **Gap seen:** Nemotron, after the change above: 8,978 of 12,503 account numbers found whole, 2,197 in part. The
  most frequent shape of a miss was `999-9999999999` (1,541), after "account number" on the same line.
- **Cause:** `us-bank` (`\b[0-9]{8,17}\b`) took the digits after the hyphen; that shorter hit won the overlap against
  `id-number-after-label`, which had the whole number, so the first digits reached the model. The label rule also
  missed `account_number` and `accountNumber`.
- **Fix 1:** `us-bank` takes no part of a hyphenated number (`PRESIDIO_WHOLE_DIGIT_RUN`); the label takes
  `account_number`, `account-number`, `accountnumber`.
- **Fix 2, tables** (the review asked for this after the 73 numbers that the label window lost; 40 of the 49 table
  cases among them sat under a column `Account Number`): a Markdown table column whose header names an account
  number (`account number`, `acct no`, `bank account number`, `mortgage account number`, `kontonummer`, `iban`;
  not `account`, `account id` or `aws account`) masks a cell of 8 to 20 digits that is no date and no placeholder.

| Measure | Before (`next`, 7aaa0033) | Fix 1 | Fix 1 and 2 |
|---|---|---|---|
| Nemotron: account numbers whole / in part | 8,978 / 2,197 | 10,858 / 37 | 11,266 / 37 |
| Nemotron: false positives, F1 | 873, 0.6537 | 872, 0.6586 | 893, 0.6596 |
| Gretel: false positives, precision | 3,687, 0.898 | 3,704, 0.897 | 3,716, 0.897 |
| Mendeley, PIILO, bank dev and val | – | no change | no change |
| False-alarm bank, seven trees (`compare`) | – | +0 | +0 |

The table rule brings back 408 account numbers, more than the 73 that the label window lost: it was written from the
column names, not from those cases. Its negative cases are in `tests/test_bank_and_company_numbers.py`.

### A card number written as one run of digits, 2026-10-19

The review of 0.6.24 kept a card number without a card word only when it is written in groups: a float, a timestamp
and an IMEI pass Luhn as often as a card does. With the issuer table (the prefix and the length of a card network),
the checks for a decimal, a longer run and an id label before it, a run of digits is safe enough: re-measured on the
baseline after the account changes, as the review asked.

| Measure | Before (`next`, 161e2a62) | One run of digits |
|---|---|---|
| Gretel: card numbers whole, false positives, F1 | 299, 3,716, 0.3509 | 431, 3,730, 0.3522 |
| Mendeley: card numbers whole, F1 | 35,425, 0.6648 | 35,544, 0.6652 |
| Nemotron, PIILO, bank dev and val | – | no change |
| False-alarm bank, seven trees (`compare`) | – | +0 |

### A password with a sign after the password word, in a tool result, 2026-10-19

- **Gap seen:** Nemotron, 4,500 passwords missed. 1,440 stood after "use the password", "a password such as",
  "and password" and the like, with a letter, a digit and a sign (`Word@2024`, `Word99!`).
- **Cause:** after the password word and only a space, `label-password-after-space` takes no value that reads like
  English words (`_wordlike`), to keep "password iPhone15" and "Passwort SHA256-Hash" as prose; `Word@2024` reads like
  a word.
- **Fix:** the tool-channel form `secret-password-with-sign` (`maisecrets/detection/personal.py`): a value after the
  password word and a space or a short connector (`such as`, `like`, `e.g.`, `for example`, `of`, `set to`, `to`)
  that holds a letter, a digit and one of `@ # $ ! % & * ?`. An e-mail address and a variable (`$NAME`, `%NAME%`) stay
  text; a `!` or `?` at the end stays part of the value. A typed prompt is never blocked by it.

| Measure | Before (`next`, 161e2a62) | This change and the card run above |
|---|---|---|
| Nemotron: passwords whole, false positives, F1 | 2,485, 893, 0.6596 | 3,918, 893, 0.6634 |
| Gretel: passwords whole, false positives, F1 | 152, 3,716, 0.3509 | 168, 3,730, 0.3523 (cards +132) |
| Mendeley, PIILO, bank dev and val, secret catalogs (11,902 examples) | – | no change except Mendeley cards +119 |
| False-alarm bank, seven trees (`compare`) | – | +0 |

### A birth date after "born on", and after a birth label with "is" or "was", 2026-10-20

The first change of the corrected method (`docs/BENCHMARK-V2.md`, draft): the cases were read on the `dev` split
only, the change was decided on `val` and the false-alarm bank.

- **Gap seen (dev):** Nemotron missed 6,214 birth dates, 6,201 of them ISO dates, after "was born on", "date of birth
  is", "date of birth" and "<name> born on".
- **Fix:** `birth-date-after-label` takes `born on`, the spellings `DateOfBirth` and `date_of_birth`, and a copula
  (`is`, `was`, `as`) after the label. The checks stay: a real past day, no placeholder. Tool channel only. A known
  limit: "the project was born on <date>" is masked too.

| Measure | Before (`next`, 69d99234) | This change |
|---|---|---|
| Nemotron dev: birth dates whole, false positives, F1 | 4,736, 503, 0.6633 | 9,609, 503, 0.6839 |
| Nemotron val: birth dates whole, false positives, F1 | 1,594, 187, 0.6678 | 3,068, 187, 0.6865 |
| Gretel dev / val: birth dates whole | 712 / 235 | 746 / 253 (false positives unchanged) |
| Mendeley, PIILO, bank dev and val | – | no change |
| False-alarm bank, seven trees (`compare`) | – | +0 |

### An id after its label, whole: `of`, a certificate or license number, a letter prefix, 2026-10-20

Read on the `dev` split, decided on `val` and the false-alarm bank.

- **Gap seen (dev):** Nemotron's national ids (health plan beneficiary, medical record, certificate and license
  numbers) missed 4,107 and found 1,213 in part, after "plan beneficiary number", "medical record number",
  "certificate license number", often with `is` or `of`. No checksum rule would reach them: they have no checksum.
- **Causes:** the id label took no `of` after it; `license number` without "driver's" was no label; and the digit
  rule `us-license#1` took the digits after a letter prefix (`CL-4882019`), and that shorter hit won the overlap
  against the label rule's whole id (the same collision as `us-bank` above).
- **Fix:** `of` after the label; `license number` and `certificate license number` as labels; `us-bank` and
  `us-license#1` take no part of a token joined by a hyphen to letters or digits.

| Measure | Before (`next`, 113fa044) | This change |
|---|---|---|
| Nemotron dev: national ids whole / in part, false positives, F1 | 15,713 / 1,213, 503, 0.6839 | 17,123 / 220, 498, 0.6899 |
| Nemotron val: national ids whole / in part, false positives, F1 | 5,072 / 386, 187, 0.6865 | 5,490 / 80, 185, 0.6918 |
| Gretel dev: national ids whole, false positives | 1,023, 2,246 | 1,066, 2,165 |
| Gretel val: national ids whole, false positives | 333, 764 | 353, 734 |
| Mendeley, PIILO, bank dev and val | – | no change |
| False-alarm bank, seven trees (`compare`) | – | +0 |

### A user name after the label in a sentence, 2026-10-20

Read on the `dev` split only (a classification first, not a hunt for the 12,951 misses), decided on `val` and the
false-alarm bank.

- **Classes of the dev misses (Nemotron, 7,695):** the label in a sentence ("the user name ...", "your user name is
  ...", about 1,800); table rows under a `username` column (2,149, kept out on purpose: the column counts only next to
  a column of a person, as a table of service accounts has one too); "user id ..." (an id, not clearly a user name);
  "author", "prepared by", "dear" (mostly names). Only the first is changed.
- **Fix:** `username-after-label` also reads the label in a sentence, with `is` or `was` or only a space, when the
  value has a digit, a dot or an underscore. A word (`field`, `harlow`), a product or sign-in provider (`Okta`), a
  version, an address, a variable and a call stay text; the label with a colon is unchanged.

| Measure | Before (`next`, 15c4107c) | This change |
|---|---|---|
| Nemotron dev: user names whole, false positives, F1 | 1,680, 498, 0.6899 | 3,211, 500, 0.6961 |
| Nemotron val: user names whole, false positives, F1 | 584, 185, 0.6918 | 1,124, 186, 0.6985 |
| Gretel dev / val: user names whole | 71 / 24 | 72 / 25 (false positives unchanged) |
| Mendeley, PIILO, bank dev and val | – | no change |
### A driver license in hyphenated groups, masked whole, 2026-10-20

Found by the partial-detection audit of the dev splits: 114 Gretel licenses like `A999-9999-999-9` with 11 of 15
characters in the clear. Hyphenated licenses are a real format (Wisconsin `A123-4567-8901-23`, Illinois
`A123-4567-8901`). Decided on `val` and the false-alarm bank.

- **Cause:** Presidio's license pattern ends at a word boundary, so it took the letter and the first digits.
- **Fix:** the hit of `us-license#0` takes up to four following groups of digits when the token ends there
  (`PRESIDIO_HYPHEN_TAIL`); a token that goes on keeps the hit it had.

| Measure | Before (`next`, 15c4107c) | This change |
|---|---|---|
| Gretel dev: national ids whole / in part | 1,066 / 118 | 1,180 / 4 |
| Gretel val: national ids whole / in part | 353 / 30 | 381 / 2 |
| Nemotron dev / val: national ids in part | 220 / 80 | 208 / 76 |
| False positives on every source | – | no change |
| False-alarm bank, seven trees (`compare`) | – | +0 |

### A double name with a hyphen, masked whole, 2026-10-20

Found by the partial-detection audit of the dev splits (the largest cluster: 896 names whose part after the hyphen
stayed in the clear). Decided on `val` and the false-alarm bank.

- **Cause:** a name word took a small letter after a hyphen only, so `Garcia-Lopez` and `Al-Rashid` ended at the hyphen.
- **Fix:** a part after a hyphen may start with a capital (two parts at most).

| Measure | Before (`next`, 15c4107c) | This change |
|---|---|---|
| Gretel dev: names whole / in part, false positives, F1 | 3,242 / 811, 2,165, 0.3595 | 4,125 / 55, 2,170, 0.3741 |
| Gretel val: names whole / in part, false positives, F1 | 1,028 / 273, 734, 0.3479 | 1,343 / 9, 734, 0.3640 |
| Nemotron dev / val: names whole / in part | 16,266 / 103; 5,554 / 36 | 16,382 / 5; 5,591 / 1 |
| Mendeley, PIILO, bank dev and val | – | no change |
| False-alarm bank, seven trees (`compare`) | – | +0 |

### An address keeps its unit after `Ste.` or `Apt.`, 2026-10-20

Found by the partial-detection audit of the dev splits (Gretel, 682 addresses after a label with the unit number in the
clear). Decided on `val` and the false-alarm bank.

- **Cause:** the value after an address label ended at a dot and a space, so `1200 Harbor Road, Ste. 300` ended at `Ste`.
- **Fix:** a dot ends the value only when no digit follows, or when the word before it is not a unit or a short street
  name (`Ste`, `Apt`, `Rm`, `Fl`, `Bldg`, `No`, `Nr`, `…str`).

| Measure | Before (`next`, 40e638ef) | This change |
|---|---|---|
| Gretel dev: addresses whole / in part, false positives, F1 | 3,141 / 1,052, 2,170, 0.3760 | 3,763 / 389, 2,163, 0.3857 |
| Gretel val: addresses whole / in part, false positives, F1 | 1,008 / 290, 734, 0.3654 | 1,177 / 110, 732, 0.3736 |
| Nemotron dev / val: addresses whole / in part | 3,420 / 313; 1,103 / 108 | 3,435 / 313; 1,108 / 107 |
| Mendeley, PIILO, bank dev and val | – | no change |
| False-alarm bank, seven trees (`scripts/compare_bench.py`) | – | 0 findings |

### A medical license, masked whole around its DEA-shaped part, 2026-10-20

Found by the partial-detection audit of the dev splits (Nemotron, 121 medical licenses found in part). Decided on `val`
and the false-alarm bank.

- **Cause:** Presidio's DEA pattern (two letters, seven digits) has no word boundary. It matched inside a longer license
  number and left the letters before it and the digits after it in the clear.
- **Fix:** a validated `medical-license` hit takes the whole token of letters and digits around it.

| Measure | Before (`next`, 40e638ef) | This change |
|---|---|---|
| Nemotron dev: national ids whole / in part, F1 | 17,135 / 208, 0.6967 | 17,244 / 99, 0.6971 |
| Nemotron val: national ids whole / in part, F1 | 5,494 / 76, 0.6990 | 5,529 / 41, 0.6995 |
| Gretel dev / val: national ids whole / in part | 1,180 / 4; 381 / 2 | 1,181 / 3; 383 / 0 |
| False positives and too-wide spans, every source | – | no change |
| False-alarm bank, seven trees (`scripts/compare_bench.py`) | – | 0 findings |

### A phone extension, masked with its number, 2026-10-20

Found by the partial-detection audit of the dev splits (Gretel, 61 phone numbers whose extension stayed in the clear).
Decided on `val` and the false-alarm bank.

- **Cause:** each phone rule ended before an extension (`x204`, `ext. 31`). The international rule also refused a
  number followed by a letter and a digit, so it stepped back one group and left its last digits in the clear too.
- **Fix:** a phone hit takes an extension right after it (`x`, `ext.`, `extension`, up to six digits). The
  international rule no longer refuses a number followed by `x` and a digit.

| Measure | Before (`next`, 8b11dedf) | This change |
|---|---|---|
| Gretel dev: phone numbers whole / in part, false positives, F1 | 1,865 / 86, 2,163, 0.3857 | 1,900 / 51, 2,164, 0.3862 |
| Gretel val: phone numbers whole / in part, false positives, F1 | 587 / 20, 732, 0.3736 | 597 / 10, 732, 0.3741 |
| PIILO dev: phone numbers whole / in part | 0 / 3 | 3 / 0 |
| Nemotron, Mendeley, bank dev and val | – | no change |
| False-alarm bank, seven trees (`scripts/compare_bench.py`) | – | 0 findings |

## CredData, results per release

CredData line method, without repository `2ba83c6a` (23,667 rows: 10,106 credentials, 13,561 non-secrets),
`--locale de_DE`. Source: `scripts/measure_creddata.py`, 2026-10-14; 0.6.18 to 0.6.21 on 2026-10-15, each from a worktree
of its tag (0.6.21: the merge request branch); 0.6.24 on 2026-10-16 from its release branch. 0.6.22 and 0.6.23 changed
no detection and give the rows of 0.6.21 (0.6.23 measured as the base of 0.6.24). A release before 0.6.17 has one channel.

| Release | Channel | TP | FN | FP | P | R | F1 | F1, `--regions us` |
|---|---|---|---|---|---|---|---|---|
| 0.6.14 | one | 4,822 | 5,284 | 427 | 0.919 | 0.477 | 0.628 | 0.607 |
| 0.6.15 | one | 4,882 | 5,224 | 429 | 0.919 | 0.483 | 0.633 | 0.612 |
| 0.6.16 | one | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.17 | prompt | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.17 | tool | 5,838 | 4,268 | 443 | 0.929 | 0.578 | 0.713 | 0.690 |
| 0.6.18 | prompt | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.18 | tool | 5,854 | 4,252 | 445 | 0.929 | 0.579 | 0.714 | 0.691 |
| 0.6.19 | prompt | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.19 | tool | 5,854 | 4,252 | 445 | 0.929 | 0.579 | 0.714 | 0.691 |
| 0.6.20 | prompt | 5,337 | 4,769 | 441 | 0.924 | 0.528 | 0.672 | 0.650 |
| 0.6.20 | tool | 5,854 | 4,252 | 445 | 0.929 | 0.579 | 0.714 | 0.691 |
| 0.6.21 | prompt | 5,345 | 4,761 | 441 | 0.924 | 0.529 | 0.673 | 0.650 |
| 0.6.21 | tool | 5,862 | 4,244 | 446 | 0.929 | 0.580 | 0.714 | 0.691 |
| 0.6.24 | prompt | 5,345 | 4,761 | 441 | 0.924 | 0.529 | 0.673 | 0.650 |
| 0.6.24 | tool | 5,870 | 4,236 | 446 | 0.929 | 0.581 | 0.715 | 0.692 |
| 0.6.25 | prompt | 5,345 | 4,761 | 441 | 0.924 | 0.529 | 0.673 | 0.650 |
| 0.6.25 | tool | 5,870 | 4,236 | 446 | 0.929 | 0.581 | 0.715 | 0.692 |

This table uses all 29,893 rows (14,471 credentials, 15,422 non-secrets). Source: `scripts/measure_creddata.py
--exclude-repo ""`, 2026-10-14; 0.6.18 to 0.6.21 on 2026-10-15.

| Release | Channel | P | R | F1 | P, R, F1 with `--regions us` |
|---|---|---|---|---|---|
| 0.6.14 | one | 0.953 | 0.613 | 0.746 | 0.900, 0.613, 0.729 |
| 0.6.15 | one | 0.953 | 0.617 | 0.749 | 0.901, 0.617, 0.732 |
| 0.6.16 | one | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.17 | prompt | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.17 | tool | 0.956 | 0.683 | 0.797 | 0.908, 0.683, 0.780 |
| 0.6.18 | prompt | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.18 | tool | 0.956 | 0.684 | 0.798 | 0.908, 0.684, 0.781 |
| 0.6.19 | prompt | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.19 | tool | 0.956 | 0.684 | 0.798 | 0.908, 0.684, 0.781 |
| 0.6.20 | prompt | 0.954 | 0.649 | 0.772 | 0.904, 0.649, 0.755 |
| 0.6.20 | tool | 0.956 | 0.684 | 0.798 | 0.908, 0.684, 0.781 |
| 0.6.21 | prompt | 0.954 | 0.649 | 0.773 | 0.904, 0.649, 0.756 |
| 0.6.21 | tool | 0.956 | 0.685 | 0.798 | 0.908, 0.685, 0.781 |
| 0.6.24 | prompt | 0.954 | 0.649 | 0.773 | 0.904, 0.649, 0.756 |
| 0.6.24 | tool | 0.956 | 0.686 | 0.799 | 0.909, 0.686, 0.782 |
| 0.6.25 | prompt | 0.954 | 0.649 | 0.773 | 0.904, 0.649, 0.756 |
| 0.6.25 | tool | 0.956 | 0.686 | 0.799 | 0.909, 0.686, 0.782 |

## CredData, split by repository

0.6.17 tool channel against 0.6.16, without `2ba83c6a`, `--regions de`. The maintainers wrote the rules of 0.6.16
and 0.6.17 on half D. Half V holds the other repositories. Source: `scripts/measure_creddata.py --split half
--baseline <0.6.16>`, 2026-10-14.

| Half | P | R | F1 | Credentials only 0.6.17 catches | False alarms only 0.6.17 raises | Rows only 0.6.16 catches |
|---|---|---|---|---|---|---|
| D | 0.920 | 0.646 | 0.759 | 263 | 2 | 0 |
| V | 0.940 | 0.514 | 0.664 | 247 | 0 | 0 |

## CredData, credentials still missed

0.6.17 tool channel, without `2ba83c6a`, `--regions de`, by class (see "Method and limits"). Source:
`scripts/measure_creddata.py`, 2026-10-14.

| Class | Credentials missed | Share | Same-class non-secrets | Credentials ÷ (credentials + same-class non-secrets) |
|---|---|---|---|---|
| identifier (UUID, bucket name, id) | 2,589 | 60.7 % | 3,728 | 0.41 |
| labelled value, not a word | 1,140 | 26.7 % | 7,536 | 0.13 |
| value without a label | 300 | 7.0 % | 1,011 | 0.23 |
| password of letters only | 239 | 5.6 % | 843 | 0.22 |

## False alarms in developer text

`detect.scan` on each text of `tests/fp_corpus.py`, with each channel, `--locale de_DE`. Source:
`tests/test_fp_corpus.py` (the suite fails on a change), 2026-10-14.

| Set | Size | 0.6.17 prompt channel | 0.6.17 tool channel |
|---|---|---|---|
| `NO_HIT`: code, configuration, docs, logs and prose without a secret | 1,114 texts | 0 texts with a hit | 0 texts with a hit |
| `HIT`: texts with known values | 136 texts | 136 give exactly their values | 136 give exactly their values |

0.6.24 against 0.6.23 (2026-10-16): 0 new hits on the 1,114 NO_HIT texts in either channel, 0 new hits on 2,464
developer texts in the tool channel (`tests/fp_corpus.py` and the review corpora of 0.6.15 and 0.6.16), 0 new blocks over
771 typed prompts, 0 new hits on the 367 texts of `tests/fp_corpus_pii.py`. The negative corpus of the forms of 0.6.24
(`tests/fp_corpus_forms.py`, 157 texts in exactly their shapes, among them the inputs of three review rounds) holds the
hits listed in "Rule classes". 19,189 files of public code (the Python 3.14 standard library, its site-packages and one
`node_modules`): one hit of a new rule, a fake person's address in a package's test data; 800 of these files with
card-like digits: no new card hit.

Typed prompts from the maintainers' own sessions, through the hook: 0 new blocks against 0.6.16 over 771 prompts.
Source: the 0.6.17 release measurement, 2026-10-14. The prompts are not published, so this number cannot be
repeated outside the maintainers' machines.

### Four public trees on fixed commits, 2026-10-19

`scripts/measure_fp_bank.py` on `next` 9f5d2506. The trees hold the test values of their projects and no secret that
we know of, so each hit a Read would act on is a false alarm or a test value. `acted` counts the hits after the
test-code rule; the last column is the part outside test code.

| Tree | Commit | Files | MB | Hits | Acted | Acted, not in test code |
|---|---|---|---|---|---|---|
| CPython `Lib/` (3.14.0) | ebf955df | 2,069 | 36.3 | 1,328 | 1,325 | 195 |
| Yelp/detect-secrets | 5e141933 | 201 | 0.6 | 117 | 85 | 26 |
| awslabs/ferret-scan | e8c6fe24 | 1,488 | 14.3 | 1,352 | 1,143 | 295 |
| thirtysix/Preserve | 01dbd771 | 90 | 0.8 | 124 | 119 | 51 |

A second run on the same commit gives the same counts (`compare`: +0). The run takes about 85 seconds on an
M-series laptop. A detector change measures the bank before and after and reports the result of `compare`.

## Coverage against other catalogs

The built-in examples of six other secret catalogs, scanned by maisecrets. Per rule with examples, up to 6
examples, each in two forms: the secret alone ("bare") and after `token = ` ("after a label"). A rule counts as
found when the hits of one channel cover the whole secret of one of its examples. "0.6.19" is the tag `v0.6.19`;
"0.6.20" is the branch of that release. Source: `scripts/measure_catalog_coverage.py`, 2026-10-15; its docstring has
the method. The tables show which forms maisecrets misses, not a ranking between tools: the other tools also verify a
key with its provider, pair a key with its id and use provider logic, and maisecrets uses labels and shapes only.

| Catalog | Commit | Rules | Rules with examples | 0.6.19 bare | 0.6.20 bare | 0.6.19 after a label | 0.6.20 after a label |
|---|---|---|---|---|---|---|---|
| Nosey Parker | `2e6e7f36ce36` | 189 | 189 | 67 (35.4 %) | 78 (41.3 %) | 171 (90.5 %) | 171 (90.5 %) |
| Kingfisher | `82d050530cde` (v1.113.0) | 1,095 | 1,095 | 211 (19.3 %) | 230 (21.0 %) | 994 (90.8 %) | 994 (90.8 %) |
| gitleaks | `b58d3f102cf3` | 225 | 158 | 73 (46.2 %) | 74 (46.8 %) | 153 (96.8 %) | 153 (96.8 %) |
| betterleaks | `c613797a6843` | 467 | 360 | 147 (40.8 %) | 152 (42.2 %) | 346 (96.1 %) | 346 (96.1 %) |
| trufflehog | `27d8ea2876d9` | 943 | 890 | 61 (6.9 %) | 66 (7.4 %) | 838 (94.2 %) | 838 (94.2 %) |
| GitLab secret detection rules | `cae5670b0d83` | 217 | 172 | 91 (52.9 %) | 104 (60.5 %) | 161 (93.6 %) | 161 (93.6 %) |

## Timing

Median time of one scan, 15 runs after one warm-up run; "import + first scan" is the median of 5 new processes,
as each hook call is a new process. Machine as above, load average below 4, round 2 of two rounds (the rounds
differ by up to 7 %). Source: `scripts/measure_scan_time.py --maisecrets <v0.6.17>`, 2026-10-14.

| Input | Python 3.14, prompt | Python 3.14, tool | Python 3.9, prompt | Python 3.9, tool |
|---|---|---|---|---|
| import + first scan | 46 ms | 46 ms | 64 ms | 68 ms |
| typed prompt, 1 KB | 1.8 ms | 1.9 ms | 2.1 ms | 2.2 ms |
| Python code, 70 KB | 121 ms | 122 ms | 135 ms | 135 ms |
| log, 70 KB | 80 ms | 80 ms | 96 ms | 94 ms |
| configuration, 70 KB, 2,092 password labels | 187 ms | 185 ms | 242 ms | 241 ms |

Hook time, 0.6.24 against 0.6.23 (2026-10-16): the CPU time (user + system) of one hook call, a new process each, the
median of 21 calls after one warm-up, with compiled modules in both trees. Synthetic payloads: a typed prompt of 1 KB
(`UserPromptSubmit`), a Bash result of 20 KB of log lines and a Read result of 70 KB of Python code (`PostToolUse`).
Load average 2 to 3. Source: a script outside this repository that runs `hooks/dispatch.py` with each payload;
`scripts/profile_hook.py` uses the same payloads (the "70 KB" Read result holds 62,311 characters) and a similar method,
and splits the time into interpreter, import, rule list, regex compilation and scan, per rule class.

| Payload | Python 3.14, 0.6.23 | Python 3.14, 0.6.24 | Python 3.9, 0.6.23 | Python 3.9, 0.6.24 |
|---|---|---|---|---|
| typed prompt, 1 KB | 68.8 ms | 72.4 ms | 83.9 ms | 86.2 ms |
| Bash result, 20 KB | 98.8 ms | 103.6 ms | 118.9 ms | 120.6 ms |
| Read result, 70 KB | 163.4 ms | 171.3 ms | 193.2 ms | 197.9 ms |

The forms and the new checks compile their regexes at their first use. One review round measured a long line of
hits: every new rule stays linear from 70 KB to 560 KB on one line (ratio 7 to 9 for 8 times the text).

## Values from your own tools, 2026-10-16

The imports of part 3 of #19 (`maisecrets/values.py`, the registry pass `imports`), measured on the branch of the merge
request against `next` at `fcd2535`.

**Without an import, nothing changes.** `scripts/detection_fingerprint.py --creddata` gives byte-identical files for
`next` and the branch: 50,387 inputs, 503,871 lines, 290,822 hits; and 771 typed prompts as samples, 7,711 lines.
Without an import, no hook imports `maisecrets/values.py` or `maisecrets/terms.py`; the only new module on the hook path
is `maisecrets/value_files.py` (one `scandir`, below 1 ms).

**Hook time.** CPU time (user + system) of one hook call, a new process each, the median of 21 calls after one
warm-up, the configurations called in turn. The payloads of `scripts/profile_hook.py`, with no imported value in them.
Each tree had fresh byte code (a stale `__pycache__` of an edited `hooks.py` cost 45 ms per call in a first run and
looked like a regression). The imports are invented NER output (55 % full names, 25 % e-mail addresses, the rest
surnames, company names and case numbers). Load average 12 (Python 3.14) and 32 (Python 3.9).

| Payload | next | branch, no import | 10 values | 1,000 values | 100,000 values |
|---|---|---|---|---|---|
| Python 3.14, typed prompt, 1 KB | 194.0 ms | 194.0 ms | 202.6 ms | 207.2 ms | 210.6 ms |
| Python 3.14, Bash result, 20 KB | 263.3 ms | 263.0 ms | 276.4 ms | 275.9 ms | 282.6 ms |
| Python 3.14, Read result, 70 KB | 295.3 ms | 267.4 ms | 317.1 ms | 306.1 ms | 282.8 ms |
| Python 3.9, typed prompt, 1 KB | 224.3 ms | 224.8 ms | 235.8 ms | 234.5 ms | 244.0 ms |
| Python 3.9, Bash result, 20 KB | 304.4 ms | 308.3 ms | 318.9 ms | 319.3 ms | 324.8 ms |
| Python 3.9, Read result, 70 KB | 492.7 ms | 494.1 ms | 519.8 ms | 519.3 ms | 531.6 ms |

The row of the 70 KB Read on Python 3.14 is noisy (its spread is larger than the differences). With an import a hook
pays about 10 to 20 ms (the import of the term matcher and one pass over the text), and 100,000 values cost a few ms
more than 10: one index, looked up once per word, never a regex per value.

**The index per size**, in separate processes, at load 95 to 105 (read the ratios, not the levels): the import and
the build took 0.4 s for 10 and for 1,000 values, and 10 s (Python 3.9) to 19 s (Python 3.14) for 100,000; the cache
`.values-cache` is 16.4 MB for 100,000 values and loads in 8 to 27 ms; the steady pass over 70 KB takes 16 to 35 ms for
10, 1,000 and 100,000 values alike. maisecrets builds the index after an import and at session start, so a tool hook
only loads it.

**False hits.** An import of 1,000 invented values (above) on 2,464 developer texts (tool channel), 771 typed prompts
(prompt channel) and the 1,649 NO_HIT snippets of the three fp corpora (both channels): 0 texts with an import hit. All
1,000 values were masked in a probe text (745 by the import pass, the rest by a rule that found them first: the
e-mail addresses). `tests/test_values_corpora.py` holds the corpus part with 400 values.

## Terms, 2026-10-16

The terms of part 2 of #19 (`maisecrets/terms.py`, the registry pass `terms`), measured on the branch of the merge
request against `v0.6.25` (`04ee5db`).

**Without a term list, nothing changes.** `scripts/detection_fingerprint.py --creddata` (CredData, the corpora, the
token lists, the probes and the recorded scans of the detector tests: 50,387 inputs, 503,871 lines, 290,812 hits)
gives byte-identical files for `v0.6.25` and the branch. Without a list, no hook imports `maisecrets/terms.py`
(13 ms at import); the check for a list (`maisecrets/term_files.py`) costs 0.2 ms.

**Hook time.** CPU time (user + system) of one hook call, a new process each, the median of 31 calls after one
warm-up, the trees called in turn so that the load hits each alike. Synthetic payloads as in "Timing" above, with no
listed name in them. Load average 35 to 60 (other sessions on the same machine), so every number is about 3 to 4
times the time on an idle machine; read the differences, not the levels. Source: a script outside this repository
that runs `hooks/dispatch.py` with each payload, in a fresh temp home per tree.

| Payload | 0.6.25 | branch, no list | 10 terms | 100 terms | 1,000 terms |
|---|---|---|---|---|---|
| Python 3.14, typed prompt, 1 KB | 309.9 ms | 308.8 ms | 324.8 ms | 320.7 ms | 324.3 ms |
| Python 3.14, Bash result, 20 KB | 330.0 ms | 329.4 ms | 346.5 ms | 344.3 ms | 339.8 ms |
| Python 3.14, Read result, 70 KB | 701.8 ms | 702.7 ms | 727.8 ms | 736.6 ms | 734.6 ms |
| Python 3.9, typed prompt, 1 KB | 348.2 ms | 353.2 ms | 365.6 ms | 365.8 ms | 367.0 ms |
| Python 3.9, Bash result, 20 KB | 350.4 ms | 347.8 ms | 368.5 ms | 362.5 ms | 363.4 ms |
| Python 3.9, Read result, 70 KB | 824.6 ms | 817.9 ms | 848.7 ms | 857.0 ms | 851.2 ms |

Without a list the branch is within -0.8 % to +1.4 % of 0.6.25, inside the spread of the runs. With a list, a hook
pays about 15 to 35 ms at this load: the import of the terms module, the load of the cached index (0.7 ms) and one
pass over the text. The cost does not grow with the number of terms: the matcher is one index of every list, looked
up once per word of the text, never a regex per term. In separate processes the term pass over the 70 KB text took
18 to 20 ms for 10, 100, 1,000 and 10,000 terms alike (Python 3.14, same load).

**A team list of many `*…*` entries.** A 3.75 MB team list of 150,000 unique `*…*` entries took 5.33 s of CPU to
parse on the branch before review round 1 (each entry walked the stop list) and 1.55 s after it (one lookup in a table
of substrings), at load 50.

**False hits.** A realistic list (10 people with full name, surname and genitive, among them the surname `Koch`, which
is also a German word; two case numbers; three customer names) on every NO_HIT snippet of `tests/fp_corpus.py`,
`tests/fp_corpus_pii.py` and `tests/fp_corpus_forms.py` (1,649 snippets), in both channels: 0 term hits.
`tests/test_terms_corpora.py` holds it, with a probe text that shows the list is loaded.

## Cloakroom holdout sets, 2026-10-15

Cloakroom's holdout sets v2 to v7 (`bench/holdout_v*.jsonl` at commit `cc3c88d76a`, 2026-10-14): 1,652 planted values in
470 samples, and 215 clean samples (200 in v2 to v6, 15 in v7). A value counts as leaked when it still appears after
every match is masked. Tool channel (`detect.scan(text, channel="tool")`), `--locale de_DE`. Source:
`scripts/measure_holdouts.py` (written 2026-10-16; the numbers were first taken on 2026-10-15 with the scratch scripts
it replaces, and it gives the same numbers for 0.6.20, 0.6.21, 0.6.23, 0.6.24 and 0.6.25). 0.6.20 is tag `v0.6.20`;
0.6.21 is the release of these rules.

Each sample falls into half D or half C by the first 8 hex digits of sha256 of `<set>/<id>` (even: D). The rules of
0.6.21 were written from the values of half D that 0.6.18 leaked; half C was counted. Half C is the number to read.
Regions `us`, `uk`, `in`:

| Set | Values, D | Leaked D, 0.6.20 → 0.6.21 | Values, C | Leaked C, 0.6.20 → 0.6.21 | Clean samples | False alarms, 0.6.20 → 0.6.21 |
|---|---|---|---|---|---|---|
| v2 | 92 | 36 → 24 | 127 | 46 → 33 | 40 | 1 → 1 |
| v3 | 208 | 88 → 49 | 112 | 48 → 30 | 40 | 1 → 1 |
| v4 | 154 | 86 → 55 | 174 | 90 → 60 | 40 | 2 → 2 |
| v5 | 178 | 85 → 58 | 216 | 116 → 77 | 40 | 2 → 2 |
| v6 | 157 | 83 → 51 | 157 | 80 → 59 | 40 | 0 → 0 |
| v7 | 33 | 2 → 0 | 44 | 1 → 0 | 15 | 1 → 1 |
| v2 to v6 | 789 | 378 → 237 | 786 | 380 → 259 | 200 | 6 → 6 |
| v2 to v7 | 822 | 380 → 237 | 830 | 381 → 259 | 215 | 7 → 7 |

Regions `de`:

| Set | Values, D | Leaked D, 0.6.20 → 0.6.21 | Values, C | Leaked C, 0.6.20 → 0.6.21 | Clean samples | False alarms, 0.6.20 → 0.6.21 |
|---|---|---|---|---|---|---|
| v2 | 92 | 41 → 30 | 127 | 53 → 39 | 40 | 0 → 0 |
| v3 | 208 | 97 → 58 | 112 | 51 → 36 | 40 | 0 → 0 |
| v4 | 154 | 89 → 59 | 174 | 92 → 62 | 40 | 0 → 0 |
| v5 | 178 | 89 → 62 | 216 | 120 → 84 | 40 | 0 → 0 |
| v6 | 157 | 94 → 67 | 157 | 87 → 69 | 40 | 0 → 0 |
| v7 | 33 | 2 → 0 | 44 | 1 → 0 | 15 | 1 → 1 |
| v2 to v6 | 789 | 410 → 276 | 786 | 403 → 290 | 200 | 0 → 0 |
| v2 to v7 | 822 | 412 → 276 | 830 | 404 → 290 | 215 | 1 → 1 |

By class of the planted value (the shape of the value, `value_class` in `scripts/measure_holdouts.py`; for example a
name is one capitalised word, or two to five, without a digit), regions `us`, `uk`, `in`:

| Class | Values | Leaked 0.6.20, D / C | Leaked 0.6.21, D / C |
|---|---|---|---|
| names | 324 | 167 / 154 | 103 / 107 |
| user names | 146 | 66 / 79 | 57 / 68 |
| addresses | 26 | 15 / 11 | 14 / 11 |
| birth dates | 72 | 37 / 35 | 9 / 14 |
| ID numbers | 114 | 18 / 18 | 10 / 8 |
| phone numbers | 207 | 12 / 18 | 0 / 6 |
| tokens and passwords | 334 | 31 / 31 | 24 / 24 |
| e-mail addresses | 286 | 0 / 3 | 0 / 3 |
| other | 143 | 34 / 32 | 20 / 18 |

Each new rule alone on 0.6.20: values it closes, half D / half C, and new hits on the sets of ordinary text. "PII
corpus" is `tests/fp_corpus_pii.py` (367 developer texts in the shape of personal data that are none, ten regions);
"developer texts" are 2,464 texts in the tool channel (`tests/fp_corpus.py` and the review corpora of 0.6.15 and
0.6.16) and "prompts" are 771 typed prompts of the maintainers in the prompt channel.

| Rule | Closed, us uk in: D / C | Closed, de: D / C | New false alarms, holdouts | New hits, PII corpus (tool / prompt) | New hits, developer texts | Newly blocked prompts |
|---|---|---|---|---|---|---|
| `name-after-label` | 42 / 21 | 42 / 21 | 0 | 0 / 0 | 0 | 0 |
| `name-before-email` | 23 / 24 | 23 / 24 | 0 | 0 / 0 | 0 | 0 |
| `birth-date-after-label` | 26 / 21 | 26 / 21 | 0 | 0 / 0 | 0 | 0 |
| `street-address` | 14 / 14 | 4 / 3 | 0 | 0 / 0 | 0 | 0 |
| `id-number-after-label` | 12 / 8 | 14 / 11 | 0 | 0 / 0 | 0 | 0 |
| `csv-personal-column` | 10 / 8 | 15 / 9 | 0 | 0 / 0 | 0 | 0 |
| `user-in-home-path` | 5 / 9 | 5 / 9 | 0 | 0 / 0 | 0 | 0 |
| `user-in-url` | 4 / 2 | 4 / 2 | 0 | 0 / 0 | 0 | 0 |
| `phone-one-digit-groups` | 3 / 10 | 3 / 10 | 0 | 0 / 0 | 0 | 0 |
| `phone-us-national` | 4 / 1 | 0 / 0 | 0 | 0 / 0 | 0 | 0 |
| `twilio-account-sid-labelled` | 3 / 5 | 3 / 5 | 0 | 0 / 0 | 0 | 0 |
| `openai-anthropic-key-relaxed` | 3 / 1 | 3 / 1 | 0 | 0 / 0 | 0 | 0 |
| `slack-token-relaxed` | 1 / 1 | 1 / 1 | 0 | 0 / 0 | 0 | 0 |

The rules of 0.6.20 already hit 8 of the 367 texts of the PII corpus (4 by `phone`, one each by `de-vat-id`,
`email`, `us-bank` and `de-plz`); 0.6.21 adds none. The 44 true hits of the corpus (46 values): 0.6.20 masks 8,
0.6.21 masks 46. Two review rounds (codex gpt-5.6-sol and Opus) wrote about 360 more developer snippets; after the
fixes, 12 of 182 and 0 of 98 still give a hit of a new rule, most of them a person's name or path.

Left out after measuring, each alone on 0.6.20 (the closed values are both halves; prompts are the prompt
channel, the rest the tool channel):

| Rule | Closed, us uk in | New false alarms, v2 to v6 | New hits, PII corpus | New hits, developer texts | Newly blocked prompts |
|---|---|---|---|---|---|
| a user name after a user label (`user:`, `login:`, `requested by`) | 55 | 3 | 4 | 68 | 28 |
| a password after a password word in prose | 5 | 0 | 0 | 80 | 53 |
| a random token after a token word in prose | 11 | 0 | 0 | 17 | 5 |

An AWS key id with any capital and digit was left out on CredData (+105 credentials, +48 false alarms, precision
−0.006, holdout analysis of 2026-10-14); a Twilio Account SID without its name was left out as an id of other uses.

The values 0.6.21 still leaks (regions `us`, `uk`, `in`), by class and by reason (this sorting and the table of each new
rule alone above need probe trees with single rules switched on or off; the script does not make them). A name or an
address without a label or a postcode needs a model; a user name or a date with no label is ambiguous without context;
"left out" are the values that one of the three rules above would close; the rest is a remaining gap:

| Class | needs a model (no label, no postcode) | ambiguous without context | left out for its false hits | remaining gap |
|---|---|---|---|---|
| names | 210 | 0 | 0 | 0 |
| user names | 0 | 79 | 46 | 0 |
| addresses | 25 | 0 | 0 | 0 |
| birth dates | 0 | 23 | 0 | 0 |
| ID numbers | 0 | 0 | 0 | 18 |
| phone numbers | 0 | 0 | 0 | 6 |
| tokens and passwords | 0 | 0 | 11 | 37 |
| e-mail addresses | 0 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 38 |
| all | 235 | 102 | 57 | 102 |

The rules of 0.6.20 already hit 8 of the 367 texts of the PII corpus (4 by `phone`, one each by `de-vat-id`, `email`,
`us-bank` and `de-plz`); 0.6.21 adds none. The 44 true hits of the corpus (46 values): 0.6.20 masks 8, 0.6.21 masks
46. Two review rounds (codex gpt-5.6-sol and Opus) wrote about 360 more developer snippets; after the fixes, 12 of 182
and 0 of 98 still give a hit of a new rule, most of them a person's name or path. CredData and the time per scan of
0.6.21 are in the release tables above.

Limits of this measurement:

- This is a result on Cloakroom's benchmark, not on an unseen holdout. The analysis of 2026-10-14 sorted all 765
  values that 0.6.18 leaked by class, in both halves, so the classes of half C were seen; the rule texts came from the
  values of half D. The false alarms of both halves were read and the rules changed after them.
- Two rule families come from Cloakroom's code: a name before an e-mail address and the columns of a CSV header
  (Apache-2.0, credited in the commits and in "Credit"); the code here is written anew.
- Cloakroom tuned its own engine on v2 to v5 after their first run; v6 is its set that was never tuned on (their
  `bench/RESULTS.md`).

### 0.6.24, 2026-10-16

0.6.23 (`origin/main` at `717a83e`, the base of 0.6.24, with the same detection as 0.6.21) against the release
branch of 0.6.24. Tool channel, `--locale de_DE`. Source: `scripts/measure_holdouts.py`, 2026-10-16; the tags
`v0.6.23` and `v0.6.24` give the same numbers. The rules of 0.6.24
come from a class analysis of the 102 values that 0.6.21 leaked for no other reason than a missing rule. That
analysis looked at the leaked values of both halves, so half C is no unseen holdout for these rules either.

Regions `us`, `uk`, `in`:

| Set | Values, D | Leaked D, 0.6.23 → 0.6.24 | Values, C | Leaked C, 0.6.23 → 0.6.24 | Clean samples | False alarms, 0.6.23 → 0.6.24 |
|---|---|---|---|---|---|---|
| v2 | 92 | 24 → 22 | 127 | 33 → 29 | 40 | 1 → 1 |
| v3 | 208 | 49 → 42 | 112 | 30 → 26 | 40 | 1 → 1 |
| v4 | 154 | 55 → 45 | 174 | 60 → 51 | 40 | 2 → 2 |
| v5 | 178 | 58 → 53 | 216 | 77 → 65 | 40 | 2 → 2 |
| v6 | 157 | 51 → 41 | 157 | 59 → 48 | 40 | 0 → 0 |
| v7 | 33 | 0 → 0 | 44 | 0 → 0 | 15 | 1 → 1 |
| v2 to v6 | 789 | 237 → 203 | 786 | 259 → 219 | 200 | 6 → 6 |
| v2 to v7 | 822 | 237 → 203 | 830 | 259 → 219 | 215 | 7 → 7 |

Regions `de`:

| Set | Values, D | Leaked D, 0.6.23 → 0.6.24 | Values, C | Leaked C, 0.6.23 → 0.6.24 | Clean samples | False alarms, 0.6.23 → 0.6.24 |
|---|---|---|---|---|---|---|
| v2 | 92 | 30 → 30 | 127 | 39 → 35 | 40 | 0 → 0 |
| v3 | 208 | 58 → 48 | 112 | 36 → 28 | 40 | 0 → 0 |
| v4 | 154 | 59 → 46 | 174 | 62 → 52 | 40 | 0 → 0 |
| v5 | 178 | 62 → 56 | 216 | 84 → 71 | 40 | 0 → 0 |
| v6 | 157 | 67 → 56 | 157 | 69 → 55 | 40 | 0 → 0 |
| v7 | 33 | 0 → 0 | 44 | 0 → 0 | 15 | 1 → 1 |
| v2 to v6 | 789 | 276 → 236 | 786 | 290 → 241 | 200 | 0 → 0 |
| v2 to v7 | 822 | 276 → 236 | 830 | 290 → 241 | 215 | 1 → 1 |

By class, values leaked in half D / half C, regions `us`, `uk`, `in`:

| Class | Values | 0.6.23 | 0.6.24 |
|---|---|---|---|
| names | 324 | 103 / 107 | 103 / 107 |
| user names | 146 | 57 / 68 | 57 / 68 |
| addresses | 26 | 14 / 11 | 8 / 5 |
| birth dates | 72 | 9 / 14 | 9 / 14 |
| ID numbers | 114 | 10 / 8 | 4 / 2 |
| phone numbers | 207 | 0 / 6 | 0 / 4 |
| tokens and passwords | 334 | 24 / 24 | 15 / 10 |
| e-mail addresses | 286 | 0 / 3 | 0 / 0 |
| other | 143 | 20 / 18 | 7 / 9 |

The 102 values of the "remaining gap" column of 0.6.21: 61 closed (28 in half D, 33 in half C), 41 still leak. The
values that 0.6.24 still leaks, by reason (the same sorting as for 0.6.21 above):

| Class | needs a model (no label, no postcode) | ambiguous without context | left out for its false hits | remaining gap |
|---|---|---|---|---|
| names | 210 | 0 | 0 | 0 |
| user names | 0 | 79 | 46 | 0 |
| addresses | 13 | 0 | 0 | 0 |
| birth dates | 0 | 23 | 0 | 0 |
| ID numbers | 0 | 0 | 0 | 6 |
| phone numbers | 0 | 0 | 0 | 4 |
| tokens and passwords | 0 | 0 | 10 | 15 |
| other | 0 | 0 | 0 | 16 |
| all | 223 | 102 | 56 | 41 |

Values closed per rule of 0.6.24 (regions `us`, `uk`, `in`, both halves; a value counts for the rule whose hit covers
it): `address-after-label` 22, `id-number-after-record-label` 10, `id-letters-after-label` 6,
`secret-hex48-after-token-word` 4, `name-non-latin-after-label` 4, `secret-in-login-code` 4, `address-jp-postcode` 3,
`secret-postman-variable` 2, `id-number-fhir-identifier` 2, `id-number-in-member-parentheses` 2,
`secret-after-user-slash` 2, `email-percent-encoded` (new contexts) 2, `id-number-under-sql-alias` 2, the e-mail and
phone rules next to CJK text 2, and one each for `address-in-form`, `phone-url-encoded`, `secret-add-mask`,
`secret-shared-access-key`, `csv-personal-column`, `phone-wrapped-line`, `address-under-sql-alias`. No value that
0.6.23 masked leaks in 0.6.24.

Left out after measuring (2026-10-15 and 2026-10-16): a card number found by its Luhn digit alone when it is written as
one run of digits (floats, microsecond timestamps and IMEIs pass Luhn as often; 0.6.24 masks a card number without a
card word only in groups of four with an issuer prefix), a password after a password word in prose, a US phone number
without a phone word, 48 hex digits without a token word (a digest looks the same), a Twilio Account SID without its
name.

### 0.6.25, 2026-10-16

0.6.24 (`origin/main` at `5208dca`) against the release branch of 0.6.25 (`a44dd52`). Tool channel, `--locale de_DE`,
`scripts/measure_holdouts.py`; the tags `v0.6.24` and `v0.6.25` give the same numbers. Leaked values, all of v2 to v7:
half D 203 → 197 and half C 219 → 219 (regions `us`, `uk`, `in`), half D 236 → 230 and half C 241 → 241 (`de`); the
names row of the class table moves from 103 / 107 to 97 / 107 in both region sets. 0.6.25 closes three gaps of 0.6.24: a
vCard property with parameters and a vCard address, name and birth date in their fields; an encoded e-mail address in a
CSV column whose header names its owner; and a measured decision on the company window before an address label.

- Holdout values: 6 more masked in half D (the family and given names of three vCard samples of v4), 0 in half C, in
  both region sets; no value that 0.6.24 masked leaks. False alarms on the 215 clean samples: 7 → 7 (`us uk in`),
  1 → 1 (`de`).
- CredData (four runs: both channels, `--regions de` and `us`): 0 rows changed. `scripts/detection_fingerprint.py`
  over CredData, `tests/fp_corpus.py`, the PII corpus and the token lists of the tests (503,871 lines): byte-identical
  to 0.6.24.
- Labelled PII datasets (`scripts/measure_datasets.py run`): no count of any type changes in either channel.
- 0 new hits on the 2,464 developer texts, the 771 typed prompts, the 1,114 NO_HIT texts of `tests/fp_corpus.py` and
  the 367 texts of the PII corpus. The negative corpus of the forms (`tests/fp_corpus_forms.py`, now 168 texts with the
  inputs of two review rounds) keeps its 6 known hits in the tool channel and 4 in the prompt channel.
- Rule classes (`scripts/measure_rule_classes.py`): `pii:name` alone masks 110 holdout values (0.6.24: 104); no other
  class changes on CredData, the holdout sets or the corpora.
- Time: Gate B timed a 70 KB single line and thousands of lines for each new regex and the CSV cell check: 0.2 to
  0.45 s, linear.

Left out after measuring: the check for a company before an address label reads back to the start of the JSON object
instead of 120 characters. Six synthetic records in minified JSON: the company record and the head office are no longer
masked (two false hits removed), but the address of a person's record with an employer, or with a hotel in a note,
passes (two new leaks). Pretty JSON masks all six with and without the change. The holdout sets, the datasets, the
developer texts, the prompts and the false-hit corpora show no change, so the six records are the whole evidence. A
false hit masks a company address; a leak sends a home address to the provider. An employer or a hotel within 120
characters already lets a home address pass in 0.6.24 and 0.6.25 (`tests/test_company_address_window.py`).

Left out after review: a vCard property folded over two lines, a vCard line without its `BEGIN:VCARD`, and a CSV row
without a header (its shape is the shape of a locale table). An encoded address at a `.md` domain in a CSV cell stays
text, because `name%40draft.md` is a file name more often.

### 0.6.26, 2026-10-16

0.6.25 (`origin/main` at `04ee5db`) against the fix commit of the branch of 0.6.26 (the next commit only adds a
quick test before the person-key regex, which needs a `:` or `=`). Tool channel, `--locale de_DE`. Holdout numbers:
`scripts/measure_holdouts.py` on the rebased branch, with the same result as the scratch script of the other rows.
0.6.26 closes a half mask of a field report: a PDF invoice to a German GmbH, read in the
tool channel. The address rules left the company's address as text, because a legal form stood before it, but de-plz
masked its postcode and de-vat-id its VAT ID, so the street stayed in the clear. Now the postcode of such an address
and a German VAT ID right after it stay text too. The decision reads the legal forms of the existing company check and
stays masked in the cases of `tests/test_company_numbers_follow_the_address.py` (a sole trader, a hotel or an office,
a person's name or record key, an employer label, a second address or a blank line, the sender's VAT label).

- Holdout values (v2 to v7, both halves, regions `us uk in` and `de`): no value changes. Leaked in half D / C:
  197 / 219 (`us uk in`) and 230 / 241 (`de`), as in 0.6.25. False alarms on the 215 clean samples: 7 → 7 and 1 → 1.
- CredData (four runs: both channels, `--regions de` and `us`): 0 rows changed. `scripts/detection_fingerprint.py`
  over CredData, `tests/fp_corpus.py`, the PII corpus and the token lists of the tests (503,870 lines): byte-identical
  to 0.6.25. These inputs hold no company address with a German postcode or VAT ID.
- Labelled PII datasets (`scripts/measure_datasets.py run`): the prompt channel does not change. In the tool channel
  only Gretel changes, in four German documents, each about a company: the postcode in the contact line of an
  insurer (an AG; DE_PLZ FP 267 → 266), the VAT ID after the address of a seller (a GmbH; DE_VAT_ID FP 5 → 4), and the
  postcode in the delivery address of a GmbH and in the address of a GmbH that sends a report. Gretel labels these two
  company addresses as ADDRESS, so ADDRESS TP goes 6,203 → 6,201: the postcode was the only part of them that 0.6.25
  masked.
  No address of a person changes.
- 0 new hits and 0 lost hits on the 2,464 developer texts, the 771 typed prompts, the 1,114 NO_HIT texts of
  `tests/fp_corpus.py`, the 367 texts of the PII corpus and the 168 texts of the forms corpus.
- Rule classes (`scripts/measure_rule_classes.py`): no class changes.
- Values masked in 0.6.25 and free now: the four company values above, and no other. The shapes of both review gates
  (a person's postcode or VAT ID next to a company) are tests now, and each gives the result of 0.6.25.
- Time: 2,000 and 4,000 company addresses with a VAT ID each on one line (176 KB and 351 KB), CPU time: 0.78 s and
  1.81 s in 0.6.25, 0.90 s and 2.0 s in 0.6.26 (+7 to 15 %), linear.

Left out after review: a company's postcode and VAT ID stay masked when a line such as a department stands between
the company's name and its address, when a `Kunde:` label stands before the company, and when the street and the
postcode stand on two lines (no address rule reads that form, so there is no company decision to follow). A VAT ID of
another EU country and a billing ID have no rule here.

### A password after its word in a sentence, 2026-10-16

0.6.28 (`af5ef91`; 0.6.29 and 0.6.30 have the same detection) against the branch of this change. A field report from Codex in the
ChatGPT app: "Messe-Account: <mail>, Passwort <value>." masked the address and kept the password in the clear, and
"password: <value>." stored the value with the dot. Two label rules now read the password words of each label
language after a copula (`label-password-after-word`) or after only a space, an arrow, a dash or a parenthesis
(`label-password-after-space`), and a stop after an unquoted label value is cut from the span.

A matrix of invented sentences: 16 label languages, 32 password words, 10 separators (`:`, ` :`, `=`, ` = `, a
space, the copula of the language, `->`, ` – `, a quoted value after `:`, parentheses), 6 value shapes and 7 endings,
11,970 cells per channel. A value in the shape of a credential (letters and digits, with signs, two words and a
digit) is masked in 1,001 of the 1,995 cells of each shape in 0.6.28 and in 1,829 now, in both channels. A dictionary word and a PIN are
masked in no new cell. In 0.6.28, 1,011 cells with a final `.` or `;` took it into the value (prompt channel); now
none does.
`!` stays part of a value (Winter2024!), and `?` stays part of a value after `:` or `=`, as the detection matrix of
the tests needs. Per language, credential-shaped cells masked, prompt channel:

| Language | 0.6.28 | Now | Cells |
|---|---|---|---|
| en | 590 | 831 | 1,050 |
| de | 210 | 414 | 420 |
| es | 210 | 414 | 630 |
| fr, it, nl, nb, sv, fi, cs, th (each) | 105 to 106 | 207 | 210 |
| pt, pl, da | 210 | 414 | 420 |
| tr | 210 | 372 | 378 |
| ko | 315 | 558 | 567 |

The cells still missed are by design: `pass` and `pwd` with no `:` or `=` (a boarding pass, a test pass), Spanish
`clave` alone (also a code or an id: `clave: CURP-ABCD010101`), a value with `)` before a `!`, and a passphrase of
letters only.

- 0 new hits on the 771 typed prompts and the 2,464 developer texts, also with all 16 label languages on. One prompt
  that 0.6.28 already blocked (`--password=VALUE.`) keeps its hit without the dot.
- 0 new hits and 0 lost hits on the 1,114 NO_HIT texts of `tests/fp_corpus.py`, the 367 texts of the PII corpus and
  the 168 texts of the forms corpus, in both channels.
- CredData (six runs: both channels, `--regions de` and `us`, and all rows): +1 credential (a SQL `CREATE USER …
  PASSWORD '…'` line), 0 false alarms, in each run. `scripts/detection_fingerprint.py` (503,800 lines; the lines of
  the recorded test inputs differ, because the new test module adds scans): 9 inputs change. The end of the value
  moves before a final `;` or `.` on 7 CredData lines (3 credentials, and 4 rows labelled no credential that
  0.6.28 already masked), the SQL line is new, and one HIT text of `tests/fp_corpus.py` gives the same span by the new rule.
- Holdout values (v2 to v7): half D 197 → 196 and half C 219 → 219 (`us uk in`), 230 → 229 and 241 → 241 (`de`), all
  in "tokens and passwords". False alarms on the 215 clean samples: 7 → 7 and 1 → 1.
- Labelled PII datasets (`scripts/measure_datasets.py run`, both channels): only SECRET changes. Nemotron-PII: TP
  2,840 → 3,276 (prompt channel; tool 2,851 → 3,287), FP 33 → 33. Gretel: TP 515 → 540, FP 92 → 101 (prompt; tool 530
  → 555 and 98 → 107). The 9 new false hits by the labels of Gretel are passwords in the text that the labels miss or
  cut at a Markdown escape (`wachtwoord is <value>`, `Passwort lautet: <value>`, `the password "<value>"`); one hit is
  neutral. Mendeley and PIILO do not change.
- Rule classes (`scripts/measure_rule_classes.py`): `label:keyword` has 18 rules (16 before) and alone masks one more
  CredData credential and one more holdout value in each channel; no other class changes.
- Time: the new rules check the value before the checks of the code around it. 200 KB of `password is `,
  `Passwort `, `Passwort Ab1x ` and a JSON log of `"password changed"` take the time of 0.6.28 (0.9 to 1.9 s CPU on a
  loaded machine).

Left out after review (Fable for Gate A, as codex had no credits, and Opus for Gate B, two rounds each with their own
inputs): in the space form, a value that starts with a sign, a run of English words (iPhone15), an id or a reference
(PBE-3403, CVE-2024-3094, BSI-C5:2020), a rule (Länge>=12), a word and a short number (Version2), and the example of a
weak password (Sommer2024!, Hunter2!) stay text; such a value needs a `:` or a copula. Still a hit after a password
word and a space: a band (WLAN-5GHz), a room number (Raum3.12), a rule word with a number (2FA-Pflicht). A token in a
URL query or after `Bearer` keeps a final dot, as in 0.6.28: these are no label rules.

### Personal data after its label in more forms, 2026-10-17

`origin/next` at `fcd2535` (the detection of 0.6.31) against the branch of seven rules, each its own commit. The
rules come from the gap analysis of 2026-10-16 on half D of Nemotron-PII and Gretel; the numbers below are half C
(the samples whose first 8 hex digits of sha256 of `<dataset>/<id>` are odd), counted after the rules were fixed. All
seven rules run in the tool channel only. A typed prompt takes no personal-data rule (0.6.21: a person who types a
name means to send it), so the prompt numbers below show that nothing changes there. Each rule was measured alone (the
branch with the other six switched off) and all seven together. `--locale de_DE`, by-language regions.

1. **Bold label.** The cleaned copy of a tool result drops the stars around a Markdown bold label (`**Label:** value`,
   `**Label**: value`, `__Label:__ value`), so every label rule reads the value. Only the stars go: each character
   keeps its own offset, and the opening stars inside a line become one space, so a value ends before the next bold
   label.
2. **ID after a health, tax or national label** (`_ID_RE`): medical record number, health plan beneficiary number,
   beneficiary ID, national ID, tax ID number, taxpayer identification number, TIN, social security number.
3. **Passport and driving licence labels** of de, fr, es, it, nl, pt, sv and pl, and "driving licence".
4. **Phone number after a phone word** (`phone-after-phone-word`): a national form after a phone label in the label
   languages; a North American 3-3-4 number also after a phone verb, with region `us` or `ca` only (as
   `phone-us-national`); the `(312) 846-…` form stays with `phone-us-national`.
5. **One name word after a first or last name label** (`name-single-after-label`), in the label languages.
6. **Street line after an address label or a verb of residence** (`address-street-after-label`), with the company
   check of the address rules.
7. **Person columns of a Markdown table** (`md-table-personal-column`): the CSV rule for `|` tables.

Gain, tool channel, half C. TP before → after (values in half C); FP is a hit on no gold span of any kind (an upper
bound: both datasets leave real values unlabelled).

| Rule alone | Nemotron-PII, half C | Gretel, half C | Mendeley | PIILO |
|---|---|---|---|---|
| 1 bold label | NAME +2,673, BIRTH_DATE +1,281, ID_NUMBER +451, SECRET +315, US_BANK_NUMBER +210, ADDRESS +61; FP ID 8 → 14, NAME 3 → 14, ADDRESS 1 → 2 | NAME +41, ADDRESS +4, BIRTH_DATE +4, ID_NUMBER +3; FP SECRET 53 → 55 | 0 | 0 |
| 2 health, tax, national ID | ID_NUMBER +5,187 (FP 8 → 10) | US_SSN +4; FP ID_NUMBER 52 → 54 | 0 | 0 |
| 3 EU passport and licence | 0 | ID_NUMBER +98 (FP 52 → 54) | 0 | 0 |
| 4 phone after a phone word | PHONE +7,059 (FP 10 → 22) | PHONE +214 (FP 180 → 225) | 0 | 0 |
| 5 one name word | NAME +6,523 (FP 3 → 3) | NAME +283 (FP 22 → 51) | 0 | 0 |
| 6 street line | ADDRESS +2,049 (FP 1 → 1) | ADDRESS +318 (FP 199 → 246) | ADDRESS +241 (FP 0 → 13) | 0 |
| 7 Markdown table | NAME +138, ID_NUMBER +73, BIRTH_DATE +59, ADDRESS +12, PHONE +12 | NAME +7, ADDRESS +5 | 0 | 0 |

All seven together, half C, TP and recall:

| Dataset, type | Values | Before | After | R before → after | FP before → after |
|---|---|---|---|---|---|
| Nemotron PHONE | 15,348 | 4,024 | 11,662 | 0.262 → 0.760 | 10 → 23 |
| Nemotron ID_NUMBER | 14,516 | 4,504 | 11,093 | 0.310 → 0.764 | 8 → 18 |
| Nemotron NAME | 71,970 | 2,335 | 14,206 | 0.032 → 0.197 | 3 → 14 |
| Nemotron ADDRESS | 8,448 | 477 | 3,070 | 0.056 → 0.363 | 1 → 3 |
| Nemotron BIRTH_DATE | 9,123 | 2,700 | 4,040 | 0.296 → 0.443 | 0 → 0 |
| Nemotron SECRET | 5,793 | 1,599 | 1,914 | 0.276 → 0.330 | 10 → 10 |
| Nemotron US_BANK_NUMBER | 5,848 | 5,035 | 5,245 | 0.861 → 0.897 | 56 → 56 |
| Gretel PHONE | 2,305 | 1,377 | 1,593 | 0.597 → 0.691 | 180 → 225 |
| Gretel ID_NUMBER | 1,122 | 544 | 645 | 0.485 → 0.575 | 52 → 57 |
| Gretel NAME | 38,616 | 2,974 | 3,306 | 0.077 → 0.086 | 22 → 51 |
| Gretel ADDRESS | 15,615 | 3,060 | 3,392 | 0.196 → 0.217 | 199 → 246 |
| Mendeley ADDRESS | 23,062 | 0 | 241 | 0 → 0.010 | 0 → 13 |

Half D moves by the same amounts (Nemotron PHONE +7,542, ID_NUMBER +6,536, NAME +11,165, ADDRESS +2,634, BIRTH_DATE
+1,283). The prompt channel of all four datasets does not change. PIILO does not change.

The new dataset FP, read by their context (4 word tokens before, the shape of the value, no value printed): in Gretel
most are personal values the labels miss, such as the last name after `Efternamn:` when only the first name carries a
label, the address after `John Doe … Address:`, and a phone after `Telefon:`; a few are company phones and company
addresses (a Swedish company phone, an address after a company name with `AB`). In Mendeley, all 13 are a person's
street after "residing at" or "billing address on file is", which the labels cover only in part. In Nemotron, the bold
label shows the plain-label behaviour of `name-after-label` to more values: a campaign, challenge or product name of
two invented capitalised words after `**Campaign Name:**` (`Campaign Name:` in plain text gives the same hit).

- **Developer texts and prompts:** 0 new hits and 0 lost hits on the 2,464 developer texts (tool channel) and the 771
  typed prompts, for each rule alone and for all seven. The same on the 1,114 NO_HIT texts of `tests/fp_corpus.py`,
  the 367 texts of the PII corpus and the 218 texts of the forms corpus (168 before; the branch adds 50 Markdown and
  form negatives first), in both channels.
- **Holdout values** (v2 to v7): half D does not change. Half C: 219 → 217 (`us uk in`) and 241 → 237 (`de`): rule 5
  closes 2 names in each region set, rules 2 and 6 one ID and one address in `de`. False alarms on the 215 clean
  samples: 7 → 7 and 1 → 1.
- **CredData** (four runs: both channels, `--regions de` and `us`): tool channel +1 credential (a password after a
  label that the bold stage now reads), 0 false alarms; the prompt channel does not change.
- **`scripts/detection_fingerprint.py`** (503,870 lines, the same inputs in both trees): 19 lines change, all new hits.
  The CredData line above in all 5 region sets (`ds-keyword-colon`). One positive of the PII corpus (a German street
  after `Anschrift:`) gets the span of the street rule too (regions `none` and `us`). In the recorded test scans,
  the same German street, and five German passport numbers after `Reisepass` or `Reisepassnummer`, now hit in the
  regions `none` and `us`: the EU labels are generic, as the English passport label is.
- **Rule classes** (`scripts/measure_rule_classes.py`): the classes `pii:address`, `pii:column`, `pii:name` and
  `pii:phone` each get one rule; no class masks a new false hit. Holdout values masked in the tool channel: 1,182 →
  1,186.
- **Time:** one hook call, CPU time, median of 21 calls (`scripts/profile_hook.py`, load 4 to 5): typed prompt of 1 KB
  85.6 → 87.6 ms, Bash result of 20 KB 119.3 → 122.4 ms, Read result of 70 KB 193.8 → 195.5 ms. Long adversarial
  lines of 70 KB (repeated labels, stars, underscores, bars, digit groups, street words) take 0.08 to 0.21 s, and
  0.51 to 0.84 s at 280 KB (linear). A text dense with bold labels takes about twice the time of 0.6.31, because a
  bold label sends the text through the cleaned copy, as an HTML entity does.

Review: Gate A (codex, gpt-5.6-sol, read-only) and Gate B (Fable), two rounds each. They found false hits on a Markdown
table of servers, on the label words of i18n files (`"first_name": "Vorname"`), on a timestamp and a count after a
phone word, on "the server lives at", on "Beneficiary: VENDOR …", and on a build line after "Mobile"; and misses for
`123 5th Avenue`, `Numer prawa jazdy`, Vietnamese names, a table without outer bars, and a person's address with "bank
account" on the line before. Each is a test now. Left out after review: a street line in lower case (the address rules
of 0.6.21 also need capitals); a list of ports or screen sizes after a phone word (`tel 80 443 8080 8443`); a famous
example address after `address:` (`1 Infinite Loop`); a date after `medical record #`; a Polish licence number with
slashes (the value of `_ID_RE` ends at `/`); the label words of a language that the list of `_NAME_LABEL_VALUES` does
not hold, when the file holds no listed label word. Not built: "born on" with a year (rule 11 of the gap analysis).

### vCard lines and company addresses in more forms, 2026-10-17

`origin/next` at `07e56ff` against the branch of three gaps that 0.6.25 and 0.6.26 left out (six commits, the last at
`dc42866`). Tool channel only; a typed prompt does not change. `--locale de_DE`.

1. **A folded vCard property.** RFC 6350 folds a line with a line break and one space or tab. A new stage of the cleaned
   copy (`unfold`, `maisecrets/detection/normalise.py`) joins the parts inside `BEGIN:VCARD` to `END:VCARD`, and the mask covers
   both parts in the true text. The indent of `BEGIN:VCARD` counts as part of each line; a binary property (`PHOTO`,
   `KEY`, `ENCODING=b`) stays folded; a folded line that starts with `END:VCARD` does not end the card.
2. **A vCard line without its card.** `ADR`, `N` and `BDAY` (TEL, EMAIL and FN were found already) after a `.vcf` file
   name (grep output, also a Windows path), or in the structure of the property: `ADR` in capitals with a parameter of
   a card and an empty box and extended field, `N` in capitals with five fields and a title or nothing as the prefix,
   `BDAY` with a parameter of a card.
3. **A company's postcode and VAT ID in three more forms** of the company decision of 0.6.26: the street and the
   postcode on two lines after the company's name, a department of a closed list between them, and a `Kunde:` or
   `Customer:` key whose value is the company's name. In these forms the company's name has at most two words.

Before the change, the developer texts, the prompts, CredData and the forms corpora held no line in the shape of a bare
`ADR`, `N` or `BDAY` property (a count over all of them, any case, with and without a grep prefix): 0 candidates. In
the 11,565 files of CredData, one `n;…:` line has a `;` after the property, and it is no vCard.

- Holdout values (v2 to v7, both halves, regions `us uk in` and `de`): no value changes. Leaked in half D / C: 196 / 217
  and 229 / 237. False alarms on the clean samples: no change.
- CredData (four runs: both channels, `--regions de` and `us`): 0 rows changed. `scripts/detection_fingerprint.py`
  (504,920 lines): byte-identical.
- Labelled PII datasets (`scripts/measure_datasets.py run`): the prompt channel does not change. In the tool channel
  only Gretel changes: three postcodes of a GmbH in the two-line form (two delivery addresses after `Lieferadresse:`
  and the address of a GmbH in a transfer notice) are text now. DE_PLZ FP 266 → 264; ADDRESS TP 6,842 → 6,841, because
  Gretel labels the third company address as ADDRESS and its postcode was the only part that `origin/next` masked. No
  address of a person changes. Nemotron-PII, Mendeley and PIILO do not change.
- 0 new hits and 0 lost hits on the 2,464 developer texts, the 771 typed prompts, the 1,114 NO_HIT texts of
  `tests/fp_corpus.py`, the 367 texts of the PII corpus (its positives: +0, -0) and the forms corpus, in both
  channels.
- Rule classes (`scripts/measure_rule_classes.py`): no class changes.
- Time, CPU, best of three on a loaded machine (load 11 to 15): a `.vcf` of 300 folded cards (939 KB) 1.95 → 3.82 s,
  because each folded line sends its window through the cleaned copy, as a bold label does; 3,000 bare `ADR` lines
  (159 KB) 0.35 → 0.40 s; 3,000 grep lines with a prefix of 190 characters (651 KB) 1.39 → 1.58 s; a 70 KB log
  0.173 → 0.175 s. Each is linear in the text.

Review: Gate A (codex, gpt-5.6-sol, read-only) and Gate B (Opus), two rounds each. They found a person's name in the
department slot (`Abteilung <name>`), a person on the company's line or on the line above it in the two-line form, a
salutation or a longer key before the company (`Kunde: Frau …`, `customer_name:`), a person's name glued to the
company's name, a config row as an address (`ADR:;;Cache 2;Primary;;8080;prod`, also with `TYPE=cache`), a folded
line that starts with `END:VCARD`, `BEGIN:VCARD` in a sentence, and a belief whose mutation could not reach its test.
Each is a test now. The fixes of round 2 had no third round.

Left out after review: a department line between the company's name and a street and postcode on one line (the address
rule masks that address whole, so there is no half mask); a company's name of more than two words in the new forms (a
person's name glued to it reads the same, so the values stay masked); a grep context line (`file.vcf-12-`); a property
in lower case folded more than 2,048 characters after its `BEGIN:VCARD` (the window of the cleaned copy does not reach
the card's start). On one line after a company word, a person's name glued to the company's name frees the values as
in 0.6.26.

## Labelled PII datasets, 2026-10-15

Four public datasets with labelled personal data and secrets. "0.6.21" is tag `v0.6.21`; "0.6.20" is tag `v0.6.20`.
Regions by language (`us` for English text), the locale of the language (`en_US` for English). Source:
`scripts/measure_datasets.py run`, 2026-10-15; "Method and limits" and "Repeat this measurement" below have the
details.

| Dataset | Version | Licence and attribution | Samples | Records left out |
|---|---|---|---|---|
| [Gretel synthetic_pii_finance_multilingual](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual) | Hugging Face commit `7b844d16738527a04264f50214cb426a4cea0897`, `data/train` and `data/test` | [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0), Gretel.ai | 41,932 documents in 7 languages | 14,008 below Gretel's `quality_score` 90 |
| [NVIDIA Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) | Hugging Face commit `b70ffaf5ff39e079776134c5bf4381f00a9fd1ed`, `data/test` | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), NVIDIA | 100,000 documents (50,000 `us`, 50,000 `intl` locale) | 0 |
| [Synthetic Dataset for PII Detection and Anonymization in Financial Documents](https://doi.org/10.17632/tzrjx692jy.1) (Mendeley Data) | version 1, doi 10.17632/tzrjx692jy.1 | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), the authors named at the DOI | 45,030 documents (`Training_Set.xlsx`, `Testing_Set.xlsx`) | 0; 5,003 texts repaired (mojibake) |
| [PIILO](https://www.kaggle.com/datasets/lburleigh/piilo-dataset) (PII Labeling and Obfuscation) | Kaggle dataset version 2 (2024-10-03), `train.json` | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), "PIILO © 2024 by The Learning Agency Lab" | 6,807 student essays | 0 |

The script pins the sha256 of each file. No dataset value enters this repository; the tables hold counts. The script
cleans the labels as "Method and limits" says and repairs Mendeley's text in memory; it changes no file.

Per type, one row per channel. "Values" are the labelled values that stay after the cleaning. P counts detections, R
counts values ("Method and limits", "Scoring"). "R, own type" counts a value as found only by a detection of its own
type; "R, covered" only when the detections cover all of it. "R raw" is the recall over the labels before the
cleaning, at their original offsets. A type with no labelled values has a row when it has detections. "F1 0.6.20" is
the same row for tag `v0.6.20`. The types NAME, ADDRESS, BIRTH_DATE, ID_NUMBER and USERNAME (tier "personal") have
rules from 0.6.21, in the tool channel only (`maisecrets/detection/personal.py`); 0.6.20 has none.


### Gretel

Cleaning, labelled values per type:

| Type | Labelled | Kept as a value | Of these trimmed | Merged (labelled twice) | Uncertain, by reason | Negative (label error) | Offset moved | Dropped (offset outside the text) |
|---|---|---|---|---|---|---|---|---|
| SECRET | 1,415 | 1,411 | 0 | 0 | 0 | 0 | 0 | 4 |
| EMAIL | 10,657 | 8,556 | 457 | 65 | 1,794: no value of its type 1, reserved domain 1,694, syntax 99 | 224 | 0 | 18 |
| PHONE | 6,857 | 4,563 | 71 | 16 | 2,053: digit count 28, letters 14, no value of its type 29, placeholder 1,982 | 208 | 0 | 17 |
| IP | 2,324 | 2,073 | 0 | 0 | 246: not public 193, syntax 53 | 0 | 0 | 5 |
| IBAN | 1,530 | 1,185 | 7 | 6 | 336: checksum 336 | 0 | 0 | 3 |
| CARD | 1,012 | 501 | 1 | 0 | 508: checksum 508 | 0 | 0 | 3 |
| US_SSN | 1,117 | 774 | 148 | 0 | 343: checksum 343 | 0 | 0 | 0 |
| ABA_ROUTING_NUMBER | 1,178 | 129 | 0 | 0 | 1,046: checksum 1,046 | 0 | 0 | 3 |
| NAME | 78,600 | 77,117 | 0 | 1,327 | 0 | 0 | 0 | 156 |
| ADDRESS | 31,618 | 31,414 | 0 | 160 | 0 | 0 | 0 | 44 |
| BIRTH_DATE | 1,916 | 1,912 | 0 | 1 | 0 | 0 | 0 | 3 |
| ID_NUMBER | 2,284 | 2,273 | 0 | 4 | 0 | 0 | 0 | 7 |
| USERNAME | 729 | 725 | 0 | 0 | 0 | 0 | 0 | 4 |

132,457 more labels have no type that maisecrets claims (`OUT_OF_SCOPE`); a detection on one is neither a find nor a
false alarm.

Results per type, 0.6.21:

| Type | Channel | Values | TP | FN | FP | P | R | F1 | R, own type | R, covered | R raw | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SECRET | prompt | 1,411 | 515 | 896 | 95 | 0.844 | 0.365 | 0.510 | 0.364 | 0.364 | 0.365 | 0.510 |
| SECRET | tool | 1,411 | 530 | 881 | 101 | 0.840 | 0.376 | 0.519 | 0.375 | 0.374 | 0.376 | 0.519 |
| EMAIL | prompt | 8,556 | 8,551 | 5 | 56 | 0.994 | 0.999 | 0.996 | 0.999 | 0.994 | 0.809 | 0.996 |
| EMAIL | tool | 8,556 | 8,551 | 5 | 56 | 0.994 | 0.999 | 0.996 | 0.999 | 0.994 | 0.809 | 0.996 |
| PHONE | prompt | 4,563 | 2,567 | 1,996 | 317 | 0.889 | 0.563 | 0.689 | 0.556 | 0.545 | 0.457 | 0.689 |
| PHONE | tool | 4,563 | 2,752 | 1,811 | 332 | 0.891 | 0.603 | 0.719 | 0.596 | 0.577 | 0.485 | 0.689 |
| IP | prompt | 2,073 | 1,929 | 144 | 28 | 0.986 | 0.930 | 0.957 | 0.930 | 0.930 | 0.834 | 0.957 |
| IP | tool | 2,073 | 1,929 | 144 | 28 | 0.986 | 0.930 | 0.957 | 0.930 | 0.930 | 0.834 | 0.957 |
| IBAN | prompt | 1,185 | 1,160 | 25 | 43 | 0.964 | 0.979 | 0.972 | 0.977 | 0.977 | 0.764 | 0.972 |
| IBAN | tool | 1,185 | 1,160 | 25 | 43 | 0.964 | 0.979 | 0.972 | 0.977 | 0.977 | 0.764 | 0.972 |
| CARD | prompt | 501 | 222 | 279 | 10 | 0.951 | 0.443 | 0.605 | 0.389 | 0.443 | 0.227 | 0.605 |
| CARD | tool | 501 | 223 | 278 | 10 | 0.951 | 0.445 | 0.606 | 0.389 | 0.445 | 0.309 | 0.605 |
| US_SSN | prompt | 774 | 460 | 314 | 51 | 0.894 | 0.594 | 0.714 | 0.558 | 0.592 | 0.421 | 0.714 |
| US_SSN | tool | 774 | 475 | 299 | 51 | 0.894 | 0.614 | 0.728 | 0.558 | 0.611 | 0.436 | 0.714 |
| ABA_ROUTING_NUMBER | prompt | 129 | 44 | 85 | 25 | 0.432 | 0.341 | 0.381 | 0.147 | 0.341 | 0.367 | 0.381 |
| ABA_ROUTING_NUMBER | tool | 129 | 45 | 84 | 25 | 0.432 | 0.349 | 0.386 | 0.147 | 0.349 | 0.371 | 0.381 |
| US_BANK_NUMBER | prompt | 0 | 0 | 0 | 3,276 | 0.000 | – | – | – | – | – | – |
| US_BANK_NUMBER | tool | 0 | 0 | 0 | 3,276 | 0.000 | – | – | – | – | – | – |
| NAME | prompt | 77,117 | 232 | 76,885 | 0 | – | 0.003 | – | 0.000 | 0.003 | 0.003 | – |
| NAME | tool | 77,117 | 5,873 | 71,244 | 32 | 0.994 | 0.076 | 0.141 | 0.073 | 0.059 | 0.076 | – |
| ADDRESS | prompt | 31,414 | 167 | 31,247 | 0 | – | 0.005 | – | 0.000 | 0.000 | 0.005 | – |
| ADDRESS | tool | 31,414 | 922 | 30,492 | 105 | 0.883 | 0.029 | 0.057 | 0.025 | 0.020 | 0.029 | – |
| BIRTH_DATE | prompt | 1,912 | 2 | 1,910 | 0 | – | 0.001 | – | 0.000 | 0.001 | 0.001 | – |
| BIRTH_DATE | tool | 1,912 | 1,186 | 726 | 85 | 0.933 | 0.620 | 0.745 | 0.619 | 0.620 | 0.620 | – |
| ID_NUMBER | prompt | 2,273 | 914 | 1,359 | 0 | – | 0.402 | – | 0.000 | 0.294 | 0.402 | – |
| ID_NUMBER | tool | 2,273 | 1,092 | 1,181 | 77 | 0.698 | 0.480 | 0.569 | 0.078 | 0.373 | 0.480 | – |
| USERNAME | prompt | 725 | 55 | 670 | 0 | – | 0.076 | – | 0.000 | 0.076 | 0.076 | – |
| USERNAME | tool | 725 | 57 | 668 | 5 | 0.286 | 0.079 | 0.123 | 0.003 | 0.079 | 0.079 | – |

Results per tier, region and tag, 0.6.21:

| Tier | Part | Channel | TP | FN | FP | P | R | F1 | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|
| core | all | prompt | 15,448 | 3,744 | 3,901 | 0.797 | 0.805 | 0.801 | 0.801 |
| core | region `de` | prompt | 969 | 306 | 61 | 0.941 | 0.760 | 0.841 | 0.841 |
| core | region `es` | prompt | 1,419 | 269 | 52 | 0.965 | 0.841 | 0.898 | 0.898 |
| core | region `fr` | prompt | 1,192 | 303 | 60 | 0.952 | 0.797 | 0.868 | 0.868 |
| core | region `it` | prompt | 1,213 | 268 | 48 | 0.962 | 0.819 | 0.885 | 0.885 |
| core | region `nl` | prompt | 1,239 | 479 | 26 | 0.979 | 0.721 | 0.831 | 0.831 |
| core | region `se` | prompt | 1,197 | 404 | 50 | 0.959 | 0.748 | 0.840 | 0.840 |
| core | region `us` | prompt | 8,219 | 1,715 | 3,604 | 0.693 | 0.827 | 0.754 | 0.754 |
| core | `format:structured` | prompt | 2,288 | 963 | 2,883 | 0.440 | 0.704 | 0.541 | 0.541 |
| core | `format:unstructured` | prompt | 13,160 | 2,781 | 1,018 | 0.928 | 0.826 | 0.874 | 0.874 |
| core | all | tool | 15,665 | 3,527 | 3,922 | 0.798 | 0.816 | 0.807 | 0.801 |
| core | region `de` | tool | 975 | 300 | 61 | 0.941 | 0.765 | 0.844 | 0.842 |
| core | region `es` | tool | 1,421 | 267 | 52 | 0.965 | 0.842 | 0.899 | 0.898 |
| core | region `fr` | tool | 1,192 | 303 | 61 | 0.951 | 0.797 | 0.868 | 0.868 |
| core | region `it` | tool | 1,213 | 268 | 48 | 0.962 | 0.819 | 0.885 | 0.885 |
| core | region `nl` | tool | 1,245 | 473 | 26 | 0.979 | 0.725 | 0.833 | 0.831 |
| core | region `se` | tool | 1,200 | 401 | 50 | 0.959 | 0.750 | 0.842 | 0.840 |
| core | region `us` | tool | 8,419 | 1,515 | 3,624 | 0.697 | 0.848 | 0.765 | 0.755 |
| core | `format:structured` | tool | 2,325 | 926 | 2,902 | 0.441 | 0.715 | 0.546 | 0.543 |
| core | `format:unstructured` | tool | 13,340 | 2,601 | 1,020 | 0.928 | 0.837 | 0.880 | 0.874 |
| personal | all | prompt | 1,370 | 112,071 | 0 | – | 0.012 | – | – |
| personal | region `de` | prompt | 194 | 9,690 | 0 | – | 0.020 | – | – |
| personal | region `es` | prompt | 11 | 9,863 | 0 | – | 0.001 | – | – |
| personal | region `fr` | prompt | 43 | 8,182 | 0 | – | 0.005 | – | – |
| personal | region `it` | prompt | 45 | 9,394 | 0 | – | 0.005 | – | – |
| personal | region `nl` | prompt | 18 | 12,198 | 0 | – | 0.002 | – | – |
| personal | region `se` | prompt | 29 | 11,672 | 0 | – | 0.003 | – | – |
| personal | region `us` | prompt | 1,030 | 51,072 | 0 | – | 0.020 | – | – |
| personal | `format:structured` | prompt | 230 | 20,179 | 0 | – | 0.011 | – | – |
| personal | `format:unstructured` | prompt | 1,140 | 91,892 | 0 | – | 0.012 | – | – |
| personal | all | tool | 9,130 | 104,311 | 304 | 0.962 | 0.081 | 0.148 | – |
| personal | region `de` | tool | 826 | 9,058 | 64 | 0.913 | 0.084 | 0.153 | – |
| personal | region `es` | tool | 555 | 9,319 | 23 | 0.959 | 0.056 | 0.106 | – |
| personal | region `fr` | tool | 635 | 7,590 | 14 | 0.977 | 0.077 | 0.143 | – |
| personal | region `it` | tool | 840 | 8,599 | 43 | 0.949 | 0.089 | 0.163 | – |
| personal | region `nl` | tool | 248 | 11,968 | 12 | 0.950 | 0.020 | 0.040 | – |
| personal | region `se` | tool | 323 | 11,378 | 15 | 0.951 | 0.028 | 0.054 | – |
| personal | region `us` | tool | 5,703 | 46,399 | 133 | 0.972 | 0.110 | 0.197 | – |
| personal | `format:structured` | tool | 1,254 | 19,155 | 154 | 0.868 | 0.061 | 0.115 | – |
| personal | `format:unstructured` | tool | 7,876 | 85,156 | 150 | 0.978 | 0.085 | 0.156 | – |

Detections of a type of no tier on no labelled value, 0.6.21: prompt 1,053 (0.6.20: 1,053), tool 1,048 (0.6.20:
1,053). By type, tool channel: DE_PLZ 274, US_DRIVER_LICENSE 246, US_PASSPORT 191, IT_VAT_CODE 132, SE_PERSONNUMMER
97, US_NPI 40, SE_ORGANISATIONSNUMMER 34, DE_TAX_NUMBER 11, DE_KFZ 6, ES_NIF 6, DE_VAT_ID 5, US_ITIN 3, IT_FISCAL_CODE
2, MEDICAL_LICENSE 1.

### Nemotron-PII

Cleaning, labelled values per type:

| Type | Labelled | Kept as a value | Of these trimmed | Merged (labelled twice) | Uncertain, by reason | Negative (label error) | Offset moved | Dropped (offset outside the text) |
|---|---|---|---|---|---|---|---|---|
| SECRET | 11,652 | 11,652 | 0 | 0 | 0 | 0 | 0 | 0 |
| EMAIL | 53,930 | 53,550 | 48 | 0 | 105: reserved domain 92, syntax 13 | 275 | 0 | 0 |
| PHONE | 30,353 | 30,240 | 7 | 0 | 113: digit count 2, no value of its type 1, placeholder 110 | 0 | 0 | 0 |
| IP | 9,217 | 7,971 | 3 | 0 | 1,246: no value of its type 7, not public 955, syntax 284 | 0 | 0 | 0 |
| CARD | 12,867 | 1,527 | 2 | 0 | 11,340: checksum 11,340 | 0 | 0 | 0 |
| US_SSN | 6,062 | 6,035 | 1 | 0 | 27: checksum 25, no value of its type 2 | 0 | 0 | 0 |
| ABA_ROUTING_NUMBER | 8,354 | 843 | 0 | 0 | 7,511: checksum 7,511 | 0 | 0 | 0 |
| US_BANK_NUMBER | 16,693 | 11,660 (6 more are IBANs) | 0 | 0 | 5,027: digit count 9, letters 5,018 | 0 | 0 | 0 |
| NAME | 143,639 | 143,639 | 0 | 0 | 0 | 0 | 0 | 0 |
| ADDRESS | 16,879 | 16,879 | 0 | 0 | 0 | 0 | 0 | 0 |
| BIRTH_DATE | 18,079 | 18,079 | 0 | 0 | 0 | 0 | 0 | 0 |
| ID_NUMBER | 28,807 | 28,807 | 0 | 0 | 0 | 0 | 0 | 0 |
| USERNAME | 15,800 | 15,800 | 0 | 0 | 0 | 0 | 0 | 0 |

478,008 more labels have no type that maisecrets claims (`OUT_OF_SCOPE`); a detection on one is neither a find nor a
false alarm.

Results per type, 0.6.21:

| Type | Channel | Values | TP | FN | FP | P | R | F1 | R, own type | R, covered | R raw | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SECRET | prompt | 11,652 | 2,841 | 8,811 | 33 | 0.988 | 0.244 | 0.391 | 0.242 | 0.239 | 0.244 | 0.391 |
| SECRET | tool | 11,652 | 2,852 | 8,800 | 33 | 0.988 | 0.245 | 0.392 | 0.242 | 0.239 | 0.245 | 0.392 |
| EMAIL | prompt | 53,550 | 53,550 | 0 | 6 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.993 | 1.000 |
| EMAIL | tool | 53,550 | 53,550 | 0 | 6 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.993 | 1.000 |
| PHONE | prompt | 30,240 | 7,004 | 23,236 | 19 | 0.997 | 0.232 | 0.376 | 0.229 | 0.230 | 0.231 | 0.376 |
| PHONE | tool | 30,240 | 8,034 | 22,206 | 24 | 0.997 | 0.266 | 0.419 | 0.263 | 0.264 | 0.265 | 0.376 |
| IP | prompt | 7,971 | 7,958 | 13 | 62 | 0.992 | 0.998 | 0.995 | 0.998 | 0.998 | 0.864 | 0.995 |
| IP | tool | 7,971 | 7,958 | 13 | 62 | 0.992 | 0.998 | 0.995 | 0.998 | 0.998 | 0.864 | 0.995 |
| IBAN | prompt | 6 | 5 | 1 | 3 | 0.500 | 0.833 | 0.625 | 0.500 | 0.500 | – | 0.625 |
| IBAN | tool | 6 | 5 | 1 | 3 | 0.500 | 0.833 | 0.625 | 0.500 | 0.500 | – | 0.625 |
| CARD | prompt | 1,527 | 1,458 | 69 | 1 | 0.999 | 0.955 | 0.977 | 0.951 | 0.955 | 0.117 | 0.977 |
| CARD | tool | 1,527 | 1,458 | 69 | 1 | 0.999 | 0.955 | 0.977 | 0.951 | 0.955 | 0.118 | 0.977 |
| US_SSN | prompt | 6,035 | 6,033 | 2 | 424 | 0.934 | 1.000 | 0.966 | 1.000 | 1.000 | 0.995 | 0.966 |
| US_SSN | tool | 6,035 | 6,033 | 2 | 424 | 0.934 | 1.000 | 0.966 | 1.000 | 1.000 | 0.995 | 0.966 |
| ABA_ROUTING_NUMBER | prompt | 843 | 834 | 9 | 3 | 0.996 | 0.989 | 0.993 | 0.989 | 0.989 | 0.973 | 0.993 |
| ABA_ROUTING_NUMBER | tool | 843 | 834 | 9 | 3 | 0.996 | 0.989 | 0.993 | 0.989 | 0.989 | 0.973 | 0.993 |
| US_BANK_NUMBER | prompt | 11,660 | 7,818 | 3,842 | 115 | 0.986 | 0.670 | 0.798 | 0.669 | 0.480 | 0.477 | 0.798 |
| US_BANK_NUMBER | tool | 11,660 | 10,018 | 1,642 | 115 | 0.986 | 0.859 | 0.918 | 0.669 | 0.669 | 0.802 | 0.798 |
| NAME | prompt | 143,639 | 49 | 143,590 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| NAME | tool | 143,639 | 4,509 | 139,130 | 12 | 0.995 | 0.031 | 0.061 | 0.031 | 0.031 | 0.031 | – |
| ADDRESS | prompt | 16,879 | 2 | 16,877 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ADDRESS | tool | 16,879 | 262 | 16,617 | 0 | 1.000 | 0.015 | 0.031 | 0.015 | 0.015 | 0.015 | – |
| BIRTH_DATE | prompt | 18,079 | 0 | 18,079 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| BIRTH_DATE | tool | 18,079 | 5,286 | 12,793 | 1 | 1.000 | 0.292 | 0.453 | 0.292 | 0.292 | 0.292 | – |
| ID_NUMBER | prompt | 28,807 | 4,350 | 24,457 | 0 | – | 0.151 | – | 0.000 | 0.079 | 0.151 | – |
| ID_NUMBER | tool | 28,807 | 4,701 | 24,106 | 14 | 0.962 | 0.163 | 0.279 | 0.012 | 0.091 | 0.163 | – |
| USERNAME | prompt | 15,800 | 43 | 15,757 | 0 | – | 0.003 | – | 0.000 | 0.003 | 0.003 | – |
| USERNAME | tool | 15,800 | 43 | 15,757 | 0 | – | 0.003 | – | 0.000 | 0.003 | 0.003 | – |

Results per tier, region and tag, 0.6.21:

| Tier | Part | Channel | TP | FN | FP | P | R | F1 | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|
| core | all | prompt | 87,501 | 35,983 | 666 | 0.992 | 0.709 | 0.827 | 0.827 |
| core | `format:structured` | prompt | 47,708 | 19,367 | 405 | 0.992 | 0.711 | 0.828 | 0.828 |
| core | `format:unstructured` | prompt | 39,793 | 16,616 | 261 | 0.994 | 0.705 | 0.825 | 0.825 |
| core | `locale:intl` | prompt | 50,723 | 14,656 | 532 | 0.990 | 0.776 | 0.870 | 0.870 |
| core | `locale:us` | prompt | 36,778 | 21,327 | 134 | 0.996 | 0.633 | 0.774 | 0.774 |
| core | all | tool | 90,742 | 32,742 | 671 | 0.993 | 0.735 | 0.844 | 0.827 |
| core | `format:structured` | tool | 49,274 | 17,801 | 410 | 0.992 | 0.735 | 0.844 | 0.828 |
| core | `format:unstructured` | tool | 41,468 | 14,941 | 261 | 0.994 | 0.735 | 0.845 | 0.825 |
| core | `locale:intl` | tool | 52,769 | 12,610 | 533 | 0.990 | 0.807 | 0.889 | 0.870 |
| core | `locale:us` | tool | 37,973 | 20,132 | 138 | 0.996 | 0.653 | 0.789 | 0.774 |
| personal | all | prompt | 4,444 | 218,760 | 0 | – | 0.020 | – | – |
| personal | `format:structured` | prompt | 2,348 | 111,993 | 0 | – | 0.021 | – | – |
| personal | `format:unstructured` | prompt | 2,096 | 106,767 | 0 | – | 0.019 | – | – |
| personal | `locale:intl` | prompt | 1,510 | 108,856 | 0 | – | 0.014 | – | – |
| personal | `locale:us` | prompt | 2,934 | 109,904 | 0 | – | 0.026 | – | – |
| personal | all | tool | 14,801 | 208,403 | 27 | 0.997 | 0.066 | 0.124 | – |
| personal | `format:structured` | tool | 10,553 | 103,788 | 19 | 0.997 | 0.092 | 0.169 | – |
| personal | `format:unstructured` | tool | 4,248 | 104,615 | 8 | 0.995 | 0.039 | 0.075 | – |
| personal | `locale:intl` | tool | 7,240 | 103,126 | 16 | 0.997 | 0.066 | 0.123 | – |
| personal | `locale:us` | tool | 7,561 | 105,277 | 11 | 0.997 | 0.067 | 0.126 | – |

Detections of a type of no tier on no labelled value, 0.6.21: prompt 146 (0.6.20: 146), tool 146 (0.6.20: 146). By
type, tool channel: US_DRIVER_LICENSE 106, US_PASSPORT 20, US_NPI 10, MEDICAL_LICENSE 9, US_ITIN 1.

### Mendeley financial documents

Cleaning, labelled values per type:

| Type | Labelled | Kept as a value | Of these trimmed | Merged (labelled twice) | Uncertain, by reason | Negative (label error) | Offset moved | Dropped (offset outside the text) |
|---|---|---|---|---|---|---|---|---|
| EMAIL | 34,637 | 0 | 0 | 0 | 34,637: reserved domain 34,637 | 0 | 0 | 0 |
| PHONE | 45,028 | 45,028 | 0 | 0 | 0 | 0 | 0 | 0 |
| CARD | 42,527 | 39,060 | 39,060 | 0 | 3,467: checksum 3,102, no value of its type 365 | 0 | 0 | 0 |
| US_SSN | 51,283 | 51,283 | 0 | 0 | 0 | 0 | 0 | 0 |
| NAME | 77,200 | 77,200 | 0 | 0 | 0 | 0 | 0 | 0 |
| ADDRESS | 46,264 | 46,264 | 0 | 0 | 0 | 0 | 0 | 0 |

100,461 more labels have no type that maisecrets claims (`OUT_OF_SCOPE`); a detection on one is neither a find nor a
false alarm.

Results per type, 0.6.21:

| Type | Channel | Values | TP | FN | FP | P | R | F1 | R, own type | R, covered | R raw | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PHONE | prompt | 45,028 | 42,268 | 2,760 | 0 | 1.000 | 0.939 | 0.968 | 0.911 | 0.911 | 0.939 | 0.968 |
| PHONE | tool | 45,028 | 42,268 | 2,760 | 0 | 1.000 | 0.939 | 0.968 | 0.911 | 0.911 | 0.939 | 0.968 |
| CARD | prompt | 39,060 | 31,687 | 7,373 | 0 | 1.000 | 0.811 | 0.896 | 0.677 | 0.811 | 0.757 | 0.896 |
| CARD | tool | 39,060 | 31,687 | 7,373 | 0 | 1.000 | 0.811 | 0.896 | 0.677 | 0.811 | 0.757 | 0.896 |
| US_SSN | prompt | 51,283 | 51,283 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| US_SSN | tool | 51,283 | 51,283 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| NAME | prompt | 77,200 | 0 | 77,200 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| NAME | tool | 77,200 | 0 | 77,200 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ADDRESS | prompt | 46,264 | 0 | 46,264 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ADDRESS | tool | 46,264 | 0 | 46,264 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |

Results per tier, region and tag, 0.6.21:

| Tier | Part | Channel | TP | FN | FP | P | R | F1 | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|
| core | all | prompt | 125,238 | 10,133 | 0 | 1.000 | 0.925 | 0.961 | 0.961 |
| core | all | tool | 125,238 | 10,133 | 0 | 1.000 | 0.925 | 0.961 | 0.961 |
| personal | all | prompt | 0 | 123,464 | 0 | – | 0.000 | – | – |
| personal | all | tool | 0 | 123,464 | 0 | – | 0.000 | – | – |

Detections of a type of no tier on no labelled value: 0 in both channels.

### PIILO

Cleaning, labelled values per type:

| Type | Labelled | Kept as a value | Of these trimmed | Merged (labelled twice) | Uncertain, by reason | Negative (label error) | Offset moved | Dropped (offset outside the text) |
|---|---|---|---|---|---|---|---|---|
| EMAIL | 39 | 39 | 0 | 0 | 0 | 0 | 0 | 0 |
| PHONE | 6 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| NAME | 1,365 | 1,365 | 0 | 0 | 0 | 0 | 0 | 0 |
| ADDRESS | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| ID_NUMBER | 78 | 78 | 0 | 0 | 0 | 0 | 0 | 0 |
| USERNAME | 6 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |

110 more labels have no type that maisecrets claims (`OUT_OF_SCOPE`); a detection on one is neither a find nor a false
alarm.

Results per type, 0.6.21:

| Type | Channel | Values | TP | FN | FP | P | R | F1 | R, own type | R, covered | R raw | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| EMAIL | prompt | 39 | 39 | 0 | 1 | 0.975 | 1.000 | 0.987 | 1.000 | 1.000 | 1.000 | 0.987 |
| EMAIL | tool | 39 | 39 | 0 | 1 | 0.975 | 1.000 | 0.987 | 1.000 | 1.000 | 1.000 | 0.987 |
| PHONE | prompt | 6 | 0 | 6 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| PHONE | tool | 6 | 4 | 2 | 0 | 1.000 | 0.667 | 0.800 | 0.667 | 0.167 | 0.667 | – |
| IP | prompt | 0 | 0 | 0 | 1 | 0.000 | – | – | – | – | – | – |
| IP | tool | 0 | 0 | 0 | 1 | 0.000 | – | – | – | – | – | – |
| US_BANK_NUMBER | prompt | 0 | 0 | 0 | 1 | 0.000 | – | – | – | – | – | – |
| US_BANK_NUMBER | tool | 0 | 0 | 0 | 1 | 0.000 | – | – | – | – | – | – |
| NAME | prompt | 1,365 | 0 | 1,365 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| NAME | tool | 1,365 | 85 | 1,280 | 0 | 1.000 | 0.062 | 0.117 | 0.062 | 0.062 | 0.062 | – |
| ADDRESS | prompt | 2 | 0 | 2 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ADDRESS | tool | 2 | 0 | 2 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ID_NUMBER | prompt | 78 | 2 | 76 | 0 | – | 0.026 | – | 0.000 | 0.026 | 0.026 | – |
| ID_NUMBER | tool | 78 | 2 | 76 | 0 | – | 0.026 | – | 0.000 | 0.026 | 0.026 | – |
| USERNAME | prompt | 6 | 0 | 6 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| USERNAME | tool | 6 | 0 | 6 | 2 | 0.000 | 0.000 | – | 0.000 | 0.000 | 0.000 | – |

Results per tier, region and tag, 0.6.21:

| Tier | Part | Channel | TP | FN | FP | P | R | F1 | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|
| core | all | prompt | 39 | 6 | 3 | 0.929 | 0.867 | 0.897 | 0.897 |
| core | all | tool | 43 | 2 | 3 | 0.935 | 0.956 | 0.945 | 0.897 |
| personal | all | prompt | 2 | 1,449 | 0 | – | 0.001 | – | – |
| personal | all | tool | 87 | 1,364 | 2 | 0.977 | 0.060 | 0.113 | – |

Detections of a type of no tier on no labelled value: 0 in both channels.

### 0.6.24 against 0.6.23, 2026-10-16

Every type whose counts changed, both channels, by-language regions. 0.6.23 is `origin/main` at `717a83e`; 0.6.24 the
release branch. Mendeley and PIILO changed in no type. Source: `scripts/measure_datasets.py run`, 2026-10-16.

| Dataset | Type | Channel | TP | FP | P | R |
|---|---|---|---|---|---|---|
| Gretel | ADDRESS | tool | 922 → 6,203 | 105 → 380 | 0.883 → 0.942 | 0.029 → 0.198 |
| Gretel | CARD | tool | 223 → 232 | 10 → 11 | 0.951 → 0.949 | 0.445 → 0.463 |
| Gretel | DE_PLZ | tool | 0 → 0 | 274 → 267 | 0.000 → 0.000 | – → – |
| Gretel | ID_NUMBER | tool | 1,092 → 1,093 | 77 → 97 | 0.698 → 0.649 | 0.480 → 0.481 |
| Gretel | NAME | tool | 5,873 → 5,895 | 32 → 32 | 0.994 → 0.994 | 0.076 → 0.076 |
| Gretel | SECRET | tool | 530 → 530 | 101 → 98 | 0.840 → 0.844 | 0.376 → 0.376 |
| Gretel | SE_ORGANISATIONSNUMMER | tool | 0 → 0 | 34 → 5 | 0.000 → 0.000 | – → – |
| Gretel | US_NPI | tool | 0 → 0 | 40 → 0 | 0.000 → – | – → – |
| Gretel | CARD | prompt | 222 → 228 | 10 → 11 | 0.951 → 0.948 | 0.443 → 0.455 |
| Gretel | NAME | prompt | 232 → 231 | 0 → 0 | – → – | 0.003 → 0.003 |
| Gretel | SECRET | prompt | 515 → 515 | 95 → 92 | 0.844 → 0.848 | 0.365 → 0.365 |
| Gretel | SE_ORGANISATIONSNUMMER | prompt | 0 → 0 | 34 → 5 | 0.000 → 0.000 | – → – |
| Gretel | US_NPI | prompt | 0 → 0 | 40 → 0 | 0.000 → – | – → – |
| Nemotron-PII | ADDRESS | tool | 262 → 957 | 0 → 1 | 1.000 → 0.999 | 0.015 → 0.057 |
| Nemotron-PII | BIRTH_DATE | tool | 5,286 → 5,290 | 1 → 1 | 1.000 → 1.000 | 0.292 → 0.293 |
| Nemotron-PII | CARD | tool | 1,458 → 1,516 | 1 → 1 | 0.999 → 0.999 | 0.955 → 0.993 |
| Nemotron-PII | ID_NUMBER | tool | 4,701 → 8,947 | 14 → 15 | 0.962 → 0.997 | 0.163 → 0.311 |
| Nemotron-PII | PHONE | tool | 8,034 → 8,041 | 24 → 24 | 0.997 → 0.997 | 0.266 → 0.266 |
| Nemotron-PII | SECRET | tool | 2,852 → 2,851 | 33 → 33 | 0.988 → 0.988 | 0.245 → 0.245 |
| Nemotron-PII | USERNAME | tool | 43 → 45 | 0 → 0 | – → – | 0.003 → 0.003 |
| Nemotron-PII | US_BANK_NUMBER | tool | 10,018 → 10,027 | 115 → 115 | 0.986 → 0.986 | 0.859 → 0.860 |
| Nemotron-PII | US_NPI | tool | 0 → 0 | 10 → 0 | 0.000 → – | – → – |
| Nemotron-PII | ID_NUMBER | prompt | 4,350 → 4,347 | 0 → 0 | – → – | 0.151 → 0.151 |
| Nemotron-PII | SECRET | prompt | 2,841 → 2,840 | 33 → 33 | 0.988 → 0.988 | 0.244 → 0.244 |
| Nemotron-PII | US_NPI | prompt | 0 → 0 | 10 → 0 | 0.000 → – | – → – |

The new detections by rule, tool channel (`maisecrets/detection/personal.py`, `FORMS`): `address-after-label` 5,372
detections on labelled Gretel addresses and 276 on no labelled value (most of these are addresses of a company named in
the line before the label, or addresses Gretel did not label), 709 on Nemotron-PII addresses;
`id-number-after-record-label` 4,269 detections on labelled Nemotron-PII ID numbers. Gretel ID_NUMBER +20 false alarms: account numbers after `account` and `account number` that Gretel did not
label. Gretel SE_ORGANISATIONSNUMMER −29 and US_NPI −40, Nemotron-PII US_NPI −10 false alarms: Presidio's check
digits. CARD: +9 (Gretel) and +58 (Nemotron-PII) card numbers, mostly in groups without a card word or after the new
card words (`pan`, `cardnumber`, Nordic and Polish words). Nemotron-PII SECRET −1: a lowercase password after a label in
a markdown table cell followed by `and` (the table-cell check of item C4); Nemotron-PII ID_NUMBER −3 in the prompt
channel: the check digit of `us-npi` drops a hit that covered an ID value of another label.

### Label to type

A dataset label maps to the maisecrets type below; every other label is `OUT_OF_SCOPE`. The tables are `LABELS` in
`scripts/measure_datasets.py`.

| Type | Gretel | Nemotron-PII | Mendeley | PIILO |
|---|---|---|---|---|
| SECRET | `password`, `api_key` | `password`, `api_key` | – | – |
| EMAIL | `email` | `email` | `email` | `EMAIL` |
| PHONE | `phone_number` | `phone_number`, `fax_number` | `phone` | `PHONE_NUM` |
| IP | `ipv4`, `ipv6` | `ipv4`, `ipv6` | – | – |
| IBAN | `iban` | an `account_number` that is a valid IBAN | – | – |
| CARD | `credit_card_number` | `credit_debit_card` | `credit_card` | – |
| US_SSN | `ssn` | `ssn` | `ssn` | – |
| ABA_ROUTING_NUMBER | `bank_routing_number` | `bank_routing_number` | – | – |
| US_BANK_NUMBER | – | `account_number` | – | – |
| NAME | `name`, `first_name`, `last_name` | `first_name`, `last_name` | `name` | `NAME_STUDENT` |
| ADDRESS | `street_address` | `street_address` | `address` | `STREET_ADDRESS` |
| BIRTH_DATE | `date_of_birth` | `date_of_birth` | – | – |
| ID_NUMBER | `passport_number`, `driver_license_number` | `national_id`, `tax_id`, `medical_record_number`, `health_plan_beneficiary_number`, `certificate_license_number` | – | `ID_NUM` |
| USERNAME | `user_name` | `user_name` | – | `USERNAME` |

## Rule classes, 2026-10-16

What each class of rules adds at the margin, 0.6.24 against 0.6.23: the script switches one class off and scans every
input again (`scripts/measure_rule_classes.py`, regions `de`, `--locale de_DE`). When a class is off, another rule
can still take the span, so a number counts what only that class catches. The classes come from the rule registry
(`maisecrets/detection/registry.py`, `coarse_class`): a token class per source, one class per label rule, a PII class per
type and region, and one class per secret form of 0.6.24 (`form:`). `maisecrets rules list` shows the class, the
channel, the region and what a rule needs (a label or a form) for each rule.

Base, all rules on (0.6.23 → 0.6.24):

| Input | Items | Prompt channel | Tool channel |
|---|---:|---:|---:|
| CredData, T values masked | 14471 | 9396 → 9396 | 9913 → 9935 |
| CredData, F lines with a masked F value | 9439 | 324 → 324 | 329 → 329 |
| Developer texts (`tests/fp_corpus.py`), HIT values masked | 139 | 139 → 139 | 139 → 139 |
| Developer texts, NO_HIT snippets with a hit | 1114 | 0 → 0 | 0 → 0 |
| PII corpus (`tests/fp_corpus_pii.py`), POSITIVE values masked | 46 | 6 → 6 | 41 → 41 |
| PII corpus, PII_NO_HIT samples with a hit | 367 | 7 → 7 | 7 → 7 |
| Forms corpus (`tests/fp_corpus_forms.py`), FORMS_HIT values masked | 38 | 7 | 37 |
| Forms corpus, FORMS_NO_HIT samples with a hit | 157 | 4 | 6 |
| Cloakroom holdout v2 to v7, planted values masked | 1652 | 854 → 858 | 1086 → 1175 |
| Cloakroom holdout, clean samples with a hit | 215 | 1 → 1 | 1 → 1 |

The hits on FORMS_NO_HIT are hits of older rules on the corpus, measured on 0.6.23 and named in
`tests/test_fp_corpus_forms.py` (`KNOWN`): `us-bank` on a 12-digit AWS account id (two texts), an OID read as an IPv4
address, `generic-api-key` on a 48-digit digest after `key` (two texts), `name-after-label` on `owner: Équipe
Plateforme`, `ds-keyword-equal-signs` on base64 of a name after `apiKey =`. The only hit of 0.6.24 there is
`secret-add-mask` on `::add-mask::` with a word value in the tool channel: `::add-mask::` declares its value a secret.

Per class, sorted by the values it alone catches (tool channel, CredData plus holdout plus PII corpus). "T only this
class" is a value the base masks and the variant does not; "F only this class" is a CredData F line that has a false
hit in the base and none in the variant. "Margin precision" is T / (T + F) of the CredData tool column: the precision of
what only this class adds. The other corpora are in the tool channel, as values lost / clean samples saved. A number in
brackets is 0.6.23 where it differs.

| Class | Rules | CredData T only this class, prompt / tool | CredData F only this class, prompt / tool | Margin precision, tool | Holdout values / clean samples | PII corpus values / clean | Forms corpus values / clean | Developer texts HIT / NO_HIT |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `label:generic-api-key` | 1 | 3561 / 2555 (0.6.23: 3563) | 58 / 60 | 0.98 | 5 / 0 | 0 / 0 | 0 / 2 | 0 / 0 |
| `label:auth-scheme` | 1 | 767 / 766 | 0 / 0 | 1.00 | 3 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `label:literal` | 4 | 230 / 739 (0.6.23: 741) | 7 / 9 | 0.99 | 3 / 0 | 0 / 0 | 0 / 0 | 7 / 0 |
| `label:keyword` | 16 | 1007 / 576 (0.6.23: 588) | 140 / 134 | 0.81 | 23 / 0 | 0 / 0 | 0 / 0 | 64 / 0 |
| `token:betterleaks` | 416 | 318 / 303 | 18 / 18 | 0.94 | 63 / 0 | 0 / 0 | 0 / 0 | 5 / 0 |
| `pii:email` | 2 | 9 / 9 | 20 / 20 | 0.31 | 300 / 0 | 0 / 1 | 4 / 0 | 2 / 0 |
| `token:own-secret` | 21 | 233 / 220 | 3 / 3 | 0.99 | 10 / 0 | 0 / 0 | 0 / 0 | 3 / 0 |
| `pii:phone` | 3 → 5 | 0 / 0 | 0 / 0 | – | 180 / 0 | 3 / 4 | 2 / 0 | 3 / 0 |
| `token:detect-secrets` | 1 | 128 / 128 | 7 / 7 | 0.95 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:name` | 2 → 3 | 0 / 0 | 0 / 0 | – | 104 / 0 | 11 / 0 | 4 / 1 | 0 / 0 |
| `pii:id_number` | 1 → 6 | 0 / 0 | 0 / 0 | – | 49 / 0 | 8 / 0 | 7 / 0 | 0 / 0 |
| `pii:ip` | 5 | 0 / 0 | 15 / 15 | 0.00 | 61 / 0 | 0 / 0 | 0 / 1 | 0 / 0 |
| `pii:birth_date` | 1 | 0 / 0 | 0 / 0 | – | 47 / 0 | 8 / 0 | 0 / 0 | 0 / 0 |
| `pii:address` | 1 → 4 | 0 / 0 | 0 / 0 | – | 47 / 0 | 1 / 0 | 4 / 0 | 0 / 0 |
| `pii:column` | 1 | 0 / 0 | 0 / 0 | – | 25 / 0 | 3 / 0 | 0 / 0 | 0 / 0 |
| `pii:iban` | 2 | 2 / 1 | 0 / 0 | 1.00 | 24 / 0 | 0 / 0 | 0 / 0 | 2 / 0 |
| `pii:username` | 2 | 0 / 0 | 0 / 1 | 0.00 | 20 / 0 | 4 / 0 | 0 / 0 | 0 / 0 |
| `pii:card` | 1 | 0 / 0 | 0 / 0 | – | 18 / 0 | 0 / 0 | 4 / 0 | 0 / 0 |
| `form:secret-hex48-after-token-word` | 0 → 1 | 0 / 14 (0.6.23: 0) | 0 / 0 | 1.00 | 3 / 0 | 0 / 0 | 1 / 0 | 0 / 0 |
| `form:secret-in-login-code` | 0 → 1 | 0 / 0 | 0 / 0 | – | 4 / 0 | 0 / 0 | 2 / 0 | 0 / 0 |
| `form:secret-postman-variable` | 0 → 1 | 0 / 0 | 0 / 0 | – | 2 / 0 | 0 / 0 | 3 / 0 | 0 / 0 |
| `token:fallback` | 4 | 0 / 0 | 0 / 0 | – | 5 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `form:secret-after-user-slash` | 0 → 1 | 0 / 0 | 0 / 0 | – | 2 / 0 | 0 / 0 | 2 / 0 | 0 / 0 |
| `form:secret-add-mask` | 0 → 1 | 0 / 0 | 0 / 0 | – | 1 / 0 | 0 / 0 | 2 / 1 | 0 / 0 |
| `form:secret-shared-access-key` | 0 → 1 | 0 / 0 | 0 / 0 | – | 1 / 0 | 0 / 0 | 1 / 0 | 0 / 0 |
| `pii:de_passport@de` | 1 | 0 / 0 | 0 / 0 | – | 0 / 0 | 1 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_plz@de` | 1 | 0 / 0 | 0 / 0 | – | 1 / 0 | 0 / 1 | 0 / 0 | 0 / 0 |
| `token:own-json` | 9 | 0 / 0 | 0 / 0 | – | 1 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `label:url-query-secret` | 1 | 1 / 1 | 7 / 7 | 0.12 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `label:auth-scheme-apikey` | 1 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 2 / 0 |
| `pii:de_social_security@de` | 3 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_vat_id@de` | 2 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 1 | 0 / 0 | 0 / 0 |
| `pii:de_id_card@de` | 1 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_kfz@de` | 5 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 0 |
| `pii:de_tax_number@de` | 3 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 0 |
| `pii:de_health_insurance@de` | 1 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_lanr@de` | 1 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_tax_id@de` | 2 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_bsnr@de` | 1 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:address@in` | 0 → 1 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_fuehrerschein@de` | 1 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `token:prefixes` | 44 | 0 / 0 | 0 / 0 | – | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

`label:generic-api-key` alone catches fewer values than in 0.6.23 (tool 2555, 0.6.23: 3563) because the secret forms
of 0.6.24 also take many of its values when it is off (`form:secret-hex48-after-token-word` 14 alone); together they
mask more (CredData T values masked in the tool channel 9913 → 9935).

With a class switched off, the variant also masked values that the base leaves: `label:url-query-secret` off: 3 / 3
(CredData, prompt / tool); `token:own-secret` off: 1 / 1. There the class takes a span, and with the class off a later
rule masks the value. See "Rule order" below.

### Rule order, measured and kept (0.6.24)

The registry measurement of 2026-10-15 found that the own SECRET rules ranked after every other built-in rule catch 4
more CredData credentials. Measured again on 0.6.24 (`scripts/detection_fingerprint.py --creddata`, regions `de`,
both channels, and the unit suite):

Measured on the branch at the commit of the entropy floors (`a0d2628`, CredData T 5,876 and F 446 in the tool channel):

| Variant | CredData T / F, tool, regions `de` | Hit lists that change (CredData lines, per channel) | Unit tests red |
|---|---|---|---|
| own SECRET rules first (as released) | 5,876 / 446 | – | 0 |
| own SECRET rules last (band 850) | 5,880 / 446 (+4 in half V) | 396 | at least 9 test methods |
| only `url-query-secret` and `aws-secret-after-access-key` last | 5,880 / 446 (+4 in half V) | not measured | 5 test methods |

The 4 rows: three tokens of the CredData category UUID that `ds-keyword-equal-signs` takes whole when
`url-query-secret` comes later, and one AWS key id that `label-secret-literal` takes when
`aws-secret-after-access-key` comes later. What the move costs, by transition of the hit list (CredData, regions `de`,
per channel): `auth-scheme` → `grafana-api-key` 69 lines and → `jwt` 22 (same characters, a label rule becomes a shape
rule), `paseto-token` → `ds-keyword-colon` 39, `url-query-secret` → `ds-keyword-equal-signs` 33 (same characters)
and 20 (more characters: the next query parameter, `&x=1`, joins the value), `auth-scheme` → `curl-auth-header` 5;
in the token lists of the tests, 20 provider ids each become `ds-keyword-equal-signs` (a token in test code then counts
as a label hit). With only the two rules moved, `?token=<value>&x=1` stores `<value>&x=1`, and the secret half of an
AWS key pair in the console's two-line form is no longer found. The order stays.

Inputs: CredData as in "CredData, results per release" (every unique labelled line, 23155 lines; a T value counts once
per line); Cloakroom's holdout sets v2 to v7 as in "Cloakroom holdout sets"; the three test corpora of this tree. The
0.6.23 column runs the same script with the same corpora. A run takes about 60 seconds with 6 workers.

## Comparison with other tools

"Theirs" is Cloakroom's
[`bench/RESULTS.md`](https://github.com/shanjeevrajendran/cloakroom/blob/cf4360c8bd/bench/RESULTS.md) at commit
`cf4360c8bd` (2026-10-12); each cell names the version and the date that file gives. Their maisecrets runs equal
`--regions us` here. "Ours" is a script of this repository, 2026-10-14, unless the cell says otherwise. Machines
and inputs differ, so a time gives an order of magnitude, not a ranking.

| Measure | maisecrets | Cloakroom (rules and model) | Source |
|---|---|---|---|
| CredData, all rows, P / R / F1 | 0.6.14: 0.90 / 0.61 / 0.73 | 0.2.0: 0.66 / 0.65 / 0.66 | theirs, 2026-10-12 |
| CredData, all rows, P / R / F1, `--regions us` | 0.6.14: 0.900 / 0.613 / 0.729; 0.6.17 tool: 0.908 / 0.683 / 0.780 | – | ours |
| CredData without `2ba83c6a`, P / R / F1 | 0.6.14: 0.83 / 0.48 / 0.61 | 0.2.2: 0.66 / 0.73 / 0.69 | theirs, 2026-10-12 |
| CredData without `2ba83c6a`, P / R / F1 | 0.6.17 tool: 0.855 / 0.578 / 0.690 (`--regions us`), 0.929 / 0.578 / 0.713 (`--regions de`) | – | ours |
| CredData, non-secret rows masked | 0.6.14: 981 | 0.2.0: 4,750 | theirs, 2026-10-12 |
| CredData recall by category: passwords / tokens / URL credentials / AWS client IDs | 0.6.14: 0.62 / 0.66 / 0.70 / 0.36 | 0.2.0: 0.97 / 0.96 / 1.00 / 0.99 | theirs, 2026-10-12 |
| CredData recall by category: generic keys | 0.6.14: 0.88 | 0.2.0: 0.36 | theirs, 2026-10-12 |
| Holdouts v2–v6 rerun, values leaked: critical of 334 / high of 1,005 / low of 221 | 0.6.14: 78 / 550 / 161 (default regions), 67 / 550 / 161 (us, uk, in) | 0.2.0: 2 / 1 / 1 | theirs, 2026-10-12; sets seen before, their file: "not an honest score" |
| Holdouts v2–v6 rerun, false alarms in 200 clean samples | 0.6.14: 5 (default regions), 6 (us, uk, in) | 0.2.0: 23 | theirs, 2026-10-12; sets seen before |
| Holdout v6, values leaked of 314 / false alarms of 40 | 176 / 5 (version not given) | 3 / 12 | theirs, 2026-10-10 |
| Holdout v7, real vendor key formats: values leaked of 77 / false alarms of 15 | 0.6.14: 13 / 1 | 0 / 3 | theirs, 2026-10-12 |
| Holdout v7, values leaked of 77 | 0.6.15: 3 (Twilio Account SIDs) | – | ours, 2026-10-13, their `holdout_v7` set, reported in [#17](https://github.com/Mcpgate-de/maisecrets/issues/17); `scripts/measure_holdouts.py` gives the same 3 (2026-10-16) |
| Names and street addresses | not detected (README, "Names are not detected") | detected by its model (PII-Tracer) | README; theirs |
| Time per item in their harness, holdout v6 | 0.4 ms (version not given) | 63 ms | theirs, 2026-10-10 |
| Time per item, other machines | – | 62 ms on an Apple M-series CPU; 887 ms on a 2-vCPU Windows server; `cloakroom doctor`, one check on that server: 412 ms | theirs, 2026-10-10 |
| Time per scan, v0.6.17 | 1.8–2.2 ms per 1 KB prompt; 80–242 ms per 70 KB tool result; 46–68 ms import + first scan (Apple M5) | – | ours, "Timing" above |

maisecrets uses rules, checksums and labels and no model; Cloakroom adds a language model to its rules.

## Credit

The line method (each labelled line alone, without its file path) and the split without the test-vector
repository come from the [Cloakroom](https://github.com/shanjeevrajendran/cloakroom) benchmark
([`bench/RESULTS.md`](https://github.com/shanjeevrajendran/cloakroom/blob/cf4360c8bd/bench/RESULTS.md)) and from
the discussion in [Mcpgate-de/maisecrets#17](https://github.com/Mcpgate-de/maisecrets/issues/17).
`scripts/measure_creddata.py` follows its `bench/credata.py`. The holdout sets v2 to v7 are Cloakroom's. The rule families of 0.6.21 for a name before an
e-mail address and for the columns of a CSV header follow Cloakroom's rules (Apache-2.0); the code is written anew.

The rules of 0.6.24 from the same fork's list (`docs/UPSTREAM-DETECTION.md`, Apache-2.0): Presidio's check digits for
the US NPI, the Swedish organisation number and the UK number plate, no UK postcode alone, the IBAN after an MT940
subfield code, four checks of the password-label rules, one entropy floor per alphabet for `generic-api-key`, a card
number without a card word, and the masked copy that the skill offers before it reads a file full of secrets. Each
commit names the fork's commits; the code is written again and measured here.

The method of the labelled PII datasets comes from the bench of the public fork
[danszymkowiak/maisecrets](https://github.com/danszymkowiak/maisecrets) (Apache-2.0, commit `73f36bd`, `bench/` and
`docs/UPSTREAM-DETECTION.md`): the choice of the datasets, the cleaning of the labels before a rule is judged (a
checksum, a placeholder, a reserved domain, a private address, a label error, the rule that no cut drops a group of a
value, the repair of Mendeley's mojibake), the label tables and the Mendeley sheet reader.
`scripts/measure_datasets.py` adapts them; the checks are written again with the standard library.

## Method and limits

- **Rows.** A row is a CredData label with `GroundTruth` T or F, on one line, with a value position and a value of
  4 or more characters.
- **Line method.** Each line is scanned alone, without its file path, the way a prompt or a tool result reaches the
  hook. A row is caught when its labelled value no longer appears after every match is masked.
- **No file path.** In the hook, a file path can change the result (test files, `is_fixture`). CredData lines carry
  no path here, so a rule that uses the path shows no effect in this benchmark.
- **The test-vector repository.** Repository `2ba83c6a` holds 3,427 of CredData's 3,822 "Key" credentials, nearly
  all cipher test vectors (`Key = <hex>`; count from Cloakroom's `bench/RESULTS.md`). The first table leaves it
  out; the second keeps it.
- **Split.** A repository is in half D when the first 8 hex digits of sha256 of its id give an even number, and in
  half V otherwise.
- **Classes of missed rows.** In this order: an identifier (the value is a UUID, or the category names a UUID, a
  bucket or an id); a password of letters only (a "Password" row whose parts between `_`, `.` and `-` are letters);
  a value without a label (no name right before the value, after an optional `=`, `:`, `(` or quote); else a
  labelled value. The
  same-class non-secrets are the non-secret rows of that class that the release leaves alone.
- **Regions.** `--regions` selects the country rules for personal data. With `us`, the US bank-account rule takes
  digit runs; this adds 546 false alarms to every release on the split without `2ba83c6a`. `--locale` sets the
  system setting maisecrets sees (the label languages); for 0.6.17 (tool channel, all rows, `--regions us`),
  `de_DE` and `en_US` give the same numbers.
- **Channel.** From 0.6.17, a typed prompt (`prompt`) and a tool result or a file (`tool`) take different password
  rules. A harness that calls `detect.scan(text)` measures the prompt channel.
- **The store.** Each run uses a new temp store. Values that a session stores and looks for later play no part.
- **Obfuscation.** CredData replaces each credential with a random value of the same shape. The seed is fixed per
  row (`obfuscate_creds.py`, `--noise 0`), so a download at the pinned commit gives the same lines.

- **Labelled PII datasets: the cleaning.** Each labelled value of a type with a check goes through it before it is
  counted. A value that fails is *uncertain*: neither a miss nor a false alarm, and a detection on it counts neither
  way. The checks: CARD Luhn over 13 to 19 digits; IBAN two letters, two digits, 11 to 30 letters or digits and mod
  97; US_SSN no area 000, 666 or 9xx, no group 00, no serial 0000, and not an advertising number such as 123-45-6789;
  ABA_ROUTING_NUMBER the 3-7-1 checksum; PHONE 7 to 15 digits, no letters, not one repeated digit, and a North
  American number with an area code and an exchange that start with 2 to 9 and an area code without a 9 in the middle
  (`(123) 456-7890`, `(800) 123-4567` and `555-555-5555` fail). A number is North American when it starts with `+1`
  or `1`, or, in English text only, when it has the US layout without a leading 0. EMAIL: the address syntax (a full
  stop after the address is trimmed off) and not a reserved domain (example.com, .net, .org, and .test, .example,
  .invalid, .localhost); maisecrets leaves these alone on purpose. It also leaves `.local` and `.internal` alone;
  those count as values here, so they lower R. IP: a public address by Python's `ipaddress` (`is_global`), as
  maisecrets masks public addresses only; the resolver addresses that maisecrets skips count as values. Python 3.9
  and 3.14 differ on a few IPv6 ranges; `--out` names the Python of the run (3.14.8 here). US_BANK_NUMBER: 4 to 17
  digits and no letters. The checks are written in the script; they do not use the measured checkout, so a release
  cannot change its own gold.
- **Label errors.** A PHONE, EMAIL or IP label with no digit or no `@` in it (`[Phone Number]`, a phrase) is
  negative: a detection there is a false alarm.
- **Spans wider than the value.** A span with text around a valid value (a card block with holder, expiry and CVC)
  is trimmed to the value. A cut falls only at a separator, and only when the first group it drops differs in length
  from the last group it keeps (the ` 12` of an expiry after a card number). A fake card or IBAN cut at a group
  boundary passes its checksum by chance (1 in 10, 1 in 97); such a span stays uncertain. PHONE, EMAIL and IP spans are
  never shortened inside a match: a shorter phone number passes the rules as easily as the whole one.
- **Offsets.** A span outside the text is dropped and counted. Where a dataset says what a span holds (Nemotron's own
  copy of the value, Mendeley's value columns), a span that does not hold it moves to the nearest copy within 64
  characters, or else becomes uncertain. Mendeley's texts are UTF-8 read as cp1252; the script repairs them first,
  and then every span holds its value (0 moved).
- **Values labelled twice.** Positive spans of one type that overlap are one value (Gretel labels some values
  twice); the cleaning table counts them under "merged". The raw recall merges them the same way.
- **Account numbers as IBANs.** A Nemotron `account_number` that is no US bank number but a valid IBAN counts as an
  IBAN.
- **Scoring.** A labelled value is found (TP) when a detection of any type overlaps it by one character or more.
  "R, own type" counts a value only when a detection of its own type overlaps it; "R, covered" only when the
  detections together cover every character of it. A detection on no labelled value of any type and on no uncertain
  value is a false alarm (FP) of the detected type. P is the share of a type's detections on a labelled value of
  that type among those detections and its FP; a detection on a value of another type only counts in neither, and
  each detection counts once (two fragments on one value count twice). Unlabelled text counts as clean: an FP can be
  a real value that the dataset left unlabelled (the generated datasets have values outside their labels; PIILO
  labels only a student's own data). A type of no tier (`US_PASSPORT`, `DE_PLZ`, …) has no labelled values; its
  detections on no labelled value are listed under each dataset.
- **Gretel.** Train and test splits; records below Gretel's own `quality_score` 90 are left out, as the fork did. The
  structured formats (CSV, EDI, SWIFT, FIX, BAI, XBRL, FpML, MT940) stay and carry the tag `format:structured`.
- **Regions.** Each language group runs with its own regions setting and locale: English `us`/`en_US`, German
  `de`/`de_DE`, French `fr`, Spanish `es`, Italian `it`, Dutch `nl`, Swedish `se`/`sv_SE`. `--regions` sets one
  regions setting for every text.
- **The store.** Each language group runs in a new temp home. Values that a session stores play no part.

## Repeat this measurement

On Linux or macOS (CredData has file names that Windows does not allow). The download fetches the 337
repositories of the meta files and needs about 1 GB. The scripts are on `main`; each release to measure is a
worktree of its tag.

```bash
git clone https://github.com/Samsung/CredData.git
cd CredData
git checkout 0b1940e171725ad8937311120b191602608a4801
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python download_data.py --data_dir data
cd ..

git clone https://github.com/Mcpgate-de/maisecrets.git
cd maisecrets
git worktree add ../maisecrets-0.6.17 v0.6.17
git worktree add ../maisecrets-0.6.16 v0.6.16
python3 scripts/measure_creddata.py ../CredData --maisecrets ../maisecrets-0.6.17 --channel tool --split half \
    --baseline ../maisecrets-0.6.16
python3 scripts/measure_scan_time.py --maisecrets ../maisecrets-0.6.17 --channel tool
python3 scripts/measure_rule_classes.py --creddata ../CredData --holdout <Cloakroom checkout>/bench --workers 6
```

The download took about 1 hour here. If a clone stops on a network error, run `download_data.py` again; it keeps
the repositories it already has. A fresh download on 2026-10-14 gave the same `data/` tree, file for file, as the
copy behind the tables, and the same output below.

One CredData run takes about 10 seconds on the machine above (8 worker processes). The CredData command prints:

```text
CredData line method, without 2ba83c6a, channel tool, regions de, locale de_DE: 23667 rows
maisecrets                   TP  5838  FN  4268  FP   443  TN 13118  P 0.929  R 0.578  F1 0.713
  half D                     TP  3158  FN  1730  FP   273  TN  8666  P 0.920  R 0.646  F1 0.759
  half V                     TP  2680  FN  2538  FP   170  TN  4452  P 0.940  R 0.514  F1 0.664
baseline                     TP  5328  FN  4778  FP   441  TN 13120  P 0.924  R 0.527  F1 0.671
  half D: caught only by maisecrets +263 credentials / +2 false alarms; caught only by the baseline 0 / 0
  half V: caught only by maisecrets +247 credentials / +0 false alarms; caught only by the baseline 0 / 0
credentials still missed: 4268
  identifier (UUID, bucket name, id)    2589 (60.7%)   same-class non-secrets  3728   precision of a rule that took the class 0.41
  labelled value, not a word            1140 (26.7%)   same-class non-secrets  7536   precision of a rule that took the class 0.13
  value without a label                  300 ( 7.0%)   same-class non-secrets  1011   precision of a rule that took the class 0.23
  password of letters only               239 ( 5.6%)   same-class non-secrets   843   precision of a rule that took the class 0.22
```

Options: `--channel prompt`, `--regions us`, `--exclude-repo ""` (all rows), `--out result.json` (counts and
per-row results with row ids, labels and rule ids; no value).

The Cloakroom holdout sets (six files, about 230 KB, Apache-2.0) come from their pinned commit; `fetch` checks the
sha256 of each file, and `--bench <Cloakroom checkout>/bench` reads a checkout instead. One run of two releases in both
region sets takes about 10 seconds:

```bash
python3 -I scripts/measure_holdouts.py fetch          # into ~/.cache/maisecrets-datasets/cloakroom
git worktree add ../maisecrets-0.6.24 v0.6.24
git worktree add ../maisecrets-0.6.25 v0.6.25
python3 -I scripts/measure_holdouts.py run --maisecrets ../maisecrets-0.6.25 --baseline ../maisecrets-0.6.24
```

It prints the tables of "Cloakroom holdout sets": per set and half, the sums v2 to v6 and v2 to v7, the false alarms on
the clean samples and the class table, once for the regions `us`, `uk`, `in` and once for `de` (`--regions`). `--out`
writes the counts and, per planted value, its set, sample id, index, half, class and whether it leaked; no value.

The catalog coverage needs Python 3.11 or newer (tomllib) and PyYAML. Clone each catalog at its pinned commit into one
directory, under the names below, and run the script; it reads the catalogs as data and prints counts only:

```bash
mkdir catalogs && cd catalogs
for spec in noseyparker=https://github.com/praetorian-inc/noseyparker@2e6e7f36ce36619852532bbe698d8cb7a26d2da7 \
    kingfisher=https://github.com/mongodb/kingfisher@82d050530cdef9af070b8f9a75701c9c27a948c3 \
    gitleaks=https://github.com/gitleaks/gitleaks@b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b \
    betterleaks=https://github.com/betterleaks/betterleaks@c613797a684337a014168063577bb6fa6e3b6296 \
    trufflehog=https://github.com/trufflesecurity/trufflehog@27d8ea2876d990b274996fc97aff0f8d952d364c \
    gitlab=https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-rules@cae5670b0d83aaea0ff37c085119e82ff394f283
do
  name=${spec%%=*}; rest=${spec#*=}
  git clone -q "${rest%@*}" "$name" && git -C "$name" checkout -q "${rest##*@}"
done
cd ..
python3 maisecrets/scripts/measure_catalog_coverage.py catalogs --maisecrets maisecrets-0.6.20 \
    --baseline maisecrets-0.6.19
```

The labelled PII datasets need about 400 MB of disk outside the repository (default `~/.cache/maisecrets-datasets`).
The fetch reads the Hugging Face parquet files with pyarrow (26.0.0 here) and stores them as gzipped JSON lines; the
run needs the standard library only and works on Python 3.9:

```bash
python3 -m venv ../pyarrow-venv && ../pyarrow-venv/bin/pip install pyarrow
../pyarrow-venv/bin/python -I scripts/measure_datasets.py fetch     # about 1 minute; checks each sha256
git worktree add ../maisecrets-0.6.20 v0.6.20
python3 -I scripts/measure_datasets.py run --maisecrets ../maisecrets-0.6.20 \
    --out ~/.cache/maisecrets-datasets/result-0.6.20.json
git worktree add ../maisecrets-0.6.21 v0.6.21
python3 -I scripts/measure_datasets.py run --maisecrets ../maisecrets-0.6.21 \
    --out ~/.cache/maisecrets-datasets/result-0.6.21.json
```

One run of all four datasets took 6 to 9 minutes here (6 worker processes, load average 8 to 15): Gretel 80 to 95 s,
Nemotron-PII 160 to 220 s, Mendeley 80 to 170 s, PIILO 30 to 50 s. `--only nemotron` runs one dataset, `--channel
tool` one channel, `--limit 2000` a fixed choice of about 2,000 samples per dataset. The script prints the cleaning
counts and, per channel, one line per type and per tier, region and tag; `--out` writes the same counts and, per
sample, its id, the gold spans (offsets, label, type, verdict), the detections (offsets, type, rule id, class) and
whether each span was found. It holds no value.

To judge a rule class: run the release before the change and the change, each with `--out`, and compare the rows of
the rule's type in both channels. TP and FN show the gain; FP shows the cost; "R raw" against R shows how much of a
change falls on values the cleaning set aside.

## Add a new release row

1. Add a worktree of the new release tag, and one of the release before it for `--baseline`.
2. For the first table, run the CredData command four times: `--channel prompt` and `--channel tool`, each with
   `--regions de` and `--regions us`.
3. For the second table, run the same four commands with `--exclude-repo ""`.
4. Run `scripts/measure_scan_time.py` with both channels, on Python 3.9 and on the newest Python, two rounds at a
   load average below 5.
5. Run `scripts/measure_datasets.py run --maisecrets <release> --out <file>` and add a column for the release to
   the tables of "Labelled PII datasets".
6. Add the rows to the tables above. Change the date, the release and the machine in the snapshot table. Keep the
   rows of earlier releases as they are.
7. If the CredData commit or a pinned dataset changes, run every release again and name the new version.
