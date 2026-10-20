# Benchmark V3: a draft of the method

Status: **draft** (2026-10-20). V2 stays as frozen (`docs/BENCHMARK-V2.md`); no V2 result is scored again. This
file says what a V3 changes and why, with the counts that led to it. Nothing here is implemented yet.

## Why a V3

V2 counts a finding as a false positive when it lies on no labelled span. That is right only where a dataset labels
every value of the kind the finding has. The counts below show where this does not hold.

All counts: maisecrets on `next` at 898a95c2, regions `generic,de,us`, tool channel. On the development data cases
were read; on Privy only totals by class and by rule (`docs/BENCHMARK-V2.md`, "Which data is what").

### Finding 1: a source type that the dataset does not label

| Dataset | False positives | in a class the dataset labels | in a class it does not label |
|---|---|---|---|
| Privy (all) | 3,443 | 1,708 | 1,735 (`email` 738, `ip` 760, phone 136, secret 101) |
| Gretel dev | 2,164 | 2,100 | 64 (secret) |
| Nemotron dev | 501 | 483 | 18 (secret) |
| Mendeley dev | 16 | 16 | 0 |
| PIILO dev | 2 | 1 | 1 |

The class view hides part of the gap. Privy labels `pii.national_id` through driver licenses, passports and ITINs,
but has no SSN label: its 796 `us-ssn` findings fall into a labelled class. Privy has no IBAN label either; its 7
IBAN spans are `US_BANK_NUMBER` labels that the label cleaning retyped because the value is a valid IBAN
(`scripts/measure_datasets.py`), so the class `pii.iban` counts as labelled while 820 IBAN findings meet no label.

### Finding 2: a labelled class whose labels are not exhaustive

| Dataset, split | Rule | False positives | with a label word of the class in the 40 characters before |
|---|---|---|---|
| Nemotron dev | `us-ssn` | 254 | 236 (SSN, social security) |
| Gretel dev | `us-bank` | 762 | 709 (account, acct, routing, bank) |

Gretel labels 85 bank accounts on dev; 709 more numbers stand after an account word and carry no label. Nemotron
labels SSNs, and 236 more stand after an SSN word without a label. A label word is evidence, not proof: these counts
are an upper bound of the missing labels, and a sample must be read before a number is trusted.

## What V3 changes

1. **Scope per source label type, not per class.** Each dataset gets a list of the source label types it annotates
   (from its card and its label inventory, fixed before a run, as Privy's mapping was in V2). A finding counts for
   precision only when its type maps to one of them. A class that a dataset reaches only through retyping (Privy's
   IBANs) is out of scope for that dataset.
2. **`out_of_scope` findings are reported apart.** A finding of a type the dataset does not annotate is neither right
   nor wrong. The report lists them per type next to the scored numbers, so a scanner that finds e-mail addresses in
   Privy is not punished for it, and nothing is hidden either.
3. **An exhaustiveness check per dataset and type.** Before a type is in scope, a sample of its unlabelled findings
   with a label word before them is read (development data only; for an independent set the dataset's own
   documentation decides). When the labels are not exhaustive, the type is scored for recall only, and its precision
   is reported as a lower bound with the sample's result.
4. **The same rules for every scanner.** The scope is a property of the dataset, never of a scanner.

## Privy stays unread

Privy is the one independent public set. Its cases are not read, also not for an audit and not by a separate
person. Its precision is reported as **observed precision under incomplete annotation**, a conservative lower bound.
`out_of_scope` is counted for Privy only where the source label types and the finding's type decide it, without a
case text. A calibrated Privy precision would need its own audit procedure, frozen before the first case is read
(seed, sample size, scheme, an independent reader); there is none now.

## The false-positive audit on development data (registered before the first case is read)

Registered 2026-10-20 in this commit, before any case of the sample was read.

- **Population:** the false positives of maisecrets `next` 898a95c2 (regions `generic,de,us`, tool channel) on the
  `dev` split, in four strata: Nemotron `us-ssn` (254), Nemotron all other rules (247), Gretel `us-bank` (762),
  Gretel all other rules (1,402).
- **Sample:** 40 per stratum, 160 in all. Order the false positives of a stratum by
  `sha256("v3-audit-20261020/" + case_id + "/" + start)` and take the first 40. The script is
  `scripts/fp_audit_sample.py`; it prints each finding's class, rule and context with the value replaced by its
  shape (letters and digits counted, no character of the value).
- **Scheme**, one code per finding, decided from the context and the shape:
  - `real-same`: a real value of the finding's class that the dataset did not label;
  - `real-other`: a real sensitive value of another class (the finding's type is wrong, the masking is right);
  - `not-sensitive`: no sensitive value (an id of a thing, a placeholder, a version, a count);
  - `unclear`: the context does not decide it.
- **Report:** per stratum, the count of each code and the share of `real-same` + `real-other` with a 95 % Wilson
  interval. The stratum totals scale the shares to an estimate of true false positives per dataset. The result
  changes no rule; it changes how V3 reports precision.

### The audit result (read 2026-10-20, after the registration)

One reader (the maintainer's session that registered it), codes from the masked context. `unclear` counts as a true
false positive, so the estimate is conservative.

| Stratum | False positives | real-same | real-other | not-sensitive | unclear | real share, 95 % Wilson |
|---|---|---|---|---|---|---|
| Nemotron `us-ssn` | 254 | 38 | 0 | 1 | 1 | 0.95 [0.83, 0.99] |
| Nemotron other rules | 247 | 12 | 2 | 19 | 7 | 0.35 [0.22, 0.50] |
| Gretel `us-bank` | 762 | 32 | 0 | 4 | 4 | 0.80 [0.65, 0.90] |
| Gretel other rules | 1,402 | 14 | 5 | 16 | 5 | 0.47 [0.33, 0.63] |

Scaled to the strata, the true false positives on `dev` are about **173** of 501 on Nemotron (interval 126 to 234)
and about **888** of 2,164 on Gretel (606 to 1,205). The observed precision understates the real one:

| Dataset, dev | Observed precision (V2) | Estimated precision, 95 % |
|---|---|---|
| Nemotron | 0.9954 | 0.9984 [0.9978, 0.9988] |
| Gretel | 0.9024 | 0.958 [0.943, 0.971] |

What the true false positives are: reference numbers in EDI and SWIFT messages and vehicle recalls taken by
`us-passport` and `us-license`, bank routing codes and policy numbers taken by `us-bank`, company addresses and
postcodes, gateway addresses of network configurations, and template text after a password word. These are the
false-positive work for the next rounds; the audit changes no rule by itself.

The bench adapter also puts a `us-bank` hit into the class `pii.national_id` (`cls_of` in
`bench/adapters/maisecrets.py` does not know `US_BANK_NUMBER`). A false positive is counted the same either way; a
per-class table is not. To fix with V3.

## What V3 keeps

The split rule, the span outcomes (`full`, `partial`, `missed`), `too wide`, the classes, the scanners and their
configurations. V2 results stay as they are; a V3 report runs the same result files through the new scoring and
names both.

## Open before V3 is frozen

- The label inventory per dataset as a committed file (source label type, count, mapped class), and its test.
- The size of the sample for the exhaustiveness check, and who reads it.
- Whether the bank and Holdout V2 need a scope list (they are written by this project and label every type they use,
  so their scope is every class they contain).
