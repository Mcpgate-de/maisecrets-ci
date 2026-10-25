# V3 PII recall split by class (post-hoc diagnostic, 2026-10-25)

Not a new benchmark. `bench/stratify_v3.py` reads the result files in `../run` (maisecrets 0.7.3, Presidio,
Preserve, pii-anon), runs no scanner and changes no number of the V3 report.

- Samples: Nemotron-PII, Mendeley and Gretel 1/25 of `val`; Privy 1/10 of its test set.
- Recall is strict, as in `bench/score.py`: a labelled value is found when the tool's findings cover it whole, of
  any class. Only the denominator is split: names (`pii.name`) and every other PII class.
- The classes add up to the PII total of each file (the script asserts it). The `all` total of a result file also
  holds the secret spans of the scanners that look for secrets; these files count PII only.
- False positives are copied as they are: `fp_v3` counts a finding in a class the dataset labels, `fp_v2` every
  finding, `out_of_scope_findings_v3` the difference. A result file keeps no class and no position of a false
  positive, so they cannot be split by class without a new run.
- `small_sample` marks a class with less than 30 labelled values.
- Lower-bound labels (`lower_bound_classes`): Nemotron `national_id`, Gretel `bank_account`. Privy's
  `excluded_shapes` (`bench/v3.py`) take an SSN-shaped `national_id` finding out of the false positives, because
  Privy labels no SSN; it does not change a recall.
- F1 under V3 uses `precision_v3`. The `f1` field of a result file uses the V2 precision and differs from it.
