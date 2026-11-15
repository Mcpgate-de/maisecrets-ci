# 0.9.12: the gate stopped, and the release went out with this trade-off

The release gate (next 916fda2f) stopped because spans got worse on four splits of Gretel and Nemotron. Holdout V2,
catalog coverage and CPU time did not get worse. The maintainer let the decision to the release author, who released.

All the worse spans come from two checks of 0.9.12 (`detection/public_values.py`):

- A bank number that is a run or one repeated digit (123456789, 0000000000) is no person's number. The bank-number
  rule needs an account word near the value, so every run it finds stands after an account label: the false alarms it
  removes and the values it loses have the same form. On the full splits the datasets leave about 205 such runs
  unlabelled and label about 42 (Nemotron val 14 and holdout 25 as `pii.bank_account`; Gretel labels the runs after
  `account number:` as `pii.name`, val 28, holdout 23).
- A North American toll-free number in its NANP form (1-800-…) is a business line. Gretel labels some of them as a
  person's phone (val 15, holdout 14), after cues such as "contact us at", "department at", "hotline", "emergency
  phone"; the check removes 21 false alarms on Nemotron val.

False alarms against 0.9.11: Gretel val 999 → 799, dev 2890 → 2259, holdout 915 → 735; Nemotron dev 526 → 496,
val 193 → 172. Values found whole: Mendeley val +529, dev +1589; Gretel val +154. `release-gate.md` in this folder is
the gate's report.
