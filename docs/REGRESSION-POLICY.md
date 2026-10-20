# Regression policy for detection changes: a draft

Status: **draft** (2026-10-20). Nothing here blocks a merge yet. `scripts/compare_bench.py` lists what a reviewer must
explain; the thresholds below are proposals from the changes measured on 2026-10-19 and 2026-10-20, to be tried on the
next rule rounds before any of them becomes a gate.

## What can be checked by a machine

Run the same sources and splits for the merge base and the change (`bench/run.py`, Benchmark V2), the false-alarm
bank for both (`scripts/measure_fp_bank.py measure --json`), then:

```bash
python3 scripts/compare_bench.py RESULTS_OF_THE_BASE RESULTS_OF_THE_CHANGE      # --strict exits 1 on a finding
```

| Signal | Finding when | Why this line |
|---|---|---|
| False-alarm bank | any rule acts on more files than before | the bank holds public trees with no real secrets: a new hit is a false alarm or a test value, and each one needs a reason (the card fix of 2026-10-19 added 2, test cards of a card scanner's tests) |
| Whole spans on `val` | a class loses more than 5 spans or more than 0.5 % of its spans | the us-bank label window lost 6 accounts, 18 names, 7 ids and 3 phone numbers on Gretel; each such loss was real, and small ones are where a reason is still cheap |
| Partial spans | any class has more spans found in part | a partial hit leaves part of a value in the clear: the worst outcome for this tool (2,197 accounts and 896 names were found in part before their fixes) |
| False positives per source and split | more than 1 % more | the phone experiment raised Gretel's by 5 % (118) and was not merged |
| Time per case | never judged from two single runs | see below |

The counts are deterministic: the same code on the same cases gives the same numbers, so every difference is real and
none is noise. A finding is not a veto; it asks for a sentence in the merge request that explains it.

## Time

The median time per case of the same detection code moved between 26 % and 233 % across the runs of 2026-10-20
(other measurements and test suites ran on the machine at the same time). So a single pair of runs says nothing. A
performance claim needs alternating runs of both commits on an idle machine, three each at least, as the user name
change of 2026-10-19 was measured (`docs/BENCHMARKS.md`).

## Not machine-checkable

- Whether a lost span is a loss or a label error of the dataset (the phone review found real numbers counted as false
  positives in Gretel).
- Whether a rule changes a decision of the design (the phone experiment masked business numbers that a test keeps as
  text).
- Anything on the independent data (Privy, Holdout V2): only totals are read, and no rule follows from them.
