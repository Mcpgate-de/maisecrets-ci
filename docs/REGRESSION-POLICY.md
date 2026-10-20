# Regression policy for detection changes

Status: **lines set from the release history** (2026-10-20). `scripts/compare_bench.py` lists what a reviewer must
explain. The lines below come from measuring the releases 0.6.41, 0.6.42, 0.6.43, 0.6.44 and 0.7.0 once each with the
same benchmark code and comparing the neighbours (see "The history behind the lines"). Nothing blocks a merge by
itself yet: a finding asks for a sentence in the merge request.

## What can be checked by a machine

Run the same sources and splits for the merge base and the change (`bench/run.py`, Benchmark V2), the false-alarm
bank for both (`scripts/measure_fp_bank.py measure --json`), then:

```bash
python3 scripts/compare_bench.py RESULTS_OF_THE_BASE RESULTS_OF_THE_CHANGE      # --strict exits 1 on a finding
```

| Signal | Finding when | Why this line |
|---|---|---|
| False-alarm bank | any rule acts on more files than before | the bank holds public trees with no real secrets: a new hit is a false alarm or a test value, and each one needs a reason (the card fix of 2026-10-19 added 2, test cards of a card scanner's tests) |
| Spans that got worse | any span whose outcome fell, case by case: whole to partial or missed, partial to missed | the counts per class hid it: 0.6.42 and 0.6.43 made 85 Gretel `dev` spans worse while many more got better, so their totals rose. A span that falls is a value that was masked and is now (partly) in the clear |
| Whole spans on `val` | a class loses any whole span | no release from 0.6.41 to 0.7.0 lost one |
| Partial spans | more spans in part, **only when the runs hold no outcomes per case** | with the outcomes, a rise of partial spans from missed to partial is a gain, not a loss (0.7.0: 25 such spans) |
| False positives per source and split | more than 1 % more | the phone experiment raised Gretel's by 5 % (118) and was not merged |
| Same cases | the two runs of a file scored different cases (`cases_sha256`) | the file is not compared and the finding says so: another generator, dataset revision or sample would read as a change of the rules |
| Time per case | never judged from two single runs | see below |

The counts are deterministic: the same code on the same cases gives the same numbers, so every difference is real and
none is noise. A finding is not a veto; it asks for a sentence in the merge request that explains it.

## The history behind the lines

Each release measured once on the `dev` and `val` splits of Nemotron, Gretel, Mendeley, PIILO, the bank and the traces,
and the false-alarm bank, with the benchmark code of 2026-10-20 (`scripts/release_compare.py`):

| Releases | Spans that got worse (Gretel dev / val) | Largest false-positive rise | Whole spans lost on `val` |
|---|---|---|---|
| 0.6.41 → 0.6.42 | 26 / 3 | +0.6 % (Nemotron dev, 498 → 501) | 0 |
| 0.6.42 → 0.6.43 | 59 / 16 | 0 | 0 |
| 0.6.43 → 0.6.44 | 0 / 0 | 0 | 0 |
| 0.6.44 → 0.7.0 | 0 / 0 | +5.2 % (Gretel dev) and +8.1 % (Gretel val), read: values of persons without a label | 0 |

**What the new line found at once:** the spans that 0.6.42 and 0.6.43 made worse were real losses. 0.6.42 took the
second part of a double name into the value; when that part ends like a noun (`-ing`, `-ers`), the whole name read as
words and was dropped, where 0.6.41 had masked it up to the hyphen (25 names). 0.6.43 let an address run on after
`Apt.` and its number; when a template followed (`, [City], [State]`), the bracket filter dropped the whole value,
where 0.6.42 had masked the street (59 addresses). Both are fixed by the change that follows this policy.

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
