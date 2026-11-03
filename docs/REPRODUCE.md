# Reproduce a release benchmark in about 10 minutes

Each release of maisecrets publishes its benchmark results in `bench/results/`. This page shows how you measure a
release yourself and check that you get the same numbers. You need no account and no key, and nothing leaves your
computer except the download of the public datasets.

We tested these steps on 2026-11-02 with v0.8.12. A fresh clone on a laptop (Apple M5, macOS) gave the same counts as
the published run on our reference server (Linux, AMD EPYC), for every case of both datasets.

## What you need

- git and Python 3.9 or newer (Linux or macOS).
- `pyarrow` for the download step only (`pip install pyarrow`). The measurement itself uses the standard library.
- About 300 MB of disk for the two datasets, and about 3 minutes of CPU time.

## Steps

```bash
git clone https://github.com/Mcpgate-de/maisecrets.git
cd maisecrets
git worktree add ../maisecrets-0.8.12 v0.8.12        # the release to measure
cd ../maisecrets-0.8.12

# the datasets at their pinned version; each file is checked against its sha256
python3 scripts/measure_datasets.py fetch --data ../datasets --only nemotron,gretel

# the validation split of each dataset, as the release gate measured it
for d in nemotron gretel; do
  python3 bench/run.py --scanner maisecrets --maisecrets . --source $d --split val \
      --data ../datasets --out ../mine/$d-val.json
done

# compare with the published results of the release
cd ../maisecrets
for d in nemotron gretel; do
  python3 bench/verify_result.py ../mine/$d-val.json \
      ../maisecrets-0.8.12/bench/results/2026-11-02-v3-0.8.12/$d-val-maisecrets-full.json.gz
done
```

## What you get

`bench/run.py` prints one line per dataset. For v0.8.12:

```text
maisecrets 0.8.12 on nemotron/val: 19806 cases, spans 68637, full 43108, partial 94, missed 25435, FP 193, recall 0.6281, precision 0.9953, F1 0.7702, too wide 6
maisecrets 0.8.12 on gretel/val: 8359 cases, spans 26163, full 8011, partial 172, missed 17980, FP 972, recall 0.3062, precision 0.8932, F1 0.4561, too wide 68
```

`bench/verify_result.py` then prints, for each dataset:

```text
nemotron/val: 19806 cases; the same cases and the same counts
gretel/val: 8359 cases; the same cases and the same counts
```

It compares the hash of the cases, all metrics, the Benchmark V3 block and the outcome of every case. It ignores the
date, the times and the paths. It prints no value and no text of the data. If a part differs, it names the part and
exits with 1. Please tell us then (an issue on GitHub): a difference is a defect, in the benchmark or in our result.

## Notes

- The published files name the commit that the release gate measured, the release candidate `ee548252`. The tag
  `v0.8.12` adds only the version numbers, the changelog and the results. `git diff --stat ee548252 v0.8.12 --
  maisecrets hooks` prints nothing: the measured code is the same.
- The timing in your result file depends on your computer and is not compared.
- What this does not cover: the private holdout (it gives totals only, `bench/HOLDOUT-LOG.md`), the other scanners in
  `report-v3.md` (each needs its own environment, `docs/BENCHMARK-V3.md`, "Repeat"), and the optional name service
  (`bench/results/2026-11-01-v3-0.8.7-prompt-ner/README.md` has its own recipe; it needs Docker).
- Another release: use its tag and the folder of its results in `bench/results/`.

If you reproduced a result, we are glad to hear it, with your platform and the output of `bench/verify_result.py`.
