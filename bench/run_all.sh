#!/usr/bin/env bash
# Run Benchmark V1 for every scanner on every source it can take, and write the report (docs/BENCHMARK-V1.md).
#
#   bench/run_all.sh OUT_DIR [MAISECRETS_CHECKOUT]
#
# Needs: BENCH_DETECT_SECRETS_PYTHON, BENCH_SECRET_SCAN_PYTHON, BENCH_PII_ANON_PYTHON, BENCH_PRESERVE_PYTHON (a scanner
# whose variable is empty is left out); BENCH_PYTHON (a Python 3.11+ with PyYAML for the catalog source, default
# python3); BENCH_CATALOGS (the six catalog clones, else the catalog source is left out; BENCH_EVERY_CATALOGS, default
# 1, samples them); the PII datasets in
# ~/.cache/maisecrets-datasets (scripts/measure_datasets.py fetch). BENCH_EVERY (default 50) is the fixed sample of the
# datasets for the comparison (a scanner at 280 ms per document needs 8 hours for Nemotron in full); maisecrets also
# runs each dataset in full. The holdout is not run here.
set -eu
out=$1
ms=${2:-.}
py=${BENCH_PYTHON:-python3}
every=${BENCH_EVERY:-50}
every_catalogs=${BENCH_EVERY_CATALOGS:-1}
mkdir -p "$out"
run() { "$py" bench/run.py --maisecrets "$ms" "$@"; }

scanners="maisecrets"
if [ -n "${BENCH_DETECT_SECRETS_PYTHON:-}" ]; then scanners="$scanners detect_secrets"; fi
if [ -n "${BENCH_SECRET_SCAN_PYTHON:-}" ]; then scanners="$scanners secret_scan"; fi
if [ -n "${BENCH_PII_ANON_PYTHON:-}" ]; then scanners="$scanners pii_anon"; fi
if [ -n "${BENCH_PRESERVE_PYTHON:-}" ]; then scanners="$scanners preserve"; fi
if [ -n "${BENCH_PRESIDIO_PYTHON:-}" ]; then scanners="$scanners presidio"; fi

for s in $scanners; do
  for split in dev val; do
    run --scanner "$s" --source bank --split "$split" --out "$out/bank-$split-$s.json"
  done
  # every scanner on every dataset: its scope decides what counts (Gretel and Nemotron also label passwords and keys)
  for d in nemotron gretel mendeley piilo privy; do
    run --scanner "$s" --source "$d" --split all --every "$every" --out "$out/$d-all-every$every-$s.json"
    if [ "$s" = maisecrets ]; then run --scanner "$s" --source "$d" --split all --out "$out/$d-all-$s.json"; fi
  done
  if [ -n "${BENCH_CATALOGS:-}" ]; then
    run --scanner "$s" --source catalogs --catalogs "$BENCH_CATALOGS" --split all --every "$every_catalogs" \
      --out "$out/catalogs-all-every$every_catalogs-$s.json"
  fi
done
"$py" bench/manifest.py "$out" "$ms"
"$py" bench/report.py --csv "$out/report.csv" $(ls "$out"/*.json | grep -v '/environment.json$') > "$out/report.md"
echo "report: $out/report.md"
