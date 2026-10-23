#!/usr/bin/env bash
# Run Benchmark V3 (docs/BENCHMARK-V3.md) for every scanner that has its environment, and write the V3 report.
#
#   bench/run_all_v3.sh OUT_DIR MAISECRETS_CHECKOUT
#
# The environments as for bench/run_all.sh (BENCH_*_PYTHON; a scanner whose variable is empty is left out), plus the
# gateway as a consumer: BENCH_GATEWAY_PYTHON and BENCH_GATEWAY_REPO (a clean ai-gateway checkout). BENCH_CATALOGS as
# for V1. What V3 runs, and why:
# - maisecrets on each development dataset in full, one file per split (dev was read to write rules, val decided,
#   holdout is reported apart), and on Privy in full;
# - every scanner on the same salted sample (--sample-salt v3/), 1 in 25 of val and of holdout per dataset and 1 in 10
#   of Privy: V1 and V2 compared on samples that were dev alone;
# - every scanner on the bank (dev, val) and the catalogs, as in V1.
# The holdout of the project (bench/holdout_v2.py) is not run here: it runs once per release candidate.
set -eu
out=$1
ms=$2
py=${BENCH_PYTHON:-python3}
salt=v3/
mkdir -p "$out"
run() { "$py" bench/run.py --maisecrets "$ms" "$@"; }

scanners="maisecrets"
for pair in detect_secrets:BENCH_DETECT_SECRETS_PYTHON secret_scan:BENCH_SECRET_SCAN_PYTHON \
            pii_anon:BENCH_PII_ANON_PYTHON preserve:BENCH_PRESERVE_PYTHON presidio:BENCH_PRESIDIO_PYTHON \
            ai_gateway:BENCH_GATEWAY_PYTHON; do
  var=${pair#*:}
  if [ -n "${!var:-}" ]; then scanners="$scanners ${pair%%:*}"; fi
done
echo "scanners: $scanners"

for s in $scanners; do
  for split in dev val; do
    [ -s "$out/bank-$split-$s.json" ] || run --scanner "$s" --source bank --split "$split" --out "$out/bank-$split-$s.json"
  done
  for d in nemotron gretel mendeley piilo; do
    for split in val holdout; do
      f="$out/$d-$split-every25-$s.json"
      [ -s "$f" ] || run --scanner "$s" --source "$d" --split "$split" --every 25 --sample-salt "$salt" --out "$f"
    done
  done
  f="$out/privy-all-every10-$s.json"
  [ -s "$f" ] || run --scanner "$s" --source privy --split all --every 10 --sample-salt "$salt" --out "$f"
  if [ -n "${BENCH_CATALOGS:-}" ]; then
    f="$out/catalogs-all-every1-$s.json"
    [ -s "$f" ] || run --scanner "$s" --source catalogs --catalogs "$BENCH_CATALOGS" --split all --out "$f"
  fi
done
for d in nemotron gretel mendeley piilo aparte llmredactor credsweeper; do
  for split in dev val holdout; do
    f="$out/$d-$split-maisecrets-full.json"
    [ -s "$f" ] || run --scanner maisecrets --source "$d" --split "$split" --out "$f"
  done
done
[ -s "$out/privy-all-maisecrets-full.json" ] || run --scanner maisecrets --source privy --split all \
  --out "$out/privy-all-maisecrets-full.json"
"$py" bench/manifest.py "$out" "$ms"
"$py" bench/report_v3.py "$out" > "$out/report-v3.md"
echo "report: $out/report-v3.md"
