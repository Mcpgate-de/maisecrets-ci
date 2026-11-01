#!/usr/bin/env bash
# Run the prompt NER bench only on a quiet host, and say afterwards whether it stayed quiet.
# Quiet: no CI build container and a 1-minute load average below 0.5, three checks 20 s apart.
# During the run a monitor writes the load and the count of build containers every 10 s.
# Usage: quiet_bench.sh OUTDIR SOURCE DATA CUT [SOURCE DATA CUT ...]
# Run it from the repository root, with the service on 127.0.0.1:8766 (README of the results). The client runs on
# cores 4-7 and keeps 4 requests open; a CI build is a container whose name starts with runner-.
set -u
OUT=$1; shift
mkdir -p "$OUT"
builds() { docker ps --format '{{.Names}}' | grep -c '^runner-' ; }
load1() { cut -d' ' -f1 /proc/loadavg; }
quiet() { [ "$(builds)" = 0 ] && awk -v l="$(load1)" 'BEGIN{exit !(l < 0.5)}'; }
echo "waiting for a quiet host: $(date -u +%FT%TZ)"
ok=0
while [ $ok -lt 3 ]; do
  if quiet; then ok=$((ok + 1)); else ok=0; fi
  sleep 20
done
echo "quiet: $(date -u +%FT%TZ) load $(load1)"
( while :; do echo "$(date -u +%T) $(load1) $(builds)"; sleep 10; done ) > "$OUT/monitor.log" &
MON=$!
curl -s http://127.0.0.1:8766/info > "$OUT/service-info.json"
while [ $# -ge 3 ]; do
  src=$1 data=$2 cut=$3; shift 3
  taskset -c 4-7 python3 bench/ner/prompt_names.py "$src" "$data" "$cut" "$OUT/$src-dev-cut$cut.json" --url=http://127.0.0.1:8766/ --parallel 4
done
kill $MON
echo "done: $(date -u +%FT%TZ)"
awk '{ if ($2 > m) m = $2; if ($3 > b) b = $3 } END { print "max load " m+0 ", max build containers " b+0 ", samples " NR }' "$OUT/monitor.log"
