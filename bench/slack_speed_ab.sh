#!/usr/bin/env bash
# CPU time of findings_by_leaf on two generated Slack responses, two checkouts in turns on one core of a quiet host
# (no CI build, load below 1.0 three times): one line per round and checkout, microseconds per character.
#   bash bench/slack_speed_ab.sh BASE_CHECKOUT FIX_CHECKOUT ROUNDS > ab.log
here=$(cd "$(dirname "$0")" && pwd)
quiet() { [ "$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c '^runner-')" = 0 ] \
  && awk -v l="$(cut -d' ' -f1 /proc/loadavg)" 'BEGIN{exit !(l < 1.0)}'; }
ok=0; while [ $ok -lt 3 ]; do if quiet; then ok=$((ok+1)); else ok=0; fi; sleep 20; done
echo "ab start $(date -u +%FT%TZ) load $(cut -d' ' -f1 /proc/loadavg) base $(git -C "$1" rev-parse --short=8 HEAD) fix $(git -C "$2" rev-parse --short=8 HEAD)"
for r in $(seq 1 "${3:-15}"); do for n in base fix; do
  w=$1; [ $n = fix ] && w=$2
  echo "slack $r $n $(cd /tmp && taskset -c 4 python3 "$here/slack_speed.py" "$w" 2>/dev/null | tail -1)"
done; done
echo "ab exit end $(date -u +%FT%TZ) builds $(docker ps --format '{{.Names}}' 2>/dev/null | grep -c '^runner-')"
