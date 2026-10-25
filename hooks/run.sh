#!/usr/bin/env bash
# Hook launcher: picks the Python interpreter this machine has.
#   macOS / Linux: python3 (a stock Mac ships 3.9 in /usr/bin; Homebrew and python.org put
#                  a newer one in /opt/homebrew/bin, /usr/local/bin or /Library/Frameworks)
#   Windows: Claude Code requires Git Bash, so this script runs there too; Python
#            installs as python.exe or the py launcher (winget install Python.Python.3.12)
# Usage: run.sh <user-prompt|pre-tool|post-tool|post-tool-failure|session-start> | run.sh <cli command…>
set -u
# the payload is UTF-8 JSON; on Windows python.exe would otherwise decode a pipe with the
# console code page and a prompt with umlauts fails the hook (fail closed, but for no reason)
export PYTHONUTF8=1
HERE="$(cd "$(dirname "$0")" && pwd)"
FOUND=""
# One probe per candidate. It answers by its exit code only: 0 for 3.9 or newer, 60 + minor for an older 3, 50 + minor
# for a 2 (codes clear of 126 and 127 of the shell, 128 + n of a signal, and 9009 % 256 of a Windows store alias). A probe gets none of the hook's stdin, stdout and stderr: all three are /dev/null, so a wrapper (a shim, a
# script that starts a job in the background) cannot eat the payload or hold the pipe that the client reads. Codex
# reads a hook until its stdout closes, and both clients let the call through when a hook runs past their timeout
# (measured on Claude Code 2.1.302 and codex-cli 0.162.0, docs/THREAT-MODEL.md, C13).
PROBE='import sys; v = sys.version_info; sys.exit(0 if v >= (3, 9) else 60 + v[1] if v[0] == 3 else 50 + v[1] if v[0] == 2 else 1)'
# All probes together get BUDGET seconds. Then a timer stops the probe that runs, and the launcher refuses: the hook's
# own watchdog (7 s) must still answer before the client's shortest timeout (10 s). A normal probe takes 0.05 s.
BUDGET=2
PROBE_PID=""
EXPIRED=""
# the timer's signal: the first of USR1, USR2 and ALRM that this shell can trap. A signal that was ignored when the
# shell started cannot be trapped, and the timer would send it in vain (codex review, 2026-10-17). The shell sends
# each one to itself and keeps the first whose trap ran. With none, the probes have no bound
SIG=""
for S in USR1 USR2 ALRM; do
  T=""
  trap 'T=1' "$S"
  kill -"$S" $$
  if [ -n "$T" ]; then SIG="$S"; break; fi
done
[ -n "$SIG" ] && trap 'EXPIRED=1; [ -n "$PROBE_PID" ] && kill -9 "$PROBE_PID"' "$SIG"
find_python() {
  # the timer sends SIG to this shell after a sleep that ran to its end; on TERM it stops the sleep, so it leaves no
  # process behind. The fixed paths come first, so a sleep that the PATH puts before them cannot take the bound
  # (codex review, 2026-10-17); a PATH sleep only where neither exists, and without any the timer does nothing
  # (no bound) instead of refusing every call
  (
    trap 'kill "$s"; exit 0' TERM
    for z in /bin/sleep /usr/bin/sleep sleep ""; do command -v "$z" >/dev/null && break; done
    [ -n "$z" ] && [ -n "$SIG" ] || exit 0
    "$z" "$BUDGET" & s=$!
    wait "$s" && kill -"$SIG" $$
  ) </dev/null >/dev/null 2>&1 &
  TIMER=$!
  for PY in python3 python "py -3" python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 \
            /opt/homebrew/bin/python3 /usr/local/bin/python3 \
            /Library/Frameworks/Python.framework/Versions/Current/bin/python3; do
    $PY -c "$PROBE" </dev/null >/dev/null 2>&1 &
    PROBE_PID=$!
    wait "$PROBE_PID"
    RC=$?
    # the signal ends the wait early; the probe that the timer stopped is reaped here, so its end is not reported later
    [ -n "$EXPIRED" ] && wait "$PROBE_PID"
    PROBE_PID=""
    if [ "$RC" -eq 0 ]; then
      OK="$PY"
      break
    fi
    if [ -n "$EXPIRED" ]; then
      FOUND="${FOUND:+$FOUND, }$PY gave no answer in $BUDGET s"
      break
    fi
    if [ "$RC" -ge 60 ] && [ "$RC" -le 68 ]; then
      FOUND="${FOUND:+$FOUND, }$PY is 3.$((RC - 60))"
    elif [ "$RC" -ge 50 ] && [ "$RC" -le 59 ]; then
      FOUND="${FOUND:+$FOUND, }$PY is 2.$((RC - 50))"
    fi
  done
  # no signal of the timer can arrive after this wait: the exec below must not get one, its default action ends the process
  kill "$TIMER"
  wait "$TIMER"
}
OK=""
# 2>/dev/null: the shell reports a probe that the timer stopped ("Killed: 9") on its stderr
find_python 2>/dev/null
[ -n "$SIG" ] && trap - "$SIG"
if [ -n "$OK" ]; then
  exec $OK "$HERE/dispatch.py" "$@"
fi
# an incident marker for /maisecrets:report incident (docs/DIAGNOSTICS.md, section 3): after the answer, one mkdir
# in a home that exists and is no link; it never fails the launcher
mark() {
  H="${MAISECRETS_HOME:-${HOME:-}/.maisecrets}"
  # in the background with no output of its own: a stalled home cannot hold the launcher past the client's timeout
  if [ -d "$H" ] && [ ! -L "$H" ]; then
    (umask 077; mkdir "$H/incident-marker.launcher.no-python") </dev/null >/dev/null 2>&1 &
  fi
  return 0
}
MSG="maisecrets needs Python 3.9 or newer on the PATH of the client (found: ${FOUND:-none}). Install it: macOS 'brew install python' or python.org, Windows, as an administrator, 'winget install --id Python.Python.3.12 --exact --scope machine', Linux your package manager; then restart the client."
case "${1:-}" in
  post-tool-failure)
    # the client shows a failed output as it is: there is nothing to withhold, only the reason to name
    printf '{"systemMessage":"%s Until then every prompt and every tool call is blocked."}' "$MSG"
    mark
    exit 0 ;;
  post-tool)
    # Claude Code ignores exit 2 here and would show the raw output to the model: answer
    # fail-closed with the JSON the hook itself would give (review, 2026-09-26). One shape per
    # client: Codex's strict schema dropped an answer that carried Claude's updatedToolOutput
    # (Codex review, 2026-09-28); Codex sends turn_id in its payload.
    P="$(cat)"
    case "$P" in
      *'"turn_id"'*)
        printf '{"decision":"block","reason":"[%s Tool output withheld; the tool ran and finished, do not run it again.]"}' "$MSG" ;;
      *)
        printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"[%s Tool output withheld; the tool ran and finished, do not run it again.]"}}' "$MSG" ;;
    esac
    mark
    exit 0 ;;
  session-start)
    printf '{"systemMessage":"%s Until then every prompt and every tool call is blocked."}' "$MSG"
    mark
    exit 0 ;;
esac
# JSON, not exit 2: Codex runs the tool when a hook exits 2 (harness/codex.py); both clients read this
case "${1:-}" in
  pre-tool)
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s Until then every prompt and every tool call is blocked."}}' "$MSG"
    mark
    exit 0 ;;
  user-prompt)
    printf '{"decision":"block","reason":"%s Until then every prompt and every tool call is blocked."}' "$MSG"
    mark
    exit 0 ;;
esac
echo "$MSG Until then every prompt and every tool call is blocked." >&2
exit 2   # any other use of the launcher (a CLI command): fail closed
