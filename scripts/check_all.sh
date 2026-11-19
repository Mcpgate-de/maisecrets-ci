#!/bin/bash
# Everything the GitLab merge request pipeline checks, run locally: lint, the repository scan, the plugin
# lint, the derived counts, the unit tests on this Python and on /usr/bin/python3 (3.9, the oldest
# supported), the belief replay and the hook harness (needs a logged-in `claude`).
# MAISECRETS_SKIP_HARNESS=1 leaves out the harness.
set -u
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 1
fail() { echo "check_all: $1"; exit 1; }
if command -v ruff >/dev/null 2>&1; then
  ruff check --select E,F,W --line-length 120 maisecrets hooks harness tests scripts skills || fail "lint"
fi
python3 scripts/scan_tree.py >/dev/null || { python3 scripts/scan_tree.py | tail -5; fail "repository scan"; }
python3 scripts/lint_plugin.py >/dev/null || fail "plugin lint"
python3 scripts/derived_counts.py >/dev/null || { python3 scripts/derived_counts.py | grep BAD; fail "derived counts"; }
python3 -m unittest discover -s tests -q || fail "unit tests"
if [ -x /usr/bin/python3 ]; then /usr/bin/python3 -m unittest discover -s tests -q || fail "unit tests on /usr/bin/python3"; fi
python3 scripts/replay_can_fail.py || fail "belief replay"
python3 scripts/replay_can_fail.py --mod || fail "belief replay of the mod"
if [ "${MAISECRETS_SKIP_HARNESS:-0}" != "1" ] && command -v claude >/dev/null 2>&1; then
  python3 harness/run.py || fail "harness"
fi
echo "check_all: all green"
