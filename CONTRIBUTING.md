# Contributing

The quickest useful contribution is a token prefix that went through
undetected. Add one line to `maisecrets/detection/rules/prefixes.txt`:

```
<service>-<token-kind>    <prefix>[A-Za-z0-9_-]{<minimum length>,}
```

and one line to `tests/test_core.py` next to the existing prefix test, with a
synthetic value of the right shape. Never a real value, not even a revoked
one: the pre-commit hook scans the diff and refuses it.

For a larger change, open an issue first. A branch for it may exist already
(epic #19 has four), and a short exchange can save you a fork.

## What every change needs

- A commit subject `type(scope): text`. The subject is the changelog line;
  `feat`, `fix` and `perf` release a new version on merge.
- A test that fails without the change.
- No value anywhere in the tree. Write test values that name themselves
  (`my-test-token`, `testpass`, addresses at `example.com`).
- For a rule that should hold for good: a file in `beliefs/` that names the
  test and the mutation that must turn it red.
  `python3 scripts/replay_can_fail.py` checks every belief.

Run `scripts/install-hooks.sh` once, so the pre-commit hook scans your diff
and checks your commit subject. `python3 -m unittest discover -s tests` runs
the tests; `/usr/bin/python3` (3.9) is the oldest Python we support.

## A detection rule

A new or changed detection rule needs numbers, not only tests:

- **CredData.** Measure precision and recall before and after with
  `scripts/measure_creddata.py`. `docs/BENCHMARKS.md` has the steps and the
  current numbers. Put both lines in the merge request.
- **No new false hits.** The test suite holds ordinary text that must stay
  text (`tests/fp_corpus.py`). A rule that adds a hit there does not ship.
- **The channel.** `detect.scan(text, channel=...)` has two channels. A typed
  prompt (`prompt`) is blocked on a hit, so its rules stay strict. A tool
  result or a file (`tool`) is masked, so a looser rule can run there. Say
  which channel your rule belongs to.
- **The region.** A rule for a national number (a tax id, an id card) belongs
  to its country in the `regions` setting.

## Rules from other projects

Rules from MIT or Apache-2.0 sources are welcome. Name the source in the
commit body; `maisecrets/detection/rules/` keeps the licence of each vendored set. From
an AGPL source (for example trufflehog) take the token format as a fact, but
never its code or its regex text.

## Reports and pull requests

Wrong detections and feature requests: `/maisecrets:report` in Claude Code
prepares the issue, or open one on the repository's issues page.

The GitHub repository is a read-only mirror of the primary repository. Open
a pull request there; a maintainer applies it upstream, and the mirror brings
it back with your authorship.

`docs/REPO-STANDARDS.md` has the details of the repository's rules;
`docs/THREAT-MODEL.md` says what the plugin defends and where it stops.
