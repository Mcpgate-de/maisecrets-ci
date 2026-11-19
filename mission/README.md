# Missions

One file per product promise (`M*.toml`). Each file says the promise in plain words, the actors of
`docs/THREAT-MODEL.md` it protects against, the controls (C*) and invariants (I*) that serve it, where the
promise ends, and its parts: one sentence each, with the beliefs (`beliefs/*.toml`, ids or globs) that prove
that sentence. A part that only a test without a belief covers names that test in `tests` and still counts as
a gap: no mutation proves that the test can fail.

`claims.toml` maps the promises that `README.md` and `PRIVACY.md` make to users onto the missions: a promise
to the mission that keeps it, a limit ("What it does not protect") to the mission whose `ends` names it, a
function to none. Every bullet of the gated README sections must start with the quote of a claim, so a new
or reworded promise turns the check red until it is mapped.

Each mission names its measured number in `[measure]` (a source file, the row and column that hold it, and the
gate that keeps its bound), or says in `none` why it has none: most promises are kept or broken, not a rate.

M1 to M5 are derived from the controls (bottom-up); M6 comes from README.md and PRIVACY.md (top-down) and
brought control C33 into the threat model.

    python3 scripts/mission_coverage.py            # report
    python3 scripts/mission_coverage.py --strict   # exit 1 on a gap, an orphan, an unknown name or a claim

The beliefs prove that each test can fail; this layer shows which promise each belief serves. It is not a CI
gate yet.
