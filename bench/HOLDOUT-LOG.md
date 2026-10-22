# Holdout log

Each run on the private frozen holdout adds one row here (`bench/run.py --source holdout`). The holdout is not used to
write rules (docs/BENCHMARK-V1.md, "Splits"). A row names the scanner, its version and commit, and the totals; it
holds no case and no value. Many rows between two releases are a warning sign: each run tells a little about the
holdout.

On 2026-10-19 the generator of German tax ids was fixed (its values failed the IdNr rules): the four tax ids of the
holdout changed, and so did `bench/holdout.manifest`. Rows from before that commit measured the old values.

From now on the holdout runs only on a release candidate (docs/BENCHMARK-V1.md, "Splits"); the rows below were taken
while V1 was set up. A holdout V2 will be written and sealed after the current round of rule changes.

| Date | Scanner | Source | Cases | Recall, strict | Precision | FP |
|---|---|---|---|---|---|---|
| 2026-10-19 | maisecrets 0.6.39 a6846dc35417147451e75bb8920ba3b2d9927b48 | holdout | 80 | 0.8333 | 1.0 | 0 |
| 2026-10-19 | maisecrets 0.6.30 3b29d0593d69906a305d00d92dde50a81a9c2ceb | holdout | 80 | 0.8333 | 1.0 | 0 |
| 2026-10-19 | maisecrets 0.6.39 a6846dc35417147451e75bb8920ba3b2d9927b48 | holdout | 80 | 0.875 | 1.0 | 0 |
| 2026-10-19 | maisecrets 0.6.30 305a3747ae9a37d12d50fbce255132edbd8ff142 | holdout | 80 | 0.875 | 1.0 | 0 |
| 2026-10-19 | maisecrets 0.6.30 af36b94b6ec834c6f6e3bbefaabd5c4ff4f55765 | holdout | 80 | 0.875 | 1.0 | 0 |
| 2026-10-19 | maisecrets 0.6.30 69d99234af19ab7cbc458ddbf9fd4d721b15bdd9 | holdout | 80 | 0.875 | 1.0 | 0 |
| 2026-10-21 | maisecrets 0.7.4 4be44e6063cc2fc1174310473d849ce71d51105b | holdout-v2 | 872 | 0.6256 | 0.9955 | 3 |
