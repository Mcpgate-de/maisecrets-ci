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
| 2026-10-22 | maisecrets 0.7.6 bef132cf917b93069175ee8474e54cfcffe64e89 | holdout-v2 | 872 | 0.6256 | 0.9955 | 3 |
| 2026-10-22 | maisecrets 0.7.7 8888a849a2764d18f6ff5c444fb7bc357034d04f | holdout-v2 | 872 | 0.6256 | 0.9955 | 3 |
| 2026-10-22 | maisecrets 0.7.8 b4693b7fd2f4e164f70e80762a3a47e2a765a728 | holdout-v2 | 872 | 0.6256 | 0.9955 | 3 |
| 2026-10-22 | maisecrets 0.7.9 5c2ba8af1b3b65d6d8c74ccf33dbb8f0ce5bf6c9 | holdout-v2 | 872 | 0.6256 | 0.9955 | 3 |
| 2026-10-23 | maisecrets 0.7.10 d09a84fb1583b9ebd0a861971bf55185d3ec313a | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-23 | maisecrets 0.7.11 cd2ed400baa3e1500ae69a849f4253e88dfc8080 | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-23 | maisecrets 0.7.12 fca8f5f2b1961eb0c9843f86dc88a80cf0f89c09 | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-23 | maisecrets 0.7.13 49d1dde63f085e7e2a3ce0d1db09d0a6e342e0a3 | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-23 | maisecrets 0.7.14 b71d43df355d97488ae19f9eea61c1eba1512c28 | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-23 | maisecrets 0.7.16 61caedd9ddf8b25637ef0431cf2a0df8d2389b9c | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-23 | maisecrets 0.7.17 8592ed0eacac46491570164c80bd66bf59839cd1 | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-23 | maisecrets 0.7.18 8c134595d7cc6029d6b38178da83bde2fe1f3eae | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-23 | maisecrets 0.7.19 2912042e78f9eb9c7c31e27b9c8a3b79f3d08faf | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-24 | maisecrets 0.7.20 ddc430568dfb332cce7bde02f99a9319656f8cc1 | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
