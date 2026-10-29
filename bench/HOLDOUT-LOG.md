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
| 2026-10-24 | maisecrets 0.8.0 73c695a04d25ac3acb22f350cc49de915a176d1e | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |
| 2026-10-25 | maisecrets 0.8.1 4f726f59fb85fb7916698e3ef30ed150500072e8 | holdout-v2 | 872 | 0.6329 | 0.9956 | 3 |

## GitHub-issues holdout (sealed 2026-10-25)

The holdout half of the GitHub-issues secret set ("Secret Leak Detection in Software Issue Reports using LLMs", MSR 2026, Zenodo records 17430335 and
19622962, CC BY 4.0, credited as listed in the record;
`bench/ghissues.py`). The data stays outside the repository; nobody reads a holdout case, and a run gives totals only.

- Source: `Secret-Leak-Detection-Issue-Report.zip`, sha256 `0512d4aebc0612c161e9036d26746573acc00fb8a29d7fe3d8156486de559cbf`
  (md5 `af40bd3329508fb47ed1b37143fd43df`, as Zenodo lists it), member `Data/main_data.csv`, 54,203 rows.
- Split rule: the issue id is `<owner>/<repo>#<number>` from the issue url, owner and repository in lower case. The
  issue is `holdout` when `int(HMAC-SHA256(key=SALT, msg=issue id).hexdigest()[:8], 16)` is odd, else `dev`.
  SALT = `maisecrets/ghissues/2026-10-25`. One issue never lies in both halves.
- Sealed on 2026-10-25, before any case was read (only the column inventory and counts of the whole file were taken):
  - `dev/cases.jsonl` sha256 `3af20af9a17e748d63a4c7899056c24652127ecd4117fb11e752711ac66ab02d`: 25,340 issues,
    27,080 rows, 2,961 true;
  - `holdout/cases.jsonl` sha256 `ff6689f2dd5fe5a6050e95f7bee090eadbef7c40ae0723ef47d9ad268fc28aed`: 25,340 issues,
    27,123 rows, 2,912 true.
- 24 of 5,815 distinct true values occur in both halves (the same secret in two issues).
- The core rule and the class map of the loader were fixed on aggregate counts of the dev half only.

Recall strict and precision of a run are counted as `bench/ghissues.py` counts them (snippet level: a finding
on a labelled candidate); FP = findings on a false candidate.

## nym and DialogPII holdouts (sealed 2026-10-25)

Two external PII sets for gap discovery (`bench/nym.py`, `bench/dialogpii.py`, `bench/sealed.py`). The data stays
outside the repository. Each set has three sealed splits: `dev` (read by aggregates and shapes), `val` (aggregate
counts only) and `holdout` (never read, totals only). Rule: the first 8 hex digits of HMAC-SHA256(key=SALT, msg=group)
modulo 10; 0-5 `dev`, 6-7 `val`, 8-9 `holdout`. Both were sealed before any example was read (only the file
inventory, the record keys and aggregate counts of the whole files were taken).

**nym** (`Wismut/nym-pii-multilingual-data`, revision `abe23bf08c305f5824b1643dc4f079f06ccb2ad1`, MIT): the files
`train.jsonl` `ca04c6c5…`, `validation.jsonl` `2970f8ea…`, `test.jsonl` `7b07818e…` (sha256 = the LFS ids), 805,000
rows. SALT = `maisecrets/nym/2026-10-25`. The group is the sequence of a row's labels in text order (5,444 sequences
for the card's 5,959 template shapes), so the fills of one template stay in one split; a row without a span is grouped
by its letters. A first seal with a finer key (143,535 groups) was discarded unread.

- `dev/cases.jsonl` sha256 `234eeac791def8fbc5b4980531d6e0bddbcc39617b9f99298f96f1e48b87d3cc`: 498,485 rows, 10,110 groups;
- `val/cases.jsonl` sha256 `84c5989f805bbba4b3b885e4403e6bcc6e97a4b8071501facd31d76aeb403ec9`: 150,883 rows, 3,427 groups;
- `holdout/cases.jsonl` sha256 `5d4a711b9d732a4111a808f8a03af42dc4120a1bcb0de091ea43d6e4d8ea0fee`: 155,632 rows, 3,469 groups.

**DialogPII** (Zenodo record 20863452, version 1.0, doi:10.5281/zenodo.20863452, CC BY 4.0): `DialogPII.zip` sha256
`70e7d3a419e40034352af550c4d5658fc5f8b663b6731fec689c28b236c9221c` (md5 `6b034ea96364a3f638133eefee3ee481`, as Zenodo
lists it), 3,234 dialogues (147 per language and form, 11 languages, the original and the transcript).
SALT = `maisecrets/dialogpii/2026-10-25`. The group is `<scenario>/<chat_number>`, so a dialogue lies in one split in
every language and in both forms.

- `dev/cases.jsonl` sha256 `f38e81019e73a68913668325deb10505e981d4cdbec37c49e1a8c3cb60b73447`: 1,980 dialogues, 90 groups;
- `val/cases.jsonl` sha256 `0521ea3f6b60a2cd96a0a5cdb81d8ed728590c2bfbb90d0c42283f6aca5b1605`: 616 dialogues, 28 groups;
- `holdout/cases.jsonl` sha256 `bb5ea2d32d6a838fb8de0e149f3ceb6f47c857a2873b744016196ab50f4a7421`: 638 dialogues, 29 groups.

The label maps of both loaders were fixed on aggregate counts of `dev` only. nym's holdout runs on the sample
`--every 5 --sample-salt v3/`, DialogPII's in full.

## Structured corpus, set B (sealed 2026-10-25)

The independent holdout of the structured corpus (docs/BENCHMARK-STRUCTURED.md, "The holdout SPEC"). A second author
wrote its templates, field-name vocabulary and value generators from the SPEC alone. The attestation in the private
directory says: role "independent set-B author agent" (no name), date 2026-10-25, `seen_set_a: false`,
`seen_miss_lists: false`. The templates, the generators and the cases stay private; nobody reads a case or a list of
its misses, and a run gives totals only (`bench/structured_b.py`, `bench/run.py --source structured-b`).

- `cases.jsonl` sha256 `bdcb963988f169d65089305783b1507d1b8e31c16e1ce055466f996de57c03b9`; `bench/structured_b.py` refuses any other file.
- Seed 20261025. The sha256 of the private build files: `build.py` `c9d7d84174a9f522…`,
  `templates.py` `2ba8153bcd708626…`, `vocab.py` `4ff7cf3ec18eb8a2…`,
  `values.py` `526d4246a71e1612…`, `sources.csv` `e143005086f0c041…`.
- 2000 cases: 1500 positive, 500 negative; channel prompt 378, tool 1622.
- Scored spans per class: pii.address 630, pii.bank_account 255, pii.birth_date 556, pii.card 505, pii.iban 550, pii.ip 505, pii.name 1166, pii.national_id 479, pii.phone 762, pii.tax_id 241, pii.username 490, secret.connection_string 528, secret.password 526, secret.private_key 324, secret.token 517. Neutral spans: pii.address 327, pii.email 366.
- Cases per format: code 133, csv 133, env 134, html 133, http 133, ini 134, json 134, log 133, markdown 133, query 133, sql 133, toml 134, tsv 133, xml 133, yaml 134.
- Cases per field-name language: de 223, en 223, es 222, fr 222, it 222, nl 222, pl 222, pt 222, sv 222.
- Spans per field-name style: abbrev 923, camel 739, dotted 918, doubled 934, human 811, kebab 783, pascal 910, prefixed 956, snake 716, upper 1037.
- Negative cases per kind: company_contact 59, config_default 60, enum_role 59, event_date 59, fixture 60, hash 59, masked 60, placeholder 60, private_ip 60, schema_doc 60, uuid 60, version_build 60.

## Runs on the sealed holdouts of the external and structured sets

Each run on one of the holdouts above adds one row here (`bench/run.py --split holdout` for ghissues, nym and
DialogPII; `--source structured-b` for set B). The rows of 2026-10-25 marked "not published" were taken while the
sets were built, on development commits; they are listed so that every look at a holdout is counted. Their totals
are not published: the numbers of record come from the release baseline (`scripts/extended_baseline.py`).

| Date | Scanner | Source | Cases | Recall, strict | Precision | FP |
|---|---|---|---|---|---|---|
| 2026-10-25 | maisecrets 0.7.2 4f726f59fb85fb7916698e3ef30ed150500072e8 | ghissues | 25401 | not published | not published | – |
| 2026-10-25 | detect-secrets 1.5.0 | ghissues | 25401 | not published | not published | – |
| 2026-10-25 | gitleaks 8.30.1 | ghissues | 25401 | not published | not published | – |
| 2026-10-25 | betterleaks 1.9.0 | ghissues | 25401 | not published | not published | – |
| 2026-10-25 | trufflehog 3.99.2 | ghissues | 25401 | not published | not published | – |
| 2026-10-25 | kingfisher 2.11.1 | ghissues | 25401 | not published | not published | – |
| 2026-10-25 | kingfisher 1.113.0 | ghissues | 25401 | not published | not published | – |
| 2026-10-25 | noseyparker 0.24.0 | ghissues | 25401 | not published | not published | – |
| 2026-10-25 | maisecrets 0.7.2 2da66c0c3886ba853b860c2f877501830c03eacc | dialogpii | 638 | not published | not published | – |
| 2026-10-25 | maisecrets 0.7.2 2da66c0c3886ba853b860c2f877501830c03eacc | nym | 31294 | not published | not published | – |
| 2026-10-25 | presidio 2.2.364  | nym | 6211 | 0.521 | 0.59 | 11649 |
| 2026-10-25 | pii-anon 1.7.0rc1 2171ace5847a0d2add555419c02b41c47155cabe | nym | 6211 | 0.4158 | 0.8569 | 1439 |
| 2026-10-25 | presidio 2.2.364  | dialogpii | 638 | 0.5995 | 0.1304 | 36994 |
| 2026-10-25 | pii-anon 1.7.0rc1 2171ace5847a0d2add555419c02b41c47155cabe | dialogpii | 638 | 0.4235 | 0.6466 | 2010 |
| 2026-10-25 | presidio 2.2.364  | structured-b | 2000 | 0.555 | 0.6991 | 2796 |
| 2026-10-25 | preserve 0.6.1 01dbd7710de79e21bef851aaa8b6cbfb4b1188ad | structured-b | 2000 | 0.5307 | 0.7414 | 1783 |
| 2026-10-25 | pii-anon 1.7.0rc1 2171ace5847a0d2add555419c02b41c47155cabe | structured-b | 2000 | 0.4787 | 0.5336 | 3003 |
| 2026-10-25 | detect-secrets 1.5.0  | ghissues | 25401 | 0.2943 | 0.4834 | 1528 |
| 2026-10-25 | gitleaks 8.30.1  | ghissues | 25401 | 0.5323 | 0.8895 | 245 |
| 2026-10-25 | betterleaks 1.9.0  | ghissues | 25401 | 0.5456 | 0.6321 | 1193 |
| 2026-10-25 | trufflehog 3.99.2  | ghissues | 25401 | 0.1231 | 0.66 | 239 |
| 2026-10-25 | kingfisher 2.11.1  | ghissues | 25401 | 0.2175 | 0.7891 | 212 |
| 2026-10-25 | kingfisher 1.113.0  | ghissues | 25401 | 0.2965 | 0.7833 | 359 |
| 2026-10-25 | noseyparker 0.24.0  | ghissues | 25401 | 0.3111 | 0.5905 | 867 |
| 2026-10-25 | preserve 0.6.1 01dbd7710de79e21bef851aaa8b6cbfb4b1188ad | nym | 1239 | 0.4615 | 0.4904 | 2329 |
| 2026-10-25 | preserve 0.6.1 01dbd7710de79e21bef851aaa8b6cbfb4b1188ad | dialogpii | 124 | 0.5658 | 0.1072 | 7759 |
| 2026-10-26 | maisecrets 0.8.2 a52ea5a814dcd140498d0e5c1cacda33d8615935 (gate stopped: CPU time, two spans worse) | holdout-v2 | 872 | 0.6473 | 0.9957 | 3 |
| 2026-10-26 | maisecrets 0.8.2 357bbe2429be50fefd8033b1dac4b9432527de40 (gate stopped: two spans worse) | holdout-v2 | 872 | 0.6473 | 0.9957 | 3 |
| 2026-10-26 | maisecrets 0.8.2 097e68dd8960b4ca37c3d3c605920dd691c51ed4 | holdout-v2 | 872 | 0.6473 | 0.9957 | 3 |
| 2026-10-26 | maisecrets 0.8.2 097e68dd8960b4ca37c3d3c605920dd691c51ed4 | nym | 31294 | 0.1863 | 0.9954 | 97 |
| 2026-10-26 | maisecrets 0.8.2 097e68dd8960b4ca37c3d3c605920dd691c51ed4 | nym | 6211 | 0.1859 | 0.996 | 17 |
| 2026-10-26 | maisecrets 0.8.2 097e68dd8960b4ca37c3d3c605920dd691c51ed4 | dialogpii | 638 | 0.04 | 1.0 | 0 |
| 2026-10-26 | maisecrets 0.8.2 097e68dd8960b4ca37c3d3c605920dd691c51ed4 | structured-b | 2000 | 0.5286 | 0.9797 | 92 |
| 2026-10-26 | maisecrets 0.8.2 097e68dd8960b4ca37c3d3c605920dd691c51ed4 | ghissues | 25401 | 0.7198 | 0.6514 | 1468 |
| 2026-10-26 | maisecrets 0.8.2 097e68dd8960b4ca37c3d3c605920dd691c51ed4 | nym | 1239 | 0.1859 | 0.9976 | 2 |
| 2026-10-26 | maisecrets 0.8.2 097e68dd8960b4ca37c3d3c605920dd691c51ed4 | dialogpii | 124 | 0.0507 | 1.0 | 0 |
| 2026-10-29 | maisecrets 0.7.2 1f9724adb2cbe3f54dba1719cd5eef0c82be2e00 (gate stopped: no PyYAML for the catalog coverage) | holdout-v2 | 872 | 0.6473 | 0.9957 | 3 |
| 2026-10-29 | maisecrets 0.7.2 1f9724adb2cbe3f54dba1719cd5eef0c82be2e00 | holdout-v2 | 872 | 0.6473 | 0.9957 | 3 |
