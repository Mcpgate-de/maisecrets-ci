# maisecrets 0.8.6 + NER on the V3 chart samples

The point "maisecrets + NER (opt-in)" of the benchmark chart. The samples and the scoring are those of the chart:
Benchmark V3, `val` 1 in 25 of Nemotron, Gretel and Mendeley, and Privy 1 in 10, salt `v3/`, the `pii` block. The
run was on 2026-10-31 on one Apple M machine.

- Scanner: `maisecrets_remote` (`bench/adapters/maisecrets_remote.py`). The maisecrets runtime is that of v0.8.6. The
  run was in a checkout at 5b06462c, which differs from v0.8.6 only in bench results, and `version` in the files
  still reads 0.7.2, as before the release commit.
- Service: the container `mcpgate/ner:latest`, image id `sha256:7937ef3ef7fd…`, repo digest
  `sha256:36a043c0a42605b9eefe3c92477e7e2639f21edc5ce440b0dbff55a9db6a1a25`. Its `/info`: D3
  (`Davlan/distilbert-base-multilingual-cased-ner-hrl@d421f57d`), int8 ONNX, persons only. It ran on 127.0.0.1:8765.
- `BENCH_REMOTE_MASK=1`: the findings of the rules go to the service as filler, as in the plugin.
- maisecrets without NER on the same samples is in `../2026-10-31-v3-0.8.6/` (`*-every25-maisecrets`,
  `privy-all-every10-maisecrets`).

Repeat (with the container running):

```bash
BENCH_REMOTE_URL=http://127.0.0.1:8765/ BENCH_REMOTE_FORMAT=hf BENCH_REMOTE_MASK=1 \
  python3 bench/run.py --maisecrets . --scanner maisecrets_remote --source gretel --split val --every 25 \
  --sample-salt v3/ --out gretel-val-every25-maisecrets_remote.json
```
