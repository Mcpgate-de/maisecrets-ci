# maisecrets 0.9.11 + NER on the V3 chart samples

The point "maisecrets + NER (opt-in)" of the benchmark chart. The samples and the scoring are those of the chart:
Benchmark V3, `val` 1 in 25 of Nemotron, Mendeley and Gretel, and Privy 1 in 10, salt `v3/`, the `pii` block. The
run was on 2026-11-15 on the reference host (netcup, AMD EPYC 9645, 8 vCPU, Debian 13), alone under the host lock.

- Scanner: `maisecrets_remote` (`bench/adapters/maisecrets_remote.py`), in a checkout of the release commit of v0.9.11
  (`0f2d8a1d`).
- Service: `mcpgate/ner:v2.0.3916@sha256:cde7bdb1d2dc753f41fbf6dd5179af56a570f62804bdc8d0da1021b83ae18a4b`, the pin of
  0.9.11 (unchanged since 0.9.10), started with the limits of the plugin's container (`--cpus 4 --memory 1536m`) on 127.0.0.1:8766. Its `/info`:
  D3 (`Davlan/distilbert-base-multilingual-cased-ner-hrl@d421f57d`), int8 ONNX, aggregation `snap`.
- `BENCH_REMOTE_MASK=1`: the findings of the rules go to the service as filler, as in the plugin.
- maisecrets without NER on the same samples is in `../2026-11-15-v3-0.9.11/` (`*-every25-maisecrets`,
  `privy-all-every10-maisecrets`).

| Sample | Recall (strict) | Precision (V3) | False alarms | F1 |
|---|---:|---:|---:|---:|
| Nemotron val | 0.875 | 0.993 | 15 | 0.930 |
| Mendeley val | 0.936 | 0.864 | 313 | 0.899 |
| Gretel val | 0.513 | 0.921 | 62 | 0.659 |
| Privy | 0.852 | 0.959 | 40 | 0.902 |

Repeat (with the container running on port 8766):

```bash
BENCH_REMOTE_URL=http://127.0.0.1:8766/ BENCH_REMOTE_FORMAT=hf BENCH_REMOTE_MASK=1 \
  python3 bench/run.py --maisecrets . --scanner maisecrets_remote --source gretel --split val --every 25 \
  --sample-salt v3/ --out gretel-val-every25-maisecrets_remote.json
```
