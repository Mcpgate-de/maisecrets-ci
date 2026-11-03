# maisecrets 0.8.12: names in typed prompts with the name service

The same measurement as `bench/results/2026-11-01-v3-0.8.7-prompt-ner/`, with the runtime of v0.8.12. Everything else
is the same: the service, its limits, the host, the data, the timeout and the script (`bench/ner/prompt_names.py`).
The run was on 2026-11-02.

- Runtime: v0.8.12 (`6c83f5b6`), a clean checkout of the tag commit.
- Service: the container `mcpgate/ner:v2.0.3584`, repo digest
  `sha256:cc871eb56c6fad40855bb1967832acddc5c2e8b6ada9118eece4f8fc8095fe3e`, with `--cpus 4 --memory 1536m` and no
  worker setting (4 workers, one thread each). `service-info.json` is its `/info`: D3, int8 ONNX, onnxruntime 1.31.1.
- Host: netcup RS 2000 G12, 8 cores AMD EPYC 9645 (Zen 5), 16 GB, Debian 13. The service had a quota of 4 cores; the
  client ran on cores 4 to 7 (`taskset`). Times include HTTP on loopback.
- Load: `bench/ner/quiet_bench.sh` started on a quiet host and logged every 10 s (`monitor.log`): no CI build ran
  during the run; the highest load average, 4.41, is the run itself.
- Requests: 4 at once, the timeout of the plugin (300 ms); a request without an answer in time counts as no name.
- Data: the `dev` split of DialogPII and of ghissues, each text cut at the last space before 500 or 1,000 characters.

| File | Texts | Names found whole: rules → rules + NER | NER spans on no labelled value | Median / p95 | No answer in time | Texts per second |
|---|---|---|---|---|---|---|
| `dialogpii-dev-cut500.json` | 1,980 | 137 → 3,040 of 5,361 (2.6 % → 56.7 %) | 3.37 per 1,000 words | 56 / 82 ms | 0 | 67.9 |
| `dialogpii-dev-cut1000.json` | 1,980 | 217 → 4,789 of 8,297 (2.6 % → 57.7 %) | 2.69 per 1,000 words | 105 / 161 ms | 0 | 35.9 |
| `ghissues-dev-cut1000.json` | 25,387 | names are not labelled | 0.49 per 1,000 words (1,445 spans in 972 texts) | 105 / 171 ms | 39 | 37.6 |

The reading of the columns is that of the 0.8.7 README: 3.37 and 2.69 are a lower bound for the false masks (a span
on a labelled value of another class counts as not false), and 0.49 is an upper bound for developer prose (ghissues
labels no names, so each span counts).

Against 0.8.7 on the same data: 3 and 3 more names found whole (3,040 and 4,789), fewer spans on no labelled value
(592 instead of 619, 952 instead of 984; since 0.8.7 a greeting or a product name alone is no longer masked as a
person), and the same times within their scatter. In ghissues the spans went from 1,590 to 1,445. In ghissues, 39 of 25,387 requests had no answer in time
(0.15 %); in the 0.8.7 run it was 13.

## Repeat

Use a host with 8 cores and Docker. `DIALOGPII_DIR` and `GHISSUES_DIR` are the directories that
`bench/dialogpii.py seal` and `bench/ghissues.py seal` wrote. Pin the service by its digest, so that you test the same
model:

```bash
git clone https://github.com/Mcpgate-de/maisecrets && cd maisecrets && git checkout v0.8.12
docker run -d --name ner-bench --cpus 4 --memory 1536m -p 127.0.0.1:8766:8765 \
  mcpgate/ner@sha256:cc871eb56c6fad40855bb1967832acddc5c2e8b6ada9118eece4f8fc8095fe3e
bash bench/ner/quiet_bench.sh OUT_DIR dialogpii DIALOGPII_DIR 500 dialogpii DIALOGPII_DIR 1000 \
  ghissues GHISSUES_DIR 1000
```

Compare `names`, `names_whole_rules`, `names_whole_rules_ner`, `ner_spans_on_no_labelled_value` and `words` in each
JSON file of `OUT_DIR` with the file of the same name here. The counts can differ by a few: a request that gets no
answer in 300 ms counts as no name, and that depends on the load of your host (`no_answer_in_time`). The times depend
on your CPU and are not compared.

### A rerun on 2026-11-03

`rerun-2026-11-03/` is the same measurement on the same host and service (`service-info.json` is identical), with the
runtime of `next` at `a669fa40`: 0.8.14 and a fix of the release tool. Its detection differs from 0.8.12 only in the
phone rule for typed prompts (`maisecrets/detection/personal.py`); the name service client and the bench scripts are
the same. The run was from 10:26 to 10:41 UTC, with no CI build and a highest load average of 4.79, the run itself.

- DialogPII, cut at 500 and at 1,000: the same counts, 3,040 of 5,361 and 4,789 of 8,297 names found whole, 592 and
  952 spans on no labelled value.
- ghissues: 1,449 spans instead of 1,445, with 13 requests without an answer in time instead of 39.
