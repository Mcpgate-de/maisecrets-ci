# maisecrets 0.8.7: names in typed prompts with the name service

0.8.7 sends a typed prompt to the local name service when NER is on (`/maisecrets:ner local`). These files measure
that path on texts of prompt length, with the timeout of the plugin (300 ms), on one reference setup with the
resource limits of a production name service. The run was on 2026-11-01. The script is
`bench/ner/prompt_names.py`; its docstring says what it counts.

- Runtime: the maisecrets runtime of v0.8.7. The checkout was at 97a66d4e (`next`), whose `maisecrets/` and
  `hooks/` do not differ from v0.8.7.
- Service: the container `mcpgate/ner:v2.0.3584` (linux/amd64), repo digest
  `sha256:cc871eb56c6fad40855bb1967832acddc5c2e8b6ada9118eece4f8fc8095fe3e`, started with `--cpus 4 --memory 1536m`
  and no worker setting, so it runs 4 workers with one thread each. `service-info.json` is its `/info`: D3, int8 ONNX,
  onnxruntime 1.31.1. It offers DATE, LOC, ORG and PER; the plugin asks for no labels, and without labels the service
  answers PER only. The plugin also keeps only PER (`DEFAULT_CLASSES` in `maisecrets/detection/remote.py`); the script
  uses the same client.
- Host: netcup RS 2000 G12, 8 cores AMD EPYC 9645 (Zen 5), 16 GB, Debian 13, Docker 29.9. The service had a quota of
  4 cores; the client ran on cores 4 to 7 (`taskset`). Times include HTTP on loopback.
- Load: `bench/ner/quiet_bench.sh` started the runs only on a quiet host (no CI build, a 1-minute load average below
  0.5) and wrote the load and the count of CI builds every 10 s to `monitor.log`. No CI build ran during the runs;
  the highest load average, 4.55, is the run itself.
- Requests: 4 at once (`--parallel 4`), as 4 people or a gateway with 4 tool results at the same time.
- Data: the `dev` split of DialogPII and of ghissues. Neither split was used to tune a rule. Each text is cut at the
  last space before 500 or 1,000 characters, the length of a typed prompt.
- The rules run first. The service gets the text with each finding of the rules as filler, as the plugin sends it.
  A request without an answer in 300 ms counts as no name, as in the plugin.

| File | Texts | Names found whole: rules → rules + NER | NER spans on no labelled value | Median / p95 | No answer in time | Texts per second |
|---|---|---|---|---|---|---|
| `dialogpii-dev-cut500.json` | 1,980 | 137 → 3,037 of 5,361 (2.6 % → 56.6 %) | 3.53 per 1,000 words | 54 / 84 ms | 0 | 69.0 |
| `dialogpii-dev-cut1000.json` | 1,980 | 217 → 4,786 of 8,297 (2.6 % → 57.7 %) | 2.78 per 1,000 words | 100 / 164 ms | 0 | 36.5 |
| `ghissues-dev-cut1000.json` | 25,387 | names are not labelled | 0.54 per 1,000 words (1,590 spans in 1,044 texts) | 92 / 147 ms | 13 | 42.9 |

In DialogPII, a span that overlaps no labelled value of any class counts as false. A span on a labelled value of
another class (an email address, a street) counts as not false, so 3.53 and 2.78 are a lower bound. ghissues labels
no names, so each span of the service counts there: 0.54 per 1,000 words is an upper bound for the false masks in
developer prose. A request without an answer in time leaves the text to the rules, as in the plugin.

Texts per second is the rate of 4 requests at once on 4 cores, not the most the service can take. A production host
of the same size with another CPU (for example Zen 4) gives other times.

A whole dialogue is longer than a prompt (median 3,557 characters), and most whole dialogues get no answer in
300 ms. Do not compare these figures with a run on whole texts or with a longer timeout.

Repeat on a host with 8 cores. `DIALOGPII_DIR` and `GHISSUES_DIR` are the directories that `bench/dialogpii.py seal`
and `bench/ghissues.py seal` wrote:

```bash
docker run -d --name ner-bench --cpus 4 --memory 1536m -p 127.0.0.1:8766:8765 mcpgate/ner:v2.0.3584
bash bench/ner/quiet_bench.sh OUT_DIR dialogpii DIALOGPII_DIR 500 dialogpii DIALOGPII_DIR 1000 \
  ghissues GHISSUES_DIR 1000
```
