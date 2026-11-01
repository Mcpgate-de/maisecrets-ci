# maisecrets 0.8.7: names in typed prompts with the local name service

0.8.7 sends a typed prompt to the local name service when NER is on (`/maisecrets:ner local`). These files measure
that path on texts of prompt length, with the timeout of the plugin (300 ms). The run was on 2026-11-01 on one
Apple M5 machine. The script is `bench/ner/prompt_names.py`; its docstring says what it counts.

- Runtime: the maisecrets runtime of v0.8.7. The run was in a checkout at 97a66d4e (`next`), whose `maisecrets/` and
  `hooks/` do not differ from v0.8.7.
- Service: the container `mcpgate/ner:v2.0.3584` (linux/arm64), image id `sha256:4142de7b76c0…`, repo digest
  `sha256:cc871eb56c6fad40855bb1967832acddc5c2e8b6ada9118eece4f8fc8095fe3e`. Its `/info` is in `service-info.json`:
  D3, int8 ONNX, 10 workers. It offers DATE, LOC, ORG and PER, but the plugin asks for no labels, and without
  labels the service answers PER only. The plugin also keeps only PER (`DEFAULT_CLASSES` in
  `maisecrets/detection/remote.py`); the script uses the same client.
- Machine: one Apple M5 with 10 cores, the service on the same machine. The times include HTTP on loopback. On
  another machine, or with fewer workers, the times differ, and more requests can miss the 300 ms.
- Data: the `dev` split of DialogPII and of ghissues. Neither split was used to tune a rule. Each text is cut at the
  last space before 500 or 1,000 characters, the length of a typed prompt.
- The rules run first. The service gets the text with each finding of the rules as filler, as the plugin sends it.
  A request without an answer in 300 ms counts as no name, as in the plugin.

| File | Texts | Names found whole: rules → rules + NER | NER spans on no labelled value | Median / p95 | No answer in time |
|---|---|---|---|---|---|
| `dialogpii-dev-cut500.json` | 1,980 | 137 → 3,032 of 5,361 (2.6 % → 56.6 %) | 3.50 per 1,000 words | 49 / 68 ms | 0 |
| `dialogpii-dev-cut1000.json` | 1,980 | 217 → 4,780 of 8,297 (2.6 % → 57.6 %) | 2.76 per 1,000 words | 95 / 133 ms | 0 |
| `ghissues-dev-cut1000.json` | 25,387 | names are not labelled | 0.54 per 1,000 words (1,576 spans in 1,027 texts) | 100 / 176 ms | 72 |

ghissues labels no names, so each span of the service counts there: 0.54 per 1,000 words is an upper bound for the
false masks in developer prose. In DialogPII, a span that overlaps no labelled value of any class counts as false. A
span on a labelled value of another class (an email address, a street) counts as not false, so 3.50 and 2.76 are a
lower bound.

The ghissues run shared the machine with other work (a second service and tests), so its times are longer and 72
requests got no answer in 300 ms. A second run on the same image, at a load average of 1.5 to 4.9, gave 0.53 per
1,000 words and 91 requests without an answer; a first run at night on the image before v2.0.3584 (the same model
file) had 2. The rate of spans does not depend on the load; the requests without an answer do (about 0.3 % of
the texts here). Such a request leaves the text to the rules, as in the plugin.

A whole dialogue is longer than a prompt (median 3,557 characters), and most whole dialogues get no answer in
300 ms. Do not compare these figures with a run on whole texts or with a longer timeout.

Repeat with the container `mcpgate/ner:v2.0.3584` running on 127.0.0.1:8765. `DIALOGPII_DIR` and `GHISSUES_DIR` are
the directories that `bench/dialogpii.py seal` and `bench/ghissues.py seal` wrote:

```bash
python3 bench/ner/prompt_names.py dialogpii DIALOGPII_DIR 500 dialogpii-dev-cut500.json
python3 bench/ner/prompt_names.py dialogpii DIALOGPII_DIR 1000 dialogpii-dev-cut1000.json
python3 bench/ner/prompt_names.py ghissues GHISSUES_DIR 1000 ghissues-dev-cut1000.json
```
