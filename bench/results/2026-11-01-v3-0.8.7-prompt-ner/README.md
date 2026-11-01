# maisecrets 0.8.7: names in typed prompts with the local name service

0.8.7 sends a typed prompt to the local name service when NER is on (`/maisecrets:ner local`). These files measure
that path on texts of prompt length, with the timeout of the plugin (300 ms). The run was on 2026-11-01 on one
Apple M machine. The script is `bench/ner/prompt_names.py`; its docstring says what it counts.

- Runtime: the maisecrets runtime of v0.8.7. The run was in a checkout at 97a66d4e (`next`), whose `maisecrets/` and
  `hooks/` do not differ from v0.8.7.
- Service: the container `mcpgate/ner:latest`, image id `sha256:7937ef3ef7fd…`, repo digest
  `sha256:36a043c0a42605b9eefe3c92477e7e2639f21edc5ce440b0dbff55a9db6a1a25`, the image of the 0.8.6 results. Its
  `/info` is in `service-info.json` (D3, int8 ONNX, persons only).
- Data: the `dev` split of DialogPII and of ghissues. Neither split was used to tune a rule. Each text is cut at the
  last space before 500 or 1,000 characters, the length of a typed prompt.
- The rules run first. The service gets the text with each finding of the rules as filler, as the plugin sends it.
  A request without an answer in 300 ms counts as no name, as in the plugin.

| File | Texts | Names found whole: rules → rules + NER | NER spans on no labelled value | Median / p95 | No answer in time |
|---|---|---|---|---|---|
| `dialogpii-dev-cut500.json` | 1,980 | 137 → 3,032 of 5,361 (2.6 % → 56.6 %) | 3.50 per 1,000 words | 48 / 68 ms | 0 |
| `dialogpii-dev-cut1000.json` | 1,980 | 217 → 4,780 of 8,297 (2.6 % → 57.6 %) | 2.76 per 1,000 words | 94 / 132 ms | 0 |
| `ghissues-dev-cut1000.json` | 25,387 | names are not labelled | 0.54 per 1,000 words (1,578 spans in 1,028 texts) | 88 / 132 ms | 2 |

ghissues labels no names, so each span of the service counts there: 0.54 per 1,000 words is an upper bound for the
false masks in developer prose. In DialogPII, a span that overlaps no labelled value of any class counts as false.

A whole dialogue is longer than a prompt (median 3,557 characters), and most whole dialogues get no answer in
300 ms. Do not compare these figures with a run on whole texts or with a longer timeout.

Repeat (with the container running on 127.0.0.1:8765). `DIALOGPII_DIR` and `GHISSUES_DIR` are the directories that
`bench/dialogpii.py seal` and `bench/ghissues.py seal` wrote:

```bash
python3 bench/ner/prompt_names.py dialogpii DIALOGPII_DIR 500 dialogpii-dev-cut500.json
python3 bench/ner/prompt_names.py dialogpii DIALOGPII_DIR 1000 dialogpii-dev-cut1000.json
python3 bench/ner/prompt_names.py ghissues GHISSUES_DIR 1000 ghissues-dev-cut1000.json
```
