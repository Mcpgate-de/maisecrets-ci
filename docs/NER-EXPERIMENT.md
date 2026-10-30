# The NER experiment: an optional PERSON layer after the deterministic detector

Status: an experiment on maisecrets 0.7.3. Nothing here is part of the plugin or of `maisecrets.detection`; the code is
in `bench/` (`bench/ner/person_worker.py`, `bench/adapters/maisecrets_ner.py`), which the release tree leaves out.

## The question

The Benchmark V1 snapshot of 0.7.3 (`bench/results/2026-10-21-v0.7.3.md`) leaves 48.7 % of the missed spans of the four
PII datasets in category D, 96 % of them names in running text, and on Privy 0.7.3 masks 312 of 8,121 names whole.
Can a local PERSON model, run after the deterministic detector and only where it found nothing, close a real part of
that gap without giving up the precision of maisecrets?

## The design under test

1. The deterministic detector of the checkout runs first, as in the benchmark (`bench/adapters/maisecrets.py`).
2. Its findings are kept as they are.
3. The model reads the whole text (its context is the same with or without the layer).
4. A PERSON span of the model is kept only when it overlaps no deterministic finding and no PERSON span kept before
   it; it becomes a `pii.name` finding. A deterministic finding is never made smaller, moved or retyped.
5. Without the NER environment the adapter refuses to run; the deterministic adapter is the baseline and stays as it
   was. (In a product, a missing or failing layer would mean the findings of step 1 alone.)

## Fixed before the first measurement (2026-10-21)

This section was committed before any measurement of a candidate on a dataset, and is not changed afterwards.

**Candidates.**

| | A: spaCy small | B: spaCy large | C: GLiNER |
|---|---|---|---|
| Model | `en_core_web_sm` 3.8.0 | `en_core_web_lg` 3.8.0 (Presidio's default) | `urchade/gliner_multi-v2.1` at `443d26d6` |
| Library | spaCy 3.8.16 | spaCy 3.8.16 | gliner 0.2.29, torch 2.14.1, transformers 5.16.1 |
| Licence | MIT (library and model) | MIT | Apache-2.0 (library and model); encoder mDeBERTa-v3-base, MIT |
| Model size | 15 MB | 428 MB | 1.1 GB |
| Environment on disk | 587 MB (with both models) | the same | 928 MB, of it torch 587 MB |
| Languages | English | English | multilingual |
| Python | 3.9 to 3.14 | 3.9 to 3.14 | 3.10 or later |
| CPU only | yes | yes | yes (measured on CPU) |
| Setting | PERSON entities, no threshold | the same | label `person`, threshold 0.5 (the library default) |

A fourth variant, **C-high**, is GLiNER with threshold 0.3: one explicit high-recall setting, not a tuned value.

Left out, with the reason: the PII-specific GLiNER models `nvidia/gliner-PII` and `knowledgator/gliner-pii-*` (their
training data is synthetic PII of the kind of Nemotron and Gretel, so the benchmark could measure their training set;
the NVIDIA licence is not Apache-2.0); `urchade/gliner_multi_pii-v1` (2024, the same concern); Presidio as a whole
(its PERSON comes from `en_core_web_lg`, which is candidate B; its other recognizers are vendored into maisecrets
already); Flair and BERT token classifiers (a transformer of the same cost as C with fewer languages).

**Added later, on the maintainer's request (2026-10-21, after the Nemotron sample of B, C and C-high was seen):**
candidate **D**, DistilBERT, `dslim/distilbert-NER` at `dfa2838a` (Apache-2.0, 250 MB, trained on CoNLL-2003,
English), run with transformers 5.16.1 and torch 2.14.1 in the GLiNER environment: the `token-classification`
pipeline with `aggregation_strategy="simple"`, its `PER` entities, no threshold, the text in pieces of 100 tokens. The
setting was fixed before D's first measurement; nothing else in this section changed. After D's samples (all `dev`):
1,868 of its false positives in the family "rest" end inside a word, 1,348 of them on Gretel, the part that is not
English. `aggregation_strategy="simple"` returns pieces of words. **D2** is D with `aggregation_strategy="first"`, which
keeps whole words: a choice made on `dev`, as the rules allow.

**Added after the results above, on the maintainer's question why DistilBERT finds only about half of the names on
Gretel and Privy (2026-10-21):** candidate **D3**, the model and the setting of the support-copilot's NER layer:
`Davlan/distilbert-base-multilingual-cased-ner-hrl` at `d421f57d` (licence AFL-3.0, ten languages), aggregation
`simple`, each span widened to whole words (`hf:<dir>::snap`). Fixed before its first measurement; run on the samples
and then on Privy (sample and full). Privy results of the other candidates were known when D3 was chosen; it was not
chosen from them.

**Data and splits.** The four PII datasets of Benchmark V1 with the case hashes of the 0.7.3 snapshot: the fixed sample
of 1 in 50 for every variant, and each dataset in full for the baseline, A and B (C on the sample only: about 0.1 to
0.5 s per document). The bank and the catalogs are left out (6 and 0 names). No threshold or setting is chosen from a
result; `val` is reported, not used.

**Measures.** Per variant against the baseline of the same run: the `pii.name` class (whole, partial, missed, strict
recall) and the PII family (false positives, precision, F1); the names the layer adds and the false positives it adds;
spans made worse (must be 0); the PERSON spans dropped on a deterministic finding, by its type; names by bucket of
`bench/funnel.py` (running text against record fields) and by language where a dataset has one; the time per
document (cold start, model load, median, 95th percentile), the peak memory of the NER process, the throughput, one
input of 1 MB, and many requests on one loaded model.

**The false positives the layer adds** are sorted by rules fixed here, before reading any: a span that is a gold span
of another class (address, user name, other), a span in a record field (funnel bucket), a span with a digit, `@`, `_`
or `/` (technical identifier), a span with a company word (Inc, LLC, Ltd, Corp, GmbH, AG, Bank, Group, Company,
Partners, Holdings, Technologies, Solutions, Services, University, Hospital, Foundation), a span of one word at the
start of a sentence, a span of role or title words only, and the rest. Then a sample of the rest is read on `dev`
in masked form.

**Privy**, after all of the above and with nothing changed: totals only, the sample for every variant, in full for
A and B and, when the time allows, for C. No Privy case is read, before or after.

Fixed before the Privy run, after the development measurements: the variants and their settings stay as above (A, B,
C, C-high, D, D2); the baseline is run again in this tree; in full: the baseline, A, B, C and D2.

## Results (2026-10-21)

Raw results, analysis and every table: `bench/results/2026-10-21-ner/` (`runs/<variant>/`, `privy/<variant>/`,
`analysis/`; `analysis/tables.md` has all tables of this section and more). The baseline of this tree gives the same
outcome for every span as the 0.7.3 snapshot on all eight files (the four datasets in full and on the sample); its
full-run files are therefore not repeated here. All 58 result files name a clean benchmark tree.

**The samples of 1 in 50 are all `dev`**: V1 derives the split and the sample from the same sha256 of the case id, so
the sample holds no `val` and no holdout case. `val` appears only in the full runs of A and B, as totals.

### The answers

1. **How much of the name gap closes?** On the development samples the layer turns 72 % (spaCy sm) to 86 % (GLiNER)
   of the names 0.7.3 leaves partial or missed into whole names (1,206 of 5,604 whole before); D3 77 %. On Privy,
   which nobody read, it is 16 % (spaCy sm), 27 % (spaCy lg), 52 % (D2), 62 % (D3) and 96 % (GLiNER) of the 7,809
   names 0.7.3 does not mask whole.
2. **The best trade-off is the multilingual DistilBERT with whole words (D3)**, the model of the support-copilot. On
   Privy it raises whole names from 312 to 5,157 of 8,121 for 413 more false positives (PII F1 0.31 → 0.67); D2 reaches
   4,345 for 283 more, spaCy lg 2,439 for 4,744 more, GLiNER 7,812 for 31,138 more. On the development samples D3 adds
   913 false positives for 3,372 more whole names; D2 1,335 for 3,470; spaCy lg 3,123 for 3,447; GLiNER 6,122 for
   3,761. D3 is also the cheapest transformer: 0.7 GB, 33 ms median and 88 ms p95 per document.
3. **Recall on the known datasets** (whole names, samples): 21.5 % → 78.0 % (spaCy sm), 83.0 % (spaCy lg), 88.6 %
   (GLiNER 0.5), 83.4 % (D2), 81.7 % (D3). In full, spaCy lg: Nemotron 29.2 % → 91.5 %, Gretel 12.7 % → 58.4 %,
   Mendeley 19.1 % → 95.1 %, PIILO 7.2 % → 80.1 %; on `val` the same as on `dev` (13,463 → 49,724 of 59,339 against
   39,726 → 149,952 of 178,624).
4. **Recall on Privy (totals only):** whole names 3.8 % → 19.6 % (A), 30.0 % (B), 96.2 % (C), 53.5 % (D2), 63.5 %
   (D3); on the sample also C-high 99.0 % and D 55.5 %.
5. **Real false positives:** the counts above are what the scoring calls a false positive. Part of them are names the
   datasets do not label: of D3's 868 false positives in the family "rest" on `dev`, 751 are a PERSON for spaCy lg
   too (738 of the 868 on Mendeley, whose documents name more people than it labels). On English running text
   (Nemotron) D3 adds 38 false positives for 1,743 more whole names, on Gretel's other languages 44 for 234.
6. **The false-positive families** (below): GLiNER marks pronouns (1,332) and lower-case role nouns (1,333), words at
   a sentence start (954) and role or title words (570); DistilBERT with `simple` aggregation returns pieces of words
   (1,868); spaCy masks running text in German, Dutch, Italian and Swedish (on Gretel in full 100,345 of spaCy lg's
   108,953 added false positives), record fields and sentence starts. D2's and D3's are mostly capitalised words the
   other model also calls a person, and sentence starts.
7. **Is an optional layer sensible?** Technically yes: it never made a span worse (0 in all files), it adds only, and
   it runs offline in its own process. As a product, only as an opt-in with a clear scope (the languages measured,
   below) and a simple install; record fields stay a weak spot of every model (D3: 14 → 144 of 295).
8. **Recommendation: keep it experimental now, and make it an optional feature when the open points below are
   closed.** Not on by default. GLiNER only as a later candidate for an explicit high-recall mode: it finds almost
   every name, at 6.7 times the false positives of D3 on the samples and 75 times on Privy, and 3.5 GB.
9. **What a product would need** (none of it done here; each is the maintainer's decision): a second-layer seam in
   `Detector` (a public API change, approval needed); an installable extra outside the plugin folder, since the plugin
   installs no package at run time (`docs/REPO-STANDARDS.md`) and torch alone is 587 MB (an ONNX runtime with a
   quantised model may be far smaller; not measured); one install step with a pinned model and its sha256, served
   from a place a company proxy allows; a size limit or chunk budget per hook call (1 MB took 36 s with D3, and 15
   to 17 s and 3.4 to 4.4 GB of memory with spaCy); and a fail-safe that keeps the deterministic findings when the
   layer is missing, fails or times out.
10. **Open questions:** false positives in developer text (the false-alarm bank of seven code trees was not measured
    with a layer; it is the text maisecrets sees most); languages outside the data (below); why every model masks
    only about half of Gretel's names in running text (D3: 278 of 730); the cost inside a real hook (the latency
    budget of a prompt and of a tool result, Windows, memory next to the client); an ONNX build; the holdout V2 for a
    release candidate; and whether names in record fields should stay with the deterministic record layer
    (category C) instead.

### Languages

The data covers English (Nemotron, Mendeley, PIILO, most of Gretel) and, in Gretel, German, Spanish, French, Italian,
Dutch and Swedish; Privy's languages are not known here (its cases are not read). D3 was trained on ten languages
(its model card: Arabic, German, English, Spanish, French, Italian, Latvian, Dutch, Portuguese, Chinese). Measured
with it, Gretel sample, whole names and added false positives: English 360 of 547, +37; German 62 of 170, +11;
Spanish 67 of 139, +6; French 24 of 65, +10; Italian 60 of 132, +5; Dutch 46 of 169, +9; Swedish (not in its training
data) 55 of 187, +3. Nothing here says how any model does in Polish, Czech, Russian, Turkish, or in Arabic, Chinese or
Japanese script. A product would name the languages it measured; elsewhere the deterministic core works as today. The
deterministic core itself is already uneven: emails, IBANs, cards and tokens do not depend on the language, its
name and address rules do.

### Names, false positives and precision

Samples of 1 in 50, all `dev`. Cells: whole names (share of the names), false positives the layer adds, PII precision.

| Variant | Nemotron (2,696 names) | Gretel (1,409) | Mendeley (1,485) | PIILO (14) |
|---|---|---|---|---|
| maisecrets 0.7.3 | 743 (27.6 %), –, 0.996 | 189 (13.4 %), –, 0.927 | 273 (18.4 %), –, 0.987 | 1, –, 1.0 |
| + A spaCy sm | 2,245 (83.3 %), 730, 0.862 | 764 (54.2 %), 2,731, 0.370 | 1,350 (90.9 %), 763, 0.854 | 11, 150, 0.074 |
| + B spaCy lg | 2,434 (90.3 %), 96, 0.978 | 802 (56.9 %), 2,264, 0.419 | 1,404 (94.5 %), 715, 0.862 | 13, 48, 0.226 |
| + C GLiNER 0.5 | 2,518 (93.4 %), 1,468, 0.769 | 971 (68.9 %), 1,392, 0.526 | 1,465 (98.7 %), 1,102, 0.802 | 13, 2,160, 0.006 |
| + C-high GLiNER 0.3 | 2,540 (94.2 %), 2,010, 0.711 | 991 (70.3 %), 1,889, 0.458 | 1,466 (98.7 %), 1,272, 0.779 | 13, 2,766, 0.005 |
| + D DistilBERT | 2,521 (93.5 %), 329, 0.944 | 702 (49.8 %), 1,681, 0.567 | 1,426 (96.0 %), 749, 0.856 | 6, 91, 0.099 |
| + D2 DistilBERT, whole words | 2,531 (93.9 %), 140, 0.970 | 713 (50.6 %), 570, 0.728 | 1,426 (96.0 %), 575, 0.882 | 6, 50, 0.138 |
| + D3 multilingual DistilBERT, whole words | 2,486 (92.2 %), 38, 0.990 | 674 (47.8 %), 81, 0.918 | 1,410 (94.9 %), 746, 0.856 | 8, 48, 0.172 |

PIILO labels only the students' names in essays; every other person in them counts as a false positive, so its
precision says little. Mendeley marks company names as neutral spans; a PERSON on one is neither right nor wrong.

Full datasets (all splits), A and B: Nemotron 41,959 → 120,827 (A) and 131,404 (B) of 143,639, false positives +39,908
and +5,863; Gretel 9,801 → 40,706 and 45,042 of 77,117, +130,444 and +108,953; Mendeley 14,748 → 70,608 and 73,385 of
77,200, +38,573 and +37,420; PIILO 98 → 902 and 1,094 of 1,365, +8,877 and +4,039.

**Spans made worse: 0** for every variant on every file. PERSON spans dropped because they overlapped a deterministic
finding (samples and full runs): A 65,252, B 71,551 (most on a name or an address maisecrets found), C 1,637, C-high
1,822, D 1,959, D2 1,058, D3 1,069.

**Running text and record fields** (samples, whole names before → after, of all): running text without a cue
498 → 2,800 of 3,349 with D2 (D3 2,737, B 2,712, C 2,931); after a person cue 315 → 1,059 of 1,134; record fields
14 → 142 of 295 (D3 144, C 207).

**By language** (Gretel sample, whole names before → after, added false positives), D2: English 109 → 383 of 547, 209;
German 11 → 74 of 170, 82; Spanish 21 → 55 of 139, 38; French 7 → 24 of 65, 45; Italian 17 → 61 of 132, 33; Dutch
18 → 53 of 169, 106; Swedish 6 → 63 of 187, 57. GLiNER, the multilingual model, has the most names in every language
(German 110, Swedish 79) and the fewest false positives outside English among C, A and B.

### The false positives the layer adds, by family (samples, `dev`)

The families fixed before reading (record field, technical identifier, company word, one word at a sentence start,
role or title words, rest), then the "rest" sorted after the fact without reading it (`bench/ner/rest_dump.py`,
`bench/ner/rest_label.py`): the form of the span, and the entity spaCy lg sees on the same span (another model, not a
truth; for B it is the same model and says nothing).

| Variant | Record field | Technical | Company word | Sentence start | Role or title | Rest | Rest: piece of a word | Rest: pronoun | Rest: lower-case word | Rest: PERSON for spaCy lg | Rest: ORG for spaCy lg |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A spaCy sm | 498 | 246 | 2 | 431 | 3 | 3,194 | 1 | 0 | 967 | 1,102 | 235 |
| B spaCy lg | 115 | 138 | 0 | 209 | 0 | 2,661 | 6 | 0 | 813 | (same model) | – |
| C GLiNER 0.5 | 90 | 44 | 39 | 954 | 570 | 4,425 | 0 | 1,332 | 1,333 | 745 | 208 |
| C-high GLiNER 0.3 | 145 | 77 | 62 | 1,137 | 687 | 5,829 | 0 | 1,680 | 2,013 | 848 | 270 |
| D DistilBERT | 65 | 3 | 3 | 320 | 0 | 2,459 | 1,868 | 1 | 20 | 497 | 13 |
| D2 DistilBERT, whole words | 38 | 1 | 0 | 278 | 10 | 1,008 | 28 | 1 | 40 | 608 | 35 |
| D3 multilingual DistilBERT, whole words | 3 | 0 | 0 | 34 | 8 | 868 | 0 | 0 | 0 | 751 | 31 |

### Privy, the independent check (totals only)

Run after everything above, with the variants and settings fixed in this file beforehand; no case read. Privy's
precision is low for maisecrets alone because Privy does not label several classes maisecrets finds (most of its
3,344 false positives are SSNs, IBANs, IPs and emails); read the added false positives, not the precision.

| Privy, full (28,843 cases) | Whole names (of 8,121) | Partial | PII false positives | PII recall | PII precision | PII F1 |
|---|---|---:|---|---:|---:|---:|
| maisecrets 0.7.3 | 312 (3.8 %) | 9 | 3,344 | 0.240 | 0.448 | 0.313 |
| + A spaCy sm | 1,593 (19.6 %) | 215 | 7,020 (+3,676) | 0.355 | 0.375 | 0.365 |
| + B spaCy lg | 2,439 (30.0 %) | 541 | 8,088 (+4,744) | 0.429 | 0.399 | 0.414 |
| + C GLiNER 0.5 | 7,812 (96.2 %) | 31 | 34,482 (+31,138) | 0.910 | 0.229 | 0.366 |
| + D2 DistilBERT, whole words | 4,345 (53.5 %) | 137 | 3,627 (+283) | 0.599 | 0.655 | 0.626 |
| + D3 multilingual DistilBERT, whole words | 5,157 (63.5 %) | 119 | 3,757 (+413) | 0.671 | 0.672 | 0.671 |

On the Privy sample (595 cases, 191 names): C-high 189 names for +1,025 false positives; D 106 for +41; D2 112 for
+9; B 54 for +99; A 32 for +71; C 187 for +597; D3 133 for +7.

### Cost

One process per candidate on an idle machine (Apple M5, CPU only), 300 documents of the samples (319 KB),
`bench/ner/perf.py`:

| | A spaCy sm | B spaCy lg | C GLiNER 0.5 | D2 DistilBERT | D3 multilingual DistilBERT |
|---|---:|---:|---:|---:|---:|
| Model load | 0.39 s | 0.77 s | 7.0 s | 2.3 s | 1.8 s |
| Cold start to the first result | 0.40 s | 0.78 s | 7.1 s | 2.6 s | 1.8 s |
| Per document, median / 95th percentile | 12 / 38 ms | 14 / 43 ms | 152 / 411 ms | 62 / 263 ms | 33 / 88 ms |
| Throughput | 63 KB/s | 56 KB/s | 5.6 KB/s | 11.6 KB/s | 26.2 KB/s |
| Memory after load / after the documents | 137 / 168 MB | 753 / 779 MB | 3,510 / 3,510 MB | 333 / 614 MB | 351 / 668 MB |
| One input of 1 MB | 15 s, peak 3.4 GB | 17 s, peak 4.4 GB | 204 s | 52 s | 36 s |
| 1,000 calls of one short text, median / 95th | 1.7 / 1.8 ms | 1.9 / 2.2 ms | 44 / 50 ms | 9.9 / 13 ms | 5.9 / 6.6 ms |
| Model on disk | 15 MB | 428 MB | 1.1 GB | 250 MB | 515 MB |
| Environment on disk | 587 MB (spaCy, both models) | the same | 928 MB (torch 587 MB) | the same as C | the same as C |

The deterministic core alone takes 0.25 to 9.8 ms per case (the snapshot). A reused model keeps its speed and its
memory over 1,000 calls; spaCy's memory jumps on one large input, so a layer would need a chunk budget.

### The three modes

| | A: deterministic only (0.7.3) | B: + optional local PERSON layer (D3) | C: high-recall mode (GLiNER) |
|---|---|---|---|
| Names on Privy | 3.8 % whole | 63.5 % | 96.2 % |
| Names on the samples | 21.5 % | 81.7 % | 88.6 % |
| Added false positives (Privy / samples) | – | +413 / +913 | +31,138 / +6,122 |
| Time per document | 0.25 to 9.8 ms | + 33 ms median, 88 ms p95 | + 152 ms median, 411 ms p95 |
| Memory | the hook process | + 0.7 GB | + 3.5 GB |
| Distribution | the plugin, standard library only | a second environment with torch and a pinned model (about 1.4 GB), installed by choice | the same, 2 GB |
| Data protection | local | local, offline (no network at run time, measured) | local, offline |
| Offline | yes | yes, after a one-time model download | the same |
| Maintenance | the rules | plus model and torch updates, a second test matrix | the same, and a threshold to keep |
| Licence | Apache-2.0 project | AFL-3.0 model (to check before shipping, as its training data) | Apache-2.0 model and encoder |
| Effect for a user | no names in running text | most names in prose, in the languages measured; slower calls; a larger install | almost every name; many pronouns, role words and sentence starts masked |

**Decision rule of the task, applied:** D3 reduces the name gap substantially (Privy 3.8 % → 63.5 %), its precision
cost is small on running text in the measured languages and on Privy, it never changed a deterministic finding, it runs offline and it can stay
optional. Operationally it is not yet acceptable as a feature: the cost inside a hook, developer text and the
packaging are open (answer 10). So: experimental, with a product prototype as the next step, if the maintainer
wants one.

## Product feasibility (Phase B, 2026-10-21)

The questions of answer 9 and 10, measured on D3. Nothing here is in the product: the layer is a bench module
(`bench/ner/`), and the hook proofs patch a checkout of 0.7.3 in a test process.

### B1: D3 without torch (ONNX, fp32 and int8)

`bench/ner/export_onnx.py` exports D3 at `d421f57d` to ONNX; `bench/ner/person_worker.py` (backend `onnx:<dir>`,
`onnx:<dir>::int8`) runs it with onnxruntime, tokenizers and numpy and rebuilds the whole-word aggregation (snap) of
the transformers pipeline. The model files and their sha256 are written next to the export (`SHA256SUMS`).

| | fp32 ONNX | int8 ONNX (dynamic quantisation) |
|---|---|---|
| Model on disk | 539 MB | 135 MB |
| Same PERSON spans as D3 with torch, 300 documents of the samples | 300 of 300 documents | 232 of 300 documents (606 spans the same, 42 lost, 74 new) |

fp32 ONNX is D3: every later number of D3 holds for it. int8 is a different model in effect and is measured on its
own below.

### B2: accuracy on the V3 data

The salted V3 samples (docs/BENCHMARK-V3.md): `val` and the public holdout split 1 in 25, Privy 1 in 10, maisecrets
`v0.7.3` with and without the layer, the same cases (`cases_sha256`). `bench/ner/analyze.py` per file; PII precision
as V3 counts it.

| Data | Names whole: 0.7.3 | + D3 fp32 ONNX | + D3 int8 ONNX | PII precision (V3): 0.7.3 / fp32 / int8 |
|---|---:|---:|---:|---|
| Privy, 1 in 10 (796 names) | 35 | 507 | 508 | 0.992 / 0.932 / 0.935 |
| Nemotron `val` (1,159) | 338 | 1,043 | 1,042 | 0.996 / 0.993 / 0.991 |
| Nemotron holdout split (1,293) | 353 | 1,201 | 1,207 | 0.996 / 0.991 / 0.993 |
| Gretel `val` (668) | 83 | 313 | 321 | 0.913 / 0.912 / 0.919 |
| Gretel holdout split (620) | 86 | 251 | 257 | 0.915 / 0.928 / 0.924 |
| Mendeley `val` (633) | 126 | 605 | 611 | 0.990 / 0.856 / 0.856 |
| Mendeley holdout split (726) | 120 | 679 | 683 | 0.989 / 0.864 / 0.864 |

- **No span got worse** in any file, with either model.
- **Privy's PII recall** goes from 0.225 to 0.664 (fp32) and 0.665 (int8). Names whole: 4.4 % to 63.7 %, the same as
  the full Privy run of the first experiment (63.5 %), on a sample that is independent of its split.
- **int8 costs no accuracy here:** it finds as many names as fp32 and its precision is within 0.004.
- **Mendeley:** the layer adds about 330 false positives per split. In the first experiment 738 of D3's 868 such false
  positives on Mendeley were a PERSON for spaCy too: names the dataset does not label.
- Nemotron's holdout split: the first runs of both models failed on one document of 528 word pieces (the model reads
  512). The worker now cuts such a piece (`a5fd1ff3`), and the row above is the run after the fix.
- **Privy in full** (8,121 names, totals only): fp32 ONNX 5,157 names whole, the same number as D3 with torch; int8
  5,161. PII recall 0.671 for both; precision (V3) 0.941 (fp32) and 0.952 (int8), against 0.992 without the layer.

### B3: developer text (the false-alarm bank)

`bench/ner/devtext.py` cuts the developer bank (`scripts/measure_fp_bank.py`'s trees and the tickets) into the
categories below and counts each PERSON span the layer adds beyond the deterministic result, with a coarse label of
its context. Counts only; no span is printed. D3 as fp32 and as int8 ONNX:

| Category | Added spans, fp32 | Added spans, int8 | Most of them (fp32) |
|---|---:|---:|---|
| Python code (2.2 MB) | 49 | 45 | identifiers 16, comments 12, prose 12, author lines 9 |
| JS/TS code | 16 | 17 | author or copyright lines 15 |
| Tests and examples | 19 | 15 | identifiers, paths or literals 19 |
| Configuration (2.3 MB) | 3 | 7 | |
| Logs (2 MB) | 0 | 5 | |
| Stack traces | 22 | 22 | prose of the message 21 |
| Tickets | 6 | 6 | |
| Technical documentation (2 MB) | 120 | 111 | comments 56, identifiers 36, prose 16, handles or URLs 11 |
| All | 235 | 228 | |

An author or copyright line names a real person, so a mask there is right for the layer and harmless for the code.
The rest are false positives: capitalised identifiers and words in docstrings. int8 adds about as many (228 against
235), but 5 of them in log lines, where fp32 adds none.

### B4: cost in a service

The layer runs as a service of its own (`bench/ner/sidecar.py`, a Unix socket, the model loaded once); the hook
asks it over the socket. `bench/ner/perf_service.py` measures it from the client side on 300 Nemotron documents
(272 KB). Measured twice: on 2026-10-22 at a load average of 2 to 4 (the machine without benchmark runs), and on
2026-10-21 at 4 to 6 (other benchmark runs) in brackets:

| | int8 ONNX | fp32 ONNX |
|---|---:|---:|
| Start to ready (model files in the page cache), and a restart | 0.27 s, 0.18 s (0.23, 0.23) | 0.30 s, 0.28 s (0.31, 0.36) |
| First request | 12 ms (13) | 13 ms (14) |
| Per document, median / 95th percentile | 16 / 42 ms (22 / 62) | 18 / 49 ms (30 / 75) |
| 1,000 short requests in a row, median / 95th | 1.8 / 2.0 ms (2.2 / 2.3) | 2.8 / 3.5 ms (3.8 / 9.7) |
| 2 / 4 / 8 clients at once, median per request | 32 / 72 / 156 ms (46 / 105 / 224) | 39 / 87 / 194 ms (58 / 125 / 268) |
| Throughput with several clients | 54 documents/s (37) | 43 documents/s (31) |
| A request after 60 s idle | 37 ms (23) | 49 ms (25) |
| One input of 1 MB | 22 s (29) | 25 s (36) |
| Memory: after the run / highest seen | 327 / 431 MB (341 / 431) | 714 / 1,341 MB (723 / 1,342) |

The service answers one request at a time, so parallel hook calls wait in line; it keeps its speed over 1,000
requests and after an idle minute. A 1 MB tool result takes half a minute, so a product needs a size limit per hook
call (the budget of B5 already returns the deterministic result when time runs out).

### B5: the real hook path

`bench/ner/hook_layer.py` wraps the detector of a real checkout (`core.scan`; `detect` is the same module) so that
the deterministic result comes first and the layer may only add a PERSON span where no finding lies.
`bench/ner/hook_experiment.py` sends 395 tool results (the bank's dev cases, 200 Nemotron val cases of the V3 sample,
120 developer texts; 669 KB) through the real PostToolUse hook of 0.7.3, each run in a new temp home. One time budget
of 300 ms per hook call, not per scan: a hook call scans about five texts (the output, its parts, the name
check), and a budget per scan let one call wait 1.6 s.

| Proof | Result (int8, under load) |
|---|---|
| The layer installed and switched off answers byte for byte as without it | yes, 395 of 395 |
| The service 2 s slow: every answer as without the layer | 395 of 395; the slowest call 339 ms |
| The service dies after 20 requests: every answer as without it, no error text | 395 of 395; the slowest call 107 ms |
| The service answers nonsense | 395 of 395 |
| The layer on: every placeholder type of the answer without the layer is still there | yes, in all 395 |
| The layer on: a value of a deterministic hit in the text the model gets that the answer without the layer does not show in plain text | 0. A count of hits gave 1 (`de-tax-id`): that tax id is in plain text in both answers (the hook of 0.7.3 leaves it in that test home), and a rule with a context word finds it next to a new placeholder only. The experiment now compares the values, in memory |
| The layer on: names added | 48, with 557 of 1,975 scans out of time under the load |
| The same run at a load average of 2 to 5 | 94 names added, no scan out of time; a hook call takes 39 to 55 ms median, 152 to 210 ms p95, 235 ms at most in two runs (6 to 8 ms median without the layer); the other proofs as above |

So the layer cannot make a finding worse, a slow, failing or broken service changes nothing, and switched off it is
invisible. `bench/ner/hook_experiment.py` exits with 1 when any of these promises fails (codex Gate A asked for it:
the first version only wrote the numbers). Since codex Gate A, `install()` also gives each real hook call its one
budget; before, the experiment set it by hand. The cost multiplier is the number of scans per hook call (about five), which a product would cut to one
request per call.

### B6: packaging

A second environment (no package goes into the plugin folder), measured with a fresh venv per Python:

- onnxruntime 1.31 needs Python 3.11 or newer; it has wheels for macOS arm64, Linux x86_64 and aarch64 (glibc 2.28)
  and Windows amd64 and arm64. No 1.31 wheel for macOS x86_64.
- Python 3.9 gets onnxruntime 1.19.2, which runs the model. Python 3.15 has no wheel yet.
- The environment is about 175 MB, plus 135 MB for the int8 model.
- Offline: a run with the network blocked in the process made 0 network attempts on 3.9, 3.11 and 3.14.

## The decision (Phase D, 2026-10-21)

### The matrix

Recall and precision: Privy, V3 sample 1 in 10 (B2). Developer FP: added PERSON spans on the developer text of B3
(about 12 MB); the deterministic core's own false alarms are on another bank (`scripts/measure_fp_bank.py`) and are not
the same unit. RAM and latency: one model process; the times of the torch models are from the idle machine of
"Cost", the ONNX times from B4 (the service, at a load average of 2 to 4).

| Option | Recall (Privy names whole / PII) | Precision (Privy PII, V3) | Developer FP | RAM | Latency per document | Install size | Complexity | Recommendation |
|---|---|---|---|---|---|---|---|---|
| Deterministic only (0.7.3) | 4.4 % / 0.225 | 0.992 | – (the rules' own bank) | the hook process | 0.25–9.8 ms | the plugin, standard library | low | the default, unchanged |
| + D3 (torch) | 63.5 % (full Privy) | as fp32 ONNX | as fp32 ONNX (the same spans) | 0.7 GB | 33 ms median, 88 ms p95 | about 1.4 GB (torch 587 MB) | high | no: ONNX gives the same spans without torch |
| + D3 ONNX fp32 | 63.7 % / 0.664 (full: 63.5 % / 0.671) | 0.932 (full: 0.941) | 235 | 1.3 GB peak | 18 ms median, 49 ms p95 | about 175 MB + 539 MB | medium | no: int8 is as accurate at a quarter of the model |
| + D3 ONNX int8 | 63.8 % / 0.665 (full: 63.6 % / 0.671) | 0.935 (full: 0.952) | 228 (5 in logs) | 0.43 GB peak | 16 ms median, 42 ms p95, start 0.27 s | about 175 MB + 135 MB | medium | **opt-in prototype** |
| + GLiNER (high recall) | 96.2 % (full Privy) | – | not measured | 3.5 GB | 152 ms median, 411 ms p95 | about 2 GB | high | not now: 75 times D3's false positives on Privy |

### The answers

1. **Does the core generalise?** Yes, within its scope. The rules of 0.6.40 to 0.7.3 were written from `dev` and hold
   on `val` and on the public holdout split within two points (docs/BENCHMARK-V3.md). On the independent Holdout V2,
   0.7.4 has recall 0.626 and precision 0.9955. Its weak classes there: names (5 of 48), connection strings and URL
   credentials (masked in part), passwords, user names and tax ids (half).
2. **How reliable is V3?** Reliable for the comparison of releases and of splits: salted samples, a fixed scope per
   dataset, case hashes, and a holdout written without a miss list. Its limits: samples of 300 to 800 documents per
   split; the public holdout split was read once (2026-10-19); Privy's labels are not exhaustive; Holdout V2 has one
   run and is template text.
3. **D3 on independent data:** Privy names whole from 4.4 % to 63.7 %, PII recall 0.225 to 0.664, precision (V3)
   0.992 to 0.932. No span got worse.
4. **Is ONNX/int8 usable?** Yes. fp32 ONNX gives the spans of the torch model; int8 is as accurate on V3 (508 against
   507 names on Privy) with a 135 MB model and no torch.
5. **Developer false positives:** about 230 added spans in 12 MB of developer text, most in documentation (comments,
   identifiers) and author lines; 5 in log lines with int8. Acceptable for a layer a person switches on, not for a
   default: a capitalised identifier in pasted code would become a placeholder.
6. **The cost in the real hook:** the layer cannot make a result worse, and a slow, failing or broken service changes
   nothing (B5). At a moderate load a hook call takes 39 to 55 ms median and 152 to 210 ms p95 with the layer, against 6 to 8 ms
   without it, and no scan runs out of the 300 ms budget; under heavy load 557 of 1,975 scans did, and the hook then
   answers as without the layer. A hook call scans about five texts, so a product should ask the service once per
   call.
7. **Is a simple local install realistic?** Yes, as an opt-in step: one second environment of about 310 MB (int8),
   pinned wheels and model sha256, offline after the install, Python 3.9 to 3.14 on macOS arm64, Linux and Windows.
   Gaps: no onnxruntime 1.31 wheel for Intel Macs and none yet for Python 3.15.
8. **Reject, experimental, opt-in prototype or high-recall mode?** An **opt-in prototype** with D3 int8. Not on by
   default; a high-recall mode (GLiNER) is not worth its false positives now.
9. **The next block:** the opt-in prototype outside the public API: the sidecar of B5 as an installable extra, one
   request per hook call, an install command with the pinned model, and the quiet cost measurement. The record layer
   (category C) continues as small measured rule changes beside it.
10. **The 0.8 decision:** 0.8 makes the detection contract explicit and additive (`docs/DETECTION-CONTRACT-PROPOSAL.md`):
    a published type vocabulary, an optional `fields` argument for structured context, a JSON entry point with the
    conformance runner on it, offsets defined as code points, and the announced deprecations. No NER seam in the
    public API in 0.8: the contract's optional `confidence` and `provenance.layer` already leave room for a model
    layer, so the prototype of answer 9 needs no API change.

### Open after this block

- B4 on Windows and Linux.

## The remote path (2026-10-29)

The layer is now a part of the library (`maisecrets/detection/remote.py`, docs/DETECTION.md "A remote detector"):
a service in the Hugging Face or the Presidio format, asked after the rules, and in the plugin the setting
`remote_detector` for tool results. Two questions, measured on maisecrets at `f6e0a21d` with D3 as fp32 ONNX
(`bench/ner/export_onnx.py` of the snapshot `d421f57d`, `model.onnx` sha256 `1e1535af…`), served by
`examples/ner_service.py`, on the salted V3 samples (`--sample-salt v3/`): `val` of Nemotron, Gretel and Mendeley
1 in 25, and Privy 1 in 10 (totals only). The holdout split was not read.

**Does the remote path lose or add anything against the experiment's layer?** No. `bench/adapters/maisecrets_remote.py`
with `BENCH_REMOTE_MASK=0` (the whole text, as the experiment's model read it) against `bench/adapters/maisecrets_ner.py`
with the same model: the same spans with the same scores in 4,346 of 4,346 cases, and so the same numbers.

**What does the filler cost?** The library sends each finding of the rules as `_` of the same length. The model then
finds a few names fewer, in every set:

| Data | Names whole: rules alone | + D3, whole text | + D3, with filler | PII false positives: whole text / filler |
|---|---:|---:|---:|---|
| Nemotron `val` (1,159) | 365 | 1,054 | 1,044 | 15 / 14 |
| Gretel `val` (668) | 91 | 316 | 314 | 74 / 74 |
| Mendeley `val` (633) | 126 | 605 | 600 | 334 / 326 |
| Privy 1 in 10 (796) | 41 | 507 | 503 | 391 / 391 |

21 of 2,482 names, and 9 false positives fewer; no span worse in any variant (`bench/ner/analyze.py`). So the filler
stays the default, the one path for every service, and a service on loopback or a Unix socket may read the findings
as they are (`"mask": false` in the setting); any other host always gets the filler.

The 0.7.3 rows of B2 are not this table's baseline: the rules changed since, so "rules alone" is measured again.

## Repeat

```bash
git worktree add --detach ../ms-0.7.3 v0.7.3                    # the release under test
# the environments (Python 3.11), every distribution pinned
python3.11 -m venv ner-spacy && ner-spacy/bin/pip install --no-deps -r bench/adapters/requirements/ner-spacy.txt
python3.11 -m venv ner-torch && ner-torch/bin/pip install --no-deps -r bench/adapters/requirements/ner-gliner.txt
# the models, once, into a cache of their own; the runs read it offline
HF_HOME=hf ner-torch/bin/python -c "from huggingface_hub import snapshot_download as d
d('urchade/gliner_multi-v2.1', revision='443d26d654e0324125a96bebd8e796c14ff2efe6')
d('microsoft/mdeberta-v3-base', revision='a0484667b22365f84929a935b5e50a51f71f159d',
  allow_patterns=['config.json', 'spm.model', 'tokenizer_config.json'])
d('dslim/distilbert-NER', revision='dfa2838a127384aabb82ed7719e16dab84c42a2a')
d('Davlan/distilbert-base-multilingual-cased-ner-hrl', revision='d421f57d5b1d36b375408588669e9340f9b11a89')"
# one variant on one dataset; BENCH_NER: spacy:en_core_web_sm | spacy:en_core_web_lg | gliner:<dir>:0.5 | hf:<dir>::first
# | hf:<dir>::snap (D3)
HF_HOME=hf BENCH_NER_PYTHON=ner-torch/bin/python BENCH_NER=hf:<model dir>::first \
  BENCH_NER_SIDECAR=OUT/nemotron-all-every50-ner.jsonl \
  python3 bench/run.py --scanner maisecrets_ner --maisecrets ../ms-0.7.3 --source nemotron --split all --every 50 \
  --out OUT/nemotron-all-every50-maisecrets.json
python3 bench/run.py --scanner maisecrets --maisecrets ../ms-0.7.3 --source nemotron --split all --every 50 \
  --out BASE/nemotron-all-every50-maisecrets.json                 # the baseline
python3 bench/ner/analyze.py BASE OUT --maisecrets ../ms-0.7.3 --json analysis/D2.json
python3 bench/ner/tables.py analysis > analysis/tables.md
python3 bench/ner/rest_dump.py BASE OUT rest.jsonl ../ms-0.7.3 nemotron-all-every50-maisecrets.json
ner-spacy/bin/python -I bench/ner/rest_label.py rest.jsonl
HF_HOME=hf ner-torch/bin/python -I bench/ner/perf.py hf:<model dir>::first TEXTS.jsonl   # the cost
```

The sidecars of the full runs of A and B are not kept (about 9 MB); the commands above write them again. Privy runs
the same way with `--source privy`; its sidecars are not kept either, and no script here reads a Privy case.
