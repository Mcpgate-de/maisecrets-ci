"""The PERSON layer of the NER experiment (docs/NER-EXPERIMENT.md). It runs in the Python of the NER environment, never
in maisecrets, and sees one case per input line: the text and the spans the deterministic detector already found.

    python -I person_worker.py IN OUT BACKEND

BACKEND is `spacy:<model package>`, `gliner:<model directory>:<threshold>` or `hf:<model directory>[::<aggregation>]`
(a token classifier, its PER entities; aggregation `simple` by default, `first` keeps whole words,
`snap` widens the spans of `simple` to whole words). The model reads the
whole text, so its context is the same as without the layer; a PERSON span it returns is kept only when it overlaps no
span of the deterministic detector (that span decided the text there; a finding is never made smaller, moved or
retyped). OUT gets,
per case, the kept spans `[start, end, score]` and the types of the deterministic findings a dropped span overlapped.
stdout gets the timing and the memory. No network: the model is a local package or directory."""
from __future__ import annotations

import json
import re
import sys
import time

GLINER_WORDS = 200      # tokens per chunk: GLiNER reads 384 words and its encoder 512 pieces, and drops the rest
                        # without a word (a name late in a long text is never seen)
TOKEN = re.compile(r"\w+(?:[-_]\w+)*|\S")   # how GLiNER splits words
BERT_WORDS = 100


def _chunks(text: str, limit: int = GLINER_WORDS):
    """(start, end) pieces of whole lines, each at most `limit` tokens; a longer line is cut between tokens."""
    out, start, words = [], 0, 0
    for m in re.finditer(r"[^\n]*\n?", text):
        if not m.group(0):
            continue
        n = len(TOKEN.findall(m.group(0)))
        if words and words + n > limit:
            out.append((start, m.start()))
            start, words = m.start(), 0
        if n > limit:
            spans = [w.span() for w in TOKEN.finditer(m.group(0))]
            for i in range(0, len(spans), limit):
                a = m.start() + spans[i][0] if i else start
                b = m.start() + spans[min(i + limit, len(spans)) - 1][1]
                out.append((a, b))
            start, words = m.end(), 0
            continue
        words += n
    if start < len(text):
        out.append((start, len(text)))
    return out


def disjoint(text: str, found, occupied):
    """The spans of `found` (trimmed of white space) that overlap no occupied span and no span kept before them, and
    the types of the occupied spans the others overlapped."""
    keep, conflicts = [], []
    for s, e, score in found:
        while s < e and text[s].isspace():
            s += 1
        while e > s and text[e - 1].isspace():
            e -= 1
        if s >= e:
            continue
        hit = [o for o in occupied if s < o[1] and o[0] < e]
        if hit:
            conflicts += [o[2] for o in hit]
        elif not any(s < k[1] and k[0] < e for k in keep):
            keep.append([s, e, score])
    return keep, conflicts


def load(backend: str):
    kind, _, arg = backend.partition(":")
    if kind == "spacy":
        import spacy
        nlp = spacy.load(arg, exclude=["parser", "lemmatizer", "attribute_ruler", "tagger", "senter"])
        nlp.max_length = 10_000_000

        def find(text):
            return [(e.start_char, e.end_char, 1.0) for e in nlp(text).ents if e.label_ == "PERSON"]
        return find, {"library": "spacy", "library_version": spacy.__version__, "model": arg,
                      "model_version": nlp.meta.get("version"), "threshold": None}
    if kind == "gliner":
        path, _, thr = arg.rpartition(":")
        threshold = float(thr)
        import gliner
        import torch
        torch.set_grad_enabled(False)
        model = gliner.GLiNER.from_pretrained(path, local_files_only=True)

        def find(text):
            spans = []
            for a, b in _chunks(text):
                for e in model.predict_entities(text[a:b], ["person"], threshold=threshold):
                    spans.append((a + e["start"], a + e["end"], round(float(e["score"]), 4)))
            return spans
        return find, {"library": "gliner", "library_version": gliner.__version__, "torch": torch.__version__,
                      "model": path.rstrip("/").split("/")[-1], "threshold": threshold}
    if kind == "hf":
        import torch
        import transformers
        torch.set_grad_enabled(False)
        path, _, strategy = arg.partition("::")
        strategy = strategy or "simple"
        # `snap`: `simple`, then each span widened to whole words, as the support-copilot's NER layer does
        snap = strategy == "snap"
        pipe = transformers.pipeline("token-classification", model=path,
                                     aggregation_strategy="simple" if snap else strategy, device="cpu")

        def find(text):
            spans = []
            # BERT reads 512 word pieces and drops the rest without a word; 100 tokens stay far below that
            for a, b in _chunks(text, BERT_WORDS):
                for e in pipe(text[a:b]):
                    if e["entity_group"] == "PER":
                        s, t = a + int(e["start"]), a + int(e["end"])
                        if snap:
                            while s > 0 and text[s - 1].isalnum():
                                s -= 1
                            while t < len(text) and text[t].isalnum():
                                t += 1
                        spans.append((s, t, round(float(e["score"]), 4)))
            return spans
        return find, {"library": "transformers", "library_version": transformers.__version__,
                      "torch": torch.__version__, "model": path.rstrip("/").split("/")[-1], "threshold": None,
                      "aggregation": strategy}
    raise SystemExit(f"unknown backend {kind!r}")


def main() -> int:
    inp, outp, backend = sys.argv[1:4]
    t0 = time.perf_counter()
    find, desc = load(backend)
    load_s = time.perf_counter() - t0
    first, times = None, []
    with open(inp, encoding="utf-8") as fin, open(outp, "w", encoding="utf-8") as fout:
        for line in fin:
            case = json.loads(line)
            text, occupied = case["text"], case["occupied"]
            t = time.perf_counter()
            found = find(text)
            times.append(time.perf_counter() - t)
            if first is None:
                first = time.perf_counter() - t0
            keep, conflicts = disjoint(text, found, occupied)
            fout.write(json.dumps({"add": keep, "conflicts": conflicts}) + "\n")
    import resource      # here, not at the top: Windows has no resource module, and the tests import this file
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    json.dump({**desc, "load_s": load_s, "cold_start_s": first, "times_s": times,
               "max_rss_mb": round(rss / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
