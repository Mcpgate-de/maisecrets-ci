"""Sort the 'rest' false positives after the fact, without reading them: the entity spaCy en_core_web_lg sees on the
same span (another model, not a truth), and the form of the span. Counts only. Runs in the spaCy environment.

    python -I bench/ner/rest_label.py IN.jsonl > counts.json"""
import collections
import json
import re
import sys

import spacy

nlp = spacy.load("en_core_web_lg", exclude=["parser", "lemmatizer", "tagger", "attribute_ruler"])
PRON = {"he", "she", "him", "her", "his", "hers", "they", "them", "their", "i", "me", "my", "we", "us", "our", "you",
        "your", "someone", "somebody", "everyone", "anyone", "who"}
by_source = collections.defaultdict(collections.Counter)
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    text, s, e = r["text"], r["s"], r["e"]
    v = text[s:e]
    words = re.findall(r"[\w'-]+", v)
    if (s > 0 and text[s - 1].isalnum()) or (e < len(text) and text[e].isalnum()):
        k = "a piece of a word (the span ends inside a word)"
    elif words and all(w.lower() in PRON for w in words):
        k = "pronoun"
    elif v == v.lower():
        k = "lower-case word"
    elif v.isupper() and len(v) > 1:
        k = "all capitals"
    else:
        lab = [ent.label_ for ent in nlp(text).ents if ent.start_char < e and s < ent.end_char]
        if "PERSON" in lab:
            k = "PERSON for spaCy lg too (likely an unlabelled name)"
        elif lab:
            k = "spaCy lg: " + lab[0]
        else:
            k = "capitalised, no entity for spaCy lg"
    by_source[r["source"]][k] += 1
    by_source["all"][k] += 1
print(json.dumps({s: dict(c.most_common()) for s, c in by_source.items()}, indent=1))
