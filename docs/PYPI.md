# maisecrets

Find secrets and personal data in text. This package is the detection core of the
[maisecrets plugin](https://github.com/Mcpgate-de/maisecrets) for Claude Code and Codex, as a library without the
plugin.

```bash
pip install maisecrets
```

It needs no other package and runs on Python 3.9 and later.

```python
from maisecrets.detection import Active, Detector, Host, NO_REFERENCES, NO_SOURCES

d = Detector(
    regions=Active(regions=("generic", "de"), languages=("en", "de"), source="mine"),
    sources=NO_SOURCES,
    references=NO_REFERENCES,
    host=Host(user="me", year=2026),
)
text = open("app.log", encoding="utf-8").read()
for m in d.findings(text, channel="tool"):
    print(m.type, m.kind, m.start, m.end)     # e.g. SECRET gitlab-pat 120 146
```

A detector with these four arguments reads nothing of the computer it runs on: no home folder, no config.

## What it finds

- **Secrets** (type `SECRET`): API keys and tokens of many vendors, private keys, passwords and keys after a label,
  credentials in URLs and connection strings.
- **Personal data** (89 types): e-mail addresses, phone numbers, cards, bank accounts, national ID and tax numbers
  of the regions you activate, names and addresses after a label.

It finds by rules, not by a model. It leaves documented test values (a test card, an address at example.com) alone,
and it misses what a rule does not describe. `maisecrets.detection.TYPES` lists every type.

## Links

- [Library documentation](https://github.com/Mcpgate-de/maisecrets/blob/main/docs/DETECTION.md): the API, the
  arguments, the fields of a hit
- [Changelog](https://github.com/Mcpgate-de/maisecrets/blob/main/CHANGELOG.md)
- [Issues](https://github.com/Mcpgate-de/maisecrets/issues)
- License: Apache-2.0
