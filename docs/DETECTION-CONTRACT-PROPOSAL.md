# A language-neutral detection contract: analysis and proposal for 0.8 (2026-10-21)

Status: a proposal. Nothing here changes the API or the runtime; the maintainer decides (docs/DETECTION.md, "The API:
the decision of 2026-10-20"). It builds on `docs/DETECTION-SPEC-DRAFT.md` (what is data and what is Python in the
core) and answers a narrower question: what is the smallest stable contract a caller in any language can rely on, and
which parts of today's Python API are convenience around it.

It is deliberately not bound to a vendor format. Presidio's `RecognizerResult` (entity type, start, end, score) shaped
the vendored recognizers, but its entity names, its score and its analyzer configuration are Presidio's; a contract
that copied them would inherit their changes. The proposal below maps to it in a few lines (an adapter), not the
other way round.

## What the contract is for

Three callers need the same answer from different places:

- **the plugin's hooks** (Python, in process);
- **a server consumer** such as the AI Gateway (#1573), which already wraps the core behind its own detector seam and
  asked for an enumerated type, a field-name input and clearer reference semantics (2026-10-21);
- **a second implementation or a test suite** (`tests/conformance/cases.json`), which must tell a right answer from
  a wrong one without reading Python.

## The smallest stable contract

### Request

| Field | Normative | Meaning |
|---|---|---|
| `contract` | yes | the contract version, `maisecrets.detect/1` |
| `text` | yes | a Unicode string; offsets count **Unicode code points** (a UTF-16 caller converts; the contract says so, because `start`/`end` mean nothing without a unit) |
| `channel` | yes | `prompt` (a person typed it) or `tool` (a tool result or a file): the tool channel takes forms a prompt does not |
| `regions` | yes | the country rule sets to load, `generic` plus ISO-style codes (`de`, `us`, …) |
| `languages` | yes | the label languages (`en`, `de`, …) |
| `context.path` | optional | the file the text came from (a password export, a test file) |
| `context.fields` | optional | structured context: see below |
| `exclusions` | optional | spans or literal values the caller says are never a finding (its own references, its placeholders) |

Not in the request, on purpose: the host (user name, year), the sources (rules of your own, allow list, terms,
imported values) and the reference form. They are configuration of an engine instance, not of one call; in the
contract they appear only as the engine's `ruleset` digest in the response, so two answers can be compared.

### Response

| Field | Normative | Meaning |
|---|---|---|
| `contract` | yes | echoes the version |
| `engine` | yes | `name`, `version`, `ruleset` (sha256 of the loaded rule list, regions and sources): the same request and ruleset give the same findings |
| `findings[].start`, `.end` | yes | code point offsets, `start < end`, inside the text |
| `findings[].type` | yes | one value of a closed, versioned vocabulary (below) |
| ordering and overlap | yes | findings are sorted by `start` and never overlap (today's `first-claim-wins`) |
| `findings[].confidence` | optional, informative | absent for a deterministic rule; a model layer may set it. Never normative: a deterministic engine has no calibrated probability, and a threshold on it would differ between engines |
| `findings[].provenance` | optional, informative | `rule` (today's `Match.kind`), `origin` (`builtin`, `user`, `term`, `import`, `model`), `layer` (`deterministic` or `model`) |

`value` is not in the contract: it is `text[start:end]`. A Python `Match.value` stays as convenience.

### The type vocabulary

Today the core emits 60 types: 55 from its rules (measured 2026-10-21, all regions loaded: `SECRET`, `EMAIL`,
`PHONE`, `IP`, `IBAN`, `CARD`, `ABA_ROUTING_NUMBER`, `US_BANK_NUMBER`, `US_SSN`, `DE_TAX_ID`, `UK_NHS`, … 44 country
ids) and 5 from the personal pass (`NAME`, `ADDRESS`, `BIRTH_DATE`, `USERNAME`, `ID_NUMBER`). They are strings with no
published list; the gateway asked for one. The proposal: a published list (`types.json`), each type with a family
(`secret`, `pii`) and a class (`pii.phone`, `pii.national_id`, … the classes of the benchmark), and the rule that a
new type is added in a minor version and a type is never renamed or removed within a major version.

## Structured context: when the field name carries the meaning

A value such as `0171 4829173`, `X1234567` or `hunter2` means little alone; `{"telefon": "…"}`, `passport_no=…` or
`password: …` makes it sensitive, and `build_number: …` makes a similar value harmless. The core reads field names
today, but only by parsing them out of the text itself (JSON, XML, CSV, Markdown and SQL parsers in `personal.py`,
`label-before` in the rules). A caller that already has the structure (the gateway walks JSON responses with a field
path; a log pipeline has key-value records) loses it when it flattens the record to text, and the core then guesses
it back.

The contract carries it as spans with names, not as a second data model:

```json
"context": {
  "fields": [
    {"start": 12, "end": 24, "name": ["customer", "telefon"], "format": "json"},
    {"start": 41, "end": 49, "name": ["passport_no"], "format": "env"}
  ]
}
```

- `start`/`end` is the span of the **value** in `text`; `name` is the field path, outermost first, as the caller's
  data has it (no normalisation by the caller); `format` is informative.
- **Semantics, normative:** a field span is evidence like a label before the value. It may make a value a finding
  that would not be one bare (`telefon` → `PHONE`), and it may hold one back (a field the engine knows as
  non-sensitive). It never moves a finding outside the span, and a finding the engine makes without the field stays
  a finding (the field adds evidence, it does not veto a detector shape: a token in a field named `example` is still
  a token, as today).
- **Without `fields`** the engine parses the text as today. With them it uses the caller's structure first. The field
  lexicon itself (which names mean what) is engine data, not contract: it changes with releases, as the word lists do.

This is also where the record-field misses of the benchmark (category C, about 8 % of what 0.7.3 misses) would be
taken: one declarative field lexicon read by both the text parsers and `context.fields`.

## The conformance cases

`tests/conformance/cases.json` already has the shape: `input` (text), `channel`, `regions`, `languages`, `expected`
and `not_expected` spans judged on `start`, `end` and `type`, an informative rule id, and `why`. To become the test
suite of the contract it needs four things, none of them an API change:

1. `contract: "maisecrets.detect/1"` and the code point rule stated in the file;
2. an optional `context` per case (path and fields), with cases where only the field decides (`{"telefon": …}` in,
   `{"build_number": …}` out);
3. `exclusions` cases (a caller's placeholder is never a finding);
4. a runner that speaks only JSON (a request in, a response out), so a second implementation or a server can run the
   same file. Today `tests/test_conformance_cases.py` calls the Python API.

## What is Python convenience and what is contract

| Today's Python API | Contract or convenience |
|---|---|
| `Detector(regions, sources, references, host)` | convenience: an engine instance; its configuration becomes the `ruleset` digest |
| `Detector.findings(text, channel, path)` | the contract's call (with `context.path`); `scan` is the same without the fixture filter |
| `Match.start`, `Match.end`, `Match.type` | contract |
| `Match.kind` | contract as informative `provenance.rule`; not normative (a port may name rules differently) |
| `Match.value` | convenience (`text[start:end]`) |
| `Active`, `resolve_regions` | `regions`/`languages` are contract; the resolution from a locale is convenience |
| `Sources`, `user_rule`, `Rule` | engine configuration, not the call contract; `user_rule` is a stable Python helper |
| `References` | the contract's `exclusions`: today a reference form is "never a finding" and nothing else (the gateway's point 7) |
| `Detector.rules`, `allow_list`, `explain_allowed`, `slowest_user_rule`, `activate`, `reset` | convenience and diagnostics |

## What is 0.8-worthy, and what to avoid

**Worth a minor version (additive; the stable names keep working):**

1. **A published type vocabulary** (`maisecrets/detection/types.json` and a constant), with family and class per type.
   It answers the gateway's request and makes the benchmark's class mapping data instead of an adapter dict.
2. **`context.fields` as an optional argument** of `Detector.findings` (`fields=[(start, end, ("customer",
   "telefon"))]`), first used by the record layer. Additive and testable through conformance cases.
3. **A JSON entry point** (`python -m maisecrets.detection < request.json`) that speaks the contract, and the
   conformance runner on it. It lets a non-Python consumer and a second implementation use the same cases.
4. **The deprecations already announced:** `LazyRegex` removed; `TypeError` for a non-`str` text (parked for 0.8).
5. **Offsets defined as code points** in docs/DETECTION.md, with a test on a text with astral characters (an emoji
   before a value), since a UTF-16 caller is the likeliest second consumer.

**To avoid in 0.8:**

- binding the contract to Presidio's names or its score;
- a normative `confidence`;
- exposing the rule tables, priorities or `Rule` construction as API (they change with the rules; `user_rule` stays
  the one way in);
- a model or NER seam in the API before the NER decision (docs/NER-EXPERIMENT.md): the contract already has room for
  it (`provenance.layer`, optional `confidence`), so nothing has to change when a layer comes;
- changing `Match` fields or the behaviour of `References` without the deprecation path of docs/DETECTION.md.

## An example request and response

```json
{
  "contract": "maisecrets.detect/1",
  "text": "{\"customer\": {\"telefon\": \"0171 4829173\", \"build_number\": \"20261021\"}}",
  "channel": "tool",
  "regions": ["generic", "de"],
  "languages": ["de", "en"],
  "context": {"fields": [{"start": 26, "end": 38, "name": ["customer", "telefon"], "format": "json"},
                         {"start": 58, "end": 66, "name": ["customer", "build_number"], "format": "json"}]}
}
```

```json
{
  "contract": "maisecrets.detect/1",
  "engine": {"name": "maisecrets", "version": "0.8.0", "ruleset": "sha256:…"},
  "findings": [
    {"start": 26, "end": 38, "type": "PHONE",
     "provenance": {"rule": "phone-after-phone-word", "origin": "builtin", "layer": "deterministic"}}
  ]
}
```

The second field stays text: its name marks a build number, and the value has no shape of its own. Measured on `next` after !196 without `fields` (the core parses the JSON itself): exactly this finding, `phone-after-phone-word` 26–38. The `fields` would let a caller that already has the structure say the same without the parse.
