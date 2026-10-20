# Detection spec and conformance: how far the core is from a language-neutral spec (draft, 2026-10-20)

This is an analysis, not a plan to port. It asks: which parts of `maisecrets/detection/` are data today, which are
Python, how few semantic primitives would describe the rest, and how a conformance suite could tell a second
implementation from a wrong one. Nothing here changes the runtime.

Measured on `next` at the street change (`47a45117`), all regions and six languages active: 631 rules in the rule list
and 45 specs of passes outside it (`detection.core.rule_specs`, `pass_specs`).

## 1. What is declarative today

| Part | Where | Count | Language-neutral already? |
|---|---|---|---|
| Rule identity: key, id, source, origin, priority (phase, band, seq), channel, region, type, class, form | `rulespec.RuleSpec`, `registry.py` | 676 specs | yes: plain fields |
| The regex of a rule | `Rule.regex` | 658 of 676 run as plain `finditer` (`matcher_of`) | almost: Python `re` syntax; 416 betterleaks rules come from RE2 through `re2_to_python` |
| Keywords (the cheap prefilter) | `Rule.keywords` | most vendored rules | yes |
| Secret group, entropy floor | `Rule.secret_group` (30 rules), `Rule.entropy` (7) | | yes |
| Upstream origin and digest, patches with reason | `Upstream`, `Patch` | 521 with upstream, 58 patched | yes |
| Named filters | `registry.FILTERS`, `PREFIX_FILTERS` | 34 rules, 18 filter names | the **name** is data, the check is Python |
| Validators | `Rule.validator` | 72 rules, 40 validators | the **reference** is data, the check is Python |
| Rule limits | `docs/rule-limits.json` | | yes |
| Regions and languages | `regions.py` | 13 regions, 58 types | yes |

## 2. What is Python semantics today

| Part | Size | Why it is code |
|---|---|---|
| Validators (`checksums.py` and `core`) | 40 functions | check digits (Luhn, IBAN mod 97, ICAO, PESEL, NIF/NIE, NHS, ABA, NPI, AHV, UID, codice fiscale), Base58Check (WIF, xprv), BIP39, value checks (`ds_value`, `word_value`, `token_not_words`) |
| Filters | 18 functions | context of the hit: escaped quotes, constant names, templates, SigV4 scope, `user=password` |
| Non-regex matchers | 8 (`lines`, `windowed`, `curl`, `list`, `literal`, `seed`, `term`, `import`) | per-line state, windows around keywords, shell parsing, a judge of a literal password, an index of listed terms |
| Personal pass (`personal.py`) | 32 forms (20 after a label, 12 by form), about 2,000 lines | record parsers (CSV, Markdown, SQL, HTML, JSON, XML), word lists, name and address judgement, company windows, widening (`ONLY_WIDENS`, a place after a street) |
| Normalisation | 7 stages (`unfold`, `entity`, `ansi`, `invisible`, `fullwidth`, `emphasis`, `decode`) with an offset map | the hits are found on a cleaned copy and mapped back |
| Overlap and order | `_scan`: leftmost first, the first rule to claim a span wins, in priority order; passes (personal, terms, imports) fill only free space; a personal form in `ONLY_WIDENS` counts only when it overlaps another hit | a stateful walk |
| Fixtures and allow list | `is_fixture`, the allow list of `Sources` | a second scan of the value in the prompt channel |

## 3. The semantic primitives

The 676 specs and the passes reduce to about 30 primitives. Each is a small, testable unit of meaning.

**Matching (6):** `regex` (with a value group), `literal-list` (terms, imports), `keyword-prefilter`,
`line-scoped` (a match that ends at its line), `keyword-window` (a long text read in windows around keywords),
`structured-field` (a record field: name, value, row; CSV, Markdown, SQL, HTML, JSON, XML give it).

**Context (6):** `label-before` (a label word and a separator before the value), `context-before` /
`context-after` (a word within n characters), `not-in-code-context` (`example:` keys, a constant name, a template),
`company-window` (a company, a hotel, an office on the line or the two lines before), `person-anchor` (a row or
record that holds a strong person field).

**Value checks (9):** `digit-boundary`, `whole-token`, `checksum:<algorithm>` (luhn, iban-mod97, icao, pesel, nif,
nhs, aba, npi, ahv, uid, codice-fiscale, base58check, bip39), `entropy-floor`, `not-placeholder` (the placeholder
lists, `999`, `[City]`), `not-words` (a value of dictionary words), `name-shape`, `phone-shape`, `date-shape`.

**Span building (5):** `widen-existing` (a hit grows over a direction, a unit, a place; never starts one),
`only-widens` (a form that counts only on an existing hit), `trim` (the stop of a sentence, a quote, Markdown stars),
`value-end` (where a value ends: separator, line end, sentence end), `cut-at-next-label`.

**Resolution (3):** `priority-order` (phase, band, seq), `first-claim-wins` (leftmost, no overlaps),
`pass-fills-free-space`.

**Input (2):** `normalise-with-offset-map` (the 7 stages), `channel` (prompt or tool: a tool result takes more forms).

About 31 primitives. Of these, about 20 are stable enough for a v1: the matching and resolution primitives, the
checksums, `digit-boundary`, `whole-token`, `label-before`, `value-end`, `widen-existing`, `only-widens`,
`entropy-floor`. The rest change with almost every detection release today (the word lists, `not-words`,
`name-shape`, `company-window`, `person-anchor`) and should stay Python-specific in a v1: a second implementation
would call them through the conformance cases, not re-derive them from prose.

## 4. A conformance case format

```json
{
  "id": "street-direction-after-label-001",
  "kind": "normative",
  "input": "Street Address: 12 Oak Street SW\nCity: Springfield",
  "channel": "tool",
  "regions": ["generic", "us"],
  "languages": ["en"],
  "host": {"user": "someone", "year": 2026},
  "sources": {"user_rules": [], "allow": []},
  "expected": [
    {"start": 16, "end": 32, "type": "ADDRESS", "rule": "address-street-after-label", "primitive": "widen-existing"}
  ],
  "not_expected": [{"start": 33, "end": 50, "type": "ADDRESS"}],
  "why": "a direction after the street type belongs to the street (BENCHMARKS.md, 2026-10-20)"
}
```

- `kind`: `normative` (a second implementation must give exactly this) or `snapshot` (a regression record of this
  implementation; a difference is a finding to explain, not a failure of conformance).
- `expected[].rule` is optional and informative: conformance is judged on `start`, `end` and `type`. A port may
  name its rules differently.
- `not_expected` holds the boundary: the part that must stay text. Most of the value of a case is there.
- `why` points to the measurement or decision behind the case.

## 5. Where the cases come from

| Source | Kind | Count today (estimate) | Note |
|---|---|---|---|
| Unit tests with an exact span (`text.replace(value, "•") == masked(text)`) | normative | a few hundred | the strongest source; many tests today only check "not in the masked text", which a partial mask also passes (seen on 2026-10-20). A first step is to tighten them |
| Boundary tests (`… Street 3 days a week` stays text) | normative | | each widening has some |
| Region and channel cases | normative | | the same text in two regions, two channels |
| User-rule cases (`user_rule`, `ValueError`) | normative | | the public API |
| Structure cases (CSV, Markdown, SQL, HTML, JSON, XML) | normative | | one per format and per policy decision |
| The detection fingerprint (27,337 + 23,729 inputs) | snapshot | about 51,000 | **not** a standard: it records what this implementation does, including its known errors (`docs/rule-limits.json`) |

## 6. Recommendation

A spec-v1 block is useful once two things hold. First, the tests that state an exact span are a clear, tagged set
(`normative`); today exactness is spread over many test files and some tests cannot fail on a partial mask. Second,
the word-list primitives (`not-words`, `name-shape`) stop moving every release. Until then, the cheapest step with
lasting value is the first one: tag and tighten the exact-span tests, and export them in the case format above as a
by-product. That makes them useful for this implementation now and for a second one later.
