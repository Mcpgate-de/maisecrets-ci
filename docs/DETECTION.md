# The detection core

`maisecrets/detection/` is the detector: it finds secrets and personal data in text. It holds no plugin, no home
folder and no reference form of its own. The plugin gives those to it; a library caller can give its own.

## Use it as a library

`pyproject.toml` builds the core as a wheel. It holds `maisecrets/__init__.py` and `maisecrets/detection/` with its
rule data, and no module of the plugin. It needs no other package and runs on Python 3.9 and later. It is not on PyPI:

```bash
python3 -m pip wheel --no-deps -w dist .        # dist/maisecrets-<version>-py3-none-any.whl
python3 -m pip install dist/maisecrets-*.whl
```

The version is the plugin's version (`.claude-plugin/plugin.json`); a wheel from `main` or a tag has the released
one. `importlib.metadata.version("maisecrets")` gives it. Without the plugin modules, each argument left `None` takes
no config, no sources and no reference form: a detector from the wheel never reads the home folder.

```python
from maisecrets.detection import Active, Detector, Host, NO_REFERENCES, NO_SOURCES

d = Detector(
    regions=Active(regions=("generic", "de"), languages=("en", "de"), source="mine"),
    sources=NO_SOURCES,          # rules of your own, allow list, term lists, imported values: a Sources object
    references=NO_REFERENCES,    # how the caller writes a reference into text: a References object
    host=Host(user="me", year=2026),
)
for m in d.findings(text, channel="tool", path="notes.txt"):
    print(m.kind, m.type, m.start, m.end)
```

- **Each argument left `None`** takes the plugin's default when the plugin is there: the config of this computer,
  the readers of the home folder (`maisecrets/sources.py`), the placeholder form (`maisecrets/placeholder.py`), and
  this computer's user name and year.
- **A detector with all four given** reads nothing of the host and imports no module of the plugin
  (`tests/test_detection_package.py` shows this in a fresh process).
- **Two detectors in one process** keep their own rule lists, allow lists and caches, also in two threads and one
  inside a scan of the other (`tests/test_detector.py`).
- **A function given as `regions`** is asked when the rules load: the first scan and each `reset()`. A changed config
  takes effect at `reset()`. `regions()` names the regions that the rule list was loaded for.
- **`with d.activate():`** makes every function of the module in this thread use `d`, for a caller (such as a hook)
  that calls `maisecrets.detect.scan` directly.

## The API

`maisecrets.detection.__all__`:

| Name | What |
|---|---|
| `Detector` | A detector with its own configuration: `scan`, `findings`, `rules`, `allow_list`, `explain_allowed`, `regions`, `reset`, `slowest_user_rule`, `activate`. `scan` and `findings` take the text as a `str` (a subclass of `str` too) and raise `TypeError` for anything else, `bytes` and `None` included (since 0.8). They take an optional keyword argument `fields` (since 0.8, additive): the field names of values in the text, below |
| `Match` | One hit: `kind` (the rule id), `type`, `value`, `start`, `end`. `start` and `end` count the Unicode code points of the `str` that was scanned, and `text[start:end] == value` |
| `Sources`, `NO_SOURCES` | What a scan takes besides the built-in rules |
| `References`, `NO_REFERENCES` | The reference form of the caller |
| `Host`, `THIS_COMPUTER` | What a scan reads of its computer |
| `Active`, `resolve_regions` | The regions and label languages, and their resolution from a config (`locale=` to give the locale) |
| `user_rule` | A rule of your own, for `Sources.user_rules` (returns a `Rule`) |
| `TYPES` | The type vocabulary: each type a `Match` can carry, with its `family` and `class` (`maisecrets/detection/types.json`) |

The rule tables and the helpers of `core.py` are no API: they change with the rules.

`core.py` keeps four parts in modules of their own, so that each file stays readable: `value_checks.py` (the
checks of a value), `own_rules.py` (`OWN_RULES`, `FALLBACK_RULES`), `text_index.py` (the index of a text and the
test-code check) and `encoded_mail.py` (an address with its @ as %40). `core.py` imports each of their names, so
`core.<name>` is the same object. A patch of such a name on the core does not reach the functions of the part:
patch the module that defines the name.

## Field names: `fields` (since 0.8)

A caller that has the structure of its data (a JSON response walked with a field path, a key-value record) can give
the field name of a value with the text, instead of the core guessing it back from the text:

```python
d.findings("0171 4829173", channel="tool", fields=[(0, 12, ("customer", "telefon"))])   # one PHONE, 0-12
d.findings("0171 4829173", channel="tool")                                            # no hit
```

- **The shape:** a list or tuple of `(start, end, name)`. `start` and `end` are the span of the value in code points
  of the text, `0 <= start < end <= len(text)`; `name` is the field path, outermost first, a tuple (or list) of `str`
  and `int` parts. A wrong shape raises `TypeError`, an offset outside the text `ValueError`; the message names the
  position (`fields[1]`) and never a part of the text or of a name. Fields may overlap.
- **What a name does:** it is evidence as the same label before the value in text is, and only that. The last part of
  the path that is no list index is put before a copy of the value (`telefon: <value>`) and that line is scanned with
  the rules of the call. A hit inside the value is added when the bare value has none there and the scan of the whole
  text has none there either (`maisecrets/detection/fields.py`).
- **What it never does:** take a hit away (the hits of the text stay as they are), add a hit outside its span, bring
  back a hit that the text around the value took away, or parse anything: the core reads JSON and the other formats of
  the text itself, as without fields. A field that names what the core read itself adds no second hit.
- **Names that add nothing:** a name the label rules give no evidence for (`id`, `value`, `data`, `title`, an unknown
  word), `key` alone (in API data it names a ticket key, an object key or a translation key as often as a credential;
  `api_key`, `secret_key` are labels as in text, and so is `token` alone), the cursor of a paged list
  (`nextPageToken`, `syncToken`, `continuationToken`, `purchaseToken`; not `PrevAuthToken`), and a name with a line
  break, `:`, `=` or a quote, or longer than 64 characters. `build_number` stays text.
- **Without `fields`** (or with an empty list) a scan is the one of before: `scripts/detection_fingerprint.py` gives
  the same bytes. Each field costs two scans of its value, one with the label and one bare. In `findings()` with no
  `path`, a field over the whole text costs one, since the scan of the text is its bare scan; `scan(..., fields=)`
  scans twice.
- `tests/test_detection_fields.py` holds these points; `tests/conformance/cases.json` has cases with
  `context.fields` in the gateway's shapes (a leaf with its field path, and a JSON text with fields of its own keys).

## The API: the decision of 2026-10-20

The wheel (`pyproject.toml`) makes the core usable without the plugin, so its names carry a promise. Decided by the
maintainer on 2026-10-20 (merge request !160):

| Name | Promise |
|---|---|
| `Detector`, `Match` (`kind`, `type`, `value`, `start`, `end`), `Sources`, `NO_SOURCES`, `References`, `NO_REFERENCES`, `Host`, `THIS_COMPUTER`, `Active`, `resolve_regions` | **stable** |
| `user_rule(id, type, pattern, keywords=(), secret_group=0)` | **stable**: the one way for a caller to make a rule of its own. The id becomes `user:<id>`; a wrong argument raises `ValueError` |
| `Rule` | **no stable constructor**: the type that `user_rule` returns and `Detector.rules()` lists. Of its fields only `id`, `type`, `keywords` and `secret_group` are promised; the other 17 belong to the detector |
| `TYPES` and `maisecrets/detection/types.json` | **stable** as the section "The type vocabulary" says: a listed type and its family stay; a class may be refined in a minor release; new types may come |
| `LazyRegex` | **removed in 0.8** (deprecated in 0.7.0): give `user_rule` the pattern as a string |
| The text of `scan` and `findings` | **a `str`**: anything else raises `TypeError` since 0.8, decided without a `DeprecationWarning` in 0.7. Before, `None`, `b""` and `0` gave no hits and other bytes or numbers raised whatever the first regex raised |
| The offsets of a `Match` | **Unicode code points** of the scanned `str`, `text[start:end] == value`. A UTF-16 caller (JavaScript, Java, .NET) counts a character outside the BMP, such as an emoji, as two units and converts. In a tool result a value hidden by ANSI codes or zero-width characters has the span of its original text, those characters included |
| `maisecrets.detect` and the other old names | **not API**: plugin modules, not in the wheel |
| The hits themselves | **not API**: a patch version may find more or fewer values; `docs/BENCHMARKS.md` and `scripts/compare_bench.py` report how |

**Changes to a stable name go through a deprecation, also before 1.0:** the old form keeps working with a
`DeprecationWarning` for at least one minor version, the changelog says so under "API" (a commit footer
`API: …`, `scripts/release.py`), and only then it goes. A
1.0 of the wheel would freeze the stable names. `region` and `channel` for `user_rule` come only when they are meant
to be carried as API.

**Checks that hold it:** `tests/test_detection_package.py` pins `__all__`, the parameters of `user_rule`, the stable
`Match` fields, a rule of your own found through a `Detector`, the `ValueError` of a wrong argument, that
`LazyRegex` is gone and the `TypeError` of a text that is not a `str`. `tests/test_code_point_offsets.py` pins the
offsets on texts with emoji and combining characters. `scripts/wheel_smoke.py` makes a rule of its own through
`user_rule` in a fresh venv.

## The type vocabulary

`maisecrets/detection/types.json` lists every type that a `Match.type` of a built-in rule or pass can carry, and
`TYPES` is the same list as a read-only mapping:

```python
from maisecrets.detection import TYPES
TYPES["DE_TAX_ID"]       # {"family": "pii", "class": "pii.tax_id"}
TYPES["SECRET"]          # {"family": "secret", "class": "secret"}
```

- **`family`** is `secret` or `pii`. **`class`** is one of the classes of the benchmark (`bench/cases.py`), such as
  `pii.phone`, `pii.national_id` or `pii.bank_account`, or the family alone when the type does not say which kind it
  is (`SECRET`). The benchmark reads its classes from this file (`bench/sources.py`). The classes today are the
  classes of the benchmark, so several types under `pii.national_id` (postcodes, vehicle plates, tax and company
  numbers) are candidates for a finer class later.
- **Stable:** a type that a release lists is not renamed or removed without the deprecation path above. When its
  last rule goes, the entry stays with a `deprecated` field for at least one minor version. The family of a listed
  type never changes.
- **May be refined in a minor release:** the class of a listed type. The changelog names each type whose class moved.
- **May grow in any release:** new types (a new rule, a new region, a vendored rule set that brings a new entity),
  and new optional fields in an entry. A caller handles a type it does not know by its `family` and `class` from
  `TYPES` of the installed version: that version lists every type it emits.
- **Not listed:** the type of a rule of your own (`user_rule`) and of a term list or an imported value of the
  plugin; the caller or the person chose it. The terms and imports of the plugin take listed types only.

`tests/test_type_vocabulary.py` derives the emitted types from the rules of every region and label language and from
the passes, and fails when a type is emitted and not listed, or listed and emitted by nothing (unless it is
`deprecated`). A vendored rule-set update that brings a new type is therefore red until the type gets an entry.

## The JSON entry point: maisecrets.detect/1

A caller in any language runs the core as a process: one JSON request on stdin, one JSON response on stdout.

```bash
python3 -m maisecrets.detection < request.json > response.json
```

It needs Python 3.9 or later and the wheel installed (or the plugin folder as the working directory), and no other
package. It reads no home folder, no config and no network. Each call is one process; it loads the rules of its
request and ends (about 0.1 s on an M-series laptop). A Python server uses the library in process instead.

The schema of the request and of the response is `maisecrets/detection/detect-1.schema.json` (JSON Schema 2020-12,
`$defs/request` and `$defs/response`); it ships in the wheel next to the code. The contract follows
`docs/DETECTION-CONTRACT-PROPOSAL.md`, with the keys the core fills today.

**The request.** A JSON object in UTF-8 (a byte order mark is allowed):

| Key | Required | Meaning |
|---|---|---|
| `contract` | yes | `"maisecrets.detect/1"` |
| `text` | yes | the text to scan, a string |
| `channel` | yes | `"prompt"` (a person typed it) or `"tool"` (a tool result or a file). The tool channel takes forms a prompt does not, such as a phone number under a key that names a phone |
| `regions` | yes | the country rule sets, such as `["generic", "de"]`: `generic` and the country codes the rules name (`de`, `us`, `uk`, …; an unknown code is an error). `generic` is always on; `[]` gives it alone |
| `languages` | yes | the label languages, such as `["en", "de"]`: the files of `maisecrets/detection/rules/labels/`. English is always on |
| `context.path` | no | the file the text came from: a value of a test file can then be a fixture and no finding |
| `context.fields` | no | the field names of values in the text: a list of `{"start", "end", "name", "format"}`, the span of a value in code points, its field path outermost first (strings and integers, at least one part) and an informative format. It is the `fields` argument of `Detector.findings` ("Field names" above): evidence as a label, never a finding taken away. A wrong field is an error with the path `context.fields[i]…` |

The order of `regions` and of `languages` does not matter. A key that the table does not name is an error, so a
misspelt key never goes unnoticed. One key of the proposal is
not in `maisecrets.detect/1` yet: `exclusions` has no form in the core today (a reference form is a `References` object of six questions, not a list
of spans). A caller drops a finding inside its own placeholders itself. A later release may accept it as a new
optional key; a request without them keeps its meaning.

```json
{"contract": "maisecrets.detect/1",
 "text": "{\"customer\": {\"telefon\": \"0171 4829173\", \"build_number\": \"20261021\"}}",
 "channel": "tool", "regions": ["generic", "de"], "languages": ["en", "de"]}
```

**The response.** One line of JSON with a fixed key order:

```json
{"contract": "maisecrets.detect/1",
 "engine": {"name": "maisecrets", "version": "0.8.0", "ruleset": "sha256:…"},
 "findings": [{"start": 26, "end": 38, "type": "PHONE",
               "provenance": {"rule": "phone-after-phone-word", "origin": "builtin", "layer": "deterministic"}}]}
```

- **`start` and `end`** count Unicode code points of `text`, `end` exclusive. The value is `text[start:end]`; the
  response never carries it, so a secret stays out of the output stream. A UTF-16 caller (JavaScript, Java, .NET)
  counts a character outside the BMP, such as an emoji, as two units and converts.
- **`type`** is a type of `maisecrets/detection/types.json` (section "The type vocabulary"), with its family and class
  there. The findings are sorted by `start`, `end`, `type` and `rule`, and no two of them overlap.
- **`provenance`** is informative: `rule` is the rule id (`Match.kind`), and it may change with the rules; `origin`
  is `builtin` and `layer` is `deterministic` in this release. There is no confidence.
- **`engine.version`** is the version of the plugin or the wheel. **`engine.ruleset`** is a sha256 over the rule list
  the request loaded (each rule's id, type, pattern, keywords and checks, in scan order), the regions, the label
  languages and the year. It is computed from the loaded rules, not from the files: a checkout with CRLF line ends
  and the release tree give the same digest. The same request, version and ruleset give the same bytes.
- **The year** is the one input from outside the request: a birth date must lie before the current year (UTC). It is
  part of `ruleset`, so the digest changes on 1 January.

**Errors.** An error is a response too, on stdout, with a non-zero exit status. stderr stays empty.

```json
{"contract": "maisecrets.detect/1", "error": {"code": "invalid_request", "path": "regions[1]", "message": "is no known region"}}
```

| `code` | Exit status | When |
|---|---|---|
| `invalid_json` | 2 | the input is not one JSON document in UTF-8, has a key twice in one object, or holds `NaN` |
| `unsupported_contract` | 2 | `contract` is not `maisecrets.detect/1` |
| `invalid_request` | 2 | a required key is missing, a value has the wrong type or is not known, a key is not defined, or the process got arguments; `path` names the field (`channel`, `regions[1]`, `context.path`; `""` for the request itself) |
| `internal_error` | 3 | the engine failed; the message names the class of the exception |

Exit status 0 is a response with findings. Any other status (1 from the interpreter itself, for example when the
package is not found) means no response was written. The message of an error is a fixed text of the engine: it
never holds a value of the request, not even the name of an unknown key, since a key is input as well.

`tests/test_detection_entry_point.py` runs the conformance cases (`tests/conformance/cases.json`) through the entry
point and compares each response with the Python API, checks every response kind and the two examples above against
the schema, runs one request twice in fresh processes and compares the bytes, and sends a secret-shaped value in each
wrong field and checks that no output holds it. `scripts/wheel_smoke.py` calls the entry point from the installed
wheel.

## A remote detector (optional)

The rules find few names (docs/NER-EXPERIMENT.md). A named-entity service can add them after the rules, through
`maisecrets/detection/remote.py`. It is off unless a caller gives one, and the entry point above never asks one: it
reads no network.

```python
from maisecrets.detection import remote

ner = remote.RemoteDetector("http://127.0.0.1:8765/", format="hf", model="d3-onnx-fp32@d421f57d", timeout=0.3)
result = detector.findings_with(text, channel="tool", remote=ner)
result.findings          # the findings of the rules as they are, and the spans of the service (Match.score set)
result.remote.state      # "ok", "unavailable" (result.remote.reason: timeout, refused, http, answer), "too_long"
response = contract.result_response(detector, result)    # the same as JSON (maisecrets.detect/1)
```

- **Offsets** of the answer are code points of the text, as a Python service counts them (`str` indices). A service
  that counts UTF-16 units or bytes masks the wrong place after a character outside the BMP; the rules' findings
  stay, the name does not get masked.
- **Wire formats.** `hf`: Hugging Face token classification, `{"inputs": text}` in, `[{"entity_group" (or
  `entity`), "start", "end", "score"}]` out. `presidio`: Presidio Analyzer, `POST /analyze` with `{"text",
  "language"}`, `[{"entity_type", "start", "end", "score"}]` out. A label `B-PER` or `I-PER` counts as `PER`.
- **Classes.** `classes` maps a class of the service to a type of `types.json`. The default is `PER` and `PERSON` to
  `NAME`, the one class the NER experiment measured; an operator adds more (`{"LOC": "ADDRESS"}`). `min_score` sets
  the least score per type; there is none by default, and no threshold here was chosen from a benchmark.
- **It only adds.** A span is kept only where no finding of the rules and no span kept before it lies. A finding of
  the rules is never removed, made smaller, moved or retyped. A span that ends inside a word is widened to the whole
  word.
- **The service never sees a finding of the rules.** Each one goes out as filler (`_`) of the same length, so the
  offsets of the answer fit the text. `mask=False` sends them as they are: the filler costs the model of the NER
  experiment 21 of 2,482 names on the V3 samples (docs/NER-EXPERIMENT.md, "The remote path"). The plugin allows it
  only for a service on loopback or a Unix socket.
- **A failing service changes nothing.** Slow (over `timeout`, or past the `deadline` of `findings_with`, one budget
  for several texts), refused, an HTTP error, or an answer with any item it cannot read: the findings of the rules
  alone, and `result.remote` says `unavailable` and why. A text longer than `max_chars` is not sent (`too_long`).
  Nothing raises.
- **No network unless asked.** The URL must be a loopback address (127.0.0.0/8, `::1`, `localhost`) or a Unix socket
  (`unix:/path`), else `RemoteDetector` raises `ValueError`; `allow_network=True` allows any `http` or `https` host.
  A host name is looked up at each request: without `allow_network` every address must be loopback, and the
  connected peer is checked again before a byte is sent, so a `localhost` that a hosts file sends elsewhere is
  refused.
- **The deadline holds for the whole request.** Name lookup, connect, send and the answer run in a thread that the
  caller leaves at the deadline, so a service that sends its answer a byte at a time cannot hold the caller. A wrong
  setting (`classes`, `min_score`, `timeout`, `max_chars`) raises `ValueError` when the detector is made.
- **The model version is the operator's word.** Neither format names its model in the answer, so `model` is what the
  operator states, and `engine.remote.model` of a response is only as true as that setting. The reference service
  (`examples/ner_service.py`) reports its own at `GET /info`, so an operator can compare.
- **In a response** (`contract.result_response`), a finding of the service has `score` and `provenance.origin` and
  `layer` `model`; `engine.remote` holds `format`, `model`, `state` and, when unavailable, `reason`. Without a
  remote detector the response is the one of the entry point. The schema has both fields as optional.

These names are **new and provisional**: `RemoteDetector`, `RemoteStatus`, `Result`, `Detector.findings_with`,
`contract.result_response` and `Match.score` (`None` for a finding of the rules). They are not in `__all__`; a
change to them goes into the changelog under "API" without a deprecation until a minor release makes them stable.
`tests/test_remote_detector.py` holds the points above against a fake service of each format.

## The old names

`maisecrets.detect` and `maisecrets.checksums`, `lazy_regex`, `normalise`, `regions`, `registry`, `rulespec`,
`rule_filter` and `personal` stay. Each is the same module object as its module in `maisecrets/detection/`, so an
import or a patch through an old name reaches the core itself. The plugin and its tests use them.
`detect.scan()`, `detect.findings()` and the other functions use the default detector, which `use_regions`,
`use_sources` and `use_references` configure.

## The boundary tests

| Test | It holds |
|---|---|
| `tests/test_detection_boundary.py` | No module outside the core uses a private name of the core, by any of its names. A plain scan imports only the plugin modules on a list that may only get shorter. |
| `tests/test_scan_context.py` | A scan writes no new module state; the state left is the per-thread text index and caches that depend on no configuration. |
| `tests/test_detector.py` | Two detectors, their caches, their threads and the snapshot of a rule load. |
| `tests/test_detector_host.py` | An explicit host reads neither the user name nor the clock; an explicit detector gives one result on two hosts. |
| `tests/test_detection_package.py` | The API, the old names, the rule data, and a library caller that imports nothing of the plugin. |
| `tests/test_code_point_offsets.py` | The offsets count code points: emoji and combining characters before, around and inside a value, in a JSON line and in the cleaned copy of a tool result. |
| `tests/test_detection_entry_point.py` | The JSON entry point: the conformance cases through it, the schema, the errors, the bytes of two runs, no value in any output. |
| `tests/test_detection_fields.py` | The `fields` argument: evidence as a label in text, nothing for a weak name, no hit taken away, the same hits on a JSON text the core parses itself, the `TypeError` and `ValueError` of a wrong shape. |
| `tests/test_library_consumer.py` | A server-like caller of the public names only (`examples/library_consumer.py`): its own sources and rules, `reset()`, two detectors in eight threads, a large input, many requests, no file under HOME. |

`scripts/detection_fingerprint.py` records the hits of 27,337 inputs. A change that moves the code and not the rules
leaves the fingerprint byte-identical.

## A language-neutral spec

`docs/DETECTION-SPEC-DRAFT.md` measures how far the core is from a spec that a second implementation could follow:
what is data today, what is Python, about 31 semantic primitives, and a case format that tells normative cases from
snapshot records. It is an analysis; nothing in the runtime depends on it.
