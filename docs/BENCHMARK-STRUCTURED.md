# The structured corpus

Status: version 1 (2026-10-25). Template set A (development) is in the repository. Template set B (the independent
holdout) was written from the SPEC in this file and sealed on 2026-10-25 (`bench/HOLDOUT-LOG.md`).

**What this corpus is, and what it is not.** It is a targeted regression benchmark: it was built because maisecrets
has known gaps in structured text, and it measures whether those gaps close and stay closed. It is not independent
evidence that maisecrets is better than another scanner. This project chose the formats, the classes and the field
names, and the author of set A saw the detector. Set B has an independent author, but its SPEC comes from this
project too. Another scanner may run on the corpus, and the baseline reports it, but every table of it carries this
label (`scripts/extended_baseline.py`).

## Why

maisecrets finds many values only after a label: a JSON key, a column name, an XML element, a `.env` key. In
structured text the label decides the recall. No public dataset puts personal data and secrets into JSON, XML, SQL,
CSV and Markdown with field names in many spellings and languages. The PII datasets of Benchmark V3 are mostly prose,
and the secret catalogs give a value after `token = `. This corpus fills that gap with our own synthetic data.

The corpus answers three questions:

1. Which structures does maisecrets read as records, and which does it read only as text?
2. Which field names does it know, in which spelling style and in which language?
3. Which look-alike values in the same structures does it mask by mistake?

## The two template sets

| Set | Author | What it is | Where it lives | Use |
|---|---|---|---|---|
| A | this project, with sight of the detector | `bench/structgen.py`, `bench/structvocab.py`, `bench/structvalues.py`: templates, vocabulary and value generators in the repository | public | development: read the cases, cluster the misses, write rules |
| B | a second author who has not seen set A or a miss list | its own templates and generators, written from the SPEC below only | private, sealed by a manifest | holdout: a release candidate meets it, nobody reads it |

Set B is not a second seed of set A. A rule tuned on set A could pass a second seed of A without generalising,
because the templates, the field names and the value shapes would be the same. Set B therefore has its own author,
its own vocabulary and its own templates. The SPEC fixes only what both sets must cover.

## Classes

The classes are those of `bench/cases.py` and `bench/sources.py` (the published type vocabulary,
`maisecrets/detection/types.json`).

| Class | Concepts in set A | Notes |
|---|---|---|
| `pii.name` | first name, last name, full name, account holder | a first and a last name in two fields are two spans |
| `pii.address` | street line; one-line address | the one-line address has a `core`: the street and the house number |
| `pii.address` (neutral) | city, postcode in their own fields | neither right nor wrong (city and postcode stay text by policy) |
| `pii.email` (neutral) | e-mail | every address is under `example.com` or `example.org`; see "E-mail addresses" |
| `pii.phone` | phone, mobile | national and international forms per locale |
| `pii.birth_date` | date of birth | the date forms of the locale |
| `pii.national_id` | US SSN, DE Rentenversicherungsnummer, DE Personalausweis, DE Führerschein, FR NIR, ES DNI, IT codice fiscale, NL BSN, SE personnummer, PL PESEL | each with its public check digit, where one exists |
| `pii.tax_id` | DE Steuer-IdNr, PT NIF | |
| `pii.iban` | IBAN of the nine locales | ISO 13616 length and mod 97; national check digits for fr, es, it, nl, pt |
| `pii.card` | Visa, Mastercard (both ranges), Amex, Discover | Luhn; plain, grouped by spaces or by hyphens |
| `pii.bank_account` | account number, ABA routing number | ABA with its 3-7-1 check digit |
| `pii.username` | login, user name, handle | |
| `pii.ip` | global unicast IPv4, global IPv6 | no private, documentation or reserved block |
| `secret.password` | password | four generator shapes |
| `secret.token` | GitHub (with its CRC32 tail), GitLab, Slack, AWS key id and secret, Stripe, OpenAI, Google, JWT, npm, SendGrid, 32/40 hex, base64 | |
| `secret.private_key` | RSA, EC, OpenSSH and PKCS#8 PEM blocks | the span is the whole block |
| `secret.connection_string` | postgresql, mysql, mongodb+srv, redis, amqp URIs; ADO.NET; JDBC | the span is the whole string, the `core` is the password |

## Formats

26 formats. Each format has its own renderer in `bench/structgen.py`; the renderer escapes each value as the format
writes it, and the span covers the value as written.

| Format | What it looks like | `context` |
|---|---|---|
| `json_flat` | one object, pretty or on one line | json |
| `json_nested` | an API envelope; `data` → entity or `items` array; groups; a phone, an e-mail or a birth date sometimes as `{"type": …, "value": …}` under its key (the label is the parent key) | json |
| `json_escaped` | an event whose `payload` is JSON inside a JSON string (`\"key\": \"value\"`) | json |
| `yaml` | a record or a list of records; plain, single-quoted, double-quoted scalars; a PEM as a block scalar | yaml |
| `env` | `KEY=value`, mostly UPPER_CASE; a PEM with `\n` escapes in double quotes | config |
| `ini` | sections and `key = value` | config |
| `xml_element` | `<customer><firstName>…</firstName></customer>` | code |
| `xml_attribute` | `<customer firstName="…" />` | code |
| `html_table` | `<th>` heads and `<td>` cells | code |
| `sql_insert` | `INSERT INTO t (cols) VALUES (…), (…)` | code |
| `sql_dump` | mysqldump: `CREATE TABLE` with the columns, then `INSERT INTO \`t\` VALUES (1,'…'),(2,'…')` without a column list | code |
| `sql_insert_bare` | the same INSERT without its CREATE TABLE: no label in the text at all | code |
| `sql_update` | `UPDATE t SET col = '…', … WHERE id = n` | code |
| `sql_where` | `SELECT … WHERE col = '…' AND …` | code |
| `csv` | comma, semicolon (the Excel separator of the European locales) or tab, with a header | code |
| `md_table` | a Markdown table with a header row | doc |
| `md_kv` | a two-column field/value table, half with a header and half with an empty header row | doc |
| `log_kv` | log lines with `key=value` and `key="value with spaces"` | log |
| `http` | a request line with the record in the query string (percent-encoded), the token in `Authorization: Bearer` or an `X-Api-Key` header | url |
| `stacktrace` | a Python traceback with `request body: {…}`, or a Jackson exception with the body inside `(String)"…"` | stacktrace |
| `debug_print` | a Python dict repr or a PHP `print_r` | code |
| `seed_script` | a knex seed (JavaScript) or a Django data migration (Python) | code |
| `migration` | a Flyway SQL migration with an ALTER TABLE and backfill UPDATEs | code |
| `api_response` | an HTTP response head and a JSON body | json |
| `docker_compose` | an `environment:` block as a list (`- KEY=value`) or a map (`KEY: value`) | yaml |
| `ci_log` | a GitLab runner log with `$ export KEY=value`, `[deploy] key: value` and a heredoc PEM | log |

A table format holds two to four rows with the same columns. A PEM block never goes into a table cell or a URL.
Some cases have a `path` (`deploy/.env.production`, `backup/<table>.sql`, `exports/<table>.csv`), as a file read
gives one. About 20 % of the cases of eight formats come on the `prompt` channel (a person pastes a table); the rest
are tool output.

## Field names

### Vocabulary

`bench/structvocab.py` holds 27 concepts. Each concept has, per language, the word sequences that name it in a form,
a column or a key, for example `("date", "of", "birth")`, `("geburtsdatum",)`, `("date", "de", "naissance")`,
`("fecha", "de", "nacimiento")`, `("data", "urodzenia")`. The languages are en, de, fr, es, it, nl, sv, pl and pt.
A concept that a language does not name in practice uses the English words (a German `.env` also says `API_KEY`).

The short forms are a separate list (`ABBREVIATIONS`): `dob`, `ssn_no`, `tel`, `addr`, `pwd`, `fname`, `lname`,
`acct_no`, `cc_num`, `uname`, `geb_dat`, `kto_nr`, `mdp`, `f_nac`, `cf`, `pnr`, `nr_tel` and others.

**Sources.** The author wrote the vocabulary from common usage of localized forms and schemas, in the spellings of
real forms (`Geburtsdatum`, `Führerscheinnummer`, `Straße`, `date_de_naissance`, `numéro_de_téléphone`,
`contraseña`, `wachtwoord`, `lösenord`, `hasło`, `senha`, `palavra-passe`). Each word was not checked against a cited
source, as `docs/label-sources.md` does for the credential labels. That check is open work (see "Limits").

### Spelling styles

| Style | Example (`date of birth`) |
|---|---|
| `snake` | `date_of_birth` |
| `camel` | `dateOfBirth` |
| `pascal` | `DateOfBirth` |
| `kebab` | `date-of-birth` |
| `upper` | `DATE_OF_BIRTH` |
| `dotted` | `date.of.birth` |
| `doubled` | `customer__date__of__birth` (a single word gets the entity as prefix: `kunde__geburtsdatum`) |
| `human` | `Date of birth` (only in formats that allow a space: JSON, YAML, CSV, Markdown, HTML, debug prints) |
| `abbr` | a short form, in snake or camel case |

A word with a diacritic appears as written (`kept`) or folded to ASCII (`folded`): German as `ae oe ue ss`
(`fuehrerscheinnummer`), sometimes without the `e` (`fuhrerscheinnummer`), the other languages without the accent
(`telefono`, `losenord`, `haslo`). Each span records its field name, concept, style, language and diacritics, so the
report can split by each.

## Values

`bench/structvalues.py` draws every value from a `random.Random` with a fixed seed (`SEED = 20261025`). No value is
real.

- **Names:** a random pair of a common given name and a common surname of the locale (16 of each). No pair is meant
  to name a person; `bench/traces.py` uses the same method.
- **E-mail addresses:** only under `example.com` and `example.org`.
- **Hosts:** only under `example.org` and the reserved TLD `.internal`.
- **IP addresses:** global unicast from a fixed list of public /8 blocks; the negatives use private, loopback and
  documentation addresses.
- **Numbers with a check digit:** each generator is written from the public definition that its docstring names
  (ISO 13616, ISO/IEC 7812, § 139b AO, VKVV, the NIR key, the DNI letter, DM 23/12/1976, the BSN 11-check,
  Skatteverket, PESEL, the NIF mod 11, the ABA 3-7-1 check). `tests/test_structgen.py` checks IBAN, Luhn, PESEL,
  DNI, codice fiscale and ABA with the detector's own check functions as a second reading.
- **Secrets:** made from the public format of each vendor at run time. The source holds only the prefixes, split
  (`"glp" + "at-"`), so `scripts/scan_tree.py` finds no secret shape in the tree.

Nothing is stored. The cases are made at run time, as `bench/traces.py` does.

## Spans

The span convention is that of `bench/score.py`:

- `start` and `end` count code points, `end` exclusive. The span covers the value as the format writes it: escaped
  in JSON (`\"`, `\n`), doubled quote in SQL, entity in XML, percent-encoded in a URL. The quotes around a value are
  not in the span.
- `core`: a span counts as found when its core is masked whole. A one-line address has the street and the house
  number as core (city and postcode stay text by policy). A connection string has the password as core.
- `neutral`: a city or a postcode in its own field, and every e-mail address. A finding there is neither right nor
  wrong.
- Each span carries `field`, `concept`, `style`, `lang` and `diacritics`; a parent-key case also `keypath: parent`.

### E-mail addresses

maisecrets keeps an address under `example.com`, `example.net` or `example.org` as text
(`maisecrets/detection/value_checks.py:1089-1110`, `_reserved_domain`). The repository rule allows no other domain.
So every e-mail span is neutral and carries `policy: reserved-mail-domain`. The report counts how many of them a
scanner masked. The corpus does not measure e-mail recall. To measure it, a private run needs a
generator option with a non-reserved synthetic domain; that option does not exist yet.

### Look-alikes

A value that is text is recorded in `lookalikes` with its `kind`, `concept` and `field`. A false positive on it gets
its kind in the report; a false positive elsewhere (a field name, a port, an id attribute) is `structure`.

## Negatives

A quarter of the cases are negatives: the same formats and field names, and no value in scope. Each negative case
takes one or two kinds:

| Kind | What it holds |
|---|---|
| `placeholder` | `changeme`, `<password>`, `${DB_PASSWORD}`, `{{ .Values.db.password }}`, `<your-api-key>`, `xxx`, `%API_KEY%`, `+1 (000) 000-0000`, a URI with `user:password@localhost` |
| `masked` | `**** **** **** 4242`, `XXX-XX-1234`, a masked IBAN and phone |
| `hash` | a bcrypt hash under `<password>_hash`, sha256, a git commit, an ETag |
| `uuid` | `id`, `request_id`, `trace_id`, `<user>_id` |
| `version_build` | a version, a build number, a build id, an image tag |
| `event_date` | a creation date, `valid_until`, `founded`, `contract_start`, some in birth-date years |
| `company_contact` | a company name, the company address, a support phone, a hotline |
| `schema_doc` | the field names of sensitive concepts with a description of the type as the value |
| `fixture` | public example values: Max/Erika Mustermann, John/Jane Doe, `4111 1111 1111 1111`, the documentation IBANs, `078-05-1120`; path under `tests/fixtures/` |
| `config_default` | a port, `<password>_min_length`, `max_login_attempts`, `<api_key>_ttl`, `key_size` |
| `enum_role` | a role, a system user (`root`, `postgres`, `ci-bot`), a non-person name (`Default`, `Support Team`), a plan |
| `private_ip` | private, loopback and documentation addresses, `0.0.0.0` |

Every case, positive or negative, also has one to three plain fields (an order number, a timestamp, a status, a
country, an amount, a UUID, a locale, a flag) with localized field names.

Two kinds hold values whose policy is not written down. A company phone under a support key and a public example
IBAN under a test path are negatives here; the report shows them apart, so a policy decision can move them.

## Size of set A

3744 cases: 26 formats × 9 languages × 16. The style turns with the case number, so each format meets each style.
`python3 bench/structgen.py --stats` prints the counts.

| | dev | val | total |
|---|---|---|---|
| cases | 2201 | 1543 | 3744 |
| of them negative | 575 | | 930 |

Total spans 24,026 (of them 2,236 neutral city and postcode and 1,542 neutral e-mail), and 20,653 look-alikes.

Scored spans of the dev split per class: name 3414, address 1330, IP 832, username 820, password 777, card 753,
birth date 688, IBAN 674, phone 674, national id 586, token 324, bank account 239, connection string 165, private key
153, tax id 61. A language has between 1123 and 1492 scored spans on dev, a format between 151 (`http`) and 869
(`md_table`).

## Split policy

- Set A gives `dev` (60 %) and `val` (40 %) by `split_of("structured", record)`. `val` is the same templates with
  other values: a check before a merge, not a measure of generalisation. Set A has no holdout split.
- Set B is the holdout. It is written by a second author from the SPEC, sealed, and run only on a release candidate,
  as Holdout V2 is (`bench/holdout_v2.py`, `bench/HOLDOUT-LOG.md`).
- A rule written from set A cites set A. A rule must not cite set B; nobody reads set B's cases or a list of its
  misses.

## Run it

```bash
python3 bench/run.py --source structured --split dev --out structured-dev.json     # the standard result file
python3 bench/struct_report.py                                                     # the split by format, language, style
python3 bench/struct_report.py --regions all --languages all                       # the rules of all nine locales
```

`bench/run.py --languages en,de,fr,…` passes the label languages to the maisecrets worker; the release baseline uses
the bench default (regions `de,us`).

`bench/struct_report.py` prints counts, rule ids and field names only. The worker of the bench adapter takes
`--languages` now; without it the label languages stay `en` (and `de` with region `de`), as before.

## The holdout SPEC (set B)

This section is the whole brief for the author of set B. The author reads this section, `bench/cases.py` (the case
format) and `bench/score.py` (the span rule). The author does not read `bench/structgen.py`, `bench/structvocab.py`,
`bench/structvalues.py`, a report of set A, a miss list, or the detector code.

### Independence

1. Write the templates, the field-name vocabulary and the value generators yourself. Do not copy a word list from
   this repository. Take field names from real public sources of your choice (open-source schemas, localized UI
   files, public API documentation, database dumps of open data). Record the source of each field name in the
   private directory.
2. Use other structures than the examples of this file where the format allows it: other envelopes, other nesting,
   other column orders, other log layouts, other comment styles.
3. Do not run maisecrets on set B while you write it. Do not tune a case after a run.
4. Write `ATTESTATION.json`: your role (no name), the date, `"seen_set_a": false`, `"seen_miss_lists": false`.

### Coverage

| Dimension | Required |
|---|---|
| Formats | each of: JSON (flat, nested, arrays, JSON inside a JSON string), YAML, `.env`, INI or TOML, XML (elements and attributes), HTML table, SQL (INSERT with a column list, mysqldump CREATE TABLE + INSERT without a column list, UPDATE … SET, WHERE col = '…'), CSV and TSV with a header, Markdown table with and without a header, log lines with `key=value`, HTTP headers and query strings |
| Developer contexts | each of: a stack trace with a request body, a debug print of a dict or object, a migration file, a seed script, an API response, a docker-compose `environment:` block, a CI log |
| Field-name styles | each of: snake_case, camelCase, PascalCase, kebab-case, UPPER_CASE, a doubled separator, a dotted path, a prefixed name, an abbreviation, a human label with spaces |
| Field-name languages | en, de, fr, es, it, nl, sv, pl, pt; with and without diacritics where the language has them |
| Classes | each class of the table "Classes" above, with at least 30 scored spans per class |
| Negatives | each kind of the table "Negatives" above, with at least 20 cases per kind |
| Size | 1500 to 2500 cases; about a quarter negative; no format and no language below 4 % of the cases |

### Values

- Synthetic only. Names as random pairs of common names; e-mail addresses only under `example.com` or
  `example.org`; hosts only under `example.org`, `example.com` or `.internal`; IP addresses outside private and
  documentation blocks for positives.
- Each number with a check digit has a valid one, computed from the public definition.
- Each secret follows the public format of its vendor and is made at run time; a stored case file splits each value
  with `§` (the bank convention, `bench/cases.py`), so `scripts/scan_tree.py` stays clean if a file ever enters the
  tree.

### Spans

- The case format of `bench/cases.py`; `split` is `holdout`; `source.name` is `structured-b`.
- One span per sensitive value, on the value as written (escaped as the format writes it), quotes outside.
- `core` for a one-line address (street and house number) and for a connection string (the password).
- City and postcode in their own fields, and every e-mail address: `neutral: true`.
- Each span carries `field`, `style`, `lang`; each look-alike value is listed in `lookalikes` with its `kind`.

### Delivery

- A private directory with `ATTESTATION.json`, the templates, the generators, the seed, and the rendered
  `cases.jsonl`.
- The seal: a manifest with the sha256 of the templates and of `cases.jsonl`, and the counts per class, format and
  language. `bench/HOLDOUT-LOG.md` records it; `bench/structured_b.py` pins the sha256 of `cases.jsonl`.

### Runner

```bash
python3 bench/structured_b.py verify CASES_FILE        # the file matches the seal; counts only
python3 bench/run.py --scanner maisecrets --maisecrets CANDIDATE --source structured-b \
    --holdout CASES_FILE --release-candidate --out structured-b.json
```

`bench/run.py` refuses a file whose sha256 differs, and for maisecrets a checkout that is no release candidate (as
for Holdout V2). The result file holds totals and per-class aggregates only, no case id and no outcome per case, and
the run adds one row to `bench/HOLDOUT-LOG.md`. Set B runs once per release candidate; no rule is written or tuned
on its totals.

## Limits

- **The vocabulary of set A has no cited source per word.** The words follow common usage; a check against localized
  UI catalogs, as `docs/label-sources.md` does for the credential labels, is open.
- **The author of set A saw the detector.** Set A is development data and may resemble the rules. Its numbers show
  where the gaps are; they are not a measure of generalisation. Set B measures generalisation to other templates
  and field names, within the scope of the SPEC.
- **A regression benchmark, not a comparison.** See "What this corpus is" at the top.
- **E-mail recall is not measured.** See "E-mail addresses".
- **Some national formats are approximations:** the German driving licence follows the shape of public recognisers
  without its check digit; the SE, PL and DE BBANs are random digits with a valid IBAN check.
- **Company phones and public example IBANs** are counted as negatives; their policy is not written down.
- **A table by locale mixes label and shape:** a locale changes both the field name and the value forms.
- **Results** are not in this file. The numbers of record come from the release baseline.
