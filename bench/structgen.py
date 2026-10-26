"""The structured corpus, template set A: a seeded generator of development cases in structured text
(docs/BENCHMARK-STRUCTURED.md).

maisecrets finds many values only after a label: a key, a column, an element name. This source puts personal data
and secrets into 26 structured formats (JSON, YAML, .env, INI, XML, HTML tables, SQL, CSV/TSV, Markdown tables, log
lines, HTTP, and developer contexts such as a stack trace, a seed script or a CI log), under field names in nine
languages and nine spelling styles, next to fields that only look sensitive. Each sensitive value is a span with its
exact offsets; each look-alike value is recorded as a `lookalike` with its kind, so a false positive can be named.

Nothing is stored: the cases are made at run time from one seed, so the tree holds no value (bench/traces.py does the
same). Template set A is development data: read it, cluster its misses, write rules from it. The independent
holdout (set B) is written by another author from the SPEC in the design doc and never from this file.

    python3 bench/run.py --source structured --split dev --out structured-dev.json
    python3 bench/structgen.py --stats"""
from __future__ import annotations

import json
import random
import sys
import urllib.parse
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench import cases  # noqa: E402
from bench import structvalues as V  # noqa: E402
from bench.structvocab import ENTITIES, STYLES, field_name  # noqa: E402

SEED = 20261025
COUNT = 3744          # 26 formats x 9 languages x 16
NEGATIVE_SHARE = 0.25


# -------------------------------------------------------------------------------------------------- fields --
class F:
    """A field of a record: its name, its value as written, and what it is. cls is a class of bench/cases.py,
    "neutral" (a city or a postcode: neither right nor wrong) or "" (text); kind names a look-alike."""

    __slots__ = ("name", "value", "cls", "core", "kind", "concept", "tags", "raw")

    def __init__(self, name, value, cls="", core=None, kind="", concept="", tags=None, raw=False):
        self.name, self.value, self.cls, self.core, self.kind = name, value, cls, core, kind
        self.concept, self.tags, self.raw = concept, tags or {}, raw   # raw: a number or a literal, no quotes


class Text:
    """Text with spans: append pieces, mark a value with its class or its look-alike kind."""

    def __init__(self):
        self.parts, self.spans, self.lookalikes, self.n = [], [], [], 0

    def add(self, s: str) -> None:
        self.parts.append(s)
        self.n += len(s)

    def value(self, f: F, written: str) -> None:
        """Append the value as the format writes it (escaped, quoted inside); the span covers what is written."""
        if f.cls:
            span = {"start": self.n, "end": self.n + len(written), "field": f.name, "concept": f.concept,
                    **f.tags}
            if f.cls == "neutral":
                span.update({"class": "pii.address", "neutral": True})
            elif f.cls == "pii.email":
                # every address lies under example.com or example.org, which maisecrets keeps as text by policy
                # (value_checks.py, _reserved_domain): scored apart, never as a miss
                span.update({"class": "pii.email", "neutral": True, "policy": "reserved-mail-domain"})
            else:
                span["class"] = f.cls
            if f.core is not None:
                a, b = f.core
                if written != f.value:
                    # each escape here works character by character: the core moves by the escaped length before it
                    esc = next((e for e in _escapes() if e(f.value) == written), None)
                    if esc is None:
                        raise ValueError("an escape moved the core of a span and the escape is not known")
                    a, b = len(esc(f.value[:a])), len(esc(f.value[:a])) + len(esc(f.value[a:b]))
                    if written[a:b] != esc(f.value[f.core[0]:f.core[1]]):
                        raise ValueError("an escape moved the core of a span")
                span["core"] = [self.n + a, self.n + b]
            self.spans.append(span)
        elif f.kind:
            self.lookalikes.append({"start": self.n, "end": self.n + len(written), "kind": f.kind,
                                    "concept": f.concept, "field": f.name})
        self.add(written)

    def text(self) -> str:
        return "".join(self.parts)


def _json_esc(v: str) -> str:
    return json.dumps(v, ensure_ascii=False)[1:-1]


def _xml_esc(v: str) -> str:
    return v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _sql_esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "''").replace("\n", "\\n")


def _py_esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")


def _escapes():
    return (_json_esc, lambda v: _json_esc(_json_esc(v)), _xml_esc, _sql_esc, _py_esc,
            lambda v: urllib.parse.quote_plus(v, safe=""), lambda v: v.replace("|", "\\|"),
            lambda v: v.replace('"', '""'), lambda v: v.replace('"', '\\"'))


# --------------------------------------------------------------------------------------- record contents --
PERSON_POOL = ("email", "phone", "birth_date", "street", "address", "nid", "iban", "card", "username", "ip",
               "account_number", "password")
CONFIG_POOL = ("password", "api_key", "api_key", "private_key", "connection_string", "username", "email", "ip")


def _person_fields(r: random.Random, lang: str, style: str, p: dict, n_extra: int, prefix: str = "") -> list:
    """The sensitive fields of one person's record: a name (whole or split) and n_extra others."""
    def fn(concept):
        return field_name(concept, lang, style, r, prefix)

    out = []
    if r.random() < 0.55:
        for concept, v in (("first_name", p["first"]), ("last_name", p["last"])):
            name, tags = fn(concept)
            out.append(F(name, v, "pii.name", concept=concept, tags=tags))
    else:
        name, tags = fn("full_name")
        out.append(F(name, p["name"], "pii.name", concept="full_name", tags=tags))
    pool = [c for c in PERSON_POOL if not (c == "account_number" and lang not in ("en", "de"))]
    for concept in r.sample(pool, n_extra):
        out.extend(_concept_fields(r, lang, style, p, concept, prefix))
    return out


def _concept_fields(r, lang, style, p, concept, prefix=""):
    def fn(c):
        return field_name(c, lang, style, r, prefix)
    if concept == "street":
        out = []
        name, tags = fn("street")
        out.append(F(name, p["street"], "pii.address", concept="street", tags=tags))
        for c, v in (("postcode", p["postcode"]), ("city", p["city"])):
            name, tags = fn(c)
            out.append(F(name, v, "neutral", concept=c, tags=tags))
        return out
    if concept == "address":
        v, n = V.full_address(r, p)
        name, tags = fn("address")
        return [F(name, v, "pii.address", core=(0, n), concept="address", tags=tags)]
    if concept == "nid":
        c, v, cls = V.national_id(r, p)
        name, tags = fn(c)
        return [F(name, v, cls, concept=c, tags=tags)]
    if concept == "account_number":
        out = []
        name, tags = fn("account_number")
        out.append(F(name, V.account_number(r, lang), "pii.bank_account", concept=concept, tags=tags))
        if lang == "en":
            name, tags = fn("routing_number")
            out.append(F(name, V.aba_routing(r), "pii.bank_account", concept="routing_number", tags=tags))
        return out
    value, cls = {
        "email": lambda: (p["email"], "pii.email"), "phone": lambda: (p["phone"], "pii.phone"),
        "birth_date": lambda: (p["dob"], "pii.birth_date"), "iban": lambda: (V.iban(r, lang), "pii.iban"),
        "card": lambda: (V.card(r), "pii.card"), "username": lambda: (V.username(r, p), "pii.username"),
        "ip": lambda: (V.ipv4(r) if r.random() < 0.8 else V.ipv6(r), "pii.ip"),
        "password": lambda: (V.password(r), "secret.password"),
        "api_key": lambda: (V.token(r)[1], "secret.token"),
        "private_key": lambda: (V.private_key(r), "secret.private_key"),
    }[concept]()
    name, tags = fn(concept)
    return [F(name, value, cls, concept=concept, tags=tags)]


def _conn_field(r, lang, style, p):
    user = V.username(r, p).replace(".", "_")
    pw = V.pw_for_uri(r)
    v, at = V.connection_string(r, user, pw)
    name, tags = field_name("connection_string", lang, style, r)
    return F(name, v, "secret.connection_string", core=(at, at + len(pw)), concept="connection_string", tags=tags)


def _config_fields(r, lang, style, p, n: int) -> list:
    out = []
    for concept in r.sample(CONFIG_POOL, n):
        if concept == "connection_string":
            out.append(_conn_field(r, lang, style, p))
        else:
            out.extend(_concept_fields(r, lang, style, p, concept))
    return out


# plain fields: (concept, {lang: words}, value maker); they are text, recorded as look-alikes of kind "plain"
PLAIN = (
    ("id", {"en": ("id",)}, lambda r: str(r.randint(1, 99999)), True),
    ("order", {"en": ("order", "id"), "de": ("bestellnummer",), "fr": ("numéro", "commande"),
               "es": ("número", "pedido"), "it": ("numero", "ordine"), "nl": ("ordernummer",), "sv": ("ordernummer",),
               "pl": ("numer", "zamówienia"), "pt": ("número", "encomenda")},
     lambda r: f"{r.choice(('ORD', 'SO', 'A'))}-{r.randint(2024, 2026)}-{r.randint(1, 999999):06d}", False),
    ("created", {"en": ("created", "at"), "de": ("erstellt", "am"), "fr": ("date", "création"),
                 "es": ("fecha", "alta"), "it": ("data", "creazione"), "nl": ("aangemaakt", "op"),
                 "sv": ("skapad",), "pl": ("data", "utworzenia"), "pt": ("data", "criação")},
     lambda r: f"2026-{r.randint(1, 10):02d}-{r.randint(1, 28):02d}T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:00Z",
     False),
    ("status", {"en": ("status",), "de": ("status",), "fr": ("statut",), "es": ("estado",), "it": ("stato",),
                "nl": ("status",), "sv": ("status",), "pl": ("status",), "pt": ("estado",)},
     lambda r: r.choice(("active", "pending", "suspended", "verified", "closed")), False),
    ("country", {"en": ("country",), "de": ("land",), "fr": ("pays",), "es": ("país",), "it": ("paese",),
                 "nl": ("land",), "sv": ("land",), "pl": ("kraj",), "pt": ("país",)},
     lambda r: r.choice(("US", "DE", "FR", "ES", "IT", "NL", "SE", "PL", "PT")), False),
    ("amount", {"en": ("amount",), "de": ("betrag",), "fr": ("montant",), "es": ("importe",), "it": ("importo",),
                "nl": ("bedrag",), "sv": ("belopp",), "pl": ("kwota",), "pt": ("montante",)},
     lambda r: f"{r.randint(1, 4999)}.{r.randint(0, 99):02d}", True),
    ("uuid", {"en": ("uuid",)}, lambda r: "-".join(V.rd(r, n, V.HEX) for n in (8, 4, 4, 4, 12)), False),
    ("locale", {"en": ("locale",)}, lambda r: r.choice(("en_US", "de_DE", "fr_FR", "es_ES", "pl_PL")), False),
    ("newsletter", {"en": ("newsletter",), "de": ("newsletter",), "fr": ("infolettre",)},
     lambda r: r.choice(("true", "false")), True),
)


def _plain_fields(r, lang, style, n) -> list:
    out = []
    for concept, words, make, raw in r.sample(PLAIN, n):
        w = words.get(lang) or words["en"]
        from bench.structvocab import render
        st = style if style not in ("abbr",) else "snake"
        name = render(tuple(V.fold_plain(x) for x in w) if st != "human" else w, st, lang)
        out.append(F(name, make(r), "", kind="plain", concept=concept, raw=raw))
    return out


# --------------------------------------------------------------------------------------- negative fields --
def _neg_fields(r, lang, style, kind) -> list:
    """Look-alikes of one kind: the field names of sensitive concepts (or near them) with values that are not."""
    def fn(concept, pre=""):
        return field_name(concept, lang, style, r, pre)[0]

    def f(concept, value, raw=False, name=None):
        return F(name or fn(concept), value, "", kind=kind, concept=concept, raw=raw)

    if kind == "placeholder":
        return [f("password", r.choice(("changeme", "<password>", "${DB_PASSWORD}", "{{ .Values.db.password }}",
                                        "********", "your_password_here", "REDACTED", "TODO"))),
                f("api_key", r.choice(("<your-api-key>", "xxx", "YOUR_API_KEY", "${API_TOKEN}", "<redacted>",
                                       "sk-...", "xxxxxxxxxxxxxxxx", "%API_KEY%"))),
                f("phone", r.choice(("+1 (000) 000-0000", "XXX-XXX-XXXX", "<phone>", "+49 000 0000000", "n/a"))),
                f("connection_string", r.choice(("postgres://user:password@localhost:5432/db",
                                                 "${DATABASE_URL}", "mysql://<user>:<pass>@<host>/<db>")))]
    if kind == "masked":
        return [f("card", r.choice(("**** **** **** 4242", "XXXX-XXXX-XXXX-1881", "•••• 0005"))),
                f("iban", r.choice(("DE** **** **** **** **12 34", "FR76 XXXX XXXX XXXX XXXX XXX4 189"))),
                f("ssn", r.choice(("XXX-XX-1234", "***-**-6789"))),
                f("password", "********"), f("phone", r.choice(("+49 *** ****123", "(***) ***-4410")))]
    if kind == "hash":
        return [f("password", "$2b$12$" + V.rd(r, 53, V.AN + "./"), name=fn("password") + "_hash"),
                F("sha256", V.rd(r, 64, V.HEX), kind=kind, concept="hash"),
                F("commit", V.rd(r, 40, V.HEX), kind=kind, concept="hash"),
                F("etag", '"' + V.rd(r, 32, V.HEX) + '"', kind=kind, concept="hash")]
    if kind == "uuid":
        def u():
            return "-".join(V.rd(r, n, V.HEX) for n in (8, 4, 4, 4, 12))
        return [F(n, u(), kind=kind, concept="uuid") for n in ("id", "request_id", "trace_id", fn("username") + "_id")]
    if kind == "version_build":
        return [F("version", f"{r.randint(0, 9)}.{r.randint(0, 40)}.{r.randint(0, 200)}", kind=kind, concept="version"),
                F("build", str(r.randint(10000, 999999)), kind=kind, concept="build", raw=True),
                F("build_id", f"{r.randint(2024, 2026)}{r.randint(1, 12):02d}{r.randint(1, 28):02d}."
                  f"{r.randint(1, 99)}", kind=kind, concept="build"),
                F("image", f"registry.example.org/app:{r.randint(1, 3)}.{r.randint(0, 30)}.{r.randint(0, 9)}-alpine",
                  kind=kind, concept="version")]
    if kind == "event_date":
        y = r.randint(1970, 2006)
        names = {"en": ("created", "at"), "de": ("erstellt", "am"), "fr": ("date", "de", "création"),
                 "es": ("fecha", "de", "alta"), "it": ("data", "di", "creazione"), "nl": ("aangemaakt", "op"),
                 "sv": ("skapad", "datum"), "pl": ("data", "utworzenia"), "pt": ("data", "de", "criação")}
        from bench.structvocab import render
        st = style if style != "abbr" else "snake"
        return [F(render(tuple(V.fold_plain(x) for x in names[lang]) if st != "human" else names[lang], st, lang),
                  V.date_text(r, lang, r.randint(2019, 2026), r.randint(1, 12), r.randint(1, 28)), kind=kind,
                  concept="event_date"),
                F("valid_until", f"{r.randint(2026, 2031)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}", kind=kind,
                  concept="event_date"),
                F("founded", V.date_text(r, lang, y, r.randint(1, 12), r.randint(1, 28)), kind=kind,
                  concept="event_date"),
                F("contract_start", V.date_text(r, lang, r.randint(1990, 2026), r.randint(1, 12), r.randint(1, 28)),
                  kind=kind, concept="event_date")]
    if kind == "company_contact":
        org = r.choice(("Nordwind Logistik GmbH", "Atelier Solenne SARL", "Cobalt Systems Inc.", "Vela Ricambi S.r.l.",
                        "Kuststad Verktyg AB", "Lumen Software B.V."))
        pre = {"en": "company", "de": "firma", "fr": "societe", "es": "empresa", "it": "azienda", "nl": "bedrijf",
               "sv": "foretag", "pl": "firma", "pt": "empresa"}[lang]
        p = V.person(r, lang)
        return [F(pre + "_name" if style != "human" else pre.title(), org, kind=kind, concept="company"),
                f("address", V.full_address(r, p)[0], name=field_name("address", lang, style, r, pre)[0]),
                f("phone", V.phone(r, lang), name=field_name("phone", lang, style, r, "support")[0]),
                F("hotline" if lang == "en" else "service_hotline", V.phone(r, lang), kind=kind, concept="phone")]
    if kind == "schema_doc":
        return [f("email", "string, format email: the customer's e-mail address"),
                f("birth_date", "string (date), ISO 8601, e.g. YYYY-MM-DD"),
                f("phone", "E.164 phone number, max 15 digits"),
                f("iban", "IBAN of the payout account, validated with mod 97"),
                f("password", "min 12 chars, hashed with bcrypt before storage")]
    if kind == "fixture":
        return [f("full_name", r.choice(("Max Mustermann", "Erika Mustermann", "John Doe", "Jane Doe"))),
                f("card", r.choice(("4111 1111 1111 1111", "4242424242424242", "5555555555554444"))),
                f("iban", r.choice((
                    "DE89370400440532013000", "GB82WEST12345698765432", "FR1420041010050500013M02606"))),
                f("ssn", r.choice(("078-05-1120", "123-45-6789", "000-00-0000"))),
                f("email", r.choice(("test@example.com", "user@example.org", "jane.doe@example.com")))]
    if kind == "config_default":
        return [F("port", str(r.choice((5432, 3306, 6379, 8080))), kind=kind, concept="port", raw=True),
                F(fn("password") + "_min_length", str(r.choice((8, 10, 12, 16))), kind=kind, concept="password",
                  raw=True),
                F("max_login_attempts", str(r.randint(3, 10)), kind=kind, concept="config", raw=True),
                F(fn("api_key") + "_ttl", r.choice(("15m", "3600", "24h", "P30D")), kind=kind, concept="api_key"),
                F(fn("phone") + "_verification", r.choice(("true", "false", "required")), kind=kind, concept="phone"),
                F("key_size", r.choice(("2048", "4096")), kind=kind, concept="private_key", raw=True)]
    if kind == "enum_role":
        return [F("role", r.choice(("admin", "owner", "viewer", "editor", "guest")), kind=kind, concept="role"),
                f("username", r.choice(("root", "postgres", "www-data", "admin", "service-account", "ci-bot"))),
                f("full_name", r.choice(("Default", "Administrator", "System", "Production", "Main warehouse",
                                         "Support Team", "Unknown"))),
                F("plan", r.choice(("free", "pro", "enterprise")), kind=kind, concept="enum"),
                F("gender_options", "female|male|diverse", kind=kind, concept="enum")]
    if kind == "private_ip":
        return [f("ip", r.choice(("10.0.3.17", "192.168.1.20", "172.17.0.2", "127.0.0.1", "192.0.2.44",
                                  "198.51.100.7", "::1", "fd00::12"))),
                F("bind_address", "0.0.0.0", kind=kind, concept="ip"),
                F("gateway", "10.0.0.1", kind=kind, concept="ip")]
    raise ValueError(kind)


NEG_KINDS = ("placeholder", "masked", "hash", "uuid", "version_build", "event_date", "company_contact", "schema_doc",
             "fixture", "config_default", "enum_role", "private_ip")


# --------------------------------------------------------------------------------------------- renderers --
def _quoted_name(name: str) -> str:
    return name if name.replace("_", "").isalnum() and name.isascii() and name[:1].isalpha() else f"`{name}`"


def _json_value(t, f):
    if f.raw:
        t.value(f, f.value)
    else:
        t.add('"')
        t.value(f, _json_esc(f.value))
        t.add('"')


def r_json_flat(t, rows, r, meta):
    pretty = r.random() < 0.7
    sep, ind = (",\n", "  ") if pretty else (", ", "")
    t.add("{\n" if pretty else "{")
    for i, f in enumerate(rows[0]):
        t.add((sep if i else "") + ind + json.dumps(f.name, ensure_ascii=False) + ": ")
        _json_value(t, f)
    t.add("\n}\n" if pretty else "}\n")
    return "json"


_PARENT = {"phone": ("number",), "email": ("address",), "birth_date": ("date",)}


def r_json_nested(t, rows, r, meta):
    """A response envelope: data -> entity (one record) or items (several), each record split into groups; a phone,
    an e-mail or a birth date sometimes as {"<field>": {"type": …, "value": …}} so the label is the parent key."""
    ent = ENTITIES[meta["lang"]][1]

    def record(fields, depth):
        pad = "  " * depth
        t.add("{")
        for i, f in enumerate(fields):
            t.add(("," if i else "") + "\n" + pad + "  " + json.dumps(f.name, ensure_ascii=False) + ": ")
            if f.cls and f.concept in _PARENT and r.random() < 0.35:
                f.tags["keypath"] = "parent"
                t.add('{"type": "' + r.choice(("primary", "home", "work", "mobile")) + '", "'
                      + r.choice(("value",) + _PARENT[f.concept]) + '": ')
                _json_value(t, f)
                t.add("}")
            else:
                _json_value(t, f)
        t.add("\n" + pad + "}")

    t.add('{\n  "status": "ok",\n  "data": {\n    ')
    if len(rows) == 1:
        t.add(json.dumps(ent) + ": ")
        record(rows[0], 2)
    else:
        t.add('"items": [')
        for i, row in enumerate(rows):
            t.add(", " if i else "")
            record(row, 3)
        t.add("]")
    t.add('\n  },\n  "meta": {"page": 1, "request_id": "' + V.rd(r, 16, V.HEX) + '"}\n}\n')
    return "json"


def r_json_escaped(t, rows, r, meta):
    """An event whose payload is JSON inside a JSON string: every quote of the payload is written \\"."""
    t.add('{"event": "' + r.choice(("customer.updated", "user.created", "profile.synced", "webhook.received"))
          + '", "attempt": ' + str(r.randint(1, 5)) + ', "payload": "{')
    for i, f in enumerate(rows[0]):
        t.add((", " if i else "") + '\\"' + _json_esc(_json_esc(f.name)) + '\\": ')
        if f.raw:
            t.value(f, f.value)
        else:
            t.add('\\"')
            t.value(f, _json_esc(_json_esc(f.value)))
            t.add('\\"')
    t.add('}"}\n')
    return "json"


def _yaml_scalar(v: str, r) -> tuple:
    if "\n" in v:
        return None
    plain = v and not any(c in v for c in ":#{}[],&*!|>'\"%@`") and v[0] not in "-? " and v == v.strip()
    if plain and r.random() < 0.6:
        return "", v, ""
    if r.random() < 0.5 and "'" not in v:
        return "'", v, "'"
    return '"', _json_esc(v), '"'


def r_yaml(t, rows, r, meta):
    ent = ENTITIES[meta["lang"]][0 if len(rows) > 1 else 1]
    t.add(f"{ent}:\n")
    for row in rows:
        for i, f in enumerate(row):
            lead = ("  - " if i == 0 else "    ") if len(rows) > 1 else "  "
            key = f.name if not any(c in f.name for c in ": ") else json.dumps(f.name, ensure_ascii=False)
            t.add(f"{lead}{key}: ")
            if "\n" in f.value:
                ind = " " * (len(lead) + 2)
                t.add("|\n" + ind)
                lines = f.value.split("\n")
                t.value(f, ("\n" + ind).join(lines))
                t.add("\n")
                continue
            q1, v, q2 = _yaml_scalar(f.value, r)
            t.add(q1)
            t.value(f, v)
            t.add(q2 + "\n")
    return "yaml"


def _env_line(t, f, r, sep="="):
    if "\n" in f.value:
        t.add(f.name + sep + '"')
        t.value(f, f.value.replace("\n", "\\n"))
        t.add('"\n')
        return
    q = '"' if (" " in f.value or r.random() < 0.25) else ""
    t.add(f.name + sep + q)
    t.value(f, f.value)
    t.add(q + "\n")


def r_env(t, rows, r, meta):
    t.add(r.choice(("# .env\n", "# production settings\n", "")))
    for f in rows[0]:
        _env_line(t, f, r)
    return "config"


def r_ini(t, rows, r, meta):
    t.add(f"[{r.choice(('database', 'service', ENTITIES[meta['lang']][1], 'auth'))}]\n")
    for i, f in enumerate(rows[0]):
        if i and i % 4 == 0:
            t.add(f"\n[{r.choice(('smtp', 'api', 'profile', 'billing'))}]\n")
        if "\n" in f.value:
            t.add(f"{f.name} = ")
            t.value(f, f.value.replace("\n", "\n  "))
            t.add("\n")
            continue
        t.add(f"{f.name} = ")
        t.value(f, f.value)
        t.add("\n")
    return "config"


def _xml_tag(name: str) -> str:
    return name if name[:1].isalpha() and all(c.isalnum() or c in "-_." for c in name) else name.replace(" ", "_")


def r_xml_elem(t, rows, r, meta):
    ent = ENTITIES[meta["lang"]]
    t.add('<?xml version="1.0" encoding="UTF-8"?>\n' if r.random() < 0.6 else "")
    t.add(f"<{ent[0]}>\n")
    for row in rows:
        t.add(f'  <{ent[1]} id="{r.randint(1, 9999)}">\n')
        for f in row:
            tag = _xml_tag(f.name)
            t.add(f"    <{tag}>")
            t.value(f, _xml_esc(f.value))
            t.add(f"</{tag}>\n")
        t.add(f"  </{ent[1]}>\n")
    t.add(f"</{ent[0]}>\n")
    return "code"


def r_xml_attr(t, rows, r, meta):
    ent = ENTITIES[meta["lang"]]
    t.add(f"<{ent[0]}>\n")
    for row in rows:
        t.add(f"  <{ent[1]}")
        for f in row:
            t.add(f' {_xml_tag(f.name)}="')
            t.value(f, _xml_esc(f.value).replace("\n", "&#10;"))
            t.add('"')
        t.add(" />\n")
    t.add(f"</{ent[0]}>\n")
    return "code"


def r_html_table(t, rows, r, meta):
    t.add('<table class="' + r.choice(("table", "data-grid", "report")) + '">\n  <thead><tr>')
    t.add("".join(f"<th>{_xml_esc(f.name)}</th>" for f in rows[0]) + "</tr></thead>\n  <tbody>\n")
    for row in rows:
        t.add("    <tr>")
        for f in row:
            t.add("<td>")
            t.value(f, _xml_esc(f.value))
            t.add("</td>")
        t.add("</tr>\n")
    t.add("  </tbody>\n</table>\n")
    return "code"


def _sql_values(t, row, sep=", ", lead=""):
    t.add("(" + lead)
    for j, f in enumerate(row):
        t.add(sep if j or lead else "")
        if f.raw:
            t.value(f, f.value)
        else:
            t.add("'")
            t.value(f, _sql_esc(f.value))
            t.add("'")
    t.add(")")


def r_sql_insert(t, rows, r, meta):
    table = ENTITIES[meta["lang"]][0]
    t.add(f"INSERT INTO {table} (" + ", ".join(_quoted_name(f.name) for f in rows[0]) + ") VALUES\n")
    for i, row in enumerate(rows):
        t.add("  " if i == 0 else ",\n  ")
        _sql_values(t, row)
    t.add(";\n")
    return "code"


def r_sql_dump(t, rows, r, meta):
    """mysqldump: CREATE TABLE with the columns, then INSERT INTO `t` VALUES (…),(…) without a column list."""
    table = ENTITIES[meta["lang"]][0]
    t.add(f"--\n-- Table structure for table `{table}`\n--\n\nDROP TABLE IF EXISTS `{table}`;\n"
          f"CREATE TABLE `{table}` (\n  `id` int(11) NOT NULL AUTO_INCREMENT,\n")
    for f in rows[0]:
        typ = "int(11) NOT NULL" if f.raw else f"varchar({r.choice((64, 128, 255))}) DEFAULT NULL"
        t.add(f"  `{f.name}` {typ},\n")
    t.add("  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n")
    t.add(f"LOCK TABLES `{table}` WRITE;\nINSERT INTO `{table}` VALUES ")
    for i, row in enumerate(rows):
        t.add("," if i else "")
        _sql_values(t, row, ",", str(i + 1))
    t.add(";\nUNLOCK TABLES;\n")
    return "code"


def r_sql_bare(t, rows, r, meta):
    """An INSERT without a column list and without its CREATE TABLE: the values have no label in the text."""
    table = ENTITIES[meta["lang"]][0]
    t.add(f"INSERT INTO `{table}` VALUES ")
    for i, row in enumerate(rows):
        t.add("," if i else "")
        _sql_values(t, row, ",", str(r.randint(1, 9999)))
    t.add(";\n")
    meta["labels"] = "none"
    return "code"


def r_sql_update(t, rows, r, meta):
    table = ENTITIES[meta["lang"]][0]
    t.add(f"UPDATE {table} SET ")
    for j, f in enumerate(rows[0]):
        t.add((", " if j else "") + _quoted_name(f.name) + " = ")
        if f.raw:
            t.value(f, f.value)
        else:
            t.add("'")
            t.value(f, _sql_esc(f.value))
            t.add("'")
    t.add(f" WHERE id = {r.randint(1, 99999)};\n")
    return "code"


def r_sql_where(t, rows, r, meta):
    table = ENTITIES[meta["lang"]][0]
    t.add(f"SELECT id, {r.choice(('status', 'created_at', '*'))} FROM {table}\nWHERE ")
    for j, f in enumerate(rows[0]):
        t.add(("\n  AND " if j else "") + _quoted_name(f.name) + " = ")
        if f.raw:
            t.value(f, f.value)
        else:
            t.add("'")
            t.value(f, _sql_esc(f.value))
            t.add("'")
    t.add(";\n")
    return "code"


_CSV_SEP = {"en": ",", "de": ";", "fr": ";", "es": ";", "it": ";", "nl": ";", "sv": ";", "pl": ";", "pt": ";"}


def r_csv(t, rows, r, meta):
    sep = "\t" if r.random() < 0.3 else (_CSV_SEP[meta["lang"]] if r.random() < 0.7 else ",")
    meta["variant"] = "tsv" if sep == "\t" else "semicolon" if sep == ";" else "comma"
    t.add(sep.join(f.name if sep not in f.name else f'"{f.name}"' for f in rows[0]) + "\n")
    for row in rows:
        for j, f in enumerate(row):
            t.add(sep if j else "")
            q = sep in f.value or '"' in f.value or (" " in f.value and r.random() < 0.5)
            t.add('"' if q else "")
            t.value(f, f.value.replace('"', '""'))
            t.add('"' if q else "")
        t.add("\n")
    return "code"


def r_md_table(t, rows, r, meta):
    t.add("| " + " | ".join(f.name for f in rows[0]) + " |\n|" + "|".join("---" for _ in rows[0]) + "|\n")
    for row in rows:
        t.add("|")
        for f in row:
            t.add(" ")
            t.value(f, f.value.replace("|", "\\|"))
            t.add(" |")
        t.add("\n")
    return "doc"


_KV_HEAD = {"en": ("Field", "Value"), "de": ("Feld", "Wert"), "fr": ("Champ", "Valeur"), "es": ("Campo", "Valor"),
            "it": ("Campo", "Valore"), "nl": ("Veld", "Waarde"), "sv": ("Fält", "Värde"), "pl": ("Pole", "Wartość"),
            "pt": ("Campo", "Valor")}


def r_md_kv(t, rows, r, meta):
    """A two-column table of field and value; half of them with an empty head row (no header)."""
    if r.random() < 0.5:
        a, b = _KV_HEAD[meta["lang"]]
        t.add(f"| {a} | {b} |\n|---|---|\n")
    else:
        meta["variant"] = "no-header"
        t.add("| | |\n|---|---|\n")
    for f in rows[0]:
        t.add(f"| {f.name} | ")
        t.value(f, f.value.replace("|", "\\|"))
        t.add(" |\n")
    return "doc"


def r_log_kv(t, rows, r, meta):
    for row in rows:
        t.add(f"2026-10-{r.randint(1, 24):02d}T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}."
              f"{r.randint(0, 999):03d}Z {r.choice(('INFO', 'WARN', 'DEBUG', 'ERROR'))} "
              f"[{r.choice(('api', 'billing', 'auth', 'worker', 'sync'))}] "
              f"{r.choice(('profile updated', 'login', 'signup', 'payment captured', 'export row'))}")
        for f in row:
            if "\n" in f.value:
                continue
            q = '"' if " " in f.value else ""
            t.add(f" {f.name}={q}")
            t.value(f, f.value.replace('"', '\\"'))
            t.add(q)
        t.add("\n")
    return "log"


def r_http(t, rows, r, meta):
    """A request as a proxy or a debug log prints it: the token in a header, the record in the query string (each
    value percent-encoded as it stands in the URL)."""
    fields = list(rows[0])
    header = next((f for f in fields if f.concept == "api_key"), None)
    t.add(f"{r.choice(('GET', 'POST'))} /api/v{r.randint(1, 3)}/{r.choice(('customers', 'search', 'profile'))}?")
    q = [f for f in fields if f is not header and "\n" not in f.value]
    for j, f in enumerate(q):
        t.add(("&" if j else "") + urllib.parse.quote(f.name, safe="") + "=")
        t.value(f, urllib.parse.quote_plus(f.value, safe=""))
    t.add(f" HTTP/1.1\nHost: api.{r.choice(V.HOST_SUFFIXES)}\nAccept: application/json\n")
    if header is not None:
        if r.random() < 0.6:
            t.add("Authorization: Bearer ")
        else:
            t.add(r.choice(("X-Api-Key", "X-Auth-Token", "Api-Key")) + ": ")
        t.value(header, header.value)
        t.add("\n")
    t.add(f"User-Agent: {r.choice(('curl/8.7.1', 'python-requests/2.32.3', 'okhttp/4.12.0'))}\n")
    for f in fields:
        if "\n" in f.value:     # a key cannot go into a URL; a debug print shows it after the request
            t.add(f"\n{f.name}:\n")
            t.value(f, f.value)
            t.add("\n")
    return "url"


def r_stacktrace(t, rows, r, meta):
    body_t = rows[0]
    if r.random() < 0.5:
        t.add("Traceback (most recent call last):\n  File \"/srv/app/api/views.py\", line "
              f"{r.randint(20, 400)}, in update_profile\n    serializer.is_valid(raise_exception=True)\n"
              "rest_framework.exceptions.ValidationError: invalid request\nrequest body: {")
        for i, f in enumerate(body_t):
            t.add((", " if i else "") + json.dumps(f.name, ensure_ascii=False) + ": ")
            _json_value(t, f)
        t.add("}\n")
    else:
        t.add("com.fasterxml.jackson.databind.exc.InvalidFormatException: Cannot deserialize value\n"
              " at [Source: (String)\"{")
        for i, f in enumerate(body_t):
            t.add((",\"" if i else '"') + _json_esc(f.name) + '":')
            if f.raw:
                t.value(f, f.value)
            else:
                t.add('"')
                t.value(f, _json_esc(f.value))
                t.add('"')
        t.add('}"; line: 1, column: ' + str(r.randint(10, 300)) + ']\n'
              "\tat com.example.api.CustomerController.update(CustomerController.java:"
              f"{r.randint(30, 300)})\n\tat java.base/java.lang.Thread.run(Thread.java:1583)\n")
    return "stacktrace"


def r_debug_print(t, rows, r, meta):
    """A Python dict repr or a PHP print_r of the record."""
    if r.random() < 0.6:
        t.add(r.choice(("DEBUG payload=", ">>> print(user)\n", "data = ")) + "{")
        for i, f in enumerate(rows[0]):
            t.add((", " if i else "") + "'" + _py_esc(f.name) + "': ")
            if f.raw:
                t.value(f, f.value)
            else:
                t.add("'")
                t.value(f, _py_esc(f.value))
                t.add("'")
        t.add("}\n")
    else:
        meta["variant"] = "php"
        t.add("Array\n(\n")
        for f in rows[0]:
            t.add(f"    [{f.name}] => ")
            t.value(f, f.value)
            t.add("\n")
        t.add(")\n")
    return "code"


def r_seed_script(t, rows, r, meta):
    """A knex seed (JavaScript) or a Django data migration (Python) that inserts the records."""
    table = ENTITIES[meta["lang"]][0]
    if r.random() < 0.5:
        t.add(f"exports.seed = async function (knex) {{\n  await knex('{table}').del();\n"
              f"  await knex('{table}').insert([\n")
        for row in rows:
            t.add("    { ")
            for j, f in enumerate(row):
                key = f.name if f.name.replace("_", "").isalnum() and f.name.isascii() else f"'{f.name}'"
                t.add((", " if j else "") + key + ": ")
                if f.raw:
                    t.value(f, f.value)
                else:
                    t.add("'")
                    t.value(f, _py_esc(f.value))
                    t.add("'")
            t.add(" },\n")
        t.add("  ]);\n};\n")
    else:
        meta["variant"] = "django-migration"
        t.add("from django.db import migrations\n\n\ndef seed(apps, schema_editor):\n"
              f"    Model = apps.get_model('crm', '{ENTITIES[meta['lang']][1].title()}')\n")
        for row in rows:
            t.add("    Model.objects.create(**{")
            for j, f in enumerate(row):
                t.add((", " if j else "") + "'" + _py_esc(f.name) + "': ")
                if f.raw:
                    t.value(f, f.value)
                else:
                    t.add("'")
                    t.value(f, _py_esc(f.value))
                    t.add("'")
            t.add("})\n")
        t.add("\n\nclass Migration(migrations.Migration):\n    dependencies = [('crm', '0007_auto')]\n"
              "    operations = [migrations.RunPython(seed)]\n")
    return "code"


def r_migration(t, rows, r, meta):
    """A Flyway SQL migration: an ALTER TABLE and a backfill UPDATE per record."""
    table = ENTITIES[meta["lang"]][0]
    t.add(f"-- V{r.randint(2, 90)}__backfill_{table}.sql\nALTER TABLE {table} ADD COLUMN "
          f"{_quoted_name(rows[0][0].name)} VARCHAR(255);\n")
    for row in rows:
        t.add(f"UPDATE {table} SET ")
        for j, f in enumerate(row):
            t.add((", " if j else "") + _quoted_name(f.name) + " = ")
            if f.raw:
                t.value(f, f.value)
            else:
                t.add("'")
                t.value(f, _sql_esc(f.value))
                t.add("'")
        t.add(f" WHERE id = {r.randint(1, 99999)};\n")
    return "code"


def r_api_response(t, rows, r, meta):
    t.add(f"HTTP/1.1 200 OK\nContent-Type: application/json; charset=utf-8\nX-Request-Id: {V.rd(r, 24, V.HEX)}\n"
          f"Date: Sat, {r.randint(1, 24):02d} Oct 2026 {r.randint(0, 23):02d}:{r.randint(0, 59):02d}:00 GMT\n\n")
    return r_json_flat(t, rows, r, meta)


def r_docker_compose(t, rows, r, meta):
    svc = r.choice(("api", "db", "worker", "app"))
    t.add(f"services:\n  {svc}:\n    image: registry.example.org/{svc}:{r.randint(1, 4)}.{r.randint(0, 20)}\n"
          "    environment:\n")
    lst = r.random() < 0.5
    meta["variant"] = "list" if lst else "map"
    for f in rows[0]:
        if "\n" in f.value:
            t.add(f"      {f.name}: |\n        ")
            t.value(f, f.value.replace("\n", "\n        "))
            t.add("\n")
        elif lst:
            t.add(f"      - {f.name}=")
            t.value(f, f.value)
            t.add("\n")
        else:
            q = '"' if r.random() < 0.5 else ""
            t.add(f"      {f.name}: {q}")
            t.value(f, _json_esc(f.value) if q else f.value)
            t.add(q + "\n")
    t.add(f"    ports:\n      - \"{r.choice((8080, 5432, 3000))}:{r.choice((8080, 5432, 3000))}\"\n")
    return "yaml"


def r_ci_log(t, rows, r, meta):
    t.add(f"Running with gitlab-runner 17.{r.randint(0, 9)}.{r.randint(0, 3)}\n"
          f"Preparing the \"docker\" executor\nGetting source from Git repository\n"
          f"$ echo \"deploying to {r.choice(('staging', 'production'))}\"\n")
    for f in rows[0]:
        if "\n" in f.value:
            t.add("$ cat > key.pem <<'EOF'\n")
            t.value(f, f.value)
            t.add("\nEOF\n")
        elif r.random() < 0.5:
            t.add(f"$ export {f.name}=")
            t.value(f, f.value)
            t.add("\n")
        else:
            t.add(f"[deploy] {f.name}: ")
            t.value(f, f.value)
            t.add("\n")
    t.add("Job succeeded\n")
    return "log"


# name, renderer, kind of content (record: a person; config: secrets), allows a name with spaces, private keys
FORMATS = (
    ("json_flat", r_json_flat, "record", True), ("json_nested", r_json_nested, "record", True),
    ("json_escaped", r_json_escaped, "record", True), ("yaml", r_yaml, "mixed", True),
    ("env", r_env, "config", False), ("ini", r_ini, "config", False),
    ("xml_element", r_xml_elem, "record", False), ("xml_attribute", r_xml_attr, "record", False),
    ("html_table", r_html_table, "table", True), ("sql_insert", r_sql_insert, "table", False),
    ("sql_dump", r_sql_dump, "table", False), ("sql_insert_bare", r_sql_bare, "table", False),
    ("sql_update", r_sql_update, "record", False), ("sql_where", r_sql_where, "record", False),
    ("csv", r_csv, "table", True), ("md_table", r_md_table, "table", True), ("md_kv", r_md_kv, "record", True),
    ("log_kv", r_log_kv, "mixed", False), ("http", r_http, "config", False),
    ("stacktrace", r_stacktrace, "record", True), ("debug_print", r_debug_print, "record", True),
    ("seed_script", r_seed_script, "table", True), ("migration", r_migration, "table", False),
    ("api_response", r_api_response, "record", True), ("docker_compose", r_docker_compose, "config", False),
    ("ci_log", r_ci_log, "config", False),
)
FORMAT_NAMES = tuple(f[0] for f in FORMATS)
_PATHS = {"env": "deploy/.env.production", "ini": "conf/app.ini", "yaml": "config/{ent}.yml",
          "docker_compose": "docker-compose.yml", "sql_dump": "backup/{ent}.sql", "migration": "db/migrations/V7.sql",
          "csv": "exports/{ent}.csv", "seed_script": "db/seeds/{ent}.js", "xml_element": "export/{ent}.xml"}
_PROMPT_FORMATS = ("csv", "md_table", "md_kv", "sql_insert", "json_flat", "html_table", "stacktrace", "log_kv")


def _rows(r, kind_of, lang, style, n_rows, fmt, negative, neg_kinds):
    """The rows of a case: the same field names in each row, new values per row."""
    no_pem = fmt in ("csv", "md_table", "md_kv", "html_table", "sql_insert", "sql_dump", "sql_insert_bare",
                     "sql_update", "sql_where", "migration", "xml_attribute", "log_kv", "seed_script")
    rows = []
    proto = None
    for _ in range(n_rows):
        if negative:
            fields = []
            for k in neg_kinds:
                fields.extend(_neg_fields(r, lang, style, k))
            fields.extend(_plain_fields(r, lang, style, r.randint(1, 3)))
        else:
            p = V.person(r, lang)
            if kind_of == "config":
                fields = _config_fields(r, lang, style, p, r.randint(2, 4))
            elif kind_of == "mixed" and r.random() < 0.5:
                fields = _config_fields(r, lang, style, p, r.randint(2, 3)) + _person_fields(r, lang, style, p, 1)
            else:
                fields = _person_fields(r, lang, style, p, r.randint(2, 5))
                if kind_of != "table" and r.random() < 0.2:
                    fields.extend(_config_fields(r, lang, style, p, 1))
            fields.extend(_plain_fields(r, lang, style, r.randint(1, 3)))
        if no_pem:
            fields = [f for f in fields if "\n" not in f.value]
        seen, uniq = set(), []
        for f in fields:
            if f.name not in seen:
                seen.add(f.name)
                uniq.append(f)
        if proto is None:
            r.shuffle(uniq)
            proto = uniq
            rows.append(uniq)
        else:
            by_concept = {}
            for f in uniq:
                by_concept.setdefault(f.concept, f)
            row = []
            for pf in proto:
                nf = by_concept.get(pf.concept)
                if nf is None or nf.cls != pf.cls or nf.kind != pf.kind:
                    nf = F(pf.name, pf.value, pf.cls, pf.core, pf.kind, pf.concept, dict(pf.tags), pf.raw)
                else:
                    nf.name, nf.tags = pf.name, dict(pf.tags)
                row.append(nf)
            rows.append(row)
    return rows


def generate(count: int = COUNT, seed: int = SEED):
    """The cases, balanced over format x language x style; a quarter of them negatives."""
    rnd = random.Random(seed)
    nf, nl = len(FORMATS), len(V.LANGS)
    for i in range(count):
        fmt, render_fn, kind_of, spaces = FORMATS[i % nf]
        lang = V.LANGS[(i // nf) % nl]
        style = STYLES[(i // (nf * nl) + i) % len(STYLES)]
        r = random.Random(f"{seed}/{i}/{rnd.random()}")
        if fmt == "env" and r.random() < 0.8:
            style = "upper"
        if style == "human" and not spaces:
            style = "snake"
        negative = r.random() < NEGATIVE_SHARE
        neg_kinds = r.sample(NEG_KINDS, r.choice((1, 1, 2))) if negative else []
        n_rows = r.choice((2, 2, 3, 4)) if kind_of == "table" else (r.choice((1, 1, 2)) if fmt in (
            "yaml", "json_nested", "log_kv", "xml_element", "xml_attribute") else 1)
        rows = _rows(r, kind_of, lang, style, n_rows, fmt, negative, neg_kinds)
        meta = {"lang": lang}
        t = Text()
        context = render_fn(t, rows, r, meta)
        record = f"{fmt}/{lang}/{i}"
        channel = "prompt" if fmt in _PROMPT_FORMATS and r.random() < 0.2 else "tool"
        path = None
        if "fixture" in neg_kinds:
            path = f"tests/fixtures/{ENTITIES[lang][0]}_{fmt}.txt"
        elif fmt in _PATHS and r.random() < 0.6:
            path = _PATHS[fmt].format(ent=ENTITIES[lang][0])
        if fmt == "seed_script" and path and meta.get("variant") == "django-migration":
            path = "crm/migrations/0008_seed.py"
        tags = [f"format:{fmt}", f"lang:{lang}", f"style:{style}", f"kind:{'negative' if negative else kind_of}"]
        tags += [f"neg:{k}" for k in neg_kinds] + ([f"variant:{meta['variant']}"] if "variant" in meta else [])
        tags += ["labels:none"] * (meta.get("labels") == "none")
        yield {"id": f"structured/{record}", "text": t.text(), "channel": channel, "context": context, "path": path,
               "spans": t.spans, "lookalikes": t.lookalikes, "split": _split(record), "tags": tags,
               "region": V.REGION[lang], "lang": lang,
               "source": {"name": "structured", "set": "A", "record": record, "seed": seed}}


def _split(record: str) -> str:
    """Template set A is development data: dev (60 %) and val (40 %, the same templates with other values, for a
    check before a merge). Its holdout is set B, never a split of A."""
    return "dev" if cases.split_of("structured", record) == "dev" else "val"


def stats(cs) -> dict:
    import collections
    out = {k: collections.Counter() for k in ("format", "lang", "style", "class", "kind", "neg", "context",
                                              "channel", "split", "diacritics")}
    for c in cs:
        for tag in c["tags"]:
            k, _, v = tag.partition(":")
            if k in out:
                out[k][v] += 1
        out["context"][c["context"]] += 1
        out["channel"][c["channel"]] += 1
        out["split"][c["split"]] += 1
        for s in c["spans"]:
            out["class"][s["class"] + (" (neutral)" if s.get("neutral") else "")] += 1
            out["diacritics"][s.get("diacritics", "-")] += 1
    return {k: dict(v.most_common()) for k, v in out.items()}


if __name__ == "__main__":
    if "--stats" in sys.argv:
        cs = list(generate())
        print(json.dumps({"cases": len(cs), "spans": sum(len(c["spans"]) for c in cs),
                          "lookalikes": sum(len(c["lookalikes"]) for c in cs), **stats(cs)}, indent=1,
                         ensure_ascii=False))
