"""Protocol traces: a seeded generator of development cases in the shapes a tool result has (docs/BENCHMARK-V2.md,
"Development sources after the freeze").

Privy, the independent set of Benchmark V2, showed a precision of 0.44 for maisecrets on personal data against 0.90 to
0.99 on the development data, and its cases are protocol traces. Its cases are never read for a rule, so this source
gives the same kind of text as development data of its own: records of an API, a database, a web page and a log, each
with a few personal fields among many fields that only look like them (order numbers, ids, hashes, timestamps,
prices, versions). The formats and field names come from common practice of these protocols, not from Privy.

Nothing is stored: the cases are made at run time from one seed, so the tree holds no value. A personal field is a
span of its class. The city and the postcode of a split address are neutral spans (a hit there is neither right nor
wrong); every other field is text that must stay text.

    python3 bench/run.py --source traces --split dev --out traces-dev.json"""
from __future__ import annotations

import json
import random

from bench import cases

SEED = 20261020
COUNT = 3000

FIRST = ("James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda", "David", "Elizabeth",
         "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Carlos", "Karen",
         "Daniel", "Lisa", "Matthew", "Nancy", "Anthony", "Sandra", "Mark", "Ashley", "Priya", "Emily", "Wei",
         "Fatima", "Lukas", "Sofia", "Mateo", "Aisha", "Hiroshi", "Ingrid", "Olumide", "Elena")
LAST = ("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
        "Hernandez", "Lopez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee",
        "Thompson", "White", "Harris", "Clark", "Lewis", "Robinson", "Walker", "Young", "Nguyen", "Patel", "Kim",
        "Schneider", "Fischer", "Okafor", "Kowalski", "Rossi", "Haddad", "Novak", "Lindqvist", "Tanaka")
STREETS = ("Oak", "Maple", "Cedar", "Pine", "Elm", "Washington", "Lake", "Hill", "Park", "Sunset", "River", "Highland",
           "Meadow", "Forest", "Church", "Spring", "Ridge", "Willow", "Harbor", "Mill")
STREET_KINDS = ("Street", "Avenue", "Road", "Drive", "Lane", "Court", "Boulevard", "Way", "Place", "Terrace")
CITIES = ("Springfield", "Riverside", "Fairview", "Madison", "Georgetown", "Franklin", "Clinton", "Salem", "Arlington",
          "Ashland", "Burlington", "Dover", "Milton", "Newport", "Oxford")
STATES = ("CA", "TX", "NY", "FL", "IL", "PA", "OH", "GA", "NC", "MI", "WA", "AZ", "MA", "CO", "OR")
DOMAINS = ("mailbox.net", "postfach.de", "inboxly.com", "quickmail.org", "letterpost.io", "corpmail.biz")
PRODUCTS = ("USB-C Cable 2m", "Wireless Mouse M310", "Laptop Stand Pro", "Noise Cancelling Headphones",
            "4K Monitor 27in", "Mechanical Keyboard K2", "Webcam HD 1080p", "Desk Lamp LED", "Portable SSD 1TB")
STATUSES = ("pending", "shipped", "delivered", "cancelled", "refunded", "processing", "active", "suspended")
DEPARTMENTS = ("Engineering", "Sales", "Support", "Finance", "Marketing", "Operations", "Legal", "Research")
TITLES = ("Account Manager", "Software Engineer", "Support Specialist", "Data Analyst", "Product Owner")
AGENTS = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
          "Version/17.6 Safari/605.1",
          "curl/8.7.1", "python-requests/2.32.3", "okhttp/4.12.0")
NOTES = ("Customer asked about the delivery date.", "Payment retried after timeout.", "Address verified by courier.",
         "Refund issued for damaged item.", "Ticket escalated to tier 2.", "Duplicate request ignored.")


def _luhn_complete(prefix: str, length: int, rnd: random.Random) -> str:
    body = prefix + "".join(rnd.choice("0123456789") for _ in range(length - len(prefix) - 1))
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


def _iban_de(rnd: random.Random) -> str:
    bban = "".join(rnd.choice("0123456789") for _ in range(18))
    check = 98 - int(bban + "131400") % 97
    return f"DE{check:02d}{bban}"


def _ssn(rnd: random.Random) -> str:
    area = rnd.choice([a for a in range(1, 900) if a != 666])
    return f"{area:03d}-{rnd.randint(1, 99):02d}-{rnd.randint(1, 9999):04d}"


def _nanp(rnd: random.Random) -> str:
    area = rnd.choice([a for a in range(201, 990) if a % 100 != 11 and str(a)[1] != "9"])
    exch = rnd.choice([e for e in range(201, 1000) if e % 100 != 11 and e != 555])
    line = rnd.randint(0, 9999)
    return rnd.choice((f"({area}) {exch}-{line:04d}", f"{area}-{exch}-{line:04d}", f"{area}.{exch}.{line:04d}",
                       f"+1 {area} {exch} {line:04d}", f"+1-{area}-{exch}-{line:04d}"))


def _person(rnd: random.Random) -> dict:
    first, last = rnd.choice(FIRST), rnd.choice(LAST)
    year = rnd.randint(1940, 2005)
    return {
        "first": first, "last": last, "name": f"{first} {last}",
        "email": rnd.choice((f"{first}.{last}", f"{first[0]}{last}", f"{first}{rnd.randint(1, 99)}")).lower()
                 + "@" + rnd.choice(DOMAINS),
        "phone": _nanp(rnd),
        "street": f"{rnd.randint(1, 9899)} {rnd.choice(STREETS)} {rnd.choice(STREET_KINDS)}",
        "city": rnd.choice(CITIES), "state": rnd.choice(STATES), "zip": f"{rnd.randint(1001, 99950):05d}",
        "dob": rnd.choice((f"{year}-{rnd.randint(1, 12):02d}-{rnd.randint(1, 28):02d}",
                           f"{rnd.randint(1, 12):02d}/{rnd.randint(1, 28):02d}/{year}")),
        "ssn": _ssn(rnd),
        "card": _luhn_complete(rnd.choice(("4", "51", "52", "53", "54", "55", "37", "6011")),
                               15 if rnd.random() < 0.15 else 16, rnd),
        "iban": _iban_de(rnd),
        "account": "".join(rnd.choice("0123456789") for _ in range(rnd.randint(9, 12))),
        "username": rnd.choice((f"{first.lower()}{rnd.randint(10, 9999)}", f"{first[0].lower()}.{last.lower()}",
                                f"{last.lower()}_{first.lower()[:3]}")),
        "password": rnd.choice(("Summer", "Winter", "Falcon", "Tiger", "Orbit", "Maple")) + str(rnd.randint(10, 99))
                    + rnd.choice("!#$%&*") + rnd.choice(("xQ", "Lm", "Rz", "Tk")) + str(rnd.randint(100, 999)),
        "ip": f"{rnd.choice((73, 98, 174, 24, 67, 108))}.{rnd.randint(1, 254)}.{rnd.randint(0, 254)}."
              f"{rnd.randint(1, 254)}",
    }


# field name, the person key or None, the class or "" (text) or "neutral"
PERSONAL = (
    ("full_name", "name", "pii.name"), ("customer_name", "name", "pii.name"), ("email", "email", "pii.email"),
    ("contact_email", "email", "pii.email"), ("phone", "phone", "pii.phone"), ("mobile", "phone", "pii.phone"),
    ("street", "street", "pii.address"), ("address_line1", "street", "pii.address"),
    ("city", "city", "neutral"), ("postal_code", "zip", "neutral"), ("date_of_birth", "dob", "pii.birth_date"),
    ("dob", "dob", "pii.birth_date"), ("ssn", "ssn", "pii.national_id"), ("card_number", "card", "pii.card"),
    ("iban", "iban", "pii.iban"), ("account_number", "account", "pii.bank_account"),
    ("username", "username", "pii.username"), ("password", "password", "secret.password"),
    ("client_ip", "ip", "pii.ip"),
)
CLASS_CONTEXT = {"pii.name", "pii.email", "pii.phone", "pii.address", "pii.birth_date", "pii.national_id", "pii.card",
                 "pii.iban", "pii.bank_account", "pii.username", "secret.password", "pii.ip"}


def _plain_fields(rnd: random.Random) -> list:
    """Fields that look like the personal ones and are not: numbers, ids, dates of events, codes."""
    hexs = "0123456789abcdef"
    ts = (f"2026-{rnd.randint(1, 9):02d}-{rnd.randint(1, 28):02d}T{rnd.randint(0, 23):02d}:{rnd.randint(0, 59):02d}:"
          f"{rnd.randint(0, 59):02d}Z")
    pool = [
        ("order_id", str(rnd.randint(10_000_000, 99_999_999_999))), ("invoice_no", f"INV-{rnd.randint(2024, 2026)}-"
                                                                      f"{rnd.randint(1, 99999):05d}"),
        ("sku", f"{rnd.choice('ABCDEFGH')}{rnd.choice('KLMNPQRS')}-{rnd.randint(1000, 9999)}-{rnd.randint(10, 99)}"),
        ("product", rnd.choice(PRODUCTS)), ("quantity", str(rnd.randint(1, 12))),
        ("price", f"{rnd.randint(1, 1999)}.{rnd.randint(0, 99):02d}"), ("currency", rnd.choice(("USD", "EUR", "GBP"))),
        ("status", rnd.choice(STATUSES)), ("created_at", ts), ("updated_at", ts),
        ("request_id", "".join(rnd.choice(hexs) for _ in range(32))),
        ("uuid", "-".join("".join(rnd.choice(hexs) for _ in range(n)) for n in (8, 4, 4, 4, 12))),
        ("session_id", "".join(rnd.choice(hexs) for _ in range(24))),
        ("commit", "".join(rnd.choice(hexs) for _ in range(40))),
        ("tracking_number", "1Z" + "".join(rnd.choice("0123456789ABCDEFGHJKLMNPRSTUVWXYZ") for _ in range(16))),
        ("version", f"{rnd.randint(1, 9)}.{rnd.randint(0, 30)}.{rnd.randint(0, 200)}"),
        ("http_status", str(rnd.choice((200, 201, 204, 301, 400, 401, 403, 404, 409, 422, 500, 503)))),
        ("latency_ms", str(rnd.randint(3, 4800))), ("user_agent", rnd.choice(AGENTS)),
        ("department", rnd.choice(DEPARTMENTS)), ("job_title", rnd.choice(TITLES)),
        ("region", rnd.choice(("us-east-1", "eu-central-1", "ap-southeast-2"))),
        ("error_code", f"E{rnd.randint(1000, 9999)}"), ("build", str(rnd.randint(1000, 99999))),
        ("port", str(rnd.choice((443, 8080, 5432, 6379, 3306)))), ("country", rnd.choice(("US", "DE", "GB", "FR"))),
        ("customer_id", str(rnd.randint(100000, 9999999))), ("employee_no", f"E{rnd.randint(10000, 99999)}"),
        ("note", rnd.choice(NOTES)), ("ticket", f"SUP-{rnd.randint(100, 99999)}"),
        ("checksum", "".join(rnd.choice(hexs) for _ in range(64))),
    ]
    return rnd.sample(pool, rnd.randint(4, 9))


def _record(rnd: random.Random) -> list:
    """(field, value, class) in a random order; at least one personal field and mostly plain ones."""
    person = _person(rnd)
    personal = [(f, person[k], c) for f, k, c in rnd.sample(PERSONAL, rnd.randint(1, 5))]
    # a customer record names its person: most rows with a contact field also have a name field (a list of depots
    # or stations has none, and a scanner may keep its addresses as text)
    if not any(c == "pii.name" for _, _, c in personal) and rnd.random() < 0.85:
        personal.append((rnd.choice(("full_name", "customer_name")), person["name"], "pii.name"))
    fields = personal + [(f, v, "") for f, v in _plain_fields(rnd)]
    rnd.shuffle(fields)
    seen, out = set(), []
    for f, v, c in fields:
        if f not in seen:
            seen.add(f)
            out.append((f, v, c))
    return out


class _Text:
    """Text with spans: append text pieces, mark a value with its class."""

    def __init__(self):
        self.parts, self.spans, self.n = [], [], 0

    def add(self, s: str) -> None:
        self.parts.append(s)
        self.n += len(s)

    def value(self, v: str, cls: str) -> None:
        if cls:
            span = {"start": self.n, "end": self.n + len(v), "class": "pii.address" if cls == "neutral" else cls}
            if cls == "neutral":
                span["neutral"] = True
            self.spans.append(span)
        self.add(v)

    def text(self) -> str:
        return "".join(self.parts)


def _json(rows, rnd, t: _Text) -> str:
    t.add('{"data": [' if len(rows) > 1 else "{")
    for i, row in enumerate(rows):
        if len(rows) > 1:
            t.add(", {" if i else "{")
        for j, (f, v, c) in enumerate(row):
            t.add(("" if j == 0 else ", ") + json.dumps(f) + ": ")
            if f in ("quantity", "latency_ms", "http_status", "port", "build", "customer_id") and not c:
                t.add(v)
            else:
                t.add('"')
                t.value(v, c)
                t.add('"')
        t.add("}")
    t.add("], \"next_cursor\": null}" if len(rows) > 1 else "")
    return "json"


def _sql(rows, rnd, t: _Text) -> str:
    table = rnd.choice(("customers", "orders", "users", "accounts", "payments"))
    t.add(f"INSERT INTO {table} (" + ", ".join(f for f, _, _ in rows[0]) + ") VALUES\n")
    for i, row in enumerate(rows):
        t.add("  (" if i == 0 else ",\n  (")
        for j, (f, v, c) in enumerate(row):
            t.add("" if j == 0 else ", ")
            t.add("'")
            t.value(v.replace("'", "''"), c)
            t.add("'")
        t.add(")")
    t.add(";\n")
    return "code"


def _html(rows, rnd, t: _Text) -> str:
    if len(rows) == 1 and rnd.random() < 0.5:
        t.add('<form method="post" action="/account/update">\n')
        for f, v, c in rows[0]:
            t.add(f'  <label for="{f}">{f.replace("_", " ").title()}</label>\n  <input id="{f}" name="{f}" value="')
            t.value(v, c)
            t.add('">\n')
        t.add("</form>\n")
        return "code"
    t.add("<table>\n  <tr>" + "".join(f"<th>{f}</th>" for f, _, _ in rows[0]) + "</tr>\n")
    for row in rows:
        t.add("  <tr>")
        for f, v, c in row:
            t.add("<td>")
            t.value(v, c)
            t.add("</td>")
        t.add("</tr>\n")
    t.add("</table>\n")
    return "code"


def _xml(rows, rnd, t: _Text) -> str:
    t.add('<?xml version="1.0" encoding="UTF-8"?>\n<records>\n')
    for row in rows:
        t.add("  <record>\n")
        for f, v, c in row:
            t.add(f"    <{f}>")
            t.value(v, c)
            t.add(f"</{f}>\n")
        t.add("  </record>\n")
    t.add("</records>\n")
    return "code"


def _csv(rows, rnd, t: _Text) -> str:
    t.add(",".join(f for f, _, _ in rows[0]) + "\n")
    for row in rows:
        for j, (f, v, c) in enumerate(row):
            t.add("" if j == 0 else ",")
            quote = "," in v or " " in v
            t.add('"' if quote else "")
            t.value(v, c)
            t.add('"' if quote else "")
        t.add("\n")
    return "code"


def _log(rows, rnd, t: _Text) -> str:
    for row in rows:
        ts = next((v for f, v, c in row if f in ("created_at", "updated_at")), "2026-10-20T08:15:00Z")
        t.add(f"{ts} {rnd.choice(('INFO', 'WARN', 'DEBUG'))} [{rnd.choice(('api', 'billing', 'auth', 'worker'))}] ")
        for j, (f, v, c) in enumerate(row):
            t.add(("" if j == 0 else " ") + f + "=")
            quote = " " in v
            t.add('"' if quote else "")
            t.value(v, c)
            t.add('"' if quote else "")
        t.add("\n")
    return "log"


def _query(rows, rnd, t: _Text) -> str:
    t.add(f"{rnd.choice(('GET', 'POST'))} /api/v2/{rnd.choice(('customers', 'checkout', 'signup', 'search'))}?")
    for j, (f, v, c) in enumerate(rows[0]):
        t.add(("" if j == 0 else "&") + f + "=")
        t.value(v.replace(" ", "+").replace("@", "%40").replace("/", "%2F") if c in ("", "neutral") else v, c)
    t.add(" HTTP/1.1\n")
    return "url"


FORMATS = (("json", _json), ("sql", _sql), ("html", _html), ("xml", _xml), ("csv", _csv), ("log", _log),
           ("query", _query))


def _same_fields(rnd: random.Random, n: int) -> list:
    """n rows with the fields of the first one: a table, a result set, a CSV file."""
    first = _record(rnd)
    rows = [first]
    for _ in range(n - 1):
        person = _person(rnd)
        plain = dict((f, v) for f, v in _plain_fields(random.Random(rnd.random())))
        row = []
        for f, v, c in first:
            key = next((k for pf, k, _ in PERSONAL if pf == f), None)
            row.append((f, person[key] if key else plain.get(f, v), c))
        rows.append(row)
    return rows


def generate(count: int = COUNT, seed: int = SEED):
    rnd = random.Random(seed)
    for i in range(count):
        name, fmt = FORMATS[i % len(FORMATS)]
        rows = _same_fields(rnd, 1 if name == "query" else rnd.choice((1, 1, 2, 3)))
        t = _Text()
        context = fmt(rows, rnd, t)
        # a query string carries an address with + for spaces and %40 for @: that is the value as it stands
        record = f"{name}/{i}"
        yield {"id": f"traces/{record}", "text": t.text(), "channel": "tool", "context": context,
               "spans": t.spans, "split": cases.split_of("traces", record), "tags": [f"format:{name}"],
               "source": {"name": "traces", "record": record, "seed": seed}}
