#!/usr/bin/env python3
"""Write the public bank of Benchmark V1 (bench/bank/dev/*.jsonl, bench/bank/val/*.jsonl) from the templates below.

    python3 bench/bank/make_bank.py [--check]

Every value is random from a fixed seed, so a run writes the same files; --check fails when a file differs. No value
is real: each one is drawn here, with the checksum its type needs (IBAN, Luhn, the German tax id). A `§` splits each
value, so scripts/scan_tree.py does not take the case files for leaked secrets; bench/cases.py removes it.

The private holdout is not written here (docs/BENCHMARK-V1.md, "Splits")."""
from __future__ import annotations

import argparse
import json
import random
import string
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEED = "maisecrets bench v1"
VARIANTS = 3
L, U, D = string.ascii_lowercase, string.ascii_uppercase, string.digits
AN, HEX = L + U + D, "0123456789abcdef"


def rd(r, n, chars=AN):
    return "".join(r.choice(chars) for _ in range(n))


def guid(r):
    return "-".join(rd(r, n, HEX) for n in (8, 4, 4, 4, 12))


def luhn_complete(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


def iban_de(r):
    bban = rd(r, 8, D) + rd(r, 10, D)
    check = 98 - int(bban + "131400") % 97
    return f"DE{check:02d}{bban}"


def de_tax_id(r):
    """A German tax id (IdNr, § 139b AO), written from the rules here and not taken from the detector: eleven digits,
    the first never 0; in the first ten one digit twice or three times and every other digit once at most; a digit
    three times never at three places in a row; the eleventh the check digit, ISO 7064 MOD 11,10 (10 becomes 0)."""
    while True:
        digits = [r.randint(1, 9)] + [r.randint(0, 9) for _ in range(9)]
        counts = [digits.count(d) for d in set(digits)]
        if sorted(counts, reverse=True)[0] not in (2, 3) or sum(1 for n in counts if n > 1) != 1:
            continue
        if any(digits[i] == digits[i + 1] == digits[i + 2] for i in range(8)):
            continue
        break
    product = 10
    for d in digits:
        s = (d + product) % 10 or 10
        product = (s * 2) % 11
    check = 11 - product
    return "".join(map(str, digits)) + str(0 if check == 10 else check)


FIRST = ("Jonas", "Lea", "Mehmet", "Sofia", "Lukas", "Anna", "Elias", "Mia", "Noah", "Emilia")
LAST = ("Brandt", "Kowalski", "Yilmaz", "Hoffmann", "Petersen", "Vogel", "Schreiber", "Lindner")
STREETS = ("Lindenstraße", "Am Mühlbach", "Gartenweg", "Bahnhofstraße", "Rosenallee")
CITIES = ("10115 Berlin", "50667 Köln", "80331 München", "20095 Hamburg", "04109 Leipzig")
DOMAINS = ("posteo.de", "gmx.net", "web.de", "outlook.com", "gmail.com", "mailbox.org")

# kind -> function(r) -> value
VALUES = {
    "github_pat": lambda r: "ghp_" + rd(r, 36),
    "github_fine": lambda r: "github_pat_" + rd(r, 22) + "_" + rd(r, 59),
    "gitlab_pat": lambda r: "glpat-" + rd(r, 20, AN + "_-"),
    "slack_bot": lambda r: "xoxb-" + rd(r, 12, D) + "-" + rd(r, 12, D) + "-" + rd(r, 24),
    "slack_webhook": lambda r: "https://hooks.slack.com/services/T" + rd(r, 10, U + D) + "/B" + rd(r, 10, U + D)
    + "/" + rd(r, 24),
    "teams_webhook": lambda r: "https://" + rd(r, 8, L) + ".webhook.office.com/webhookb2/" + guid(r) + "@" + guid(r)
    + "/IncomingWebhook/" + rd(r, 32, HEX) + "/" + guid(r),
    "teams_legacy": lambda r: "https://outlook.office.com/webhook/" + guid(r) + "@" + guid(r) + "/IncomingWebhook/"
    + rd(r, 32, HEX) + "/" + guid(r),
    "discord_webhook": lambda r: "https://discord.com/api/webhooks/" + rd(r, 18, D) + "/" + rd(r, 68, AN + "_-"),
    "aws_key_id": lambda r: "AKIA" + rd(r, 16, U + "234567"),
    "aws_secret": lambda r: rd(r, 40, AN + "+/"),
    "openai_key": lambda r: "sk-proj-" + rd(r, 48, AN + "_-") + "T3BlbkFJ" + rd(r, 48, AN + "_-"),
    "anthropic_key": lambda r: "sk-ant-api03-" + rd(r, 93, AN + "_-") + "AA",
    "stripe_live": lambda r: "sk_live_" + rd(r, 24),
    "google_api": lambda r: "AIza" + rd(r, 35, AN + "_-"),
    "npm_token": lambda r: "npm_" + rd(r, 36),
    "sendgrid": lambda r: "SG." + rd(r, 22, AN + "_-") + "." + rd(r, 43, AN + "_-"),
    "jwt": lambda r: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + rd(r, 60, AN + "_-") + "." + rd(r, 43, AN + "_-"),
    "password": lambda r: rd(r, 4, L) + rd(r, 2, D) + r.choice("!$%&#") + rd(r, 5, U + L) + rd(r, 2, D),
    "db_password": lambda r: rd(r, 6, L + U) + rd(r, 3, D) + rd(r, 3, L),
    "generic_key": lambda r: rd(r, 32, HEX),
    "pem_body": lambda r: "\n".join(rd(r, 64, AN + "+/") for _ in range(4)),
    # the whole block is the span: a finding on the header line alone leaves the key in the clear ("partial")
    "pem_block": lambda r: ("-----BEGIN RSA PRI§VATE KEY-----\n" + VALUES["pem_body"](r)
                            + "\n-----END RSA PRI§VATE KEY-----"),
    "email": lambda r: f"{r.choice(FIRST).lower()}.{r.choice(LAST).lower()}{r.randint(1, 99)}@{r.choice(DOMAINS)}",
    "phone_de": lambda r: f"+49 {r.choice(['151', '160', '171', '176'])} {rd(r, 4, D)} {rd(r, 4, D)}",
    "phone_de_local": lambda r: f"0{r.choice(['30', '221', '89', '40'])} {rd(r, 3, D)} {rd(r, 4, D)}",
    "iban_de": iban_de,
    "iban_de_spaced": lambda r: " ".join((lambda s: [s[i:i + 4] for i in range(0, len(s), 4)])(iban_de(r))),
    "card_visa": lambda r: luhn_complete("4" + rd(r, 14, D)),
    "de_tax_id": de_tax_id,
    "ipv4_public": lambda r: f"{r.choice([84, 91, 185, 212])}.{r.randint(1, 254)}.{r.randint(1, 254)}."
                             f"{r.randint(1, 254)}",
    "name": lambda r: f"{r.choice(FIRST)} {r.choice(LAST)}",
    "address": lambda r: f"{r.choice(STREETS)} {r.randint(1, 120)}, {r.choice(CITIES)}",
    "birth_date": lambda r: f"{r.randint(1, 28):02d}.{r.randint(1, 12):02d}.{r.randint(1950, 2005)}",
    "username": lambda r: f"{r.choice(FIRST).lower()}{r.choice(['_', '.', ''])}{r.choice(LAST).lower()[:4]}"
                          f"{r.randint(1, 99)}",
    # values that are no secret, for the hard negatives
    "git_sha": lambda r: rd(r, 40, HEX),
    "sha256": lambda r: rd(r, 64, HEX),
    "uuid": guid,
}

# (id, channel, context, split, difficulty, tags, template); {kind|class} is an expected span, {kind} is filler that
# is no span (a value on a hard negative case). The template text is written as a person or a tool would.
T = [
    # --- prompts
    ("prompt/github-pat", "prompt", "prose", "dev", "easy", ["provider:github"],
     "can you check why the CI fails? here is my token {github_pat|secret.token}"),
    ("prompt/openai-key-env", "prompt", "shell", "dev", "easy", ["provider:openai"],
     "export OPENAI_API_KEY={openai_key|secret.token} and then run the script"),
    ("prompt/password-sentence", "prompt", "prose", "dev", "medium", ["form:sentence"],
     "the admin password for the staging db is {password|secret.password}, please update the config"),
    ("prompt/password-de", "prompt", "prose", "val", "medium", ["form:sentence", "lang:de"],
     "Das Passwort für den Testserver lautet {password|secret.password}"),
    ("prompt/email-and-phone", "prompt", "prose", "dev", "easy", ["lang:de"],
     "Bitte schreib an {email|pii.email} oder ruf an unter {phone_de|pii.phone}."),
    ("prompt/iban", "prompt", "prose", "dev", "easy", ["lang:de"],
     "Überweis die Rechnung bitte auf {iban_de_spaced|pii.iban}"),
    ("prompt/slack-webhook", "prompt", "prose", "val", "easy", ["provider:slack"],
     "post the alert to {slack_webhook|secret.webhook}"),
    ("prompt/teams-webhook", "prompt", "prose", "dev", "medium", ["provider:microsoft"],
     "our Teams channel hook is {teams_webhook|secret.webhook} - add it to the notifier"),
    ("prompt/name-address", "prompt", "prose", "val", "hard", ["lang:de"],
     "Kunde: {name|pii.name}, {address|pii.address}, geboren am {birth_date|pii.birth_date}"),
    # --- tool results and logs
    ("tool/env-file", "tool", "config", "dev", "easy", ["file:.env"],
     "DATABASE_URL=postgres:§//app:{db_password|secret.password}@db.internal:5432/app\n"
     "STRIPE_SECRET_KEY={stripe_live|secret.token}\nSENDGRID_API_KEY={sendgrid|secret.token}\nDEBUG=false\n"),
    ("tool/aws-credentials", "tool", "config", "dev", "easy", ["provider:aws", "file:credentials"],
     "[default]\naws_access_key_id = {aws_key_id|secret.token}\naws_secret_access_key = {aws_secret|secret.generic}\n"
     "region = eu-central-1\n"),
    ("tool/docker-compose", "tool", "yaml", "dev", "medium", ["file:docker-compose.yml"],
     "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_USER: app\n"
     "      POSTGRES_PASSWORD: {db_password|secret.password}\n"),
    ("tool/k8s-secret", "tool", "yaml", "val", "medium", ["file:secret.yaml"],
     "apiVersion: v1\nkind: Secret\nstringData:\n  api-key: {generic_key|secret.generic}\n  npm-token: "
     "{npm_token|secret.token}\n"),
    ("tool/json-api", "tool", "json", "dev", "easy", ["form:json"],
     '{{"user": {{"id": 4711, "email": "{email|pii.email}", "phone": "{phone_de|pii.phone}"}}, '
     '"session": "{jwt|secret.token}"}}'),
    ("tool/json-escaped", "tool", "json", "val", "hard", ["form:escaped-json"],
     '{{"content": "config:\\n  token: {gitlab_pat|secret.token}\\n  url: {teams_legacy|secret.webhook}\\n"}}'),
    ("tool/app-log", "tool", "log", "dev", "medium", ["form:log"],
     "2026-10-19T07:12:03Z INFO request from {ipv4_public|pii.ip} user={email|pii.email}\n"
     "2026-10-19T07:12:04Z WARN retry with Authorization: Bearer {jwt|secret.token}\n"),
    ("tool/stacktrace", "tool", "stacktrace", "dev", "hard", ["form:stacktrace"],
     "Traceback (most recent call last):\n  File \"app/db.py\", line 42, in connect\n"
     "    conn = psycopg.connect(\"postgresql:§//admin:{db_password|secret.password}@10.0.3.7/prod\")\n"
     "psycopg.OperationalError: connection refused\n"),
    ("tool/curl-history", "tool", "shell", "dev", "easy", ["form:shell"],
     "$ curl -H \"Authorization: token {github_pat|secret.token}\" https://api.github.com/user\n"),
    ("tool/git-remote", "tool", "shell", "val", "medium", ["form:url-credential"],
     "origin  https:§//oauth2:{gitlab_pat|secret.token}@gitlab.com/group/project.git (fetch)\n"),
    ("tool/python-code", "tool", "code", "dev", "medium", ["lang:python"],
     "import anthropic\nclient = anthropic.Anthropic(api_key=\"{anthropic_key|secret.token}\")\n"),
    ("tool/js-config", "tool", "code", "val", "medium", ["lang:javascript"],
     "module.exports = {{\n  googleMapsKey: '{google_api|secret.token}',\n  slack: '{slack_bot|secret.token}',\n}};\n"),
    ("tool/pem", "tool", "config", "dev", "easy", ["form:pem"],
     "{pem_block|secret.private_key}\n"),
    ("tool/csv-customers", "tool", "doc", "dev", "medium", ["form:csv", "lang:de"],
     "name;email;iban;steuer_id\n{name|pii.name};{email|pii.email};{iban_de|pii.iban};{de_tax_id|pii.tax_id}\n"),
    ("tool/payment-log", "tool", "log", "val", "medium", ["form:log"],
     "payment declined card={card_visa|pii.card} customer={email|pii.email}\n"),
    ("tool/discord", "tool", "config", "dev", "easy", ["provider:discord"],
     "DISCORD_WEBHOOK_URL={discord_webhook|secret.webhook}\n"),
    ("tool/user-record", "tool", "json", "dev", "hard", ["form:json"],
     '{{"username": "{username|pii.username}", "full_name": "{name|pii.name}", '
     '"phone": "{phone_de_local|pii.phone}"}}'),
    ("tool/markdown-doc", "tool", "doc", "val", "hard", ["form:markdown", "lang:de"],
     "## Ansprechpartner\n\n- {name|pii.name}, {email|pii.email}, Tel. {phone_de_local|pii.phone}\n"),
    # --- hard negatives (no span)
    ("neg/git-log", "tool", "log", "dev", "hard", ["negative", "form:git"],
     "commit {git_sha}\nAuthor: CI Bot <ci@example.com>\n\n    fix(build): pin the runner image\n"),
    ("neg/lockfile", "tool", "json", "dev", "hard", ["negative", "form:lockfile"],
     '{{"name": "left-pad", "version": "1.3.0", "integrity": "sha256-{sha256}", "resolved": '
     '"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}'),
    ("neg/placeholders", "tool", "doc", "dev", "hard", ["negative", "form:docs"],
     "Set GITHUB_TOKEN=<your-token> and OPENAI_API_KEY=YOUR_API_KEY before you run `make deploy`.\n"),
    ("neg/env-reference", "tool", "shell", "dev", "hard", ["negative", "form:shell"],
     "docker login -u ci -p \"$REGISTRY_PASSWORD\" registry.example.com\nexport DB_PASSWORD=${{DB_PASSWORD:-}}\n"),
    ("neg/uuid-ids", "tool", "json", "val", "hard", ["negative", "form:json"],
     '{{"request_id": "{uuid}", "trace_id": "{generic_key}", "status": "ok"}}'),
    ("neg/masked", "tool", "log", "dev", "hard", ["negative"],
     "login ok for user ****, password: ********, token: [REDACTED]\n"),
    ("neg/example-email", "prompt", "prose", "val", "medium", ["negative"],
     "send the test mail to test@example.com and alice@example.org\n"),
    ("neg/digest-in-prose", "prompt", "prose", "dev", "hard", ["negative"],
     "the image digest is sha256:{sha256} and the commit is {git_sha}\n"),
    ("neg/test-fixture", "tool", "code", "dev", "hard", ["negative", "form:test"],
     "def test_login():\n    assert login(\"testuser\", \"testpass\") is True\n"),
]


def split_value(v: str) -> str:
    """A § after the second character, and after every 16th, so no run of a value is long enough to look real."""
    return "§".join(v[i:i + 16] for i in range(0, len(v), 16)) if len(v) > 2 else v


def render(r, template: str):
    """The marked text and the classes of its spans, in order."""
    out, classes, pos = [], [], 0
    while True:
        a = template.find("{", pos)
        if a < 0:
            out.append(template[pos:])
            break
        if template[a:a + 2] == "{{":
            out.append(template[pos:a] + "{")
            pos = a + 2
            continue
        b = template.index("}", a)
        out.append(template[pos:a])
        kind, _, cls = template[a + 1:b].partition("|")
        v = VALUES[kind](r)
        v = v[:2] + "§" + split_value(v[2:])
        out.append(f"«{v}»" if cls else v)
        if cls:
            classes.append(cls)
        pos = b + 1
    return "".join(out).replace("}}", "}"), classes


def build() -> dict:
    files: dict = {}
    for tid, channel, context, split, difficulty, tags, template in T:
        group = tid.split("/")[0]
        for i in range(VARIANTS):
            r = random.Random(f"{SEED}/{tid}/{i}")
            text, classes = render(r, template)
            case = {"id": f"bank/{tid}-{i}", "channel": channel, "context": context, "text": text,
                    "spans": [{"class": c} for c in classes], "split": split, "difficulty": difficulty,
                    "tags": tags, "region": "de" if "lang:de" in tags else "intl",
                    "source": {"name": "maisecrets bank", "license": "Apache-2.0", "record": f"{tid}-{i}"}}
            files.setdefault(f"{split}/{group}.jsonl", []).append(json.dumps(case, ensure_ascii=False))
    return {name: "\n".join(lines) + "\n" for name, lines in sorted(files.items())}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    bad = 0
    built = build()
    if a.check:
        for path in sorted(HERE.rglob("*.jsonl")):
            if path.relative_to(HERE).as_posix() not in built:
                print(f"{path.relative_to(HERE)}: no template gives it")
                bad += 1
    for name, body in built.items():
        path = HERE / name
        if a.check:
            if not path.exists() or path.read_text(encoding="utf-8") != body:
                print(f"{name}: differs from the templates; run bench/bank/make_bank.py")
                bad += 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
