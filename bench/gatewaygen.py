"""The gateway corpus: seeded synthetic tool responses in the shapes the mcpgate gateway sees most (2026-11-01, the
fields where its shadow measurement found something over 7 days), with each person's name, username and mail address
as a labelled span and the values that only look personal (bot and system accounts, team mailboxes, project and
group names, branches, product words) as look-alikes.

It answers one question: how precise is maisecrets on gateway traffic, where most findings sit in structured user
objects (GitLab author/merge_user/reviewers, calendar attendees, Jira displayName) and not in prose. The shadow found
thousands of names and usernames that only maisecrets reported, none of them labelled; here every value is.

Nothing is stored: the cases are made at run time from one seed. Names come from bench/structvalues.py; mail domains
are made-up names under .internal, which maisecrets treats as a person's mailbox (value_checks._reserved_domain), so
an address is measured and not set aside as a reserved test domain.

    python3 bench/run.py --source gateway --split dev --out gateway-dev.json
    python3 bench/gatewaygen.py --stats"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench import cases  # noqa: E402
from bench import structvalues as V  # noqa: E402

SEED = 20261101
COUNT = 2000
LANGS = ("en", "de")
SERVICES = ("gitlab", "google_workspace", "slack", "jira", "notion")
ITEMS = {"gitlab": 9, "google_workspace": 14, "slack": 11, "jira": 17, "notion": 29}

# made-up company domains under .internal (an intranet mailbox names a person); built here, never a real address
_DOMAIN_PARTS = (("nord", "sued", "west", "ost", "blau", "fels", "linden", "eichen"),
                 ("werk", "bahn", "tal", "feld", "hafen", "brueck"))
_BOTS = (("GitLab Bot", "gitlab-bot"), ("Renovate Bot", "renovate-bot"), ("Dependabot", "dependabot"),
         ("Release Bot", "release-bot"), ("CI Runner", "ci-runner"), ("Ghost User", "ghost"))
_SYSTEM_MAIL = ("noreply", "no-reply", "calendar-notification", "notifications", "postmaster", "mailer-daemon")
_TEAM_MAIL = ("team-backend", "team-mobile", "support", "billing", "it-ops", "all-hands")
_PROJECTS = ("Vokabeltrainer", "Lernplan", "Kartenstapel", "Billing Service", "Mobile Release", "Data Pipeline")
_PRODUCTS = ("Claude", "Copilot", "GitHub", "Jira", "Grafana", "Kubernetes", "Docker", "Slack")
_BRANCHES = ("feature/login-flow", "fix/null-check", "release/2026.11", "main", "chore/deps")


class Out:
    """JSON text with spans: values go in as placeholders and are written out with their offsets."""

    def __init__(self):
        self.values: list = []

    def put(self, value: str, cls: str = "", kind: str = "") -> str:
        self.values.append((value, cls, kind))
        return f"\ue000{len(self.values) - 1}\ue001"

    def render(self, obj) -> tuple:
        raw = json.dumps(obj, ensure_ascii=False, indent=1)
        text, spans, looks, i = [], [], [], 0
        n = 0
        while i < len(raw):
            j = raw.find("\ue000", i)
            if j < 0:
                text.append(raw[i:])
                break
            text.append(raw[i:j])
            n += j - i
            k = raw.index("\ue001", j)
            value, cls, kind = self.values[int(raw[j + 1:k])]
            written = json.dumps(value, ensure_ascii=False)[1:-1]
            if cls:
                spans.append({"start": n, "end": n + len(written), "class": cls})
            elif kind:
                looks.append({"start": n, "end": n + len(written), "kind": kind})
            text.append(written)
            n += len(written)
            i = k + 1
        return "".join(text), spans, looks

    def leaf(self, value: str) -> tuple:
        """One string leaf as the gateway reads it (no JSON quoting), with its spans and look-alikes."""
        text, spans, looks, n, i = [], [], [], 0, 0
        while i < len(value):
            j = value.find("\ue000", i)
            if j < 0:
                text.append(value[i:])
                break
            text.append(value[i:j])
            n += j - i
            k = value.index("\ue001", j)
            v, cls, kind = self.values[int(value[j + 1:k])]
            if cls:
                spans.append({"start": n, "end": n + len(v), "class": cls})
            elif kind:
                looks.append({"start": n, "end": n + len(v), "kind": kind})
            text.append(v)
            n += len(v)
            i = k + 1
        return "".join(text), spans, looks


def _domain(r: random.Random) -> str:
    return f"{r.choice(_DOMAIN_PARTS[0])}{r.choice(_DOMAIN_PARTS[1])}.internal"


def _person(r: random.Random, lang: str, domain: str) -> dict:
    p = V.person(r, lang)
    first, last = V.fold_plain(p["first"]).lower(), V.fold_plain(p["last"]).lower()
    handle = r.choice((f"{first}.{last}", f"{first[0]}{last}", f"{first}{last[0]}", f"{first}_{last}",
                       f"{first}{r.randint(1, 99)}"))
    return {"name": p["name"], "username": handle.replace(" ", ""), "email": f"{handle.replace(' ', '')}@{domain}"}


def _user(o: Out, r: random.Random, people: list, bot_share: float = 0.15) -> dict:
    if r.random() < bot_share:
        name, handle = r.choice(_BOTS)
        return {"id": r.randint(1000, 99999), "username": o.put(handle, kind="bot"), "name": o.put(name, kind="bot"),
                "state": "active"}
    p = r.choice(people)
    return {"id": r.randint(1000, 99999), "username": o.put(p["username"], "pii.username"),
            "name": o.put(p["name"], "pii.name"), "state": "active"}


def _prose(o: Out, r: random.Random, people: list, lang: str) -> str:
    """A sentence or two as people write them in a description or a comment: a name, a mention, product words."""
    p = r.choice(people)
    form = r.randrange(3)
    product, project = o.put(r.choice(_PRODUCTS), kind="product"), o.put(r.choice(_PROJECTS), kind="project")
    if form == 0:
        first = o.put(p["name"].split()[0], "pii.name")
        return (f"Hallo {first}, kannst du dir das in {product} anschauen? Betrifft {project}." if lang == "de" else
                f"Hi {first}, could you check this in {product}? It touches {project}.")
    if form == 1:
        name = o.put(p["name"], "pii.name")
        return (f"Mit {name} abgestimmt: wir mergen nach dem Review." if lang == "de" else
                f"Agreed with {name}: we merge after the review.")
    handle = o.put(p["username"], "pii.username")
    return (f"@{handle} bitte prüfen, {product} meldet einen Fehler im Build von {project}." if lang == "de" else
            f"@{handle} please have a look, {product} reports a failing build of {project}.")


def _gitlab(o, r, people, lang):
    return {"iid": r.randint(1, 4000), "title": o.put(r.choice(_PROJECTS) + ": " + r.choice(("fix", "update", "add")),
                                                        kind="project"),
            "description": _prose(o, r, people, lang), "state": "merged",
            "source_branch": o.put(r.choice(_BRANCHES), kind="branch"), "target_branch": "main",
            "author": _user(o, r, people), "merge_user": _user(o, r, people), "merged_by": _user(o, r, people),
            "reviewers": [_user(o, r, people) for _ in range(r.randint(0, 2))],
            "assignees": [_user(o, r, people) for _ in range(r.randint(0, 1))],
            "labels": [o.put(r.choice(_PROJECTS), kind="project")]}


def _mail(o, r, people, domain):
    roll = r.random()
    if roll < 0.12:
        return o.put(f"{r.choice(_SYSTEM_MAIL)}@{domain}", kind="system mailbox")
    if roll < 0.22:
        return o.put(f"{r.choice(_TEAM_MAIL)}@{domain}", kind="team mailbox")
    return o.put(r.choice(people)["email"], "pii.email")


def _calendar(o, r, people, lang, domain):
    return {"kind": "calendar#event", "summary": o.put(r.choice(_PROJECTS) + " sync", kind="project"),
            "organizer": {"email": _mail(o, r, people, domain)}, "creator": {"email": _mail(o, r, people, domain)},
            "attendees": [{"email": _mail(o, r, people, domain),
                           "responseStatus": r.choice(("accepted", "needsAction"))} for _ in range(r.randint(1, 5))],
            "description": _prose(o, r, people, lang)}


def _slack(o, r, people, lang):
    msgs = []
    for _ in range(r.randint(1, 4)):
        p = r.choice(people)
        msgs.append({"user": f"U{r.randint(10 ** 8, 10 ** 9 - 1)}", "username": o.put(p["username"], "pii.username"),
                     "text": _prose(o, r, people, lang),
                     "ts": f"{r.randint(1_700_000_000, 1_800_000_000)}.{r.randint(0, 999999):06d}"})
    return {"ok": True, "messages": msgs}


def _jira(o, r, people, lang, domain):
    def person():
        if r.random() < 0.1:
            return {"displayName": o.put("Automation for Jira", kind="bot"), "active": True}
        p = r.choice(people)
        return {"displayName": o.put(p["name"], "pii.name"), "emailAddress": o.put(p["email"], "pii.email"),
                "active": True}
    return {"key": f"PRJ-{r.randint(1, 9999)}",
            "fields": {"summary": o.put(r.choice(_PROJECTS) + ": " + r.choice(("crash", "slow", "wrong text")),
                                        kind="project"),
                       "reporter": person(), "assignee": person(),
                       "comment": {"comments": [{"author": person(), "body": _prose(o, r, people, lang)}
                                                for _ in range(r.randint(0, 3))]}}}


def _notion(o, r, people, lang, domain):
    p = r.choice(people)
    return {"results": [{"object": "page",
                         "properties": {"Name": {"title": [{"plain_text": o.put(p["name"], "pii.name")}]},
                                        "Email": {"email": o.put(p["email"], "pii.email")},
                                        "Project": {"select": {"name": o.put(r.choice(_PROJECTS), kind="project")}}},
                         "content": _prose(o, r, people, lang)}]}


def _split(record: str) -> str:
    # synthetic development data, as structgen: no sealed holdout, the holdout share goes to val
    return "dev" if cases.split_of("gateway", record) == "dev" else "val"


def generate(count: int = COUNT, seed: int = SEED):
    for case, _o, _obj in objects(count, seed):
        yield case


def objects(count: int = COUNT, seed: int = SEED):
    """Each case with its writer and its object, for a report that reads the leaves (bench/gateway_report.py)."""
    for i in range(count):
        r = random.Random(f"{seed}/{i}")
        service, lang = SERVICES[i % len(SERVICES)], LANGS[(i // len(SERVICES)) % len(LANGS)]
        domain = _domain(r)
        people = [_person(r, lang, domain) for _ in range(r.randint(2, 6))]
        o = Out()
        one = {"gitlab": lambda: _gitlab(o, r, people, lang),
               "google_workspace": lambda: _calendar(o, r, people, lang, domain),
               "slack": lambda: _slack(o, r, people, lang),
               "jira": lambda: _jira(o, r, people, lang, domain),
               "notion": lambda: _notion(o, r, people, lang, domain)}[service]
        # a list of objects, as a list call returns them: ITEMS is set so the mean response is near the gateway's
        # 3,385 characters of leaf text (the mean of 7 days on prod, 2026-11-01)
        obj = [one() for _ in range(r.randint(1, 2 * ITEMS[service] - 1))]
        text, spans, looks = o.render(obj)
        record = f"{service}/{lang}/{i}"
        yield {"id": f"gateway/{record}", "text": text, "channel": "tool", "context": "json", "path": None,
               "spans": spans, "lookalikes": looks, "split": _split(record),
               "tags": [f"service:{service}", f"lang:{lang}"], "region": "us" if lang == "en" else "de", "lang": lang,
               "source": {"name": "gateway", "record": record, "seed": seed}}, o, obj


if __name__ == "__main__":
    import collections
    cs = list(generate())
    by = collections.Counter(s["class"] for c in cs for s in c["spans"])
    look = collections.Counter(x["kind"] for c in cs for x in c["lookalikes"])
    print(json.dumps({"cases": len(cs), "spans": dict(by), "lookalikes": dict(look),
                      "splits": dict(collections.Counter(c["split"] for c in cs))}, indent=1))
