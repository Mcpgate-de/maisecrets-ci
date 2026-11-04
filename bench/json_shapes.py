"""Synthetic API responses in the shapes of four services, with the expected class of each string field.

The shapes follow the public API documentation of each service (field names and nesting): a Jira issue with an
Atlassian document description, a GitLab merge request, a Slack conversations.history page and a Microsoft Graph
user list. Every value comes from bench/structvalues.py (synthetic names, mail at example.com/.org, checksum-valid
numbers) or from the generators here. This project chose the shapes, the fields and the values; the results are a
benchmark of our own making, labelled as such (docs/BENCHMARK-JSON.md).

    responses(seed, n) -> [(name, obj, truth)]   truth: {path: set of classes}, path as leaves.Leaf.path
"""
from __future__ import annotations

import random
import string

from bench import structvalues as sv

# the classes a field can hold; a tool's own classes are mapped to these (bench/json_bench.py)
CLASSES = ("name", "email", "phone", "iban", "address", "username", "card", "ip", "secret")


class _V:
    """A value with its class, resolved into the plain object; the path of its string is the truth."""
    __slots__ = ("cls", "value")

    def __init__(self, cls: str, value: str) -> None:
        self.cls, self.value = cls, value


class _T:
    """A string that holds values of classes inside its text (a description, a message)."""
    __slots__ = ("classes", "value")

    def __init__(self, classes, value: str) -> None:
        self.classes, self.value = set(classes), value


def _resolve(x, path=(), truth=None):
    if isinstance(x, _V):
        truth.setdefault(path, set()).add(x.cls)
        return x.value
    if isinstance(x, _T):
        if x.classes:
            truth.setdefault(path, set()).update(x.classes)
        return x.value
    if isinstance(x, dict):
        return {k: _resolve(v, path + (k,), truth) for k, v in x.items()}
    if isinstance(x, list):
        return [_resolve(v, path + (i,), truth) for i, v in enumerate(x)]
    return x


def _mail(r: random.Random, p: dict) -> str:
    """The person's address at a domain made up at run time: maisecrets leaves example.com/.org alone on purpose (a
    test value), which another tool does not, so the bench would score that policy and not the detection."""
    local = p["email"].split("@")[0]
    host = f"{sv.rd(r, 7, string.ascii_lowercase)}-{r.choice(('mail', 'post', 'web'))}"
    return f"{local}@{host}.{r.choice(('de', 'com', 'net'))}"


def _hex(r: random.Random, n: int) -> str:
    return "".join(r.choice("0123456789abcdef") for _ in range(n))


def _token(r: random.Random) -> tuple:
    """A secret in a shape a scanner of secrets knows, and the label people write before it."""
    kind = r.randrange(4)
    if kind == 0:
        return "glpat-" + sv.rd(r, 20, string.ascii_letters + string.digits), "token"
    if kind == 1:
        return "AKIA" + sv.rd(r, 16, string.ascii_uppercase + string.digits), "aws_access_key_id"
    if kind == 2:
        return "ghp_" + sv.rd(r, 36, string.ascii_letters + string.digits), "GITHUB_TOKEN"
    return sv.rd(r, 6, string.ascii_letters) + "!" + sv.rd(r, 3, string.digits) + sv.rd(r, 4, string.ascii_letters), \
        "password"


_PROSE = {
    "en": ["Please check the failing build before the release.", "The customer called about the invoice.",
           "Meeting moved to tomorrow, see the notes.", "Deploy finished, the dashboard is green again."],
    "de": ["Bitte schau dir den roten Build vor dem Release an.", "Der Kunde hat wegen der Rechnung angerufen.",
           "Das Meeting ist auf morgen verschoben.", "Das Deployment ist durch, alles wieder grün."],
}


def jira_issue(r: random.Random, lang: str) -> dict:
    rep, ass, com = sv.person(r, lang), sv.person(r, lang), sv.person(r, lang)
    key = f"PROJ-{r.randrange(100, 9999)}"
    para = [{"type": "text", "text": r.choice(_PROSE[lang]) + " "}]
    desc_classes: list = []
    k = r.randrange(3)
    if k == 0:
        para += [{"type": "text", "text": "Rückruf an " if lang == "de" else "Call back "},
                 _V("name", ass["name"]), {"type": "text", "text": " unter " if lang == "de" else " at "},
                 {"type": "text", "text": _V("phone", ass["phone"]), "marks": [{"type": "strong"}]}]
    elif k == 1:
        para += [{"type": "text", "text": "Mail: " + _mail(r, ass)}]
        desc_classes = ["email"]
    else:
        tok, label = _token(r)
        para += [{"type": "text", "text": f"{label}: "}, {"type": "text", "text": _V("secret", tok),
                                                          "marks": [{"type": "code"}]}]
    content = []
    for node in para:
        if isinstance(node, _V):
            content.append({"type": "text", "text": node})
        elif desc_classes and node["text"].startswith("Mail: "):
            content.append({"type": "text", "text": _T(desc_classes, node["text"])})
        else:
            content.append(node)
    return {
        "id": str(r.randrange(10000, 99999)), "key": key, "self": f"https://example.atlassian.net/rest/api/3/issue/{key}",
        "fields": {
            "summary": r.choice(_PROSE[lang]), "created": f"2026-10-{r.randint(1, 28):02d}T09:12:00.000+0000",
            "status": {"name": "In Progress", "id": "3"},
            "reporter": {"accountId": _hex(r, 24), "displayName": _V("name", rep["name"]),
                         "emailAddress": _V("email", _mail(r, rep)), "timeZone": "Europe/Berlin"},
            "assignee": {"accountId": _hex(r, 24), "displayName": _V("name", ass["name"])},
            "description": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": content}]},
            "customfield_10042": _V("iban", sv.iban(r, lang)),
            "labels": ["backend", "release"],
            "comment": {"comments": [{"id": str(r.randrange(10000, 99999)),
                                      "author": {"displayName": _V("name", com["name"])},
                                      "body": _T(["phone"], f"{r.choice(_PROSE[lang])} Tel. {com['phone']}"),
                                      "created": "2026-10-30T10:00:00.000+0000"}]},
        },
    }


def gitlab_mr(r: random.Random, lang: str) -> dict:
    a, rev = sv.person(r, lang), sv.person(r, lang)
    tok, label = _token(r)
    iid = r.randrange(1, 4000)
    return {
        "id": r.randrange(10 ** 6, 10 ** 7), "iid": iid, "title": r.choice(_PROSE[lang]),
        "description": _T(["secret"], f"{r.choice(_PROSE[lang])}\n\nFor the test run set {label}={tok} in CI."),
        "state": "opened", "source_branch": f"fix/{_hex(r, 6)}", "target_branch": "main",
        "sha": _hex(r, 40), "merge_commit_sha": None, "web_url": f"https://gitlab.example.com/g/p/-/merge_requests/{iid}",
        "author": {"id": r.randrange(100, 9999), "name": _V("name", a["name"]),
                   "username": _V("username", sv.username(r, a)), "state": "active",
                   "web_url": "https://gitlab.example.com/" + "user" + str(r.randrange(99))},
        "reviewers": [{"id": r.randrange(100, 9999), "name": _V("name", rev["name"]),
                       "username": _V("username", sv.username(r, rev))}],
        "labels": ["bug"], "created_at": "2026-11-01T08:00:00.000Z", "has_conflicts": False,
    }


def slack_history(r: random.Random, lang: str, n: int = 6) -> dict:
    msgs = []
    for i in range(n):
        p = sv.person(r, lang)
        k = r.randrange(4)
        base = r.choice(_PROSE[lang])
        if k == 0:
            text, classes = f"{base} Schreib an {_mail(r, p)}" if lang == "de" else f"{base} Write to {_mail(r, p)}", \
                ["email"]
        elif k == 1:
            text, classes = f"{base} Handy: {p['phone']}" if lang == "de" else f"{base} Mobile: {p['phone']}", ["phone"]
        elif k == 2:
            tok, label = _token(r)
            text, classes = f"{base} {label}: {tok}", ["secret"]
        else:
            text, classes = base, []
        msgs.append({"type": "message", "ts": f"1762{r.randrange(10 ** 6):06d}.{r.randrange(10 ** 6):06d}",
                     "user": "U0" + sv.rd(r, 8, string.ascii_uppercase + string.digits), "text": _T(classes, text),
                     "user_profile": {"real_name": _V("name", p["name"]), "display_name": p["first"].lower()},
                     "blocks": [{"type": "rich_text", "elements": [{"type": "rich_text_section",
                                                                    "elements": [{"type": "text",
                                                                                  "text": _T(classes, text)}]}]}]})
    return {"ok": True, "messages": msgs, "has_more": False}


def graph_users(r: random.Random, lang: str, n: int = 4) -> dict:
    users = []
    for _ in range(n):
        p = sv.person(r, lang)
        users.append({"id": f"{_hex(r, 8)}-{_hex(r, 4)}-{_hex(r, 4)}-{_hex(r, 4)}-{_hex(r, 12)}",
                      "displayName": _V("name", p["name"]), "givenName": _V("name", p["first"]),
                      "surname": _V("name", p["last"]), "mail": _V("email", _mail(r, p)),
                      "userPrincipalName": _V("email", _mail(r, p)), "mobilePhone": _V("phone", p["phone"]),
                      "businessPhones": [_V("phone", sv.phone(r, lang))], "jobTitle": "Engineer",
                      "officeLocation": "HQ", "streetAddress": _V("address", p["street"]), "city": p["city"],
                      "postalCode": p["postcode"], "preferredLanguage": "de-DE" if lang == "de" else "en-US"})
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users", "value": users}


SHAPES = {"jira_issue": jira_issue, "gitlab_mr": gitlab_mr, "slack_history": slack_history, "graph_users": graph_users}


def responses(seed: int = 7, n: int = 40) -> list:
    """n responses of each shape, half in English and half in German."""
    r = random.Random(seed)
    out = []
    for name, make in SHAPES.items():
        for i in range(n):
            truth: dict = {}
            obj = _resolve(make(r, "de" if i % 2 else "en"), (), truth)
            out.append((name, obj, truth))
    return out
