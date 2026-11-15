"""User names in prose after a user cue and in a user-id element (#51, the gap to Cloakroom 1.4.0 on the V3 samples:
Nemotron 82 values), read by key_values.hits in the tool channel. Kept out of personal.py, which is at the size limit
of a release file; it imports personal.py only when it runs."""
from __future__ import annotations

import re

# a handle: parts joined by . _ or -, or letters with digits at the end; a word alone is no handle
_HANDLE = r"(?:[A-Za-z][A-Za-z0-9]{0,20}(?:[._-][A-Za-z0-9]{1,20}){1,3}|[A-Za-z]{2,20}\d{1,6})"
# a CamelCase pair (KalinOrbek) names a person only before a login verb; else it is a class or a product name
_CAMEL = r"[A-Z][a-z]{1,15}[A-Z][a-z0-9]{1,15}"
# the cues: `for user kalin.orbek`, `for invalid user k.orbek` (sshd), `User kalin.orbek successfully logged in` (also
# after a log prefix), `Welcome, kalin_orb_42.` and `Welcome back, ...`
# matched only where str.find saw `user` or `welcome`: one regex pass over a megabyte cost 0.09 s (#51)
# a plain word is never a user name here, not even in quotes or after `user=`: the word list lacks many ordinary
# words and service accounts (`User=caddy` in a systemd unit, `?user=dashboard`, `for user 'profile'`; Gate A of #52)
_AT_RE = re.compile(r"(?i:user|welcome(?: back)?,)(?:[ \t]+(?P<q>[\"'])?|(?P<eq>=))(?P<v>" + _HANDLE + "|" + _CAMEL
                    + r")(?(q)(?P=q))(?=[.,;:!?)(@\s&]|$)")
_STRONG = ("for", "by", "from", "the", "a", "invalid", "of")  # `for user x` needs no verb of a login after it
# sshd `Accepted password for kmorgan42 from`, sudo `sudo: kmorgan42 : TTY=`, pam `by kmorgan42(uid=1001)` (#52)
# a Unix login without digits (jdoe) only in these two forms, which name a login and nothing else; the value checks
# still refuse a word of the word list, a service account and a tool word
_LOGIN = r"[a-z][a-z0-9_]{3,31}"
_SSHD_RE = re.compile(r"(?:(?:Accepted|Failed) (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
                      r"|Invalid user )(" + _HANDLE + "|" + _LOGIN + r") from\b")
_SUDO_RE = re.compile(r"sudo:[ \t]+(" + _HANDLE + "|" + _LOGIN + r")[ \t]+:[ \t]+(?:TTY=|\d+ incorrect password)")
_UID_RE = re.compile(r"\bby[ \t]+(" + _HANDLE + r")$")
_LOGIN_VERB_RE = re.compile(r"[ \t]+(?:successfully|logged|signed|accessed|failed|was|has|reported|attempted)\b")
_IS_RE = re.compile(r"(?i)user ?name is[ \t]+([A-Za-z][A-Za-z0-9._-]{1,30}?)(?=[.,;:!?)\s]|$)")


def user_names(text: str) -> list:
    """(start, end) of a user name after a cue in prose, and in an sshd, a sudo or a pam line."""
    low = text.lower()
    starts = _at(low, "user") + _at(low, "welcome")
    lines = _all(low, "accepted ") + _all(low, "failed ") + _all(low, "invalid user ")
    sudo = _all(low, "sudo:")
    uids = _all(low, "(uid=")
    if not (starts or sudo or uids or lines):
        return []
    from .core import _word_set
    from .personal import _username_value_ok
    out = []

    def keep(v: str, a: int, b: int) -> None:
        # the word list loads only for a candidate value: a text with the word `user` and no value loads nothing
        if _username_value_ok(v, False, " ") and _handle_ok(v, _word_set()):
            out.append((a, b))
    for pos in sorted(starts):
        before = low[max(0, pos - 9):pos].split()
        m = _AT_RE.match(text, pos)
        if m is not None:
            v = m.group("v")
            login = bool(_LOGIN_VERB_RE.match(text, m.end("v") + (1 if m.group("q") else 0)))
            cue = before[-1] if before and low[pos - 1] == " " else ""
            marked = bool(m.group("q") or m.group("eq"))
            # `user x` alone names an account only before a verb of a login (`User k.orbek logged in`); quotes and
            # `user=` mark a value (`User "lena.hartmann" cannot list`, `user=lhartmann7`)
            weak = low.startswith("user", pos) and cue not in _STRONG and not marked
            if (weak or re.fullmatch(_CAMEL, v)) and not login:
                continue
            keep(v, m.start("v"), m.end("v"))
            continue
        if before and before[-1] == "my":
            m = _IS_RE.match(text, pos)
            if m is not None:
                v = m.group(1).rstrip("._-")
                # _username_value_ok refuses a word of the word list of 3 letters or more (`my username is visible`)
                if len(v) > 2 and _username_value_ok(v, False, " "):
                    out.append((m.start(1), m.start(1) + len(v)))
    for at in lines:
        m = _SSHD_RE.match(text, at)
        if m is not None:
            keep(m.group(1), m.start(1), m.end(1))
    for at in sudo:
        m = _SUDO_RE.match(text, at)
        if m is not None:
            keep(m.group(1), m.start(1), m.end(1))
    for at in uids:
        m = _UID_RE.search(text, max(0, at - 40), at)
        if m is not None:
            keep(m.group(1), m.start(1), m.end(1))
    return sorted(set(out))


def _all(low: str, word: str) -> list:
    """Every start of `word` in the lowercased text (str.find)."""
    out, i = [], low.find(word)
    while i >= 0:
        out.append(i)
        i = low.find(word, i + 1)
    return out


def _at(low: str, word: str) -> list:
    """The starts of `word` at the start of a word in the lowercased text (str.find, no regex pass)."""
    out, i = [], low.find(word)
    while i >= 0:
        if i == 0 or not (low[i - 1].isalnum() or low[i - 1] == "_"):
            out.append(i)
        i = low.find(word, i + 1)
    return out


# a part that names a daemon, a tool or a bot, not a person: `user kibana8`, `codecov-commenter`, `jira-integration2`
_TOOL_PARTS = frozenset(
    "bot bots svc service daemon cron cronjob runner deploy deployer integration commenter webhook kibana zabbix "
    "nagios pgbouncer grafana prometheus elastic elasticsearch logstash redis mongo mongodb mariadb postgres "
    "mysql jenkins gitlab github bitbucket jira confluence sonar sonarqube nexus artifactory ansible terraform "
    "docker podman kube kubernetes helm vault consul nomad airflow celery rabbitmq kafka zookeeper hadoop spark "
    "nginx apache httpd tomcat jetty ubuntu debian centos fedora alpine admin root guest webmaster postmaster "
    "backup borgbackup rsync rsyncd monitor monitoring codecov dependabot renovate travis circleci magento drupal "
    "moodle nextcloud minikube "
    "kubelet traefik telegraf caddy jellyfin pihole polkitd lightdm restic borg rhel linux wordpress joomla "
    "keycloak".split())


def _handle_ok(v: str, known) -> bool:
    """A person's handle, not a device, a hex id or words of the word list: each part is letters with digits at the
    end at most, a part of letters is not all capitals, longer than two letters and no word of the list, and one
    has four letters or more (x86_64, v1.2.3, my_app, django_app, john.doe, eth0, SAML2, utf-8 and
    pod-7f9c stay text). An initial may lead (k.orbek, a corporate login)."""
    parts = [p for p in re.split(r"[._-]|(?<=[a-z])(?=[A-Z])", v) if p]
    if any(not re.fullmatch(r"[A-Za-z]+\d*|\d+", p) for p in parts):
        return False
    letters = [re.sub(r"\d+$", "", p) for p in parts if not p.isdigit()]
    if not letters or max(len(w) for w in letters) < 4:
        return False
    if len(letters) > 1 and len(letters[0]) == 1 and letters[0].islower():
        letters = letters[1:]                       # k.orbek: the initial of a given name
    return all(len(w) > 2 and not w.isupper() and w.lower() not in known and w.lower() not in _TOOL_PARTS
               for w in letters)


# a key whose value is a user name and that personal.py's username label does not read (#51); not `handle` or
# `screenName`, which name product slugs and app screens as often
USER_ID_KEYS = frozenset({"userid", "userlogin", "loginname", "loginid"})


_USER_ID_KEY = r"(?i:user[_-]?(?:id|login)|login[_-]?(?:name|id))"
_ID_FORMS: dict = {}


def user_id_forms(value: str, ops: str, end: str) -> list:
    """The forms of key_values.forms with the key in the pattern: the general forms take every `key: value` of a text
    and check the key after, which cost 0.08 s on a megabyte for this one family. Groups as there: 2 or 3 the key,
    4 the value."""
    got = _ID_FORMS.get((value, ops, end))
    if got is None:
        k = _USER_ID_KEY
        got = _ID_FORMS[(value, ops, end)] = [
            re.compile(r"(?:([\"'`])(" + k + r")\1|(?<![\w.-])(" + k + r"))[ \t]{0,3}" + ops + r"[ \t]{0,3}[\"'`]?"
                       + value + end, re.M),
            re.compile(r"<th(?:\s[^<>]{0,80})?>\s{0,32}()(" + k + r")()\s{0,32}</th>\s{0,64}"
                       r"<td(?:\s[^<>]{0,80})?>\s{0,32}" + value + r"\s{0,32}</td>"),
            re.compile(r"<()(" + k + r")()(?:\s[^<>]{0,200})?>[ \t]*" + value + r"[ \t]*</\2>"),
        ]
    return got


def user_id_matches(text: str, low: str, value: str, ops: str, end: str):
    """The matches of user_id_forms in `text`. The key form is tried only where str.find saw `user` or `login` (one
    regex pass over a megabyte cost 0.03 s); the table and the element forms are cheap passes."""
    first, *rest = user_id_forms(value, ops, end)
    for pos in sorted(_at(low, "user") + _at(low, "login")):
        for at in (pos - 1, pos) if pos and low[pos - 1] in "\"'`" else (pos,):
            m = first.match(text, at)
            if m is not None:
                yield m
                break
    for rx in rest:
        yield from rx.finditer(text)


def user_id_ok(v: str) -> bool:
    from .core import _word_set
    from .personal import _username_value_ok
    # _username_value_ok refuses a service user (ftpuser2), as on the cue path
    return bool(re.fullmatch(_HANDLE, v)) and _username_value_ok(v, False, " ") and _handle_ok(v, _word_set())
