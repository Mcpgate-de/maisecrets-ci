"""Field names a caller gives with a text (`scan(..., fields=...)`, `findings(..., fields=...)`).

A caller that has the structure of its data (a JSON response walked with a field path, a key-value record) can name
the field of a value: `fields=[(start, end, ("customer", "telefon"))]`, the span of the value in the text and the field
path, outermost first. The name is evidence as a label before the value is in text, and only that: the last part of
the path that is no list index is put before a copy of the value (`telefon: <value>`) and that line is scanned with
the same rules. A hit inside the value is added when the bare value gives no hit there and the scan of the whole text
has none there either. So a field name

- adds no hit that the same label in text would not give, and none that the bare value gives (the context of the text
  decided that one: a test file, a build number before it);
- takes no hit away: the hits of the text stay as they are, and with no fields the scan is the one of before;
- parses nothing: the core reads JSON, CSV and the other formats of the text itself, as without fields. A field that
  names what the core read itself adds no second hit, since the hit of the text is there already.

One label is not the path's own: a person's name under a person's role (author.name, assignee.displayName) is read
after full_name, when the value reads as a name and not as words (`_person_value`). After the weak label `name` a
surname that is also an English word made the whole name words; under author.name it is a person's.

A name the label rules give no evidence for (id, value, data, an unknown word) adds nothing, as it would in text. Three
kinds of name add nothing either, though the label rules read a key word in them, because in API data they name
identifiers far more often than credentials (measured: under them a ticket key, a file path, a cache key and a
cursor each became a SECRET):

- `key` alone (a Jira issue key, an object key, a translation key); a name with more words, such as api_key or
  secret_key, is a label as in text. `token` alone is a label: under it a 64-hex value, a UUID or a legacy GitLab
  token is found by the label only (gateway review gates, 2026-10-30);
- the cursor of a paged list or a sync (nextPageToken, syncToken, continuationToken, ...): every list response of
  many APIs carries one.
"""
from __future__ import annotations

import dataclasses

from .lazy_regex import LazyRx as _LazyRx

# a word before `token` that makes the field the cursor of a paged list or a sync, not a credential (measured on
# synthetic cursors: under nextPageToken, pageToken, syncToken and continuationToken each one was a SECRET). Only the
# word right before `token` counts: NextToken (AWS) is a cursor, PrevAuthToken (Grafana) names an auth token. In text
# `next` and `prev` alone stay out: Samsung CredData labels 40 AWS NextToken values credentials, and the text scan
# took them before this release too
_CURSOR_WORDS = frozenset({"page", "sync", "continuation", "continue", "cursor", "pagination", "resume", "purchase",
                           "sequence", "delta", "skip", "rewrite"})
_FIELD_CURSOR_WORDS = _CURSOR_WORDS | {"next", "prev", "previous"}
# the word before `key` in the name of a key that is an identifier: file_key (Figma), partition_key, idempotency_key
_HANDLE_KEY_WORDS = frozenset({"file", "node", "component", "style", "property", "partition", "sort", "row", "primary",
                               "foreign", "idempotency"})
_SECRET_WORDS = frozenset({"secret", "secrets", "password", "passwords", "passwd", "pwd", "token", "tokens", "key",
                           "keys"})
# the last word of a label that names a time or a state of a secret: lastPasswordChangeDateTime, password_set
_TIME_STATE_END = frozenset({"date", "time", "timestamp", "expires", "expiry", "expiration", "set", "changed",
                             "created", "updated", "enabled", "required", "state", "status", "revoked", "rotated"})
# `at` and `on` end such a label only after a verb: token_expires_at, secretCreatedAt; not secret_at or api_key_on
_AT_ON_AFTER = frozenset({"created", "updated", "changed", "expires", "expired", "revoked", "rotated", "issued",
                          "used", "set", "modified", "reset"})
# the words of a credential label in generic-api-key and the keyword rules; a label that ends in `id` after one of them
# names an identifier: accessReviewId, privateKeyMetadataId, vppTokenAppleId (Microsoft 365, App Store Connect)
_CREDENTIAL_WORDS = _SECRET_WORDS | {"access", "auth", "authentication", "authorization", "api", "credential",
                                     "credentials", "private"}
_REVISION_END = frozenset({"commit", "sha", "sha1", "sha256", "revision", "rev", "digest", "checksum"})
_HEX = _LazyRx(r"(?i)(?:sha256:)?[0-9a-f]{7,64}")
# parts of a credential word, also glued to another word (mysecret, apikey, passwordhash); maisecrets is a product name
_CREDENTIAL_PARTS = ("secret", "pass", "pwd", "token", "key", "auth", "cred", "private", "api", "access", "bearer",
                     "session", "cookie")
_TIME_STATE_PAIRS = frozenset({("valid", "from"), ("valid", "until"), ("not", "before"), ("not", "after"),
                               ("last", "used")})
# a word that is no label alone (`key`); with another word before it, it is one
_NO_LABEL_ALONE = frozenset({"key"})
# a parent field whose value is always a person: its `name` or `displayName` is a person's full name, as after the label
# full_name. In API data `name` alone is a project, a label or a team as often as a person (author.name in GitLab,
# reporter.displayName in Jira, organizer.displayName in Google Calendar, gateway corpus 2026-11-01: after `name:` a
# surname that is also an English word made the name words, and a quarter of these names stayed in the clear)
_PERSON_PARENTS = frozenset({"author", "reviewer", "reviewers", "assignee", "assignees", "reporter", "creator",
                             "organizer", "attendee", "attendees", "committer", "approver", "requester", "merge_user",
                             "merged_by", "closed_by", "approved_by", "requested_by"})
_PERSON_NAME_FIELDS = (["name"], ["display", "name"], ["full", "name"])
# a word of an account, a group or an account's state: under author.name the value names no person (Removed Account,
# Former Member, Guest User, Platform Team)
_NOT_A_PERSON_WORDS = frozenset({"user", "users", "account", "accounts", "member", "members", "team", "teams", "group",
                                 "groups", "department", "admin", "administrator", "system", "service", "bot", "guest",
                                 "deleted", "removed", "former", "inactive", "deactivated", "disabled", "archived",
                                 "unknown", "anonymous", "external", "unassigned", "nobody", "everyone", "automation"})
_LABEL_MAX = 64
# characters that would end the label line or make the name a label and a value of its own
_NOT_IN_LABEL = _LazyRx(r"[\x00-\x1f\x7f\x85\u2028\u2029:=\"']")
_CAMEL = _LazyRx(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")   # APIKeyCreatedAt: API, Key, Created, At
_WORD_SPLIT = _LazyRx(r"[\s._\-]+")


def checked(text: str, fields) -> tuple:
    """The fields as ((start, end, label), ...), or () when they add nothing. Raises TypeError or ValueError for a wrong
    shape; a message names the position of the field and never a part of the text or of a name."""
    if fields is None:
        return ()
    if not isinstance(text, str):   # as scan() says it, before a length is read
        raise TypeError(f"text must be a str, not {type(text).__name__}")
    if isinstance(fields, (str, bytes, bytearray, dict)) or not isinstance(fields, (list, tuple)):
        raise TypeError(f"fields must be a list or tuple of (start, end, name), not {type(fields).__name__}")
    out = []
    for i, f in enumerate(fields):
        if not isinstance(f, (list, tuple)) or len(f) != 3:
            raise TypeError(f"fields[{i}] must be a (start, end, name) tuple, not {type(f).__name__}")
        start, end, name = f
        for what, v in (("start", start), ("end", end)):
            if not isinstance(v, int) or isinstance(v, bool):
                raise TypeError(f"fields[{i}] {what} must be an int, not {type(v).__name__}")
        if not 0 <= start < end <= len(text):
            raise ValueError(f"fields[{i}] must have 0 <= start < end <= len(text), got start={start} end={end} "
                             f"for a text of {len(text)} code points")
        if not isinstance(name, (list, tuple)) or not name:
            raise TypeError(f"fields[{i}] name must be a non-empty tuple of path parts, not {type(name).__name__}")
        for part in name:
            if not isinstance(part, (str, int)) or isinstance(part, bool):
                raise TypeError(f"fields[{i}] name parts must be str or int, not {type(part).__name__}")
        label = _label(name)
        if label and _person_path(name) and _person_value(text[start:end]):
            label = "full_name"
        if label:
            out.append((start, end, label))
    return tuple(out)


def _person_parent(part: str) -> bool:
    return len(part) <= _LABEL_MAX and "_".join(label_words(part)) in _PERSON_PARENTS


def _person_value(value: str) -> bool:
    """The value reads as a person's name and not as words: two to four words, and the first is no English word (a
    given name that is also one, Grace or Mark, counts as a name). Under author.name a deleted or system user, a team
    or a department (Deleted User, Human Resources) stays under the plain label (codex review, 2026-11-01)."""
    from .core import _word_set
    from .personal import _GIVEN_NAME_WORDS, _NOT_A_NAME_START, _NOT_A_NAME_WORD, _inflected_word
    words = value.split()
    if not 2 <= len(words) <= 4:
        return False
    low = [w.lower().strip(".") for w in words]
    if low[0] in _NOT_A_NAME_START or any(w in _NOT_A_NAME_WORD or w in _NOT_A_PERSON_WORDS for w in low):
        return False
    return low[0] in _GIVEN_NAME_WORDS or not (low[0] in _word_set() or _inflected_word(low[0]))


def label_words(label: str) -> list:
    """The words of a label in lower case: camelCase, snake_case, kebab-case, dots and spaces split it."""
    return [w for w in _WORD_SPLIT.split(_CAMEL.sub("_", label).lower()) if w]


def is_cursor(words, field: bool = False) -> bool:
    """The label names the cursor of a paged list or a sync: nextPageToken, syncToken, purchaseToken; as a field name
    also NextToken. The word right before `token` decides: purchaseAccessToken and syncRefreshToken name a
    credential."""
    cursor_words = _FIELD_CURSOR_WORDS if field else _CURSOR_WORDS
    return len(words) >= 2 and words[-1] == "token" and words[-2] in cursor_words


def is_handle_key(words) -> bool:
    """The label names the key of a file, a node or a record, an identifier: file_key, partitionKey."""
    return len(words) == 2 and words[1] == "key" and words[0] in _HANDLE_KEY_WORDS


def is_time_or_state(words) -> bool:
    """The label names the time or the state of a secret, not the secret: token_expires_at, password_set."""
    i = next((k for k, w in enumerate(words) if w in _SECRET_WORDS), None)
    tail = words[i + 1:] if i is not None else []
    if not tail:
        return False
    return (tail[-1] in _TIME_STATE_END or tuple(tail[-2:]) in _TIME_STATE_PAIRS
            or (tail[-1] in ("at", "on") and len(tail) >= 2 and tail[-2] in _AT_ON_AFTER))


def is_an_id(words) -> bool:
    """The label ends in id after a word of a credential label: an identifier, not the credential."""
    return len(words) >= 2 and words[-1] in ("id", "ids") and any(w in _CREDENTIAL_WORDS for w in words[:-1])


def is_a_revision(words, value: str) -> bool:
    """The label ends in a word of a revision, no word of it names a credential, and the value is hex:
    MAISECRETS_COMMIT=<git sha>, image_digest (gateway report, 2026-10-30: secrets inside a product name made the label
    of a commit a secret label). SECRET_SHA, key_rev, MYSECRET_SHA and passwordhash_revision stay credential labels."""
    rest = "".join(words[:-1]).replace("maisecrets", "")
    return (len(words) >= 2 and words[-1] in _REVISION_END and not any(c in rest for c in _CREDENTIAL_PARTS)
            and bool(_HEX.fullmatch(value)))


def names_no_secret(words) -> bool:
    """A cursor, a key that is an identifier, an id, or the time or the state of a secret."""
    return is_cursor(words) or is_handle_key(words) or is_an_id(words) or is_time_or_state(words)


def _person_path(name) -> bool:
    """The path ends in name, displayName or fullName under a person's role: author.name, assignee.displayName."""
    parts = [p.strip() for p in name if not isinstance(p, int) and p.strip() and not p.strip().isdigit()]
    return len(parts) >= 2 and label_words(parts[-1]) in _PERSON_NAME_FIELDS and _person_parent(parts[-2])


def _label(name) -> str:
    """The label of a field path: its last part that is no list index, or "" when it can give no evidence."""
    for part in reversed(name):
        if isinstance(part, int) or not part.strip() or part.strip().isdigit():
            continue
        label = part.strip()
        if len(label) > _LABEL_MAX or _NOT_IN_LABEL.search(label):
            return ""
        words = label_words(label)
        if is_cursor(words, field=True) or is_handle_key(words):
            return ""
        if len(words) == 1 and words[0] in _NO_LABEL_ALONE:
            return ""
        return label
    return ""


def added(text: str, hits: list, spans: tuple, scan, same_scan: bool = False) -> list:
    """`hits` (the scan of the text) with the hits the field labels add; `scan(text)` scans a text with the rules,
    the channel and the rule list of the call. With `same_scan`, `hits` came from `scan(text)` itself: a field over
    the whole text then reuses them as its bare scan (one scan per field, not two)."""
    taken = [(m.start, m.end) for m in hits]
    whole = list(taken) if same_scan else None
    extra = []
    for start, end, label in spans:
        value = text[start:end]
        if not value.strip():
            continue
        lead = len(label) + 2
        if whole is not None and (start, end) == (0, len(text)):
            bare = whole
        else:
            bare = [(m.start, m.end) for m in scan(value)]
        for m in scan(f"{label}: {value}"):
            a, b = m.start - lead, m.end - lead
            if a < 0 or b > len(value) or any(a < y and x < b for x, y in bare):
                continue   # in the label, or the bare value has a hit there: the field gives no evidence for it
            a, b = a + start, b + start
            if text[a:b] != m.value or any(a < y and x < b for x, y in taken):
                continue
            taken.append((a, b))
            extra.append(dataclasses.replace(m, start=a, end=b))
    if not extra:
        return hits
    return sorted(hits + extra, key=lambda m: m.start)
