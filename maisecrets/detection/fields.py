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
_LABEL_MAX = 64
# characters that would end the label line or make the name a label and a value of its own
_NOT_IN_LABEL = _LazyRx(r"[\x00-\x1f\x7f\x85\u2028\u2029:=\"']")
_CAMEL = _LazyRx(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")   # APIKeyCreatedAt: API, Key, Created, At
_WORD_SPLIT = _LazyRx(r"[\s._\-]+")
# the checksum of a file after its name: the sha256 of ('maisecrets-0.8.27.tar.gz', '<sha256>') is no secret (#28).
# Only a value of a digest's length: the password of an archive (password for backup.zip: <value>) stays a hit
_FILE_LABEL_RE = _LazyRx(r"(?i)[\w.-]\.(?:tar\.(?:gz|bz2|xz|zst)|tgz|tar|zip|7z|whl|gz|xz|zst|jar|deb|rpm|dmg|msi|exe"
                         r"|apk|nupkg|gem)[\"']?\s*[,:=]\s*[\"'`]?$")
_DIGEST_RE = _LazyRx(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}")


# a content digest names content, it opens nothing: `sha256:<hex>` alone or an image reference pinned by it
# (SECRET_IMAGE = mcpgate/ner:v2.0.3798@sha256:<hex>, a public image, 2026-11-08)
# An image reference has a path (`team/app`): `admin:<password>@sha256:…` is a password, not a tag (Opus review)
_CONTENT_DIGEST_RE = _LazyRx(r"(?:(?:[a-z0-9][\w.-]*(?::\d+)?/)+[a-z0-9][\w.-]*(?::[\w.-]+)?@)?"
                             r"sha(?:256:[0-9a-f]{64}|512:[0-9a-f]{128})")
# after a password label a digest is the password's hash, which an unsalted guess finds offline
_PASSWORD_LABEL_RE = _LazyRx(r"(?i)pass(?:w(?:or)?d)?|pwd|kennwort|passphrase")


def content_digest(value: str, before: str = "") -> bool:
    return bool(_CONTENT_DIGEST_RE.fullmatch(value.strip("\"'` ")) and not _PASSWORD_LABEL_RE.search(before))


def file_digest(text: str, pos: int, end: int, value: str) -> bool:
    """A hex digest (MD5, SHA-1, SHA-256, SHA-512) right after a file name with an archive or package extension, or a
    content digest after any label."""
    return content_digest(value, text[pos:end]) or bool(_DIGEST_RE.fullmatch(value.strip("\"'` "))
                                          and _FILE_LABEL_RE.search(text, pos, end))


# the key of a Figma file (22 to 24 letters and digits) or of a component or a style (40 hex) after `key` or `file_key`
# in a Figma answer: a public id, no credential (#22, about 138 false alarms in 12 hours at a gateway). The answer
# shows itself within 600 characters by a field only Figma has, or a thumbnail on figma.com. A figma.com link alone, a
# time (`id: 10:30`) and a figd_ token are no sign: a key there stays a hit
_FIGMA_KEY_LABEL_RE = _LazyRx(r"(?i)(?<![\w.-])(?:file_)?key[\"']?\s*:\s*[\"']?$")
_FIGMA_KEY_RE = _LazyRx(r"[0-9a-f]{40}|(?=[a-f0-9]*[g-zA-Z])[A-Za-z0-9]{22,24}")
_FIGMA_ANSWER_RE = _LazyRx(r"\b(?:editorType|componentSetId|containing_frame|documentationLinks|styleType)\b"
                           r"|\bnode_id[\"']?\s*:\s*[\"']?I?\d+:\d+"
                           r"|\bthumbnail_?url[\"']?\s*:\s*[\"']?https://[\w.-]*\.figma\.com/")
_FIGMA_WINDOW = 600


def figma_id(text: str, pos: int, start: int, value: str) -> bool:
    """A Figma file, component or style key after `key` or `file_key` (text[pos:start]), in a text that shows a Figma
    answer within 600 characters of the value."""
    return bool(_FIGMA_KEY_RE.fullmatch(value.strip("\"'` ")) and _FIGMA_KEY_LABEL_RE.search(text, pos, start)
                and _FIGMA_ANSWER_RE.search(text, max(0, start - _FIGMA_WINDOW), start + _FIGMA_WINDOW))


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
        if label:
            out.append((start, end, label))
    return tuple(out)


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


# a last part that only holds the value of the object above it: {"phone": [{"value": ...}]}, {"phone": {"number": ...}}.
# The part above it names the value (ai-gateway #1764: Pipedrive, HubSpot and vCard-like contacts)
# not `text`: it is the content of a message (Slack text and blocks[].text), and the label of a copy must stay the same
_WRAPPER_WORDS = frozenset({"value", "values", "number", "nummer", "wert", "val"})
# a phone word with qualifiers only names a phone: phone_home, telefon_privat, mobileBusiness, phone_cell. A name with
# another word stays as it is: phone_type, phone_country_code and mobile_app_version name no phone number
_PHONE_HEADS = frozenset({"phone", "telephone", "tel", "telefon", "mobile", "mobil", "handy", "cell", "fax"})
_PHONE_QUALIFIERS = frozenset({"home", "work", "business", "office", "private", "privat", "personal", "direct",
                               "direkt", "main", "primary", "secondary", "alt", "alternate", "other", "mobile", "mobil",
                               "cell", "cellular", "geschaeftlich", "geschäftlich", "dienstlich", "buero", "büro",
                               "number", "numbers", "nummer", "nr", "no"})


def _part_label(part) -> str | None:
    """The label of one path part, "" when it can give no evidence, None when it is a list index."""
    if isinstance(part, int) or not part.strip() or part.strip().isdigit():
        return None
    label = part.strip()
    if len(label) > _LABEL_MAX or _NOT_IN_LABEL.search(label):
        return ""
    words = label_words(label)
    if is_cursor(words, field=True) or is_handle_key(words):
        return ""
    if len(words) == 1 and words[0] in _NO_LABEL_ALONE:
        return ""
    return phone_head(words) or label


def phone_head(words) -> str:
    """The phone word of a name that is a phone word with qualifiers only (phone_home -> phone), else ""."""
    if len(words) >= 2 and (
            (words[0] in _PHONE_HEADS and all(w in _PHONE_QUALIFIERS for w in words[1:]))
            or (words[-1] in _PHONE_HEADS and all(w in _PHONE_QUALIFIERS for w in words[:-1]))):
        return words[0] if words[0] in _PHONE_HEADS else words[-1]
    return ""


def named_key(keys) -> str:
    """The key that names a value, from the string keys of its path, outermost first: a last key that only wraps the
    value gives the key above it (not bare cell or mobile), and a phone word with qualifiers only gives the phone
    word. The same reading as the labels of `fields=`, for the record scan of leaves.py (ai-gateway #1764: the
    gateway's main path scans by leaf). "" when the wrapper has nothing above it that names."""
    if not keys:
        return ""
    last = keys[-1]
    words = label_words(last)
    if len(keys) >= 2 and words and set(words) <= _WRAPPER_WORDS:
        above = keys[-2]
        if label_words(above) in (["cell"], ["mobile"]):
            return ""
        last, words = above, label_words(above)
    return phone_head(words) or last


def _label(name) -> str:
    """The label of a field path: its last part that is no list index, or "" when it can give no evidence. A last
    part that only wraps the value (`value`, `number`) gives the label of the part above it."""
    parts = [p for p in name if _part_label(p) is not None]
    if not parts:
        return ""
    label = _part_label(parts[-1])
    if label and len(parts) >= 2 and set(label_words(label)) <= _WRAPPER_WORDS:
        above = _part_label(parts[-2]) or ""
        # cell and mobile alone name a spreadsheet cell or a layout as often as a phone: ("cell", "value")
        return "" if label_words(above) in (["cell"], ["mobile"]) else above
    return label or ""


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
        bare = whole if whole is not None and (start, end) == (0, len(text)) else None
        for m in scan(f"{label}: {value}"):
            a, b = m.start - lead, m.end - lead
            if a < 0 or b > len(value) or text[a + start:b + start] != m.value \
                    or any(a + start < y and x < b + start for x, y in taken):
                continue   # in the label, or the text has a hit there already
            if bare is None:
                # the bare value is scanned only for a hit the label gave: most fields give none, and the scan of
                # each value was half the cost of a field (gateway corpus, 2026-11-02)
                bare = [(m.start, m.end) for m in scan(value)]
            if any(a < y and x < b for x, y in bare):
                continue   # the bare value has a hit there: the field gives no evidence for it
            a, b = a + start, b + start
            taken.append((a, b))
            extra.append(dataclasses.replace(m, start=a, end=b))
    if not extra:
        return hits
    return sorted(hits + extra, key=lambda m: m.start)


# a row of a two-column Markdown table whose first cell names the second: | Date of Birth | 1984-07-12 |. The cell is
# a label as `Date of Birth: 1984-07-12` would be (the field rule of this module), and only personal data comes of it
_MD_KV_ROW_RE = _LazyRx(r"(?m)^[ \t]*\|[ \t]*(\*{0,2})([A-Za-z][A-Za-z ()/#.'_-]{1,40}?)\1[ \t]*:?[ \t]*\|[ \t]*"
                        r"([^|\n]{1,120}?)[ \t]*\|[ \t]*$")


def md_key_value_hits(text: str, hits: list, scanner) -> list:
    spans = []
    for m in _MD_KV_ROW_RE.finditer(text):
        if set(m.group(3)) <= set("-: "):
            continue
        label = _label((m.group(2).strip(),))
        if label:
            spans.append((m.start(3), m.end(3), label))
    if not spans:
        return hits
    from .vocabulary import TYPES
    before = {(h.start, h.end) for h in hits}
    out = added(text, hits, tuple(spans), scanner)
    # a name stays with the record rules of the Markdown table: a first name alone in a form is no person
    return [h for h in out if (h.start, h.end) in before
            or (h.type != "NAME" and TYPES.get(h.type, {}).get("family") == "pii")]
