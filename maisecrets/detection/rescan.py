"""The bounded rescans of a long line (maisecrets/detection/reach.py says how far each reader reads).

core.py calls these by its own names (_changed_windows_scan, _label_scan_near). They live here so that core.py stays
under the size of a file that the plugin directory reads whole (scripts/build_release_tree.py, FILE_BYTES). The core
imports this module at its own import; the names of the core are read when a function runs.
"""
from __future__ import annotations

import contextvars

from . import checksums, core, reach, regex_reach

# the last long text that core._scan read in this context: (text, order, gates, channel, enabled, where its copy
# started). A labelled scan of the same text (label_scan_near) takes its gates and the outcome of its copy from here
LAST_SCAN: contextvars.ContextVar = contextvars.ContextVar("maisecrets_last_scan", default=None)
# set by findings() and scan() with fields for the length of the call: only then does core._scan remember its text
WANT = object()


def is_marker(rule) -> bool:
    """The steps of the scan order that are no rule: the personal data, the terms, the imported values."""
    return rule is core._PERSONAL or rule is core._TERMS or rule is core._IMPORTS


def gate_ok(rule, text: str, low: str, keywords_in: dict, channel: str) -> bool:
    """Whether the gates of a rule let its regex run on this text: a keyword, the leading literal, a required literal
    and a context word that it needs, each searched in the whole text."""
    if rule.keywords and not core._any_keyword(rule.keywords, low, keywords_in):
        return False
    if core._lacks_prefix(rule.prefix, text, low):
        return False
    if core._lacks_required(rule.need, text, low):
        return False
    # a rule that cannot fire without a context word need not run its regex without one
    alone = channel == "tool" and rule.id in core.CARD_ALONE_IN_TOOL
    return not (rule.context and (rule.require_context or rule.score < 0.5) and not alone
                and not core._has_context_word(low, rule.context))


def gate_words(order: tuple) -> tuple:
    """((rule, its gate words in lower case), ...) of a scan order, and the length of the longest word. Kept per
    order on the detector."""
    d = core._det()
    got = getattr(d, "_gate_words", None)
    if got is not None and got[0] is order:
        return got[1], got[2]
    out = []
    longest = 1
    for rule in order:
        if is_marker(rule):
            continue
        need, _icase = rule.prefix or core._NO_PREFIX
        words = tuple(w.lower() for w in (*(rule.keywords or ()), *((need,) if need else ()), *(rule.need or ()),
                                          *(rule.context or ())) if w)
        longest = max([longest] + [len(w) for w in words])
        out.append((rule, words))
    d._gate_words = (order, tuple(out), longest)
    return d._gate_words[1], longest


def gates_for(order: tuple, text: str, enabled, channel: str, known: dict | None = None,
               again: frozenset = frozenset()) -> dict:
    """id(rule) -> whether the gates of the rule let it run on `text`, for each rule of `order` that `enabled`
    allows. A rule in `known` and not in `again` keeps the answer of `known`."""
    low = core._lower(text)
    words_in: dict = {}
    out = {}
    for rule in order:
        if is_marker(rule) or (enabled is not None and rule.id not in enabled and rule.key not in enabled):
            continue
        k = id(rule)
        if known is not None and k in known and k not in again:
            out[k] = known[k]
        else:
            out[k] = gate_ok(rule, text, low, words_in, channel)
    return out


def matcher(rule) -> str:
    return rule.matcher or core._registry.matcher_of(rule.id, "literal" if rule.id in core._LITERAL_IDS else "")


# matchers whose hits do not come from one match of the rule's regex: a list to its closing bracket, a curl part back
# to its `curl`, a seed phrase back to its context word, a quoted literal to its closing quote
_FAR_MATCHERS = frozenset({"list", "curl", "seed", "literal"})


def far_rules(order: tuple) -> tuple:
    """The built-in rules of a scan order whose one match can run further from a whitespace inside it than a window
    reaches (regex_reach.spread against reach.COPY_MARGIN and reach.LABEL_REACH), or that a matcher reads further.
    Kept per order on the detector."""
    d = core._det()
    got = getattr(d, "_far_rules", None)
    if got is not None and got[0] is order:
        return got[1]
    before = min(reach.COPY_MARGIN, reach.LABEL_REACH) - reach.CONTEXT
    after = reach.COPY_MARGIN - reach.AFTER
    out = []
    for rule in order:
        if is_marker(rule):
            continue
        pattern = getattr(rule.regex, "pattern", None)
        b, a = regex_reach.spread(pattern, rule.regex.flags or 0) if isinstance(pattern, str) else \
            (regex_reach.FAR, regex_reach.FAR)
        if b >= before or a >= after or matcher(rule) in _FAR_MATCHERS:
            out.append(rule)
    d._far_rules = (order, tuple(out))
    return d._far_rules[1]


def far_rule_matches(order: tuple, gates: dict, text: str, channel: str) -> bool:
    """A far rule (far_rules) that may run on `text` (gates) matches somewhere in it: its hit may cross the edge of
    a window, so the whole text is read. A far rule with no match in the text has no hit there to lose."""
    for rule in far_rules(order):
        if gates.get(id(rule), False) and next(iter(core._matches(rule, text, channel)), None) is not None:
            return True
    return False


def label_far_match(order: tuple, gates: dict, labelled: str, lead: int, value: str, channel: str) -> bool:
    """A far rule that may run reads otherwise with the label before the value. A rule that did not match the value
    bare (its gate is True, not 2: core._scan marks a rule that matched) and runs as one regex over the text, or over
    each line, must not match the labelled text at all. Any other far rule has its matches with and without the
    label compared: only a match that starts after `lead` and its longest lookbehind is one of the value."""
    lines = None
    for rule in far_rules(order):
        seen = gates.get(id(rule), False)
        if not seen:
            continue
        m = matcher(rule)
        rx = rule.regex._for(labelled) if hasattr(rule.regex, "_for") else rule.regex
        if seen != 2 and m in ("", "regex"):
            if rx.search(labelled):
                return True
            continue
        if seen != 2 and m == "lines":
            lines = labelled.split("\n") if lines is None else lines
            if not any(core._LABEL_ONLY_RE.search(x) for x in lines):
                if any(rx.search(x) for x in lines):
                    return True
                continue
        pattern = getattr(rule.regex, "pattern", None)
        near = lead + (regex_reach.behind(pattern, rule.regex.flags or 0) if isinstance(pattern, str)
                       else regex_reach.FAR)
        got = [(x.start(), x.end()) for x in core._matches(rule, labelled, channel)]
        if any(a < near for a, _ in got) or \
                got != [(x.start() + lead, x.end() + lead) for x in core._matches(rule, value, channel)]:
            return True
    return False


def unbounded(order: tuple, enabled, text: str) -> bool:
    """The reach of a window holds no proof here: a rule of your own runs (its regex may read anything), or the text
    holds a run of whitespace or of non-whitespace longer than regex_reach counts with."""
    if any(not is_marker(r) and core._runs_after_personal(r)
           and (enabled is None or r.id in enabled or r.key in enabled) for r in order):
        return True
    return reach.long_run(text)


def long_personal_match(text: str) -> bool:
    """A regex of personal.py that reads the whole text and whose one match has no bound (a row of title words before
    a name, an XML element named by a back reference) matches CONTEXT characters or more somewhere in the text."""
    try:
        from . import personal as p
    except ImportError:   # a copy of detect.py without its sibling modules
        return False
    return any(m.end() - m.start() >= reach.CONTEXT for rx in (p._DE_TITLE_RE, p._XML_NAME_ELEMENT_RE)
               for m in rx.finditer(text))


def far_reaching_match(order: tuple, gates: dict, text: str, lo: int = 0, hi: int | None = None) -> bool:
    """A rule with the list or the curl matcher that may run (gates) has its label or its `curl` in text[lo:hi]: its
    hits run on past any window (a list to its closing bracket, a curl part over the rest of its line)."""
    for rule in order:
        if is_marker(rule) or not gates.get(id(rule), False):
            continue
        m = matcher(rule)
        if m == "list":
            rx = rule.regex
        elif m == "curl":
            parts = core._curl_parts(rule)
            rx = parts[0] if parts is not None else rule.regex
        else:
            continue
        if rx.search(text if lo == 0 and hi is None else text[lo:hi]):
            return True
    return False


def copy_window_gates(text: str, norm, wa: int, wb: int, runs: list, order: tuple, enabled, channel: str,
                       raw_gates: dict) -> dict | None:
    """The gates of the copy's window [wa, wb), as a scan of that window decides them, or None when the copy opens a
    rule that the raw text keeps closed: a word the cleaning made (pass&shy;word) lets that rule run anywhere in the
    window, so the window is read whole."""
    copy = norm.text
    whole = wa == 0 and wb == len(copy)
    again: set = set()
    if whole:
        # the copy is the raw text except at the runs: only a rule with a gate word near a run can read otherwise
        words, longest = gate_words(order)
        near = []
        for x, y in runs:
            near.append(core._lower(copy[max(0, x - longest):y + longest]))
            near.append(core._lower(text[max(0, norm.starts[x] - longest):norm.ends[y - 1] + longest]))
        again = {id(r) for r, ws in words if any(w in piece for piece in near for w in ws)}
    gates = gates_for(order, copy[wa:wb], enabled, channel, raw_gates if whole else None, frozenset(again))
    raw_low = None
    raw_words: dict = {}
    for rule in order:
        if is_marker(rule) or not gates.get(id(rule), False):
            continue
        k = id(rule)
        opened = raw_gates.get(k)
        if opened is None:   # a rule of your own runs after the copy: its gates on the raw text are asked here
            raw_low = core._lower(text) if raw_low is None else raw_low
            opened = gate_ok(rule, text, raw_low, raw_words, channel)
        if not opened:
            return None
    return gates


def record_hits(text: str, channel: str) -> list:
    """The hits of the record and table readers of personal.py alone, under the conditions that personal._form_hits
    and personal.hits run them with (keep the two in step): a hit of one of them can depend on a key, a header or a
    BEGIN:VCARD anywhere in its record. None without that module."""
    try:
        from . import personal as p
    except ImportError:   # a copy of detect.py without its sibling modules
        return []
    want = p.RULE_IDS if channel == "tool" else p.PROMPT_RULES.intersection(p.RULE_IDS)
    out = []
    if any(f in want for f in p._VCARD_FORMS) and ("VCARD" in text.upper() or (
            p._VCARD_BARE_WORDS_RE.search(text) and p._VCARD_BARE_HINT_RE.search(text))):
        out += p._vcard_hits(text, want)
    if "md-table-personal-column" in want and "|" in text and "---" in text:
        out += p._md_table_hits(text)
    if "sql-insert-personal-column" in want and "(" in text and ("INSERT" in text or "insert" in text):
        out += p._sql_insert_hits(text)
    if "html-table-personal-column" in want and "<t" in text:
        out += p._html_table_hits(text)
    if "json-personal-field" in want and "{" in text and '":' in text.replace('" :', '":'):
        out += p._json_record_hits(text)
    if "xml-personal-field" in want and ("</" in text or "/>" in text):
        out += p._xml_record_hits(text)
    if "json-personal-field" in want and ('\\":' in text or "{'" in text):
        out += p._quoted_json_hits(text)
    if "kv-personal-field" in want:
        out += p._kv_record_hits(text)
    if channel == "tool" and "csv-personal-column" in want and "\n" in text:
        out += p._csv_hits(text)
    if channel == "tool" and "secret-under-password-column" in want and "\n" in text and ("|" in text or "\t" in text):
        from .secret_table import secret_table_hits
        out += secret_table_hits(text)
    return out


def bounded_copy_windows(text: str, norm, wa: int, wb: int, lines: list, enabled, channel: str, path: str,
                          raw_gates: dict, taken: set) -> int | None:
    """The window [wa, wb) of the copy holds a changed line longer than reach.LONG. Rescan only the parts of it
    around each changed run (reach.COPY_MARGIN before and after, cut at whitespace) with the gates of the whole
    window. The start of its first part when no hit there changes a hit of the raw text (each one has the span of a
    raw hit): then no hit of
    the whole window can, as a hit reads at most core._WINDOW_BEFORE and 4,000 characters back and _WINDOW_AFTER on, and
    the readers that read further (reach.py) are asked first. None when the whole window must be read: a hit that is
    new or other, a reader of a record, a seed phrase, a list or a curl command in the window, a word the cleaning
    made, or no whitespace to cut at."""
    copy, starts, ends = norm.text, norm.starts, norm.ends
    n = len(copy)
    subs: list = []
    runs_all: list = []
    for a, b in lines:
        oa = ends[a - 1] if a > 0 else 0
        ob = starts[b] if b < n else len(text)
        runs = reach.changed_runs(text, copy, starts, ends, a, b)
        if a < b and starts[a] != oa:
            runs.insert(0, [a, a + 1])     # a character deleted before the first one of the line
        if a < b and ends[b - 1] != ob:
            runs.append([b - 1, b])        # or after its last one
        if not runs:
            runs = [[a, min(b, a + 1)]] if a < b else [[max(0, a - 1), a]]
        runs_all += runs
        line_wa = copy.rfind("\n", 0, max(0, a - core._WINDOW_BEFORE)) + 1 if a > core._WINDOW_BEFORE else 0
        line_wb = copy.find("\n", min(n, b + core._WINDOW_AFTER))
        line_wb = n if line_wb < 0 else line_wb
        if b - a <= reach.LONG:
            subs.append([line_wa, line_wb])
            continue
        for x, y in runs:
            p, q = x - reach.COPY_MARGIN, y + reach.COPY_MARGIN
            # within reach.SNAP of an edge of the line without whitespace, the window takes the line's own edge
            s = line_wa if p - reach.SNAP <= a else reach.start_after_space(copy, p, a)
            e = line_wb if q + reach.SNAP >= b else reach.cut_at_space(copy, q, b)
            if s is None or e is None:
                return None
            if s > a and copy[s:s + 64].lstrip(" \t")[:1] == "|":
                return None   # a window that starts with | would read its first line as a row of a table
            subs.append([s, e])
    subs.sort()
    merged: list = []
    for s, e in subs:
        if merged and s <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    if 2 * sum(e - s for s, e in merged) > wb - wa:
        return None   # the parts are most of the window
    window = copy[wa:wb]
    order = core._in_scan_order(core.rules())
    gates = copy_window_gates(text, norm, wa, wb, runs_all, order, enabled, channel, raw_gates)
    if gates is None or unbounded(order, enabled, window) or record_hits(window, channel) \
            or next(iter(checksums.bip39_spans(window)), None) or far_reaching_match(order, gates, window) \
            or far_rule_matches(order, gates, window, channel) or long_personal_match(window):
        return None
    for s, e in merged:
        for m in core._scan(copy[s:e], enabled, _copy=True, channel=channel, path=path, _gate=gates):
            if norm.span(m.start + s, m.end + s) not in taken:
                return None
    return merged[0][0]


def label_scan_near(labelled: str, lead: int, value: str, enabled, channel: str) -> list | None:
    """The hits of `label: value` (lead: the length of `label: `) as far as the label can reach: the first
    reach.LABEL_REACH characters of the value, cut at whitespace, with the gates of the whole labelled text. None
    when the label may reach further and the whole labelled text must be scanned: a label that is not plain words, a
    value whose start a label changes the reading of (a blank first line, a quote, a table row), a gate the label
    opens, a seed phrase or a list after the label, a record or table that reads otherwise with the label, and in the
    tool channel a cleaned copy that changes the value near its start or was read whole (reach.py)."""
    try:
        from .normalise import normalise
    except ImportError:   # a copy of detect.py without its sibling modules
        return None
    label = labelled[:lead - 2]
    if not reach.plain_label(label) or (not label.isascii() and value.isascii()):
        return None
    nl = value.find("\n")
    if not value[:nl if nl >= 0 else len(value)].strip() or value.lstrip(" \t")[:1] in ("|", '"', "'", "`"):
        return None
    cut = reach.cut_at_space(labelled, lead + reach.LABEL_REACH, len(labelled))
    if cut is None:
        return None
    tool = channel == "tool"
    order = core._in_scan_order(core.rules())
    last = LAST_SCAN.get()
    if last is not None and last[0] is value and last[1] is order and last[3] == ("tool" if tool else "prompt") \
            and last[4] == enabled:
        gates, copy_start = last[2], last[5]
    else:
        # not from a scan of the value: whether a rule matched it is not known, so each counts as matched (2)
        gates, copy_start = {k: 2 if v else v for k, v in gates_for(order, value, enabled, channel).items()}, None
    copy_v = value
    if tool:
        prefix = labelled[:lead]
        if normalise(prefix).text is not prefix:
            return None   # the cleaning changes the label itself
        copy_v = normalise(value).text
        if copy_v is not value and (copy_start is None or copy_start + lead < cut):
            return None   # the copy of the value changes near its start, or was read whole: its windows reach the label
    # a gate the label opens: a rule then runs over the whole value, wherever its regex matches
    words, longest = gate_words(order)
    head = core._lower(labelled[:lead + longest + 1])
    low = None
    for rule, ws in words:
        k = id(rule)
        if k not in gates or gates[k] or not any(w in head for w in ws):
            continue
        low = core._lower(labelled) if low is None else low
        if gate_ok(rule, labelled, low, {}, channel):
            return None
        cl = labelled[:lead] + copy_v
        if copy_v is not value and gate_ok(rule, cl, core._lower(cl), {}, channel) \
                and not gate_ok(rule, copy_v, core._lower(copy_v), {}, channel):
            return None
    # a seed phrase reads its context word back to the start of its line; a list runs on to its closing bracket
    if (core._SEED_CONTEXT_RE.search(labelled, 0, lead) and next(iter(checksums.bip39_spans(value)), None)) \
            or far_reaching_match(order, gates, labelled, 0, lead + 512) or unbounded(order, enabled, labelled[:cut]) \
            or label_far_match(order, gates, labelled, lead, value, channel) or long_personal_match(labelled):
        return None
    if tool:
        # a record or a table: the label must not change a hit of its readers anywhere in the value
        for lab, bare in ((labelled, value), (labelled[:lead] + copy_v, copy_v)) if copy_v is not value else \
                ((labelled, value),):
            with_label = {(a - lead, b - lead, k, t) for a, b, k, t in record_hits(lab, channel)}
            if with_label != set(record_hits(bare, channel)):
                return None
    near = labelled[:cut]
    hits = core._scan(near, enabled, channel=channel, path="", _gate=gates)
    if tool and "|" in near:
        hits = core._fields.md_key_value_hits(near, hits, lambda t: core.scan(t, enabled, channel, "", None))
    return hits


def changed_windows_scan(text: str, norm, enabled, channel: str = "prompt", path: str = "",
                          raw_gates: dict | None = None, taken: set | None = None) -> tuple:
    """The hits of the cleaned copy, scanned only around its changed lines: each changed line with the whole lines
    that hold the _WINDOW_BEFORE characters before it and the _WINDOW_AFTER characters after it, windows that touch
    merged. A line the stages left alone holds the hits the raw scan already has, and a rescan of the whole text
    doubled the time of a 70 KB tool result with one coloured line or one JWT. A window with a line longer than
    reach.LONG is read in parts around its changes (bounded_copy_windows) when `raw_gates` and `taken` are given.
    Returns (hits, start): `start` is the start in the copy of the first window when no window of a long line was
    read whole, else None."""
    copy, starts, ends = norm.text, norm.starts, norm.ends
    windows: list = []
    a = 0
    n = len(copy)
    while a <= n:
        b = copy.find("\n", a)
        b = n if b < 0 else b
        # the original range of this line, from after the previous line break to this one: deleted characters at
        # its edges and a line that only deleted characters held count as a change (Gate A, round 2)
        oa = ends[a - 1] if a > 0 else 0
        ob = starts[b] if b < n else len(text)
        if ob - oa != b - a or text[oa:ob] != copy[a:b]:
            wa = copy.rfind("\n", 0, max(0, a - core._WINDOW_BEFORE)) + 1 if a > core._WINDOW_BEFORE else 0
            wb = copy.find("\n", min(n, b + core._WINDOW_AFTER))
            wb = n if wb < 0 else wb
            if windows and wa <= windows[-1][1] + 1:
                windows[-1][1] = max(windows[-1][1], wb)
                windows[-1][2].append((a, b))
            else:
                windows.append([wa, wb, [(a, b)]])
        a = b + 1
    out = []
    first = n
    whole = False
    for wa, wb, lines in windows:
        part = None
        long_line = any(b - a > reach.LONG for a, b in lines)
        if long_line and raw_gates is not None and taken is not None:
            part = bounded_copy_windows(text, norm, wa, wb, lines, enabled, channel, path, raw_gates, taken)
        if part is not None:
            first = min(first, part)
            continue
        whole = whole or long_line
        first = min(first, wa)
        out += [core.Match(m.kind, m.type, m.value, m.start + wa, m.end + wa)
                for m in core._scan(copy[wa:wb], enabled, _copy=True, channel=channel, path=path)]
    return out, None if whole else first
