"""The corrections to the vendored betterleaks rules (rules/betterleaks.json), applied when the rules load.

scripts/sync_betterleaks.py overwrites rules/betterleaks.json, so the corrections live here. Each regex or filter
correction names the upstream text it expects; rules/patched_upstream.txt keeps the digest of each corrected upstream
rule, and tests/test_registry.py goes red after a sync that changes one. Moved out of core.py (its size limit, 0.9.7).
"""
from __future__ import annotations


# Corrections to vendored betterleaks rules. scripts/sync_betterleaks.py overwrites rules/betterleaks.json, so they
# live here and apply when the rules load. Each names the upstream regex it expects ("expect"); after a re-sync that
# changes that regex, tests/test_rules_from_the_catalogs.py goes red, and the correction is checked against the new
# rule (and dropped if upstream fixed it). Found by a coverage measurement against other catalogs (0.6.20):
# - three keyword lists named only the provider, so a bare token without the provider's name was never searched;
#   the token's own prefix is now a keyword too (the regex is unchanged). The Airtable regex also used the RE2 class
#   [[:alnum:]], which Python read as a set of six characters; _re2_to_python now translates the POSIX classes
# - WakaTime's waka_ key is waka_ and a UUID (Kingfisher's rule and examples); the regex took no hyphen
BETTERLEAKS_PATCHES = {
    "resend-api-key.1": {"add_keywords": ("re_",)},
    "ionic-personal-access-token": {"add_keywords": ("ion_",)},
    "airtable-personnal-access-token": {"add_keywords": ("pat",)},
    "microsoft-teams-webhook": {
        "expect": r"https://[a-z0-9]+\.webhook\.office\.com/"
                  r"webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@"
                  r"[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/"
                  r"IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
        # the ids also in capital hex (the vendored [a-z0-9] stays, so no old hit is lost), a word boundary on both
        # sides, and a further path part after the last id stays in the hit (codex Gate A of 0.6.39)
        "regex": r"https(?:(?<![A-Za-z0-9]https)|(?<=\\[nrt]https))://[a-z0-9]+\.webhook\.office\.com/"
                 r"webhookb2/[0-9a-zA-F]{8}-(?:[0-9a-zA-F]{4}-){3}[0-9a-zA-F]{12}@"
                 r"[0-9a-zA-F]{8}-(?:[0-9a-zA-F]{4}-){3}[0-9a-zA-F]{12}/"
                 r"IncomingWebhook/[0-9a-zA-F]{32}/[0-9a-zA-F]{8}-(?:[0-9a-zA-F]{4}-){3}[0-9a-zA-F]{12}"
                 r"(?:/[0-9A-Za-z_-]{20,})?(?![0-9A-Za-z_-])",
        "reason": "the ids were capturing groups, so a hit masked 17 of 204 characters; the whole URL is the "
                  "credential (0.6.39, #11)"},
    "wakatime-api-key.2": {
        "expect": r"""(?i)\b(waka_[a-z0-9]{36,64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)""",
        "regex": r"""(?i)\b(waka_(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z0-9]{36,64}))"""
                 r"""(?:\\?['"\x60]|[\s;]|\\[nr]|$)"""},
    # its own terminator refused "." and ":", so "the client secret is <value>." was no hit at all (13 catalog
    # examples, 0.7.13); a full stop or colon before a space or the end of the text now ends the value, as for the
    # 336 rules with the gitleaks terminator (_SENTENCE_END)
    "azure-ad-client-secret": {
        "expect": "(?:^|[\\\\'\"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})"
                  "(?:$|[\\\\'\"\\x60\\s<),])",
        "regex": "(?:^|[\\\\'\"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})"
                 "(?:$|[\\\\'\"\\x60\\s<),]|[.:](?=\\s|$))"},
    # v1.10.0 drops a finding whose label contains "client" (a Box client id or secret, not an access token), in a
    # program with let bindings and slices that rule_filter does not read, so the rule was left out. The same test in
    # the subset: the label part of the match ("box_client_id = …"); a word joined before "box" (CLIENT_BOX_ID) is not
    # seen, as before v1.10.0 (0.9.7)
    "box-api-access-token": {
        "expect_filter": ("let prefix = filter.findMatch(finding[\"fragment_raw\"]"
                          "[finding[\"match_line_start_idx\"]:finding[\"match_start_idx\"]], "
                          "\"[\\\\w.-]*$\");\n"
                          "let identifier = prefix + filter.findMatch(finding[\"match\"], \"^[\\\\w .-]+\");\n"
                          "lower(identifier) contains \"client\" || entropy(finding[\"secret\"]) < 3.5"
                          " || filter.tokenRatio(finding[\"secret\"]) >= 2.5\n\n"),
        "filter": 'entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5'
                  ' || matchesAny(finding["match"], ["(?i)^[\\\\w .-]*client"])\n',
        "reason": "the upstream filter is a program; the same label test in the subset rule_filter reads (0.9.7)"},
    # v1.10.0 adds nuget-api-key; the own rule of the same id (own_rules.py) starts with its literal and refuses a word
    # after oy2, so the vendored copy is left out. Of 20,000 random keys in the upstream shape the own rule found all
    # but 6, each without a digit (the own rule wants one); NuGet issues the key in lower case (0.9.7)
    "nuget-api-key": {"skip": "the own rule nuget-api-key covers it (0.9.7)"},
}


# The terminator that 336 vendored rules end with takes a quote, a space, ";" or a line end, which is right for an
# assignment and wrong for a sentence: "the key is <token>." or "(<token>)" lost the whole hit. The terminator now
# also takes sentence punctuation before a space or the end of the text; a dot before a letter (a host name) is still
# no end, nor is punctuation next to a quote: `"<value>", "next"` and `<key>: "…"` are code, not a sentence (two
# false alarms in the FP bank). The terminator is outside the secret group, so no value changes (0.7.11)
_VENDORED_END = r"""(?:\\?['"\x60]|[\s;]|\\[nr]|$)"""
_SENTENCE_END = r"""(?:\\?['"\x60]|[\s;]|\\[nr]|$|(?<!['"\x60])[.,:!?)](?=\s|$)(?!\s*['"\x60]))"""


def _patched(r: dict):
    """The rule with its BETTERLEAKS_PATCHES entry applied, then the sentence terminator, or None for a rule that is
    left out. A regex or filter correction applies only to the text it expects."""
    patch = BETTERLEAKS_PATCHES.get(r.get("id"))
    if patch and patch.get("skip"):
        return None
    r = dict(r)
    if patch and patch.get("filter") and r.get("filter") == patch["expect_filter"]:
        r["filter"] = patch["filter"]
    if patch and patch.get("add_keywords"):
        r["keywords"] = list(r.get("keywords") or []) + [k for k in patch["add_keywords"]
                                                        if k not in (r.get("keywords") or [])]
    if patch and patch.get("regex") and r.get("regex") == patch["expect"]:
        r["regex"] = patch["regex"]
    if r.get("regex", "").endswith(_VENDORED_END):
        r["regex"] = r["regex"][:-len(_VENDORED_END)] + _SENTENCE_END
    return r
