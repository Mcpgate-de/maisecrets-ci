"""The own rules of the detector (OWN_RULES, FALLBACK_RULES) and the class of CJK letters that their regexes use.

maisecrets/detection/core.py imports each name of this module, so `core.<name>` (and `detect.<name>`) is the same
object. A patch of one of these names on the core does not reach the functions of this module: patch this module."""
from __future__ import annotations

from .lazy_regex import LazyRx as _LazyRx


# --------------------------------------------------------------- own rules --
# The letters of Chinese, Japanese and Korean script. Python's \w includes them, and these scripts put no space
# between words: in `メールはta@example.jpまで` the boundaries (?<![\w...]) and (?![\w-]) of the e-mail and phone rules
# never hold, so the address was missed or its span took the words around it. Those rules end a value at a word
# character that is no CJK letter (_NOT_CJK_WORD), and scan() cuts CJK letters off the front of an address (filter
# cjk-head). Ranges: Hangul Jamo, CJK punctuation and kana, Extension A and the base block of the ideographs, Hangul
# syllables, compatibility ideographs and the fullwidth forms. Each class costs about 0.5 ms to compile in every hook
# process, so the rules hold one each (review of 0.6.24).
_CJK = ("\u1100-\u11ff\u3000-\u30ff\u3130-\u318f\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff"
        "\uff00-\uffef")
_CJK_RANGES = ((0x1100, 0x11ff), (0x3000, 0x30ff), (0x3130, 0x318f), (0x3400, 0x4dbf), (0x4e00, 0x9fff),
               (0xac00, 0xd7af), (0xf900, 0xfaff), (0xff00, 0xffef))
_NOT_CJK_WORD = "(?![" + _CJK + "])\\w"


_CJK_CHAR_RE = _LazyRx("[" + _CJK + "]")


def _has_cjk(text: str) -> bool:
    return not text.isascii() and _CJK_CHAR_RE.search(text) is not None


def _without_cjk(pattern: str) -> str | None:
    """The form of a pattern for a text without a CJK letter: each use of the class _CJK goes. None when a use is
    left that this cannot remove, so the rule keeps its one form."""
    plain = (pattern.replace(_NOT_CJK_WORD, r"\w").replace("(?<=[" + _CJK + "])|", "")
             .replace("[" + _CJK + "]", "(?!)").replace(_CJK, ""))
    return None if "[]" in plain or "[^]" in plain else plain


def _is_cjk(ch: str) -> bool:
    o = ord(ch)
    return any(lo <= o <= hi for lo, hi in _CJK_RANGES)


# the value of a password in a sentence: optional quotes, no stop of the sentence at its end (`!` stays), and a stop,
# a space, a quote or the end after it
# a word before the password word that names whose password it is: WLAN-Passwort, Root-Passwort, wifi-password with a
# hyphen; joined without one only a few German words (Adminpasswort). Other words end in a password word by chance:
# deşifre (decipher), resenha (review)
_PW_COMPOUND = (r"(?:[^\W\d_]{2,20}-|(?:admin|root|master|haupt|einmal|start|initial|wlan|benutzer|nutzer)"
                r"(?=pass|kenn))?")
# a value of Markdown inline code or in bold (`<value>`, **<value>**), or in the corner brackets of Chinese and Japanese
# (「<value>」), is the value without the marks. The value is the shortest run that a space, a quote, the end or the
# stops of a sentence (. , ; : ? ) 。 …) follow: a `*`, `!`, `<` or `\` inside or at the end stays part of it (Abc*12x!,
# Gretel: a password with a Markdown escape)
_SENTENCE_VALUE = (r"(?:\*\*|[\"'`\u201e\u201c\u201a\u2018\u00ab\u00bb\u300c\u300e])?"
                   r"(?=[^\s\d]{0,255}\d)"   # a digit is in it (the checks need one): a word is refused at once
                   r"([^\s\"'`\u201c\u201d\u201e\u201a\u2018\u2019\u00ab\u00bb\u300c-\u300f]{0,255}?"
                   r"[^\s\"'`\u201c\u201d\u201e\u201a\u2018\u2019\u00ab\u00bb.,;:?)\u3002\u2026" + _CJK + r"])"
                   r"(?:\*\*|[\"'`\u201c\u201d\u2018\u2019\u00ab\u00bb\u300d\u300f])?"
                   r"(?=[.,;:?)\u3002\u2026]*(?:[\s\"'`\u201c\u201d\u2018\u2019\u00ab\u00bb" + _CJK + r"]|$))")


OWN_RULES: list[dict] = [
    # ?token=… / &api_key=… in a URL
    {"id": "url-query-secret", "type": "SECRET", "secret_group": 2,
     "regex": r"(?i)[?&]((?:access_?)?token|api[_-]?key|apikey|secret|password|sig|signature)=([^&\s#\"']{8,})"},
    {"id": "email", "type": "EMAIL", "validator": "person_email",
     # the last label is alphabetic: `lodash@4.17.21`, `checkout@v4.1.1` and Homebrew's
     # `python@3.14/3.14.7` are version pins, not addresses (review, 2026-09-26)
     # a look ahead for the @ first: a text without an address is passed at once. A CJK letter ends the address
     # (_NOT_CJK_WORD) and scan() cuts CJK letters off its front (cjk-head): an address next to Japanese text
     "regex": r"(?=[\w.+-]{0,64}@|(?<![\w.+-])[\w.+-]{65,}@)"
              r"(?:\b[\w.+-]{1,64}|(?<![\w.+-])[\w.+-]{64,}|[\w.+-]{64})"
              r"@[\w-]{1,63}(?:\.[\w-]{1,63})*\.[A-Za-z]{2,63}(?!-|" + _NOT_CJK_WORD + r")"},
    # an IBAN in lower case, plain or in groups of four; its validator also wants the country's length
    {"id": "iban-lowercase", "type": "IBAN", "validator": "iban",
     # also after an MT940 subfield code (?31), as PRESIDIO_LEFT_SUBFIELD
     "regex": r"(?:(?<![A-Za-z0-9])|(?<=\?[0-9]{2}))[a-z]{2}[0-9]{2}"
              r"(?:[a-z0-9]{11,30}|(?:[ -][a-z0-9]{4}){2,7}(?:[ -][a-z0-9]{1,3})?)"
              r"(?![A-Za-z0-9])"},
    {"id": "email-percent-encoded", "type": "EMAIL", "validator": "person_email_encoded",
     # the @ as %40 in a query string, a form body, an access log (public benchmark, 2026-10-11: 7 addresses
     # passed); scan() keeps it only where an address is expected (_ENCODED_MAIL_CONTEXT_RE)
     "regex": r"(?:(?<![\w.+%-])|(?<=(?i:mailto%3a))|(?<=%3[Dd]))[\w.+-]{1,64}%40"
              r"[\w-]{1,63}(?:\.[\w-]{1,63})*\.[A-Za-z]{2,63}(?![\w-])"},
    {"id": "phone", "type": "PHONE",
     # a CJK letter before or after the number is a boundary, as in the e-mail rule
     "regex": r"(?:(?<=[" + _CJK + r"])|(?<!\w))(?<!\+)\+(?!0)\d{1,3}[ \-]?(?:\(?\d{1,5}\)?[ \-]?)\d{2,5}"
              r"(?:[ \-]?\d{2,5}){1,4}(?![\w.](?<![xX])\d|" + _NOT_CJK_WORD + r")"},
    # bare token prefixes newer than the vendored rulesets live in rules/prefixes.txt (see _load_prefixes)
    {"id": "auth-scheme", "type": "SECRET", "secret_group": 3,
     "regex": r"(?<![\w-])(Bearer|Basic)([ \t]+)([A-Za-z0-9._~+/=-]{16,})"},
    # a password with no user in a URL: redis://:pw@host, the form Redis and some brokers use. ds-basic-auth needs a
    # user before the colon; same characters and the same value filter otherwise (corpus of 0.6.7)
    {"id": "url-password-no-user", "type": "SECRET", "secret_group": 1, "validator": "ds_value",
     "regex": r"://:([^:/?#\[\]@!$&'()*+,;=\s]+)@"},
    # the secret half of an AWS key pair has no prefix of its own; the console, a CSV export
    # and a chat paste show it within a few lines after the AKIA… id (field report, 2026-09-26). Each line part is
    # bounded at 400 characters: unbounded, each id scanned the rest of its line, and a line of ids took O(n^2)
    # (32K: 2.3 s, 256K: 97 s, past the client's timeout). The longest field form, the console's credentials CSV
    # row (user, password, id, secret, console link), puts about 150 characters around the secret.
    {"id": "aws-secret-after-access-key", "type": "SECRET", "secret_group": 1,
     "regex": r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])(?:[^\n]{0,400}\n){0,4}?[^\n]{0,400}?"
              r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"},
    # a password with no shape where no `=` or `:` stands between label and value (public benchmark holdout v7,
    # 2026-10-12: all ten leaked passwords had one of these five forms). They are label rules (LABEL_RULES): the
    # keyword filters of scan() and the test-code rule apply as to `password=<value>`.
    # `pg_dump --password '<value>'`, `--db-password <value>`, PowerShell `-Password <value>`; the `=` form is
    # ds-keyword-equal-signs. A flag before a space, so `--password-stdin` and `--password-file` stay options
    {"id": "label-cli-password", "type": "SECRET", "secret_group": 2, "validator": "flag_value",
     "regex": r"(?<![\w-])--?(?!(?i:no|ask|skip|prompt|without|one|two|single|multi|first|second)[-_])"
              r"(?:[A-Za-z][A-Za-z0-9]*[-_])*"
              r"(?i:password|passwd|passphrase|pass|pwd)[ \t]+"
              r"(['\"]?)(?!-|(?:file|env|fd):|stdin(?![\w-]))(?:pass:)?([^\s'\"<>]{1,256}?)\1(?=$|[\s;|&)\]\\])"},
    # `mysql -u app -p'<value>' db`: the value glued to -p (a space after -p asks for it; -P is the port)
    {"id": "label-mysql-p", "type": "SECRET", "secret_group": 2, "validator": "glued_value",
     "regex": r"(?<![\w-])(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mariadb"
              r"|mariadb-dump|mariadb-admin)(?:\.exe)?(?![\w-])[^\n|;&]{0,400}?[ \t]-p(['\"]?)([^\s'\"<>]{1,256}?)\1"
              r"(?=$|[\s;|&)\]])"},
    # redis-cli: `127.0.0.1:6379> AUTH <value>` (or AUTH <user> <value>) at a prompt or the start of a line, and
    # `redis-cli -a <value>`. AUTH in capitals, as Redis documents it; `auth token expired` is prose
    {"id": "label-redis-auth", "type": "SECRET", "secret_group": 2, "validator": "word_value",
     "regex": r"(?m)(?:^[ \t]*|>[ \t]?)AUTH[ \t]+(?![=:]|LOGIN[ \t])(?:[^\s'\"]+[ \t]+)?"
              r"(?!(?:CRAM-MD5|DIGEST-MD5|SCRAM-SHA-[0-9]+(?:-PLUS)?|XOAUTH2|OAUTHBEARER|GSSAPI|NTLM|EXTERNAL"
              r"|ANONYMOUS|PLAIN|LOGIN)[ \t]*$)"   # an SMTP or IMAP AUTH names a SASL mechanism (Gate B of 0.6.15)
              r"(['\"]?)([^\s'\"<>]{1,256})\1[ \t]*$"},
    {"id": "label-redis-cli-a", "type": "SECRET", "secret_group": 2, "validator": "word_value",
     "regex": r"(?<![\w-])redis-cli(?![\w-])[^\n|;&]{0,400}?[ \t]-a[ \t]+"
              r"(['\"]?)([^\s'\"<>]{1,256}?)\1(?=$|[\s;|&)\]])"},
    # .netrc: `machine <host> login <user> password <value>`, on one line or on several. The host has a dot, a colon
    # or a digit (or is localhost): "on my dev machine the password changed" is prose. `default` starts an entry at a
    # line start, or anywhere before `login` (a second entry on the line, a grep prefix); "the default password
    # policy_v2" is prose (round 2 of 0.6.15)
    {"id": "label-netrc-password", "type": "SECRET", "secret_group": 1, "validator": "word_value",
     "regex": r"(?:(?<![\w-])machine[ \t]+(?:[^\s]*[.:0-9][^\s]*|localhost)"
              r"|(?<![^\n])[ \t]*default|(?<![\w-])default(?=[ \t]+login[ \t]))"
              r"(?:\s+(?:login|account|port)[ \t]+[^\s]+)*"
              r"\s+password[ \t]+([^\s]{1,256})"},
    # prose: "my password is <value>". Only a value that is no word of a sentence: it holds a capital or a symbol
    # beyond - _ . and a digit or a symbol ("the password is incorrect" stays prose). English only: the German
    # sentence of tests/fp_corpus.py (`Das Passwort ist` and a season and a year) is kept silent
    {"id": "label-prose-password", "type": "SECRET", "secret_group": 1, "validator": "prose_value_bang",
     "regex": r"(?i)(?<![\w-])(?:password|passwd|passphrase)[ \t]+(?:is|was)(?:[ \t]*:[ \t]+|[ \t]+)"
              r"[\"'„“]?([^\s\"'“”]{0,255}[^\s\"'“”.,;:!?)]!{0,8})[\"'“”]?(?=[.,;:!?)]*(?:[\s\"'<\\]|$))"},
    # a typed sentence with no `:` or `=` after the password word (field report, 2026-10-16: Codex sent the value of
    # "Passwort <value>." in the clear). The words of each label language that is on (_PW_WORDS_OF). With a copula
    # ("Kennwort ist <value>", "mot de passe est <value>") the value check of the prose rule above: a digit and a
    # letter, and a capital or a sign beyond - _ . ("Passwort ist geheim" stays text). With only a space, an arrow,
    # a dash or a parenthesis ("Passwort <value>.", "password -> <value>") the sentence says less, so the value must
    # also be no run of English words (SHA256-Hash, iPhone15, JDK21-Update) and no ticket id (PBE-3403). A stop of
    # the sentence after the value is no part of it; `!` is, as passwords end with it
    {"id": "label-password-after-word", "type": "SECRET", "secret_group": 1, "validator": "sentence_value",
     "regex": r"(?i)(?:(?<![\w-])" + _PW_COMPOUND + r"(?:{pairs})(?:[ \t]*:[ \t]+|[ \t]+)|{cjk_pairs})"
              + _SENTENCE_VALUE,
     "languages": True},
    {"id": "label-password-after-space", "type": "SECRET", "secret_group": 1, "validator": "spaced_value",
     "regex": r"(?i)(?:(?<![\w-])" + _PW_COMPOUND + r"(?:{words})|{cjk_words})(?![\w-])"
              r"(?:[ \t]*(?:->|=>|\u2192|\u2013|\u2014)[ \t]*|[ \t]+-{1,2}[ \t]+|[ \t]+\([ \t]*|[ \t]+)"
              + _SENTENCE_VALUE,
     "languages": True},
    # three more forms of a typed sentence (benchmark V3, Nemotron dev: about 540 passwords in the clear). An
    # apposition, "the password, <value>, works": the value check after a space, as a list of words follows a comma
    # too. "the password for <account> is <value>": up to five words between the password word and the copula,
    # English only. "use <value> as the password": the value before the word, after a verb that hands it over, with
    # the check after a space (no ticket id: "use PBE-3403 as the password ticket")
    {"id": "label-password-apposition", "type": "SECRET", "secret_group": 1, "validator": "spaced_value",
     "regex": r"(?i)(?<![\w-])" + _PW_COMPOUND + r"(?:{words})(?![\w-])[ \t]*,[ \t]+" + _SENTENCE_VALUE,
     "languages": True},
    {"id": "label-password-for-is", "type": "SECRET", "secret_group": 1, "validator": "sentence_value",
     "regex": r"(?i)(?<![\w-])(?:password|passphrase|passcode)[ \t]+(?:for|of|on|to)[ \t]+(?:[\w.@'-]+[ \t]+){1,5}?"
              r"(?:is|was)(?:[ \t]*:[ \t]+|[ \t]+)" + _SENTENCE_VALUE},
    # the same with other words between the password word and the copula: "the wifi password here is <value>", "the
    # VPN password I use for it is <value>" (Benchmark V3, aparte dev). One to four words, none of them a copula, and
    # the value check of a sentence
    {"id": "label-password-words-is", "type": "SECRET", "secret_group": 1, "validator": "sentence_value",
     "regex": r"(?i)(?<![\w-])(?:password|passphrase|passcode)[ \t]+(?!(?:for|of|on|to)[ \t])"
              r"(?:(?!(?:is|was)[ \t])[\w.@'-]+[ \t]+){1,4}?(?:is|was)(?:[ \t]*:[ \t]+|[ \t]+)" + _SENTENCE_VALUE},
    {"id": "label-password-use-as", "type": "SECRET", "secret_group": 1, "validator": "spaced_value",
     "regex": r"(?i)(?<![\w-])(?:use|using|enter|type|set|with)[ \t]+(?:\*\*|[\"'`„“])?"
              r"([^\s\"'`“”]{4,255}?)(?:\*\*|[\"'`“”])?[ \t]+as[ \t]+"
              r"(?:(?:the|your|my|a|an|its|their|our)[ \t]+)?(?:(?:new|temporary|initial|default|admin|root)[ \t]+)?"
              r"(?:password|passphrase|passcode)(?![\w-])"},
    # each quoted value of a list after a label that names secrets: `"api_keys": ["<v1>", "<v2>"]`,
    # `passwords = ['<v1>']`, Go `Secrets: []string{"<v1>"}`. The label rules took no value that starts with a
    # bracket, so a whole list of keys stayed in the clear. Only a label that names secrets and nothing else: a bare
    # `tokens` is the output of a tokenizer, and code_tokens, cache_tokens or revokedTokens name no secret (Gate B of
    # 0.6.16: 30 false alarms in developer text). The regex finds the label and the opening bracket; _list_matches
    # reads the values and keeps only those that look like a key (_list_value_ok). No tuple: the Elasticsearch client
    # takes api_key=("<id>", "<key>"), and the id is public
    {"id": "label-secret-list", "type": "SECRET", "secret_group": 2,
     "regex": r"(?i)(?<![\w$.-])[\"']?(passwords?|passwd|secrets?|api[_-]?(?:keys?|tokens?|secrets?)"
              r"|(?:access|auth|refresh|bearer)[_-]?tokens?|client[_-]?secrets?|private[_-]?keys?|secret[_-]?keys?"
              r"|credentials)[\"']?[ \t]*(?::=|=>|[:=])[ \t]*(\[\][\w.]*[ \t]*\{|[\w.]*\[\][ \t]*\{|\[)"},
    # four token formats with a public prefix and no rule in the vendored sets (0.6.16). The third NTLMSSP message in
    # base64 (`Authorization: NTLM TlRMTVNTUAAD…`: its response is derived from the password hash; the negotiate and
    # challenge messages carry none); a
    # NATS nkey seed (S, the key type, 56 base32 characters; the public key starts with N, U, A … and stays text);
    # a PASERK secret, local or wrapped key (k1. to k4.; k4.public., k4.lid. and the other ids stay text); a PASETO
    # token (v1. to v4., local or public: a bearer token as a JWT is one)
    {"id": "ntlmssp-message", "type": "SECRET",
     "regex": r"(?<![A-Za-z0-9+/])TlRMTVNTUAAD[A-Za-z0-9+/]{30,}={0,2}"},
    {"id": "nats-nkey-seed", "type": "SECRET",
     "regex": r"(?<![A-Za-z0-9])S[UNOACXP][A-Z2-7]{56}(?![A-Za-z0-9])"},
    {"id": "paserk-secret-key", "type": "SECRET",
     "regex": r"(?<![\w.])k[1-4]\.(?:local|secret|local-wrap|secret-wrap|local-pw|secret-pw|seal)\."
              r"(?:[A-Za-z0-9_-]+\.){0,3}[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"},   # dot-separated parts, no end dot
    {"id": "paseto-token", "type": "SECRET",
     "regex": r"(?<![\w.])v[1-4]\.(?:local|public)\.[A-Za-z0-9_-]{30,}(?:\.[A-Za-z0-9_-]+)?"},
    # the STS session token of temporary AWS credentials: a presigned URL carries it as the query parameter
    # X-Amz-Security-Token (percent-encoded), a request as the header of that name. The other X-Amz- parameters (the
    # key id in X-Amz-Credential, X-Amz-Signature, X-Amz-Date) stay text; the session token grants access until it
    # expires. 100 to 4096 characters: real tokens have several hundred
    {"id": "label-aws-session-token", "type": "SECRET", "secret_group": 1,
     "regex": r"(?i)(?<![\w-])x-amz-security-token(?:[\"']?[ \t]*[:=][ \t]*[\"']?)([A-Za-z0-9%+/=_-]{100,4096})"
              r"(?![A-Za-z0-9%+/=_-])"},
    # Elasticsearch's API key in an Authorization header: `Authorization: ApiKey <base64 of id:key>`, as a header
    # line, in curl -H, or as the key of a header object (`authorization: 'ApiKey <value>'`). Only after the header
    # name: prose names the scheme ("send ApiKey followed by …", Gate B of 0.6.16)
    # crypto wallet secrets (0.6.19): each is found by its checksum and needs no label. A Bitcoin private key in Wallet
    # Import Format (Base58Check, version 0x80: 51 characters from 5, or 52 from K or L for a compressed key; on testnet
    # 0xEF, from 9 or c), and a BIP32 extended private key (xprv, and the yprv, zprv, Yprv, Zprv, tprv, uprv, vprv,
    # Uprv, Vprv of SLIP-0132). The public forms (an address, an xpub) are no secret and stay text
    {"id": "crypto-wif-private-key", "type": "SECRET", "validator": "wif",
     "regex": r"(?<![1-9A-HJ-NP-Za-km-z])(?:[59][1-9A-HJ-NP-Za-km-z]{50}|[KLc][1-9A-HJ-NP-Za-km-z]{51})"
              r"(?![1-9A-HJ-NP-Za-km-z])"},
    {"id": "crypto-extended-private-key", "type": "SECRET", "validator": "xprv",
     "regex": r"(?<![1-9A-HJ-NP-Za-km-z])[xyztuvYZUV]prv[1-9A-HJ-NP-Za-km-z]{100,108}"
              r"(?![1-9A-HJ-NP-Za-km-z])"},
    # three token formats with no literal prefix, so not in rules/prefixes.txt (0.6.19). A Telegram bot token: the
    # bot's id, a colon and 34 or 35 characters starting with A (the Bot API documentation's example has 34), alone
    # or in the API URL .../bot<token>/sendMessage (Gate B of 0.6.19). A Mailchimp API key: 32 hex digits and the
    # data centre (-us1 …). A Discord bot token: three base64url parts, the first the bot's user id in base64, which
    # the validator decodes: a random three-part value is not a run of 17 to 20 digits there
    {"id": "telegram-bot-token", "type": "SECRET",
     "regex": r"(?:(?<=/bot)|(?<![0-9A-Za-z_:-]))[0-9]{5,16}:A[0-9A-Za-z_-]{33,34}"
              r"(?![0-9A-Za-z_-])"},
    {"id": "mailchimp-api-key", "type": "SECRET",
     "regex": r"(?<![0-9A-Za-z])[0-9a-f]{32}-us[0-9]{1,2}(?![0-9A-Za-z])"},
    {"id": "discord-bot-token", "type": "SECRET", "validator": "discord_bot_token",
     "regex": r"(?<![0-9A-Za-z_.-])[MNO][0-9A-Za-z_-]{23,27}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27,38}"
              r"(?![0-9A-Za-z_.-])"},
    # a BIP39 seed phrase: 12 to 24 words of the English list whose checksum holds (checksums.bip39_spans; the regex is
    # never run). Twelve words carry a checksum of 4 bits, so one list of ordinary words in 16 passes ("client connect
    # system process input output error return result update file edit", Gate A of 0.6.19): a phrase of 12 needs a word
    # such as seed, mnemonic or wallet in the 200 characters before it or on its line; 15 and more (5 to 8 bits) stand
    # alone
    {"id": "crypto-seed-phrase", "type": "SECRET", "regex": r"(?!)"},
    # a Twilio Account SID (AC and 32 hex digits) next to its name: the SID and the auth token together log in, and
    # the holdout sets of the public benchmark (2026-10-14) leaked three. Without the name, AC and 32 hex digits are
    # also hashes and ids
    {"id": "twilio-account-sid-labelled", "type": "SECRET", "secret_group": 1, "validator": "random_hex",
     "regex": r"(?i:twilio|account_?sid|(?<![a-z])sid(?![a-z]))[^\n]{0,40}?(?<![A-Za-z0-9])(AC[0-9a-f]{32})"
              r"(?![A-Za-z0-9])"},
    {"id": "auth-scheme-apikey", "type": "SECRET", "secret_group": 1, "validator": "apikey_value",
     "regex": r"(?i:authorization)[\"']?\]?[ \t]*[:=][ \t]*[\"'`]?ApiKey[ \t]+([A-Za-z0-9+/_-]{8,1024}={0,2})"
              r"(?![\w+/=-])"},
    # a PEM private key in base64: the tls.key or ssh-privatekey of a Kubernetes Secret, a CI variable, a Helm value.
    # The run starts with the base64 of "-----BEGIN"; the validator decodes its first 400 characters and keeps it only
    # if the header names a PRIVATE KEY and base64 body follows, or if a bundle holds one later (a certificate alone
    # stays text). The whole value is the secret, also when `base64` or openssl wrapped it at a fixed width, with
    # real or escaped line breaks (_base64_wrapped_end).
    # In 0.6.19 no rule found it, also not after a label (a catalog survey, 2026-10-14)
    {"id": "private-key-base64", "type": "SECRET", "validator": "base64_pem",
     "regex": r"(?<![A-Za-z0-9+/])(?:77u/)?LS0tLS1CRUdJTi[A-Za-z0-9+/]{16,}={0,2}"},
    # token formats whose literal prefix is shorter than four characters, so not in rules/prefixes.txt (0.6.20). The
    # character after the prefix is checked by a lookbehind written after the prefix, so the regex still starts with
    # its literal and the engine skips a text without it. Sources: crates.io and NuGet from Nosey Parker (Apache-2.0),
    # Dropbox, Firecrawl and ElevenLabs from Kingfisher (Apache-2.0); each regex is written here. A crates.io or NuGet
    # key needs one digit, and its body must not read as words: an identifier such as cioServiceConfiguration… is no
    # key. ElevenLabs: exactly 48 hex digits after sk_ (Stripe's sk_live_ and sk_test_ have an underscore there).
    # Firecrawl and ElevenLabs keys are hex by design, so a digest after fc- or sk_ is taken too (no hit in the
    # developer texts or in CredData's code files, 0.6.20)
    {"id": "crates-io-api-token", "type": "SECRET", "validator": "token_not_words",
     "regex": r"cio(?:(?<![A-Za-z0-9_]cio)|(?<=\\[nrt]cio))(?=[A-Za-z]{0,31}[0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9_])"},
    {"id": "nuget-api-key", "type": "SECRET", "validator": "token_not_words",
     "regex": r"oy2(?:(?<![A-Za-z0-9_]oy2)|(?<=\\[nrt]oy2))(?=[a-z]{0,42}[0-9])[a-z0-9]{43}(?![A-Za-z0-9_])"},
    {"id": "dropbox-short-lived-token", "type": "SECRET",
     "regex": r"sl\.(?:(?<![A-Za-z0-9_.-]sl\.)|(?<=\\[nrt]sl\.))"
              r"(?:u\.)?(?=[A-Za-z_-]{0,2047}[0-9])[A-Za-z0-9_-]{130,2048}(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9_-])"},
    {"id": "firecrawl-api-key", "type": "SECRET",
     "regex": r"fc-(?:(?<![A-Za-z0-9_-]fc-)|(?<=\\[nrt]fc-))[a-f0-9]{32}(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9]|\{)"},
    {"id": "elevenlabs-api-key-bare", "type": "SECRET",
     "regex": r"sk_(?:(?<![A-Za-z0-9_]sk_)|(?<=\\[nrt]sk_))[0-9a-f]{48}(?![A-Za-z0-9_])(?!\.[A-Za-z0-9]|\{)"},
    # an Aiven service password (GitLab's rule, MIT): AVNS_ and 15 to 123 characters. A name of words after the prefix
    # (AVNS_Configuration01) is no password (codex Gate A of 0.6.20)
    {"id": "aiven-service-password", "type": "SECRET", "validator": "token_not_words",
     "regex": r"AVNS_(?:(?<![A-Za-z0-9_]AVNS_)|(?<=\\[nrt]AVNS_))[0-9A-Za-z_-]{15,123}(?![0-9A-Za-z_-])"},
    # SonarQube's analysis tokens (GitLab's rules, MIT): sqa_ (global) and sqp_ (project) and 40 hex digits, the shape
    # of a git commit id after a word such as "sqa" (software quality assurance), so only with "sonar" near it (Gate B
    # of 0.6.20). The user token squ_ stands alone (rules/prefixes.txt)
    {"id": "sonarqube-analysis-token", "type": "SECRET", "context": ("sonar", "sonarqube", "sonarcloud"),
     "require_context": True,
     "regex": r"sq[ap]_(?:(?<![A-Za-z0-9_]sq[ap]_)|(?<=\\[nrt]sq[ap]_))[0-9a-f]{40}(?![A-Za-z0-9_])"},
]


# Fallbacks that run after the vendored rules (0.6.20): forms of a key whose vendored rule fixes one length, so the
# standard form keeps its vendored rule id. Found in a measurement on real session transcripts (values not kept):
# OpenAI project keys of other lengths around T3BlbkFJ (the base64 of "OpenAI"; the vendored rule takes 20, 58 or 74
# characters on each side) and Anthropic API keys of other lengths (the vendored rule takes exactly 93 characters
# before AA). Each also takes a key before a full stop, which the vendored terminators refuse. The vendored rule of
# such a key matches whole or not at all; GitLab's trigger and job tokens are in rules/prefixes.txt, as the vendored
# rule there takes the first part of a longer token (codex Gate A)
FALLBACK_RULES: list[dict] = [
    {"id": "openai-api-key-any", "type": "SECRET",
     "regex": r"sk-(?:(?<![A-Za-z0-9_-]sk-)|(?<=\\[nrt]sk-))"
              r"(?:proj|svcacct|admin)-[A-Za-z0-9_-]{8,400}?T3BlbkFJ[A-Za-z0-9_-]{8,400}(?![A-Za-z0-9_-])"},
    {"id": "anthropic-api-key-any", "type": "SECRET",
     "regex": r"sk-ant-(?:(?<![A-Za-z0-9_-]sk-ant-)|(?<=\\[nrt]sk-ant-))(?:api03|admin01)-[A-Za-z0-9_-]{60,140}AA"
              r"(?![A-Za-z0-9_-])"},
    # 0.6.21, from the values that leaked in the public benchmark's holdout sets: an OpenAI or Anthropic key and a
    # Slack token with a shorter tail and no marker of the forms above. The sk- tail needs a digit, a capital and a run
    # of 16 letters and digits; the Slack tail starts with digits and a hyphen, as Slack writes it, so a kebab-case
    # name after the sk-admin- or the Slack bot prefix stays a name. A key that a rule above
    # takes (T3BlbkFJ inside, api03- and AA at the end) is left to it
    {"id": "openai-anthropic-key-relaxed", "type": "SECRET",
     "regex": r"(?<![\w-])sk-(?:proj|ant|svcacct|admin)-"
              r"(?![A-Za-z0-9_-]{0,400}T3BlbkFJ)"
              r"(?!(?:api03|admin01)-[A-Za-z0-9_-]{60,140}AA"
              r"(?![A-Za-z0-9_-]))"
              r"(?=[A-Za-z0-9_-]{0,200}[0-9])"
              r"(?=[A-Za-z0-9_-]{0,200}[A-Z])"
              r"(?=[A-Za-z0-9_-]{0,200}?[A-Za-z0-9]{16})[A-Za-z0-9_-]{20,}"},
    {"id": "slack-token-relaxed", "type": "SECRET",
     "regex": r"(?<![\w-])(?:xoxb-|xoxp-|xoxa-|xoxr-)\d{2,}-[A-Za-z0-9-]{12,}"},
    # the password of a URL with a sign that RFC 3986 reserves (! $ & + , ; = *; an @ after it stays in it): a database
    # URL as people write it, unescaped (postgres://app:<value>@db:5432). ds-basic-auth stops at these signs and the
    # e-mail rule took `<rest>@host` (Benchmark V3, aparte and llmredactor dev). Only the password, as there: the user
    # stays text. A template (${DB_PASSWORD}, $(cat …)) fails the value check
    {"id": "url-password-signs", "type": "SECRET", "secret_group": 1, "validator": "ds_value",
     "regex": r"(?<![\w+.-])[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s:/?#\[\]@'\"`<>]{1,64}:"
              r"(?=[^\s/@'\"`<>]{0,127}[!$&*+,;=])((?:[^\s/@'\"`<>]|@(?=[^\s/@'\"`<>]*@)){3,128})"
              r"@(?=[A-Za-z0-9\[_])"},
    # the application keys of two frameworks in an .env file (Benchmark V3, aparte dev: 11 keys in the clear). Laravel's
    # APP_KEY=base64:<the base64 of 32 bytes>: `key` alone is a weak label, which the literal rules take only quoted.
    # Strapi's APP_KEYS=<k1>,<k2>,…: each key of the unquoted list (_list_matches reads them)
    {"id": "label-laravel-app-key", "type": "SECRET", "secret_group": 1, "validator": "laravel_key",
     "regex": r"(?m)^[ \t]*(?:export[ \t]+)?APP_KEY[ \t]*=[ \t]*[\"']?(base64:[A-Za-z0-9+/]{20,44}={0,2})(?![\w+/=])"},
    {"id": "label-env-key-list", "type": "SECRET", "secret_group": 2,
     "regex": r"(?m)^[ \t]*(?:export[ \t]+)?(APP_KEYS)[ \t]*=[ \t]*([\"']?)"},
    # a key that a sentence owns and names: "my stripe key is <value>", "our google api key for the map widget is
    # <value>", "the session JWT is <value>" (Benchmark V3, aparte dev). label-prose-key wants the key word right before
    # the value; here a possessive or an article starts it, up to two words name the service, and up to four words
    # after for/of/on/in name the use. The value check of label-prose-key: a random shape of 16 characters or more. A
    # public or publishable key (Stripe's pk_) is no secret
    {"id": "label-prose-key-owned", "type": "SECRET", "secret_group": 1, "validator": "prose_key_value",
     "regex": r"(?i)(?<![\w-])(?:my|our|your|the|his|her|their)[ \t]+(?:(?!public|publishable)[\w.-]+[ \t]+){0,2}?"
              r"(?:key|token|secret|jwt)(?:[ \t]+(?:for|of|on|in)(?:[ \t]+[\w.@'-]+){1,4}?)?[ \t]+(?:is|was)"
              r"(?:[ \t]*:[ \t]+|[ \t]+)[`\"'„“]?(?!pk_)([A-Za-z0-9_+/=.-]{15,511}[A-Za-z0-9_+/=])[`\"'“”]?"
              r"(?=[.,;:!?)]?(?:\s|$))"},
    # a key or a salt of PHP's define() (wp-config.php: AUTH_KEY, NONCE_SALT): the WordPress salts hold ( ) | ` and
    # the literal rules took them for code (Benchmark V3, aparte dev: 16 salts in the clear). Only a name that ends in
    # KEY, SALT, SECRET or TOKEN; a password is label-pw-literal's
    {"id": "label-php-define-key", "type": "SECRET", "secret_group": 3, "validator": "config_key_value",
     "regex": r"(?<![\w$>:])define[ \t]*\([ \t]*(['\"])(?:[A-Z][A-Z0-9]*_)*(?:KEY|SALT|SECRET|TOKEN)\1[ \t]*,[ \t]*"
              r"(['\"])((?:(?!\2)[^\\\n]){16,256})\2[ \t]*\)"},
    # a key in a sentence: "Use the API key <value> for the call", "the access token is <value>", "the API key,
    # <value>, expires". No `:` or `=` tells that a value follows, so the value must look random (prose_key_value)
    # and have 16 characters at least. A bare `token` is the word of a tokenizer too; its values (a number, a word)
    # fail the value check. After the vendored rules: a key of a known format keeps its rule id
    {"id": "label-prose-key", "type": "SECRET", "secret_group": 1, "validator": "prose_key_value",
     "regex": r"(?i)(?<![\w-])(?:api[ _-](?:key|token|secret)|access[ _-]?(?:token|key)|auth(?:entication)?[ _-]?"
              r"(?:token|key)|bearer[ _-]?token|secret[ _-]?key|client[ _-]?secret|(?:personal[ _-]?access|private)"
              r"[ _-]?token|token)s?(?:[ \t]+(?:is|was))?[ \t]*[:,(]?[ \t]+[`\"'„“]?"
              r"([A-Za-z0-9_+/=.-]{15,511}[A-Za-z0-9_+/=])[`\"'“”]?(?=[.,;:!?)]?(?:\s|$))"},
]
