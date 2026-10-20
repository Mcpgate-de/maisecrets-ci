"""Personal data that a label or a fixed form names: a name after `name:`, a birth date after `dob:`, an ID number
after `passport no:`, a street address with its postcode, the user in `user:pass@host` and in a home path, the cells
of a CSV column such as `address` or `phone`.

Each rule needs its label or its form. A name or an address without one stays text: maisecrets has no model, and
"Emma Johansson" alone looks like any two capitalised words (README, "Known gaps").

The rules come from the values that leaked in the public benchmark's holdout sets v2 to v7 (2026-10-14, 765 values).
Rules p13 (a name before an e-mail address) and p14 (the columns of a CSV header) follow the rule families of the
Cloakroom benchmark (https://github.com/shanjeevrajendran/cloakroom, Apache-2.0); the code here is written anew.

Channel: these rules run on tool results and files only. A typed prompt is blocked on a hit, and a person who types
a name or an address means to send it; the prompt keeps the stricter rules it had (docs/THREAT-MODEL.md).
Region: an address form of a country runs when that country's region is active; the phone and label rules are
generic.

Every check is bounded: each regex has bounded repeats, and a CSV header is read for at most _CSV_ROWS rows.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------------------------------- types --
NAME, ADDRESS, BIRTH_DATE, ID_NUMBER, USERNAME, PHONE = "NAME", "ADDRESS", "BIRTH_DATE", "ID_NUMBER", "USERNAME", \
    "PHONE"

# documentation names: a value that is one of them is an example, not a person
PLACEHOLDER_NAMES = frozenset({"jane doe", "john doe", "max mustermann", "erika mustermann", "john smith",
                               "jane smith", "joe bloggs", "john q. public", "richard roe", "jane roe",
                               "max muster", "maria musterfrau", "otto normalverbraucher", "alice", "bob"})

# ------------------------------------------------------------------------------- phone with one-digit groups --
# the phone rule of detect.py wants groups of two digits or more after the country code: "+1 4 15 22 3344" and
# "+44 7 911 123456" passed (holdout v6). Same bounds otherwise: 8 to 15 digits, not a run of two digits
_PHONE_GROUPS_RE = re.compile(r"(?<![\w+])\+(?!0)\d{1,3}(?:[ \-]\(?\d{1,5}\)?){2,10}(?![\w.]\d|\w)")

# a US number in its national form, (415) 555-0123, after a phone word; the 555 exchange is fictional
_US_PHONE_RE = re.compile(r"(?<![\w(])\([2-9]\d{2}\)[ ]?[2-9]\d{2}[-. ]\d{4}(?!\d)")   # NANP: no 0 or 1 first
_PHONE_WORD_RE = re.compile(r"(?i)phone|(?<![a-z])(?:telefon\w*|tel|cell|mobile?|handy|fax|contact|kontakt|call"
                            r"|reach|whatsapp|sms)(?![a-z])")

# ------------------------------------------------------------------------------------ birth date after a label --
_DATE = (r"(?:\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{1,2}\.?\s+[A-Za-zäéû]{3,9}\.?\s+\d{4}"
         r"|[A-Za-z]{3,9}\.?\s+\d{1,2},\s*\d{4})")
# the parameters of a vCard property between its name and the colon: ADR;TYPE=home:, FN;CHARSET=UTF-8:,
# BDAY;VALUE=date:, and the bare type of vCard 2.1 (TEL;CELL:). With them, the property is the same field as without.
# A colon must follow: /api/users/bday;from=2020-01-01 is a path, and its date is no birth date (review of 0.6.25)
_VCARD_PARAMS = r"(?:(?:;[A-Za-z][\w-]{0,20}(?:=(?:\"[^\"\n]{0,80}\"|[^:;\"\n]{0,60}))?){1,8}(?=:))?"
# "born" alone is left out: "born 23 June 1912" is history in a text about a public person (holdout v6 negative)
_BIRTH_RE = re.compile(r"(?i)(?:\bd\.?o\.?b\b|date[ _-]?of[ _-]?birth|birth[ _-]?date|\bborn on"
                       r"|\bbday\b" + _VCARD_PARAMS
                       + r"|\bgeb(?:\.|oren am|urtsdatum)"
                       r"|n[ée]\(?e?\)? le|date de naissance|fecha de nacimiento|\bnac[ií](?:d[oa])? el"
                       r"|data de nascimento|data di nascita|\bnato il)[\"'\]]?"
                       r"\s{0,3}(?:(?:is|was|as)\s{1,3})?[:=]?\s{0,3}[\"'(]?\s{0,3}"
                       r"(" + _DATE + r"|(?:19|20)\d{6})(?!\d)")   # and YYYYMMDD after the label (Gretel, 2026-10-19)

# --------------------------------------------------------------------------------- ID number after a label --
# the labels of health, tax and national numbers: the number of a health plan's beneficiary, a medical record, a
# national ID card, a tax ID and a social security number (Nemotron-PII writes them in its forms and notes, 2026-10-16)
# "beneficiary" and "social security" alone name a payee and a benefit (Beneficiary: VENDOR 00042)
_HEALTH_ID_LABELS = (r"|health[ _-]?plan[ _-]?beneficiary(?:[ _-]?(?:number|no\.?|id|#))?"
                     r"|beneficiary[ _-]?(?:number|no\.?|id|#)"
                     r"|medical[ _-]?record(?:[ _-]?(?:number|no\.?|#))?"
                     r"|national[ _-]?id(?:entification|entity)?(?:[ _-]?(?:number|no\.?|card))?"
                     r"|tax(?:payer)?[ _-]?id(?:entification)?(?:[ _-]?(?:number|no\.?))?|tin"
                     r"|social[ _-]?security[ _-]?(?:number|no\.?|#)")
# passport and driving licence in the label languages of the EU (Gretel writes them in its forms, 2026-10-16), and the
# English "driving licence": de, fr, es, it, nl, pt, sv, pl. "pass" alone is a password, "patente" alone a patent
_TRAVEL_ID_LABELS = (r"|driving[ _-]?licen[cs]e(?:[ _-]?(?:no|number))?"
                     r"|reisepass(?:[ _-]?(?:nummer|nr\.?))?|pass(?:nummer|[ _-]nr\.?)"
                     r"|f(?:ü|ue)hrerschein(?:[ _-]?(?:nummer|nr\.?))?"
                     r"|(?:num[ée]ro (?:de |du )?)?(?:passeport|permis de conduire)"
                     r"|(?:n[úu]mero (?:de |del |do )?)?(?:pasaporte|passaporte"
                     r"|(?:carn[ée]t|permiso|licencia) de conducir"
                     r"|carta de condu[çc][ãa]o|carteira de (?:motorista|habilita[çc][ãa]o))"
                     r"|(?:numero (?:di |del |della )?)?passaporto|numero (?:di |della )?patente|patente di guida"
                     r"|paspoort(?:nummer)?|rijbewijs(?:nummer)?|k[öo]rkort(?:snummer)?"
                     r"|(?:numer )?paszportu?|(?:numer )?praw[oa] jazdy")
_ID_RE = re.compile(r"(?i)(?<![a-z])(?:mrn|member[ -]?id|passport(?:[ _-]?(?:no|number))?|driver'?s? licen[cs]e"
                    r"(?:[ _-]?(?:no|number))?|dl[ _-]?(?:no|number|#)|(?-i:DL)(?=\s{0,3}[:#])|sin|tfn|nir|tax[ _-]?id"
                    r"|insurance (?:member )?id"
                    r"|account[ _-]?(?:number|no\.?)|(?:certificate[ _-]?)?licen[cs]e[ _-]?(?:number|no\.?)"
                    r"|patient[ -]?id|id on file" + _HEALTH_ID_LABELS
                    + _TRAVEL_ID_LABELS + r")(?![a-z])[\"']?"
                    r"(?:\s{0,3}(?:on file|is|of|number|no\.?|#|n\.?[º°o]\.?|nr\.?|num[ée]ro|n[úu]mero|numero"
                    r"|nummer|numer))?"
                    r"\s{0,3}[:=#]?\s{0,3}[\"']?"
                    r"((?-i:[A-Z0-9](?:[A-Z0-9]|[ -](?=[A-Z0-9])){4,24}))(?![A-Za-z0-9])")

# ------------------------------------------------------------------------------------- user in a URL or path --
_URL_USER_RE = re.compile(r"://([^:/?#\s@\[\]]{1,64}):[^@\s/]{1,128}@")
_HOME_USER_RE = re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\\\?Users\\\\?)([A-Za-z][A-Za-z0-9._-]{1,31})(?=[/\\])")
# service accounts and the words of documentation: no person
SERVICE_USERS = frozenset({
    "root", "runner", "ubuntu", "user", "admin", "shared", "public", "default", "ec2-user", "git", "node", "app",
    "vscode", "jenkins", "gitlab-runner", "circleci", "travis", "docker", "dev", "developer", "me", "you",
    "username", "yourname", "your-user", "your_user", "name", "foo", "bar", "test", "pi", "linuxbrew", "runneradmin",
    "builder", "build", "ci", "www-data", "nobody", "postgres", "mysql", "jovyan", "vagrant", "centos", "fedora",
    "debian", "alpine", "azureuser", "opc", "cloud-user", "core", "steam", "guest", "administrator", "all users",
    "default user", "defaultapppool", "localservice", "networkservice", "systemprofile", "redis", "elastic",
    "oracle", "sa", "deploy", "deployer", "ansible", "github", "gitlab", "bitbucket", "bamboo", "teamcity",
    "buildkite", "buildbot", "actions", "codespace", "gitpod", "coder", "workspace", "sandbox", "tester", "demo",
    "example", "sample", "someone", "somebody", "john", "jane", "alice", "bob", "x", "xxx", "home", "users",
    "anonymous", "anon", "apikey", "api", "api_key", "token", "oauth", "oauth2", "x-access-token", "x-token-auth",
    "x-oauth-basic", "bearer", "key", "secret", "pass", "password", "login", "account", "service", "client",
    "nonroot", "airflow", "rstudio", "rocky", "kali", "vsts", "keycloak", "rabbitmq", "kubeadmin", "aws", "gcp",
    "azure", "wordpress", "gitlab-ci-token", "personalaccesstoken", "jupyter", "spark", "hadoop", "kafka",
    "zookeeper", "grafana", "prometheus", "nginx", "apache", "httpd", "tomcat", "minio", "gitea", "sonar",
    "sonarqube", "nexus", "odoo", "ftp", "mail", "www", "web", "backup", "ops", "devops", "cloud", "ubuntu-server",
    "arch", "manjaro", "suse", "opensuse", "kubernetes", "k8s", "pi", "postgresql", "mongodb", "mongo", "mariadb",
    "couchdb", "neo4j", "influxdb", "clickhouse", "sentry", "superset", "metabase", "n8n", "frappe", "erpnext",
    "dependabot", "renovate", "github-actions", "travis-ci", "drone", "woodpecker", "argocd", "flux", "vault",
    "consul", "nomad", "terraform", "packer", "bitnami", "daemon", "bin", "sys", "sync", "games", "man", "lp",
    "news", "uucp", "proxy", "list", "irc", "gnats", "systemd-network", "messagebus", "sshd", "chrony", "ntp",
    "oai", "readonly", "read_only", "reader", "writer", "readwrite", "migration", "migrations", "migrator",
    "replication", "replicator", "repl", "monitor", "monitoring", "metrics", "exporter", "healthcheck", "probe",
    "owner", "dbo", "dbadmin", "dba", "superuser", "su", "operator", "scheduler", "etl", "analytics", "report",
    "reporting", "integration", "webhook", "smtp", "imap", "noreply", "no-reply", "relay", "upload", "download",
})
# a user name that a tool or an image creates, not a person: appuser, app_user, mambauser, seluser, pwuser, user1
_SERVICE_USER_RE = re.compile(r"(?i)^(?:.{0,12}[-_]?user\d*|user[-_]?\d+|.{0,20}(?:bot|svc|service|admin|runner|"
                              r"agent|daemon|worker|deploy|build)(?:[-_]?\d+)?|[a-z]{1,3}\d+|.*\[bot\])$")


def _service_user(u: str) -> bool:
    low = u.lower()
    return low in SERVICE_USERS or bool(_SERVICE_USER_RE.match(low)) or low.startswith("__") \
        or sum(c.isdigit() for c in u) >= 4 or bool(re.search(r"[{}$<>%]", u))

# ------------------------------------------------------------------------------- street address with postcode --
_STREET = (r"(?:St|Street|Rd|Road|Ave|Avenue|Lane|Ln|Blvd|Boulevard|Drive|Dr|Way|Court|Ct|Place|Pl|Terrace|Close"
           r"|Crescent|Marg|Nagar|Square|Sq|Highway|Hwy)")
# per region: (regions, regex). The postcode of each country: US and CA (state and ZIP, or the Canadian A1A 1A1),
# UK, IN (six digits), AU and NZ (state and four digits)
_POSTCODES = {
    "us": r"\b[A-Z]{2} \d{5}(?:-\d{4})?\b", "ca": r"\b[A-Z]{2} [A-Z]\d[A-Z] ?\d[A-Z]\d\b",
    "uk": r"\b[A-Z]{1,2}\d[A-Z\d]? \d[A-Z]{2}\b", "ie": r"\b[A-Z]\d{2} ?[A-Z0-9]{4}\b", "in": r"\b\d{6}\b",
    "au": r"\b[A-Z]{2,3} \d{4}\b", "nz": r"\b\d{4}\b",
}
_EN_STREET = (r"\b\d{1,5}[A-Za-z]?(?:/\d{1,4})?,? (?:[A-Z][\w'.-]{0,30} ){1,4}" + _STREET
              + r"\.?,[^\n\"';|]{2,40}?(?:{codes})")
_CITY = r"[A-ZÄÖÜÉ][\wäöüßéèàç-]{1,40}"
# street and postcode on two lines (Hafenweg 3\n12345 Ort). No address rule masks it; after a company's name it feeds
# the company decision alone, so its postcode and VAT ID follow the street, which stays text
_DE_TWO_LINES_RE = re.compile(r"\b[A-ZÄÖÜ][\wäöüß-]{0,40}(?:straße|strasse|str\.|weg|gasse|platz|allee|ring|damm) "
                              r"\d{1,4}[a-z]?[ \t]*\r?\n[ \t]*\d{4,5} (" + _CITY + ")")
_DEPARTMENT_LINE_RE = re.compile(r"(?i)[ \t]*(?:abteilung|abt\.|department|dept\.?|division|bereich)[ \t]")
_ADDRESS_FORMS = tuple(
    (frozenset({r}), re.compile(_EN_STREET.replace("{codes}", code))) for r, code in _POSTCODES.items()) + (
    (frozenset({"de", "at", "ch"}),
     re.compile(r"\b[A-ZÄÖÜ][\wäöüß-]{0,40}(?:straße|strasse|str\.|weg|gasse|platz|allee|ring|damm) \d{1,4}[a-z]?, "
                r"\d{4,5} (" + _CITY + ")")),
    (frozenset({"fr", "be", "lu", "ch"}),
     re.compile(r"\b\d{1,4},? (?:rue|avenue|boulevard|bd|chemin|allée|place|impasse) [^\n,\"]{2,40}, \d{5} "
                r"(" + _CITY + ")")),
    (frozenset({"pt", "br", "es", "it"}),
     re.compile(r"(?:^|(?<=[\s:;,(\"']))(?:Rua|Avenida|Av\.|Calle|Carrer|Via|Viale|Piazza) [^\n,\"]{2,40}, \d{1,5}"
                r"[^\n\"]{0,40}?\b(?:\d{5}(?:-\d{3})?|\d{4}-\d{3}) (" + _CITY + ")")),
)
# the street word of an English gerund is no German street: Filtering 2, Scoring 4
_GERUND_STREET_RE = re.compile(r"(?:er|or|ur|ar|ir|in)ing \d")
# the address of a company, an office or a public building is no personal data: a word for one on the same line
# before the address, or inside it, keeps it text (Impressum, HQ, the Empire State Building in a travel text)
# The legal forms among these words name a company as the holder of the address. _company_window() reads them alone:
# the postcode and the VAT ID of such an address follow the address (README, "Personal data")
_LEGAL_FORMS = (r"gmbh|ag|ug|kg|sas|sa|srl|bv|e\.v\."
                r"|inc|corp|corporation|llc|ltd|limited|plc|s\.a\.|sarl|s\.r\.l\.")
_NOT_A_HOME_RE = re.compile(
    r"(?i)(?<![a-z])(?:hq|headquarters?|head office|office|offices|campus|building|tower|center|centre|museum"
    r"|embassy|botschaft|consulate|station|airport|flughafen|hotel|hospital|klinik|university|universität|school"
    r"|library|stadium|arena|park|mall|store|shop|restaurant|caf[eé]|bank|impressum|anschrift der firma|firmensitz"
    r"|sitz der gesellschaft|niederlassung|filiale|zweigstelle|branch office|" + _LEGAL_FORMS
    + r"|company|firm|registered|visitor|visit us|our address|unsere adresse|landmark|monument|parliament"
    r"|town hall|rathaus|city hall|cathedral|church|kirche|mairie)(?![a-z])")
_LEGAL_FORM_RE = re.compile(r"(?i)(?<![a-z])(?:" + _LEGAL_FORMS + r")(?![a-z])")
# Before a legal form: a word of the company's name (Beispiel GmbH, Muster & Co. KG)
_NAME_BEFORE_FORM_RE = re.compile(r"\w[\w&.'’-]{0,40}[ ]$")
# between the company's name and its address: separators, at most one department of one or two words (Abteilung Einkauf,
# on its line or before a comma) and at most one label of the company's own address. A label that names another party
# (recipient_address, Lieferadresse, ship to) or a home keeps the mask
# the name of a department: a closed list, so a person's name in the slot (Abteilung Mara Winter) keeps the mask
_DEPARTMENTS = (r"einkauf|beschaffung|buchhaltung|finanzbuchhaltung|kreditorenbuchhaltung|debitorenbuchhaltung"
                r"|kreditoren|debitoren|rechnungswesen|rechnungseingang|finanzen|controlling|personal|vertrieb"
                r"|verkauf|marketing|logistik|versand|lager|recht|rechtsabteilung|it|edv|verwaltung|kundenservice"
                r"|accounting|accounts|payable|receivable|purchasing|procurement|finance|sales|hr|human|resources"
                r"|legal|billing|operations|shipping|support|administration")
_FORM_TO_ADDRESS_RE = re.compile(r"[\s,;:|·\"'()]{0,12}"
                                 r"(?:(?i:abteilung|abt\.|department|dept\.?|division|bereich)[ \t]"
                                 r"(?i:" + _DEPARTMENTS + r")(?:[ ](?:(?:und|and|&)[ ])?(?i:" + _DEPARTMENTS + r"))?"
                                 r"[ \t]*(?:,[ \t]*|\r?\n[ \t]*))?"
                                 r"(?:(?i:(?:rechnungs|firmen|geschäfts|post|haupt)?(?:adresse|anschrift)"
                                 r"|(?:(?:company|business|billing|postal|registered|office)[ _-]?)?address|sitz|adr)"
                                 r"[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?)?")
# a label before the legal form that makes the company a person's employer, job or club
_EMPLOYER_RE = re.compile(r"(?i)employ|arbeitgeber|works? (?:at|for)|beschäftigt|angestellt|tätig bei|mitglied|member"
                          r"|job|title|role|position|occupation|beruf|tätigkeit")
# a short legal form after a preposition is a floor or a court: im UG (Untergeschoss), beim AG
_PREPOSITION_BEFORE_RE = re.compile(r"(?i)(?:^|[^\w])(?:im|in|ins|am|an|vom|zum|beim|unter|über|ab|bis|at|on)[ ]$")


def _company_window(text: str, lo: int, a_start: int, a_end: int, kind: str, company) -> None:
    """The address rule `kind` left the address at a_start..a_end as text: a word of _NOT_A_HOME_RE stands in
    text[lo:a_end]. The caller's list `company` gets (lo, the start of the legal form, a_start, a_end, kind) when the
    holder of the address is a company: a legal form of _LEGAL_FORMS that ends the company's name right before the
    address. detect.py then leaves the postcode in this address and a VAT ID right after it as text too.
    Not a company's address, so the postcode and the VAT ID stay masked:
    - an office, a hotel or a park: it leaves the address as text, but it names no holder;
    - a short legal form in lower case or in mixed case (2 kg, Sa for Saturday), or after a preposition (im UG is
      a floor, beim AG a court);
    - other text between the company's name and the address (a contact person, a record boundary, a value), or a
      label that names a home (home_address, Wohnadresse);
    - an employer label before the company's name (employer, Arbeitgeber), the company in parentheses after a
      person (Max Muster (Beispiel GmbH)), or a key of a person's record (name,
      resident, customer, Kunde) in the paragraph up to 160 characters before it: the address is a person's. A
      customer key whose value is the company's name (Kunde: Beispiel GmbH) names the company."""
    if company is None:
        return
    f = None
    for m in _LEGAL_FORM_RE.finditer(text, lo, a_start):
        f = m   # the last legal form before the address
    if f is None:
        return
    form = f.group()
    if len(form) <= 3 and not form.isupper() and form.lower() not in ("inc", "ltd", "llc", "plc"):
        return
    if len(form) <= 3 and _PREPOSITION_BEFORE_RE.search(text, max(0, f.start() - 8), f.start()):
        return
    if not _NAME_BEFORE_FORM_RE.search(text, max(0, f.start() - 42), f.start()):
        return
    between = text[f.end():a_start]
    if not _FORM_TO_ADDRESS_RE.fullmatch(between):
        return
    if _EMPLOYER_RE.search(text, max(0, f.start() - 60), f.start()):
        return
    head = text[_line_back(text, f.start()):f.start()]
    if head.count("(") > head.count(")"):
        return   # Max Muster (Beispiel GmbH), Gartenweg 3: the company in parentheses is a person's affiliation
    para = text.rfind("\n\n", max(0, f.start() - 160), f.start())
    key_lo = max(0, f.start() - 160) if para < 0 else para
    # a key ends in : or =; without one the long alternation need not run (a line of many company addresses)
    if (text.find(":", key_lo, a_start) >= 0 or text.find("=", key_lo, a_start) >= 0) \
            and any(not (_CUSTOMER_KEY_RE.fullmatch(k.group())
                         and _COMPANY_AFTER_KEY_RE.fullmatch(text, k.end(), f.start()))
                    for k in _PERSON_KEY_RE.finditer(text, key_lo, a_start)):
        return   # Kunde: Beispiel GmbH, Customer: Beispiel GmbH: the customer is the company, not a person
    company.append((lo, f.start(), a_start, a_end, kind))


# --------------------------------------------------------------------------------- name after a name label --
# a letter of Latin Extended-A (Ł, ś, ř, ğ) is a letter of a name too: Łukasz Wiśniewski, Dvořák (holdout, 2026-10-15)
_UP, _LO = "A-ZÀ-ÖØ-ÞĀ-ſ", "a-zà-öø-ÿĀ-ſ"
_NAME_WORD = r"(?:[" + _UP + r"][" + _LO + r"'’-]{1,30}|[A-Z]\.)"
_NAME_PARTICLE = r"(?:van|von|de|da|del|der|al|bin|di|du|la|le)"
_NAME_VALUE = (r"((?:[" + _UP + r"][" + _LO + r"'’-]{1,30})(?:[ ](?:" + _NAME_WORD + "|" + _NAME_PARTICLE + r")){1,3})")
# the value of a customer key up to the legal form: the company's name alone, on the key's line
# at most two words, and & or und between them: a person and a company without a separator
# (Kunde: Lena Brückner Lindner GmbH) cannot be told from a longer company name, so a longer name keeps the mask
_COMPANY_NAME = r"\w[\w.'’-]{0,40}(?:[ ](?:(?:&|\+|und|and)[ ])?\w[\w.'’-]{0,40})?[ ]"
_COMPANY_AFTER_KEY_RE = re.compile(r"[ \t\"']{0,3}(?!(?i:frau|herrn?|mrs?|ms|mx|dr|prof)\b)" + _COMPANY_NAME)
# the key itself, not a longer one (customer_name: is a person's)
_CUSTOMER_KEY_RE = re.compile(r"(?i)(?:kunde|customer)[\"']?[ \t]{0,3}[:=]")
# before the company's name on its line, in the two-line form: the start of the text, a blank line or a heading of the
# address. Another line there may be a person (Frau Lena Brückner\nBeispiel GmbH\nHafenweg 3\n12345 Ort)
_ADDRESS_HEADING_RE = re.compile(r"(?i)[ \t]*(?:(?:rechnungs|liefer)?(?:adresse|anschrift)|rechnungsempfänger"
                                 r"|empfänger|billing address|invoice address|bill to|invoice to|sold to|an|to)"
                                 r"[ \t]*:?[ \t]*\r?")
# the company's line in the two-line form: the company's name alone, or after a Kunde: or Customer: key
_COMPANY_LINE_RE = re.compile(r"[ \t]*(?:(?i:kunde|customer)[ \t]*:[ \t]*)?(?!(?i:frau|herrn?|mrs?|ms|mx|dr|prof)\b)"
                              + _COMPANY_NAME)
# a label that names a person and nothing else
_PERSON_LABELS = (r"full[ _-]?name|customer[ _-]?name|first[ _-]?name|last[ _-]?name|given[ _-]?name|family[ _-]?name"
                  r"|patient(?:[ _-]?name)?|employee(?:[ _-]?name)?|student(?:[ _-]?name)?|contact[ _-]?person"
                  r"|account[ _-]?holder|card[ _-]?holder|cardholder|passenger|tenant|landlord|signer|co-signer"
                  r"|guardian|beneficiary|billed to|oncall|on-call|requested by|reviewed by|approved by|salari[ée]"
                  r"|vorname|nachname|mieter|vermieter|ansprechpartner(?:in)?|pr[ée]nom")
# a key or label of a person's record before the company's name, in the same paragraph: the record is a person's,
# whether or not the name rules find the name in its value (a lower-case or abbreviated name)
_PERSON_KEY_RE = re.compile(r"(?i)(?<![a-z])(?:" + _PERSON_LABELS + r"|name|person|resident|bewohner(?:in)?"
                            r"|privat\w*|private|home|wohn\w*|customer|kunde|user|login|mitarbeiter(?:in)?"
                            r"|employee|staff|member|mitglied|student|schüler(?:in)?)(?![a-z])[\"']?[ \t]{0,3}[:=]")
# a label that also names a product, a service, a team or a document: its value must not read as words
_WEAK_LABELS = (r"fn" + _VCARD_PARAMS
                + r"|name|display[ _-]?name|owner|author|driver|holder|kunde|inhaber(?:in)?|nom|nombre|nome")
_NAME_LABEL_RE = re.compile(
    r"(?i:(?<![a-z_./-])(?:(" + _PERSON_LABELS + r")|(" + _WEAK_LABELS + r")))"
    r"[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?[ \t]{0,3}" + _NAME_VALUE + r"(?![\w'’])")
# the end of a word that makes it a noun, not a name: Streaming, Expedition, Management, Wörterbuch, Verwaltung
_NOUN_END_RE = re.compile(r"(?i)(?:ing|tion|sion|ment|ness|ity|ism|ogy|ware|ance|ence|able|ible|buch|ung|heit|keit"
                          r"|schaft|isch|tät|ive|ics|ers|ies)$")


# English words of two and three letters (the word list starts at four): the verb of a CI step name, `Run Pytest`
_SHORT_EN = frozenset({"run", "set", "get", "add", "use", "fix", "new", "old", "all", "the", "and", "for", "not", "top",
                       "end", "log", "job", "app", "web", "api", "dev", "ops", "off", "on", "up", "out", "key", "map",
                       "tag", "pin", "cut", "mix", "bug", "put", "pop", "via", "to", "of", "in", "at", "by", "is",
                       "no", "go", "do", "my", "our", "own", "per", "pre", "sub", "max", "min", "raw", "dry", "lint"})


def _city_is_a_word(city: str) -> bool:
    """65536 Bytes, 30022 Rows: an English word after the postcode is no city."""
    from .core import _word_set
    low = city.lower()
    return low in _word_set() or (low.endswith("s") and low[:-1] in _word_set())


def _reads_as_words(v: str, every: bool = False) -> bool:
    """A value whose words are English words or nouns, not a name: `Customer Portal`, `Run Pytest`, `Product Owner`,
    `Won't Do`, `Mgmt Vpc`. A given name that is also a word (`Mark`, `Rose`) counts as a name."""
    from .core import _word_set
    words = _word_set()
    hits = []
    for i, w in enumerate(v.replace("’", "'").split()):
        lw = w.lower().strip(".")
        if "'" in lw and not lw.startswith(("o'", "d'", "l'")):
            return True          # won't, don't: a contraction is prose
        if len(lw) >= 2 and not re.search(r"[aeiouyäöüéèàáíóú]", lw):
            return True          # Mgmt, Vpc: no vowel, an abbreviation
        if len(lw) <= 1 or (i == 0 and lw in _GIVEN_NAME_WORDS):
            hits.append(False)
            continue
        stem = lw[:-1] if lw.endswith("s") and len(lw) > 4 else lw
        hits.append(lw in _SHORT_EN or (len(lw) >= 3 and (lw in words or stem in words
                                                          or bool(_NOUN_END_RE.search(lw)))))
    return all(hits) if every else any(hits)


# given names that are also English words (SCOWL); a value that starts with one may still be a person
_GIVEN_NAME_WORDS = frozenset({"john", "peter", "maria", "mark", "rose", "grace", "will", "bill", "jack", "frank",
                               "dean", "drew", "faith", "hope", "joy", "june", "may", "pat", "ray", "rich", "sue",
                               "ruby", "pearl", "amber", "rob", "tom", "tim", "ben", "dan", "don", "ian", "eve",
                               "lily", "iris", "holly", "ivy", "jade", "dawn", "summer", "victor", "carl", "sam"})


# the first word of a value that is no name
_NOT_A_NAME_START = frozenset({
    "the", "a", "an", "my", "your", "our", "this", "that", "new", "old", "none", "null", "true", "false", "test",
    "example", "admin", "user", "team", "service", "system", "default", "unknown", "anonymous", "all", "any", "no",
    "not", "see", "tbd", "todo", "n/a", "der", "die", "das", "ein", "eine", "kein", "keine", "le", "la", "les", "el",
    "github", "gitlab", "google", "microsoft", "amazon", "apple", "meta", "docker", "kubernetes", "visual",
})
# a word in a value that makes it an organisation, a product or a place, not a person
_NOT_A_NAME_WORD = frozenset({
    "team", "teams", "group", "squad", "crew", "department", "dept", "division", "org", "organisation", "organization",
    "inc", "corp", "corporation", "company", "co", "llc", "ltd", "limited", "plc", "gmbh", "ag", "kg", "ug", "se",
    "sa", "sarl", "bv", "nv", "foundation", "project", "developers", "contributors", "community", "authors",
    "maintainers", "bot", "robot", "agent", "server", "service", "services", "cache", "cluster", "proxy", "gateway",
    "controller", "operator", "worker", "manager", "engine", "platform", "studio", "code", "app", "application",
    "suite", "cloud", "api", "sdk", "cli", "ui", "web", "data", "database", "store", "storage", "queue", "stream",
    "network", "labs", "lab", "systems", "solutions", "software", "technologies", "tech", "digital", "media", "games",
    "university", "universität", "school", "college", "institute", "hospital", "city", "street", "road",
    "avenue", "center", "centre", "building", "tower", "station", "airport", "river", "lake", "mountain",
    "north", "south", "east", "west", "new", "san", "los", "las", "saint", "st", "fort", "port", "am", "main",
    "edition", "version", "release", "update", "preview", "beta", "alpha", "stable", "nightly", "pro", "plus",
    "enterprise", "community", "free", "basic", "premium", "standard", "default", "custom", "local", "global",
    "nord", "süd", "sued", "ost", "mitte", "vertrieb", "einkauf", "stadtwerke", "werke", "retail", "studios",
    "workers", "weblate", "autofix", "ci", "oss", "snyk", "sonar", "codecov", "github", "gitlab", "bitbucket",
    "atlassian", "jenkins", "grafana", "loki", "kibana", "elastic", "datadog", "sentry", "jira", "confluence",
    "sammlung", "verwaltung", "abteilung", "gruppe", "dienst", "konto", "kunden", "ordner", "datei", "seite",
    "monitoring", "logging", "security", "support", "sales", "marketing", "finance", "ops", "devops", "infra",
    "infrastructure", "backend", "frontend", "mobile", "desktop", "release", "build", "deploy", "staging",
    "production", "prod", "dev", "test", "tests", "testing", "demo", "sample", "example", "template", "docs",
    "documentation", "readme", "guide", "manual", "handbook", "policy", "rule", "rules", "config", "settings",
    "dashboard", "report", "reports", "alert", "alerts", "job", "jobs", "task", "tasks", "pipeline", "workflow",
})


def _name_ok(v: str) -> bool:
    words = v.replace("’", "'").split()
    low = [w.lower().strip(".") for w in words]
    if v.lower() in PLACEHOLDER_NAMES or low[0] in _NOT_A_NAME_START:
        return False
    if any(w in _NOT_A_NAME_WORD for w in low):
        return False
    return sum(1 for w in words if len(w.strip(".")) >= 2) >= 2


# ------------------------------------------------------------------------------- name before an e-mail address --
# "Erika Beispiel <erika@example.org>", a git log line, a mail header. The address is the e-mail rule's; this is the
# name before it. A service mailbox (noreply, a bot) names no person
_NAME_MAIL_RE = re.compile(r"((?:[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ'’-]{1,30})(?: (?:[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ'’-]{1,30}|[A-Z]\.)){1,3})"
                           r"[ \t]{0,2}[<(\[]([\w.%+-]{1,64})@([\w-]{1,63}(?:\.[\w-]{1,63}){0,8})")
_SERVICE_LOCAL_RE = re.compile(r"(?i)^(?:no-?reply|do-?not-?reply|notifications?|support|info|hello|contact|team"
                               r"|admin|root|git|bot|ci|build|release|deploy|security|alerts?|monitoring|postmaster"
                               r"|webmaster|mailer-daemon|bounces?|github-actions|actions|dependabot|renovate)"
                               r"(?:[+._-].*)?$|.*[-_.]bot$|.*\[bot\]$")

# ---------------------------------------------------------------------------------------- CSV header columns --
# a header with a column that holds personal data on every row. A name or a user column alone is no proof (a product
# list has a `name` column): it counts only next to a strong column
_STRONG_COLS = frozenset({"address", "street", "street_address", "home_address", "endereco", "direccion", "adresse",
                          "anschrift", "strasse", "dob", "date_of_birth", "birth_date", "birthdate", "birthday",
                          "geburtsdatum", "phone", "phone_number", "telephone", "telefone", "telefono", "telefon",
                          "mobile", "mobile_phone", "cell", "ssn", "tfn", "aadhaar", "nir",
                          "passport", "passport_number", "national_id", "tax_id", "mrn",
                          # German ids that only a person has (2026-10-19): the tax identification number, the social
                          # insurance and the identity card number. `steuernummer` and `steuer_id` stay out: a company
                          # register and a table of tax rates have them too (codex Gate A); a tax id in such a column is
                          # found by its checksum rule (de-tax-id, region de)
                          # only the long names: `sv_nummer` and `ausweisnummer` also number versions and badges
                          "steueridentifikationsnummer", "steuer_identifikationsnummer", "sozialversicherungsnummer",
                          "rentenversicherungsnummer", "personalausweisnummer"})
_WEAK_COLS = frozenset({"name", "full_name", "fullname", "first_name", "last_name", "firstname", "lastname",
                        "given_name", "family_name", "surname", "customer", "customer_name", "employee",
                        "employee_name", "emp_name", "patient", "patient_name", "nome", "nombre", "nom", "vorname",
                        "nachname", "username", "user_name"})
_CSV_ROWS = 10000   # rows read under one header; a larger table is read in its first rows only
_CSV_CELL_RE = {sep: re.compile(r'"[^"\n]{0,512}"|[^' + sep + r'\n]{0,512}') for sep in (",", ";", "\t")}
_NOT_A_CELL = frozenset({"", "null", "none", "n/a", "na", "-", "true", "false", "nan"})


_DATE_CELL_RE = re.compile(_DATE)
_ADDRESS_WORD_RE = re.compile(r"[^\W\d_]{3}")
_HOST_PORT_RE = re.compile(r":\d{2,5}(?!\d)|://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\.(?:com|net|org|io|local|internal)\b")
_NAME_CELL_RE = re.compile(_NAME_VALUE)


def _column_type(col: str) -> str:
    if col in ("dob", "date_of_birth", "birth_date", "birthdate", "birthday", "geburtsdatum"):
        return BIRTH_DATE
    if col in ("phone", "phone_number", "telephone", "telefone", "telefono", "telefon", "mobile", "mobile_phone",
               "cell"):
        return PHONE
    if col in ("address", "street", "street_address", "home_address", "endereco", "direccion", "adresse",
               "anschrift", "strasse"):
        return ADDRESS
    if col in _WEAK_COLS:
        return USERNAME if "user" in col else NAME
    return ID_NUMBER


def _cell_ok(v: str, typ: str) -> bool:
    """The cell holds what its column names: a desk extension is no phone, `Front Desk` no name."""
    digits = sum(c.isdigit() for c in v)
    if typ == PHONE:
        return digits >= 7
    if typ == BIRTH_DATE:
        return bool(_DATE_CELL_RE.fullmatch(v)) and not _placeholder_digits(v, dates=True) and _past_year(v)
    if typ == ADDRESS:
        # two words, one of three letters, and no host, port or URL: 127.0.0.1:8080 and node1.acme.dev in a table of
        # servers are no address
        return digits >= 1 and len(v) >= 8 and " " in v.strip() and not _NOT_A_HOME_RE.search(v) \
            and bool(_ADDRESS_WORD_RE.search(v)) and not _HOST_PORT_RE.search(v)
    if typ == NAME:
        return bool(_NAME_CELL_RE.fullmatch(v)) and _name_ok(v) and not _reads_as_words(v)
    if typ == USERNAME:
        return not _service_user(v)
    return digits >= 5 and not _placeholder_digits(v)


def _csv_hits(text: str) -> list:
    out = []
    lines = text.split("\n")
    pos = 0
    li = 0
    while li < len(lines) - 1:
        hdr = lines[li]
        sep = max((",", ";", "\t"), key=hdr.count)
        if hdr.count(sep) < 1 or " " in hdr.strip() or len(hdr) > 2000:
            pos += len(hdr) + 1
            li += 1
            continue
        names = [h.strip().strip("\"'").lower() for h in hdr.split(sep)]
        strong = {i for i, h in enumerate(names) if h in _STRONG_COLS}
        cols = strong | {i for i, h in enumerate(names) if h in _WEAK_COLS} if strong else set()
        pos += len(hdr) + 1
        li += 1
        if not cols:
            continue
        rows = 0
        while li < len(lines) and rows < _CSV_ROWS:
            line = lines[li]
            if not line.strip() or (line.count(sep) != hdr.count(sep) and '"' not in line):
                break
            j = col = 0
            row: list = []
            cell = _CSV_CELL_RE[sep]
            while j <= len(line):
                m = cell.match(line, j)
                a, b = m.span()
                if col in cols:
                    s2, e2 = (a + 1, b - 1) if line[a:b].startswith('"') and b - a >= 2 else (a, b)
                    v = line[s2:e2].strip()
                    typ = _column_type(names[col])
                    if v.lower() not in _NOT_A_CELL and len(v) >= 2 and _cell_ok(v, typ):
                        lead = len(line[s2:e2]) - len(line[s2:e2].lstrip())
                        row.append((pos + s2 + lead, pos + s2 + lead + len(v), "csv-personal-column", typ, col))
                col += 1
                j = b + 1
            # a name or a user cell counts only beside a strong cell of the same row that holds what it names, and an
            # address or a phone only beside a cell that names a person (a name, a birth date, an id): a list of
            # depots or of stations has addresses and no person
            if any(c in strong for *_, c in row) and any(h[3] in (NAME, BIRTH_DATE, ID_NUMBER) for h in row):
                out += [h[:4] for h in row]
            pos += len(line) + 1
            li += 1
            rows += 1
    return out


# ------------------------------------------------------------------------------------ Markdown table columns --
# the CSV rule for a Markdown table: a header row of `|` cells, a row of dashes, then rows. Its column names hold
# spaces (Date of Birth, Phone Number), so a name is folded to the CSV form (date_of_birth) and a few longer names map
# to a column of the CSV rule. The same person check: a strong column, and a row that also names a person
_MD_SEP_RE = re.compile(r"[ \t]*(?:\|[ \t]*)?:?-{3,}:?(?:[ \t]*\|[ \t]*:?-{3,}:?)*[ \t]*(?:\|[ \t]*)?")
_MD_ALIASES = {"telephone_number": "telephone", "mobile_number": "mobile", "cell_phone": "cell",
               "contact_number": "phone", "phone_no": "phone", "social_security_number": "ssn",
               "national_id_number": "national_id", "tax_id_number": "tax_id", "medical_record_number": "mrn",
               "passport_no": "passport_number", "home_address": "home_address", "street_address": "street_address",
               "patient": "patient", "date_of_birth_dob": "date_of_birth", "dob_date_of_birth": "date_of_birth"}


def _md_column(cell: str) -> str:
    name = re.sub(r"[\s/.-]+", "_", cell.strip().strip("*_`'\" ").strip().lower()).strip("_")
    name = re.sub(r"_?\(.*\)$", "", name)   # Date of Birth (YYYY-MM-DD)
    return _MD_ALIASES.get(name, name)


def _md_cells(line: str) -> list:
    """(start, end) of each cell's text in a table row; the outer bars open and close the row."""
    out = []
    a = line.find("|") + 1 if line.lstrip().startswith("|") else 0
    while a <= len(line):
        b = line.find("|", a)
        while b > 0 and line[b - 1] == "\\":
            b = line.find("|", b + 1)
        if b < 0:
            if line[a:].strip():
                out.append((a, len(line)))
            break
        out.append((a, b))
        a = b + 1
    return out


# a column whose header names an account number holds one on each row, whatever the other columns are: Benchmark V1,
# Nemotron, 40 of the 73 account numbers that the us-bank label window lost were cells under `Account Number`. Only
# the names that say number: `account`, `account_id` and `aws_account` hold a cloud account or a user id, and a
# 12-digit AWS account id in a table of resources is no bank account
_ACCOUNT_NUMBER_COL_RE = re.compile(r"(?:bank_|mortgage_|savings_|checking_|loan_|customer_|primary_)?"
                                    r"(?:account|acct)_?(?:number|no|nr|num|#)|kontonummer|iban")
_ACCOUNT_CELL_RE = re.compile(r"\d{2,17}(?:[ -]\d{2,12}){0,3}")


def _account_cell(v: str) -> bool:
    digits = sum(c.isdigit() for c in v)
    return bool(_ACCOUNT_CELL_RE.fullmatch(v)) and 8 <= digits <= 20 and not _placeholder_digits(v) \
        and not _DATE_CELL_RE.fullmatch(v)


def _md_table_hits(text: str) -> list:
    out = []
    lines = text.split("\n")
    pos = [0]
    for ln in lines:
        pos.append(pos[-1] + len(ln) + 1)
    li = 0
    while li < len(lines) - 2:
        hdr = lines[li]
        if "|" not in hdr or len(hdr) > 2000 or len(lines[li + 1]) > 2000 \
                or not _MD_SEP_RE.fullmatch(lines[li + 1]):
            li += 1
            continue
        names = [_md_column(hdr[a:b]) for a, b in _md_cells(hdr)]
        strong = {i for i, h in enumerate(names) if h in _STRONG_COLS}
        cols = strong | {i for i, h in enumerate(names) if h in _WEAK_COLS} if strong else set()
        accounts = {i for i, h in enumerate(names) if _ACCOUNT_NUMBER_COL_RE.fullmatch(h)}
        li += 2
        rows = 0
        while li < len(lines) and rows < _CSV_ROWS and "|" in lines[li] and lines[li].strip():
            line = lines[li]
            row: list = []
            for col, (a, b) in enumerate(_md_cells(line)):
                if col in accounts:
                    v = line[a:b].strip().strip("*`")
                    if _account_cell(v):
                        s0 = a + line[a:b].index(v)
                        out.append((pos[li] + s0, pos[li] + s0 + len(v), "md-table-personal-column", ID_NUMBER))
            if cols:
                for col, (a, b) in enumerate(_md_cells(line)):
                    if col not in cols:
                        continue
                    v = line[a:b].strip().strip("*`")
                    typ = _column_type(names[col])
                    if v.lower() not in _NOT_A_CELL and len(v) >= 2 and _cell_ok(v, typ):
                        s0 = a + line[a:b].index(v)
                        row.append((pos[li] + s0, pos[li] + s0 + len(v), "md-table-personal-column", typ, col))
            # a date alone names no person in a table of releases (| Name | Birthday | Version |): a name or an id
            if any(c in strong for *_, c in row) and any(h[3] in (NAME, ID_NUMBER) for h in row):
                out += [h[:4] for h in row]
            li += 1
            rows += 1
    return out


class _lazy:
    """A regex compiled at its first use: a hook pays every millisecond of import, and most texts need no form."""
    __slots__ = ("_args", "_rx")

    def __init__(self, *args):
        self._args, self._rx = args, None

    def __getattr__(self, name):
        if self._rx is None:
            object.__setattr__(self, "_rx", re.compile(*self._args))
        return getattr(self._rx, name)



# ------------------------------------------------------------------------------------------ the forms of 0.6.24 --
# A value in a fixed form or after a label that names it, from the holdout values that 0.6.21 still leaked
# (2026-10-15). Each rule declares (type, channel, region, needs): channel "tool" (tool results and files) or "both".
# All run in the tool channel only: a typed question about a form (`How does ::add-mask::x work?`) is no secret, and
# a hit there blocks the prompt (review of 0.6.24);
# region "generic" or a country; needs "form" (a fixed syntax names the value: ::add-mask::, SharedAccessKey=, a FHIR
# identifier, a 〒 postcode) or "label" (a word before the value names it: member, record, token, address).
# tests/fp_corpus_forms.py holds the developer text in the same shapes that each rule must leave alone.
FORMS = {
    "secret-add-mask": ("SECRET", "tool", "generic", "form"),
    "secret-shared-access-key": ("SECRET", "tool", "generic", "form"),
    "secret-postman-variable": ("SECRET", "tool", "generic", "form"),
    "secret-hex48-after-token-word": ("SECRET", "tool", "generic", "label"),
    "secret-in-login-code": ("SECRET", "tool", "generic", "form"),
    "secret-after-user-slash": ("SECRET", "tool", "generic", "label"),
    "id-number-fhir-identifier": (ID_NUMBER, "tool", "generic", "form"),
    "id-number-after-record-label": (ID_NUMBER, "tool", "generic", "label"),
    "id-letters-after-label": (ID_NUMBER, "tool", "generic", "label"),
    "id-number-in-member-parentheses": (ID_NUMBER, "tool", "generic", "label"),
    "id-number-under-sql-alias": (ID_NUMBER, "tool", "generic", "label"),
    "address-under-sql-alias": (ADDRESS, "tool", "generic", "label"),
    "address-after-label": (ADDRESS, "tool", "generic", "label"),
    "address-jp-postcode": (ADDRESS, "tool", "generic", "form"),
    "address-in-form": (ADDRESS, "tool", "in", "form"),
    "name-non-latin-after-label": (NAME, "tool", "generic", "label"),
    "phone-url-encoded": (PHONE, "tool", "generic", "label"),
    "phone-wrapped-line": (PHONE, "tool", "generic", "form"),
    "address-vcard-fields": (ADDRESS, "tool", "generic", "form"),
    "name-vcard-n": (NAME, "tool", "generic", "form"),
    "birth-date-vcard-compact": (BIRTH_DATE, "tool", "generic", "form"),
    "phone-after-phone-word": (PHONE, "tool", "generic", "label"),
    "name-single-after-label": (NAME, "tool", "generic", "label"),
    "address-street-after-label": (ADDRESS, "tool", "generic", "label"),
    "md-table-personal-column": ("COLUMN", "tool", "generic", "label"),
    "username-after-label": (USERNAME, "tool", "generic", "label"),
    "secret-password-with-sign": ("SECRET", "tool", "generic", "label"),
}
# a value that only names one: a variable, a template, an elision, a path
_NOT_A_VALUE_START = ("$", "%", "{", "<", "(", "[", "*", "#", "/", ".")


def _random_value(v: str, n: int = 8) -> bool:
    """A value of a secret: n characters or more, a letter and a digit, no space, not a variable or a template."""
    return (len(v) >= n and not v.startswith(_NOT_A_VALUE_START) and "${" not in v and "{{" not in v and "$(" not in v
            and not re.search(r"\s", v) and any(c.isdigit() for c in v) and any(c.isalpha() for c in v))


def _complex(v: str) -> bool:
    """Three of four classes: lower, upper, digit, sign. A password that someone chose, not a word or a path."""
    return sum((any(c.islower() for c in v), any(c.isupper() for c in v), any(c.isdigit() for c in v),
                any(not c.isalnum() for c in v))) >= 3


_ADD_MASK_RE = _lazy(r"::add-mask::([^\s\"'`]{6,256})")
_SAS_KEY_RE = _lazy(r"(?i)\bSharedAccessKey=([A-Za-z0-9+/_=-]{16,256})(?![A-Za-z0-9+/_=-])")
# a Postman or Insomnia variable, a HAR header: {"key"|"name": "<secret word>", "value": "..."}
_KV_SECRET_RE = _lazy(r"\"(?:key|name)\"\s*:\s*\"([^\"\n]{1,60})\"\s*,\s*\"value\"\s*:\s*\"([^\"\n]{6,512})\"")
_SECRET_NAME_PARTS = frozenset({"password", "passwd", "pwd", "secret", "token", "apikey", "pass", "credential",
                                 "credentials", "auth", "passphrase", "bearer", "jwt", "privatekey", "signingkey",
                                 "clientkey", "accesskey", "secretkey"})
_META_NAME_RE = _lazy(r"(?i)(?:type|url|uri|name|header|policy|length|len|ttl|seconds|expiry|expires|endpoint|path"
                           r"|id|ids|hint|label|format|scheme|prefix|mode|kind|version|count|audience|issuer|provider"
                           r"|scope|store|tokenizer|algorithm|alg|encoding|status|method|rate|format)$")
_HOST_RE = _lazy(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.?")


def _name_parts(name: str) -> list:
    """`x-internal-token` -> x, internal, token; `clientSecret` -> client, secret; `API_KEY` -> api, key."""
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [p.lower() for p in re.split(r"[^A-Za-z0-9]+", name) if p]


def _secret_name(name: str) -> bool:
    parts = _name_parts(name)
    joined = ["".join(parts[i:i + 2]) for i in range(len(parts) - 1)]
    # a part with a counter counts as its word: password2, token_1
    return any(p.rstrip("0123456789") in _SECRET_NAME_PARTS for p in parts + joined)


def _words_inside(v: str) -> bool:
    """A value with a dictionary word of five letters or more in it (Release2026Alpha, Billing2FA-Setup) is a name or
    a placeholder: a chosen password or a key has none (holdout values of 0.6.21, review of 0.6.24)."""
    from .core import _word_set
    if re.search(r"[^\w.-]", v):
        return False   # a sign other than - _ . (Summer2024!x, Sunshine#2024): a chosen password, words or not
    words = _word_set()
    return any(r.lower() in words for r in re.findall(r"[A-Z][a-z]{4,}|[a-z]{5,}|[A-Z]{5,}", v))


_HEX48_RE = _lazy(r"(?i)(?<![a-z])(token|code|secret|key)(?![a-z])[^\n]{0,24}?(?<![0-9a-fA-F])([0-9a-f]{48})"
                       r"(?![0-9a-zA-Z])")
_DIGEST_WORD_RE = _lazy(r"(?i)hash|digest|checksum|fingerprint|cache|etag|sha|md5|tiger|integrity|commit")
_REDIS_AUTH_RE = _lazy(r"\"AUTH\"\s+\"([^\"\n]{6,128})\"(?!\s+\")")
_LOGIN_CALL_RE = _lazy(r"\.login\(\s*([\"'])[^\"'\n]{1,64}\1\s*,\s*([\"'])([^\"'\n]{6,128})\2\s*\)")
_OP_FIELDS_RE = _lazy(r"op item get[^\n]*--fields[^\n]*\busername,password\b[^\n]*\n[^\n]{1,128}\n([^\s]{6,128})"
                           r"(?=\n|$)")
_SQL_CREDS_RE = _lazy(r"(?i)INSERT INTO \w*(?:cred|passw|secret|login)\w*\s+VALUES\s*\(([^)\n]{1,300})\)")
_USER_SLASH_RE = _lazy(r"(?i)(?<![a-z])(?:login|user|creds?|credentials|account)(?![a-z])[^\n]{0,30}?(?<!\S)"
                            r"[\w.@-]{2,64} / (\S{8,64})(?!\S)")
_FHIR_RE = _lazy(r"(?i)\"system\"\s*:\s*\"([^\"\n]{0,80})\"\s*,\s*\"value\"\s*:\s*\"([^\"\n]{4,40})\"")
_FHIR_SYSTEM_RE = _lazy(r"(?i)(?:^|[/:._#-])(?:mrn|passport(?:-[a-z]{2,3}|[-_]?(?:number|no))?|ssn|nid"
                             r"|national[-_]?id|tax[-_]?id"
                             r"|member[-_]?id|insurance(?:[-_]member)?(?:[-_]id)?)(?:$|[/:._#-])")
_IDENTIFIER_KEY_RE = _lazy(r"\"identifier\"\s*:\s*\[")


def _in_identifier_array(text: str, pos: int, most: int = 4000) -> bool:
    """`pos` lies inside a FHIR `"identifier": [...]` array: the last such key within `most` characters before it,
    with its bracket still open (an `identifierRequired` flag or a closed array does not count)."""
    lo = max(0, pos - most)
    last = None
    for m in _IDENTIFIER_KEY_RE.finditer(text, lo, pos):
        last = m
    if last is None:
        return False
    depth = 1
    for ch in text[last.end():pos]:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return False   # the identifier array closed before the value
    return True


_VERSION_RE = _lazy(r"(?i)^v?\d+(?:\.\d+)+$")
_ID_VALUE = r"((?-i:[A-Z0-9](?:[A-Z0-9]|[ -](?=[A-Z0-9])){4,24}))(?![A-Za-z0-9])"
_RECORD_LABEL_RE = _lazy(
    r"(?i)(?<![a-z])(?:insurance(?:[ _-]?member)?(?:[ _-]?id)?|member(?:[ _-]?(?:id|no|number|#))?"
    r"|record(?:[ _-]?(?:no|number|#))?|patient(?:[ _-]?id)?|account|(?<=\")nid(?=\")|(?-i:DL)(?=[\"']?[\s:#]))"
    r"(?![a-z])[\"']?"
    r"(?:\s{0,3}(?:is|number|no\.?|#))?\s{0,3}[:=#]?\s{0,3}[\"']?" + _ID_VALUE)
_ID_LETTERS_RE = _lazy(r"(?i)(?<![a-z])(?:member(?:[ _-]?id)?|passport|insurance(?:[ _-]?id)?)(?![a-z])[\"']?"
                            r"(?:\s{0,3}(?:is|number|no\.?|#))?\s{0,3}[:=#]?\s{0,3}[\"']?"
                            r"((?-i:[A-Z0-9][A-Z0-9-]{6,22}[A-Z0-9]))(?![A-Za-z0-9])")
_MEMBER_PAREN_RE = _lazy(r"(?i)(?<![a-z])member[\"']?\s{0,3}:\s{0,3}[^\n()]{2,40}\((?-i:([A-Z0-9][A-Z0-9-]{4,22}"
                              r"[A-Z0-9]))\)")
_SQL_ALIAS_RE = _lazy(r"'([^'\n]{5,80})'\s+(?i:AS)\s+(?i:(sin|ssn|tax_?id|mrn|nid|passport(?:_no)?|member_?id"
                           r"|national_?id|aadhaar|pan|nhs|tfn|address|home_address))\b")
_JP_ADDRESS_RE = _lazy(r"〒\d{3}-\d{4}[ 　]?[^\s\"',;<>|]{2,40}")
_JP_COMPANY_RE = _lazy(r"株式会社|有限会社|合同会社|本社|支社|支店|営業所|事務所|工場|センター|ビル|役所"
                            r"|大学|病院")
_ADDRESS_LABEL_RE = _lazy(
    r"(?i)(?<![a-z_])(address(?: on file)?|home[ _-]?address|adr" + _VCARD_PARAMS
    + r"|ship[ _-]?to|reship to|property|lives"
    r"|endere[cç]o|direcci[oó]n|adresse|location)[\"']?\s{0,3}:\s{0,3}[\"']?(;*)([^\n\"|;]{8,100}?)"
    r"(?=[\"\n|]|\s{2}|\.\s|$)")
# a house number and a street word, in either order: 12 Harbour Lane, Rua das Flores 12,
_HOUSE_RE = _lazy(r"\b\d{1,5}[A-Za-z]?(?:/\d{1,4})?,? [A-ZÀ-Þ][a-zà-ÿ]{2,}\b(?! \d)"
                       r"|[A-ZÀ-Þ][a-zà-ÿ]{2,} \d{1,5}[A-Za-z]?,")
_NOT_AN_ADDRESS_RE = _lazy(r"(?i)\b(?:rack|row|slot|zone|version|build|schema|width|height|signal|size|page"
                                r"|step|round|score|accepted|proposed|rejected|field|line|port|http|status|max|min)\b|0x")
# one name word after a label that names a first or a last name (Nemotron-PII, 2026-10-16: `first name: Dana`). The
# name rule needs two words; a first or a last name alone is one. The word must not read as an English word or noun
# (`first_name: String`, `last name: Required`), and a second capitalised word leaves the value to the name rule
_SINGLE_NAME_LABELS = (r"first[ _-]?name|last[ _-]?name|given[ _-]?name|family[ _-]?name|middle[ _-]?name|surname"
                       r"|forename|vorname|nachname|familienname|rufname|pr[ée]nom|nom de famille|apellidos?"
                       r"|nombre de pila|cognome|sobrenome|voornaam|achternaam|f[öo]rnamn|efternamn")
_SINGLE_NAME_RE = _lazy(r"(?i:(?<![a-z_./-])(?:" + _SINGLE_NAME_LABELS + r"))[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?"
                        r"[ \t]{0,3}([" + _UP + "\u1e00-\u1eff" + r"]"
                        r"[" + _LO + "\u1e00-\u1eff\u0300-\u036f" + r"'’-]{1,30})"
                        r"(?![\w'’-])"   # Nguyễn, Ạnh, and a combining accent
                        r"(?![ \t]{1,2}[" + _UP + r"])")
# a user name after a label that names one (`"username": "jdoe42"`, `user_name: jdoe42`): the label of a record, not
# the word `user` or `login` alone (`"user": {`, `login: true`). The whole value is read first (a quoted string, else
# the scalar up to a space, a comma, a semicolon or a bracket) and judged as one: it is masked whole or not at all, so
# `jdoe.x/tenant` never leaves `/tenant` in the clear. It must read as a person's account name: a service account, a
# placeholder, a schema word, a Kubernetes principal (`system:serviceaccount:…`), a name of words (`database_owner`,
# `ci_actor`) or a name in code (`username = os.environ[...]`, `username = account.name`) stays (Benchmark V1 bank and
# codex Gate A, 2026-10-19). An e-mail address after the label is left to the e-mail rule
_USERNAME_LABEL_RE = _lazy(r"(?i)(?<![a-z_.-])(?:user[ _-]?name|benutzername|nutzername|login[ _-]?name)[\"']?"
                           r"([ \t]{0,3}[:=][ \t]{0,3})(?:\"([^\"\n]{1,64})\"|'([^'\n]{1,64})'"
                           r"|([^\s\"',;{}\[\]()<>]{1,64})(?=[\s,;}\])]|$))")
# the label in a sentence ("the user name jdoe84", "your user name is j.harlow"): only a value with a digit, a dot or
# an underscore, as a sentence goes on after the label with a word ("the user name field"). Benchmark V1, Nemotron
# dev split: about 1,800 user names missed after these forms, 2026-10-20
_USERNAME_PROSE_RE = _lazy(r"(?i)(?<![a-z_.-])(?:user[ _-]?name|username)(?:[ \t]+(?:is|was))?[ \t]+"
                           r"([A-Za-z][\w.@+-]{1,62}[A-Za-z0-9])(?=[\s,;:!?)]|\.(?:\s|$)|$)")
_EXAMPLE_KEY_RE = _lazy(r"(?i)[\"']?examples?[\"']?[ \t]{0,3}:[ \t]*(?:\{|\|)?")
_USERNAME_SHAPE_RE = _lazy(r"[\w][\w.@+\\/-]{1,63}")
# a name in code, not a value: `username = os.environ[...]`, `user_name: self.user.name`
_USERNAME_CODE_START = ("self.", "this.", "os.", "request.", "req.", "user.", "config.", "settings.", "args.", "env.",
                        "process.", "params.", "form.", "data.", "props.", "ctx.", "context.", "options.", "opts.",
                        "cls.", "obj.", "row.", "item.", "record.", "payload.", "body.", "event.", "input.")
# the last word of a field, a role or a variable, not of a person's name: ci_actor, database_owner, enum_value
_USERNAME_NOT_A_NAME_END = ("_actor", "_account", "_owner", "_value", "_name", "_user", "_id", "_type", "_field",
                            "_key", "_role", "_group", "_bot", "_service", "_svc", "_admin", "acct", "_reader",
                            "_writer")
# the last part of an attribute in code: `username=authn.principal`, `username: current.user`
_USERNAME_ATTRIBUTE_END = frozenset({"name", "user", "username", "login", "principal", "id", "email", "value",
                                     "current", "subject", "sub", "identity", "account", "owner"})
# a service account by its form only (the short-name rule of a home path, `ab12`, is no help here: js42 is a person)
_USERNAME_SERVICE_RE = re.compile(r"(?i)^(?:.{0,12}[-_]?user\d*|user[-_]?\d+|.{0,20}(?:bot|svc|service|admin|runner|"
                                  r"agent|daemon|worker|deploy|build)(?:[-_]?\d+)?|.*\[bot\])$")
_USERNAME_NOT_A_VALUE = frozenset({"string", "null", "none", "true", "false", "required", "optional", "undefined",
                                   "unknown", "changeme", "placeholder", "value", "empty", "text", "varchar",
                                   "your_username", "yourusername", "my_username", "myusername", "username_here",
                                   "ok", "no", "na", "yes", "on", "off", "nil", "tbd", "todo"})


_JSON_EXAMPLE_RE = _lazy(r"(?i)[\"']examples?[\"']\s*:\s*[\[{]")


def _under_example_key(text: str, pos: int) -> bool:
    """Whether the label at pos sits inside an `example:` or `examples:` value: one of its YAML ancestors (each nearest
    line above with less indentation) is that key, or an `"example": {` / `"examples": [` before it on its line is
    still open. The look is bounded (200 characters of the line, 40 lines up), so a long line costs no more."""
    start = text.rfind("\n", 0, pos) + 1
    head_from = max(start, pos - 200)
    for m in _JSON_EXAMPLE_RE.finditer(text, head_from, pos):
        rest = text[m.end() - 1:pos]
        if rest.count("{") + rest.count("[") > rest.count("}") + rest.count("]"):
            return True
    line_head = text[start:pos] if pos - start <= 200 else ""
    indent = len(line_head) - len(line_head.lstrip(" ")) if line_head else 0
    end = start - 1
    for _ in range(40):
        if end <= 0 or indent == 0:
            return False
        prev_start = max(text.rfind("\n", 0, end) + 1, end - 200)
        line = text[prev_start:end]
        end = prev_start - 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        ind = len(line) - len(line.lstrip(" "))
        if ind < indent:
            if _EXAMPLE_KEY_RE.fullmatch(line.strip().lstrip("- ")):
                return True
            indent = ind       # the next ancestor is above this one
    return False


def _username_value_ok(v: str, quoted: bool, sep: str) -> bool:
    """Whether the whole value after a user-name label reads as a person's account name (see _USERNAME_LABEL_RE)."""
    low = v.lower()
    core = low.strip("._-")
    if not _USERNAME_SHAPE_RE.fullmatch(v) or not any(c.isalpha() for c in core) or len(core) < 2:
        return False
    bare = re.sub(r"[-_.]?\d+$", "", low)     # default_reader01, database_owner2: the digits of a numbered role
    if low in SERVICE_USERS or bare in SERVICE_USERS or _USERNAME_SERVICE_RE.match(low) or low.startswith("__") \
            or core in _USERNAME_NOT_A_VALUE or core in PLACEHOLDER_NAMES or low.startswith("system:") \
            or bare.endswith(_USERNAME_NOT_A_NAME_END):
        return False
    if low.startswith(_USERNAME_CODE_START):
        return False
    # an attribute in code, not a value: `username = account.name`, `username=authn.principal`
    if not quoted and re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", v) and (
            sep.strip() == "=" and sep != "=" or v.rsplit(".", 1)[1].lower().endswith(tuple(_USERNAME_ATTRIBUTE_END))):
        return False   # authn.userPrincipalName: the last part ends in a field word
    # a field or a role of dictionary words joined by `_` or `-` (local_account, fixture-account), not a person; a
    # dot joins a person's names (hunter.king42), and a part under three letters (js42) is no word
    if "." in core or "@" in core:
        return True
    words = [w for w in re.split(r"[_+\\/-]+", re.sub(r"\d+$", "", core)) if w]
    return not (all(w.isalpha() and len(w) >= 3 for w in words) and _reads_as_words(" ".join(words), every=True))


# the value of an i18n file or a form schema, not a name: the label in another language (first_name: Vorname) and the
# words of a type, a case or an option
# the translations of a name label: a text whose name fields hold these is an i18n file or a form schema
_NAME_LABEL_TRANSLATIONS = frozenset({
    "firstname", "lastname", "surname", "forename", "givenname", "familyname", "middlename", "name", "vorname",
    "nachname", "familienname", "rufname", "prénom", "prenom", "nom", "nombre", "apellido", "apellidos", "nome",
    "cognome", "prenome", "sobrenome", "voornaam", "achternaam", "förnamn", "fornamn", "efternamn", "imię", "imie",
    "nazwisko", "etunimi", "sukunimi", "fornavn", "etternavn", "efternavn", "jméno", "jmeno", "příjmení", "prijmeni",
    "keresztnév", "vezetéknév", "ad", "soyad", "soyadı", "patronymic"})
# a word that starts a validation message or a changelog line after a name label
_NAME_SENTENCE_START = frozenset({"too", "may", "was", "renamed", "must", "should", "cannot", "is", "not"})
# a lower-case word right after the value on the same line: the value starts a sentence
_WORD_AFTER_RE = _lazy(r"[ \t]+[a-zäöüßàâçéèêëîïôûùüÿñ]{2,}")
_NAME_LABEL_VALUES = frozenset({
    "firstname", "lastname", "surname", "forename", "givenname", "familyname", "middlename", "name", "vorname",
    "nachname", "familienname", "rufname", "prénom", "prenom", "nom", "nombre", "apellido", "apellidos", "nome",
    "cognome", "prenome", "sobrenome", "voornaam", "achternaam", "förnamn", "fornamn", "efternamn", "imię", "imie",
    "nazwisko", "etunimi", "sukunimi", "fornavn", "etternavn", "efternavn", "jméno", "jmeno", "příjmení", "prijmeni",
    "keresztnév", "vezetéknév", "ad", "soyad", "soyadı", "unicode", "lowercase", "uppercase", "titlecase", "asc",
    "desc", "latin", "validator", "sanitizer", "enum", "alphanumeric", "alpha", "patronymic", "untitled", "pydantic",
    "joi", "yup", "zod", "deprecated", "removed", "normalized", "normalised", "translated", "pseudonymized",
    "pseudonymised", "capitalized", "capitalised", "trimmed", "hidden", "visible", "editable", "default", "string",
    "text", "unknown", "anonymous", "texte", "zeichenfolge", "zeichenkette", "chaîne", "chaine", "cadena", "testo",
    "tekst", "sträng", "strang", "ciąg", "teksto", "zahl", "número", "numero", "nummer", "liczba", "erforderlich",
    "obligatoire", "requis", "facultatif", "optionnel", "opcional", "obbligatorio", "facoltativo", "verplicht",
    "optioneel", "wymagane", "opcjonalne", "obligatorisk", "valfri", "vazio", "vacío", "vide", "leer", "pusty",
    "prenume", "nume", "ime", "prezime", "priimek", "vardas", "pavardė", "pavarde", "vārds", "vards", "uzvārds",
    "uzvards", "eesnimi", "perekonnanimi", "fornafn", "eftirnafn", "cognoms", "nom de pila", "nama", "meno",
    "priezvisko", "jina", "input", "textfield", "textbox", "textarea", "attribute", "multiline", "nvarchar",
    "lowercased", "uppercased", "confidential", "pii", "sensitive", "label", "placeholder", "field", "value"})
# the surnames and given names of documentation, which the name rule finds as a pair
_PLACEHOLDER_NAME_WORDS = frozenset({"doe", "roe", "mustermann", "musterfrau", "muster", "bloggs", "normalverbraucher",
                                     "john", "jane", "max", "erika", "alice", "bob", "foo", "bar", "baz", "qux"})
# a street line after an address label or a verb of residence, without a city or a postcode (Nemotron-PII,
# 2026-10-16: "street address: 4821 Maple Ridge Drive", "resides at 77 Harbour Lane"). The company check of the
# address label holds: a company, an office or a public place on the line keeps the address text
# a street name word: a capital word or an ordinal (123 5th Avenue)
_STREET_LINE = (r"(?:\d{1,6}[A-Za-z]?(?:-\d{1,4})? (?:(?:[A-Z][A-Za-z'.-]{0,30}|\d{1,3}(?:st|nd|rd|th)) ){1,4}"
                r"(?:" + _STREET[3:-1]
                + r"|Circle|Cir|Parkway|Pkwy|Trail|Trl|Loop|Pike|Alley|Grove|Gardens|Heights|Mews)\.?"
                r"(?:,? (?:Apt|Apartment|Suite|Unit|Flat|#)\.? ?[A-Za-z0-9-]{1,6})?"
                r"|[A-ZÄÖÜ][\wäöüß-]{1,40}(?:straße|strasse|str\.|weg|gasse|platz|allee|ring|damm) \d{1,4}[a-z]?"
                r"|(?:Calle|Avenida|Via|Viale|Piazza|Rua|Carrer) (?:[A-ZÀ-Þ][\wà-ÿ'’-]{1,30} |d[aeio]l?l?[aeo]? |de "
                r"|das? |dos? ){1,5}?\d{1,5}[A-Za-z]?)(?![\w-])")
_STREET_LABEL_RE = _lazy(
    r"(?i)(?<![a-z_])(?:(?:street|home|residential|mailing|postal|billing|shipping|delivery|permanent|current)[ _-]?"
    r"address|address(?: on file)?|anschrift|wohnadresse|wohnanschrift|adresse|domicilio|direcci[oó]n|indirizzo"
    r"|endere[cç]o|adres)[\"']?[ \t]{0,3}(?:is[ \t]{1,3}|[:=][ \t]{0,3})[\"']?[ \t]{0,2}(?-i:(" + _STREET_LINE + "))"
    r"|(?<![a-z])(?:resides?|residing|reside|lives?|living|domiciled|wohnt|wohnhaft)"
    r"(?: (?:at|in|on|im|am|in der|an der))?[ \t]{1,3}(?-i:(" + _STREET_LINE + "))")


# the state of a form field after its label, not a name: the word list holds the stems only (require, mandate)
_FIELD_STATES = frozenset({"required", "optional", "mandatory", "nullable", "readonly", "redacted", "masked",
                           "anonymized", "anonymised", "withheld", "missing", "blank", "empty", "varchar", "str", "int",
                           "char", "pflicht", "pflichtfeld", "leer", "obligatoire", "obligatorio", "obbligatorio"})


def _no_marks(w: str) -> str:
    """w without its accents (Ạnh: Anh), so the vowel check of _reads_as_words sees the vowels of Vietnamese."""
    import unicodedata
    return "".join(c for c in unicodedata.normalize("NFD", w) if not unicodedata.combining(c))


def _inflected_word(w: str) -> bool:
    """An English word in an inflected form (required, hashed, encrypted, nullable) or the state of a field."""
    from .core import _word_set
    words = _word_set()
    if w in _FIELD_STATES:
        return True
    for end, back in (("ied", "y"), ("ed", ""), ("ed", "e"), ("able", ""), ("able", "e"), ("ly", ""), ("ing", "")):
        if w.endswith(end) and len(w) - len(end) >= 3 and w[:-len(end)] + back in words:
            return True
    return False


# the address of a business partner, not of a person (Gretel, 2026-10-16: "Employer address:", "Industries\nAddress:")
_BUSINESS_RE = _lazy(r"(?i)(?<![a-z])(?:employer|industries|enterprises?|holdings?|vendor|supplier|business"
                     r"|organi[sz]ation|agency|institution|clinic|practice|pharmacy|lender|insurer|warehouse|depot|factory"
                     r"|distribution|fulfil?ment"
                     r"|bank(?![ _-]?(?:account|details|statement|transfer|card|code|holiday|balance|info)))(?![a-z])")
_BANK_ACCOUNT_RE = _lazy(r"(?i)bank[ _-]?(?:account|details|statement|transfer|card|code|holiday|balance|info)")


def _not_a_home(text: str, a: int, b: int) -> bool:
    """A company, office or public place word in text[a:b]; "bank account" names a person's account, not a bank."""
    for m in _NOT_A_HOME_RE.finditer(text, a, b):
        if not (m.group().lower() == "bank" and _BANK_ACCOUNT_RE.match(text, m.start())):
            return True
    return False


# an address of a machine, a mail box or a wallet, not a street (IP address: 10 Network Drive)
_NOT_A_STREET_LABEL_RE = _lazy(r"(?i)(?<![a-z])(?:ip|ipv[46]|mac|e-?mail|server|listen|bind|remote|local|web|wallet"
                               r"|contract|memory|base|host|proxy|gateway|broadcast|multicast|network|bitcoin"
                               r"|ethereum|ens)[ _-]?$")
# a placeholder street of docs, seed files and fixtures (123 Main Street, 1 Infinite Loop, Musterstraße 1)
_PLACEHOLDER_STREET_RE = _lazy(r"(?i)^\s*(?:123\s+main\s+st(?:reet|\.)?\b|1\s+infinite\s+loop\b"
                                r"|[\w-]*(?:muster|beispiel)[\w-]*\s*\d*\b)")
# the parent key of a YAML or TOML block names a machine (server:\n  address: …): its address is no street
_PARENT_NOT_A_STREET_RE = _lazy(r"(?i)(?<![a-z])(?:server|servers|host|hosts|listen|bind|network|proxy|gateway|upstream"
                                r"|backend|endpoint|node|peer|cluster|smtp|mail|dns|ldap)[\w-]*[ \t]*:[ \t]*\r?\n"
                                r"(?:[ \t]+[\w-]+[ \t]*:[^\n]*\r?\n){0,3}[ \t]+$")
# a thing that "lives at" a place in prose about code (the server lives at, the function lives in)
# the thing word stands right before the verb: "Dana, our office manager, lives at" is a person
_THING_SUBJECT_RE = _lazy(r"(?i)(?<![a-z])(?:server|service|function|file|files|code|class|module|config|repo"
                          r"|repository|package|bucket|app|process|daemon|component|method|helper|store"
                          r"|shop|office|company|business|logic|variable|api|database|db|endpoint|library|sdk|docs"
                          r"|documentation"
                          r"|site|website|page|bot|script|binary|image|container|cluster|host|shard|handler|worker|job|task)"
                          r"[ \t]{1,3}$")
_HOME_LABEL_RE = _lazy(r"(?i)home|residential|permanent|wohn|resid|liv|domicil")
_STREET_LABEL_WORDS = ("address", "anschrift", "adresse", "domicilio", "direcci", "indirizzo", "endere", "adres",
                       "resid", "live", "living", "domiciled", "wohn")
_PHONE_WORDS = ("phone", "tel", "mobil", "cell", "fax", "handy", "portable", "rufnummer", "whatsapp", "hotline",
                "contact", "call", "reach", "text")
_ADDRESS_WORDS = ("address", "adr", "ship", "property", "lives", "endere", "direcci", "adresse", "location")
_IN_ADDRESS_RE = _lazy(r"\b\d{1,4}(?:/\d{1,4})?, [^\n]{10,90}?, [A-Z][a-z]+ \d{6}\b")
_NONLATIN = "Ͱ-ϿЀ-ӿ֐-׿؀-ۿऀ-ॿঀ-৿"
_CJK_NAME = "一-鿿가-힯぀-ヿ"
# labels that name a person and nothing else; `name`, `owner` and `admin` also name a product, a language or a group
_NONLATIN_LABEL_RE = _lazy(
    r"(?i)(?:(?<![a-z_])(?:full[ _-]?name|native name|(?:employee|patient|customer|contact|recipient)[ _-]?name"
    r"|beneficiary)[\"']?[ \t]{0,3}[:=]?"
    r"|^fn" + _VCARD_PARAMS + r"[\"']?[ \t]{0,3}[:=])[ \t]{0,3}[\"']?"
    r"((?:[" + _NONLATIN + r"]{2,20}(?: [" + _NONLATIN + r"]{2,20}){1,3})|[" + _CJK_NAME + r"]{2,5})(?![\w])", re.M)
# names of a language in its own script: a locale table is no person
_AUTONYMS = frozenset({"русский", "українська", "беларуская", "български", "српски", "македонски", "ελληνικά",
                       "עברית", "العربية", "فارسی", "اردو", "हिन्दी", "বাংলা", "中文", "简体中文", "繁體中文", "日本語",
                       "한국어", "русский язык", "қазақ тілі"})
_PHONE_URL_RE = _lazy(r"(?i)(?<![a-z])(?:phone|tel|mobile|msisdn|cell)[\w-]{0,10}=(%2B\d{7,15})(?!\d)")
# a phone number in its national form after a phone word (Nemotron-PII and Gretel, 2026-10-16: 999-999-9999 after
# "phone number:", 99 9999 9999 after "telefoonnummer:"). A label (phone, Telefon, téléphone, + number, then `:`, `=`
# or "is") takes any national form; a verb (call, reach … at, contact … at) and a label with words between them take a
# North American number only, whose shape is rare outside a phone number
_PHONE_LABEL_WORDS = (r"phone|telephone|tel|mobile?|mobil(?:e|nummer|telefon)?|cell(?:ular|phone)?|fax|handy"
                      r"|telefon(?:nummer|o)?|t[ée]l[ée]phone|tel[ée]fono|telefoon(?:nummer)?|telefone|portable"
                      r"|cellulare|rufnummer|whatsapp|hotline|contact[ _-]?(?:number|no)")
_PHONE_NUMBER_WORD = r"(?:[ _-]?(?:number|no\.?|nr\.?|nummer|num[ée]ro|n[úu]mero|numero|#))?"
_PHONE_TIGHT_RE = _lazy(r"(?i)(?<![\w-])(?:" + _PHONE_LABEL_WORDS + r")" + _PHONE_NUMBER_WORD + r"(?![\w-])\.?[\"']?"
                        r"(?:[ \t]{0,3}(?:is|ist|est|es|è|é|:|=|-|–)[ \t]{0,3}|[ \t]{1,3})[\"']?[ \t]{0,2}"
                        r"(\+?(?:\(\d{1,8}\)|\d{1,8})(?:[ .\-/]{1,2}(?:\(\d{1,8}\)|\d{1,8})){0,5})(?![\w+]|[.,/:-]\d)")
_PHONE_LOOSE_RE = _lazy(r"(?i)(?<![\w-])(?:" + _PHONE_LABEL_WORDS + r"|call(?:ed)?|reach(?:ed)?(?: \w{1,12}){0,2} at"
                        r"|contact(?:ed)?(?: \w{1,12}){0,2} at|text(?:ed)?)(?![\w-])[^\n\d+]{0,30}?(?<![\w+.-])"
                        r"((?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?[2-9]\d{2}[-. ]\d{4})(?![\w-]|[.,:]\d)")
_PHONE_DATE_RE = _lazy(r"\d{4}[-./]\d{1,2}[-./]\d{1,2}|\d{1,2}[-./]\d{1,2}[-./]\d{2,4}|\d{1,2}:\d{2}")
_ISO_DATE_RE = _lazy(r"(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)")
# a North American number (3-3-4); it needs region us or ca, as phone-us-national (0.6.24)
_NANP_SHAPE_RE = _lazy(r"(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?[2-9]\d{2}[-. ]\d{4}")
# a count with a space between thousands (3 412 908 users, 1 000 000) and a list of small numbers (4 8 15 16 23 42)
# fullmatch on a value of _PHONE_TIGHT_RE only (6 groups at most): the last branch is quadratic on a long text
_COUNT_RE = _lazy(r"\d{1,2}(?: \d{3})+|\d{1,3}(?: \d{3})* 000(?: \d{3})*"
                  r"|[1-9]\d*(?:[ .\-/]+\d+)*[ .\-/]\d(?:[ .\-/]\d+)*")
# the words between a phone label and a number that end in a colon: a phone word or its number word ends them
_GAP_SEP_RE = _lazy(r"[:=]| [-–] ")
_PAREN_END_RE = _lazy(r"[ \t]*\([^()\n]{0,15}\)[ \t]*$")   # Phone (work): 938-274-6157
_PHONE_GAP_END_RE = _lazy(r"(?i)(?:" + _PHONE_LABEL_WORDS + r"|number|no\.?|nr\.?|#|num[ée]ro|n[úu]mero|nummer)$")


def _national_phone_ok(v: str) -> bool:
    """7 to 15 digits in groups: not a date, a time, a version, an IP address, a range of years or a placeholder. A
    single run needs 10 to 12 digits, a pair of groups 9 or more; dots only in the North American 3.3.4 or in pairs."""
    d = re.sub(r"\D", "", v)
    groups = re.findall(r"\d+", v)
    if not 7 <= len(d) <= 15 or _placeholder_digits(v) or _PHONE_DATE_RE.fullmatch(v.strip("+()")):
        return False
    if _ISO_DATE_RE.search(v) or (not v.startswith("+") and _COUNT_RE.fullmatch(v)):
        return False
    if len(groups) == 1 and not 10 <= len(d) <= 12:
        return False
    if len(groups) >= 3 and all(len(g) == 4 for g in groups) and not v.startswith(("+", "0")):
        return False   # Telefon 2024 2025 2026, Cell 1024 2048 4096: years and sizes (review, 2026-10-17)
    if len(groups) == 2 and len(d) < 9:
        return False
    if len(groups[-1]) >= 4 and _placeholder_digits(groups[-1]):
        return False   # 0151 1111111, 030 12345678: a subscriber number of one digit or of a run is a placeholder
    if "." in v and not (re.fullmatch(r"\(?\d{3}\)?\.\d{3}\.\d{4}", v)
                         or all(len(g) == 2 for g in groups[1:])):
        return False
    return _nanp_ok(v)


def _nanp_ok(v: str) -> bool:
    """A North American number (ten digits, or 1 and ten): the area code and the exchange start with 2 to 9, and the
    fictional 555-0100 to 555-0199 is an example."""
    d = re.sub(r"\D", "", v)
    if len(d) == 11 and d[0] == "1":
        d = d[1:]
    elif len(d) != 10 or v.lstrip("(").startswith("0") or v.startswith("+"):
        return True   # not North American: its own country's rules
    if len(re.findall(r"\d+", v)) == 2 and not v.startswith("("):
        return True   # 99 9999 9999 and the like: a national form of another country
    return d[0] not in "01" and d[3] not in "01" and not (d[3:6] == "555" and d[6:8] == "01")


_PHONE_WRAP_RE = _lazy(r"(?<![\w+])\+(?!0)\d{1,3}[ \-]?\d{2,5}(?:[ \-]\d{2,5}){0,2}-\n[ \t]{0,4}\d{2,5}"
                            r"(?:[ \-]\d{2,5}){0,3}(?![\w.]\d|\w)")


def _line_back(text: str, pos: int, most: int = 120) -> int:
    """The start of the line of `pos`, at most `most` characters back: the search itself is bounded, so a long line of
    hits stays linear (review of 0.6.24)."""
    lo = max(0, pos - most)
    nl = text.rfind("\n", lo, pos)
    return nl + 1 if nl >= 0 else lo


# the structured properties of a vCard (RFC 6350), one per line, in any group (item1.ADR, home.ADR): ADR holds
# box;extended;street;locality;region;code;country, N holds family;given;additional;prefix;suffix. Contact exports
# of Apple, Google and Outlook write the address in its fields, so the address label never saw it (review of 0.6.25).
# A line starts after a newline, after spaces (YAML, a heredoc) or after an escaped \n (a vCard in a JSON string), and
# its value ends there too
_VCARD_LINE = r"(?im)(?:^|(?<=\\n))[ \t]*(?:[a-z0-9-]{1,64}\.)?"
_VCARD_VALUE = r":((?:\\[^nr]|[^\n\r\\\"]){3,400})"
_VCARD_ADR_RE = _lazy(_VCARD_LINE + r"ADR" + _VCARD_PARAMS + _VCARD_VALUE)
_VCARD_N_RE = _lazy(_VCARD_LINE + r"N" + _VCARD_PARAMS + _VCARD_VALUE)
_VCARD_BDAY_RE = _lazy(_VCARD_LINE + r"BDAY" + _VCARD_PARAMS + r":(\d{8})(?:T[\dZ:+-]{1,20})?(?![\w-])")
_VCARD_FORMS = ("address-vcard-fields", "name-vcard-n", "birth-date-vcard-compact")
# a vCard property on a line of its own, without its BEGIN:VCARD: grep output (contacts.vcf:12:ADR;TYPE=home:…) or a
# line copied from a card. After a .vcf file name the line is a vCard line. Without one it needs the structure that
# no other format writes: ADR in capitals with a parameter of a card (TYPE, PREF, HOME) and an empty box and extended
# field, N in capitals with its five fields and a title or nothing as the prefix, BDAY with a parameter of a card
# (BDAY:20240101 alone is no card)
_VCARD_KIND = {"ADR": "address-vcard-fields", "N": "name-vcard-n", "BDAY": "birth-date-vcard-compact"}
_VCARD_BDAY_VALUE_RE = re.compile(r"(\d{8})(?:T[\dZ:+-]{1,20})?(?![\w-])")
_VCARD_BARE_RE = _lazy(r"(?im)^(?:((?:[a-z]:\\)?[^\s:]{1,200}):(?:\d{1,9}[:-])?|\d{1,9}[:-])?[ \t]*"
                       r"(?:[a-z0-9-]{1,64}\.)?"
                       r"(ADR|N|BDAY)(" + _VCARD_PARAMS + r")" + _VCARD_VALUE)
# the cheap check before _VCARD_BARE_RE: a property name before its parameters or its colon at the start of a line
_VCARD_BARE_HINT_RE = re.compile(r"(?im)(?:^|:)[ \t]*(?:[a-z0-9-]{1,64}\.)?(?:ADR|N|BDAY)[;:]")
# a parameter of a card; TYPE with a type of an address or a date (TYPE=cache is a config key)
_VCARD_PARAM_NAME_RE = re.compile(r"(?i);(?:type=\"?(?:home|work|pref|postal|parcel|dom|intl|other)(?![\w-])"
                                  r"|pref|label|charset|language|value|altid|pid|calscale|home|work|postal|parcel"
                                  r"|dom|intl)(?![\w-])")
_VCARD_BARE_WORDS_RE = re.compile(r"(?i)adr|n[:;]|bday")
_VCARD_TITLE_RE = re.compile(r"(?i)(?:dr|prof|mr|mrs|ms|mx|miss|sir|herr|frau|mme|mlle|m|sr|sra|sig|dott|ing|mag)\.?"
                             r"(?:[ ,]+(?:dr|prof|med|rer|nat|phil|ing)\.?){0,3}")
_VCARD_SUFFIX_RE = re.compile(r"(?i)(?:jr|sr|ii|iii|iv|phd|md|esq|msc|bsc|mba)\.?")


def _vcard_fields(value: str, start: int) -> list:
    """(start, end) of each field of a structured vCard value; a semicolon after a backslash stays in its field."""
    out, i, a = [], 0, 0
    while i < len(value):
        if value[i] == "\\":
            i += 2
            continue
        if value[i] == ";":
            out.append((start + a, start + i))
            a = i + 1
        i += 1
    out.append((start + a, start + len(value)))
    return out


# BEGIN:VCARD at the start of a line, after an escaped \n or after a quote (a card in a JSON string): in a sentence
# (the markers are BEGIN:VCARD and END:VCARD) it starts no card
_VCARD_BEGIN_LINE_RE = re.compile(r"(?m)(?:^[ \t]*|(?<=\\N)[ \t]*|(?<=[\"'>]))BEGIN:VCARD")
_VCARD_END_LINE_RE = re.compile(r"(?im)(?:^|(?<=\\n))[ \t]*END:VCARD")


def _vcard_spans(text: str) -> list:
    """(start, end) of each vCard: from BEGIN:VCARD to its END:VCARD or the end of the text. A line counts only
    inside one: `ADR: 0012;Accepted;Use Postgres 16;…` in the docs and `N:Europe;Asia;…` in a config are no vCard
    (review of 0.6.25)."""
    up = text.upper()
    out = []
    for m in _VCARD_BEGIN_LINE_RE.finditer(up):
        if out and m.start() < out[-1][1]:
            continue
        e = _VCARD_END_LINE_RE.search(text, m.end())   # at the start of a line: NOTE:… END:VCARD … is a value
        out.append((m.start(), len(text) if e is None else e.start()))
    return out


def _vcard_bare(text: str, m, val) -> bool:
    """A line outside a vCard that is one of its properties (see _VCARD_BARE_RE)."""
    if m.group(1) and m.group(1).lower().endswith(".vcf"):
        return True
    prop = m.group(2)
    if prop != prop.upper():
        return False
    if prop.upper() != "N" and not _VCARD_PARAM_NAME_RE.search(m.group(3)):
        return False   # ADR:;;Cache 2;Primary;;8080;prod is a config row: ADR and BDAY need a parameter of a card
    if prop.upper() == "BDAY":
        return True
    fields = _vcard_fields(m.group(4), m.start(4))
    if prop.upper() == "ADR":
        return (len(fields) == 7 and not val(fields[0]) and not val(fields[1])
                and bool(re.search(r"\d", val(fields[2])) and re.search(r"[^\W\d_]{3}", val(fields[2])))
                and bool(re.search(r"[^\W\d_]", val(fields[3]))) and bool(val(fields[5]) or val(fields[6])))
    if len(fields) != 5:
        return False
    extra, title, suffix = (val(f) for f in fields[2:])
    return ((not extra or bool(re.fullmatch(r"[^\W\d_][^\W\d_'’-]{0,30}\.?", extra)))
            and (not title or bool(_VCARD_TITLE_RE.fullmatch(title)))
            and (not suffix or bool(_VCARD_SUFFIX_RE.fullmatch(suffix))))


def _vcard_hits(text: str, want) -> list:
    out: list = []
    spans = _vcard_spans(text)
    import bisect   # here: the hooks pay for every module at import
    starts = [a for a, _ in spans]

    def inside(pos: int) -> bool:
        i = bisect.bisect_right(starts, pos) - 1
        return i >= 0 and pos < spans[i][1]

    def val(f) -> str:
        return text[f[0]:f[1]].strip()

    # (property, start and end of its value): the lines of each vCard, then the vCard lines outside one
    lines: list = []
    if spans:
        for prop, rx in (("ADR", _VCARD_ADR_RE), ("N", _VCARD_N_RE)):
            if _VCARD_KIND[prop] in want:
                lines += [(prop, m.start(1), m.end(1)) for m in rx.finditer(text) if inside(m.start())]
        if "birth-date-vcard-compact" in want:
            lines += [("BDAY", m.start(1), m.end(1)) for m in _VCARD_BDAY_RE.finditer(text) if inside(m.start())]
    if ";" in text or ".vcf" in text.lower():
        for m in _VCARD_BARE_RE.finditer(text):
            prop = m.group(2).upper()
            if _VCARD_KIND[prop] in want and not inside(m.start(2)) and _vcard_bare(text, m, val):
                lines.append((prop, m.start(4), m.end(4)))
    for prop, a, b in lines:
        if prop == "ADR":
            fields = _vcard_fields(text[a:b], a)
            filled = [f for f in fields if val(f)]
            if len(fields) != 7 or len(filled) < 2:
                continue   # a vCard address has seven fields
            # a number in the box, the extended or the street field, or a postal code: Rose Cottage;Dunmore;Y35 X2K
            if any(re.search(r"\d", val(f)) for f in fields[:3]) or val(fields[5]):
                out.append((filled[0][0], filled[-1][1], "address-vcard-fields", ADDRESS))
        elif prop == "N":
            fields = _vcard_fields(text[a:b], a)
            if len(fields) < 2:
                continue   # vCard 2.1 may write family;given alone
            family, given = val(fields[0]), val(fields[1])
            if family and given and _name_ok(given + " " + family) and not _reads_as_words(given + " " + family):
                end = fields[2][1] if len(fields) > 2 and val(fields[2]) else fields[1][1]   # a middle name
                out.append((fields[0][0], end, "name-vcard-n", NAME))
        else:
            m = _VCARD_BDAY_VALUE_RE.match(text, a, b)
            v = m.group(1) if m else ""
            if v and _a_date(v) and _past_year(v[:4]) and not _placeholder_digits(v, dates=True):
                out.append((m.start(1), m.end(1), "birth-date-vcard-compact", BIRTH_DATE))
    return out


def _cut_at_a_word(v: str) -> str:
    """An ID ends before a word that follows its digits: `20231115 LIMIT 10` is a value and an SQL clause."""
    parts = v.split(" ")
    for i in range(1, len(parts)):
        if parts[i].isalpha() and len(parts[i]) >= 3 and any(c.isdigit() for c in parts[i - 1]):
            return " ".join(parts[:i])
    return v


def _a_date(v: str) -> bool:
    """Eight digits that read as a day of 1900 to 2099 (YYYYMMDD)."""
    return bool(re.fullmatch(r"(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])", v))


# a password after the password word and a space or a short connector ("use the password <v>", "a password such as
# <v>", "and password <v>"), in a tool result. The prose rules take only a value that is no word of a sentence after
# a plain space, so `Word@2024` stayed in the clear (Benchmark V1, Nemotron: 1,440 of 4,500 missed passwords had this
# form). Only a value with a letter, a digit and a sign: a word, a version (iPhone15), a hash name (SHA256-Hash) and
# an e-mail address stay text
_PW_REFERENCE_RE = _lazy(r"(?i)(?<![\w-])(?:password|passwd|passphrase|pwd)s?"
                         r"(?:[ \t]+(?:such[ \t]+as|like|e\.g\.,?|for[ \t]+example,?|of|set[ \t]+to|to))?"
                         r"[ \t]+[\"'`]?([^\s\"'`]{6,64})")
_PW_WITH_SIGN_RE = _lazy(r"(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$!%&*?])[A-Za-z0-9@#$!%&*?._+=~^-]{6,64}")
_EMAIL_SHAPE_RE = _lazy(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")
# a reference after the word: a pull request or issue (#PR-1234, #4711), a ticket (OPS-1234)
_PW_REFERENCE_VALUE_RE = _lazy(r"#?[A-Z][A-Z0-9]{0,9}-\d{1,7}|#\d{1,7}")


def _form_hits(text: str, channel: str, regions: tuple, want, company=None) -> list:
    out = []
    if "secret-password-with-sign" in want and ("pass" in text.lower() or "pwd" in text.lower()):
        for m in _PW_REFERENCE_RE.finditer(text):
            v = m.group(1).rstrip(".,;:)")   # a stop of the sentence; `!` and `?` end many passwords and stay
            if len(v) >= 6 and _PW_WITH_SIGN_RE.fullmatch(v) and not _EMAIL_SHAPE_RE.fullmatch(v) \
                    and not _PW_REFERENCE_VALUE_RE.fullmatch(v) \
                    and not v.startswith(("$", "%", "{", "<", "*")):
                out.append((m.start(1), m.start(1) + len(v), "secret-password-with-sign", "SECRET"))
    if "secret-add-mask" in want and "::add-mask::" in text:
        for m in _ADD_MASK_RE.finditer(text):
            # ::add-mask:: declares its value a secret: a password made of words stays one
            if _random_value(m.group(1)):
                out.append((m.start(1), m.end(1), "secret-add-mask", "SECRET"))
    if "secret-shared-access-key" in want and "haredaccesskey=" in text.lower():
        for m in _SAS_KEY_RE.finditer(text):
            v = m.group(1)
            if _random_value(v, 16) and not re.fullmatch(r"[A-Z0-9_]+", v) and not _words_inside(v):
                out.append((m.start(1), m.end(1), "secret-shared-access-key", "SECRET"))
    if "secret-postman-variable" in want and "\"value\"" in text:
        for m in _KV_SECRET_RE.finditer(text):
            name, v = m.group(1), m.group(2)
            strong = bool(set(_name_parts(name)) & {"password", "passwd", "pwd", "passphrase"})
            if _secret_name(name) and not _META_NAME_RE.search(name.rstrip("0123456789")) and _random_value(v) \
                    and "://" not in v and not _HOST_RE.fullmatch(v) and (strong or not _words_inside(v)):
                out.append((m.start(2), m.end(2), "secret-postman-variable", "SECRET"))
    low = text.lower()
    if "secret-hex48-after-token-word" in want and any(w in low for w in ("token", "code", "secret", "key")):
        for m in _HEX48_RE.finditer(text):
            v = m.group(2)
            if _DIGEST_WORD_RE.search(text, max(0, m.start() - 16), m.start(2)):
                continue   # a hash: cache key, key fingerprint, the digest of a build
            if sum(c.isdigit() for c in v) >= 4 and sum(c.isalpha() for c in v) >= 4:
                out.append((m.start(2), m.end(2), "secret-hex48-after-token-word", "SECRET"))
    if channel != "tool":
        return out
    if "secret-in-login-code" in want:
        for rx, g in ((_REDIS_AUTH_RE, 1), (_LOGIN_CALL_RE, 3), (_OP_FIELDS_RE, 1)):
            for m in rx.finditer(text):
                v = m.group(g)
                if _complex(v) and not v.startswith(_NOT_A_VALUE_START) and "{{" not in v:
                    out.append((m.start(g), m.end(g), "secret-in-login-code", "SECRET"))
        for m in _SQL_CREDS_RE.finditer(text):
            cells = list(re.finditer(r"'([^'\n]{6,128})'", m.group(1)))
            if cells and _complex(cells[-1].group(1)) and not cells[-1].group(1).startswith(_NOT_A_VALUE_START):
                c = cells[-1]
                out.append((m.start(1) + c.start(1), m.start(1) + c.end(1), "secret-in-login-code", "SECRET"))
    if "secret-after-user-slash" in want and " / " in text:
        for m in _USER_SLASH_RE.finditer(text):
            v = m.group(1)
            if _complex(v) and any(c.isdigit() for c in v) and "/" not in v and not _words_inside(v):
                out.append((m.start(1), m.end(1), "secret-after-user-slash", "SECRET"))
    if "id-number-fhir-identifier" in want and "\"system\"" in text:
        for m in _FHIR_RE.finditer(text):
            v = m.group(2)
            if not _in_identifier_array(text, m.start()):
                continue   # a FHIR identifier stands in an `identifier` array; `{"system": "license", ...}` is metadata
            if _FHIR_SYSTEM_RE.search(m.group(1)) and sum(c.isdigit() for c in v) >= 5 and not _VERSION_RE.match(v) \
                    and not v.startswith(_NOT_A_VALUE_START) and not _placeholder_digits(v):
                out.append((m.start(2), m.end(2), "id-number-fhir-identifier", ID_NUMBER))
    if any(w in low for w in ("member", "record", "patient", "account", "insurance", "nid", "dl")):
        if "id-number-after-record-label" in want:
            for m in _RECORD_LABEL_RE.finditer(text):
                v = _cut_at_a_word(m.group(1))
                digits = sum(c.isdigit() for c in v)
                if _a_date(v):
                    continue   # member_id = 20231115: a day, not a member
                if re.match(r"(?i)(?:account|record)", m.group(0)) and v.replace(" ", "").isdigit():
                    continue   # an AWS account id, a row counter: digits alone after account or record
                if m.group(0).startswith("nid") and digits < 8:
                    continue   # a node id of a CMS ("nid": "10234"); a national id has eight digits or more
                if re.match(r"(?i)account", m.group(0)) and digits < 6:
                    continue   # a ticket key after account (REL-20481): an account number has six digits or more
                if digits >= 5 and not (v.isdigit() and len(v) >= 17) and not _placeholder_digits(v):
                    out.append((m.start(1), m.start(1) + len(v), "id-number-after-record-label", ID_NUMBER))
        if "id-letters-after-label" in want:
            for m in _ID_LETTERS_RE.finditer(text):
                v = m.group(1)
                nd = sum(c.isdigit() for c in v)
                # letters after a digit (MBR-4XK7Q2): TEAM-ALPHA-2024 and PLAN-2024 are names and years
                if nd and sum(c.isalpha() for c in v) >= 2 and re.search(r"\d[A-Z]", v) \
                        and not (nd >= 3 and _placeholder_digits(v)):
                    out.append((m.start(1), m.end(1), "id-letters-after-label", ID_NUMBER))
        if "id-number-in-member-parentheses" in want:
            for m in _MEMBER_PAREN_RE.finditer(text):
                v = m.group(1)
                # a member number mixes letters into its digits (ABC-4XY5Z6): TEAM-4821 and RUNNER-0042 are names
                if sum(c.isdigit() for c in v) >= 2 and re.search(r"\d[A-Z]", v):
                    out.append((m.start(1), m.end(1), "id-number-in-member-parentheses", ID_NUMBER))
    if ("id-number-under-sql-alias" in want or "address-under-sql-alias" in want) and "'" in text:
        for m in _SQL_ALIAS_RE.finditer(text):
            v, al = m.group(1), m.group(2).lower()
            if "addr" in al:
                if "address-under-sql-alias" in want and any(c.isdigit() for c in v) and "," in v \
                        and not _NOT_A_HOME_RE.search(v):
                    out.append((m.start(1), m.end(1), "address-under-sql-alias", ADDRESS))
            elif "id-number-under-sql-alias" in want and sum(c.isdigit() for c in v) >= 5 \
                    and not _placeholder_digits(v):
                out.append((m.start(1), m.end(1), "id-number-under-sql-alias", ID_NUMBER))
    if "address-jp-postcode" in want and "〒" in text:
        for m in _JP_ADDRESS_RE.finditer(text):
            line = _line_back(text, m.start())
            if not _JP_COMPANY_RE.search(text, line, m.end()):
                out.append((m.start(), m.end(), "address-jp-postcode", ADDRESS))
    if "address-after-label" in want and any(w in low for w in _ADDRESS_WORDS):
        for m in _ADDRESS_LABEL_RE.finditer(text):
            if re.match(r"(?i)adr(?![a-z])", m.group(1)) and not m.group(2):
                continue   # ADR alone is an architecture decision record; the vCard field is ADR:;;<street>, also
                #            with parameters (ADR;TYPE=home:;;<street>)
            v = m.group(3).strip()
            # the check for a company or a public place reads at most 120 characters of the line before the label:
            # unbounded, a long line of addresses took quadratic time (review of 0.6.24). Back to the start of a
            # JSON object was measured in 0.6.25 and left out: it also finds the employer in a person's record
            # (tests/test_company_address_window.py)
            line = _line_back(text, m.start())
            if (any(c.isdigit() for c in v) and "," in v and _HOUSE_RE.search(v)
                    and "://" not in v and not re.search(r"\d+\.\d+\.\d+|:\d{2,5}\b|[{}<>$()=_\[\]#@]", v)
                    and not _NOT_AN_ADDRESS_RE.search(v)):
                s0 = m.start(3) + (len(m.group(3)) - len(m.group(3).lstrip()))
                if not _NOT_A_HOME_RE.search(text, line, m.end()):
                    out.append((s0, s0 + len(v), "address-after-label", ADDRESS))
                else:
                    _company_window(text, line, s0, s0 + len(v), "address-after-label", company)
    if any(f in want for f in _VCARD_FORMS) and ("VCARD" in text.upper() or (
            _VCARD_BARE_WORDS_RE.search(text) and _VCARD_BARE_HINT_RE.search(text))):
        out += _vcard_hits(text, want)
    if "address-in-form" in want and "in" in regions:
        for m in _IN_ADDRESS_RE.finditer(text):
            line = _line_back(text, m.start())
            if m.group().count(",") >= 3 and not _NOT_A_HOME_RE.search(text, line, min(len(text), m.end() + 80)):
                out.append((m.start(), m.end(), "address-in-form", ADDRESS))
    if "name-non-latin-after-label" in want and not text.isascii():
        for m in _NONLATIN_LABEL_RE.finditer(text):
            if m.group(1).lower() not in _AUTONYMS:
                out.append((m.start(1), m.end(1), "name-non-latin-after-label", NAME))
    if "phone-url-encoded" in want and "%2" in text.upper():
        for m in _PHONE_URL_RE.finditer(text):
            d = m.group(1)[3:]
            if 8 <= len(d) <= 15 and len(set(d)) > 2:
                out.append((m.start(1), m.end(1), "phone-url-encoded", PHONE))
    if "phone-after-phone-word" in want and any(w in low for w in _PHONE_WORDS):
        us = bool(_US_PHONE_REGIONS.intersection(regions))
        for rx in (_PHONE_TIGHT_RE, _PHONE_LOOSE_RE):
            for m in rx.finditer(text):
                v = m.group(1).rstrip(" .-/")
                if _US_PHONE_RE.fullmatch(v) or (_NANP_SHAPE_RE.fullmatch(v) and not us):
                    continue   # (312) 846-2291 is phone-us-national's; a North American number needs us or ca
                gap = text[m.start():m.start(1)]
                sep = [x.start() for x in _GAP_SEP_RE.finditer(gap)] if rx is _PHONE_LOOSE_RE else ()
                if sep and not _PHONE_GAP_END_RE.search(_PAREN_END_RE.sub("", gap[:sep[-1]]).rstrip(" )\"'")):
                    continue   # Mobile build artifact: 938-274-6157: the words before the colon name no phone
                if (_national_phone_ok(v) if rx is _PHONE_TIGHT_RE else _nanp_ok(v)):
                    out.append((m.start(1), m.start(1) + len(v), "phone-after-phone-word", PHONE))
    if "name-single-after-label" in want and ("name" in low or "nom" in low or "apellido" in low or "cognome" in low
                                              or "voornaam" in low or "achternaam" in low or "namn" in low):
        found = []
        for m in _SINGLE_NAME_RE.finditer(text):
            v = m.group(1)
            low_v = v.lower().strip("'’-")
            if low_v in _NAME_LABEL_TRANSLATIONS:
                # a label translation as a value: an i18n file or a form schema, whose other values are labels too
                # (first_name: Prenume, last_name: Nume): no single name of this text is a person's
                found = []
                break
            if low_v in _NAME_LABEL_VALUES:
                continue   # a type or state word (Unknown, Default, String): this value only, a real record keeps
                # its other names (review, 2026-10-17)
            if v.lower() in _NAME_SENTENCE_START or _WORD_AFTER_RE.match(text, m.end(1)):
                continue   # first_name: Too long (maximum…), Renamed to given_name: a sentence, not a name
            if low_v in _PLACEHOLDER_NAME_WORDS or low_v in PLACEHOLDER_NAMES \
                    or low_v in _NOT_A_NAME_START or low_v in _NOT_A_NAME_WORD or low_v in _SHORT_EN \
                    or len(low_v) < 2 or _reads_as_words(_no_marks(v)) or _inflected_word(low_v):
                continue
            found.append((m.start(1), m.end(1), "name-single-after-label", NAME))
        out += found
    if "username-after-label" in want and "name" in low:
        for m in _USERNAME_LABEL_RE.finditer(text):
            g = next(i for i in (2, 3, 4) if m.group(i) is not None)
            # inside an `example:` value (OpenAPI, Swagger): the value of the documentation, not of a person
            if _under_example_key(text, m.start()):
                continue
            if _username_value_ok(m.group(g), g != 4, m.group(1)):
                out.append((m.start(g), m.end(g), "username-after-label", USERNAME))
        for m in _USERNAME_PROSE_RE.finditer(text):
            v = m.group(1)
            if (re.search(r"[\d._]", v) and "@" not in v and not _VERSION_RE.match(v)
                    and not _under_example_key(text, m.start())
                    and _username_value_ok(v, False, " ")):
                out.append((m.start(1), m.end(1), "username-after-label", USERNAME))
    if "address-street-after-label" in want and any(w in low for w in _STREET_LABEL_WORDS):
        for m in _STREET_LABEL_RE.finditer(text):
            g = 1 if m.group(1) is not None else 2
            v = m.group(g)
            if _NOT_AN_ADDRESS_RE.search(v) or _GERUND_STREET_RE.search(v) or v.startswith("0") \
                    or _PLACEHOLDER_STREET_RE.match(v) \
                    or _PARENT_NOT_A_STREET_RE.search(text, max(0, m.start() - 60), m.start()) \
                    or _NOT_A_STREET_LABEL_RE.search(text, max(0, m.start() - 12), m.start()) \
                    or (g == 2 and _THING_SUBJECT_RE.search(text, max(0, m.start() - 40), m.start())):
                continue
            # the company's name often stands on the line before its address label (Acme Inc.\nAddress: ...): the
            # window holds that line too, as for street-address, at most 160 characters back
            line = _line_back(text, m.start(), 160)
            if line > 0 and text[line - 1] == "\n":
                line = _line_back(text, line - 1, max(1, 160 - (m.start() - line)))
            # a label that names a home (home address, Wohnadresse) or a verb of residence is a person's: no company
            # word nearby turns it into a company's address (an employer on the line before)
            home = _HOME_LABEL_RE.search(text, m.start(), m.start(g))
            if home or (not _not_a_home(text, line, m.end()) and not _BUSINESS_RE.search(text, line, m.start())):
                out.append((m.start(g), m.end(g), "address-street-after-label", ADDRESS))
            else:
                _company_window(text, line, m.start(g), m.end(g), "address-street-after-label", company)
    if "md-table-personal-column" in want and "|" in text and "---" in text:
        out += _md_table_hits(text)
    if "phone-wrapped-line" in want and "-\n" in text:
        for m in _PHONE_WRAP_RE.finditer(text):
            d = re.sub(r"\D", "", m.group())
            # after a phone word: `delta: +12 345-` and a next line of digits is arithmetic in a log
            if 8 <= len(d) <= 15 and len(set(d)) > 2 and _PHONE_WORD_RE.search(text, max(0, m.start() - 30),
                                                                               m.start()):
                out.append((m.start(), m.end(), "phone-wrapped-line", PHONE))
    return out


# ------------------------------------------------------------------------------------------------- the scan --
# words one of which a text must hold before a rule's regex runs (a cheap test on the lowered text)
_BIRTH_WORDS = ("dob", "d.o.b", "birth", "born", "bday", "geb", "n\u00e9", "ne le", "nee le", "naissance", "nacimiento",
                "naci", "nac\u00ed", "nascimento", "nascita", "nato")
_ID_WORDS = ("mrn", "member", "passport", "licen", "dl", "sin", "tfn", "nir", "tax", "insurance", "account",
             "patient", "id on file", "beneficiary", "medical", "national", "tin", "social",
             "reisepass", "passnummer", "pass-nr", "pass nr", "hrerschein", "passeport", "permis", "pasaporte",
             "passaporte", "conducir", "condu", "carteira", "passaporto", "patente", "paspoort", "rijbewijs",
             "körkort", "korkort", "paszport", "prawo jazdy", "prawa jazdy", "driving")
RULE_IDS = ("phone-one-digit-groups", "phone-us-national", "birth-date-after-label", "id-number-after-label",
            "user-in-url", "user-in-home-path", "street-address", "name-after-label", "name-before-email",
            "csv-personal-column") + tuple(FORMS)
# the rules a typed prompt also takes: a fix of the phone rule that both channels have
PROMPT_RULES = frozenset({"phone-one-digit-groups"} | {k for k, v in FORMS.items() if v[1] == "both"})
# the type and the region of each rule, for the registry (detect.pass_specs)
TYPES = {"phone-one-digit-groups": PHONE, "phone-us-national": PHONE, "birth-date-after-label": BIRTH_DATE,
         "id-number-after-label": ID_NUMBER, "user-in-url": USERNAME, "user-in-home-path": USERNAME,
         "street-address": ADDRESS, "name-after-label": NAME, "name-before-email": NAME,
         "csv-personal-column": "COLUMN", **{k: v[0] for k, v in FORMS.items()}}
REGIONS = {k: v[2] for k, v in FORMS.items()}
NEEDS = {"birth-date-after-label": "label", "id-number-after-label": "label", "name-after-label": "label",
         "name-before-email": "form", "street-address": "form", "csv-personal-column": "label",
         **{k: v[3] for k, v in FORMS.items()}}
_US_PHONE_REGIONS = frozenset({"us", "ca"})


# the default of a form, not a date: the Unix epoch and the first day of 1900
_PLACEHOLDER_DATES = frozenset({"01011970", "19700101", "010170", "01011900", "19000101", "010100", "00000000"})


def _placeholder_digits(v: str, dates: bool = False) -> bool:
    """A specimen or a form default: one digit repeated (X0000000), a run up or down (123456789), the epoch."""
    d = re.sub(r"\D", "", v)
    if dates and d in _PLACEHOLDER_DATES:
        return True
    return len(set(d)) <= 1 or d in "01234567890" or d in "98765432109"


def _compact_birth_date(v: str) -> bool:
    """YYYYMMDD after a birth label: a real day of the calendar, in a year before this one."""
    import datetime
    try:
        day = datetime.date(int(v[:4]), int(v[4:6]), int(v[6:]))
    except ValueError:
        return False
    return day.year < _host().this_year()


def _past_year(date: str) -> bool:
    """A birth date lies before this year: a date of this year or later is an event, a release, a deadline."""
    years = re.findall(r"(?<!\d)(\d{4})(?!\d)", date)
    return not years or int(years[-1]) < _host().this_year()


def _own_user() -> str:
    return _host().user_name()


def _host():
    """What the scan that runs reads of its computer (detect.Host): the host of its detector."""
    from . import core
    return core._det().host


def hits(text: str, channel: str, regions: tuple, company: list | None = None) -> list:
    """(start, end, rule id, type) of each hit. The caller drops a span another rule took and a placeholder. A list
    `company` gets each address that a legal form left as text (_company_window)."""
    want = RULE_IDS if channel == "tool" else PROMPT_RULES.intersection(RULE_IDS)
    out = []
    if "phone-one-digit-groups" in want and "+" in text:
        for m in _PHONE_GROUPS_RE.finditer(text):
            d = re.sub(r"\D", "", m.group())
            groups = re.findall(r"\d+", m.group())[1:]
            # a group of two digits or more after the country code: "+1 0 0 1 2 3 4 5" is a row of a matrix
            # in a typed prompt only after a phone word: "+1 2 3 4 56 7 89" is a row of numbers
            if 8 <= len(d) <= 15 and len(set(d)) > 2 and any(len(g) >= 2 for g in groups) and (
                    channel == "tool" or _PHONE_WORD_RE.search(text, max(0, m.start() - 30), m.start())):
                out.append((m.start(), m.end(), "phone-one-digit-groups", PHONE))
    if "phone-us-national" in want and _US_PHONE_REGIONS.intersection(regions) and "(" in text:
        for m in _US_PHONE_RE.finditer(text):
            if re.search(r"\)\s?555[-. ]", m.group()):
                continue
            if _PHONE_WORD_RE.search(text, max(0, m.start() - 30), m.start()):
                out.append((m.start(), m.end(), "phone-us-national", PHONE))
    out += _form_hits(text, channel, regions, want, company)
    if channel != "tool":
        return out
    low = text.lower()
    if "birth-date-after-label" in want and any(k in low for k in _BIRTH_WORDS):
        for m in _BIRTH_RE.finditer(text):
            if _placeholder_digits(m.group(1), dates=True) or not _past_year(m.group(1)):
                continue
            # YYYYMMDD: a real past day; after a vCard BDAY it stays with birth-date-vcard-compact (its rule id)
            if m.group(1).isdigit() and (not _compact_birth_date(m.group(1)) or "bday" in m.group(0).lower()):
                continue
            out.append((m.start(1), m.end(1), "birth-date-after-label", BIRTH_DATE))
    if "id-number-after-label" in want and any(k in low for k in _ID_WORDS):
        for m in _ID_RE.finditer(text):
            v = m.group(1)
            # 17 digits and more: a snowflake id of a chat platform or a database key, no document number
            if sum(c.isdigit() for c in v) >= 5 and not (v.isdigit() and len(v) >= 17) and not _placeholder_digits(v):
                out.append((m.start(1), m.end(1), "id-number-after-label", ID_NUMBER))
    if "user-in-url" in want and "://" in text:
        for m in _URL_USER_RE.finditer(text):
            u = m.group(1)
            # __token__ is PyPI's user for an API token; a template or a variable is no user
            # __token__ is PyPI's; an app key or an account id (four digits and more) names no person (CredData)
            if _service_user(u):
                continue
            out.append((m.start(1), m.end(1), "user-in-url", USERNAME))
    if "user-in-home-path" in want and ("/home/" in text or "/Users/" in text or "Users\\" in text):
        own = _own_user()
        for m in _HOME_USER_RE.finditer(text):
            u = m.group(1).lower()
            # the person's own home: the client tells the model the working directory, so masking it protects nothing
            if _service_user(u) or u == own:
                continue
            out.append((m.start(1), m.end(1), "user-in-home-path", USERNAME))
    if "street-address" in want:
        for regs, rx in _ADDRESS_FORMS:
            if not regs.intersection(regions):
                continue
            for m in rx.finditer(text):
                line = text.rfind("\n", 0, m.start()) + 1
                prev = text.rfind("\n", 0, max(0, line - 1)) + 1
                # the line before counts too: a heading (Acme Corp Niederlassung München), a label (Venue: Empire
                # State Building). "branch" alone is no word here: it is a git branch more often than an office
                if line:
                    line = prev
                if _GERUND_STREET_RE.search(m.group()) or (rx.groups and _city_is_a_word(m.group(1))):
                    continue
                end = m.end(1) if rx.groups else m.end()
                lo = max(line, m.start() - 160)
                if _NOT_A_HOME_RE.search(text, lo, m.end()):
                    _company_window(text, lo, m.start(), end, "street-address", company)
                    continue
                out.append((m.start(), end, "street-address", ADDRESS))
        if company is not None and {"de", "at", "ch"}.intersection(regions) and "\n" in text:
            for m in _DE_TWO_LINES_RE.finditer(text):
                line = text.rfind("\n", 0, m.start()) + 1
                if not line or text[line:m.start()].strip():
                    continue   # the street starts its line, after the line of the company's name
                lo = text.rfind("\n", 0, line - 1) + 1
                if lo and _DEPARTMENT_LINE_RE.match(text, lo):
                    lo = text.rfind("\n", 0, lo - 1) + 1   # Beispiel GmbH\nAbteilung Einkauf\nHafenweg 3
                f = _LEGAL_FORM_RE.search(text, lo, line)
                if f is None or not _COMPANY_LINE_RE.fullmatch(text, lo, f.start()):
                    continue   # Lena Brückner, Beispiel GmbH: a person on the company's line
                above = text.rfind("\n", 0, lo - 1) + 1 if lo else -1
                if above >= 0 and text[above:lo].strip() and not _ADDRESS_HEADING_RE.fullmatch(text, above, lo - 1):
                    continue   # the line above the company's name may be a person's
                _company_window(text, lo, m.start(), m.end(1), "street-address", company)
    if "name-after-label" in want and (":" in text or "=" in text):
        for m in _NAME_LABEL_RE.finditer(text):
            v = m.group(3).rstrip("'’")   # tenant: 'Jonas Wendler': the closing quote is no part of the name
            # after a person label (patient, full_name) a surname may be a word (Sarah Park): only a value of words
            # alone (Product Owner) is no name. After a weak label (name, owner) one word is enough
            words_only = _reads_as_words(v, every=True) if m.group(1) else _reads_as_words(v)
            if _name_ok(v) and not words_only:
                out.append((m.start(3), m.start(3) + len(v), "name-after-label", NAME))
    if "name-before-email" in want and "@" in text:
        for m in _NAME_MAIL_RE.finditer(text):
            if _SERVICE_LOCAL_RE.match(m.group(2)) or not _name_ok(m.group(1)) or _reads_as_words(m.group(1)):
                continue
            out.append((m.start(1), m.end(1), "name-before-email", NAME))
    if "csv-personal-column" in want and "\n" in text:
        out += _csv_hits(text)
    return out
