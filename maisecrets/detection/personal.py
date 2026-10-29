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
                       r"|data de nascimento|data di nascita|\bnat[oa] il|\bnascid[oa] em"
                       # the label in the other label languages and in Greek, Romanian, Ukrainian and Arabic (nym dev,
                       # 2026-10-25: 1,693 of 2,140 birth dates stayed text, most after such a label). A verb of birth
                       # with its preposition only (geboren op, född den), as `born on`: alone it is history
                       r"|geboortedatum|\bgeboren op|f[öo]delsedatum|\bf[öo]dd den|f[øo]dselsdato"
                       r"|syntym[äa]aika(?:ni|nsa|si)?|data urodzenia|\burodzon[ya] dnia|datum narozen[íi]"
                       r"|\bnarozen[ýáa]? dne|do[ğg]um tarih(?:i|im|iniz)?|дат[аеуы] рождения|дата народження"
                       r"|data na[șşs]terii|data na[șşs]tere|ημερομηνία γέννησης|تاريخ (?:ال)?ميلاد\w*"
                       r"|生年月日|出生日期|생년월일(?:은|는)?)[\"'\]]?"
                       # a comma (Date of birth, 1984-07-12, …) and Markdown bold around the colon (**DOB:**)
                       r"\*{0,2}\s{0,3}(?:(?:is|was|as|ist|war|est|es|era|è|é|er|var|är|on|oli|jest|je|este|είναι)"
                       r"\s{1,3})?"
                       r"[:=,\uff1a]?\*{0,2}\s{0,3}[\"'(]?\s{0,3}"
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
                    # a comma too: `your health plan beneficiary number, <id>, to medical professionals` (Nemotron-PII)
                    r"\s{0,3}[:=#,]?\s{0,3}[\"']?"
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
# a US postal address on two lines (1234 Harbor Mission Apt. 5\nSpringfield, IL 62704), and the military one (PSC 1234,
# Box 5678\nAPO AE 09876): the second line, a city, a state code and a ZIP code, is the strong part, so the street line
# needs no street word (Mendeley, 2026-10-20: 27,427 such addresses, all on two lines, were missed)
_US_STATES = ("AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND"
              "|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|PR|GU|VI|AS|MP")
_US_TWO_LINES_RE = re.compile(
    # the house number starts the line or follows a separator or a word of place (at, to, is): `Release 2 Notes` has
    # its number inside a heading
    r"(?:(?<=^)|(?<=\n)|(?<=[:;,(\"'] )|(?<=\()|(?<=\bat )|(?<=\bto )|(?<=\bis )|(?<=\bin )|(?<=\bon )"
    r"|(?<=\bfrom )|(?<=\baddress ))"
    r"(?:\d{1,6} (?:[A-Z][a-z'.-]{1,30} ){1,4}"
    r"[A-Z][a-z'.-]{1,30}\.?"
    r"(?:,? (?:Apt|Apartment|Suite|Ste|Unit|#)\.? ?[A-Za-z0-9-]{1,6})?"
    r"[ \t]*\r?\n[ \t]*(?:[A-Z][a-z'.-]{1,30} ){0,3}[A-Z][a-z'.-]{1,30}, (?:" + _US_STATES + r") \d{5}(?:-\d{4})?"
    r"|(?:PSC \d{3,5}, Box \d{3,5}|Unit \d{3,5} Box \d{3,5}|US(?:NS|NV|CGC|S) [A-Z][a-z]{1,30})"
    r"[ \t]*\r?\n[ \t]*(?:APO|FPO|DPO) (?:AA|AE|AP) \d{5})(?![\w-])")
# the same address on one line (4821 Harbor Mission Apt. 5 Springfield, IL 62704; PSC 1234, Box 5678, APO AE 09876):
# the city, the state code and the ZIP code still end it, and the street starts after a separator or a word of place,
# as on two lines. Benchmark V3, Mendeley dev: about 8,400 such addresses were missed
_US_ONE_LINE_RE = re.compile(
    r"(?:(?<=^)|(?<=\n)|(?<=[:;,(\"'] )|(?<=\()|(?<=\bat )|(?<=\bto )|(?<=\bis )|(?<=\bin )|(?<=\bon )"
    r"|(?<=\bfrom )|(?<=\baddress ))"
    r"(?:\d{1,6} (?:[A-Z][a-z'.-]{1,30} ){1,4}"
    r"[A-Z][a-z'.-]{1,30}\.?"
    r"(?:,? (?:Apt|Apartment|Suite|Ste|Unit|#)\.? ?[A-Za-z0-9-]{1,6})?"
    r",?[ \t]+(?:[A-Z][a-z'.-]{1,30} ){0,3}[A-Z][a-z'.-]{1,30}, (?:" + _US_STATES + r") \d{5}(?:-\d{4})?"
    r"|(?:PSC \d{3,5}, Box \d{3,5}|Unit \d{3,5} Box \d{3,5}|US(?:NS|NV|CGC|S) [A-Z][a-z]{1,30})"
    r",?[ \t]+(?:APO|FPO|DPO) (?:AA|AE|AP) \d{5})(?![\w-])")
# a label that names a person's home right before the address (residential address (…), home address: …): the address
# is the person's, whatever company the sentence names before it
_HOME_ADDRESS_BEFORE_RE = re.compile(r"(?i)(?<![a-z])(?:residential|home|permanent|private)[ _-]?(?:address|addr\.?)"
                                     r"[\"']?[ \t]{0,3}[:(=-]?[ \t]{0,3}$")
_NAMED_PLACE_BEFORE_RE = re.compile(r"\bat the (?:[A-Z][\w'&.-]*[ \t]+){0,4}[A-Z][\w'&.-]*,[ \t]*$")
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
# a part after a hyphen may start with a capital: Garcia-Lopez, Al-Rashid, Müller-Lüdenscheidt. The value ended at the
# hyphen and left the second part in the clear (Benchmark V1, Gretel and Nemotron dev: 896 names found in part)
_NAME_STEM = r"[" + _UP + r"][" + _LO + r"'’]{1,30}(?:-[" + _UP + _LO + r"][" + _LO + r"'’]{1,30}){0,2}"
_NAME_WORD = r"(?:" + _NAME_STEM + r"|[A-Z]\.)"
_NAME_PARTICLE = r"(?:van|von|de|da|del|der|al|bin|di|du|la|le)"
_NAME_VALUE = (r"((?:" + _NAME_STEM + r")(?:[ ](?:" + _NAME_WORD + "|" + _NAME_PARTICLE + r")){1,3})")
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
                + r"|name|display[ _-]?name|owner|author|driver|holder|kunde|inhaber(?:in)?|nom|nombre|nome|naam|namn")
_NAME_LABEL_RE = re.compile(
    r"(?i:(?<![a-z_./-])(?:(" + _PERSON_LABELS + r")|(" + _WEAK_LABELS + r")))"
    r"[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?[ \t]{0,3}" + _NAME_VALUE + r"(?![\w'’])")
# a key that names a role only a person has: the value after it is that person (payer: …, "policyholder": "…")
_ROLE_KEYS = (r"payer|payee|policyholder|policy[ _-]?holder|borrower|insured|physician|recipient|consignee"
              r"|shipper|buyer|seller|sender|guarantor")
_ROLE_KEY_NAME_RE = re.compile(r"(?i:(?<![\w.-])(?:" + _ROLE_KEYS + r"))[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?[ \t]{0,3}"
                               + _NAME_VALUE + r"(?![\w'’])")
# a key of words joined by _ - or camel case before a name; the key is judged after folding (_COMPOUND_PERSON_KEY_RE)
_COMPOUND_NAME_KEY_RE = re.compile(r"(?<![\w.-])[\"']?([A-Za-z][A-Za-z0-9]{0,30}(?:[_-]{1,3}[A-Za-z0-9]{1,30}){0,4})"
                                   r"[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?[ \t]{0,3}" + _NAME_VALUE + r"(?![\w'’])")
# a person's role, then name (account_holder_name, investorName, card_holder_name), or a full name (full__name). Not
# account, company, fund or issuer: their name is no person's; not user (a login) or agent (a program)
_COMPOUND_PERSON_KEY_RE = re.compile(
    r"(?:[a-z0-9]+_){0,3}(?:account_holder|card_holder|cardholder|holder|investor|contact|client|customer|cust"
    r"|recipient|sender|trader|beneficiary|payer|payee|applicant|patient|employee|owner|policyholder|policy_holder"
    r"|insured|borrower|member|student|passenger|tenant|guarantor|signer|consignee|shipper|buyer|seller|person"
    r"|representative|rep|manager|advisor|adviser|physician|doctor|witness)_(?:full_)?name"
    r"|full_name")
# an element whose name is a person label, around a name alone: <card_holder>, <customerName>, <ns:fullName>
_XML_NAME_ELEMENT_RE = re.compile(r"<([A-Za-z_][\w.:-]{0,64})(?:\s[^<>]{0,200})?>[ \t]*" + _NAME_VALUE
                                  + r"[ \t]*</\1>")
_PERSON_TAG_RE = re.compile(r"(?i)(" + _PERSON_LABELS + r")|(" + _WEAK_LABELS + r")")
# the parent of a name element that is a thing, not a person: a pom.xml project, a product, a package, and the
# instruments and parties of a financial message (a party or a counterparty is a company as often as a person)
_THING_PARENTS = frozenset({"project", "product", "item", "package", "plugin", "dependency", "module", "artifact",
                            "application", "app", "service", "component", "repository", "organization",
                            "organisation", "company", "team", "group", "parent", "build", "profile", "site",
                            "instrument", "security", "commodity", "unit", "issuer", "party", "counterparty", "fund",
                            "asset"})
_XML_OPEN_RE = re.compile(r"<(/?)([A-Za-z_][\w.:-]{0,64})(?:\s[^<>]{0,200})?(/?)>")


def _xml_parent(text: str, at: int) -> str:
    """The local name of the element still open at `at`, looking at most 2000 characters back."""
    depth = 0
    tags = list(_XML_OPEN_RE.finditer(text, max(0, at - 2000), at))
    for t in reversed(tags):
        if t.group(3):
            continue
        if t.group(1):
            depth += 1
        elif depth:
            depth -= 1
        else:
            return t.group(2).rsplit(":", 1)[-1].lower()
    return ""
# a lower-case word right after a value, or after its comma: the sentence goes on, the value is no field of a record
_PROSE_GOES_ON_RE = re.compile(r"(?:,[ \t]?| )[a-zà-ÿ]")
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
# a name next to words that say it is a person (Nemotron-PII and Gretel, 2026-10-20): a declaration (I, <name>, hereby),
# a self-introduction (my name is <name>), and a person's birth or residence right after the name (<name>, born on).
# One primitive for the three: the cue is a short phrase, the value has the shape of a name and does not read as words
_CUE_NAME = r"((?:" + _NAME_STEM + r")(?: (?:" + _NAME_STEM + r")){0,3})"
_PERSON_CUE_RES = (
    re.compile(r"(?<![\w,])I, " + _CUE_NAME + r", (?=(?:hereby|am|the undersigned|residing|currently|born|a resident"
               r"|being|declare|certify|of legal age)\b)"),
    # and in the other label languages (nym dev, 2026-10-25: a self-introduction in another language stayed text)
    # (not `ich heiße`: ich heiße Neue Kollegen willkommen is a welcome)
    re.compile(r"(?<![\w])(?i:my (?:full )?name is|mein (?:vollständiger )?name ist"
               r"|je m['’]appelle|mon nom (?:complet )?est|mi nombre (?:completo )?es|me llamo"
               r"|il mio nome (?:completo )?è|mi chiamo|mijn (?:volledige )?naam is|ik heet|jag heter"
               r"|mitt (?:fullständiga )?namn är|jeg heter|jeg hedder|mit (?:fulde )?navn er|mitt navn er"
               r"|nazywam się|mam na imię|(?:o )?meu nome (?:completo )?é|chamo-me|eu me chamo|jmenuji se"
               r"|nimeni on|numele meu (?:complet )?este|mă numesc) " + _CUE_NAME
               + r"(?![\w'’-])"),
    re.compile(_CUE_NAME + r", (?=(?:born on|born in|date of birth|a resident of|residing at|resides at|who resides"
               r"|who lives|currently residing|currently resides)\b)"),
    # a title before a full name (Mr Dana Okafor, Mrs. …); not Dr, which is also a street (… Dr. We are)
    re.compile(r"(?<![A-Za-z])(?:Mr|Mrs|Ms|Mx|Miss)\.? " + _CUE_NAME + r"(?![\w'’-])"),
    # a salutation before a full name and its comma or line end (Dear Dana Okafor,)
    re.compile(r"(?<![A-Za-z])(?:Dear|Hi|Hello|Hey) " + _CUE_NAME + r"(?=[ \t]*[,:!\n])"))
# the roles a salutation names instead of a person, which the word list lacks (Dear Valued Policyholder): read on the
# dev split of Gretel and Nemotron-PII, 2026-10-20, with their common relatives
_ROLE_WORDS = frozenset({
    "valued", "esteemed", "prospective", "policyholder", "policyholders", "subscriber", "subscribers", "cardholder",
    "beneficiary", "applicant", "applicants", "customer", "customers", "member", "members", "client", "clients", "team",
    "committee", "manager", "managers", "sir", "madam", "colleague", "colleagues", "partner", "partners", "patron",
    "investor", "investors", "shareholder", "shareholders", "stakeholder", "stakeholders", "user", "users",
    "participant", "participants", "resident", "residents", "homeowner", "homeowners", "tenant", "tenants", "borrower",
    "insured",
    "claimant", "account", "holder", "student", "students", "parent", "parents", "guardian", "patient", "patients",
    "employee", "employees", "friend", "friends", "admissions", "hiring", "selection", "support", "sales", "board"})
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
                          "rentenversicherungsnummer", "personalausweisnummer",
                          # ids only a person has, as the records of the datasets name them (Benchmark V3 Phase C,
                          # 2026-10-22: 54 health plan and 26 certificate license numbers in Markdown tables of dev)
                          "health_plan_beneficiary_number", "beneficiary_number", "certificate_license_number",
                          "driver_license_number", "patient_id"})
_WEAK_COLS = frozenset({"name", "full_name", "fullname", "first_name", "last_name", "firstname", "lastname",
                        "given_name", "family_name", "surname", "customer", "customer_name", "employee",
                        "employee_name", "emp_name", "patient", "patient_name", "nome", "nombre", "nom", "vorname",
                        "nachname", "username", "user_name", "user_id", "userid",
                        # the name of a person in a role (Benchmark V3 Phase C, 2026-10-21: candidate, player, client,
                        # recipient name columns of Nemotron dev stayed text); weak, so only beside a strong column
                        "candidate_name", "client_name", "player_name", "recipient_name", "applicant_name",
                        "student_name", "member_name", "contact_name", "passenger_name", "beneficiary_name",
                        "tenant_name"})
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


# a field that names one part of a name holds one word (| First Name | X |): a record with a person in it says so
# (Benchmark V3 Phase C, 2026-10-21: 1,272 first and last names alone in field-value tables of Nemotron dev stayed text)
_NAME_PART_COLS = frozenset({"first_name", "last_name", "firstname", "lastname", "given_name", "family_name",
                             "surname", "vorname", "nachname"})
_NAME_PART_RE = re.compile(_NAME_STEM)
_NOT_A_NAME_PART = frozenset({"required", "optional", "unknown", "none", "redacted", "pending", "mandatory",
                              "string", "text", "varchar", "first", "last", "name", "value", "field", "example",
                              "sample", "test",
                              # the words of fixtures and seed data (first_name,last_name / Foo,Bar)
                              "foo", "bar", "baz", "qux", "quux", "user", "demo", "dummy", "fake", "placeholder",
                              "lorem", "ipsum", "guest", "anonymous"})
_FIRST_PART_COLS = frozenset({"first_name", "firstname", "given_name", "vorname"})


_FIXTURE_USER_RE = re.compile(r"(?i)(?:^|[^a-z])(?:fixture|mock|sample|dummy|test|example|demo|fake|placeholder)"
                               r"(?:[^a-z]|s?$|user|account)")


def _cell_ok(v: str, typ: str, col: str = "") -> bool:
    """The cell holds what its column names: a desk extension is no phone, `Front Desk` no name."""
    if typ == NAME and col in _NAME_PART_COLS and " " not in v.strip():
        w = v.strip()
        return bool(_NAME_PART_RE.fullmatch(w)) and w.lower() not in _NOT_A_NAME_PART \
            and w.lower() not in PLACEHOLDER_NAMES and w.lower() not in _NOT_A_NAME_WORD
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
        # a fixture or a test account (fixture_account, mock-user2): no person's (codex Gate A, 2026-10-22)
        return not _service_user(v) and not _FIXTURE_USER_RE.search(v)
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
        names = [_md_column(h) for h in hdr.split(sep)]
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
            j = 0
            cells: list = []
            cell = _CSV_CELL_RE[sep]
            while j <= len(line):
                m = cell.match(line, j)
                a, b = m.span()
                s2, e2 = (a + 1, b - 1) if line[a:b].startswith('"') and b - a >= 2 else (a, b)
                cells.append((pos + s2, pos + e2))
                j = b + 1
            # in a CSV file a birth date also names the person of its row
            out += _grid_hits(text, names, [cells], "csv-personal-column", anchors=(NAME, BIRTH_DATE, ID_NUMBER),
                              accounts_column=False)
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
               "patient": "patient", "date_of_birth_dob": "date_of_birth", "dob_date_of_birth": "date_of_birth",
               # the first line of a postal address in common APIs (address_line1, schema.org streetAddress folded to
               # streetaddress) and camel case written as one word
               "address_line1": "street", "address_line_1": "street", "address1": "street", "addressline1": "street",
               "streetaddress": "street_address", "dateofbirth": "date_of_birth", "phonenumber": "phone_number",
               "mobilephone": "mobile_phone", "givenname": "given_name", "familyname": "family_name",
               # the address of a person under its purpose, and the ids of a person written as one word or with "'s"
               "property_address": "address", "billing_address": "address", "shipping_address": "address",
               "mailing_address": "address", "residential_address": "address", "postal_address": "address",
               "permanent_address": "address", "current_address": "address", "propertyaddress": "address",
               "billingaddress": "address", "shippingaddress": "address", "mailingaddress": "address",
               "healthplanbeneficiarynumber": "health_plan_beneficiary_number",
               "medicalrecordnumber": "mrn", "driverlicensenumber": "driver_license_number",
               "drivers_license_number": "driver_license_number", "driver's_license_number": "driver_license_number",
               "passportnumber": "passport_number", "patientid": "patient_id",
               "beneficiarynumber": "beneficiary_number", "certificatelicensenumber": "certificate_license_number",
               # the name column of a role in camel case (candidateName)
               "candidatename": "candidate_name", "clientname": "client_name", "playername": "player_name",
               "recipientname": "recipient_name", "applicantname": "applicant_name", "studentname": "student_name",
               "membername": "member_name", "contactname": "contact_name", "passengername": "passenger_name",
               "beneficiaryname": "beneficiary_name", "tenantname": "tenant_name",
               # the same columns in the languages of the regions (de, fr, es, it, nl, sv, pt): each maps to a name the
               # lists above already hold, so the policy stays one
               "straße": "strasse", "telefonnummer": "telephone", "handynummer": "mobile",
               "prénom": "first_name", "prenom": "first_name", "nom_de_famille": "last_name",
               "date_de_naissance": "date_of_birth", "téléphone": "telephone",
               "apellido": "last_name", "apellidos": "last_name", "fecha_de_nacimiento": "date_of_birth",
               "teléfono": "telefono", "dirección": "direccion",
               "cognome": "last_name", "indirizzo": "address", "data_di_nascita": "date_of_birth",
               "voornaam": "first_name", "achternaam": "last_name", "naam": "name", "adres": "address",
               "geboortedatum": "date_of_birth", "telefoonnummer": "telephone",
               "förnamn": "first_name", "efternamn": "last_name", "namn": "name", "adress": "address",
               "födelsedatum": "date_of_birth",
               "sobrenome": "last_name", "endereço": "endereco", "data_de_nascimento": "date_of_birth"}
# the field names of a person in the languages of the label files and their common short forms, written without
# diacritics (a name is looked up as written and folded: hasło, haslo). Each maps to a name the lists above hold, so
# the policy stays one: a weak column counts only beside a strong one and a person (structured corpus, set A dev,
# 2026-10-25). Left out: words that name a thing as often as a person's field (via, str, login, uid, titular)
_MD_ALIASES_FOLDED = {
    # first, last and full names
    "fname": "first_name", "first_nm": "first_name", "firstnm": "first_name", "vname": "first_name",
    "forename": "first_name", "rufname": "first_name", "imie": "first_name", "tilltalsnamn": "first_name",
    "roepnaam": "first_name", "primeiro_nome": "first_name", "nombre_pila": "first_name",
    "nombre_de_pila": "first_name",
    "lname": "last_name", "last_nm": "last_name", "lastnm": "last_name", "nname": "last_name",
    "familienname": "last_name", "nazwisko": "last_name", "apelido": "last_name", "primer_apellido": "last_name",
    "segundo_apellido": "last_name", "nom_famille": "last_name", "cust_nm": "customer_name",
    "custnm": "customer_name", "customer_nm": "customer_name", "kundenname": "customer_name",
    "kundnamn": "customer_name", "klantnaam": "customer_name", "nome_cliente": "customer_name",
    "nombre_cliente": "customer_name", "nom_client": "customer_name", "nominativo": "full_name",
    "nome_completo": "full_name", "nombre_completo": "full_name", "nom_complet": "full_name",
    "volledige_naam": "full_name", "imie_i_nazwisko": "full_name", "vollstandiger_name": "full_name",
    "fullstandigt_namn": "full_name",
    # user names
    "uname": "username", "usr": "username", "gebruikersnaam": "username", "anvandarnamn": "username",
    "benutzername": "username", "anmeldename": "username", "nom_utilisateur": "username",
    "identifiant": "username", "nombre_usuario": "username", "nombre_de_usuario": "username",
    "usuario": "username", "nome_utente": "username", "utente": "username", "utilizador": "username",
    "nome_usuario": "username", "nome_de_usuario": "username", "nazwa_uzytkownika": "username",
    "login_name": "username", "loginname": "username", "benutzer": "username",
    # addresses
    "addr": "address", "adr": "address", "domicilio": "address", "postadress": "address", "postadres": "address",
    "hemadress": "address", "woonadres": "address", "adres_zamieszkania": "address", "residenza": "address",
    "wohnadresse": "address", "wohnort": "address", "morada": "address", "endereco_residencial": "address",
    "straatnaam": "street", "gatuadress": "street_address", "calle": "street", "ulica": "street", "rue": "street",
    "strasse_hausnummer": "street",
    # dates of birth
    "geb_dat": "date_of_birth", "gebdat": "date_of_birth", "geb_datum": "date_of_birth",
    "data_urodzenia": "date_of_birth", "fecha_nacimiento": "date_of_birth", "f_nac": "date_of_birth",
    "fec_nac": "date_of_birth", "data_nascita": "date_of_birth", "data_nascimento": "date_of_birth",
    "date_naissance": "date_of_birth", "fodelsedag": "date_of_birth", "fodelsedatum": "date_of_birth",
    "geburtsdatum": "geburtsdatum", "dob_date": "date_of_birth",
    # phones
    "tel": "telephone", "tel_no": "telephone", "tel_nr": "telephone", "telnr": "telephone", "nr_tel": "telephone",
    "numer_telefonu": "telephone", "telefonnummer": "telephone", "numero_de_telephone": "telephone",
    "numero_telephone": "telephone", "numero_de_telefono": "telephone", "numero_telefono": "telephone",
    "numero_di_telefono": "telephone", "mobilnummer": "mobile", "mobiltelefon": "mobile", "gsm": "mobile",
    "cellulare": "mobile", "movil": "mobile", "celular": "mobile", "telemovel": "mobile", "portable": "mobile",
    "mobiel": "mobile", "komorka": "mobile", "telefon_komorkowy": "mobile",
    # national ids
    "ssn_no": "ssn", "ssn_nr": "ssn", "personnummer": "national_id", "bsn": "national_id",
    "burgerservicenummer": "national_id", "dni": "national_id", "pesel": "national_id",
    "codice_fiscale": "national_id", "numero_securite_sociale": "national_id", "nie": "national_id",
    "cpf": "national_id", "nif": "tax_id", "henkilotunnus": "national_id"}


def _fold(name: str) -> str:
    """A field name without its diacritics: hasło haslo, lösenord losenord, straße strasse."""
    import unicodedata
    name = name.replace("ß", "ss").replace("ł", "l").replace("ø", "o").replace("æ", "ae")
    return "".join(c for c in unicodedata.normalize("NFKD", name) if not unicodedata.combining(c))


# an entity before a field name (customer__surname, kunde.geburtsdatum, klient__nazwisko): the field alone names the
# value. Only the entities of a person: company_name and account_name stay text
_PERSON_PREFIX_RE = re.compile(r"(?:customer|cust|client|cliente|klient|klant|kunde|kunden|kund|patient|paciente"
                               r"|member|person|persona|persoon|employee|mitarbeiter|applicant|student|guest|buyer"
                               r"|contact|kontakt|user|utente|usuario|benutzer)_(?=[a-z])")


def _known_column(name: str) -> str:
    """The column of a folded name in the lists, or ""."""
    for n in (name, _fold(name)):
        n = _MD_ALIASES.get(n, _MD_ALIASES_FOLDED.get(n, n))
        if n in _STRONG_COLS or n in _WEAK_COLS or _ACCOUNT_NUMBER_COL_RE.fullmatch(n):
            return n
    return ""


def _md_column(cell: str) -> str:
    """The field name of a column, a key or an element, folded to the names of _STRONG_COLS and _WEAK_COLS: no XML
    namespace prefix (fpml:name), no Markdown escape (first\\_name), lower case, separators as `_`, then an alias"""
    cell = re.sub(r"^\s*[A-Za-z][\w.-]{0,40}:(?=[A-Za-z_])", "", cell.replace("\\_", "_"))
    name = re.sub(r"[\s/.-]+", "_", cell.strip().strip("*_`'\" ").strip().lower()).strip("_")
    name = re.sub(r"_?\(.*\)$", "", name)   # Date of Birth (YYYY-MM-DD)
    alias = _MD_ALIASES.get(name, name)
    if alias in _STRONG_COLS or alias in _WEAK_COLS or len(name) > 64:
        return alias
    # a doubled separator (customer__date__of__birth), a name in another language or a short form, a person's
    # entity before the field
    name = re.sub(r"_{2,}", "_", name)
    known = _known_column(name)
    if not known:
        p = _PERSON_PREFIX_RE.match(name)
        known = _known_column(name[p.end():]) if p else ""
    return known or alias


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
        hdr_line = li
        li += 2
        rows: list = []
        while li < len(lines) and len(rows) < _CSV_ROWS and "|" in lines[li] and lines[li].strip():
            rows.append([(pos[li] + a, pos[li] + b) for a, b in _md_cells(lines[li])])
            li += 1
        # a date alone names no person in a table of releases (| Name | Birthday | Version |): a name or an id
        out += _grid_hits(text, names, rows, "md-table-personal-column", strip="*`")
        # a table of fields and values (| Passenger Name | … |, one field per row) is one record: the first cell of
        # each row is the field name, the second its value, judged by the same policy (the header row may be a field)
        if len(names) == 2:
            head = [(pos[hdr_line] + a, pos[hdr_line] + b) for a, b in _md_cells(hdr)]
            kv = [r for r in [head] + rows if len(r) == 2]
            fields = [_md_column(text[r[0][0]:r[0][1]].strip("*` ")) for r in kv]
            if sum(f in _STRONG_COLS or f in _WEAK_COLS for f in fields) >= 2 or any(map(_password_column, fields)):
                out += _grid_hits(text, fields, [[r[1] for r in kv]], "md-table-personal-column", strip="*`")
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


# a column or field that names a password holds one on each row, whatever the other columns are (structured corpus,
# set A dev, 2026-10-25: tables and SQL found 0 of 230 passwords). The word last, after at most two parts
# (db_password, admin_user_pwd); a stored hash (password_hash, hashed_password) is no password
# `pass` alone names a boarding pass or a test result: only after a part that names an account (db_pass)
_PASSWORD_WORDS = ("password|passwort|passwd|pwd|kennwort|wachtwoord|losenord|haslo|contrasena|mot_de_passe"
                   "|mdp|senha|palavra_passe|parola_d_ordine|adgangskode|passord|salasana|heslo|sifre|passphrase")
_PASSWORD_COL_RE = re.compile(r"(?:(?!(?:hash|hashed|encrypted|enc|crypt|crypted|salted|salt)_)[a-z0-9]{1,16}_){0,2}"
                              r"(?:" + _PASSWORD_WORDS + r")|(?:[a-z0-9]{1,16}_)?(?:db|database|user|admin|root|login"
                              r"|account|mail|smtp|ftp|wifi|wlan|app|api|sql|redis|ldap)_pass")
# a value that is no password: a hash or a reference to one, a placeholder or a type
_NOT_A_PASSWORD_RE = re.compile(
    r"(?i)\$(?:2[abxy]?|argon2\w*|pbkdf2[\w-]*|scrypt|[156]|sha\d+)\$|(?:pbkdf2|bcrypt|argon2|sha\d+|md5)[_$:]"
    r"|\{[A-Z0-9-]+\}|[0-9a-f]{32,}$|[$%{<\[(*]|\w+\(\d*\)$|^(?:enc|env|vault|secret|ref|file|op):|^x{4,}$")


_TABLE_KINDS = frozenset({"csv-personal-column", "md-table-personal-column", "html-table-personal-column",
                          "sql-insert-personal-column"})


def _password_column(name: str) -> bool:
    return bool(_PASSWORD_COL_RE.fullmatch(_fold(re.sub(r"_{2,}", "_", name))))


def _password_cell(v: str) -> bool:
    """A cell under a password column that reads as one: no space, 6 to 128 characters, a letter and a digit (a single
    word, `required` or `string`, is none), no slash, and no hash, placeholder or type."""
    if not 6 <= len(v) <= 128 or any(c.isspace() for c in v) or v.lower() in _NOT_A_CELL:
        return False
    kinds = sum((any(c.islower() for c in v), any(c.isupper() for c in v), any(c.isdigit() for c in v),
                 any(not c.isalnum() for c in v)))
    from .core import _ds_value_ok
    # a letter and a digit: a word with a sign (Seat:, rgb/top) is a heading or a value of another table
    return kinds >= 2 and any(c.isdigit() for c in v) and any(c.isalpha() for c in v) and "/" not in v \
        and not _NOT_A_PASSWORD_RE.match(v) and not _NOT_A_PASSWORD_RE.search(v[:1]) and len(set(v)) > 2 \
        and _ds_value_ok(v, min_len=6)


_BIRTH_ANCHOR_COLS = frozenset({"dob", "date_of_birth", "birth_date", "birthdate", "geburtsdatum"})
_NEW_ID_COLS = frozenset({"health_plan_beneficiary_number", "beneficiary_number", "certificate_license_number",
                          "driver_license_number", "patient_id"})
_SOFTWARE_COLS = frozenset({"product", "version", "release", "build", "sku", "package", "app", "application"})


def _birth_anchor(text: str, names: list, hit: tuple) -> bool:
    """A date of birth makes a row a person's when its column says birth and the year lies 12 years back or more: a
    release candidate's date (| Name | Date of Birth |, 2024-05-01) is no person's."""
    if hit[3] != BIRTH_DATE or names[hit[4]] not in _BIRTH_ANCHOR_COLS:
        return False
    years = re.findall(r"(?<!\d)(1[89]\d\d|20\d\d)(?!\d)", text[hit[0]:hit[1]])
    return bool(years) and int(years[-1]) <= _host().this_year() - 12


def _grid_hits(text: str, names: list, rows, kind: str, anchors=(NAME, ID_NUMBER), strip: str = "",
               accounts_column: bool = True) -> list:
    """The personal-field policy of every table and record format: names are the column or field names, each row a
    list of (start, end) of its cell values in text. A strong column (an address, a birth date, a phone, an id) and
    the weak ones beside it (a name, a user) count only in a row that also holds a value of a person (`anchors`): a
    list of depots has addresses and no person. A column that names an account number counts on every row.
    `strip` are the marks a format puts around a value (Markdown bold and code)."""
    out = []
    strong = {i for i, h in enumerate(names) if h in _STRONG_COLS}
    cols = strong | {i for i, h in enumerate(names) if h in _WEAK_COLS} if strong else set()
    # the one exception to "a name part alone is no person": a record with a first-name and a last-name column. Its
    # row is a person when both cells read as name parts (the placeholder pair check below still applies)
    pair = not strong and any(h in _FIRST_PART_COLS for h in names) and \
        any(h in _NAME_PART_COLS - _FIRST_PART_COLS for h in names)
    if pair:
        cols = {i for i, h in enumerate(names) if h in _NAME_PART_COLS}
    accounts = {i for i, h in enumerate(names) if _ACCOUNT_NUMBER_COL_RE.fullmatch(h)} if accounts_column else set()
    # a table of software with one personal column (| Product | Certificate License Number | Version |): only a name
    # makes a row a person's there, neither an id nor a date of birth (codex Gate A, 2026-10-22). A record of an order
    # (sku, product, customer_name, dob, ssn) has more personal columns and stays a person's (the traces, 2026-10-22)
    software = any(h in _SOFTWARE_COLS for h in names) and \
        sum(h in _STRONG_COLS or h in _WEAK_COLS for h in names) < 2
    # a password column in a table; a record of JSON, XML or lines has its `key: value` read by the keyword rules
    secrets = {i for i, h in enumerate(names) if _password_column(h)} if kind in _TABLE_KINDS else set()
    if not cols and not accounts and not secrets:
        return out
    for n, cells in enumerate(rows):
        if n >= _CSV_ROWS:
            break
        row: list = []
        for col, (a, b) in enumerate(cells):
            v = text[a:b].strip()
            if strip:
                v = v.strip(strip)
            s0 = a + text[a:b].index(v) if v else a
            if col in accounts and _account_cell(v):
                out.append((s0, s0 + len(v), kind, ID_NUMBER))
            if col in secrets and _password_cell(v):
                out.append((s0, s0 + len(v), "secret-under-password-column", "SECRET"))
            if col in cols:
                typ = _column_type(names[col])
                if v.lower() not in _NOT_A_CELL and len(v) >= 2 and _cell_ok(v, typ, names[col]):
                    row.append((s0, s0 + len(v), kind, typ, col))
        # a first and a last name that together make a placeholder (Jane, Doe) are a fixture, not a person
        first = [h for h in row if names[h[4]] in _FIRST_PART_COLS and h[3] == NAME]
        last = [h for h in row if names[h[4]] in _NAME_PART_COLS - _FIRST_PART_COLS and h[3] == NAME]
        if first and last and (text[first[0][0]:first[0][1]] + " " + text[last[0][0]:last[0][1]]).lower() \
                in PLACEHOLDER_NAMES:
            row = [h for h in row if h not in first and h not in last]
        # a date of birth under its own name is a person too (| Date of Birth | Address |): only the names that say
        # birth, not "birthday", which a table of releases has (Benchmark V3 Phase C, 2026-10-22)
        # in a table of software the ids this lexicon took on 2026-10-22 and a date of birth under its name are no
        # person; the anchors a format had before keep their role (a CSV row's birth date, an SSN)
        if pair:
            if len({names[h[4]] in _FIRST_PART_COLS for h in row if h[3] == NAME}) == 2:
                out += [h[:4] for h in row]
            continue
        if any(c in strong for *_, c in row) and any(
                (h[3] in anchors and not (software and names[h[4]] in _NEW_ID_COLS))
                or (not software and _birth_anchor(text, names, h)) for h in row):
            out += [h[:4] for h in row]
    return out


# INSERT INTO customers (full_name, street, dob) VALUES ('…', '…', '…'), (…): the column list names each value of
# every tuple, as the header of a CSV file does
_SQL_INSERT_RE = _lazy(r"(?i)\binsert\s+into\s+[\w.`\"\[\]]{1,128}\s*\(([^()]{1,2000})\)\s*values\s*")
_SQL_CELL_RE = _lazy(r"\s*(?:'((?:[^'\n]|''){0,512})'|(-?[\w.:+-]{1,64}))\s*([,)])")


# a dump (mysqldump, pg_dump --inserts) writes INSERT INTO t VALUES (…) without a column list: the CREATE TABLE of t
# above it names the columns
_SQL_INSERT_BARE_RE = _lazy(r"(?i)\binsert\s+into\s+([\w.`\"\[\]]{1,128})\s+values\s*")
_SQL_CREATE_RE = _lazy(r"(?is)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?([\w.`\"\[\]]{1,128})\s*\((.{1,20000}?)\)\s*"
                       r"(?:[\w=\s]{0,200})?;")
_SQL_NOT_A_COLUMN = frozenset({"primary", "key", "unique", "constraint", "foreign", "index", "check", "fulltext"})


def _sql_create_columns(text: str) -> dict:
    """{table: [column names]} of each CREATE TABLE in the text."""
    out = {}
    for m in _SQL_CREATE_RE.finditer(text):
        cols = []
        for item in re.split(r",\s*(?![^()]*\))", m.group(2)):
            w = item.strip().split(None, 1)
            if w and w[0].strip("`\"[]").lower() not in _SQL_NOT_A_COLUMN:
                cols.append(_md_column(w[0].strip("`\"[]")))
        out[m.group(1).strip("`\"[]").lower()] = cols
    return out


def _sql_insert_hits(text: str) -> list:
    out = []
    found = [(m, [_md_column(c.strip().strip("`\"[]")) for c in m.group(1).split(",")])
             for m in _SQL_INSERT_RE.finditer(text)]
    tables = _sql_create_columns(text) if "create" in text.lower() else {}
    for m in _SQL_INSERT_BARE_RE.finditer(text) if tables else ():
        cols = tables.get(m.group(1).strip("`\"[]").lower())
        if cols:
            found.append((m, cols))
    for m, names in found:
        rows, j = [], m.end()
        while j < len(text) and len(rows) < _CSV_ROWS and text[j] == "(":
            cells, j = [], j + 1
            while True:
                c = _SQL_CELL_RE.match(text, j)
                if not c:
                    break
                g = 1 if c.group(1) is not None else 2
                cells.append((c.start(g), c.end(g)))
                j = c.end()
                if c.group(3) == ")":
                    break
            if len(cells) != len(names):
                break
            rows.append(cells)
            k = re.match(r"\s*,\s*", text[j:j + 64])
            if not k:
                break
            j += k.end()
        out += _grid_hits(text, names, rows, "sql-insert-personal-column")
    return out


# an HTML table: the <th> cells of its first row name the <td> cells of each row after it
_HTML_TABLE_RE = _lazy(r"(?is)<table\b[^>]{0,500}>(.{0,200000}?)</table>")
_HTML_ROW_RE = _lazy(r"(?is)<tr\b[^>]{0,500}>(.*?)</tr>")
_HTML_CELL_RE = _lazy(r"(?is)<(t[hd])\b[^>]{0,500}>(.{0,2048}?)</t[hd]>")
_HTML_TAG_RE = _lazy(r"<[^<>]{0,500}>")


def _html_cell_text(text: str, a: int, b: int) -> tuple:
    """The span of a cell's text: the one text run between its inline tags (<b>, <a href>, <span>). A cell with two
    runs (a name and a note) or a nested table gives an empty span, so its row is no row of this rule"""
    runs, pos = [], a
    for m in _HTML_TAG_RE.finditer(text, a, b):
        runs.append((pos, m.start()))
        pos = m.end()
    runs = [r for r in runs + [(pos, b)] if text[r[0]:r[1]].strip()]
    if len(runs) != 1 or "<table" in text[a:b].lower():
        return (a, a)
    return runs[0]


def _html_table_hits(text: str) -> list:
    out = []
    for t in _HTML_TABLE_RE.finditer(text):
        names, rows = None, []
        for r in _HTML_ROW_RE.finditer(text, t.start(1), t.end(1)):
            cells = list(_HTML_CELL_RE.finditer(text, r.start(1), r.end(1)))
            if names is None:
                if not cells or any(c.group(1).lower() != "th" for c in cells):
                    break
                names = [_md_column(text[slice(*_html_cell_text(text, *c.span(2)))]) for c in cells]
                continue
            if len(cells) == len(names) and all(c.group(1).lower() == "td" for c in cells):
                rows.append([_html_cell_text(text, *c.span(2)) for c in cells])
        if names:
            out += _grid_hits(text, names, rows, "html-table-personal-column")
            continue
        # a table of fields and values (<tr><th>Full name</th><td>…</td></tr>, one field per row) is one record, as
        # a two-column Markdown table is
        fields, values = [], []
        for r in _HTML_ROW_RE.finditer(text, t.start(1), t.end(1)):
            cells = list(_HTML_CELL_RE.finditer(text, r.start(1), r.end(1)))
            if len(cells) == 2 and cells[0].group(1).lower() == "th" and cells[1].group(1).lower() == "td":
                fields.append(_md_column(text[slice(*_html_cell_text(text, *cells[0].span(2)))]))
                values.append(_html_cell_text(text, *cells[1].span(2)))
        if sum(f in _STRONG_COLS or f in _WEAK_COLS for f in fields) >= 2:
            out += _grid_hits(text, fields, [values], "html-table-personal-column")
    return out


# a JSON object and an XML record are rows of the same kind: their keys or child element names name each value. Both
# go through _grid_hits, so the columns, the cell checks and the person check are those of the table rules
_JSON_TOKEN_RE = _lazy(r'"((?:[^"\\\n]|\\.){0,512})"|([{}\[\]:,])|(-?[\w.+-]{1,64})')
_JSON_RECORDS_MAX = 20000


def _record_rows(text: str, pairs: list, nested: list, kind: str) -> list:
    """The hits of one record: its own pairs, and its pairs joined with those of the records nested right in it. A
    person named in the record (a name, an id) is the person of its nested address or phone too: <party><name>, then
    <postalAddress><streetAddress>. One level only, so a list of a company's branches under a person stays apart."""
    out = _grid_hits(text, [_md_column(k) for k, _ in pairs], [[s for _, s in pairs]], kind) if pairs else []
    for child in nested:
        joined = pairs + child
        if pairs and child:
            out += _grid_hits(text, [_md_column(k) for k, _ in joined], [[s for _, s in joined]], kind)
    return out


def _json_record_hits(text: str) -> list:
    """Each object's direct pairs whose value is a string: (key, value span). A nested object is a row of its own and
    joins the row of the object it sits in (_record_rows)."""
    out, stack, rows = [], [], 0
    key = None
    expect_key = False
    for m in _JSON_TOKEN_RE.finditer(text):
        if m.group(2):
            ch = m.group(2)
            if ch == "{":
                # a nested object directly under a key of an object (not inside an array) joins that object
                stack.append({"pairs": [], "nested": [], "joins": key is not None and bool(stack)
                              and stack[-1] is not None})
                expect_key, key = True, None
            elif ch == "}":
                if stack and stack[-1] is not None:
                    obj = stack.pop()
                    if rows < _JSON_RECORDS_MAX:
                        rows += 1
                        out += _record_rows(text, obj["pairs"], obj["nested"], "json-personal-field")
                    if obj["joins"] and stack and stack[-1] is not None:
                        stack[-1]["nested"].append(obj["pairs"])
                elif stack:
                    stack.pop()
                expect_key, key = False, None
            elif ch == "[":
                stack.append(None)
                expect_key, key = False, None
            elif ch == "]":
                if stack:
                    stack.pop()
                expect_key, key = False, None
            elif ch == ",":
                expect_key, key = bool(stack) and stack[-1] is not None, None
            # ":" keeps the key for the value after it
        elif m.group(1) is not None:
            if expect_key:
                key, expect_key = m.group(1), False
            elif key is not None and stack and stack[-1] is not None:
                stack[-1]["pairs"].append((key, m.span(1)))
                key = None
        else:
            key = None
    return out


_XML_ATTR_RE = _lazy(r"""\s([A-Za-z_][\w.:-]{0,64})\s*=\s*(?:"([^"<>]{0,512})"|'([^'<>]{0,512})')""")
_XML_TAG_RE = _lazy(r"<(/?)([A-Za-z_][\w.:-]{0,64})(?:\s[^<>]{0,500})?(/?)>|<[!?][^<>]{0,2000}>")


def _xml_record_hits(text: str) -> list:
    """An element whose children are leaf elements (<street>12 Oak Lane</street>) is a row: the leaf names name the
    values. An element with text and child elements both, or a leaf that holds markup, is no row."""
    out, stack, rows = [], [], 0
    pos = 0
    for m in _XML_TAG_RE.finditer(text):
        between = text[pos:m.start()]
        pos = m.end()
        if m.group(2) is None:
            continue    # a comment, a declaration, CDATA
        name, closing, empty = m.group(2), m.group(1), m.group(3)
        if not closing and rows < _JSON_RECORDS_MAX:
            # <Admin user_name="…" name="…" street_address="…"/>: the attribute names name the attribute values
            attrs = [(x.group(1), x.span(2) if x.group(2) is not None else x.span(3))
                     for x in _XML_ATTR_RE.finditer(text, m.start(), m.end())]
            if len(attrs) >= 2:
                rows += 1
                out += _grid_hits(text, [_md_column(n) for n, _ in attrs], [[s for _, s in attrs]],
                                  "xml-personal-field")
        if empty:
            continue
        if not closing:
            if stack and between.strip():
                stack[-1]["mixed"] = True
            stack.append({"name": name, "start": m.end(), "leaves": [], "children": 0, "mixed": False,
                          "nested": []})
            continue
        if not stack or stack[-1]["name"] != name:
            stack = []          # not well formed: start again at the next element
            continue
        el = stack.pop()
        if el["children"] == 0:
            if stack and "<" not in between:
                stack[-1]["children"] += 1
                stack[-1]["leaves"].append((name, (el["start"], m.start())))
        else:
            if stack:
                stack[-1]["children"] += 1
            if not el["mixed"] and el["leaves"] and rows < _JSON_RECORDS_MAX:
                rows += 1
                out += _record_rows(text, el["leaves"], el["nested"], "xml-personal-field")
                if stack and not el["nested"] and el["children"] == len(el["leaves"]):
                    stack[-1]["nested"].append(el["leaves"])   # a record of leaves only joins its parent
    return out


# the records of the line formats: YAML, .env, INI, a compose `environment:` list, PHP print_r (one `key: value`,
# `KEY=value` or `[key] => value` per line, a run of lines at one indent is one record, `- ` opens the next), a log
# line with two `key=value` pairs or more (one record per line), and the pairs of a SQL UPDATE … SET … WHERE and of a
# WHERE clause (one record per statement). The same policy as the tables (_grid_hits): structured corpus, set A dev,
# 2026-10-25, 3,226 values under a known field name stayed text because no reader read these formats
_KV_LINE_RE = _lazy(r"(?m)^([ \t]*)(?:(-[ \t]+)|export[ \t]+)?(?:\[([^\]\n]{1,64})\][ \t]*=>|([^\W\d][\w.-]{0,63}"
                    r"(?: [^\W\d][\w.-]{0,30}){0,3})[ \t]*([:=]))[ \t]*(?:\"([^\"\n]{1,512})\"|'([^'\n]{1,512})'"
                    r"|([^\s\"'#|>&][^\n]{0,511}?))[ \t]*$")
_KV_INLINE_RE = _lazy(r"(?<![\w.:/-])([^\W\d][\w.-]{0,63})=(?:\"([^\"\n]{1,512})\"|'([^'\n]{1,512})'"
                      r"|([^\s\"',;&]{1,512}))")
_SQL_STMT_RE = _lazy(r"(?is)\b(?:update\s+[\w.`\"\[\]]{1,128}\s+set|select\s[^;]{1,2000}?\swhere|delete\s+from\s"
                     r"[^;]{1,200}?\swhere)\s([^;]{1,4000})")
_SQL_PAIR_RE = _lazy(r"([\w.`\"\[\]-]{1,64})\s*=\s*(?:'((?:[^'\n]|''){1,512})'|(-?[\w.]{1,64}))")


def _kv_line_hits(text: str) -> list:
    out, rows = [], 0
    record: list = []
    indent = None
    last_end = -1

    def flush():
        nonlocal record, rows
        if len(record) >= 2 and rows < _JSON_RECORDS_MAX:
            rows += 1
            return _grid_hits(text, [_md_column(k) for k, _ in record], [[s for _, s in record]],
                              "kv-personal-field")
        return []

    for m in _KV_LINE_RE.finditer(text):
        ind = len(m.group(1)) + (len(m.group(2)) if m.group(2) else 0)
        between = text[last_end:m.start()] if last_end >= 0 else ""
        # a line between two pairs that is not deeper than the record (a heading) or a blank line ends the record; a
        # deeper one (the lines of a block scalar) does not
        lines = between.split("\n")[1:-1]
        gap = any(not ln.strip() or len(ln) - len(ln.lstrip()) <= (indent or 0) for ln in lines)
        if record and ((m.group(2) and m.group(5) != "=") or ind != indent or gap):
            out += flush()
            record = []
        indent = ind
        last_end = m.end()
        key = m.group(3) or m.group(4)
        g = next(i for i in (6, 7, 8) if m.group(i) is not None)
        record.append((key, m.span(g)))
    out += flush()
    return out


def _kv_inline_hits(text: str) -> list:
    out, rows = [], 0
    start = 0
    for line in text.split("\n"):
        a, start = start, start + len(line) + 1
        # a line with two `=` at least: a regex for that line backtracked over every long line with one (a base64
        # block with its padding) and took quadratic time
        if line.count("=") < 2:
            continue
        pairs = []
        for m in _KV_INLINE_RE.finditer(text, a, a + len(line)):
            g = next(i for i in (2, 3, 4) if m.group(i) is not None)
            pairs.append((m.group(1), m.span(g)))
        if len(pairs) >= 2 and rows < _JSON_RECORDS_MAX:
            rows += 1
            out += _grid_hits(text, [_md_column(k) for k, _ in pairs], [[s for _, s in pairs]], "kv-personal-field")
    return out


def _sql_pair_hits(text: str) -> list:
    out = []
    for st in _SQL_STMT_RE.finditer(text):
        pairs = []
        for m in _SQL_PAIR_RE.finditer(text, st.start(1), st.end(1)):
            g = 2 if m.group(2) is not None else 3
            pairs.append((m.group(1).strip("`\"[]").rsplit(".", 1)[-1], m.span(g)))
        if pairs:
            out += _grid_hits(text, [_md_column(k) for k, _ in pairs], [[s for _, s in pairs]], "kv-personal-field")
    return out


def _kv_record_hits(text: str) -> list:
    out = []
    if ":" in text or "=" in text:
        out += _kv_line_hits(text)
    if text.count("=") >= 2:
        out += _kv_inline_hits(text)
    if "=" in text and ("SET" in text or "set" in text or "WHERE" in text or "where" in text):
        out += _sql_pair_hits(text)
    return out


# JSON inside a JSON string and a Python dict repr: the JSON reader on a copy of the same length
_JSON_STRING_RE = _lazy(r'"((?:[^"\\\n]|\\.){8,200000})"')


def _quoted_json_hits(text: str) -> list:
    """JSON inside a JSON string (\\"key\\": \\"value\\") and a Python dict repr ({'key': 'value'}) read as JSON: a
    copy of the same length with the quotes made plain, so each span is the span of the text."""
    out = []
    if '\\":' in text:
        # each string that holds JSON, alone: the text around it blanked, its escaped quotes plain
        inner = [" "] * len(text)
        for m in _JSON_STRING_RE.finditer(text):
            if '\\":' in m.group(1):
                inner[m.start(1):m.end(1)] = m.group(1).replace('\\"', ' "')
        out += _json_record_hits("".join(inner))
    if "{'" in text and "': " in text:
        out += _json_record_hits(text.replace("'", '"'))
    return out


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
    "name-next-to-a-person-cue": (NAME, "tool", "generic", "label"),
    "address-street-after-label": (ADDRESS, "tool", "generic", "label"),
    "address-street-postcode-city": (ADDRESS, "tool", "generic", "form"),
    "address-us-two-lines": (ADDRESS, "tool", "us", "form"),
    "address-us-one-line": (ADDRESS, "tool", "us", "form"),
    "md-table-personal-column": ("COLUMN", "tool", "generic", "label"),
    "sql-insert-personal-column": ("COLUMN", "tool", "generic", "label"),
    "html-table-personal-column": ("COLUMN", "tool", "generic", "label"),
    "json-personal-field": ("COLUMN", "tool", "generic", "label"),
    "xml-personal-field": ("COLUMN", "tool", "generic", "label"),
    "kv-personal-field": ("COLUMN", "tool", "generic", "label"),
    "secret-under-password-column": ("SECRET", "tool", "generic", "label"),
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
# a unit or a street written short before its number does not end an address: `Ste. 300`, `Apt. 12`, `Hauptstr. 5`
_UNIT_BEFORE_DOT = "".join(f"(?<!\\b{w})" for w in ("ste", "apt", "rm", "fl", "bldg", "no", "nr")) + "(?<!str)"
_ADDRESS_LABEL_RE = _lazy(
    r"(?i)(?<![a-z_])(address(?: on file)?|home[ _-]?address|adr" + _VCARD_PARAMS
    + r"|ship[ _-]?to|reship to|property|lives|street[ _-]?address"
    # the labels of the record layer's address columns in Dutch, Swedish, Italian and German (Gretel, 2026-10-20)
    r"|endere[cç]o|direcci[oó]n|adresse|adress?|indirizzo|anschrift|location)[\"']?\s{0,3}:\s{0,3}[\"']?(;*)([^\n\"|;]{8,100}?)"
    r"(?=[\"\n|]|\s{2}|\.\s(?!\d)|" + _UNIT_BEFORE_DOT + r"\.\s|$)")
# the end of a value before 0.6.43, at any dot and space: the second pass of address-after-label for a label whose
# longer value the filters refused (a template with `[City]` after `Apt. 999`, a sentence going on after the unit)
_ADDRESS_LABEL_SHORT_RE = _lazy(_ADDRESS_LABEL_RE._args[0].replace(
    r"(?=[\"\n|]|\s{2}|\.\s(?!\d)|" + _UNIT_BEFORE_DOT + r"\.\s|$)", r"(?=[\"\n|]|\s{2}|\.\s|$)"))
_UNIT_NUMBER_AFTER_RE = _lazy(r"\.\s\d{1,6}[A-Za-z]?(?![\w.-])")
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
# the separator: `:`, `=`, or `is` in a sentence (your first name is <name>)
_SINGLE_NAME_RE = _lazy(r"(?i:(?<![a-z_./-])(?:" + _SINGLE_NAME_LABELS + r"))[\"']?(?:[ \t]{0,3}[:=]|(?i: is))"
                        r"[ \t]{0,3}[\"']?"
                        r"[ \t]{0,3}([" + _UP + "\u1e00-\u1eff" + r"]"
                        r"[" + _LO + "\u1e00-\u1eff\u0300-\u036f" + r"'’-]{1,30}"
                        # a double surname: a second part with its own capital after the hyphen
                        r"(?:-[" + _UP + r"][" + _LO + r"\u1e00-\u1eff\u0300-\u036f'’]{1,30})?)"
                        r"(?![\w'’-])"   # Nguyễn, Ạnh, and a combining accent
                        r"(?![ \t]{1,2}[" + _UP + r"])")
# a first or last name that is also a word (Grace, Hunter, Rose): capitalised, no noun ending, the whole value of its
# field (the line, the quotes or the cell end after it). It counts only in a person's record (_form_hits)
_FIELD_END_RE = _lazy(r"[\"']?[ \t]*(?:[,;}\]|]|$)", re.M)
_WORD_NAME_NEAR = 300


def _word_as_name(text: str, m, v: str) -> bool:
    return v[:1].isupper() and v[1:] == v[1:].lower() and len(v) >= 3 and not _NOUN_END_RE.search(v) \
        and bool(_FIELD_END_RE.match(text, m.end(1)))
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
_USERNAME_PROSE_RE = _lazy(r"(?i)(?<![a-z_.-])(?P<label>user[ _-]?name|username)(?:[ \t]+(?:is|was))?"
                           # an apposition too: the user name, jdoe42, … and the user name (jdoe42)
                           r"(?P<sep>[ \t]+|[ \t]*[,(][ \t]*)"
                           r"(?P<v>[A-Za-z][\w.@+-]{1,62}[A-Za-z0-9])(?=[\s,;:!?)]|\.(?:\s|$)|$)")
# a user id that is an account name (user_id: jdoe42, userId: "j.harlow"): letters first, a dot, an underscore or up to
# four digits in it; a number, a UUID or a hash after the label stays text
_USER_ID_VALUE = r"[A-Za-z]{2,}(?:[._][A-Za-z]{2,}){0,2}\d{0,4}"
_USER_ID_LABEL_RE = _lazy(r"(?i)(?<![a-z_.-])user[ _-]?id[\"']?([ \t]{0,3}[:=][ \t]{0,3})(?:\"(" + _USER_ID_VALUE
                          + r")\"|'(" + _USER_ID_VALUE + r")'|(" + _USER_ID_VALUE + r")(?=[\s,;}\])]|$))")
_USER_ID_WORD_RE = _lazy(r"user[ _-]?id")
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
# a service account by its form only (the short-name rule of a home path, `ab12`, is no help here: js42 is a person).
# The service forms: a short name that ends in a service word (up to 20 characters before it, as before), and a
# forge's own forms (service_account_<id>, the token bots project_<id>_bot_<hex> and group_<id>_bot_<hex>). A service
# word alone is no service form in a longer name: a person's handle can end in -bot (a surname), -svc or -worker, and
# start with svc- or bot- (svc-jsmith, bot-anna99).
_USERNAME_SERVICE_RE = re.compile(r"(?i)^(?:.{0,12}[-_]?user\d*|user[-_]?\d+|.{0,20}(?:bot|svc|service|admin|runner|"
                                  r"agent|daemon|worker|deploy|build)(?:[-_]?\d+)?|.*\[bot\]"
                                  r"|service_account_[a-z0-9_]*[a-z0-9][a-z0-9_]*|(?:project|group)_\d+_bot_[0-9a-f]{8,})$")
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
_STREET_DIRECTION = r"(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West|Northeast|Northwest|Southeast|Southwest)"
# the end of a street value: a separator, the end of the line or of a sentence, Markdown bold, or the place after it
_STREET_VALUE_END = r"[ \t]*(?:$|[,;|\n)]|\.(?:\s|$)|\*\*| (?:in|and)\b)"
_STREET_LINE = (r"(?:\d{1,6}[A-Za-z]?(?:-\d{1,4})? (?:(?:[A-Z][A-Za-z'.-]{0,30}|\d{1,3}(?:st|nd|rd|th)) ){1,4}"
                r"(?:" + _STREET[3:-1]
                + r"|Circle|Cir|Parkway|Pkwy|Trail|Trl|Loop|Pike|Alley|Grove|Gardens|Heights|Mews)\.?"
                # a direction after the street type and a unit, also without a unit word (Main St SW, Oak Ave 12B,
                # Elm Rd N Ste A): only where the value ends right after it, so a number of the sentence stays out
                r"(?:(?: " + _STREET_DIRECTION + r")?"
                r"(?:,? (?:Apt|Apartment|Suite|Ste|Unit|Flat|#)\.? ?[A-Za-z0-9-]{1,6}"
                r"| (?:\d{1,5}[A-Z]?|[A-Z]\d{0,4}))(?=" + _STREET_VALUE_END + r")"
                r"| " + _STREET_DIRECTION + r"(?=" + _STREET_VALUE_END + r")"
                r"|,? (?:Apt|Apartment|Suite|Unit|Flat|#)\.? ?[A-Za-z0-9-]{1,6})?"
                r"|[A-ZÄÖÜ][\wäöüß-]{1,40}(?:straße|strasse|str\.|weg|gasse|platz|allee|ring|damm) \d{1,4}[a-z]?"
                r"|(?:Calle|Avenida|Via|Viale|Piazza|Rua|Carrer) (?:[A-ZÀ-Þ][\wà-ÿ'’-]{1,30} |d[aeio]l?l?[aeo]? |de "
                r"|das? |dos? ){1,5}?\d{1,5}[A-Za-z]?)(?![\w-])")
# the street forms of more EU languages, after an address label or a verb of residence only, and not in a
# business's record or before a template (_eu_street_ok): Dutch and Swedish names that end in their street word
# (Kerkstraat 12, Storgatan 5), a comma between a Romance street name and its number (Calle Mayor, 12) and the
# French form with the number first (12 rue de la Paix)
_STREET_LINE_EU = (r"(?:[A-ZÅÄÖ][\wåäöé-]{1,40}(?:straat|laan|gracht|plein|kade|singel|dijk|gatan|vägen|gränd|torget"
                   r"|backe),? \d{1,4}[a-zA-Z]?"
                   r"|(?:Calle|Avenida|Via|Viale|Piazza|Corso|Vicolo|Largo|Plaza|Paseo|Rua|Carrer) "
                   r"(?:[A-ZÀ-Þ][\wà-ÿ'’-]{1,30} |d[aeio]l?l?[aeo]? |de |das? |dos? ){0,4}?[A-ZÀ-Þ][\wà-ÿ'’-]{1,30},? "
                   r"\d{1,5}[A-Za-z]?"
                   r"|\d{1,4}(?: ?(?:bis|ter))?,? (?:rue|avenue|boulevard|bd|chemin|allée|place|impasse|quai|cours) "
                   r"(?:(?:de la|de l'|des|du|de|d'|la|le|les) ?)?[A-ZÀ-Þ][\wà-ÿ'’-]{1,30}"
                   r"(?: [A-ZÀ-Þ][\wà-ÿ'’-]{1,30}){0,3}"
                   r")(?![\w-])")
_STREET_LINE_RE = _lazy(_STREET_LINE)
# a company, a supplier or a legal form in the record before an EU street form: a business's address
_EU_BUSINESS_RE = _lazy(r"(?i)(?<![a-z])(?:fornitore|azienda|societ[aà]|ditta|proveedor|empresa|entreprise"
                        r"|soci[eé]t[eé]|fournisseur|bedrijf|leverancier|f[oö]retag|leverant[oö]r|provider|supplier|vendor|company"
                        r"|s\.?p\.?a\.?|s\.?r\.?l\.?|ab|nv|bv|sarl|sas|sl|s\.l\.|gmbh|ag|inc|ltd|llc)(?![a-z])")
_STREET_LABEL_RE = _lazy(
    r"(?i)(?<![a-z_])(?:(?:street|home|residential|mailing|postal|billing|shipping|delivery|permanent|current)[ _-]?"
    r"address|address(?: on file)?|anschrift|wohnadresse|wohnanschrift|adresse|domicilio|direcci[oó]n|indirizzo"
    r"|endere[cç]o|adres|adress|gatuadress|straatadres|stra(?:ß|ss)e|residenza)[\"']?[ \t]{0,3}"
    r"(?:is[ \t]{1,3}|[:=][ \t]{0,3})[\"']?[ \t]{0,2}(?-i:(" + _STREET_LINE + "|" + _STREET_LINE_EU + "))"
    r"|(?<![a-z])(?:resides?|residing|reside|lives?|living|domiciled|wohnt|wohnhaft"
    # a place word before a street line: the property located at, situated at (the company check below holds)
    r"|located|situated|property)"
    r"(?: (?:at|in|on|im|am|in der|an der))?[ \t]{1,3}(?-i:(" + _STREET_LINE + "|" + _STREET_LINE_EU + "))")


def _eu_street_ok(text: str, a: int, b: int) -> bool:
    """An EU street form after its label is a person's street when no template follows it on its line or the next
    ([city], <postal code>) and no business or legal form stands in its record before it."""
    end = text.find("\n", text.find("\n", b) + 1)
    after = text[b:end if end != -1 else len(text)][:200]
    if "[" in after or "<" in after or "{" in after:
        return False
    line = text.rfind("\n", 0, a) + 1
    lo = max(_block_back(text, line), a - 300)
    return not (_EU_BUSINESS_RE.search(text, lo, a) or _not_a_home(text, lo, a))


# e.g, i.e: an abbreviation, no account name
_ABBREVIATION_RE = _lazy(r"(?i)[a-z]{1,2}(?:\.[a-z]{1,2})+")


# a place word (located at, situated at, property at) after a business, its goods or a bank code: no home
_PLACE_OF_A_BUSINESS_RE = _lazy(r"(?i)(?<![a-z])(?:provider|insurance|insurer|vendor|supplier|contractor|swift|bic|iban"
                                r"|commercial|assets?|equipment|inventory|goods|facility|facilities|plant|premises"
                                r"|warehouse|branch|headquarters?|office|offices)(?![a-z])")


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
                       "adress", "straße", "strasse", "residenza",
                       "resid", "live", "living", "domiciled", "wohn", "located", "situated", "property")
_PHONE_WORDS = ("phone", "tel", "mobil", "cell", "fax", "handy", "portable", "rufnummer", "whatsapp", "hotline",
                "contact", "call", "reach", "text", "dial",
                # the personal cues of phone-after-phone-word without a phone word (my number is, … him at)
                "number is", "line is", "me at", "him at", "her at", "them at", "directly at", "me on",
                "him on", "her on", "them on", "directly on")
_ADDRESS_WORDS = ("address", "adr", "ship", "property", "lives", "endere", "direcci", "adresse", "location",
                  "indirizzo", "anschrift")
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
                        r"(\+?(?:\(\d{1,8}\)|\d{1,15})(?:[ .\-/]{1,2}(?:\(\d{1,8}\)|\d{1,8})){0,5})(?![\w+]|[.,/:-]\d)")
# the verbs of a call before a North American number: call, calling, dial, reach … at, contact … at, and contact right
# before the number (Nemotron-PII, 2026-10-20: `by calling`, `contact the report coordinator at`, `please contact`)
_PHONE_LOOSE_RE = _lazy(r"(?i)(?<![\w-])(?:" + _PHONE_LABEL_WORDS + r"|call(?:ed|ing)?|dial(?:ed|ing)?"
                        r"|reach(?:ed)?(?: \w{1,12}){0,2} at|contact(?:ed)?(?: \w{1,15}){0,4} at"
                        # contact alone only right before the number: an earlier start would swallow a later cue
                        r"|contact(?:ed)?(?=[ \t]{1,3}[(+]?\d)|text(?:ed)?"
                        # a contact label before its colon (Contact information: 312-…), and the number a sentence
                        # names (contact the following number: …); the number stays the strict North American form
                        r"|contact(?:[ _-]?(?:information|info|details|person))?(?=[ \t]*:)"
                        r"|contact(?: \w{1,15}){0,3} number(?=[ \t]*:)"
                        # a person's own number in a sentence: reach out to me at, call him directly at, my number is.
                        # A company's or an office's (to us at, our support team at) stays text, as in a table
                        r"|(?:me|him|her|them)(?: directly)? (?:at|on)"
                        r"|my (?:direct |personal |private |mobile |cell )?(?:number|line) is)(?![\w-])"
                        r"[^\n\d+]{0,30}?(?<![\w+.-])"
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
# also a contact label (Emergency contact information:) and a phone word with its purpose (Fax number for notice:)
_PHONE_GAP_END_RE = _lazy(r"(?i)(?:" + _PHONE_LABEL_WORDS + r"|number|no\.?|nr\.?|#|num[ée]ro|n[úu]mero|nummer"
                          r"|contact(?:[ _-]?(?:information|info|details|person))?"
                          r"|(?:" + _PHONE_LABEL_WORDS + r")" + _PHONE_NUMBER_WORD + r" for(?: \w{1,15}){1,2})$")


def _national_phone_ok(v: str) -> bool:
    """7 to 15 digits in groups: not a date, a time, a version, an IP address, a range of years or a placeholder. A
    single run needs 10 to 12 digits, a pair of groups 9 or more; dots only in the North American 3.3.4 or in pairs."""
    d = re.sub(r"\D", "", v)
    groups = re.findall(r"\d+", v)
    if not 7 <= len(d) <= 15 or _placeholder_digits(v) or _PHONE_DATE_RE.fullmatch(v.strip("+()")):
        return False
    if _ISO_DATE_RE.search(v) or (not v.startswith("+") and _COUNT_RE.fullmatch(v)):
        return False
    # one run of digits: a national number starts with its trunk 0 (0171…, 030…), an international one with + (E.164);
    # a run without either is a timestamp, an order or a count (Telefon: 01714829173, 2026-10-21)
    national, e164 = v.startswith("0") and 10 <= len(d) <= 12, v.startswith("+") and 11 <= len(d) <= 15
    if len(groups) == 1 and not (national or e164):
        return False
    tail = d[-7:]   # the subscriber part of one run: 01711111111 and 012345678901 are specimens
    if len(groups) == 1 and (len(set(tail)) <= 1 or tail in "0123456789" * 2 or tail in "9876543210" * 2):
        return False
    if len(groups) >= 3 and all(len(g) == 4 for g in groups) and not v.startswith(("+", "0")):
        return False   # Telefon 2024 2025 2026, Cell 1024 2048 4096: years and sizes (review, 2026-10-17)
    if len(groups) == 2 and len(d) < 9:
        return False
    if len(groups[-1]) >= 6 and _placeholder_digits(groups[-1]):
        return False   # 0151 1111111, 030 12345678: a subscriber number of one digit or of a run is a placeholder
    # four or five digits that count (…-4567) are no sign of a specimen: a real number ends so once in about 400, and
    # a test file's number counts in all its digits (above) or uses 555 (Benchmark V3, dev, 2026-10-22: 185 numbers
    # after a phone label stayed text for their last four digits)
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


def _address_value_ok(v: str) -> bool:
    """The value after an address label reads as an address: a digit, a comma, a house number with a street word, and
    no URL, version, port, markup or word of a thing (rack, version, status)."""
    return (any(c.isdigit() for c in v) and "," in v and bool(_HOUSE_RE.search(v)) and "://" not in v
            and not re.search(r"\d+\.\d+\.\d+|:\d{2,5}\b|[{}<>$()=_\[\]#@]", v)
            and not _NOT_AN_ADDRESS_RE.search(v))


def _block_back(text: str, line: int, lines: int = 2, most: int = 200) -> int:
    """The start of the block of an address line: the line itself and up to `lines` lines above it, at most `most`
    characters back, and never past a blank line (a blank line ends the block above)."""
    lo, pos = max(0, line - most), line
    for _ in range(lines):
        if pos <= lo or pos < 2 or text[pos - 2] == "\n":
            break
        nl = text.rfind("\n", lo, pos - 1)
        pos = nl + 1 if nl >= 0 else lo
    return pos


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
        done: set = set()
        for rx in (_ADDRESS_LABEL_RE, _ADDRESS_LABEL_SHORT_RE):
            for m in rx.finditer(text):
                if m.start() in done:
                    continue
                if re.match(r"(?i)adr(?![a-z])", m.group(1)) and not m.group(2):
                    continue   # ADR alone is an architecture decision record; the vCard field is ADR:;;<street>, also
                    #            with parameters (ADR;TYPE=home:;;<street>)
                s0 = m.start(3) + (len(m.group(3)) - len(m.group(3).lstrip()))
                v = m.group(3).strip()
                if rx is _ADDRESS_LABEL_SHORT_RE:
                    # the short value ends at a unit word: its number belongs to it (`…, Apt. 999`)
                    u = _UNIT_NUMBER_AFTER_RE.match(text, s0 + len(v))
                    if u and re.search(r"(?i)\b(?:ste|apt|rm|fl|bldg|no|nr)$", v) and _address_value_ok(
                            v + text[s0 + len(v):u.end()]):
                        v = text[s0:u.end()]
                if not _address_value_ok(v):
                    continue
                done.add(m.start())
                # the check for a company or a public place reads at most 120 characters of the line before the
                # label: unbounded, a long line of addresses took quadratic time (review of 0.6.24). Back to the start
                # of a JSON object was measured in 0.6.25 and left out: it also finds the employer in a person's
                # record (tests/test_company_address_window.py)
                line = _line_back(text, m.start())
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
                if _US_PHONE_RE.fullmatch(v):
                    # (312) 846-2291 is phone-us-national's when its phone word is there; after a cue of this rule
                    # only (reached at, me at) it is this rule's. The 555 exchange stays an example, as there
                    if not us or re.search(r"\)\s?555[-. ]", v) or _PHONE_WORD_RE.search(
                            text, max(0, m.start(1) - 30), m.start(1)):
                        continue
                elif _NANP_SHAPE_RE.fullmatch(v) and not us:
                    continue   # a North American number needs us or ca
                gap = text[m.start():m.start(1)]
                sep = [x.start() for x in _GAP_SEP_RE.finditer(gap)] if rx is _PHONE_LOOSE_RE else ()
                if sep and not _PHONE_GAP_END_RE.search(_PAREN_END_RE.sub("", gap[:sep[-1]]).rstrip(" )\"'")):
                    continue   # Mobile build artifact: 938-274-6157: the words before the colon name no phone
                if sep and gap.lower().startswith("contact") and gap[sep[-1] + 1:].strip(" \t\"'*_`"):
                    # Contact: build 938-274-6157: after a contact label's colon the number comes first, unless the
                    # words there name it themselves (Escalation contact: Contact the coordinator at …), which the
                    # label's match would else swallow (0.7.6 lost such a number, Benchmark V3, 2026-10-22)
                    rest = _PHONE_LOOSE_RE.search(text, m.start() + sep[-1] + 1, m.end())
                    if not (rest and rest.start(1) == m.start(1)
                            and not _GAP_SEP_RE.search(text[rest.start():rest.start(1)])):
                        continue
                if (_national_phone_ok(v) if rx is _PHONE_TIGHT_RE else _nanp_ok(v)):
                    out.append((m.start(1), m.start(1) + len(v), "phone-after-phone-word", PHONE))
    if "name-single-after-label" in want and ("name" in low or "nom" in low or "apellido" in low or "cognome" in low
                                              or "voornaam" in low or "achternaam" in low or "namn" in low):
        found, wordy = [], []
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
                    or len(low_v) < 2 or _inflected_word(low_v):
                continue
            if _reads_as_words(_no_marks(v)):
                if _word_as_name(text, m, v):
                    wordy.append((m.start(1), m.end(1), "name-single-after-label", NAME))
                continue
            # a double surname is words when each part is a word (Self-Employed, Non-Applicable), as in name-after-label
            parts = [w for w in _no_marks(v).split("-") if w]
            if len(parts) > 1 and all(_reads_as_words(w) or _inflected_word(w.lower()) for w in parts):
                continue
            found.append((m.start(1), m.end(1), "name-single-after-label", NAME))
        # a name that is also a word counts only in a person's record: a name part that is no word, and it or an
        # e-mail address within 300 characters (first_name: Unique / last_name: Index is a schema)
        out += found
        for h in wordy if found else ():
            lo, hi = max(0, h[0] - _WORD_NAME_NEAR), h[0] + _WORD_NAME_NEAR
            if any(abs(f[0] - h[0]) <= _WORD_NAME_NEAR for f in found) or text.find("@", lo, hi + 1) >= 0:
                out.append(h)
    if "username-after-label" in want and ("name" in low or _USER_ID_WORD_RE.search(low)):
        for m in _USERNAME_LABEL_RE.finditer(text):
            g = next(i for i in (2, 3, 4) if m.group(i) is not None)
            # inside an `example:` value (OpenAPI, Swagger): the value of the documentation, not of a person
            if _under_example_key(text, m.start()):
                continue
            if _username_value_ok(m.group(g), g != 4, m.group(1)):
                out.append((m.start(g), m.end(g), "username-after-label", USERNAME))
        for m in _USER_ID_LABEL_RE.finditer(text):
            g = next(i for i in (2, 3, 4) if m.group(i) is not None)
            v = m.group(g)
            if re.search(r"[\d._]", v) and not _under_example_key(text, m.start()) \
                    and _username_value_ok(v, g != 4, m.group(1)):
                out.append((m.start(g), m.end(g), "username-after-label", USERNAME))
        for m in _USERNAME_PROSE_RE.finditer(text):
            v = m.group("v")
            # an apposition after `user_name` is the next argument of a call (login(user_name, api_key)), and
            # (e.g. …) is no value
            if m.group("sep").strip() and ("_" in m.group("label") or _ABBREVIATION_RE.fullmatch(v)):
                continue
            if (re.search(r"[\d._]", v) and "@" not in v and not _VERSION_RE.match(v)
                    and not _under_example_key(text, m.start())
                    and _username_value_ok(v, False, " ")):
                out.append((m.start("v"), m.end("v"), "username-after-label", USERNAME))
    if "address-street-after-label" in want and any(w in low for w in _STREET_LABEL_WORDS):
        for m in _STREET_LABEL_RE.finditer(text):
            g = 1 if m.group(1) is not None else 2
            v = m.group(g)
            if _NOT_AN_ADDRESS_RE.search(v) or _GERUND_STREET_RE.search(v) or v.startswith("0") \
                    or _PLACEHOLDER_STREET_RE.match(v) \
                    or _PARENT_NOT_A_STREET_RE.search(text, max(0, m.start() - 60), m.start()) \
                    or _NOT_A_STREET_LABEL_RE.search(text, max(0, m.start() - 12), m.start()) \
                    or (g == 2 and _THING_SUBJECT_RE.search(text, max(0, m.start() - 40), m.start())) \
                    or (g == 2 and m.group().lower().startswith(("located", "situated", "property"))
                        and _PLACE_OF_A_BUSINESS_RE.search(text, max(0, m.start() - 60), m.start())) \
                    or (not _STREET_LINE_RE.fullmatch(v) and not _eu_street_ok(text, m.start(g), m.end(g))):
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
    if "sql-insert-personal-column" in want and "(" in text and ("INSERT" in text or "insert" in text):
        out += _sql_insert_hits(text)
    if "html-table-personal-column" in want and "<t" in text:
        out += _html_table_hits(text)
    if "json-personal-field" in want and "{" in text and '":' in text.replace('" :', '":'):
        out += _json_record_hits(text)
    if "xml-personal-field" in want and ("</" in text or "/>" in text):
        out += _xml_record_hits(text)
    if "json-personal-field" in want and ('\\":' in text or "{'" in text):
        out += _quoted_json_hits(text)
    if "kv-personal-field" in want:
        out += _kv_record_hits(text)
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
                "naci", "nac\u00ed", "nascimento", "nascita", "nato", "nata il", "nascid", "geboorte", "geboren",
                "delsedatum", "dd den", "dselsdato", "syntym", "urodz", "narozen", "tarih", "рождения", "народження",
                "na\u0219ter", "na\u015fter", "naster", "γέννησης", "ميلاد", "生年月日", "出生日期", "생년월일")
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
                # MRN4829173: the label glued to the number is the id's own prefix, masked with it
                start = m.start() if text[m.start():m.start(1)].isalpha() else m.start(1)
                out.append((start, m.end(1), "id-number-after-label", ID_NUMBER))
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
    if "address-us-two-lines" in want and "\n" in text and "us" in regions:
        for m in _US_TWO_LINES_RE.finditer(text):
            line = text.rfind("\n", 0, m.start()) + 1
            lo = max(_block_back(text, line), m.start() - 160)
            # a company, an office or a public place on the lines above or before it keeps the address text
            home = _HOME_ADDRESS_BEFORE_RE.search(text, max(line, m.start() - 40), m.start())
            if not home and (_NOT_A_HOME_RE.search(text, lo, m.start()) or _BUSINESS_RE.search(text, lo, m.start())):
                _company_window(text, lo, m.start(), m.end(), "address-us-two-lines", company)
            else:
                out.append((m.start(), m.end(), "address-us-two-lines", ADDRESS))
    if "address-us-one-line" in want and "us" in regions and ", " in text:
        for m in _US_ONE_LINE_RE.finditer(text):
            line = text.rfind("\n", 0, m.start()) + 1
            lo = max(_block_back(text, line), m.start() - 160)
            # "at the Harbor View Inn, 12 …": a named place before the address, as a venue's name on the line above
            home = _HOME_ADDRESS_BEFORE_RE.search(text, max(line, m.start() - 40), m.start())
            if not home and (_NOT_A_HOME_RE.search(text, lo, m.start()) or _BUSINESS_RE.search(text, lo, m.start())
                             or _NAMED_PLACE_BEFORE_RE.search(text, max(line, m.start() - 60), m.start())):
                _company_window(text, lo, m.start(), m.end(), "address-us-one-line", company)
            else:
                out.append((m.start(), m.end(), "address-us-one-line", ADDRESS))
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
            # a double name is judged with and without the parts after its hyphens, and is words only when both read as
            # words: with them, a second surname with a noun ending (Bakker-Fleming) made the name words (25 names lost
            # in 0.6.42); without them, a first surname that is a word alone (Llanos) did
            plain = re.sub(r"-[^\s]*", "", v)
            if m.group(1):
                words_only = _reads_as_words(v, every=True) and _reads_as_words(plain, every=True)
            else:
                words_only = _reads_as_words(v) and _reads_as_words(plain)
            short = re.match(r"\S+(?: \S+)*?-\S+", v)
            if words_only and short and short.end() < len(v):
                # the value ran on into the next word of its line (Name: Ana Ruiz-Diaz Address: …): the name up to the
                # end of its double surname, as it was found up to the hyphen before 0.6.42
                cut = short.group(0)
                if not _reads_as_words(cut) or not _reads_as_words(re.sub(r"-[^\s]*", "", cut)):
                    v, words_only = cut, False
            if m.group(1) and m.group(1).lower() == "student" and _PROSE_GOES_ON_RE.match(text, m.start(3) + len(v)):
                continue   # Student: Informatik Bachelor an der …: a course of study in a sentence, not a name
            if _name_ok(v) and not words_only:
                out.append((m.start(3), m.start(3) + len(v), "name-after-label", NAME))
    if "name-after-label" in want and (":" in text or "=" in text):
        for m in _ROLE_KEY_NAME_RE.finditer(text):
            v = m.group(1).rstrip("'’")
            plain = re.sub(r"-[^\s]*", "", v)
            if _name_ok(v) and not (_reads_as_words(v, every=True) and _reads_as_words(plain, every=True)):
                out.append((m.start(1), m.start(1) + len(v), "name-after-label", NAME))
    if "name-after-label" in want and "name" in low and (":" in text or "=" in text):
        # account_holder_name: …, "investorName": "…": a key whose last words name a person in a role and a name
        for m in _COMPOUND_NAME_KEY_RE.finditer(text):
            key = re.sub(r"[_\s.-]+", "_", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", m.group(1)).lower()).strip("_")
            if not _COMPOUND_PERSON_KEY_RE.fullmatch(key):
                continue
            v = m.group(2).rstrip("'’")
            plain = re.sub(r"-[^\s]*", "", v)
            if _name_ok(v) and not (_reads_as_words(v, every=True) and _reads_as_words(plain, every=True)):
                out.append((m.start(2), m.start(2) + len(v), "name-after-label", NAME))
    if "name-after-label" in want and "</" in text:
        # <card_holder>Jane Roe</card_holder>: the element's name is the label of its text
        for m in _XML_NAME_ELEMENT_RE.finditer(text):
            person = _PERSON_TAG_RE.fullmatch(m.group(1).rsplit(":", 1)[-1])
            if not person:
                continue
            if _xml_parent(text, m.start()) in _THING_PARENTS:
                continue   # <project><name>, <security><fullName>: the name of a thing
            v = m.group(2).rstrip("'’")
            plain = re.sub(r"-[^\s]*", "", v)
            every = bool(person.group(1))
            if _name_ok(v) and not (_reads_as_words(v, every=every) and _reads_as_words(plain, every=every)):
                out.append((m.start(2), m.start(2) + len(v), "name-after-label", NAME))
    if "name-next-to-a-person-cue" in want and any(w in low for w in ("i, ", "name is", "born", "resid", "lives", "mr",
                                                                         "ms", "mx", "miss", "dear", "hi ", "hello",
                                                                         "hey ", "name ist", "appelle",
                                                                         "mon nom", "mi nombre", "llamo", "mio nome",
                                                                         "chiamo", "mijn naam", "ik heet", "heter",
                                                                         "mitt namn", "hedder", "navn er", "nazywam",
                                                                         "na imię", "meu nome", "chamo", "jmenuji",
                                                                         "nimeni", "numele", "numesc")):
        for rx in _PERSON_CUE_RES:
            for m in rx.finditer(text):
                words, start = m.group(1).split(" "), m.start(1)
                # a word before the name that is no part of it (Patient Dana Okafor, born on): drop it
                while len(words) > 1 and _reads_as_words(words[0]) and words[0].lower() not in _GIVEN_NAME_WORDS:
                    start += len(words.pop(0)) + 1
                v = " ".join(words)
                # two name words at least: one word next to the cue is as often a role or a place (The Applicant,
                # Texas, born on) as a name
                if not _name_ok(v) or _reads_as_words(v) or words[0].lower() in _PLACEHOLDER_NAME_WORDS:
                    continue
                # a salutation also greets a role (Dear Valued Policyholder); the other cues name a person already
                if rx is _PERSON_CUE_RES[-1] and any(w.lower() in _ROLE_WORDS for w in words):
                    continue
                out.append((start, start + len(v), "name-next-to-a-person-cue", NAME))
    if "name-before-email" in want and "@" in text:
        for m in _NAME_MAIL_RE.finditer(text):
            if _SERVICE_LOCAL_RE.match(m.group(2)) or not _name_ok(m.group(1)) or _reads_as_words(m.group(1)):
                continue
            out.append((m.start(1), m.end(1), "name-before-email", NAME))
    if "csv-personal-column" in want and "\n" in text:
        out += _csv_hits(text)
    if "address-street-postcode-city" in want and "," in text:
        for m in _STREET_POSTCODE_CITY_RE.finditer(text):
            if not _STREET_WORD_RE.search(m.group(1)):
                continue
            line = _line_back(text, m.start())
            # the name of a hotel, an office or a company stands on the lines above an address block, not on its line
            block = _block_back(text, line)
            end = m.end()
            while text[end - 1] in ".,":   # the stop of a sentence is no part of the place (Berlin.)
                end -= 1
            if not _not_a_home(text, block, end) and not _BUSINESS_RE.search(text, block, m.start()):
                out.append((m.start(), end, "address-street-postcode-city", ADDRESS))
            else:
                _company_window(text, line, m.start(), end, "address-street-postcode-city", company)
    return _address_with_its_place(text, out)


# The place after a street on the same line belongs to the address: 12 Via Roma, 00184 Roma; Calle Mayor 5, Madrid,
# 28013; 4821 Maple Street, Springfield, IL 62704, USA. A street rule stops at the comma, and the postcode and the city
# stayed in the clear (Benchmark V2, Gretel dev: about 220 addresses found in part). The rest is taken only in these
# shapes and only when the line ends after it or a separator follows, so a sentence that goes on is not taken
_PLACE = r"(?:\d{4,5}(?:-\d{3,4})?[ \t]+)?" + r"[A-ZÀ-Þ][\w'’.-]{1,30}(?:[ \t-][A-ZÀ-Þa-zà-ÿ][\w'’.-]{1,30}){0,3}" \
    + r"(?:[ \t]+\d{4,5}(?:-\d{3,4})?)?(?:[ \t]*\([A-Z]{2}\))?"
_PLACE_SEGMENT = (r"(?:" + _PLACE + r"|\d{4,5}(?:-\d{3,4})?|[A-Z]{2}[ \t]+\d{5}(?:-\d{4})?"
                  r"|[A-Z][A-Z0-9]{1,3}[ \t]\d[A-Z]\d)")
_PLACE_AFTER_RE = _lazy(r"(?:[ \t]*[,–-][ \t]*|[ \t]*\n[ \t]*(?=\d{4,5}[ \t]))" + _PLACE_SEGMENT
                        + r"(?:[ \t]*,[ \t]*" + _PLACE_SEGMENT + r"){0,3}"
                        + r"(?=[ \t]*(?:$|\n|[\"|<;)\]]|\.(?:\s|$)))", re.M)
# a word that names a street in the languages of the regions, as a word or as the end of one (Hauptstraße, Storgatan)
_STREET_WORD_RE = _lazy(r"(?i)(?:stra(?:ss|ß)e|str\.|weg|gasse|allee|platz|ring|damm|ufer|chaussee|street"
                        r"|st\.?|road|rd\.?|avenue|ave\.?|lane|drive|dr\.|boulevard|blvd|way|place|court|ct\.?|terrace|highway"
                        r"|rue|chemin|impasse|via|viale|corso|piazza|vicolo|incrocio|calle|avenida|plaza|paseo|camino"
                        r"|carrer|pasadizo|acceso|rua|travessa|largo|straat|laan|plein|gracht|gatan|vägen|gränd)\b")
_ADDRESS_RULES_WITH_PLACE = frozenset({"address-street-after-label", "street-address", "address-after-label",
                                       "address-street-postcode-city"})
# The forms that only widen a hit of another rule (core._personal_hits drops them when they overlap none): a street
# line around a postcode that de-plz found. Alone, the form took company, hospital and venue addresses (Gretel dev,
# 62 new false positives on 2026-10-20); around a postcode hit it turns a partial address into a whole one
ONLY_WIDENS = frozenset({"address-street-postcode-city"})
# Street, number, postcode, city in one line, the European order: Max-Planck-Straße 12, 80333 München; 12 Rue de
# Rivoli, 75001 Paris. A street word and a house number before the comma, a postcode and a capitalised place after it
# a small word inside a street name: Rue de Rivoli, Via della Stazione, Am Ufer, Calle del Sol. Any other small word
# starts no street (Die Adresse ist Lindenstraße 42)
_STREET_PARTICLE = (r"(?:de|del|della|delle|dei|di|da|do|dos|das|du|des|la|le|les|lo|el|los|las|von|van|der|den"
                    r"|dem|am|an|auf|im|in|zum|zur|y|e|et|und|and|of|the)")
_STREET_POSTCODE_CITY_RE = _lazy(
    r"(?<![\w-])((?:\d{1,4}[a-z]?[ \t]+[A-ZÀ-Þ][\w'’.-]{1,30}(?:[ \t][A-ZÀ-Þa-zà-ÿ][\w'’.-]{0,30}){0,4}"
    r"|[A-ZÀ-Þ][\w'’.-]{2,30}(?:[ \t-](?:[A-ZÀ-Þ][\w'’.-]{0,30}|" + _STREET_PARTICLE + r")){0,4}[ \t]+\d{1,4}[a-z]?))"
    r",[ \t]*\d{4,5}[ \t]*,?[ \t]*[A-ZÀ-Þ][\w'’.-]{1,30}(?:[ \t-][A-ZÀ-Þ][\w'’.-]{1,30}){0,2}")


def _address_with_its_place(text: str, out: list) -> list:
    """Each address hit of a street rule runs on over the place after it on the same line (_PLACE_AFTER_RE)."""
    if not any(k in _ADDRESS_RULES_WITH_PLACE for _s, _e, k, _t in out):
        return out
    res = []
    wider = [(s, e) for s, e, _k, typ in out if typ == ADDRESS]
    for s, e, k, typ in out:
        # an address hit that another one already holds and runs past stays as it was: that one owns the span
        if typ == ADDRESS and k in _ADDRESS_RULES_WITH_PLACE \
                and not any(s2 <= s and e2 > e for s2, e2 in wider):
            m = _PLACE_AFTER_RE.match(text, e)
            if m:
                e = m.end()
        res.append((s, e, k, typ))
    return res
