"""The field-name vocabulary of the structured corpus (docs/BENCHMARK-STRUCTURED.md, "Field names").

A concept (a kind of field) has, per language, the word sequences that name it in a form, a database column or a
config key, and the short forms developers write. A spelling style turns a word sequence into a field name:
snake_case, camelCase, PascalCase, kebab-case, UPPER_CASE, dotted, a doubled separator, or the words a person
reads in a table head. A word with a diacritic appears as written and folded to ASCII.

This is template set A, the development set. The independent holdout (set B) gets its vocabulary from its own
author, from the SPEC in the design doc, never from this file."""
from __future__ import annotations

import random

from bench.structvalues import fold, fold_plain

# concept: (class, {lang: [word sequences]}); a class "neutral" is a span neither right nor wrong (city, postcode)
CONCEPTS = {
    "first_name": ("pii.name", {
        "en": [("first", "name"), ("given", "name"), ("forename",)],
        "de": [("vorname",), ("rufname",)], "fr": [("prénom",)], "es": [("nombre",), ("nombre", "pila")],
        "it": [("nome",)], "nl": [("voornaam",), ("roepnaam",)], "sv": [("förnamn",), ("tilltalsnamn",)],
        "pl": [("imię",), ("pierwsze", "imię")], "pt": [("primeiro", "nome"), ("nome", "próprio")]}),
    "last_name": ("pii.name", {
        "en": [("last", "name"), ("surname",), ("family", "name")],
        "de": [("nachname",), ("familienname",)], "fr": [("nom", "de", "famille"), ("nom",)],
        "es": [("apellidos",), ("primer", "apellido")], "it": [("cognome",)], "nl": [("achternaam",)],
        "sv": [("efternamn",)], "pl": [("nazwisko",)], "pt": [("apelido",), ("sobrenome",)]}),
    "full_name": ("pii.name", {
        "en": [("full", "name"), ("customer", "name"), ("contact", "name"), ("account", "holder")],
        "de": [("vollständiger", "name"), ("kundenname",), ("kontoinhaber",), ("ansprechpartner",)],
        "fr": [("nom", "complet"), ("titulaire", "du", "compte"), ("nom", "du", "client")],
        "es": [("nombre", "completo"), ("titular",), ("nombre", "del", "cliente")],
        "it": [("nome", "completo"), ("intestatario",), ("nominativo",)],
        "nl": [("volledige", "naam"), ("tenaamstelling",), ("naam", "klant")],
        "sv": [("fullständigt", "namn"), ("kontoinnehavare",), ("kundnamn",)],
        "pl": [("imię", "i", "nazwisko"), ("właściciel", "rachunku")],
        "pt": [("nome", "completo"), ("titular", "da", "conta"), ("nome", "do", "cliente")]}),
    "email": ("pii.email", {
        "en": [("email",), ("e", "mail"), ("email", "address"), ("contact", "email")],
        "de": [("e", "mail", "adresse"), ("email",), ("mailadresse",)],
        "fr": [("courriel",), ("adresse", "e", "mail"), ("adresse", "électronique")],
        "es": [("correo", "electrónico"), ("correo",), ("email",)],
        "it": [("indirizzo", "email"), ("posta", "elettronica"), ("email",)],
        "nl": [("e", "mailadres"), ("emailadres",)], "sv": [("e", "post"), ("epostadress",)],
        "pl": [("adres", "e", "mail"), ("email",)], "pt": [("correio", "eletrónico"), ("email",)]}),
    "phone": ("pii.phone", {
        "en": [("phone",), ("phone", "number"), ("mobile",), ("telephone",), ("cell", "phone")],
        "de": [("telefon",), ("telefonnummer",), ("handynummer",), ("mobilnummer",), ("rufnummer",)],
        "fr": [("téléphone",), ("numéro", "de", "téléphone"), ("portable",), ("tél", "mobile")],
        "es": [("teléfono",), ("móvil",), ("número", "de", "teléfono")],
        "it": [("telefono",), ("cellulare",), ("numero", "di", "telefono")],
        "nl": [("telefoon",), ("telefoonnummer",), ("mobiel", "nummer")],
        "sv": [("telefon",), ("telefonnummer",), ("mobilnummer",)],
        "pl": [("telefon",), ("numer", "telefonu"), ("telefon", "komórkowy")],
        "pt": [("telefone",), ("telemóvel",), ("número", "de", "telefone")]}),
    "birth_date": ("pii.birth_date", {
        "en": [("date", "of", "birth"), ("birth", "date"), ("birthday",), ("birthdate",)],
        "de": [("geburtsdatum",), ("geburtstag",), ("geb", "datum")],
        "fr": [("date", "de", "naissance"), ("date", "naissance")],
        "es": [("fecha", "de", "nacimiento"), ("fecha", "nacimiento")],
        "it": [("data", "di", "nascita"), ("data", "nascita")], "nl": [("geboortedatum",)],
        "sv": [("födelsedatum",), ("födelsedag",)], "pl": [("data", "urodzenia")],
        "pt": [("data", "de", "nascimento"), ("data", "nascimento")]}),
    "street": ("pii.address", {
        "en": [("street",), ("address", "line1"), ("street", "address")],
        "de": [("straße",), ("straße", "hausnummer"), ("anschrift",)], "fr": [("adresse",), ("rue",)],
        "es": [("dirección",), ("calle",), ("domicilio",)], "it": [("indirizzo",), ("via",)],
        "nl": [("adres",), ("straat",), ("straatnaam",)], "sv": [("adress",), ("gatuadress",)],
        "pl": [("adres",), ("ulica",)], "pt": [("morada",), ("endereço",), ("rua",)]}),
    "address": ("pii.address", {
        "en": [("address",), ("home", "address"), ("mailing", "address")],
        "de": [("adresse",), ("wohnanschrift",), ("postanschrift",)],
        "fr": [("adresse", "postale"), ("adresse", "complète")], "es": [("dirección", "postal"), ("domicilio",)],
        "it": [("indirizzo", "di", "residenza"), ("residenza",)], "nl": [("woonadres",), ("postadres",)],
        "sv": [("postadress",), ("hemadress",)], "pl": [("adres", "zamieszkania"), ("adres", "korespondencyjny")],
        "pt": [("morada", "completa"), ("endereço", "postal")]}),
    "city": ("neutral", {
        "en": [("city",)], "de": [("ort",), ("stadt",), ("wohnort",)], "fr": [("ville",)],
        "es": [("ciudad",), ("localidad",)], "it": [("città",), ("comune",)], "nl": [("plaats",), ("woonplaats",)],
        "sv": [("ort",), ("postort",)], "pl": [("miasto",), ("miejscowość",)], "pt": [("cidade",), ("localidade",)]}),
    "postcode": ("neutral", {
        "en": [("zip", "code"), ("postal", "code")], "de": [("plz",), ("postleitzahl",)], "fr": [("code", "postal")],
        "es": [("código", "postal")], "it": [("cap",)], "nl": [("postcode",)], "sv": [("postnummer",)],
        "pl": [("kod", "pocztowy")], "pt": [("código", "postal")]}),
    "ssn": ("pii.national_id", {"en": [("ssn",), ("social", "security", "number"), ("social", "security", "no")]}),
    "tax_id": ("by-value", {
        "de": [("steuer", "id"), ("steueridentifikationsnummer",), ("steuerliche", "identifikationsnummer")],
        "it": [("codice", "fiscale")], "pt": [("nif",), ("número", "de", "contribuinte")]}),
    "social_security": ("pii.national_id", {
        "de": [("sozialversicherungsnummer",), ("rentenversicherungsnummer",), ("sv", "nummer")],
        "fr": [("numéro", "de", "sécurité", "sociale"), ("nir",), ("numéro", "sécu")]}),
    "id_card": ("pii.national_id", {"de": [("personalausweisnummer",), ("ausweisnummer",)]}),
    "driving_licence": ("pii.national_id", {"de": [("führerscheinnummer",), ("führerschein", "nr")]}),
    "national_id": ("pii.national_id", {
        "es": [("dni",), ("número", "dni"), ("documento", "de", "identidad")],
        "nl": [("bsn",), ("burgerservicenummer",)], "sv": [("personnummer",)], "pl": [("pesel",), ("numer", "pesel")]}),
    "iban": ("pii.iban", {
        "en": [("iban",)], "de": [("iban",), ("bankverbindung",)], "fr": [("iban",), ("rib", "iban")],
        "es": [("iban",), ("cuenta", "bancaria")], "it": [("iban",), ("coordinate", "bancarie")],
        "nl": [("iban",), ("rekeningnummer",)], "sv": [("iban",), ("bankkonto",)],
        "pl": [("iban",), ("numer", "rachunku")], "pt": [("iban",), ("nib",)]}),
    "account_number": ("pii.bank_account", {
        "en": [("account", "number"), ("bank", "account"), ("acct", "no")],
        "de": [("kontonummer",), ("konto", "nr")]}),
    "routing_number": ("pii.bank_account", {"en": [("routing", "number"), ("aba", "routing")]}),
    "card": ("pii.card", {
        "en": [("card", "number"), ("credit", "card"), ("cc", "number"), ("pan",)],
        "de": [("kartennummer",), ("kreditkartennummer",), ("kreditkarte",)],
        "fr": [("numéro", "de", "carte"), ("carte", "bancaire")], "es": [("número", "de", "tarjeta"), ("tarjeta",)],
        "it": [("numero", "carta"), ("carta", "di", "credito")], "nl": [("kaartnummer",), ("creditcardnummer",)],
        "sv": [("kortnummer",)], "pl": [("numer", "karty")], "pt": [("número", "do", "cartão"), ("cartão",)]}),
    "username": ("pii.username", {
        "en": [("username",), ("user", "name"), ("login",), ("handle",)],
        "de": [("benutzername",), ("benutzer",), ("anmeldename",)],
        "fr": [("nom", "d", "utilisateur"), ("identifiant",)], "es": [("nombre", "de", "usuario"), ("usuario",)],
        "it": [("nome", "utente"), ("utente",)], "nl": [("gebruikersnaam",)], "sv": [("användarnamn",)],
        "pl": [("nazwa", "użytkownika"), ("login",)], "pt": [("nome", "de", "utilizador"), ("utilizador",)]}),
    "password": ("secret.password", {
        "en": [("password",), ("passwd",), ("db", "password"), ("admin", "password")],
        "de": [("passwort",), ("kennwort",)], "fr": [("mot", "de", "passe"), ("mdp",)],
        "es": [("contraseña",), ("clave",)], "it": [("password",), ("parola", "chiave")],
        "nl": [("wachtwoord",)], "sv": [("lösenord",)], "pl": [("hasło",)], "pt": [("senha",), ("palavra", "passe")]}),
    "ip": ("pii.ip", {
        "en": [("ip", "address"), ("client", "ip"), ("remote", "addr"), ("last", "login", "ip")],
        "de": [("ip", "adresse"),], "fr": [("adresse", "ip")], "es": [("dirección", "ip")], "it": [("indirizzo", "ip")],
        "nl": [("ip", "adres")], "sv": [("ip", "adress")], "pl": [("adres", "ip")], "pt": [("endereço", "ip")]}),
    "api_key": ("secret.token", {
        "en": [("api", "key"), ("access", "token"), ("auth", "token"), ("secret", "key"), ("client", "secret")],
        "de": [("api", "schlüssel"), ("zugangsschlüssel",), ("zugangstoken",)],
        "fr": [("clé", "api"), ("jeton", "d", "accès"), ("clé", "secrète")],
        "es": [("clave", "api"), ("clave", "secreta"), ("token", "de", "acceso")],
        "it": [("chiave", "api"), ("chiave", "segreta"), ("token", "di", "accesso")],
        "nl": [("api", "sleutel"), ("toegangstoken",)], "sv": [("api", "nyckel"), ("åtkomstnyckel",)],
        "pl": [("klucz", "api"), ("klucz", "dostępu")], "pt": [("chave", "api"), ("chave", "secreta")]}),
    "private_key": ("secret.private_key", {
        "en": [("private", "key"), ("ssh", "key"), ("tls", "key"), ("signing", "key")],
        "de": [("privater", "schlüssel"),], "fr": [("clé", "privée")], "es": [("clave", "privada")],
        "it": [("chiave", "privata")], "nl": [("privésleutel",)], "sv": [("privat", "nyckel")],
        "pl": [("klucz", "prywatny")], "pt": [("chave", "privada")]}),
    "connection_string": ("secret.connection_string", {
        "en": [("database", "url"), ("connection", "string"), ("dsn",), ("db", "uri"), ("jdbc", "url")],
        "de": [("datenbank", "url"), ("verbindungszeichenfolge",)], "fr": [("chaîne", "de", "connexion")],
        "es": [("cadena", "de", "conexión")], "it": [("stringa", "di", "connessione")],
        "nl": [("verbindingsreeks",)], "sv": [("anslutningssträng",)], "pl": [("ciąg", "połączenia")],
        "pt": [("cadeia", "de", "ligação"), ("string", "de", "conexão")]}),
}

# the short forms developers write; one per element, rendered in snake or camel case
ABBREVIATIONS = {
    "first_name": {"en": ["fname", "first_nm"], "de": ["vname"]},
    "last_name": {"en": ["lname", "last_nm"], "de": ["nname"]},
    "full_name": {"en": ["cust_nm"]},
    "email": {"en": ["mail", "eml"], "fr": ["mel"]},
    "phone": {"en": ["tel", "ph", "mob", "phone_no"], "de": ["tel", "tel_nr", "handy"], "fr": ["tel"],
              "es": ["tlf", "tel"], "it": ["tel", "cell"], "nl": ["tel", "tel_nr"], "sv": ["tel", "mob"],
              "pl": ["tel", "nr_tel"], "pt": ["tel", "tlm"]},
    "birth_date": {"en": ["dob", "bday", "birth_dt"], "de": ["geb_dat", "gebdat"], "fr": ["date_naiss"],
                   "es": ["f_nac", "fec_nac"], "it": ["data_nasc"], "nl": ["geb_datum"], "sv": ["fodd"],
                   "pl": ["data_ur"], "pt": ["dt_nasc"]},
    "street": {"en": ["addr", "addr1", "str"], "de": ["str", "strasse_nr"], "pt": ["end"]},
    "address": {"en": ["addr", "adr"], "de": ["adr"]},
    "ssn": {"en": ["ssn_no", "soc_sec_no"]},
    "tax_id": {"de": ["stid", "st_idnr"], "it": ["cf", "cod_fisc"], "pt": ["nif_nr"]},
    "social_security": {"de": ["sv_nr", "rv_nr"], "fr": ["num_secu", "nss"]},
    "id_card": {"de": ["ausweis_nr", "perso_nr"]}, "driving_licence": {"de": ["fs_nr"]},
    "national_id": {"es": ["dni_nie"], "nl": ["bsn_nr"], "sv": ["pnr"], "pl": ["nr_pesel"]},
    "iban": {"en": ["iban_no"]},
    "account_number": {"en": ["acct", "acct_num"], "de": ["kto_nr", "ktonr"]},
    "routing_number": {"en": ["rtn", "aba"]},
    "card": {"en": ["cc_num", "ccnum", "card_no"], "de": ["kk_nr"], "fr": ["num_cb"]},
    "username": {"en": ["uname", "usr", "uid"], "de": ["benutzer_kz"]},
    "password": {"en": ["pwd", "pw", "pass", "passwd"], "de": ["pw", "pwd"], "fr": ["mdp"], "es": ["pwd", "clave"],
                 "it": ["pwd"], "nl": ["ww"], "sv": ["losen"], "pl": ["haslo"], "pt": ["pwd"]},
    "ip": {"en": ["ip", "ip_addr", "src_ip"]},
    "api_key": {"en": ["apikey", "api_tok", "tok"], "de": ["api_key"]},
    "private_key": {"en": ["priv_key", "pkey"]},
    "connection_string": {"en": ["conn_str", "db_url", "dburl"]},
}

STYLES = ("snake", "camel", "pascal", "kebab", "upper", "dotted", "doubled", "human", "abbr")

# the record a case describes, per language: its name as a table and as a key prefix
ENTITIES = {
    "en": ("customers", "customer"), "de": ("kunden", "kunde"), "fr": ("clients", "client"),
    "es": ("clientes", "cliente"), "it": ("clienti", "cliente"), "nl": ("klanten", "klant"),
    "sv": ("kunder", "kund"), "pl": ("klienci", "klient"), "pt": ("clientes", "cliente"),
}


def words_for(concept: str, lang: str):
    """The word sequences of a concept in a language; English when the language has none (a German config file
    also says api_key)."""
    table = CONCEPTS[concept][1]
    return table.get(lang) or table.get("en") or next(iter(table.values()))


def _ascii(words: tuple, lang: str, r: random.Random) -> tuple:
    if all(w.isascii() for w in words):
        return words
    if r.random() < 0.5:
        return words
    f = fold if (lang == "de" and r.random() < 0.7) else fold_plain
    return tuple(f(w) for w in words)


def render(words: tuple, style: str, lang: str) -> str:
    """A field name of the words in a spelling style."""
    if style == "snake":
        return "_".join(words)
    if style == "camel":
        return words[0] + "".join(w[:1].upper() + w[1:] for w in words[1:])
    if style == "pascal":
        return "".join(w[:1].upper() + w[1:] for w in words)
    if style == "kebab":
        return "-".join(words)
    if style == "upper":
        return "_".join(words).upper()
    if style == "dotted":
        return ".".join(words)
    if style == "doubled":
        return "__".join(words)
    if style == "human":
        if lang == "de":
            out = " ".join(w if w in ("der", "des", "von") else w[:1].upper() + w[1:] for w in words)
        else:
            out = " ".join(words)
            out = out[:1].upper() + out[1:]
        return out.replace("E mail", "E-Mail").replace("e mail", "e-mail").replace(" d ", " d'")
    raise ValueError(style)


def field_name(concept: str, lang: str, style: str, r: random.Random, prefix: str = "") -> tuple:
    """(name, tags) of a field of the concept: a word sequence of the language, maybe folded, in the style. The
    style abbr takes a short form when the concept has one and falls back to snake_case. A prefix (the entity)
    joins the words in the same style; the doubled style always puts the prefix before a single word."""
    tags = {"style": style, "lang": lang}
    if style == "abbr":
        short = ABBREVIATIONS.get(concept, {}).get(lang) or ABBREVIATIONS.get(concept, {}).get("en")
        if short:
            name = r.choice(short)
            tags["diacritics"] = "none"
            return (name if r.random() < 0.7 else render(tuple(name.split("_")), "camel", lang)), tags
        style = tags["style"] = "snake"
    words = r.choice(words_for(concept, lang))
    orig = words
    words = _ascii(words, lang, r)
    tags["diacritics"] = "none" if all(w.isascii() for w in orig) else ("kept" if words == orig else "folded")
    if style == "human":
        words = orig
        tags["diacritics"] = "none" if all(w.isascii() for w in orig) else "kept"
    if style == "doubled" and len(words) == 1:
        prefix = prefix or ENTITIES[lang][1]
    if prefix and style != "human":
        words = (prefix,) + words
    return render(words, style, lang), tags
