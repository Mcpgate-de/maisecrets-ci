"""The synthetic values of the structured corpus (docs/BENCHMARK-STRUCTURED.md, "Values").

Each value is drawn from a random.Random that the caller seeds, so a run gives the same values. No value is real:
names are a random pair of common given names and surnames, e-mail addresses lie under example.com or example.org,
hosts lie under example.org or the reserved .internal, and each number with a check digit gets the check digit of
its public algorithm. A secret is put together from its public format at run time, so the tree holds no secret
shape (scripts/scan_tree.py).

Every number algorithm here is written from its public definition (the reference in each docstring), not from the
detector. The locales: en (region us), de, fr, es, it, nl, sv (region se), pl, pt."""
from __future__ import annotations

import base64
import json
import random
import string
import zlib

LANGS = ("en", "de", "fr", "es", "it", "nl", "sv", "pl", "pt")
REGION = {"en": "us", "de": "de", "fr": "fr", "es": "es", "it": "it", "nl": "nl", "sv": "se", "pl": "pl", "pt": "pt"}
D, U, L = string.digits, string.ascii_uppercase, string.ascii_lowercase
AN, HEX, B62 = D + U + L, "0123456789abcdef", D + U + L
B64 = U + L + D + "+/"

# common given names and surnames per locale; a case pairs two at random, so no pair is meant to name anyone
GIVEN = {
    "en": ("James", "Mary", "Robert", "Linda", "Michael", "Emily", "Daniel", "Sarah", "Kevin", "Laura", "Brian",
           "Megan", "Tyler", "Hannah", "Marcus", "Olivia"),
    "de": ("Lukas", "Anna", "Jonas", "Lea", "Felix", "Laura", "Tobias", "Katrin", "Jürgen", "Sabine", "Matthias",
           "Ines", "Niklas", "Jana", "Björn", "Heike"),
    "fr": ("Camille", "Lucas", "Manon", "Hugo", "Chloé", "Théo", "Léa", "Mathis", "Inès", "Antoine", "Margaux",
           "Julien", "Océane", "Rémi", "Élodie", "Gaëtan"),
    "es": ("Lucía", "Hugo", "Martina", "Mateo", "Paula", "Álvaro", "Sofía", "Javier", "Carmen", "Diego", "Nerea",
           "Sergio", "Irene", "Rubén", "Ainhoa", "Íñigo"),
    "it": ("Giulia", "Lorenzo", "Chiara", "Matteo", "Francesca", "Alessandro", "Martina", "Davide", "Elisa",
           "Riccardo", "Federica", "Simone", "Ilaria", "Niccolò", "Beatrice", "Gianluca"),
    "nl": ("Daan", "Emma", "Sem", "Julia", "Lars", "Sanne", "Bram", "Fleur", "Thijs", "Lotte", "Joris", "Anouk",
           "Ruben", "Femke", "Stijn", "Maaike"),
    "sv": ("Erik", "Elsa", "Oskar", "Maja", "Axel", "Astrid", "Viktor", "Ebba", "Gustav", "Linnéa", "Hugo", "Saga",
           "Anders", "Ingrid", "Måns", "Åsa"),
    "pl": ("Jakub", "Zofia", "Kacper", "Julia", "Mateusz", "Agnieszka", "Paweł", "Katarzyna", "Łukasz", "Małgorzata",
           "Wojciech", "Ewa", "Michał", "Joanna", "Bartosz", "Żaneta"),
    "pt": ("João", "Beatriz", "Tiago", "Inês", "Rodrigo", "Mariana", "Gonçalo", "Leonor", "Duarte", "Carolina",
           "Afonso", "Matilde", "Rui", "Sofia", "Vasco", "Lúcia"),
}
SURNAMES = {
    "en": ("Miller", "Johnson", "Carter", "Brooks", "Turner", "Hayes", "Foster", "Bennett", "Griffin", "Coleman",
           "Russell", "Parker", "Sullivan", "Hughes", "Price", "Reed"),
    "de": ("Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Becker", "Wagner", "Hoffmann", "Schäfer", "Koch",
           "Krüger", "Zimmermann", "Braun", "Hartmann", "Lange", "Weiß"),
    "fr": ("Martin", "Bernard", "Dubois", "Thomas", "Robert", "Petit", "Durand", "Leroy", "Moreau", "Lefèvre",
           "Fournier", "Girard", "Bonnet", "Mercier", "Faure", "Rousseau"),
    "es": ("García", "Fernández", "González", "Rodríguez", "López", "Martínez", "Sánchez", "Pérez", "Gómez",
           "Jiménez", "Ruiz", "Hernández", "Díaz", "Moreno", "Muñoz", "Álvarez"),
    "it": ("Rossi", "Russo", "Ferrari", "Esposito", "Bianchi", "Romano", "Colombo", "Ricci", "Marino", "Greco",
           "Bruno", "Gallo", "Conti", "De Luca", "Mancini", "Lombardi"),
    "nl": ("de Jong", "Jansen", "de Vries", "van den Berg", "van Dijk", "Bakker", "Janssen", "Visser", "Smit",
           "Meijer", "de Boer", "Mulder", "de Groot", "Bos", "Vos", "Peters"),
    "sv": ("Andersson", "Johansson", "Karlsson", "Nilsson", "Eriksson", "Larsson", "Olsson", "Persson", "Svensson",
           "Gustafsson", "Pettersson", "Jonsson", "Lindberg", "Lindqvist", "Bergström", "Åberg"),
    "pl": ("Nowak", "Kowalski", "Wiśniewski", "Wójcik", "Kowalczyk", "Kamiński", "Lewandowski", "Zieliński",
           "Szymański", "Woźniak", "Dąbrowski", "Kozłowski", "Jankowski", "Mazur", "Kwiatkowski", "Krawczyk"),
    "pt": ("Silva", "Santos", "Ferreira", "Pereira", "Oliveira", "Costa", "Rodrigues", "Martins", "Jesus", "Sousa",
           "Fernandes", "Gonçalves", "Gomes", "Lopes", "Marques", "Alves"),
}
STREET = {
    "en": ("{n} {w} {k}", ("Oak", "Maple", "Cedar", "Hillcrest", "Lakeview", "Willow", "Sunset", "Ridge"),
           ("Street", "Avenue", "Road", "Drive", "Lane", "Court", "Blvd", "St.")),
    "de": ("{w}{k} {n}", ("Linden", "Birken", "Garten", "Bahnhof", "Schiller", "Goethe", "Rosen", "Mühlen"),
           ("straße", "str.", "weg", "allee", "gasse", "ring")),
    "fr": ("{n} {k} {w}", ("des Lilas", "de la Paix", "Victor Hugo", "du Moulin", "des Écoles", "Pasteur",
                           "de la Gare", "Jean Jaurès"), ("rue", "avenue", "boulevard", "allée", "impasse", "chemin")),
    "es": ("{k} {w}, {n}", ("Mayor", "de Alcalá", "del Sol", "de la Paz", "Real", "de Cervantes", "Nueva",
                            "San Fernando"), ("Calle", "Avenida", "Paseo", "Plaza", "C/")),
    "it": ("{k} {w}, {n}", ("Roma", "Garibaldi", "Mazzini", "dei Mille", "Verdi", "Cavour", "della Libertà",
                            "Dante"), ("Via", "Viale", "Piazza", "Corso", "Vicolo")),
    "nl": ("{w}{k} {n}", ("Kerk", "Molen", "Dorps", "Linden", "Beuken", "School", "Spoor", "Wilhelmina"),
           ("straat", "weg", "laan", "plein", "gracht", "dijk")),
    "sv": ("{w}{k} {n}", ("Stor", "Kyrko", "Skol", "Björk", "Ek", "Sjö", "Kvarn", "Drottning"),
           ("gatan", "vägen", "gränd", "stigen", "backen")),
    "pl": ("{k} {w} {n}", ("Kwiatowa", "Lipowa", "Polna", "Leśna", "Słoneczna", "Mickiewicza", "Szkolna",
                           "Ogrodowa"), ("ul.", "al.", "ulica", "pl.")),
    "pt": ("{k} {w}, {n}", ("das Flores", "da Liberdade", "do Comércio", "de São João", "dos Pescadores",
                            "da Igreja", "Direita", "do Sol"), ("Rua", "Avenida", "Travessa", "Largo", "Praça")),
}
CITY = {
    "en": (("Springfield", "IL"), ("Fairview", "OR"), ("Riverside", "CA"), ("Madison", "WI"), ("Georgetown", "TX")),
    "de": ("Leipzig", "Kassel", "Erfurt", "Würzburg", "Göttingen"),
    "fr": ("Lyon", "Nantes", "Rennes", "Grenoble", "Besançon"),
    "es": ("Zaragoza", "Valladolid", "Córdoba", "Alicante", "Logroño"),
    "it": ("Bologna", "Torino", "Verona", "Parma", "Perugia"),
    "nl": ("Utrecht", "Groningen", "Haarlem", "Zwolle", "Leiden"),
    "sv": ("Uppsala", "Västerås", "Örebro", "Linköping", "Umeå"),
    "pl": ("Kraków", "Poznań", "Wrocław", "Gdańsk", "Łódź"),
    "pt": ("Braga", "Coimbra", "Aveiro", "Faro", "Évora"),
}
MAIL_DOMAINS = ("example.com", "example.org")
HOST_SUFFIXES = ("example.org", "example.internal", "corp.internal")


def rd(r: random.Random, n: int, chars: str = AN) -> str:
    return "".join(r.choice(chars) for _ in range(n))


def fold(s: str) -> str:
    """The ASCII spelling a developer types in an identifier: ß ss, ä ae (German), others without the accent."""
    import unicodedata
    for a, b in (("ß", "ss"), ("Ä", "Ae"), ("Ö", "Oe"), ("Ü", "Ue"), ("ä", "ae"), ("ö", "oe"), ("ü", "ue"),
                 ("ł", "l"), ("Ł", "L"), ("ø", "o"), ("æ", "ae"), ("å", "a"), ("Å", "A")):
        s = s.replace(a, b)
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


def fold_plain(s: str) -> str:
    """The ASCII spelling without the German ae/oe/ue (the Swedish and Polish identifiers, and a lazy German one)."""
    import unicodedata
    s = s.replace("ß", "ss").replace("ł", "l").replace("Ł", "L")
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


# ----------------------------------------------------------------------------------------- people and places --
def person(r: random.Random, lang: str) -> dict:
    first, last = r.choice(GIVEN[lang]), r.choice(SURNAMES[lang])
    year = r.randint(1946, 2006)
    month, day = r.randint(1, 12), r.randint(1, 28)
    local = r.choice((f"{first}.{last}", f"{first[0]}{last}", f"{first}{r.randint(1, 99)}", f"{last}.{first[0]}"))
    local = fold_plain(local).lower().replace(" ", "")
    city = r.choice(CITY[lang])
    return {
        "lang": lang, "first": first, "last": last, "name": f"{first} {last}",
        "email": f"{local}@{r.choice(MAIL_DOMAINS)}",
        "phone": phone(r, lang), "street": street(r, lang), "city": city[0] if isinstance(city, tuple) else city,
        "state": city[1] if isinstance(city, tuple) else "", "postcode": postcode(r, lang),
        "dob": date_text(r, lang, year, month, day), "dob_iso": f"{year}-{month:02d}-{day:02d}",
        "year": year, "month": month, "day": day,
    }


def street(r: random.Random, lang: str) -> str:
    form, words, kinds = STREET[lang]
    n = str(r.randint(1, 240)) + (r.choice(("", "", "", "a", "b")) if lang in ("de", "nl", "it") else "")
    return form.format(n=n, w=r.choice(words), k=r.choice(kinds))


def postcode(r: random.Random, lang: str) -> str:
    n = r.randint
    return {"en": f"{n(10001, 99950):05d}", "de": f"{n(1067, 99998):05d}", "fr": f"{n(1000, 95999):05d}",
            "es": f"{n(1001, 52080):05d}", "it": f"{n(10, 98168):05d}", "nl": f"{n(1011, 9999)} {rd(r, 2, U)}",
            "sv": f"{n(100, 984)} {n(10, 99)}", "pl": f"{n(10, 99)}-{n(100, 999)}",
            "pt": f"{n(1000, 9999)}-{n(100, 999)}"}[lang]


def full_address(r: random.Random, p: dict) -> tuple:
    """A one-line address and the length of its street part (the core of the span: city and postcode stay text by
    policy, docs/BENCHMARK-STRUCTURED.md, "Spans")."""
    lang = p["lang"]
    if lang == "en":
        tail = f", {p['city']}, {p['state']} {p['postcode']}"
    elif lang in ("sv", "nl"):
        tail = f", {p['postcode']}  {p['city']}" if lang == "sv" else f", {p['postcode']} {p['city']}"
    else:
        tail = f", {p['postcode']} {p['city']}"
    return p["street"] + tail, len(p["street"])


def phone(r: random.Random, lang: str) -> str:
    n = r.randint
    if lang == "en":
        a = r.choice([x for x in range(201, 990) if x % 100 != 11 and str(x)[1] != "9"])
        e, x = n(201, 989), n(0, 9999)
        return r.choice((f"({a}) {e}-{x:04d}", f"{a}-{e}-{x:04d}", f"+1 {a} {e} {x:04d}", f"{a}.{e}.{x:04d}"))
    if lang == "de":
        mob = r.choice(("151", "152", "160", "170", "171", "176", "157"))
        body = f"{n(1000000, 9999999)}"
        land = r.choice(("30", "40", "89", "221", "341", "561", "911"))
        return r.choice((f"+49 {mob} {body}", f"0{mob} {body}", f"+49 ({land}) {n(100000, 9999999)}",
                         f"0{land}/{n(100000, 9999999)}", f"0{mob}-{body[:3]} {body[3:]}"))
    if lang == "fr":
        g = [f"{n(0, 99):02d}" for _ in range(4)]
        k = r.choice(("6", "7", "1", "4"))
        return r.choice((f"0{k} {' '.join(g)}", f"+33 {k} {' '.join(g)}", f"0{k}.{'.'.join(g)}", f"+33{k}{''.join(g)}"))
    if lang == "es":
        k = r.choice(("6", "7", "9"))
        a, b, c = n(10, 99), n(100, 999), n(100, 999)
        return r.choice((f"{k}{a} {b} {c}", f"+34 {k}{a} {b} {c}", f"+34{k}{a}{b}{c}", f"{k}{a}-{b}-{c}"))
    if lang == "it":
        k = r.choice(("320", "333", "347", "339", "02", "06"))
        return r.choice((f"+39 {k} {n(100, 999)} {n(1000, 9999)}", f"{k} {n(1000000, 9999999)}",
                         f"+39{k}{n(1000000, 9999999)}"))
    if lang == "nl":
        return r.choice((f"06-{n(10000000, 99999999)}", f"+31 6 {n(10000000, 99999999)}",
                         f"020-{n(1000000, 9999999)}", f"+31 (0)6 {n(1000, 9999)} {n(1000, 9999)}"))
    if lang == "sv":
        k = r.choice(("70", "72", "73", "76"))
        return r.choice((f"0{k}-{n(100, 999)} {n(10, 99)} {n(10, 99)}",
                         f"+46 {k} {n(100, 999)} {n(10, 99)} {n(10, 99)}",
                         f"08-{n(100, 999)} {n(100, 999)} {n(10, 99)}"))
    if lang == "pl":
        k = r.choice(("50", "51", "53", "60", "66", "69", "72", "78", "88"))
        return r.choice((f"+48 {k}{n(1, 9)} {n(100, 999)} {n(100, 999)}", f"{k}{n(1, 9)}-{n(100, 999)}-{n(100, 999)}",
                         f"{k}{n(1, 9)} {n(100, 999)} {n(100, 999)}"))
    k = r.choice(("91", "92", "93", "96", "21", "22"))
    return r.choice((f"+351 {k}{n(1, 9)} {n(100, 999)} {n(100, 999)}", f"{k}{n(1, 9)} {n(100, 999)} {n(100, 999)}",
                     f"+351{k}{n(1000000, 9999999)}"))


MONTHS = {
    "en": ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
           "November", "December"),
    "de": ("Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober",
           "November", "Dezember"),
    "fr": ("janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre",
           "novembre", "décembre"),
}


def date_text(r: random.Random, lang: str, y: int, m: int, d: int) -> str:
    """A date as a person or a system of the locale writes it."""
    iso = f"{y}-{m:02d}-{d:02d}"
    if lang == "en":
        return r.choice((iso, f"{m:02d}/{d:02d}/{y}", f"{m}/{d}/{y}", f"{MONTHS['en'][m - 1]} {d}, {y}"))
    if lang in ("de", "pl"):
        return r.choice((iso, f"{d:02d}.{m:02d}.{y}", f"{d}.{m}.{y}"))
    if lang in ("fr", "es", "it", "pt"):
        return r.choice((iso, f"{d:02d}/{m:02d}/{y}", f"{d:02d}-{m:02d}-{y}"))
    if lang == "nl":
        return r.choice((iso, f"{d:02d}-{m:02d}-{y}", f"{d}-{m}-{y}"))
    return r.choice((iso, f"{y}{m:02d}{d:02d}", f"{y}-{m:02d}-{d:02d}"))


def ipv4(r: random.Random) -> str:
    """A global unicast address (no private, documentation, shared or reserved block)."""
    first = r.choice((23, 31, 37, 46, 62, 77, 81, 85, 91, 95, 109, 176, 185, 188, 212, 213, 217, 24, 64, 68, 73, 98,
                      108, 174))
    return f"{first}.{r.randint(1, 254)}.{r.randint(0, 254)}.{r.randint(1, 254)}"


def ipv6(r: random.Random) -> str:
    head = r.choice(("2a02", "2a01", "2003", "2600", "2001:16b8", "2a00"))
    parts = head.split(":") + [f"{r.randint(0, 0xffff):x}" for _ in range(4 - head.count(":"))]
    return ":".join(parts) + "::" + f"{r.randint(1, 0xffff):x}"


def username(r: random.Random, p: dict) -> str:
    f, la = fold_plain(p["first"]).lower(), fold_plain(p["last"]).lower().replace(" ", "")
    return r.choice((f"{f}.{la}", f"{f[0]}{la}", f"{f}{r.randint(10, 9999)}", f"{la}_{f[:3]}", f"{f}-{la[:4]}",
                     f"{f[:1]}{la[:6]}{r.randint(1, 99)}"))


# ------------------------------------------------------------------------------------ checksum numbers --
def luhn_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return str((10 - total % 10) % 10)


def card(r: random.Random) -> str:
    """A payment card number (ISO/IEC 7812-1, Luhn): Visa, Mastercard, American Express or Discover, as printed."""
    kind = r.choice(("visa", "visa", "mc", "mc2", "amex", "disc"))
    prefix, length = {"visa": ("4", 16), "mc": (str(r.randint(51, 55)), 16), "mc2": (str(r.randint(2221, 2720)), 16),
                      "amex": (r.choice(("34", "37")), 15), "disc": ("6011", 16)}[kind]
    body = prefix + rd(r, length - len(prefix) - 1, D)
    num = body + luhn_digit(body)
    if length == 15:
        return r.choice((num, f"{num[:4]} {num[4:10]} {num[10:]}"))
    return r.choice((num, " ".join(num[i:i + 4] for i in range(0, 16, 4)), "-".join(num[i:i + 4]
                                                                                    for i in range(0, 16, 4))))


def _mod97(s: str) -> int:
    return int("".join(str(int(c, 36)) for c in s)) % 97


_IT_ODD = dict(zip(D + U, (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3,
                           6, 8, 12, 14, 16, 10, 22, 25, 24, 23)))


def _it_check(s: str) -> str:
    """The check letter of the Italian codice fiscale and of the CIN of an Italian account (DM 23/12/1976; CIN by
    the ABI convention): odd places by the odd table, even places by their value (A=0), the sum modulo 26."""
    total = sum(_IT_ODD[c] if i % 2 == 0 else (int(c) if c.isdigit() else ord(c) - 65) for i, c in enumerate(s))
    return chr(65 + total % 26)


def _es_dc(digits: str) -> str:
    w = (1, 2, 4, 8, 5, 10, 9, 7, 3, 6)
    v = 11 - sum(int(c) * k for c, k in zip(digits, w)) % 11
    return "0" if v == 11 else "1" if v == 10 else str(v)


def iban(r: random.Random, lang: str) -> str:
    """An IBAN (ISO 13616) with the length and BBAN structure of the SWIFT registry, and the national check digits
    where they are simple (fr RIB key, es DC, it CIN, nl 11-check, pt NIB)."""
    if lang == "fr":
        bank, branch, acct = rd(r, 5, D), rd(r, 5, D), rd(r, 11, D)
        key = 97 - (89 * int(bank) + 15 * int(branch) + 3 * int(acct)) % 97
        cc, bban = "FR", f"{bank}{branch}{acct}{key:02d}"
    elif lang == "es":
        bank, branch, acct = rd(r, 4, D), rd(r, 4, D), rd(r, 10, D)
        cc, bban = "ES", bank + branch + _es_dc("00" + bank + branch) + _es_dc(acct) + acct
    elif lang == "it":
        abi, cab, acct = rd(r, 5, D), rd(r, 5, D), rd(r, 12, D)
        cc, bban = "IT", _it_check(abi + cab + acct) + abi + cab + acct
    elif lang == "nl":
        while True:
            acct = rd(r, 10, D)
            if sum(int(c) * w for c, w in zip(acct, range(10, 0, -1))) % 11 == 0 and acct[0] != "0":
                break
        cc, bban = "NL", r.choice(("ABNA", "RABO", "INGB", "SNSB", "TRIO", "ASNB")) + acct
    elif lang == "sv":
        cc, bban = "SE", rd(r, 20, D)
    elif lang == "pl":
        cc, bban = "PL", rd(r, 24, D)
    elif lang == "pt":
        b = rd(r, 4, D) + rd(r, 4, D) + rd(r, 11, D)
        cc, bban = "PT", b + f"{98 - int(b + '00') % 97:02d}"
    else:
        cc, bban = "DE", rd(r, 8, D) + rd(r, 10, D)
    check = 98 - _mod97(bban + cc + "00")
    v = f"{cc}{check:02d}{bban}"
    return r.choice((v, v, " ".join(v[i:i + 4] for i in range(0, len(v), 4))))


def aba_routing(r: random.Random) -> str:
    """An ABA routing number: a Federal Reserve prefix and the 3-7-1 check digit."""
    head = r.choice([f"{x:02d}" for x in list(range(1, 13)) + list(range(21, 33))])
    body = head + rd(r, 6, D)
    s = sum(int(c) * w for c, w in zip(body, (3, 7, 1, 3, 7, 1, 3, 7)))
    return body + str((10 - s % 10) % 10)


def account_number(r: random.Random, lang: str) -> str:
    return rd(r, r.randint(9, 12), D) if lang == "en" else rd(r, r.choice((8, 10)), D)


def us_ssn(r: random.Random) -> str:
    area = r.choice([a for a in range(1, 900) if a != 666])
    v = f"{area:03d}-{r.randint(1, 99):02d}-{r.randint(1, 9999):04d}"
    return r.choice((v, v, v.replace("-", ""), v.replace("-", " ")))


def de_tax_id(r: random.Random) -> str:
    """The German IdNr (§ 139b AO): 11 digits, the first not 0, one digit two or three times in the first ten and no
    other repeated, no digit three times in a row, the check digit by ISO 7064 MOD 11,10."""
    while True:
        digits = [r.randint(1, 9)] + [r.randint(0, 9) for _ in range(9)]
        counts = sorted((digits.count(x) for x in set(digits)), reverse=True)
        if counts[0] in (2, 3) and sum(1 for c in counts if c > 1) == 1 and not any(
                digits[i] == digits[i + 1] == digits[i + 2] for i in range(8)):
            break
    product = 10
    for x in digits:
        s = (x + product) % 10 or 10
        product = (s * 2) % 11
    check = 11 - product
    v = "".join(map(str, digits)) + str(0 if check == 10 else check)
    return r.choice((v, v, f"{v[:2]} {v[2:5]} {v[5:8]} {v[8:]}"))


def de_social_security(r: random.Random, p: dict) -> str:
    """The German Rentenversicherungsnummer (§ 147 SGB VI, VKVV): area, birth date DDMMYY, the initial of the birth
    name as two digits, a serial and a check digit (weights 2 1 2 5 7 1 2 1 2 1 2 1, cross sums, modulo 10)."""
    area = r.choice(("02", "04", "08", "10", "12", "13", "15", "16", "17", "18", "21", "23", "24", "25", "26", "28"))
    birth = f"{p['day']:02d}{p['month']:02d}{p['year'] % 100:02d}"
    letter = fold(p["last"])[0].upper()
    serial = f"{r.randint(0, 49) if r.random() < .5 else r.randint(50, 99):02d}"
    digits = area + birth + f"{ord(letter) - 64:02d}" + serial
    total = sum(sum(divmod(int(c) * w, 10)) for c, w in zip(digits, (2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1)))
    return f"{area}{birth}{letter}{serial}{total % 10}"


def de_id_card(r: random.Random) -> str:
    """A German ID card number since 2010: 9 characters of the digits and the consonants C F G H J K L M N P R T V
    W X Y Z (Personalausweisverordnung)."""
    return r.choice("CFGHJKLMNPRTVWXYZ") + rd(r, 8, "CFGHJKLMNPRTVWXYZ0123456789")


def de_driving_licence(r: random.Random) -> str:
    """A German card driving licence number as printed: 11 characters, an authority code and serial (letters and
    digits). The format follows the shape public recognisers use; its check digit is not computed (a limit)."""
    return rd(r, 2, U) + rd(r, 8, D) + r.choice(U + D)


def fr_nir(r: random.Random, p: dict) -> str:
    """The French NIR (numéro de sécurité sociale): sex, YY, MM, département, commune, order, and the key 97 - n mod
    97."""
    sex = r.choice("12")
    dept = f"{r.randint(1, 95):02d}"
    body = f"{sex}{p['year'] % 100:02d}{p['month']:02d}{dept}{r.randint(1, 990):03d}{r.randint(1, 999):03d}"
    key = 97 - int(body) % 97
    v = body + f"{key:02d}"
    return r.choice((v, f"{v[0]} {v[1:3]} {v[3:5]} {v[5:7]} {v[7:10]} {v[10:13]} {v[13:]}"))


def es_dni(r: random.Random) -> str:
    n = r.randint(10000000, 99999999)
    v = f"{n}{'TRWAGMYFPDXBNJZSQVHLCKE'[n % 23]}"
    return r.choice((v, v, f"{v[:8]}-{v[8]}"))


def it_codice_fiscale(r: random.Random, p: dict) -> str:
    """The Italian codice fiscale (DM 23/12/1976): three consonants of the surname and of the name, YY, the month
    letter, the day (+40 for women), a municipality code and the check letter."""
    def cons(s):
        s = fold(s).upper().replace(" ", "")
        c = [x for x in s if x.isalpha() and x not in "AEIOU"] + [x for x in s if x in "AEIOU"] + ["X"] * 3
        return "".join(c[:3])
    day = p["day"] + (40 if r.random() < 0.5 else 0)
    body = (cons(p["last"]) + cons(p["first"]) + f"{p['year'] % 100:02d}" + "ABCDEHLMPRST"[p["month"] - 1]
            + f"{day:02d}" + r.choice("ABCDEFGHILM") + f"{r.randint(1, 999):03d}")
    return body + _it_check(body)


def nl_bsn(r: random.Random) -> str:
    """The Dutch BSN: 9 digits, the 11-check with weights 9 to 2 and -1."""
    while True:
        d = rd(r, 9, D)
        if d[0] != "0" and (sum(int(c) * w for c, w in zip(d, (9, 8, 7, 6, 5, 4, 3, 2, -1))) % 11 == 0):
            return d


def se_personnummer(r: random.Random, p: dict) -> str:
    """The Swedish personnummer (Skatteverket): YYMMDD, a separator, three digits and a Luhn digit over the ten."""
    body = f"{p['year'] % 100:02d}{p['month']:02d}{p['day']:02d}{r.randint(1, 999):03d}"
    v = body + luhn_digit(body)
    return r.choice((f"{v[:6]}-{v[6:]}", f"{p['year'] // 100}{v[:6]}-{v[6:]}", f"{p['year'] // 100}{v}"))


def pl_pesel(r: random.Random, p: dict) -> str:
    """The Polish PESEL: YYMMDD (the month +20 after 1999), four digits, the check digit by weights 1 3 7 9."""
    month = p["month"] + (20 if p["year"] >= 2000 else 0)
    body = f"{p['year'] % 100:02d}{month:02d}{p['day']:02d}{r.randint(0, 9999):04d}"
    s = sum(int(c) * w for c, w in zip(body, (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)))
    return body + str((10 - s % 10) % 10)


def pt_nif(r: random.Random) -> str:
    """The Portuguese NIF: 9 digits, a person's starts with 1, 2 or 3, the check digit by modulo 11."""
    body = r.choice("123") + rd(r, 7, D)
    s = sum(int(c) * w for c, w in zip(body, range(9, 1, -1)))
    c = 11 - s % 11
    return body + ("0" if c >= 10 else str(c))


def national_id(r: random.Random, p: dict) -> tuple:
    """(concept, value, class) of a national number of the person's locale."""
    lang = p["lang"]
    options = {
        "en": [("ssn", us_ssn(r), "pii.national_id")],
        "de": [("tax_id", de_tax_id(r), "pii.tax_id"), ("social_security", de_social_security(r, p),
                                                       "pii.national_id"),
               ("id_card", de_id_card(r), "pii.national_id"), ("driving_licence", de_driving_licence(r),
                                                              "pii.national_id")],
        "fr": [("social_security", fr_nir(r, p), "pii.national_id")],
        "es": [("national_id", es_dni(r), "pii.national_id")],
        "it": [("tax_id", it_codice_fiscale(r, p), "pii.national_id")],
        "nl": [("national_id", nl_bsn(r), "pii.national_id")],
        "sv": [("national_id", se_personnummer(r, p), "pii.national_id")],
        "pl": [("national_id", pl_pesel(r, p), "pii.national_id")],
        "pt": [("tax_id", pt_nif(r), "pii.tax_id")],
    }[lang]
    return r.choice(options)


# ------------------------------------------------------------------------------------------------ secrets --
def password(r: random.Random) -> str:
    """A password a person or a generator makes (NIST SP 800-63B allows any printable character)."""
    words = ("Falke", "Orbit", "Kiwi", "Tundra", "Lantern", "Mosaik", "Zephyr", "Granit", "Velvet", "Quarz")
    kind = r.randrange(4)
    if kind == 0:
        return r.choice(words) + str(r.randint(10, 99)) + r.choice("!#$%&*?") + rd(r, 3, AN)
    if kind == 1:
        return rd(r, r.randint(14, 24), AN + "!#%*+-_=")
    if kind == 2:
        return "-".join(r.choice(("amber", "copper", "harbor", "violin", "meadow", "pixel", "glacier", "nectar"))
                        for _ in range(4)) + str(r.randint(1, 9))
    return rd(r, 2, U) + rd(r, 6, L) + str(r.randint(1000, 9999)) + r.choice("@$!.")


def _gh(r: random.Random, kind: str) -> str:
    """A GitHub token (ghp_, gho_, ghs_ …): 30 random base62 characters and the CRC32 of them in 6 base62 digits."""
    body = rd(r, 30, B62)
    crc = zlib.crc32(body.encode()) & 0xffffffff
    tail = ""
    while crc:
        crc, d = divmod(crc, 62)
        tail = B62[d] + tail
    return kind + "_" + body + tail.rjust(6, "0")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def jwt(r: random.Random) -> str:
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"sub": str(r.randint(10000, 99999999)), "iat": r.randint(1760000000, 1790000000),
              "scope": r.choice(("read", "read write", "admin"))}
    body = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    return f"{head}.{body}.{_b64url(bytes(r.randrange(256) for _ in range(32)))}"


def token(r: random.Random) -> tuple:
    """(kind, value) of an API key or token, in the public format of its vendor."""
    kind = r.choice(("github", "gitlab", "slack", "aws_id", "aws_secret", "stripe", "openai", "google", "jwt", "npm",
                     "sendgrid", "hex32", "hex40", "b64"))
    v = {
        "github": lambda: _gh(r, r.choice(("ghp", "gho", "ghs"))),
        "gitlab": lambda: "glp" + "at-" + rd(r, 20, AN + "_-"),
        "slack": lambda: "xox" + r.choice("bp") + f"-{rd(r, 12, D)}-{rd(r, 12, D)}-{rd(r, 24, AN)}",
        "aws_id": lambda: "AK" + "IA" + rd(r, 16, U + "234567"),
        "aws_secret": lambda: rd(r, 40, AN + "+/"),
        "stripe": lambda: "sk_" + "live_" + rd(r, 24, AN),
        "openai": lambda: "sk-" + "proj-" + rd(r, 48, AN + "_-"),
        "google": lambda: "AI" + "za" + rd(r, 35, AN + "_-"),
        "jwt": lambda: jwt(r),
        "npm": lambda: "npm" + "_" + rd(r, 36, AN),
        "sendgrid": lambda: "SG" + "." + rd(r, 22, AN + "_-") + "." + rd(r, 43, AN + "_-"),
        "hex32": lambda: rd(r, 32, HEX),
        "hex40": lambda: rd(r, 40, HEX),
        "b64": lambda: rd(r, 43, AN + "+/") + "=",
    }[kind]()
    return kind, v


def private_key(r: random.Random) -> str:
    kind = r.choice(("RSA ", "EC ", "OPENSSH ", ""))
    lines = [rd(r, 64, B64) for _ in range(r.randint(5, 12))] + [rd(r, r.randint(8, 60), B64) + "=="]
    dashes = "-" * 5
    return f"{dashes}BEGIN {kind}PRIVATE KEY{dashes}\n" + "\n".join(lines) + f"\n{dashes}END {kind}PRIVATE KEY{dashes}"


def connection_string(r: random.Random, user: str, pw: str) -> tuple:
    """(value, start of the password in it): a URI or a key-value string with a password."""
    host = f"{r.choice(('db', 'pg', 'mysql', 'mongo', 'cache', 'mq'))}{r.randint(1, 9)}.{r.choice(HOST_SUFFIXES)}"
    kind = r.randrange(7)
    if kind == 0:
        pre = f"postgresql://{user}:"
        return pre + pw + f"@{host}:5432/{r.choice(('app', 'crm', 'billing'))}", len(pre)
    if kind == 1:
        pre = f"mysql://{user}:"
        return pre + pw + f"@{host}:3306/shop", len(pre)
    if kind == 2:
        pre = f"mongodb+srv://{user}:"
        return pre + pw + f"@{host}/orders?retryWrites=true&w=majority", len(pre)
    if kind == 3:
        pre = "redis://:"
        return pre + pw + f"@{host}:6379/0", len(pre)
    if kind == 4:
        pre = f"amqp://{user}:"
        return pre + pw + f"@{host}:5672/%2F", len(pre)
    if kind == 5:
        pre = f"Server={host};Database=crm;User Id={user};Password="
        return pre + pw + ";Encrypt=True;", len(pre)
    pre = f"jdbc:postgresql://{host}:5432/app?user={user}&password="
    return pre + pw + "&ssl=true", len(pre)


def pw_for_uri(r: random.Random) -> str:
    """A password that needs no percent-encoding in a URI or a key-value string."""
    return rd(r, r.randint(12, 22), AN + "-_.~")
