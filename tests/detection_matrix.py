"""A generated matrix of inputs with known answers for the detector.

Each case combines a label, a separator, a value shape, what follows the value and the text
around it, and says exactly which span is the secret (and which is an e-mail address). The
cases are drawn from the full product with a fixed seed, so a run is reproducible and a
failure names its combination. Every value is generated here; nothing comes from real data.

Two cases found by hand on 2026-09-27 started it: `password:X and a@b.de` lost the password
(the value ran to the end of the line and was then rejected as prose), and
a password of two letters in turn after `password:` was taken for filler.
"""
from __future__ import annotations

import itertools
import random
import string
from dataclasses import dataclass, field

# the detect-secrets denylist words, and the examples of the label files of English and German
# (maisecrets/detection/rules/labels/*.txt): a new label file adds its words to the matrix
DENYLIST_LABELS = ["password", "pwd", "passwd", "Password", "PASSWORD", "secret", "api_key", "apikey", "API_KEY",
                   "db_password", "client_secret"]


def _file_labels() -> list[str]:
    # the languages of the pinned test locale (de_DE); since 0.8.2 every label file is on by default, and
    # tests/test_label_languages.py runs the examples of the others in the same shapes
    from maisecrets import regions
    return [ex for lang in ("en", "de") for lab in regions.load_labels(lang) for ex in lab.examples]


LABELS = DENYLIST_LABELS + _file_labels()
# " : " and "\u00a0: " are French typography, and a common way to type a label anywhere
SEPARATORS = [":", ": ", "=", " = ", ":\n", ": \n\n", " : ", "\u00a0: "]
AFTER = ["", " and more words", " {mail}", " and {mail}", ", thanks", "\nnext line here", " (see above)"]
CONTEXTS = ["{x}", "please use {x} for the login", "Bitte nimm {x} fuer den Zugang",
            "2026-09-27 12:00:01 INFO request {x}", "- {x}", "> {x}"]


@dataclass
class Case:
    text: str
    secret: str | None            # the exact value that must be found as a SECRET, or None
    mail: str | None = None       # an e-mail address that must be found as EMAIL
    combo: tuple = field(default_factory=tuple)


def _value(rnd: random.Random, shape: str) -> str:
    if shape == "mixed":
        while True:
            v = "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(rnd.randint(10, 24)))
            if any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
                return v
    if shape == "two-letters":
        # not x: a run of x is a placeholder mask on purpose (xxxxxxxx)
        a, b = rnd.sample(string.ascii_lowercase.replace("x", ""), 2)
        return "".join(rnd.choice(a + b) for _ in range(rnd.randint(12, 20)))
    if shape == "special":
        # a value wrapped in %…% reads as a Windows variable and one opening with $NAME as a shell
        # variable, on purpose, so the first character is neither % nor $
        pool = string.ascii_letters + string.digits + "!#$%&*+-_@"
        first = rnd.choice(pool.replace("%", "").replace("$", ""))
        return first + "".join(rnd.choice(pool) for _ in range(rnd.randint(9, 17))) + rnd.choice("!#$")
    if shape == "german":
        return rnd.choice(["Sommer", "Winter", "Fruehling"]) + str(rnd.randint(2020, 2030)) + rnd.choice("!?#")
    raise ValueError(shape)


def _mail(rnd: random.Random) -> str:
    return rnd.choice(["anna", "a.kruse", "max.m"]) + "@" + rnd.choice(["firma-xyz.de", "beispiel-gmbh.de"])


def cases(n: int = 2500, seed: int = 27) -> list[Case]:
    rnd = random.Random(seed)
    shapes = ["mixed", "two-letters", "special", "german"]
    product = list(itertools.product(LABELS, SEPARATORS, shapes, AFTER, CONTEXTS))
    rnd.shuffle(product)
    out = []
    for label, sep, shape, after, ctx in product[:n]:
        value = _value(rnd, shape)
        mail = _mail(rnd) if "{mail}" in after else None
        x = f"{label}{sep}{value}{after.format(mail=mail) if mail else after}"
        out.append(Case(ctx.format(x=x), value, mail, (label, sep, shape, after, ctx)))
    return out


# inputs where nothing may be a SECRET, with the reason
NEGATIVES = [
    ("password: ********", "a mask"),
    ("password: xxxxxxxx", "a mask"),
    ("secret: ........", "a mask"),
    ("password: changeme", "a placeholder word"),
    ("password: <your-password>", "a placeholder"),
    ("token: ${API_TOKEN}", "a template"),
    ("password: $DB_PASSWORD", "a variable"),
    ("api_key" + " = os.environ['API_KEY']", "code reading a variable"),   # assembled: the repo scan flags it
    ('if kind != "SECRET":\n    continue', "a code condition"),
    ("enter your password: below", "prose"),
    ("Add API key", "a UI label"),
    ("the secret_key_base setting", "an identifier"),
    ("password reset link sent to the user", "prose"),
]
