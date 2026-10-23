"""The label files of the languages that the pinned test locale does not turn on.

tests/detection_matrix.py takes the label files of the active languages only, and the tests pin
MAISECRETS_LOCALE=de_DE (tests/_isolate.py): English and German. Here each other label file runs
through the detector with its language on: every example, with generated values in the shapes of
the matrix, gives exactly its value (and the e-mail address after it); ordinary sentences with the
word as prose give no hit. The prose includes the words left out of the files on purpose (clave,
chiave, clé, klucz, anahtar, şifreleme: see docs/label-sources.md), so a later line that takes
one of them fails here.

Run: python3 -m unittest tests.test_label_languages -v
Every value is generated at run time, so no literal sits in the tree.
"""
from __future__ import annotations

import itertools
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
sys.path.insert(0, str(ROOT))
from maisecrets import detect, regions  # noqa: E402
import detection_matrix as dm  # noqa: E402

# ordinary sentences per language: the label word in running text, a word that is left out of the
# file in a label position, or a separator followed by prose. None of them may give any hit.
PROSE = {
    "es": ["Olvidé la clave de acceso del portal y pedí una nueva ayer",
           "Palabra clave: sostenibilidad",
           "Las credenciales del servidor caducan cada noventa días",
           "La clave secreta de su éxito es la paciencia"],
    "it": ["Parola chiave: sostenibilità",
           "Ho dimenticato la chiave di accesso della cantina",
           "Le credenziali scadono dopo novanta giorni",
           "Chiave: sottozerobianco"],
    "fi": ["Unohdin salasanan eilen illalla",
           "Salasana vaihdetaan joka kolmas kuukausi",
           "Salaisuus: rakkausrunot",
           "Avain: ovimaton alla"],
    "sv": ["Jag glömde mitt lösenord igår kväll",
           "Byt lösenord var tredje månad",
           "Nyckel: hållbarhetsfrågor",
           "Autentiseringsuppgifter skickas per post"],
    "pl": ["Zapomniałem hasła do skrzynki wczoraj",
           "Hasło dnia to cierpliwość",
           "Klucz: bezpieczeństwo",
           "Poświadczenia wygasają po dziewięćdziesięciu dniach"],
    "tr": ["Şifreleme: AES-256-GCM",
           "Dosya şifrelenmiş: evet2024",
           "Şifremi dün unuttum",
           "Anahtar kelime: sürdürülebilirlik",
           "Deşifre: tamamlandı2024"],
    "ko": ["암호화: AES256GCM",
           "암호문: 3f9a7c2e1b",
           "비밀번호를 잊어버렸어요",
           "키: 180센티미터",
           "토큰이 만료되었습니다"],
    "th": ["ฉันลืมรหัสผ่านเมื่อวานนี้",
           "รหัสสินค้า: SKU2024ABC",
           "โทเค็นหมดอายุแล้ว"],
    "fr": ["Mot clé: référencement2024",
           "J'ai perdu la clé d'accès du garage hier soir",
           "Vos identifiants sont envoyés par courrier",
           "Identifiant: dupont2024",
           "Clé: sousleparapluie"],
    "nl": ["Ik ben mijn wachtwoord vergeten",
           "Sleutel: duurzaamheid2030",
           "Uw inloggegevens worden per post verstuurd"],
    "pt": ["Palavra-chave: sustentabilidade",
           "Esqueci a senha do banco ontem",
           "Chave: debaixodotapete",
           "As credenciais expiram em noventa dias"],
    "da": ["Jeg har glemt min adgangskode",
           "Nøgle: sikkerhedsregler",
           "Skift kodeord hver tredje måned"],
    "nb": ["Jeg glemte passordet mitt i går",
           "Nøkkel: sikkerhetsregler",
           "Påloggingsdetaljer sendes med posten"],
    "ru": ["Я забыл пароль от почты",
           "Пароль истекает: 2026-12-31",
           "Пароль неверный: попробуйте ещё раз",
           "Длина пароля: минимум 12 символов",
           "Ключ: зажигание2024",
           "Токен действителен до: 2026-12-31"],
    "zh": ["密码错误",
           "密码错误：请重新输入您的密码",
           "令牌过期时间：2026-12-31",
           "密码长度：至少8个字符",
           "公开密钥：MIIBIjANBgkqhkiG9w0BAQEFAAOC",
           "我忘记密码了，请帮我重置"],
    "ja": ["パスワードを忘れた",
           "パスワードが違います：もう一度入力してください",
           "トークンの有効期限：2026年12月31日",
           "パスワード変更日：2026-10-23",
           "シークレットモード：オン2024",
           "キー：エンター2024"],
    "cs": ["Zapomněl jsem heslo k e-mailu",
           "Heslo dne: trpělivost",
           "Klíč: bezpečnostní2024",
           "Přihlašovací údaje vyprší za devadesát dní"],
}


def _other_languages() -> list[str]:
    active = set(detect.active_regions().languages)
    return [lang for lang in regions.label_languages_available() if lang not in active]


def _scan(languages: tuple[str, ...], texts: list[str]) -> list[list[tuple[str, str]]]:
    """The detector's result for each text with exactly these label languages on."""
    active = regions.Active(regions=("generic",), languages=languages, source="test")
    with detect.Detector(regions=active).activate():
        return [[(m.type, m.value) for m in detect.scan(t)] for t in texts]


def _cases(lang: str, n: int = 300, seed: int = 28) -> list[dm.Case]:
    rnd = random.Random(f"{seed}-{lang}")
    examples = [ex for lab in regions.load_labels(lang) for ex in lab.examples]
    product = list(itertools.product(examples, dm.SEPARATORS, ["mixed", "two-letters", "special", "german"],
                                     dm.AFTER, dm.CONTEXTS))
    rnd.shuffle(product)
    # every example at least once, whatever the shuffle drew
    head = [next(p for p in product if p[0] == ex) for ex in examples]
    out = []
    for label, sep, shape, after, ctx in head + product[:max(0, n - len(head))]:
        value = dm._value(rnd, shape)
        mail = dm._mail(rnd) if "{mail}" in after else None
        x = f"{label}{sep}{value}{after.format(mail=mail) if mail else after}"
        out.append(dm.Case(ctx.format(x=x), value, mail, (label, sep, shape, after, ctx)))
    return out


class LabelLanguageTests(unittest.TestCase):
    def test_each_label_file_outside_the_matrix_has_prose_here(self):
        others = _other_languages()
        self.assertGreaterEqual(len(others), 14, "a population test must fail on a thin population")
        self.assertEqual(sorted(others), sorted(PROSE), "a new label file needs its prose here")

    def test_every_example_gives_exactly_its_value_and_its_mail(self):
        for lang in _other_languages():
            cases = _cases(lang)
            got = _scan(("en", lang), [c.text for c in cases])
            wrong = []
            for c, g in zip(cases, got):
                want = [("SECRET", c.secret)] + ([("EMAIL", c.mail)] if c.mail else [])
                if g != want:
                    wrong.append((c.combo, c.text, g))
            with self.subTest(lang=lang):
                self.assertEqual(wrong[:5], [], f"{lang}: {len(wrong)} of {len(cases)} combinations fail")

    def test_the_file_is_what_finds_its_labels(self):
        # with English only, the labels of a language that English does not share are no labels
        value = "Qz" + "".join(random.Random(7).choice("abcdefgh23456789") for _ in range(12))
        for lang in _other_languages():
            examples = [ex for lab in regions.load_labels(lang) for ex in lab.examples]
            texts = [f"{ex}: {value}" for ex in examples]
            on = _scan(("en", lang), texts)
            off = _scan(("en",), texts)
            with self.subTest(lang=lang):
                self.assertTrue(all(r == [("SECRET", value)] for r in on), lang)
                self.assertTrue(any(r == [] for r in off), f"{lang}: English alone finds every label")

    def test_no_label_opens_the_keyword_rule_on_ordinary_technical_lines(self):
        # A label's prefilter decides on which lines the keyword rule runs at all. `acc` and `api`
        # (French clé d'accès, clé API) were in almost every log line: with French on, a 1 MB log
        # took 2.2 s instead of 0.9 s (2026-09-28). No timing here: the lines a prefilter opens
        # that English and German do not open already are counted on a fixed technical corpus.
        rnd = random.Random(11)
        words = ("GET POST PUT request response status ok error warn info debug user id path items "
                 "api v1 v2 endpoint client server session cache config access accept account "
                 "application acceptance accurate update delete create list detail page limit offset "
                 "token_file csrf_token count timeout retry connection database query index table "
                 "column value default enabled disabled true false null build test deploy release "
                 "service container image pod node cluster namespace region zone bucket object key_id "
                 "Anfrage Antwort Benutzer Zugriff Konto Datei Ordner Seite Fehler Warnung passed").split()
        lines = [" ".join(rnd.choice(words) for _ in range(rnd.randint(6, 14))).lower() for _ in range(4000)]
        base = {lab.prefilter for lang in ("en", "de") for lab in regions.load_labels(lang)}
        base |= {"key", "pass", "pwd", "secret", "contrase"}      # the literals of the denylist
        closed = [ln for ln in lines if not any(b in ln for b in base)]
        self.assertGreater(len(closed), 1000, "the corpus must leave the rule closed on most lines")
        for lang in _other_languages():
            for lab in regions.load_labels(lang):
                opened = sum(lab.prefilter in ln for ln in closed)
                with self.subTest(lang=lang, prefilter=lab.prefilter):
                    self.assertLessEqual(opened / len(closed), 0.005,
                                         f"{lang}: the prefilter {lab.prefilter!r} opens {opened} ordinary lines")

    def test_turkish_capitals_are_labels_too(self):
        # İ lowers to i plus a combining dot; the prefilter must still see ifre and kimlik
        value = "Qz" + "".join(random.Random(9).choice("abcdefgh23456789") for _ in range(12))
        for label in ("ŞİFRE", "Şİfre", "KİMLİK DOĞRULAMA BİLGİLERİ", "PAROLA"):
            with self.subTest(label):
                self.assertEqual(_scan(("en", "tr"), [f"{label}: {value}"]), [[("SECRET", value)]])

    def test_prose_with_the_label_word_gives_no_hit(self):
        for lang, sentences in PROSE.items():
            for text, got in zip(sentences, _scan(("en", lang), sentences)):
                with self.subTest(lang=lang, text=text):
                    self.assertEqual(got, [], text)


# a value with a capital, a digit and a sign, built from pieces: the sentence rules need all three
_SENTENCE_V = "Kx" + "9#" + "pL" + "2v" + "!"
_COLON_V = "Qz" + "7m" + "Lp" + "4x" + "Rt" + "9k"


class SentenceFormsWithoutSpacesTests(unittest.TestCase):
    """Chinese and Japanese write no space between words and use the fullwidth colon; Russian writes a dash or
    это where other languages have a copula. Each form gives exactly its value, with the language on."""

    FORMS = {
        "ru": ["Пароль: {c}", "пароль от почты: {c}", "Пароль приложения: {c}", "пароль — {s}", "мой пароль это {s}",
               "Ключ API: {c}", "Токен доступа: {c}"],
        "zh": ["密码：{c}", "数据库密码：{c}，请保密", "我的密码是{s}", "密码为{s}。", "Wi-Fi密码是{s}，别告诉别人",
               "密碼：{c}", "API 密钥：{c}", "访问令牌：{c}", "密码是“{s}”"],
        "ja": ["パスワード：{c}", "新しいパスワード：{c}、忘れないで", "パスワードは{s}です", "パスワードは {s} です。",
               "パスワードは「{s}」です", "APIキー：{c}", "アクセストークン：{c}"],
    }

    def test_each_form_gives_exactly_its_value(self):
        for lang, forms in self.FORMS.items():
            texts = [f.format(c=_COLON_V, s=_SENTENCE_V) for f in forms]
            for form, text, got in zip(forms, texts, _scan(("en", lang), texts)):
                want = _COLON_V if "{c}" in form else _SENTENCE_V
                with self.subTest(lang=lang, form=form):
                    self.assertEqual(got, [("SECRET", want)])

    def test_the_forms_need_their_language(self):
        # with English and German only, the CJK words and the fullwidth colon are no label: the rules of the other
        # languages stay as they were
        for lang, forms in self.FORMS.items():
            forms = [f for f in forms if "API:" not in f]   # `API: <value>` is an English label of its own
            texts = [f.format(c=_COLON_V, s=_SENTENCE_V) for f in forms]
            for form, got in zip(forms, _scan(("en", "de"), texts)):
                with self.subTest(lang=lang, form=form):
                    self.assertEqual(got, [])
        self.assertEqual(_scan(("en", "de"), [f"password：{_COLON_V}"]), [[]])

    def test_a_private_key_after_a_label_stays_one_block(self):
        # `Закрытый ключ: -----BEGIN …`: the label rule took the ten characters of the armour, and the private-key
        # rule lost the block (ProwlBench observation, 2026-10-23; English `password:` did the same)
        rnd = random.Random(5)
        body = "\n".join("".join(rnd.choice("abcdefghKLMNOPQR0123456789+/") for _ in range(64)) for _ in range(5))
        kind = "PRI" + "VATE KEY"
        pem = f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"
        for lang, label in (("en", "password"), ("ru", "Закрытый ключ"), ("zh", "私钥"), ("ja", "秘密鍵")):
            with self.subTest(label=label):
                self.assertEqual(_scan(("en", lang), [f"{label}: {pem}"]), [[("SECRET", pem)]])
        self.assertEqual(_scan(("en", "zh"), [f"password：{_COLON_V}"]), [[("SECRET", _COLON_V)]])


if __name__ == "__main__":
    unittest.main()
