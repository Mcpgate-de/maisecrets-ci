"""Rules that a coverage measurement against other secret catalogs (Nosey Parker, Kingfisher, betterleaks, gitleaks,
trufflehog, GitLab's secret detection rules) showed missing or wrong in 0.6.19: a PEM private key in base64, four
vendored betterleaks rules, and token formats with a public prefix.

Run: python3 -m unittest tests.test_rules_from_the_catalogs -v
Every value is generated at run time from a seeded generator, so no literal sits in the tree. Each token rule has a
token that is a hit and a look-alike that is not.
"""
from __future__ import annotations

import base64
import os
import random
import string
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
from _timing import assert_linear  # noqa: E402

from maisecrets import detect  # noqa: E402

J = "".join
D = string.digits
L = string.ascii_lowercase
U = string.ascii_uppercase
AN = string.ascii_letters + D
HEXL = "0123456789abcdef"
HEXU = "0123456789ABCDEF"
B64U = AN + "_-"


def rd(r: random.Random, n: int, alphabet: str = D) -> str:
    return J(r.choice(alphabet) for _ in range(n))


def rd_mixed(r: random.Random, n: int, alphabet: str) -> str:
    """n characters of alphabet with at least one digit (the rules that need one)."""
    while True:
        v = rd(r, n, alphabet)
        if any(c.isdigit() for c in v):
            return v


def found(text: str, channel: str = "prompt") -> list:
    return [(m.kind, m.type, m.value) for m in detect.scan(text, channel=channel)]


def kinds_over(text: str, value: str, channel: str = "prompt") -> list:
    """The rule ids of the hits that overlap the value."""
    a = text.index(value)
    return [m.kind for m in detect.scan(text, channel=channel) if m.start < a + len(value) and m.end > a]


def _uuid(r: random.Random) -> str:
    return "-".join(rd(r, n, HEXL) for n in (8, 4, 4, 4, 12))


def _b64url(r: random.Random, n: int) -> str:
    return base64.urlsafe_b64encode(bytes(r.randrange(256) for _ in range(n))).decode().rstrip("=")


def _jwt(r: random.Random) -> str:
    head = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip("=")
    return J([head, ".", _b64url(r, 300), ".", _b64url(r, 256)])


def _intercom(r: random.Random) -> str:
    """dG9rO is the base64 of "tok:"; the token is 60 characters of base64."""
    raw = J(["to", "k:"]).encode() + J([_uuid(r).replace("-", "_"), ":1:0"]).encode()
    return base64.b64encode(raw[:45]).decode()


def gitlab_routable(r: random.Random, prefix: str = "glpat-", payload_bytes: int = 40) -> str:
    """GitLab's routable token (lib/authn/token_field/generator/routable_token.rb): base64url of 16 random bytes, the
    routing payload and its size; ".01."; the payload length (2 base36) and CRC32 (7 base36)."""
    import zlib
    raw = bytes(r.randrange(256) for _ in range(16 + payload_bytes))
    payload = base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def b36(n: int, w: int) -> str:
        out = ""
        while n:
            n, d = divmod(n, 36)
            out = (D + L)[d] + out
        return out.rjust(w, "0")
    body = J([prefix, payload, ".01.", b36(len(payload), 2)])
    return body + b36(zlib.crc32(body.encode()) & 0xffffffff, 7)


# rule id -> (a token, a look-alike that is not one). Every part after the prefix is random
TOKENS = {
    "google-oauth-client-secret": lambda r: (J(["GOC", "SPX-"]) + rd(r, 28, B64U), J(["GOC", "SPX-"]) + rd(r, 12, AN)),
    "sonarqube-token": lambda r: (J(["sq", "u_"]) + rd(r, 40, HEXL), J(["sq", "u_"]) + rd(r, 30, HEXL)),
    "dynatrace-platform-token": lambda r: (J(["dt0", "s", rd(r, 2), "."]) + rd(r, 8, U + D) + "." + rd(r, 64, U + D),
                                           J(["dt0", "s16."]) + rd(r, 8, U + D) + "." + rd(r, 20, U + D)),
    "postman-collection-token": lambda r: (J(["PM", "AT-"]) + rd(r, 26, U + D), J(["PM", "AT-"]) + rd(r, 12, U + D)),
    "shopify-partner-api-token": lambda r: (J(["prt", "api_"]) + rd(r, 32, HEXL), J(["prt", "api_"]) + rd(r, 12, HEXL)),
    "aiven-service-password": lambda r: (J(["AV", "NS_"]) + rd(r, r.randint(15, 100), B64U),
                                         J(["AV", "NS_"]) + rd(r, 10, AN)),
    "planetscale-app-secret": lambda r: (J(["pscale_app", "_secret_"]) + rd(r, 43, B64U),
                                         J(["pscale_app", "_secret_"]) + rd(r, 12, AN)),
    "intercom-access-token": lambda r: (_intercom(r), J(["dG9r", "O"]) + rd(r, 20, AN)),
    "netlify-personal-token": lambda r: (J(["nf", "p_"]) + rd(r, r.randint(40, 48), AN),
                                         J(["nf", "p_"]) + rd(r, 20, AN)),
    "teamcity-access-token": lambda r: (J(["eyJ0eXAiOiAi", "VENWMiJ9."]) + rd(r, 36, B64U) + "." + rd(r, 48, B64U),
                                        J(["eyJ0eXAiOiAi", "VENWMiJ9."]) + rd(r, 20, B64U)),
    "dependency-track-api-key": lambda r: (J(["od", "t_"]) + rd_mixed(r, 32, AN) + "Z",
                                           J(["od", "t_"]) + rd(r, 12, AN)),
    "tavily-api-key": lambda r: (J(["tv", "ly-", r.choice(["", "dev-"])]) + rd(r, 32, AN),
                                 J(["tv", "ly-"]) + rd(r, 12, AN)),
    "jina-api-key": lambda r: (J(["ji", "na_"]) + rd(r, 60, AN), J(["ji", "na_"]) + rd(r, 20, AN)),
    "aws-appsync-api-key": lambda r: (J(["da", "2-"]) + rd_mixed(r, 26, L + D), J(["da", "2-"]) + rd(r, 26, L)),
    "stackhawk-api-key": lambda r: (J(["haw", "k."]) + rd(r, 20, B64U) + "." + rd(r, 20, B64U),
                                    J(["haw", "k."]) + rd(r, 12, B64U)),
    "heroku-api-key-uuid": lambda r: (J(["HR", "KU-"]) + _uuid(r), J(["HR", "KU-"]) + rd(r, 8, HEXL)),
    "github-app-installation-jwt": lambda r: (J(["gh", "s_", rd(r, 1, D[1:]), rd(r, 6), "_"]) + _jwt(r),
                                              J(["gh", "s_", rd(r, 6), "_"]) + rd(r, 30, AN)),
    "crates-io-api-token": lambda r: (J(["ci", "o"]) + rd_mixed(r, 32, AN),
                                      J(["ci", "o"]) + rd(r, 32, string.ascii_letters)),
    "nuget-api-key": lambda r: (J(["oy", "2"]) + rd_mixed(r, 43, L + D), J(["oy", "2"]) + rd(r, 43, L)),
    "dropbox-short-lived-token": lambda r: (J(["s", "l.", r.choice(["", "u."])])
                                            + rd(r, r.randint(130, 1300), B64U),
                                            J(["s", "l."]) + rd(r, 60, B64U)),
    "firecrawl-api-key": lambda r: (J(["f", "c-"]) + rd(r, 32, HEXL), J(["f", "c-"]) + rd(r, 31, HEXL)),
    "elevenlabs-api-key-bare": lambda r: (J(["s", "k_"]) + rd(r, 48, HEXL), J(["s", "k_"]) + rd(r, 47, HEXL)),
    "gitlab-pipeline-trigger-token-any": lambda r: (gitlab_routable(r, J(["gl", "ptt-"])),
                                                    J(["gl", "ptt-"]) + rd(r, 12, AN)),
    "gitlab-ci-job-token-any": lambda r: (J(["gl", "cbt-"]) + rd(r, 24, AN), J(["gl", "cbt-"]) + rd(r, 12, AN)),
    "storyblok-personal-access-token": lambda r: (J(["sb_", "pat_"]) + rd(r, 43, AN + "_"),
                                                  J(["sb_", "pat_"]) + rd(r, 20, AN)),
    "labelbox-api-key": lambda r: (J(["lb", "x_"]) + rd(r, 42, AN + "_-") + rd(r, 1, "AEIMQUYcgkosw048"),
                                   J(["lb", "x_"]) + rd(r, 42, AN) + "B"),
    "labelbox-recursion-api-key": lambda r: (J(["rm", "a_"]) + rd(r, 42, AN + "_-") + rd(r, 1, "AEIMQUYcgkosw048"),
                                             J(["rm", "a_"]) + rd(r, 30, AN) + "Q"),
    # Composio: oak_ needs a capital and a digit among its 20 characters; the look-alikes have 20 without one
    "oak-api-key": lambda r: (J(["o", "ak_"]) + rd(r, 1, D) + rd(r, 18, B64U) + rd(r, 1, U),
                                       J(["o", "ak_"]) + rd(r, 20, r.choice((L + D, string.ascii_letters + "_-")))),
    "composio-user-api-key": lambda r: (J(["u", "ak_"]) + rd(r, 43, B64U), J(["u", "ak_"]) + rd(r, 20, AN)),
    # the legacy Office 365 connector URL of Microsoft Teams; the look-alike lacks the last id
    "microsoft-teams-webhook-legacy": lambda r: (
        J(["https://outlook.of", "fice.com/webhook/"]) + _uuid(r) + "@" + _uuid(r) + "/IncomingWebhook/"
        + rd(r, 32, HEXL) + "/" + _uuid(r),
        J(["https://outlook.of", "fice.com/webhook/"]) + _uuid(r) + "@" + _uuid(r) + "/IncomingWebhook/"
        + rd(r, 32, HEXL)),
}

PREFIX_IDS_BEFORE = {"gitlab-runner-token", "gitlab-deploy-token-any", "webhook-signing-secret",
                     "cloudflare-user-api-token"}
OWN_SHORT_PREFIX_IDS = {"crates-io-api-token", "nuget-api-key", "dropbox-short-lived-token", "firecrawl-api-key",
                        "elevenlabs-api-key-bare", "aiven-service-password"}


class TokenFormatTests(unittest.TestCase):
    def test_each_token_is_found_whole_by_its_rule_and_a_look_alike_is_not(self):
        for rule_id, gen in TOKENS.items():
            r = random.Random(rule_id)
            for _ in range(20):
                tok, miss = gen(r)
                for text in (tok, f"export TOKEN_VALUE={tok}\n", f"here it is: {tok} thanks", f'"{tok}"'):
                    for channel in ("prompt", "tool"):
                        with self.subTest(rule=rule_id, text=text[:30], channel=channel):
                            self.assertIn((rule_id, "SECRET", tok), found(text, channel))
                with self.subTest(rule=rule_id, miss=miss):
                    self.assertNotIn(rule_id, [k for k, _t, _v in found(f"see {miss} there")])

    def test_a_token_after_an_escaped_line_break_or_before_a_full_stop_is_found(self):
        """Gate B of 0.6.20: JSON text in a tool result has \\n before a token; a sentence ends with a full stop."""
        for rule_id, gen in TOKENS.items():
            tok, _ = gen(random.Random(rule_id + "escaped"))
            for text in ('{"content": "API_URL=https://x\\n' + tok + '\\n"}', "line\\t" + tok,
                         f"My token is {tok}.", f"({tok}), next"):
                for channel in ("prompt", "tool"):
                    with self.subTest(rule=rule_id, text=text[:12], channel=channel):
                        self.assertIn((rule_id, "SECRET", tok), found(text, channel))

    def test_a_sonarqube_analysis_token_needs_the_word_sonar(self):
        r = random.Random(23)
        for p in ("sqa_", "sqp_"):
            tok = J([p[:2], p[2:]]) + rd(r, 40, HEXL)
            for text in (f"SONAR_TOKEN={tok}", f"sonar.token: {tok}", f"run the SonarQube scan with {tok}"):
                with self.subTest(text=text[:12]):
                    self.assertIn(("sonarqube-analysis-token", "SECRET", tok), found(text, "tool"))
            for text in (f"docker pull app:{tok}", f"git checkout -b {tok}"):
                with self.subTest(text=text[:12]):
                    self.assertNotIn("sonarqube-analysis-token", [k for k, _t, _v in found(text, "tool")])

    def test_every_loaded_regex_has_no_posix_class_left(self):
        """Python reads [[:space:]] as a set of characters; _re2_to_python translates the classes it knows."""
        for rule in detect.rules():
            with self.subTest(rule=rule.id):
                # the colon and the fullwidth colon of the Chinese and Japanese labels are a set, no POSIX class
                pattern = rule.regex.pattern.replace("[:\uff1a]", "").replace("[:\\uff1a]", "")
                self.assertNotIn("[:", pattern.replace("[:=]", "").replace("[:,", ""))

    def test_a_token_inside_a_longer_word_is_no_hit(self):
        """The short prefixes: fc-, sl., sk_, cio, oy2, da2- glued to a word before them are part of that word."""
        for rule_id, gen in TOKENS.items():
            tok, _ = gen(random.Random(rule_id + "glued"))
            for before in ("x", "9"):
                with self.subTest(rule=rule_id, before=before):
                    self.assertNotIn(rule_id, [k for k, _t, _v in found(f"see {before}{tok} there")])

    def test_every_new_rule_has_a_token(self):
        new = {line.split()[0] for line in (detect.RULES_DIR / "prefixes.txt").read_text().splitlines()
               if line.strip() and not line.startswith("#")}
        own = {d["id"] for d in detect.OWN_RULES}
        self.assertTrue(set(TOKENS) - OWN_SHORT_PREFIX_IDS <= new)
        self.assertTrue(OWN_SHORT_PREFIX_IDS <= own)

    def test_each_rule_starts_with_its_literal(self):
        """The regex starts with the literal prefix (the boundary is a lookbehind after it), so the regex engine
        skips a text without the prefix."""
        rx = {r.id: r.regex.pattern for r in detect.rules()}
        for rule_id in TOKENS:
            with self.subTest(rule=rule_id):
                self.assertRegex(rx[rule_id], r"^(?:\(\?:)?[A-Za-z0-9]")

    def test_a_long_run_of_near_misses_takes_linear_time(self):
        r = random.Random(20)
        for rule_id, gen in TOKENS.items():
            tok, _ = gen(r)
            with self.subTest(rule=rule_id):             # each copy one short of a match; not a fixed 3 s of CPU
                assert_linear(self, found, lambda n, tok=tok: (tok[:-2] + "  ") * n, 200, hang=7.0, wall=20.0)

    def test_an_identifier_or_a_digest_after_a_prefix_is_no_hit(self):
        """codex Gate A of 0.6.20: names of words after AVNS_, cio or oy2, and a hex digest after nfp_ or odt_."""
        r = random.Random(22)
        cio = J(["ci", "o", "ServiceConfigurationManagerFactory"])[:34] + "1"     # cio and 32 characters
        oy2 = J(["oy", "2", "configurationmanagerservicefactoryprovider"])[:45] + "1"
        self.assertEqual((len(cio), len(oy2)), (35, 46))
        for text in (J(["AV", "NS_Configuration01"]), J(["AV", "NS_DatabaseConnectionPool"]), cio, oy2,
                     "/static/js/" + J(["f", "c-"]) + rd(r, 32, HEXL) + ".js",
                     "." + J(["f", "c-"]) + rd(r, 32, HEXL) + "{",
                     J(["od", "t_"]) + rd(r, 40, L), J(["od", "t_"]) + rd_mixed(r, 32, AN) + ".odt",
                     J(["ji", "na_"]) + rd(r, 60, string.ascii_letters),
                     J(["s", "l."]) + rd(r, 140, string.ascii_letters),
                     J(["nf", "p_"]) + rd(r, 40, HEXL), J(["od", "t_"]) + rd(r, 32, HEXL),
                     J(["od", "t_"]) + rd(r, 64, HEXL)):
            with self.subTest(text=text[:8]):
                self.assertEqual(found(f"see {text} there"), [])

    def test_stripe_and_other_sk_keys_stay_with_their_own_rules(self):
        r = random.Random(21)
        stripe = J(["sk", "_live_"]) + rd(r, 48, HEXL)
        self.assertNotIn("elevenlabs-api-key-bare", kinds_over(f"key {stripe}", stripe))
        for word in ("sl.no", "fc-dark", "da2-config", J(["ci", "oServiceConfigurationManagerFactoryXYZ"])):
            with self.subTest(word=word):
                self.assertEqual(found(f"see {word} there"), [])


# ------------------------------------------------------------ base64 PEM key --
def pem(r: random.Random, kind: str = "RSA PRIVATE KEY", body_bytes: int = 1190) -> bytes:
    # the body starts as a key does: the OpenSSH magic, a PGP packet tag, else DER (a SEQUENCE)
    start = b"openssh-key-v1\x00" if kind.startswith("OPENSSH") else b"\x95" if kind.startswith("PGP") else b"\x30\x82"
    body = base64.b64encode(start + bytes(r.randrange(256) for _ in range(body_bytes))).decode()
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    dashes = "-" * 5
    return J([dashes, "BEGIN ", kind, dashes, "\n", lines, "\n", dashes, "END ", kind, dashes, "\n"]).encode()


def b64_pem(r: random.Random, kind: str = "RSA PRIVATE KEY") -> str:
    return base64.b64encode(pem(r, kind)).decode()


def k8s_secret(tls_key: str, cert: str) -> str:
    return ("apiVersion: v1\nkind: Secret\nmetadata:\n  name: web-tls\ntype: kubernetes.io/tls\ndata:\n"
            f"  tls.crt: {cert}\n  tls.key: {tls_key}\n")


class Base64PemTests(unittest.TestCase):
    KINDS = ("RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
             "DSA PRIVATE KEY", "PGP PRIVATE KEY BLOCK")

    def test_a_private_key_in_a_kubernetes_secret_is_masked_whole(self):
        r = random.Random(30)
        cert = b64_pem(r, "CERTIFICATE")
        for kind in self.KINDS:
            key = b64_pem(r, kind)
            text = k8s_secret(key, cert)
            for channel in ("prompt", "tool"):
                with self.subTest(kind=kind, channel=channel):
                    hits = found(text, channel)
                    self.assertIn(("private-key-base64", "SECRET", key), hits)
                    # betterleaks' kubernetes-secret-yaml takes the first value of a Secret; no new rule takes the
                    # certificate
                    self.assertFalse(any(k == "private-key-base64" and (cert in v or v in cert) for k, _t, v in hits))

    def test_a_certificate_or_a_public_key_in_base64_stays_text(self):
        r = random.Random(31)
        for kind in ("CERTIFICATE", "PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE REQUEST", "PGP PUBLIC KEY BLOCK"):
            v = b64_pem(r, kind)
            with self.subTest(kind=kind):
                self.assertEqual(kinds_over(f"ca.crt: {v}\n", v), [])

    def test_a_wrapped_value_is_masked_over_all_its_lines(self):
        """codex Gate A of 0.6.20: a value wrapped at 40 columns was missed, and a last line of 4 characters stayed
        in the clear."""
        r = random.Random(32)
        for width in (40, 64, 76):
            for tail in (4, 8, 12, 0):
                n = 1190
                key = base64.b64encode(pem(r, body_bytes=n)).decode()
                # a key whose last line has `tail` characters; a full last line without padding when tail is 0
                while len(key) % width != tail or (tail == 0 and key.endswith("=")):
                    n += 1
                    key = base64.b64encode(pem(r, body_bytes=n)).decode()
                wrapped = "\n".join(key[i:i + width] for i in range(0, len(key), width))
                # a longer line of base64 alone is of another value; after a full last line, the decoded END line
                # tells that a shorter line is the next text (codex Gate A of 0.6.20)
                longer = "\n" + rd(r, width + 4, AN) + "\n"
                afters = ("\n$ echo done\n", "", longer, "\n0123456789abcdef\nnext\n", "\nnext\n")
                for after in afters:
                    text = f"$ base64 -w {width} server.key\n{wrapped}{after}"
                    with self.subTest(width=width, tail=tail, after=after[:6]):
                        self.assertIn(("private-key-base64", "SECRET", wrapped), found(text, "tool"))

    def test_an_indented_wrapped_value_in_yaml_is_masked_whole(self):
        r = random.Random(36)
        key = b64_pem(r)
        lines = [key[i:i + 64] for i in range(0, len(key), 64)]
        block = "\n    ".join(lines)
        text = f"data:\n  tls.key: |\n    {block}\n  tls.crt: abc\n"
        self.assertIn(("private-key-base64", "SECRET", block), found(text, "tool"))

    def test_a_banner_with_a_word_after_it_is_no_hit(self):
        """codex Gate A of 0.6.20: a CamelCase word after the banner read as a key body."""
        dashes = "-" * 5
        for kind, line in (("PRIVATE KEY", "ThisIsOnlyBannerText"), ("OPENSSH PRIVATE KEY", "ExampleKeyGoesHere00"),
                           ("PGP PRIVATE KEY BLOCK", "ABCDEFGHIJKLMNOPQRST")):
            raw = J([dashes, "BEGIN ", kind, dashes, "\n", line, "\n", dashes, "END ", kind, dashes, "\n"])
            v = base64.b64encode(raw.encode()).decode()
            with self.subTest(kind=kind):
                self.assertEqual(kinds_over(f"key: {v}\n", v, "prompt"), [])

    def test_a_bundle_with_a_legacy_encrypted_key_is_found(self):
        """Gate B round 2 of 0.6.20: Proc-Type and DEK-Info after the header did not fit the decoded window."""
        r = random.Random(42)
        dashes = "-" * 5
        body = base64.b64encode(bytes(r.randrange(256) for _ in range(1190))).decode()
        key = J([dashes, "BEGIN RSA PRIVATE KEY", dashes, "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,",
                 rd(r, 32, "0123456789ABCDEF"), "\n\n", body, "\n", dashes, "END RSA PRIVATE KEY", dashes, "\n"])
        v = base64.b64encode(pem(r, "CERTIFICATE") + key.encode()).decode()
        self.assertIn(("private-key-base64", "SECRET", v), found(f"tls.pem: {v}\n", "prompt"))

    def test_a_bundle_after_a_byte_order_mark_is_found(self):
        r = random.Random(41)
        v = base64.b64encode(b"\xef\xbb\xbf" + pem(r, "CERTIFICATE") + pem(r)).decode()
        self.assertIn(("private-key-base64", "SECRET", v), found(f"tls.pem: {v}\n", "prompt"))

    def test_a_banner_without_key_material_is_no_hit(self):
        dashes = "-" * 5
        prose = "not key material, only a banner in a document " * 8   # long enough to pass the length check
        fake = J([dashes, "BEGIN PRIVATE KEY", dashes, "\n", prose, "\n", dashes, "END PRIVATE KEY", dashes, "\n"])
        v = base64.b64encode(fake.encode()).decode()
        # the prompt channel: in the tool channel the decoder of 0.6.18 (maisecrets/detection/normalise.py) hands the
        # decoded
        # banner to the vendored private-key rule
        self.assertEqual(kinds_over(f"tls.key: {v}\n", v, "prompt"), [])

    def test_escaped_line_breaks_a_bundle_and_a_byte_order_mark(self):
        """Gate B of 0.6.20: a value wrapped with \\n in a JSON string, a certificate chain with the key at its end, a
        byte order mark before the PEM."""
        r = random.Random(38)
        key = b64_pem(r)
        escaped = "\\n".join(key[i:i + 76] for i in range(0, len(key), 76))
        self.assertIn(("private-key-base64", "SECRET", escaped), found('{"key": "' + escaped + '"}', "tool"))
        bundle = base64.b64encode(pem(r, "CERTIFICATE") + pem(r, "CERTIFICATE") + pem(r)).decode()
        self.assertIn(("private-key-base64", "SECRET", bundle), found(f"tls.pem: {bundle}\n", "tool"))
        wrapped = "\n".join(bundle[i:i + 64] for i in range(0, len(bundle), 64))
        self.assertIn(("private-key-base64", "SECRET", wrapped), found(f"$ base64 bundle.pem\n{wrapped}\n", "tool"))
        bom = base64.b64encode(b"\xef\xbb\xbf" + pem(r)).decode()
        self.assertIn(("private-key-base64", "SECRET", bom), found(f"key: {bom}\n", "tool"))
        chain = base64.b64encode(pem(r, "CERTIFICATE") + pem(r, "CERTIFICATE")).decode()
        self.assertEqual(kinds_over(f"ca.pem: {chain}\n", chain, "tool"), [])

    def test_the_first_line_alone_is_masked_where_the_lines_are_quoted(self):
        """A Python or JavaScript string split over quoted lines: the first line decodes to the header."""
        r = random.Random(39)
        key = b64_pem(r)
        lines = [key[i:i + 64] for i in range(0, len(key), 64)]
        text = "KEY = (\n" + "".join(f'    "{x}"\n' for x in lines) + ")\n"
        self.assertIn(("private-key-base64", "SECRET", lines[0]), found(text, "prompt"))
        self.assertTrue(kinds_over(text, lines[0], "tool"))   # the tool channel's decoder may take more

    def test_many_certificate_lines_take_linear_time(self):
        """Gate B of 0.6.20: each line that starts with the base64 of BEGIN walked all following lines."""
        r = random.Random(40)
        head = b64_pem(r, "CERTIFICATE")[:76]
        times = []
        for n in (500, 2000):
            text = "\n".join(head[:20] + rd(r, 56, AN) for _ in range(n)) + "\n"
            t0 = time.process_time()
            detect.scan(text, enabled={"private-key-base64"}, channel="tool")
            times.append(time.process_time() - t0)
        # Windows counts CPU time in steps of about 15.6 ms: the slack must hold several steps
        self.assertLess(times[1], 8 * times[0] + 0.1)

    def test_the_forms_a_value_takes(self):
        r = random.Random(33)
        key = b64_pem(r, "OPENSSH PRIVATE KEY")
        for text in (f'{{"data": {{"ssh-privatekey": "{key}"}}}}', f"SSH_KEY_B64={key}",
                     f"kubectl ... -o yaml\n  key: {key}", f"tls.key: '{key}'", key):
            with self.subTest(form=text[:20]):
                self.assertIn(("private-key-base64", "SECRET", key), found(text, "tool"))

    def test_a_large_yaml_is_fast_for_this_rule(self):
        r = random.Random(34)
        cert, key = b64_pem(r, "CERTIFICATE"), b64_pem(r)
        # The growth from 50 to 400 documents is the check (linear: 8 times, quadratic: 64 times). A fixed
        # 1.0 s failed on loaded CI runners at 1.07 to 1.21 s with no change to this rule (2026-10-16, four
        # pipelines). 5 s only catches a hang.
        for doc, per_doc in ((k8s_secret(cert, cert), 0), (k8s_secret(key, cert), 1)):
            times = []
            for count in (50, 400):                                                   # 400: 1.8 MB
                t0 = time.process_time()
                hits = detect.scan(doc * count, enabled={"private-key-base64"}, channel="tool")
                times.append(time.process_time() - t0)
                with self.subTest(keys=per_doc * count):
                    self.assertEqual(len(hits), per_doc * count)
            with self.subTest(keys=per_doc * 400):
                self.assertLess(times[1], 16 * times[0] + 0.2)
                self.assertLess(times[1], 5.0)

    def test_the_validator_decodes_only_the_head(self):
        r = random.Random(35)
        key = b64_pem(r)
        self.assertTrue(detect.VALIDATORS["base64_pem"](key))
        self.assertTrue(detect.VALIDATORS["base64_pem"](key[:60] + "\n  " + key[60:]))
        self.assertFalse(detect.VALIDATORS["base64_pem"](b64_pem(r, "CERTIFICATE")))
        self.assertFalse(detect.VALIDATORS["base64_pem"](key[:20] + "%%%%" + key[24:]))


# ------------------------------------------------------- betterleaks patches --
class BetterleaksPatchTests(unittest.TestCase):
    def test_each_patch_applies_to_the_vendored_rule_it_names(self):
        """After a re-sync that changes one of these rules, this goes red: check the correction against the new rule
        and drop it if upstream fixed the gap."""
        import json
        cfg = json.loads((detect.RULES_DIR / "betterleaks.json").read_text(encoding="utf-8"))
        vendored = {r["id"]: r for r in cfg["rules"]}
        loaded = {r.id: r for r in detect._load_betterleaks()}
        for rule_id, patch in detect.BETTERLEAKS_PATCHES.items():
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, vendored)
                self.assertIn(rule_id, loaded)
                for kw in patch.get("add_keywords", ()):
                    self.assertNotIn(kw, vendored[rule_id].get("keywords") or [])
                    self.assertIn(kw, loaded[rule_id].keywords)
                if "regex" in patch:
                    self.assertEqual(vendored[rule_id]["regex"], patch["expect"])
                    want = patch["regex"]   # then the sentence terminator, as for every vendored rule
                    if want.endswith(detect._VENDORED_END):
                        want = want[:-len(detect._VENDORED_END)] + detect._SENTENCE_END
                    self.assertEqual(loaded[rule_id].regex.pattern, detect._re2_to_python(want))

    def test_a_bare_token_without_the_providers_name_is_found(self):
        b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        r = random.Random(40)
        for _ in range(20):
            cases = {
                "resend-api-key.1": J(["r", "e_"]) + rd(r, 8, b58) + "_" + rd(r, 24, b58),
                "ionic-personal-access-token": J(["io", "n_"]) + rd(r, 42, AN),
                "airtable-personnal-access-token": J(["pa", "t"]) + rd(r, 14, AN) + "." + rd(r, 64, HEXL),
                "wakatime-api-key.2": J(["wak", "a_"]) + r.choice([_uuid(r), rd(r, 40, L + D)]),
            }
            for rule_id, tok in cases.items():
                for text in (tok, f"here it is: {tok} thanks\n", f"echo '{tok}' | tool\n"):
                    with self.subTest(rule=rule_id, text=text[:12]):
                        self.assertIn(rule_id, kinds_over(text, tok, "tool"))

    def test_a_posix_class_of_re2_becomes_a_python_class(self):
        self.assertEqual(detect._re2_to_python(r"\b(pat[[:alnum:]]{14})"), r"\b(pat[A-Za-z0-9]{14})")
        self.assertEqual(detect._re2_to_python(r"[[:xdigit:]_-]"), r"[0-9A-Fa-f_-]")

    def test_a_waka_key_is_masked_whole(self):
        r = random.Random(41)
        tok = J(["wak", "a_"]) + _uuid(r)
        self.assertIn(("wakatime-api-key.2", "SECRET", tok), found(f"use {tok} here\n"))

    def test_a_teams_webhook_is_masked_whole(self):
        # the vendored regex had its ids as capturing groups, so the hit was one group, 17 of 204 characters (#11)
        r = random.Random(42)

        def guid():
            return "-".join(rd(r, n, HEXL) for n in (8, 4, 4, 4, 12))
        url = ("https://" + rd(r, 8, HEXL) + ".webhook.office.com/webhookb2/" + guid() + "@" + guid()
               + "/IncomingWebhook/" + rd(r, 32, HEXL) + "/" + guid())
        self.assertEqual(len(url), 205)
        for text in (url, f"webhook: {url}\n", '{{"url": "{u}"}}'.format(u=url)):
            with self.subTest(text=text[:10]):
                self.assertIn(("microsoft-teams-webhook", "SECRET", url), found(text))
        # a URL without the last id or on another host is no Teams webhook
        for miss in (url[:url.rindex("/")], url.replace(".webhook.office.com/", ".webhook.example.com/")):
            with self.subTest(miss=miss[-12:]):
                self.assertNotIn("microsoft-teams-webhook", [k for k, _t, _v in found(f"see {miss} there")])
        # codex Gate A of 0.6.39: hex in capitals, a further path part, a word glued before, one character too many
        head, ids = url.split("/webhookb2/")
        upper = head + "/webhookb2/" + ids.upper().replace("/INCOMINGWEBHOOK/", "/IncomingWebhook/")
        longer = url + "/" + rd(r, 30, AN)
        for want in (upper, longer):
            with self.subTest(want=want[-6:]):
                self.assertIn(("microsoft-teams-webhook", "SECRET", want), found(f"see {want} there"))
        not_hex = head + "/webhookb2/" + ids.replace(ids[:8], "Z" * 8, 1)    # a capital that is no hex digit
        for miss in ("x" + url, url + "a", url + "_", not_hex):
            with self.subTest(miss=miss[-3:]):
                self.assertNotIn("microsoft-teams-webhook", [k for k, _t, _v in found(f"see {miss} there")])

    def test_a_legacy_teams_webhook_takes_hex_in_capitals_and_needs_the_uuid_form(self):
        # codex Gate A of 0.6.39: the first rule took [0-9a-f-]{36}, so a hyphen anywhere passed and a capital did not
        r = random.Random(43)

        def guid(digits=HEXL):
            return "-".join(rd(r, n, digits) for n in (8, 4, 4, 4, 12))
        rule = "microsoft-teams-webhook-legacy"
        start = J(["https://outlook.of", "fice.com/webhook/"])
        upper = start + guid(HEXU) + "@" + guid(HEXU) + "/IncomingWebhook/" + rd(r, 32, HEXU) + "/" + guid(HEXU)
        self.assertIn((rule, "SECRET", upper), found(f"see {upper} there"))
        bad = rd(r, 32, HEXL) + "----"
        for miss in (start + bad + "@" + guid() + "/IncomingWebhook/" + rd(r, 32, HEXL) + "/" + guid(),
                     start + guid() + "@" + guid() + "/IncomingWebhook/" + rd(r, 32, HEXL) + "/" + bad):
            with self.subTest(miss=miss[-8:]):
                self.assertNotIn(rule, [k for k, _t, _v in found(f"see {miss} there")])


# ------------------------------------------------------- forms of a session measurement --
class SessionFormTests(unittest.TestCase):
    """Forms that real session transcripts held and 0.6.17 missed or masked in part (the values were not kept; these
    are built from the vendors' formats)."""

    FORMS = ("{t}", "use {t} now", "export TOKEN={t}\n", '{{"k": "{t}"}}', "key {t}.", 'TOKEN="{t}"\n')

    def whole(self, tok: str, kind: str | None = None):
        for form in self.FORMS:
            text = form.format(t=tok)
            for channel in ("prompt", "tool"):
                with self.subTest(form=form[:8], channel=channel, n=len(tok)):
                    hits = [(k, v) for k, _t, v in found(text, channel) if tok in v or v in tok]
                    self.assertTrue(any(v == tok for _k, v in hits), hits and [(k, len(v)) for k, v in hits])
                    if kind and form == "{t}":   # a label rule or, before a full stop, the fallback may take it
                        self.assertIn((kind, tok), hits)

    def test_a_routable_gitlab_token_with_a_long_payload_is_one_hit(self):
        """The payload runs up to 235 characters (a routing payload of 159 bytes); the token characters stopped
        128 after the vendored shape, and the rest with the ".01.<id>" tail stayed in the clear."""
        r = random.Random(50)
        for n in (20, 60, 120, 159):
            self.whole(gitlab_routable(r, payload_bytes=n))

    def test_gitlab_trigger_and_job_tokens_are_found_in_their_newer_forms(self):
        r = random.Random(51)
        self.whole(J(["gl", "ptt-"]) + rd(r, 40, HEXL))
        self.whole(gitlab_routable(r, J(["gl", "ptt-"])))
        self.whole(J(["gl", "cbt-"]) + rd(r, 2, AN) + "_" + rd(r, 20, B64U))
        self.whole(J(["gl", "cbt-"]) + rd(r, 24, B64U), "gitlab-ci-job-token-any")
        self.whole(gitlab_routable(r, J(["gl", "cbt-"])))
        self.whole(J(["gl", "cbt-", "eyJ"]) + rd(r, 30, B64U) + ".eyJ" + rd(r, 120, B64U) + "." + rd(r, 43, B64U))
        # codex Gate A of 0.6.20: the vendored rule took the first part of a three-part token with _ in it
        part = "Ab3_xY7-"
        self.whole(J(["gl", "cbt-"]) + part * 5 + "." + part * 2 + "Ab3_" + "." + part * 2 + "Ab3_")
        for miss in (J(["gl", "ptt-"]) + rd(r, 12, AN), J(["gl", "cbt-"]) + rd(r, 12, AN)):
            self.assertEqual(found(f"see {miss} there"), [])

    def test_openai_project_keys_of_every_length_are_found(self):
        r = random.Random(52)
        mid = J(["T3Blbk", "FJ"])
        self.whole(J(["sk-", "proj-"]) + rd(r, 74, B64U) + mid + rd(r, 74, B64U), "openai-api-key")
        for a, b in ((80, 84), (100, 60), (60, 100), (120, 40), (30, 30)):
            self.whole(J(["sk-", r.choice(["proj", "svcacct", "admin"]), "-"]) + rd(r, a, B64U) + mid + rd(r, b, B64U))
        no_marker = J(["sk-", "proj-"]) + rd(r, 150, AN)
        self.assertNotIn("openai-api-key-any", [k for k, _t, _v in found(f"see {no_marker} there")])

    def test_anthropic_api_keys_of_other_lengths_are_found(self):
        r = random.Random(53)
        self.whole(J(["sk-ant-", "api03-"]) + rd(r, 93, B64U) + "AA", "anthropic-api-key")
        for n in (80, 90, 95, 106, 120):
            self.whole(J(["sk-ant-", r.choice(["api03", "admin01"]), "-"]) + rd(r, n, B64U) + "AA")
        short = J(["sk-ant-", "api03-"]) + rd(r, 30, AN) + "AA"
        self.assertNotIn("anthropic-api-key-any", [k for k, _t, _v in found(f"see {short} there")])

    def test_a_long_run_of_near_misses_takes_linear_time(self):
        r = random.Random(54)
        mid = J(["T3Blbk", "FJ"])
        # each run of 8 times the copies takes at most 16 times the CPU time (tests/_timing.py), not a fixed 3 s
        for one, copies in ((J(["sk-", "proj-"]) + rd(r, 390, B64U) + " ", 300),
                            (J(["sk-", "proj-"]) + rd(r, 200, B64U) + mid + rd(r, 500, B64U) + " ", 100),
                            (J(["sk-ant-", "api03-"]) + rd(r, 139, B64U) + " ", 500),
                            (J(["gl", "pat-"]) + rd(r, 390, B64U) + ".01. ", 300)):
            with self.subTest(n=len(one) * copies):
                assert_linear(self, lambda text: found(text, "tool"), lambda n, one=one: one * n, copies,
                              hang=7.0, wall=20.0)


if __name__ == "__main__":
    unittest.main()
