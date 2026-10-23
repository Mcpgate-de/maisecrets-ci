"""Provider word and shape (0.7.10): a provider's word, then a key label, then the value, from kingfisher's rules.

Only the 16 of 61 candidate rules that find a value the rest of the detector misses: for the other 45 a realistic
value after the same words is already a hit (kingfisher's own examples were missed for their low-entropy values).

Run: python3 -m unittest tests.test_provider_context_rules -v
EXAMPLES holds, per rule, the text around one kingfisher example verbatim and the example's value as a class template
(a, A, 9 for a small letter, a capital, a digit; other characters as they are) with a flag for a hex value. The test
fills the template at run time, so no value sits in the tree, and the rule must find the value whole.
"""
from __future__ import annotations

import os
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

N_RULES = 16
EXAMPLES = dict([
    ('provider-agora-app-certificate',
     ('agora.app_certificate=',
      '999a9aa9aa9999aaaa99a9a9aa99aaaa',
      '', True)),
    ('provider-asana-client-secret',
     ("asana :'",
      '99a9A9a99999aa999aa9aAA9999A9A9AAaa',
      "'", True)),
    ('provider-bitbucket-secret',
     ('bitbucket_key=',
      'AaaaaA9a9AA_aa9AA9AaA9aaAa9AaaAA9aaaaaaA9aaA',
      '', False)),
    ('provider-coveralls-personal-api-token',
     ('coveralls_SECRETTOKEN ',
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaa99999aaaa',
      '', False)),
    ('provider-credentials-in-psexec',
     ('cmd.exe /C PSEXEC \\\\10.0.94.120 -u ',
      'Aaaaaaaaaaaaa',
      ' -p dev_admin CMD /C ECHO', False)),
    ('provider-gemfury-full-access-token',
     ('GEMFURY_URL=https://',
      'Aaaa9a99AaAAAaAaAaAa',
      ':@pypi.fury.io/myorg', False)),
    ('provider-godaddy-api-credentials',
     ('Authorization: sso-key ',
      'Aaa999AAA999Aaa999AaA999Aaa999AaAaA:aA9aA9aAaA9aA9aAaAaAaA',
      '', False)),
    ('provider-hex-pm-organization-repository-key',
     ('mix hex.organization auth acme --key ',
      '999a99aa9999aa99999999aaaa99a999',
      '', True)),
    ('provider-html-password-input-pre-populated-credential-value-befor',
     ('<input class="form-control" value="',
      'aaaaaa_aaaaaa_AAA!',
      '" type="password" name="jasper_password" />', False)),
    ('provider-mailjetsms-api-key',
     ('mailjet ',
      'AAAAAAAAAAAAAAAAAAAAAAAAAA999999',
      '', False)),
    ('provider-owlbot-api-key',
     ('owlbot SECRET ',
      'a9a99a9a99a9a9a9999aa999a9a9a9a999aaa9a9',
      '', True)),
    ('provider-packagecloud-api-key',
     ('packagecloud accessKEY ',
      '9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa',
      '', True)),
    ('provider-statuspage-api-key',
     ('statuspage_api: OAuth ',
      '99a999aa9a9aaaa9aa99999aaa99aa9a9999999aaa999999999aaaa9999aa9a9',
      '', True)),
    ('provider-thingsboard-access-token',
     ('http://thingsboard.cloud/api/v1/',
      '999a9a999aaaa9aaa9a9',
      '/telemetry', False)),
    ('provider-windows-unattend-xml-administrator-password',
     ('<AdministratorPassword><Value>',
      'AaAaaaaAaaaAaaaaaaa',
      '</Value><PlainText>true</PlainText></AdministratorPassword>', False)),
    ('provider-windows-unattend-xml-autologon-password',
     ('<AutoLogon><Password><Value>',
      'AAAAAAAAaaA9AAAAaaAaAA==',
      '</Value></Password></AutoLogon>', False)),
])


def sample(rule_id: str) -> tuple[str, str]:
    """(the text, the value in it) for a rule, filled from its template."""
    before, tpl, after, hexd = EXAMPLES[rule_id]
    r = random.Random(rule_id)
    pick = {"a": "abcdef" if hexd else "abcdefghijkmnpqrstuvwxyz",
            "A": "ABCDEF" if hexd else "ABCDEFGHJKLMNPQRSTUVWXYZ", "9": "0123456789"}
    value = "".join(r.choice(pick[c]) if c in pick else c for c in tpl)
    return before + value + after, value


class ProviderContextTests(unittest.TestCase):
    def test_every_rule_is_loaded(self):
        loaded = {r.id for r in detect.rules()}
        self.assertEqual(set(EXAMPLES) - loaded, set())
        self.assertEqual(len(EXAMPLES), N_RULES)

    def test_each_rule_finds_the_value_after_its_provider_word(self):
        for rule_id in sorted(EXAMPLES):
            text, value = sample(rule_id)
            with self.subTest(rule=rule_id):
                found = [m for m in detect.scan(text, channel="tool")]
                self.assertTrue(any(m.value == value and m.type == "SECRET" for m in found), rule_id)

    def test_the_value_without_its_provider_word_is_no_hit_of_the_rule(self):
        for rule_id in sorted(EXAMPLES):
            _text, value = sample(rule_id)
            with self.subTest(rule=rule_id):
                self.assertNotIn(rule_id, [m.kind for m in detect.scan(f"value: {value}", channel="tool")])

    def test_the_tail_of_a_commit_id_after_the_hex_word_is_no_key(self):
        # a link into a hexpm repository: the rule skipped 8 characters of the commit id and took the last 32
        r = random.Random(5)
        commit = "".join(r.choice("0123456789abcdef") for _ in range(40))
        text = f"Hex key format: https://github.com/hexpm/hex/blob/{commit}/lib/hex/api.ex\n"
        self.assertNotIn("provider-hex-pm-organization-repository-key",
                         [m.kind for m in detect.scan(text, channel="tool")])


if __name__ == "__main__":
    unittest.main()
