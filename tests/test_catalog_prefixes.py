"""The token formats with a fixed prefix that the catalogs know and maisecrets missed without a label (0.7.9).

Run: python3 -m unittest tests.test_catalog_prefixes -v
Every token is generated at run time from the rule's own regex, seeded by its id, so no literal sits in the tree.
The rules are the block of maisecrets/detection/rules/prefixes.txt after "# 0.7.9: 97 token formats".
"""
from __future__ import annotations

import os
import random
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import measure_catalog_coverage as mcc  # noqa: E402
from maisecrets import detect  # noqa: E402

# rule id -> (prefix, class template of one catalog example after the prefix: a, A, 9 for a small letter, a capital,
# a digit; any other character as it is, and the fixed words of a format such as Mercury's _yrucrem).
# Written from the catalog, not from the rule, so it checks the rule's
# length and structure; never a value
TEMPLATES = {
    '1password-recovery-key': ('1PRK',
        '-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA99-9999-999A-AAAA-AAAA-AAAA-AAAA'),
    'age-identity-mlkem768-x25519-secret-key': ('AGE-SECRET-KEY-PQ-1',
        'AAA9AA9AAAA9AAAAAAA9AAAA9AAAA9AA99A9A99A9AA9AAAA9AAA9AA9AA'),
    'ai71-api-key': ('ai71-api-',
        '9a99a9a9-9a9a-9a9a-9a99-9a99a9a9a9a9'),
    'akamai-api-client-token': ('akab-',
        'aAaaAAAAa9aAa99aAAa'),
    'alibaba-sts-access-key-id': ('STS.',
        'AAAaaaAaaAaA9AaA999AA'),
    'alibaba-sts-security-token': ('CAIS',
        'aaA9a9Aa9A9aa9Aaaa9A9AaAA9a9a9A9a9A9a9A9a9A9aAa'),
    'arcjet-api-key': ('ajkey_',
        '99aaa9aaa9aa9aaaaaaaaaaaaa'),
    'astral-pyx-user-key-v1': ('sk-pyx-',
        'AAAAAAAAaaaaaaaa99999999AAAAAAAAaaaaaaaa99999999AAAAAAAAAAAAAAAA'),
    'astral-pyx-user-key-v2': ('sk-pyx-2',
        'AAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaaaa'),
    'atlassian-connect-shared-secret': ('ATCO',
        'Aa9_aaaAa9-Aa9AaA9AaA9AaAa9AaAa9Aa9_aaaAa9-Aa9AaA9AaA9AaAa9AaAa9'),
    'axiom-api-token': ('xaat-',
        'aa99a999-a999-99a9-9a9a-a9a9aaa999aa'),
    'axiom-personal-access-token': ('xapt-',
        '999a99a9-9a9a-9aaa-9a99-a99a99a99a9a'),
    'bitbucket-app-password': ('ATBB',
        '9a9aAAaaAaAaAa9AAAAaAaaa9A99999A'),
    'block-protocol-api-key': ('b10ck5.',
        'AaAaAaAaAaAaAaAaAaAaAaAaAa999999.AaAaAaAaAaAaAaAaAaAaAaAaAa9999999999'),
    'branch-io-live-key': ('key_live_',
        'aaAaAa9AaA9aa9a9aAaA9aaaaaaA9Aaa'),
    'branch-io-test-key': ('key_test_',
        'aaaaaa9AaA9aAaA9aAaa9aaaaaaaaAAA'),
    'builder-io-private-api-key': ('bpk-',
        '999999999aa999aaa9999aa99aaa999a'),
    'buildkite-agent-registration-token': ('bkar_',
        '9a9999a9a9a9a99aa9a9aaaa9a999a9a9a999999'),
    'buildkite-cluster-agent-token': ('bkct_',
        '9a9999a9a9a9a99aa9a9aaaa9a999a9a9a999999'),
    'cfx-re-fivem-server-key': ('cfxk_',
        'AaAaAaAaAaAaAaAaAaAaAaAaAa9999999999_aaaaaa'),
    'checkout-com-sandbox-secret-key': ('sk_test_',
        '9a9a9a9a-9999-9999-aaaa-aa9999999999'),
    'circleci-api-project-token-prefixed': ('CCIPRJ_',
        'AAAaaa9aAA9AaaAA9aaaaa_9a99aa99aaa9aa99a9aaaa99999a9999a99a9a99'),
    'confluent-api-secret-updated-format': ('cflt',
        'aAAAaaAaA9aaaaaaAaAaa9aAAaaA9AaAaA9AaaAaA+AaAaaAaAa9A9AaaaaA'),
    'databricks-oauth-client-secret': ('dose',
        'AaAaaaaaaaaaaAAaAa.a9aaAa99AaAaA'),
    'defined-networking-api-token-bare': ('dnkey-',
        'AAAAAAAA9AAA9AAAA9AAAAAAA9-AAA9AA99AAAA9AA9AAAAAAAAA9A9AAAAAAAAAA9AAAAAAAAA9AAA'),
    'deno-organization-token': ('ddo_',
        'a9aa99aAAAa9AAAAaaaAAaaaAaAaAa99aaaA'),
    'discord-mfa-token': ('mfa.',
        '9aaaaaA9Aa9aaAa99a_AaaaaA9AaaaaAAAA9AAAaaaAAaAAA'),
    'dryrun-security-api-key': ('dryrunsec_',
        'AAA9AaAaAa9A9AaAaAa99AaAa9aaAAaA'),
    'dub-co-api-key': ('dub_',
        'AaAaaAAaAAaAAAAAaAa9aAa9'),
    'e2b-api-key': ('e2b_',
        '9a999aa9aa9999999a9a9a99999aaa99a9aa9a99'),
    'endor-labs-api-key': ('endr+',
        'aaa9999999999aaa'),
    'fleetbase-api-key': ('flb_live',
        '_9999999999aaaaaaAAAA'),
    'flutterwave-encrypted-key': ('FLWSECK_TEST',
        'a999aaaaa9a9'),
    'friendli-ai-api-key': ('flp_',
        'aa9AAa9AAaAAAAaaAAAAAAaA9AAaaA9AaAAaA9aaaaAa99'),
    'gitlab-oauth-application-secret': ('gloas-',
        'aA9aAaAaAaAaAaAaAa99999999999aaaaaaaaaaaaaaaaaaaaaaaaaa999999999'),
    'guardsquare-appsweep-api-key': ('gs_appsweep_',
        'a9A9a9A9a9A9a9A9a9A9a9A9'),
    'hack-club-ai-api-key': ('sk-hc-v1-',
        '9a999a9a999a99999a9aa99aa9a99a9a9999aa99aa9a9999a9aaa99999aaa9a9'),
    'hashicorp-vault-recovery-token-v1-10': ('hvr.',
        'AAaAAaAaAAaaA99aaAaAA9aaA9a9aaaa9AAa9'),
    'hashicorp-vault-service-token-v1-10': ('hvs.',
        'AAaAAaAaAAaaA99aaAaAA9aaA9a9aaaa9AAa9'),
    'heartland-portico-api-key': ('skapi_cert_',
        'AaAaAAAA9aAa9AaAAAAAaAaAAa9a9AaAA9a'),
    'hop-personal-access-token': ('hop_pat_',
        'AaAaAaAaAaAaAaAaAaAaAaAaAa999999'),
    'hop-project-token': ('ptk_',
        'a999A9A9A9AaAaAaAAA9AaA9A9AaAaAaAAAaAAA9AAAaAA99AAaaAaAaAaAaAaa9AAAaA9'),
    'inngest-signing-key': ('signkey-',
        'aaaa-999a9a9a9aaaaaaa9999999aa9a99aaaa99a9999aa99a999aa99aa99aa9a9aa9'),
    'instagram-graph-api-access-token': ('IGQVJ',
        'AAAaAAA9aaA9A9a9AaAAAAAaAaAAaaA9AaAa9AAAaaAAaaAaAaAAaAAAAaAAaAaAaaAAA9aAAAaAaAaAAaAAaA9AaA'
        'AAA9AaAAAAaAaAAA99aA9AAAAaaaAaAAAA9'),
    'iterative-dvc-studio-access-token': ('isat_',
        'a9a9a9a9-a9a9-99aa-a999-9999aa999999'),
    'mappedin-api-key': ('mik_',
        'aaAa9Aa9aAAaaaaaa999a99a9'),
    'mappedin-api-secret': ('mis_',
        '9aAAAa9aaaaAaAAAAAAaAAaa99A9aaA9AaaAAaAa9AA9aaa999a'),
    'mercado-pago-access-token': ('APP_USR-',
        '9999999999999999-999999-9a9a9a9a9a9a9999999a9a9a9a9a9a99-9999999999'),
    'mercury-non-production-api-token': ('mercury_sandbox_rma_',
        '99aaaaA9AaaAaaAAa9aAaAaAAaa9aA99A9a9AAAa9AAAa_yrucrem'),
    'midtrans-production-server-client-key-bare': ('Mid-server-',
        'Aa99AaAA9aAAaaA9'),
    'midtrans-sandbox-server-client-key': ('SB-Mid-server-',
        'Aa99AaAA9aAAaaA9'),
    'minimax-api-key-bare': ('MINIMAX-',
        'A9A9A9A9-A9A9A9A9-A9A9A9A9-A9A9A9A9'),
    'mintlify-api-key': ('mint_',
        'a9a9a9a9a9a9a9a9a9a9a9a9'),
    'new-relic-browser-api-token-bare': ('NRJS-',
        'a9a9a9a9a9a99999a9a'),
    'new-relic-pixie-deploy-key': ('px-dep-',
        'a99aa999-aa9a-9999-9999-9aa9a9a99999'),
    'openai-api-key-short-prefixed': ('sk-None-',
        'aaaaaaaaaa9999999999AAAAAAAAAA9999999999aaaaaaaa'),
    'openvsx-access-token': ('ovsxat_',
        '9a9aaa99-999a-9a99-a9a9-99999aa99a99'),
    'ory-api-key': ('ory_pat_',
        'aA9a9AaAa9aA9aAa9aA9aA9aA9aA9a'),
    'ory-session-token': ('ory_st_',
        'aA9a9AaAa9aA9aAa9aA9aA9aA9aA9a'),
    'packagist-api-key': ('packagist_ack_',
        'a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9'),
    'packagist-api-secret': ('packagist_acs_',
        '9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa'),
    'packagist-conductor-update-token': ('packagist_cut_',
        '9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999'),
    'packagist-organization-read-token': ('packagist_ort_',
        '9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999'),
    'packagist-organization-update-token': ('packagist_out_',
        '9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999'),
    'packagist-user-update-token': ('packagist_uut_',
        '9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999999999aaaaaa9999'),
    'pangea-service-token': ('pts_',
        'a9a9aa9aaaaaaaaaaaaaaaaaaaaaaaaa'),
    'permit-io-api-key': ('permit_key_',
        'a9AaAaaAaAaa9aaAaAAA9AaaaaaaAAAaaa99AaaA9AaAAAAAAaAaa9aaAaAaAaaAAaaaA9aAaaa9aaaAAAaAaA'),
    'pinterest-refresh-token': ('pinr_',
        'aaAaaAaaAaAAAaA9AaA9.aaAaaAAaAaAaAaA9AAA9AAaaAa9.aaa999'),
    'plaid-access-token-production': ('access-production-',
        '999a9aa9-aa9a-999a-9aa9-a9aa9999a9a9'),
    'plaid-access-token-sandbox': ('access-sandbox-',
        '999a9aa9-aa9a-999a-9aa9-a9aa9999a9a9'),
    'portainer-api-token': ('ptr_',
        'aAaAaAaAaAaAaAaAaAaAaAaAaA999999999999'),
    'posthog-feature-flags-secure-api-key': ('phs_',
        '9AaaAAAAAA9A9aAa9AaaaaaaaAAaAAAA99aaaaAaaaAaa9A'),
    'posthog-oauth-access-token': ('pha_',
        'AaaAAaaaaaAAaaaAAA9aa9aaAAaaaAaa9AA9aaaaaaA'),
    'posthog-oauth-refresh-token': ('phr_',
        '9aaAaAaaAAAA9A9aaAAAaAA9AAaAAaaaaAAaaaaaaAA'),
    'ramp-application-signup-token': ('ramp_business_tok_',
        'A9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9a'),
    'riot-games-api-key': ('RGAPI-',
        '9aa9a9a9-9999-9a99-9a99-9aa9a99a99a9'),
    'robinhood-crypto-api-key': ('rh-api-',
        '99a9a999-9aa9-9a9a-99aa-aa99999aa999'),
    'saladcloud-user-api-key': ('salad_cloud_user_',
        'aaaAaAAA9AaaAaa9AAAaAaAA9a9a9AAa9aaaAAA99Aa9AAAaa'),
    'scale-callback-auth-key': ('live_auth_',
        '999aa999aaa999a99a99999a999a999a'),
    'seam-api-key': ('seam_test2',
        'aAA_99AaAAAaAA9AaAaaaaAAAa9a'),
    'shortcut-api-token': ('sct_r_',
        'aaaaaaaaaa_AaA9AaAaAaAaAAAaAa99AAAaAAAaAaAaAaA9AAAaAAA9AAAaAaAaAaAaAaaaAAA9AaAaAAA9Aa99AAA'
        'aAAAaAAA9AAA9AAAaAAa9AAAaAAA9AAAaAAa9AAAaAAAaAAAaAaA9AaaaAaAaAA'),
    'slack-app-token-bare': ('xapp-',
        '999999999999-AaAAaaa/99A9aA9a9aA99aAA'),
    'testkube-api-key': ('tkcapi_',
        'aa999aaaa9aa9aa99aa9aaaaaa99aa'),
    'tigris-access-key-id': ('tid_',
        'A9a9A9a9A9a9A9a9A9a9A9a9A9a9A9a9A9a9A9a9A9a9A9a9A9'),
    'tigris-secret-access-key': ('tsec_',
        'Aa9A9aAa9Aa9AaAaAaAaAaAaAa9999999999_+-AaAaAaAaAaAaAaAaAaAaAaAaAaAaAAa'),
    'tinybird-static-token': ('p.eyJ1I',
        'aaaAaaaAaA9AAAaAAA9AAaaAAAaAa99AAAaAAA9AaA9AaaaAAA9AaAaAAAaAAA9AAA9AAAaAAA9AA9aA9A9AAAaAaa'
        'aAAA9AA9aAaaaAaA9AAAaAAAaAAAaaA9aaAA9AAAaA9AaAAAaa9AaAAaaa9AaAa9.AaAAA9aAaAAaA9AAa9_aAaAa9'
        'a9aaaAAAaaaAAAaAaa'),
    'tolgee-personal-access-token': ('tgpat_',
        '9aa9aaaaaaaaaa9aaaa99aaaaaaa9aaaaaa9aaaa9a99aa9aaaa9'),
    'tolgee-project-api-key': ('tgpak_',
        'aaaaa9aaaaaaaaaaaaaaaaaaaaaaa9aaaaaa9aaaaaaa9'),
    'trend-micro-cloud-one-api-key': ('tmc1',
        '9a99a9aaaAaA99AAa9AA9AaaA9A:9AaaA9a9aaaA9aaaAAaAAa9aAaaAAAaAAaAA9aaAa9A9aa9AA9aa9aAa9aAaaa'
        'aAa9'),
    'trigger-dev-personal-access-token': ('tr_pat_',
        'A9AaAaAAa9AAAAaaAAa9'),
    'ubidots-api-key': ('BBUS-',
        'aAaA9Aaa9AAaaAAaaaAaA9A9AAAaAa99aaa'),
    'vkontakte-access-token': ('vk1.a.',
        'AaA9AAAAA9AaaA9a9aAaaAAAAAaA_AA9AAAAAaAAAAAaAaAAaA-aA9aAAA99AaA-9AaAAA9aAAaa9AA9A_aAaaaaa9'
        'AaAaAaAaAa'),
    'voiceflow-api-key': ('VF.DM.',
        '9999a9a9a9a9a9999a9a9a9a.a9A9a9A9a9A9a9A9'),
    'warpstream-api-key-secret': ('aks_',
        'a99a9aa99aa9a9aa999999aa99aa999999aaaaa9999a9a999999a99aa9a9a999'),
    'workato-api-token': ('wrka-eyJ',
        'aaAaaAaAAAaA9AaAaAaA9aAA9AaaAAAA9.aaAaaAAaAaAaAAAaa9aaAa99AaaaaaAaAaaaA9aaAaA9AAA9AAAaa9Aa'
        'AAAaaAAaAaAaAAAaAAAaAAA9.aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA'
        '9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9aA9AaAaAaAaAaAaAaAaAa'),
    'workos-api-key': ('sk_live_a2V5Xz',
        'AaA9AAAA9AAaAAAA9AAaaAA9AAAaA9AAA9AAaaAAaAAAAAA99aAaaaAA9aAAaAaAaAAAA'),
    'xata-api-key': ('xau_',
        'A9a9A9a9A9a9A9a9A9a9A9a9A9a9A9a9A'),
}


MARK = "# 0.7.9: 97 token formats"
# PREFIX(?:(?<!…PREFIX)|(?<=\\[nrt]PREFIX))BODY(?![A-Za-z0-9_-])
_SHAPE = re.compile(r"^(?P<prefix>.+?)\(\?:\(\?<!\[[^\]]+\](?P=prefix)\)\|\(\?<=\\\\\[nrt\](?P=prefix)\)\)"
                    r"(?P<body>.+)\(\?!\[A-Za-z0-9_-\]\)$")


def block() -> list[tuple[str, str]]:
    text = (detect.RULES_DIR / "prefixes.txt").read_text(encoding="utf-8")
    rows = []
    # up to the next block, which tests/test_researched_formats.py owns
    part = text.split(MARK, 1)[1].split("# 0.7.9, researched", 1)[0]
    for line in part.splitlines()[1:]:   # the rest of the marker line is its comment
        if line.strip() and not line.startswith("#"):
            rule_id, rx = line.split(None, 1)
            rows.append((rule_id, rx.strip()))
    return rows


def token(rule_id: str, rx: str) -> tuple[str, str]:
    """A token the rule must find, and a look-alike with half its body that it must not find."""
    m = _SHAPE.match(rx)
    assert m, rule_id
    prefix = re.sub(r"\\(.)", r"\1", m.group("prefix")).replace("[L]", "L").replace("[O]", "O")
    body = mcc.new_secret(m.group("body"), random.Random(rule_id))
    assert body, rule_id
    return prefix + body, prefix + body[: len(body) // 2]


def from_template(rule_id: str) -> str:
    """A token from the catalog's template: letters from a-f and A-F, digits from 2-7, which hex, base32, base58 and
    letters-and-digits alphabets all hold."""
    prefix, tpl = TEMPLATES[rule_id]
    r = random.Random("t" + rule_id)
    pick = {"a": "abcdef", "A": "ABCDEF", "9": "234567"}
    return prefix + "".join(r.choice(pick[c]) if c in pick else c for c in tpl)


def kinds(text: str, channel: str) -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in detect.scan(text, channel=channel)]


class CatalogPrefixTests(unittest.TestCase):
    def test_the_block_holds_97_rules(self):
        self.assertEqual(len(block()), 97)

    def test_each_token_is_found_whole_by_its_rule_and_a_half_token_is_not(self):
        for rule_id, rx in block():
            tok, half = token(rule_id, rx)
            for channel in ("tool", "prompt"):
                for text in (tok, f"here it is: {tok} thanks", f"export TOKEN_VALUE={tok}\n"):
                    with self.subTest(rule=rule_id, channel=channel, text=text[:12]):
                        self.assertIn((rule_id, tok), kinds(text, channel))
            with self.subTest(rule=rule_id, half=True):
                self.assertNotIn(rule_id, [k for k, _v in kinds(f"see {half} there", "tool")])

    def test_a_token_in_the_shape_of_its_catalog_example_is_found_whole(self):
        self.assertEqual(set(TEMPLATES), {rule_id for rule_id, _rx in block()})
        for rule_id, _rx in block():
            tok = from_template(rule_id)
            for text in (tok, f"use {tok} now"):
                with self.subTest(rule=rule_id, text=text[:8]):
                    self.assertIn((rule_id, tok), kinds(text, "tool"))

    def test_a_token_inside_a_longer_word_is_no_hit_of_its_rule(self):
        for rule_id, rx in block():
            tok, _half = token(rule_id, rx)
            with self.subTest(rule=rule_id):
                self.assertNotIn(rule_id, [k for k, _v in kinds(f"x{tok}", "tool")])


if __name__ == "__main__":
    unittest.main()
