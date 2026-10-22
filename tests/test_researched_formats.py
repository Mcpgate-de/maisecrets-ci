"""Token formats researched from the providers' documentation (0.7.9): the providers that GitHub secret scanning names.

Run: python3 -m unittest tests.test_researched_formats -v
SOURCES holds the pattern each format was researched with, a copy kept apart from the rules in
maisecrets/detection/rules/prefixes.txt and own_secret_rules.json, so a rule that drifts from its format turns red.
Every token is generated at run time from that pattern, seeded by the rule id; no value sits in the tree.
"""
from __future__ import annotations

import os
import random
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

SOURCES = dict([
    ('1password-service-account-token-bare',
     'ops_eyJ[A-Za-z0-9+/_-]{250,}={0,3}'),
    ('asaas-production-key',
     '\\$aact_prod_[A-Za-z0-9_\\-+/=:$]{20,200}'),
    ('asaas-sandbox-key',
     '\\$aact_hmlg_[A-Za-z0-9_\\-+/=:$]{20,200}'),
    ('atlassian-org-admin-scoped-api-key-sibling',
     'ATCTT3xFfG[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8}'),
    ('aws-bedrock-short-term-api-key',
     'bedrock-api-key-[A-Za-z0-9+/]+={0,2}'),
    ('azure-apim-direct-management-key-identifiable',
     '[A-Za-z0-9+/]{76}APIM[A-Za-z0-9+/]{5}[AQgw]=='),
    ('azure-batch-account-key-identifiable',
     '[A-Za-z0-9+/]{76}\\+ABa[A-Za-z0-9+/]{5}[AQgw]=='),
    ('azure-cache-for-redis-access-key-identifiable',
     '[A-Za-z0-9+/]{33}AzCa[A-P][A-Za-z0-9+/]{5}='),
    ('azure-common-annotated-security-key',
     '[A-Za-z0-9]{52}JQQJ99[A-Za-z0-9][A-L][A-Za-z0-9]{12}AAAAACOG[A-Za-z0-9]{4}(?:[A-Za-z0-9]{2}==)?'),
    ('azure-container-registry-key-identifiable',
     '[A-Za-z0-9+/]{42}\\+ACR[A-D][A-Za-z0-9+/]{5}'),
    ('azure-cosmos-db-key-identifiable',
     '[A-Za-z0-9+/]{76}ACDb[A-Za-z0-9+/]{5}[AQgw]=='),
    ('azure-event-grid-key-identifiable-44-chars',
     '[A-Za-z0-9+/]{33}AZEG[A-P][A-Za-z0-9+/]{5}='),
    ('azure-event-hub-key-identifiable',
     '[A-Za-z0-9+/]{33}\\+AEh[A-P][A-Za-z0-9+/]{5}='),
    ('azure-function-key-identifiable',
     '[A-Za-z0-9_\\-]{44}AzFu[A-Za-z0-9_\\-]{5}[AQgw]=='),
    ('azure-iot-device-key-identifiable',
     '[A-Za-z0-9+/]{33}AIoT[A-P][A-Za-z0-9+/]{5}='),
    ('azure-ml-studio-classic-web-service-key',
     '[A-Za-z0-9+/]{76}\\+AMC[A-Za-z0-9+/]{5}[AQgw]=='),
    ('azure-relay-identifiable-key',
     '[A-Za-z0-9+/]{33}\\+ARm[A-P][A-Za-z0-9+/]{5}='),
    ('azure-search-identifiable-admin-key',
     '[A-Za-z0-9]{42}AzSe[A-D][A-Za-z0-9]{5}'),
    ('azure-service-bus-identifiable-key',
     '[A-Za-z0-9+/]{33}\\+ASb[A-P][A-Za-z0-9+/]{5}='),
    ('azure-storage-identifiable-key',
     '[A-Za-z0-9+/]{76}\\+ASt[A-Za-z0-9+/]{5}[AQgw]=='),
    ('baidu-qianfan-api-key-bce-v3',
     'bce-v3/ALTAK-[A-Za-z0-9]{10,}/[A-Za-z0-9]{20,}'),
    ('bitbucket-data-center-http-access-token',
     'BBDC-[A-Za-z0-9+/@_\\-]{40,50}'),
    ('brevo-smtp-key-standard',
     'xsmtpsib-[a-f0-9]{64}-[A-Za-z0-9]{16}'),
    ('buildkite-portal-token-long-lived-ephemeral-user-invoked',
     'bkpat_[A-Za-z0-9_-]{54}'),
    ('canadian-digital-service-gc-notify-api-key',
     'gcntfy-[a-z0-9_]+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    ('cashfree-secret-key-production',
     'cfsk_ma_prod_[A-Za-z0-9_]{20,}'),
    ('cashfree-secret-key-sandbox',
     'cfsk_ma_test_[A-Za-z0-9_]{20,}'),
    ('checkout-com-sandbox-secret-key-current',
     'sk_sbox_[a-z0-9]{27}'),
    ('cloudflare-access-service-token-client-secret-sibling',
     'cfast_[A-Za-z0-9]{40}[a-f0-9]{8}'),
    ('coveo-api-key-rotation-secret-sibling',
     'coveo_apikey_rotation_v1_[A-Za-z0-9]{10}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}_[A-Za-z0-9]{8}'),
    ('databricks-dkea-token',
     'dkea[a-f0-9]{32}'),
    ('databricks-dosa-token',
     'dosa[a-f0-9]{32}'),
    ('datadog-personal-access-token',
     'ddpat_[A-Za-z0-9]{20,24}_[A-Za-z0-9]{40,52}'),
    ('datadog-service-access-token',
     'ddsat_[A-Za-z0-9]{20,24}_[A-Za-z0-9]{40,52}'),
    ('datastax-astra-application-token-bare',
     'AstraCS:[A-Za-z0-9]{24}:[a-f0-9]{64}'),
    ('ebay-production-cert-id',
     'PRD-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4,12}'),
    ('firebase-fcm-legacy-server-key',
     'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    ('fullstory-api-key-eu1-data-center',
     'eu1\\.[A-Za-z0-9+/]{100}={0,2}'),
    ('fullstory-api-key-na1-data-center',
     'na1\\.[A-Za-z0-9+/]{100}={0,2}'),
    ('gocardless-live-access-token',
     'live_[A-Za-z0-9_=-]{40}'),
    ('google-oauth-access-token-bare',
     'ya29\\.[0-9A-Za-z_-]{20,1024}'),
    ('grafana-cloud-access-policy-token',
     'glc_[A-Za-z0-9+/]{32,400}={0,3}'),
    ('guardsquare-appsweep-api-key-bare',
     'gs_appsweep_[A-Za-z0-9_-]{16,}'),
    ('hashicorp-vault-batch-token-1-10',
     'hvb\\.[A-Za-z0-9_-]{24,300}'),
    ('hashicorp-vault-root-token-service-token-with-root-policy',
     'hvs\\.[A-Za-z0-9_-]{24,}'),
    ('highnote-secret-key-test',
     'sk_test_a2V5Xz[A-Za-z0-9+/]{69}={0,2}'),
    ('hop-personal-access-token-bare',
     'pat_[A-Za-z0-9]{16,64}'),
    ('hop-project-token-bare',
     'ptk_[A-Za-z0-9]{16,64}'),
    ('hop-user-bearer-token',
     'bearer_[A-Za-z0-9]{16,64}'),
    ('intercom-access-token-bare',
     'dG9rOj[A-Za-z0-9+/]{53}='),
    ('iterative-dvc-studio-client-access-token',
     'isat_[A-Za-z0-9_-]{20,}'),
    ('jfrog-jwt-access-token',
     'eyJ2ZXIiOiIyIiwidHlwIjoiSldUIi[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'),
    ('launchdarkly-api-access-token',
     'api-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12}'),
    ('launchdarkly-server-sdk-key',
     'sdk-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12}'),
    ('lichess-oauth-access-token',
     'lio_[A-Za-z0-9]{32}'),
    ('linear-oauth-access-token',
     'lin_oauth_[A-Za-z0-9]{32,64}'),
    ('linkedin-client-secret-current',
     'WPL_AP1\\.[A-Za-z0-9]{16}\\.[A-Za-z0-9+/]{6}=='),
    ('lob-live-secret-api-key',
     'live_[a-f0-9]{35}'),
    ('lob-test-secret-api-key',
     'test_[a-f0-9]{35}'),
    ('logicmonitor-bearer-token',
     'lmb_[A-Za-z0-9+/=_-]{20,}'),
    ('lovable-labs-workspace-api-key',
     'lov_[A-Za-z0-9_-]{20,}'),
    ('mailgun-private-api-key-legacy-key-format',
     'key-[0-9a-f]{32}'),
    ('mapbox-temporary-token',
     'tk\\.eyJ1Ijoi[A-Za-z0-9_-]{20,400}\\.[A-Za-z0-9_-]{22}'),
    ('new-relic-license-ingest-key-us-and-eu',
     '(?:[0-9a-f]{32}|eu01xx[0-9a-f]{26})FFFFNRAL'),
    ('notion-legacy-internal-integration-token',
     'secret_[A-Za-z0-9]{43}'),
    ('octopus-deploy-api-key-bare',
     'API-[A-Z0-9]{26,34}'),
    ('onfido-sandbox-all-regions',
     'api_sandbox(?:_us|_ca)?\\.[A-Za-z0-9_-]{20,80}'),
    ('openvsx-personal-access-token-open-vsx-org',
     'ovsxat_[A-Za-z0-9-]{36,43}'),
    ('openvsx-publish-only-token-sibling',
     'ovsxap_[A-Za-z0-9]{43}'),
    ('paddle-sandbox',
     'pdl_sdbx_apikey_[a-z0-9]{26}_[A-Za-z0-9]{22}_[A-Za-z0-9]{3}'),
    ('pangea-service-access-token',
     'pts_[a-z0-9]{20,64}'),
    ('persona-identities-sandbox',
     'persona_sandbox_[a-z0-9_-]{20,80}'),
    ('pinterest-client-credentials-access-token',
     'pinc[._][A-Za-z0-9_.-]{20,200}'),
    ('polar-customer-session-token',
     'polar_cst_[A-Za-z0-9]{43}'),
    ('polar-member-session-token-sibling',
     'polar_mst_[A-Za-z0-9]{43}'),
    ('polar-oauth-authorization-code',
     'polar_ac_[A-Za-z0-9]{43}'),
    ('polar-oauth-client-registration-token',
     'polar_crt_[A-Za-z0-9]{43}'),
    ('polar-oauth-client-secret',
     'polar_cs_[A-Za-z0-9]{43}'),
    ('polar-oauth-refresh-token-user-org-subject',
     'polar_rt_(?:[uo]_)?[A-Za-z0-9]{43}'),
    ('polar-user-session-token',
     'polar_us_[A-Za-z0-9]{43}'),
    ('posthog-oauth-refresh-token-bare',
     'phr_[A-Za-z0-9_-]{43,48}'),
    ('posthog-project-secret-api-key',
     'phs_[A-Za-z0-9_-]{43,48}'),
    ('pydantic-services-inc-write-api-token',
     'pylf_v[0-9]+_[a-z]+_(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_)?[A-Za-z0-9]{20,}'),
    ('pypi-test-pypi-org-upload-token-sibling',
     'pypi-AgENdGVzdC5weXBpLm9yZ[A-Za-z0-9_-]{50,1000}'),
    ('rainforest-pay-production',
     'apikey_[a-f0-9]{64}'),
    ('rainforest-pay-sandbox',
     'sbx_apikey_[a-f0-9]{64}'),
    ('sentry-integration-token',
     'sntryi_[a-f0-9]{64}'),
    ('sentry-organization-auth-token',
     'sntrys_eyJpYXQiO[A-Za-z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[A-Za-z0-9+/]{10,200}={0,2}_[A-Za-z0-9+/]{43}'),
    ('sentry-user-app-auth-token',
     'sntrya_[a-f0-9]{64}'),
    ('shopify-partner-api-client-access-token',
     'prtapi_[A-Za-z0-9]{32}'),
    ('slack-workflow-token',
     'xwfp-[A-Za-z0-9-]{20,}'),
    ('slack-workflow-trigger-url',
     'https://hooks\\.slack\\.com/triggers/T[A-Z0-9]+/[0-9]+/[a-f0-9]{32}'),
    ('slack-workflow-webhook-url-legacy-workflow-builder',
     'https://hooks\\.slack\\.com/workflows/T[A-Z0-9]+/A[A-Z0-9]+/[0-9]{17,19}/[A-Za-z0-9]{23,25}'),
    ('sourcegraph-dotcom-user-gateway-access-token',
     'sgd_[a-fA-F0-9]{64}'),
    ('sourcegraph-license-key-token',
     'slk_[a-fA-F0-9]{64}'),
    ('sourcegraph-product-enterprise-subscription-token',
     'sgs_[a-fA-F0-9]{64}'),
    ('square-access-token-current',
     'EAAA[A-Za-z0-9_\\-+=]{60}'),
    ('square-sandbox-application-secret',
     'sandbox-sq0cs[bp]-[A-Za-z0-9_-]{43}'),
    ('stripe-organization-api-key',
     'sk_org_[A-Za-z0-9_]{24,247}'),
    ('temporal-cloud-api-key-jwt',
     'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]*InRlbXBvcmFsLmlv[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]{20,}'),
    ('tencent-cloud-secretid',
     'AKID[A-Za-z0-9]{32}'),
    ('typeform-personal-access-token',
     'tfp_[A-Za-z0-9_\\-=.]{59}'),
    ('wakatime-oauth-access-token',
     'waka_tok_[A-Za-z0-9]{20,}'),
    ('wave-mobile-money-inc-production-api-key',
     'wave_[a-z]{2}_prod_[A-Za-z0-9_-]{20,}'),
    ('yandex-cloud-api-key',
     'AQVN[A-Za-z0-9_\\-]{35,38}'),
    ('yandex-refresh-token-sibling',
     'rt1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2}'),
    ('yandex-smartcaptcha-server-key',
     'ysc2_[a-zA-Z0-9]{40}[0-9a-f]{8}'),
    ('yandex-translate-api-key-legacy-v1-5',
     'trnsl\\.1\\.1\\.[0-9]{8}T[0-9]{6}Z\\.[a-f0-9]{16}\\.[a-f0-9]{40}'),
])
# formats whose body has no upper length and a short lower one: any cut of a token is again one
OPEN_ENDED = {"aws-bedrock-short-term-api-key"}
N_RULES = 108


def token(rule_id: str) -> str:
    tok = mcc.new_secret(SOURCES[rule_id], random.Random(rule_id))
    assert tok, rule_id
    return tok


def kinds(text: str, channel: str) -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in detect.scan(text, channel=channel)]


class ResearchedFormatTests(unittest.TestCase):
    def test_every_rule_of_the_research_is_loaded(self):
        loaded = {r.id for r in detect.rules()}
        self.assertEqual(set(SOURCES) - loaded, set())
        self.assertEqual(len(SOURCES), N_RULES)

    def test_each_token_is_found_whole_by_its_rule(self):
        for rule_id in sorted(SOURCES):
            tok = token(rule_id)
            for channel in ("tool", "prompt"):
                for text in (tok, f"here it is: {tok} thanks"):
                    with self.subTest(rule=rule_id, channel=channel, text=text[:12]):
                        self.assertIn((rule_id, tok), kinds(text, channel))
                # after a label, a label rule may take it first (the signature rules run after detect-secrets): whole
                with self.subTest(rule=rule_id, channel=channel, label=True):
                    self.assertIn(tok, [v for _k, v in kinds(f"export TOKEN_VALUE={tok}\n", channel)])

    def test_half_a_token_is_no_hit_of_its_rule(self):
        # at most 40 characters: half of a 2,000-character Bedrock key is still longer than its shortest form
        for rule_id in sorted(set(SOURCES) - OPEN_ENDED):
            tok = token(rule_id)
            with self.subTest(rule=rule_id):
                self.assertNotIn(rule_id, [k for k, _v in kinds(f"see {tok[: min(len(tok) // 2, 40)]} there", "tool")])


if __name__ == "__main__":
    unittest.main()
