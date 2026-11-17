# Rotate a leaked credential

Rotate first. A leaked value stays valid until the issuer revokes it; deleting a message or a
commit does not revoke it. For every service: create the new credential, put it where the
old one was used, revoke the old one, then read the audit log for the time since the leak.

The session audit (`scripts/audit_transcripts.py`) names the page for each real token from
`scripts/rotation.json`: the same providers as below, each with the documentation page that names the
place, per token kind where the detector tells the kinds apart. A rule that covers several token kinds,
or a kind whose page the docs do not name, gets "see the provider's settings".

Menu paths change over time. If a path below is not there, search the service's
documentation for "revoke token" or "rotate key".

## GitHub

- Personal access token: Settings, Developer settings, Personal access tokens. Delete the
  token, create a new one with the smallest scope that works.
- OAuth app token: Settings, Applications, Authorized OAuth Apps; Revoke the app.
- GitHub App user token or refresh token: Settings, Applications, Authorized GitHub Apps;
  Revoke the app.
- Deploy key or SSH key: repository Settings, Deploy keys, or account Settings, SSH keys.
  Delete the key, generate a new key pair.
- GitHub App private key: the app's settings, Private keys. Generate a new key, then delete
  the old one.
- Audit: the organization audit log; for a pushed secret, also the repository's secret
  scanning alerts.

## GitLab

- Personal access token: your avatar, Edit profile, Access, Personal access tokens
  (https://gitlab.com/-/user_settings/personal_access_tokens, on your own GitLab the same path on
  its host); Rotate or Revoke. A project or group token: the project's or group's settings,
  Access tokens.
- CI/CD variable that leaked in a job log: change the value in Settings, CI/CD, Variables,
  mark it masked and protected, and delete the job log.
- Audit: the audit events of the project or group, if the plan has them.

## AWS

- Access key: IAM, Users, the user, Security credentials. Create a new access key, switch the
  application over, then deactivate and delete the old key.
- Audit: CloudTrail events for the old access key id since the leak. For a key with wide
  rights, also look for new IAM users, keys and running instances.

## Google Cloud

- Service account key: IAM and Admin, Service accounts, the account, Keys. Delete the key,
  create a new one, or better switch to workload identity.
- API key: https://console.cloud.google.com/apis/credentials. Regenerate or delete the key, and
  restrict it.
- Audit: Cloud Audit Logs for the service account.

## Microsoft Azure / Entra ID

- Client secret: App registrations, the app, Certificates and secrets. Add a new secret,
  switch over, delete the old one.
- Storage account key: the storage account, Access keys, Rotate key.
- Audit: the Entra ID sign-in logs for the service principal.

## Stripe

- Secret or restricted key: https://dashboard.stripe.com/apikeys. Rotate the key; Stripe lets you
  keep the old key valid for up to 7 days while you switch over.
- Webhook signing secret: Developers, Webhooks, the endpoint, Roll secret.
- Audit: the request logs in the dashboard.

## OpenAI

- API key: https://platform.openai.com/api-keys. Delete the key, create a new one.
- Audit: the usage page, for usage you do not expect.

## Anthropic

- API key: https://platform.claude.com/settings/keys (the Claude Console). Delete the key, create a new one.
- Audit: the usage and cost pages.

## Slack

- Bot or user token: https://api.slack.com/apps, the app, OAuth and Permissions. Rotate or
  revoke the tokens, reinstall the app if Slack asks for it.
- Incoming webhook URL: the app's Incoming Webhooks page. Remove the URL, add a new one.
- Audit: the workspace access logs and the app's activity.

## Atlassian (Jira, Confluence) and Bitbucket

- An Atlassian API token is revoked on the API tokens page of your Atlassian account
  (https://id.atlassian.com/manage-profile/security/api-tokens). Then create a new one.
- Bitbucket API token: your profile, Account settings, Security, Create and manage API tokens.
  Select the token, Revoke.

## Cloudflare

- API token: https://dash.cloudflare.com/profile/api-tokens, the token's menu, Roll.

## Hugging Face

- Access token: https://huggingface.co/settings/tokens, Manage, then delete or refresh it.

## npm

- Access token: npmjs.com, your profile picture, Access Tokens, the x next to the token; or
  `npm token delete <token id>`.

## Postmark

- Server API token: Servers, the server, API Tokens. Account API token: Account, API Tokens.

## Storyblok

- Personal access token: My account, Account settings, Personal access tokens
  (https://app.storyblok.com/#/me/account?tab=token). A space access token: the space,
  Settings, Access Tokens.

## Database password

- Change the password of the database user (`ALTER USER ... PASSWORD ...` or the provider's
  console), update every application that connects, and end open sessions of the old
  password where the database allows it.
- If the database was reachable from the internet, check its connection log.

## SSH private key

- Remove the public key from every `authorized_keys` file and every service that holds it,
  generate a new key pair, and deploy the new public key.

## Anything else

1. Find the page where the credential was created and revoke or regenerate it there.
2. If the service cannot revoke single credentials, change the account password and end all
   sessions.
3. Update every place that uses the credential.
4. Check the service's log for use in the time since the leak.
5. If personal data leaked, the GDPR may require a notice to the supervisory authority
   within 72 hours; involve the data protection officer.
