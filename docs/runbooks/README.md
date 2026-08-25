# Impala runbooks

Operational documentation for the Impala bridge, the admin UI, and `impalactl`.

Start from the task you have, not from the document you think you want.

## I need to…

| Task | Go to |
|---|---|
| Run the whole stack on my laptop | [`deploy-local-stack.md`](./deploy-local-stack.md) |
| Ship a normal code change to an existing bridge | [`deploy.md`](./deploy.md) |
| Stand up a **staging** environment from nothing | [`deploy-staging-openbao-kms-cloudflare.md`](./deploy-staging-openbao-kms-cloudflare.md) |
| Stand up a **production** environment from nothing | [`deploy-production-vault-kms-ldap.md`](./deploy-production-vault-kms-ldap.md) |
| Deploy or repoint the **admin UI** | [`deploy-admin-ui.md`](./deploy-admin-ui.md) |
| Turn on Okta SSO for the UI | [`deploy-okta-sso-admin-ui-cloudflare.md`](./deploy-okta-sso-admin-ui-cloudflare.md) |
| Test SSO locally without an IdP account | [`test-sso-openbao-local.md`](./test-sso-openbao-local.md) |
| Drive the bridge from a terminal or a script | [`impalactl-operations.md`](./impalactl-operations.md) |
| Onboard or offboard an operator; grant a role; fix lost MFA | [`accounts-and-roles.md`](./accounts-and-roles.md) |
| Install or rotate a provider credential or custodial seed | [`import-keys.md`](./import-keys.md) |
| Rotate `JWT_SECRET`, database or delivery credentials | [`rotate-secrets.md`](./rotate-secrets.md) |
| Enable, fund or operate the conversion reserve | [`conversion-reserve.md`](./conversion-reserve.md) |
| Work out what an error, log line or failure means | [`triage.md`](./triage.md) |
| Run an incident: severity, comms, containment | [`incident-response.md`](./incident-response.md) |

## The documents

**Deployment**

- [`deploy-local-stack.md`](./deploy-local-stack.md) — bridge + UI + CLI on a
  laptop, the first-admin bootstrap, and why local logs look empty.
- [`deploy.md`](./deploy.md) — steady-state rollout of an existing stack:
  image, `terraform apply`, migrations, smoke tests, rollback, DR failover.
- [`deploy-staging-openbao-kms-cloudflare.md`](./deploy-staging-openbao-kms-cloudflare.md)
  — staging from nothing: OpenBao with KMS auto-unseal, admin UI, CloudFlare
  edge. Marks explicitly what the repo does *not* provide.
- [`deploy-production-vault-kms-ldap.md`](./deploy-production-vault-kms-ldap.md)
  — production: multi-AZ bridge + UI, HashiCorp Vault, LDAP account sync.
- [`deploy-admin-ui.md`](./deploy-admin-ui.md) — the UI specifically: hosting
  shapes, `config.js`, nginx upstreams, CSP/CORS, SSO redirect URIs. **The UI
  has no pipeline and no Terraform** — this is the whole story.
- [`deploy-okta-sso-admin-ui-cloudflare.md`](./deploy-okta-sso-admin-ui-cloudflare.md)
  — Okta SSO for the admin UI, with an optional CloudFlare Access gate.
- [`test-sso-openbao-local.md`](./test-sso-openbao-local.md) — exercise the SSO
  flow locally against OpenBao as the IdP.

**Operating**

- [`impalactl-operations.md`](./impalactl-operations.md) — task-oriented CLI
  guide: pointing at a bridge, auth, account lifecycle, keys and seeds,
  transfers, audit, offline batches, exit codes.
- [`accounts-and-roles.md`](./accounts-and-roles.md) — the role model, the
  first-admin trigger, onboarding, offboarding, the deletion guards, MFA
  recovery.
- [`import-keys.md`](./import-keys.md) — provider credentials and custodial
  seeds. **Read its danger section before touching `/admin/keys/*`.**
- [`rotate-secrets.md`](./rotate-secrets.md) — the secret inventory, blast
  radius per secret, and emergency rotation order.
- [`conversion-reserve.md`](./conversion-reserve.md) — enabling, funding, day-2
  operations, and the failure queues.

**When something is wrong**

- [`triage.md`](./triage.md) — the reference: how to get logs at all, the error
  envelope, why 401s and 403s are indistinguishable from the response, the log
  prefix index, startup failures, and a symptom index.
- [`incident-response.md`](./incident-response.md) — severity guide, first ten
  minutes, common failure modes, escalation.

## Conventions

Every runbook opens with an **Audience** line and, where it matters,
**Prerequisites** and **See also**. Commands are shown as the operator types
them. Steps that move real money, or that cannot be undone, are called out in
place rather than collected at the end.

Where the repo does not actually provide something, the runbooks say so plainly
instead of describing an aspiration. If you find one that no longer matches the
code, fix the runbook in the same change.
