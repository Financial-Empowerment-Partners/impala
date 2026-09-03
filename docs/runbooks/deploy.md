# Runbook — Deploying impala-bridge

**Audience:** anyone rolling out a change to the production or staging bridge.

**Prerequisites:** AWS credentials with permission to assume the deploy role;
`terraform` 1.6+; `gh` CLI; access to the ECR repository.

**See also:** scenario‑specific stand‑up guides (this runbook covers the steady‑state rollout of the
existing bridge stack):
- **Staging** — OpenBao (KMS auto‑unseal), admin UI, CloudFlare front end:
  [`deploy-staging-openbao-kms-cloudflare.md`](./deploy-staging-openbao-kms-cloudflare.md).
- **Production** — multi‑AZ redundant bridge + admin UI, HashiCorp Vault (KMS auto‑unseal), LDAP
  account sync: [`deploy-production-vault-kms-ldap.md`](./deploy-production-vault-kms-ldap.md).
- **Okta SSO** — turn on Okta single sign‑on for the admin UI (local + AWS) with an optional
  CloudFlare Access edge gate:
  [`deploy-okta-sso-admin-ui-cloudflare.md`](./deploy-okta-sso-admin-ui-cloudflare.md).

## Deploy checklist (normal change)

1. **Merge to `main`** with CI green. CI builds one image per architecture, pushes them as `:<sha>-amd64` / `:<sha>-arm64`, and stitches them into a multi-arch manifest tagged `:<sha>` — the commit SHA **only**. The ECR repository is immutable: there is no `:latest`, no tag is ever re-pushed, and every deploy pins an explicit SHA.
2. **Verify the image exists.** `aws ecr describe-images --repository-name impala-bridge --image-ids imageTag=<sha> --region <aws_region>` should return the manifest.
3. **Roll the migration task definition first (if the release carries migrations).** Migrations are compiled into the binary (`sqlx::migrate!("./migrations")`), so the migrate task runs whichever migration set is in the image its task definition points at — and that pointer only moves on `terraform apply`. Running the task against the previous revision applies the previous release's migrations: a no-op that looks like success. Update just that resource, from `terraform/`:
    ```
    terraform init
    terraform apply \
      -target=aws_ecs_task_definition.migrate \
      -var "container_image_tag=<sha>" \
      -var "jwt_secret=${JWT_SECRET}"
    ```
    The plan Terraform shows before applying must contain a new revision of the migrate task definition and nothing else you did not expect. (Terraform warns that `-target` is for exceptional use; this is one — the server and worker must not move yet.)
4. **Run the migrations and wait for exit 0.** See [Database migrations](#database-migrations) below. Do **not** continue on a non-zero exit.
   - **Server-side roles (migrations 023–025; extended to seven roles by
     035):** these add the account `role` column, a first-account-admin
     bootstrap trigger + backfill, `profile_source`, and the
     `transaction_review` table; 035 widens the role CHECK for treasurer /
     key-custodian / auditor and must run **before** rolling a binary that
     grants them. **After this deploy, every existing
     session must refresh its token** (or re-login) to obtain the new server-side
     `role` claim — tokens minted before the deploy lack it and are treated as
     `view-only`, so admins will lose admin access in the web UI until they
     refresh. On an existing database the 023 backfill promotes the earliest
     account to `admin`; confirm at least one admin exists
     (`SELECT count(*) FROM impala_account WHERE role='admin'`) before relying on
     the admin console.
   - **036 (USDT0 reserve bucket):** seeds the `USDT0` row in
     `conversion_reserve` and changes no behavior on its own. It is required
     before `RESERVE_USDT0_ISSUER` is set — the bridge refuses to start
     otherwise. There is nothing to roll back.
5. **Run terraform plan for the full release.** From `terraform/`:
    ```
    terraform plan \
      -var "container_image_tag=<sha>" \
      -var "jwt_secret=${JWT_SECRET}" \
      -out plan.tfplan
    ```
    Review the diff. The only expected changes for a code-only deploy are the server and worker ECS task definitions and services (new image reference); the migrate task definition already moved in step 3.
6. **Apply.** `terraform apply plan.tfplan`. ECS rolls the server + worker services one task at a time with the health check as the gate — onto a schema that already exists.
7. **Smoke-test production.**
    - `curl -f https://<alb-dns>/healthz` → 200
    - `curl -sf https://<alb-dns>/readyz` → 200
    - `curl -sf https://<alb-dns>/version | jq` — confirm `build_date` and `version` match the deploy.
8. **Watch dashboards** for ~10 min post-rollout:
    - CloudWatch dashboard `impala-bridge-ops` (CPU, memory, 5xx, p99 latency, SQS backlog + DLQ depth).
    - SigNoz service `impala-bridge` if `signoz_endpoint` is configured.

## Database migrations

Migrations run as a one-off ECS task with `RUN_MODE=migrate`. Always run them
*before* shifting traffic to a version that requires the new schema — which
means the migrate task definition must already point at the new image (step 3
of the checklist: `terraform apply -target=aws_ecs_task_definition.migrate`).
The `migrate_task_definition` output names the latest applied revision.

```
aws ecs run-task \
  --cluster $(cd terraform && terraform output -raw ecs_cluster_name) \
  --task-definition $(cd terraform && terraform output -raw migrate_task_definition) \
  --launch-type FARGATE \
  --network-configuration "$(cd terraform && terraform output -json migrate_network_config)"
```

Poll `aws ecs describe-tasks ...` and wait for `lastStatus=STOPPED` and
`containers[0].exitCode=0`. If the task fails, review the CloudWatch log
group before retrying. Never re-run a failed migration without understanding
what state was left behind.

## Rollback

If post-deploy smoke-tests or dashboards show a regression:

1. **Identify the last-known-good SHA.** Either the previous commit on `main`
   or the tag of the last release.
2. **Re-apply with that tag.** From `terraform/`:
    ```
    terraform apply \
      -var "container_image_tag=<last_good_sha>" \
      -var "jwt_secret=${JWT_SECRET}"
    ```
    ECS rolls back in place.
3. **Verify** using the same smoke-tests as above.
4. **Open a post-mortem issue** and do not re-roll forward until the
   regression is fixed and a new PR has landed.

**Schema rollbacks are not automatic.** If the bad change included a
destructive migration, restore Postgres from the most recent Multi-AZ
snapshot. Do not attempt ad-hoc `ALTER TABLE` reversals in prod.

## Cross-region DR failover

If the primary region is unavailable and `dr_enabled = true`:

1. **Confirm primary is actually down** via AWS Health Dashboard + failure to
   reach `/healthz` from at least two external locations.
2. **Promote the DR RDS replica** in the console (RDS → Databases →
   *impala-dr* → Actions → Promote). This is irreversible; only do it once
   you're committed to the failover.
3. **Update Route 53 failover record** if the automatic health-check-driven
   failover hasn't already triggered. The staging/prod DNS records in
   `dr.tf` fail over automatically when the primary ALB health check fails
   twice in a row.
4. **Scale DR services up.** By default `dr_enabled = true` provisions the
   DR ECS services at desired_count = 0 to save money. Scale the server and
   worker services to their production counts via `terraform apply -var
   'dr_server_desired_count=4' ...`.
5. **Invalidate every bearer token and session — mandatory.** The DR
   ElastiCache group (`dr.tf`) starts **empty**: nothing replicates the
   primary's Redis into it. Redis is the *only* store for token revocation
   (`impala:revoked:*`), refresh-token rotation and family revocation
   (`impala:rotated:*`, `impala:revoked_family:*`), the per-account auth
   epochs that logout-everywhere, role changes and account deletion rely on
   (`impala:auth_epoch:*`), and the `__Host-` sessions (`impala:session:*`).
   Failing over onto an empty Redis silently resurrects every bearer token
   that was revoked, rotated away, or minted before a demotion, for the rest
   of its lifetime: a rotated refresh token mints again, and reuse detection
   only trips once a second presentation of the *same* token collides.
   Nothing logs this. Before serving traffic from DR:
   1. Rotate `JWT_SECRET` **without** `JWT_SECRET_PREVIOUS` — the
      emergency procedure in
      [`rotate-secrets.md`](./rotate-secrets.md#emergency-rotation-suspected-compromise).
      Every refresh and temporal token dies at once; API clients and admins
      re-authenticate.
   2. Force cookie re-login. An empty Redis has already done this (sessions
      live only there). A *stale* Redis — one restored from a snapshot — has
      not: delete `impala:session:*` (SCAN + DEL; never `KEYS` on a live
      node).

   The same two steps are mandatory after **any** Redis data loss in the
   primary — a flush, a node replacement without replication, a restore
   from snapshot. See "Redis lost its data" in
   [`incident-response.md`](./incident-response.md).
6. **Notify downstream consumers** that the bridge DNS has failed over.

Planned failover drills should happen at least quarterly; see the bridge
on-call rotation doc for cadence.

## Gotchas

- **ECR image scanning runs on push.** If a scanner flags a CRITICAL CVE on
  the base image, CI will surface it but not block the deploy — you must
  review before merging.
- **First `terraform apply` on a fresh account** fails because there is no
  image to point the ECS service at. Push an image first, then re-apply.
- **`skip_final_snapshot` defaults to `false` for RDS.** A `terraform
  destroy` will take a snapshot, which is correct for prod but may surprise
  you when tearing down a throwaway environment. Set it to `true` on the
  throwaway stack or expect the snapshot cost.
- **The worker and server deploy together.** If a change breaks the worker
  but not the server, both roll back together — we don't support
  independent rollouts today.
