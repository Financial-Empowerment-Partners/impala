# Impala Terraform

Provisions the Impala AWS infrastructure. Three independent ECS stacks, all off
by default, selected per environment:

| Stack | Toggle | VPC CIDR | Notes |
|-------|--------|----------|-------|
| testnet | `var.testnet_enabled` | `10.2.0.0/16` | Stellar testnet bridge stack |
| live | `var.live_enabled` | `10.3.0.0/16` | Stellar pubnet bridge stack |
| impala | `var.impala_enabled` | `10.4.0.0/16` | `impala-api` + `impala-admin`, public-only, hardened; requires `var.impala_certificate_arn` |

Shared files: `ecr.tf`, `ses.tf`, `main.tf`, `variables.tf`, `outputs.tf`.
VPC CIDRs are guarded against collisions by cross-variable `validation` blocks
(needs Terraform ≥ 1.9; `required_version` is set accordingly).

## Quick checks (no AWS needed)

```bash
terraform fmt -check -recursive
terraform init -backend=false && terraform validate
```

CI runs these in the `terraform-checks` job (`.github/workflows/ci.yml`) along
with `tflint` and a Trivy IaC config scan — **both blocking** since the
2026-06-09 triage. Trivy runs twice: once plain and once with
`--tf-vars trivy-scan.tfvars` (a scanner-only, never-auto-loaded file that
turns all three stack toggles on so the modules are actually evaluated).
Accepted findings carry `#trivy:ignore:AVD-AWS-xxxx` annotations with a
one-line justification next to the resource; new findings must be fixed or
get the same treatment.

## Stack hardening knobs (modules/ecs-stack)

The testnet/live stacks opt into hardening via module variables whose
**defaults preserve the pre-hardening behavior** (a bare module call still
plans 0/0/0 after the moved-block migration). Per-stack values live in
`testnet.tf` / `live.tf`. Operator notes:

- **Redis TLS is staged**: `transit_encryption_mode = "preferred"` accepts
  both TLS and plaintext clients; flip a stack to `"required"` only after the
  bridge image with `rediss://` support is deployed there. With
  `redis_auth_enabled` the task definitions read `REDIS_URL` (a `rediss://`
  URL embedding the AUTH token) from Secrets Manager — so that rollout also
  needs the TLS-capable bridge image. If AWS rejects enabling TLS and AUTH in
  a single modify, apply `transit_encryption_mode` first, then
  `redis_auth_enabled`.
- **SQS uses SSE-SQS, deliberately not `alias/aws/sqs`**: SNS cannot deliver
  to a queue encrypted with the AWS-managed SQS key (no `kms:GenerateDataKey`
  grant for SNS on that key), so jobs would be silently dropped.
- **`az_count` / `nat_count`**: the historical single-subnet topology is
  rejected by real `aws_db_subnet_group` (needs >= 2 AZs) and `aws_lb`
  (needs >= 2 public subnets) applies. live sets `az_count = 2`; testnet can
  set `az_count = 2, nat_count = 1` to fix this while staying on one NAT.
- **Reviewer gate for the hardening apply**: adds, in-place changes and new
  task-definition revisions are expected; **zero destroys of stateful
  resources** (RDS, ElastiCache, SQS, Secrets Manager) — reject the plan
  otherwise.

## WS4 hardening toggles

The WS4 (terraform-stream) pass added the following knobs. All of them keep
the zero-diff convention **except** `waf_enabled` (default-ON) and
`rds_storage_type` (default `gp3`) — those two change the plan of every
existing stack on the first apply after the upgrade; review their diff first.

| Toggle | Where | Default | What it does |
|--------|-------|---------|--------------|
| `waf_enabled` | both modules | **`true`** | WAFv2 web ACL on the stack ALB(s): AWS managed Common/KnownBadInputs/SQLi rule groups + per-IP rate-based block rule (`waf_rate_limit`, default 2000 req/5 min, min 100). ecs-stack gets one ACL per stack; impala-stack shares one ACL across both service ALBs. |
| `flow_logs_enabled` | ecs-stack | `false` (on in testnet + live) | REJECT-traffic VPC flow logs to a 30-day CloudWatch log group (impala-stack keeps its always-on ALL-traffic flow logs). |
| `rds_max_allocated_storage` | ecs-stack | `0` (100 in testnet + live) | RDS storage autoscaling cap in GiB; 0 = off. |
| `rds_storage_type` | ecs-stack | **`gp3`** | RDS storage type (`gp2`/`gp3`). |
| `rds_force_ssl_enabled` | ecs-stack | `false` | Parameter group with `rds.force_ssl = 1` + `?sslmode=require` appended to the `DATABASE_URL` secret. |
| `autoscaling_enabled` | ecs-stack | `false` (on in testnet + live) | CPU target-tracking autoscaling for both ECS services (`server_max_count` default 4 — testnet sets 2, `worker_max_count` default 2, `autoscaling_cpu_target` default 60%; min = desired count). |
| `redis_parameter_group_enabled` | ecs-stack | `false` (on in testnet + live) | Stack ElastiCache parameter group pinning `maxmemory-policy = noeviction` (the bridge's Redis security checks are fail-closed — a full Redis must *error*, never silently evict rate-limit/lockout/revocation keys) and `timeout = 0`. |
| `ops_alerts_enabled` / `ops_alert_email` | root (`ops.tf`) | `false` / `""` | Shared CMK-encrypted SNS ops topic; its ARN is threaded into every stack as `alarm_sns_topic_arn` so all CloudWatch alarms get `alarm_actions` + `ok_actions`. |
| `private_tasks_enabled` | impala-stack | `false` (left off) | Moves the impala tasks into private subnets behind a single NAT gateway, `assign_public_ip = false`. |

### Rollout cautions

- **`gp3` storage (default-changing)**: the first apply migrates existing gp2
  instances **in place** — online, but the instance passes through
  `storage-optimization` and storage **cannot be modified again for ~6 hours**.
  Don't stack a same-day storage resize on top of it.
- **`rds_force_ssl_enabled`**: the parameter-group swap **reboots the DB**
  (`apply_immediately = true`; `rds.force_ssl` is a static, pending-reboot
  parameter), and the new `?sslmode=require` secret value only reaches tasks
  on the **next ECS deployment** — sequence: apply → force a new deployment →
  verify connectivity. Roll out on **testnet first**, then live. The bridge
  needs no code change (sqlx `tls-rustls-aws-lc-rs`; `sslmode=require` does
  TLS without CA verification, no RDS CA bundle).
- **WAF is default-ON** (deliberate convention break — SECURITY.md already
  claimed a WAF): the next apply adds ~$5/mo per web ACL + ~$1/mo per
  rule/rule group + per-request charges to *every enabled stack*. The
  CommonRuleSet's `SizeRestrictions_BODY` rule blocks request bodies > 8 KB —
  real bridge payloads are far smaller, but if legitimate traffic trips a
  managed rule, add a `rule_action_override` in `waf.tf` or set
  `waf_enabled = false` per stack.
- **`ops_alert_email`**: SNS email subscriptions require **manual
  confirmation** (AWS mails a link); delivery is inactive until confirmed.
- **`private_tasks_enabled`**: adds a NAT gateway (~$33/mo + data) — operator
  cost decision, hence left off in `impala.tf`.

## Deferred hardening items

Evaluated in the WS4 design and deliberately **not** built — each needs
coordinated bridge work, not just infrastructure:

- **Secrets-rotation lambdas** (RDS password / JWT secret): requires an
  in-VPC rotation function *and* app-side reconnect/re-read behavior — the
  bridge reads `DATABASE_URL`/`JWT_SECRET` once at task start, so rotation
  without coordinated redeploys causes outages and JWT-invalidation storms.
  Backlog with the bridge team.
- **IAM database authentication**: 15-minute auth tokens require sqlx
  connection-string refresh plumbing in the bridge (a code change, not
  infra). Backlog.
- **Image signing** (Signer/cosign): needs a CI signing step plus an
  enforcement point — ECS has no native admission control, so enforcement
  would need EventBridge + a custom check. Low value until then. Backlog.

The AWS provider is on `~> 6.0` (root + both modules; `bootstrap/` keeps its
own local-state pin). The v6 upgrade was checked against the v6 upgrade
guide; the only config-visible change was `aws_elasticache_replication_group.
auth_token_update_strategy` losing its implicit `ROTATE` default (now set
explicitly in the module). The first plan after the upgrade may show benign
in-place `region` attribute refreshes from the provider's multi-region
support.

## Remote state

State lives in S3 with DynamoDB locking. The backend is a **partial config**
(`backend.tf`); the bucket/key/region/lock-table are passed at init time.

### One-time bootstrap (creates the bucket + lock table)

```bash
cd terraform/bootstrap
terraform init
terraform apply -var="state_bucket_name=impala-tfstate-<account-id>"
# outputs: state_bucket, lock_table
```

`bootstrap/` keeps local state (gitignored). Run it once per account.

### Initialize the main root against S3

```bash
cd terraform
terraform init \
  -backend-config="bucket=impala-tfstate-<account-id>" \
  -backend-config="key=impala/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="dynamodb_table=impala-tflock"
```

CI passes these from repo variables `TF_STATE_BUCKET` / `TF_LOCK_TABLE` and
`secrets.AWS_REGION` (see the `deploy` job).

## Planned refactor: deduplicate the stacks into modules

`testnet.tf` and `live.tf` are ~42 near-identical resources each, differing only
by CIDR, instance sizes/counts, secrets, the name suffix, and a small block of
Stellar env vars. `impala.tf` has a genuinely different topology (public-only,
two-service `for_each`, hardened). Target structure:

```
modules/
  ecs-stack/      # shared by testnet + live (network + RDS + Redis + SNS/SQS + Secrets + ALB + ECS)
  impala-stack/   # the hardened public-only two-service cluster
```

`testnet.tf` / `live.tf` collapse to `module "testnet" { count = var.testnet_enabled ? 1 : 0 ... }`
calls passing the per-stack differences; the Stellar env-var difference is
handled with an `optional()`-typed object so each stack keeps its exact env
(testnet keeps `SOROBAN_CONTRACT_ID`/no passphrase; live keeps the passphrase/no
contract id). The root variable surface is unchanged so `TF_VAR_*` / `-var=` /
`terraform.tfvars` keep working.

> Note (historical): at refactor time the `*.tf` had no WAF, no autoscaling and
> hardcoded single-AZ RDS, and the migration kept it that way to stay zero-diff.
> Those have since been added as the WS4 toggles documented above (plus
> `rds_multi_az` from the C3 pass).

### Zero-destroy migration runbook (operator-run, plan-gated)

The module move changes resource **state addresses** but must not destroy/create
anything. It can only be verified against the real state (a `terraform plan`
showing `0 to add, 0 to change, 0 to destroy` + only moves), so it is run by the
operator who holds state — not in CI, and not blindly in the repo.

1. **Back up**: `terraform state pull > pre-migration.tfstate`. Confirm
   `terraform plan` is already clean. Abort if not.
2. **Backend first**: add `backend.tf` (done), `terraform init -migrate-state ...`,
   re-`plan` → must still be `0/0/0`.
3. **Introduce one module at a time** (testnet → live → impala): add the module
   files, replace the stack body with the `module {}` call, and add `moved {}`
   blocks mapping every old address to its new one. `plan` must show only moves
   (`0 to add, 0 to change, 0 to destroy`); then `apply`.

`moved {}` block patterns (module is `count`-gated, so index `[0]`):

```hcl
# testnet/live: inner count=1 singletons keep their [0] index
moved { from = aws_vpc.testnet[0]               to = module.testnet[0].aws_vpc.this[0] }
moved { from = aws_db_instance.testnet[0]       to = module.testnet[0].aws_db_instance.this[0] }
moved { from = aws_ecs_service.testnet_server[0] to = module.testnet[0].aws_ecs_service.server[0] }
# ... one per resource for all ~42; repeat for live (testnet -> live both sides)

# impala: count-gated singletons drop the inner index; for_each keys MUST match
moved { from = aws_vpc.impala[0]                  to = module.impala[0].aws_vpc.this }
moved { from = aws_lb.impala["impala-api"]        to = module.impala[0].aws_lb.this["impala-api"] }
moved { from = aws_ecs_service.impala["impala-admin"] to = module.impala[0].aws_ecs_service.this["impala-admin"] }
```

Verification (must match before any apply):

```bash
terraform plan -no-color | tee migration-plan.txt
grep -E "Plan: 0 to add, 0 to change, 0 to destroy" migration-plan.txt   # required
```

If any add/change/destroy appears, STOP and diff the churning resource (usually a
renamed argument, a non-identical `Name` tag, or a `for_each` key mismatch). Keep
the `moved {}` blocks for at least one release before removing them in a cleanup PR.
Do not bump providers during the migration — isolate state moves from provider churn.
