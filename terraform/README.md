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
with `tflint` and a Trivy IaC config scan (both warn-first — triage findings,
add justified `#tfsec:ignore`/`#trivy:ignore` annotations, then make them
blocking).

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

> Note: the current `*.tf` has **no WAF and no autoscaling**, and RDS Multi-AZ is
> hardcoded `false`. Keep those as-is in the refactor to stay zero-diff; exposing
> them is a separate feature, not part of the dedup.

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
