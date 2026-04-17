# Terraform — impala-bridge infrastructure

This directory provisions the AWS infrastructure that runs `impala-bridge`
in production: VPC, ECS Fargate services (server + worker), RDS PostgreSQL,
ElastiCache Redis, ALB + WAF, SNS/SQS, ECR, Secrets Manager, CloudWatch
dashboards and alarms, optional SigNoz OTel collector, and optional
cross-region disaster recovery.

For the architectural picture of what the bridge *does* on top of this infra,
read the root [`ARCHITECTURE.md`](../ARCHITECTURE.md). For the bridge's
runtime environment variables, see [`CLAUDE.md`](../CLAUDE.md) or
[`impala-bridge/.env.example`](../impala-bridge/.env.example).

## Prerequisites

- Terraform ≥ 1.6
- AWS credentials with permission to create: VPC, ECS, ECR, RDS, ElastiCache, ALB, WAF, SNS, SQS, Secrets Manager, IAM, KMS, Route 53 (optional), S3.
- An ECR repository path the account can push to (created by this module on first apply).
- A container image for the bridge published to ECR (see `impala-bridge/Dockerfile`).

## Files (map)

| File | Responsibility |
|---|---|
| `main.tf` | Providers, locals, shared tags |
| `vpc.tf` | VPC, subnets, route tables, NAT gateways, VPC endpoints |
| `alb.tf` | ALB, listeners, target groups, WAF, access logs |
| `ecs.tf` | ECS cluster, task definitions, services, auto-scaling |
| `ecr.tf` | Container registry with image scanning |
| `rds.tf` | Postgres 16, Multi-AZ, KMS, parameter group |
| `redis.tf` | ElastiCache Redis 7, replication group |
| `sns_sqs.tf` | Background job topic + queue + DLQ |
| `secrets.tf` | Secrets Manager entries (JWT secret, DB URL) |
| `iam.tf` | Task execution + task roles |
| `monitoring.tf` | CloudWatch dashboards and alarms |
| `otel.tf` | Optional OpenTelemetry collector sidecar |
| `dr.tf` | Optional cross-region DR replica and Route 53 failover |
| `variables.tf` | All input variables |
| `outputs.tf` | ALB DNS, ECR URI, DB endpoint |
| `terraform.tfvars.example` | Copy to `terraform.tfvars` and fill in |

## Required variables

| Variable | Purpose |
|---|---|
| `aws_region` | Primary region (e.g. `us-east-1`) |
| `jwt_secret` | 32+ byte random string; becomes `JWT_SECRET` in the bridge env |
| `container_image_tag` | ECR tag to deploy (e.g. `v1.2.3` or commit SHA) |

Everything else has defaults; see `variables.tf`.

## Recommended workflow

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in secrets locally; do NOT commit
terraform init                                  # install providers + backend
terraform fmt -check -recursive                 # verify formatting
terraform validate                              # verify HCL
terraform plan -out plan.tfplan                 # review the change
terraform apply plan.tfplan                     # apply the reviewed plan
```

After the first `apply`:

1. Push a container image to the ECR repo it created (output: `ecr_repository_url`).
2. Re-`apply` with `container_image_tag` set to that tag so ECS picks it up.
3. Run the one-off DB migration task (below).

## Database migrations

Migrations run as a one-off ECS task using the same image with `RUN_MODE=migrate`:

```bash
aws ecs run-task \
  --cluster $(terraform output -raw ecs_cluster_name) \
  --task-definition $(terraform output -raw migrate_task_definition) \
  --launch-type FARGATE \
  --network-configuration "$(terraform output -json migrate_network_config)"
```

Wait for the task to reach `STOPPED` with `exitCode=0`, then roll out the
server/worker services (they will restart naturally on the next deploy).

## Secrets injection

| Secret | Source | Injection path |
|---|---|---|
| `JWT_SECRET` | `var.jwt_secret` → Secrets Manager | ECS task definition `secrets` block |
| `DATABASE_URL` | Auto-generated RDS URL → Secrets Manager | ECS task definition `secrets` block |
| `TWILIO_TOKEN`, `FCM_SERVICE_ACCOUNT_KEY`, `OKTA_CLIENT_SECRET` | Optional — create SM entries and reference via `additional_secrets` map | ECS task definition `secrets` block |

Secrets never appear in task-definition plaintext env vars — only in the
`secrets` block that resolves from Secrets Manager at task start.

## Rollback

The preferred rollback is the reverse of deploy: re-apply with the previous
`container_image_tag`. ECS rolls back in-place. If the new image is
actively unhealthy:

```bash
# Force a new deployment on the previous tag
terraform apply -var 'container_image_tag=<previous-tag>'
```

RDS rollback is **not** automatic — destructive schema changes require
manual `pg_restore` from the Multi-AZ snapshot. Always test migrations in a
staging environment first.

## Cross-region disaster recovery

Set `dr_enabled = true` and `dr_region = "<secondary>"` to provision:

- RDS cross-region read replica in the DR region.
- ECS cluster + services in the DR region (standby, scaled to 0 by default).
- Route 53 failover record sets.
- S3 and ECR cross-region replication.

See `dr.tf` for the full list.

## Security scanning

Run `tfsec` and `checkov` locally before sending for review:

```bash
tfsec .
checkov -d .
```

These are also gated in CI once Phase B of the improvement plan lands.

## Common gotchas

- **`skip_final_snapshot` defaults to `false`** — destroying `rds.tf` in place requires either flipping this temporarily (don't, in prod) or accepting the snapshot cost.
- **First `terraform apply` fails on the ECS service** until you push an image. Push the image, then re-apply.
- **`certificate_arn`** (for HTTPS at the ALB) must be in the same region as the ALB.
- **SigNoz sidecar** only activates when `signoz_endpoint` is set — otherwise it is omitted from task definitions.

## Outputs

Run `terraform output` after apply for:

- `alb_dns_name` — public hostname for the bridge
- `ecr_repository_url` — where to push images
- `rds_endpoint` — Postgres DNS (inside the VPC only)
- `redis_endpoint` — ElastiCache DNS (inside the VPC only)
- `ecs_cluster_name`, `migrate_task_definition` — for one-off migration runs
