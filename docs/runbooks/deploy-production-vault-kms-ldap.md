# Runbook — Production cluster: multi‑AZ bridge + admin UI, HashiCorp Vault (KMS auto‑unseal), LDAP account sync

**Audience:** an operator standing up the **production** Payala‑Impala environment on AWS with
**redundant, multi‑AZ** tasks for **impala‑bridge** and the **admin UI**, custodial seed protection
via **HashiCorp Vault backed by AWS KMS**, and **LDAP** directory account sync.

**Scope.** Production hardening of the existing Terraform stack. Read [`deploy.md`](./deploy.md) for
the steady‑state image/rollout loop, and the staging guide
[`deploy-staging-openbao-kms-cloudflare.md`](./deploy-staging-openbao-kms-cloudflare.md) — the Vault
setup here is the HashiCorp‑Vault twin of that guide's OpenBao section (the bridge code path is
identical; see §5).

---

## 0. What the repo provides vs. what this guide adds

| Piece | Status in repo | This guide |
|---|---|---|
| Multi‑AZ VPC (per‑AZ subnets + NAT), ALB (cross‑AZ), ECS server+worker, RDS multi‑AZ, Redis multi‑AZ, autoscaling, WAF | ✅ `terraform/` — **always on**, driven by `az_count` (not the `environment` string) | Size for prod (§2) |
| RDS deletion protection | ✅ only when `environment="production"` (`rds.tf:139`) | Set `environment="production"` |
| HashiCorp **Vault server** + `seal "awskms"` auto‑unseal | ❌ Terraform injects only `VAULT_ADDR`/`VAULT_TRANSIT_KEY` *pointers* (`seeds.tf:28‑31`); no server, no seal stanza anywhere | **§4 — you run a Raft HA cluster** |
| **LDAP** config on the task | ❌ Zero `LDAP_*` in Terraform (grep‑confirmed) | **§6 — add env + bind‑password secret + SG egress** |
| `profile_source='ldap'` tagging (so force‑sync works) | ❌ Nothing writes `'ldap'`; accounts default `'local'`/`'okta'` (`migrations/020`, `ldap.rs`, `okta.rs`) | **§6 — tag accounts; feature is dormant otherwise** |
| Admin UI hosting | ❌ Not in Terraform; no UI Dockerfile | **§7 — multi‑AZ ECS nginx *or* S3+CloudFront** |
| `PUBLIC_ENDPOINT` / `CORS_ALLOWED_ORIGINS` | ❌ Unset → `http://localhost:8080` / `*` | **§5/§7 — set them** |
| DB **migrate** runner | ❌ No migrate task (README is wrong) | **§8 — one‑off `ecs run-task`** |

### Target topology (multi‑AZ)

```
                         ┌──────────── DNS / edge (Route 53 or CloudFlare) ────────────┐
   browser ─────────────►│  app.<domain>  ──► admin UI (multi‑AZ: ECS nginx ×2  or  S3+CloudFront)
                         │  api.<domain>  ──► ALB (ACM 443, cross‑AZ) ──► bridge tasks
                         └──────────────────────────────────────────────────────────────┘
        AZ‑a                                   AZ‑b                          (≥2 AZs; az_count)
   ┌──────────────┐                       ┌──────────────┐
   │ bridge task  │  ◄── ALB spreads ──►  │ bridge task  │   server min=2 (1/AZ), worker min≥2
   │ worker task  │                       │ worker task  │
   └──────────────┘                       └──────────────┘
        │   │                                  │   │
        ▼   ▼                                  ▼   ▼
   RDS multi‑AZ (sync standby)          ElastiCache Redis (auto‑failover, multi‑AZ)
        │                                                       ▲ Transit encrypt/decrypt seeds
   Vault Raft HA cluster (3 nodes, 1/AZ) ── seal "awskms" auto‑unseal ── KMS unseal key
        ▲                                  LDAP directory (LDAPS) ◄── bridge directory sync
   bridge ──(VAULT_ROLE_ID/SECRET_ID out‑of‑band)──► Vault Transit
```

---

## 1. Prerequisites

- `terraform >= 1.5`, `aws` CLI v2 (production account creds), `docker buildx` (ARM64), `jq`,
  `vault` CLI (for §4).
- A region with **≥ 2 AZs** (≥ 3 recommended — set `az_count` accordingly; subnets index into
  `data.aws_availability_zones.available.names`, `vpc.tf:32‑41`).
- **ACM certificate** in the ALB region for `api.<domain>` (and `app.<domain>` if the UI is
  same‑origin behind the ALB). Terraform does **not** create ACM certs.
- Production `JWT_SECRET` (≥ 32 chars).
- A reachable **LDAPS** directory (AD/OpenLDAP) and a read‑only bind account.
- Decide the production Stellar network and set `stellar_horizon_url` / `stellar_rpc_url` **both**
  explicitly (defaults mix mainnet Horizon with testnet RPC).
- **Remote Terraform state** — the repo uses **local state** (no S3/DynamoDB backend, no workspaces).
  Configure an S3+DynamoDB backend before running production so the state is shared and locked.

---

## 2. Production sizing & multi‑AZ redundancy

`environment="production"` itself **only** turns on RDS deletion protection and changes
naming/tags/OTEL labels (`rds.tf:139`, `main.tf:22,35,43`, `otel.tf:37`) — there is no other
production branch. **All HA is always‑on and driven by `az_count` + counts**, so set those for
redundancy. Create `terraform/production.tfvars`:

```hcl
environment          = "production"     # enables RDS deletion_protection + prod naming
aws_region           = "us-east-1"
az_count             = 3                 # 3-AZ redundancy (region must have ≥3 AZs)

# Bridge redundancy — keep server min ≥ 2 (1 task/AZ survives an AZ loss).
server_desired_count = 3
server_min_count     = 3                 # default min=2; raise to match az_count if desired
server_max_count     = 12
server_cpu           = 512               # default 256/512 is small for prod; size to load
server_memory        = 1024

# WORKER is a single-AZ SPOF at the defaults (desired=1/min=1) — fix it:
worker_desired_count = 2
worker_min_count     = 2                 # ≥2 so async/SQS processing survives an AZ loss
worker_max_count     = 6

# Data tier (multi_az / auto-failover are already on; size for prod)
rds_instance_class        = "db.r6g.large"
rds_allocated_storage     = 100
rds_backup_retention_days = 30           # default 7
rds_skip_final_snapshot   = false
redis_node_type           = "cache.r6g.large"

# TLS at the ALB
certificate_arn      = "arn:aws:acm:us-east-1:<acct>:certificate/<id>"
stellar_horizon_url  = "https://horizon.stellar.org"
stellar_rpc_url      = "https://soroban-rpc.stellar.org"
alert_email          = "prod-alerts@<domain>"
# Optional observability
# signoz_endpoint    = "https://<otel-collector>:4317"
```

**Why these matter (all confirmed in the Terraform):**
- ECS Fargate `awsvpc` services use `subnets = aws_subnet.private[*].id` (one subnet per AZ,
  `ecs.tf:178,211`; `vpc.tf:32‑41`). With `desired_count ≥ 2`, the ECS scheduler **auto‑spreads tasks
  across the per‑AZ subnets** (Fargate has no placement strategy; spread is implicit). Both services
  have `deployment_circuit_breaker { rollback = true }` and `lifecycle { ignore_changes =
  [desired_count] }` (autoscaling owns the live count) — `ecs.tf:189‑196,216‑223`.
- RDS `multi_az = true`, KMS‑encrypted with rotation, `deletion_protection` (prod), final snapshot
  on destroy (`rds.tf:101‑146`). Redis `automatic_failover_enabled` + `multi_az_enabled`,
  `num_cache_clusters = az_count`, TLS at rest + in transit (`elasticache.tf:11‑34`).
- ALB spans public subnets across AZs, health check `/health`, HTTP→HTTPS 301 when `certificate_arn`
  set (`alb.tf`). NAT is one gateway per AZ (no NAT SPOF, `vpc.tf:55‑116`).
- Autoscaling: server CPU 85% / mem 90% / `ALBRequestCountPerTarget` 1000 / latency step at 250 ms;
  worker CPU/mem + SQS `ApproximateNumberOfMessagesVisible > 10` step (`autoscaling.tf`).

---

## 3. Build & push the bridge image (ECR)

```bash
ECR=$(cd terraform && terraform output -raw ecr_repository_url)
aws ecr get-login-password --region <aws_region> | docker login --username AWS --password-stdin "${ECR%/*}"
docker buildx build --platform linux/arm64 -t "$ECR:prod-$(git rev-parse --short HEAD)" --push impala-bridge/
```
Use the tag as `-var container_image_tag=...` (match `container_architecture`, default `ARM64`).

---

## 4. HashiCorp Vault — Raft HA cluster backed by KMS  ⟵ net‑new

The bridge's `vault`/`openbao` backends are **identical code** (`seed_protect/mod.rs:154‑157`; both
use `VaultSeedProtector` over Transit and persist the canonical `vault:` tag). For HashiCorp Vault
set `SEED_PROTECTION_BACKEND=vault`. Terraform does **not** run Vault — `vault_addr`'s own
description says *"The server is external — Terraform does not provision it"* (`variables.tf:269‑273`)
and there is **no `seal "awskms"` anywhere**. "Backed by KMS" = a Vault server **you** operate with
**KMS auto‑unseal**. The bridge **fails closed at boot** if Vault is unreachable/misconfigured
(`main.rs` → `build_protector` → `exit(1)`), so stand Vault up first.

### 4a. KMS unseal key + per‑node IAM

```bash
aws kms create-key --description "vault-prod-unseal" --key-usage ENCRYPT_DECRYPT
aws kms create-alias --alias-name alias/vault-prod-unseal --target-key-id <key-id>
```
Each Vault node's instance role needs `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey` on **this key
only**.

### 4b. Production HA: Integrated Storage (Raft), 3 nodes, one per AZ

HashiCorp Vault **OSS supports Raft HA** (no Enterprise license needed for clustering). Run 3 (or 5)
nodes across the Terraform VPC's private subnets, behind an **internal NLB/ALB** so the bridge has a
single, TLS‑trusted `VAULT_ADDR`. Per‑node config (`/etc/vault.d/vault.hcl`):

```hcl
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-prod-<az>"
  retry_join { leader_api_addr = "https://vault.<domain>:8200" }   # via the internal LB
}

# KMS auto-unseal — the "backed by KMS" part.
seal "awskms" {
  region     = "<aws_region>"
  kms_key_id = "<unseal-key-id-or-arn>"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "/etc/vault.d/tls/cert.pem"
  tls_key_file  = "/etc/vault.d/tls/key.pem"
}

api_addr     = "https://vault.<domain>:8200"
cluster_addr = "https://<node-private-ip>:8201"
ui           = true
```

**TLS trust (hard requirement):** the bridge builds its Vault client with
`danger_accept_invalid_certs(false)` (`seed_protect/vault.rs:84`) — verification is **always on**.
Front the cluster with an **internal ALB/NLB carrying an ACM cert** for `vault.<domain>` (publicly
trusted) and point `VAULT_ADDR=https://vault.<domain>`, or bake a private CA root into the bridge
image. Open the Vault SG to the `ecs_tasks` SG on 8200; allow 8201 between Vault nodes.

### 4c. Initialize, Transit, AppRole

KMS auto‑unseal means nodes unseal themselves on boot; `init` still emits **recovery** keys + a root
token — store them offline (e.g. split among officers).

```bash
export VAULT_ADDR=https://vault.<domain>
vault operator init -recovery-shares=5 -recovery-threshold=3   # save recovery keys + root token OFFLINE
export VAULT_TOKEN=<root-token>
# (join the other two nodes via retry_join; `vault operator raft list-peers` should show 3)

vault secrets enable transit
vault write -f transit/keys/impala-seeds                       # name must match VAULT_TRANSIT_KEY

vault policy write impala-seeds - <<'EOF'
path "transit/encrypt/impala-seeds" { capabilities = ["update"] }
path "transit/decrypt/impala-seeds" { capabilities = ["update"] }
# add the next line only if you use DATABASE_URL_WRAPPED (§4e):
path "sys/wrapping/unwrap"          { capabilities = ["update"] }
EOF
vault auth enable approle
vault write auth/approle/role/impala-bridge token_policies="impala-seeds" \
  token_ttl=1h token_max_ttl=4h secret_id_num_uses=0 secret_id_ttl=0
ROLE_ID=$(vault read -field=role_id auth/approle/role/impala-bridge/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/impala-bridge/secret-id)
```

### 4d. Hand the AppRole to the bridge out‑of‑band

Terraform injects only the non‑secret `VAULT_ADDR`/`VAULT_TRANSIT_KEY` pointers (`seeds.tf:28‑31`);
the **auth credential is out‑of‑band**. The bridge resolves `VAULT_ROLE_ID`/`VAULT_SECRET_ID` (or
`VAULT_TOKEN`); `BAO_*` would take precedence if also set.

```bash
aws secretsmanager create-secret --name impala-bridge-production/vault-approle \
  --secret-string "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}"
```
Wire it into the **server and worker** task `secrets` (both invoke the protector) — see §5.

### 4e. (Optional) `DATABASE_URL_WRAPPED` — fetch the DB URL from Vault at boot

The bridge can avoid a plaintext `DATABASE_URL` by unwrapping a Vault **response‑wrapping (cubbyhole)**
token at startup (`main.rs:89‑107` → `vault::box_unwrap`, `POST {VAULT_ADDR}/v1/sys/wrapping/unwrap`).
Set `DATABASE_URL_WRAPPED=<wrapping-token>` instead of the `DATABASE_URL` secret. **Caveat — the
wrapping token is single‑use**: a restart with an already‑consumed token returns non‑2xx and the
bridge `exit(1)`s. So every task start needs a **fresh** wrapping token (generate/deliver per deploy,
e.g. a sidecar that creates the wrap and writes it to the task). For most deployments the
Secrets‑Manager `DATABASE_URL` (Terraform's default, `rds.tf`) is simpler and AZ‑safe; treat
`DATABASE_URL_WRAPPED` as an advanced, Vault‑centric option.

---

## 5. Terraform apply — production stack + task‑def edits

```bash
cd terraform
terraform init      # with your S3/DynamoDB backend configured
terraform plan  -var-file=production.tfvars -var "jwt_secret=$JWT_SECRET" \
                -var "container_image_tag=prod-<sha>" \
                -var 'seed_protection_backend=vault' \
                -var 'vault_addr=https://vault.<domain>' \
                -var 'vault_transit_key=impala-seeds' -out plan.tfplan
terraform apply plan.tfplan
```

The stock task def carries only `DATABASE_URL` + `JWT_SECRET` secrets and sets neither
`PUBLIC_ENDPOINT` nor `CORS_ALLOWED_ORIGINS`. **Extend both server (`ecs.tf:61‑86`) and worker
(`ecs.tf:128‑152`) task definitions:**

```hcl
# secrets (server + worker) — Vault AppRole + (optionally) the LDAP bind password (§6)
{ name = "VAULT_ROLE_ID",   valueFrom = "${aws_secretsmanager_secret.vault_approle.arn}:role_id::" },
{ name = "VAULT_SECRET_ID", valueFrom = "${aws_secretsmanager_secret.vault_approle.arn}:secret_id::" },

# environment (server) — public origin + CORS for the UI
{ name = "PUBLIC_ENDPOINT",      value = "https://api.<domain>" },
{ name = "CORS_ALLOWED_ORIGINS", value = "https://app.<domain>" },
```
Grant the **execution** role `secretsmanager:GetSecretValue` on the new secret ARNs (extend
`aws_iam_role_policy.ecs_execution_secrets`, `iam.tf:25`). Leaving `CORS_ALLOWED_ORIGINS=*` (the
default) is flagged at bridge startup and is unacceptable in production behind a real UI origin.

---

## 6. LDAP account sync  ⟵ net‑new wiring + a dormant‑feature prerequisite

### How it works (verified in code)
- The bridge reads five vars (`config.rs:143‑159`): `LDAP_URL`, `LDAP_BIND_DN`,
  `LDAP_BIND_PASSWORD`, `LDAP_BASE_DN`, `LDAP_SEARCH_FILTER` (default filter `(uid={})`, the `{}`
  replaced with the RFC‑4515‑escaped `payala_account_id`).
- **Startup `directory_sync`** runs once, inline, in **every server task** at boot, gated on
  `LDAP_URL` (`main.rs:416`, `ldap.rs:198‑201`). It is **read‑only** — it binds, walks
  `impala_account`, searches each id, and only **logs** found/not‑found. It writes nothing
  (`ldap.rs:197‑293`). The worker task does **not** run it.
- **On‑demand force‑sync** `POST /admin/accounts/:id/sync-profile` (admin‑only) re‑pulls from LDAP and
  **writes back** `first_name/middle_name/last_name/affiliation` via COALESCE + `profile_synced_at`
  (`ldap.rs:159‑181`, mapping `givenName/sn/initials/o|ou`). **It branches on `profile_source`:**
  only `'ldap'` does a live re‑pull; `'okta'`/`'local'` return **400**.

### ⚠️ Dormant‑feature prerequisite — tag accounts as `profile_source='ldap'`
Nothing in the code ever sets `profile_source='ldap'` (default is `'local'`; Okta sets `'okta'`;
`directory_sync` doesn't tag). So **out of the box the force‑sync endpoint returns 400 for every
account.** To activate LDAP sync you must tag the LDAP‑sourced accounts, e.g.:
```sql
UPDATE impala_account SET profile_source='ldap' WHERE payala_account_id = ANY($1);
```
Decide your tagging policy (e.g. tag on provisioning, or a periodic job). Until then, only the
read‑only startup reconciliation runs.

### Terraform wiring (none exists today)
Grep confirms **zero `LDAP_*` in `terraform/`**. Add to the **server** task def (the worker doesn't
need it):
```hcl
# environment (server) — non-secret LDAP config
{ name = "LDAP_URL",           value = "ldaps://ldap.<domain>:636" },   # MUST be ldaps:// (see below)
{ name = "LDAP_BIND_DN",       value = "cn=impala-ro,ou=svc,dc=<domain>" },
{ name = "LDAP_BASE_DN",       value = "ou=people,dc=<domain>" },
{ name = "LDAP_SEARCH_FILTER", value = "(uid={})" },                   # exactly one {} placeholder
# secrets (server) — bind password via Secrets Manager, NEVER plaintext env
{ name = "LDAP_BIND_PASSWORD", valueFrom = aws_secretsmanager_secret.ldap_bind.arn },
```
Add a `aws_security_group_rule` egress from `ecs_tasks` to the LDAPS port (636), and ensure the
private‑subnet route to the directory (VPC peering / TGW / on‑prem VPN as applicable). Grant the
execution role read on the new secret.

### Production safety notes (from the code)
- **Use `ldaps://`.** `ldap3` only does TLS if the URL scheme says so — there is no StartTLS call,
  and the bind is a cleartext‑credential `simple_bind` (`ldap.rs:64,76`). `ldap://` sends the bind
  password in the clear. The directory cert must be trusted by the task's CA bundle (TLS verification
  follows ldap3/rustls defaults).
- **Don't run the bridge at debug level in prod.** `Config` is `Debug`‑logged at boot
  (`main.rs:87`), which includes `ldap_bind_password`. Leave `DEBUG_MODE` unset (info level).
- **Boot cost / readiness.** `directory_sync` is **awaited before the server listens**, runs on every
  task, and does one subtree search per account — N tasks × full table on every deploy/scale‑out. A
  slow/unreachable LDAP delays task readiness (it won't crash the task — failures log and return
  early, `ldap.rs:212‑217`). For large directories keep the account table reasonable or expect slow
  boots.
- **Filter‑injection:** the `{}` value is RFC‑4515 escaped (`validate::ldap_escape`), but the
  `LDAP_SEARCH_FILTER` template itself is operator‑supplied and unescaped — keep it a trusted,
  well‑formed filter with exactly one `{}`.
- **Bind‑credential rotation = rolling redeploy** — the password is read once at boot into
  `Arc<LdapConfig>` and never refreshed.

---

## 7. Admin UI — multi‑AZ hosting  ⟵ net‑new

The UI is a static SPA (`impala-ui/html/`) with no Terraform footprint and no Dockerfile. Two
production‑HA options; pick by whether you want **redundant tasks** (matching the bridge) or the
lowest‑ops path.

**Option A — nginx on ECS Fargate, redundant across AZs (matches "redundant tasks").**
Mirror the server service: a UI `Dockerfile` baking `html/` + `nginx.conf` into `nginx:1.27-alpine`
→ ECR; a new `aws_ecs_task_definition` + `aws_ecs_service` with `subnets = aws_subnet.private[*].id`
and `desired_count >= 2` (auto‑spreads across AZs, same mechanism as the bridge); a new
`aws_lb_target_group` (`target_type="ip"`, `/` health check) and a new `aws_lb_listener_rule` on
`aws_lb_listener.https[0]` (host rule `app.<domain>`). None of these exist today — they're net‑new.
Repoint the nginx upstreams (`testnet-bridge`/`mainnet-bridge`/`impala-bridge`) at the bridge ALB DNS
or to `api.<domain>`. Same‑origin keeps WAF/cookies on one hostname.

**Option B — S3 + CloudFront (inherently multi‑AZ/global, recommended for lowest ops).**
S3 is multi‑AZ within the region; CloudFront is global edge — **no AZs, tasks, health checks, or
autoscaling to operate**, and it survives origin‑AZ impairment via edge caching. Add a small
`ui.tf` (S3 bucket + `aws_s3_bucket_website_configuration` with `error_document=index.html` for SPA
fallback) and a CloudFront distribution; serve the UI at `app.<domain>`. Configure
`html/config.js` with an absolute API base and have the bridge `CORS_ALLOWED_ORIGINS` list
`https://app.<domain>` (the UI's `X-Request-Nonce` header makes calls preflighted; the bridge already
allows `authorization`/`content-type`/`x-request-nonce`):
```js
window.IMPALA_CONFIG = {
  networks: { mainnet: { base: 'https://api.<domain>', label: 'Production' } },
  default: 'mainnet'
};
```
```bash
aws s3 sync impala-ui/html/ s3://impala-ui-production-<acct>/ --delete --cache-control 'public,max-age=300'
```

> **Recommendation:** if "redundant tasks across AZs for the admin UI" is a hard requirement, use
> **Option A** (ECS nginx, `desired_count>=2`). Otherwise **Option B** (S3+CloudFront) is the
> simpler, cheaper, inherently‑HA production choice. Either way the bridge ALB (§2) provides the
> redundant API tier.

---

## 8. Database migrations (one‑off task)

There is **no migrate task in Terraform**. Run migrations (incl. **019–021**: account `role` +
first‑admin bootstrap + backfill, `profile_source`, `transaction_review`) as a one‑off against the
server task definition, overriding `RUN_MODE`:
```bash
CL=$(cd terraform && terraform output -raw ecs_cluster_name)
aws ecs run-task --cluster "$CL" --launch-type FARGATE --task-definition impala-bridge-production-server \
  --network-configuration "awsvpcConfiguration={subnets=[<private-subnets>],securityGroups=[<ecs_tasks-sg>],assignPublicIp=DISABLED}" \
  --overrides '{"containerOverrides":[{"name":"impala-bridge-server","environment":[{"name":"RUN_MODE","value":"migrate"}]}]}'
```
Watch `/ecs/impala-bridge-production-server` for "Migrations completed successfully". Migration 019
promotes the earliest account to `admin` if none exists; on a fresh DB the **first** registered
account becomes admin. Confirm `SELECT count(*) FROM impala_account WHERE role='admin'`. **Post‑deploy:
all existing sessions must refresh** to pick up the new `role` claim (pre‑existing tokens are treated
as `view-only`).

---

## 9. Smoke tests & HA verification

```bash
curl -fsS https://api.<domain>/healthz   # 200
curl -fsS https://api.<domain>/readyz    # 200 (DB+Redis up)
curl -fsS https://api.<domain>/version | jq
```
In the browser at `https://app.<domain>`: log in (first account → admin), exercise the account
console, transaction flag/review, and **on‑chain Refresh**.

**Prove each production dimension:**
- **Multi‑AZ bridge redundancy:** in the ECS console confirm server tasks span ≥ 2 AZs; force‑drain
  one task (or simulate an AZ event) and confirm the ALB keeps serving from the other AZ and a
  replacement task launches.
- **Vault + KMS:** create a custodial account (`POST /managed-account/generate`) and sign a payment
  (`/managed-account/sign`). Success means the seed round‑tripped through Vault Transit, whose nodes
  unsealed via KMS. (If Vault were down the bridge wouldn't have started — fail‑closed.)
- **LDAP:** tag a test account `profile_source='ldap'` (§6), then `POST
  /admin/accounts/<id>/sync-profile` and confirm the name/affiliation update + `profile_synced_at`.
  A 400 means the account isn't tagged `'ldap'`.

---

## 10. Day‑2 / rotation

- **Vault AppRole `secret_id`:** rotate by issuing a new `secret_id`, updating the
  `vault-approle` secret, and rolling the ECS services (creds are read at boot).
- **LDAP bind password:** update the `ldap_bind` secret → rolling redeploy (read once at boot).
- **`JWT_SECRET` / `DATABASE_URL`:** see [`rotate-secrets.md`](./rotate-secrets.md). Note the
  blast radius: rotating these forces a redeploy; `DATABASE_URL_WRAPPED` (if used) needs a fresh
  single‑use wrap per task start.
- **Vault Raft:** schedule `vault operator raft snapshot save` backups; keep recovery keys offline;
  patch nodes one AZ at a time.
- **RDS:** production has `deletion_protection`; restores come from automated backups / the final
  snapshot. Redis failover is automatic.

---

## 11. Gaps & caveats

- **LDAP force‑sync is dormant by default** — nothing tags `profile_source='ldap'`; you must tag
  accounts (§6) or the endpoint 400s for everyone. The startup `directory_sync` is read‑only (no
  writeback) and runs on every task at boot.
- **Net‑new Terraform required:** Vault HA cluster (server‑side, not in repo), the `ecs.tf` task‑def
  edits (Vault AppRole + LDAP env/secret + `PUBLIC_ENDPOINT`/`CORS`), the LDAPS SG egress, the UI
  hosting (Option A service+TG+listener‑rule+Dockerfile, or Option B `ui.tf`+CloudFront), and the
  migrate run‑task. None ship in `terraform/` today.
- **`environment="production"` gates only RDS deletion protection** — everything else HA is via
  `az_count`/counts. Don't assume the env string sizes the cluster.
- **Worker is a SPOF at defaults** (`worker_min_count=1`) — set `≥ 2` (§2).
- **Local Terraform state** — configure a remote backend before production.
- **Vault/LDAP TLS trust is mandatory** — both clients verify certs (no override); use ACM‑fronted
  internal endpoints or bake the CA into the bridge image.
- **`DATABASE_URL_WRAPPED` single‑use** — only adopt with per‑task fresh‑token delivery; otherwise
  keep the Secrets‑Manager `DATABASE_URL`.
