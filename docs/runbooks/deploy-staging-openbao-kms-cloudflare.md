# Runbook — Staging cluster: OpenBao (KMS auto‑unseal) + Terraform bridge + admin UI + CloudFlare

**Audience:** an operator standing up a fresh **staging** environment on AWS for Payala‑Impala,
with custodial seed protection via **OpenBao backed by AWS KMS**, the **impala‑bridge** and **admin
UI** deployed, fronted by **AWS ALB** and a **CloudFlare** edge.

**Scope of this guide.** It deploys one staging cluster (one bridge stack). It complements the
existing bridge‑only runbook [`deploy.md`](./deploy.md); read that first for the normal
image‑build/rollout loop.

---

## 0. What the repo provides vs. what this guide adds

Be clear‑eyed about this before you start — three pieces are **not** in the repo and are specified
here as net‑new infrastructure.

| Piece | Status in repo | This guide |
|---|---|---|
| Bridge ECS service + worker, ALB, RDS, Redis, ECR, WAF, Secrets, autoscaling | ✅ `terraform/` (`environment="staging"` default) | Apply as‑is with staging vars |
| KMS **seed CMK** (for `seed_protection_backend="kms"`) | ✅ `terraform/seeds.tf` (only when backend=`kms`) | **Not used** here — we use OpenBao |
| OpenBao/Vault **server** | ❌ Terraform only injects `VAULT_ADDR`/`VAULT_TRANSIT_KEY` *pointers* (`seeds.tf:23‑43`); no server, no `seal "awskms"` anywhere | **§3 — you stand it up** (KMS auto‑unseal) |
| Admin UI hosting | ❌ Not in Terraform — only local `docker compose` nginx | **§6 — new S3 origin (or nginx/ECS alt)** |
| CloudFlare / any CDN / public DNS | ❌ Zero CloudFlare; Route 53 is failover‑only and off by default | **§7 — you add it** |
| DB **migration** runner | ❌ No `RUN_MODE=migrate` task in Terraform (the `terraform/README.md` claims one — it's wrong) | **§5 — one‑off `ecs run-task`** |
| `PUBLIC_ENDPOINT` / `CORS_ALLOWED_ORIGINS` on the bridge task | ❌ Unset → insecure defaults (`http://localhost:8080` / `*`) | **§4 — you set them** |

### Target topology

```
                 ┌──────────────── CloudFlare (edge TLS, WAF, DNS) ────────────────┐
   browser  ───► │  admin.staging.<domain>  ──► S3 static UI origin                │
                 │  api.staging.<domain>    ──► AWS ALB (ACM 443) ──► ECS bridge:8080
                 └──────────────────────────────────────────────────────────────────┘
                                                          │ (private subnets)
                                   ┌──────────────────────┼───────────────────────┐
                                   ▼                       ▼                       ▼
                          RDS Postgres 16            ElastiCache Redis      OpenBao server
                          (multi‑AZ, KMS)            (TLS, multi‑AZ)        (Transit engine)
                                                                            ▲   seal "awskms"
                                                                            └── KMS unseal key
   Bridge ──(BAO_ROLE_ID/SECRET_ID via Secrets Manager)──► OpenBao Transit (encrypt/decrypt seeds)
```

"**OpenBao backed by KMS**" here means: the OpenBao **server auto‑unseals using an AWS KMS key**
(a `seal "awskms"` stanza). The bridge then uses OpenBao's **Transit** engine to wrap/unwrap
custodial Stellar seeds (`SEED_PROTECTION_BACKEND=openbao`). The KMS *unseal* key is **separate**
from the Terraform seed CMK (which we don't use in this OpenBao topology).

---

## 1. Prerequisites

- Tools: `terraform >= 1.5`, `aws` CLI v2 (creds for the staging account), `docker` (buildx for
  ARM64 — the bridge defaults to Graviton), `jq`, `bao` (OpenBao CLI) for §3.
- A registered domain in **CloudFlare** (zone active, API token with `Zone:DNS:Edit` + `Zone
  Settings:Edit`).
- An **ACM certificate** in the ALB's region covering `api.staging.<domain>` (and, if you front the
  UI origin with TLS, `admin.staging.<domain>`). Terraform does **not** create ACM certs — provision
  it (DNS‑validate via a temporary CloudFlare record) and note its ARN.
- A strong `JWT_SECRET` (≥ 32 chars) for staging.
- Decide your staging Stellar network — set `stellar_horizon_url` / `stellar_rpc_url` accordingly
  (defaults point at mainnet Horizon / **testnet** RPC, which is inconsistent — set both explicitly).

---

## 2. Build & push the bridge image (ECR)

The ECR repo is created by Terraform, so do a first `terraform apply` (next section) **or** create
just ECR first. Then:

```bash
# from repo root
ECR=$(cd terraform && terraform output -raw ecr_repository_url)
aws ecr get-login-password --region <aws_region> | docker login --username AWS --password-stdin "${ECR%/*}"
docker buildx build --platform linux/arm64 -t "$ECR:staging-$(git rev-parse --short HEAD)" \
  --push impala-bridge/
```
Note the tag — it becomes `-var container_image_tag=...`. (Match `container_architecture`; default
is `ARM64`.)

---

## 3. Stand up OpenBao with KMS auto‑unseal  ⟵ net‑new

The repo has **no** OpenBao server and **no** `seal "awskms"` config. Stand one up before the bridge
(the bridge **fails closed at boot** if `SEED_PROTECTION_BACKEND=openbao` and it can't reach a
working Transit key — `main.rs:209‑216`). The local `impala-bridge/docker-compose.yml` `openbao` +
`openbao-init` services are the **shape reference** (dev‑mode, in‑memory) — production staging needs
persistent storage, TLS, and KMS auto‑unseal.

### 3a. KMS unseal key (separate from the seed CMK)

```bash
aws kms create-key --description "openbao-staging-unseal" --key-usage ENCRYPT_DECRYPT \
  --tags TagKey=Project,TagValue=impala-bridge TagKey=Environment,TagValue=staging
aws kms create-alias --alias-name alias/openbao-staging-unseal --target-key-id <key-id>
```
The OpenBao host's IAM role needs `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey`,
`kms:GenerateDataKey` **on this key only**.

### 3b. Run OpenBao (recommended: small EC2/ASG in the private subnets)

Use the Terraform VPC's private subnets and an SG that allows ingress `8200` from the bridge's
`ecs_tasks` SG. Single‑node Raft storage on an EBS volume is fine for staging. OpenBao config
(`/etc/openbao/openbao.hcl`):

```hcl
storage "raft" { path = "/opt/openbao/data"; node_id = "openbao-staging-1" }

# KMS auto-unseal — this is the "backed by KMS" part.
seal "awskms" {
  region     = "<aws_region>"
  kms_key_id = "<unseal-key-id-or-arn>"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/etc/openbao/tls/cert.pem"
  tls_key_file  = "/etc/openbao/tls/key.pem"
}

api_addr     = "https://vault.staging.<domain>:8200"
cluster_addr = "https://<private-ip>:8201"
ui           = true
```

**TLS‑trust gotcha (important):** the bridge verifies OpenBao's TLS cert — verification is **always
on** (`seed_protect/vault.rs` builds the client with `danger_accept_invalid_certs(false)`). So
OpenBao must present a cert the bridge container trusts. Pick one:
- **Recommended:** put an **internal ALB/NLB with an ACM cert** for `vault.staging.<domain>` in
  front of OpenBao (listener 443 → OpenBao 8200); the bridge dials the ALB over a publicly‑trusted
  cert and points `VAULT_ADDR=https://vault.staging.<domain>`. No custom CA to manage.
- **Alternative:** run a private CA and bake its root into the bridge image's trust store.

### 3c. Initialize, enable Transit, create the key + AppRole

KMS auto‑unseal means OpenBao unseals itself on start; `init` still emits **recovery** keys — store
them offline.

```bash
export BAO_ADDR=https://vault.staging.<domain>      # or the internal ALB DNS
bao operator init                                    # save recovery keys + initial root token OFFLINE
export BAO_TOKEN=<initial-root-token>

# Transit engine + the key the bridge will use (must match VAULT_TRANSIT_KEY below)
bao secrets enable transit
bao write -f transit/keys/impala-seeds

# Least-privilege policy + AppRole for the bridge
bao policy write impala-seeds - <<'EOF'
path "transit/encrypt/impala-seeds" { capabilities = ["update"] }
path "transit/decrypt/impala-seeds" { capabilities = ["update"] }
EOF
bao auth enable approle
bao write auth/approle/role/impala-bridge token_policies="impala-seeds" \
  token_ttl=1h token_max_ttl=4h secret_id_ttl=0
ROLE_ID=$(bao read -field=role_id auth/approle/role/impala-bridge/role-id)
SECRET_ID=$(bao write -f -field=secret_id auth/approle/role/impala-bridge/secret-id)
```

### 3d. Hand the AppRole to the bridge out‑of‑band (Secrets Manager)

Terraform injects only the non‑secret `VAULT_ADDR`/`VAULT_TRANSIT_KEY` pointers — the **auth
credential must be supplied separately**. Store it and wire it into the task's `secrets`:

```bash
aws secretsmanager create-secret --name impala-bridge-staging/bao-approle \
  --secret-string "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}"
```
You will reference this in the ECS task definition `secrets` block (§4). The bridge resolves
`BAO_ROLE_ID`/`BAO_SECRET_ID` (preferred over `VAULT_*`) and exchanges them at
`auth/approle/login`; `BAO_TOKEN` is an alternative if you prefer a static token.

---

## 4. Terraform — apply the staging cluster

`environment` already defaults to `"staging"` → every resource is prefixed `impala-bridge-staging`.
Create `terraform/staging.tfvars` (copy from `terraform.tfvars.example`):

```hcl
aws_region              = "us-east-1"
environment             = "staging"        # gates naming/tags; RDS deletion_protection stays OFF
container_image_tag     = "staging-<sha>"  # from §2
container_architecture  = "ARM64"

# TLS at the ALB (ACM cert for api.staging.<domain>, same region as ALB)
certificate_arn         = "arn:aws:acm:us-east-1:<acct>:certificate/<id>"

# Staging Stellar network — set BOTH explicitly
stellar_horizon_url     = "https://horizon-testnet.stellar.org"
stellar_rpc_url         = "https://soroban-testnet.stellar.org"

# Seed protection via OpenBao (external server from §3). Terraform injects these
# two pointers into the task env; the AppRole credential is supplied via §4a.
seed_protection_backend = "openbao"
vault_addr              = "https://vault.staging.<domain>"
vault_transit_key       = "impala-seeds"

# Staging-sized; tune as needed (defaults are already small)
rds_instance_class      = "db.t3.micro"
redis_node_type         = "cache.t3.micro"
server_desired_count    = 2
worker_desired_count    = 1
alert_email             = "staging-alerts@<domain>"
```

Apply (`jwt_secret` is the only required var with no default, kept off‑disk):

```bash
cd terraform
terraform init
terraform plan  -var-file=staging.tfvars -var "jwt_secret=$JWT_SECRET" -out plan.tfplan
terraform apply plan.tfplan
```

### 4a. Add the bridge → OpenBao auth + public‑origin env (task‑definition edit)

The stock `terraform/ecs.tf` task `secrets` block only carries `DATABASE_URL` and `JWT_SECRET`, and
sets neither `PUBLIC_ENDPOINT` nor `CORS_ALLOWED_ORIGINS`. For this topology, extend **both** the
server and worker task definitions (`ecs.tf:61‑86`, `:128‑152`):

```hcl
# add to the `secrets = [...]` list (server + worker)
{ name = "BAO_ROLE_ID",   valueFrom = "${aws_secretsmanager_secret.bao_approle.arn}:role_id::" },
{ name = "BAO_SECRET_ID", valueFrom = "${aws_secretsmanager_secret.bao_approle.arn}:secret_id::" },

# add to the server `environment = concat([...])` list
{ name = "PUBLIC_ENDPOINT",       value = "https://api.staging.<domain>" },
{ name = "CORS_ALLOWED_ORIGINS",  value = "https://admin.staging.<domain>" },
```
Also grant the **execution** role `secretsmanager:GetSecretValue` on the new secret ARN (extend
`aws_iam_role_policy.ecs_execution_secrets`, `iam.tf:25`), and open the OpenBao SG to the
`ecs_tasks` SG on 8200/443. Re‑apply. (If you prefer not to edit `ecs.tf`, set
`CORS_ALLOWED_ORIGINS`/`PUBLIC_ENDPOINT` cannot be done out‑of‑band — they must live in the task
def, so this edit is required for a correct front‑end.)

> Security note: leaving `CORS_ALLOWED_ORIGINS=*` (the default) is flagged at bridge startup and is
> not acceptable behind a real UI origin. Set it to the exact `https://admin.staging.<domain>`.

---

## 5. Run database migrations (one‑off task)  ⟵ net‑new

There is **no migrate task in Terraform**. The bridge runs all migrations (incl. the new
**019–021**: account `role` + first‑account‑admin bootstrap trigger + backfill, `profile_source`,
`transaction_review`) when started with `RUN_MODE=migrate`, then exits. Run it as a one‑off against
the server task definition, overriding `RUN_MODE`:

```bash
CL=$(cd terraform && terraform output -raw ecs_cluster_name)
TD=impala-bridge-staging-server     # family; or the full ARN from the console
SUBNETS=<private-subnet-ids-csv>; SG=<ecs_tasks-sg-id>
aws ecs run-task --cluster "$CL" --launch-type FARGATE \
  --task-definition "$TD" \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SG],assignPublicIp=DISABLED}" \
  --overrides '{"containerOverrides":[{"name":"impala-bridge-server","environment":[{"name":"RUN_MODE","value":"migrate"}]}]}'
```
Watch the `/ecs/impala-bridge-staging-server` log group; it should log "Migrations completed
successfully" and the task should exit 0.

**Post‑migration admin bootstrap.** Migration 019 promotes the earliest account to `admin` if none
exists; on a brand‑new DB the **first account to register** becomes admin automatically. Confirm at
least one admin exists before relying on the admin console:
```sql
SELECT count(*) FROM impala_account WHERE role='admin';
```
**Post‑deploy:** any pre‑existing JWTs lack the new `role` claim and are treated as `view-only` — all
sessions must refresh/re‑login to gain server‑side roles (see [`deploy.md`](./deploy.md)).

---

## 6. Deploy the admin UI  ⟵ net‑new

The UI is static (`impala-ui/html/`) — no build step. The repo only runs it via local `docker
compose` nginx. For staging, host the static files in **S3** behind CloudFlare (simplest,
Terraform‑native). Add a small `terraform/ui.tf`:

```hcl
resource "aws_s3_bucket" "ui" { bucket = "impala-ui-staging-<acct>" }
resource "aws_s3_bucket_website_configuration" "ui" {
  bucket = aws_s3_bucket.ui.id
  index_document { suffix = "index.html" }
  error_document { key = "index.html" }   # SPA-ish fallback
}
# Public-read is acceptable: the bundle is just JS/HTML; all auth is JWT-to-API.
# (Or keep private and use a CloudFlare Worker/Access with a signed origin.)
```
Upload the static site and point its API base at the staging bridge. Because CloudFlare serves the
UI on a **different** subdomain than the API, configure `html/config.js` with an **absolute** base
(the `NetConfig.resolveBase` accepts any base string) and a single staging network:

```js
window.IMPALA_CONFIG = {
  networks: { testnet: { base: 'https://api.staging.<domain>', label: 'Staging (testnet)' } },
  default: 'testnet'
};
```
Then:
```bash
aws s3 sync impala-ui/html/ s3://impala-ui-staging-<acct>/ --delete \
  --exclude '*.map' --cache-control 'public,max-age=300'
```
Because the API is cross‑origin (`api.` vs `admin.`), the bridge's `CORS_ALLOWED_ORIGINS` from §4a
must list `https://admin.staging.<domain>` — the UI's `X-Request-Nonce` header makes requests
preflighted, and the bridge already allows `authorization`/`content-type`/`x-request-nonce`.

> **Alternative (keep the nginx proxy + two‑bridge routing):** containerize `impala-ui` (add a
> Dockerfile baking `html/` + `nginx.conf` into `nginx:1.27-alpine`), push to ECR, run it as a second
> ECS service behind the ALB on a host/path rule, and repoint the nginx upstreams
> (`testnet-bridge`/`mainnet-bridge`) at the bridge ALB DNS instead of docker service names. Use this
> only if you want same‑origin `/api/<network>/*` routing and a true two‑network UI. For a single
> staging cluster the S3 split‑subdomain path above is simpler.

---

## 7. CloudFlare front end  ⟵ net‑new

No CloudFlare exists in the repo. Add it as its own Terraform (or click‑ops). Provider + DNS:

```hcl
terraform { required_providers { cloudflare = { source = "cloudflare/cloudflare", version = "~> 4" } } }
provider "cloudflare" { api_token = var.cloudflare_api_token }

# UI: admin.staging.<domain> -> S3 website endpoint (proxied / orange-cloud)
resource "cloudflare_record" "admin" {
  zone_id = var.cloudflare_zone_id
  name    = "admin.staging"
  type    = "CNAME"
  content = aws_s3_bucket_website_configuration.ui.website_endpoint
  proxied = true
}

# API: api.staging.<domain> -> ALB DNS (proxied)
resource "cloudflare_record" "api" {
  zone_id = var.cloudflare_zone_id
  name    = "api.staging"
  type    = "CNAME"
  content = data.terraform_remote_state.core.outputs.alb_dns_name   # or paste alb_dns_name
  proxied = true
}
```

CloudFlare settings:
- **SSL/TLS mode: Full (strict).** CloudFlare terminates the public cert; it re‑encrypts to origin.
  The ALB's **ACM cert** for `api.staging.<domain>` is publicly trusted → Full (strict) works with no
  origin‑cert work. For the S3 website endpoint (HTTP‑only), either use a CloudFlare **Origin CA**
  cert if you front it with a TLS origin, or accept that the S3 website origin hop is HTTP inside
  CloudFlare's network (use **Full** for the UI host, **Full (strict)** for the API host) — prefer
  putting the UI behind CloudFlare R2/Pages or an ACM‑fronted origin if strict end‑to‑end is required.
- **Do not cache the API.** Add a cache rule: `Host eq api.staging.<domain>` → *Bypass cache*
  (the bridge sets short‑lived JWTs and dynamic responses). Cache the UI's static assets normally.
- **WAF.** CloudFlare's managed ruleset complements the AWS WAF already on the ALB
  (`terraform/waf.tf`). Optionally restrict the admin UI host to office IPs / CloudFlare Access.
- Enable **HSTS** at CloudFlare (the bridge already sends HSTS; the UI's nginx HSTS/CSP are commented
  out and irrelevant for the S3 path).
- Lock the origin: restrict the ALB SG ingress (80/443) to CloudFlare's published IP ranges so the
  origin can't be reached directly, bypassing the edge.
- **Okta SSO + CloudFlare Access.** To turn on Okta single sign‑on for the dashboard and gate the
  admin host with CloudFlare Access (Okta as the IdP, layered on the app login), see
  [`deploy-okta-sso-admin-ui-cloudflare.md`](./deploy-okta-sso-admin-ui-cloudflare.md).

---

## 8. Smoke test & verify

```bash
# Edge → API → bridge
curl -fsS https://api.staging.<domain>/healthz            # 200
curl -fsS https://api.staging.<domain>/readyz             # 200 (DB+Redis up)
curl -fsS https://api.staging.<domain>/version | jq       # build_date/version match the deploy
curl -fsS https://api.staging.<domain>/network | jq       # confirms the staging Stellar network

# UI
curl -fsS https://admin.staging.<domain>/ | head          # serves index.html
```
In the browser at `https://admin.staging.<domain>`:
1. Register/login — the **first** account is auto‑bootstrapped to `admin`; confirm the admin nav +
   Accounts console load.
2. Exercise the new admin surface: account list/search, role grant, transaction list + flag/review,
   directory force‑sync, and **on‑chain Refresh** (proves `GET /account/onchain` reaches Horizon).
3. **Prove OpenBao+KMS end‑to‑end:** create a custodial account
   (`POST /managed-account/generate`) and sign a payment (`/managed-account/sign`). Success means the
   bridge encrypted/decrypted the seed via OpenBao Transit, whose server unsealed via KMS. If
   OpenBao is unreachable/misconfigured the **bridge would not have started** (fail‑closed), so a
   healthy `/readyz` plus a successful custodial op is the proof.

---

## 9. Teardown

```bash
aws s3 rm s3://impala-ui-staging-<acct>/ --recursive
cd terraform && terraform destroy -var-file=staging.tfvars -var "jwt_secret=$JWT_SECRET"
# then: delete the CloudFlare records/zone settings, the OpenBao EC2/ALB + EBS,
# and (after the recovery window) the KMS unseal key + the bao-approle Secrets Manager secret.
```
Staging RDS has `deletion_protection=false` (only `production` enables it), so `destroy` removes it;
`rds_skip_final_snapshot` defaults to `false`, so a final snapshot is taken unless you override it.

---

## 10. Gaps & caveats (read before relying on this in prod)

- **OpenBao is single‑node** as written. For anything beyond staging, run a 3‑node Raft cluster
  (still KMS auto‑unsealed), back up Raft snapshots, and rotate the AppRole `secret_id`.
- **Terraform edits required:** the bridge task def must be extended (§4a) for `BAO_ROLE_ID/SECRET_ID`
  + `PUBLIC_ENDPOINT` + `CORS_ALLOWED_ORIGINS`; these are net‑new to `ecs.tf`. The UI `ui.tf` and the
  CloudFlare config are net‑new modules. None of this is in the repo today.
- **Migration runner** is a manual one‑off (`§5`) — there is no migrate task/`migrate_*` outputs in
  Terraform despite the `terraform/README.md`.
- **State is local** (no S3/DynamoDB backend, no workspaces). Use a remote backend before sharing the
  staging state across operators.
- **`stellar_rpc_url` default is testnet while `stellar_horizon_url` default is mainnet** — always set
  both explicitly so the staging bridge talks to one consistent network.
- This guide does **not** stand up the optional `testnet_enabled` second bridge stack; the UI is
  configured single‑network. For a true two‑network UI selector, enable that stack and front each
  bridge ALB under `/api/testnet` and `/api/mainnet` (CloudFlare path/host rules or the nginx‑origin
  alternative in §6).
