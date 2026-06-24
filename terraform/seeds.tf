# Custodial Stellar seed protection.
#
# Provisions the KMS CMK(s) used by impala-bridge to envelope-encrypt custodial
# Stellar secret seeds, the IAM grants for the ECS task roles, and the env vars
# injected into the task definitions. Everything is gated on
# var.seed_protection_backend, so a "none"/"vault" deployment creates no KMS
# resources. Consuming code: impala-bridge/src/seed_protect.

locals {
  seed_kms_enabled = var.seed_protection_backend == "kms"

  # Primary-region seed CMK ARN (an external passthrough ARN wins over a created key).
  seed_kms_key_arn = local.seed_kms_enabled ? (
    var.kms_seed_key != "" ? var.kms_seed_key : aws_kms_key.stellar_seeds[0].arn
  ) : ""

  # DR-region ARN: the multi-Region replica of the primary key (regional endpoint).
  seed_kms_key_arn_dr = (local.seed_kms_enabled && var.kms_seed_key == "" && var.dr_enabled) ? aws_kms_replica_key.stellar_seeds_dr[0].arn : local.seed_kms_key_arn

  # Testnet runs in the primary region but uses its own independent key.
  seed_kms_key_arn_testnet = (local.seed_kms_enabled && var.testnet_enabled) ? aws_kms_key.stellar_seeds_testnet[0].arn : ""

  _seed_env_base = [{ name = "SEED_PROTECTION_BACKEND", value = var.seed_protection_backend }]
  _seed_env_vault = var.seed_protection_backend == "vault" ? [
    { name = "VAULT_ADDR", value = var.vault_addr },
    { name = "VAULT_TRANSIT_KEY", value = var.vault_transit_key },
  ] : []

  seed_protection_env = concat(local._seed_env_base,
    local.seed_kms_enabled ? [{ name = "KMS_SEED_KEY_ID", value = local.seed_kms_key_arn }] : [],
  local._seed_env_vault)

  seed_protection_env_dr = concat(local._seed_env_base,
    local.seed_kms_enabled ? [{ name = "KMS_SEED_KEY_ID", value = local.seed_kms_key_arn_dr }] : [],
  local._seed_env_vault)

  seed_protection_env_testnet = concat(local._seed_env_base,
    local.seed_kms_enabled ? [{ name = "KMS_SEED_KEY_ID", value = local.seed_kms_key_arn_testnet }] : [],
  local._seed_env_vault)
}

# --- Primary-region CMK for envelope-encrypting custodial seeds ---
resource "aws_kms_key" "stellar_seeds" {
  count                   = local.seed_kms_enabled && var.kms_seed_key == "" ? 1 : 0
  description             = "Envelope-encryption CMK for custodial Stellar seeds - ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  # Multi-Region so primary-encrypted seeds stay decryptable in the DR region.
  multi_region = var.dr_enabled

  tags = {
    Name = "${local.name_prefix}-stellar-seeds-kms"
  }
}

resource "aws_kms_alias" "stellar_seeds" {
  count         = local.seed_kms_enabled && var.kms_seed_key == "" ? 1 : 0
  name          = "alias/${local.name_prefix}-stellar-seeds"
  target_key_id = aws_kms_key.stellar_seeds[0].key_id
}

# --- DR-region replica (same key material, decrypts primary-region ciphertext) ---
resource "aws_kms_replica_key" "stellar_seeds_dr" {
  count                   = local.seed_kms_enabled && var.kms_seed_key == "" && var.dr_enabled ? 1 : 0
  provider                = aws.dr
  description             = "DR replica CMK for custodial Stellar seeds - ${local.name_prefix}"
  primary_key_arn         = aws_kms_key.stellar_seeds[0].arn
  deletion_window_in_days = 30

  tags = {
    Name = "${local.name_prefix}-stellar-seeds-kms-dr"
  }
}

# --- Testnet independent CMK (kept separate from pubnet seeds) ---
resource "aws_kms_key" "stellar_seeds_testnet" {
  count                   = local.seed_kms_enabled && var.testnet_enabled ? 1 : 0
  description             = "Testnet CMK for custodial Stellar seeds - ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-stellar-seeds-kms-testnet"
  }
}

resource "aws_kms_alias" "stellar_seeds_testnet" {
  count         = local.seed_kms_enabled && var.testnet_enabled ? 1 : 0
  name          = "alias/${local.name_prefix}-stellar-seeds-testnet"
  target_key_id = aws_kms_key.stellar_seeds_testnet[0].key_id
}

# --- IAM: grant each ECS task role use of its seed CMK (KMS backend only) ---
# Kept as a separate, narrowly-scoped policy from the SQS/SES/S3 grant so the
# KMS access is auditable in isolation and bound to the seed key only.
resource "aws_iam_role_policy" "ecs_task_kms_seeds" {
  count = local.seed_kms_enabled ? 1 : 0
  name  = "${local.name_prefix}-task-kms-seeds"
  role  = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:GenerateDataKey",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:DescribeKey",
      ]
      Resource = local.seed_kms_key_arn
    }]
  })
}

resource "aws_iam_role_policy" "dr_ecs_task_kms_seeds" {
  count    = local.seed_kms_enabled && var.dr_enabled ? 1 : 0
  provider = aws.dr
  name     = "${local.name_prefix}-dr-task-kms-seeds"
  role     = aws_iam_role.dr_ecs_task[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:GenerateDataKey",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:DescribeKey",
      ]
      Resource = local.seed_kms_key_arn_dr
    }]
  })
}

resource "aws_iam_role_policy" "testnet_ecs_task_kms_seeds" {
  count = local.seed_kms_enabled && var.testnet_enabled ? 1 : 0
  name  = "${local.name_prefix}-testnet-task-kms-seeds"
  role  = aws_iam_role.testnet_ecs_task[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:GenerateDataKey",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:DescribeKey",
      ]
      Resource = local.seed_kms_key_arn_testnet
    }]
  })
}
