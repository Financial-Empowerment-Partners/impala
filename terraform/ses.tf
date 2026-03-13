# =============================================================================
# SES Email Identity (optional, created only if ses_from_address is provided)
# =============================================================================

resource "aws_ses_email_identity" "sender" {
  count = var.ses_from_address != "" ? 1 : 0
  email = var.ses_from_address
}
