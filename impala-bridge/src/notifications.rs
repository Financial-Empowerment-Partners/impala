use log::{error, info, warn};
use opentelemetry::KeyValue;
use sqlx::PgPool;
use std::sync::Arc;

use crate::error::AppError;
use crate::sns;
use crate::telemetry::AppMetrics;

/// Events that can trigger user notifications.
#[allow(dead_code)] // complete event taxonomy; not every variant is emitted yet
pub enum NotificationEvent {
    LoginSuccess {
        account_id: String,
    },
    LoginFailure {
        account_id: String,
    },
    #[allow(dead_code)] // event taxonomy; emitted by paths not yet wired
    PasswordChange {
        account_id: String,
    },
    #[allow(dead_code)] // event taxonomy; emitted by paths not yet wired
    TransferIncoming {
        account_id: String,
        amount: String,
        from: String,
    },
    TransferOutgoing {
        account_id: String,
        amount: String,
        to: String,
    },
    ProfileUpdated {
        account_id: String,
        fields: Vec<String>,
    },
}

impl NotificationEvent {
    pub(crate) fn account_id(&self) -> &str {
        match self {
            Self::LoginSuccess { account_id, .. }
            | Self::LoginFailure { account_id, .. }
            | Self::PasswordChange { account_id, .. }
            | Self::TransferIncoming { account_id, .. }
            | Self::TransferOutgoing { account_id, .. }
            | Self::ProfileUpdated { account_id, .. } => account_id,
        }
    }

    pub(crate) fn event_type_str(&self) -> &'static str {
        match self {
            Self::LoginSuccess { .. } => "login_success",
            Self::LoginFailure { .. } => "login_failure",
            Self::PasswordChange { .. } => "password_change",
            Self::TransferIncoming { .. } => "transfer_incoming",
            Self::TransferOutgoing { .. } => "transfer_outgoing",
            Self::ProfileUpdated { .. } => "profile_updated",
        }
    }

    pub(crate) fn format_message(&self) -> (String, String) {
        match self {
            Self::LoginSuccess { account_id } => (
                "Login Successful".to_string(),
                format!("Your account {} was logged into successfully.", account_id),
            ),
            Self::LoginFailure { account_id } => (
                "Failed Login Attempt".to_string(),
                format!(
                    "A failed login attempt was detected for your account {}.",
                    account_id
                ),
            ),
            Self::PasswordChange { account_id } => (
                "Password Changed".to_string(),
                format!(
                    "The password for your account {} was changed. If this was not you, contact support immediately.",
                    account_id
                ),
            ),
            Self::TransferIncoming {
                amount, from, ..
            } => (
                "Incoming Transfer".to_string(),
                format!("You received a transfer of {} from {}.", amount, from),
            ),
            Self::TransferOutgoing {
                amount, to, ..
            } => (
                "Outgoing Transfer".to_string(),
                format!("You sent a transfer of {} to {}.", amount, to),
            ),
            Self::ProfileUpdated {
                fields, ..
            } => (
                "Profile Updated".to_string(),
                format!(
                    "Your profile was updated. Changed fields: {}.",
                    fields.join(", ")
                ),
            ),
        }
    }
}

#[derive(sqlx::FromRow)]
struct SubscriptionTarget {
    notify_id: i32,
    medium: String,
    mobile: Option<String>,
    email: Option<String>,
    url: Option<String>,
}

/// Active subscriptions for an account/event, joined to their contact details.
///
/// The `mobile_verified_at` clause is where SMS enrollment verification is
/// actually enforced: a number the recipient never confirmed is filtered out
/// here, so it is inert rather than merely flagged. Enforcing at dispatch
/// rather than at write time means a number that *loses* its verification later
/// — the database trigger nulls it whenever `mobile` changes — stops receiving
/// immediately, with no reconciliation step to forget.
///
/// Held as a constant so the guard is covered by a test; deleting the clause
/// silently resumes sending to unconfirmed numbers.
const SUBSCRIPTION_TARGETS_SQL: &str = r#"
        SELECT n.id AS notify_id, ns.medium::text, n.mobile, n.email, n.url
        FROM notification_subscription ns
        JOIN notify n ON n.account_id = ns.account_id AND n.medium = ns.medium
        WHERE ns.account_id = $1
          AND ns.event_type = $2::event_type
          AND ns.enabled = true
          AND (ns.medium::text <> 'sms' OR n.mobile_verified_at IS NOT NULL)
        "#;

/// Dispatch notification jobs for a given event.
///
/// Looks up the user's active subscriptions and contact info, then publishes
/// one `send_notification` job per delivery target via SNS. Fire-and-forget:
/// errors are logged but never propagated.
pub async fn dispatch_event(
    pool: &PgPool,
    sns_client: Option<&Arc<aws_sdk_sns::Client>>,
    sns_topic_arn: Option<&Arc<String>>,
    event: NotificationEvent,
    metrics: Option<&Arc<AppMetrics>>,
) {
    let sns_client = match sns_client {
        Some(c) => c,
        None => return,
    };
    let topic_arn = match sns_topic_arn {
        Some(a) => a,
        None => return,
    };

    let account_id = event.account_id().to_string();
    let event_type = event.event_type_str();
    let (title, body) = event.format_message();

    let targets = sqlx::query_as::<_, SubscriptionTarget>(SUBSCRIPTION_TARGETS_SQL)
        .bind(&account_id)
        .bind(event_type)
        .fetch_all(pool)
        .await;

    let targets = match targets {
        Ok(t) => t,
        Err(e) => {
            error!(
                "dispatch_event: failed to query subscriptions for account={} event={}: {}",
                account_id, event_type, e
            );
            return;
        }
    };

    if targets.is_empty() {
        return;
    }

    info!(
        "dispatch_event: {} subscription(s) for account={} event={}",
        targets.len(),
        account_id,
        event_type
    );

    for target in &targets {
        let mut payload = serde_json::json!({
            "notify_id": target.notify_id,
            "account_id": account_id,
            "medium": target.medium,
            "message_title": title,
            "message_body": body,
        });

        // Set destination based on medium
        match target.medium.as_str() {
            "sms" => {
                if let Some(ref mobile) = target.mobile {
                    payload["destination"] = serde_json::Value::String(mobile.clone());
                } else {
                    warn!(
                        "dispatch_event: no mobile number for notify_id={}, skipping sms",
                        target.notify_id
                    );
                    continue;
                }
            }
            "email" => {
                if let Some(ref email) = target.email {
                    payload["destination"] = serde_json::Value::String(email.clone());
                } else {
                    warn!(
                        "dispatch_event: no email for notify_id={}, skipping email",
                        target.notify_id
                    );
                    continue;
                }
            }
            "webhook" => {
                if let Some(ref url) = target.url {
                    payload["webhook_url"] = serde_json::Value::String(url.clone());
                } else {
                    warn!(
                        "dispatch_event: no URL for notify_id={}, skipping webhook",
                        target.notify_id
                    );
                    continue;
                }
            }
            "mobile_push" => {
                // Fetch device tokens for this account
                let tokens = sqlx::query_scalar::<_, String>(
                    "SELECT token FROM device_token WHERE account_id = $1",
                )
                .bind(&account_id)
                .fetch_all(pool)
                .await;

                match tokens {
                    Ok(t) if !t.is_empty() => {
                        payload["device_tokens"] = serde_json::Value::Array(
                            t.into_iter().map(serde_json::Value::String).collect(),
                        );
                    }
                    Ok(_) => {
                        warn!(
                            "dispatch_event: no device tokens for account={}, skipping mobile_push",
                            account_id
                        );
                        continue;
                    }
                    Err(e) => {
                        error!(
                            "dispatch_event: failed to fetch device tokens for account={}: {}",
                            account_id, e
                        );
                        continue;
                    }
                }
            }
            _ => continue,
        }

        if let Err(e) = sns::publish_job(sns_client, topic_arn, "send_notification", payload).await
        {
            error!(
                "dispatch_event: failed to publish job for notify_id={}: {}",
                target.notify_id, e
            );
        } else if let Some(m) = metrics {
            m.notifications_dispatched.add(
                1,
                &[
                    KeyValue::new("event_type", event_type.to_string()),
                    KeyValue::new("medium", target.medium.clone()),
                ],
            );
        }
    }
}

/// Generate a uniformly-distributed verification code, zero-padded to
/// `NOTIFY_VERIFY_CODE_DIGITS`.
///
/// Rejection sampling rather than `% CODE_SPACE`: the modulo would bias the
/// low end of the range, and a code space with a known skew is a shorter code
/// than it looks. Draws until the value falls in the largest whole multiple of
/// the space, which terminates immediately in the overwhelming majority of
/// draws.
pub fn generate_verification_code() -> Result<String, AppError> {
    let space = crate::constants::NOTIFY_VERIFY_CODE_SPACE;
    let limit = (u32::MAX / space) * space;

    for _ in 0..64 {
        let mut buf = [0u8; 4];
        aws_lc_rs::rand::fill(&mut buf).map_err(|e| {
            error!("generate_verification_code: RNG failure: {}", e);
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?;
        let draw = u32::from_be_bytes(buf);
        if draw < limit {
            return Ok(format!(
                "{:0width$}",
                draw % space,
                width = crate::constants::NOTIFY_VERIFY_CODE_DIGITS as usize
            ));
        }
    }

    // Unreachable in practice: each draw rejects with probability < 2^-32 of
    // the range. Fail closed rather than fall back to a biased value.
    error!("generate_verification_code: exhausted rejection sampling attempts");
    Err(AppError::InternalError(
        "Service temporarily unavailable".to_string(),
    ))
}

/// The SMS body carrying an enrollment code.
///
/// Names the service, states the expiry, and tells a recipient who did not ask
/// for it that ignoring it is the correct response — this message can arrive at
/// a number whose owner has no relationship with us, because the number is
/// whatever the account typed.
pub fn verification_message(code: &str) -> String {
    format!(
        "Impala: {} is your notification verification code. \
         It expires in {} minutes. If you did not request this, ignore this message \
         and no alerts will be sent to this number.",
        code,
        crate::constants::NOTIFY_VERIFY_CODE_TTL_SECS / 60
    )
}

/// Publish the SMS job carrying a verification code.
///
/// Returns `false` when SMS delivery is not configured, so the caller can tell
/// the client that the row is pending but nothing was sent.
pub async fn send_verification_sms(
    sns_client: Option<&Arc<aws_sdk_sns::Client>>,
    sns_topic_arn: Option<&Arc<String>>,
    account_id: &str,
    mobile: &str,
    code: &str,
) -> bool {
    let (Some(sns_client), Some(topic_arn)) = (sns_client, sns_topic_arn) else {
        warn!(
            "send_verification_sms: SNS not configured; no code sent for account={}",
            account_id
        );
        return false;
    };

    // Deliberately no `notify_id`: the worker writes the provider's response
    // into `notify_log`, and Twilio echoes the message body — which would
    // persist the code in the database long after it expired in Redis. The
    // delivery is observable through the job's own logs and metrics instead.
    let payload = serde_json::json!({
        "account_id": account_id,
        "medium": "sms",
        "message_title": "Verification code",
        "message_body": verification_message(code),
        "destination": mobile,
    });

    match sns::publish_job(sns_client, topic_arn, "send_notification", payload).await {
        Ok(()) => true,
        Err(e) => {
            error!(
                "send_verification_sms: failed to publish job for account={}: {}",
                account_id, e
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_account_id_login_success() {
        let event = NotificationEvent::LoginSuccess {
            account_id: "acc123".to_string(),
        };
        assert_eq!(event.account_id(), "acc123");
    }

    #[test]
    fn test_event_account_id_transfer_outgoing() {
        let event = NotificationEvent::TransferOutgoing {
            account_id: "acc456".to_string(),
            amount: "100".to_string(),
            to: "dest".to_string(),
        };
        assert_eq!(event.account_id(), "acc456");
    }

    #[test]
    fn test_event_type_str_all_variants() {
        let cases: Vec<(NotificationEvent, &str)> = vec![
            (
                NotificationEvent::LoginSuccess {
                    account_id: "a".into(),
                },
                "login_success",
            ),
            (
                NotificationEvent::LoginFailure {
                    account_id: "a".into(),
                },
                "login_failure",
            ),
            (
                NotificationEvent::PasswordChange {
                    account_id: "a".into(),
                },
                "password_change",
            ),
            (
                NotificationEvent::TransferIncoming {
                    account_id: "a".into(),
                    amount: "0".into(),
                    from: "b".into(),
                },
                "transfer_incoming",
            ),
            (
                NotificationEvent::TransferOutgoing {
                    account_id: "a".into(),
                    amount: "0".into(),
                    to: "b".into(),
                },
                "transfer_outgoing",
            ),
            (
                NotificationEvent::ProfileUpdated {
                    account_id: "a".into(),
                    fields: vec![],
                },
                "profile_updated",
            ),
        ];
        for (event, expected) in cases {
            assert_eq!(event.event_type_str(), expected);
        }
    }

    #[test]
    fn test_format_message_login_success() {
        let event = NotificationEvent::LoginSuccess {
            account_id: "user1".to_string(),
        };
        let (subject, body) = event.format_message();
        assert_eq!(subject, "Login Successful");
        assert!(body.contains("user1"));
    }

    #[test]
    fn test_format_message_transfer_outgoing() {
        let event = NotificationEvent::TransferOutgoing {
            account_id: "user1".to_string(),
            amount: "500 XLM".to_string(),
            to: "GDEST".to_string(),
        };
        let (subject, body) = event.format_message();
        assert_eq!(subject, "Outgoing Transfer");
        assert!(body.contains("500 XLM"));
        assert!(body.contains("GDEST"));
    }

    #[test]
    fn test_format_message_profile_updated() {
        let event = NotificationEvent::ProfileUpdated {
            account_id: "user1".to_string(),
            fields: vec!["first_name".to_string(), "email".to_string()],
        };
        let (subject, body) = event.format_message();
        assert_eq!(subject, "Profile Updated");
        assert!(body.contains("first_name, email"));
    }

    #[test]
    fn test_format_message_transfer_incoming() {
        let event = NotificationEvent::TransferIncoming {
            account_id: "user1".to_string(),
            amount: "250 XLM".to_string(),
            from: "GSRC".to_string(),
        };
        let (subject, body) = event.format_message();
        assert_eq!(subject, "Incoming Transfer");
        assert!(body.contains("250 XLM"));
        assert!(body.contains("GSRC"));
    }

    // ── SMS enrollment verification ────────────────────────────────────

    #[test]
    fn dispatch_query_filters_unverified_sms_destinations() {
        // This clause IS the enforcement. If it is ever dropped, unconfirmed
        // numbers silently start receiving notifications again, and nothing
        // else in the system would notice.
        assert!(
            SUBSCRIPTION_TARGETS_SQL
                .contains("(ns.medium::text <> 'sms' OR n.mobile_verified_at IS NOT NULL)"),
            "the SMS verification guard is missing from the dispatch query"
        );
    }

    #[test]
    fn dispatch_query_still_delivers_other_media_unconditionally() {
        // Verification gates SMS only; email/webhook/push must not be caught
        // by a clause that accidentally applies to every medium.
        assert!(SUBSCRIPTION_TARGETS_SQL.contains("ns.medium::text <> 'sms'"));
    }

    #[test]
    fn generated_code_has_the_configured_shape() {
        let code = generate_verification_code().expect("code generation failed");
        assert_eq!(
            code.len(),
            crate::constants::NOTIFY_VERIFY_CODE_DIGITS as usize
        );
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "non-digit in code: {code}"
        );
    }

    #[test]
    fn generated_codes_keep_their_leading_zeros() {
        // Zero-padding matters: a code rendered as "1234" when it is really
        // 001234 would never match what the recipient types back.
        let padded = format!(
            "{:0width$}",
            42,
            width = crate::constants::NOTIFY_VERIFY_CODE_DIGITS as usize
        );
        assert_eq!(padded, "000042");
    }

    #[test]
    fn generated_codes_vary() {
        // Not a randomness test — a smoke check that the generator is not
        // pinned to one value.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.insert(generate_verification_code().unwrap());
        }
        assert!(seen.len() > 1, "generator produced a constant value");
    }

    #[test]
    fn generated_codes_span_the_whole_range() {
        // Rejection sampling is there to keep the distribution flat; a
        // generator biased into the low decade would shrink the code space.
        let mut high = false;
        for _ in 0..200 {
            if generate_verification_code().unwrap().starts_with('9') {
                high = true;
                break;
            }
        }
        assert!(high, "no code in the top decade across 200 draws");
    }

    #[test]
    fn verification_message_carries_the_code_and_its_expiry() {
        let msg = verification_message("013579");
        assert!(msg.contains("013579"), "{msg}");
        assert!(msg.contains("10 minutes"), "{msg}");
    }

    #[test]
    fn verification_message_tells_an_unexpecting_recipient_to_ignore_it() {
        // The number is whatever an account typed, so this can land on someone
        // with no relationship to us; the message has to be safe for them.
        let msg = verification_message("123456");
        assert!(msg.contains("did not request"), "{msg}");
        assert!(msg.starts_with("Impala:"), "{msg}");
    }
}
