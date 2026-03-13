use log::{error, info, warn};
use opentelemetry::KeyValue;
use sqlx::PgPool;
use std::sync::Arc;

use crate::sns;
use crate::telemetry::AppMetrics;

/// Events that can trigger user notifications.
pub enum NotificationEvent {
    LoginSuccess {
        account_id: String,
    },
    LoginFailure {
        account_id: String,
    },
    PasswordChange {
        account_id: String,
    },
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
    fn account_id(&self) -> &str {
        match self {
            Self::LoginSuccess { account_id, .. }
            | Self::LoginFailure { account_id, .. }
            | Self::PasswordChange { account_id, .. }
            | Self::TransferIncoming { account_id, .. }
            | Self::TransferOutgoing { account_id, .. }
            | Self::ProfileUpdated { account_id, .. } => account_id,
        }
    }

    fn event_type_str(&self) -> &'static str {
        match self {
            Self::LoginSuccess { .. } => "login_success",
            Self::LoginFailure { .. } => "login_failure",
            Self::PasswordChange { .. } => "password_change",
            Self::TransferIncoming { .. } => "transfer_incoming",
            Self::TransferOutgoing { .. } => "transfer_outgoing",
            Self::ProfileUpdated { .. } => "profile_updated",
        }
    }

    fn format_message(&self) -> (String, String) {
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

    // Query active subscriptions joined with contact info
    let targets = sqlx::query_as::<_, SubscriptionTarget>(
        r#"
        SELECT n.id AS notify_id, ns.medium::text, n.mobile, n.email, n.url
        FROM notification_subscription ns
        JOIN notify n ON n.account_id = ns.account_id AND n.medium = ns.medium
        WHERE ns.account_id = $1
          AND ns.event_type = $2::event_type
          AND ns.enabled = true
          AND n.active = true
        "#,
    )
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
                            t.into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
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

        if let Err(e) =
            sns::publish_job(sns_client, topic_arn, "send_notification", payload).await
        {
            error!(
                "dispatch_event: failed to publish job for notify_id={}: {}",
                target.notify_id, e
            );
        } else if let Some(m) = metrics {
            m.notifications_dispatched.add(1, &[
                KeyValue::new("event_type", event_type.to_string()),
                KeyValue::new("medium", target.medium.clone()),
            ]);
        }
    }
}
