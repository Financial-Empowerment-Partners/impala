use log::{error, info, warn};
use opentelemetry::KeyValue;
use serde::Deserialize;

use crate::validate::validate_callback_url;
use crate::worker::{JobError, WorkerContext};

#[derive(Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct NotificationPayload {
    notify_id: Option<i32>,
    account_id: String,
    medium: String,
    message_body: String,
    #[serde(default)]
    message_title: Option<String>,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default)]
    device_tokens: Option<Vec<String>>,
}

/// Deliver a notification via webhook or SMS (Twilio).
pub async fn execute(ctx: &WorkerContext, payload: &serde_json::Value) -> Result<(), JobError> {
    let parsed: NotificationPayload = serde_json::from_value(payload.clone())
        .map_err(|e| JobError::Permanent(format!("Invalid send_notification payload: {}", e)))?;

    info!(
        "send_notification: account={} medium={}",
        parsed.account_id, parsed.medium
    );

    let start = std::time::Instant::now();
    let delivery_result = match parsed.medium.as_str() {
        "webhook" => send_webhook(ctx, &parsed).await,
        "sms" => send_sms(ctx, &parsed).await,
        "email" => send_email(ctx, &parsed).await,
        "mobile_push" => send_push(ctx, &parsed).await,
        other => {
            warn!("send_notification: unsupported medium '{}'", other);
            return Err(JobError::Permanent(format!(
                "Unsupported notification medium: {}",
                other
            )));
        }
    };

    let duration = start.elapsed().as_secs_f64();
    let medium_attr = KeyValue::new("medium", parsed.medium.clone());
    ctx.metrics
        .notification_delivery_duration
        .record(duration, &[medium_attr.clone()]);

    let (service_id, service_response, result) = match delivery_result {
        Ok(tuple) => {
            ctx.metrics
                .notifications_delivered
                .add(1, &[medium_attr, KeyValue::new("outcome", "success")]);
            tuple
        }
        Err(e) => {
            ctx.metrics
                .notifications_delivered
                .add(1, &[medium_attr, KeyValue::new("outcome", "error")]);
            return Err(e);
        }
    };

    // Log delivery to notify_log table
    if let Some(notify_id) = parsed.notify_id {
        if let Err(e) = sqlx::query(
            "INSERT INTO notify_log (notify_id, notify_type, service_id, service_response, result) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(notify_id)
        .bind(&parsed.medium)
        .bind(&service_id)
        .bind(&service_response)
        .bind(&result)
        .execute(&ctx.pool)
        .await
        {
            error!("send_notification: failed to log delivery: {}", e);
        }
    }

    Ok(())
}

async fn send_webhook(
    ctx: &WorkerContext,
    payload: &NotificationPayload,
) -> Result<(String, String, String), JobError> {
    let url = payload
        .webhook_url
        .as_deref()
        .ok_or_else(|| JobError::Permanent("webhook medium requires webhook_url".to_string()))?;

    validate_callback_url(url)
        .map_err(|e| JobError::Permanent(format!("Invalid webhook URL: {}", e)))?;

    let body = serde_json::json!({
        "account_id": payload.account_id,
        "message": payload.message_body,
    });

    let response = ctx
        .http_client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| JobError::Transient(format!("Webhook request failed: {}", e)))?;

    let status = response.status().as_u16();
    let response_body = response.text().await.unwrap_or_default();

    if status >= 200 && status < 300 {
        info!("send_notification: webhook to {} returned {}", url, status);
        Ok((url.to_string(), response_body, "delivered".to_string()))
    } else {
        Err(JobError::Transient(format!(
            "Webhook returned HTTP {}",
            status
        )))
    }
}

async fn send_sms(
    ctx: &WorkerContext,
    payload: &NotificationPayload,
) -> Result<(String, String, String), JobError> {
    let sid = ctx
        .config
        .twilio_sid
        .as_deref()
        .ok_or_else(|| JobError::Permanent("SMS delivery requires TWILIO_SID".to_string()))?;
    let token = ctx
        .config
        .twilio_token
        .as_deref()
        .ok_or_else(|| JobError::Permanent("SMS delivery requires TWILIO_TOKEN".to_string()))?;
    let from_number =
        ctx.config.twilio_number.as_deref().ok_or_else(|| {
            JobError::Permanent("SMS delivery requires TWILIO_NUMBER".to_string())
        })?;
    let to_number = payload.destination.as_deref().ok_or_else(|| {
        JobError::Permanent("SMS medium requires destination phone number".to_string())
    })?;

    let twilio_url = format!(
        "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
        sid
    );

    let response = ctx
        .http_client
        .post(&twilio_url)
        .basic_auth(sid, Some(token))
        .form(&[
            ("To", to_number),
            ("From", from_number),
            ("Body", &payload.message_body),
        ])
        .send()
        .await
        .map_err(|e| JobError::Transient(format!("Twilio request failed: {}", e)))?;

    let status = response.status().as_u16();
    let response_body = response.text().await.unwrap_or_default();

    if status >= 200 && status < 300 {
        info!(
            "send_notification: SMS to {} via Twilio returned {}",
            to_number, status
        );
        Ok((
            format!("twilio:{}", to_number),
            response_body,
            "delivered".to_string(),
        ))
    } else {
        error!(
            "send_notification: Twilio returned HTTP {}: {}",
            status, response_body
        );
        Err(JobError::Transient(format!(
            "Twilio returned HTTP {}",
            status
        )))
    }
}

async fn send_email(
    ctx: &WorkerContext,
    payload: &NotificationPayload,
) -> Result<(String, String, String), JobError> {
    let ses_client = ctx.ses_client.as_ref().ok_or_else(|| {
        JobError::Permanent("Email delivery requires SES_FROM_ADDRESS to be configured".to_string())
    })?;
    let from_address = ctx.config.ses_from_address.as_deref().ok_or_else(|| {
        JobError::Permanent("Email delivery requires SES_FROM_ADDRESS".to_string())
    })?;
    let to_address = payload.destination.as_deref().ok_or_else(|| {
        JobError::Permanent("Email medium requires destination email address".to_string())
    })?;

    let subject = payload
        .message_title
        .as_deref()
        .unwrap_or("Impala Bridge Notification");

    use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};

    let result = ses_client
        .send_email()
        .from_email_address(from_address)
        .destination(Destination::builder().to_addresses(to_address).build())
        .content(
            EmailContent::builder()
                .simple(
                    Message::builder()
                        .subject(Content::builder().data(subject).build().map_err(|e| {
                            JobError::Permanent(format!("Failed to build email subject: {}", e))
                        })?)
                        .body(
                            Body::builder()
                                .text(
                                    Content::builder()
                                        .data(&payload.message_body)
                                        .build()
                                        .map_err(|e| {
                                            JobError::Permanent(format!(
                                                "Failed to build email body: {}",
                                                e
                                            ))
                                        })?,
                                )
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await;

    match result {
        Ok(output) => {
            let message_id = output.message_id().unwrap_or("unknown").to_string();
            info!(
                "send_notification: email to {} sent, message_id={}",
                to_address, message_id
            );
            Ok((
                format!("ses:{}", to_address),
                message_id,
                "delivered".to_string(),
            ))
        }
        Err(e) => {
            error!(
                "send_notification: SES send to {} failed: {}",
                to_address, e
            );
            Err(JobError::Transient(format!("SES send failed: {}", e)))
        }
    }
}

async fn send_push(
    ctx: &WorkerContext,
    payload: &NotificationPayload,
) -> Result<(String, String, String), JobError> {
    let project_id = ctx.fcm_project_id.as_deref().ok_or_else(|| {
        JobError::Permanent("Push delivery requires FCM_PROJECT_ID to be configured".to_string())
    })?;

    let tokens = payload
        .device_tokens
        .as_ref()
        .ok_or_else(|| JobError::Permanent("Push delivery requires device_tokens".to_string()))?;

    if tokens.is_empty() {
        return Err(JobError::Permanent(
            "Push delivery: device_tokens array is empty".to_string(),
        ));
    }

    let fcm_url = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        project_id
    );

    let title = payload.message_title.as_deref().unwrap_or("Impala Bridge");

    let mut sent_count = 0u32;
    let mut last_response = String::new();

    // FCM HTTP v1 API requires per-token requests
    for token in tokens {
        let body = serde_json::json!({
            "message": {
                "token": token,
                "notification": {
                    "title": title,
                    "body": payload.message_body,
                },
                "data": {
                    "account_id": payload.account_id,
                    "medium": "mobile_push",
                },
            }
        });

        let response = ctx
            .http_client
            .post(&fcm_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| JobError::Transient(format!("FCM request failed: {}", e)))?;

        let status = response.status().as_u16();
        let response_body = response.text().await.unwrap_or_default();

        if status >= 200 && status < 300 {
            sent_count += 1;
            last_response = response_body;
        } else {
            warn!(
                "send_notification: FCM push to token {} returned HTTP {}: {}",
                &token[..token.len().min(20)],
                status,
                response_body
            );
        }
    }

    if sent_count > 0 {
        info!(
            "send_notification: push sent to {}/{} device(s) for account={}",
            sent_count,
            tokens.len(),
            payload.account_id
        );
        Ok((
            format!("fcm:{}", payload.account_id),
            last_response,
            "delivered".to_string(),
        ))
    } else {
        Err(JobError::Transient(
            "FCM push failed for all device tokens".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_payload_deserialize_webhook() {
        let json = serde_json::json!({
            "account_id": "user1",
            "medium": "webhook",
            "message_body": "Test notification",
            "webhook_url": "https://example.com/hook"
        });
        let parsed: NotificationPayload = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.medium, "webhook");
        assert_eq!(
            parsed.webhook_url,
            Some("https://example.com/hook".to_string())
        );
        assert!(parsed.destination.is_none());
    }

    #[test]
    fn test_notification_payload_deserialize_sms() {
        let json = serde_json::json!({
            "account_id": "user1",
            "medium": "sms",
            "message_body": "Your code is 123456",
            "destination": "+1234567890"
        });
        let parsed: NotificationPayload = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.medium, "sms");
        assert_eq!(parsed.destination, Some("+1234567890".to_string()));
    }

    #[test]
    fn test_notification_payload_deserialize_email() {
        let json = serde_json::json!({
            "account_id": "user1",
            "medium": "email",
            "message_body": "You have a new transfer",
            "message_title": "Transfer Alert",
            "destination": "user@example.com"
        });
        let parsed: NotificationPayload = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.medium, "email");
        assert_eq!(parsed.message_title, Some("Transfer Alert".to_string()));
    }

    #[test]
    fn test_notification_payload_deserialize_push() {
        let json = serde_json::json!({
            "account_id": "user1",
            "medium": "mobile_push",
            "message_body": "New login detected",
            "device_tokens": ["token1", "token2"]
        });
        let parsed: NotificationPayload = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.medium, "mobile_push");
        assert_eq!(
            parsed.device_tokens,
            Some(vec!["token1".to_string(), "token2".to_string()])
        );
    }

    #[test]
    fn test_notification_payload_missing_required_field() {
        let json = serde_json::json!({
            "medium": "sms",
            "message_body": "test"
        });
        let result: Result<NotificationPayload, _> = serde_json::from_value(json);
        assert!(result.is_err()); // missing account_id
    }

    #[test]
    fn test_notification_payload_defaults() {
        let json = serde_json::json!({
            "account_id": "user1",
            "medium": "webhook",
            "message_body": "test"
        });
        let parsed: NotificationPayload = serde_json::from_value(json).unwrap();
        assert!(parsed.message_title.is_none());
        assert!(parsed.destination.is_none());
        assert!(parsed.webhook_url.is_none());
        assert!(parsed.device_tokens.is_none());
        assert!(parsed.notify_id.is_none());
    }
}
