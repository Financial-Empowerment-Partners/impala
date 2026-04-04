use aws_sdk_sqs::types::MessageSystemAttributeName;
use aws_sdk_sqs::Client as SqsClient;
use log::{debug, error, info, warn};
use opentelemetry::KeyValue;
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::config::Config;
use crate::constants::DEFAULT_HTTP_CLIENT_TIMEOUT_SECS;
use crate::jobs;
use crate::telemetry::AppMetrics;

/// Shared context passed to all job handlers.
pub struct WorkerContext {
    pub pool: PgPool,
    pub redis_pool: Arc<deadpool_redis::Pool>,
    pub http_client: reqwest::Client,
    pub config: Config,
    pub stellar_rpc_url: String,
    pub horizon_url: String,
    pub ses_client: Option<aws_sdk_sesv2::Client>,
    pub fcm_project_id: Option<String>,
    pub metrics: Arc<AppMetrics>,
}

/// Job message envelope published to SNS and received via SQS.
#[derive(Debug, Deserialize)]
pub struct JobMessage {
    pub job_type: String,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub job_id: Option<String>,
}

/// SNS wraps the actual message in an envelope when delivering to SQS.
#[derive(Debug, Deserialize)]
struct SnsEnvelope {
    #[serde(rename = "Message")]
    message: String,
    #[serde(rename = "Type", default)]
    notification_type: Option<String>,
}

/// Job execution error type.
#[derive(Debug)]
pub enum JobError {
    /// Transient error — message will be retried via SQS visibility timeout.
    Transient(String),
    /// Permanent error — message will eventually go to DLQ after max receives.
    Permanent(String),
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobError::Transient(msg) => write!(f, "Transient error: {}", msg),
            JobError::Permanent(msg) => write!(f, "Permanent error: {}", msg),
        }
    }
}

/// Main worker entry point. Polls SQS in a loop with graceful shutdown.
pub async fn run(
    pool: PgPool,
    redis_pool: Arc<deadpool_redis::Pool>,
    config: Config,
    metrics: Arc<AppMetrics>,
) {
    let queue_url = config
        .sqs_queue_url
        .as_ref()
        .expect("SQS_QUEUE_URL must be set when RUN_MODE=worker")
        .clone();

    let stellar_rpc_url = config.stellar_rpc_url.clone();
    let horizon_url = config.stellar_horizon_url.clone();

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    let ses_client = if config.ses_from_address.is_some() {
        info!("worker: SES email delivery enabled");
        Some(aws_sdk_sesv2::Client::new(&aws_config))
    } else {
        None
    };

    let fcm_project_id = config.fcm_project_id.clone();

    let ctx = Arc::new(WorkerContext {
        pool,
        redis_pool,
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_HTTP_CLIENT_TIMEOUT_SECS))
            .build()
            .expect("Failed to create HTTP client"),
        config: config.clone(),
        stellar_rpc_url,
        horizon_url,
        ses_client,
        fcm_project_id,
        metrics,
    });
    let sqs_client = SqsClient::new(&aws_config);
    let semaphore = Arc::new(Semaphore::new(config.worker_concurrency));

    info!("worker: starting SQS poll loop on {}", queue_url);

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                info!("worker: received shutdown signal, draining in-flight jobs...");
                let _ = semaphore
                    .acquire_many(config.worker_concurrency as u32)
                    .await;
                info!("worker: all in-flight jobs complete, exiting");
                return;
            }
            result = poll_once(&sqs_client, &queue_url, &ctx, &semaphore) => {
                if let Err(e) = result {
                    error!("worker: poll error: {}, backing off 5s", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }
}

async fn poll_once(
    sqs: &SqsClient,
    queue_url: &str,
    ctx: &Arc<WorkerContext>,
    semaphore: &Arc<Semaphore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = sqs
        .receive_message()
        .queue_url(queue_url)
        .max_number_of_messages(10)
        .wait_time_seconds(ctx.config.sqs_wait_time_seconds)
        .visibility_timeout(ctx.config.sqs_visibility_timeout)
        .message_system_attribute_names(MessageSystemAttributeName::ApproximateReceiveCount)
        .send()
        .await?;

    let messages = response.messages.unwrap_or_default();
    if messages.is_empty() {
        return Ok(());
    }

    debug!("worker: received {} message(s)", messages.len());

    for message in messages {
        let permit = semaphore.clone().acquire_owned().await?;
        let ctx = ctx.clone();
        let sqs = sqs.clone();
        let queue_url = queue_url.to_string();

        let visibility_timeout = ctx.config.sqs_visibility_timeout;
        tokio::spawn(async move {
            let _permit = permit; // held until task completes
            let timeout_duration = Duration::from_secs(visibility_timeout as u64);
            if tokio::time::timeout(
                timeout_duration,
                process_message(&sqs, &queue_url, &ctx, &message),
            )
            .await
            .is_err()
            {
                error!(
                    "worker: message {} timed out after {}s",
                    message.message_id().unwrap_or("unknown"),
                    visibility_timeout
                );
            }
        });
    }

    Ok(())
}

async fn process_message(
    sqs: &SqsClient,
    queue_url: &str,
    ctx: &WorkerContext,
    message: &aws_sdk_sqs::types::Message,
) {
    let message_id = message.message_id().unwrap_or("unknown").to_string();
    let receipt_handle = match message.receipt_handle() {
        Some(rh) => rh.to_string(),
        None => {
            error!("worker: message {} has no receipt handle", message_id);
            return;
        }
    };

    let body = match message.body() {
        Some(b) => b.to_string(),
        None => {
            warn!("worker: message {} has empty body, skipping", message_id);
            return;
        }
    };

    info!("worker: processing message_id={}", message_id);

    // Try to parse as SNS envelope first, fall back to direct JobMessage
    let job: JobMessage = if let Ok(envelope) = serde_json::from_str::<SnsEnvelope>(&body) {
        if envelope.notification_type.as_deref() == Some("Notification") {
            match serde_json::from_str::<JobMessage>(&envelope.message) {
                Ok(j) => j,
                Err(e) => {
                    error!(
                        "worker: message {} has invalid inner JSON: {}",
                        message_id, e
                    );
                    return;
                }
            }
        } else {
            // Not an SNS notification, try direct parse
            match serde_json::from_str::<JobMessage>(&body) {
                Ok(j) => j,
                Err(e) => {
                    error!("worker: message {} has invalid JSON: {}", message_id, e);
                    return;
                }
            }
        }
    } else {
        match serde_json::from_str::<JobMessage>(&body) {
            Ok(j) => j,
            Err(e) => {
                error!("worker: message {} has invalid JSON: {}", message_id, e);
                return;
            }
        }
    };

    let job_id = job.job_id.as_deref().unwrap_or("none");
    info!(
        "worker: dispatching job_type={} job_id={} message_id={}",
        job.job_type, job_id, message_id
    );

    let job_type_attr = KeyValue::new("job_type", job.job_type.clone());
    ctx.metrics.jobs_active.add(1, &[job_type_attr.clone()]);
    let start = std::time::Instant::now();

    let result = match job.job_type.as_str() {
        "batch_sync" => jobs::batch_sync::execute(ctx, &job.payload).await,
        "send_notification" => jobs::send_notification::execute(ctx, &job.payload).await,
        "stellar_reconcile" => jobs::stellar_reconcile::execute(ctx, &job.payload).await,
        unknown => {
            error!(
                "worker: unknown job_type '{}' in message {}",
                unknown, message_id
            );
            ctx.metrics.jobs_active.add(-1, &[job_type_attr]);
            return;
        }
    };

    let duration = start.elapsed().as_secs_f64();
    ctx.metrics.jobs_active.add(-1, &[job_type_attr.clone()]);
    ctx.metrics
        .job_duration
        .record(duration, &[job_type_attr.clone()]);

    let outcome = match &result {
        Ok(()) => "success",
        Err(JobError::Transient(_)) => "transient_error",
        Err(JobError::Permanent(_)) => "permanent_error",
    };
    ctx.metrics
        .jobs_processed
        .add(1, &[job_type_attr, KeyValue::new("outcome", outcome)]);

    match result {
        Ok(()) => {
            info!("worker: message {} completed successfully", message_id);
            if let Err(e) = sqs
                .delete_message()
                .queue_url(queue_url)
                .receipt_handle(&receipt_handle)
                .send()
                .await
            {
                error!("worker: failed to delete message {}: {}", message_id, e);
            }
        }
        Err(e) => {
            error!("worker: message {} failed: {}", message_id, e);
            // Do NOT delete — SQS visibility timeout will make it re-appear,
            // and after maxReceiveCount the DLQ will catch it.
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("Failed to listen for Ctrl+C");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_message_deserialize() {
        let json = r#"{
            "job_type": "send_notification",
            "payload": {"account_id": "user1", "medium": "sms"},
            "job_id": "job-123"
        }"#;
        let msg: JobMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.job_type, "send_notification");
        assert_eq!(msg.job_id, Some("job-123".to_string()));
        assert!(msg.payload.is_object());
    }

    #[test]
    fn test_job_message_deserialize_without_job_id() {
        let json = r#"{
            "job_type": "batch_sync",
            "payload": {"account_ids": ["a", "b"]}
        }"#;
        let msg: JobMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.job_type, "batch_sync");
        assert!(msg.job_id.is_none());
    }

    #[test]
    fn test_sns_envelope_deserialize() {
        let json = r#"{
            "Message": "{\"job_type\":\"test\",\"payload\":{}}",
            "Type": "Notification"
        }"#;
        let env: SnsEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(env.notification_type, Some("Notification".to_string()));

        // Verify inner message can be parsed
        let inner: JobMessage = serde_json::from_str(&env.message).unwrap();
        assert_eq!(inner.job_type, "test");
    }

    #[test]
    fn test_sns_envelope_without_type() {
        let json = r#"{"Message": "{}"}"#;
        let env: SnsEnvelope = serde_json::from_str(json).unwrap();
        assert!(env.notification_type.is_none());
    }

    #[test]
    fn test_job_error_display_transient() {
        let err = JobError::Transient("connection timeout".to_string());
        assert_eq!(err.to_string(), "Transient error: connection timeout");
    }

    #[test]
    fn test_job_error_display_permanent() {
        let err = JobError::Permanent("invalid payload".to_string());
        assert_eq!(err.to_string(), "Permanent error: invalid payload");
    }
}
