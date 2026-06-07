use log::{error, info};

/// Publish a job message to the SNS topic for background worker processing.
pub async fn publish_job(
    client: &aws_sdk_sns::Client,
    topic_arn: &str,
    job_type: &str,
    payload: serde_json::Value,
) -> Result<(), String> {
    let message = serde_json::json!({
        "job_type": job_type,
        "payload": payload,
        "job_id": uuid::Uuid::new_v4().to_string(),
    });

    let message_str = serde_json::to_string(&message).map_err(|e| {
        error!("sns::publish_job: failed to serialize message: {}", e);
        format!("Failed to serialize message: {}", e)
    })?;

    client
        .publish()
        .topic_arn(topic_arn)
        .message(&message_str)
        .send()
        .await
        .map_err(|e| {
            error!(
                "sns::publish_job: failed to publish to {}: {}",
                topic_arn, e
            );
            format!("SNS publish error: {}", e)
        })?;

    info!(
        "sns::publish_job: published job_type={} to {}",
        job_type, topic_arn
    );
    Ok(())
}
