use log::info;
use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use std::sync::Arc;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::Config;

/// Application-level metrics covering all interaction points.
pub struct AppMetrics {
    // HTTP server
    pub http_request_duration: Histogram<f64>,
    pub http_active_requests: UpDownCounter<i64>,

    // Authentication
    pub auth_attempts: Counter<u64>,

    // Transactions
    pub transactions_created: Counter<u64>,

    // MFA
    pub mfa_enrollments: Counter<u64>,
    pub mfa_verifications: Counter<u64>,

    // Notifications
    pub notifications_dispatched: Counter<u64>,
    pub notifications_delivered: Counter<u64>,
    pub notification_delivery_duration: Histogram<f64>,

    // Worker / Jobs
    pub jobs_processed: Counter<u64>,
    pub job_duration: Histogram<f64>,
    pub jobs_active: UpDownCounter<i64>,

    // Stellar reconciliation
    pub stellar_reconcile_txns: Counter<u64>,

    // Batch sync
    pub batch_sync_accounts: Counter<u64>,
}

impl AppMetrics {
    pub fn new(meter: Meter) -> Self {
        Self {
            http_request_duration: meter
                .f64_histogram("http.server.request.duration")
                .with_description("HTTP request duration in seconds")
                .build(),
            http_active_requests: meter
                .i64_up_down_counter("http.server.active_requests")
                .with_description("Number of in-flight HTTP requests")
                .build(),

            auth_attempts: meter
                .u64_counter("auth.attempts")
                .with_description("Authentication attempts by outcome")
                .build(),

            transactions_created: meter
                .u64_counter("transaction.created")
                .with_description("Transactions created")
                .build(),

            mfa_enrollments: meter
                .u64_counter("mfa.enrollment")
                .with_description("MFA enrollment attempts by type and outcome")
                .build(),
            mfa_verifications: meter
                .u64_counter("mfa.verification")
                .with_description("MFA verification attempts by type and outcome")
                .build(),

            notifications_dispatched: meter
                .u64_counter("notification.dispatched")
                .with_description("Notification events dispatched by event type and medium")
                .build(),
            notifications_delivered: meter
                .u64_counter("notification.delivered")
                .with_description("Notifications delivered by medium and outcome")
                .build(),
            notification_delivery_duration: meter
                .f64_histogram("notification.delivery.duration")
                .with_description("Notification delivery duration in seconds")
                .build(),

            jobs_processed: meter
                .u64_counter("worker.job.processed")
                .with_description("Background jobs processed by type and outcome")
                .build(),
            job_duration: meter
                .f64_histogram("worker.job.duration")
                .with_description("Background job processing duration in seconds")
                .build(),
            jobs_active: meter
                .i64_up_down_counter("worker.job.active")
                .with_description("Currently in-flight background jobs")
                .build(),

            stellar_reconcile_txns: meter
                .u64_counter("stellar.reconcile.transactions")
                .with_description("Stellar reconciliation transaction match outcomes")
                .build(),

            batch_sync_accounts: meter
                .u64_counter("batch_sync.accounts")
                .with_description("Batch sync account outcomes")
                .build(),
        }
    }
}

/// Initialize OpenTelemetry with OTLP exporter for traces and metrics.
///
/// When `OTEL_EXPORTER_OTLP_ENDPOINT` is configured, replaces the syslog logger
/// with a `tracing-subscriber` that captures both `tracing` spans and `log` macros,
/// forwarding them to SigNoz via the OTLP protocol.
///
/// Returns `true` if OTEL was initialized (caller should skip syslog setup).
pub fn init_otel(config: &Config) -> bool {
    let endpoint = match config.otel_exporter_endpoint.as_ref() {
        Some(ep) if !ep.is_empty() => ep.clone(),
        _ => return false,
    };

    let service_name = config
        .otel_service_name
        .as_deref()
        .unwrap_or("impala-bridge")
        .to_string();

    let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "server".to_string());

    let resource = Resource::builder()
        .with_attributes(vec![
            KeyValue::new("service.name", service_name),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_string()),
            KeyValue::new(
                "deployment.environment",
                config
                    .otel_environment
                    .as_deref()
                    .unwrap_or("staging")
                    .to_string(),
            ),
            KeyValue::new(
                "service.instance.id",
                format!("{}-{}", run_mode, uuid::Uuid::new_v4()),
            ),
        ])
        .build();

    // OTLP trace exporter + provider
    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .expect("Failed to build OTLP span exporter");

    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter)
        .with_resource(resource.clone())
        .build();

    let tracer = tracer_provider.tracer("impala-bridge");
    opentelemetry::global::set_tracer_provider(tracer_provider);

    // OTLP metrics exporter + provider
    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .expect("Failed to build OTLP metric exporter");

    let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_periodic_exporter(metric_exporter)
        .with_resource(resource)
        .build();

    opentelemetry::global::set_meter_provider(meter_provider);

    // Replace syslog with tracing-subscriber that captures log macros + exports to OTLP
    let otel_layer = OpenTelemetryLayer::new(tracer);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_level(true);

    let filter = if config.debug_mode {
        tracing_subscriber::EnvFilter::new("debug")
    } else {
        tracing_subscriber::EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    info!("OpenTelemetry initialized: endpoint={}", endpoint);
    true
}

/// Create application metrics from the global meter provider.
/// Returns no-op metrics when OTEL is not configured (by design in the OTel API).
pub fn create_metrics() -> Arc<AppMetrics> {
    let meter = opentelemetry::global::meter("impala-bridge");
    Arc::new(AppMetrics::new(meter))
}

/// Flush and shut down OpenTelemetry providers.
///
/// In OpenTelemetry 0.31 the global `shutdown_tracer_provider` helper was
/// removed; shutdown is performed on the provider directly. The bridge does
/// not currently retain a handle to the provider it installs, so the global
/// shutdown is a no-op (the providers will be dropped on process exit).
pub fn shutdown_otel() {
    // Intentionally empty — see doc comment above.
}
