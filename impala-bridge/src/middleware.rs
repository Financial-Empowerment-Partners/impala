use axum::http::{Request, Response};
use opentelemetry::KeyValue;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tower::Layer;
use tower::Service;

use crate::telemetry::AppMetrics;

/// Tower layer that records HTTP request metrics (duration, active requests, status codes).
#[derive(Clone)]
pub struct MetricsLayer {
    metrics: Arc<AppMetrics>,
}

impl MetricsLayer {
    pub fn new(metrics: Arc<AppMetrics>) -> Self {
        Self { metrics }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            metrics: self.metrics.clone(),
        }
    }
}

#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
    metrics: Arc<AppMetrics>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for MetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let method = req.method().to_string();
        let path = normalize_path(req.uri().path());
        let metrics = self.metrics.clone();

        // Tower clone-and-swap pattern: take the ready inner service, replace with clone
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            metrics.http_active_requests.add(1, &[]);
            let start = Instant::now();

            let result = inner.call(req).await;

            let duration = start.elapsed().as_secs_f64();
            metrics.http_active_requests.add(-1, &[]);

            let status = match &result {
                Ok(response) => response.status().as_u16().to_string(),
                Err(_) => "500".to_string(),
            };

            let attrs = [
                KeyValue::new("http.request.method", method),
                KeyValue::new("http.route", path),
                KeyValue::new("http.response.status_code", status),
            ];

            metrics.http_request_duration.record(duration, &attrs);

            result
        })
    }
}

/// Normalize URI path for metrics to avoid high cardinality.
/// Replaces numeric and UUID path segments with `:id`.
fn normalize_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.is_empty() {
                segment
            } else if segment.chars().all(|c| c.is_ascii_digit()) {
                ":id"
            } else if uuid::Uuid::parse_str(segment).is_ok() {
                ":id"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
