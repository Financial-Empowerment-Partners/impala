use axum::http::{header, HeaderValue, StatusCode};
use axum::Json;
use serde::Serialize;

#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    BadRequest(String),
    NotFound(String),
    RateLimited {
        retry_after: u64,
    },
    InternalError(String),
    Forbidden,
    Conflict(String),
    /// A transient failure that provably left NO side effect — e.g. a Horizon
    /// error reading the source sequence *before* a transaction was ever
    /// signed or submitted. Distinct from `InternalError` so a caller can
    /// safely retry rather than treating the operation as ambiguous. Maps to
    /// 503 for HTTP clients.
    Retryable(String),
    /// A refusal whose code clients branch on. Unlike the other variants the
    /// code is chosen by the handler, not derived from the variant: the
    /// custodial money paths answer with machine-readable refusals
    /// (`custodial_paused`, `idempotency_conflict`, ...) and clients must
    /// never have to parse message text to learn what happened.
    Coded {
        status: StatusCode,
        code: &'static str,
        message: String,
        details: Option<serde_json::Value>,
    },
}

impl AppError {
    /// A machine-readable refusal. `code` is what clients branch on.
    pub fn coded(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        AppError::Coded {
            status,
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Attach structured details (ids, limits, timestamps) to a `Coded`
    /// refusal. A no-op on every other variant.
    pub fn with_details(self, details: serde_json::Value) -> Self {
        match self {
            AppError::Coded {
                status,
                code,
                message,
                ..
            } => AppError::Coded {
                status,
                code,
                message,
                details: Some(details),
            },
            other => other,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
    /// Structured refusal details (append-only contract: absent unless the
    /// error is a `Coded` refusal that carries them).
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // Handle RateLimited specially to add Retry-After header
        if let AppError::RateLimited { retry_after } = &self {
            let body = ErrorBody {
                error: ErrorDetail {
                    code: "rate_limited".to_string(),
                    message: "Too many requests, please try again later".to_string(),
                    details: None,
                },
            };
            let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            if let Ok(val) = HeaderValue::from_str(&retry_after.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, val);
            }
            return response;
        }

        // Coded refusals carry their own status and code.
        if let AppError::Coded {
            status,
            code,
            message,
            details,
        } = self
        {
            let body = ErrorBody {
                error: ErrorDetail {
                    code: code.to_string(),
                    message,
                    details,
                },
            };
            return (status, Json(body)).into_response();
        }

        let (status, code, message) = match self {
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required".to_string(),
            ),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            AppError::RateLimited { .. } => unreachable!(),
            AppError::InternalError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg)
            }
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Access denied".to_string(),
            ),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
            AppError::Retryable(msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", msg)
            }
            AppError::Coded { .. } => unreachable!(),
        };

        let body = ErrorBody {
            error: ErrorDetail {
                code: code.to_string(),
                message,
                details: None,
            },
        };

        (status, Json(body)).into_response()
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Unauthorized => write!(f, "Unauthorized"),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::RateLimited { retry_after } => {
                write!(f, "Rate limited (retry after {}s)", retry_after)
            }
            AppError::InternalError(msg) => write!(f, "Internal error: {}", msg),
            AppError::Forbidden => write!(f, "Forbidden"),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::Retryable(msg) => write!(f, "Retryable: {}", msg),
            AppError::Coded { code, message, .. } => write!(f, "{}: {}", code, message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn test_unauthorized_status() {
        let response = AppError::Unauthorized.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_bad_request_status() {
        let response = AppError::BadRequest("test".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_not_found_status() {
        let response = AppError::NotFound("test".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_rate_limited_status() {
        let response = AppError::RateLimited { retry_after: 60 }.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_internal_error_status() {
        let response = AppError::InternalError("test".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_forbidden_status() {
        let response = AppError::Forbidden.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_conflict_status() {
        let response = AppError::Conflict("test".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn coded_error_serializes_code_and_details() {
        let err = AppError::coded(
            StatusCode::CONFLICT,
            "custodial_daily_limit",
            "daily cap reached",
        )
        .with_details(serde_json::json!({ "remaining_stroops": 5, "resets_at": "x" }));
        assert_eq!(err.to_string(), "custodial_daily_limit: daily cap reached");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "custodial_daily_limit");
        assert_eq!(body["error"]["message"], "daily cap reached");
        assert_eq!(body["error"]["details"]["remaining_stroops"], 5);
        assert_eq!(body["error"]["details"]["resets_at"], "x");
    }

    #[tokio::test]
    async fn coded_error_without_details_omits_the_key() {
        let err = AppError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "custodial_paused",
            "paused",
        );
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "custodial_paused");
        assert!(
            body["error"].get("details").is_none(),
            "details must be absent, not null, when not supplied"
        );
        // Existing variants keep their wire shape: no details key ever.
        let body = body_json(AppError::Forbidden.into_response()).await;
        assert!(body["error"].get("details").is_none());
    }

    #[test]
    fn with_details_is_a_no_op_on_other_variants() {
        let err = AppError::BadRequest("x".to_string()).with_details(serde_json::json!({}));
        assert!(matches!(err, AppError::BadRequest(_)));
    }
}
