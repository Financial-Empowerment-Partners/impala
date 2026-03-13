use axum::http::{header, HeaderValue, StatusCode};
use axum::Json;
use serde::Serialize;

#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    BadRequest(String),
    NotFound(String),
    RateLimited { retry_after: u64 },
    InternalError(String),
    Forbidden,
    Conflict(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // Handle RateLimited specially to add Retry-After header
        if let AppError::RateLimited { retry_after } = &self {
            let body = ErrorBody {
                error: ErrorDetail {
                    code: "rate_limited".to_string(),
                    message: "Too many requests, please try again later".to_string(),
                },
            };
            let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            if let Ok(val) = HeaderValue::from_str(&retry_after.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, val);
            }
            return response;
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
            AppError::InternalError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                msg,
            ),
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Access denied".to_string(),
            ),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
        };

        let body = ErrorBody {
            error: ErrorDetail {
                code: code.to_string(),
                message,
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
            AppError::RateLimited { retry_after } => write!(f, "Rate limited (retry after {}s)", retry_after),
            AppError::InternalError(msg) => write!(f, "Internal error: {}", msg),
            AppError::Forbidden => write!(f, "Forbidden"),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
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
}
