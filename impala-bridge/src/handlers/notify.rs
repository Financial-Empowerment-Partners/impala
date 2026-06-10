use axum::extract::{Extension, Query};
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{
    CreateNotifyRequest, NotifyListItem, NotifyResponse, PaginatedResponse, PaginationParams,
    UpdateNotifyRequest,
};

/// List notification preferences for the authenticated user (`GET /notify`).
/// Supports pagination via `?page=1&per_page=20` query parameters.
pub async fn list_notify(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<NotifyListItem>>, AppError> {
    let (per_page, offset) = pagination.clamped();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notify WHERE account_id = $1")
        .bind(&user.account_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("list_notify: count query error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;

    let rows = sqlx::query_as::<_, NotifyListItem>(
        r#"
        -- NOTE: notify has no `active` column (see migrations/016's header);
        -- selecting one here used to 500 this endpoint against a real schema.
        SELECT id, account_id, medium::text, mobile, wa, signal, tel, email, url, app
        FROM notify
        WHERE account_id = $1
        ORDER BY id
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(&user.account_id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("list_notify: database error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    Ok(Json(PaginatedResponse {
        data: rows,
        page: pagination.page.max(1),
        per_page: per_page as u64,
        total: total as u64,
    }))
}

/// Create a notification preference record (`POST /notify`).
pub async fn create_notify(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateNotifyRequest>,
) -> Result<Json<NotifyResponse>, AppError> {
    crate::auth::require_owner(&user, &payload.account_id)?;
    info!(
        "POST /notify: medium={} for account_id={}",
        payload.medium, payload.account_id
    );

    let valid_mediums = ["webhook", "sms", "mobile_push", "to_app", "email"];
    if !valid_mediums.contains(&payload.medium.as_str()) {
        warn!("create_notify: invalid medium '{}'", payload.medium);
        return Ok(Json(NotifyResponse {
            success: false,
            message: format!(
                "Invalid medium '{}'. Must be one of: webhook, sms, mobile_push, to_app, email",
                payload.medium
            ),
            id: None,
        }));
    }

    // Validate email format if provided
    if let Some(ref email) = payload.email {
        crate::validate::validate_email(email)?;
    }

    // Validate webhook URL if provided (SSRF prevention)
    if let Some(ref url) = payload.url {
        crate::validate::validate_callback_url(url)?;
    }

    let result = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO notify (account_id, medium, mobile, wa, signal, tel, email, url, app)
        VALUES ($1, $2::notify_medium, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
    )
    .bind(&payload.account_id)
    .bind(&payload.medium)
    .bind(&payload.mobile)
    .bind(&payload.wa)
    .bind(&payload.signal)
    .bind(&payload.tel)
    .bind(&payload.email)
    .bind(&payload.url)
    .bind(&payload.app)
    .fetch_one(&pool)
    .await;

    match result {
        Ok(id) => {
            info!(
                "create_notify: created notify id={} for account_id={}",
                id, payload.account_id
            );
            Ok(Json(NotifyResponse {
                success: true,
                message: "Notification record created successfully".to_string(),
                id: Some(id),
            }))
        }
        Err(e) => {
            error!("create_notify: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Update an existing notification record by ID (`PUT /notify`).
pub async fn update_notify(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<UpdateNotifyRequest>,
) -> Result<Json<NotifyResponse>, AppError> {
    info!("PUT /notify: updating id={}", payload.id);

    if let Some(ref medium) = payload.medium {
        let valid_mediums = ["webhook", "sms", "mobile_push", "to_app", "email"];
        if !valid_mediums.contains(&medium.as_str()) {
            warn!("update_notify: invalid medium '{}'", medium);
            return Ok(Json(NotifyResponse {
                success: false,
                message: format!(
                    "Invalid medium '{}'. Must be one of: webhook, sms, mobile_push, to_app, email",
                    medium
                ),
                id: None,
            }));
        }
    }

    // Validate email format if provided
    if let Some(ref email) = payload.email {
        crate::validate::validate_email(email)?;
    }

    // Validate webhook URL if provided (SSRF prevention)
    if let Some(ref url) = payload.url {
        crate::validate::validate_callback_url(url)?;
    }

    let Some(mut qb) = build_notify_update(&payload, &user.account_id) else {
        warn!(
            "update_notify: no fields provided to update for id={}",
            payload.id
        );
        return Ok(Json(NotifyResponse {
            success: false,
            message: "No fields provided to update".to_string(),
            id: None,
        }));
    };

    let result = qb.build().execute(&pool).await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                debug!("update_notify: no record found for id={}", payload.id);
                Ok(Json(NotifyResponse {
                    success: false,
                    message: "No notification record found with the provided id".to_string(),
                    id: None,
                }))
            } else {
                info!("update_notify: updated id={}", payload.id);
                Ok(Json(NotifyResponse {
                    success: true,
                    message: "Notification record updated successfully".to_string(),
                    id: Some(payload.id),
                }))
            }
        }
        Err(e) => {
            error!("update_notify: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Build the UPDATE statement for `PUT /notify`. Returns `None` when no SET
/// fields are present.
///
/// INVARIANT (cross-account write protection): the WHERE clause always pins
/// `account_id` to the authenticated caller alongside the row id.
fn build_notify_update<'a>(
    payload: &'a UpdateNotifyRequest,
    user_account_id: &'a str,
) -> Option<sqlx::QueryBuilder<'a, sqlx::Postgres>> {
    let mut qb = sqlx::QueryBuilder::new("UPDATE notify SET ");
    let mut any_set = false;
    {
        let mut sets = qb.separated(", ");
        if let Some(ref v) = payload.medium {
            sets.push("medium = ");
            sets.push_bind_unseparated(v);
            sets.push_unseparated("::notify_medium");
            any_set = true;
        }
        if let Some(ref v) = payload.mobile {
            sets.push("mobile = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.wa {
            sets.push("wa = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.signal {
            sets.push("signal = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.tel {
            sets.push("tel = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.email {
            sets.push("email = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.url {
            sets.push("url = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.app {
            sets.push("app = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
    }
    if !any_set {
        return None;
    }

    qb.push(" WHERE id = ");
    qb.push_bind(payload.id);
    qb.push(" AND account_id = ");
    qb.push_bind(user_account_id);

    Some(qb)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_payload() -> UpdateNotifyRequest {
        UpdateNotifyRequest {
            id: 7,
            medium: None,
            mobile: None,
            wa: None,
            signal: None,
            tel: None,
            email: None,
            url: None,
            app: None,
        }
    }

    #[test]
    fn medium_gets_enum_cast_and_account_pin() {
        let payload = UpdateNotifyRequest {
            medium: Some("email".to_string()),
            url: Some("https://example.com/hook".to_string()),
            ..empty_payload()
        };
        let qb = build_notify_update(&payload, "alice").expect("builder");
        assert_eq!(
            qb.sql(),
            "UPDATE notify SET medium = $1::notify_medium, url = $2 \
             WHERE id = $3 AND account_id = $4"
        );
    }

    #[test]
    fn single_field_update() {
        let payload = UpdateNotifyRequest {
            email: Some("a@b.cd".to_string()),
            ..empty_payload()
        };
        let qb = build_notify_update(&payload, "alice").expect("builder");
        assert_eq!(
            qb.sql(),
            "UPDATE notify SET email = $1 WHERE id = $2 AND account_id = $3"
        );
    }

    #[test]
    fn all_fields_in_legacy_order() {
        let payload = UpdateNotifyRequest {
            id: 7,
            medium: Some("sms".to_string()),
            mobile: Some("+15550000000".to_string()),
            wa: Some("w".to_string()),
            signal: Some("s".to_string()),
            tel: Some("t".to_string()),
            email: Some("a@b.cd".to_string()),
            url: Some("https://example.com".to_string()),
            app: Some("app".to_string()),
        };
        let qb = build_notify_update(&payload, "alice").expect("builder");
        assert_eq!(
            qb.sql(),
            "UPDATE notify SET medium = $1::notify_medium, mobile = $2, wa = $3, signal = $4, \
             tel = $5, email = $6, url = $7, app = $8 WHERE id = $9 AND account_id = $10"
        );
    }

    #[test]
    fn no_fields_returns_none() {
        assert!(build_notify_update(&empty_payload(), "alice").is_none());
    }

    /// Ownership-WHERE invariant: every generated statement pins account_id.
    #[test]
    fn every_generated_where_clause_pins_the_account() {
        let field_setters: Vec<fn(&mut UpdateNotifyRequest)> = vec![
            |p| p.medium = Some("v".to_string()),
            |p| p.mobile = Some("v".to_string()),
            |p| p.wa = Some("v".to_string()),
            |p| p.signal = Some("v".to_string()),
            |p| p.tel = Some("v".to_string()),
            |p| p.email = Some("v".to_string()),
            |p| p.url = Some("v".to_string()),
            |p| p.app = Some("v".to_string()),
        ];
        for mask in 1u32..(1 << field_setters.len()) {
            let mut payload = empty_payload();
            for (i, setter) in field_setters.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    setter(&mut payload);
                }
            }
            let qb = build_notify_update(&payload, "alice").expect("non-empty mask");
            assert!(
                qb.sql().contains("AND account_id = "),
                "WHERE must pin the account: {}",
                qb.sql()
            );
        }
    }
}
