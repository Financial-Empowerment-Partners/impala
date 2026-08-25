use axum::extract::{Extension, Query};
use axum::Json;
use log::{debug, error, info, warn};
use opentelemetry::KeyValue;
use sqlx::PgPool;
use std::sync::Arc;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{
    CreateNotifyRequest, NotifyListItem, NotifyResponse, NotifyVerificationResponse,
    NotifyVerificationTarget, PaginatedResponse, PaginationParams, SendNotifyVerificationRequest,
    UpdateNotifyRequest, VerifyNotifyRequest,
};
use crate::telemetry::AppMetrics;

/// Generic failure for a submitted code, used for every rejection reason.
///
/// A caller must not be able to tell "no code outstanding" from "wrong code"
/// from "the number changed underneath you" — the distinctions would confirm
/// whether a code is currently in flight for a row.
const INVALID_CODE_MESSAGE: &str = "Invalid or expired verification code";

/// Same message the update path returns for an id that does not exist, so a
/// caller cannot distinguish "not yours" from "not there".
const NO_SUCH_ROW_MESSAGE: &str = "No notification record found with the provided id";

/// Matches the timestamp rendering used by the admin listings.
const TS_FMT: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

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

    let list_sql = format!(
        r#"
        -- NOTE: notify has no `active` column (see migrations/016's header);
        -- selecting one here used to 500 this endpoint against a real schema.
        SELECT id, account_id, medium::text, mobile, wa, signal, tel, email, url, app,
               to_char(mobile_verified_at AT TIME ZONE 'UTC', '{ts}') AS mobile_verified_at
        FROM notify
        WHERE account_id = $1
        ORDER BY id
        LIMIT $2 OFFSET $3
        "#,
        ts = TS_FMT
    );

    let rows = sqlx::query_as::<_, NotifyListItem>(&list_sql)
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
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<crate::sns::SnsTopicArn>>,
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
        return Ok(Json(NotifyResponse::plain(
            false,
            format!(
                "Invalid medium '{}'. Must be one of: webhook, sms, mobile_push, to_app, email",
                payload.medium
            ),
            None,
        )));
    }

    // Validate email format if provided
    if let Some(ref email) = payload.email {
        crate::validate::validate_email(email)?;
    }

    // Validate webhook URL if provided (SSRF prevention)
    if let Some(ref url) = payload.url {
        crate::validate::validate_callback_url(url)?;
    }

    // Validate the SMS destination before storing it. Previously unchecked:
    // an unparseable number was accepted and only failed later at Twilio, and
    // it is now also the address we send a verification code to.
    if let Some(ref mobile) = payload.mobile {
        crate::validate::validate_phone_number(mobile)?;
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

            // An SMS row starts unverified, so prompt the recipient straight
            // away: adding the number is the moment the confirmation belongs.
            if payload.medium == "sms" {
                if let Some(ref mobile) = payload.mobile {
                    let sent = try_issue_verification(
                        &redis_pool,
                        sns_client.as_ref().map(|e| &e.0),
                        sns_topic_arn.as_ref().map(|e| &e.0 .0),
                        &metrics,
                        id,
                        &payload.account_id,
                        mobile,
                    )
                    .await;
                    return Ok(Json(NotifyResponse {
                        success: true,
                        message: verification_pending_message(sent),
                        id: Some(id),
                        verification_required: Some(true),
                        verification_sent: Some(sent),
                    }));
                }
            }

            Ok(Json(NotifyResponse::plain(
                true,
                "Notification record created successfully",
                Some(id),
            )))
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
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<crate::sns::SnsTopicArn>>,
    Json(payload): Json<UpdateNotifyRequest>,
) -> Result<Json<NotifyResponse>, AppError> {
    info!("PUT /notify: updating id={}", payload.id);

    if let Some(ref medium) = payload.medium {
        let valid_mediums = ["webhook", "sms", "mobile_push", "to_app", "email"];
        if !valid_mediums.contains(&medium.as_str()) {
            warn!("update_notify: invalid medium '{}'", medium);
            return Ok(Json(NotifyResponse::plain(
                false,
                format!(
                    "Invalid medium '{}'. Must be one of: webhook, sms, mobile_push, to_app, email",
                    medium
                ),
                None,
            )));
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

    // See create_notify: the number is both stored and messaged, so it has to
    // parse before either happens.
    if let Some(ref mobile) = payload.mobile {
        crate::validate::validate_phone_number(mobile)?;
    }

    let Some(mut qb) = build_notify_update(&payload, &user.account_id) else {
        warn!(
            "update_notify: no fields provided to update for id={}",
            payload.id
        );
        return Ok(Json(NotifyResponse::plain(
            false,
            "No fields provided to update",
            None,
        )));
    };

    let result = qb.build().execute(&pool).await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                debug!("update_notify: no record found for id={}", payload.id);
                return Ok(Json(NotifyResponse::plain(
                    false,
                    NO_SUCH_ROW_MESSAGE,
                    None,
                )));
            }
            info!("update_notify: updated id={}", payload.id);

            // Re-read rather than infer. A changed number has had its
            // confirmation cleared by the database trigger, and the medium may
            // have just moved to or from `sms`; the stored row is the only
            // thing that knows the resulting state.
            let row = load_verification_target(&pool, payload.id, &user.account_id).await?;

            if let Some(row) = row {
                if row.medium == "sms" && !row.mobile_verified {
                    if let Some(ref mobile) = row.mobile {
                        let sent = try_issue_verification(
                            &redis_pool,
                            sns_client.as_ref().map(|e| &e.0),
                            sns_topic_arn.as_ref().map(|e| &e.0 .0),
                            &metrics,
                            payload.id,
                            &row.account_id,
                            mobile,
                        )
                        .await;
                        return Ok(Json(NotifyResponse {
                            success: true,
                            message: verification_pending_message(sent),
                            id: Some(payload.id),
                            verification_required: Some(true),
                            verification_sent: Some(sent),
                        }));
                    }
                }
            }

            Ok(Json(NotifyResponse::plain(
                true,
                "Notification record updated successfully",
                Some(payload.id),
            )))
        }
        Err(e) => {
            error!("update_notify: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Compare a submitted code against the issued one in constant time.
///
/// Length is compared first and separately — `ct_eq` requires equal-length
/// inputs — which leaks only the length of a fixed-width numeric code, not its
/// contents.
fn codes_match(expected: &str, submitted: &str) -> bool {
    use subtle::ConstantTimeEq;
    expected.len() == submitted.len() && expected.as_bytes().ct_eq(submitted.as_bytes()).into()
}

fn verification_pending_message(sent: bool) -> String {
    if sent {
        "Notification record saved. A verification code has been sent to the number; \
         SMS notifications start once it is confirmed."
            .to_string()
    } else {
        "Notification record saved, but the verification code could not be sent. \
         SMS notifications will not be delivered until the number is confirmed — \
         retry with POST /notify/verify/send."
            .to_string()
    }
}

/// Load the verification-relevant fields of a row, pinned to its owner.
///
/// INVARIANT (mirrors `build_notify_update`): `account_id` is always part of
/// the predicate, so one account can never read or act on another's row, and a
/// foreign id is indistinguishable from a missing one.
async fn load_verification_target(
    pool: &PgPool,
    notify_id: i32,
    account_id: &str,
) -> Result<Option<NotifyVerificationTarget>, AppError> {
    sqlx::query_as::<_, NotifyVerificationTarget>(
        "SELECT account_id, medium::text, mobile,
                (mobile_verified_at IS NOT NULL) AS mobile_verified
         FROM notify WHERE id = $1 AND account_id = $2",
    )
    .bind(notify_id)
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("load_verification_target: database error: {}", e);
        AppError::InternalError("Database error".to_string())
    })
}

/// Mint a code, store it, and send it. Returns whether an SMS went out.
///
/// Stores before sending: a code that reached the recipient but was never
/// stored can never be confirmed, which strands them. The reverse (stored but
/// not sent) is recoverable with a resend.
async fn issue_verification(
    redis_pool: &Arc<deadpool_redis::Pool>,
    sns_client: Option<&Arc<aws_sdk_sns::Client>>,
    sns_topic_arn: Option<&Arc<String>>,
    metrics: &Arc<AppMetrics>,
    notify_id: i32,
    account_id: &str,
    mobile: &str,
) -> Result<bool, AppError> {
    let code = crate::notifications::generate_verification_code()?;

    crate::redis_helpers::store_notify_verification(
        redis_pool,
        notify_id,
        &code,
        mobile,
        crate::constants::NOTIFY_VERIFY_CODE_TTL_SECS,
    )
    .await?;

    let sent = crate::notifications::send_verification_sms(
        sns_client,
        sns_topic_arn,
        account_id,
        mobile,
        &code,
    )
    .await;

    // The number is never logged or labelled — it is the subscriber's PII and
    // metric labels are unbounded cardinality besides.
    info!(
        "issue_verification: code issued for notify_id={} account_id={} sent={}",
        notify_id, account_id, sent
    );
    metrics.notification_verifications_sent.add(
        1,
        &[KeyValue::new(
            "outcome",
            if sent { "sent" } else { "not_sent" },
        )],
    );

    Ok(sent)
}

/// `issue_verification` for the write paths, where the row already exists.
///
/// A failure here must not fail the write: the row is committed, and a 500
/// would push the client to retry the whole create — which, with no uniqueness
/// on (account, medium), silently accumulates duplicate rows. The row is inert
/// while unverified, so degrading to "saved, nothing sent" is safe, and the
/// response says so rather than implying a code is on its way.
async fn try_issue_verification(
    redis_pool: &Arc<deadpool_redis::Pool>,
    sns_client: Option<&Arc<aws_sdk_sns::Client>>,
    sns_topic_arn: Option<&Arc<String>>,
    metrics: &Arc<AppMetrics>,
    notify_id: i32,
    account_id: &str,
    mobile: &str,
) -> bool {
    match issue_verification(
        redis_pool,
        sns_client,
        sns_topic_arn,
        metrics,
        notify_id,
        account_id,
        mobile,
    )
    .await
    {
        Ok(sent) => sent,
        Err(e) => {
            error!(
                "try_issue_verification: could not issue a code for notify_id={}: {}",
                notify_id, e
            );
            false
        }
    }
}

/// `POST /notify/verify/send` — (re)send a verification code.
///
/// The retry path when the first message did not arrive, and the only path
/// when SMS delivery was unconfigured at the time the row was written.
pub async fn send_notify_verification(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<crate::sns::SnsTopicArn>>,
    Json(payload): Json<SendNotifyVerificationRequest>,
) -> Result<Json<NotifyVerificationResponse>, AppError> {
    info!(
        "POST /notify/verify/send: notify_id={} account_id={}",
        payload.notify_id, user.account_id
    );

    // Ownership is established BEFORE any rate limit is charged. `notify.id`
    // is a SERIAL, so an attacker can walk it; charging the per-row budget
    // first would let anyone authenticated exhaust a stranger's resend
    // allowance and strand them mid-enrollment.
    let Some(row) = load_verification_target(&pool, payload.notify_id, &user.account_id).await?
    else {
        return Err(AppError::NotFound(NO_SUCH_ROW_MESSAGE.to_string()));
    };

    if row.medium != "sms" {
        return Err(AppError::BadRequest(
            "Verification applies only to notification records with medium 'sms'".to_string(),
        ));
    }

    let Some(mobile) = row.mobile.as_deref() else {
        return Err(AppError::BadRequest(
            "This notification record has no mobile number to verify".to_string(),
        ));
    };

    // Already confirmed: answer without spending an SMS, and without spending
    // budget. Idempotent, so a client retrying a lost response neither bills
    // another message nor eats into its own allowance.
    if row.mobile_verified {
        return Ok(Json(NotifyVerificationResponse {
            success: true,
            message: "This number is already verified".to_string(),
            verified: true,
        }));
    }

    // Two budgets. The per-row one stops a single number being pumped; the
    // per-account one stops the same trick spread across many rows, which the
    // per-row limit alone would allow.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        crate::constants::NOTIFY_VERIFY_SEND_SCOPE,
        &payload.notify_id.to_string(),
        crate::constants::NOTIFY_VERIFY_SEND_MAX,
        crate::constants::NOTIFY_VERIFY_SEND_WINDOW_SECS,
    )
    .await?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        crate::constants::NOTIFY_VERIFY_SEND_SCOPE,
        &format!("acct:{}", user.account_id),
        crate::constants::NOTIFY_VERIFY_SEND_ACCOUNT_MAX,
        crate::constants::NOTIFY_VERIFY_SEND_WINDOW_SECS,
    )
    .await?;

    let sent = issue_verification(
        &redis_pool,
        sns_client.as_ref().map(|e| &e.0),
        sns_topic_arn.as_ref().map(|e| &e.0 .0),
        &metrics,
        payload.notify_id,
        &row.account_id,
        mobile,
    )
    .await?;

    if !sent {
        // The stored code is genuinely unusable by the recipient, so this is a
        // failure from their point of view even though the row is intact.
        return Err(AppError::InternalError(
            "Verification code could not be sent".to_string(),
        ));
    }

    Ok(Json(NotifyVerificationResponse {
        success: true,
        message: "Verification code sent".to_string(),
        verified: false,
    }))
}

/// `POST /notify/verify` — confirm the code the recipient received.
pub async fn verify_notify(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Json(payload): Json<VerifyNotifyRequest>,
) -> Result<Json<NotifyVerificationResponse>, AppError> {
    info!(
        "POST /notify/verify: notify_id={} account_id={}",
        payload.notify_id, user.account_id
    );

    // Ownership first, for the same reason as the send path: the per-row
    // submit budget must only be spendable by the row's owner.
    let Some(row) = load_verification_target(&pool, payload.notify_id, &user.account_id).await?
    else {
        return Err(AppError::NotFound(NO_SUCH_ROW_MESSAGE.to_string()));
    };

    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        crate::constants::NOTIFY_VERIFY_SUBMIT_SCOPE,
        &payload.notify_id.to_string(),
        crate::constants::RATE_LIMIT_MAX_REQUESTS,
        crate::constants::RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    if row.mobile_verified {
        return Ok(Json(NotifyVerificationResponse {
            success: true,
            message: "This number is already verified".to_string(),
            verified: true,
        }));
    }

    let Some(current_mobile) = row.mobile.clone() else {
        return Err(AppError::BadRequest(
            "This notification record has no mobile number to verify".to_string(),
        ));
    };

    let failed = |metrics: &Arc<AppMetrics>, outcome: &'static str| {
        metrics
            .notification_verification_results
            .add(1, &[KeyValue::new("outcome", outcome)]);
        Ok(Json(NotifyVerificationResponse {
            success: false,
            message: INVALID_CODE_MESSAGE.to_string(),
            verified: false,
        }))
    };

    let Some(pending) =
        crate::redis_helpers::peek_notify_verification(&redis_pool, payload.notify_id).await?
    else {
        warn!(
            "verify_notify: no pending code for notify_id={}",
            payload.notify_id
        );
        return failed(&metrics, "no_pending_code");
    };

    // The code was minted for a specific number. If the row has moved on, the
    // code is meaningless — confirming it would attach the recipient's consent
    // to a number they never saw.
    if pending.mobile != current_mobile {
        warn!(
            "verify_notify: pending code targets a number the row no longer holds, \
             notify_id={} — discarding",
            payload.notify_id
        );
        crate::redis_helpers::clear_notify_verification(&redis_pool, payload.notify_id).await;
        return failed(&metrics, "number_changed");
    }

    if payload.code.is_empty() {
        return failed(&metrics, "empty_code");
    }

    if !codes_match(&pending.code, &payload.code) {
        let exhausted = crate::redis_helpers::increment_notify_verification_attempts(
            &redis_pool,
            payload.notify_id,
            crate::constants::NOTIFY_VERIFY_MAX_ATTEMPTS,
            crate::constants::NOTIFY_VERIFY_CODE_TTL_SECS,
        )
        .await;

        if exhausted {
            warn!(
                "verify_notify: attempt budget spent for notify_id={}; code discarded",
                payload.notify_id
            );
            crate::redis_helpers::clear_notify_verification(&redis_pool, payload.notify_id).await;
            return failed(&metrics, "attempts_exhausted");
        }

        warn!(
            "verify_notify: wrong code for notify_id={}",
            payload.notify_id
        );
        return failed(&metrics, "wrong_code");
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!("verify_notify: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    // `mobile = $3` is the race guard: if the number changed between the peek
    // above and this write, no row matches and nothing is marked verified.
    let updated = sqlx::query(
        "UPDATE notify SET mobile_verified_at = CURRENT_TIMESTAMP
         WHERE id = $1 AND account_id = $2 AND mobile = $3",
    )
    .bind(payload.notify_id)
    .bind(&user.account_id)
    .bind(&current_mobile)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("verify_notify: update error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    if updated.rows_affected() == 0 {
        warn!(
            "verify_notify: row changed under a correct code, notify_id={}",
            payload.notify_id
        );
        crate::redis_helpers::clear_notify_verification(&redis_pool, payload.notify_id).await;
        return failed(&metrics, "number_changed");
    }

    crate::events::emit_event(
        &mut tx,
        &crate::events::AccountEvent::NotifyMobileVerified {
            account_id: user.account_id.clone(),
            notify_id: payload.notify_id,
        },
    )
    .await?;

    tx.commit().await.map_err(|e| {
        error!("verify_notify: commit error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    // Only after the commit: a cleared code with an uncommitted row would
    // leave the recipient unable to retry.
    crate::redis_helpers::clear_notify_verification(&redis_pool, payload.notify_id).await;

    info!(
        "verify_notify: notify_id={} verified for account_id={}",
        payload.notify_id, user.account_id
    );
    metrics
        .notification_verification_results
        .add(1, &[KeyValue::new("outcome", "verified")]);

    Ok(Json(NotifyVerificationResponse {
        success: true,
        message: "Number verified. SMS notifications are now active for this record.".to_string(),
        verified: true,
    }))
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

    // ── SMS enrollment verification ────────────────────────────────────

    #[test]
    fn codes_match_accepts_the_issued_code() {
        assert!(codes_match("123456", "123456"));
    }

    #[test]
    fn codes_match_rejects_a_different_code_of_the_same_length() {
        assert!(!codes_match("123456", "123457"));
    }

    #[test]
    fn codes_match_rejects_a_prefix() {
        // Guards the length check: without it `ct_eq` would panic or, worse,
        // a naive comparison would accept a truncated submission.
        assert!(!codes_match("123456", "12345"));
        assert!(!codes_match("123456", ""));
    }

    #[test]
    fn codes_match_rejects_a_longer_submission() {
        assert!(!codes_match("123456", "1234567"));
    }

    #[test]
    fn pending_message_names_the_resend_endpoint_when_nothing_was_sent() {
        // A caller told "saved" with no code on its way needs to know that SMS
        // is inert and how to retry, or the row sits unverified forever.
        let msg = verification_pending_message(false);
        assert!(msg.contains("POST /notify/verify/send"), "{msg}");
        assert!(msg.contains("not be delivered"), "{msg}");
    }

    #[test]
    fn pending_message_says_a_code_is_coming_when_it_was_sent() {
        let msg = verification_pending_message(true);
        assert!(msg.contains("verification code has been sent"), "{msg}");
        assert!(!msg.contains("POST /notify/verify/send"), "{msg}");
    }

    #[test]
    fn plain_response_omits_the_verification_fields() {
        // Non-SMS writes and every rejection path must not imply a pending
        // verification that does not exist.
        let json = serde_json::to_value(NotifyResponse::plain(true, "ok", Some(3))).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["id"], 3);
        assert!(json.get("verification_required").is_none());
        assert!(json.get("verification_sent").is_none());
    }

    #[test]
    fn pending_response_reports_both_verification_fields() {
        let json = serde_json::to_value(NotifyResponse {
            success: true,
            message: "m".to_string(),
            id: Some(9),
            verification_required: Some(true),
            verification_sent: Some(false),
        })
        .unwrap();
        assert_eq!(json["verification_required"], true);
        assert_eq!(json["verification_sent"], false);
    }

    #[test]
    fn every_rejection_reason_returns_one_indistinguishable_message() {
        // The handler maps no_pending_code / number_changed / wrong_code /
        // attempts_exhausted to this single string on purpose: a caller able to
        // tell them apart learns whether a code is in flight for a row.
        assert_eq!(INVALID_CODE_MESSAGE, "Invalid or expired verification code");
    }
}
