//! Reserve journal / replenishment / snapshot anchors (031, 032, 037 C+D).

use chrono::Utc;
use uuid::Uuid;

use crate::harness::{
    self, hash, sql_const, unique_violation, RECONCILIATION_SRC, REPLENISH_SRC, RESERVE_SRC,
};

async fn bucket(pool: &sqlx::PgPool, currency: &str) -> (i64, i64) {
    sqlx::query_as("SELECT available, held FROM conversion_reserve WHERE currency = $1")
        .bind(currency)
        .fetch_one(pool)
        .await
        .expect("bucket")
}

/// A `replenish_attempt`-shaped journal row for `cycle_id` through the
/// binary's 17-bind INSERT.
fn journal_row<'q>(
    sql: &'q str,
    currency: &'q str,
    kind: &'q str,
    balance_after: i64,
    held_after: i64,
    cycle_id: Uuid,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(sql)
        .bind(currency)
        .bind(kind)
        .bind(0i64)
        .bind(0i64)
        .bind(balance_after)
        .bind(held_after)
        .bind(Option::<Uuid>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<Uuid>::None)
        .bind(Some(cycle_id))
        .bind(Option::<Uuid>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
}

/// A cycle row. `uq_crr_inflight` admits ONE live cycle per kind, so a test
/// that needs two live cycles seeds one of each kind.
async fn seed_cycle(
    pool: &sqlx::PgPool,
    kind: &str,
    state: &str,
    tag: u8,
) -> Result<Uuid, sqlx::Error> {
    let (spend, recv, provider) = if kind == "xlm_to_usdc" {
        ("XLM", "USDC", "changelly_crypto")
    } else {
        ("USDC", "USD", "owlpay")
    };
    sqlx::query_scalar(
        "INSERT INTO conversion_reserve_replenishment \
         (kind, state, cycle_ref, trigger_source, need_minor, spend_currency, spend_minor, \
          recv_currency, quoted_recv_minor, provider, send_address) \
         VALUES ($1, $2, $3, 'admin', 100, $4, 100, $5, 10, $6, $7) \
         RETURNING cycle_id",
    )
    .bind(kind)
    .bind(state)
    .bind(format!("REF{:02X}", tag))
    .bind(spend)
    .bind(recv)
    .bind(provider)
    .bind(harness::g_addr(tag))
    .fetch_one(pool)
    .await
}

#[tokio::test]
#[ignore]
async fn journal_insert_conflict_rolls_back_bucket_apply() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    sqlx::query(
        "UPDATE conversion_reserve SET available = 1000, held = 500 WHERE currency = 'XLM'",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let cycle = seed_cycle(&db.pool, "xlm_to_usdc", "created", 1)
        .await
        .expect("seed cycle");
    let entry_sql = sql_const(RESERVE_SRC, "RESERVE_ENTRY_INSERT_SQL");
    // First attempt row commits normally.
    journal_row(&entry_sql, "XLM", "replenish_attempt", 1000, 500, cycle)
        .execute(&db.pool)
        .await
        .expect("first attempt row");

    // Second worker: bucket apply, then the SAME (cycle_id, kind) row — the
    // unique index turns the replay into a 23505 and the whole transaction,
    // bucket movement included, must roll back.
    let mut tx = db.pool.begin().await.unwrap();
    let applied: Option<(i64, i64, i64)> =
        sqlx::query_as(&sql_const(RESERVE_SRC, "RESERVE_BUCKET_APPLY_SQL"))
            .bind("XLM")
            .bind(-100i64)
            .bind(100i64)
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
    assert_eq!(applied, Some((900, 600, 0)));
    let err = journal_row(&entry_sql, "XLM", "replenish_attempt", 900, 600, cycle)
        .execute(&mut *tx)
        .await
        .expect_err("one entry of each kind per cycle, ever");
    assert_eq!(
        unique_violation(&err),
        "uq_conversion_reserve_entry_cycle_kind"
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        bucket(&db.pool, "XLM").await,
        (1000, 500),
        "the apply rolled back with the conflict"
    );

    // The apply itself is guarded: neither column may go negative.
    let refused: Option<(i64, i64, i64)> =
        sqlx::query_as(&sql_const(RESERVE_SRC, "RESERVE_BUCKET_APPLY_SQL"))
            .bind("XLM")
            .bind(0i64)
            .bind(-501i64)
            .fetch_optional(&db.pool)
            .await
            .unwrap();
    assert_eq!(refused, None);
    assert_eq!(bucket(&db.pool, "XLM").await, (1000, 500));
    db.finish().await;
}

#[tokio::test]
#[ignore]
async fn uq_crr_send_tx_hash_rejects_second_cycle() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let a = seed_cycle(&db.pool, "xlm_to_usdc", "sending", 1)
        .await
        .expect("seed a");
    // One live cycle per kind is a constraint, not a scan (032).
    let err = seed_cycle(&db.pool, "xlm_to_usdc", "sending", 9)
        .await
        .expect_err("uq_crr_inflight");
    assert_eq!(unique_violation(&err), "uq_crr_inflight");
    let b = seed_cycle(&db.pool, "usdc_to_usd", "sending", 2)
        .await
        .expect("seed b");
    let row_sql = sql_const(REPLENISH_SRC, "CYCLE_ROW_HASH_SQL");
    let armed = sqlx::query(&row_sql)
        .bind(a)
        .bind(hash(0xaa))
        .execute(&db.pool)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(armed, 1);
    // NULL-CAS: a hash that may already have been submitted is never
    // overwritten by a re-arm.
    let rearmed = sqlx::query(&row_sql)
        .bind(a)
        .bind(hash(0xbb))
        .execute(&db.pool)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(rearmed, 0);
    // 037 part D: two cycles can never share one signed envelope.
    let err = sqlx::query(&row_sql)
        .bind(b)
        .bind(hash(0xaa))
        .execute(&db.pool)
        .await
        .expect_err("uq_crr_send_tx_hash");
    assert_eq!(unique_violation(&err), "uq_crr_send_tx_hash");
    // And only a `sending` row may be armed at all (b is still hashless:
    // the refused insert above wrote nothing).
    sqlx::query(
        "UPDATE conversion_reserve_replenishment SET state = 'created' WHERE cycle_id = $1",
    )
    .bind(b)
    .execute(&db.pool)
    .await
    .unwrap();
    let wrong_state = sqlx::query(&row_sql)
        .bind(b)
        .bind(hash(0xcc))
        .execute(&db.pool)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(wrong_state, 0);
    let b_hash: Option<String> = sqlx::query_scalar(
        "SELECT send_tx_hash FROM conversion_reserve_replenishment WHERE cycle_id = $1",
    )
    .bind(b)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(b_hash, None);
    db.finish().await;
}

#[tokio::test]
#[ignore]
async fn reconciliation_snapshot_daily_anchor_admits_one_row_per_date() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let sql = sql_const(RECONCILIATION_SRC, "SNAPSHOT_INSERT_SQL");
    let today = Utc::now().date_naive();
    let insert = |kind: &'static str| {
        sqlx::query_scalar::<_, Uuid>(&sql)
            .bind(today)
            .bind(kind)
            .bind(1i32)
            .bind(Utc::now())
            .bind(Option::<chrono::DateTime<Utc>>::None)
            .bind(false)
            .bind(true)
            .bind(false)
            .bind(false)
            .bind(serde_json::json!({"schema_version": 1}))
            .bind(Option::<String>::None)
    };
    let first = insert("daily").fetch_optional(&db.pool).await.unwrap();
    assert!(first.is_some(), "the first daily row for a date wins");
    let second = insert("daily").fetch_optional(&db.pool).await.unwrap();
    assert!(
        second.is_none(),
        "a second instance's daily row is a no-op (ON CONFLICT DO NOTHING)"
    );
    let manual = insert("manual").fetch_optional(&db.pool).await.unwrap();
    assert!(
        manual.is_some(),
        "manual snapshots are not bounded per date"
    );
    let manual2 = insert("manual").fetch_optional(&db.pool).await.unwrap();
    assert!(manual2.is_some());
    let daily_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reconciliation_snapshot WHERE kind = 'daily' AND snapshot_date = $1",
    )
    .bind(today)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(daily_rows, 1);
    db.finish().await;
}
