//! `custodial_payment_intent` anchors and CAS rollbacks (037 part A).

use uuid::Uuid;

use crate::harness::{self, g_addr, hash, sql_const, unique_violation, INTENT_SRC, SWEEP_SRC};

/// Claim a `sign` intent with the binary's 13-bind INSERT.
async fn claim(
    pool: &sqlx::PgPool,
    account: &str,
    key: &str,
    fingerprint: &str,
    origin: &str,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(&sql_const(INTENT_SRC, "INTENT_INSERT_SQL"))
        .bind(account)
        .bind(g_addr(1))
        .bind(origin)
        .bind(key)
        .bind("client")
        .bind(fingerprint)
        .bind(g_addr(2))
        .bind("XLM")
        .bind(Option::<String>::None)
        .bind(1_000_000i64)
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<Uuid>::None)
        .fetch_one(pool)
        .await
}

async fn arm(pool: &sqlx::PgPool, intent_id: Uuid, h: &str) -> Result<u64, sqlx::Error> {
    sqlx::query(&sql_const(INTENT_SRC, "INTENT_ARM_SQL"))
        .bind(intent_id)
        .bind(h)
        .execute(pool)
        .await
        .map(|r| r.rows_affected())
}

async fn reject_prepared(pool: &sqlx::PgPool, intent_id: Uuid) {
    let n = sqlx::query(&sql_const(INTENT_SRC, "INTENT_REJECT_PREPARED_SQL"))
        .bind(intent_id)
        .bind("prepare_rejected")
        .bind("test")
        .execute(pool)
        .await
        .expect("reject")
        .rows_affected();
    assert_eq!(n, 1);
}

async fn status(pool: &sqlx::PgPool, intent_id: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT status, resolution FROM custodial_payment_intent WHERE intent_id = $1")
        .bind(intent_id)
        .fetch_one(pool)
        .await
        .expect("status")
}

#[tokio::test]
#[ignore]
async fn uq_custodial_intent_key_rejects_second_insert() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let first = claim(&db.pool, "acct-a", "key-1", &hash(0xaa), "sign")
        .await
        .expect("first claim");
    // Take the live-intent guard out of the picture: a terminal row still
    // owns its key.
    reject_prepared(&db.pool, first).await;
    let err = claim(&db.pool, "acct-a", "key-1", &hash(0xbb), "sign")
        .await
        .expect_err("same (account, key) must be refused");
    assert_eq!(unique_violation(&err), "uq_custodial_intent_key");
    // A different account may reuse the key string.
    harness::seed_account(&db.pool, "acct-b").await;
    claim(&db.pool, "acct-b", "key-1", &hash(0xbb), "sign")
        .await
        .expect("other account, same key");
    db.finish().await;
}

#[tokio::test]
#[ignore]
async fn uq_custodial_intent_hash_rejects_second_arm() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let a = claim(&db.pool, "acct-a", "k", &hash(1), "sign")
        .await
        .unwrap();
    let b = claim(&db.pool, "acct-b", "k", &hash(2), "sign")
        .await
        .unwrap();
    assert_eq!(arm(&db.pool, a, &hash(0xcc)).await.unwrap(), 1);
    let err = arm(&db.pool, b, &hash(0xcc))
        .await
        .expect_err("one signed envelope can never belong to two intents");
    assert_eq!(unique_violation(&err), "uq_custodial_intent_hash");
    // The arm is a NULL-CAS: re-arming an armed row changes nothing.
    assert_eq!(arm(&db.pool, a, &hash(0xdd)).await.unwrap(), 0);
    let (s, _) = status(&db.pool, a).await;
    assert_eq!(s, "submitted");
    db.finish().await;
}

#[tokio::test]
#[ignore]
async fn one_inflight_index_admits_one_live_sign_intent() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let first = claim(&db.pool, "acct-a", "k1", &hash(1), "sign")
        .await
        .unwrap();
    let err = claim(&db.pool, "acct-a", "k2", &hash(2), "sign")
        .await
        .expect_err("a second live sign intent for the account is refused");
    assert_eq!(unique_violation(&err), "uq_custodial_intent_one_inflight");
    // The guard is on `sign` rows only: a redemption payout for the same
    // beneficiary is serialized by the watcher lock instead.
    claim(&db.pool, "acct-a", "k-red", &hash(3), "redemption")
        .await
        .expect("redemption origin is not blocked by a live sign intent");
    // Once the first is terminal the slot is free again.
    reject_prepared(&db.pool, first).await;
    claim(&db.pool, "acct-a", "k2", &hash(2), "sign")
        .await
        .expect("slot freed by the terminal row");
    db.finish().await;
}

#[tokio::test]
#[ignore]
async fn arm_cas_loses_to_abandon_sweep() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let intent = claim(&db.pool, "acct-a", "k", &hash(1), "sign")
        .await
        .unwrap();
    sqlx::query(
        "UPDATE custodial_payment_intent SET created_at = CURRENT_TIMESTAMP - interval '1 hour' \
         WHERE intent_id = $1",
    )
    .bind(intent)
    .execute(&db.pool)
    .await
    .unwrap();
    let abandoned = sqlx::query(&sql_const(SWEEP_SRC, "ABANDON_SQL"))
        .bind(120f64)
        .execute(&db.pool)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(abandoned, 1);
    // A late arm (the submit task waking up after the sweep) affects no row,
    // so the caller refuses to submit: the row was never armed, no envelope
    // can exist on-chain.
    assert_eq!(arm(&db.pool, intent, &hash(0xcc)).await.unwrap(), 0);
    let (s, r) = status(&db.pool, intent).await;
    assert_eq!(
        (s.as_str(), r.as_deref()),
        ("rejected", Some("sweep_abandoned"))
    );
    db.finish().await;
}

#[tokio::test]
#[ignore]
async fn abandon_sweep_rejects_only_hashless_rows() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let armed = claim(&db.pool, "acct-a", "k", &hash(1), "sign")
        .await
        .unwrap();
    assert_eq!(arm(&db.pool, armed, &hash(0xaa)).await.unwrap(), 1);
    let unarmed = claim(&db.pool, "acct-b", "k", &hash(2), "sign")
        .await
        .unwrap();
    sqlx::query(
        "UPDATE custodial_payment_intent \
         SET created_at = CURRENT_TIMESTAMP - interval '1 hour', \
             armed_at = CASE WHEN armed_at IS NULL THEN NULL \
                             ELSE CURRENT_TIMESTAMP - interval '1 hour' END",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let abandoned = sqlx::query(&sql_const(SWEEP_SRC, "ABANDON_SQL"))
        .bind(120f64)
        .execute(&db.pool)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(abandoned, 1, "only the hashless row is abandoned");
    assert_eq!(status(&db.pool, armed).await.0, "submitted");
    assert_eq!(status(&db.pool, unarmed).await.0, "rejected");
    db.finish().await;
}

#[tokio::test]
#[ignore]
async fn settle_tx_is_atomic_when_intent_cas_fails() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    harness::seed_account(&db.pool, "acct-a").await;
    let intent = claim(&db.pool, "acct-a", "k", &hash(1), "sign")
        .await
        .unwrap();
    // Not armed: the settle CAS must find no row, and record_settlement's
    // contract is to roll the ledger row back with it.
    let h = hash(0xee);
    let mut tx = db.pool.begin().await.unwrap();
    let btxid: Uuid = sqlx::query_scalar(&sql_const(INTENT_SRC, "SETTLEMENT_TX_INSERT_SQL"))
        .bind(&h)
        .bind(&h)
        .bind(g_addr(1))
        .bind(Option::<String>::None)
        .bind("acct-a")
        .bind("custodial_sign")
        .bind(1_000_000i64)
        .bind(g_addr(2))
        .bind("XLM")
        .bind(Option::<String>::None)
        .fetch_one(&mut *tx)
        .await
        .expect("ledger row inserts inside the transaction");
    let settled = sqlx::query(&sql_const(INTENT_SRC, "INTENT_SETTLE_SQL"))
        .bind(intent)
        .bind(btxid)
        .bind("submit_ok")
        .bind(&h)
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(settled, 0, "an unarmed row cannot settle");
    tx.rollback().await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM transaction WHERE stellar_hash = $1")
        .bind(&h)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        rows, 0,
        "the duplicate ledger row is discarded with the rollback"
    );
    assert_eq!(status(&db.pool, intent).await.0, "prepared");

    // And the happy path: armed with THIS hash, the same two statements
    // commit together and the CHECK `chk_cpi_settled_has_row` holds.
    assert_eq!(arm(&db.pool, intent, &h).await.unwrap(), 1);
    let mut tx = db.pool.begin().await.unwrap();
    let btxid: Uuid = sqlx::query_scalar(&sql_const(INTENT_SRC, "SETTLEMENT_TX_INSERT_SQL"))
        .bind(&h)
        .bind(&h)
        .bind(g_addr(1))
        .bind(Option::<String>::None)
        .bind("acct-a")
        .bind("custodial_sign")
        .bind(1_000_000i64)
        .bind(g_addr(2))
        .bind("XLM")
        .bind(Option::<String>::None)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let settled = sqlx::query(&sql_const(INTENT_SRC, "INTENT_SETTLE_SQL"))
        .bind(intent)
        .bind(btxid)
        .bind("submit_ok")
        .bind(&h)
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(settled, 1);
    tx.commit().await.unwrap();
    let (s, r) = status(&db.pool, intent).await;
    assert_eq!((s.as_str(), r.as_deref()), ("settled", Some("submit_ok")));
    // A second resolver (sweep replaying the same Horizon page) finds no row.
    let again = sqlx::query(&sql_const(INTENT_SRC, "INTENT_SETTLE_SQL"))
        .bind(intent)
        .bind(btxid)
        .bind("sweep_settled")
        .bind(&h)
        .execute(&db.pool)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(again, 0);
    db.finish().await;
}
