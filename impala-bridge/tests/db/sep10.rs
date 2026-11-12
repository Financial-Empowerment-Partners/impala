//! SEP-10 with card keys (040): the card Stellar columns and their partial
//! unique index, the card lookup the POST handler runs, and the signing-key
//! lifecycle statements (generate, schedule, promote, revoke) against the
//! real constraints.

use uuid::Uuid;

use crate::harness::{self, sql_const, unique_violation};

const CARD_SRC: &str = include_str!("../../src/handlers/card.rs");
const KEY_SRC: &str = include_str!("../../src/sep10/key.rs");
const BACKEND_SRC: &str = include_str!("../../src/sep10/backend.rs");
const ADMIN_SRC: &str = include_str!("../../src/handlers/admin_sep10.rs");

fn point(tag: u8) -> String {
    format!("04{}", format!("{:02x}", tag).repeat(64))
}

async fn insert_stellar_card(
    pool: &sqlx::PgPool,
    account: &str,
    card_id: &str,
    pubkey: &str,
    address: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(&sql_const(CARD_SRC, "CARD_INSERT_STELLAR_SQL"))
        .bind(account)
        .bind(card_id)
        .bind(pubkey)
        .bind(Option::<&str>::None)
        .bind(address)
        .bind("30".repeat(35))
        .bind("ab".repeat(64))
        .execute(pool)
        .await
        .map(|r| r.rows_affected())
}

async fn card_account(pool: &sqlx::PgPool, address: &str) -> Option<String> {
    sqlx::query_scalar(&sql_const(BACKEND_SRC, "CARD_BY_STELLAR_ADDRESS_SQL"))
        .bind(address)
        .fetch_optional(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore]
async fn one_active_card_per_stellar_address_and_legacy_cards_unchanged() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let pool = &db.pool;
    let account = Uuid::new_v4().to_string();
    harness::seed_account(pool, &account).await;
    let addr = harness::g_addr(7);

    // Legacy registrations (no Stellar fields) still take the 4-bind statement
    // and any number of them may leave the address NULL.
    for (i, card) in [
        "a0a1a2a3a4a5a6a7a8a9aaabacadae00",
        "a0a1a2a3a4a5a6a7a8a9aaabacadae01",
    ]
    .iter()
    .enumerate()
    {
        sqlx::query(&sql_const(CARD_SRC, "CARD_INSERT_SQL"))
            .bind(&account)
            .bind(*card)
            .bind(point(i as u8 + 1))
            .bind(Option::<&str>::None)
            .execute(pool)
            .await
            .unwrap();
    }

    let first = "b0b1b2b3b4b5b6b7b8b9babbbcbdbe00";
    assert_eq!(
        insert_stellar_card(pool, &account, first, &point(10), &addr)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        card_account(pool, &addr).await.as_deref(),
        Some(account.as_str())
    );

    // A second ACTIVE card with the same address is refused by the index the
    // handler maps to 409 stellar_address_in_use.
    let e = insert_stellar_card(
        pool,
        &account,
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbe01",
        &point(11),
        &addr,
    )
    .await
    .unwrap_err();
    assert_eq!(unique_violation(&e), "uq_card_active_stellar_address");

    // Soft-deleting the first frees the address (and the lookup forgets it).
    sqlx::query("UPDATE card SET is_delete = TRUE WHERE card_id = $1")
        .bind(first)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(card_account(pool, &addr).await, None);
    insert_stellar_card(
        pool,
        &account,
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbe02",
        &point(12),
        &addr,
    )
    .await
    .unwrap();
    assert_eq!(
        card_account(pool, &addr).await.as_deref(),
        Some(account.as_str())
    );

    // The dashboard views: the count of active Stellar cards, and the
    // account's cards newest first with their (nullable) addresses.
    let count: i64 = sqlx::query_scalar(&sql_const(ADMIN_SRC, "REGISTERED_CARD_KEYS_SQL"))
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "the deleted Stellar card and the legacy cards do not count"
    );
    type CardRow = (
        String,
        bool,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    );
    let cards: Vec<CardRow> = sqlx::query_as(&sql_const(ADMIN_SRC, "ADMIN_ACCOUNT_CARDS_SQL"))
        .bind(&account)
        .fetch_all(pool)
        .await
        .unwrap();
    assert_eq!(cards.len(), 4);
    assert_eq!(
        cards[0].0, "b0b1b2b3b4b5b6b7b8b9babbbcbdbe02",
        "newest first"
    );
    assert_eq!(cards[0].4.as_deref().map(str::trim), Some(addr.as_str()));
    assert!(
        cards.iter().any(|c| c.1 && c.0 == first),
        "deleted cards are listed"
    );
    assert!(cards.iter().filter(|c| c.4.is_none()).count() == 2);
    let none: Vec<CardRow> = sqlx::query_as(&sql_const(ADMIN_SRC, "ADMIN_ACCOUNT_CARDS_SQL"))
        .bind("no-such-account")
        .fetch_all(pool)
        .await
        .unwrap();
    assert!(none.is_empty());

    // The column CHECK refuses anything that is not a G strkey shape.
    for bad in [
        addr.to_lowercase(),
        format!("M{}", &addr[1..]),
        addr[..55].to_string(),
        format!("{}1", &addr[..55]),
    ] {
        let e = insert_stellar_card(
            pool,
            &account,
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbe03",
            &point(13),
            &bad,
        )
        .await
        .unwrap_err();
        let sqlx::Error::Database(d) = &e else {
            panic!("{e:?}")
        };
        assert!(
            matches!(d.code().as_deref(), Some("23514") | Some("22001")),
            "{bad}: {e:?}"
        );
    }
    db.finish().await;
}

/// `PUT /card/stellar-key`: the lookup and the guarded attach statement
/// against the real table. A card registered without a Stellar key gets one
/// exactly once; an owner mismatch, a deleted card and a second attach all
/// touch nothing; an address active on another card hits the unique index.
#[tokio::test]
#[ignore]
async fn a_stellar_key_is_attached_once_to_the_owners_live_card() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let pool = &db.pool;
    let owner = Uuid::new_v4().to_string();
    let other = Uuid::new_v4().to_string();
    harness::seed_account(pool, &owner).await;
    harness::seed_account(pool, &other).await;
    let card = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
    sqlx::query(&sql_const(CARD_SRC, "CARD_INSERT_SQL"))
        .bind(&owner)
        .bind(card)
        .bind(point(0x51))
        .bind(Option::<&str>::None)
        .execute(pool)
        .await
        .unwrap();

    let lookup = |account: String| async move {
        sqlx::query_as::<_, (String, Option<String>)>(&sql_const(
            CARD_SRC,
            "CARD_STELLAR_LOOKUP_SQL",
        ))
        .bind(card)
        .bind(account)
        .fetch_optional(pool)
        .await
        .unwrap()
    };
    let attach = |account: String, address: String| async move {
        sqlx::query(&sql_const(CARD_SRC, "CARD_SET_STELLAR_SQL"))
            .bind(address)
            .bind("30".repeat(35))
            .bind("ab".repeat(64))
            .bind(card)
            .bind(account)
            .execute(pool)
            .await
            .map(|r| r.rows_affected())
    };

    // The owner sees the row, with its stored EC key and no address yet.
    let (ec, address) = lookup(owner.clone()).await.unwrap();
    assert_eq!(ec.trim(), point(0x51));
    assert!(address.is_none());
    // Nobody else does, and nobody else can attach.
    assert!(lookup(other.clone()).await.is_none());
    assert_eq!(attach(other.clone(), harness::g_addr(21)).await.unwrap(), 0);

    // The owner attaches once; the second attach (any address) changes nothing.
    assert_eq!(attach(owner.clone(), harness::g_addr(21)).await.unwrap(), 1);
    assert_eq!(attach(owner.clone(), harness::g_addr(22)).await.unwrap(), 0);
    let (_, address) = lookup(owner.clone()).await.unwrap();
    assert_eq!(
        address.as_deref().map(str::trim),
        Some(harness::g_addr(21).as_str())
    );
    assert_eq!(
        card_account(pool, &harness::g_addr(21)).await,
        Some(owner.clone())
    );

    // An address that is active on another card is refused by the index.
    let second = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
    sqlx::query(&sql_const(CARD_SRC, "CARD_INSERT_SQL"))
        .bind(&owner)
        .bind(second)
        .bind(point(0x52))
        .bind(Option::<&str>::None)
        .execute(pool)
        .await
        .unwrap();
    let clash = sqlx::query(&sql_const(CARD_SRC, "CARD_SET_STELLAR_SQL"))
        .bind(harness::g_addr(21))
        .bind("30".repeat(35))
        .bind("ab".repeat(64))
        .bind(second)
        .bind(&owner)
        .execute(pool)
        .await;
    assert_eq!(
        unique_violation(&clash.unwrap_err()),
        "uq_card_active_stellar_address"
    );

    // A deleted card is neither found nor updated.
    sqlx::query(
        "UPDATE card SET is_delete = TRUE, deleted_at = CURRENT_TIMESTAMP WHERE card_id = $1",
    )
    .bind(second)
    .execute(pool)
    .await
    .unwrap();
    let gone = sqlx::query(&sql_const(CARD_SRC, "CARD_SET_STELLAR_SQL"))
        .bind(harness::g_addr(23))
        .bind("30".repeat(35))
        .bind("ab".repeat(64))
        .bind(second)
        .bind(&owner)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(gone.rows_affected(), 0);
}

async fn insert_key(pool: &sqlx::PgPool, version: i32, tag: u8) -> Result<u64, sqlx::Error> {
    sqlx::query(&sql_const(KEY_SRC, "SSK_INSERT_SQL"))
        .bind(version)
        .bind("vault")
        .bind(vec![tag])
        .bind(Option::<Vec<u8>>::None)
        .bind(Option::<Vec<u8>>::None)
        .bind("impala-seeds")
        .bind(Some("1"))
        .bind(harness::g_addr(tag))
        .bind(format!("fp{tag}"))
        .bind("admin")
        .execute(pool)
        .await
        .map(|r| r.rows_affected())
}

async fn promote(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(&sql_const(KEY_SRC, "SSK_LOCK_LIVE_SQL"))
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    sqlx::query(&sql_const(KEY_SRC, "SSK_PROMOTE_SUPERSEDE_SQL"))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(&sql_const(KEY_SRC, "SSK_PROMOTE_ACTIVATE_SQL"))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// `SSK_RING_LIST_SQL`'s row shape.
type RingRow = (i32, String, String, String, Option<i64>, Option<i64>);

async fn states(pool: &sqlx::PgPool) -> Vec<(i32, String)> {
    sqlx::query_as("SELECT version, state FROM sep10_signing_key ORDER BY version")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn schedule(pool: &sqlx::PgPool, version: i32, delay: i64) -> Option<i64> {
    sqlx::query_scalar::<_, Option<i64>>(&sql_const(KEY_SRC, "SSK_SCHEDULE_ACTIVATION_SQL"))
        .bind(version)
        .bind(delay)
        .fetch_optional(pool)
        .await
        .unwrap()
        .flatten()
}

#[tokio::test]
#[ignore]
async fn signing_key_lifecycle_keeps_one_pending_and_one_active() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let pool = &db.pool;
    let next: i32 = sqlx::query_scalar(&sql_const(KEY_SRC, "SSK_NEXT_VERSION_SQL"))
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(next, 1);
    insert_key(pool, 1, 1).await.unwrap();
    // One pending at a time.
    let e = insert_key(pool, 2, 2).await.unwrap_err();
    assert_eq!(unique_violation(&e), "uq_sep10_signing_key_pending");

    // A future activation does not promote; a due one does, exactly once.
    assert!(schedule(pool, 1, 3600).await.is_some());
    assert!(schedule(pool, 1, 0).await.is_none(), "already scheduled");
    promote(pool).await;
    assert_eq!(states(pool).await, [(1, "pending".to_string())]);
    sqlx::query(
        "UPDATE sep10_signing_key SET activate_at = CURRENT_TIMESTAMP - INTERVAL '1 second'",
    )
    .execute(pool)
    .await
    .unwrap();
    promote(pool).await;
    promote(pool).await;
    assert_eq!(states(pool).await, [(1, "active".to_string())]);

    // Rotation: v2 pending, scheduled, promoted; v1 superseded AS OF v2's instant.
    insert_key(pool, 2, 2).await.unwrap();
    schedule(pool, 2, 0).await.unwrap();
    promote(pool).await;
    assert_eq!(
        states(pool).await,
        [(1, "superseded".to_string()), (2, "active".to_string())]
    );
    let same: bool = sqlx::query_scalar(
        "SELECT (SELECT superseded_at FROM sep10_signing_key WHERE version = 1) = \
         (SELECT activate_at FROM sep10_signing_key WHERE version = 2)",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(same);

    // The ring's list and material reads.
    let listed: Vec<RingRow> = sqlx::query_as(&sql_const(KEY_SRC, "SSK_RING_LIST_SQL"))
        .fetch_all(pool)
        .await
        .unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed[0].5.is_some() && listed[1].4.is_some());
    let _: i64 = sqlx::query_scalar(&sql_const(KEY_SRC, "SSK_DB_NOW_SQL"))
        .fetch_one(pool)
        .await
        .unwrap();

    // Housekeeping: a superseded version keeps its sealed material inside
    // the delay, then loses exactly what a revoke clears. The active row is
    // never touched, and the statement is idempotent.
    let scrub = sql_const(KEY_SRC, "SSK_SCRUB_SUPERSEDED_SQL");
    let n = sqlx::query(&scrub)
        .bind(3600_i64)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(n.rows_affected(), 0, "inside the delay");
    let n = sqlx::query(&scrub).bind(0_i64).execute(pool).await.unwrap();
    assert_eq!(n.rows_affected(), 1);
    let n = sqlx::query(&scrub).bind(0_i64).execute(pool).await.unwrap();
    assert_eq!(n.rows_affected(), 0, "idempotent");
    let kept: Vec<(i32, bool, bool)> = sqlx::query_as(
        "SELECT version, ciphertext IS NULL, scrubbed_at IS NOT NULL FROM sep10_signing_key \
         ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(kept, [(1, true, true), (2, false, false)]);

    // Revoke scrubs in the same statement and is guarded.
    let revoke = sql_const(KEY_SRC, "SSK_REVOKE_SQL");
    let n = sqlx::query(&revoke).bind(1).execute(pool).await.unwrap();
    assert_eq!(n.rows_affected(), 1);
    let n = sqlx::query(&revoke).bind(1).execute(pool).await.unwrap();
    assert_eq!(n.rows_affected(), 0);
    let scrubbed: (Option<Vec<u8>>, bool) = sqlx::query_as(
        "SELECT ciphertext, scrubbed_at IS NOT NULL FROM sep10_signing_key WHERE version = 1",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(scrubbed, (None, true));
    let material: Option<(String,)> = sqlx::query_as(&format!(
        "SELECT backend FROM ({}) t",
        sql_const(KEY_SRC, "SSK_MATERIAL_SQL")
    ))
    .bind(1)
    .fetch_optional(pool)
    .await
    .unwrap();
    assert!(material.is_none(), "a revoked version yields no material");

    // The constraints the custody model relies on.
    let e = sqlx::query(
        "INSERT INTO sep10_signing_key (version, state, backend, public_address, fingerprint, \
         generated_by) VALUES (9, 'pending', 'vault', $1, 'x', 'admin')",
    )
    .bind(harness::g_addr(9))
    .execute(pool)
    .await
    .unwrap_err();
    assert!(e.to_string().contains("chk_ssk_material"), "{e}");
    let e = sqlx::query("UPDATE sep10_signing_key SET state = 'revoked' WHERE version = 2")
        .execute(pool)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("chk_ssk_revoked"), "{e}");
    let e = insert_key(pool, 3, 2).await.unwrap_err();
    assert!(
        e.to_string().contains("public_address"),
        "public_address is unique: {e}"
    );
    db.finish().await;
}
