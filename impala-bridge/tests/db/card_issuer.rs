//! Card registration without an RSA key (038) and the card issuer custody
//! statements (039): the anchors and guards the handlers rely on.

use uuid::Uuid;

use crate::harness::{self, sql_const, unique_violation};

const CARD_SRC: &str = include_str!("../../src/handlers/card.rs");
const ISSUER_SRC: &str = include_str!("../../src/offline/issuer.rs");
const PUBLIC_SRC: &str = include_str!("../../src/handlers/card_issuer.rs");

async fn insert_card(
    pool: &sqlx::PgPool,
    account: &str,
    card_id: &str,
    pubkey: &str,
    rsa: Option<&str>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(&sql_const(CARD_SRC, "CARD_INSERT_SQL"))
        .bind(account)
        .bind(card_id)
        .bind(pubkey)
        .bind(rsa)
        .execute(pool)
        .await
        .map(|r| r.rows_affected())
}

fn point(tag: u8) -> String {
    format!("04{}", format!("{:02x}", tag).repeat(64))
}

async fn insert_issuer(pool: &sqlx::PgPool, version: i32, tag: u8) -> Result<u64, sqlx::Error> {
    sqlx::query(&sql_const(ISSUER_SRC, "ISSUER_INSERT_SQL"))
        .bind(version)
        .bind("vault")
        .bind(vec![tag])
        .bind(Option::<Vec<u8>>::None)
        .bind(Option::<Vec<u8>>::None)
        .bind("impala-seeds")
        .bind(Some("1"))
        .bind(point(tag))
        .bind(format!("fp{tag}"))
        .bind("admin")
        .execute(pool)
        .await
        .map(|r| r.rows_affected())
}

#[tokio::test]
#[ignore]
async fn cards_without_rsa_keys_register_and_present_keys_stay_unique() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let account = Uuid::new_v4().to_string();
    harness::seed_account(&db.pool, &account).await;
    assert_eq!(
        insert_card(
            &db.pool,
            &account,
            "00112233445566778899aabbccddeeff",
            &point(1),
            None
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        insert_card(
            &db.pool,
            &account,
            "00112233445566778899aabbccddee00",
            &point(2),
            None
        )
        .await
        .unwrap(),
        1
    );
    let rsa = "A".repeat(200);
    insert_card(
        &db.pool,
        &account,
        "00112233445566778899aabbccddee01",
        &point(3),
        Some(&rsa),
    )
    .await
    .unwrap();
    let e = insert_card(
        &db.pool,
        &account,
        "00112233445566778899aabbccddee02",
        &point(4),
        Some(&rsa),
    )
    .await
    .unwrap_err();
    assert_eq!(unique_violation(&e), "uq_card_rsa_pubkey");
    db.finish().await;
}

#[tokio::test]
#[ignore]
async fn issuer_key_rotation_keeps_one_active_key_and_the_program_identity() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let pool = &db.pool;
    let next: i32 = sqlx::query_scalar(&sql_const(ISSUER_SRC, "ISSUER_NEXT_VERSION_SQL"))
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(next, 1);
    insert_issuer(pool, 1, 0xaa).await.unwrap();
    let mint = sql_const(ISSUER_SRC, "POLICY_MINT_IDENTITY_SQL");
    let first: (Option<Vec<u8>>, Option<Uuid>) = sqlx::query_as(&mint)
        .bind(vec![7u8; 16])
        .bind("admin")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(first.0.as_deref(), Some(&[7u8; 16][..]));
    assert!(first.1.is_some());

    // A second active key is impossible without superseding the first.
    let e = insert_issuer(pool, 2, 0xbb).await.unwrap_err();
    assert_eq!(unique_violation(&e), "uq_card_issuer_key_single_active");
    sqlx::query(&sql_const(ISSUER_SRC, "ISSUER_SUPERSEDE_SQL"))
        .execute(pool)
        .await
        .unwrap();
    insert_issuer(pool, 2, 0xbb).await.unwrap();
    let again: (Option<Vec<u8>>, Option<Uuid>) = sqlx::query_as(&mint)
        .bind(vec![9u8; 16])
        .bind("admin")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(
        again, first,
        "rotation never changes program_id or redemption_uuid"
    );

    let load = sql_const(ISSUER_SRC, "ISSUER_LOAD_SQL");
    let (v, state): (i32, String) =
        sqlx::query_as(&format!("SELECT version, state FROM ({load}) t"))
            .bind(Option::<i32>::None)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((v, state.as_str()), (2, "active"));
    let (v, state): (i32, String) =
        sqlx::query_as(&format!("SELECT version, state FROM ({load}) t"))
            .bind(Some(1))
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((v, state.as_str()), (1, "superseded"));

    let public: (i32, String, String, Option<Uuid>, Option<Vec<u8>>) =
        sqlx::query_as(&sql_const(PUBLIC_SRC, "CARD_ISSUER_PUBLIC_SQL"))
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(public.0, 2);
    assert_eq!(public.4.as_deref(), Some(&[7u8; 16][..]));
    db.finish().await;
}

#[tokio::test]
#[ignore]
async fn certificates_are_write_once_unless_recertified_and_only_on_active_rows() {
    let Some(db) = harness::fresh().await else {
        return;
    };
    let pool = &db.pool;
    let account = Uuid::new_v4().to_string();
    harness::seed_account(pool, &account).await;
    let card = "aabbccddeeff00112233445566778899";
    insert_card(pool, &account, card, &point(5), None)
        .await
        .unwrap();
    insert_issuer(pool, 1, 0xcc).await.unwrap();
    let certify = sql_const(ISSUER_SRC, "CERTIFY_SQL");
    let run = |cert: &'static str, recertify: bool| {
        let certify = certify.clone();
        async move {
            sqlx::query(&certify)
                .bind(card)
                .bind(cert)
                .bind(1i32)
                .bind("XLM")
                .bind(7i16)
                .bind(recertify)
                .execute(pool)
                .await
                .map(|r| r.rows_affected())
        }
    };
    assert_eq!(run("3006020101020101", false).await.unwrap(), 1);
    assert_eq!(
        run("3006020101020102", false).await.unwrap(),
        0,
        "write-once"
    );
    assert_eq!(
        run("3006020101020103", true).await.unwrap(),
        1,
        "recertify replaces"
    );
    let stored: String = sqlx::query_scalar("SELECT issuer_cert_hex FROM card WHERE card_id = $1")
        .bind(card)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(stored, "3006020101020103");

    sqlx::query("UPDATE card SET is_delete = TRUE WHERE card_id = $1")
        .bind(card)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        run("3006020101020104", true).await.unwrap(),
        0,
        "deleted cards are never certified"
    );

    // An unknown issuer version or currency is refused by the foreign keys.
    let other = "aabbccddeeff00112233445566778800";
    insert_card(pool, &account, other, &point(6), None)
        .await
        .unwrap();
    let e = sqlx::query(&certify)
        .bind(other)
        .bind("3006020101020101")
        .bind(99i32)
        .bind("XLM")
        .bind(7i16)
        .bind(false)
        .execute(pool)
        .await
        .unwrap_err();
    assert!(
        matches!(&e, sqlx::Error::Database(d) if d.code().as_deref() == Some("23503")),
        "{e:?}"
    );
    db.finish().await;
}
