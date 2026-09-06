//! Per-test schema + the SQL the binary actually runs.

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

/// A fresh schema with every migration applied. Dropped on `finish`; left in
/// place when a test fails, so the state can be inspected.
pub struct Db {
    pub pool: PgPool,
    admin: PgPool,
    schema: String,
}

/// `Some(db)` when `RUN_DB_TESTS=1`; `None` (after a notice) otherwise.
pub async fn fresh() -> Option<Db> {
    if std::env::var("RUN_DB_TESTS").ok().as_deref() != Some("1") {
        eprintln!("RUN_DB_TESTS is not 1; skipping the DB lane");
        return None;
    }
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required when RUN_DB_TESTS=1");
    let schema = format!("dbtest_{}", uuid::Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect DATABASE_URL");
    sqlx::query(&format!("CREATE SCHEMA \"{}\"", schema))
        .execute(&admin)
        .await
        .expect("create schema");
    let opts: PgConnectOptions = url.parse().expect("DATABASE_URL parses");
    let opts = opts.options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .expect("connect with search_path");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply into a fresh schema");
    Some(Db {
        pool,
        admin,
        schema,
    })
}

impl Db {
    /// Drop the schema. Call at the END of a passing test only.
    pub async fn finish(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .expect("drop schema");
    }
}

/// The value of `pub(crate) const NAME: &str = "..."` in a bridge source
/// file, with Rust's `\`-newline continuations collapsed exactly as the
/// compiler does. The tests run the binary's statements, not copies of them.
pub fn sql_const(src: &'static str, name: &str) -> String {
    let decl = format!("const {}: &str = \"", name);
    let start = src
        .find(&decl)
        .unwrap_or_else(|| panic!("{} not found in source", name))
        + decl.len();
    let rest = &src[start..];
    let end = rest.find("\";").expect("literal terminated");
    let raw = &rest[..end];
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('\n') => {
                    chars.next();
                    while matches!(chars.peek(), Some(' ') | Some('\t')) {
                        chars.next();
                    }
                }
                Some('"') => {
                    chars.next();
                    out.push('"');
                }
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                }
                other => panic!("unsupported escape in {}: {:?}", name, other),
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub const INTENT_SRC: &str = include_str!("../../src/custody/intent.rs");
pub const SWEEP_SRC: &str = include_str!("../../src/custody/sweep.rs");
pub const RESERVE_SRC: &str = include_str!("../../src/exchange/reserve.rs");
pub const REPLENISH_SRC: &str = include_str!("../../src/exchange/replenish.rs");
pub const RECONCILIATION_SRC: &str = include_str!("../../src/reconciliation/mod.rs");

/// The constraint a `23505` names, or the error's text when it is not a
/// unique violation.
pub fn unique_violation(e: &sqlx::Error) -> String {
    match e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => db
            .constraint()
            .map(str::to_string)
            .unwrap_or_else(|| "23505 without a constraint name".to_string()),
        other => panic!("expected a unique violation, got {:?}", other),
    }
}

/// A 56-char G address that passes the column width; nothing here checks a
/// checksum.
pub fn g_addr(tag: u8) -> String {
    let mut s = String::from("G");
    while s.len() < 56 {
        s.push((b'A' + (tag % 26)) as char);
    }
    s
}

/// 64 lowercase hex chars derived from `tag`.
pub fn hash(tag: u8) -> String {
    format!("{:02x}", tag).repeat(32)
}

/// An `impala_account` row (the settlement row's `account_id` FK).
pub async fn seed_account(pool: &PgPool, payala_account_id: &str) {
    sqlx::query(
        "INSERT INTO impala_account (stellar_account_id, payala_account_id, first_name, last_name) \
         VALUES ($1, $2, 'Test', 'Account') ON CONFLICT DO NOTHING",
    )
    .bind(g_addr(payala_account_id.len() as u8))
    .bind(payala_account_id)
    .execute(pool)
    .await
    .expect("seed account");
}
