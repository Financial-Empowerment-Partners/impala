//! Opt-in DB lane: integration tests that prove the money-path constraints
//! and rollbacks against a real Postgres.
//!
//! The default `cargo test` runs with no database, so every SQL fact in the
//! bridge is pinned by string. These tests are the executable half of
//! `docs/conservation-spec.md` §6.1: they apply `migrations/` into a fresh
//! schema per test and run the SAME statements the binary runs (extracted
//! from the source text by name, see `harness::sql_const`) so a constraint
//! that stops firing, or a CAS that stops rolling back, fails here.
//!
//! Every test is `#[ignore]` and connects only when `RUN_DB_TESTS=1`:
//!
//! ```text
//! RUN_DB_TESTS=1 DATABASE_URL=postgres://postgres:pw@localhost:5432/impala \
//!     cargo test --test db -- --ignored
//! ```
//!
//! Without `RUN_DB_TESTS=1` an ignored run passes vacuously (each test
//! prints a notice on stderr and returns), so `cargo test -- --ignored`
//! stays safe on a developer machine with no database.

mod custodial_intent;
mod harness;
mod reserve;
