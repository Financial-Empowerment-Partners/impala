//! Classic Stellar transaction signing + submission for custodial accounts.
//!
//! The [`StellarSigner`] trait is the stable seam the handlers depend on; the
//! concrete implementation uses `stellar-base` for keypair/strkey/build/sign and
//! the shared `reqwest` client for Horizon sequence lookup and submission.

pub mod account;
mod signer;

pub use account::{fetch_account_details, OnchainAccount};
pub use signer::{build_signer, Asset, PaymentParams, StellarSigner};
