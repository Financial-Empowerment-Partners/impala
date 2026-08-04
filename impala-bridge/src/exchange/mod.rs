//! Exchange-provider integrations: fiat<->USDC on/off-ramp and crypto->USDC swaps.
//!
//! Three optional providers, each following the house optional-Extension pattern
//! (configured => `Some(Arc<Provider>)` layered in `run_server`, otherwise the
//! routes stay mounted and handlers answer 400 "not configured"):
//!
//! - [`owlpay`] — OwlPay Harbor API (OwlTing). Quote-first v2 transfers for
//!   fiat->USDC (on-ramp) and USDC->fiat (off-ramp), HMAC-signed webhooks.
//! - [`changelly`] — Changelly Exchange API v2 (crypto->crypto swaps, e.g.
//!   XLM->USDC-on-Stellar; no webhooks, status is polled) and the Changelly
//!   Fiat API (on/off-ramp aggregator with RSA-signed requests + callbacks).
//! - [`reconcile`] — in-process poll loop that advances non-terminal
//!   `exchange_order` rows by asking the owning provider for current status.

pub mod changelly;
pub mod owlpay;
pub mod reconcile;
