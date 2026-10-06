//! Card issuer custody and the certified card transfer protocol (handoff lane
//! C1). [`signable`] holds the pure byte formats shared with the card
//! (`impala-card/docs/transfer-protocol.md`); [`issuer`] holds the
//! generate-only program key sealed by the seed protector.
//!
//! The offline issuance/redemption ledger (lane C2) builds on these and is not
//! part of this module yet.

pub mod issuer;
pub mod signable;
