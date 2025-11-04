# Payala and Stellar Integration

The Impala project integrates Payala payments with the Stellar ecosystem.


## Impala-bridge

The impala bridge provides an interface between the Stellar network, smart contracts,
and the Payala payment system.

The implementation is in [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html) using the [Axum framework](https://github.com/tokio-rs/axum/).

---

## Impala-card

The impala card is a JavaCard application facilitating on-line transfer capabilities in Payala
and Stellar. Robust authentication is also supported for various uses.

Refer to [OpenSC](https://github.com/OpenSC/OpenSC) and [GlobalPlatform](https://github.com/kaoh/globalplatform) tool installation instructions.

---

## Impala-soroban

Impala soroban smart contracts are used for bulk payments and offline escrow. Multi-party
signatures are supported for mint authorizations into the Payala system.

### soroban-into-payala

### soroban-outof-payala

### soroban-anchor-dist

For typical bulk payments the [Stellar Disbursement Platform](https://github.com/stellar/stellar-disbursement-platform-backend) could be used. For simple
bulk payments via the impala bridge a [direct smart contract for disbursement is utilized](https://github.com/stellar/soroban-examples) with proper authorization.

---

## Impala-android

The Payala android application is modified to support online transfers to Stellar
recipients and supported Stellar anchor banking rails.

A public Android Library for integrating authentication and online transactions
via Payala and Stellar is also provided.

---
