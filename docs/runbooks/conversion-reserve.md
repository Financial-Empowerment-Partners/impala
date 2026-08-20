# Runbook: Conversion Reserve

The conversion reserve is a bridge-owned pool that fulfills exchange orders
under a per-provider threshold ($20–$200) instead of routing them to
Changelly/OwlPay. This runbook covers enabling it, funding it, day-2
operations, and the two failure queues (frozen payouts, unmatched deposits).

Design summary: diverted orders are ordinary `exchange_order` rows with
`provider = 'reserve'`; the caller pays XLM/USDC into the reserve Stellar
account with an order-unique text memo; a background watcher matches
deposits, pays USDC out automatically (crypto swaps), or queues fiat
disbursements for an admin (OwlPay off-ramps). All pool accounting is the
`conversion_reserve*` tables (BIGINT minor units: USDC/XLM 7 dp, USD cents),
journaled in `conversion_reserve_entry`.

## Enabling

1. Create a dedicated custodial account and generate (never import) its seed:
   `POST /managed-account/generate` with a fresh `payala_account_id` (e.g.
   `svc-conversion-reserve`). Note the returned Stellar address.
2. Fund the address on-chain: enough XLM for fees + base reserves, a USDC
   trustline, and the USDC float you intend to serve. **Pool sizing:** the
   hold guard refuses new orders once holds reach half the pool, so the USDC
   bucket must hold at least 2× your largest threshold to serve anything.
3. Apply migration 031 (`RUN_MODE=migrate`).
4. Set env and restart:
   - `RESERVE_ACCOUNT_ID=<payala id>` — the bridge now refuses this account
     on all user-facing `/managed-account/*` endpoints and on account
     deletion (its seed signs pool payouts).
   - `RESERVE_USDC_ISSUER=<G...>` (+ `RESERVE_USDC_CODE` if not `USDC`).
   Startup fails closed if the account has no managed seed.
5. Record the initial funding in the ledger so it matches the chain:
   `POST /admin/exchange-reserve/entries` with `kind: topup` per currency
   (note the funding tx hash). Manual entries are correct HERE because the
   deposit scan starts at enablement and never reads history — funding done
   before this restart is invisible to the watcher. (Funding sent while the
   watcher is live auto-credits instead — see Day-2.) The admin UI (Reserve
   page) shows ledger-vs-on-chain side by side — they should agree now.
6. Enable routing: `PUT /admin/exchange-reserve/policies/changelly_crypto`
   (and/or `owlpay`) with `{"enabled": true, "threshold_usd_cents": ...}`
   (2000–20000). `changelly_fiat` cannot be enabled — its orders carry no
   payout coordinates the bridge could serve.

## What diverts

- `changelly_crypto` `crypto_to_crypto` xlm→usdcxlm float swaps whose payout
  address is a Stellar account **with a USDC trustline**, priced from the
  provider's own live estimate (scaled from a 100-XLM reference below the
  provider minimum) — automatic end-to-end.
- `owlpay` `crypto_to_fiat` Stellar-USDC→USD orders that include
  `beneficiary`/`payout_instrument` — pay-in is automatic, the fiat leg
  lands in the admin disbursement queue.
- Everything else — including fixed-rate swaps, non-Stellar USDC, missing
  trustlines, over-threshold amounts, an exhausted pool, or any internal
  error — passes through to the provider unchanged (`reserve.fallbacks`
  metric, by reason).

The deposit window (default 30 min, `RESERVE_DEPOSIT_TTL_SECS`) is also the
price-validity window. Do not raise it casually: the quoted `amount_to` is
honored for the whole window, so a long TTL hands out a free price option
against the pool.

## Day-2 operations

- **Reserve page (admin UI)**: buckets + on-chain drift, policies, forecast
  (EWMA depletion projection, suggested top-up), work queues, ledger,
  unmatched deposits.
- **Top-ups**: send funds on-chain to the reserve address (no memo, or a
  non-order memo). The watcher credits the inflow automatically (unmatched
  queue, reason `no_match`) — do **not** also record a manual `topup` for
  on-chain funding, that would book the same money twice. Manual `topup`
  entries are only for value the watcher cannot see: the USD fiat float,
  and corrections. Annotate the auto-credited row's decision in the
  unmatched queue instead.
- **Replenishment**: the reserve accumulates XLM (swap pay-ins) and spends
  USDC. Rebalance by converting accumulated XLM in bulk through the normal
  exchange flow and recording the resulting USDC as a `topup` (and the XLM
  out as a `withdrawal`). The forecast's suggested top-up tells you when.
- **Low-water alerts**: set per-bucket low-water marks; crossing one emits a
  `reserve.low_water` outbox event (admin webhooks) once per crossing order.

## Frozen payouts (on_hold queue)

An order freezes (`reserve.payout_pending` event, reason in `last_error`)
when a payout submit had an **ambiguous** outcome (timeout/5xx — the signed
tx stays valid ~300 s), when retries exhausted, when the destination
rejected (`op_no_trust`), or when a crash left an intent unresolved
(`stale_intent`). The funds stay held; nothing auto-retries.

Resolve from the Reserve page:
- **complete** — the payout actually landed. The bridge searches the reserve
  account's recent payments for the order's memo and records the found hash
  (or accepts one you paste), writes the `fulfillment` entry + `transaction`
  row, and completes the order.
- **fail** — the payout did not land. The bridge refuses this while the
  order changed state less than 600 s ago (each retry re-signs with a fresh
  ~300 s validity window, so only "frozen long enough" proves nothing can
  still land), when it finds a matching on-chain payment, or when Horizon
  is unreachable (fail closed). On success the hold returns to `available`
  and the order fails. **The user's deposit stays in reserve inventory** —
  refund it manually (ops sends the XLM back from the reserve account;
  record a `withdrawal` entry with the refund hash).

`resolve {action: fail}` also cancels a **disbursement order** stuck in the
fiat queue (unusable beneficiary data, disbursement impossible): the USD
hold releases, the order fails, and the deposited USDC stays in inventory
for the manual-refund flow above.

Never resolve-fail from memory or a block explorer screenshot alone; the
server-side check exists because an in-flight transaction is invisible until
it lands.

## Unmatched deposits

Every inflow the watcher cannot credit to an order is recorded durably
(`conversion_reserve_unmatched`, Reserve page queue) with a reason:
`late` (after expiry — the commonest; the order's hold was already
released), `underpaid`, `wrong_asset`, `no_match` (unknown/missing memo).
Known assets are already credited to bucket inventory so ledger == chain.
Disposition is a per-case ops decision: refund on-chain from the reserve
account (record a `withdrawal` with the hash) or absorb (leave the credit,
note the decision). For a `late` deposit where the user still wants the
conversion, refund and have them re-order.

## Drift repair

`available`/`held` must replay from the journal exactly. If an incident
leaves `held` wrong (e.g. an order was force-completed outside the flow),
repair with a `held_adjustment` entry; `adjustment` repairs `available`.
Both are audited (admin id + note required by convention). The status
endpoint's on-chain column is the ground truth to reconcile against.

## Disabling / deconfiguring

To stop diverting, disable the policies (`enabled: false`) — in-flight
orders keep being driven to completion/expiry by the watcher. To fully
deconfigure (`RESERVE_ACCOUNT_ID` unset), **drain first**: disable all
policies, wait one deposit TTL so `awaiting_deposit` orders expire, disburse
or resolve-fail the queues until the status endpoint shows zero pending.
Unsetting the account with orders in flight stops the watcher: nothing
expires, deposits go unseen on-chain, and holds stay locked. Recovery
without reconfiguring is limited: `resolve {action: complete}` still works
with an explicit `stellar_tx_hash`, but resolve-fail on payout-attempted
orders refuses (the chain cannot be checked) until the reserve is re-set.

## Multi-instance notes

The watcher takes a per-tick Postgres advisory lock, so replicas do not
duplicate work; correctness (no double payout, no double credit) is carried
by the write-ahead `payout_attempt` intent and `UNIQUE(order_id, kind)`
regardless of the lock. Ops signing manually from the reserve account can
race the watcher's sequence numbers — expect `tx_bad_seq` retries; prefer
pausing policies (disable, wait a tick) before manual on-chain operations.
