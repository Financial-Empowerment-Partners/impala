# Runbook: Conversion Reserve

The conversion reserve is a bridge-owned pool that fulfills exchange orders
under a per-provider threshold ($20–$200) instead of routing them to
Changelly/OwlPay. This runbook covers enabling it, funding it, day-2
operations, and its failure queues (frozen payouts, unmatched deposits,
frozen refunds, frozen replenishment cycles).

Since migration 032 the reserve also: issues **locked price quotes** that
reserve capacity, **refunds** deposits it cannot use, and **replenishes**
itself by selling accumulated float. Each ships behind its own flag,
defaulting off — applying 032 changes no behavior until an admin opts in.

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
- **Replenishment**: automated since 032 — see "Automated replenishment"
  below. With it disabled (the default), rebalance by hand: convert
  accumulated XLM through the normal exchange flow and record the resulting
  USDC as a `topup` and the XLM out as a `withdrawal`. The forecast's
  suggested top-up tells you when.
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
  and the order fails. The user's deposit is then **queued for refund**
  automatically (see "Automated refunds"); the response names the
  destination, or says why it could not be queued. With refunds disabled the
  deposit stays in reserve inventory and the queue row explains that.

`resolve {action: fail}` also cancels a **disbursement order** stuck in the
fiat queue (unusable beneficiary data, disbursement impossible): the USD
hold releases, the order fails, and the deposited USDC is queued for refund
on the same path.

Never resolve-fail from memory or a block explorer screenshot alone; the
server-side check exists because an in-flight transaction is invisible until
it lands.

## Unmatched deposits

Every inflow the watcher cannot credit to an order is recorded durably
(`conversion_reserve_unmatched`, Reserve page queue) with a reason:
`late` (after expiry — the commonest; the order's hold was already
released), `underpaid`, `wrong_asset`, `no_match` (unknown/missing memo).
Known assets are already credited to bucket inventory so ledger == chain.
`late` and `underpaid` rows are queued for automatic return when refunds are
enabled; `no_match` and `wrong_asset` stay a per-case ops decision, and each
row carries a `refund_skip_reason` explaining which applies. Use
`POST /admin/exchange-reserve/refunds` to return one manually rather than
sending from the reserve account by hand — see "Automated refunds" for why
that distinction now matters.

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

## Reserved price quotes

A client may ask for a locked price with `POST /exchange/quote`
(`reserve_lock: true`, plus the `payout_address` the payout will use). When
the reserve can serve it, the response gains a `reserve_quote` block with a
`quote_id`, the locked `amount_to`, and `expires_in_secs`. Creating an order
with `reserve_quote_id` honors exactly that price.

A lock **reserves capacity as well as price**, so an order against a live
quote cannot fail for lack of funds. That capacity is real exposure:

- The lock window (`RESERVE_QUOTE_TTL_SECS`, default 300s, clamped
  [60, 900]) plus the deposit window is the total time a client holds a free
  option on the pool. The bridge refuses to start if the two together exceed
  7200s — lower one of them rather than raising the cap.
- Open quotes and open orders share ONE per-account cap (3 combined), and
  quote holds count toward the same half-the-pool guard as order holds.
- Watch `held_quotes` on the status endpoint. If locks routinely consume the
  guard, ordinary orders start falling through to providers — visible as
  `reserve.fallbacks{reason="insufficient"}`.

Expired locks release their capacity on the next watcher tick. If the
watcher stops, capacity stays locked (the same exposure `awaiting_deposit`
orders already carry) but accounts are not locked out of quoting, because
the cap query ignores expired rows.

## Automated refunds

Money the reserve cannot use is returned to its payer instead of waiting for
someone to read this runbook. Two-step opt-in, both default off:

1. `PUT /admin/exchange-reserve/settings` `{"refunds_enabled": true}`.
2. Per bucket, set `refund_max_minor` and `refund_daily_max_minor` via
   `PUT /admin/exchange-reserve/buckets/{currency}`. **0 disables that
   currency** — there is deliberately no way to express "unlimited".

**What auto-refunds:** `late` deposits (arrived after expiry), `underpaid`
deposits, and deposits stranded when an admin resolve-fails an order. Each
identifies both an order and a payer.

**What stays manual, and why:** `no_match` (no memo) and `wrong_asset`. An
unmemoed inflow is exactly how ops tops the pool up — auto-refunding one
would wire the float straight back to ops. Also excluded: `create_account`
inflows (the starting balance IS the account's base reserve), path payments
(the payer parted with a different asset than arrived), muxed senders (the
visible address is a shared base account), destinations equal to the reserve
itself, and destinations equal to the asset issuer (sending an issued asset
to its issuer **burns** it). Each refusal is recorded as
`refund_skip_reason` on the queue row, so the manual queue explains itself.

**The residual risk you are accepting:** a refund to a self-custodial sender
is safe, but an exchange withdrawal arrives from an omnibus address where a
refund is generally lost, and there is no reliable programmatic test for the
difference. That is why refunds ship off by default, capped, delayed by a
cooldown, and cancellable. An order's declared `refund_address` is preferred
over the inferred sender precisely because it is a stated intent.

**Timing:** `late` and `order_failed` wait a short grace (an ops window to
cancel a wrong refund before value moves); `underpaid` waits out the whole
deposit window first, so a refund cannot race a user topping the order up.

**Resolving a frozen refund** (`GET /admin/exchange-reserve/refunds?status=frozen`):
a refund freezes when the submit outcome was ambiguous — the payment MAY
have landed, so the debit stands and nothing is retried.

- `sent` (with `stellar_tx_hash`) records a refund that did land.
- `reverse` restores the ledger for one that did not. It is refused until
  600s after the claim AND only after the bridge verifies on-chain that no
  matching refund exists. Reversing one that actually landed would credit
  `available` for money that left the chain.
- `approve` / `cancel` handle rows parked for review; neither has moved
  value yet.

**Never refund by hand any more.** Since 032, use the queue — an on-chain
send with no obligation row leaves the ledger and the chain disagreeing, and
a later automatic refund of the same deposit would pay twice. For inflows
the driver refuses, `POST /admin/exchange-reserve/refunds` mints an
obligation with an explicit destination and goes through the same audited
path. Deposits recorded before 032 have no captured sender and are manual
only — this is deliberate: they may already have been refunded by hand.

Refunds are sent **gross**; the reserve absorbs the ~100-stroop network fee
(netting across assets would be nonsense — a USDC refund's fee is XLM). That
fee accumulates as chain-below-ledger drift, exactly as payouts already do.
Book it off periodically with an `adjustment` entry.

## Automated replenishment

The pool takes XLM in and pays USDC out, so USDC drains while XLM piles up;
the USD float only drains. Replenishment sells the accumulated float back.
Two independently triggered kinds, each with its own caps, cooldown, and
single in-flight slot:

- `xlm_to_usdc` — sells XLM through Changelly, USDC returns to the reserve
  address. Fully automatic.
- `usdc_to_usd` — off-ramps USDC through OwlPay to the bridge's own bank.
  **Requires treasury beneficiary configuration** (`OWLPAY_TREASURY_JSON`);
  without it a cycle freezes rather than guessing a destination.

**Enabling** (`PUT /admin/exchange-reserve/replenishment/policies/{kind}`):
set `max_spend_minor` and `daily_spend_cap_minor` FIRST — the API refuses to
enable a kind whose caps are still 0, because 0 means *unconfigured, refuse
to run*, and an "enabled" policy that silently never runs is worse than a
disabled one. Also set `min_float_minor` to cover the Stellar base reserve
plus transaction fees, or customer payouts will start failing
`tx_insufficient_balance`.

**Sizing** reuses the same forecast the admin UI shows — mean, EWMA, and the
suggested top-up for `target_days` of coverage — with treasury entry kinds
excluded. That exclusion is load-bearing: counting the bridge's own
inventory moves would inflate the EWMA that sizes the next cycle, so an
off-ramp would buy USDC to replace the USDC it deliberately spent.

**Price guards** are the valve that matters. `min_price_minor` is a floor;
`max_slippage_bps` bounds the at-size quote against a reference quote. A
mispriced or manipulated quote is refused rather than acted on. Start
conservative.

**A cycle freezes** (never auto-retries) when a send outcome is ambiguous,
when the pay-in memo is missing or too long, or when it crashed mid-flight.
Frozen cycles keep their hold and keep the kind's slot occupied — that is
deliberate: unknown on-chain state must block further spending.

**Confirming fiat.** The bridge can observe USDC leaving and OwlPay's
transfer status, but **never a bank credit**. So a completed off-ramp books
the fiat into `held` as *in transit*, and
`POST .../replenishment/{cycle_id}/confirm-fiat` moves it into `available`
once you have seen it on the statement. If it never arrives,
`.../write-off` clears it — that writes off real money, requires a note, and
is loudly audited. Without a write-off the USD `held` column stays poisoned
and the kind stays blocked.

**Manual trigger.** `POST /admin/exchange-reserve/replenishment/run` starts
one cycle immediately. It takes the watcher's own advisory lock and returns
409 if the watcher is mid-tick — the reserve account signs from a single
sequence number, so two concurrent submissions would collide.

## Multi-instance notes

The watcher takes a per-tick Postgres advisory lock, so replicas do not
duplicate work; correctness (no double payout, no double credit) is carried
by the write-ahead `payout_attempt` intent and `UNIQUE(order_id, kind)`
regardless of the lock. Ops signing manually from the reserve account can
race the watcher's sequence numbers — expect `tx_bad_seq` retries; prefer
pausing policies (disable, wait a tick) before manual on-chain operations.
