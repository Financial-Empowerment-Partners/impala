# Runbook: Conversion Reserve

The conversion reserve is a bridge-owned pool that fulfills exchange orders
under a per-provider threshold ($20–$200) instead of routing them to
Changelly/OwlPay. This runbook covers enabling it, funding it, day-2
operations, and its failure queues (frozen payouts, unmatched deposits,
frozen refunds, frozen replenishment cycles).

Since migration 032 the reserve also: issues **locked price quotes** that
reserve capacity, **refunds** deposits it cannot use, and **replenishes**
itself by selling accumulated float. Each ships behind its own flag,
defaulting off — applying 032 changes no behavior until an operator opts in.

Reserve and replenishment operations (disburse, resolve, write-off,
confirm-fiat, refunds, policy and settings changes) require the **treasurer
or admin** role; every reserve-side read surface — status, ledger, policies,
the work queues, unmatched deposits, refunds, replenishment cycles, and
cross-account reserve orders — is also visible to **auditors**, read-only.

Design summary: diverted orders are ordinary `exchange_order` rows with
`provider = 'reserve'`; the caller pays XLM/USDC into the reserve Stellar
account with an order-unique text memo; a background watcher matches
deposits, pays USDC out automatically (crypto swaps), or queues fiat
disbursements for a treasurer or admin (OwlPay off-ramps). All pool
accounting is the
`conversion_reserve*` tables (BIGINT minor units: USDC/XLM 7 dp, USD cents),
journaled in `conversion_reserve_entry`.

## Enabling

The order below is the one the code can execute: the reserve seed can only be
created through the admin key surface, the trustline endpoint needs a live
reserve handle (which exists only after the restart), and the deposit watcher
starts scanning at enablement and never reads history.

1. **Generate (never import) the reserve seed** through the key-custody
   surface — `KEY_IMPORT_ENABLED=true` must be on for the instance you call:
   `POST /admin/stellar-seeds/generate {"payala_account_id":
   "svc-conversion-reserve", "label": "Reserve"}` (admin or key-custodian),
   or `impalactl stellar-seed generate --account svc-conversion-reserve
   --label Reserve`. The response carries the new Stellar address, which is
   all that ever leaves the bridge. Do **not** use
   `POST /managed-account/generate`: it is a user-facing endpoint that only
   accepts the caller's own account — there is no admin bypass, an admin token
   gets 403 — and it refuses the configured reserve account outright. Seed
   *import* is refused for the reserve account (see `import-keys.md`).
2. **Fund the address with XLM only**: base reserve + ~0.5 XLM per trustline
   you will add (USDC, and USDT0 if configured) + fees. Nothing else yet: the
   account has no trustlines, so a stablecoin sent now fails at the sender,
   and the watcher is not running, so it would not be booked anyway.
   **Pool sizing:** the hold guard refuses new orders once holds reach half
   the pool, so the USDC bucket must end up holding at least 2× your largest
   threshold to serve anything.
3. **Apply migrations through 036** (`RUN_MODE=migrate`): 031 creates the
   `conversion_reserve*` tables, 032 adds quotes/refunds/replenishment, and
   036 seeds the `USDT0` bucket — required before `RESERVE_USDT0_ISSUER` is
   set (the bridge refuses to start otherwise; it changes nothing on its own).
4. **Set the env and restart:**
   - `RESERVE_ACCOUNT_ID=<payala id from step 1>` — the bridge now refuses
     this account on all user-facing `/managed-account/*` endpoints and on
     account deletion (its seed signs pool payouts).
   - `RESERVE_USDC_ISSUER=<G...>` (+ `RESERVE_USDC_CODE` if not `USDC`).
     The issuer is strkey-checksummed at startup: a mistyped one refuses to
     start rather than silently classifying every real deposit as foreign.
   - Optionally `RESERVE_USDT0_ISSUER=<G...>` (+ `RESERVE_USDT0_CODE`,
     `RESERVE_USDT0_TICKERS`) — see [USDT0](#usdt0-second-stablecoin) below.

   On ECS these are non-secret values and go in the Terraform input
   `bridge_extra_environment` (a list of `{name, value}` objects), then
   `terraform apply` and let the services roll:
   `bridge_extra_environment = [{ name = "RESERVE_ACCOUNT_ID", value = "svc-conversion-reserve" }, { name = "RESERVE_USDC_ISSUER", value = "G..." }]`

   On this first start the bridge pins the deposit-scan cursor to *now* and
   logs an **ERROR per configured stablecoin the account holds no trustline
   for** — expected at this point. (If the seed is missing: with
   `KEY_IMPORT_ENABLED=true` the bridge starts *armed but inactive* and the
   log points you back to step 1; with the flag off it refuses to start.)
5. **Add the trustlines from inside the bridge:**
   `POST /admin/exchange-reserve/trustlines {"currency": "USDC"}` (and
   `"USDT0"` if configured) — admin or treasurer; the Reserve page shows a
   *no trustline* badge and an **Add trustline** button on any configured
   stablecoin bucket the account cannot hold yet. This endpoint answers 400
   `conversion reserve is not configured` until the restart in step 4 has
   produced a live reserve handle, which is why it cannot come earlier. It is
   also the only way: the generated seed exists nowhere outside the bridge,
   so no wallet can sign the `ChangeTrust`.
6. **Send the stablecoin float** (and any further XLM) to the address with
   no memo. The live watcher books each inflow itself: an `unmatched_deposit`
   credit to the bucket plus a row in the unmatched queue (reason `no_match`,
   with a `refund_skip_reason` — unmemoed inflows are never auto-refunded,
   they are how ops tops the pool up). Do **not** also record a manual
   `topup` for it: that books the same money twice.
7. **Record what the watcher cannot see** with
   `POST /admin/exchange-reserve/entries` `kind: topup`: the XLM from step 2
   (it landed before the cursor existed — the scan never reads history) and
   the USD fiat float (never on-chain). Note the funding tx hash or bank
   reference. The Reserve page shows ledger vs on-chain side by side — they
   should agree now.
8. **Enable routing:** `PUT /admin/exchange-reserve/policies/changelly_crypto`
   (and/or `owlpay`) with `{"enabled": true, "threshold_usd_cents": ...}`
   (2000–20000). `changelly_fiat` cannot be enabled — its orders carry no
   payout coordinates the bridge could serve.

`import-keys.md` ("Bootstrapping the reserve") walks the same procedure from
the key-custody side, starting from a bridge that already has
`RESERVE_ACCOUNT_ID` set and is running armed-but-inactive.

## What diverts

- `changelly_crypto` `crypto_to_crypto` xlm→usdcxlm float swaps whose payout
  address is a Stellar account **with a USDC trustline**, priced from the
  provider's own live estimate (scaled from a 100-XLM reference below the
  provider minimum) — automatic end-to-end.
- `owlpay` `crypto_to_fiat` Stellar-USDC→USD orders that include
  `beneficiary`/`payout_instrument` — pay-in is automatic, the fiat leg
  lands in the disbursement queue for a treasurer or admin.
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
  unmatched deposits. Treasurers and admins act from it; auditors see the
  same live page read-only (a banner says which roles the actions require).
- **Top-ups**: send funds on-chain to the reserve address (no memo, or a
  non-order memo). The watcher credits the inflow automatically (unmatched
  queue, reason `no_match`) — do **not** also record a manual `topup` for
  on-chain funding, that would book the same money twice. Manual `topup`
  entries are only for value the watcher cannot see: the USD fiat float,
  and corrections. The auto-credited row stays in the unmatched queue as the
  record of the inflow (its `refund_skip_reason` says why it was not
  returned); there is nothing to do to it — the queue has no annotate or
  dismiss action, and queuing a refund from it is the wrong action for a
  top-up. Keep the tx hash in your own ops log.
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
tx stays valid ~300 s), when bounded retries ran out after definitive
rejections (`max_attempts`, five attempts with backoff — a fee bid below the
ledger's surge price is the classic cause), when the payout could not be
built at all (`submit_failed`: missing or malformed `amount_to` /
`payout_address`, or the payout bucket's asset is no longer configured),
when the destination can never receive the asset (`payout_rejected`:
`op_no_trust`, `op_no_destination`, `op_line_full`, `op_not_authorized`), or
when a crash left an intent unresolved (`stale_intent`). The funds stay
held; nothing auto-retries.

**Fee bids.** Every bridge-signed transaction bids `STELLAR_MAX_FEE_STROOPS`
per operation (default 10 000 stroops = 0.001 XLM, clamped to
[100, 1 000 000]). A bid is a ceiling: the network charges the ledger's
effective fee, so a quiet ledger still costs 100 stroops, and the bid only
matters when surge pricing is on — which is exactly when a 100-stroop bid
used to fail every submission with `tx_insufficient_fee` for hours,
freezing payouts as `max_attempts` and failing refunds. If a surge outlasts
the default, raise the variable, restart, then `retry` the frozen rows;
nothing re-submits on its own.

Resolve from the Reserve page
(`POST /admin/exchange-reserve/orders/{order_id}/resolve`):
- **complete** — the payout actually landed. The bridge searches the reserve
  account's recent payments for the order's memo, records the found hash,
  writes the `fulfillment` entry + `transaction` row, and completes the
  order. You may paste a `stellar_tx_hash` instead, but it is **verified,
  never trusted** — it releases the hold and marks the customer paid:
  exactly 64 hex characters, and Horizon must show it as a *successful*
  payment from the reserve to the order's payout address for exactly
  `amount_to` in the bucket's asset (a failed transaction still lists its
  operations with their intended amounts, so success is required). A hash
  Horizon does not know is a 400, one that does not match is a 409, and if
  Horizon is unreachable the request fails with a 5xx — retry later, nothing
  was recorded.
- **retry** — re-arm the payout for the watcher. This is the right move,
  instead of `fail` + refund, when the reason was transient: a fee surge
  (`max_attempts`), a transient Horizon rejection, a deconfigured payout
  asset that has since been configured again (`submit_failed`), or a crash
  (`stale_intent`) — the customer still gets what was quoted. It applies
  **exactly the guards `fail` applies** (next bullet), because a payout may
  already have landed and re-arming after a settled one would pay twice: it
  is refused inside the 600 s quiet period, when a matching payout is found,
  and when Horizon cannot be checked. The hold is untouched (a freeze never
  released it), the attempt counter resets, and the watcher re-signs on its
  next tick — through the same bounded retry, so an unfixed cause freezes
  the order again. Do not use it for `payout_rejected` (`op_no_trust` and
  friends) unless the recipient has fixed their account: `fail` and let the
  refund path return the deposit.
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
on the same path. `retry` and `complete` are refused for disbursement
orders — their only exit is the disburse endpoint.

Never resolve-fail (or retry) from memory or a block explorer screenshot
alone; the server-side check exists because an in-flight transaction is
invisible until it lands.

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
Both are audited (the acting treasurer's or admin's id + note required by
convention). The status
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
with an explicit `stellar_tx_hash` (still verified on Horizon against the
order's recorded pay-in address, amount and destination — only the asset
check is skipped, since nothing can name it), but resolve-fail and retry on
payout-attempted orders refuse (the chain cannot be checked) until the
reserve is re-set.

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
deposits, and deposits stranded when a treasurer or admin resolve-fails an
order. Each identifies both an order and a payer.

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

**Resolving a frozen or failed refund**
(`GET /admin/exchange-reserve/refunds?status=frozen`, `?status=failed`;
`POST /admin/exchange-reserve/refunds/{refund_id}/resolve`): a refund
freezes when the submit outcome was ambiguous — the payment MAY have landed,
so the debit stands and nothing is retried. It ends `failed` only once its
debit has been **reversed**: three definitive rejections in a row (a fee
surge, typically), a permanent rejection (the destination cannot hold the
asset), or an admin `reverse` that proved nothing landed.

- `sent` (with `stellar_tx_hash`) records a frozen or in-flight refund that
  did land. The hash is **verified on Horizon before it is recorded** —
  exactly 64 hex characters, a *successful* payment from the reserve to the
  refund destination for exactly the refund amount in the bucket's asset.
  Unknown hash → 400; mismatch → 409; Horizon unreachable → 5xx, retry
  later. It fails closed because the hash becomes settlement evidence and
  the debit stands on the strength of it; it is never trusted as a string.
- `reverse` restores the ledger for one that did not. It is refused until
  600s after the claim AND only after the bridge verifies on-chain that no
  matching refund exists. Reversing one that actually landed would credit
  `available` for money that left the chain.
- `retry` re-queues a `failed` refund with its attempt counter reset; the
  driver picks it up on its next pass. This is ledger-safe because a refund
  reaches `failed` only after its debit was reversed — the driver debits
  again when it claims the row. Until this action existed there was **no
  signing path out of `failed`**: a fee surge stranded customer refunds
  permanently. Use it once the cause is gone (fee bid raised, destination
  fixed); a rejection that is still permanent just fails it again.
- `approve` / `cancel` handle rows parked for review; neither has moved
  value yet.

**Never refund by hand any more.** Since 032, use the queue — an on-chain
send with no obligation row leaves the ledger and the chain disagreeing, and
a later automatic refund of the same deposit would pay twice. For inflows
the driver refuses, `POST /admin/exchange-reserve/refunds` mints an
obligation with an explicit destination and goes through the same audited
path. Deposits recorded before 032 have no captured sender and are manual
only — this is deliberate: they may already have been refunded by hand.

Refunds are sent **gross**; the reserve absorbs the network fee (netting
across assets would be nonsense — a USDC refund's fee is XLM). The bridge
bids `STELLAR_MAX_FEE_STROOPS` per operation (default 10 000 stroops =
0.001 XLM) but is charged only the ledger's effective fee — 100 stroops
when the network is quiet — see "Fee bids" under Frozen payouts. That fee
accumulates as chain-below-ledger drift, exactly as payouts already do.
Book it off periodically with an `adjustment` entry.

## Automated replenishment

The pool takes XLM in and pays USDC out, so USDC drains while XLM piles up;
the USD float only drains. Replenishment sells the accumulated float back.
Two independently triggered kinds, each with its own caps, cooldown, and
single in-flight slot:

- `xlm_to_usdc` — sells XLM through Changelly, USDC returns to the reserve
  address. Fully automatic.
- `usdc_to_usd` — would off-ramp USDC through OwlPay to the bridge's own
  bank, but **the bridge has no treasury-beneficiary configuration today**,
  so the kind cannot run: enabling its policy is refused (400). Should a
  cycle of that kind ever reach the driver, it is aborted, not frozen — the
  row ends `state = failed`, `last_error = no_treasury_config`, its USDC hold
  is released with a `replenish_release` entry, and nothing lands in the
  frozen queue (nothing was sent, so there is no ambiguous on-chain state to
  guard).

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

## USDT0 (second stablecoin)

Tether's USDT0 — the LayerZero OFT form of USDT, backed 1:1 by USDT and
operated by Everdawn Labs under license — is issued natively on Stellar as a
classic asset since 2026-09-02. The reserve treats it as a second
**issuer-pinned** stablecoin next to USDC: one bucket (`USDT0`, 7 dp, seeded
by migration 036), one `(code, issuer)` identity from configuration, and
every asset decision in the engine (deposit classification, payout and
refund asset, on-chain balances, issuer burn-guards, trustlines) flows
through the same list that USDC does. There is nothing USDT0-specific in
the money paths — that is the point.

**What the issuer means.** Asset codes are not unique on Stellar; anyone can
issue a "USDT0". The bridge recognizes money by `(code, issuer)` only, and it
never ships an issuer — you set it, and it becomes the trust anchor for the
bucket. Verify it against the official deployments table
(<https://docs.usdt0.to> → Technical documentation → Contract Deployments)
and stellar.expert before setting it. At launch the pubnet issuer is
`GATISXX6BZ6NC7IKQBY37CJD4SOZL3CYZJWXEDG6JVIY4WBS6KXJHN6Q` (asset code
`USDT0`; no testnet deployment is published — on testnet, issue your own test
asset). The bridge checks the strkey checksum and refuses to start on a typo.

**Enabling.**

Same shape as the main [Enabling](#enabling) sequence — migrate, configure
and restart, trustline, then fund while the watcher is live:

1. Apply migration 036 (`RUN_MODE=migrate`) — seeds the bucket, changes no
   behavior. It must precede step 2: with `RESERVE_USDT0_ISSUER` set and no
   bucket row the bridge refuses to start.
2. Set `RESERVE_USDT0_ISSUER=<G...>` (and `RESERVE_USDT0_CODE` if not
   `USDT0`) — on ECS via `bridge_extra_environment`, like the USDC variables
   — and restart. Startup validation: checksummed issuer, 1–12 alphanumeric
   code, an identity distinct from the USDC asset, and the reserve not being
   its own issuer. Expect an ERROR line about the missing trustline.
3. Add the reserve account's trustline:
   `POST /admin/exchange-reserve/trustlines {"currency": "USDT0"}` (admin or
   treasurer). The account needs ~0.5 XLM of free base reserve;
   `op_low_reserve` is reported verbatim. Until this is done the bucket is
   flagged *no trustline* on the Reserve page and the bridge logs an ERROR at
   every startup — a payment to an account without a trustline fails at the
   **sender**, so nothing is lost, but nothing arrives either.
4. Send the USDT0 float to the reserve address with no memo, **after** the
   trustline exists and while the watcher is live. It is booked
   automatically as an `unmatched_deposit` credit (reason `no_match`) — no
   manual `topup` entry, that would double-book, exactly as for USDC
   (Enabling, steps 6–7).

**What works with only the issuer set** (no provider tickers): USDT0
deposits are recognized and booked (matched to orders expecting USDT0, or
queued as unmatched/wrong-asset like any other tracked asset), refunds and
manual refunds pay out in USDT0, admin sends refuse the USDT0 issuer as a
destination (it would burn the asset), and the Reserve page shows the
on-chain USDT0 balance and trustline state per bucket.

**Provider diversion needs tickers.** Whether an exchange order diverts to
the USDT0 leg is decided by ticker strings (`to_currency` of a Changelly
auto-swap, `from_currency` of an OwlPay disburse), and those strings are
provider-specific. The bridge ships none for USDT0: set
`RESERVE_USDT0_TICKERS=<comma-separated>` with the exact values from each
provider's currency list. They may not collide with the tickers that already
mean XLM or USDC (`xlm`, `usdcxlm`, `usdc`) — startup refuses that, because a
collision would silently route USDC orders to the USDT0 leg. Setting tickers
without an issuer is likewise refused. An order records the stablecoin leg
it was created with (`provider_payload.deposit_currency` for the pay-in,
`hold_currency` for the payout), so later ticker or issuer changes never
re-interpret an existing order: a pay-in in the other stablecoin is a
`wrong_asset` inflow for the unmatched queue, and a payout whose asset was
deconfigured freezes `on_hold` for an admin instead of guessing.

**Not covered yet.** Automated replenishment (`xlm_to_usdc`, `usdc_to_usd`)
stays USDC-only; a USDT0 bucket that drains is topped up by ops through the
unmatched-deposit credit path, exactly as USDC was before 032. The Soroban
wrapper is USDC-specific and unrelated to the reserve.

## Multi-instance notes

The watcher takes a per-tick Postgres advisory lock, so replicas do not
duplicate work; correctness (no double payout, no double credit) is carried
by the write-ahead `payout_attempt` intent and `UNIQUE(order_id, kind)`
regardless of the lock. Ops signing manually from the reserve account can
race the watcher's sequence numbers — expect `tx_bad_seq` retries; prefer
pausing policies (disable, wait a tick) before manual on-chain operations.
