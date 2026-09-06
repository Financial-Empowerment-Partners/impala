# Impala transfer protocol v1 (applet 0.2)

Normative reference for the issuer-certified offline transfer protocol. This
document, `apdu.md`, and the applet source are the three places the protocol is
pinned; the golden vectors in §4 are shared byte-for-byte with the SDK
(`TransferProtocolGoldenTest.kt`) and the bridge (`card_auth.rs`).

Protocol v0 (applet 0.1, the untagged 60-byte envelope) is **retired**. No
fielded card ever held an account identity, so there is no deployed balance to
migrate; a 0.2 receiver refuses every v0 envelope.

## 1. Lifecycle and state

```
BLANK ──INITIALIZE 0x2C──▶ INITIALIZED ──PERSONALIZE 0x72 (A[,B],C)──▶ PERSONALIZED ──TERMINATE 0x73──▶ TERMINATED
initialized=false           initialized=true, personalized=false          personalized=true                terminated=true
orthogonal flags: programBound, scp03KeysCustom, pinProvisioned, provisioningEnforced
```

- **BLANK** — public reads and INITIALIZE only; `GET_EC_PUB_KEY` answers `0x6230`.
- **INITIALIZED** — `SIGN_AUTH`, `SIGN_TRANSFER_V2`, `VERIFY_TRANSFER_V2` answer `0x6234`.
- **PERSONALIZED** — full function. `accountId`, `currency`, `programId`,
  `issuerPubKey` and the card certificate are immutable forever; re-issue is
  `gp --delete/--install`, which wipes all state.
- **TERMINATED** — every guarded command answers `0x6687`; the signing key is
  cleared. `GET_BALANCE` / `GET_PERSONALIZATION` / `GET_RECEIVE_STATE` /
  `GET_LAST_TRANSFER` / `GET_USER_DATA` stay readable for post-mortem.

`GET_PERSONALIZATION` (0x34) returns 159 bytes:
`state(1) ‖ flags(1) ‖ programId(16) ‖ currency(4) ‖ issuerPubKey(65, zeros unless set) ‖ certificate(72B slot)`.
State byte: `0xFF` terminated, else `0x02` personalized, else `0x01` initialized,
else `0x00` blank. Flags bits: 0 initialized, 1 programBound, 2 personalized,
3 SCP03 keys are the GP defaults (`!scp03KeysCustom`), 4 pinProvisioned,
5 provisioningEnforced, 6 terminated.

## 2. Card key certificate

The issuer certifies each card's public key. The **CERT message** an issuer
signs is 114 bytes:

| off | len | field |
|---|---|---|
| 0 | 12 | `"IMPALA-CERT:"` = `49 4D 50 41 4C 41 2D 43 45 52 54 3A` |
| 12 | 1 | `CERT_VERSION` = `0x01` |
| 13 | 16 | `programId` (issuer-allocated, unique per (issuer, network, program)) |
| 29 | 16 | `accountId` (RFC-4122 big-endian) |
| 45 | 4 | `currency` |
| 49 | 65 | `cardPubKey` = `04 ‖ X ‖ Y`, exactly as `GET_EC_PUB_KEY` returns it |

Signature: ECDSA secp256r1 / SHA-256, DER 8..72 bytes, carried zero-padded in a
72-byte slot; consumers take `slot[1] + 2` bytes. There is no expiry, serial, or
cardId — every field is reconstructible by a receiving card from its own
`programId`, the signable's sender and currency, and the tail pubkey, so the
slot carries only the signature. `cert_id := SHA-256(CERT message)`.

**Custody.** The program (issuer) key never lives on a card or terminal. It is
install-only on the bridge (`/admin/keys*`, fingerprint-only responses); a
signing request never returns key bytes. Rotation means a new `programId` and a
re-issue — old-program cards cannot pay new-program cards, because a receiver
rebuilds the CERT with its own `programId`.

## 3. Transfer envelope v1

The **XFER message** a card signs is 89 bytes:

| off | len | field |
|---|---|---|
| 0 | 12 | `"IMPALA-XFER:"` = `49 4D 50 41 4C 41 2D 58 46 45 52 3A` |
| 12 | 1 | `TRANSFER_PROTOCOL_VERSION` = `0x01` |
| 13 | 16 | signing card's `programId` |
| 29 | 60 | signable |

The 60-byte **signable** layout (unchanged from v0):
`dateTime(8)@0 ‖ sender(16)@8 ‖ recipient(16)@24 ‖ currency(4)@40 ‖ amount(4)@44 ‖ phoneId(8)@48 ‖ counter(4)@56`,
all big-endian. `amount` is an unsigned 32-bit minor-unit amount and must be
≥ 1. `transfer_id := SHA-256(XFER message)` is THE canonical id of a card
transfer (deterministic, independent of the ECDSA nonce, unique per
`(sender accountId, dateTime)` within a program).

**`dateTime` is a send sequence, not a timestamp.** It is a 63-bit strictly
increasing per-sender value; the sender's card refuses a value that is not
strictly greater than the last it signed (`0x6238`) and refuses the MSB being
set. Terminals allocate `max(previous + 1, now_unix_ms)`; after any ambiguous
outcome, read `GET_LAST_TRANSFER` before allocating. No host staleness or expiry
policy may rely on it.

`SIGN_TRANSFER_V2` (0x30) response, 209 bytes, deterministic and zero-filled:
`[0..72)` DER transfer signature slot ‖ `[72..137)` card pubkey ‖ `[137..209)`
card certificate slot. A complete offline-verifiable envelope is
`signable(60) ‖ response(209)` = 269 bytes. A byte-identical re-send of the same
signable replays the cached response — no second debit, no PIN check, no
PIN-less budget burn (torn-response recovery); the anchor is the last committed
signable.

`VERIFY_TRANSFER_V2` (0x31) accepts a credit only after: the sender is not this
card (`0x6231`); the recipient is this card (`0x6232`); the currency matches
(`0x6229`); the amount is non-zero (`0x6239`); the receive counter passes §6;
the credit does not overflow (`0x6984`); the certificate verifies under this
card's `issuerPubKey` over the rebuilt CERT message (`0x0022`); and the transfer
signature verifies under the tail pubkey over the XFER message (`0x0023`). The
credit, the counter and `lastReceiveDigest = transfer_id` commit in one
transaction.

## 4. Golden vectors (byte-exact; shared fixture)

`programId` = `a0a1a2a3a4a5a6a7a8a9aaabacadaeaf`; `accountId` =
`00112233-4455-6677-8899-aabbccddeeff`; `currency` = `"USDC"` = `55534443`;
`cardPubKey` = the P-256 generator; signable = dateTime `1`, sender = accountId,
recipient `ffeeddccbbaa99887766554433221100`, currency USDC, amount `1000`,
phoneId `0`, counter `1`.

- CERT message (114 B): `494d50414c412d434552543a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00112233445566778899aabbccddeeff55534443046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5`
- XFER message (89 B): `494d50414c412d584645523a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000000100112233445566778899aabbccddeeffffeeddccbbaa9988776655443322110055534443000003e8000000000000000000000001`
- `transfer_id` = SHA-256(XFER) = `6b3c272189bde62d55636e21b345929c1c077d008bb533af44f813adf56b67b9`
- `cert_id` = SHA-256(CERT) = `82cb580b058873f2554b100cfee07bc7ef7fa5def3ddc477e333f2f60258b77b`

## 5. Personalization ceremony

`PERSONALIZE` (CLA 0x84, INS 0x72, P2 = 0x00) runs over an SCP03 channel that
must carry C-DEC (`0x6982` otherwise) and must not be on the GP default keys
(`0x6236`). Three parts, each plaintext before the SCP03 wrap:

| P1 | Part | Plaintext | Lc |
|---|---|---|---|
| `0x01` | A identity | `accountId(16) ‖ currency(4) ‖ programId(16) ‖ initialReceiveCounter(4)` | 40 |
| `0x02` | B issuer key | `issuerPubKey(65)` = `04‖X‖Y` (omitted when program-bound at install) | 65 |
| `0x03` | C certificate | DER ECDSA signature over the §2 CERT message | 8..72 |

Part C verifies the certificate over the staged identity and the card's own
public key, under the staged issuer key (or the install-bound key), then commits
`accountId`, `currency`, `programId`, `lastReceiveCounter := initialReceiveCounter`,
`issuerPubKey`, the certificate, and `personalized = true` (the last write) in
one transaction. A tear before commit leaves the card unpersonalized and the
ceremony re-runs from part A. Idempotency anchor: `personalized` (a second
ceremony → `0x6235`).

Install-parameter TLV (`gp --params`):
`[0x01][flags] [ENC16 MAC16 DEK16 if 0x02] [masterPIN8 userPIN4 if 0x04] [programId16 ‖ issuerPubKey65 if 0x08]`.
Flag `0x08` (program bind) **requires** `0x02` (a bound card must never run on
default keys). Any SCP03 key equal to the GP default (`0x40..0x4F`) fails the
install (`0x6684`); a zero `programId` or a non-`0x04` issuer key fails
(`0x6A80`). All validation runs before any mutation.

Full issuance ceremony: install (flags `0x0B` = ENFORCE|KEYS|PROGRAM, or `0x03`
then bind with part B) → INITIALIZE → read cardId + card pubkey → rotate to
per-card keys via APPLET_UPDATE seq 0x0001 → issuer HSM signs the CERT →
PERSONALIZE A[,B],C over the per-card channel → PROVISION_PIN (lifts ENFORCE) →
`GET_PERSONALIZATION` read-back → register with the bridge.

*Honesty statements:* the default-keys flag is a policy tripwire, not a
cryptographic barrier — whoever holds the current SCP03 keys can rotate them;
the only cross-card trust is the receiver's issuer key; an issuer-certified
treasury key is unbounded mint authority the bridge must journal against a
reserve hold before signing; no on-card expiry or revocation exists in v1.

## 6. Receive counter and send sequence

### 6.1 Accept rule (receiving card; one stream per card, all senders)

`L = lastReceiveCounter` (starts at 0 or the issuer-supplied
`initialReceiveCounter`), `c = signable.counter`, `J = 1024`:

`accept ⇔ (c & 0x80000000) == 0 ∧ c ≠ 0 ∧ c > L ∧ c ≤ min(L + J, 0x7FFFFFFF)`
and every identity/signature check passes; on accept `L := c` in the same
transaction as the credit. `c ≤ 0 ∨ c ≤ L → 0x6233` (stale/replay);
`c − L > J → 0x623A` (allocator ahead — re-read `GET_RECEIVE_STATE`). Jamming
the stream now needs a certified sender, a real debit per accepted transfer, and
≈ 2.1 M accepted credits (`2³¹/1024`). The sender refuses `c ≤ 0` (`0x6233`)
because no receiver could ever accept it; its own replay guard is the send
sequence (§3).

### 6.2 Ownership

| Stream | Owner | Unique id | Idempotency anchor | Read-back |
|---|---|---|---|---|
| credits | receiving card | `(recipient pubkey, counter)` | `lastReceiveCounter`, committed with the credit; `lastReceiveDigest` | GET_RECEIVE_STATE |
| debits | sending card | `(sender pubkey, dateTime)` | `lastSentSignable` (byte-identical retry replays the cached response) | GET_LAST_TRANSFER |
| both, off-card | bridge mirror keyed by pubkey | `transfer_id = SHA-256(XFER)` | `UNIQUE(sender_pubkey, date_time)`, `UNIQUE(recipient_pubkey, counter)`, `UNIQUE(transfer_id)` | reconciliation |

### 6.3 Allocation

Tap-present is the only mode for card recipients: the terminal holding both
cards reads the recipient's `GET_RECEIVE_STATE`, sets `counter = L + 1`, has the
sender sign (SIGN_TRANSFER_V2) and presents the tail (VERIFY_TRANSFER_V2). The
recipient card is the serialization point; terminals never hold counter ranges.
Store-and-forward to a card recipient is unsupported and terminals must refuse to
compose it; it is allowed only when the recipient is the bridge treasury (whose
counter is the bridge's own stream). Loads (bridge → card) are ordinary
VERIFY_TRANSFER_V2 credits from the issuer-certified treasury key; the counter is
read live at load time. `dateTime` allocation is `max(previous + 1, now_ms)`;
`0x6238` means the terminal's clock/sequence lags the card — read
GET_LAST_TRANSFER and re-allocate, never re-sign an already-signed transfer.

### 6.4 Out-of-order / torn delivery

With tap-present allocation "102 before 101" cannot arise for card recipients.
If a terminal violates §6.3, the refused transfer is **stranded, not lost**: the
sender's debit is provable (`signable ‖ sig ‖ pubkey ‖ cert`), the terminal must
NOT ask the sender to re-sign, it uploads the envelope at sync, and the bridge
credits the recipient's *account* from the sender-signed record (deduped on
`transfer_id`). On-card acceptance is never a precondition for settlement.

Torn VERIFY_TRANSFER_V2 — read `GET_RECEIVE_STATE`:
- `digest == SHA-256(my XFER message)` ⇒ committed (done);
- `counter < c` ⇒ not committed ⇒ re-present (P1=0x00 then P1=0x01);
- `counter ≥ c ∧ digest ≠` ⇒ another credit landed in between ⇒ bridge exception
  queue, **never auto-credit**.

### 6.5 Resync after long offline periods

The terminal uploads GET_VERSION, GET_PERSONALIZATION, GET_BALANCE,
GET_RECEIVE_STATE and GET_LAST_TRANSFER with every held envelope. The bridge
verifies each envelope (cert against the program key, signature over the XFER
message), dedupes on the three unique keys, and reconciles its mirror. Envelopes
the card refused settle server-side (§6.4); a card `L` ahead of the mirror
advances the mirror (the card is authoritative for its own stream); a balance
that does not reconcile quarantines the card (hot-listed) until an operator
resolves — fail closed. Nothing on the card is rewound; there is no
counter-reset command.

### 6.6 Revocation, lost card, replacement, exhaustion

- **Lost/stolen:** the bridge revokes the pubkey/cert_id; terminals get the
  hot-list at next sync and refuse to *present* from it (the receiving card
  cannot know — v1 limitation). Offline exposure is bounded by the on-card
  balance, the PIN (5 tries) and the PIN-less budget (≤ 200 × 4).
- **Replacement:** a new card, full ceremony with the **same accountId**, a
  **new certificate** (new key), and `initialReceiveCounter ≥ the bridge's last
  known L for that account` — so every envelope the lost card accepted
  (`counter ≤ old L`) can never re-verify on the replacement (the recipient is
  the unchanged accountId). Send streams are keyed by pubkey and cannot collide.
- **Recovered card:** read balance/counters for the record, then TERMINATE over
  its per-card keys.
- **Issuer-key compromise / rotation:** new `programId` + program key, re-issue;
  old-program cards are refused at settlement.
- **Exhaustion** (`L = 0x7FFFFFFF`): handled as replacement.

### 6.7 Bounded out-of-order window — not added

An IPsec-style replay bitmap was rejected for this tranche: tap-present
allocation removes the case by construction, store-and-forward to cards is
disallowed, and a bitmap adds a second replay-state structure to the money path
in a language without integer arithmetic. What is added instead — forward-jump
bound, non-zero amounts, an idempotent send sequence, readable counters/digests,
the replacement floor, and bridge settlement of stranded envelopes — answers the
reviewer questions. Revisit only if a pilot shows stranded transfers at an
operationally painful rate.

## 7. Protocol versions

| Direction | Outcome |
|---|---|
| 0.1 sender → 0.2 receiver | a v0 tail carries a zero certificate slot → DER-invalid → `0x6A80`; a v0 raw signature over the bare 60 bytes → `0x0023` |
| 0.2 sender → 0.1 receiver | the old receiver never sees INS 0x30; a 0.2 sender's `SIGN_TRANSFER_V2` on a 0.1 card is `0x6D00` |

No in-place upgrade: `gp --delete/--install` wipes all state; reflash then run
the ceremony. `ImpalaSDK.requireCertifiedProtocol()` stops the SDK driving V2
flows against a 0.1 card.

## 8. Claims → tests

| Claim | Evidence (`sdk/src/jvmTest`) |
|---|---|
| A certified card-to-card transfer credits the recipient and verifies host-side | `CertifiedTransferInteropTest::certified card-to-card transfer credits the recipient and verifies host-side` (C1) |
| An uncertified key credits nothing | C2 |
| A certificate for another account/currency/program is refused | C3, C5 |
| A v0 (untagged) signature is refused | C4 |
| Transfer to self, currency mismatch and zero amount are refused on both sides | C6, C7, C8 |
| An unpersonalized card signs and credits nothing | C9 |
| The 209-byte response is zero-padded and carries the certificate | C10 |
| Two cards conserve value across a round-trip | C13 |
| Counter replay/stale/jump are rejected; gaps accepted | K1, K2 |
| Zero/negative counters are never accepted; the sender refuses to sign them | K3 |
| Identical re-send replays without a second debit | K4 |
| The send sequence must strictly increase | K5 |
| GET_LAST_TRANSFER is readable after a send | K6 |
| The replacement floor refuses envelopes the lost card accepted | K7 |
| Personalization commits atomically; parts are ordered; the ceremony is idempotent | `PersonalizationInteropTest` P1–P8 |
| PERSONALIZE / TERMINATE are gated on custom keys and C-DEC; TERMINATE is irreversible | P2, P7, P12 |
| The golden vectors reproduce byte-for-byte | `TransferProtocolGoldenTest` |

## 9. Physical-card checklist (manual; CI never claims it)

Record per card: cardId, CAP sha256, GET_VERSION, and the results below.

1. `GET_VERSION` reports `0.2`.
2. Two cards, ceremony §5 by hand (install → INITIALIZE → key rotation →
   PERSONALIZE → PROVISION_PIN → GET_PERSONALIZATION read-back).
3. C13 by hand (treasury → A, A → B with PIN, B → A PIN-less; balances conserve).
4. Tear tests: pull the card during SIGN_TRANSFER_V2 after the PIN and during
   VERIFY_TRANSFER_V2 P1=0x01; before/after read GET_BALANCE, GET_RECEIVE_STATE,
   GET_LAST_TRANSFER; assert the §6.4 decision table.
5. `JCSystem.getMaxCommitCapacity() ≥ 256`.
6. Confirm `setIncomingAndReceive` is called once per command (the applet moved
   it to the top of `process()`; the old per-handler calls were removed).
