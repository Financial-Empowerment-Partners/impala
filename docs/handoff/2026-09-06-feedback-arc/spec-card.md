# impala-card protocol hardening — implementation spec (applet 0.2, transfer protocol v1)

All paths are absolute under `/Users/user/sonoranpub/impala/`; `impala-card/…` below means `/Users/user/sonoranpub/impala/impala-card/…`. Line numbers are the current working tree (verified while writing this spec). An implementer must read this spec top to bottom once; every number here is normative.

## 0. Verified ground truth this spec is built on

| Fact | Where |
|---|---|
| `accountId[16]`/`currency[4]` are allocated and never written; INS 0x26 has no dispatch case; every card is the nil UUID | `ImpalaApplet.java:201,206`, dispatch `:390-524` |
| SIGN_TRANSFER (0x06) signs the untagged 60-byte signable; debits atomically; persists no sender record; response 209 = `sigBuffer(72, stale tail) ‖ pubkey(65) ‖ 30 06 02 01 00 02 01 00 + stale scratchpad` | `:812-877`, `:120-126` |
| VERIFY_TRANSFER (0x14) trusts the tail pubkey, never reads bytes 137..208, needs no `initialized`/PIN, DER length from `buffer[CDATA+1]` unbounded, unknown P1 → silent 0x9000 | `:891-963` |
| Receive rule: MSB clear ∧ `counter > lastReceiveCounter` (unsigned), gaps unbounded; 0x6233 declared only at `:71` | `:942-957` |
| Negative sender counter (`:846-849`) and balance overflow (`:1059-1061`) throw `ISO7816.SW_DATA_INVALID` = **0x6984** (not 0x6A80); install-TLV validation throws `SW_WRONG_DATA` = 0x6A80 (`:572-622`) | verified against jcardsim's `ISO7816` class |
| SCP03 defaults 0x40..0x4F, no flag; `KEY_DIVERSIFICATION` ten zeros; PROVISION_PIN over defaults lifts ENFORCE; APPLET_UPDATE unknown seq → silent 0x9000 | `:236-244`, `SCP03.java:43-49`, `:662-696`, `:703-725` |
| `unwrapCommand` builds the C-MAC input in the APDU buffer at `dataOffset+dataLength` and assumes 261 bytes (`SCP03.java:373-392`); **jcardsim 3.0.6.0 allocates a 260-byte buffer** (`javacard.framework.APDU` constructor `sipush 260`). Cap: secured plaintext **≤ 113 bytes without C-DEC, ≤ 111 with C-DEC** (`34 + 2·pad16(P) ≤ 260`). Secured **responses** ≤ 111 plaintext bytes (`2·pad16(len) + 18 ≤ 260`, `ImpalaApplet.java:1116-1121`) | |
| jcardsim `ECPublicKeyImpl.getW` on an uninitialized key throws `CryptoException(UNINITIALIZED_KEY)`; `setW` does not validate the point; `JCSystem` transactions are depth flags only (**no rollback**), `getMaxCommitCapacity()` = 32767 | javap of the jar in `~/.gradle/caches` |
| `APDU.setIncomingAndReceive()` throws `APDUException.ILLEGAL_USE` when called twice; today it is called only inside `processUpdateUserPIN` (`:992`) and `processVerifyPIN` (`:1018`) | |
| `terminated` only ever assigned `false` (`:199`); INITIALIZE one-shot, unauthenticated (`:391-411`) | |
| SDK parses SIGN_TRANSFER as exactly 209 = 72‖65‖72 (`ImpalaSDK.kt:250-260`), GET_VERSION as 10 bytes (`:69`), pins SCP03 key version 0x02 (`SCP03Channel.kt:85-91`), discards the 10 diversification bytes (`:80-83`); `CommandAPDU(ins)` is a case-1 APDU (`CommandAPDU.kt:127`) | |
| Nothing outside `impala-card/` calls SIGN_TRANSFER/VERIFY_TRANSFER/setCardData/updateMasterPin (Android reader uses INS 30/36/7/37/24/35/100 only; `ImpalaCardReader.kt:73-79`) | flow area F1 |
| Bridge golden test for the auth message lives in `impala-bridge/src/handlers/card_auth.rs:380-404` with UUID `00112233-4455-6677-8899-aabbccddeeff`; `CARD_AUTH_DOMAIN_PREFIX` at `constants.rs:227`; the bridge is a bin crate and marks unused constants `#[allow(dead_code)]` per item | |
| CI `impala-card.yml:218-219` uploads test reports only `if: failure()`; the release job runs on tags `impala-card-v*` (none exist) | |

Consequence: no fielded card can hold an accountId, so there is no deployed balance or login to migrate. The untagged v0 envelope is **retired**, not carried.

Target property (the applet must make this true): *after personalization, a card signs nothing without an issuer-certified identity, credits nothing that is not signed by an issuer-certified key of the same program bound to the signable's sender and currency, and no command reachable with card-management (SCP03) keys can alter that trust root.*

## 1. Number registry (single source; every entry lands in `Constants.java` AND `Constants.kt`)

### 1.1 INS

| INS | Constant (Java / Kotlin identical) | CLA | Notes |
|---|---|---|---|
| `0x30` | `INS_SIGN_TRANSFER_V2` | 0x00 only | 209-byte response cannot be R-wrapped |
| `0x31` | `INS_VERIFY_TRANSFER_V2` | 0x00 only | 209-byte tail cannot be C-DEC-wrapped |
| `0x32`, `0x33` | **never assigned** | — | `README.md:32,:250-276` historically documented 50/51 as Set/Get Ext Pubkey; never dispatched in this repo; left unassigned forever (apdu.md never-reuse rule) |
| `0x34` | `INS_GET_PERSONALIZATION` | 0x00 only | 159-byte response |
| `0x35` | `INS_GET_RECEIVE_STATE` | 0x00 or 0x84 | 36-byte response fits the wrap |
| `0x36` | `INS_GET_LAST_TRANSFER` | 0x00 only | 132-byte response |
| `0x72` | `INS_SCP03_PERSONALIZE` (Kotlin also `SCP03Constants.INS_PERSONALIZE`) | 0x84 only | three parts, C-DEC required |
| `0x73` | `INS_SCP03_TERMINATE` (Kotlin also `SCP03Constants.INS_TERMINATE`) | 0x84 only | C-DEC required |
| `0x06`, `0x14` | `INS_SIGN_TRANSFER`, `INS_VERIFY_TRANSFER` stay declared | — | **dispatch cases removed** → 0x6D00; documented "Retired — never reuse" |
| `0x07 0x23 0x26 0x2B 0x2D` | unchanged | — | still declared-not-dispatched |

### 1.2 Status words (all new codes added to both Constants files, `ImpalaException.fromStatusWord`, `ExceptionMappingTest`, `docs/apdu.md`)

| SW | Constant | Status | Emitted by | `fromStatusWord` → |
|---|---|---|---|---|
| `0x6233` | `SW_ERROR_TRANSFER_COUNTER_INVALID` | moved from `ImpalaApplet.java:71` into Constants | VERIFY_V2: c ≤ 0 or c ≤ L; SIGN_V2: c ≤ 0 | `ImpalaTransferException("Transfer counter invalid (0x6233)")` |
| `0x6234` | `SW_ERROR_NOT_PERSONALIZED` | new | SIGN_AUTH, SIGN_V2, VERIFY_V2 (P1=0 and P1=1) | `ImpalaPersonalizationException` (new class) |
| `0x6235` | `SW_ERROR_ALREADY_PERSONALIZED` | new | PERSONALIZE | `ImpalaPersonalizationException` |
| `0x6236` | `SW_ERROR_DEFAULT_SCP03_KEYS` | new | PERSONALIZE, TERMINATE, PROVISION_PIN when `provisioningEnforced` | `ImpalaSecurityException` |
| `0x6237` | `SW_ERROR_PERSONALIZE_SEQUENCE` | new | PERSONALIZE part out of order | `ImpalaPersonalizationException` |
| `0x6238` | `SW_ERROR_SEND_SEQUENCE_INVALID` | new | SIGN_V2 dateTime not strictly increasing (or MSB set) | `ImpalaTransferException` |
| `0x6239` | `SW_ERROR_ZERO_AMOUNT` | new | SIGN_V2, VERIFY_V2 | `ImpalaTransferException` |
| `0x623A` | `SW_ERROR_TRANSFER_COUNTER_JUMP` | new | VERIFY_V2: `c − L > 1024` (distinct from replay so a terminal knows to re-read) | `ImpalaTransferException` |
| `0x623B` | `SW_ERROR_PROGRAM_ALREADY_BOUND` | new | PERSONALIZE part B (or part A with a different programId) on an install-bound card | `ImpalaPersonalizationException` |
| `0x6A80` | `SW_WRONG_DATA` | add constant (ISO) | malformed DER header, non-0x04 point, nil ids, bad initial counter, TERMINATE accountId mismatch, install TLV | `ImpalaCardDataException("Wrong data (0x6A80)")` |
| `0x6984` | `SW_DATA_INVALID` | add constant (ISO) | balance overflow on credit (**existing behaviour retained**, now checked before the transaction) | `ImpalaCardDataException("Data invalid (0x6984)")` |
| `0x6A83` | `SW_RECORD_NOT_FOUND` | add constant (ISO `ISO7816.SW_RECORD_NOT_FOUND`) | GET_LAST_TRANSFER before any signed transfer | `ImpalaCardDataException("Record not found (0x6A83)")` |
| `0x6E00` | `SW_CLA_NOT_SUPPORTED` | add constant (ISO `ISO7816.SW_CLA_NOT_SUPPORTED`) | 0x30/0x31/0x34/0x36 arriving at CLA 0x84 | `ImpalaInstructionNotSupportedException("CLA not supported for this instruction (0x6E00)")` |
| `0x6982` | exists | — | PERSONALIZE/TERMINATE without C-DEC | existing |
| `0x0022` | exists (never thrown today) | — | VERIFY_V2 certificate check | existing `ImpalaCryptoException` |
| `0x6677` | exists (never thrown today) | — | PERSONALIZE part C self-check | existing `ImpalaCardDataException` |
| `0x6683` | exists | — | any `CryptoException` (new global catch) | existing |
| `0x6684` | exists | — | GP default key bytes supplied at install or APPLET_UPDATE | existing |
| `0x6A86` | exists | — | PERSONALIZE/VERIFY_V2 bad P1/P2, APPLET_UPDATE unknown (seq,len) | existing |
| `0x6688` | exists | — | keeps its SCP03 C-MAC-failure meaning (pinned by `Scp03CounterIcvTest.kt:148-154`); apdu.md gains the collision note | existing |

### 1.3 Other constants (both files unless noted)

`PROGRAM_ID_LENGTH=16`, `CURRENCY_LENGTH=4`, `DOMAIN_TAG_LENGTH=12`, `XFER_MESSAGE_LENGTH=89`, `CERT_MESSAGE_LENGTH=114`, `PERSONALIZE_IDENTITY_LENGTH=40`, `PERSONALIZE_STAGE_LENGTH=177`, `PERSONALIZATION_LENGTH=159`, `RECEIVE_STATE_LENGTH=36`, `LAST_TRANSFER_LENGTH=132`, `TRANSFER_RESPONSE_LENGTH=209`, `MIN_DER_SIG_LENGTH=8`, `PROGRAM_BLOCK_LENGTH=81`, `KEY_DIVERSIFICATION_LENGTH=10`, `TRANSFER_PROTOCOL_VERSION=(byte)0x01`, `CERT_VERSION=(byte)0x01`, `MAX_COUNTER_JUMP=(short)1024`, `P1_PERSONALIZE_IDENTITY=0x01`, `P1_PERSONALIZE_ISSUER_KEY=0x02`, `P1_PERSONALIZE_CERTIFICATE=0x03`, `PERSONALIZATION_STATE_BLANK=0x00`, `_INITIALIZED=0x01`, `_PERSONALIZED=0x02`, `_TERMINATED=(byte)0xFF`, flag bits `PFLAG_INITIALIZED=0x01, PFLAG_PROGRAM_BOUND=0x02, PFLAG_PERSONALIZED=0x04, PFLAG_SCP03_KEYS_DEFAULT=0x08, PFLAG_PIN_PROVISIONED=0x10, PFLAG_PROVISIONING_ENFORCED=0x20, PFLAG_TERMINATED=0x40`. Applet-private: `FLAG_INSTALL_PROGRAM=(byte)0x08`, `XFER_DOMAIN_TAG`, `CERT_DOMAIN_TAG` (12-byte arrays next to `AUTH_DOMAIN_TAG`, `ImpalaApplet.java:100-104`), `DEFAULT_SCP03_KEY` (hoisted from the constructor local `:238-243`). Kotlin keeps `HASHABLE_LENGTH` but annotates it `@Deprecated("the 252-byte hashable record was removed in applet 0.2")`.

## 2. Lifecycle and state

### 2.1 Derived states

```
BLANK ──INITIALIZE 0x2C──▶ INITIALIZED ──PERSONALIZE 0x72 (A[,B],C)──▶ PERSONALIZED ──TERMINATE 0x73──▶ TERMINATED
initialized=false           initialized=true, personalized=false          personalized=true                terminated=true
orthogonal: programBound (install flag 0x08, or PERSONALIZE part C commit); scp03KeysCustom; pinProvisioned; provisioningEnforced
```
- BLANK: public reads + INITIALIZE; SIGN_* → 0x6230 (unchanged). GET_EC_PUB_KEY → **0x6230** (was 65 stale bytes).
- INITIALIZED: SIGN_AUTH, SIGN_V2, VERIFY_V2 → **0x6234**.
- PERSONALIZED: full function; `accountId/currency/programId/issuerPubKey/cardCert` are immutable forever (re-issue = `gp --delete/--install`, which wipes all state).
- TERMINATED: every `failIfCardIsTerminated()` command → 0x6687; `cardECPrivateKey.clearKey()` so signing is impossible even if a guard were missed; GET_BALANCE / GET_PERSONALIZATION / GET_RECEIVE_STATE / GET_LAST_TRANSFER / GET_USER_DATA stay readable for post-mortem.

State byte (GET_PERSONALIZATION): `terminated ? 0xFF : personalized ? 0x02 : initialized ? 0x01 : 0x00`.

### 2.2 New persistent fields (allocate in the constructor, after line 223)

| Field | Type | Initial | Written by |
|---|---|---|---|
| `programId` | `byte[16]` | zeros | install flag 0x08; PERSONALIZE part C commit |
| `issuerPubKey` | `ECPublicKey` = `SecP256r1.newPubKey()` (persistent) | uninitialized | install flag 0x08; PERSONALIZE part C commit |
| `programBound` | `boolean` | false | same two places |
| `cardCert` | `byte[72]` DER zero-padded | zeros | PERSONALIZE part C commit |
| `personalized` | `boolean` | false | PERSONALIZE part C commit — **last write of the transaction** |
| `scp03KeysCustom` | `boolean` | false | `applyProvisioningParameters` (FLAG_INSTALL_KEYS); `processAppletUpdate` seq 0x0001 |
| `lastSentSignable` | `byte[60]` | zeros | SIGN_V2 commit. Its `[0..8)` IS the send sequence (`lastSentSeq`); "never sent" ⇔ bytes `[8..24)` (sender) all zero |
| `lastSentSig` | `byte[72]` | zeros | SIGN_V2 commit |
| `lastReceiveDigest` | `byte[32]` | zeros | VERIFY_V2 commit (= SHA-256 of the accepted XFER message = transfer id) |

Unchanged: `accountId`, `cardId`, `currency`, `myBalance`, `lastReceiveCounter` (now also seeded by PERSONALIZE part A), PINs, `howManyPINless`, `provisioningEnforced`, `pinProvisioned`, `initialized`, `terminated`.

### 2.3 New transient buffers (constructor)

| Buffer | Size | Clear | Purpose |
|---|---|---|---|
| `personalizeStage` | 177 | `CLEAR_ON_DESELECT` | A(40) @0, B(65) @40, staged across the PERSONALIZE APDUs |
| `stageState` | 1 | `CLEAR_ON_DESELECT` | bit0 = A received, bit1 = B received; also zeroed in the CLA 0x80 INS 0x50 case (new SCP03 session) and after every PERSONALIZE outcome |
| `verifyStage` | 1 | `CLEAR_ON_DESELECT` | 1 after a successful P1=0x00; P1=0x01 without it → 0x6985 |
| `tempLimit` | 4 | `CLEAR_ON_RESET` | counter bound arithmetic |
| `tempBalance` | 8 | `CLEAR_ON_RESET` | overflow-checked credit computed before the transaction |

Removed: `hashable`, `hashBuffer` stays (32, reused for the receive digest), `SIXTY_FOUR_ZEROES`, `makeHashable()`, files `Hashable.java` and `CryptoPrimitivesConverter.java` (unreferenced afterwards; delete). `CardNonce.java` untouched.

## 3. Byte formats (append-only contracts; every one pinned by a golden test)

### 3.1 CERT message — what the issuer signs (114 bytes)

| off | len | field |
|---|---|---|
| 0 | 12 | `"IMPALA-CERT:"` = `49 4D 50 41 4C 41 2D 43 45 52 54 3A` |
| 12 | 1 | `CERT_VERSION` = `0x01` |
| 13 | 16 | `programId` (issuer-allocated, unique per (issuer, Stellar network, program); UUIDv4 recommended) |
| 29 | 16 | `accountId` (RFC-4122 big-endian) |
| 45 | 4 | `currency` |
| 49 | 65 | `cardPubKey` = `04 ‖ X ‖ Y` exactly as GET_EC_PUB_KEY returns it |

Signature: ECDSA secp256r1 / SHA-256 (JavaCard `ALG_ECDSA_SHA_256`; host `SHA256withECDSA` / aws-lc `ECDSA_P256_SHA256_ASN1`), DER 8..72 bytes, carried zero-padded in a 72-byte slot; consumers take `slot[1]+2` bytes. No expiry, no serial, no cardId (not reconstructible by a receiver; enforced off-card, §6.6). Every field is reconstructible by a receiving card from its own `programId`, the signable's sender `[8..24)` and currency `[40..44)`, and the tail pubkey — so the slot carries only the signature. `cert_id := SHA-256(CERT message)` (bridge registry / revocation key).

### 3.2 XFER message — what a card signs (89 bytes)

| off | len | field |
|---|---|---|
| 0 | 12 | `"IMPALA-XFER:"` = `49 4D 50 41 4C 41 2D 58 46 45 52 3A` |
| 12 | 1 | `TRANSFER_PROTOCOL_VERSION` = `0x01` (untagged format = v0, retired) |
| 13 | 16 | signing card's `programId` |
| 29 | 60 | signable, layout unchanged: `dateTime(8)@0 ‖ sender(16)@8 ‖ recipient(16)@24 ‖ currency(4)@40 ‖ amount(4)@44 ‖ phoneId(8)@48 ‖ counter(4)@56` (`TransactionParser.java:13-24`) |

`transfer_id := SHA-256(XFER message)` — THE canonical id in the card domain (deterministic, independent of ECDSA nonce, unique per `(sender accountId, dateTime)` within a program because the sender never signs the same signable twice). The three tags differ in their last four bytes from `"IMPALA-AUTH:"` (`…41 55 54 48 3A`) at equal length; the domains cannot collide.

**`dateTime` semantics change (documented everywhere):** it is a 63-bit strictly-increasing per-sender **send sequence**, never a trusted timestamp. Terminals allocate `max(previous + 1, now_unix_ms)`; after any ambiguous outcome read GET_LAST_TRANSFER before allocating; no host staleness/expiry policy may rely on it.

### 3.3 Golden vectors (fixture shared by card, SDK and bridge tests)

programId `a0a1a2a3a4a5a6a7a8a9aaabacadaeaf`; accountId `00112233-4455-6677-8899-aabbccddeeff` (`card_auth.rs:373`); currency `"USDC"` = `55534443`; cardPubKey = P-256 generator `SecP256r1.P_secp256r1`; signable = dateTime `1`, sender = accountId, recipient `ffeeddccbbaa99887766554433221100`, currency USDC, amount `1000`, phoneId `0`, counter `1`.

- CERT message hex (114 B): `494d50414c412d434552543a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00112233445566778899aabbccddeeff55534443046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5`
- XFER message hex (89 B): `494d50414c412d584645523a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000000100112233445566778899aabbccddeeffffeeddccbbaa9988776655443322110055534443000003e8000000000000000000000001`
- `transfer_id` = SHA-256(XFER) = `6b3c272189bde62d55636e21b345929c1c077d008bb533af44f813adf56b67b9`
- `cert_id` = SHA-256(CERT) = `82cb580b058873f2554b100cfee07bc7ef7fa5def3ddc477e333f2f60258b77b`

### 3.4 SIGN_TRANSFER_V2 response (209 bytes, unchanged layout, now deterministic)

`[0..72)` DER transfer signature zero-padded ‖ `[72..137)` card pubkey ‖ `[137..209)` `cardCert` slot. Assembled into a **zero-filled** `scratchpad[0..209)`. A complete offline-verifiable envelope = `signable(60) ‖ response(209)` = 269 bytes.

### 3.5 PERSONALIZE parts (CLA 0x84, INS 0x72, P2=0x00; plaintext before SCP03 wrap)

| P1 | Part | Plaintext | Lc | Layout |
|---|---|---|---|---|
| `0x01` | A identity | `accountId(16) ‖ currency(4) ‖ programId(16) ‖ initialReceiveCounter(4)` | 40 | @0 @16 @20 @36 |
| `0x02` | B issuer key | `issuerPubKey(65)` = `04‖X‖Y` | 65 | omitted when the card was program-bound at install |
| `0x03` | C certificate | DER ECDSA signature over §3.1 | 8..72, exact | `data[0]==0x30`, `(data[1]&0xFF)+2 == Lc` |

Wire sizes with the SDK default level 0x33: 40→48 (+8 MAC = 56), 65→80 (88), 72→80 (88): MAC build ends at 5+88+21+80 = 194 ≤ 260. Response: no data, 0x9000.

### 3.6 Install-parameter TLV (extends `applyProvisioningParameters`, `ImpalaApplet.java:605-655`)

`[0x01][flags] [ENC16 MAC16 DEK16 if flags&0x02] [masterPIN8 userPIN4 if flags&0x04] [programId16 ‖ issuerPubKey65 if flags&0x08]`; mask at `:610` becomes `0x0F`; `expectedLength += 81` for 0x08. Flag 0x08 **requires** 0x02 in the same TLV (else 0x6A80: a bound card must never run on default keys). Any of ENC/MAC/DEK equal to `DEFAULT_SCP03_KEY` → 0x6684 (install fails). programId all-zero or pubkey[0] ≠ 0x04 → 0x6A80. All validation before any mutation (existing pattern).

### 3.7 Read responses

| INS | Response |
|---|---|
| `0x34` GET_PERSONALIZATION | `state(1) ‖ flags(1) ‖ programId(16) ‖ currency(4) ‖ issuerPubKey(65; zeros unless `issuerPubKey.isInitialized()`) ‖ cardCert(72 slot)` = 159; readable in every state, no gate |
| `0x35` GET_RECEIVE_STATE | `lastReceiveCounter(4 BE) ‖ lastReceiveDigest(32)` = 36; no gate |
| `0x36` GET_LAST_TRANSFER | `lastSentSignable(60) ‖ lastSentSig(72 slot)` = 132; 0x6A83 when never sent; no gate |

flags bits: 0 initialized, 1 programBound, 2 personalized, 3 scp03 keys are the GP defaults (`!scp03KeysCustom`), 4 pinProvisioned, 5 provisioningEnforced, 6 terminated.

### 3.8 SCP03 INITIALIZE UPDATE

`KEY_DIVERSIFICATION` (ten zeros, `SCP03.java:43-45`) is replaced by `cardId[0..10)`: `SCP03` gets `public void setDiversificationSource(byte[] src)` storing the **reference** (the applet calls it once in the constructor; INITIALIZE regenerates `cardId` in place so the reference stays valid); `processInitializeUpdate` copies `src[0..10)` at response offset 0. `KEY_INFO` stays `02 03 70`.

## 4. Applet changes — `impala-card/applet/src/jvmMain/java/com/impala/applet/ImpalaApplet.java`

### 4.1 Imports / statics
Add `import javacard.security.CryptoException;`, the new `Constants` imports, `XFER_DOMAIN_TAG`/`CERT_DOMAIN_TAG` arrays, `private static final byte[] DEFAULT_SCP03_KEY = {0x40..0x4F}` (constructor uses it at `:244`), `FLAG_INSTALL_PROGRAM`. Delete `SIXTY_FOUR_ZEROES` (`:120-126`) and the applet-local `SW_ERROR_TRANSFER_COUNTER_INVALID` (`:71`, import from Constants). Fix the comment at `SCP03.java:373` to say 260.

### 4.2 `process()` skeleton changes
1. CLA 0x00 branch (before the switch): `if (dataLength > 0) { short received = apdu.setIncomingAndReceive(); if (received < dataLength) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); }` and **remove** the `setIncomingAndReceive()` calls (and their `count < pinLength` checks) from `processUpdateUserPIN` (`:992-995`) and `processVerifyPIN` (`:1018-1021`) — a second call throws `APDUException`. Record in the physical-card checklist that this is a precondition for hardware runs.
2. CLA 0x80 INS 0x50 case: add `stageState[0] = 0; verifyStage[0] = 0;` before `processInitializeUpdate`.
3. CLA 0x84 branch after `unwrapCommand`: add `if (ins == INS_SCP03_PERSONALIZE) { failIfCardIsTerminated(); processPersonalize(buffer, dataLength); return; }` and `if (ins == INS_SCP03_TERMINATE) { failIfCardIsTerminated(); processTerminate(buffer, dataLength); return; }`.
4. Switch: remove `case INS_SIGN_TRANSFER` and `case INS_VERIFY_TRANSFER`; add cases for 0x30, 0x31, 0x34, 0x35, 0x36 (below); `INS_SIGN_AUTH` gains `failIfNotPersonalized()` after `failIfProvisioningRequired()`; `INS_GET_EC_PUB_KEY`: `if (cardECPublicKey == null) ISOException.throwIt(SW_ERROR_EC_CARD_KEY_MISSING);`.
5. Catch clauses: add `catch (CryptoException e) { ISOException.throwIt(SW_ERROR_CRYPTO_EXCEPTION); }` beside the existing two (`:525-529`). (An exception leaving `process()` inside an open transaction is aborted by the JCRE on real cards; jcardsim does not roll back — hence every value check in this spec runs **before** `beginTransaction`.)

### 4.3 Helpers (new)
```java
private void failIfNotPersonalized() { if (!personalized) ISOException.throwIt(SW_ERROR_NOT_PERSONALIZED); }
private void failIfSecured() { if (scp03.isSecuredCommand()) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED); } // 0x6E00
private void failIfDefaultKeys() { if (!scp03KeysCustom) ISOException.throwIt(SW_ERROR_DEFAULT_SCP03_KEYS); }
private void failIfNoCdec() { if ((scp03.getSecurityLevel() & SCP03.SEC_CDEC) == 0) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); }
/** 0x30 LL …; total length; 0x6A80 unless 8 <= len <= 72 and len == available (slot check done by caller). */
private short derSigLength(byte[] b, short off) {
    if (b[off] != (byte) 0x30) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short len = (short) ((b[(short) (off + 1)] & 0xFF) + TAG_LENGTH_LENGTH);
    if (len < MIN_DER_SIG_LENGTH || len > MAX_SIG_LENGTH) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    return len;
}
private static boolean isAllZero(byte[] b, short off, short len) { for (short i = 0; i < len; i++) if (b[(short)(off+i)] != 0) return false; return true; }
private static boolean containsDefaultScp03Key(byte[] b, short off) {
    return Util.arrayCompare(b, off, DEFAULT_SCP03_KEY, ZERO, (short)16) == 0
        || Util.arrayCompare(b, (short)(off+16), DEFAULT_SCP03_KEY, ZERO, (short)16) == 0
        || Util.arrayCompare(b, (short)(off+32), DEFAULT_SCP03_KEY, ZERO, (short)16) == 0;
}
/** scratchpad[0..89) := XFER_DOMAIN_TAG ‖ 0x01 ‖ programId ‖ src[srcOff..+60) */
private void buildXferMessage(byte[] src, short srcOff) {
    Util.arrayCopyNonAtomic(XFER_DOMAIN_TAG, ZERO, scratchpad, ZERO, DOMAIN_TAG_LENGTH);
    scratchpad[DOMAIN_TAG_LENGTH] = TRANSFER_PROTOCOL_VERSION;
    Util.arrayCopyNonAtomic(programId, ZERO, scratchpad, (short) 13, PROGRAM_ID_LENGTH);
    Util.arrayCopyNonAtomic(src, srcOff, scratchpad, (short) 29, SIGNABLE_LENGTH);
}
/** scratchpad[0..114) := CERT_DOMAIN_TAG ‖ 0x01 ‖ prog ‖ acct ‖ cur ‖ pub65 (pub may be null → cardECPublicKey.getW into scratchpad@49) */
private void buildCertMessage(byte[] prog, short progOff, byte[] acct, short acctOff, byte[] cur, short curOff, byte[] pub, short pubOff) {
    Util.arrayCopyNonAtomic(CERT_DOMAIN_TAG, ZERO, scratchpad, ZERO, DOMAIN_TAG_LENGTH);
    scratchpad[DOMAIN_TAG_LENGTH] = CERT_VERSION;
    Util.arrayCopyNonAtomic(prog, progOff, scratchpad, (short) 13, PROGRAM_ID_LENGTH);
    Util.arrayCopyNonAtomic(acct, acctOff, scratchpad, (short) 29, UUID_LENGTH);
    Util.arrayCopyNonAtomic(cur, curOff, scratchpad, (short) 45, CURRENCY_LENGTH);
    if (pub == null) cardECPublicKey.getW(scratchpad, (short) 49); else Util.arrayCopyNonAtomic(pub, pubOff, scratchpad, (short) 49, PUB_KEY_LENGTH);
}
/** scratchpad[0..209) := sig72 ‖ pubkey65 ‖ cardCert72, zero-filled first (no stale bytes). */
private void buildTransferResponse(byte[] sig72) {
    Util.arrayFillNonAtomic(scratchpad, ZERO, TRANSFER_RESPONSE_LENGTH, (byte) 0);
    Util.arrayCopyNonAtomic(sig72, ZERO, scratchpad, ZERO, MAX_SIG_LENGTH);
    cardECPublicKey.getW(scratchpad, MAX_SIG_LENGTH);
    Util.arrayCopyNonAtomic(cardCert, ZERO, scratchpad, (short) (MAX_SIG_LENGTH + PUB_KEY_LENGTH), MAX_SIG_LENGTH);
}
/** tempBalance := myBalance + amount; 0x6984 on carry-out. Called BEFORE beginTransaction. */
private void computeCredit(byte[] amount) {
    short carry = 0;
    for (short i = INT64_LENGTH - 1; i >= 0; i--) {
        short r = (short) ((myBalance[i] & 0xFF) + (amount[i] & 0xFF) + carry);
        tempBalance[i] = (byte) r; carry = (short) ((r >> 8) & 1);
    }
    if (carry != 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
}
/** Exact receive accept rule on tempCounter vs lastReceiveCounter. Throws 0x6233 / 0x623A. */
private void checkReceiveCounter() {
    if (isNegative(tempCounter) || ArrayUtil.isZero(tempCounter)
        || ArrayUtil.unsignedByteArrayCompare(tempCounter, ZERO, lastReceiveCounter, ZERO, INT32_LENGTH) <= 0)
        ISOException.throwIt(SW_ERROR_TRANSFER_COUNTER_INVALID);
    Util.arrayCopyNonAtomic(lastReceiveCounter, ZERO, tempLimit, ZERO, INT32_LENGTH);
    ArrayUtil.addUnsignedShort(tempLimit, MAX_COUNTER_JUMP);            // L + 1024, carry propagated
    if (isNegative(tempLimit)) { tempLimit[0]=0x7F; tempLimit[1]=(byte)0xFF; tempLimit[2]=(byte)0xFF; tempLimit[3]=(byte)0xFF; } // clamp
    if (ArrayUtil.unsignedByteArrayCompare(tempCounter, ZERO, tempLimit, ZERO, INT32_LENGTH) > 0)
        ISOException.throwIt(SW_ERROR_TRANSFER_COUNTER_JUMP);
}
```
`addToBalance` (`:1050-1062`) is deleted; `subtractFromBalance` stays (guarded by `checkAmount` beforehand). `ArrayUtil.java` gains:
```java
/** dst (big-endian, any length) += addend (0..32767), carry propagated; returns carry-out. */
public static short addUnsignedShort(byte[] dst, short addend) { short carry = addend; for (short i=(short)(dst.length-1); i>=0 && carry!=0; i--) { short v=(short)((dst[i]&0xFF)+(carry&0xFF)); dst[i]=(byte)v; carry=(short)((carry>>>8)+(v>>>8)); } return carry; }
```
(`addend` ≤ 32767 so the per-byte split is exact; the applet passes 1024.)

### 4.4 Install parameters (`applyProvisioningParameters`)
Mask `0x0F`; `expectedLength += PROGRAM_BLOCK_LENGTH` when 0x08; offsets: keys, pins, program in that order; validations (all before mutation, 0x6A80 unless stated): 0x08 without 0x02; `containsDefaultScp03Key` → 0x6684; program block `programId` all-zero, `issuerPubKey[0] != 0x04`; existing zero-user-PIN → 0x6691. Apply: `scp03.setStaticKeys(...)` then `scp03KeysCustom = true`; PINs as today; `provisioningEnforced`; program: `issuerPubKey.setW(bArray, progOff+16, 65)` (a `CryptoException` propagates = clean install failure), `Util.arrayCopyNonAtomic(programId…)`, `programBound = true`. Constructor: after `scp03 = new SCP03(randomData)` add `scp03.setDiversificationSource(cardId)`.

### 4.5 PROVISION_PIN (`:662`)
First statement: `if (provisioningEnforced && !scp03KeysCustom) ISOException.throwIt(SW_ERROR_DEFAULT_SCP03_KEYS);`. Non-ENFORCE dev cards keep today's behaviour (jcardsim default-key PIN tests stay green).

### 4.6 APPLET_UPDATE (`:703-725`)
```java
if (seq == (short)0x0001 && len == (short)48) {
    if (containsDefaultScp03Key(buffer, updateDataOffset)) ISOException.throwIt(SW_ERROR_INVALID_AES_KEY); // 0x6684
    JCSystem.beginTransaction();
    scp03.setStaticKeys(buffer, updateDataOffset, buffer, (short)(updateDataOffset+16), buffer, (short)(updateDataOffset+32));
    scp03KeysCustom = true;
    JCSystem.commitTransaction();
    return;
}
ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // 0x6A86: unknown (seq,len) is no longer a silent 0x9000
```
(APPLET_UPDATE remains reachable over default keys — it is how a stock card leaves them.)

### 4.7 PERSONALIZE — `processPersonalize(byte[] buffer, short dataLength)`
Common guards in order: `failIfNoCdec()` (0x6982) → `if (!initialized) 0x6230` → `if (personalized) 0x6235` → `failIfDefaultKeys()` (0x6236) → `P2 != 0 → 0x6A86`. Then by P1; every ISOException from a part clears `stageState[0]` and re-throws (`catch (ISOException e) { stageState[0]=0; ISOException.throwIt(e.getReason()); }`):
- **A (0x01):** `Lc != 40 → 0x6700`; `accountId` all-zero, `currency` all-zero, `programId` all-zero, or `initialReceiveCounter` MSB set → 0x6A80; if `programBound && arrayCompare(data+20, programId) != 0 → 0x623B`; copy 40 bytes to `personalizeStage[0..40)`; `stageState[0] = 0x01` (a repeated A discards a staged B).
- **B (0x02):** `(stageState & 1) == 0 → 0x6237`; `programBound → 0x623B`; `Lc != 65 → 0x6700`; `data[0] != 0x04 → 0x6A80`; `tempPubKey.setW(buffer, CDATA, 65)` (CryptoException → 0x6683 via the global catch); copy to `personalizeStage[40..105)`; `stageState[0] |= 0x02`.
- **C (0x03):** `(stageState & 1) == 0 || (!programBound && (stageState & 2) == 0) → 0x6237`; `Lc < 8 || Lc > 72 → 0x6700`; `derSigLength(buffer, CDATA) != Lc → 0x6A80`; `buildCertMessage(personalizeStage,20, personalizeStage,0, personalizeStage,16, null,0)` (card's OWN key from `cardECPublicKey.getW`); issuer key: `programBound ? issuerPubKey : (tempPubKey.setW(personalizeStage, 40, 65), tempPubKey)` — **always re-set from the stage** (tempPubKey is shared with VERIFY_V2 and may have been overwritten between APDUs); `verifySig(scratchpad,0,114, buffer,CDATA,Lc, key)` false → 0x6677. Commit:
```java
JCSystem.beginTransaction();
Util.arrayCopy(personalizeStage, ZERO, accountId, ZERO, UUID_LENGTH);
Util.arrayCopy(personalizeStage, (short)16, currency, ZERO, CURRENCY_LENGTH);
Util.arrayCopy(personalizeStage, (short)20, programId, ZERO, PROGRAM_ID_LENGTH);
Util.arrayCopy(personalizeStage, (short)36, lastReceiveCounter, ZERO, INT32_LENGTH);   // replacement floor
if (!programBound) { issuerPubKey.setW(personalizeStage, (short)40, PUB_KEY_LENGTH); programBound = true; }
Util.arrayFillNonAtomic(cardCert, ZERO, MAX_SIG_LENGTH, (byte)0);
Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, cardCert, ZERO, dataLength);
personalized = true;                                                                    // LAST write
JCSystem.commitTransaction();
stageState[0] = 0; Util.arrayFillNonAtomic(personalizeStage, ZERO, PERSONALIZE_STAGE_LENGTH, (byte)0);
```
Crash recovery: a tear before commit leaves `personalized == false` and every field untouched (on a platform whose `Key.setW` is not transaction-scoped, `personalized` written last still guarantees no "personalized without issuer key" state); the ceremony re-runs from part A. Idempotency anchor: `personalized` (second ceremony → 0x6235). Commit size ≈ 16+4+16+4+72+1 bytes + one EC public key (≈ 65–100) — physical checklist requires `JCSystem.getMaxCommitCapacity() ≥ 256`.

### 4.8 TERMINATE — `processTerminate(buffer, dataLength)`
`failIfNoCdec()` (0x6982) → `failIfDefaultKeys()` (0x6236) → `dataLength != 16 → 0x6700` → `Util.arrayCompare(buffer, CDATA, accountId, 0, 16) != 0 → 0x6A80` (binds the operator to the card in the reader; a blank card's accountId is the nil UUID) → `JCSystem.beginTransaction(); terminated = true; JCSystem.commitTransaction();` → `if (cardECPrivateKey != null) cardECPrivateKey.clearKey();`. Irreversible.

### 4.9 SIGN_TRANSFER_V2 — dispatch case
```java
case INS_SIGN_TRANSFER_V2: {
    failIfSecured(); failIfCardIsTerminated(); failIfProvisioningRequired(); failIfNotPersonalized();
    if (dataLength != (short)(USER_PIN_LENGTH + SIGNABLE_LENGTH)) ISOException.throwIt(SW_ERROR_WRONG_SIGNABLE_LENGTH); // 0x6226
    // Idempotent retry: byte-identical signable to the last committed debit → replay the identical 209 bytes,
    // no PIN check, no debit, no PIN-less budget burn (torn-response recovery).
    if (!isAllZero(lastSentSignable, TransactionParser.OFFSET_SENDER, UUID_LENGTH)
            && Util.arrayCompare(buffer, OFFSET_SIGNABLE, lastSentSignable, ZERO, SIGNABLE_LENGTH) == 0) {
        buildTransferResponse(lastSentSig); sendBytes(apdu, scratchpad, ZERO, TRANSFER_RESPONSE_LENGTH); break;
    }
    boolean pinless = isPINlessEligible(buffer);
    if (pinless || validatePIN(buffer, ISO7816.OFFSET_CDATA, USER_PIN_LENGTH)) {
        signTransferV2(buffer, pinless); sendBytes(apdu, scratchpad, ZERO, TRANSFER_RESPONSE_LENGTH);
    }
    break;
}
```
`signTransferV2(buffer, pinless)` checks in order: sender == `accountId` (0x6231); recipient != `accountId` (0x6232); currency == `currency` **unconditionally** (0x6229; the "skip when zero" branch `:833-839` is deleted); `getAmount → tempAmount`; all-zero → 0x6239; `!checkAmount` → 0x6224; `getCounter → tempCounter`; `isNegative || isZero` → 0x6233; dateTime: `(buffer[OFFSET_SIGNABLE] & 0x80) != 0` or `unsignedByteArrayCompare(buffer, OFFSET_SIGNABLE, lastSentSignable, 0, 8) <= 0` → 0x6238. Then `buildXferMessage(buffer, OFFSET_SIGNABLE)`; `Util.arrayFillNonAtomic(sigBuffer, 0, 72, 0)`; `signWithMyKey(scratchpad, 0, XFER_MESSAGE_LENGTH)`; then
```java
JCSystem.beginTransaction();
subtractFromBalance(tempAmount);
if (pinless) howManyPINless++;
Util.arrayCopy(buffer, OFFSET_SIGNABLE, lastSentSignable, ZERO, SIGNABLE_LENGTH);
Util.arrayCopy(sigBuffer, ZERO, lastSentSig, ZERO, MAX_SIG_LENGTH);
JCSystem.commitTransaction();
buildTransferResponse(sigBuffer);
```
Commit ≈ 8+1+60+72 = 141 bytes. Unique id of the debit: `(cardPubKey, dateTime)`; idempotency anchor: `lastSentSignable`; read-back: GET_LAST_TRANSFER. Tear semantics: before commit → nothing debited, no signature leaves the card; after commit, response lost → the terminal re-sends the identical APDU and receives the cached response, or reads GET_LAST_TRANSFER. Never re-sign with a new dateTime for the same transfer.

### 4.10 VERIFY_TRANSFER_V2 — dispatch case
`failIfSecured(); failIfCardIsTerminated(); failIfNotPersonalized(); verifyTransferV2(buffer, dataLength);`
- **P1=0x00:** `dataLength != 60 → 0x6226`; copy to `signableBuffer`; `verifyStage[0] = 1`.
- **P1=0x01**, nothing mutates before the transaction, cheap checks first: `dataLength != 209 → 0x6C02`; `verifyStage[0] != 1 → 0x6985`; `sigLen = derSigLength(buffer, CDATA)`; `certLen = derSigLength(buffer, CDATA+137)`; `buffer[CDATA+72] != 0x04 → 0x6A80`; sender == me → 0x6231; recipient != me → 0x6232; currency != mine → 0x6229; `getAmount → tempAmount`, all-zero → 0x6239; `getCounter → tempCounter`; `checkReceiveCounter()` (0x6233/0x623A); `computeCredit(tempAmount)` (0x6984); `tempPubKey.setW(buffer, CDATA+72, 65)` (CryptoException → 0x6683); **certificate first:** `buildCertMessage(programId,0 /*mine*/, signableBuffer,OFFSET_SENDER, signableBuffer,OFFSET_CURRENCY, buffer,(short)(CDATA+72))`, `verifySig(scratchpad,0,114, buffer,CDATA+137,certLen, issuerPubKey)` false → **0x0022**; **then the transfer signature:** `buildXferMessage(signableBuffer, 0)`, `verifySig(scratchpad,0,89, buffer,CDATA,sigLen, tempPubKey)` false → **0x0023**; `messageDigest.doFinal(scratchpad, 0, 89, hashBuffer, 0)`;
```java
JCSystem.beginTransaction();
Util.arrayCopy(tempBalance, ZERO, myBalance, ZERO, INT64_LENGTH);
Util.arrayCopy(tempCounter, ZERO, lastReceiveCounter, ZERO, INT32_LENGTH);
Util.arrayCopy(hashBuffer, ZERO, lastReceiveDigest, ZERO, HASH_LENGTH);
JCSystem.commitTransaction();
Util.arrayFillNonAtomic(signableBuffer, ZERO, SIGNABLE_LENGTH, (byte)0); verifyStage[0] = 0;
```
- **P1 ∉ {0,1} → 0x6A86.** No PIN is required to receive (unchanged); the trust root is `issuerPubKey`, not the holder. The single certificate verification proves: issuer certified this key, for this program (my `programId`), for exactly the signable's sender UUID and currency.

### 4.11 Reads
- `INS_GET_PERSONALIZATION`: zero-fill `scratchpad[0..159)`; `[0]` state byte; `[1]` flags; `programId`@2; `currency`@18; `if (issuerPubKey.isInitialized()) issuerPubKey.getW(scratchpad, 22)`; `cardCert`@87; send 159. CLA 0x00 only (`failIfSecured()`).
- `INS_GET_RECEIVE_STATE`: `lastReceiveCounter`→`scratchpad[0..4)`, `lastReceiveDigest`→`[4..36)`; send 36 (secured allowed).
- `INS_GET_LAST_TRANSFER`: `failIfSecured()`; `isAllZero(lastSentSignable, 8, 16) → 0x6A83`; `lastSentSignable`@0, `lastSentSig`@60; send 132.
- `BuildConfig.java`: `MINOR_VERSION = 2`. `applet/build.xml:6`: `applet.version` `0.3` → `0.4`.

### 4.12 `SCP03.java`
Add `public byte getSecurityLevel() { return channelState[IDX_SEC_LEVEL]; }`, `setDiversificationSource(byte[])` + its use in `processInitializeUpdate` (§3.8), correct the 261→260 comment. No wire change other than the diversification bytes.

## 5. Issuance ceremony (normative; the interop fixture reproduces it exactly)
1. `gp --install --params 01 0B ‖ ENC‖MAC‖DEK ‖ programId‖issuerPubKey` (flags 0x01 ENFORCE | 0x02 KEYS | 0x08 PROGRAM; add 0x04 + PIN block for factory PINs). Card: `scp03KeysCustom=true`, `provisioningEnforced=true`, `programBound=true`. (Alternative without 0x08: bind later with PERSONALIZE part B.)
2. `INITIALIZE (0x2C)` with host entropy → card keypair + final `cardId`.
3. `GET_USER_DATA` → cardId; `GET_EC_PUB_KEY` → 65-byte card key (over an R-MAC secured channel when an interposer is a concern).
4. SCP03 open with transport keys → `APPLET_UPDATE seq 0x0001` with per-card keys derived by the issuer HSM from (KMK, cardId) → close → reopen with per-card keys (INITIALIZE UPDATE now reports `cardId[0..10)` so any later session can look the keys up).
5. Issuer HSM signs the CERT message (§3.1) over (programId, accountId, currency, cardPubKey).
6. `PERSONALIZE` A (accountId, currency, programId, initialReceiveCounter = 0 for a first issuance) [, B], C over the per-card channel at level 0x33.
7. `PROVISION_PIN` master + user over the same channel (lifts ENFORCE).
8. `GET_PERSONALIZATION` + `GET_ACCOUNT_ID` read-back; `POST /card` with `card_id`, `ec_pubkey` and (bridge follow-up, append-only) `certificate`, `program_id`, `currency`.

Honesty statements (verbatim in apdu.md and README): *the default-keys flag is a policy tripwire, not a cryptographic barrier — whoever holds the current SCP03 keys can rotate them; the only cross-card trust is the receiver's issuer key; an issuer-certified treasury key is unbounded mint authority that the bridge must journal against a reserve hold before signing; no on-card expiry or revocation exists in v1.*

## 6. Counter model (lands verbatim in `docs/transfer-protocol.md` §Receive counter)

### 6.1 Exact accept rule (receiving card; one stream per card, all senders)
`L = lastReceiveCounter` (starts at 0 or the issuer-supplied `initialReceiveCounter`), `c = signable.counter`, `J = 1024`:
`accept ⇔ (c & 0x80000000) == 0 ∧ c ≠ 0 ∧ c > L ∧ c ≤ min(L + J, 0x7FFFFFFF)` and every identity/signature check passes; on accept `L := c` in the same transaction as the credit. `c ≤ 0 ∨ c ≤ L` → 0x6233 (stale/replay); `c − L > J` → 0x623A (allocator ahead, re-read). After this change a stream jam needs a certified sender, a real debit ≥ 1 minor unit per accepted transfer and ≥ 2³¹/1024 ≈ 2.1 M accepted credits (vs one tap today). Sender side: the card never chooses the recipient counter; it refuses `c ≤ 0` (0x6233) because no receiver could ever accept it (it would only burn a debit). Its own replay guard is the send sequence (§4.9).

### 6.2 Ownership table
| Stream | Owner | Unique id | Idempotency anchor | Read-back |
|---|---|---|---|---|
| credits | receiving card | `(recipient pubkey, counter)` | `lastReceiveCounter` strictly increasing, committed with the credit; `lastReceiveDigest` names the accepted transfer | GET_RECEIVE_STATE |
| debits | sending card | `(sender pubkey, dateTime)` | `lastSentSignable` (byte-identical retry replays the cached response) | GET_LAST_TRANSFER |
| both, off-card | bridge mirror keyed by pubkey (replacement cards get fresh streams) | `transfer_id = SHA-256(XFER message)` | `UNIQUE(sender_pubkey, date_time)`, `UNIQUE(recipient_pubkey, counter)`, `UNIQUE(transfer_id)` | reconciliation |

### 6.3 Allocation for multi-terminal offline environments
- **Tap-present (the only mode for card recipients):** the terminal holding both cards reads the recipient's `GET_RECEIVE_STATE`, sets `counter = L + 1`, has the sender sign (SIGN_V2), presents the tail (VERIFY_V2). The recipient card is physically in one place at a time, so it is the serialization point — no cross-terminal coordination exists or is needed; terminals never hold counter ranges (a single monotone stream cannot be partitioned: the first accepted value from a higher block voids every lower block).
- **Store-and-forward** to a card recipient is not supported and terminals must refuse to compose it (an absent card cannot serialize). It is allowed only when the recipient is the bridge treasury, whose counter is the bridge's own stream.
- **Loads (bridge → card)** are ordinary VERIFY_V2 credits from the issuer-certified treasury key (accountId = program treasury UUID, no card); the counter is read live at load time.
- `dateTime` allocation: `max(previous + 1, now_ms)`; 0x6238 means the terminal's clock/sequence lags the card → read GET_LAST_TRANSFER and re-allocate; never re-sign an already-signed transfer.

### 6.4 Out-of-order / delayed messages and the torn-delivery decision table
With tap-present allocation "102 before 101" cannot arise for card recipients. If a terminal violates §6.3, transfer 101 is refused with 0x6233 and becomes **stranded, not lost**: the sender's debit is provable (`signable ‖ sig ‖ pubkey ‖ cert`), the terminal must NOT ask the sender to re-sign (second debit), it uploads the envelope at sync, and the bridge credits the recipient's *account* from the sender-signed record (dedupe on `transfer_id`); the card is made whole by a later load with a fresh counter. On-card acceptance is never a precondition for settlement.
Torn VERIFY_V2 (host does not know whether P1=0x01 committed) — read `GET_RECEIVE_STATE`:
- `digest == SHA-256(my XFER message)` ⇒ committed (done);
- `counter < c` ⇒ not committed ⇒ re-present (P1=0x00 again, then P1=0x01);
- `counter ≥ c ∧ digest ≠` ⇒ another credit landed in between ⇒ bridge exception queue, **never auto-credit**.

### 6.5 Resync after long offline periods
1. Terminal reads GET_VERSION, GET_PERSONALIZATION, GET_BALANCE, GET_RECEIVE_STATE, GET_LAST_TRANSFER and uploads them with every envelope it holds. 2. Bridge verifies each envelope (cert against the program's issuer key, signature over the XFER message), dedupes on the three unique keys, compares its mirror to the card's `L`/`lastSentSeq`/digest. 3. Envelopes the card refused → settle server-side (§6.4); card `L` ahead of the mirror → mirror advances (the card is authoritative for its own stream); a balance that does not reconcile with the verified envelope set → card quarantined (hot-listed; bridge refuses settlement from that key) until an operator resolves — fail closed. 4. Nothing on the card is rewound; there is deliberately no counter-reset command.

### 6.6 Revocation, lost card, replacement, exhaustion
- Lost/stolen: bridge revokes the pubkey/cert_id; terminals get the hot-list at next sync and refuse to *present* from it (the receiving card cannot know — v1 limitation); offline exposure is bounded by the on-card balance, PIN (5 tries) and the PIN-less budget (≤ 200 × 4).
- Replacement: new card, full ceremony with the **same accountId**, a **new certificate** (new key), and PERSONALIZE part A carrying `initialReceiveCounter ≥ the bridge's last known L for that account` — so every envelope the lost card accepted (counter ≤ old L) can never re-verify on the replacement (recipient = accountId is unchanged, hence this floor is load-bearing); the bridge additionally dedupes by `transfer_id`. Send streams are keyed by pubkey so they cannot collide. Unreconciled offline balance on the lost card is treated as cash unless uploaded envelopes prove otherwise (documented policy).
- Recovered card: read balance/counters for the record, then `TERMINATE` over its per-card keys.
- Issuer key compromise / rotation: new programId + program key, re-issue; old-program cards cannot pay new-program cards (receiver rebuilds CERT with its own programId) and are refused at settlement.
- Exhaustion (`L = 0x7FFFFFFF`): needs ≥ 2.1 M accepted credits; handled as replacement.

### 6.7 Decision: bounded out-of-order window — **not added**
An IPsec-style bitmap over `(L−W, L]` was rejected for this tranche: tap-present allocation removes the case by construction and store-and-forward to cards is disallowed; it adds a second replay-state structure to the money path in a language without int arithmetic (the bug class it introduces is replay); it cannot help the real long-gap case. What is added instead — forward-jump bound, non-zero amounts, sender send-sequence with idempotent replay, readable counters/digests, replacement floor, and bridge settlement of stranded envelopes — answers every reviewer question. Revisit only if a pilot shows stranded transfers at an operationally painful rate.

## 7. SDK — `impala-card/sdk/src/commonMain/kotlin/com/impala/sdk/`

### 7.1 New pure module `models/TransferProtocol.kt` (no crypto; commonMain)
```kotlin
object TransferProtocol {
    val XFER_DOMAIN_TAG: ByteArray = "IMPALA-XFER:".encodeToByteArray()   // 12
    val CERT_DOMAIN_TAG: ByteArray = "IMPALA-CERT:".encodeToByteArray()   // 12
    const val TRANSFER_VERSION: Byte = 0x01; const val CERT_VERSION: Byte = 0x01
    const val MAX_COUNTER_JUMP: Int = 1024
    fun xferMessage(programId: ByteArray /*16*/, signable: ByteArray /*60*/): ByteArray /*89*/
    fun certMessage(programId: ByteArray, accountId: ByteArray /*16*/, currency: ByteArray /*4*/, cardPubKey: ByteArray /*65, [0]==0x04*/): ByteArray /*114*/
    fun transferId(programId: ByteArray, signable: ByteArray): ByteString = xferMessage(programId, signable).toByteString().sha256()
    fun certId(programId, accountId, currency, cardPubKey): ByteString
    fun trimDer(slot: ByteArray): ByteArray   // requires slot.size in 8..72, slot[0]==0x30, (slot[1]&0xFF)+2 in 8..slot.size; throws IllegalArgumentException
    fun padSlot72(der: ByteArray): ByteArray  // requires der.size in 8..72
    fun nextReceiveCounter(last: Int): Int     // last+1; throws IllegalStateException at Int.MAX_VALUE
    fun nextSendSequence(previous: Long, nowMillis: Long): Long = maxOf(previous + 1, nowMillis)  // requires ≥0
}
data class Signable(val dateTime: Long, val sender: ByteArray, val recipient: ByteArray, val currency: ByteArray,
                    val amount: Long, val phoneId: Long, val counter: Int) {
    init { require(sender.size==16 && recipient.size==16 && currency.size==4); require(amount in 1..0xFFFF_FFFFL); require(counter > 0); require(dateTime >= 0) }
    fun encode(): ByteArray /*60, offsets 0/8/24/40/44/48/56, big-endian*/
    companion object { fun decode(b: ByteArray): Signable }
}
data class TransferEnvelope(val signable: ByteArray /*60*/, val signature: ByteArray /*trimmed DER*/, val pubKey: ByteArray /*65*/, val certificate: ByteArray /*trimmed DER*/) {
    fun tail209(): ByteArray = TransferProtocol.padSlot72(signature) + pubKey + TransferProtocol.padSlot72(certificate)
    fun transferId(programId: ByteArray) = TransferProtocol.transferId(programId, signable)
}
data class ReceiveState(val counter: Int, val lastDigest: ByteString)
```
`models/PersonalizationProtocol.kt`:
```kotlin
object PersonalizationProtocol {
    const val FLAG_ENFORCE=0x01; const val FLAG_KEYS=0x02; const val FLAG_PINS=0x04; const val FLAG_PROGRAM=0x08
    fun installParams(enforce: Boolean, keys: Triple<ByteArray,ByteArray,ByteArray>? , pins: Pair<ByteArray,ByteArray>?, program: Pair<ByteArray,ByteArray>?): ByteArray // [0x01][flags]…; require(program==null || keys!=null)
    fun identityPart(accountId, currency, programId, initialReceiveCounter: Int = 0): ByteArray /*40*/  // requires non-zero ids, counter ≥ 0
    fun parsePersonalization(data: ByteArray): CardPersonalization  // exactly 159 bytes
}
data class CardPersonalization(val state: Byte, val flags: Byte, val programId: ByteArray, val currency: ByteArray, val issuerPubKey: ByteArray? /*null if all-zero*/, val certificate: ByteArray? /*trimmed; null if slot all-zero*/) {
    val initialized get() = flags.toInt() and 0x01 != 0; val programBound …0x02; val personalized …0x04; val scp03KeysDefault …0x08; val pinProvisioned …0x10; val provisioningEnforced …0x20; val terminated …0x40
}
```

### 7.2 `ImpalaSDK.kt`
- `fun requireCertifiedProtocol(): ImpalaVersion` — `getImpalaAppletVersion()`; throws `ImpalaException("applet ${major}.${minor} predates the certified transfer protocol (needs 0.2+)")` unless `major > 0 || minor >= 2`.
- `fun personalize(accountId: ByteArray, currency: ByteArray, programId: ByteArray, certificateDer: ByteArray, issuerPubKey: ByteArray? = null, initialReceiveCounter: Int = 0)` — requires open channel (existing `secureTx` throws otherwise); `require` sizes and DER (`trimDer` validity), `issuerPubKey?.let { require(it.size==65 && it[0]==0x04.toByte()) }`; sends `CLA 0x84 INS 0x72 P1=1` (40 B), `P1=2` (65 B, only when `issuerPubKey != null`), `P1=3` (trimmed DER).
- `fun terminate(accountId: ByteArray)` — `secureTx(CommandAPDU(CLA_GP, INS_TERMINATE, 0, 0, accountId))` (CLA rewritten to 0x84 by the channel, as `provisionUserPIN` does).
- `fun rotateScp03Keys(enc, mac, dek)` — typed wrapper over `sendAppletUpdate(0x0001, enc+mac+dek)`.
- `fun getPersonalization(): CardPersonalization` (exactly 159 bytes else `ImpalaException`).
- `fun getReceiveState(): ReceiveState` (exactly 36; counter must have MSB clear).
- `fun getLastTransfer(): Pair<ByteArray, ByteArray>?` — 132 → `(signable60, trimmed DER)`; `null` when the card answers 0x6A83 (`ImpalaCardDataException` with code — catch by SW text "6A83").
- `fun signTransferV2(userPin: String, signable: ByteArray): TransferEnvelope` — same 64-byte payload builder as `signTransfer`; `INS 0x30`; parses 209 = 72‖65‖72 and trims both DER slots.
- `fun verifyTransferV2(env: TransferEnvelope)` and overload `(signable, signature, pubKey, certificate)` — two APDUs `INS 0x31` P1=0/1 (tail = `padSlot72(sig) + pubKey + padSlot72(cert)`).
- `signTransfer`/`verifyTransfer`: kept, `@Deprecated("retired INS 0x06/0x14 — applet 0.2 answers 0x6D00; use signTransferV2/verifyTransferV2")`; `setCardData`, `updateMasterPin`, `getRSAPubKey`, `getNonce`: `@Deprecated("not dispatched by the applet (0x6D00)")` (no behaviour change; `ImpalaSDKTest` MockBIBO tests for them stay).
- `SCP03Channel.kt`: `var keyDiversification: ByteArray = ByteArray(10); private set` assigned from `respData.copyOfRange(0, 10)` at `:80`; `SCP03Constants.kt`: `INS_PERSONALIZE: Byte = 0x72`, `INS_TERMINATE: Byte = 0x73`.
- `models/ImpalaException.kt`: `class ImpalaPersonalizationException(message: String) : ImpalaException(message)`; the `when` arms of §1.2.
- `sdk/build.gradle.kts` `jvm { testRuns["test"].executionTask.configure { … systemProperty("impala.apdu.doc", project.rootDir.resolve("docs/apdu.md").absolutePath) } }` (rootDir = `impala-card/`).

## 8. Tests — `impala-card/sdk/src/jvmTest/kotlin/com/impala/sdk/` (all run by `cd impala-card && ./gradlew :sdk:jvmTest`, no hardware)

### 8.1 Shared fixtures — new `IssuerFixture.kt`
Move `genP256/signP256/verifyP256/uncompressedPoint/jcaPublicKey/pad72/trimDer/swOf/verifyMasterPinCmd` out of `AppletInteropTest` into `internal object Jca` (same package). Add:
```kotlin
val PROGRAM_A = ByteArray(16) { (0xA0 + it).toByte() }; val PROGRAM_B = ByteArray(16) { (0xB0 + it).toByte() }
val USDC = "USDC".encodeToByteArray(); val EUR_ = "EUR ".encodeToByteArray()
fun customKeys() = Triple(ByteArray(16){(0x10+it).toByte()}, ByteArray(16){(0x20+it).toByte()}, ByteArray(16){(0x30+it).toByte()})
fun defaultKeys() = Triple(ByteArray(16){(0x40+it).toByte()}, …)
class TestIssuer(val programId: ByteArray = PROGRAM_A) { val keys = Jca.genP256(); val pub65 = Jca.uncompressedPoint(keys.public as ECPublicKey)
    fun certify(accountId, currency, cardPub65) = Jca.signP256(keys.private, TransferProtocol.certMessage(programId, accountId, currency, cardPub65))
    fun externalSender(accountId: ByteArray, currency: ByteArray = USDC): CertifiedKey }
class CertifiedKey(val accountId, val currency, val keys: KeyPair, val pub65, val cert: ByteArray, val programId) {
    fun sign(signable) = Jca.signP256(keys.private, TransferProtocol.xferMessage(programId, signable))
    fun envelope(signable) = TransferEnvelope(signable, sign(signable), pub65, cert) }
class SeqAllocator { private var last = 0L; fun next() = ++last }   // per-test send-sequence source
fun signable(sender, recipient, amount: Long, counter: Int, seq: SeqAllocator, currency = USDC, phoneId = 0L) = Signable(seq.next(), sender, recipient, currency, amount, phoneId, counter).encode()
class PersonalizedCard(val sdk: ImpalaSDK, val accountId: ByteArray, val pub65: ByteArray, val cert: ByteArray, val keys: Triple<…>)
fun personalizedCard(issuer: TestIssuer, accountId: ByteArray, currency = USDC, userPin = "1111", initialCounter = 0, bindAtInstall = false): PersonalizedCard
   // install [0x01, 0x03 (|0x08 if bindAtInstall)] + keys (+ programId + issuer.pub65); sdk = ImpalaSDK(bibo, customKeys()); setSeed(); pub = getECPubKey();
   // cert = issuer.certify(accountId, currency, pub); openSecureChannel(); personalize(accountId, currency, issuer.programId, cert, issuerPubKey = if (bindAtInstall) null else issuer.pub65, initialCounter); provisionUserPIN(userPin); closeSecureChannel()
fun fund(card: PersonalizedCard, from: CertifiedKey, amount: Long, seq: SeqAllocator) { val c = TransferProtocol.nextReceiveCounter(card.sdk.getReceiveState().counter); card.sdk.verifyTransferV2(from.envelope(signable(from.accountId, card.accountId, amount, c, seq))) }
fun swOf(e: ImpalaException) = e.message  // assertions use assertTrue(msg.contains("6233")) as today, or assertFailsWith<Type>
```

### 8.2 Existing interop tests that change (`AppletInteropTest.kt`)
| Test (current line) | Change |
|---|---|
| `plain commands round-trip` (:54) | `assertEquals(2, version.minor)`; nil-UUID assertion stays |
| `verifyTransfer credits and signTransfer debits…` (:86) | replaced by 8.3 #C1/#C3 |
| `verifyTransfer rejects replays…` (:120) | replaced by #K1 |
| `never accepts a zero or negative counter` (:168) | replaced by #K3 |
| `sign auth … pinned domain-tagged message` (:198) | personalized fixture with accountId `00112233-4455-6677-8899-aabbccddeeff`; assert `verifyP256(pub, domainTag + uuid + challenge, sig)` and that `(domainTag + uuid).toHex() == "494d50414c412d415554483a00112233445566778899aabbccddeeff"` (bridge golden `card_auth.rs:404`); negatives unchanged |
| `sign auth accepts 8 to 64…` (:223) | personalized fixture |
| `failed PIN-less transfers do not burn…` (:247) | personalized card A + issuer external sender; V2 INS; each signable gets a fresh seq; `assertFailsWith<ImpalaInsufficientFundsException>` on zero balance; budget/reset assertions unchanged |
| `empty install parameters…` (:316) | after `setSeed()`: `assertFailsWith<ImpalaPersonalizationException> { signAuthChallenge }` (0x6234) — "no PIN gate" is still exact; SCP03-over-defaults part stays |
| `install-time key and PIN injection…` (:327) | unchanged |
| `provisioning enforcement gates signing…` (:353) | install `[0x01,0x01]`; `setSeed`; 0x6985 asserts stay; open channel with defaults → `provisionUserPIN` → **0x6236**; `rotateScp03Keys(customKeys)`; close; reopen with custom keys; `provisionUserPIN("2468")` OK; `signAuthChallenge` → 0x6234; `personalize(...)` → `signAuthChallenge` succeeds |
| `install-time PIN injection satisfies…` (:373) | install `[0x01,0x07]` + keys + pins; `setSeed`; `signAuth` → 0x6234; personalize over custom keys (no PROVISION_PIN) → signs (ENFORCE satisfied by install PINs) |
| `malformed install parameters…` (:382) | add: `[0x01,0x08] + program block` (0x08 without 0x02) fails; `[0x01,0x0A] + keys + zero programId` fails; `[0x01,0x02] + 0x40..0x4F×3` fails |
| all others | unchanged (default-key SCP03/PIN tests keep working: non-ENFORCE) |

### 8.3 New interop tests (new file `CertifiedTransferInteropTest.kt`; personalization ones in `PersonalizationInteropTest.kt`)
Personalization (P):
- P1 `personalize commits identity, issuer key, certificate and initial counter atomically` — `getAccountId()` == UUID; `getPersonalization()`: state 0x02, flags has initialized|programBound|personalized|pinProvisioned|provisioningEnforced and NOT scp03KeysDefault, programId/currency echo, issuerPubKey == issuer.pub65, certificate == JCA DER; `getReceiveState().counter == initialCounter` (run with 0 and with 4711).
- P2 `personalize is refused over default SCP03 keys` — install `[0x01,0x01]`, `setSeed`, open with defaults: part A → 0x6236; `provisionUserPIN` → 0x6236; after `rotateScp03Keys` + reopen both succeed.
- P3 `personalize twice is refused` → 0x6235; state unchanged.
- P4 `certificate over the wrong key/account/currency/program is refused and the card stays unpersonalized` — four variants → 0x6677; `getPersonalization().state == 0x01`, `programBound == false`; a correct ceremony afterwards succeeds (retry property).
- P5 `parts out of order are refused` — C first → 0x6237; B first → 0x6237; A,C (no B, not bound) → 0x6237; A then A' (new identity) then C with cert for A' succeeds (A resets the stage).
- P6 `personalize rejects nil account, zero currency, zero program, negative initial counter, non-0x04 issuer key, malformed DER, wrong lengths` → 0x6A80 ×6, 0x6700 for Lc 39/41/64/73; before INITIALIZE → 0x6230; P2 ≠ 0 → 0x6A86; P1 = 4 → 0x6A86.
- P7 `personalize without C-DEC is refused` — open at level 0x11 → 0x6982; CLA 0x00 INS 0x72 → 0x6D00; CLA 0x84 without session → 0x6985.
- P8 `program bound at install: part B refused, part A with another programId refused, A then C succeeds` — `bindAtInstall = true`; B → 0x623B; A(PROGRAM_B) → 0x623B; A(PROGRAM_A),C → 0x9000; `getPersonalization().issuerPubKey == issuer.pub65` before personalization (flags programBound set, state 0x01).
- P9 `install or update with the GP default key bytes is refused` — install fails; `rotateScp03Keys(defaults)` → 0x6684 and the old keys still open a channel.
- P10 `SCP03 key diversification reports the card id` — `sdk.openSecureChannel(); channel.keyDiversification == getUserData().cardId bytes[0..10)` (before and after INITIALIZE, values differ and each matches the then-current cardId).
- P11 `APPLET_UPDATE with an unknown sequence answers 6A86 and changes nothing` — `sendAppletUpdate(2, ByteArray(4))` → 0x6A86; keys unchanged.
- P12 `terminate blocks signing and is irreversible` — `terminate(accountId)`: `isCardAlive()` false; `signTransferV2` → 0x6687; `signAuthChallenge` → 0x6687; GET_BALANCE/GET_PERSONALIZATION (state 0xFF, flags terminated) readable; second terminate → 0x6687; wrong accountId → 0x6A80 and card still alive; without C-DEC → 0x6982; over default keys (non-ENFORCE card) → 0x6236.
- P13 `GET_EC_PUB_KEY before INITIALIZE answers 6230`.
- P14 `retired INS 06 and 14 answer 6D00` — raw APDUs on a personalized card.
- P15 `transfer commands refuse the secured CLA` — `secureTx(INS 0x30/0x31/0x34/0x36)` → 0x6E00; `secureTx(GET_RECEIVE_STATE)` → 36 bytes.

Certified transfer chain (C):
- C1 `certified card-to-card transfer credits the recipient and verifies host-side over the tagged message` — cards A, B under PROGRAM_A (fund A 1000 from treasury); `env = A.signTransferV2("1111", s)`; `B.verifyTransferV2(env)`; balances 750/250; JCA: `verifyP256(pubA, xferMessage(PROGRAM_A, s), env.signature)` true, `verifyP256(pubA, s, env.signature)` **false**, `verifyP256(issuer.pub, certMessage(PROGRAM_A, acctA, USDC, pubA), env.certificate)` true; `B.getReceiveState().lastDigest == transferId(PROGRAM_A, s)`.
- C2 `uncertified key is rejected before any credit` — external JCA key, valid tagged signature, cert slot = zeros (DER-invalid → 0x6A80) and cert slot = self-signed 8..72-byte DER → 0x0022; balance and receive state unchanged.
- C3 `certificate for another account or currency is rejected` — cert for A, signable sender = C's UUID signed by C's key → 0x0022; sender A but cert minted for EUR → 0x0022.
- C4 `untagged v0 signature is rejected` — certified key, signature over the bare 60 bytes → 0x0023; signature over a message with PROGRAM_B tag → 0x0023.
- C5 `cross-program transfer is rejected` — sender personalized under PROGRAM_B (same issuer key) → 0x0022.
- C6 `transfer to self is rejected on both sides` — SIGN_V2 recipient == own accountId → 0x6232; VERIFY_V2 sender == me → 0x6231.
- C7 `currency mismatch is rejected on both sides` → 0x6229.
- C8 `zero amount is rejected on both sides` → 0x6239.
- C9 `unpersonalized card signs and credits nothing` — INITIALIZED card: SIGN_AUTH, SIGN_V2, VERIFY_V2 P1=0 and P1=1 → 0x6234.
- C10 `SIGN_TRANSFER_V2 response slots are zero-padded and slot 3 equals the personalization certificate` — bytes after the DER length in both 72-byte slots are zero; `slot3.trim == getPersonalization().certificate`.
- C11 `bridge-style load is an ordinary certified transfer` — treasury (host JCA key certified with accountId = treasury UUID) → card; balance credited (the F1-load leg).
- C12 `malformed tails are refused before crypto` — DER length byte 0x80 → 0x6A80; sig slot `30 46…` (72 > available? no: use 0x30 0x47 → 73) → 0x6A80; pubkey[0]=0x02 → 0x6A80; tail without P1=0 staging → 0x6985; P1=2 → 0x6A86; invalid EC point → 0x6683 or 0x0022 (either; pins no 0x6F00).
- C13 `two personalized cards conserve value` — treasury→A 1000; A→B 250 (PIN); B→A 100 (PIN-less "0000"); assert A=850, B=150, sum 1000; `A.getReceiveState().counter == 2`, `B == 1`; `A.getLastTransfer()` == (A→B signable, its sig); `B.getLastTransfer()` == (B→A …); digests equal the respective transferIds.
- C14 `balance overflow is refused before the transaction` — fund A with 0xFFFFFFFF ×… (use a treasury with repeated max-amount loads until near 2⁶⁴; skip if impractical → instead assert a single credit into a card whose balance is `2⁶⁴ − 1000` is impossible to construct without a setter — **implement as a pure test of `computeCredit` semantics by driving the applet with a receiver at balance 0 and a 0xFFFFFFFF amount, then asserting the second identical-size credit still succeeds (no overflow) and `myBalance` is exactly 2·0xFFFFFFFF**); documented as the reachable bound.

Counters and sequences (K):
- K1 `counter replay is rejected` — full two-phase replay → 0x6233; tail-only replay → 0x6985 (stage consumed); stale/equal counter → 0x6233; gap of 5 accepted (ports `:119-165`); receive state tracks L and digest.
- K2 `counter jump beyond MAX_COUNTER_JUMP is refused with 623A` — L=1: c=1025 accepted, then c=L+1025 → 0x623A, c=L+1024 accepted; near the top: personalize with `initialCounter = 0x7FFFFBFF`, c=0x7FFFFFFF accepted (clamp), any further → 0x6233.
- K3 `zero and negative counters are never accepted; the sender refuses to sign them` → VERIFY 0x6233; SIGN_V2 counter 0 / −1 → 0x6233, balance unchanged (ports `:167-188`).
- K4 `identical signable retry replays the cached response without a second debit` — two identical `signTransferV2` calls return byte-identical 209 bytes; balance debited once; PIN-less budget consumed once; retry with a wrong PIN still replays (no 0x69Cx); a different signable debits again.
- K5 `send sequence must strictly increase` — dateTime lower than the last → 0x6238; equal dateTime with a different body → 0x6238; dateTime 0 on a fresh card → 0x6238; MSB set → 0x6238; balance unchanged.
- K6 `last transfer record is readable after a signed transfer` — `getLastTransfer()` == (signable, trimmed sig); `null` before any transfer (0x6A83).
- K7 `replacement card with an initial counter floor refuses envelopes the lost card already accepted` — card A1 accepts c=1..3; A2 personalized with same accountId, new key, `initialCounter = 3`; the c=2 and c=3 envelopes → 0x6233; c=4 accepted.

### 8.4 Pure / MockBIBO tests
- `TransferProtocolGoldenTest.kt` (new): `xferMessage`/`certMessage` for the §3.3 fixture equal the pinned hex; `transferId` == `6b3c27…67b9`, `certId` == `82cb58…b77b`; tag bytes `49 4D 50 41 4C 41 2D 58 46 45 52 3A` / `…43 45 52 54 3A`; lengths 89/114; `Signable.encode/decode` round trip and offsets 0/8/24/40/44/48/56; amount `0` and `0x1_0000_0000` rejected, `0xFFFF_FFFF` accepted; `trimDer`/`padSlot72` bounds; `nextReceiveCounter(Int.MAX_VALUE)` throws; `nextSendSequence(5, 3) == 6`, `(5, 9) == 9`; `PersonalizationProtocol.installParams` layouts (`[01 0B] + 48 + 81`, program without keys throws); `identityPart` 40 bytes; `parsePersonalization` rejects 158/160 and nulls all-zero key/cert.
- `ImpalaSDKTest.kt` (MockBIBO): `signTransferV2 sends INS 30 with Nc 64 and parses 209`; `verifyTransferV2 sends INS 31 P1 0 then 1 with Nc 60/209`; `getPersonalization rejects sizes other than 159`; `getReceiveState parses 36`; `getLastTransfer maps 6A83 to null`; `requireCertifiedProtocol rejects 0.1 and accepts 0.2 / 1.0`; `personalize throws without an open channel`; deprecated wrappers unchanged.
- `ExceptionMappingTest.kt`: one case per row of §1.2 (class + message contains the hex); `0xABCD` unchanged.
- `ConstantsTest.kt`: values 0x30/0x31/0x34/0x35/0x36/0x72/0x73; uniqueness list extended with the seven new INS (and `SCP03Constants.INS_PROVISION_PIN/INS_APPLET_UPDATE/INS_PERSONALIZE/INS_TERMINATE` in a second list asserting no overlap with application INS); SW values pinned; `MAX_COUNTER_JUMP == 1024`; `TRANSFER_PROTOCOL_VERSION == 1`.
- `ApduDocTest.kt` (new, doc tripwire): reads `System.getProperty("impala.apdu.doc")` (fails with a clear message if unset); splits `apdu.md` on `^## ` headings; from "Application commands", "SCP03 secure channel" and "Retired" tables collects rows matching ``^\|\s*`0x([0-9A-Fa-f]{2})`\s*\|\s*([A-Z0-9_ ]+?)\s*\|``; asserts (a) the set of application-table INS equals the hardcoded `DISPATCHED_APP_INS` mirror `{02,04,16,18,19,1E,1F,20,21,22,24,25,2C,2E,30,31,34,35,36,64}`, (b) the SCP03 table equals `{50,82,70,71,72,73}`, (c) retired equals `{06,14}`, (d) every name resolves by reflection (`Constants::class.java.getField("INS_"+name.replace(' ','_'))`, else `SCP03Constants`, else the GP names `INITIALIZE_UPDATE`/`EXTERNAL_AUTHENTICATE`) to a byte equal to the row's hex, (e) the "Common status words" section contains a ``0xXXXX`` cell for each of `6233 6234 6235 6236 6237 6238 6239 623A 623B 6A80 6984 6A83 6E00 0022 6677 6683 6684 6688 6A86`, (f) the "Declared but not dispatched" table equals `{07,23,26,2B,2D}`.

## 9. Documentation

### 9.1 `impala-card/docs/apdu.md` (edit in place)
- Header: "Applet 0.2 / transfer protocol v1 (applet 0.1 = protocol v0, retired)". CLA section: state the secured caps (≤ 113 plaintext, ≤ 111 with C-DEC; responses ≤ 111) and that 0x30/0x31/0x34/0x36 are CLA 0x00 only (0x6E00).
- Application table: delete the `0x06`/`0x14` rows; add `0x30 SIGN_TRANSFER_V2` (payload, 209 response = sig ‖ pubkey ‖ **certificate**, gates: not terminated, provisioning, personalized; PIN/PIN-less; idempotent replay; SW list), `0x31 VERIFY_TRANSFER_V2` (P1 semantics, check order, every SW), `0x34 GET_PERSONALIZATION`, `0x35 GET_RECEIVE_STATE`, `0x36 GET_LAST_TRANSFER`; SIGN_AUTH row gains "personalized (0x6234)"; GET_EC_PUB_KEY row: "0x6230 before INITIALIZE".
- Notes: replace the "not domain-tagged…" paragraph (`:55-63`) with pointers to `transfer-protocol.md` plus the one-paragraph rules (currency always, amount ≥ 1, counter rule, send sequence = strictly increasing, never a timestamp).
- New "Retired — dispatch removed, never reuse" table (`0x06`, `0x14`, reason); "Declared but not dispatched" unchanged; add the sentence reserving `0x32`/`0x33`.
- Delete both "Known gap" boxes (`:86-94`, `:169-172`); the auth-flow section says the flow completes with a personalized card and that the bridge's `rsa_pubkey` requirement is a separate bridge gap (cross-reference, do not claim fixed).
- SCP03 table: add `0x72 PERSONALIZE` (3 parts, C-DEC required, gates) and `0x73 TERMINATE`; note APPLET_UPDATE atomicity, unknown seq → 0x6A86, default-key refusal 0x6684, diversification = cardId[0..10), install flag 0x08 (+81 bytes, needs 0x02), "PROVISION_PIN over default keys is refused when ENFORCE", and the honesty statement (§5).
- SW table: every row of §1.2 plus `0x6688` "SCP03 C-MAC verification failed (collides with the NPE code; retained for host compatibility)".
- "Writing new APDUs": add steps 6 "add the SW to `ImpalaException.fromStatusWord` + `ExceptionMappingTest`", 7 "if it changes signed bytes: golden test in `TransferProtocolGoldenTest` and `impala-bridge/src/handlers/card_auth.rs`", 8 "`ApduDocTest` parses this file — keep the table shapes".

### 9.2 `impala-card/docs/transfer-protocol.md` (new, normative)
Sections: 1 Lifecycle (§2.1 diagram + state/flags bytes); 2 Card key certificate (§3.1, custody: program key never on a card/terminal; bridge-side install-only via `/admin/keys*`, fingerprint-only responses; rotation = new programId + re-issue); 3 Transfer envelope v1 (§3.2, §3.4, transfer_id, dateTime semantics); 4 Golden vectors (§3.3, byte-exact); 5 Personalization ceremony (§3.5, §3.6, §5, crash recovery, idempotency); 6 Receive counter and send sequence (§6 verbatim, incl. decision table, allocation, stranded transfers, resync, replacement, window decision); 7 Protocol versions — v0 ↔ v1 both-direction failure table (0.1 sender → 0.2 receiver: zero cert slot fails DER → 0x6A80 / a v0 raw signature → 0x0023; 0.2 sender → 0.1 receiver: 0x6D00 on INS 0x30 — the old receiver never sees v1) and the reflash rule (`gp --delete/--install` wipes state; no in-place upgrade, `ImpalaApplet.java:698-701`); 8 Claims → tests table (every test of §8.3 with the claim it evidences); 9 Physical-card checklist template (manual; CI never claims it): CAP sha256, `GET_VERSION`, two cards, ceremony §5 by hand, C13 by hand, tear tests (pull the card during SIGN_V2 after the PIN and during VERIFY_V2 P1=1; before/after `GET_BALANCE`, `GET_RECEIVE_STATE`, `GET_LAST_TRANSFER`; assert the §6.4 decision table), `JCSystem.getMaxCommitCapacity() ≥ 256`, `setIncomingAndReceive` precondition, recorded as a table (cardId, CAP sha256, version, balances, counters, SWs).

### 9.3 `impala-card/README.md` (rewrite; keep "Toolchain: JDK 17" verbatim)
1. Lines 3-7 → "Offline Payala stored-value transfer between issuer-certified cards, reconciled and settled through the bridge. Not an on-chain payment." Define **LUK** once (limited-use / issuer-certified card key; the certificate travels in the third SIGN_TRANSFER_V2 slot and is verified on the receiving card) and delete "does not support offline LUKs; only online transactions are supported".
2. Threat-scoped claim (reviewer Priority 1 wording): "A correctly personalized, non-compromised card atomically debits its local balance before releasing a transfer signature; a receiving card accepts a credit only from an issuer-certified key bound to the signable's sender, currency and program, and rejects repeated, non-increasing or out-of-bound counters." Then the dependency list: issuer-key custody, terminal integrity (live-read counter, synchronous delivery, no re-sign), card anti-cloning, bridge reconciliation/quarantine (`impala-bridge/SECURITY.md`), backend integrity, bridge custody.
3. Capability matrix (reviewer's columns; cells from evidence only): Card issuance / Offline debit / Offline credit / Issuer-key verification / Multi-hop onward spending — Implemented ✓, jcardsim ✓ (name the test), physical card "no evidence in repo", without network ✓, production ✗; Reconciliation / Stellar redemption — "not in this repo (bridge follow-up)".
4. "Issuance ceremony" (§5 incl. the exact `gp --params` hex and the SCP03 key policy), "Counter model" summary (§6.1-6.3), "Lost card / replacement" (§6.6), "Compatibility: applet 0.1 CAPs" (§10), "Reference" → `docs/apdu.md`, `docs/transfer-protocol.md`.
5. Delete "Supported APDUs" (`:26-276`) entirely (50/51, RSA, Update Master PIN, Set Card Data, 24-byte SIGN_AUTH, 7-byte hash). Version note: GET_VERSION = 10 bytes `major2 minor2 rev2 hash4`; applet 0.2 = certified protocol.

### 9.4 Cross-references (minimal required edits; the docs area owns the wider rewrite)
- `CHANGELOG.md` `[Unreleased] ### Added`: "**impala-card 0.2: issuer-certified transfer protocol.**" entry naming INS 0x30/0x31/0x34/0x35/0x36/0x72/0x73, the retired 0x06/0x14, the SW table, `dateTime` = send sequence, the reflash consequence, and an explicit **[not left open]** list: currency checked on receive; zero amount refused; DER bounds; VERIFY bad P1 → 0x6A86; deterministic 209-byte response; GET_EC_PUB_KEY pre-INITIALIZE → 0x6230; APPLET_UPDATE unknown seq → 0x6A86 and atomic key set; overflow checked before the transaction; `setIncomingAndReceive` at the top of `process()`; PROVISION_PIN over default keys refused under ENFORCE; `terminated` reachable.
- `ARCHITECTURE.md:317-372`: "23 APDU commands" → "20 application + 6 SCP03-path"; drop RSA/GET_CARD_NONCE/SET_CARD_DATA; SIGN_AUTH = challenge; SCP03 subgraph labelled CLA 0x84; state table adds `programId, issuerPubKey, programBound, cardCert, personalized, scp03KeysCustom, lastReceiveCounter, lastReceiveDigest, lastSentSignable, lastSentSig, howManyPINless, provisioningEnforced, pinProvisioned`.
- `impala-bridge/SECURITY.md` §Card (after line 200): add the two transfer/cert domain prefixes and "the bridge verifies the certificate at `POST /card` and at reconciliation (follow-up); until then card-derived balances stay quarantined".

### 9.5 CI and release
- `.github/workflows/impala-card.yml:218-219`: `if: failure()` → `if: always()`, step name "Upload test reports".
- After merge: `git tag impala-card-v0.2.0 && git push origin impala-card-v0.2.0` (the existing release job emits both CAPs + SDK zip + `SHA256SUMS`).

### 9.6 Bridge mirror (only the constant/golden part is in this area)
`impala-bridge/src/constants.rs` (next to `CARD_AUTH_DOMAIN_PREFIX`, each with `#[allow(dead_code)] // consumed by POST /card certificate verification (bridge follow-up); pinned by golden tests`): `CARD_XFER_DOMAIN_PREFIX: &[u8;12] = b"IMPALA-XFER:"`, `CARD_CERT_DOMAIN_PREFIX: &[u8;12] = b"IMPALA-CERT:"`, `CARD_TRANSFER_PROTOCOL_VERSION: u8 = 1`, `CARD_CERT_VERSION: u8 = 1`, `CARD_PROGRAM_ID_BYTES: usize = 16`, `CARD_XFER_MESSAGE_BYTES: usize = 89`, `CARD_CERT_MESSAGE_BYTES: usize = 114`, `CARD_RECEIVE_COUNTER_MAX_JUMP: u32 = 1024`. `impala-bridge/src/handlers/card_auth.rs`: `#[allow(dead_code)] pub(crate) fn build_card_xfer_message(program_id: &[u8;16], signable: &[u8;60]) -> Vec<u8>` and `build_card_cert_message(program_id, account_id: &uuid::Uuid, currency: &[u8;4], card_pubkey: &[u8;65]) -> Vec<u8>`; tests `golden_xfer_domain_prefix_bytes`, `golden_cert_domain_prefix_bytes`, `golden_xfer_message_layout` (hex of §3.3 and `sha256 == 6b3c27…67b9` via `aws_lc_rs::digest`), `golden_cert_message_layout` (hex of §3.3). Must pass `cargo clippy -- -D warnings` and `cargo test golden_`.

## 10. Compatibility statement
- Unchanged and still golden-pinned: SIGN_AUTH message and `POST /auth/card`; GET_USER_DATA / GET_ACCOUNT_ID / GET_BALANCE / GET_VERSION layouts; SCP03 wire format and key version 0x02; install TLV tag/flags (new bit 0x08 only); PIN digit encoding.
- Behaviour changes visible to existing clients: SIGN_AUTH on an unpersonalized card → 0x6234 (Android demo login against a blank card fails at the card instead of a bridge 401); GET_EC_PUB_KEY pre-INITIALIZE → 0x6230 (the demo must INITIALIZE first — registration already needs the post-INITIALIZE cardId; an all-zero key was a bridge 400 anyway); INS 0x06/0x14 → 0x6D00 (no repo client calls them); INITIALIZE UPDATE diversification bytes are now cardId[0..10) (SDK ignored them).
- Already-flashed dev CAPs (0.1): answer 0x6D00 to every new INS and keep signing v0; 0.2 receivers refuse v0 envelopes (0x6A80/0x0022/0x0023). No in-place upgrade: reflash + ceremony. `requireCertifiedProtocol()` stops the SDK driving V2 flows against 0.1.
- Bridge follow-ups this spec assumes but does not implement: optional `certificate`/`program_id`/`currency` on `POST /card` (migration + openapi additive), `CARD_PROGRAM_ID`/`CARD_ISSUER_PUBKEY` config, treasury key under `/admin/keys*` with reserve-hold journaling before any load signature, envelope settlement with the three unique anchors.

## 11. Implementation order (each step leaves `./gradlew :sdk:jvmTest` green)
1. `Constants.java` + `Constants.kt` + `SCP03Constants.kt` registry (§1); `ImpalaException` class + mapping; `TransferProtocol.kt`, `PersonalizationProtocol.kt`; pure tests (`TransferProtocolGoldenTest`, `ExceptionMappingTest`, `ConstantsTest`).
2. `ArrayUtil.addUnsignedShort`; `SCP03.getSecurityLevel`/`setDiversificationSource`/260 comment; applet fields + constructor; `scp03KeysCustom` + default-key refusal + atomic APPLET_UPDATE + unknown-seq 0x6A86 + PROVISION_PIN gate + install flag 0x08 + `setIncomingAndReceive` hoist + `CryptoException` catch; tests P2, P9, P10, P11 and the install-param rewrites.
3. PERSONALIZE / TERMINATE / GET_PERSONALIZATION + SDK methods; tests P1, P3-P8, P12, P13; `IssuerFixture.kt`.
4. SIGN_V2 / VERIFY_V2 / GET_RECEIVE_STATE / GET_LAST_TRANSFER; remove 0x06/0x14 cases, `makeHashable`, `SIXTY_FOUR_ZEROES`, `addToBalance`, `Hashable.java`, `CryptoPrimitivesConverter.java`; personalized gate on SIGN_AUTH; GET_EC_PUB_KEY 0x6230; tests C1-C14, K1-K7, P14, P15; port the modified tests (§8.2); `ImpalaSDKTest` additions.
5. `BuildConfig.MINOR_VERSION = 2`, `build.xml` 0.4; `sdk/build.gradle.kts` system property + `ApduDocTest`; docs (§9.1-9.4); CI flip; bridge constants + goldens (§9.6).
6. Tag `impala-card-v0.2.0`.

## 12. Acceptance checks
- `cd impala-card && ./gradlew :sdk:jvmTest --no-daemon` passes with every test named in §8 present (grep the JUnit XML for each name); `./gradlew :applet:buildJavacard` produces a CAP (verify=true).
- `cd impala-bridge && cargo test golden_ && cargo clippy -- -D warnings`.
- `grep -n "SIXTY_FOUR_ZEROES\|makeHashable\|case INS_SIGN_TRANSFER:\|case INS_VERIFY_TRANSFER:" impala-card/applet/src/jvmMain/java/com/impala/applet/ImpalaApplet.java` → no matches; `grep -c "0x6233" impala-card/applet/src/jvmMain/java/com/impala/applet/Constants.java` ≥ 1 and `ImpalaApplet.java:71`-style local declaration gone.
- `ApduDocTest` fails when any INS row is removed from `docs/apdu.md` (verify once by a local edit, then revert).
- `impala-card/README.md` contains the capability matrix, the LUK definition, the Priority-1 claim sentence, and no occurrence of "Ext Pubkey", "RSA", "Update Master PIN", "Set Card Data".
- Golden hex strings of §3.3 appear verbatim in `docs/transfer-protocol.md`, `TransferProtocolGoldenTest.kt` and `card_auth.rs`.
- CI workflow uploads test reports `if: always()`.