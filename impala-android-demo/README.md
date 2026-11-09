# Impala Android Demo

Android demo application for Payala-Impala, demonstrating authentication (password, Google, GitHub, Okta, smartcard), card registration, card-authorized transfers, settings, and the **Card Lab** — read-only JavaCard troubleshooting that also ships in release builds. Communicates with the [impala-bridge](../impala-bridge) REST API.

## Requirements

- Android Studio Hedgehog (2023.1.1) or later
- JDK 17 to launch Gradle (bytecode targets 17). Unit tests run on a Java 21
  toolchain — Robolectric's SDK-36 sandbox requires it — which
  `settings.gradle.kts` auto-provisions via the foojay resolver if no JDK 21 is
  installed.
- Android SDK 37 (compileSdk / targetSdk)
- minSdk 24 (Android 7.0)

## Quick Start

The app has two product flavors on the `network` dimension — `tnet` (Stellar
testnet) and `live` (Stellar pubnet) — which install side-by-side (the `tnet`
build adds the `.testnet` applicationId suffix). The flavor token is `tnet`
rather than `testnet` because the Android Gradle Plugin forbids flavor names
that start with `test`.

```bash
cd impala-android-demo
./gradlew assembleTnetDebug      # testnet APK -> app/build/outputs/apk/tnet/debug/
./gradlew assembleLiveDebug      # pubnet APK  -> app/build/outputs/apk/live/debug/
./gradlew testTnetDebugUnitTest testLiveDebugUnitTest   # JVM unit tests
```

Or open the project in Android Studio and run on an emulator or device.

### Firebase config (`app/google-services.json`)

The app applies the `com.google.gms.google-services` plugin (Firebase Cloud
Messaging), so **every** variant build — including `testTnetDebugUnitTest` —
fails with `File google-services.json is missing` until that file exists.
`app/google-services.json` is gitignored, so a fresh clone has none. Seed the
committed placeholder:

```bash
cp app/google-services.json.example app/google-services.json
```

The placeholder satisfies the plugin and leaves FCM inert (push registration
will not work); replace it with the real Firebase config to exercise push. CI
does the same copy — see the "Provision placeholder google-services.json" step
in `.github/workflows/impala-android.yml`, which never overwrites an existing
file.

## Configuration

Build config fields are defined in `app/build.gradle.kts` and sourced from
flavor-prefixed keys in `local.properties` — `TESTNET_*` for the `tnet` flavor,
`LIVE_*` for the `live` flavor (see `local.properties.example`). Replace the
placeholder values before testing:

| Field | Default | Description |
|-------|---------|-------------|
| `BRIDGE_BASE_URL` | `http://10.0.2.2:8080` (tnet), `https://api.impala.example.com` (live) | Bridge API URL (`10.0.2.2` is the emulator's loopback to the host machine) |
| `STELLAR_NETWORK` | `testnet` (tnet), `pubnet` (live) | Fixed per flavor, not read from `local.properties`. The Card Lab compares it with the bridge's `/health` `stellar_network` and raises a danger banner when they differ |
| `CARD_APPLET_AID` | `01020304050607080102` (tnet), empty (live) | The applet AID every card session SELECTs (`TESTNET_CARD_APPLET_AID` / `LIVE_CARD_APPLET_AID`). Empty means no SELECT: the card's default-selected applet answers. The same value also feeds the `impala_card_applet_aid` string resource (`resValue`), which the manifest hands to impala-lib (see below) |
| `GITHUB_CLIENT_ID` | `YOUR_GITHUB_CLIENT_ID` | GitHub OAuth App client ID |
| `GITHUB_REDIRECT_URI` | `impala://github-callback` | GitHub OAuth redirect URI (must match the OAuth App settings) |
| `GOOGLE_WEB_CLIENT_ID` | `YOUR_GOOGLE_WEB_CLIENT_ID` | Google Cloud Console Web client ID for Credential Manager |
| `OKTA_ISSUER_URL` | empty | Okta issuer; while it is empty the "Continue with Okta" button is hidden |
| `OKTA_CLIENT_ID` | empty | Okta OIDC client ID |
| `OKTA_REDIRECT_URI` | `impala://okta-callback` | Okta redirect URI, caught by `OktaRedirectActivity` |

There is no GitHub client-secret field: the bridge performs the OAuth
code→token exchange server-side (`POST /auth/github {code, redirect_uri}`),
so the secret is configured on the bridge and never ships in the APK.

**Applet AID for system-dispatched taps.** A card tapped while no Impala
screen is in the foreground goes to impala-lib's `NfcContactActivity`, which
reads the AID from application-level meta-data in `AndroidManifest.xml`:

```xml
<meta-data android:name="com.payala.impala.CARD_APPLET_AID"
           android:resource="@string/impala_card_applet_aid" />
```

It is a string resource (`resValue`, which needs `buildFeatures.resValues =
true` on AGP 9), not `android:value`, because AAPT2 types an all-digit AID such
as the testnet one as a float. `ManifestTest` pins the resource to
`BuildConfig.CARD_APPLET_AID` in both flavors. To check an installed build:
`adb shell dumpsys package com.payala.impala.demo.testnet | grep -A2 CARD_APPLET_AID`.

**Simulated card (debug builds only).** The emulator has no NFC. With
`adb shell setprop debug.impala.tcp_card 127.0.0.1:9443` (after
`adb reverse tcp:9443 tcp:9443`), or `10.0.2.2:9443` without the reverse,
every card request in a debug build is served by impala-card's
`SimulatorApduServer` (`./gradlew :simulator:serve --args="--port 9443"` in
`../impala-card`; issue the card with the issuance tool, see
`impala-card/README.md`). Clear it with `setprop debug.impala.tcp_card ""`.
Release builds compile a stub that is never configured; there is no UI switch.

### Running with impala-bridge

Start the bridge server on the host machine:

```bash
cd ../impala-bridge
docker compose up     # starts Postgres + Redis + bridge on :8080
```

The Android emulator can reach the host at `10.0.2.2:8080` (the default `BRIDGE_BASE_URL`).

## Architecture

```
com.payala.impala.demo
├── ImpalaApp.kt                  Application: TokenManager, and routes impala-lib log lines into AppLogger ("lib." tags)
├── api/
│   ├── BridgeApiService.kt       Retrofit interface for all bridge endpoints
│   ├── ApiClient.kt              Retrofit singleton; debug HTTP logging at HEADERS with credentials redacted
│   ├── AuthInterceptor.kt        Attaches the JWT (refreshing it first when it is about to expire)
│   ├── TokenAuthenticator.kt     On 401: one refresh via TokenRefresher, then one retry
│   ├── TokenRefresher.kt         The single mid-session refresh (refresh token → temporal token)
│   ├── RetryInterceptor.kt       Bounded retries for GETs on I/O failure or 5xx
│   └── BridgeErrors.kt           Parses the bridge's {"error": {code, message}} envelope
├── model/                        Auth, account, card, notify, offline (issuer/issuance/redemption) and transfer DTOs
├── auth/
│   ├── TokenManager.kt           Encrypted token storage (EncryptedSharedPreferences)
│   ├── GoogleAuthHelper.kt       Google Sign-In via Credential Manager
│   ├── GitHubAuthHelper.kt       GitHub OAuth via Custom Tabs (+ GitHubRedirectActivity)
│   └── OktaAuthHelper.kt         Okta OIDC (+ OktaRedirectActivity)
├── card/
│   ├── CardStore.kt              Per-account local record of registered cards (survives logout)
│   ├── TapProgress.kt            Non-card progress steps (CONTACTING_BRIDGE) reported to the tap sheet
│   ├── ApduTraceLog.kt           Debug only: header-only exchanges of the last 20 production taps
│   ├── SimulatorStatus.kt        READY / BUSY / DOWN of the simulated card
│   └── DebugCards.kt             debug: simulated card over TCP (emulator lane); release: stub
├── log/
│   ├── AppLogger.kt              In-app log: 1 000-entry ring, ISO-8601 UTC timestamps, live listeners
│   └── LogFilter.kt              Level set + text query for the Activity Log
├── push/ImpalaPushService.kt     FCM messages and device-token registration
├── transfer/
│   ├── Money.kt                  Integer minor-unit parsing/formatting (no floating point)
│   ├── PendingTransferStore.kt   Durable in-flight redemptions/credits (written before the card signs)
│   ├── RedemptionController.kt   Card → bridge: prepare, sign (PIN), submit, track; never re-sign
│   └── IssuanceController.kt     Bridge → card: create, fund, await, apply credit, ack
└── ui/
    ├── login/                    LoginActivity (launcher: password, Google, GitHub, Okta, card, Card Lab link)
    │                             and LoginViewModel (auth state, card login slot)
    ├── main/MainActivity.kt      Bottom navigation host; owns the one production CardReaderController,
    │                             cardAvailability(), awaitCardTap(prompt, …) and the overflow menu
    ├── tap/                      The tap-to-card sheet
    │   ├── TapPrompt.kt          Register, SignIn, Read, Sign, Apply (Sign and Apply move money)
    │   ├── TapStateMachine.kt    Pure reducer: Waiting → Busy → Finishing → Done / Failed, watchdog, actions
    │   ├── TapUiState.kt         The sheet states
    │   ├── TapViewModel.kt       Activity-scoped: the pending request, step labels, haptics
    │   ├── TapFailures.kt        Failure wording (simulator, reader, CardError)
    │   ├── TapCopy.kt            Outcome copy: Done's next-step line, Failed titles per flow
    │   └── CardTapSheet.kt       BottomSheetDialogFragment rendering the state
    ├── cards/                    CardsViewModel (registration checks, issuer/program check, POST/DELETE /card)
    │                             and CardPresentation (card face: grouped id, chip, line)
    ├── transfer/                 TransfersViewModel and TransferPresentation (labels, tones, banners, actions)
    ├── fragments/                CardsFragment, TransfersFragment, SettingsFragment, NotificationPreferencesFragment
    ├── lab/                      The Card Lab's logic
    │   ├── LabIntents.kt         The one way to open the Lab: EXTRA_TAB, EXTRA_CARD_ID, TABS
    │   ├── LabViewModel.kt       Last read, Doctor verdicts, probe results (in memory only)
    │   ├── CardDoctor.kt         Pure card ↔ bridge ↔ session diagnosis
    │   ├── BridgeProbe.kt        Unauthenticated /health, /version, /card-issuer with failure classes
    │   ├── BuildInfo.kt          Build and device facts
    │   ├── LabReport.kt          Screen rows (the only place masked values are revealed) and the redacted export
    │   └── adapters/             KeyValueAdapter, DoctorAdapter, TraceAdapter, LabColors
    ├── nfc/NfcDebugActivity.kt   The Card Lab activity (class name kept from the old NFC debug screen)
    ├── log/LogViewerActivity.kt  The Activity Log
    └── common/                   EdgeToEdge (insets and system-bar icon helpers), Identifiers, Haptics
```

All card I/O goes through impala-lib (`CardReaderController`,
`ImpalaCardSession`, `CardAuthenticator`, `CardTransfers`, `CardInspector`) and
the card SDK (`com.impala.sdk.flows`: `CardIdentity`, `CardError`,
`RedemptionFlow`, `CreditFlow`; `com.impala.sdk.apdu4j`: the header-only
`ApduExchange` trace and the `ReadOnlyBibo` guard), consumed as composite
builds (`settings.gradle.kts`). The app contains no APDU code:
`NoRawApduInAppTest` fails the build if a source under `app/src/main` mentions
`IsoDep`, `CommandAPDU`, `transceive(` or an `INS_` constant, and
`CrossLaneContractTest` holds every string file to the same rule (user copy
says "ISO 14443-4" and "card"). `DebugBoundaryTest` keeps the debug-only TCP
transport out of every source set a release APK compiles.

## Authentication Flows

### Username / Password
1. User enters account ID and password
2. `POST /authenticate` registers or verifies the credentials
3. `POST /token` with username/password returns a 14-day refresh token
4. `POST /token` with refresh token returns a 1-hour temporal token
5. Both tokens are stored in EncryptedSharedPreferences

### Google Sign-In
1. Credential Manager presents the Google account picker
2. The returned `idToken` is hashed via SHA-256 to derive a stable password
3. A placeholder account is created via `POST /account` (if it doesn't exist)
4. Standard bridge auth flow: `/authenticate` -> `/token` -> `/token`

### GitHub Sign-In
1. Custom Chrome Tab opens `github.com/login/oauth/authorize`
2. `GitHubRedirectActivity` catches the `impala://github-callback?code=...` deep link
3. The app posts the authorization code to the bridge: `POST /auth/github {code, redirect_uri}`
4. The bridge exchanges the code at GitHub's token endpoint **server-side**
   (it holds the client secret), verifies the user via `GET /user`, and returns
   bridge JWT tokens plus the profile's `login`/`display_name`
5. The app stores the tokens; no GitHub access token or client secret ever
   exists on-device

> **Note:** OAuth password derivation (SHA-256 of the provider token) is a demo shortcut. A production app would add dedicated `/oauth/google` and `/oauth/github` bridge endpoints.

### Card (NFC smartcard)
Requires an **issued** card (applet 0.2, personalized with a bridge
certificate — see `impala-card/README.md` → "Issuance tool") that is
**registered** to the account (Cards screen).
1. "Sign in with Card" opens the tap sheet and arms reader mode; only that tap
   is acted on, and a second tap while a login is in flight is ignored (logged
   as a stray tap).
2. On the NFC binder thread, **with the card still connected**: read the card
   identity — `GET_VERSION` (a 0.1 applet is refused before any V2 command),
   `GET_PERSONALIZATION` (an unissued card is refused **before** a challenge is
   requested, so it never spends the card's challenge budget), `GET_USER_DATA`,
   `GET_EC_PUB_KEY`.
3. `POST /auth/card/challenge {card_id}` — `card_id` is the dash-stripped
   32-hex card UUID; the 32-byte challenge lives 60 s and the fetch is bounded
   by the login timeout so a slow network aborts before signing.
4. `SIGN_AUTH`: the card signs `"IMPALA-AUTH:" ‖ accountId ‖ challenge`
   (DER ECDSA-P256, lowercase hex on the wire).
5. `POST /auth/card {card_id, signature}` → refresh token → `POST /token` →
   temporal token. The card id and the on-card account UUID are stored with the
   session. A 401 reads "Card not recognised or challenge expired — tap again"
   (the bridge answers an unregistered card with the same generic 401); 429 is
   the lockout (5 bad signatures → 15 min per card and source).

Card errors are typed (`CardError`) and shown with impala-lib's strings. A
card that answers no Impala applet for this flavor's AID (SW `6A82`, `6999` or
`6D00`) reads "No Impala applet for this network answered. This may be a card
for another network, not an Impala card, or an unsupported applet version."
The raw status word is shown in debug builds only (a chip on the tap sheet);
the Card Lab always shows it.

### The tap sheet

Every card request — sign-in, registering a card, redeem, load, apply, recover
— goes through one bottom sheet (`ui/tap/CardTapSheet`) driven by the pure
`TapStateMachine`:

| State | Shows | Can the user leave? |
|---|---|---|
| **Waiting** | The prompt ("Register a card", "Sign the transfer on card ····abcd", …), a ripple, and in debug builds the simulated endpoint | Cancel |
| **Busy** | The step from the card trace ("Reading card", "Card is signing the login challenge", "Verifying PIN and signing on card", "Applying credit to card") or "Contacting the bridge…", with "Keep the card still" (on the simulated card: "Talking to the simulated card") | Cancel only while contacting the bridge on a prompt that does not move money; "Still working…" after 8 s; Close after 20 s ("The operation continues; the outcome will appear in Transfers and the Activity Log") — Close never cancels the operation |
| **Finishing** | The bridge follow-up ("Registering with the bridge…", "Signing you in…", "Sending the signed transfer to the bridge…", "Reporting the credit to the bridge…") | As Busy |
| **Done** | Only after the real outcome (`POST /card` 2xx, the submit accepted, the credit ACKed, the login succeeded), with what happens next ("Card registered / It is listed under Cards…", "Signed in / Opening your account…", "Follow it in Transfers.") rather than the prompt again; dismisses itself after 1.2 s | — |
| **Failed** | A title that keeps the flow ("Couldn't register the card", "Couldn't sign on card ····abcd", …), the message, and the SW chip in debug builds | Prompts that move money (Sign, Apply) **never offer Try again**: Resume (when a recovery slot exists; it only re-enters the existing recovery paths and never re-signs) plus Close. An ambiguous outcome is a warning, "Outcome unknown — do not repeat", with Close only. NFC off offers Open NFC settings. Other prompts offer Try again plus Close |

`MainActivity.cardAvailability()` is checked before the sheet waits: a
configured simulated card wins (so the Cards FAB works on the emulator), NFC
off fails at once with the settings action, and a device with neither NFC nor
a simulator shows "NFC is not available on this device". Haptics: a context
click when the card answers, confirm/reject on Done/Failed. With animations
off (`animator_duration_scale 0`) every state draws a static frame. The sheet's
state lives in an activity-scoped view model, so it survives rotation, and a
result that arrives after the screen is gone is logged rather than lost (a
signed transfer stays "Ready to send"; it is never submitted twice).

## Card transfers

Both flows use integer **card minor units** (the card's `u32` amount; XLM cards
use scale 7) — no floating point anywhere in the transfer code
(`NoFloatingPointMoneyTest`). They need the bridge's offline
issuance/redemption endpoints (`/card-issuer`, `/offline/*`); the bridge serves
`/card-issuer` today, the `/offline/*` lane is not built yet.

**Load card** (bridge → card): tap to read the card's receive counter →
`POST /offline/issuances` → **Fund** = `POST /managed-account/sign` with the
bridge's destination, amount, memo and idempotency key *verbatim* (202
`ambiguous` = outcome unknown, only ever replayed with the same key; a new key
only after a definite `payment_rejected`) → wait for `funded` →
`GET …/credit` (persisted before the tap) → **Apply to card**
(`VERIFY_TRANSFER_V2`) → `POST …/ack {applied, status_word}`. A torn apply is
decided by the card's `GET_RECEIVE_STATE`: digest equal = already applied;
counter behind = re-present; another credit on the counter = operator
exception, never auto-credited.

**Redeem from card** (card → bridge, PIN-authorized): `GET /card-issuer`
(redemption identity) + `GET /offline/cards/{id}` (certified, last redeemed
counter) → amount + 4-digit PIN (`0000` refused) → tap: the signable
(`recipient = redemption_uuid`, `counter = last + 1`, send sequence
`max(previous + 1, now)`) is **written to disk before** `SIGN_TRANSFER_V2`, the
tuple right after → `POST /offline/redemptions` → poll every 5 s for up to 6
min. **Never re-sign**: retries re-post the stored bytes (a 202 replay or 409
`counter_consumed` means the bridge already has the debit); a tuple lost to a
crash is rebuilt from the card's `GET_LAST_TRANSFER` ("Resume pending
transfer"). `frozen` is shown as "outcome unknown — do not repeat" and blocks
new redemptions from that card; a refused tuple is stranded (the card was
debited) and shown as needing an operator.

## Screens

Every activity draws edge to edge (`ui/common/EdgeToEdge.applyEdgeToEdge`,
called before `setContentView`). The bars are transparent, so the app sets the
system-bar icon appearance itself from the night mode: dark status- and
navigation-bar icons on the light theme's surfaces, light icons in dark mode.
The Login screen keeps light status-bar icons over its dark header in both
modes, and the tap sheet's window follows the same rule (`EdgeToEdgeTest`).

### Login
- Auto-skips to the main screen if a valid refresh token exists
- Username/password form: validation errors on the fields themselves
  (non-empty, min 8 chars), network and card errors in an error card that
  TalkBack announces; autofill hints and IME actions (Next, Go)
- Google, GitHub and Okta buttons (Okta only when `OKTA_ISSUER_URL` is set);
  the brand marks are not tinted
- "Sign in with Card" (hidden when the device has no NFC and no simulated card
  is configured) — see "Card (NFC smartcard)"
- A quiet **Card Lab** link at the bottom, in every build including release:
  the Lab opens without a session (see "Card Lab")
- A **Testnet** badge in the header when the build's `STELLAR_NETWORK` is not
  `pubnet` (the same rule as Settings' network chip)
- While a sign-in is in progress, a progress bar runs along the bottom of the
  header; it overlays the header, so the form does not move

### Cards (start destination)
- Cards registered from this device for the signed-in account (local record,
  kept across logout; the bridge has no card-list endpoint), drawn as card
  faces: the **full** 32-hex card id in eight groups of four, a status chip
  (Registered, or "Not this bridge's program" when the card's program id is not
  the bridge's), and `applet <version> · <state> · registered <date>`. The
  holder name and balance are never on the face.
- FAB → tap sheet → `POST /card {account_id, card_id, ec_pubkey}`; refused
  before sending when the applet is older than 0.2, the card is not issued, or
  the card was issued to a different account ("This card was issued to a
  different account") — the bridge would accept that row but card login could
  never work
- **Program check.** Before posting, the app compares the card's program id
  with the bridge's public `GET /card-issuer`. On a mismatch the **tnet**
  flavor warns ("A different program's card … It can sign in, but it cannot
  load or redeem here. Register anyway?") and the **live** flavor refuses
  ("It cannot be registered here."). When `/card-issuer` cannot be reached,
  tnet asks before registering and live refuses (fail closed). A bridge with no
  issuer configured (`configured: false`, or no endpoint) registers directly.
  The policy is passed to `CardsViewModel.register` explicitly, so tests do not
  depend on the flavor.
- Declining "Register anyway?" (or the issuer-unknown question) says
  "Nothing was registered." in a snackbar
- Tapping an unregistered card on this screen offers "Register this card?"
- Each card's overflow: **Copy ID** (the id only), **Inspect in Card Lab**
  (opens the Doctor tab for that card), **Remove** (with confirmation; removes
  the local record only after `DELETE /card` succeeds)

### Transfers
- In-flight and finished card transfers. Each row shows the signed amount
  (integer minor units through `Money.format`), the card as ····last4, a status
  chip, and one action (Send, Fund, Apply or Details)
- Outcomes that need attention are **persistent banners in the row**, not
  snackbars: a frozen redemption ("outcome unknown — do not repeat"), an
  ambiguous funding, a refused tuple (the card was debited; an operator
  resolves it), a credit exception, a card that refused a credit
- When `GET /card-issuer` reports no issuer (or the endpoint is missing), a
  banner reads "Offline transfers aren't enabled on this bridge" and the FAB
  explains the same before asking for an amount or PIN
- FAB → **Redeem from card** or **Load card** (see "Card transfers"); the PIN is
  entered in a plain dialog (never saved instance state) and zeroed on every
  path, including cancellation

### Settings
- Account: the display name (or a person glyph) and the Payala ID, shown once
- MFA enrollment status (fetched from the bridge API) and notification
  subscriptions
- Server: the bridge URL, read-only, with a Testnet / Public network chip
- The Payala ID and the bridge URL wrap only at their separators (a UUID's
  hyphens, a URL's slashes and port), never mid-token at large font scales; a
  long press copies the value
- About: the app version and the bridge version (`GET /version`)
- Log Out, with a confirmation dialog whose Log Out action is in the error
  colour (clears all tokens, returns to login)

### Main overflow menu
- **Build Info** opens the Card Lab on its Device tab
- **Activity Log** (see "Activity Log")
- **Card Lab** opens the Card Lab on its Inspector tab

## Card Lab

`ui.nfc.NfcDebugActivity` (title "Card Lab"; the class name is kept so the
manifest, menu id and the demo kit's scenario hooks did not change) answers
"is it the card, the bridge, or this phone?". Every caller opens it through
`LabIntents.open(context, tab, cardId)`: `EXTRA_TAB` is one of
`LabIntents.TABS` (`inspector`, `doctor`, `trace`, `device`, in TabLayout
order; anything else opens the Inspector) and `EXTRA_CARD_ID` names a card to
check for. `CrossLaneContractTest` pins that order and both extras.

**Entry points.** The Login screen's "Card Lab" link (Inspector, no session),
the Main overflow's "Card Lab" (Inspector) and "Build Info" (Device), and a
card's "Inspect in Card Lab" (Doctor, with that card id: the Inspector then
says "Waiting for card <id>" and the Doctor adds "The card you chose to
inspect").

### Tabs

- **Inspector.** Hold a card to the back of the phone (reader mode is on while
  the Lab is in the foreground). The read groups Transport (UID, technologies,
  ISO 14443-4, largest command, extended length, timeout, historical bytes,
  ATQA/SAK, NFC-B facts), Applet (AID or "Default selection (no SELECT)",
  version line such as `0.2 · r17 · g1a2b3c4d`, alive), Identity (card id,
  account, holder name, card key fingerprint), Personalization (state, flags,
  program id, currency, issuer key fingerprint), Certificate (length,
  `cert_id`, "Verified under the card's issuer key" — a local ECDSA P-256
  check), Counters (receive counter and digest), Balance, Last transfer, and
  Read steps. A blank or terminated card still gives a partial read with the
  failing step named. Identifier rows (ids, AID, fingerprints, program id,
  `cert_id`, digest) are set in monospace, wrap only at their own separators,
  and have a copy button (it copies the value itself); prose values use the
  body face, and rows with personal values never have a copy button. The
  balance (and the last transfer's amount) of an XLM card reads
  `0.0000000 XLM · 0 minor units`: `Money.format` at the card scale (7), then
  the raw minor units; a currency whose card scale the app does not know shows
  minor units only.
- **Doctor.** One verdict per check, in order: Reader; ISO 14443-4 card;
  Applet selected; Applet version 0.2 or newer; Personalized, not terminated;
  Certificate verifies under the card's issuer key; Issuer matches this bridge;
  Certificate verifies under this bridge's key; Bridge knows this card
  (`GET /offline/cards/{id}`, only with a session); Recorded on this phone;
  Card account is the signed-in account; the card you chose (only with
  `EXTRA_CARD_ID`); Field quality. Verdicts are PASS, FAIL (only when the card
  or the bridge positively says no), WARN, SKIP (not checkable now, with the
  reason) and INFO; each failing or warning row carries a remedy. When no
  Impala applet answered, every later card check is SKIP. Card reads happen in
  the tap; the bridge is asked afterwards, never while the card is in the field.
  The summary line counts them (`8 passed · 2 failed · 1 warning · 1 skipped`).
  The Doctor tab has its own read action, since a card's "Inspect in Card Lab"
  opens it: **Read simulated card** in debug builds with a simulator, **Open
  NFC settings** when NFC is off; with NFC on, holding the card to the phone
  reads it on any tab.
- **Trace.** The last Lab read, headers only: `#n · INS name`, then
  `Lc n → SW name · n B · n ms`, with a stats block (commands, total, average,
  slowest, tag losses, refused, transport failures, card errors; two columns
  instead of four at a large font scale). `GET_LAST_TRANSFER` answering `6A83`
  (RECORD_NOT_FOUND) is the normal answer of a card that has never signed a
  transfer: its dot is informational and the SDK's `ApduStats` counts it under
  `expectedStatuses`, not as a card error. No command or response bytes are
  ever recorded (the SDK's `ApduExchange` has no byte or text field). Debug
  builds add "Recent app taps": the last 20 card taps taken by the app's
  readers, labelled by the flow that asked for them (`register`, `sign-in`,
  `sign`, `apply`, `read`), or `idle` for a tap nothing asked for, newest
  first, with their outcome. The label comes from the request the tap is
  running (or the armed one, for a SELECT before it), so a session with no
  SELECT, such as the simulated card's, is labelled correctly; card sign-ins on
  the Login screen are recorded as `sign-in`.
- **Device.** A **Wrong Stellar network** danger banner first when the
  bridge's `/health` `stellar_network` is not this build's `STELLAR_NETWORK`
  ("Do not move money until they match"). Then **Probe bridge**: unauthenticated
  `GET /health`, `/version` and `/card-issuer` on a client of its own (no
  session, no logging, no retries, no redirects, 5 s per call), each with its
  latency and, on failure, a class: `DNS`, `CONNECT`, `TLS`,
  `CLEARTEXT_BLOCKED` (the network security config refused `http://`),
  `TIMEOUT`, `RATE_LIMITED` (429) or `HTTP_<code>`. The probe runs once on
  open and then at most once per 10 s (a second press inside the window says
  "Probed just now; try again in N s"); the Doctor reuses a probe for 60 s.
  The bridge rows include its program id, **Bridge issuer key fingerprint**
  (the bridge key in the Inspector's `ab:cd:…` format, so it can be compared
  with a card's issuer key fingerprint at a glance) and **Operator
  fingerprint** (the bridge's own key fingerprint, as its admin tools print
  it). Then build and device facts: version, flavor, build type, application
  id, Stellar network (only until the bridge row names it), bridge URL, applet
  AID, min/target SDK, device, Android version and security patch, locale and
  UTC offset, NFC state.

**Share report** (toolbar) sends a plain-text report through the share sheet:
build facts, the probe, the card's ids, fingerprints, version and state, the
read steps, the Doctor verdicts and the header-only exchanges. `LabReport.export`
has no parameter that could carry personal data: it states "holder name,
balance, last transfer: not exported" and never includes a raw key or the
certificate.

### What the Lab will not do

- **Read-only by construction.** The Lab owns its own `CardReaderController`
  (the production reader flags and 1 s presence check) whose session factory
  opens every session with `readOnly = true`: impala-lib wraps the transport in
  the SDK's `ReadOnlyBibo`, which refuses anything outside the read-only
  allow-list (SELECT plus the non-mutating Impala commands) **before a byte
  reaches the card**, and `CardInspector.inspect` refuses a session that is not
  read-only. A refusal surfaces as "Read-only session refused <command>.
  Nothing was sent to the card." The Lab never verifies a PIN, signs, or
  writes to the card, and never writes the pending-transfer, card or session
  stores: it reads the signed-in account id and, with a session, whether this
  phone recorded the card.
- **The PII gate.** The holder name, balance and last transfer are revealed
  only while a session exists **and** the signed-in account is the card's
  account. Otherwise — and always before login — those rows read "Sign in as
  this card's account to show", with no copy action. Before login the Lab is
  the only reachable tool: the Activity Log, transfers and session data stay
  behind login, and nothing the Lab reads is persisted.
- **Release vs debug.** The Lab ships in release builds (Inspector, Doctor,
  the Lab's own trace, Device and the bridge probe). Debug builds only add
  "Read simulated card", the simulator endpoint and **Probe simulator**
  (READY, BUSY or DOWN with milliseconds, from one harmless NOP command), and
  "Recent app taps".

## Activity Log

Main overflow → **Activity Log** (after login only). `AppLogger` keeps the
newest 1 000 entries in memory with ISO-8601 UTC timestamps (`…Z`);
impala-lib's own log lines arrive with a `lib.` tag prefix. The viewer is live:
level chips (Debug, Info, Warn, Error), a search over tag or message, a count
("7 of 10 entries") and **Follow**, which keeps the newest entry in view and
turns itself off when you scroll up. Tap a row to expand it with its full
timestamp and a Copy button. The overflow offers **Share** (plain text),
**Copy all** (the clip is marked sensitive on API 33+, so it is hidden from
clipboard previews) and **Clear** (after confirmation). Log lines never carry
tokens, PINs, signatures, challenges, e-mail addresses or holder names
(`AppLogHygieneTest`).

## Troubleshooting

### A card will not sign in

1. **Open the Card Lab from the Login screen** (the "Card Lab" link) and hold
   the card to the phone. On the emulator (debug build) press "Read simulated
   card" instead.
2. **Device tab first.** If the Wrong Stellar network banner shows, this APK
   and the bridge are on different networks: stop and use the matching build.
   A failed probe names the problem: `DNS` or `CONNECT` (wrong
   `BRIDGE_BASE_URL`, bridge down, no network), `TLS`, `CLEARTEXT_BLOCKED` (an
   `http://` URL in a build whose network security config forbids it),
   `TIMEOUT`, `RATE_LIMITED`. Check the Applet AID row against the card's
   network.
3. **Doctor tab**, top to bottom; the first FAIL is the cause:
   - *Reader* FAIL: NFC is off (the row offers Open NFC settings) or absent.
   - *ISO 14443-4 card* FAIL: a tag or another kind of card, not an Impala card.
   - *Applet selected* FAIL (SW `6A82`, `6999` or `6D00`): no Impala applet for
     this flavor's AID answered — a card for the other network (tnet and live
     select different AIDs), not an Impala card, or an unsupported applet.
   - *Applet version* FAIL: reissue with a current applet.
   - *Personalized, not terminated* FAIL: the card was never issued (issue it
     with the issuance tool, `impala-card/README.md`) or is terminated (issue a
     new one).
   - *Certificate verifies under the card's issuer key* FAIL: the card was
     personalized incorrectly; reissue it.
   - *Issuer matches this bridge* FAIL — **program mismatch**: the card was
     issued by another program, typically a login-only card from a test
     issuer. This alone does **not** stop sign-in (login checks the registered
     key, not the certificate), but it decides registration: tnet registers it
     after "Register anyway?", live refuses to register it, so on live such a
     card can never sign in. It can never load or redeem on this bridge.
   - Before login, *Bridge knows this card*, *Recorded on this phone* and
     *Card account* are SKIP ("Not signed in"); that is expected.
4. **"Card not recognised or challenge expired — tap again" (HTTP 401)** with a
   card whose Doctor checks all pass usually means an **unregistered card**:
   the bridge answers an unknown card with the same generic 401. Sign in with
   the card's account another way (password), register the card on the Cards
   tab (FAB, then tap), and sign in with the card again. Then use the card's
   overflow → **Inspect in Card Lab** to see the session checks:
   - *Card account is the signed-in account* FAIL: the card was issued to the
     account shown; sign in as that account (registration refuses it anyway).
   - *Recorded on this phone* WARN: this phone has no record of registering
     the card for this account (the record is per phone; a card registered on
     another phone can still sign in).
   - *Bridge knows this card* PASS (2xx) is positive evidence. This check uses
     `GET /offline/cards/{id}`, and a bridge that does not serve the
     `/offline/*` lane yet answers 404 for **every** card. So a 404 for a card
     that **is** recorded on this phone (registered from it with `POST /card`)
     is INFO, "the bridge's offline lane has no record of this card; the
     offline lane may not be deployed", with no remedy. A 404 for a card this
     phone did not record, and any 503, is WARN ("the card is not registered,
     or the offline lane is not deployed") with the register-it remedy. SKIP
     with HTTP 401/403 means the session expired.
   - A challenge that expired (it lives 60 s) gives the same 401: tap again.
5. **"Too many failed card sign-ins" (HTTP 429)**: five bad signatures lock the
   card out for 15 minutes per card and source; wait.
6. **Trace tab**: which command failed and with which SW; *Field quality* in
   the Doctor counts tag losses and the slowest command. Repeated tag losses
   mean the card moved or the antenna spot is wrong: hold it still, flat, at the
   phone's NFC spot.
7. **Share report** from the Lab to send the findings: it carries ids,
   fingerprints, verdicts and headers, never the holder name, balance, last
   transfer, keys or the certificate. After login, the Activity Log (filter
   Warn and Error, search `lib.`) shows what the app and impala-lib saw.

### Simulated card (emulator, debug builds)

- **"Simulated card at 127.0.0.1:9443 is unreachable — is :simulator:serve
  running?"**: start `./gradlew :simulator:serve --args="--port 9443"` in
  `../impala-card`, then `adb reverse tcp:9443 tcp:9443` and
  `adb shell setprop debug.impala.tcp_card 127.0.0.1:9443`. The app stays up
  and the sheet fails readably; the half-open session is closed, so the
  simulator is not left wedged.
- **Device → Probe simulator** sends one NOP: READY (answered), BUSY (another
  client holds the one-client simulator, e.g. a test run or a second app),
  DOWN (nothing listening). On BUSY, wait or close the other client.
- For a freshly issued card, start a **new simulator on a fresh port** (for
  example `--port 9444`, then `adb reverse tcp:9444 tcp:9444` and point the
  property at it) rather than re-issuing a card another session is using; a
  simulator restarted after an SDK change also comes up with a new, blank card.

## Theme and icons

The colour roles are generated, never hand-picked: deep teal seed `#00696B`,
Material `SchemeTonalSpot`, standard contrast, light and dark. Dynamic colour
is deliberately not applied. `ThemeGeneratorTest` renders
`res/values/colors_m3.xml` and `res/values{,-night}/themes_roles.xml` (the full
M3 role set plus the custom status, brand-header and card-face families) and
asserts the committed files are byte-equal to its output, together with the
contrast floors (≥ 4.5:1 for text on the header, the card face and the status
containers; ≥ 3:1 for the FAB). After changing the seed, a tone or a family,
regenerate with:

```bash
IMPALA_THEME_WRITE=1 ./gradlew :app:testTnetDebugUnitTest --tests '*ThemeGeneratorTest*' --rerun
```

(an environment variable, which `app/build.gradle.kts` forwards to the test
JVM; a `-D` property would not reach it). `ThemeWiringTest` keeps layouts on
`?attr/` colours only (no raw hex, no `@color/m3_*`) and the day and night
themes in step.

The launcher icon is adaptive with a monochrome layer (`mipmap-anydpi-v26`)
plus layer-list fallbacks for API 24–25 (`mipmap-anydpi`, pinned by
`LauncherIconApi24Test`); `ic_stat_impala` is the notification small icon.

## Dependencies

As pinned in `app/build.gradle.kts`:

| Category | Library | Version |
|----------|---------|---------|
| Card | `com.impala:sdk`, `com.payala:impala-lib` (composite builds of `../impala-card` and `../impala-lib`) | 0.0.1-HEAD |
| Core | AndroidX core-ktx / appcompat / activity-ktx / fragment-ktx | 1.19.0 / 1.7.1 / 1.13.0 / 1.8.9 |
| Desugaring | desugar_jdk_libs (`java.time` below API 26) | 2.1.5 |
| Lifecycle | lifecycle-viewmodel-ktx, lifecycle-livedata-ktx | 2.10.0 |
| UI | Material Components (Material 3), ConstraintLayout, RecyclerView | 1.14.0 / 2.2.1 / 1.4.0 |
| Navigation | navigation-fragment-ktx, navigation-ui-ktx | 2.9.8 |
| Networking | OkHttp + logging-interceptor, Retrofit + converter-gson, Gson | 5.4.0 / 3.0.0 / 2.14.0 |
| Security | security-crypto (EncryptedSharedPreferences) | 1.1.0 |
| Auth | Credential Manager (credentials, credentials-play-services-auth), Google ID | 1.6.0 / 1.1.1 |
| Browser | Custom Tabs (androidx.browser) | 1.10.0 |
| Async | kotlinx-coroutines-android | 1.11.0 |
| Push | Firebase BoM → firebase-messaging | 34.14.1 |
| Unit tests | JUnit, Robolectric, androidx.test core / ext-junit, arch core-testing, coroutines-test, Mockito / mockito-kotlin | 4.13.2 / 4.16.1 / 1.7.0 / 1.3.0 / 2.2.0 / 1.11.0 / 5.23.0 / 6.3.0 |
| Unit tests (card) | `com.impala:simulator` (the applet on jcardsim), `com.impala:issue` (issuance ceremony, e2e lane) | 0.0.1-HEAD |
| Instrumented tests | androidx.test ext-junit, espresso-core, core, runner | 1.3.0 / 3.7.0 / 1.7.0 / 1.7.0 |

## Certificate pinning

The live flavor's `app/src/live/res/xml/network_security_config.xml` contains
a **commented-out** certificate-pinning template for the production bridge
host. It ships disabled because no production certificate exists yet —
activating a pin-set with the placeholder pins would break every TLS
connection to the host.

To enable it, follow the procedure in the XML comment (generate the leaf-cert
pin plus a backup pin, fill in the real host, set an expiration, uncomment).
Rotation discipline: add the new certificate's pin alongside the old one
*before* rotating the server certificate, and never ship a pin-set with fewer
than two pins.

CI (`.github/workflows/impala-android.yml`) guards against the
placeholder-bricking failure mode: the assemble job fails if this file ever
contains an *active* (uncommented) pin-set that still holds the placeholder
pins.

## Build Variants

- **debug** — HTTP logging at `HEADERS` with `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` redacted and `account_id` / `stellar_account_id` query values masked (never bodies; `HttpLoggingPolicyTest`); cleartext traffic allowed via `network_security_config.xml`; the simulated card, the SW suffix in product messages, and the Card Lab's debug-only parts
- **release** — no HTTP logging; ProGuard/R8 minification enabled, see `proguard-rules.pro` for keep rules; the Card Lab without its debug-only parts
