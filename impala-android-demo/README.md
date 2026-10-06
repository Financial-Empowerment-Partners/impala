# Impala Android Demo

Android demo application for Payala-Impala, demonstrating authentication (password, Google, GitHub), card management, transfer history, and settings. Communicates with the [impala-bridge](../impala-bridge) REST API.

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
| `BRIDGE_BASE_URL` | `http://10.0.2.2:8080` (tnet) | Bridge API URL (`10.0.2.2` is the emulator's loopback to the host machine) |
| `GITHUB_CLIENT_ID` | `YOUR_GITHUB_CLIENT_ID` | GitHub OAuth App client ID |
| `GITHUB_REDIRECT_URI` | `impala://github-callback` | GitHub OAuth redirect URI (must match the OAuth App settings) |
| `GOOGLE_WEB_CLIENT_ID` | `YOUR_GOOGLE_WEB_CLIENT_ID` | Google Cloud Console Web client ID for Credential Manager |

There is no GitHub client-secret field: the bridge performs the OAuth
code→token exchange server-side (`POST /auth/github {code, redirect_uri}`),
so the secret is configured on the bridge and never ships in the APK.

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
├── ImpalaApp.kt                  Application subclass, initializes TokenManager
├── api/
│   ├── BridgeApiService.kt       Retrofit interface for all bridge endpoints
│   ├── ApiClient.kt              Thread-safe Retrofit singleton with OkHttp
│   └── AuthInterceptor.kt        OkHttp interceptor attaching JWT to requests
├── model/
│   ├── AuthModels.kt             Authentication request/response DTOs
│   ├── AccountModels.kt          Account CRUD DTOs
│   ├── CardModels.kt             Card create/delete DTOs (no rsa_pubkey)
│   ├── OfflineModels.kt          Card issuer, issuance (load) and redemption DTOs
│   └── TransferModels.kt         Transaction, version, sync, MFA DTOs
├── card/
│   ├── CardStore.kt              Per-account local record of registered cards (survives logout)
│   └── DebugCards.kt             debug: simulated card over TCP (emulator lane); release: stub
├── transfer/
│   ├── Money.kt                  Integer minor-unit parsing/formatting (no floating point)
│   ├── PendingTransferStore.kt   Durable in-flight redemptions/credits (written before the card signs)
│   ├── RedemptionController.kt   Card → bridge: prepare, sign (PIN), submit, track; never re-sign
│   └── IssuanceController.kt     Bridge → card: create, fund, await, apply credit, ack
├── auth/
│   ├── TokenManager.kt           Encrypted token storage (EncryptedSharedPreferences)
│   ├── GoogleAuthHelper.kt       Google Sign-In via Credential Manager API
│   ├── GitHubAuthHelper.kt       GitHub OAuth via Custom Chrome Tabs
│   └── GitHubRedirectActivity.kt Deep-link handler for impala://github-callback
└── ui/
    ├── login/
    │   ├── LoginActivity.kt      Launcher activity (password, Google, GitHub, Okta, card)
    │   └── LoginViewModel.kt     MVVM ViewModel managing auth state (incl. the card tap)
    ├── main/
    │   └── MainActivity.kt       Bottom navigation host; owns the one CardReaderController
    ├── cards/CardsViewModel.kt   Registration checks + POST/DELETE /card
    ├── transfer/TransfersViewModel.kt
    ├── nfc/NfcDebugActivity.kt   NFC diagnostics on ImpalaCardSession (read-only commands)
    └── fragments/
        ├── CardsFragment.kt      Registered cards (local record) with register/delete
        ├── TransfersFragment.kt  Redeem from card / Load card
        └── SettingsFragment.kt   Account info, MFA, version, logout

All card I/O goes through impala-lib (`CardReaderController`,
`ImpalaCardSession`, `CardAuthenticator`, `CardTransfers`) and the card SDK's
`com.impala.sdk.flows` (`CardIdentity`, `CardError`, `RedemptionFlow`,
`CreditFlow`), consumed as composite builds (`settings.gradle.kts`). The app
contains no APDU code: `NoRawApduInAppTest` fails the build if a source under
`app/src/main` mentions `IsoDep`, `CommandAPDU`, `transceive(` or an `INS_`
constant.
```

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
1. "Sign in with Card" arms reader mode; only that tap is acted on, and a
   second tap while a login is in flight is ignored.
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
   session. A 401 reads "Card not recognised or challenge expired — tap again";
   429 is the lockout (5 bad signatures → 15 min per card and source).

Card errors are typed (`CardError`) and shown with impala-lib's strings; the
raw status word is appended in debug builds only.

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

### Login
- Auto-skips to the main screen if a valid refresh token exists
- Username/password form with validation (non-empty, min 8 chars)
- Google and GitHub sign-in buttons
- Loading indicator and error display

### Cards (start destination)
- Cards registered from this device for the signed-in account (local record,
  kept across logout; the bridge has no card-list endpoint)
- FAB → tap → `POST /card {account_id, card_id, ec_pubkey}`; refused before
  sending when the applet is older than 0.2, the card is not issued, or the card
  was issued to a different account ("This card was issued to a different
  account") — the bridge would accept that row but card login could never work
- Tapping an unregistered card on this screen offers "Register this card?"
- Delete removes the local record only after `DELETE /card` succeeds

### Transfers
- In-flight and finished card transfers with their bridge state
- FAB → **Redeem from card** or **Load card** (see "Card transfers")

### Settings
- Account info (display name, Payala ID)
- MFA enrollment status (fetched from bridge API)
- Server version info (fetched from `GET /version`)
- Logout button (clears all tokens, returns to login)

## Dependencies

| Category | Library | Version |
|----------|---------|---------|
| Core | AndroidX core-ktx, appcompat, activity-ktx, fragment-ktx | 1.13.1 / 1.7.0 / 1.9.3 / 1.8.5 |
| UI | Material Design 3, ConstraintLayout, RecyclerView | 1.12.0 / 2.1.4 / 1.3.2 |
| Navigation | navigation-fragment-ktx, navigation-ui-ktx | 2.8.4 |
| Networking | OkHttp, Retrofit, Gson | 4.12.0 / 2.11.0 / 2.11.0 |
| Security | EncryptedSharedPreferences | 1.1.0-alpha06 |
| Auth | Credential Manager, Google ID | 1.3.0 / 1.1.1 |
| Browser | Custom Tabs | 1.8.0 |
| Async | kotlinx-coroutines-android | 1.9.0 |
| Lifecycle | lifecycle-viewmodel-ktx, lifecycle-livedata-ktx | 2.8.7 |

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

- **debug** — Logging interceptor enabled, cleartext traffic allowed via `network_security_config.xml`
- **release** — ProGuard/R8 minification enabled, see `proguard-rules.pro` for keep rules
