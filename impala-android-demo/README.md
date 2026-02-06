# Impala Android Demo

Android demo application for Payala-Impala, demonstrating authentication (password, Google, GitHub), card management, transfer history, and settings. Communicates with the [impala-bridge](../impala-bridge) REST API.

## Requirements

- Android Studio Hedgehog (2023.1.1) or later
- JDK 17
- Android SDK 34 (compileSdk / targetSdk)
- minSdk 24 (Android 7.0)

## Quick Start

```bash
cd impala-android-demo
./gradlew assembleDebug
```

Or open the project in Android Studio and run on an emulator or device.

## Configuration

Build config fields are defined in `app/build.gradle.kts`. Replace the placeholder values before testing:

| Field | Default | Description |
|-------|---------|-------------|
| `BRIDGE_BASE_URL` | `http://10.0.2.2:8080` | Bridge API URL (`10.0.2.2` is the emulator's loopback to the host machine) |
| `GITHUB_CLIENT_ID` | `YOUR_GITHUB_CLIENT_ID` | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | `YOUR_GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret |
| `GITHUB_REDIRECT_URI` | `impala://github-callback` | GitHub OAuth redirect URI (must match the OAuth App settings) |
| `GOOGLE_WEB_CLIENT_ID` | `YOUR_GOOGLE_WEB_CLIENT_ID` | Google Cloud Console Web client ID for Credential Manager |

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
│   ├── CardModels.kt             Card create/delete DTOs
│   └── TransferModels.kt         Transaction, version, sync, MFA DTOs
├── auth/
│   ├── TokenManager.kt           Encrypted token storage (EncryptedSharedPreferences)
│   ├── GoogleAuthHelper.kt       Google Sign-In via Credential Manager API
│   ├── GitHubAuthHelper.kt       GitHub OAuth via Custom Chrome Tabs
│   └── GitHubRedirectActivity.kt Deep-link handler for impala://github-callback
└── ui/
    ├── login/
    │   ├── LoginActivity.kt      Launcher activity with 3 auth methods
    │   └── LoginViewModel.kt     MVVM ViewModel managing auth state
    ├── main/
    │   └── MainActivity.kt       Bottom navigation host (Cards, Transfers, Settings)
    └── fragments/
        ├── CardsFragment.kt      Registered cards list with delete
        ├── TransfersFragment.kt  Transfer history list
        └── SettingsFragment.kt   Account info, MFA, version, logout
```

## Authentication Flows

### Username / Password
1. User enters account ID and password
2. `POST /authenticate` registers or verifies the credentials
3. `POST /token` with username/password returns a 30-day refresh token
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
3. The authorization code is exchanged for an access token at GitHub's token endpoint
4. The GitHub user profile is fetched via `GET https://api.github.com/user`
5. A password is derived from the access token, then the standard bridge auth flow runs

> **Note:** OAuth password derivation (SHA-256 of the provider token) is a demo shortcut. A production app would add dedicated `/oauth/google` and `/oauth/github` bridge endpoints.

## Screens

### Login
- Auto-skips to the main screen if a valid refresh token exists
- Username/password form with validation (non-empty, min 8 chars)
- Google and GitHub sign-in buttons
- Loading indicator and error display

### Cards (start destination)
- RecyclerView of registered cards with EC public key fingerprint
- Delete card with confirmation dialog
- FAB to register a new NFC card (stub)

### Transfers
- RecyclerView of recent transfers with status chips
- FAB to initiate a new transfer (stub)

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

## Build Variants

- **debug** — Logging interceptor enabled, cleartext traffic allowed via `network_security_config.xml`
- **release** — ProGuard/R8 minification enabled, see `proguard-rules.pro` for keep rules
