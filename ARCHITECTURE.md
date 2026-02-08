# Impala Platform Architecture

## System Overview

The Imapala bridge application provides an integration between Stellar payments
 and Payala offline and online transfers. Support for Anchored payments and smart
contracts for tokenized assets is provided.

The impala-card and library supports compatible javacard authentication for payments
with a hardware root of trust for authentication.

```mermaid
graph TB
    subgraph Clients["Client Layer"]
        AndroidApp["Android Demo App<br/><i>impala-android-demo</i>"]
        AdminUI["Admin Web UI<br/><i>Dashboard</i>"]
        ExtClient["External API Client"]
    end

    subgraph Bridge["impala-bridge &lpar;Rust / Axum&rpar;"]
        direction TB
        ClientAPI["Client API"]
        AdminAPI["Admin API"]
        AuthEngine["Auth Engine<br/><i>Argon2 + JWT</i>"]
        CronSync["Cron Sync Task<br/><i>60s interval</i>"]
    end

    subgraph Storage["Data Layer"]
        Postgres[("PostgreSQL")]
        Redis[("Redis")]
        Vault["HashiCorp Vault"]
    end

    subgraph Networks["Blockchain Networks"]
        Stellar["Stellar Network<br/><i>Horizon + Soroban RPC</i>"]
        Payala["Payala Network<br/><i>TCP Event Stream</i>"]
    end

    subgraph Hardware["Hardware Security"]
        Card["Impala Smartcard<br/><i>JavaCard Applet</i>"]
    end

    subgraph MobileLibs["Mobile Libraries"]
        ImpalaLib["impala-lib<br/><i>NFC + Geolocation</i>"]
        ImpalaSDK["impala-card SDK<br/><i>APDU + SCP03</i>"]
    end

    subgraph Contracts["Smart Contracts"]
        Soroban["MultisigAssetWrapper<br/><i>impala-soroban</i>"]
    end

    AndroidApp -->|"REST / JWT"| ClientAPI
    AdminUI -->|"REST / JWT"| AdminAPI
    ExtClient -->|"REST / JWT"| ClientAPI

    ClientAPI --> AuthEngine
    AdminAPI --> AuthEngine
    AuthEngine --> Postgres
    AuthEngine --> Redis

    Bridge --> Postgres
    Bridge --> Redis
    Bridge -.->|"Secret Unwrap"| Vault

    ClientAPI -->|"SSE Subscribe"| Stellar
    ClientAPI -->|"JSON-RPC"| Stellar
    ClientAPI -->|"TCP Subscribe"| Payala
    CronSync -->|"Webhook Callbacks"| ExtClient

    Stellar --- Soroban

    AndroidApp -->|"NFC / ISO-DEP"| Card
    ImpalaLib -->|"IsoDep Adapter"| Card
    ImpalaSDK -->|"APDU Commands"| Card
    AndroidApp --- ImpalaLib
    ImpalaLib --- ImpalaSDK
```

## API Architecture

```mermaid
graph LR
    subgraph Public["Public &lpar;No Auth&rpar;"]
        Auth["/authenticate<br/>POST"]
        Token["/token<br/>POST"]
        Ver["/version<br/>GET"]
        Health["/<br/>GET"]
    end

    subgraph ClientAPI["Client API &lpar;JWT Protected&rpar;"]
        AccR["/account GET"]
        AccC["/account POST"]
        AccU["/account PUT"]
        CardC["/card POST"]
        CardD["/card DELETE"]
        TxC["/transaction POST"]
        MfaR["/mfa GET"]
        MfaE["/mfa POST"]
        MfaV["/mfa/verify POST"]
        NotifyC["/notify POST"]
        NotifyU["/notify PUT"]
    end

    subgraph AdminAPI["Admin API &lpar;JWT Protected&rpar;"]
        Sub["/subscribe POST"]
        Sync["/sync POST"]
    end

    Public --- ClientAPI
    ClientAPI --- AdminAPI
```

## Authentication Flow

```mermaid
sequenceDiagram
    participant User
    participant App as Android App
    participant Card as Impala Card
    participant Bridge as impala-bridge
    participant DB as PostgreSQL

    rect rgb(240, 248, 255)
        Note over User, Card: NFC Card Authentication
        User->>App: Tap "Sign in with Card"
        App->>App: Enable NFC Foreground Dispatch
        User->>Card: Tap smartcard to device
        App->>Card: SELECT applet (ISO-DEP)
        App->>Card: GET_USER_DATA (INS 0x1E)
        Card-->>App: accountId + cardId + fullName
        App->>Card: GET_EC_PUB_KEY (INS 0x24)
        Card-->>App: EC public key (65B secp256r1)
        App->>Card: GET_RSA_PUB_KEY (INS 0x07)
        Card-->>App: RSA public key
        App->>Card: SIGN_AUTH (INS 0x25, timestamp)
        Card-->>App: ECDSA signature
    end

    rect rgb(255, 248, 240)
        Note over App, DB: Bridge Authentication
        App->>App: derivePassword = SHA-256(cardId).take(32)
        App->>Bridge: POST /authenticate {account_id, password}
        Bridge->>DB: Verify / Register (Argon2)
        Bridge-->>App: {success, action}
        App->>Bridge: POST /card {account_id, card_id, ec_pubkey, rsa_pubkey}
        Bridge->>DB: INSERT card record
        Bridge-->>App: {success}
    end

    rect rgb(240, 255, 240)
        Note over App, DB: JWT Token Acquisition
        App->>Bridge: POST /token {username, password}
        Bridge->>DB: Verify credentials
        Bridge-->>App: refresh_token (30-day JWT)
        App->>App: Store in EncryptedSharedPreferences
        App->>Bridge: POST /token {refresh_token}
        Bridge-->>App: temporal_token (1-hour JWT)
        App->>App: Store temporal_token
        Note over App: All subsequent API calls include<br/>Authorization: Bearer {temporal_token}
    end
```

## NFC Card Communication Stack

```mermaid
graph TB
    subgraph AndroidApp["Android Demo App"]
        NfcHelper["NfcCardAuthHelper<br/><i>Foreground Dispatch</i>"]
        Reader["ImpalaCardReader<br/><i>High-level card API</i>"]
    end

    subgraph PortedSDK["Ported from impala-lib / impala-card SDK"]
        APDUBIBO["APDUBIBO<br/><i>APDU marshalling</i>"]
        IsoDepBibo["IsoDepBibo<br/><i>Android NFC adapter</i>"]
        CmdAPDU["CommandAPDU<br/><i>ISO 7816-4 encoder</i>"]
        RspAPDU["ResponseAPDU<br/><i>Status word parser</i>"]
        BIBO["BIBO Interface<br/><i>Byte-level transceive</i>"]
    end

    subgraph NFC["Android NFC Stack"]
        IsoDep["IsoDep<br/><i>ISO 14443-4</i>"]
        NfcAdapter["NfcAdapter<br/><i>Foreground Dispatch</i>"]
    end

    subgraph Card["Impala Smartcard"]
        Applet["ImpalaApplet<br/><i>JavaCard 3.0.5</i>"]
        ECKey["EC Key Pair<br/><i>secp256r1</i>"]
        PINMgr["PIN Manager<br/><i>Master + User</i>"]
        Balance["Balance Ledger"]
    end

    NfcHelper --> Reader
    Reader --> APDUBIBO
    APDUBIBO --> CmdAPDU
    APDUBIBO --> RspAPDU
    APDUBIBO --> IsoDepBibo
    IsoDepBibo --> BIBO
    IsoDepBibo --> IsoDep
    IsoDep -->|"RF / ISO 14443-4"| Applet
    NfcAdapter --> IsoDep

    Applet --> ECKey
    Applet --> PINMgr
    Applet --> Balance
```

## Bridge Network Integration

```mermaid
graph TB
    subgraph Bridge["impala-bridge"]
        SubEndpoint["/subscribe Endpoint"]
        SyncEndpoint["/sync Endpoint"]
        TxEndpoint["/transaction Endpoint"]
        CronTask["Cron Sync Task<br/><i>tokio::spawn, 60s</i>"]
    end

    subgraph Stellar["Stellar Network"]
        Horizon["Horizon API<br/><i>horizon.stellar.org</i>"]
        SorobanRPC["Soroban RPC<br/><i>soroban-testnet.stellar.org</i>"]
        Ledgers["Ledger Stream<br/><i>/ledgers?cursor=now</i>"]
        SorobanContract["MultisigAssetWrapper<br/><i>Soroban Contract</i>"]
    end

    subgraph Payala["Payala Network"]
        PayalaTCP["TCP Event Stream<br/><i>Configurable endpoint</i>"]
    end

    subgraph Storage["Storage"]
        Redis[("Redis")]
        Postgres[("PostgreSQL")]
    end

    SubEndpoint -->|"network: stellar<br/>SSE Stream"| Horizon
    Horizon --> Ledgers
    SubEndpoint -->|"network: payala<br/>TCP Listener"| PayalaTCP

    SyncEndpoint -->|"JSON-RPC<br/>getTransactions"| SorobanRPC

    Ledgers -->|"stellar:latest_ledger<br/>stellar:ledger:{seq}"| Redis
    PayalaTCP -->|"payala:latest_event<br/>payala:event:{ts}:{uuid}"| Redis
    SyncEndpoint -->|"{account_id} -> timestamp"| Redis

    TxEndpoint -->|"INSERT transaction"| Postgres
    SyncEndpoint -->|"Cross-reference<br/>stellar_tx_id"| Postgres

    CronTask -->|"SELECT callback_uri"| Postgres
    CronTask -->|"GET callback<br/>UPDATE result"| Postgres

    SorobanRPC --- SorobanContract
```

## Data Model

```mermaid
erDiagram
    impala_account {
        serial id PK
        varchar stellar_account_id UK
        varchar payala_account_id UK
        varchar first_name
        varchar middle_name
        varchar last_name
        varchar nickname
        varchar affiliation
        varchar gender
        timestamptz created_at
        timestamptz updated_at
    }

    impala_auth {
        serial id PK
        varchar account_id FK
        varchar password_hash
        timestamptz created_at
        timestamptz updated_at
    }

    card {
        serial id PK
        varchar account_id
        varchar card_id
        varchar ec_pubkey UK
        varchar rsa_pubkey UK
        boolean is_delete
        timestamptz created_at
        timestamptz updated_at
    }

    transaction {
        uuid btxid PK
        varchar stellar_tx_id
        varchar payala_tx_id
        varchar stellar_hash
        varchar source_account
        bigint stellar_fee
        text memo
        varchar payala_currency
        varchar payala_digest
        timestamptz created_at
    }

    impala_mfa {
        varchar account_id PK
        varchar mfa_type PK
        varchar secret
        varchar phone_number
        boolean enabled
        timestamptz created_at
        timestamptz updated_at
    }

    notify {
        serial id PK
        varchar account_id
        enum medium
        varchar mobile
        varchar wa
        varchar signal
        varchar tel
        varchar email
        varchar url
        varchar app
        timestamptz created_at
        timestamptz updated_at
    }

    impala_account ||--o| impala_auth : "has credentials"
    impala_account ||--o{ card : "registers"
    impala_account ||--o{ impala_mfa : "enrolls"
    impala_account ||--o{ notify : "configures"
    impala_account ||--o{ transaction : "initiates"
```

## Soroban Contract Operations

```mermaid
stateDiagram-v2
    [*] --> Initialized : initialize(signers, threshold, token, min_duration)

    Initialized --> Wrapped : wrap(signers, amount)

    Wrapped --> UnwrapScheduled : schedule_unwrap(signers, recipient, amount, delay)
    UnwrapScheduled --> Unwrapped : execute_unwrap(timelock_id) after delay elapsed
    UnwrapScheduled --> Wrapped : cancel_timelock(signers, timelock_id)

    Wrapped --> TransferScheduled : schedule_transfer(signers, from, to, amount, delay)
    TransferScheduled --> Wrapped : execute_transfer(timelock_id) after delay elapsed
    TransferScheduled --> Wrapped : cancel_timelock(signers, timelock_id)
```

## Android App Authentication Methods

```mermaid
flowchart TB
    Start(["App Launch"]) --> SessionCheck{"Valid<br/>session?"}
    SessionCheck -->|Yes| Main(["MainActivity"])
    SessionCheck -->|No| Login["Login Screen"]

    Login --> PW["Username /<br/>Password"]
    Login --> Google["Continue with<br/>Google"]
    Login --> GitHub["Continue with<br/>GitHub"]
    Login --> CardAuth["Sign in with<br/>Card"]

    PW -->|"account_id + password"| AuthFlow
    Google -->|"Credential Manager<br/>ID Token"| DeriveG["SHA-256(idToken)<br/>.take(32)"]
    GitHub -->|"OAuth Code Flow<br/>Access Token"| DeriveH["SHA-256(code)<br/>.take(32)"]
    CardAuth -->|"NFC Tap<br/>Card UUID"| DeriveC["SHA-256(cardId)<br/>.take(32)"]

    DeriveG --> EnsureAcct["POST /account<br/><i>ensure exists</i>"]
    DeriveH --> EnsureAcct
    DeriveC --> EnsureAcct
    EnsureAcct --> AuthFlow

    AuthFlow["POST /authenticate"] --> TokenFlow["POST /token<br/><i>username + password</i>"]
    TokenFlow --> RefreshTok["refresh_token<br/><i>30-day JWT</i>"]
    RefreshTok --> TemporalFlow["POST /token<br/><i>refresh_token</i>"]
    TemporalFlow --> TemporalTok["temporal_token<br/><i>1-hour JWT</i>"]
    TemporalTok --> Store["EncryptedSharedPreferences<br/><i>AES-256-SIV / GCM</i>"]
    Store --> Main

    CardAuth -->|"Best-effort"| RegCard["POST /card<br/><i>register pubkeys</i>"]

    subgraph MainApp["MainActivity Tabs"]
        Main --> Cards["Cards Tab<br/><i>NFC register / delete</i>"]
        Main --> Transfers["Transfers Tab<br/><i>POST /transaction</i>"]
        Main --> Settings["Settings Tab<br/><i>MFA / Logout</i>"]
    end

    Cards -->|"POST /card"| BridgeAPI
    Cards -->|"DELETE /card"| BridgeAPI
    Transfers -->|"POST /transaction"| BridgeAPI
    Settings -->|"GET /mfa"| BridgeAPI
    Settings -->|"POST /mfa"| BridgeAPI

    BridgeAPI["impala-bridge<br/><i>Authorization: Bearer token</i>"]
```

## Admin Web UI Architecture

```mermaid
graph TB
    subgraph AdminUI["Admin Web UI"]
        Dashboard["Dashboard<br/><i>Account overview</i>"]
        AcctMgmt["Account Management<br/><i>Create / Update / Lookup</i>"]
        CardMgmt["Card Management<br/><i>Register / Revoke</i>"]
        TxView["Transaction Viewer<br/><i>Stellar + Payala ledger</i>"]
        MfaMgmt["MFA Management<br/><i>Enroll / Verify</i>"]
        NotifyMgmt["Notification Config<br/><i>Webhook / SMS / Push</i>"]
        NetMon["Network Monitor<br/><i>Subscribe + Sync status</i>"]
        SysInfo["System Info<br/><i>Version / Health</i>"]
    end

    subgraph AdminAPI["Admin API &lpar;impala-bridge&rpar;"]
        direction LR
        EP_Acc["/account"]
        EP_Card["/card"]
        EP_Tx["/transaction"]
        EP_Mfa["/mfa"]
        EP_Notify["/notify"]
        EP_Sub["/subscribe"]
        EP_Sync["/sync"]
        EP_Ver["/version"]
    end

    Dashboard --> EP_Acc
    Dashboard --> EP_Ver
    AcctMgmt --> EP_Acc
    CardMgmt --> EP_Card
    TxView --> EP_Tx
    MfaMgmt --> EP_Mfa
    NotifyMgmt --> EP_Notify
    NetMon --> EP_Sub
    NetMon --> EP_Sync
    SysInfo --> EP_Ver
```

## Deployment Architecture

```mermaid
graph TB
    subgraph DockerCompose["Docker Compose Stack"]
        BridgeContainer["impala-bridge<br/><i>Rust / Axum</i><br/>:8080"]
        PGContainer["PostgreSQL 16<br/><i>5 migration scripts</i><br/>:5432"]
        RedisContainer["Redis 7<br/><i>Event cache + sync</i><br/>:6379"]
    end

    subgraph External["External Services"]
        Horizon["Stellar Horizon<br/><i>SSE ledger stream</i>"]
        SorobanRPC["Soroban RPC<br/><i>Transaction queries</i>"]
        PayalaTCP["Payala Network<br/><i>TCP events</i>"]
        VaultServer["HashiCorp Vault<br/><i>Secret management</i>"]
        Twilio["Twilio<br/><i>SMS MFA</i>"]
    end

    subgraph Config["Configuration"]
        EnvVars["Environment Variables<br/><i>DATABASE_URL, JWT_SECRET,<br/>REDIS_URL, STELLAR_*</i>"]
        ConfigFile["config.json<br/><i>service_address, log_file,<br/>debug_mode, twilio_*</i>"]
    end

    BridgeContainer --> PGContainer
    BridgeContainer --> RedisContainer
    BridgeContainer --> Horizon
    BridgeContainer --> SorobanRPC
    BridgeContainer --> PayalaTCP
    BridgeContainer -.-> VaultServer
    BridgeContainer -.-> Twilio

    EnvVars --> BridgeContainer
    ConfigFile --> BridgeContainer

    PGContainer -->|"Auto-migrations"| PGContainer
```

## APDU Command Reference

```mermaid
graph LR
    subgraph AuthCommands["Authentication Commands"]
        direction TB
        C1["INS 0x1E<br/>GET_USER_DATA<br/><i>accountId + cardId + name</i>"]
        C2["INS 0x24<br/>GET_EC_PUB_KEY<br/><i>65B secp256r1</i>"]
        C3["INS 0x07<br/>GET_RSA_PUB_KEY<br/><i>RSA modulus</i>"]
        C4["INS 0x25<br/>SIGN_AUTH<br/><i>ECDSA timestamp sig</i>"]
        C5["INS 0x23<br/>GET_CARD_NONCE<br/><i>4B random</i>"]
        C6["INS 0x18<br/>VERIFY_PIN<br/><i>P2: 0x81=master</i>"]
        C7["INS 0x64<br/>GET_VERSION<br/><i>major.minor.rev</i>"]
    end

    subgraph TransactionCommands["Transaction Commands"]
        direction TB
        A1["INS 0x02 NOP"]
        A2["INS 0x04 GET_BALANCE"]
        A3["INS 0x06 SIGN_TRANSFER"]
        A4["INS 0x14 VERIFY_TRANSFER"]
        A5["INS 0x16 GET_ACCOUNT_ID"]
    end

    subgraph ProvisioningCommands["Provisioning Commands"]
        direction TB
        A6["INS 0x19 UPDATE_USER_PIN"]
        A7["INS 0x1F SET_FULL_NAME"]
        A8["INS 0x22 SET_GENDER"]
        A9["INS 0x26 SET_CARD_DATA"]
        A10["INS 0x2C INITIALIZE"]
    end

    subgraph SCP03["SCP03 Secure Channel &lpar;CLA 0x80&rpar;"]
        S1["INS 0x50 INITIALIZE_UPDATE"]
        S2["INS 0x82 EXTERNAL_AUTHENTICATE"]
        S3["INS 0x70 PROVISION_PIN"]
        S4["INS 0x71 APPLET_UPDATE"]
    end
```

## JWT Token Lifecycle

```mermaid
sequenceDiagram
    participant App as Android App
    participant TM as TokenManager
    participant Int as AuthInterceptor
    participant Bridge as impala-bridge

    Note over App, Bridge: Login Phase
    App->>Bridge: POST /authenticate
    Bridge-->>App: {success}
    App->>Bridge: POST /token {username, password}
    Bridge-->>App: refresh_token (30-day)
    App->>TM: saveRefreshToken()
    App->>Bridge: POST /token {refresh_token}
    Bridge-->>App: temporal_token (1-hour)
    App->>TM: saveTemporalToken()

    Note over App, Bridge: API Request Phase
    App->>Int: API call (any endpoint)
    Int->>TM: getTemporalToken()
    TM-->>Int: token (if not expired)
    Int->>Bridge: Request + Authorization: Bearer {token}
    Bridge-->>App: Response

    Note over App, Bridge: Token Expiry
    App->>Int: API call
    Int->>TM: getTemporalToken()
    TM-->>Int: null (expired)
    Int->>Bridge: Request without Authorization
    Bridge-->>App: 401 Unauthorized
    App->>Bridge: POST /token {refresh_token}
    Bridge-->>App: new temporal_token (1-hour)
    App->>TM: saveTemporalToken()
```
