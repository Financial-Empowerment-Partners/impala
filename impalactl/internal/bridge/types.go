package bridge

import "encoding/json"

// The types below mirror impala-bridge/src/models.rs (and openapi.yaml). Server
// fields that are nullable are pointers here so "absent" stays distinguishable
// from "zero" — the CLI renders absent as "-" rather than as 0 or "".
//
// Request fields are omitempty wherever the bridge treats absent and empty
// differently; where it does not (a required name, say) the field is always
// sent so the server's own validation produces the error message.

// ── Auth ───────────────────────────────────────────────────────────────

// TokenRequest is POST /token. Supply either Username+Password or
// RefreshToken — never both.
type TokenRequest struct {
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenResponse carries the refresh/temporal pair. The refresh token is
// strictly single-use: presenting a rotated-out one revokes the whole family.
type TokenResponse struct {
	Result
	RefreshToken  string `json:"refresh_token"`
	TemporalToken string `json:"temporal_token"`
}

// LogoutResponse is POST /logout and POST /logout/all.
type LogoutResponse struct {
	Result
}

// ── Accounts ───────────────────────────────────────────────────────────

// CreateAccountRequest is POST /account.
type CreateAccountRequest struct {
	StellarAccountID string `json:"stellar_account_id"`
	PayalaAccountID  string `json:"payala_account_id"`
	FirstName        string `json:"first_name"`
	MiddleName       string `json:"middle_name,omitempty"`
	LastName         string `json:"last_name"`
	Nickname         string `json:"nickname,omitempty"`
	Affiliation      string `json:"affiliation,omitempty"`
	Gender           string `json:"gender,omitempty"`
}

// Account is GET /account.
type Account struct {
	PayalaAccountID  string  `json:"payala_account_id"`
	StellarAccountID string  `json:"stellar_account_id"`
	FirstName        string  `json:"first_name"`
	MiddleName       *string `json:"middle_name"`
	LastName         string  `json:"last_name"`
	Nickname         *string `json:"nickname"`
	Affiliation      *string `json:"affiliation"`
	Gender           *string `json:"gender"`
	Role             string  `json:"role"`
	SyncMode         string  `json:"sync_mode"`
	ProfileSource    string  `json:"profile_source"`
	ProfileSyncedAt  *string `json:"profile_synced_at"`
	CreatedAt        *string `json:"created_at"`
}

// AccountListItem is one row of GET /accounts (admin).
type AccountListItem struct {
	PayalaAccountID  string  `json:"payala_account_id"`
	StellarAccountID string  `json:"stellar_account_id"`
	FirstName        string  `json:"first_name"`
	MiddleName       *string `json:"middle_name"`
	LastName         string  `json:"last_name"`
	Nickname         *string `json:"nickname"`
	Affiliation      *string `json:"affiliation"`
	Gender           *string `json:"gender"`
	Role             string  `json:"role"`
	SyncMode         string  `json:"sync_mode"`
	ProfileSource    string  `json:"profile_source"`
	CreatedAt        *string `json:"created_at"`
}

// Page is the bridge's paginated envelope.
type Page[T any] struct {
	Data    []T    `json:"data"`
	Page    uint64 `json:"page"`
	PerPage uint64 `json:"per_page"`
	Total   uint64 `json:"total"`
}

// OnchainBalance is one balance line from Horizon.
type OnchainBalance struct {
	AssetType   string  `json:"asset_type"`
	AssetCode   *string `json:"asset_code"`
	AssetIssuer *string `json:"asset_issuer"`
	Balance     string  `json:"balance"`
}

// OnchainSigner is one signer entry from Horizon.
type OnchainSigner struct {
	Key    string `json:"key"`
	Weight int64  `json:"weight"`
	Type   string `json:"type"`
}

// OnchainAccount is GET /account/onchain — live Horizon state for the account.
type OnchainAccount struct {
	StellarAccountID string           `json:"stellar_account_id"`
	Exists           bool             `json:"exists"`
	Sequence         *string          `json:"sequence"`
	NativeBalance    *string          `json:"native_balance"`
	Balances         []OnchainBalance `json:"balances"`
	Signers          []OnchainSigner  `json:"signers"`
	SubentryCount    *int64           `json:"subentry_count"`
}

// ── Managed (custodial) accounts ───────────────────────────────────────

// GenerateManagedAccountRequest is POST /managed-account/generate.
type GenerateManagedAccountRequest struct {
	PayalaAccountID string `json:"payala_account_id"`
	FirstName       string `json:"first_name"`
	MiddleName      string `json:"middle_name,omitempty"`
	LastName        string `json:"last_name"`
	Nickname        string `json:"nickname,omitempty"`
	Affiliation     string `json:"affiliation,omitempty"`
	Gender          string `json:"gender,omitempty"`
}

// ImportManagedAccountRequest is POST /managed-account/import. SecretSeed is
// the caller's `S...` seed; it is sent once and never stored locally.
type ImportManagedAccountRequest struct {
	PayalaAccountID string `json:"payala_account_id"`
	SecretSeed      string `json:"secret_seed"`
	FirstName       string `json:"first_name"`
	MiddleName      string `json:"middle_name,omitempty"`
	LastName        string `json:"last_name"`
	Nickname        string `json:"nickname,omitempty"`
	Affiliation     string `json:"affiliation,omitempty"`
	Gender          string `json:"gender,omitempty"`
}

// ManagedAccountResponse is the reply to generate/import.
type ManagedAccountResponse struct {
	Result
	StellarAccountID string `json:"stellar_account_id"`
}

// SignSubmitRequest is POST /managed-account/sign — a real, irreversible XLM
// payment signed server-side from the custodial seed.
type SignSubmitRequest struct {
	PayalaAccountID string  `json:"payala_account_id"`
	Destination     string  `json:"destination"`
	Amount          string  `json:"amount"`
	Memo            string  `json:"memo,omitempty"`
	Fee             *uint32 `json:"fee,omitempty"`
}

// SignSubmitResponse carries the on-ledger hash and the bridge's record id.
type SignSubmitResponse struct {
	Result
	StellarHash string `json:"stellar_hash"`
	BTxID       string `json:"btxid"`
}

// ── Sync ───────────────────────────────────────────────────────────────

// SyncRequest is POST /sync. Despite the field name, AccountID is a Stellar
// G-address (the bridge validates it as one).
type SyncRequest struct {
	AccountID string `json:"account_id"`
}

// SyncResponse is the recorded sync timestamp.
type SyncResponse struct {
	Result
	Timestamp string `json:"timestamp"`
}

// SyncedProfile is the directory profile pulled by a force profile sync.
type SyncedProfile struct {
	FirstName   *string `json:"first_name"`
	MiddleName  *string `json:"middle_name"`
	LastName    *string `json:"last_name"`
	Affiliation *string `json:"affiliation"`
}

// SyncProfileResponse is POST /admin/accounts/{id}/sync-profile.
type SyncProfileResponse struct {
	Result
	ProfileSource   string         `json:"profile_source"`
	ProfileSyncedAt *string        `json:"profile_synced_at"`
	Profile         *SyncedProfile `json:"profile"`
}

// SetSyncModeRequest is PUT /admin/accounts/{id}/sync-mode. Force is required
// to leave reserve mode while a nonzero balance remains.
type SetSyncModeRequest struct {
	SyncMode string `json:"sync_mode"`
	Force    *bool  `json:"force,omitempty"`
}

// SetSyncModeResponse echoes the account's new mode.
type SetSyncModeResponse struct {
	Result
	AccountID string `json:"account_id"`
	SyncMode  string `json:"sync_mode"`
}

// PayalaSyncItem is one offline Payala transaction. Amount is a signed integer
// in minor units; the sign is the direction (+incoming / -outgoing).
type PayalaSyncItem struct {
	PayalaTxID   string `json:"payala_tx_id"`
	Amount       int64  `json:"amount"`
	Currency     string `json:"currency"`
	Memo         string `json:"memo,omitempty"`
	PayalaDigest string `json:"payala_digest,omitempty"`
}

// PayalaSyncRequest is POST /sync/payala. AccountID is the caller's Payala
// account id (the JWT sub), not a Stellar address.
type PayalaSyncRequest struct {
	AccountID    string           `json:"account_id"`
	Transactions []PayalaSyncItem `json:"transactions"`
}

// ReserveBalance is a per-currency reserve balance in minor units.
type ReserveBalance struct {
	Currency  string  `json:"currency"`
	Balance   int64   `json:"balance"`
	UpdatedAt *string `json:"updated_at"`
}

// PayalaSyncResponse reports what a batch actually applied. Duplicates are
// routine idempotency; Conflicting means a replayed id arrived with a
// different amount or currency than the stored one.
type PayalaSyncResponse struct {
	Result
	BatchID         string           `json:"batch_id"`
	SyncMode        string           `json:"sync_mode"`
	Received        int              `json:"received"`
	Applied         int              `json:"applied"`
	Duplicates      int              `json:"duplicates"`
	Conflicting     int              `json:"conflicting"`
	NetDeltas       map[string]int64 `json:"net_deltas"`
	ReserveBalances []ReserveBalance `json:"reserve_balances"`
}

// ReserveBalancesResponse is GET /reserves/{account_id}.
type ReserveBalancesResponse struct {
	AccountID string           `json:"account_id"`
	SyncMode  string           `json:"sync_mode"`
	Reserves  []ReserveBalance `json:"reserves"`
}

// ── Transactions ───────────────────────────────────────────────────────

// CreateTransactionRequest is POST /transaction — a dual-chain bookkeeping
// record. At least one of StellarTxID or PayalaTxID is required.
type CreateTransactionRequest struct {
	StellarTxID    string `json:"stellar_tx_id,omitempty"`
	PayalaTxID     string `json:"payala_tx_id,omitempty"`
	StellarHash    string `json:"stellar_hash,omitempty"`
	SourceAccount  string `json:"source_account,omitempty"`
	StellarFee     *int64 `json:"stellar_fee,omitempty"`
	StellarMaxFee  *int64 `json:"stellar_max_fee,omitempty"`
	Memo           string `json:"memo,omitempty"`
	Signatures     string `json:"signatures,omitempty"`
	Preconditions  string `json:"preconditions,omitempty"`
	PayalaCurrency string `json:"payala_currency,omitempty"`
	PayalaDigest   string `json:"payala_digest,omitempty"`
}

// CreateTransactionResponse carries the new bridge transaction id.
type CreateTransactionResponse struct {
	Result
	BTxID string `json:"btxid"`
}

// Transaction is a row of GET /transactions and the body of
// GET /transaction/{btxid} (the detail adds signatures/preconditions/digest).
type Transaction struct {
	BTxID          string  `json:"btxid"`
	StellarTxID    *string `json:"stellar_tx_id"`
	PayalaTxID     *string `json:"payala_tx_id"`
	StellarHash    *string `json:"stellar_hash"`
	SourceAccount  *string `json:"source_account"`
	StellarFee     *int64  `json:"stellar_fee"`
	StellarMaxFee  *int64  `json:"stellar_max_fee"`
	Memo           *string `json:"memo"`
	Signatures     *string `json:"signatures"`
	Preconditions  *string `json:"preconditions"`
	PayalaCurrency *string `json:"payala_currency"`
	PayalaDigest   *string `json:"payala_digest"`
	PayalaAmount   *int64  `json:"payala_amount"`
	Origin         string  `json:"origin"`
	CreatedAt      string  `json:"created_at"`
	Flagged        bool    `json:"flagged"`
	Status         string  `json:"status"`
	Note           *string `json:"note"`
	ReviewedBy     *string `json:"reviewed_by"`
	ReviewedAt     *string `json:"reviewed_at"`
}

// ReviewTransactionRequest is PUT /transaction/{btxid}/review. The PUT
// replaces the whole review state: omitted fields are reset, not preserved.
type ReviewTransactionRequest struct {
	Flagged *bool  `json:"flagged,omitempty"`
	Status  string `json:"status,omitempty"`
	Note    string `json:"note,omitempty"`
}

// ReviewTransactionResponse echoes the stored review state.
type ReviewTransactionResponse struct {
	Result
	BTxID   string `json:"btxid"`
	Flagged bool   `json:"flagged"`
	Status  string `json:"status"`
}

// ── Admin event feed ───────────────────────────────────────────────────

// Event is one entry of the admin event feed.
type Event struct {
	ID        int64           `json:"id"`
	EventType string          `json:"event_type"`
	AccountID string          `json:"account_id"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt string          `json:"created_at"`
}

// EventsResponse is GET /admin/events.
type EventsResponse struct {
	Events []Event `json:"events"`
}

// ── Service info ───────────────────────────────────────────────────────

// Health is GET /health.
type Health struct {
	Status         string `json:"status"`
	Database       string `json:"database"`
	Redis          string `json:"redis"`
	StellarNetwork string `json:"stellar_network"`
}

// Version is GET /version.
type Version struct {
	Name          string  `json:"name"`
	Version       string  `json:"version"`
	BuildDate     string  `json:"build_date"`
	RustcVersion  string  `json:"rustc_version"`
	SchemaVersion *string `json:"schema_version"`
}

// NetworkInfo is GET /network — which Stellar network the bridge is wired to.
type NetworkInfo struct {
	StellarNetwork    string `json:"stellar_network"`
	StellarHorizonURL string `json:"stellar_horizon_url"`
	StellarRPCURL     string `json:"stellar_rpc_url"`
	NetworkPassphrase string `json:"network_passphrase"`
	SorobanContractID string `json:"soroban_contract_id"`
}

// IsTestnet reports whether the bridge is on the Stellar test network, where
// funds are not real.
func (n NetworkInfo) IsTestnet() bool { return n.StellarNetwork == "testnet" }
