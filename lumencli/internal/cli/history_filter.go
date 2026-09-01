package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"
	"github.com/stellar/go-stellar-sdk/strkey"

	"lumencli/internal/wallet"
)

// historyFilter is the set of client-side predicates a history walk applies.
// All filtering happens here, after entries are built — Horizon has no
// server-side equivalents for these, and keeping them out of internal/stellar
// keeps that package a thin Horizon adapter.
type historyFilter struct {
	direction    string     // dirSent, dirReceived, or "" for both
	counterparty string     // G... (matches the underlying account) or M... (matches the exact muxed form)
	asset        *assetSpec // nil = any asset
	since, until time.Time  // zero = unbounded
}

// active reports whether any predicate is set — it decides whether an empty
// listing says "(no transactions)" or "(no entries match the filters)", which
// mean different things to someone checking whether a deposit arrived.
func (f *historyFilter) active() bool {
	return f.direction != "" || f.counterparty != "" || f.asset != nil || !f.since.IsZero() || !f.until.IsZero()
}

// match reports whether e passes every predicate.
func (f *historyFilter) match(e historyEntry) bool {
	// A self transfer is both a send and a receive, so it matches either
	// direction filter.
	if f.direction != "" && e.Direction != f.direction && e.Direction != dirSelf {
		return false
	}
	if f.counterparty != "" && !matchCounterparty(f.counterparty, e) {
		return false
	}
	// An account merge moves exclusively the native lumen, so a native filter
	// keeps merges — dropping them would hide fund movements (and silence the
	// summary's lower-bounds disclaimer) exactly when the user asked to see
	// everything XLM.
	if f.asset != nil && !f.asset.matches(e.Asset) && !f.asset.matches(e.SourceAsset) &&
		!(f.asset.native && e.EntireBalance) {
		return false
	}
	if !f.since.IsZero() && e.CreatedAt.Before(f.since) {
		return false
	}
	if !f.until.IsZero() && e.CreatedAt.After(f.until) {
		return false
	}
	return true
}

// beforeSince reports whether e is strictly older than the --since bound —
// the walk stops paging entirely there, since Horizon pages newest-first.
// Strictly: an entry exactly at the bound is included (--since is inclusive)
// and must not end the walk while same-second entries may remain.
func (f *historyFilter) beforeSince(e historyEntry) bool {
	return !f.since.IsZero() && e.CreatedAt.Before(f.since)
}

// matchCounterparty matches a G-address against the entry's counterparty
// account, or an M-address against the exact muxed form the payment carried
// (on either side). A muxed address identifies one depositor among the many
// sharing an account, so an M input must not loosely match every payment of
// the underlying account.
func matchCounterparty(spec string, e historyEntry) bool {
	if strings.HasPrefix(spec, "M") {
		return e.ToMuxed == spec || e.FromMuxed == spec
	}
	return e.Counterparty == spec
}

// parseCounterparty validates the --counterparty value: a G-address or a
// muxed M-address.
func parseCounterparty(s string) (string, error) {
	v := strings.TrimSpace(s)
	if strings.HasPrefix(v, "M") {
		if !strkey.IsValidMuxedAccountEd25519PublicKey(v) {
			return "", fmt.Errorf("invalid muxed address %q (expected an M... address)", s)
		}
		return v, nil
	}
	if err := wallet.ValidateAddress(v); err != nil {
		return "", err
	}
	return v, nil
}

// assetSpec is a fully-qualified asset filter: the native lumen, or an issued
// asset as CODE:ISSUER.
type assetSpec struct {
	native bool
	code   string
	issuer string
}

// parseAssetSpec parses --asset. "native" and "XLM" mean the native lumen;
// anything else must be CODE:ISSUER. A bare code without an issuer is
// rejected rather than matched loosely: asset codes are not unique on
// Stellar, and an issuer-less match could present a counterfeit asset as the
// real one.
func parseAssetSpec(s string) (*assetSpec, error) {
	v := strings.TrimSpace(s)
	switch strings.ToUpper(v) {
	case "":
		return nil, fmt.Errorf("--asset requires a value: native, XLM, or CODE:ISSUER")
	case "NATIVE", "XLM":
		return &assetSpec{native: true}, nil
	}
	code, issuer, ok := strings.Cut(v, ":")
	if !ok || code == "" {
		return nil, fmt.Errorf(
			"invalid asset %q: want native, XLM, or CODE:ISSUER (asset codes are not unique, so the issuer is required)", s)
	}
	if len(code) > 12 {
		return nil, fmt.Errorf("invalid asset code %q: at most 12 characters", code)
	}
	if err := wallet.ValidateAddress(issuer); err != nil {
		return nil, fmt.Errorf("invalid asset issuer in %q: %v", s, err)
	}
	return &assetSpec{code: code, issuer: issuer}, nil
}

// matches reports whether a matches the spec. The zero base.Asset (an entry
// leg with no asset) matches nothing.
func (s *assetSpec) matches(a base.Asset) bool {
	if s.native {
		return a.Type == "native"
	}
	return a.Type != "" && a.Type != "native" && a.Code == s.code && a.Issuer == s.issuer
}

// String renders the spec the way the user gave it, for messages.
func (s *assetSpec) String() string {
	if s.native {
		return "native"
	}
	return s.code + ":" + s.issuer
}

// parseTimeFlag parses --since/--until. It accepts a bare date (YYYY-MM-DD,
// interpreted as UTC) or an RFC3339 timestamp (which carries its own offset,
// so local-time precision is available). endOfDay shifts a bare date to the
// last instant of that UTC day, making a date-only --until inclusive through
// the whole day.
func parseTimeFlag(name, s string, endOfDay bool) (time.Time, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		if endOfDay {
			t = t.Add(24*time.Hour - time.Nanosecond)
		}
		return t, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s value %q: want YYYY-MM-DD (UTC) or RFC3339 (e.g. 2026-08-30T17:00:00-07:00)", name, s)
	}
	return t, nil
}
