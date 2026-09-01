package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"
)

// assetIssuer is a known-valid account (the SEP-23 test vector's underlying
// G address), usable as an issuer in fixtures without generating keys.
const assetIssuer = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"

// sep23Muxed is the SEP-23 test vector M address (multiplexes assetIssuer).
const sep23Muxed = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"

// TestFilterMatchDirection: a self transfer is both a send and a receive, so
// it passes either direction filter; the opposite direction is blocked.
func TestFilterMatchDirection(t *testing.T) {
	cases := []struct {
		name      string
		filterDir string
		entryDir  string
		want      bool
	}{
		{"sent filter passes sent", dirSent, dirSent, true},
		{"sent filter passes self", dirSent, dirSelf, true},
		{"sent filter blocks received", dirSent, dirReceived, false},
		{"received filter passes received", dirReceived, dirReceived, true},
		{"received filter passes self", dirReceived, dirSelf, true},
		{"received filter blocks sent", dirReceived, dirSent, false},
		{"no direction filter passes sent", "", dirSent, true},
		{"no direction filter passes received", "", dirReceived, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			f := historyFilter{direction: tt.filterDir}
			if got := f.match(historyEntry{Direction: tt.entryDir}); got != tt.want {
				t.Errorf("match(%q entry) with direction %q = %v, want %v",
					tt.entryDir, tt.filterDir, got, tt.want)
			}
		})
	}
}

// TestFilterMatchCounterparty: a G spec matches the counterparty account —
// with or without a muxed form on the record — while an M spec matches only
// the exact muxed form the payment carried, never every payment of the
// underlying account (an M address names one depositor among many).
func TestFilterMatchCounterparty(t *testing.T) {
	other, third := historyAddrs(t)
	mux1 := muxedFor(t, other, 1)
	mux2 := muxedFor(t, other, 2)

	cases := []struct {
		name  string
		spec  string
		entry historyEntry
		want  bool
	}{
		{"G spec matches the counterparty", other,
			historyEntry{Counterparty: other}, true},
		{"G spec blocks a different account", other,
			historyEntry{Counterparty: third}, false},
		{"G spec matches a record carrying a mux", other,
			historyEntry{Counterparty: other, ToMuxed: mux1}, true},
		{"M spec matches the exact ToMuxed", mux1,
			historyEntry{Counterparty: other, ToMuxed: mux1}, true},
		{"M spec matches the exact FromMuxed", mux1,
			historyEntry{Counterparty: other, FromMuxed: mux1}, true},
		{"M spec blocks a different mux of the same account", mux1,
			historyEntry{Counterparty: other, ToMuxed: mux2}, false},
		{"M spec blocks an unmuxed record of the same account", mux1,
			historyEntry{Counterparty: other}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			f := historyFilter{counterparty: tt.spec}
			if got := f.match(tt.entry); got != tt.want {
				t.Errorf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCounterparty(t *testing.T) {
	g, _ := historyAddrs(t)
	cases := []struct {
		name   string
		in     string
		want   string // "" with errHas set
		errHas string
	}{
		{"valid G address", g, g, ""},
		{"G address trimmed", "  " + g + "  ", g, ""},
		{"known-valid M address", sep23Muxed, sep23Muxed, ""},
		{"garbage", "garbage", "", "invalid account address"},
		{"M-prefixed garbage", "MNOPE", "", "invalid muxed address"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCounterparty(tt.in)
			if tt.errHas != "" {
				if err == nil {
					t.Fatalf("parseCounterparty(%q) = %q, want error containing %q", tt.in, got, tt.errHas)
				}
				if !strings.Contains(err.Error(), tt.errHas) {
					t.Errorf("error %q missing %q", err, tt.errHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCounterparty(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseCounterparty(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	// A built M address (not just the fixed vector) must also be accepted.
	built := muxedFor(t, g, 7)
	if got, err := parseCounterparty(built); err != nil || got != built {
		t.Errorf("parseCounterparty(%q) = %q, %v, want the address back", built, got, err)
	}
}

// parseAssetCases doubles as the parseAssetSpec table and the FuzzParseAsset
// seed corpus. A bare code is rejected because asset codes are not unique:
// an issuer-less match could present a counterfeit asset as the real one.
var parseAssetCases = []struct {
	name         string
	in           string
	native       bool
	code, issuer string
	errHas       string // "" = accepted
}{
	{"native word", "native", true, "", "", ""},
	{"XLM", "XLM", true, "", "", ""},
	{"lowercase xlm", "xlm", true, "", "", ""},
	{"issued CODE:ISSUER", "USDC:" + assetIssuer, false, "USDC", assetIssuer, ""},
	{"12-character code", "ABCDEFGHIJKL:" + assetIssuer, false, "ABCDEFGHIJKL", assetIssuer, ""},
	{"bare code", "USDC", false, "", "", "issuer is required"},
	{"bad issuer", "USDC:not-an-issuer", false, "", "", "invalid asset issuer"},
	{"over-long code", "ABCDEFGHIJKLM:" + assetIssuer, false, "", "", "at most 12 characters"},
	{"empty code", ":" + assetIssuer, false, "", "", "issuer is required"},
	{"empty", "", false, "", "", "requires a value"},
}

func TestParseAssetSpec(t *testing.T) {
	for _, tt := range parseAssetCases {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := parseAssetSpec(tt.in)
			if tt.errHas != "" {
				if err == nil {
					t.Fatalf("parseAssetSpec(%q) = %+v, want error containing %q", tt.in, spec, tt.errHas)
				}
				if !strings.Contains(err.Error(), tt.errHas) {
					t.Errorf("error %q missing %q", err, tt.errHas)
				}
				if spec != nil {
					t.Errorf("non-nil spec %+v alongside an error", spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAssetSpec(%q): %v", tt.in, err)
			}
			if spec.native != tt.native || spec.code != tt.code || spec.issuer != tt.issuer {
				t.Errorf("parseAssetSpec(%q) = %+v, want native=%v code=%q issuer=%q",
					tt.in, spec, tt.native, tt.code, tt.issuer)
			}
		})
	}
}

// FuzzParseAsset: parseAssetSpec must never panic on arbitrary input, and
// must return exactly one of a spec or an error.
func FuzzParseAsset(f *testing.F) {
	for _, tt := range parseAssetCases {
		f.Add(tt.in)
	}
	f.Fuzz(func(t *testing.T, s string) {
		spec, err := parseAssetSpec(s)
		if (spec == nil) == (err == nil) {
			t.Errorf("parseAssetSpec(%q) = %+v, %v: want exactly one of spec, error", s, spec, err)
		}
	})
}

// TestAssetSpecMatches: an issued spec requires the exact code AND issuer —
// the same code from a different issuer is a different (possibly counterfeit)
// asset — and the zero base.Asset (an entry leg with no asset) matches
// nothing.
func TestAssetSpecMatches(t *testing.T) {
	otherIssuer, _ := historyAddrs(t)
	nativeSpec := &assetSpec{native: true}
	usdcSpec := &assetSpec{code: "USDC", issuer: assetIssuer}

	nativeAsset := base.Asset{Type: "native"}
	usdc := base.Asset{Type: "credit_alphanum4", Code: "USDC", Issuer: assetIssuer}
	usdcOther := base.Asset{Type: "credit_alphanum4", Code: "USDC", Issuer: otherIssuer}

	cases := []struct {
		name  string
		spec  *assetSpec
		asset base.Asset
		want  bool
	}{
		{"native spec matches native", nativeSpec, nativeAsset, true},
		{"native spec blocks issued", nativeSpec, usdc, false},
		{"native spec blocks the zero asset", nativeSpec, base.Asset{}, false},
		{"issued spec matches exact code and issuer", usdcSpec, usdc, true},
		{"issued spec blocks the same code from another issuer", usdcSpec, usdcOther, false},
		{"issued spec blocks native", usdcSpec, nativeAsset, false},
		{"issued spec blocks the zero asset", usdcSpec, base.Asset{}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.spec.matches(tt.asset); got != tt.want {
				t.Errorf("matches(%+v) = %v, want %v", tt.asset, got, tt.want)
			}
		})
	}
}

func TestParseTimeFlag(t *testing.T) {
	got, err := parseTimeFlag("--since", "2026-08-30", false)
	if err != nil {
		t.Fatalf("bare date: %v", err)
	}
	if want := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("bare date = %v, want UTC midnight %v", got, want)
	}

	got, err = parseTimeFlag("--until", "2026-08-30", true)
	if err != nil {
		t.Fatalf("bare date endOfDay: %v", err)
	}
	if want := time.Date(2026, 8, 30, 23, 59, 59, 999999999, time.UTC); !got.Equal(want) {
		t.Errorf("endOfDay = %v, want the day's last instant %v", got, want)
	}

	const rfc = "2026-08-30T17:00:00-07:00"
	got, err = parseTimeFlag("--since", rfc, false)
	if err != nil {
		t.Fatalf("RFC3339: %v", err)
	}
	if !got.Equal(time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("RFC3339 = %v, want the instant 2026-08-31T00:00:00Z", got)
	}
	if got.Format(time.RFC3339) != rfc {
		t.Errorf("offset not preserved: %v round-trips to %q, want %q", got, got.Format(time.RFC3339), rfc)
	}

	if got, err = parseTimeFlag("--since", "", false); err != nil || !got.IsZero() {
		t.Errorf("empty value = %v, %v, want the zero time and no error", got, err)
	}

	for _, name := range []string{"--since", "--until"} {
		if _, err := parseTimeFlag(name, "yesterday", false); err == nil {
			t.Errorf("%s accepted garbage", name)
		} else if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the %s flag", err, name)
		}
	}
}

// TestFilterSinceUntilBoundaries pins the range semantics: --since is
// inclusive, a date-only --until covers its whole UTC day, and beforeSince —
// which ends the newest-first walk — is true only for strictly-older entries,
// since same-instant entries may still remain on the page.
func TestFilterSinceUntilBoundaries(t *testing.T) {
	since, err := parseTimeFlag("--since", "2026-08-30", false)
	if err != nil {
		t.Fatalf("--since: %v", err)
	}
	until, err := parseTimeFlag("--until", "2026-08-30", true)
	if err != nil {
		t.Fatalf("--until: %v", err)
	}
	f := historyFilter{since: since, until: until}

	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"exactly at --since", since, true},
		{"one second before --since", since.Add(-time.Second), false},
		{"last second of the --until day", time.Date(2026, 8, 30, 23, 59, 59, 0, time.UTC), true},
		{"midnight of the next day", time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC), false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.match(historyEntry{Direction: dirSent, CreatedAt: tt.at}); got != tt.want {
				t.Errorf("match(entry at %v) = %v, want %v", tt.at, got, tt.want)
			}
		})
	}

	if f.beforeSince(historyEntry{CreatedAt: since}) {
		t.Error("beforeSince true for an entry exactly at --since (would end the walk on an inclusive bound)")
	}
	if !f.beforeSince(historyEntry{CreatedAt: since.Add(-time.Nanosecond)}) {
		t.Error("beforeSince false for a strictly-older entry")
	}
	var unbounded historyFilter
	if unbounded.beforeSince(historyEntry{CreatedAt: since.Add(-time.Hour)}) {
		t.Error("beforeSince true with no --since bound")
	}
}
