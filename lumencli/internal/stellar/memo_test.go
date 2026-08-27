package stellar

import (
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/txnbuild"
)

func TestParseMemo(t *testing.T) {
	const hash64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var wantHash [32]byte
	for i := range wantHash {
		// 0x01, 0x23, 0x45 ... repeating, matching hash64 above.
		wantHash[i] = byte((i%8)*0x22 + 0x01)
	}

	tests := []struct {
		name      string
		memoType  string
		value     string
		want      Memo
		wantErrIs string // substring the error must contain; "" means no error
	}{
		{name: "unspecified", want: nil},
		{name: "bare value defaults to text", value: "thanks", want: txnbuild.MemoText("thanks")},
		{name: "explicit text", memoType: "text", value: "thanks", want: txnbuild.MemoText("thanks")},
		{name: "text keeps surrounding spaces", value: " pad ", want: txnbuild.MemoText(" pad ")},
		{name: "text at the byte limit", value: strings.Repeat("x", 28), want: txnbuild.MemoText(strings.Repeat("x", 28))},
		{name: "text over the byte limit", value: strings.Repeat("x", 29), wantErrIs: "too long"},
		// 10 three-byte runes are 30 bytes: under the character count, over the limit.
		{name: "multibyte text counted in bytes", value: strings.Repeat("€", 10), wantErrIs: "30 bytes"},
		{name: "text type without a value", memoType: "text", wantErrIs: "needs a memo value"},

		{name: "id", memoType: "id", value: "1234567890", want: txnbuild.MemoID(1234567890)},
		{name: "id trimmed", memoType: "id", value: "  42\n", want: txnbuild.MemoID(42)},
		{name: "id max uint64", memoType: "id", value: "18446744073709551615", want: txnbuild.MemoID(1<<64 - 1)},
		{name: "id overflow", memoType: "id", value: "18446744073709551616", wantErrIs: "invalid id memo"},
		{name: "id negative", memoType: "id", value: "-1", wantErrIs: "invalid id memo"},
		{name: "id non-numeric", memoType: "id", value: "abc", wantErrIs: "invalid id memo"},
		{name: "id without a value", memoType: "id", wantErrIs: "needs a memo value"},

		{name: "hash", memoType: "hash", value: hash64, want: txnbuild.MemoHash(wantHash)},
		{name: "hash uppercase and trimmed", memoType: "hash", value: " " + strings.ToUpper(hash64), want: txnbuild.MemoHash(wantHash)},
		{name: "hash too short", memoType: "hash", value: hash64[:63], wantErrIs: "64 hex digits"},
		{name: "hash not hex", memoType: "hash", value: strings.Repeat("z", 64), wantErrIs: "not hexadecimal"},
		{name: "hash without a value", memoType: "hash", wantErrIs: "needs a memo value"},

		{name: "return", memoType: "return", value: hash64, want: txnbuild.MemoReturn(wantHash)},
		{name: "return too short", memoType: "return", value: "ab", wantErrIs: "64 hex digits"},

		{name: "unknown type", memoType: "note", value: "x", wantErrIs: "unknown memo type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMemo(tt.memoType, tt.value)
			if tt.wantErrIs != "" {
				if err == nil {
					t.Fatalf("ParseMemo(%q, %q) = %#v, want an error", tt.memoType, tt.value, got)
				}
				if !strings.Contains(err.Error(), tt.wantErrIs) {
					t.Errorf("error = %q, want it to contain %q", err, tt.wantErrIs)
				}
				if got != nil {
					t.Errorf("memo = %v on error, want nil", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMemo(%q, %q): %v", tt.memoType, tt.value, err)
			}
			if got != tt.want {
				t.Errorf("memo = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestParseMemoBuildsValidXDR confirms every accepted memo survives the SDK's
// own encoding — the check that actually decides what lands on the ledger.
func TestParseMemoBuildsValidXDR(t *testing.T) {
	for _, tt := range []struct{ memoType, value string }{
		{"text", "thanks"},
		{"id", "42"},
		{"hash", strings.Repeat("ab", 32)},
		{"return", strings.Repeat("cd", 32)},
	} {
		m, err := ParseMemo(tt.memoType, tt.value)
		if err != nil {
			t.Fatalf("ParseMemo(%q, %q): %v", tt.memoType, tt.value, err)
		}
		if _, err := m.ToXDR(); err != nil {
			t.Errorf("%s memo ToXDR: %v", tt.memoType, err)
		}
	}
}

func TestDescribeMemo(t *testing.T) {
	tests := []struct {
		memoType, value, want string
	}{
		{"", "", ""},
		{"text", "thanks", `text memo "thanks"`},
		{"id", "42", "id memo 42"},
		{"hash", strings.Repeat("ab", 32), "hash memo " + strings.Repeat("ab", 32)},
		{"return", strings.Repeat("cd", 32), "return memo " + strings.Repeat("cd", 32)},
	}
	for _, tt := range tests {
		m, err := ParseMemo(tt.memoType, tt.value)
		if err != nil {
			t.Fatalf("ParseMemo(%q, %q): %v", tt.memoType, tt.value, err)
		}
		if got := DescribeMemo(m); got != tt.want {
			t.Errorf("DescribeMemo(%q, %q) = %q, want %q", tt.memoType, tt.value, got, tt.want)
		}
	}
}
