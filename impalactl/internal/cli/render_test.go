package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"impalactl/internal/bridge"
)

func TestRenderJSONIndentsVerbatim(t *testing.T) {
	out := &bytes.Buffer{}
	app := &App{out: out, err: &bytes.Buffer{}}

	humanCalled := false
	app.render(options{json: true}, []byte(`{"a":1,"b":[2,3]}`), func(w io.Writer) { humanCalled = true })

	if humanCalled {
		t.Error("the human renderer ran under --json")
	}
	want := "{\n  \"a\": 1,\n  \"b\": [\n    2,\n    3\n  ]\n}\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

func TestRenderJSONPassesThroughNonJSON(t *testing.T) {
	out := &bytes.Buffer{}
	app := &App{out: out, err: &bytes.Buffer{}}
	app.render(options{json: true}, []byte("Hello, World!\n"), func(w io.Writer) {})
	if strings.TrimSpace(out.String()) != "Hello, World!" {
		t.Errorf("output = %q", out.String())
	}
}

func TestRenderHumanByDefault(t *testing.T) {
	out := &bytes.Buffer{}
	app := &App{out: out, err: &bytes.Buffer{}}
	app.render(options{}, []byte(`{"a":1}`), func(w io.Writer) { w.Write([]byte("summary")) })
	if out.String() != "summary" {
		t.Errorf("output = %q", out.String())
	}
}

func TestOptionalRendering(t *testing.T) {
	value := "set"
	empty := ""
	if got := str(&value); got != "set" {
		t.Errorf("str(&%q) = %q", value, got)
	}
	if got := str(nil); got != "-" {
		t.Errorf("str(nil) = %q, want -", got)
	}
	if got := str(&empty); got != "-" {
		t.Errorf("str(&\"\") = %q, want -", got)
	}
	if got := dash(""); got != "-" {
		t.Errorf("dash(\"\") = %q", got)
	}

	var n int64 = 0
	if got := num(&n); got != "0" {
		t.Errorf("num(&0) = %q, want 0 (a real zero is not absent)", got)
	}
	if got := num(nil); got != "-" {
		t.Errorf("num(nil) = %q, want -", got)
	}
	if yesNo(true) != "yes" || yesNo(false) != "no" {
		t.Error("yesNo rendering")
	}
}

func TestShortAddrKeepsBothEnds(t *testing.T) {
	addr := "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
	got := shortAddr(&addr)
	if !strings.HasPrefix(got, "GA7QYNF7") || !strings.HasSuffix(got, "UJVSGZ") {
		t.Errorf("shortAddr = %q, want both ends preserved", got)
	}
	if len(got) >= len(addr) {
		t.Errorf("shortAddr = %q, want it shortened", got)
	}
	short := "GABC"
	if shortAddr(&short) != "GABC" {
		t.Error("a short value should be left alone")
	}
	if shortAddr(nil) != "-" {
		t.Error("shortAddr(nil) should render as -")
	}
}

func TestClip(t *testing.T) {
	long := "a memo that runs on and on"
	if got := clip(&long, 10); len([]rune(got)) != 10 {
		t.Errorf("clip = %q (%d runes), want 10", got, len([]rune(got)))
	}
	multiline := "line one\nline two"
	if got := clip(&multiline, 40); strings.Contains(got, "\n") {
		t.Errorf("clip kept a newline: %q — it would break the table", got)
	}
	short := "ok"
	if got := clip(&short, 10); got != "ok" {
		t.Errorf("clip = %q", got)
	}

	// Clipping counts runes, so a multi-byte memo cannot be cut mid-character.
	accented := "café münster straße naïve"
	got := clip(&accented, 8)
	if !utf8.ValidString(got) {
		t.Errorf("clip produced invalid UTF-8: %q", got)
	}
	if len([]rune(got)) != 8 {
		t.Errorf("clip = %q (%d runes), want 8", got, len([]rune(got)))
	}
}

func TestPlural(t *testing.T) {
	if got := plural(1, "account", "accounts"); got != "1 account" {
		t.Errorf("plural(1) = %q", got)
	}
	if got := plural(0, "account", "accounts"); got != "0 accounts" {
		t.Errorf("plural(0) = %q", got)
	}
	if got := plural(7, "account", "accounts"); got != "7 accounts" {
		t.Errorf("plural(7) = %q", got)
	}
}

func TestPageFooter(t *testing.T) {
	tests := []struct {
		shown            int
		page, per, total uint64
		want             string
	}{
		{1, 2, 1, 3, "Showing 1 of 3 accounts (page 2 of 3)"},
		{20, 1, 20, 20, "Showing 20 of 20 accounts (page 1 of 1)"},
		{0, 1, 20, 0, "Showing 0 of 0 accounts (page 1 of 1)"},
		{5, 1, 20, 5, "Showing 5 of 5 accounts (page 1 of 1)"},
	}
	for _, tc := range tests {
		out := &bytes.Buffer{}
		pageFooter(out, tc.shown, tc.page, tc.per, tc.total, "account", "accounts")
		if got := strings.TrimSpace(out.String()); got != tc.want {
			t.Errorf("pageFooter(%d, %d, %d, %d) = %q, want %q", tc.shown, tc.page, tc.per, tc.total, got, tc.want)
		}
	}
}

func TestTableAlignsColumns(t *testing.T) {
	out := &bytes.Buffer{}
	table(out, []string{"A", "B"}, [][]string{{"short", "1"}, {"much-longer-value", "2"}})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("table produced %d lines, want 3", len(lines))
	}
	if strings.Index(lines[1], "1") != strings.Index(lines[2], "2") {
		t.Errorf("columns are not aligned:\n%s", out.String())
	}
}

func TestExpiryText(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	future := bridge.Claims{ExpiresAt: now.Add(45 * time.Minute).Unix()}
	if got := expiryText(future, now); !strings.Contains(got, "in 45m0s") {
		t.Errorf("expiryText = %q, want the remaining time", got)
	}

	past := bridge.Claims{ExpiresAt: now.Add(-90 * time.Second).Unix()}
	if got := expiryText(past, now); !strings.Contains(got, "expired") {
		t.Errorf("expiryText = %q, want it marked expired", got)
	}

	if got := expiryText(bridge.Claims{}, now); got != "-" {
		t.Errorf("expiryText with no exp = %q, want -", got)
	}
}
