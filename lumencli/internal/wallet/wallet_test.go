package wallet

import (
	"strings"
	"testing"
)

func TestGenerateProducesValidKeypair(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(kp.Address(), "G") || len(kp.Address()) != 56 {
		t.Errorf("address %q is not a valid G-strkey", kp.Address())
	}
	if !strings.HasPrefix(kp.Seed(), "S") || len(kp.Seed()) != 56 {
		t.Errorf("seed is not a valid S-strkey")
	}
}

func TestGenerateIsRandom(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a.Seed() == b.Seed() {
		t.Error("two generated keypairs share a seed")
	}
}

func TestAddressFromSecretRoundTrips(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	got, err := AddressFromSecret(kp.Seed())
	if err != nil {
		t.Fatalf("AddressFromSecret: %v", err)
	}
	if got != kp.Address() {
		t.Errorf("derived address %q, want %q", got, kp.Address())
	}
}

func TestAddressFromSecretTrimsWhitespace(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	got, err := AddressFromSecret("  " + kp.Seed() + "\n")
	if err != nil {
		t.Fatalf("AddressFromSecret with whitespace: %v", err)
	}
	if got != kp.Address() {
		t.Errorf("derived address %q, want %q", got, kp.Address())
	}
}

func TestParseSecretRejectsAddress(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// A public address is not a valid secret seed.
	if _, err := ParseSecret(kp.Address()); err == nil {
		t.Error("ParseSecret accepted a public address as a seed")
	}
}

func TestParseSecretRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not-a-key", "SABC", "GABC"} {
		if _, err := ParseSecret(in); err == nil {
			t.Errorf("ParseSecret(%q) = nil error, want error", in)
		}
	}
}

func TestValidateAddress(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ValidateAddress(kp.Address()); err != nil {
		t.Errorf("ValidateAddress(valid) = %v", err)
	}
	for _, bad := range []string{"", "G123", "notanaddress", kp.Seed()} {
		if err := ValidateAddress(bad); err == nil {
			t.Errorf("ValidateAddress(%q) = nil, want error", bad)
		}
	}
}
