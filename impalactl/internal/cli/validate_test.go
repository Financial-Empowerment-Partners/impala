package cli

import (
	"strings"
	"testing"
)

func TestValidateStellarAccountID(t *testing.T) {
	valid := "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
	if err := validateStellarAccountID(valid); err != nil {
		t.Errorf("valid address rejected: %v", err)
	}

	tests := map[string]string{
		"empty":         "",
		"too short":     "GA7QYNF7",
		"too long":      valid + "A",
		"wrong prefix":  "S" + valid[1:],
		"lowercase":     strings.ToLower(valid),
		"base32 digit0": strings.Replace(valid, "7", "0", 1),
		"base32 digit1": strings.Replace(valid, "7", "1", 1),
	}
	for name, id := range tests {
		if err := validateStellarAccountID(id); err == nil {
			t.Errorf("%s: accepted %q", name, id)
		}
	}
}

func TestValidateStellarSecretSeed(t *testing.T) {
	valid := "SBLGRLAOWPJPQEBVZLPZUAJDQJZBZHY6QSMFXVDF2YAV5NM7QOMPLDBM"
	if err := validateStellarSecretSeed(valid); err != nil {
		t.Errorf("valid seed rejected: %v", err)
	}
	// A public address must not pass as a seed.
	if err := validateStellarSecretSeed("G" + valid[1:]); err == nil {
		t.Error("a G-address was accepted as a secret seed")
	}
	if err := validateStellarSecretSeed(""); err == nil {
		t.Error("an empty seed was accepted")
	}
}

func TestValidateAmount(t *testing.T) {
	for _, amount := range []string{"1", "0.1", "12.5", "1234567.1234567", "000.5"} {
		if err := validateAmount(amount); err != nil {
			t.Errorf("valid amount %q rejected: %v", amount, err)
		}
	}

	tests := map[string]string{
		"empty":          "",
		"zero":           "0",
		"zero decimal":   "0.000",
		"negative":       "-1",
		"letters":        "ten",
		"trailing dot":   "1.",
		"comma":          "1,5",
		"too precise":    "1.12345678",
		"exponent":       "1e3",
		"leading spaces": " 1",
	}
	for name, amount := range tests {
		if err := validateAmount(amount); err == nil {
			t.Errorf("%s: accepted %q", name, amount)
		}
	}
}
