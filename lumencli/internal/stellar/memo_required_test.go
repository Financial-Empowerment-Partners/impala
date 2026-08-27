package stellar

import "testing"

// withKnownEntry adds a curated-list entry for the duration of a test. The
// shipped map is empty, so the lookup needs a fixture to exercise.
func withKnownEntry(t *testing.T, address, label string) {
	t.Helper()
	knownMemoRequired[address] = label
	t.Cleanup(func() { delete(knownMemoRequired, address) })
}

func TestKnownMemoRequired(t *testing.T) {
	const addr = "GBTEZE3JLLRBS5NFXRPQU675AFLC3L7P2CXDOIM4333AUNCZ2NUA2EKV"
	if _, ok := KnownMemoRequired(addr); ok {
		t.Fatalf("%s is on the curated list before the fixture added it", addr)
	}

	withKnownEntry(t, addr, "Example Exchange")

	label, ok := KnownMemoRequired(addr)
	if !ok || label != "Example Exchange" {
		t.Errorf("KnownMemoRequired = (%q, %v), want (%q, true)", label, ok, "Example Exchange")
	}
	// Surrounding whitespace must not defeat the lookup.
	if _, ok := KnownMemoRequired("  " + addr + "\n"); !ok {
		t.Error("lookup failed on an address with surrounding whitespace")
	}
	if _, ok := KnownMemoRequired("GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"); ok {
		t.Error("an unrelated address matched the curated list")
	}
}

// TestKnownMemoRequiredShipsEmpty guards the decision to ship no entries: an
// address here that nobody verified would either misfire on a legitimate
// counterparty or lend false authority to a wrong address. Adding entries is
// fine — this test exists so that adding one is a deliberate act, together
// with the verification the map's doc comment asks for.
func TestKnownMemoRequiredShipsEmpty(t *testing.T) {
	if n := len(knownMemoRequired); n != 0 {
		t.Skipf("curated list now has %d entries; confirm each was verified per the doc comment", n)
	}
}
