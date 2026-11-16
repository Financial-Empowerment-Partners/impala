package devicekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The domain tag is a cross-stream contract (scripts/check-shared-vectors.sh
// pins the same hex on the bridge and impala-lib side).
func TestTagBytesArePinned(t *testing.T) {
	if got := hex.EncodeToString([]byte(Tag)); got != "494d50414c412d444b45593a" {
		t.Fatalf("tag hex = %s", got)
	}
	if len(Tag) != 12 {
		t.Fatalf("tag length = %d, want 12", len(Tag))
	}
}

func TestPurposeBytesArePinned(t *testing.T) {
	for name, got := range map[string]byte{
		"enroll": PurposeEnroll, "step-up": PurposeStepUp,
		"card": PurposeCardSignIn, "sep10": PurposeSep10SignIn,
	} {
		want := map[string]byte{"enroll": 1, "step-up": 2, "card": 3, "sep10": 4}[name]
		if got != want {
			t.Errorf("purpose %s = %#x, want %#x", name, got, want)
		}
	}
}

// The full message for a fixed account, purpose and challenge, as built by the
// demo's independent stdlib reference (demo/scripts/mfa-factor.py
// device-message 00112233-4455-6677-8899-aabbccddeeff 2 07×32).
func TestMessageMatchesTheReferenceVector(t *testing.T) {
	const want = "494d50414c412d444b45593a" + "01" + "02" +
		"e34f7b59834d35a6dcb646f99b7d856df3ffbc955cece7c90714d13705703680" +
		"0707070707070707070707070707070707070707070707070707070707070707"
	msg, err := Message(PurposeStepUp, "00112233-4455-6677-8899-aabbccddeeff", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(msg); got != want {
		t.Fatalf("message =\n%s\nwant\n%s", got, want)
	}
	if len(msg) != 12+1+1+32+32 {
		t.Fatalf("length = %d", len(msg))
	}
}

func TestMessageBindsThePurposeAndTheAccount(t *testing.T) {
	ch := bytes.Repeat([]byte{9}, 32)
	a, _ := Message(PurposeStepUp, "acct-1", ch)
	b, _ := Message(PurposeEnroll, "acct-1", ch)
	c, _ := Message(PurposeStepUp, "acct-2", ch)
	if bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Fatal("purpose or account not bound into the message")
	}
	sum := sha256.Sum256([]byte("acct-1"))
	if !bytes.Equal(a[14:46], sum[:]) {
		t.Fatal("account hash is not sha256(account id utf-8)")
	}
}

func TestMessageRefusesAWrongChallengeLength(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := Message(PurposeStepUp, "a", make([]byte, n)); err == nil {
			t.Errorf("challenge of %d bytes accepted", n)
		}
	}
	if _, err := Message(PurposeStepUp, "", make([]byte, 32)); err == nil {
		t.Error("empty account accepted")
	}
}

// What the bridge does: verify the hex DER signature over the rebuilt
// message under the 130-hex uncompressed public key.
func TestAssertionVerifiesLikeTheBridgeChecksIt(t *testing.T) {
	priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	pubHex, err := PublicKeyHex(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(pubHex) != 130 || !strings.HasPrefix(pubHex, "04") {
		t.Fatalf("public key = %s", pubHex)
	}
	ch := bytes.Repeat([]byte{0xab}, 32)
	sigHex, err := Assert(priv, PurposeEnroll, "acct-1", ch)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := hex.DecodeString(pubHex)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(sigHex)
	msg, _ := Message(PurposeEnroll, "acct-1", ch)
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("assertion does not verify")
	}
	other, _ := Message(PurposeStepUp, "acct-1", ch)
	d2 := sha256.Sum256(other)
	if ecdsa.VerifyASN1(pub, d2[:], sig) {
		t.Fatal("an enroll assertion verified as a step-up one")
	}
}

func TestPrivateKeyRoundTripAndMismatch(t *testing.T) {
	priv, _ := Generate()
	pubHex, _ := PublicKeyHex(&priv.PublicKey)
	enc, err := MarshalPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePrivate(enc, pubHex)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(priv) {
		t.Fatal("round trip changed the key")
	}
	other, _ := Generate()
	otherHex, _ := PublicKeyHex(&other.PublicKey)
	if _, err := ParsePrivate(enc, otherHex); err == nil {
		t.Fatal("a private key was accepted under another public key")
	}
}

func TestDeclaredPlatformIsHonest(t *testing.T) {
	if UserVerification != "none" {
		t.Fatal("a file-held key must never be declared biometric")
	}
	if Platform != "impalactl" {
		t.Fatalf("platform = %q", Platform)
	}
}
