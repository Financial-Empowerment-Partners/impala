package sep10

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"lumencli/internal/card/cardtest"
)

const testHome = "example.com"

// testCard is a card key: the account the challenges are for.
type testCard struct {
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	address string
}

func newTestCard(t *testing.T) testCard {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := strkey.Encode(strkey.VersionByteAccountID, pub)
	if err != nil {
		t.Fatal(err)
	}
	return testCard{priv: priv, pub: pub, address: addr}
}

// buildChallenge issues a challenge for account the way Go SEP-10 servers
// do; mutate, when set, changes it and the server signs it again.
func buildChallenge(t *testing.T, server *keypair.Full, account string, mutate func(*xdr.TransactionEnvelope)) string {
	t.Helper()
	tx, err := txnbuild.BuildChallengeTx(server.Seed(), account, testHome, testHome, network.TestNetworkPassphrase, 5*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	b64, err := tx.Base64()
	if err != nil {
		t.Fatal(err)
	}
	if mutate == nil {
		return b64
	}
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(b64, &env); err != nil {
		t.Fatal(err)
	}
	mutate(&env)
	hash, err := network.HashTransactionInEnvelope(env, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := server.SignDecorated(hash[:])
	if err != nil {
		t.Fatal(err)
	}
	env.V1.Signatures = []xdr.DecoratedSignature{sig}
	out, err := xdr.MarshalBase64(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func expectFor(server *keypair.Full, account string) Expect {
	return Expect{ServerKey: server.Address(), HomeDomain: testHome, WebAuthDomain: testHome,
		Passphrase: network.TestNetworkPassphrase, Account: account}
}

// TestForCardSignsWhatServersVerify runs the card path on a challenge the
// SDK built: the bytes handed to the card are the exact Transaction slice of
// the envelope, the hash is the transaction hash, and the envelope built
// around the card's signature is what a real server's verifier accepts.
func TestForCardSignsWhatServersVerify(t *testing.T) {
	server, _ := keypair.Random()
	c := newTestCard(t)
	issued := buildChallenge(t, server, c.address, nil)
	ch, err := Verify(issued, expectFor(server, c.address))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ch.ForCard(c.pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(issued)
	if !bytes.Equal(raw[4:4+len(cs.Transaction)], cs.Transaction) {
		t.Error("the card is not handed the envelope's exact Transaction bytes")
	}
	nid := network.ID(network.TestNetworkPassphrase)
	if !bytes.Equal(cs.NetworkID, nid[:]) {
		t.Error("network id")
	}
	want := sha256.Sum256(append(append(append([]byte(nil), nid[:]...), 0, 0, 0, 2), cs.Transaction...))
	if !bytes.Equal(cs.Hash, want[:]) {
		t.Error("hash is not SHA-256(network id ‖ ENVELOPE_TYPE_TX ‖ transaction)")
	}

	signed, err := cs.Envelope(ed25519.Sign(c.priv, cs.Hash))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txnbuild.VerifyChallengeTxSigners(signed, server.Address(), network.TestNetworkPassphrase, testHome, []string{testHome}, c.address); err != nil {
		t.Fatalf("a server's verifier refuses the card-signed challenge: %v", err)
	}
	var in, out xdr.TransactionEnvelope
	_ = xdr.SafeUnmarshalBase64(issued, &in)
	_ = xdr.SafeUnmarshalBase64(signed, &out)
	outTx, _ := out.V1.Tx.MarshalBinary()
	if !bytes.Equal(outTx, cs.Transaction) || len(out.V1.Signatures) != 2 ||
		!bytes.Equal(out.V1.Signatures[0].Signature, in.V1.Signatures[0].Signature) ||
		!bytes.Equal(out.V1.Signatures[1].Hint[:], c.pub[28:]) {
		t.Error("the signed envelope is not the issued one plus the card's decorated signature")
	}
}

// TestForCardReproducesTheSharedVectors: the shared vectors hold a challenge
// the bridge built for the deterministic simulator card, and that challenge
// signed by the real applet. Handed the applet's signature, lumencli must
// rebuild the applet-signed envelope byte for byte. The challenge is valid at
// a fixed time (unix 1800000000), so the checked challenge is constructed as
// Verify would leave it rather than through Verify, which judges "now".
func TestForCardReproducesTheSharedVectors(t *testing.T) {
	env, err := decodeEnvelope(cardtest.SharedSep10Issued)
	if err != nil {
		t.Fatal(err)
	}
	if err := exactXDR(cardtest.SharedSep10Issued, env); err != nil {
		t.Fatal(err)
	}
	gen, err := txnbuild.TransactionFromXDR(cardtest.SharedSep10Issued)
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := gen.Transaction()
	ch := &Challenge{tx: tx, env: env, passphrase: network.TestNetworkPassphrase, account: cardtest.SharedSep10CardAddress}

	cardKey, _ := strkey.Decode(strkey.VersionByteAccountID, cardtest.SharedSep10CardAddress)
	cs, err := ch.ForCard(cardKey)
	if err != nil {
		t.Fatal(err)
	}
	var signed xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(cardtest.SharedSep10CardSigned, &signed); err != nil {
		t.Fatal(err)
	}
	sigs := signed.Signatures()
	got, err := cs.Envelope(sigs[len(sigs)-1].Signature)
	if err != nil {
		t.Fatalf("the applet's signature is refused: %v", err)
	}
	if got != cardtest.SharedSep10CardSigned {
		t.Errorf("the envelope built around the applet's signature differs from the shared vector:\ngot  %s\nwant %s", got, cardtest.SharedSep10CardSigned)
	}
	// And Verify, judging "now", refuses the vector: it is valid only at its
	// recorded time, which is why the check above builds the Challenge itself.
	server := env.SourceAccount()
	if _, err := Verify(cardtest.SharedSep10Issued, Expect{ServerKey: server.Address(), HomeDomain: "api-testnet.example.com",
		WebAuthDomain: "api-testnet.example.com", Passphrase: network.TestNetworkPassphrase, Account: cardtest.SharedSep10CardAddress}); err == nil ||
		!strings.Contains(err.Error(), "timebounds") {
		t.Errorf("Verify of the shared vector now = %v, want a time-bounds refusal", err)
	}
}

func TestChallengeSignsOnlyForItsAccount(t *testing.T) {
	server, _ := keypair.Random()
	c := newTestCard(t)
	other := newTestCard(t)
	issued := buildChallenge(t, server, c.address, nil)

	ch, err := Verify(issued, expectFor(server, c.address))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ch.ForCard(other.pub); err == nil || !strings.Contains(err.Error(), "was checked for "+c.address) {
		t.Errorf("ForCard(another key) = %v", err)
	}
	if _, err := ch.ForCard(c.pub[:31]); err == nil {
		t.Error("ForCard accepted a 31-byte key")
	}
	wallet, _ := keypair.Random()
	if _, err := ch.Sign(wallet); err == nil {
		t.Error("Sign accepted a key other than the checked account")
	}

	unbound, err := Verify(issued, Expect{ServerKey: server.Address(), HomeDomain: testHome, WebAuthDomain: testHome, Passphrase: network.TestNetworkPassphrase})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unbound.ForCard(c.pub); err == nil || !strings.Contains(err.Error(), "without an account") {
		t.Errorf("ForCard of a challenge checked without an account = %v", err)
	}
}

func TestEnvelopeRefusesASignatureThatDoesNotVerify(t *testing.T) {
	server, _ := keypair.Random()
	c := newTestCard(t)
	ch, err := Verify(buildChallenge(t, server, c.address, nil), expectFor(server, c.address))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ch.ForCard(c.pub)
	if err != nil {
		t.Fatal(err)
	}
	good := ed25519.Sign(c.priv, cs.Hash)
	other := newTestCard(t)
	for name, sig := range map[string][]byte{
		"a flipped bit":    append([]byte{good[0] ^ 1}, good[1:]...),
		"another card":     ed25519.Sign(other.priv, cs.Hash),
		"63 bytes":         good[:63],
		"over the message": ed25519.Sign(c.priv, cs.Transaction),
	} {
		if _, err := cs.Envelope(sig); err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestForCardLimits: a challenge every SEP-10 client check accepts, but the
// card's narrower parser would refuse, is refused before the card sees it.
func TestForCardLimits(t *testing.T) {
	server, _ := keypair.Random()
	c := newTestCard(t)
	serverOp := func(name string, valueLen int) xdr.Operation {
		v := xdr.DataValue(bytes.Repeat([]byte("v"), valueLen))
		return xdr.Operation{
			SourceAccount: xdr.MustMuxedAddressPtr(server.Address()),
			Body:          xdr.OperationBody{Type: xdr.OperationTypeManageData, ManageDataOp: &xdr.ManageDataOp{DataName: xdr.String64(name), DataValue: &v}},
		}
	}
	cases := []struct {
		name   string
		mutate func(*xdr.TransactionEnvelope)
		want   string
	}{
		{"six operations", func(env *xdr.TransactionEnvelope) {
			for i := 0; len(env.V1.Tx.Operations) < 6; i++ {
				env.V1.Tx.Operations = append(env.V1.Tx.Operations, serverOp("extra"+string(rune('a'+i)), 8))
			}
		}, "at most 5 operations"},
		{"over 640 bytes", func(env *xdr.TransactionEnvelope) {
			for i := 0; len(env.V1.Tx.Operations) < 5; i++ {
				env.V1.Tx.Operations = append(env.V1.Tx.Operations, serverOp(strings.Repeat(string(rune('a'+i)), 64), 64))
			}
		}, "the card signs at most 640"},
		{"PRECOND_V2", func(env *xdr.TransactionEnvelope) {
			tb := env.V1.Tx.Cond.TimeBounds
			env.V1.Tx.Cond = xdr.Preconditions{Type: xdr.PreconditionTypePrecondV2, V2: &xdr.PreconditionsV2{TimeBounds: tb}}
		}, "PRECOND_V2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Each case passes every SEP-10 client check (the SDK accepts
			// all three shapes), so only the card's rules stand between it
			// and the card.
			ch, err := Verify(buildChallenge(t, server, c.address, tc.mutate), expectFor(server, c.address))
			if err != nil {
				t.Fatalf("the client checks refused it (%v); the case no longer tests the card's rules", err)
			}
			if _, err := ch.ForCard(c.pub); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ForCard = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}

// TestVerifyRefusesNonCanonicalEnvelopes: the SDK's decoder lets one stray
// byte after the envelope through (its "fully consumed" check counts base64
// characters); Verify does not. Line breaks inside the base64 change no
// byte and stay accepted.
func TestVerifyRefusesNonCanonicalEnvelopes(t *testing.T) {
	server, _ := keypair.Random()
	c := newTestCard(t)
	issued := buildChallenge(t, server, c.address, nil)
	raw, _ := base64.StdEncoding.DecodeString(issued)
	exp := expectFor(server, c.address)

	oneMore := base64.StdEncoding.EncodeToString(append(append([]byte(nil), raw...), 0))
	if _, _, _, _, err := txnbuild.ReadChallengeTx(oneMore, server.Address(), network.TestNetworkPassphrase, testHome, []string{testHome}); err != nil {
		t.Logf("note: the SDK now refuses a trailing byte itself (%v); Verify's own check stays", err)
	}
	if _, err := Verify(oneMore, exp); err == nil || !strings.Contains(err.Error(), "1 unexpected byte(s) follow the transaction envelope") {
		t.Errorf("Verify(one trailing byte) = %v", err)
	}
	if _, err := Verify(base64.StdEncoding.EncodeToString(append(append([]byte(nil), raw...), 0, 0, 0, 0)), exp); err == nil {
		t.Error("Verify accepted four trailing bytes")
	}
	wrapped := issued[:60] + "\n" + issued[60:]
	if _, err := Verify(wrapped, exp); err != nil {
		t.Errorf("Verify(base64 with a line break) = %v, want acceptance", err)
	}
}
