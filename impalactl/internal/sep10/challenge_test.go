package sep10_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"impalactl/internal/sep10"
	"impalactl/internal/sep10/sep10test"
)

// The shared vector (impala-bridge/src/sep10/card_vectors.rs,
// demo/scripts/testdata/sep10-challenge.b64): RFC 8032 TEST 1 server key, the
// deterministic simulator card's Stellar key, home domain
// api-testnet.example.com, issued at 1_800_000_000 for 300 s.
const (
	vecHome       = "api-testnet.example.com"
	vecNow        = 1_800_000_000
	vecPassphrase = "Test SDF Network ; September 2015"
	vecServerSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	vecCardPub    = "d72f8b652505e0ce4eeca6c15eba8b62f84bb11abc090baba21255b75553fd99"
	vecIssued     = "AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAMgAAAAAAAAAAAAAAAEAAAAAa0nSAAAAAABrSdMsAAAAAAAAAAIAAAABAAAAANcvi2UlBeDOTuymwV66i2L4S7EavAkLq6ISVbdVU/2ZAAAACgAAABxhcGktdGVzdG5ldC5leGFtcGxlLmNvbSBhdXRoAAAAAQAAAEBXbHBhV2xwYVdscGFXbHBhV2xwYVdoRWdFNlM1UHdNeE51NnhxUS8yeXRyWWsyVkhZZjFhWDczZ0djUWVqeXZkAAAAAQAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAXYXBpLXRlc3RuZXQuZXhhbXBsZS5jb20AAAAAAAAAAAH3B1EaAAAAQEaF82VZmJjfApz9tqEpS/sDsigAZIyf8SHztaUn5LdRCxw14B77qpqeKEGtGbPqepGKw3ZGe4aYXQ5PaJ64VwA="
	vecCardSigned = "AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAMgAAAAAAAAAAAAAAAEAAAAAa0nSAAAAAABrSdMsAAAAAAAAAAIAAAABAAAAANcvi2UlBeDOTuymwV66i2L4S7EavAkLq6ISVbdVU/2ZAAAACgAAABxhcGktdGVzdG5ldC5leGFtcGxlLmNvbSBhdXRoAAAAAQAAAEBXbHBhV2xwYVdscGFXbHBhV2xwYVdoRWdFNlM1UHdNeE51NnhxUS8yeXRyWWsyVkhZZjFhWDczZ0djUWVqeXZkAAAAAQAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAXYXBpLXRlc3RuZXQuZXhhbXBsZS5jb20AAAAAAAAAAAL3B1EaAAAAQEaF82VZmJjfApz9tqEpS/sDsigAZIyf8SHztaUn5LdRCxw14B77qpqeKEGtGbPqepGKw3ZGe4aYXQ5PaJ64VwBVU/2ZAAAAQD5j/mz4dfCycHkSai6dC23Xdio+GWlmCMT7i2qFmqUVrF0IsVp8Gq7w6REyFvr8gDG9VzN+TPEC+bBFAT7CIQk="
)

func vecServer(t *testing.T) ed25519.PrivateKey {
	seed, _ := hex.DecodeString(vecServerSeed)
	return ed25519.NewKeyFromSeed(seed)
}

func vecCard() []byte {
	b, _ := hex.DecodeString(vecCardPub)
	return b
}

func vecExpect(t *testing.T) sep10.Expectation {
	return sep10.Expectation{
		ServerKey:         vecServer(t).Public().(ed25519.PublicKey),
		NetworkPassphrase: vecPassphrase,
		HomeDomain:        vecHome,
		WebAuthDomain:     vecHome,
		ClientKey:         vecCard(),
	}
}

func TestTheSharedVectorFileIsTheOneHeldHere(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "demo", "scripts", "testdata", "sep10-challenge.b64"))
	if err != nil {
		t.Skipf("shared vector not available: %v", err)
	}
	if strings.TrimSpace(string(data)) != vecIssued {
		t.Fatal("demo/scripts/testdata/sep10-challenge.b64 differs from the vector held here")
	}
}

func TestTheIssuedVectorVerifies(t *testing.T) {
	ch, err := sep10.Verify(vecIssued, vecExpect(t), vecNow)
	if err != nil {
		t.Fatal(err)
	}
	if ch.MinTime != vecNow || ch.MaxTime != vecNow+300 {
		t.Errorf("bounds = %d..%d", ch.MinTime, ch.MaxTime)
	}
	// Past its lifetime it is expired.
	if _, err := sep10.Verify(vecIssued, vecExpect(t), vecNow+301); reason(err) != sep10.ReasonTimeBoundsExpired {
		t.Errorf("expired: %v", err)
	}
}

// Framing: ISSUED plus the applet's signature must be CARD_SIGNED byte for
// byte, and that signature verifies over the challenge hash under the card key.
func TestSignedEnvelopeReproducesTheCardSignedVector(t *testing.T) {
	ch, err := sep10.Verify(vecIssued, vecExpect(t), vecNow)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := base64.StdEncoding.DecodeString(vecCardSigned)
	sig := signed[len(signed)-64:]
	if !ed25519.Verify(vecCard(), ch.Hash(), sig) {
		t.Fatal("the applet's signature does not verify over Hash()")
	}
	got, err := ch.SignedEnvelope(sig)
	if err != nil {
		t.Fatal(err)
	}
	if got != vecCardSigned {
		t.Fatalf("framed envelope differs from CARD_SIGNED:\n%s", got)
	}
	issued, _ := base64.StdEncoding.DecodeString(vecIssued)
	if !bytes.Equal(ch.TransactionBytes(), issued[4:len(issued)-4-4-4-64]) {
		t.Error("TransactionBytes is not the exact tx slice")
	}
}

func reason(err error) sep10.Reason {
	var ce *sep10.ChallengeError
	if errors.As(err, &ce) {
		return ce.Reason
	}
	return ""
}

// One test per client rule: each mutation of the standard challenge must be
// refused with the reason the card SDK's verifier gives.
func TestEveryClientCheck(t *testing.T) {
	server := vecServer(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	otherPub := other.Public().(ed25519.PublicKey)
	card := vecCard()
	base := func() sep10test.Spec {
		return sep10test.Standard(server, card, vecHome, vecHome, vecPassphrase, vecNow, 300)
	}
	cases := map[string]struct {
		mutate func(*sep10test.Spec)
		raw    func(string) string
		expect func(*sep10.Expectation)
		now    int64
		want   sep10.Reason
	}{
		"ok":                   {want: ""},
		"envelope v0":          {mutate: func(s *sep10test.Spec) { s.EnvelopeType = 0x7fff }, want: sep10.ReasonEnvelopeType},
		"source not server":    {mutate: func(s *sep10test.Spec) { s.Source = otherPub }, want: sep10.ReasonServerKey},
		"sequence not 0":       {mutate: func(s *sep10test.Spec) { s.Seq = 1 }, want: sep10.ReasonSequence},
		"no time bounds":       {mutate: func(s *sep10test.Spec) { s.Cond = 2 }, want: sep10.ReasonTimeBoundsMissing},
		"maxTime 0":            {mutate: func(s *sep10test.Spec) { s.MaxTime = 0 }, want: sep10.ReasonTimeBoundsMissing},
		"min after max":        {mutate: func(s *sep10test.Spec) { s.MinTime = s.MaxTime + 1 }, want: sep10.ReasonTimeBoundsInvalid},
		"lifetime too long":    {mutate: func(s *sep10test.Spec) { s.MaxTime = s.MinTime + 901 }, want: sep10.ReasonTimeBoundsLifetime},
		"not valid yet":        {now: vecNow - 301, want: sep10.ReasonTimeBoundsTooEarly},
		"within the grace":     {now: vecNow - 300, want: ""},
		"expired":              {now: vecNow + 301, want: sep10.ReasonTimeBoundsExpired},
		"memo":                 {mutate: func(s *sep10test.Spec) { s.Memo = 1 }, want: sep10.ReasonMemo},
		"no operations":        {mutate: func(s *sep10test.Spec) { s.Ops = nil }, want: sep10.ReasonOperationCount},
		"six operations":       {mutate: func(s *sep10test.Spec) { s.Ops = append(s.Ops, s.Ops[1], s.Ops[1], s.Ops[1], s.Ops[1]) }, want: sep10.ReasonOperationCount},
		"not manage data":      {mutate: func(s *sep10test.Spec) { s.Ops[1].Type = 1 }, want: sep10.ReasonOperationType},
		"op without source":    {mutate: func(s *sep10test.Spec) { s.Ops[0].HasSource = false }, want: sep10.ReasonOperationSource},
		"op 0 not the card":    {mutate: func(s *sep10test.Spec) { s.Ops[0].Source = otherPub }, want: sep10.ReasonOperationSource},
		"op 1 not the server":  {mutate: func(s *sep10test.Spec) { s.Ops[1].Source = card }, want: sep10.ReasonOperationSource},
		"muxed op source":      {mutate: func(s *sep10test.Spec) { s.Ops[0].MuxedSrc = true }, want: sep10.ReasonOperationSource},
		"wrong home domain":    {mutate: func(s *sep10test.Spec) { s.Ops[0].Name = "evil.example auth" }, want: sep10.ReasonHomeDomainKey},
		"nonce 32 bytes":       {mutate: func(s *sep10test.Spec) { s.Ops[0].Value = make([]byte, 32) }, want: sep10.ReasonNonceLength},
		"nonce absent":         {mutate: func(s *sep10test.Spec) { s.Ops[0].Value = nil }, want: sep10.ReasonNonceLength},
		"wrong web_auth":       {mutate: func(s *sep10test.Spec) { s.Ops[1].Value = []byte("evil.example") }, want: sep10.ReasonWebAuthDomain},
		"web_auth absent":      {mutate: func(s *sep10test.Spec) { s.Ops[1].Value = nil }, want: sep10.ReasonWebAuthDomain},
		"unsigned":             {mutate: func(s *sep10test.Spec) { s.NoSignature = true }, want: sep10.ReasonSignatureCount},
		"two signatures":       {mutate: func(s *sep10test.Spec) { s.ExtraSignatures = 1 }, want: sep10.ReasonSignatureCount},
		"signed by another":    {mutate: func(s *sep10test.Spec) { s.SignWith = other }, want: sep10.ReasonServerSignature},
		"right hint, bad sig":  {mutate: func(s *sep10test.Spec) { s.SignWith = other; s.SignatureHintFrom = server.Public().(ed25519.PublicKey) }, want: sep10.ReasonServerSignature},
		"wrong network signed": {mutate: func(s *sep10test.Spec) { s.Passphrase = "Public Global Stellar Network ; September 2015" }, want: sep10.ReasonServerSignature},
		"trailing bytes":       {mutate: func(s *sep10test.Spec) { s.TrailingBytes = []byte{0, 0, 0, 0} }, want: sep10.ReasonMalformed},
		"ext not 0":            {mutate: func(s *sep10test.Spec) { s.Ext = 1 }, want: sep10.ReasonMalformed},
		"not canonical base64": {raw: func(s string) string { return strings.TrimRight(s, "=") }, want: sep10.ReasonMalformed},
		"not base64":           {raw: func(string) string { return "!!!" }, want: sep10.ReasonMalformed},
		"too long":             {raw: func(string) string { return strings.Repeat("A", 4100) }, want: sep10.ReasonMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			spec := base()
			if tc.mutate != nil {
				tc.mutate(&spec)
			}
			env := spec.Build()
			if tc.raw != nil {
				env = tc.raw(env)
			}
			exp := vecExpect(t)
			if tc.expect != nil {
				tc.expect(&exp)
			}
			now := tc.now
			if now == 0 {
				now = vecNow
			}
			_, err := sep10.Verify(env, exp, now)
			if got := reason(err); got != tc.want {
				t.Fatalf("reason = %q (%v), want %q", got, err, tc.want)
			}
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExpectationRefusesTheServerKeyAsClient(t *testing.T) {
	exp := vecExpect(t)
	exp.ClientKey = exp.ServerKey
	if _, err := sep10.Verify(vecIssued, exp, vecNow); err == nil {
		t.Fatal("client key == server key accepted")
	}
}
