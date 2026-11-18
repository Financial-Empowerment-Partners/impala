package cardtest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func sharedTx(t *testing.T) (xdr.Transaction, []byte) {
	t.Helper()
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(SharedSep10Issued, &env); err != nil {
		t.Fatal(err)
	}
	return env.V1.Tx, sharedCardKey(t)
}

func sharedCardKey(t *testing.T) []byte {
	t.Helper()
	key, err := strkey.Decode(strkey.VersionByteAccountID, SharedSep10CardAddress)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func encode(t *testing.T, tx xdr.Transaction) []byte {
	t.Helper()
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestValidatorAcceptsWhatTheAppletSigned is the fake's honesty gate: the
// challenge of the shared vectors — built by the bridge, signed by the real
// applet — passes the fake's parser for the card's key, and the applet's
// signature in the signed vector is the card key's over the transaction hash
// on testnet. A fake stricter or laxer than the card on this input fails here.
func TestValidatorAcceptsWhatTheAppletSigned(t *testing.T) {
	tx, key := sharedTx(t)
	raw := encode(t, tx)
	if sw := ValidateSep10(raw, key); sw != 0x9000 {
		t.Fatalf("the fake refuses the challenge the applet signed: SW %04X", sw)
	}
	var signed xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(SharedSep10CardSigned, &signed); err != nil {
		t.Fatal(err)
	}
	sigs := signed.Signatures()
	appletSig := sigs[len(sigs)-1]
	nid := network.ID(network.TestNetworkPassphrase)
	h := sha256.New()
	h.Write(nid[:])
	h.Write([]byte{0, 0, 0, 2})
	h.Write(raw)
	if !ed25519.Verify(key, h.Sum(nil), appletSig.Signature) {
		t.Fatal("the applet's signature in the shared vector does not verify over the testnet transaction hash")
	}
}

// TestValidatorStatusWords: each rule of docs/sep10-card-keys.md §3.3,
// broken on its own, answers its status word.
func TestValidatorStatusWords(t *testing.T) {
	cardMuxed := func(key []byte) *xdr.MuxedAccount {
		var k xdr.Uint256
		copy(k[:], key)
		return &xdr.MuxedAccount{Type: xdr.CryptoKeyTypeKeyTypeEd25519, Ed25519: &k}
	}
	cases := []struct {
		name   string
		mutate func(tx *xdr.Transaction, key []byte)
		raw    func(raw []byte) []byte
		want   uint16
	}{
		{"sequence 1", func(tx *xdr.Transaction, _ []byte) { tx.SeqNum = 1 }, nil, 0x6241},
		{"no time bounds", func(tx *xdr.Transaction, _ []byte) {
			tx.Cond = xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone}
		}, nil, 0x6245},
		{"max time 0", func(tx *xdr.Transaction, _ []byte) {
			tb := *tx.Cond.TimeBounds
			tb.MaxTime = 0
			tx.Cond.TimeBounds = &tb
		}, nil, 0x6245},
		{"transaction sourced by the card", func(tx *xdr.Transaction, key []byte) { tx.SourceAccount = *cardMuxed(key) }, nil, 0x6243},
		{"first operation not the card's", func(tx *xdr.Transaction, _ []byte) {
			tx.Operations[0].SourceAccount = tx.Operations[1].SourceAccount
		}, nil, 0x6243},
		{"later operation by the card", func(tx *xdr.Transaction, key []byte) { tx.Operations[1].SourceAccount = cardMuxed(key) }, nil, 0x6243},
		{"not an auth entry", func(tx *xdr.Transaction, _ []byte) {
			tx.Operations[0].Body.ManageDataOp.DataName = "api-testnet.example.com auth!"
		}, nil, 0x6244},
		{"another operation type", func(tx *xdr.Transaction, _ []byte) {
			tx.Operations[1].Body = xdr.OperationBody{Type: xdr.OperationTypeBumpSequence, BumpSequenceOp: &xdr.BumpSequenceOp{BumpTo: 1}}
		}, nil, 0x6242},
		{"six operations", func(tx *xdr.Transaction, _ []byte) {
			for len(tx.Operations) < 6 {
				tx.Operations = append(tx.Operations, tx.Operations[1])
			}
		}, nil, 0x6242},
		{"a memo", func(tx *xdr.Transaction, _ []byte) {
			id := xdr.Uint64(1)
			tx.Memo = xdr.Memo{Type: xdr.MemoTypeMemoId, Id: &id}
		}, nil, 0x6240},
		{"a trailing byte", nil, func(raw []byte) []byte { return append(raw, 0) }, 0x6240},
		{"truncated", nil, func(raw []byte) []byte { return raw[:len(raw)-1] }, 0x6240},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, key := sharedTx(t)
			if tc.mutate != nil {
				tc.mutate(&tx, key)
			}
			raw := encode(t, tx)
			if tc.raw != nil {
				raw = tc.raw(raw)
			}
			if sw := ValidateSep10(raw, key); sw != tc.want {
				t.Errorf("SW %04X, want %04X", sw, tc.want)
			}
		})
	}
}
