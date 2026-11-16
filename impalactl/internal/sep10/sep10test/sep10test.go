// Package sep10test builds SEP-10 challenge transactions the way the bridge
// does (impala-bridge/src/sep10/challenge.rs), with every field adjustable so
// tests can break one client rule at a time. Test support only.
package sep10test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"

	"impalactl/internal/sep10"
)

// Op is one operation. A nil Source omits the source account; a nil Value
// omits the value.
type Op struct {
	Source    []byte
	MuxedSrc  bool
	Type      int32
	Name      string
	Value     []byte
	HasSource bool
}

// Spec is a challenge. Build signs it with Server unless NoSignature.
type Spec struct {
	Server            ed25519.PrivateKey
	Source            []byte // defaults to the server's public key
	Fee               uint32
	Seq               int64
	Cond              int32 // defaults to PRECOND_TIME (1)
	MinTime, MaxTime  int64
	Memo              int32
	Ops               []Op
	Ext               int32
	EnvelopeType      int32 // defaults to 2
	Passphrase        string
	NoSignature       bool
	ExtraSignatures   int
	SignWith          ed25519.PrivateKey // overrides the signing key
	TrailingBytes     []byte
	SignatureHintFrom []byte // overrides the hint key
}

// Standard returns the challenge the bridge issues for client at now: two
// manage-data operations, "<home> auth" with a 64-byte nonce sourced by the
// client, then web_auth_domain sourced by the server.
func Standard(server ed25519.PrivateKey, client []byte, home, webAuthDomain, passphrase string, now, ttl int64) Spec {
	pub := server.Public().(ed25519.PublicKey)
	return Spec{
		Server:  server,
		Fee:     200,
		MinTime: now,
		MaxTime: now + ttl,
		Ops: []Op{
			{HasSource: true, Source: client, Type: 10, Name: home + " auth", Value: bytes.Repeat([]byte("Z"), 64)},
			{HasSource: true, Source: pub, Type: 10, Name: "web_auth_domain", Value: []byte(webAuthDomain)},
		},
		Passphrase: passphrase,
	}
}

type w struct{ bytes.Buffer }

func (x *w) u32(v uint32) { binary.Write(&x.Buffer, binary.BigEndian, v) }
func (x *w) i64(v int64)  { binary.Write(&x.Buffer, binary.BigEndian, v) }
func (x *w) opaque(b []byte) {
	x.Write(b)
	for i := 0; i < (4-len(b)%4)%4; i++ {
		x.WriteByte(0)
	}
}
func (x *w) varOpaque(b []byte) { x.u32(uint32(len(b))); x.opaque(b) }

// Transaction encodes the Transaction XDR.
func (s Spec) Transaction() []byte {
	var t w
	src := s.Source
	if src == nil {
		src = s.Server.Public().(ed25519.PublicKey)
	}
	t.u32(0)
	t.opaque(src)
	t.u32(s.Fee)
	t.i64(s.Seq)
	cond := s.Cond
	if cond == 0 {
		cond = 1
	}
	t.u32(uint32(cond))
	if cond == 1 {
		t.i64(s.MinTime)
		t.i64(s.MaxTime)
	}
	t.u32(uint32(s.Memo))
	t.u32(uint32(len(s.Ops)))
	for _, op := range s.Ops {
		if op.HasSource {
			t.u32(1)
			if op.MuxedSrc {
				t.u32(0x100)
			} else {
				t.u32(0)
			}
			t.opaque(op.Source)
		} else {
			t.u32(0)
		}
		t.u32(uint32(op.Type))
		t.varOpaque([]byte(op.Name))
		if op.Value != nil {
			t.u32(1)
			t.varOpaque(op.Value)
		} else {
			t.u32(0)
		}
	}
	t.u32(uint32(s.Ext))
	return t.Bytes()
}

// Build encodes and signs the envelope as standard base64.
func (s Spec) Build() string {
	tx := s.Transaction()
	et := s.EnvelopeType
	if et == 0 {
		et = 2
	}
	var e w
	e.u32(uint32(et))
	e.Write(tx)
	signer := s.Server
	if s.SignWith != nil {
		signer = s.SignWith
	}
	n := 1 + s.ExtraSignatures
	if s.NoSignature {
		n = 0
	}
	e.u32(uint32(n))
	hash := sep10.TransactionHash(s.Passphrase, tx)
	for i := 0; i < n; i++ {
		hintKey := signer.Public().(ed25519.PublicKey)
		if s.SignatureHintFrom != nil {
			hintKey = s.SignatureHintFrom
		}
		e.opaque(hintKey[28:32])
		e.varOpaque(ed25519.Sign(signer, hash[:]))
	}
	e.Write(s.TrailingBytes)
	return base64.StdEncoding.EncodeToString(e.Bytes())
}

// Decoded is a signed envelope taken apart: the transaction and its
// signatures.
type Decoded struct {
	Tx         []byte
	Hints      [][]byte
	Signatures [][]byte
}

// DecodeSigned splits a signed v1 envelope the server issued (whose
// transaction is exactly txLen bytes) into the transaction and signatures.
func DecodeSigned(envelope string, txLen int) (*Decoded, bool) {
	b, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil || len(b) < 8+txLen || binary.BigEndian.Uint32(b) != 2 {
		return nil, false
	}
	d := &Decoded{Tx: b[4 : 4+txLen]}
	rest := b[4+txLen:]
	n := binary.BigEndian.Uint32(rest)
	rest = rest[4:]
	for i := uint32(0); i < n; i++ {
		if len(rest) < 8 {
			return nil, false
		}
		hint := rest[:4]
		l := binary.BigEndian.Uint32(rest[4:])
		if l != 64 || len(rest) < 8+64 {
			return nil, false
		}
		d.Hints = append(d.Hints, hint)
		d.Signatures = append(d.Signatures, rest[8:8+64])
		rest = rest[8+64:]
	}
	return d, len(rest) == 0
}
