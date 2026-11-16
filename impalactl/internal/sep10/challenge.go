package sep10

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// Reason names the SEP-10 client rule a challenge broke (the card SDK's
// Sep10Exception.Reason, one for one).
type Reason string

const (
	ReasonMalformed          Reason = "MALFORMED"
	ReasonEnvelopeType       Reason = "ENVELOPE_TYPE"
	ReasonServerKey          Reason = "SERVER_KEY"
	ReasonSequence           Reason = "SEQUENCE"
	ReasonTimeBoundsMissing  Reason = "TIME_BOUNDS_MISSING"
	ReasonTimeBoundsInvalid  Reason = "TIME_BOUNDS_INVALID"
	ReasonTimeBoundsTooEarly Reason = "TIME_BOUNDS_TOO_EARLY"
	ReasonTimeBoundsExpired  Reason = "TIME_BOUNDS_EXPIRED"
	ReasonTimeBoundsLifetime Reason = "TIME_BOUNDS_LIFETIME"
	ReasonMemo               Reason = "MEMO"
	ReasonOperationCount     Reason = "OPERATION_COUNT"
	ReasonOperationType      Reason = "OPERATION_TYPE"
	ReasonOperationSource    Reason = "OPERATION_SOURCE"
	ReasonHomeDomainKey      Reason = "HOME_DOMAIN_KEY"
	ReasonNonceLength        Reason = "NONCE_LENGTH"
	ReasonWebAuthDomain      Reason = "WEB_AUTH_DOMAIN"
	ReasonSignatureCount     Reason = "SIGNATURE_COUNT"
	ReasonServerSignature    Reason = "SERVER_SIGNATURE"
	// ReasonNetwork: the network passphrases (expected, stellar.toml,
	// challenge response) disagree. Raised by the client, not by Verify.
	ReasonNetwork Reason = "NETWORK"
)

// ChallengeError is a challenge that failed a client check. It is never a
// reason to fall back to another sign-in: the server may be misconfigured or
// not who it claims to be.
type ChallengeError struct {
	Reason  Reason
	Message string
}

func (e *ChallengeError) Error() string {
	return fmt.Sprintf("the server's SEP-10 challenge failed a client check (%s): %s", e.Reason, e.Message)
}

func reject(reason Reason, format string, args ...any) error {
	return &ChallengeError{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// Constants of the SDK verifier.
const (
	EnvelopeTypeTx           = 2
	MaxOperations            = 5
	MaxEnvelopeBase64Length  = 4096
	DefaultMinTimeGrace      = 300
	DefaultMaxLifetime       = 900
	keyTypeEd25519           = 0
	keyTypeMuxedEd25519      = 0x100
	precondTime              = 1
	memoNone                 = 0
	opManageData             = 10
	maxSignatures            = 20
	webAuthDomainKey         = "web_auth_domain"
	ed25519PublicKeyLength   = 32
	ed25519SignatureLength   = 64
	manageDataMaxValueLength = 64
)

// Expectation is what the client expects of a challenge. Keys are raw
// 32-byte Ed25519 public keys: ServerKey from stellar.toml SIGNING_KEY,
// ClientKey the key that will sign (the card's Stellar key).
type Expectation struct {
	ServerKey         []byte
	NetworkPassphrase string
	HomeDomain        string
	WebAuthDomain     string
	ClientKey         []byte
	// MinTimeGrace and MaxLifetime default to 300 s and 900 s.
	MinTimeGrace int64
	MaxLifetime  int64
}

func (e *Expectation) check() error {
	if len(e.ServerKey) != 32 || len(e.ClientKey) != 32 {
		return errors.New("server and client keys must be 32 bytes")
	}
	if bytes.Equal(e.ServerKey, e.ClientKey) {
		return errors.New("client key must differ from the server signing key")
	}
	if e.NetworkPassphrase == "" {
		return errors.New("network passphrase must not be empty")
	}
	if e.HomeDomain == "" || len(e.HomeDomain+" auth") > 64 {
		return errors.New("home domain must be 1..59 bytes")
	}
	if n := len(e.WebAuthDomain); n < 1 || n > 64 {
		return errors.New("web auth domain must be 1..64 bytes")
	}
	if e.MinTimeGrace == 0 {
		e.MinTimeGrace = DefaultMinTimeGrace
	}
	if e.MaxLifetime == 0 {
		e.MaxLifetime = DefaultMaxLifetime
	}
	return nil
}

// Challenge is a challenge transaction that passed every client rule. Only
// Verify makes one. TransactionBytes is the exact Transaction slice of the
// server's envelope (never re-encoded); Hash is what the client key signs.
type Challenge struct {
	envelope            []byte
	txStart, txEnd      int
	signatureCountAt    int
	signatureCount      uint32
	networkID           [32]byte
	hash                [32]byte
	clientKey           []byte
	MinTime, MaxTime    int64
	ServerSignatureHint []byte
}

// TransactionBytes is the Transaction XDR (the tx of the v1 envelope).
func (c *Challenge) TransactionBytes() []byte {
	return append([]byte(nil), c.envelope[c.txStart:c.txEnd]...)
}

// NetworkID is SHA-256 of the network passphrase.
func (c *Challenge) NetworkID() []byte { return append([]byte(nil), c.networkID[:]...) }

// Hash is SHA-256(networkId ‖ 00000002 ‖ transaction): the Stellar
// transaction hash the client key signs.
func (c *Challenge) Hash() []byte { return append([]byte(nil), c.hash[:]...) }

// SignedEnvelope is the server's envelope byte for byte with one more
// DecoratedSignature (hint = the client key's last 4 bytes) appended, as
// standard base64. The caller verifies sig first; this only frames it.
func (c *Challenge) SignedEnvelope(sig []byte) (string, error) {
	if len(sig) != ed25519SignatureLength {
		return "", fmt.Errorf("an Ed25519 signature is 64 bytes, got %d", len(sig))
	}
	var out bytes.Buffer
	out.Write(c.envelope[:c.signatureCountAt])
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], c.signatureCount+1)
	out.Write(n[:])
	out.Write(c.envelope[c.signatureCountAt+4:])
	out.Write(c.clientKey[28:32])
	binary.BigEndian.PutUint32(n[:], uint32(len(sig)))
	out.Write(n[:])
	out.Write(sig)
	return base64.StdEncoding.EncodeToString(out.Bytes()), nil
}

// TransactionHash computes SHA-256(SHA-256(passphrase) ‖ 00000002 ‖ tx).
func TransactionHash(networkPassphrase string, tx []byte) [32]byte {
	nid := sha256.Sum256([]byte(networkPassphrase))
	h := sha256.New()
	h.Write(nid[:])
	h.Write([]byte{0, 0, 0, EnvelopeTypeTx})
	h.Write(tx)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Verify applies every SEP-10 client rule to envelopeBase64 at now (Unix
// seconds) and returns the verified challenge, or a *ChallengeError naming
// the first rule it breaks. A port of the card SDK's Sep10Challenge.verify.
func Verify(envelopeBase64 string, expect Expectation, now int64) (*Challenge, error) {
	if err := expect.check(); err != nil {
		return nil, err
	}
	if len(envelopeBase64) > MaxEnvelopeBase64Length {
		return nil, reject(ReasonMalformed, "envelope longer than %d base64 characters", MaxEnvelopeBase64Length)
	}
	env, err := base64.StdEncoding.Strict().DecodeString(envelopeBase64)
	if err != nil || len(env) == 0 || base64.StdEncoding.EncodeToString(env) != envelopeBase64 {
		return nil, reject(ReasonMalformed, "envelope is not canonical standard base64")
	}
	c, err := parse(env, &expect, now)
	var xe *xdrError
	if errors.As(err, &xe) {
		return nil, reject(ReasonMalformed, "%s", xe.msg)
	}
	return c, err
}

func parse(env []byte, expect *Expectation, now int64) (*Challenge, error) {
	r := &xdrReader{data: env}
	envelopeType, err := r.int32()
	if err != nil {
		return nil, err
	}
	if envelopeType != EnvelopeTypeTx {
		return nil, reject(ReasonEnvelopeType, "envelope type %d is not ENVELOPE_TYPE_TX", envelopeType)
	}
	txStart := r.pos

	// sourceAccount
	t, err := r.int32()
	if err != nil {
		return nil, err
	}
	switch t {
	case keyTypeEd25519:
		key, err := r.fixedOpaque(32)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(key, expect.ServerKey) {
			return nil, reject(ReasonServerKey, "transaction source is not the server signing key")
		}
	case keyTypeMuxedEd25519:
		return nil, reject(ReasonServerKey, "transaction source is a muxed account")
	default:
		return nil, xdrErr("unknown transaction source key type %d", t)
	}
	if _, err := r.uint32(); err != nil { // fee: any
		return nil, err
	}
	seq, err := r.int64()
	if err != nil {
		return nil, err
	}
	if seq != 0 {
		return nil, reject(ReasonSequence, "sequence number is not 0")
	}

	cond, err := r.int32()
	if err != nil {
		return nil, err
	}
	if cond != precondTime {
		return nil, reject(ReasonTimeBoundsMissing, "preconditions are not PRECOND_TIME (type %d)", cond)
	}
	minTime, err := r.int64()
	if err != nil {
		return nil, err
	}
	maxTime, err := r.int64()
	if err != nil {
		return nil, err
	}
	if err := checkTimeBounds(minTime, maxTime, expect, now); err != nil {
		return nil, err
	}

	memo, err := r.int32()
	if err != nil {
		return nil, err
	}
	if memo != memoNone {
		return nil, reject(ReasonMemo, "memo type %d is not MEMO_NONE", memo)
	}

	opCount, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if opCount < 1 || opCount > MaxOperations {
		return nil, reject(ReasonOperationCount, "%d operations (allowed 1..%d)", opCount, MaxOperations)
	}
	homeKey := []byte(expect.HomeDomain + " auth")
	for i := 0; i < int(opCount); i++ {
		present, err := r.optional()
		if err != nil {
			return nil, err
		}
		if !present {
			return nil, reject(ReasonOperationSource, "operation %d has no source account", i)
		}
		t, err := r.int32()
		if err != nil {
			return nil, err
		}
		var source []byte
		switch t {
		case keyTypeEd25519:
			if source, err = r.fixedOpaque(32); err != nil {
				return nil, err
			}
		case keyTypeMuxedEd25519:
			return nil, reject(ReasonOperationSource, "operation %d source is a muxed account", i)
		default:
			return nil, xdrErr("unknown operation %d source key type %d", i, t)
		}
		opType, err := r.int32()
		if err != nil {
			return nil, err
		}
		if opType != opManageData {
			return nil, reject(ReasonOperationType, "operation %d is type %d, not MANAGE_DATA", i, opType)
		}
		name, err := r.varOpaque(64)
		if err != nil {
			return nil, err
		}
		var value []byte
		hasValue, err := r.optional()
		if err != nil {
			return nil, err
		}
		if hasValue {
			if value, err = r.varOpaque(manageDataMaxValueLength); err != nil {
				return nil, err
			}
		}
		if i == 0 {
			if !bytes.Equal(source, expect.ClientKey) {
				return nil, reject(ReasonOperationSource, "operation 0 is not sourced by the client key")
			}
			if !bytes.Equal(name, homeKey) {
				return nil, reject(ReasonHomeDomainKey, "operation 0 key is not %q", expect.HomeDomain+" auth")
			}
			if !hasValue || len(value) != 64 {
				size := "absent"
				if hasValue {
					size = fmt.Sprintf("%d", len(value))
				}
				return nil, reject(ReasonNonceLength, "operation 0 value is %s, not 64 bytes", size)
			}
		} else {
			if !bytes.Equal(source, expect.ServerKey) {
				return nil, reject(ReasonOperationSource, "operation %d is not sourced by the server key", i)
			}
			if string(name) == webAuthDomainKey && (!hasValue || string(value) != expect.WebAuthDomain) {
				return nil, reject(ReasonWebAuthDomain, "web_auth_domain is not %q", expect.WebAuthDomain)
			}
		}
	}
	ext, err := r.int32()
	if err != nil {
		return nil, err
	}
	if ext != 0 {
		return nil, xdrErr("transaction ext %d is not 0", ext)
	}
	txEnd := r.pos

	sigCountAt := r.pos
	sigCount, err := r.count(maxSignatures)
	if err != nil {
		return nil, err
	}
	hints := make([][]byte, 0, sigCount)
	sigs := make([][]byte, 0, sigCount)
	for i := 0; i < sigCount; i++ {
		hint, err := r.fixedOpaque(4)
		if err != nil {
			return nil, err
		}
		sig, err := r.varOpaque(64)
		if err != nil {
			return nil, err
		}
		hints = append(hints, hint)
		sigs = append(sigs, sig)
	}
	if err := r.requireEnd(); err != nil {
		return nil, err
	}
	if sigCount != 1 {
		return nil, reject(ReasonSignatureCount, "%d signatures, expected exactly 1", sigCount)
	}

	nid := sha256.Sum256([]byte(expect.NetworkPassphrase))
	hash := TransactionHash(expect.NetworkPassphrase, env[txStart:txEnd])
	if !bytes.Equal(hints[0], expect.ServerKey[28:32]) {
		return nil, reject(ReasonServerSignature, "signature hint is not the server key's")
	}
	if len(sigs[0]) != ed25519SignatureLength || !ed25519.Verify(ed25519.PublicKey(expect.ServerKey), hash[:], sigs[0]) {
		return nil, reject(ReasonServerSignature, "the server signature does not verify")
	}
	return &Challenge{
		envelope:            env,
		txStart:             txStart,
		txEnd:               txEnd,
		signatureCountAt:    sigCountAt,
		signatureCount:      uint32(sigCount),
		networkID:           nid,
		hash:                hash,
		clientKey:           append([]byte(nil), expect.ClientKey...),
		MinTime:             minTime,
		MaxTime:             maxTime,
		ServerSignatureHint: hints[0],
	}, nil
}

func checkTimeBounds(minTime, maxTime int64, expect *Expectation, now int64) error {
	// TimePoint is uint64; a value with the top bit set reads as negative here.
	if maxTime == 0 {
		return reject(ReasonTimeBoundsMissing, "maxTime is 0 (no upper bound)")
	}
	if minTime < 0 || maxTime < 0 {
		return reject(ReasonTimeBoundsInvalid, "time bound above 2^63 - 1")
	}
	if minTime > maxTime {
		return reject(ReasonTimeBoundsInvalid, "minTime is after maxTime")
	}
	if maxTime-minTime > expect.MaxLifetime {
		return reject(ReasonTimeBoundsLifetime, "lifetime %d s exceeds %d s", maxTime-minTime, expect.MaxLifetime)
	}
	if now < minTime-expect.MinTimeGrace {
		return reject(ReasonTimeBoundsTooEarly, "challenge is not valid yet")
	}
	if now > maxTime {
		return reject(ReasonTimeBoundsExpired, "challenge has expired")
	}
	return nil
}

// ── strict XDR reader (the SDK's XdrReader) ────────────────────────────

type xdrError struct{ msg string }

func (e *xdrError) Error() string { return e.msg }

func xdrErr(format string, args ...any) error { return &xdrError{fmt.Sprintf(format, args...)} }

type xdrReader struct {
	data []byte
	pos  int
}

func (r *xdrReader) need(n int) error {
	if n < 0 || n > len(r.data)-r.pos {
		return xdrErr("truncated: need %d bytes at offset %d, have %d", n, r.pos, len(r.data)-r.pos)
	}
	return nil
}

func (r *xdrReader) uint32() (uint32, error) {
	if err := r.need(4); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *xdrReader) int32() (int32, error) {
	v, err := r.uint32()
	return int32(v), err
}

func (r *xdrReader) int64() (int64, error) {
	if err := r.need(8); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(r.data[r.pos:])
	r.pos += 8
	return int64(v), nil
}

func (r *xdrReader) fixedOpaque(n int) ([]byte, error) {
	if err := r.need(n); err != nil {
		return nil, err
	}
	out := append([]byte(nil), r.data[r.pos:r.pos+n]...)
	r.pos += n
	pad := (4 - n%4) % 4
	if err := r.need(pad); err != nil {
		return nil, err
	}
	for i := 0; i < pad; i++ {
		if r.data[r.pos] != 0 {
			return nil, xdrErr("non-zero padding at offset %d", r.pos)
		}
		r.pos++
	}
	return out, nil
}

func (r *xdrReader) varOpaque(max int) ([]byte, error) {
	n, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if int64(n) > int64(max) {
		return nil, xdrErr("opaque length %d exceeds maximum %d at offset %d", n, max, r.pos-4)
	}
	return r.fixedOpaque(int(n))
}

func (r *xdrReader) optional() (bool, error) {
	flag, err := r.uint32()
	if err != nil {
		return false, err
	}
	switch flag {
	case 0:
		return false, nil
	case 1:
		return true, nil
	}
	return false, xdrErr("optional flag %d at offset %d", flag, r.pos-4)
}

func (r *xdrReader) count(max int) (int, error) {
	n, err := r.uint32()
	if err != nil {
		return 0, err
	}
	if int64(n) > int64(max) {
		return 0, xdrErr("array count %d exceeds maximum %d at offset %d", n, max, r.pos-4)
	}
	return int(n), nil
}

func (r *xdrReader) requireEnd() error {
	if r.pos != len(r.data) {
		return xdrErr("%d trailing bytes at offset %d", len(r.data)-r.pos, r.pos)
	}
	return nil
}
