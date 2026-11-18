package sep10

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// maxEnvelopeChars bounds a base64 challenge envelope. A SEP-10 challenge is
// well under a kilobyte; anything this large is not one.
const maxEnvelopeChars = 64 * 1024

// Expect is what a challenge must match for the client to sign it.
type Expect struct {
	ServerKey     string // the stellar.toml SIGNING_KEY: the transaction source and signer
	HomeDomain    string // the first operation must be named "<HomeDomain> auth"
	WebAuthDomain string // a web_auth_domain operation, when present, must carry this
	Passphrase    string // the selected network's; the server signature is verified under it
	// Account is the wallet's account, which must source the first
	// operation. Empty skips that check — allowed only for inspect, which
	// signs nothing; Verify's callers that sign always set it.
	Account string
}

// Challenge is a challenge that passed every client check; only Verify makes
// one. It remembers the network passphrase it was checked under and the
// account its first operation was checked to name, and can be signed for
// that network by that account only — so no caller can check a challenge
// for one network or key and then sign it for another.
type Challenge struct {
	tx         *txnbuild.Transaction
	env        xdr.TransactionEnvelope // as received: a v1 envelope, canonical XDR
	passphrase string
	account    string // "" when checked without an account (inspect): it cannot be signed
}

// Verify runs every client check on a challenge and returns it, ready to be
// signed. Any failed check is an error.
//
// The SDK's txnbuild.ReadChallengeTx does most of the work: transaction
// source = server key, sequence number 0, non-infinite time bounds valid now
// (it allows the minimum time to be up to 5 minutes in the future, for clock
// drift), at least one operation, every operation manage-data with a source
// account, the first named "<home domain> auth" with a 64-character base64
// value decoding to 48 bytes, every later one sourced by the server key, a
// web_auth_domain one (when present) carrying the expected value, only an ID
// memo, no fee-bump envelope, and a valid server signature under the
// network passphrase. Verify adds what ReadChallengeTx leaves to the caller:
// a v1 envelope (ReadChallengeTx also accepts the legacy v0 form), the
// envelope being exactly its own canonical XDR (the SDK's decoder lets a
// stray byte after the envelope through), the first operation sourced by
// the wallet's own account (ReadChallengeTx returns whatever account it
// names), and no memo at all (this client never asks for one, so a memo
// would mean the challenge is for someone else's shared-account identity).
func Verify(envelope string, exp Expect) (*Challenge, error) {
	envelope = strings.TrimSpace(envelope)
	env, err := decodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if env.Type != xdr.EnvelopeTypeEnvelopeTypeTx {
		return nil, fmt.Errorf("challenge refused: a SEP-10 challenge is a v1 transaction envelope, this one is %s", envelopeName(env.Type))
	}
	if err := exactXDR(envelope, env); err != nil {
		return nil, err
	}
	if !strkeyAccount(exp.ServerKey) {
		return nil, fmt.Errorf("server key %q is not a G... account id", exp.ServerKey)
	}
	tx, client, _, memo, err := txnbuild.ReadChallengeTx(envelope, exp.ServerKey, exp.Passphrase, exp.WebAuthDomain, []string{exp.HomeDomain})
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "transaction not signed by") {
			msg += " under the selected network's passphrase (a challenge for another network, or one not signed by the server key)"
		}
		return nil, fmt.Errorf("challenge refused: %s", msg)
	}
	if exp.Account != "" && client != exp.Account {
		return nil, fmt.Errorf("challenge refused: its first operation is sourced by %s, not this wallet's account %s", client, exp.Account)
	}
	if memo != nil {
		return nil, fmt.Errorf("challenge refused: it carries memo id %d, which this client did not ask for", uint64(*memo))
	}
	return &Challenge{tx: tx, env: env, passphrase: exp.Passphrase, account: exp.Account}, nil
}

// exactXDR refuses an envelope that is not, byte for byte, the canonical XDR
// of what it decodes to. XDR has one encoding per value, so what fails here
// is bytes the decoder tolerated — the SDK's lets a single stray byte after
// the envelope through. The checks must judge exactly the bytes a signer
// sees, and an Impala card signs the Transaction bytes themselves.
func exactXDR(envelope string, env xdr.TransactionEnvelope) error {
	raw, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		return fmt.Errorf("challenge is not a base64 transaction envelope: %v", err)
	}
	canonical, err := env.MarshalBinary()
	if err != nil {
		return fmt.Errorf("re-encode the challenge: %v", err)
	}
	switch {
	case bytes.Equal(raw, canonical):
		return nil
	case len(raw) > len(canonical) && bytes.Equal(raw[:len(canonical)], canonical):
		return fmt.Errorf("challenge refused: %d unexpected byte(s) follow the transaction envelope", len(raw)-len(canonical))
	default:
		return fmt.Errorf("challenge refused: the envelope is not in canonical XDR form")
	}
}

// Account is the account the challenge was checked for ("" when none was).
func (c *Challenge) Account() string { return c.account }

// signableBy refuses a signer other than the account the challenge was
// checked for, and any signer of a challenge checked without one.
func (c *Challenge) signableBy(address string) error {
	if c.account == "" {
		return errors.New("this challenge was checked without an account, so it cannot be signed")
	}
	if address != c.account {
		return fmt.Errorf("the challenge was checked for %s, not for %s", c.account, address)
	}
	return nil
}

// Sign adds the wallet's signature, for the network the challenge was
// checked under, and returns the signed envelope, base64.
func (c *Challenge) Sign(kp *keypair.Full) (string, error) {
	if err := c.signableBy(kp.Address()); err != nil {
		return "", err
	}
	signed, err := c.tx.Sign(c.passphrase, kp)
	if err != nil {
		return "", fmt.Errorf("sign the challenge: %w", err)
	}
	return signed.Base64()
}

// The Impala card's own limits on a challenge (docs/sep10-card-keys.md §2
// and §3.3 in the Impala repository). The card parses the transaction itself
// and accepts a narrower shape than SEP-10 allows; ForCard refuses up front,
// with the reason, what the card would refuse with a status word.
const (
	CardMaxTransaction = 640 // SEP10_MAX_TX_LENGTH
	CardMaxOperations  = 5   // SEP10_MAX_OPERATIONS
)

// CardSigning is a checked challenge prepared for an Impala card. The card
// is handed the transaction, never a hash: it parses the transaction, refuses
// anything but a SEP-10 challenge for its own key, and signs the hash it
// computes itself. Hash is what that computation must give, kept here to
// verify the card's signature before anything is sent.
type CardSigning struct {
	tx        *txnbuild.Transaction
	publicKey ed25519.PublicKey
	// Transaction is the Transaction XDR (the tx of the v1 envelope), byte
	// for byte as the server sent it.
	Transaction []byte
	// NetworkID is SHA-256 of the passphrase the challenge was checked under.
	NetworkID []byte
	// Hash is SHA-256(NetworkID ‖ ENVELOPE_TYPE_TX ‖ Transaction), the
	// transaction hash: what the card signs.
	Hash []byte
}

// ForCard prepares the challenge for the card whose Stellar key is publicKey
// (32 bytes), which must be the account the challenge was checked for.
func (c *Challenge) ForCard(publicKey []byte) (*CardSigning, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("a card's Stellar key is %d bytes, got %d", ed25519.PublicKeySize, len(publicKey))
	}
	address, err := strkey.Encode(strkey.VersionByteAccountID, publicKey)
	if err != nil {
		return nil, fmt.Errorf("encode the card's Stellar key: %v", err)
	}
	if err := c.signableBy(address); err != nil {
		return nil, err
	}
	tx := c.env.V1.Tx
	if tx.Cond.Type != xdr.PreconditionTypePrecondTime {
		return nil, fmt.Errorf("challenge refused by the card's rules: the card signs only a challenge whose preconditions are plain time bounds (PRECOND_TIME); this one's are %s", precondName(tx.Cond.Type))
	}
	if tx.Ext.V != 0 {
		return nil, fmt.Errorf("challenge refused by the card's rules: the card signs only a transaction without an extension; this one carries extension v%d", tx.Ext.V)
	}
	if n := len(tx.Operations); n > CardMaxOperations {
		return nil, fmt.Errorf("challenge refused by the card's rules: the card signs a challenge of at most %d operations; this one has %d", CardMaxOperations, n)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encode the challenge transaction: %v", err)
	}
	if len(raw) > CardMaxTransaction {
		return nil, fmt.Errorf("challenge refused by the card's rules: its transaction is %d bytes; the card signs at most %d", len(raw), CardMaxTransaction)
	}
	nid := network.ID(c.passphrase)
	h := sha256.New()
	h.Write(nid[:])
	h.Write([]byte{0, 0, 0, 2}) // ENVELOPE_TYPE_TX
	h.Write(raw)
	hash := h.Sum(nil)
	// The bytes the card hashes must give the hash the server's signature
	// was verified over. Verify's exactXDR makes this hold; check it anyway.
	if sdkHash, err := c.tx.Hash(c.passphrase); err != nil || !bytes.Equal(sdkHash[:], hash) {
		return nil, errors.New("the challenge's transaction bytes do not hash to the transaction hash the server's signature was verified over")
	}
	return &CardSigning{
		tx:          c.tx,
		publicKey:   ed25519.PublicKey(append([]byte(nil), publicKey...)),
		Transaction: raw,
		NetworkID:   nid[:],
		Hash:        hash,
	}, nil
}

// Envelope checks the card's signature and returns the challenge with it
// appended, base64: the server's envelope, byte for byte, plus one decorated
// signature whose hint is the last four bytes of the card's key. A signature
// that does not verify under the card's key over Hash is refused: it means
// another card than the one whose key was read, or a faulty engine.
func (s *CardSigning) Envelope(sig []byte) (string, error) {
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(s.publicKey, s.Hash, sig) {
		return "", errors.New("the card's signature does not verify under its Stellar key over this challenge (another card, or a faulty engine)")
	}
	var hint xdr.SignatureHint
	copy(hint[:], s.publicKey[ed25519.PublicKeySize-4:])
	signed, err := s.tx.AddSignatureDecorated(xdr.DecoratedSignature{
		Hint:      hint,
		Signature: xdr.Signature(append([]byte(nil), sig...)),
	})
	if err != nil {
		return "", fmt.Errorf("attach the card's signature: %w", err)
	}
	return signed.Base64()
}

func precondName(t xdr.PreconditionType) string {
	switch t {
	case xdr.PreconditionTypePrecondNone:
		return "PRECOND_NONE"
	case xdr.PreconditionTypePrecondTime:
		return "PRECOND_TIME"
	case xdr.PreconditionTypePrecondV2:
		return "PRECOND_V2"
	default:
		return "precondition type " + strconv.Itoa(int(t))
	}
}

func strkeyAccount(s string) bool {
	_, err := keypair.ParseAddress(s)
	return err == nil && strings.HasPrefix(s, "G")
}

func decodeEnvelope(envelope string) (xdr.TransactionEnvelope, error) {
	var env xdr.TransactionEnvelope
	if envelope == "" {
		return env, fmt.Errorf("no challenge envelope given")
	}
	if len(envelope) > maxEnvelopeChars {
		return env, fmt.Errorf("challenge envelope is larger than %d characters; not a SEP-10 challenge", maxEnvelopeChars)
	}
	if err := xdr.SafeUnmarshalBase64(envelope, &env); err != nil {
		return env, fmt.Errorf("challenge is not a base64 transaction envelope: %v", err)
	}
	return env, nil
}

func envelopeName(t xdr.EnvelopeType) string {
	switch t {
	case xdr.EnvelopeTypeEnvelopeTypeTx:
		return "v1"
	case xdr.EnvelopeTypeEnvelopeTypeTxV0:
		return "v0"
	case xdr.EnvelopeTypeEnvelopeTypeTxFeeBump:
		return "fee_bump"
	default:
		return "envelope type " + strconv.Itoa(int(t))
	}
}

// Decoded is a challenge envelope taken apart for display. It describes
// whatever the envelope holds, valid challenge or not.
type Decoded struct {
	Envelope   string // "v1" or "v0"
	Source     string
	Sequence   int64
	Fee        uint32
	TimeBounds *TimeBounds // nil when the transaction has none
	Memo       *Memo       // nil for no memo
	Operations []Operation
	Signatures []Signature

	env xdr.TransactionEnvelope
}

// TimeBounds are unix seconds; 0 means unbounded on that side, as on the wire.
type TimeBounds struct {
	MinTime uint64
	MaxTime uint64
}

// Memo is a transaction memo: text verbatim, id decimal, hash/return as 64
// hex digits.
type Memo struct {
	Type  string
	Value string
}

// Operation is one operation. Name, Value and HasValue are set for
// manage_data only (HasValue false means the operation deletes the entry).
type Operation struct {
	Type         string
	Source       string // "" when the operation has no source account of its own
	IsManageData bool
	Name         string
	Value        []byte
	HasValue     bool
}

// Signature is one decorated signature. Signer is set by MatchSigners when
// one of the candidate keys verifies it.
type Signature struct {
	Hint   string // 8 hex digits
	Signer string
	sig    []byte
	hint   [4]byte
}

// Decode takes any v0 or v1 transaction envelope apart. A fee-bump envelope
// is refused: no SEP-10 challenge is one.
func Decode(envelope string) (*Decoded, error) {
	env, err := decodeEnvelope(strings.TrimSpace(envelope))
	if err != nil {
		return nil, err
	}
	if env.Type != xdr.EnvelopeTypeEnvelopeTypeTx && env.Type != xdr.EnvelopeTypeEnvelopeTypeTxV0 {
		return nil, fmt.Errorf("a %s envelope is not a SEP-10 challenge", envelopeName(env.Type))
	}
	src := env.SourceAccount()
	d := &Decoded{
		Envelope: envelopeName(env.Type),
		Source:   src.Address(),
		Sequence: env.SeqNum(),
		Fee:      env.Fee(),
		env:      env,
	}
	if tb := env.TimeBounds(); tb != nil {
		d.TimeBounds = &TimeBounds{MinTime: uint64(tb.MinTime), MaxTime: uint64(tb.MaxTime)}
	}
	d.Memo = decodeMemo(env.Memo())
	for _, op := range env.Operations() {
		o := Operation{}
		if name, ok := operations.TypeNames[op.Body.Type]; ok {
			o.Type = name
		} else {
			o.Type = "unknown_" + strconv.Itoa(int(op.Body.Type))
		}
		if op.SourceAccount != nil {
			o.Source = op.SourceAccount.Address()
		}
		if md, ok := op.Body.GetManageDataOp(); ok {
			o.IsManageData = true
			o.Name = string(md.DataName)
			if md.DataValue != nil {
				o.HasValue = true
				o.Value = append([]byte(nil), (*md.DataValue)...)
			}
		}
		d.Operations = append(d.Operations, o)
	}
	for _, s := range env.Signatures() {
		d.Signatures = append(d.Signatures, Signature{
			Hint: hex.EncodeToString(s.Hint[:]),
			sig:  append([]byte(nil), s.Signature...),
			hint: s.Hint,
		})
	}
	return d, nil
}

func decodeMemo(m xdr.Memo) *Memo {
	switch m.Type {
	case xdr.MemoTypeMemoText:
		return &Memo{Type: "text", Value: m.MustText()}
	case xdr.MemoTypeMemoId:
		return &Memo{Type: "id", Value: strconv.FormatUint(uint64(m.MustId()), 10)}
	case xdr.MemoTypeMemoHash:
		h := m.MustHash()
		return &Memo{Type: "hash", Value: hex.EncodeToString(h[:])}
	case xdr.MemoTypeMemoReturn:
		h := m.MustRetHash()
		return &Memo{Type: "return", Value: hex.EncodeToString(h[:])}
	default:
		return nil
	}
}

// MatchSigners labels each signature with the first of candidates (G...
// addresses) whose key verifies it over the transaction hash under
// passphrase. Signatures no candidate verifies stay unlabeled.
func (d *Decoded) MatchSigners(passphrase string, candidates ...string) error {
	hash, err := network.HashTransactionInEnvelope(d.env, passphrase)
	if err != nil {
		return fmt.Errorf("hash the challenge: %w", err)
	}
	for i := range d.Signatures {
		s := &d.Signatures[i]
		for _, addr := range candidates {
			kp, err := keypair.ParseAddress(addr)
			if err != nil {
				continue
			}
			if kp.Hint() != s.hint {
				continue
			}
			if kp.Verify(hash[:], s.sig) == nil {
				s.Signer = addr
				break
			}
		}
	}
	return nil
}
