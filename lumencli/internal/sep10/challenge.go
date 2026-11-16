package sep10

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"
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

// Verify runs every client check on a challenge and returns the parsed
// transaction ready for signing. Any failed check is an error.
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
// a v1 envelope (ReadChallengeTx also accepts the legacy v0 form), the first
// operation sourced by the wallet's own account (ReadChallengeTx returns
// whatever account it names), and no memo at all (this client never asks
// for one, so a memo would mean the challenge is for someone else's shared-
// account identity).
func Verify(envelope string, exp Expect) (*txnbuild.Transaction, error) {
	envelope = strings.TrimSpace(envelope)
	env, err := decodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if env.Type != xdr.EnvelopeTypeEnvelopeTypeTx {
		return nil, fmt.Errorf("challenge refused: a SEP-10 challenge is a v1 transaction envelope, this one is %s", envelopeName(env.Type))
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
	return tx, nil
}

// Sign adds the wallet's signature to a verified challenge and returns the
// signed envelope, base64.
func Sign(tx *txnbuild.Transaction, passphrase string, kp *keypair.Full) (string, error) {
	signed, err := tx.Sign(passphrase, kp)
	if err != nil {
		return "", fmt.Errorf("sign the challenge: %w", err)
	}
	return signed.Base64()
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
