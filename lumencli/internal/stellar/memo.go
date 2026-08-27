package stellar

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/txnbuild"
)

// Memo is a memo attached to a transaction. A nil Memo means no memo at all
// (MEMO_NONE); callers build one with ParseMemo. The alias keeps the SDK types
// out of the packages above this one.
type Memo = txnbuild.Memo

// The memo types a transaction may carry, as named on the command line.
const (
	MemoTypeText   = "text"   // up to 28 bytes of free text
	MemoTypeID     = "id"     // unsigned 64-bit integer — what exchanges want
	MemoTypeHash   = "hash"   // 32-byte hash, referencing another transaction
	MemoTypeReturn = "return" // 32-byte hash of the transaction being refunded
)

// MemoTypes lists the accepted memo type names in help-text order.
var MemoTypes = []string{MemoTypeText, MemoTypeID, MemoTypeHash, MemoTypeReturn}

// memoHashHexDigits is the hex-digit length of a 32-byte hash or return memo.
const memoHashHexDigits = 2 * 32

// ParseMemo turns a memo type name and its value into a memo ready to attach to
// a transfer. An empty type name means the default, text.
//
// Only the fully unspecified case — no type, no value — yields no memo
// (nil, nil). Naming a type without a value is an error rather than a silent
// MEMO_NONE: a deposit to an exchange or other pooled account is identified by
// its memo, so a transfer that quietly loses one is usually lost funds.
//
// Values for the id, hash and return types are trimmed of the surrounding
// whitespace that copy-paste picks up. Text memos are taken verbatim, since
// their bytes are the message itself and trimming would alter what the
// recipient sees.
func ParseMemo(memoType, value string) (Memo, error) {
	switch memoType {
	case "":
		if value == "" {
			return nil, nil
		}
		return memoText(value)
	case MemoTypeText:
		if value == "" {
			return nil, missingMemoValue(MemoTypeText)
		}
		return memoText(value)
	case MemoTypeID:
		v := strings.TrimSpace(value)
		if v == "" {
			return nil, missingMemoValue(MemoTypeID)
		}
		id, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid id memo %q: want an unsigned 64-bit integer", v)
		}
		return txnbuild.MemoID(id), nil
	case MemoTypeHash, MemoTypeReturn:
		h, err := memoHash(memoType, value)
		if err != nil {
			return nil, err
		}
		if memoType == MemoTypeHash {
			return txnbuild.MemoHash(h), nil
		}
		return txnbuild.MemoReturn(h), nil
	default:
		return nil, fmt.Errorf("unknown memo type %q (want: %s)", memoType, strings.Join(MemoTypes, " | "))
	}
}

// DescribeMemo renders a memo for a confirmation prompt or a receipt line. It
// returns "" for no memo.
func DescribeMemo(m Memo) string {
	switch v := m.(type) {
	case nil:
		return ""
	case txnbuild.MemoText:
		return fmt.Sprintf("text memo %q", string(v))
	case txnbuild.MemoID:
		return fmt.Sprintf("id memo %d", uint64(v))
	case txnbuild.MemoHash:
		return fmt.Sprintf("hash memo %x", [32]byte(v))
	case txnbuild.MemoReturn:
		return fmt.Sprintf("return memo %x", [32]byte(v))
	default:
		return "memo"
	}
}

// memoText validates a text memo. The limit is 28 bytes, not 28 characters:
// non-ASCII memos run out of room sooner, so the message reports bytes.
func memoText(value string) (Memo, error) {
	if len(value) > txnbuild.MemoTextMaxLength {
		return nil, fmt.Errorf("text memo too long: %d bytes (max %d)", len(value), txnbuild.MemoTextMaxLength)
	}
	return txnbuild.MemoText(value), nil
}

// memoHash decodes the 32-byte hash shared by the hash and return memo types.
func memoHash(memoType, value string) ([32]byte, error) {
	var h [32]byte
	v := strings.TrimSpace(value)
	if v == "" {
		return h, missingMemoValue(memoType)
	}
	if len(v) != memoHashHexDigits {
		return h, fmt.Errorf("invalid %s memo: want %d hex digits (32 bytes), got %d", memoType, memoHashHexDigits, len(v))
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return h, fmt.Errorf("invalid %s memo: not hexadecimal: %v", memoType, err)
	}
	copy(h[:], b)
	return h, nil
}

func missingMemoValue(memoType string) error {
	return fmt.Errorf("memo type %q needs a memo value", memoType)
}
