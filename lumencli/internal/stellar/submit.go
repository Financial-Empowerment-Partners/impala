package stellar

import (
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
)

// AmbiguousSubmitError reports a submission whose outcome is unknown.
//
// The transaction was signed and handed to Horizon, and the error that came
// back does not prove it was rejected: Horizon may have forwarded it to the
// network before answering (its 504 Timeout means exactly "still pending when
// I gave up"), or the answer may never have reached us. The transaction stays
// valid until its time bound, so it can be applied AFTER this error is
// printed. A caller that reads it as a plain failure and rebuilds the payment
// will, if the first one lands too, pay twice — a re-run reloads the account,
// sees the next sequence number, and produces a second valid transaction.
type AmbiguousSubmitError struct {
	// Hash is the network-specific hash of the signed transaction, computed
	// locally before submission so it is known even when Horizon never
	// answered. It is what to look up.
	Hash string
	// MaxTime is the transaction's upper time bound. Until it passes, a
	// "not found" from Horizon proves nothing; after it, the transaction can
	// no longer be applied and "not found" is definitive.
	MaxTime time.Time
	// Cause is the underlying submission error, already made readable.
	Cause error
}

func (e *AmbiguousSubmitError) Error() string { return e.Cause.Error() }

// Unwrap exposes the cause so errors.Is/As keep working through the wrapper.
func (e *AmbiguousSubmitError) Unwrap() error { return e.Cause }

// submitOutcomeUnknown decides whether a SubmitTransaction error leaves the
// transaction's fate open. The question is not "did it fail" but "is it
// PROVEN not to have been applied, now or later" — the safe default is no.
//
// Definitive (the transaction was not and cannot be applied):
//
//   - a Horizon problem response with a 4xx status other than 408/429: the
//     400 transaction_failed carrying result codes (tx_bad_seq,
//     tx_insufficient_fee, op_* ...), a malformed-envelope 400, 401, 403,
//     404, 405 (submission disabled), 410;
//   - a dial failure: the connection was never established, so not one byte
//     of the request left this machine.
//
// Ambiguous (everything else): Horizon's own 504 Timeout (the transaction
// was forwarded and was still pending), 503 and 429 (which may come from
// anything between here and Horizon, before or after the forward), 408, any
// other 5xx, a client-side timeout waiting for the response, a connection
// dropped mid-flight, and a response that could not be decoded — including a
// 2xx whose body was unreadable, which is a success we cannot see.
func submitOutcomeUnknown(err error) bool {
	if herr := horizonclient.GetError(err); herr != nil {
		status := 0
		if herr.Response != nil {
			status = herr.Response.StatusCode
		}
		if status == 0 {
			status = herr.Problem.Status
		}
		switch {
		case status == http.StatusRequestTimeout, status == http.StatusTooManyRequests:
			return true
		case status >= 400 && status < 500:
			return false
		default:
			return true
		}
	}
	return !neverConnected(err)
}

// neverConnected reports whether a request failed before a connection
// existed: a dial error (connection refused, no such host, network
// unreachable, dial timeout). Anything later — a timeout awaiting the
// response, a reset, an EOF — may have happened with the request already
// delivered.
func neverConnected(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}
