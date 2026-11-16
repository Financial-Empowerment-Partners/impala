package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func walletEnv() map[string]string { return map[string]string{EnvSecret: sep10WalletKP.Seed()} }

// assertNoSecrets fails if the wallet's seed appears in any output, or the
// token on stderr.
func assertNoSecrets(t *testing.T, out, errOut string, token string) {
	t.Helper()
	if strings.Contains(out, sep10WalletKP.Seed()) || strings.Contains(errOut, sep10WalletKP.Seed()) {
		t.Errorf("the secret seed appears in the output")
	}
	if token != "" && strings.Contains(errOut, token) {
		t.Errorf("the token appears on stderr")
	}
}

func TestSep10LoginSuccess(t *testing.T) {
	f := newSep10Fake(t)
	app, out, errb := f.app("", walletEnv())
	if code := app.run([]string{"--network", "testnet", "sep10", "login", "example.com"}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	queries, issued, posted, tokens := f.snapshot()
	if len(issued) != 1 || len(posted) != 1 || len(tokens) != 1 {
		t.Fatalf("issued=%d posted=%d tokens=%d, want 1 each", len(issued), len(posted), len(tokens))
	}
	if got, want := out.String(), tokens[0]+"\n"; got != want {
		t.Errorf("stdout = %q, want the token alone: %q", got, want)
	}
	if q := queries[0]; q.Get("account") != sep10WalletKP.Address() || q.Get("home_domain") != "example.com" {
		t.Errorf("challenge query = %v", q)
	}
	stderr := errb.String()
	assertNoSecrets(t, out.String(), stderr, tokens[0])
	for _, want := range []string{
		`Network: testnet (passphrase "Test SDF Network ; September 2015")`,
		"Home domain: example.com",
		"Endpoint:    https://example.com/auth",
		"Server key:  " + sep10ServerKP.Address(),
		"Account:     " + sep10WalletKP.Address(),
		"a client cannot verify the token's signature",
		"iss: https://example.com/auth",
		"sub: " + sep10WalletKP.Address(),
		"iat: 2025-11-15 09:46:40 UTC",
		"exp: 2025-11-16 09:46:40 UTC (already expired)",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
	// What was posted is the issued challenge plus exactly one signature, the
	// wallet's: the server verified it (it issued a token), and this pins
	// that nothing else was changed before signing.
	var issuedEnv, postedEnv xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(issued[0], &issuedEnv); err != nil {
		t.Fatal(err)
	}
	if err := xdr.SafeUnmarshalBase64(posted[0], &postedEnv); err != nil {
		t.Fatal(err)
	}
	if len(postedEnv.Signatures()) != 2 || postedEnv.Signatures()[1].Hint != sep10WalletKP.Hint() {
		t.Errorf("posted signatures = %d, want the server's plus the wallet's", len(postedEnv.Signatures()))
	}
	ih, _ := network.HashTransactionInEnvelope(issuedEnv, network.TestNetworkPassphrase)
	ph, _ := network.HashTransactionInEnvelope(postedEnv, network.TestNetworkPassphrase)
	if ih != ph {
		t.Error("the posted transaction differs from the issued one")
	}
}

func TestSep10LoginSecretFromStdin(t *testing.T) {
	f := newSep10Fake(t)
	app, out, errb := f.app(sep10WalletKP.Seed()+"\n", nil)
	if code := app.run([]string{"sep10", "login", "--network", "testnet", "example.com"}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	_, _, _, tokens := f.snapshot()
	if len(tokens) != 1 || out.String() != tokens[0]+"\n" {
		t.Errorf("stdout = %q", out.String())
	}
	assertNoSecrets(t, out.String(), errb.String(), tokens[0])
}

// TestSep10LoopbackHTTP: a local development server over plain http is
// accepted on loopback (the toml is fetched from http://127.0.0.1:port).
func TestSep10LoopbackHTTP(t *testing.T) {
	f := newSep10LoopbackFake(t)
	app, out, errb := f.app("", walletEnv())
	if code := app.run([]string{"--network", "testnet", "sep10", "login", f.home}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	_, _, _, tokens := f.snapshot()
	if len(tokens) != 1 || out.String() != tokens[0]+"\n" {
		t.Errorf("stdout = %q", out.String())
	}
}

// TestSep10MainnetWalletRefusesTestnetServer: the default network is
// mainnet; a server whose toml says testnet is refused before any challenge
// is requested, so a wallet never signs for the wrong network.
func TestSep10MainnetWalletRefusesTestnetServer(t *testing.T) {
	f := newSep10Fake(t)
	app, out, errb := f.app("", walletEnv())
	if code := app.run([]string{"sep10", "login", "example.com"}); code != 1 {
		t.Fatalf("exit %d, want 1; stderr:\n%s", code, errb)
	}
	if !strings.Contains(errb.String(), "not the selected one") || !strings.Contains(errb.String(), "Network: mainnet") {
		t.Errorf("stderr:\n%s", errb)
	}
	if q, _, _, _ := f.snapshot(); len(q) != 0 || out.Len() != 0 {
		t.Errorf("a challenge was requested (%d) or stdout written (%q)", len(q), out)
	}
}

// TestSep10ChallengeRefusals runs `login` against challenges that each break
// one client check. Every one must be refused before signing: exit 1,
// nothing on stdout, nothing POSTed.
func TestSep10ChallengeRefusals(t *testing.T) {
	now := time.Now().Unix()
	timeBounds := func(min, max int64) func(*xdr.TransactionEnvelope) {
		return func(env *xdr.TransactionEnvelope) {
			env.V1.Tx.Cond = xdr.Preconditions{Type: xdr.PreconditionTypePrecondTime,
				TimeBounds: &xdr.TimeBounds{MinTime: xdr.TimePoint(min), MaxTime: xdr.TimePoint(max)}}
		}
	}
	serverMuxed := xdr.MustMuxedAddress(sep10ServerKP.Address())
	cases := []struct {
		name  string
		setup func(f *sep10Fake)
		want  string
	}{
		{"wrong server key", func(f *sep10Fake) {
			f.toml = fmt.Sprintf("NETWORK_PASSPHRASE = %q\nWEB_AUTH_ENDPOINT = %q\nSIGNING_KEY = %q\n", f.signFor, f.endpoint, sep10OtherKP.Address())
		}, "transaction source account is not equal to server's account"},
		{"sequence not 0", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) { env.V1.Tx.SeqNum = 1 }
		}, "sequence number must be 0"},
		{"expired", func(f *sep10Fake) { f.mutate = timeBounds(now-900, now-600) }, "not within range of the specified timebounds"},
		{"not yet valid", func(f *sep10Fake) { f.mutate = timeBounds(now+3600, now+3900) }, "not within range of the specified timebounds"},
		{"no time bounds", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				env.V1.Tx.Cond = xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone}
			}
		}, "non-infinite timebounds"},
		{"wrong home domain", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				env.V1.Tx.Operations[0].Body.ManageDataOp.DataName = "evil.example auth"
			}
		}, "operation key does not match any homeDomains"},
		{"first op not sourced by the wallet", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				env.V1.Tx.Operations[0].SourceAccount = xdr.MustMuxedAddressPtr(sep10OtherKP.Address())
			}
		}, "not this wallet's account"},
		{"first op without a source", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) { env.V1.Tx.Operations[0].SourceAccount = nil }
		}, "operation should have a source account"},
		{"nonce of the wrong length", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				v := xdr.DataValue(strings.Repeat("A", 32))
				env.V1.Tx.Operations[0].Body.ManageDataOp.DataValue = &v
			}
		}, "should be 64 bytes long"},
		{"non-manage-data operation", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				env.V1.Tx.Operations = append(env.V1.Tx.Operations, xdr.Operation{
					SourceAccount: &serverMuxed,
					Body: xdr.OperationBody{Type: xdr.OperationTypePayment, PaymentOp: &xdr.PaymentOp{
						Destination: xdr.MustMuxedAddress(sep10OtherKP.Address()), Asset: xdr.MustNewNativeAsset(), Amount: 10_000_000,
					}},
				})
			}
		}, "operation type should be manage_data"},
		{"later op sourced by the wallet", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				v := xdr.DataValue("x")
				env.V1.Tx.Operations = append(env.V1.Tx.Operations, xdr.Operation{
					SourceAccount: xdr.MustMuxedAddressPtr(sep10WalletKP.Address()),
					Body:          xdr.OperationBody{Type: xdr.OperationTypeManageData, ManageDataOp: &xdr.ManageDataOp{DataName: "other", DataValue: &v}},
				})
			}
		}, "subsequent operations are unrecognized"},
		{"web_auth_domain mismatch", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				v := xdr.DataValue("evil.example")
				env.V1.Tx.Operations[1].Body.ManageDataOp.DataValue = &v
			}
		}, `web auth domain operation value is "evil.example" but expect "example.com"`},
		{"web_auth_domain by the wallet", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				env.V1.Tx.Operations[1].SourceAccount = xdr.MustMuxedAddressPtr(sep10WalletKP.Address())
			}
		}, "web auth domain operation must have server source account"},
		{"memo", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				id := xdr.Uint64(7)
				env.V1.Tx.Memo = xdr.Memo{Type: xdr.MemoTypeMemoId, Id: &id}
			}
		}, "carries memo id 7"},
		{"v0 envelope", func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				tx := env.V1.Tx
				*env = xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTxV0, V0: &xdr.TransactionV0Envelope{Tx: xdr.TransactionV0{
					SourceAccountEd25519: *tx.SourceAccount.Ed25519, Fee: tx.Fee, SeqNum: tx.SeqNum,
					TimeBounds: tx.Cond.TimeBounds, Memo: tx.Memo, Operations: tx.Operations,
				}}}
			}
		}, "this one is v0"},
		{"fee-bump envelope", func(f *sep10Fake) {
			f.noResign = true
			f.mutate = func(env *xdr.TransactionEnvelope) {
				inner := *env.V1
				*env = xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump, FeeBump: &xdr.FeeBumpTransactionEnvelope{Tx: xdr.FeeBumpTransaction{
					FeeSource: serverMuxed, Fee: 1000,
					InnerTx: xdr.FeeBumpTransactionInnerTx{Type: xdr.EnvelopeTypeEnvelopeTypeTx, V1: &inner},
				}}}
			}
		}, "this one is fee_bump"},
		{"missing server signature", func(f *sep10Fake) {
			f.noResign = true
			f.mutate = func(env *xdr.TransactionEnvelope) { env.V1.Signatures = nil }
		}, "not signed by " + sep10ServerKP.Address()},
		{"signature by another key", func(f *sep10Fake) {
			f.resignWith = sep10OtherKP
			f.mutate = func(*xdr.TransactionEnvelope) {}
		}, "not signed by " + sep10ServerKP.Address()},
		{"corrupted server signature", func(f *sep10Fake) {
			f.noResign = true
			f.mutate = func(env *xdr.TransactionEnvelope) { env.V1.Signatures[0].Signature[0] ^= 0xff }
		}, "not signed by " + sep10ServerKP.Address()},
		{"challenge signed for another network", func(f *sep10Fake) {
			// The toml and response say nothing about the network; only
			// the signature, checked under testnet's passphrase, reveals it.
			f.signFor = network.PublicNetworkPassphrase
			f.respPassphrase = "-"
			f.toml = fmt.Sprintf("WEB_AUTH_ENDPOINT = %q\nSIGNING_KEY = %q\n", f.endpoint, f.server.Address())
		}, "under the selected network's passphrase"},
		{"response names another network", func(f *sep10Fake) { f.respPassphrase = network.PublicNetworkPassphrase },
			"the server says it is for the network"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSep10Fake(t)
			tc.setup(f)
			app, out, errb := f.app("", walletEnv())
			code := app.run([]string{"--network", "testnet", "sep10", "login", "example.com"})
			if code != 1 {
				t.Fatalf("exit %d, want 1; stderr:\n%s", code, errb)
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Errorf("stderr missing %q:\n%s", tc.want, errb)
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", out)
			}
			if _, issued, posted, _ := f.snapshot(); len(issued) != 1 || len(posted) != 0 {
				t.Errorf("issued=%d posted=%d: a refused challenge must never be signed and sent", len(issued), len(posted))
			}
			assertNoSecrets(t, out.String(), errb.String(), "")
		})
	}
}

// TestSep10DiscoveryRefusals: a stellar.toml that cannot support a safe
// exchange is refused before any challenge is requested.
func TestSep10DiscoveryRefusals(t *testing.T) {
	key := sep10ServerKP.Address()
	pass := network.TestNetworkPassphrase
	cases := []struct {
		name, toml, want string
	}{
		{"no WEB_AUTH_ENDPOINT", fmt.Sprintf("NETWORK_PASSPHRASE = %q\nSIGNING_KEY = %q\n", pass, key), "declares no WEB_AUTH_ENDPOINT"},
		{"no SIGNING_KEY", fmt.Sprintf("NETWORK_PASSPHRASE = %q\nWEB_AUTH_ENDPOINT = \"https://example.com/auth\"\n", pass), "declares no SIGNING_KEY"},
		{"invalid SIGNING_KEY", fmt.Sprintf("WEB_AUTH_ENDPOINT = \"https://example.com/auth\"\nSIGNING_KEY = %q\n", key[:55]+"A"), "is not a valid G... account id"},
		{"secret seed as SIGNING_KEY", fmt.Sprintf("WEB_AUTH_ENDPOINT = \"https://example.com/auth\"\nSIGNING_KEY = %q\n", sep10OtherKP.Seed()), "is not a valid G... account id"},
		{"plain-http endpoint", fmt.Sprintf("WEB_AUTH_ENDPOINT = \"http://example.com/auth\"\nSIGNING_KEY = %q\n", key), "plain http is accepted only for a loopback host"},
		{"relative endpoint", fmt.Sprintf("WEB_AUTH_ENDPOINT = \"/auth\"\nSIGNING_KEY = %q\n", key), "is not an absolute URL"},
		{"pubnet server", fmt.Sprintf("NETWORK_PASSPHRASE = %q\nWEB_AUTH_ENDPOINT = \"https://example.com/auth\"\nSIGNING_KEY = %q\n", network.PublicNetworkPassphrase, key), "not the selected one"},
		{"malformed toml", "SIGNING_KEY = \"" + key + "\nWEB_AUTH_ENDPOINT = 1\n", "unterminated string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSep10Fake(t)
			f.toml = tc.toml
			app, out, errb := f.app("", walletEnv())
			if code := app.run([]string{"--network", "testnet", "sep10", "login", "example.com"}); code != 1 {
				t.Fatalf("exit %d, want 1; stderr:\n%s", code, errb)
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Errorf("stderr missing %q:\n%s", tc.want, errb)
			}
			if q, _, _, _ := f.snapshot(); len(q) != 0 || out.Len() != 0 {
				t.Errorf("challenge requests=%d stdout=%q, want none", len(q), out)
			}
			assertNoSecrets(t, out.String(), errb.String(), "")
		})
	}
}

func TestSep10TokenEndpointFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"401 with an error", 401, `{"error":"challenge is expired"}`, "HTTP 401: challenge is expired"},
		{"400 with control characters", 400, `{"error":"bad\u001b[2Jthing"}`, "HTTP 400: bad?[2Jthing"},
		{"500 without a body", 500, ``, "HTTP 500 Internal Server Error"},
		{"200 without a token", 200, `{"status":"ok"}`, "answered without a token"},
		{"200 with an empty token", 200, `{"token":""}`, "answered without a token"},
		{"200 not JSON", 200, `<html>`, "not the expected JSON"},
		{"200 multi-line token", 200, `{"token":"abc\ndef"}`, "outside visible ASCII"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSep10Fake(t)
			f.tokenStatus, f.tokenBody = tc.status, tc.body
			app, out, errb := f.app("", walletEnv())
			if code := app.run([]string{"--network", "testnet", "sep10", "login", "example.com"}); code != 1 {
				t.Fatalf("exit %d, want 1; stderr:\n%s", code, errb)
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Errorf("stderr missing %q:\n%s", tc.want, errb)
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", out)
			}
			if strings.Contains(errb.String(), "abc\ndef") {
				t.Error("the rejected token was echoed")
			}
		})
	}
}

func TestSep10ServerUnreachable(t *testing.T) {
	f := newSep10LoopbackFake(t)
	home := f.home
	f.srv.Close()
	app, _, errb := f.app("", walletEnv())
	if code := app.run([]string{"--network", "testnet", "sep10", "info", home}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "fetch http://"+home+"/.well-known/stellar.toml") {
		t.Errorf("stderr:\n%s", errb)
	}
}

// TestSep10ChallengeWithAccountNeedsNoSecret: with --account, no secret is
// read (stdin is empty and no env var is set) and nothing is signed.
func TestSep10ChallengeWithAccountNeedsNoSecret(t *testing.T) {
	f := newSep10Fake(t)
	app, out, errb := f.app("", nil)
	code := app.run([]string{"--network", "testnet", "sep10", "challenge", "--account", sep10WalletKP.Address(), "example.com"})
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	if _, _, posted, _ := f.snapshot(); len(posted) != 0 {
		t.Error("challenge POSTed something")
	}
	for _, want := range []string{
		"Envelope:     v1 transaction",
		"Source:       " + sep10ServerKP.Address() + " (server key)",
		"Sequence:     0",
		"Fee:          0.0000200 XLM",
		`  1. manage_data "example.com auth"`,
		"     Source: " + sep10WalletKP.Address() + " (this account)",
		`  2. manage_data "web_auth_domain"`,
		`     Value:  11 bytes "example.com"`,
		"Signatures (1):",
		"verified: " + sep10ServerKP.Address() + " (server key)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errb.String(), "Nothing was signed") {
		t.Errorf("stderr:\n%s", errb)
	}
}

func TestSep10ChallengeRefusesBadAccount(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	if code := app.run([]string{"sep10", "challenge", "--account", sep10WalletKP.Seed(), "example.com"}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if strings.Contains(errb.String(), sep10WalletKP.Seed()) {
		t.Error("the seed passed as --account was echoed")
	}
}

// --- golden files -----------------------------------------------------------

// sep10Placeholders replaces the per-run values of a fake-issued challenge
// (its nonce, time bounds and the envelope itself) so the rest of the output
// can be pinned byte for byte. It returns the values it replaced so the
// caller can still check them.
func sep10Placeholders(t *testing.T, got, issued string) string {
	t.Helper()
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(issued, &env); err != nil {
		t.Fatal(err)
	}
	tb := env.TimeBounds()
	if tb == nil || tb.MaxTime-tb.MinTime != 300 {
		t.Fatalf("time bounds %+v, want a 300 s window", tb)
	}
	nonce := base64.StdEncoding.EncodeToString(*env.Operations()[0].Body.ManageDataOp.DataValue)
	r := strings.NewReplacer(
		issued, "CHALLENGE_ENVELOPE",
		nonce, "NONCE_BASE64",
		`"min_time":`+strconv.FormatUint(uint64(tb.MinTime), 10), `"min_time":1111111111`,
		`"max_time":`+strconv.FormatUint(uint64(tb.MaxTime), 10), `"max_time":1111111411`,
	)
	return r.Replace(got)
}

func TestSep10InfoGoldenJSON(t *testing.T) {
	f := newSep10Fake(t)
	app, out, errb := f.app("", nil)
	if code := app.run([]string{"--network", "testnet", "sep10", "info", "--json", "example.com"}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	checkGolden(t, "sep10_info_json.golden", out.String())
	if errb.Len() != 0 {
		t.Errorf("stderr = %q, want nothing on the matching network", errb)
	}
}

func TestSep10InfoNetworkNotes(t *testing.T) {
	f := newSep10Fake(t)
	app, out, errb := f.app("", nil)
	if code := app.run([]string{"sep10", "info", "example.com"}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	for _, want := range []string{
		"WEB_AUTH_ENDPOINT:  https://example.com/auth",
		"SIGNING_KEY:        " + sep10ServerKP.Address(),
		`NETWORK_PASSPHRASE: "Test SDF Network ; September 2015"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errb.String(), "is not on the selected network (mainnet)") {
		t.Errorf("stderr:\n%s", errb)
	}
}

func TestSep10ChallengeGoldenJSON(t *testing.T) {
	f := newSep10Fake(t)
	app, out, errb := f.app("", walletEnv())
	if code := app.run([]string{"--network", "testnet", "sep10", "challenge", "--json", "example.com"}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	_, issued, _, _ := f.snapshot()
	checkGolden(t, "sep10_challenge_json.golden", sep10Placeholders(t, out.String(), issued[0]))
	var v jsonSep10Challenge
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Transaction != issued[0] {
		t.Error("transaction is not the envelope the server issued")
	}
}

func TestSep10LoginGoldenJSON(t *testing.T) {
	f := newSep10Fake(t)
	app, out, errb := f.app("", walletEnv())
	if code := app.run([]string{"--network", "testnet", "sep10", "login", "--json", "example.com"}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	checkGolden(t, "sep10_login_json.golden", out.String())
	_, _, _, tokens := f.snapshot()
	assertNoSecrets(t, out.String(), errb.String(), tokens[0])
}

// sep10FixturePath holds a challenge built by txnbuild.BuildChallengeTx
// with the fixed test keys (server key, wallet account, home domain and
// web_auth_domain example.com, testnet). It is long expired, which is the
// point: inspect decodes without judging, and a golden needs fixed bytes.
// `go test ./internal/cli -update` writes it only when it is missing.
const sep10FixturePath = "testdata/sep10_challenge.txt"

func sep10Fixture(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat(sep10FixturePath); os.IsNotExist(err) && *update {
		tx, err := txnbuild.BuildChallengeTx(sep10ServerKP.Seed(), sep10WalletKP.Address(), "example.com", "example.com", network.TestNetworkPassphrase, 5*time.Minute, nil)
		if err != nil {
			t.Fatal(err)
		}
		b64, err := tx.Base64()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(sep10FixturePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sep10FixturePath, []byte(b64+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(sep10FixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", sep10FixturePath, err)
	}
	return strings.TrimSpace(string(raw))
}

// TestSep10FixtureIsSDKBuilt is the honesty gate for the recorded fixture:
// it must have exactly the shape BuildChallengeTx produces today and carry a
// valid server signature, so the inspect goldens describe a real challenge.
func TestSep10FixtureIsSDKBuilt(t *testing.T) {
	fixture := sep10Fixture(t)
	fresh, err := txnbuild.BuildChallengeTx(sep10ServerKP.Seed(), sep10WalletKP.Address(), "example.com", "example.com", network.TestNetworkPassphrase, 5*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	freshB64, _ := fresh.Base64()
	var a, b xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(fixture, &a); err != nil {
		t.Fatal(err)
	}
	if err := xdr.SafeUnmarshalBase64(freshB64, &b); err != nil {
		t.Fatal(err)
	}
	shape := func(e xdr.TransactionEnvelope) string {
		var s strings.Builder
		src := e.SourceAccount()
		tb := e.TimeBounds()
		fmt.Fprintf(&s, "%v %s seq=%d fee=%d window=%d memo=%v sigs=%d", e.Type, src.Address(), e.SeqNum(), e.Fee(), tb.MaxTime-tb.MinTime, e.Memo().Type, len(e.Signatures()))
		for _, op := range e.Operations() {
			md := op.Body.MustManageDataOp()
			fmt.Fprintf(&s, " [%s %q %d]", op.SourceAccount.Address(), md.DataName, len(*md.DataValue))
		}
		return s.String()
	}
	if shape(a) != shape(b) {
		t.Errorf("fixture shape differs from BuildChallengeTx:\nfixture: %s\nfresh:   %s", shape(a), shape(b))
	}
	hash, _ := network.HashTransactionInEnvelope(a, network.TestNetworkPassphrase)
	if err := keypair.MustParseAddress(sep10ServerKP.Address()).Verify(hash[:], a.Signatures()[0].Signature); err != nil {
		t.Errorf("fixture server signature: %v", err)
	}
}

func TestSep10InspectGolden(t *testing.T) {
	fixture := sep10Fixture(t)
	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"sep10_inspect_text.golden", []string{"sep10", "inspect", fixture}},
		{"sep10_inspect_json.golden", []string{"sep10", "inspect", "--json", fixture}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			app, out, errb := newTestApp("", nil)
			if code := app.run(tc.args); code != 0 {
				t.Fatalf("exit %d, stderr:\n%s", code, errb)
			}
			checkGolden(t, tc.golden, out.String())
			if !strings.Contains(errb.String(), "nothing was checked") {
				t.Errorf("stderr:\n%s", errb)
			}
		})
	}
}

// TestSep10InspectVerify checks a fresh challenge offline, given as the raw
// JSON response of the challenge endpoint on stdin (as piped from curl).
func TestSep10InspectVerify(t *testing.T) {
	tx, err := txnbuild.BuildChallengeTx(sep10ServerKP.Seed(), sep10WalletKP.Address(), "example.com", "example.com", network.TestNetworkPassphrase, 5*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	b64, _ := tx.Base64()
	resp := fmt.Sprintf(`{"transaction":%q,"network_passphrase":%q}`, b64, network.TestNetworkPassphrase)
	verifyArgs := []string{"--network", "testnet", "sep10", "inspect", "--json", "--server-key", sep10ServerKP.Address(), "--home-domain", "example.com"}

	t.Run("passes", func(t *testing.T) {
		app, out, errb := newTestApp(resp, nil)
		if code := app.run(append(verifyArgs, "--account", sep10WalletKP.Address())); code != 0 {
			t.Fatalf("exit %d, stderr:\n%s", code, errb)
		}
		var v struct {
			Verified   *bool  `json:"verified"`
			Refusal    string `json:"refusal"`
			Signatures []jsonSignature
		}
		if err := json.Unmarshal(out.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if v.Verified == nil || !*v.Verified || v.Refusal != "" {
			t.Errorf("verified=%v refusal=%q", v.Verified, v.Refusal)
		}
		if len(v.Signatures) != 1 || v.Signatures[0].Signer != sep10ServerKP.Address() {
			t.Errorf("signatures = %+v", v.Signatures)
		}
		if !strings.Contains(errb.String(), "Every client check passed.") {
			t.Errorf("stderr:\n%s", errb)
		}
	})
	t.Run("without --account says what it skipped", func(t *testing.T) {
		app, _, errb := newTestApp(b64, nil)
		if code := app.run(verifyArgs); code != 0 {
			t.Fatalf("exit %d, stderr:\n%s", code, errb)
		}
		if !strings.Contains(errb.String(), "except the first operation's source") {
			t.Errorf("stderr:\n%s", errb)
		}
	})
	refusals := []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"wrong server key", b64, []string{"--network", "testnet", "sep10", "inspect", "--json", "--server-key", sep10OtherKP.Address(), "--home-domain", "example.com"}, "not equal to server's account"},
		{"wrong account", b64, append(append([]string{}, verifyArgs...), "--account", sep10OtherKP.Address()), "not this wallet's account"},
		{"wrong network", b64, []string{"--network", "mainnet", "sep10", "inspect", "--json", "--server-key", sep10ServerKP.Address(), "--home-domain", "example.com"}, "under the selected network's passphrase"},
		{"response names another network", strings.Replace(resp, network.TestNetworkPassphrase, network.PublicNetworkPassphrase, 1), verifyArgs, "the response says it is for the network"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			app, out, errb := newTestApp(tc.stdin, nil)
			if code := app.run(tc.args); code != 1 {
				t.Fatalf("exit %d, want 1; stderr:\n%s", code, errb)
			}
			var v jsonSep10Inspect
			if err := json.Unmarshal(out.Bytes(), &v); err != nil {
				t.Fatalf("stdout is not the JSON object: %v\n%s", err, out)
			}
			if v.Verified == nil || *v.Verified || !strings.Contains(v.Refusal, tc.want) {
				t.Errorf("verified=%v refusal=%q, want a refusal containing %q", v.Verified, v.Refusal, tc.want)
			}
		})
	}
}

func TestSep10InspectUsage(t *testing.T) {
	fixture := sep10Fixture(t)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"sep10", "inspect", "--server-key", sep10ServerKP.Address(), fixture}, "needs both --server-key and --home-domain"},
		{[]string{"sep10", "inspect", "--account", sep10WalletKP.Address(), fixture}, "apply only when verifying"},
		{[]string{"sep10", "inspect", "--server-key", "GBAD", "--home-domain", "example.com", fixture}, "--server-key"},
		{[]string{"sep10", "inspect", "--server-key", sep10ServerKP.Address(), "--home-domain", "https://example.com", fixture}, "not a URL"},
		{[]string{"sep10", "inspect", "not-base64!"}, "not a base64 transaction envelope"},
		{[]string{"sep10", "inspect", `{"foo":1}`}, `no "transaction" field`},
		{[]string{"sep10", "inspect"}, "no challenge envelope given"},
		{[]string{"sep10", "frob"}, "unknown sep10 subcommand"},
		{[]string{"sep10"}, "requires a subcommand"},
		{[]string{"sep10", "login"}, "usage: lumencli sep10 login"},
		{[]string{"sep10", "info", "https://example.com"}, "not a URL"},
	}
	for _, tc := range cases {
		app, _, errb := newTestApp("", nil)
		if code := app.run(tc.args); code != 1 {
			t.Errorf("%v: exit %d, want 1", tc.args, code)
		}
		if !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: stderr missing %q:\n%s", tc.args, tc.want, errb)
		}
	}
}
