package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/amount"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"golang.org/x/term"

	"lumencli/internal/netcfg"
	"lumencli/internal/sep10"
	"lumencli/internal/wallet"
)

// The sep10 command group is the client side of SEP-10 (Stellar Web
// Authentication): the wallet's key proves control of its account to a
// SEP-10 server — an anchor — by signing a challenge transaction the server
// built, and receives the server's token in return. A challenge is a real
// Stellar transaction, which is why this lives next to send: every client
// check runs before anything is signed, and a challenge failing any one of
// them is refused. Nothing here touches Horizon or moves funds.

func (a *App) runSep10(opts netcfg.Options, args []string) int {
	if len(args) == 0 {
		return a.fail("sep10 requires a subcommand: info | challenge | inspect | login")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "info":
		return a.sep10Info(opts, rest)
	case "challenge":
		return a.sep10Challenge(opts, rest)
	case "inspect":
		return a.sep10Inspect(opts, rest)
	case "login":
		return a.sep10Login(opts, rest)
	default:
		return a.fail("unknown sep10 subcommand %q (want: info | challenge | inspect | login)", sub)
	}
}

func (a *App) sep10Client() *sep10.Client {
	return &sep10.Client{HTTP: a.sep10HTTP, UserAgent: "lumencli/" + version}
}

// announceSep10 names the network a SEP-10 exchange is checked against. The
// passphrase is what matters here (the server's signature is verified under
// it); Horizon is not contacted.
func (a *App) announceSep10(net netcfg.Network) {
	fmt.Fprintf(a.err, "Network: %s (passphrase %q)\n", net.Name, net.Passphrase)
}

// sep10Info prints what SEP-10 needs from a server's stellar.toml.
func (a *App) sep10Info(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("sep10 info")
	bindNetworkFlags(fs, &opts)
	jsonOut := fs.Bool("json", false, "write a single JSON object instead of the human form")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.fail("usage: lumencli sep10 info [flags] <home-domain>")
	}
	net, err := a.resolveNetwork(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	srv, err := a.sep10Client().Discover(context.Background(), rest[0])
	if err != nil {
		return a.fail("%v", err)
	}

	if *jsonOut {
		out := jsonSep10Info{
			HomeDomain:        srv.HomeDomain,
			TOMLURL:           srv.TOMLURL,
			WebAuthEndpoint:   srv.TOML.WebAuthEndpoint,
			WebAuthDomain:     srv.WebAuthDomain,
			SigningKey:        srv.TOML.SigningKey,
			NetworkPassphrase: srv.TOML.NetworkPassphrase,
		}
		if err := newJSONEncoder(a.out).Encode(out); err != nil {
			return a.fail("write json: %v", err)
		}
	} else {
		passphrase := "(not declared)"
		if srv.TOML.NetworkPassphrase != "" {
			passphrase = strconv.Quote(srv.TOML.NetworkPassphrase)
		}
		fmt.Fprintf(a.out, "Home domain:        %s\n", srv.HomeDomain)
		fmt.Fprintf(a.out, "stellar.toml:       %s\n", srv.TOMLURL)
		fmt.Fprintf(a.out, "WEB_AUTH_ENDPOINT:  %s\n", sep10.Printable(srv.TOML.WebAuthEndpoint))
		fmt.Fprintf(a.out, "SIGNING_KEY:        %s\n", srv.TOML.SigningKey)
		fmt.Fprintf(a.out, "NETWORK_PASSPHRASE: %s\n", passphrase)
		fmt.Fprintf(a.out, "Web auth domain:    %s\n", sep10.Printable(srv.WebAuthDomain))
	}

	switch {
	case srv.TOML.NetworkPassphrase == "":
		fmt.Fprintf(a.err, "Note: %s does not declare its network; a challenge is still checked against the selected one (%s).\n", srv.HomeDomain, net.Name)
	case srv.CheckNetwork(net.Passphrase) != nil:
		fmt.Fprintf(a.err, "Note: %s is not on the selected network (%s): sep10 challenge and login would refuse it. Select the matching --network.\n", srv.HomeDomain, net.Name)
	}
	return 0
}

// sep10Discover is the shared front half of challenge and login: resolve the
// network, fetch and validate the stellar.toml, refuse a server on another
// network, and print what the exchange is about to involve.
func (a *App) sep10Discover(opts netcfg.Options, homeDomain string) (netcfg.Network, *sep10.Server, error) {
	net, err := a.resolveNetwork(opts)
	if err != nil {
		return netcfg.Network{}, nil, err
	}
	a.announceSep10(net)
	srv, err := a.sep10Client().Discover(context.Background(), homeDomain)
	if err != nil {
		return netcfg.Network{}, nil, err
	}
	if err := srv.CheckNetwork(net.Passphrase); err != nil {
		return netcfg.Network{}, nil, err
	}
	fmt.Fprintf(a.err, "Home domain: %s\n", srv.HomeDomain)
	fmt.Fprintf(a.err, "Endpoint:    %s\n", sep10.Printable(srv.Endpoint.String()))
	fmt.Fprintf(a.err, "Server key:  %s\n", srv.TOML.SigningKey)
	return net, srv, nil
}

// sep10Fetch requests a challenge for account and runs every client check.
// It returns the envelope as received and its parsed form, ready to sign.
func (a *App) sep10Fetch(net netcfg.Network, srv *sep10.Server, account string) (string, *txnbuild.Transaction, error) {
	resp, err := a.sep10Client().Challenge(context.Background(), srv, account)
	if err != nil {
		return "", nil, err
	}
	if resp.NetworkPassphrase != "" && resp.NetworkPassphrase != net.Passphrase {
		return "", nil, fmt.Errorf("challenge refused: the server says it is for the network %q, not the selected one (%q)",
			sep10.Printable(resp.NetworkPassphrase), net.Passphrase)
	}
	tx, err := sep10.Verify(resp.Transaction, a.sep10Expect(net, srv, account))
	if err != nil {
		return "", nil, err
	}
	return strings.TrimSpace(resp.Transaction), tx, nil
}

func (a *App) sep10Expect(net netcfg.Network, srv *sep10.Server, account string) sep10.Expect {
	return sep10.Expect{
		ServerKey:     srv.TOML.SigningKey,
		HomeDomain:    srv.HomeDomain,
		WebAuthDomain: srv.WebAuthDomain,
		Passphrase:    net.Passphrase,
		Account:       account,
	}
}

// sep10Challenge fetches and checks a challenge without signing it.
func (a *App) sep10Challenge(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("sep10 challenge")
	bindNetworkFlags(fs, &opts)
	acct := fs.String("account", "", "account (G...) to request the challenge for; if omitted, derived from your secret seed")
	jsonOut := fs.Bool("json", false, "write a single JSON object instead of the human form")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.fail("usage: lumencli sep10 challenge [flags] <home-domain>")
	}
	account := strings.TrimSpace(*acct)
	if account != "" {
		if err := wallet.ValidateAddress(account); err != nil {
			return a.fail("%v", err)
		}
	}

	net, srv, err := a.sep10Discover(opts, rest[0])
	if err != nil {
		return a.fail("%v", err)
	}
	if account == "" {
		secret, err := a.readSecret("Enter your secret seed to derive your address (S...): ")
		if err != nil {
			return a.fail("%v", err)
		}
		if account, err = wallet.AddressFromSecret(secret); err != nil {
			return a.fail("%v", err)
		}
	}
	fmt.Fprintf(a.err, "Account:     %s\n", account)

	envelope, _, err := a.sep10Fetch(net, srv, account)
	if err != nil {
		return a.fail("%v", err)
	}
	d, err := sep10.Decode(envelope)
	if err != nil {
		return a.fail("%v", err)
	}
	if err := d.MatchSigners(net.Passphrase, srv.TOML.SigningKey, account); err != nil {
		return a.fail("%v", err)
	}

	if *jsonOut {
		out := jsonSep10Challenge{
			Network:           net.Name,
			NetworkPassphrase: net.Passphrase,
			HomeDomain:        srv.HomeDomain,
			WebAuthEndpoint:   srv.Endpoint.String(),
			WebAuthDomain:     srv.WebAuthDomain,
			ServerKey:         srv.TOML.SigningKey,
			Account:           account,
			Transaction:       envelope,
			Challenge:         toJSONChallenge(d),
		}
		if err := newJSONEncoder(a.out).Encode(out); err != nil {
			return a.fail("write json: %v", err)
		}
	} else {
		renderChallenge(a.out, d, sep10Labels(srv.TOML.SigningKey, account))
	}
	fmt.Fprintln(a.err, "Every client check passed. Nothing was signed.")
	return 0
}

// sep10Login runs the whole exchange and prints the server's token.
func (a *App) sep10Login(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("sep10 login")
	bindNetworkFlags(fs, &opts)
	jsonOut := fs.Bool("json", false, "write a single JSON object (token included) instead of the bare token")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.fail("usage: lumencli sep10 login [flags] <home-domain>")
	}

	net, srv, err := a.sep10Discover(opts, rest[0])
	if err != nil {
		return a.fail("%v", err)
	}
	secret, err := a.readSecret("Enter your secret seed (S...): ")
	if err != nil {
		return a.fail("%v", err)
	}
	kp, err := wallet.ParseSecret(secret)
	if err != nil {
		return a.fail("%v", err)
	}
	account := kp.Address()
	fmt.Fprintf(a.err, "Account:     %s\n", account)

	// Only a challenge that passed every client check reaches Sign.
	_, tx, err := a.sep10Fetch(net, srv, account)
	if err != nil {
		return a.fail("%v", err)
	}
	signed, err := sep10.Sign(tx, net.Passphrase, kp)
	if err != nil {
		return a.fail("%v", err)
	}
	token, err := a.sep10Client().Token(context.Background(), srv, signed)
	if err != nil {
		return a.fail("%v", err)
	}

	claims, isJWT := sep10.ParseClaims(token)
	if *jsonOut {
		out := jsonSep10Login{
			Network:           net.Name,
			NetworkPassphrase: net.Passphrase,
			HomeDomain:        srv.HomeDomain,
			WebAuthEndpoint:   srv.Endpoint.String(),
			ServerKey:         srv.TOML.SigningKey,
			Account:           account,
			Token:             token,
		}
		if isJWT {
			out.Claims = &jsonSep10Claims{Issuer: claims.Issuer, Subject: claims.Subject, IssuedAt: claims.IssuedAt, Expires: claims.Expires}
		}
		if err := newJSONEncoder(a.out).Encode(out); err != nil {
			return a.fail("write json: %v", err)
		}
	} else {
		fmt.Fprintln(a.out, token)
	}

	fmt.Fprintln(a.err, "Every client check passed; signed the challenge and received a token (written to stdout).")
	a.describeClaims(claims, isJWT, account)
	return 0
}

// describeClaims shows the token's standard claims on stderr — never the
// token itself — and says plainly that they are unverified.
func (a *App) describeClaims(c sep10.Claims, isJWT bool, account string) {
	if !isJWT {
		fmt.Fprintln(a.err, "The token is not a JWT; it is printed exactly as received.")
		return
	}
	fmt.Fprintln(a.err, "Token claims, decoded for display only (a client cannot verify the token's signature; these are the server's own statements):")
	show := func(name, v string) {
		if v == "" {
			v = "(absent)"
		}
		fmt.Fprintf(a.err, "  %s: %s\n", name, v)
	}
	show("iss", sep10.Printable(c.Issuer))
	show("sub", sep10.Printable(c.Subject))
	show("iat", claimTime(c.IssuedAt, false))
	show("exp", claimTime(c.Expires, true))
	if c.Subject != "" && c.Subject != account && !strings.HasPrefix(c.Subject, account+":") {
		fmt.Fprintf(a.err, "Note: the token's sub is not this account (%s).\n", account)
	}
}

func claimTime(v *int64, expiry bool) string {
	if v == nil {
		return ""
	}
	t := time.Unix(*v, 0).UTC()
	s := t.Format("2006-01-02 15:04:05") + " UTC"
	if expiry {
		if d := time.Until(t); d > 0 {
			s += fmt.Sprintf(" (in %s)", d.Round(time.Second))
		} else {
			s += " (already expired)"
		}
	}
	return s
}

// sep10Inspect decodes a challenge offline and, given the server key and home
// domain, runs the client checks on it.
func (a *App) sep10Inspect(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("sep10 inspect")
	bindNetworkFlags(fs, &opts)
	serverKey := fs.String("server-key", "", "verify: the server's SIGNING_KEY (G...)")
	homeDomain := fs.String("home-domain", "", "verify: the home domain the challenge must name")
	webAuthDomain := fs.String("web-auth-domain", "", "verify: the web_auth_domain value (default: the home domain)")
	acct := fs.String("account", "", "verify: the account (G...) that must source the first operation")
	jsonOut := fs.Bool("json", false, "write a single JSON object instead of the human form")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 1 {
		return a.fail("usage: lumencli sep10 inspect [flags] [<base64 envelope>]  (or the envelope on stdin)")
	}
	key, home := strings.TrimSpace(*serverKey), strings.TrimSpace(*homeDomain)
	wad, account := strings.TrimSpace(*webAuthDomain), strings.TrimSpace(*acct)
	verify := key != "" || home != ""
	if verify && (key == "" || home == "") {
		return a.fail("verifying needs both --server-key and --home-domain")
	}
	if !verify && (wad != "" || account != "") {
		return a.fail("--web-auth-domain and --account apply only when verifying (with --server-key and --home-domain)")
	}
	if verify {
		if err := wallet.ValidateAddress(key); err != nil {
			return a.fail("--server-key: %v", err)
		}
		if err := sep10.ValidateHomeDomain(home); err != nil {
			return a.fail("--home-domain: %v", err)
		}
		if account != "" {
			if err := wallet.ValidateAddress(account); err != nil {
				return a.fail("--account: %v", err)
			}
		}
		if wad == "" {
			wad = home
		}
	}

	var input string
	if len(rest) == 1 {
		input = rest[0]
	} else {
		if f, ok := a.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			return a.fail("usage: lumencli sep10 inspect [flags] [<base64 envelope>]  (or pipe the envelope on stdin)")
		}
		b, err := io.ReadAll(io.LimitReader(a.lineReader(), 256*1024))
		if err != nil {
			return a.fail("read stdin: %v", err)
		}
		input = string(b)
	}
	envelope, respPassphrase, err := parseInspectInput(input)
	if err != nil {
		return a.fail("%v", err)
	}

	d, err := sep10.Decode(envelope)
	if err != nil {
		return a.fail("%v", err)
	}

	var refusal error
	if verify {
		net, err := a.resolveNetwork(opts)
		if err != nil {
			return a.fail("%v", err)
		}
		a.announceSep10(net)
		if respPassphrase != "" && respPassphrase != net.Passphrase {
			refusal = fmt.Errorf("challenge refused: the response says it is for the network %q, not the selected one (%q)",
				sep10.Printable(respPassphrase), net.Passphrase)
		} else {
			_, refusal = sep10.Verify(envelope, sep10.Expect{
				ServerKey: key, HomeDomain: home, WebAuthDomain: wad,
				Passphrase: net.Passphrase, Account: account,
			})
		}
		candidates := []string{key}
		if account != "" {
			candidates = append(candidates, account)
		}
		if err := d.MatchSigners(net.Passphrase, candidates...); err != nil {
			return a.fail("%v", err)
		}
	}

	if *jsonOut {
		out := jsonSep10Inspect{jsonChallenge: toJSONChallenge(d)}
		if verify {
			ok := refusal == nil
			out.Verified = &ok
			if refusal != nil {
				out.Refusal = refusal.Error()
			}
		}
		if err := newJSONEncoder(a.out).Encode(out); err != nil {
			return a.fail("write json: %v", err)
		}
	} else {
		var labels map[string]string
		if verify {
			labels = sep10Labels(key, account)
		}
		renderChallenge(a.out, d, labels)
	}

	switch {
	case !verify:
		fmt.Fprintln(a.err, "Decoded only; nothing was checked. Pass --server-key and --home-domain to run the client checks.")
	case refusal != nil:
		return a.fail("%v", refusal)
	case account == "":
		fmt.Fprintln(a.err, "Every client check passed, except the first operation's source: give --account to check it too.")
	default:
		fmt.Fprintln(a.err, "Every client check passed.")
	}
	return 0
}

// parseInspectInput accepts a bare base64 envelope or the challenge
// endpoint's JSON response ({"transaction": ..., "network_passphrase": ...}),
// so `curl .../auth?account=G... | lumencli sep10 inspect` works directly.
func parseInspectInput(input string) (envelope, passphrase string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", fmt.Errorf("no challenge envelope given (pass it as an argument or on stdin)")
	}
	if !strings.HasPrefix(input, "{") {
		return input, "", nil
	}
	var resp sep10.ChallengeResponse
	if err := json.Unmarshal([]byte(input), &resp); err != nil {
		return "", "", fmt.Errorf("input looks like JSON but is not a challenge response: %v", err)
	}
	if resp.Transaction == "" {
		return "", "", fmt.Errorf("the JSON input has no \"transaction\" field")
	}
	return resp.Transaction, resp.NetworkPassphrase, nil
}

// sep10Labels names the keys a challenge is expected to involve, for display.
func sep10Labels(serverKey, account string) map[string]string {
	m := map[string]string{serverKey: "server key"}
	if account != "" && account != serverKey {
		m[account] = "this account"
	}
	return m
}

// renderChallenge prints a decoded challenge in the human form. Identifiers
// are printed in full; names and values that came from the server are quoted
// so that no control character reaches the terminal.
func renderChallenge(w io.Writer, d *sep10.Decoded, labels map[string]string) {
	label := func(addr string) string {
		if l, ok := labels[addr]; ok {
			return addr + " (" + l + ")"
		}
		return addr
	}
	fmt.Fprintf(w, "Envelope:     %s transaction\n", d.Envelope)
	fmt.Fprintf(w, "Source:       %s\n", label(d.Source))
	fmt.Fprintf(w, "Sequence:     %d\n", d.Sequence)
	fmt.Fprintf(w, "Fee:          %s XLM\n", amount.StringFromInt64(int64(d.Fee)))
	if d.TimeBounds == nil {
		fmt.Fprintln(w, "Time bounds:  none")
	} else {
		fmt.Fprintf(w, "Valid from:   %s\n", boundTime(d.TimeBounds.MinTime))
		fmt.Fprintf(w, "Valid until:  %s\n", boundTime(d.TimeBounds.MaxTime))
	}
	if d.Memo == nil {
		fmt.Fprintln(w, "Memo:         none")
	} else if d.Memo.Type == "text" {
		fmt.Fprintf(w, "Memo:         text %s\n", strconv.Quote(d.Memo.Value))
	} else {
		fmt.Fprintf(w, "Memo:         %s %s\n", d.Memo.Type, d.Memo.Value)
	}
	fmt.Fprintf(w, "Operations (%d):\n", len(d.Operations))
	for i, op := range d.Operations {
		if op.IsManageData {
			fmt.Fprintf(w, "  %d. %s %s\n", i+1, op.Type, strconv.Quote(op.Name))
		} else {
			fmt.Fprintf(w, "  %d. %s\n", i+1, op.Type)
		}
		if op.Source == "" {
			fmt.Fprintln(w, "     Source: (none: the transaction source)")
		} else {
			fmt.Fprintf(w, "     Source: %s\n", label(op.Source))
		}
		if op.IsManageData {
			switch {
			case !op.HasValue:
				fmt.Fprintln(w, "     Value:  none (deletes the entry)")
			case printableASCII(op.Value):
				fmt.Fprintf(w, "     Value:  %d bytes %s\n", len(op.Value), strconv.Quote(string(op.Value)))
			default:
				fmt.Fprintf(w, "     Value:  %d bytes (binary)\n", len(op.Value))
			}
		}
	}
	fmt.Fprintf(w, "Signatures (%d):\n", len(d.Signatures))
	for i, s := range d.Signatures {
		if s.Signer != "" {
			fmt.Fprintf(w, "  %d. hint %s, verified: %s\n", i+1, s.Hint, label(s.Signer))
		} else {
			fmt.Fprintf(w, "  %d. hint %s\n", i+1, s.Hint)
		}
	}
}

func boundTime(v uint64) string {
	if v == 0 {
		return "unbounded"
	}
	if v > 1<<62 {
		return strconv.FormatUint(v, 10) + " (unix)"
	}
	return time.Unix(int64(v), 0).UTC().Format("2006-01-02 15:04:05") + " UTC (unix " + strconv.FormatUint(v, 10) + ")"
}

func printableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// The sep10 --json objects. Like every machine-readable output of this tool
// they are append-only contracts: fields are never renamed, retyped or
// reordered. Their bytes are pinned by golden files.

type jsonSep10Info struct {
	HomeDomain        string `json:"home_domain"`
	TOMLURL           string `json:"toml_url"`
	WebAuthEndpoint   string `json:"web_auth_endpoint"`
	WebAuthDomain     string `json:"web_auth_domain"`
	SigningKey        string `json:"signing_key"`
	NetworkPassphrase string `json:"network_passphrase,omitempty"`
}

// jsonChallenge is a decoded challenge. sequence is a decimal string (an
// int64); fee is a 7-decimal XLM string like every amount this tool emits;
// time bounds are unix seconds, 0 meaning unbounded, as on the wire.
type jsonChallenge struct {
	EnvelopeType  string            `json:"envelope_type"`
	SourceAccount string            `json:"source_account"`
	Sequence      string            `json:"sequence"`
	Fee           string            `json:"fee"`
	TimeBounds    *jsonTimeBounds   `json:"time_bounds,omitempty"`
	Memo          *jsonMemo         `json:"memo,omitempty"`
	Operations    []jsonChallengeOp `json:"operations"`
	Signatures    []jsonSignature   `json:"signatures"`
}

type jsonTimeBounds struct {
	MinTime uint64 `json:"min_time"`
	MaxTime uint64 `json:"max_time"`
}

// jsonChallengeOp: name, value_length and value are present for manage_data
// (value_length and value only when the operation carries a value); value
// is the raw bytes, base64.
type jsonChallengeOp struct {
	Type          string  `json:"type"`
	SourceAccount string  `json:"source_account,omitempty"`
	Name          *string `json:"name,omitempty"`
	ValueLength   *int    `json:"value_length,omitempty"`
	Value         *string `json:"value,omitempty"`
}

// jsonSignature: signer is present only when a known key (the server key,
// or the account) verifies the signature under the selected network.
type jsonSignature struct {
	Hint   string `json:"hint"`
	Signer string `json:"signer,omitempty"`
}

type jsonSep10Inspect struct {
	jsonChallenge
	Verified *bool  `json:"verified,omitempty"` // present only when checks were requested
	Refusal  string `json:"refusal,omitempty"`  // human text, not a stable code
}

type jsonSep10Challenge struct {
	Network           string        `json:"network"`
	NetworkPassphrase string        `json:"network_passphrase"`
	HomeDomain        string        `json:"home_domain"`
	WebAuthEndpoint   string        `json:"web_auth_endpoint"`
	WebAuthDomain     string        `json:"web_auth_domain"`
	ServerKey         string        `json:"server_key"`
	Account           string        `json:"account"`
	Transaction       string        `json:"transaction"`
	Challenge         jsonChallenge `json:"challenge"`
}

type jsonSep10Login struct {
	Network           string           `json:"network"`
	NetworkPassphrase string           `json:"network_passphrase"`
	HomeDomain        string           `json:"home_domain"`
	WebAuthEndpoint   string           `json:"web_auth_endpoint"`
	ServerKey         string           `json:"server_key"`
	Account           string           `json:"account"`
	Token             string           `json:"token"`
	Claims            *jsonSep10Claims `json:"claims,omitempty"`
}

// jsonSep10Claims are unverified, display-only claims (see sep10.Claims).
type jsonSep10Claims struct {
	Issuer   string `json:"iss,omitempty"`
	Subject  string `json:"sub,omitempty"`
	IssuedAt *int64 `json:"iat,omitempty"`
	Expires  *int64 `json:"exp,omitempty"`
}

func toJSONChallenge(d *sep10.Decoded) jsonChallenge {
	out := jsonChallenge{
		EnvelopeType:  d.Envelope,
		SourceAccount: d.Source,
		Sequence:      strconv.FormatInt(d.Sequence, 10),
		Fee:           amount.StringFromInt64(int64(d.Fee)),
		Operations:    []jsonChallengeOp{},
		Signatures:    []jsonSignature{},
	}
	if d.TimeBounds != nil {
		out.TimeBounds = &jsonTimeBounds{MinTime: d.TimeBounds.MinTime, MaxTime: d.TimeBounds.MaxTime}
	}
	if d.Memo != nil {
		out.Memo = &jsonMemo{Type: d.Memo.Type, Value: d.Memo.Value}
	}
	for _, op := range d.Operations {
		j := jsonChallengeOp{Type: op.Type, SourceAccount: op.Source}
		if op.IsManageData {
			name := op.Name
			j.Name = &name
			if op.HasValue {
				n := len(op.Value)
				v := base64.StdEncoding.EncodeToString(op.Value)
				j.ValueLength, j.Value = &n, &v
			}
		}
		out.Operations = append(out.Operations, j)
	}
	for _, s := range d.Signatures {
		out.Signatures = append(out.Signatures, jsonSignature{Hint: s.Hint, Signer: s.Signer})
	}
	return out
}
