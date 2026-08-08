package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"impalactl/internal/bridge"
)

var syncSubcommands = []string{
	"force <G...>        Force a sync + Soroban RPC reconcile for a Stellar account (admin)",
	"profile <id>        Force a directory profile re-pull for a Payala account (admin)",
	"payala              Ingest a batch of offline Payala transactions",
	"mode <id>           Switch an account between reserve and mirror sync (admin)",
}

// validSyncModes mirrors VALID_SYNC_MODES in the bridge.
var validSyncModes = []string{"reserve", "mirror"}

func (a *App) runSync(opts options, args []string) int {
	if len(args) == 0 {
		a.subUsage(a.err, "sync", syncSubcommands)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		a.subUsage(a.out, "sync", syncSubcommands)
		return 0
	case "force":
		return a.runSyncForce(opts, rest)
	case "profile":
		return a.runSyncProfile(opts, rest)
	case "payala":
		return a.runSyncPayala(opts, rest)
	case "mode":
		return a.runSyncMode(opts, rest)
	default:
		fmt.Fprintf(a.err, "error: unknown subcommand %q\n\n", sub)
		a.subUsage(a.err, "sync", syncSubcommands)
		return 2
	}
}

// runSyncForce records a sync timestamp and reconciles the account against
// Soroban RPC (POST /sync, admin only).
func (a *App) runSyncForce(opts options, args []string) int {
	fs := a.newFlagSet("sync force")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.usageErr("sync force requires one Stellar account id (G...)")
	}
	// The endpoint names the field account_id but validates it as a Stellar
	// address; catching that here beats a 400 round trip.
	if err := validateStellarAccountID(rest[0]); err != nil {
		return a.fail("%v (sync force takes the Stellar address, not the Payala account id)", err)
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.ForceSync(context.Background(), rest[0])
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"Stellar account:", rest[0]},
			{"Sync timestamp:", res.Timestamp},
		})
	})
}

// runSyncProfile forces a directory re-pull of an account's profile
// (POST /admin/accounts/{id}/sync-profile, admin only).
func (a *App) runSyncProfile(opts options, args []string) int {
	fs := a.newFlagSet("sync profile")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.usageErr("sync profile requires one Payala account id")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.SyncProfile(context.Background(), rest[0])
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		rows := [][2]string{
			{"Account:", rest[0]},
			{"Profile source:", res.ProfileSource},
			{"Synced at:", str(res.ProfileSyncedAt)},
		}
		if p := res.Profile; p != nil {
			rows = append(rows,
				[2]string{"First name:", str(p.FirstName)},
				[2]string{"Middle name:", str(p.MiddleName)},
				[2]string{"Last name:", str(p.LastName)},
				[2]string{"Affiliation:", str(p.Affiliation)},
			)
		}
		kv(w, rows)
	})
}

// runSyncPayala ingests a batch of offline Payala transactions
// (POST /sync/payala, owner only).
func (a *App) runSyncPayala(opts options, args []string) int {
	fs := a.newFlagSet("sync payala")
	bindGlobalFlags(fs, &opts)
	account := fs.String("account", "", "Payala account id (defaults to the logged-in account)")
	file := fs.String("file", "", `batch JSON file, or "-" for stdin (required)`)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("sync payala takes no positional arguments; pass the batch with --file")
	}
	if strings.TrimSpace(*file) == "" {
		return a.usageErr("sync payala requires --file <path> (or --file - to read stdin)")
	}

	data, err := a.readBatchFile(*file)
	if err != nil {
		return a.fail("%v", err)
	}
	req, err := parseSyncBatch(data, strings.TrimSpace(*account), a.currentAccountID(opts))
	if err != nil {
		return a.fail("%v", err)
	}
	if req.AccountID == "" {
		return a.usageErr("sync payala requires --account (or an account_id field in the batch file)")
	}
	if len(req.Transactions) == 0 {
		return a.fail("batch contains no transactions")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.SyncPayala(context.Background(), req)
	if err != nil {
		return a.fail("%v", err)
	}

	// A conflicting replay is a ledger-integrity signal, not routine
	// idempotency — surface it even when stdout is being piped or parsed.
	if res.Conflicting > 0 {
		fmt.Fprintf(a.err,
			"warning: %d replayed transaction id(s) arrived with a different amount or currency than the stored one\n",
			res.Conflicting)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"Batch:", res.BatchID},
			{"Account:", req.AccountID},
			{"Sync mode:", res.SyncMode},
			{"Received:", fmt.Sprint(res.Received)},
			{"Applied:", fmt.Sprint(res.Applied)},
			{"Duplicates:", fmt.Sprint(res.Duplicates)},
			{"Conflicting:", fmt.Sprint(res.Conflicting)},
		})
		if len(res.NetDeltas) > 0 {
			fmt.Fprintln(w, "\nNet deltas (minor units):")
			currencies := make([]string, 0, len(res.NetDeltas))
			for currency := range res.NetDeltas {
				currencies = append(currencies, currency)
			}
			sort.Strings(currencies)
			rows := make([][]string, 0, len(currencies))
			for _, currency := range currencies {
				rows = append(rows, []string{currency, fmt.Sprint(res.NetDeltas[currency])})
			}
			table(w, []string{"CURRENCY", "DELTA"}, rows)
		}
		if len(res.ReserveBalances) > 0 {
			fmt.Fprintln(w, "\nReserve balances (minor units):")
			rows := make([][]string, 0, len(res.ReserveBalances))
			for _, b := range res.ReserveBalances {
				rows = append(rows, []string{b.Currency, fmt.Sprint(b.Balance), str(b.UpdatedAt)})
			}
			table(w, []string{"CURRENCY", "BALANCE", "UPDATED"}, rows)
		}
	})
}

// runSyncMode switches an account between reserve and mirror sync
// (PUT /admin/accounts/{id}/sync-mode, admin only).
func (a *App) runSyncMode(opts options, args []string) int {
	fs := a.newFlagSet("sync mode")
	bindGlobalFlags(fs, &opts)
	mode := fs.String("mode", "", "new sync mode: "+strings.Join(validSyncModes, " | "))
	force := fs.Bool("force", false, "leave reserve mode even with a nonzero reserve balance")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.usageErr("sync mode requires one Payala account id")
	}
	newMode := strings.TrimSpace(*mode)
	if newMode == "" {
		return a.usageErr("sync mode requires --mode %s", strings.Join(validSyncModes, "|"))
	}
	if !contains(validSyncModes, newMode) {
		return a.usageErr("invalid --mode %q: must be one of %s", newMode, strings.Join(validSyncModes, ", "))
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.SetSyncMode(context.Background(), rest[0], newMode, *force)
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"Account:", res.AccountID},
			{"Sync mode:", res.SyncMode},
		})
		fmt.Fprintln(w, "\nThe flip is forward-only: existing balances and mirrored rows are unchanged.")
	})
}

// readBatchFile reads a batch from a path, or from stdin when path is "-".
func (a *App) readBatchFile(path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(a.in)
		if err != nil {
			return nil, fmt.Errorf("read batch from stdin: %w", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read batch: %w", err)
	}
	return data, nil
}

// parseSyncBatch accepts either a bare array of items or a full request
// object, resolving the account id as: an explicit --account, then the file's
// own account_id, then the logged-in account.
//
// Decoding is strict: an unknown field is a typo that would otherwise be
// dropped silently, and a dropped amount or currency corrupts the batch.
func parseSyncBatch(data []byte, explicit, fallback string) (bridge.PayalaSyncRequest, error) {
	var req bridge.PayalaSyncRequest
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return req, fmt.Errorf("batch file is empty")
	}

	if trimmed[0] == '[' {
		var items []bridge.PayalaSyncItem
		if err := strictUnmarshal(trimmed, &items); err != nil {
			return req, fmt.Errorf("parse batch: %w", err)
		}
		req.Transactions = items
	} else if err := strictUnmarshal(trimmed, &req); err != nil {
		return req, fmt.Errorf("parse batch: %w", err)
	}

	switch {
	case explicit != "":
		req.AccountID = explicit
	case req.AccountID == "":
		req.AccountID = fallback
	}
	return req, nil
}

func strictUnmarshal(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing data after the JSON value")
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
