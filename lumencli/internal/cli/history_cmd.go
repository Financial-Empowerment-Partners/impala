package cli

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
)

// historyFlags is everything the history command accepts beyond the network
// flags and the positional address.
type historyFlags struct {
	limit         int
	includeFailed bool
	jsonOut       bool
	csvOut        bool
	sent          bool
	received      bool
	counterparty  string
	asset         string
	since         string
	until         string
	summary       bool
	allOps        bool
	follow        bool
}

// runHistory lists an account's transaction history, newest first:
// `lumencli history G...`. By default it walks the account's entire history
// of fund-moving operations (payments, path payments, account creations and
// merges — Horizon's payments endpoint, which omits claimable-balance
// operations and Soroban transfers; --all-ops walks every operation type
// instead). Identifiers print in full, never abbreviated: history is what
// you consult when checking whether a deposit arrived or where funds went.
func (a *App) runHistory(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("history")
	bindNetworkFlags(fs, &opts)
	var f historyFlags
	fs.IntVar(&f.limit, "limit", 0, "stop after this many entries (0 = the full history)")
	fs.BoolVar(&f.includeFailed, "failed", false, "also list operations from failed transactions")
	fs.BoolVar(&f.jsonOut, "json", false, "write JSON Lines (one object per entry) instead of the human listing")
	fs.BoolVar(&f.csvOut, "csv", false, "write CSV instead of the human listing")
	fs.BoolVar(&f.sent, "sent", false, "only entries where this account sent funds")
	fs.BoolVar(&f.received, "received", false, "only entries where this account received funds")
	fs.StringVar(&f.counterparty, "counterparty", "", "only entries with this counterparty (G... account, or exact M... muxed address)")
	fs.StringVar(&f.asset, "asset", "", "only entries moving this asset: native | XLM | CODE:ISSUER")
	fs.StringVar(&f.since, "since", "", "only entries at or after this time: YYYY-MM-DD (UTC) or RFC3339")
	fs.StringVar(&f.until, "until", "", "only entries up to this time: YYYY-MM-DD (UTC, whole day) or RFC3339")
	fs.BoolVar(&f.summary, "summary", false, "print per-asset totals over the (filtered) range instead of the listing")
	fs.BoolVar(&f.allOps, "all-ops", false, "list every operation type, not just the fund-moving kinds")
	fs.BoolVar(&f.follow, "follow", false, "after the listing, keep streaming new payments as they arrive (Ctrl+C to stop)")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.fail("usage: lumencli history [flags] <account-address>")
	}
	address := strings.TrimSpace(rest[0])
	if strings.HasPrefix(address, "M") {
		return a.fail("history takes the account's G... address (Horizon indexes accounts, not muxed sub-addresses); to isolate one muxed depositor, pass the M... address to --counterparty on the pooled account's history")
	}

	filter, code := a.validateHistoryFlags(&f)
	if code != 0 {
		return code
	}

	net, err := a.resolveNetwork(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	a.announce(net)

	if f.summary {
		return a.runHistorySummary(net, address, &f, filter)
	}
	return a.runHistoryListing(net, address, &f, filter)
}

// validateHistoryFlags enforces the flag-compatibility matrix up front, so
// every meaningless combination is a clear error instead of an accidental,
// silently-wrong behavior a script could come to depend on.
func (a *App) validateHistoryFlags(f *historyFlags) (*historyFilter, int) {
	if f.limit < 0 {
		return nil, a.fail("--limit must be 0 (the full history) or positive")
	}
	if f.jsonOut && f.csvOut {
		return nil, a.fail("--json and --csv are mutually exclusive")
	}
	if f.sent && f.received {
		return nil, a.fail("--sent and --received are mutually exclusive (the default already shows both directions; drop one)")
	}
	if f.summary {
		if f.csvOut {
			return nil, a.fail("--summary has no CSV form; use --summary --json, or compute over the --csv listing")
		}
		if f.follow {
			return nil, a.fail("--summary and --follow are mutually exclusive (totals need a finished range)")
		}
		if f.allOps {
			return nil, a.fail("--summary works on the fund-moving history only; drop --all-ops")
		}
	}
	if f.allOps {
		// Generic operations have no amount, direction, or counterparty, so
		// these filters would silently drop every non-payment entry — a wrong
		// answer about money dressed as an empty result.
		switch {
		case f.sent || f.received:
			return nil, a.fail("--sent/--received cannot combine with --all-ops (generic operations have no direction)")
		case f.counterparty != "":
			return nil, a.fail("--counterparty cannot combine with --all-ops (generic operations have no counterparty)")
		case f.asset != "":
			return nil, a.fail("--asset cannot combine with --all-ops (generic operations move no asset)")
		case f.follow:
			return nil, a.fail("--follow streams payments only; drop --all-ops")
		}
	}
	if f.follow {
		if f.until != "" {
			return nil, a.fail("--follow watches for new entries; --until bounds the past — drop one")
		}
		if f.csvOut {
			return nil, a.fail("--follow supports the human listing and --json (a CSV export needs a finished range)")
		}
	}

	filter := &historyFilter{}
	if f.sent {
		filter.direction = dirSent
	}
	if f.received {
		filter.direction = dirReceived
	}
	if f.counterparty != "" {
		cp, err := parseCounterparty(f.counterparty)
		if err != nil {
			return nil, a.fail("%v", err)
		}
		filter.counterparty = cp
	}
	if f.asset != "" {
		spec, err := parseAssetSpec(f.asset)
		if err != nil {
			return nil, a.fail("%v", err)
		}
		filter.asset = spec
	}
	var err error
	if filter.since, err = parseTimeFlag("--since", f.since, false); err != nil {
		return nil, a.fail("%v", err)
	}
	if filter.until, err = parseTimeFlag("--until", f.until, true); err != nil {
		return nil, a.fail("%v", err)
	}
	if !filter.since.IsZero() && !filter.until.IsZero() && filter.until.Before(filter.since) {
		return nil, a.fail("--until is before --since")
	}
	return filter, 0
}

// runHistoryListing renders the (filtered) history in the selected format.
func (a *App) runHistoryListing(net netcfg.Network, address string, f *historyFlags, filter *historyFilter) int {
	// The header (and the CSV header row) appear only once the walk has
	// produced output or finished cleanly, so a failed fetch leaves stdout
	// empty — a partial machine-readable stream must not look complete.
	headerPrinted := false
	printHeader := func() {
		if !headerPrinted && !f.jsonOut && !f.csvOut {
			fmt.Fprintf(a.out, "Account: %s\nHistory (newest first):\n", address)
			headerPrinted = true
		}
	}

	var csvw *csvWriter
	if f.csvOut {
		csvw = newCSVWriter(a.out)
	}
	jsonEnc := newJSONEncoder(a.out)

	render := func(e historyEntry) {
		switch {
		case f.jsonOut:
			jsonEnc.Encode(toJSONEntry(e)) //nolint:errcheck // bytes.Buffer/stdout
		case f.csvOut:
			csvw.write(e) //nolint:errcheck // surfaced by close()
		default:
			printHeader()
			fmt.Fprintln(a.out)
			renderEntry(a.out, e)
		}
	}

	shown, truncated := 0, false
	newestToken := ""
	walkErr := a.horizon(net).EachOperation(address, stellar.HistoryOpts{IncludeFailed: f.includeFailed, AllOps: f.allOps},
		func(op operations.Operation) bool {
			if newestToken == "" {
				newestToken = op.PagingToken()
			}
			e := entryFromOp(address, op)
			if filter.beforeSince(e) {
				return false // older than --since: nothing further can match
			}
			if !filter.match(e) {
				return true
			}
			if f.limit > 0 && shown == f.limit {
				truncated = true
				return false
			}
			render(e)
			shown++
			return true
		})
	if walkErr != nil {
		return a.fail("%v", walkErr)
	}

	if f.csvOut {
		if err := csvw.close(); err != nil {
			return a.fail("write csv: %v", err)
		}
	}
	if !f.jsonOut && !f.csvOut {
		if shown == 0 {
			printHeader()
			if filter.active() {
				fmt.Fprintln(a.out, "  (no entries match the filters)")
			} else {
				fmt.Fprintln(a.out, "  (no transactions)")
			}
		} else {
			entries := "entries"
			if shown == 1 {
				entries = "entry"
			}
			fmt.Fprintf(a.out, "\n%d %s shown.\n", shown, entries)
		}
	}
	if truncated {
		fmt.Fprintf(a.err, "Stopped at --limit %d; older entries may exist.\n", f.limit)
	}

	if f.follow {
		cursor := newestToken
		if cursor == "" {
			// No history at all: stream from the beginning, which replays
			// nothing and cannot miss a payment landing right now.
			cursor = "0"
		}
		return a.runFollow(net, address, cursor, f.includeFailed, filter, render)
	}
	return 0
}

// runHistorySummary aggregates the (filtered) history into per-asset totals.
func (a *App) runHistorySummary(net netcfg.Network, address string, f *historyFlags, filter *historyFilter) int {
	acc := newSummaryAccum()
	var accErr error
	walkErr := a.horizon(net).EachOperation(address, stellar.HistoryOpts{IncludeFailed: f.includeFailed},
		func(op operations.Operation) bool {
			e := entryFromOp(address, op)
			if filter.beforeSince(e) {
				return false
			}
			if !filter.match(e) {
				return true
			}
			if f.limit > 0 && acc.entries == f.limit {
				acc.truncated = true
				return false
			}
			if accErr = acc.add(address, e); accErr != nil {
				return false
			}
			return true
		})
	if walkErr != nil {
		return a.fail("%v", walkErr)
	}
	if accErr != nil {
		return a.fail("%v", accErr)
	}

	if f.jsonOut {
		if err := newJSONEncoder(a.out).Encode(acc.toJSON(address)); err != nil {
			return a.fail("write json: %v", err)
		}
		return 0
	}
	acc.renderSummaryText(a.out, address, f.limit)
	return 0
}
