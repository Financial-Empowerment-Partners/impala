package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"impalactl/internal/bridge"
)

var activitySubcommands = []string{
	"list                List transactions with their review state",
	"show <btxid>        Show one transaction in full",
	"review <btxid>      Set review status / flag / note (admin)",
	"events              Read the admin event feed (admin)",
}

// validReviewStatuses mirrors VALID_REVIEW_STATUSES in the bridge.
var validReviewStatuses = []string{"unreviewed", "cleared", "flagged", "escalated"}

func (a *App) runActivity(opts options, args []string) int {
	if len(args) == 0 {
		a.subUsage(a.err, "activity", activitySubcommands)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		a.subUsage(a.out, "activity", activitySubcommands)
		return 0
	case "list":
		return a.runActivityList(opts, rest)
	case "show":
		return a.runActivityShow(opts, rest)
	case "review":
		return a.runActivityReview(opts, rest)
	case "events":
		return a.runActivityEvents(opts, rest)
	default:
		fmt.Fprintf(a.err, "error: unknown subcommand %q\n\n", sub)
		a.subUsage(a.err, "activity", activitySubcommands)
		return 2
	}
}

// runActivityList prints a page of transactions (GET /transactions). A regular
// caller sees only transactions sourced from accounts they own; admins see all.
func (a *App) runActivityList(opts options, args []string) int {
	fs := a.newFlagSet("activity list")
	bindGlobalFlags(fs, &opts)
	page := fs.Uint64("page", 0, "page number (default 1)")
	perPage := fs.Uint64("per-page", 0, "rows per page, 1-100 (default 20)")
	status := fs.String("status", "", "review status: "+strings.Join(validReviewStatuses, " | "))
	flagged := fs.String("flagged", "", "filter on the review flag: true | false")
	account := fs.String("account", "", "exact source Stellar account id (G...)")
	from := fs.String("from", "", "only transactions created at or after this RFC3339 timestamp")
	to := fs.String("to", "", "only transactions created before this RFC3339 timestamp")
	search := fs.String("search", "", "free-text match on memo, tx ids, hash or source account")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("activity list takes no positional arguments")
	}
	if *status != "" && !contains(validReviewStatuses, *status) {
		return a.usageErr("invalid --status %q: must be one of %s", *status, strings.Join(validReviewStatuses, ", "))
	}
	if src := strings.TrimSpace(*account); src != "" {
		if err := validateStellarAccountID(src); err != nil {
			return a.fail("%v", err)
		}
	}

	listOpts := bridge.ListTransactionsOptions{
		Page:          *page,
		PerPage:       *perPage,
		Status:        *status,
		SourceAccount: strings.TrimSpace(*account),
		From:          strings.TrimSpace(*from),
		To:            strings.TrimSpace(*to),
		Query:         *search,
	}
	if *flagged != "" {
		parsed, err := strconv.ParseBool(*flagged)
		if err != nil {
			return a.usageErr("invalid --flagged %q: must be true or false", *flagged)
		}
		listOpts.Flagged = &parsed
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.ListTransactions(context.Background(), listOpts)
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		if len(res.Data) == 0 {
			fmt.Fprintln(w, "No transactions found.")
			return
		}
		rows := make([][]string, 0, len(res.Data))
		for _, tx := range res.Data {
			rows = append(rows, []string{
				tx.BTxID,
				tx.CreatedAt,
				tx.Origin,
				tx.Status,
				yesNo(tx.Flagged),
				shortAddr(tx.SourceAccount),
				num(tx.PayalaAmount),
				str(tx.PayalaCurrency),
				clip(tx.Memo, 24),
			})
		}
		table(w, []string{"BTXID", "CREATED", "ORIGIN", "STATUS", "FLAG", "SOURCE", "AMOUNT", "CUR", "MEMO"}, rows)
		pageFooter(w, len(res.Data), res.Page, res.PerPage, res.Total, "transaction", "transactions")
	})
}

// runActivityShow prints one transaction in full.
func (a *App) runActivityShow(opts options, args []string) int {
	fs := a.newFlagSet("activity show")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.usageErr("activity show requires one bridge transaction id (btxid)")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	tx, raw, err := c.GetTransaction(context.Background(), rest[0])
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		kv(w, [][2]string{
			{"Bridge tx id:", tx.BTxID},
			{"Created:", tx.CreatedAt},
			{"Origin:", tx.Origin},
			{"Stellar tx id:", str(tx.StellarTxID)},
			{"Stellar hash:", str(tx.StellarHash)},
			{"Source account:", str(tx.SourceAccount)},
			{"Stellar fee:", num(tx.StellarFee)},
			{"Stellar max fee:", num(tx.StellarMaxFee)},
			{"Payala tx id:", str(tx.PayalaTxID)},
			{"Payala amount:", num(tx.PayalaAmount)},
			{"Payala currency:", str(tx.PayalaCurrency)},
			{"Payala digest:", str(tx.PayalaDigest)},
			{"Memo:", str(tx.Memo)},
			{"Signatures:", str(tx.Signatures)},
			{"Preconditions:", str(tx.Preconditions)},
			{"Review status:", tx.Status},
			{"Flagged:", yesNo(tx.Flagged)},
			{"Review note:", str(tx.Note)},
			{"Reviewed by:", str(tx.ReviewedBy)},
			{"Reviewed at:", str(tx.ReviewedAt)},
		})
	})
}

// runActivityReview sets a transaction's review state (admin only).
func (a *App) runActivityReview(opts options, args []string) int {
	fs := a.newFlagSet("activity review")
	bindGlobalFlags(fs, &opts)
	status := fs.String("status", "", "review status: "+strings.Join(validReviewStatuses, " | "))
	flagged := fs.Bool("flagged", false, "mark the transaction as flagged")
	note := fs.String("note", "", "review note (max 2000 characters)")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.usageErr("activity review requires one bridge transaction id (btxid)")
	}
	if *status != "" && !contains(validReviewStatuses, *status) {
		return a.usageErr("invalid --status %q: must be one of %s", *status, strings.Join(validReviewStatuses, ", "))
	}

	// The endpoint is a full replacement: whatever is not sent is reset. Send
	// the flag explicitly so the stored state always matches what was asked.
	req := bridge.ReviewTransactionRequest{
		Flagged: flagged,
		Status:  *status,
		Note:    *note,
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.ReviewTransaction(context.Background(), rest[0], req)
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"Bridge tx id:", res.BTxID},
			{"Review status:", res.Status},
			{"Flagged:", yesNo(res.Flagged)},
		})
	})
}

// runActivityEvents reads the admin event feed (admin only).
func (a *App) runActivityEvents(opts options, args []string) int {
	fs := a.newFlagSet("activity events")
	bindGlobalFlags(fs, &opts)
	since := fs.Int64("since", 0, "only events with an id greater than this cursor")
	limit := fs.Int64("limit", 0, "maximum events to return (default 100)")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("activity events takes no positional arguments")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.ListEvents(context.Background(), *since, *limit)
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		if len(res.Events) == 0 {
			fmt.Fprintln(w, "No events.")
			return
		}
		rows := make([][]string, 0, len(res.Events))
		for _, ev := range res.Events {
			rows = append(rows, []string{
				strconv.FormatInt(ev.ID, 10),
				ev.CreatedAt,
				ev.EventType,
				ev.AccountID,
				compactJSON(ev.Payload, 48),
			})
		}
		table(w, []string{"ID", "CREATED", "TYPE", "ACCOUNT", "PAYLOAD"}, rows)
		last := res.Events[len(res.Events)-1].ID
		fmt.Fprintf(w, "\nNext cursor: --since %d\n", last)
	})
}

// compactJSON renders a payload on one line, clipped for a table cell.
func compactJSON(raw json.RawMessage, max int) string {
	if len(raw) == 0 {
		return "-"
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		buf.Reset()
		buf.Write(raw)
	}
	s := buf.String()
	return clip(&s, max)
}
