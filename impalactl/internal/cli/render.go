package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
)

// render prints the server's raw JSON under --json, and the supplied
// human-readable summary otherwise. The raw body is echoed verbatim (only
// re-indented) so --json never drops fields this CLI doesn't model.
func (a *App) render(opts options, raw []byte, human func(w io.Writer)) int {
	if opts.json {
		return a.printJSON(raw)
	}
	human(a.out)
	return 0
}

func (a *App) printJSON(raw []byte) int {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		// Not JSON (an empty 204 body, say) — pass it through untouched.
		fmt.Fprintln(a.out, strings.TrimRight(string(raw), "\n"))
		return 0
	}
	fmt.Fprintln(a.out, buf.String())
	return 0
}

// kv prints aligned "label: value" lines.
func kv(w io.Writer, rows [][2]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", row[0], row[1])
	}
	tw.Flush()
}

// table prints a header row plus body rows in aligned columns.
func table(w io.Writer, headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()
}

// str renders an optional string, showing "-" for absent or empty.
func str(p *string) string {
	if p == nil || *p == "" {
		return "-"
	}
	return *p
}

// dash renders a plain string, showing "-" when empty.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// num renders an optional integer, showing "-" for absent.
func num(p *int64) string {
	if p == nil {
		return "-"
	}
	return strconv.FormatInt(*p, 10)
}

// yesNo renders a bool for a table cell.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// shortAddr abbreviates a Stellar G-address for table columns, keeping enough
// of both ends to recognise it. Full values are always available via --json or
// the corresponding `show` command.
func shortAddr(p *string) string {
	runes := []rune(str(p))
	if len(runes) <= 16 {
		return string(runes)
	}
	return string(runes[:8]) + "…" + string(runes[len(runes)-6:])
}

// clip shortens free text for a table cell. It counts runes, so clipping a
// memo mid-character cannot produce mojibake.
func clip(p *string, max int) string {
	s := strings.ReplaceAll(str(p), "\n", " ")
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return string(runes[:max-1]) + "…"
}

// plural renders "1 account" / "3 accounts".
func plural(n uint64, singular, pluralWord string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralWord)
}
