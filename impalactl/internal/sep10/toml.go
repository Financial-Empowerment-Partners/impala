package sep10

import (
	"fmt"
	"regexp"
	"strings"
)

// MaxTomlLength is SEP-1's cap on stellar.toml.
const MaxTomlLength = 100 * 1024

// Toml holds the three SEP-1 keys SEP-10 needs; a missing key is "".
type Toml struct {
	SigningKey        string
	WebAuthEndpoint   string
	NetworkPassphrase string
}

var (
	tomlKeyLine = regexp.MustCompile(`^([A-Za-z0-9_-]+)[ \t]*=(.*)$`)
	tomlHeader  = regexp.MustCompile(`^\[\[?[ \t]*[A-Za-z0-9_."' \t-]+[ \t]*]]?[ \t]*(#.*)?$`)
	tomlValue   = regexp.MustCompile("^[ \\t]*\"([^\"\\\\\\x00-\\x1f\\x7f]*)\"[ \\t]*(#.*)?$")
	tomlNeeded  = map[string]bool{"SIGNING_KEY": true, "WEB_AUTH_ENDPOINT": true, "NETWORK_PASSPHRASE": true}
)

// ParseToml reads the three keys strictly, exactly as impala-lib's
// StellarToml does: only root-table lines (before the first [table] or
// [[array]] header) count; a needed key must be a bare-key line with a basic
// double-quoted string without escapes or control characters, optionally
// followed by a # comment; each needed key may appear at most once. Every
// other line is skipped, including another key's multi-line string.
func ParseToml(text string) (*Toml, error) {
	if len(text) > MaxTomlLength {
		return nil, fmt.Errorf("stellar.toml longer than %d characters", MaxTomlLength)
	}
	found := map[string]string{}
	multiline := ""
	for index, raw := range strings.Split(text, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if multiline != "" {
			if strings.Contains(line, multiline) {
				multiline = ""
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if tomlHeader.MatchString(trimmed) {
			break // the root table ends at the first header
		}
		m := tomlKeyLine.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		key, rest := m[1], m[2]
		if !tomlNeeded[key] {
			v := strings.TrimLeft(rest, " \t")
			for _, delim := range []string{`"""`, `'''`} {
				if strings.HasPrefix(v, delim) && !strings.Contains(v[3:], delim) {
					multiline = delim
					break
				}
			}
			continue
		}
		vm := tomlValue.FindStringSubmatch(rest)
		if vm == nil {
			return nil, fmt.Errorf("line %d: %s must be a plain double-quoted string", index+1, key)
		}
		if _, dup := found[key]; dup {
			return nil, fmt.Errorf("line %d: %s appears more than once", index+1, key)
		}
		found[key] = vm[1]
	}
	return &Toml{
		SigningKey:        found["SIGNING_KEY"],
		WebAuthEndpoint:   found["WEB_AUTH_ENDPOINT"],
		NetworkPassphrase: found["NETWORK_PASSPHRASE"],
	}, nil
}
