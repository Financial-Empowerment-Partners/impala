package sep10

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// TOML holds the stellar.toml (SEP-1) fields SEP-10 needs. NetworkPassphrase
// is optional in the file; the other two are required for web authentication.
type TOML struct {
	WebAuthEndpoint   string
	SigningKey        string
	NetworkPassphrase string
}

// The stellar.toml keys read, all top-level (SEP-1 puts them before any table).
const (
	keyWebAuthEndpoint   = "WEB_AUTH_ENDPOINT"
	keySigningKey        = "SIGNING_KEY"
	keyNetworkPassphrase = "NETWORK_PASSPHRASE"
)

// ParseTOML reads the top-level string keys SEP-10 needs from a stellar.toml.
//
// The module carries no TOML library, and SEP-10 needs three root-table
// strings, so this is a small reader rather than a full TOML implementation:
// it walks the root table statement by statement — skipping every other
// value correctly, including multi-line strings, arrays and inline tables —
// and stops at the first table header ([...] or [[...]]), after which no key
// belongs to the root table. It fails closed: a syntax error it cannot step
// over, a duplicated key, or one of the three keys holding anything but a
// single-line string is an error, never a guess.
//
// Presence of the required keys is checked by the caller (Discover), so that
// the error can say which key is missing.
func ParseTOML(doc []byte) (TOML, error) {
	if !utf8.Valid(doc) {
		return TOML{}, fmt.Errorf("stellar.toml is not valid UTF-8")
	}
	p := &tomlReader{s: string(doc), line: 1}
	var out TOML
	seen := map[string]bool{}
	for {
		p.skipBlank()
		if p.eof() {
			return out, nil
		}
		if p.peek() == '[' {
			// The root table ends at the first table header.
			return out, nil
		}
		key, simple, err := p.key()
		if err != nil {
			return TOML{}, err
		}
		p.skipSpace()
		if p.eof() || p.peek() != '=' {
			return TOML{}, p.errorf("expected '=' after key %q", key)
		}
		p.i++
		p.skipSpace()
		val, isString, err := p.value()
		if err != nil {
			return TOML{}, err
		}
		if err := p.endOfStatement(); err != nil {
			return TOML{}, err
		}
		if !simple {
			continue // a dotted key is never one of ours
		}
		var dst *string
		switch key {
		case keyWebAuthEndpoint:
			dst = &out.WebAuthEndpoint
		case keySigningKey:
			dst = &out.SigningKey
		case keyNetworkPassphrase:
			dst = &out.NetworkPassphrase
		default:
			continue
		}
		if seen[key] {
			return TOML{}, fmt.Errorf("stellar.toml declares %s more than once", key)
		}
		seen[key] = true
		if !isString {
			return TOML{}, fmt.Errorf("stellar.toml %s is not a single-line string", key)
		}
		*dst = val
	}
}

// tomlReader is a cursor over a TOML document.
type tomlReader struct {
	s    string
	i    int
	line int
}

func (p *tomlReader) eof() bool  { return p.i >= len(p.s) }
func (p *tomlReader) peek() byte { return p.s[p.i] }

func (p *tomlReader) errorf(format string, args ...any) error {
	return fmt.Errorf("stellar.toml line %d: %s", p.line, fmt.Sprintf(format, args...))
}

// skipSpace skips spaces and tabs (not newlines).
func (p *tomlReader) skipSpace() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.i++
	}
}

// skipComment skips a '#' comment up to (not including) the newline.
func (p *tomlReader) skipComment() {
	if !p.eof() && p.peek() == '#' {
		for !p.eof() && p.peek() != '\n' {
			p.i++
		}
	}
}

// skipBlank skips whitespace, newlines and comments.
func (p *tomlReader) skipBlank() {
	for !p.eof() {
		switch p.peek() {
		case ' ', '\t', '\r':
			p.i++
		case '\n':
			p.i++
			p.line++
		case '#':
			p.skipComment()
		default:
			return
		}
	}
}

// endOfStatement requires the rest of the line to be blank or a comment.
func (p *tomlReader) endOfStatement() error {
	p.skipSpace()
	p.skipComment()
	if p.eof() {
		return nil
	}
	if p.peek() == '\r' {
		p.i++
	}
	if p.eof() || p.peek() != '\n' {
		return p.errorf("unexpected text after a value")
	}
	return nil
}

func isBareKeyByte(c byte) bool {
	return c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// key reads a (possibly dotted, possibly quoted) key. simple reports a key of
// exactly one part.
func (p *tomlReader) key() (string, bool, error) {
	var parts []string
	for {
		p.skipSpace()
		if p.eof() {
			return "", false, p.errorf("expected a key")
		}
		var part string
		switch c := p.peek(); {
		case c == '"':
			s, err := p.basicString()
			if err != nil {
				return "", false, err
			}
			part = s
		case c == '\'':
			s, err := p.literalString()
			if err != nil {
				return "", false, err
			}
			part = s
		case isBareKeyByte(c):
			start := p.i
			for !p.eof() && isBareKeyByte(p.peek()) {
				p.i++
			}
			part = p.s[start:p.i]
		default:
			return "", false, p.errorf("unexpected character %q where a key was expected", c)
		}
		parts = append(parts, part)
		p.skipSpace()
		if p.eof() || p.peek() != '.' {
			return strings.Join(parts, "."), len(parts) == 1, nil
		}
		p.i++
	}
}

// value reads one value. For a single-line basic or literal string it returns
// the decoded string and isString=true; any other value is skipped over.
func (p *tomlReader) value() (string, bool, error) {
	if p.eof() {
		return "", false, p.errorf("expected a value")
	}
	switch {
	case strings.HasPrefix(p.s[p.i:], `"""`):
		return "", false, p.skipMultiline(`"""`, true)
	case strings.HasPrefix(p.s[p.i:], `'''`):
		return "", false, p.skipMultiline(`'''`, false)
	case p.peek() == '"':
		s, err := p.basicString()
		return s, err == nil, err
	case p.peek() == '\'':
		s, err := p.literalString()
		return s, err == nil, err
	case p.peek() == '[':
		return "", false, p.skipContainer('[', ']')
	case p.peek() == '{':
		return "", false, p.skipContainer('{', '}')
	default:
		// A bare scalar: number, boolean, date-time. Dates may contain one
		// space ("1979-05-27 07:32:00"), so stop only at a comment, newline,
		// or a container delimiter, then trim.
		start := p.i
		for !p.eof() {
			c := p.peek()
			if c == '\n' || c == '#' || c == ',' || c == ']' || c == '}' {
				break
			}
			p.i++
		}
		if strings.TrimSpace(p.s[start:p.i]) == "" {
			return "", false, p.errorf("expected a value")
		}
		return "", false, nil
	}
}

// basicString reads a single-line "..." string, decoding escapes.
func (p *tomlReader) basicString() (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for {
		if p.eof() || p.peek() == '\n' {
			return "", p.errorf("unterminated string")
		}
		c := p.peek()
		p.i++
		switch c {
		case '"':
			return b.String(), nil
		case '\\':
			if p.eof() {
				return "", p.errorf("unterminated string")
			}
			e := p.peek()
			p.i++
			switch e {
			case 'b':
				b.WriteByte('\b')
			case 't':
				b.WriteByte('\t')
			case 'n':
				b.WriteByte('\n')
			case 'f':
				b.WriteByte('\f')
			case 'r':
				b.WriteByte('\r')
			case 'e':
				b.WriteByte(0x1b)
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'u', 'U':
				n := 4
				if e == 'U' {
					n = 8
				}
				if p.i+n > len(p.s) {
					return "", p.errorf("truncated \\%c escape", e)
				}
				v, err := strconv.ParseUint(p.s[p.i:p.i+n], 16, 32)
				if err != nil || !utf8.ValidRune(rune(v)) {
					return "", p.errorf("invalid \\%c escape", e)
				}
				p.i += n
				b.WriteRune(rune(v))
			default:
				return "", p.errorf("invalid escape \\%c", e)
			}
		default:
			b.WriteByte(c)
		}
	}
}

// literalString reads a single-line '...' string (no escapes).
func (p *tomlReader) literalString() (string, error) {
	p.i++
	start := p.i
	for {
		if p.eof() || p.peek() == '\n' {
			return "", p.errorf("unterminated string")
		}
		if p.peek() == '\'' {
			s := p.s[start:p.i]
			p.i++
			return s, nil
		}
		p.i++
	}
}

// skipMultiline skips a multi-line string (basic or literal: the delimiter
// is three double or three single quotes). Up to two quotes may
// directly precede the closing delimiter (they belong to the content).
func (p *tomlReader) skipMultiline(delim string, escapes bool) error {
	p.i += len(delim)
	for !p.eof() {
		c := p.peek()
		switch {
		case escapes && c == '\\':
			p.i++
			if !p.eof() {
				if p.peek() == '\n' {
					p.line++
				}
				p.i++
			}
		case c == '\n':
			p.line++
			p.i++
		case strings.HasPrefix(p.s[p.i:], delim):
			p.i += len(delim)
			for k := 0; k < 2 && !p.eof() && p.peek() == delim[0]; k++ {
				p.i++
			}
			return nil
		default:
			p.i++
		}
	}
	return p.errorf("unterminated multi-line string")
}

// skipContainer skips an array or inline table, with any nesting. Arrays may
// span lines and hold comments; strings inside are skipped as strings, so a
// bracket inside a string cannot end the container early.
func (p *tomlReader) skipContainer(open, close byte) error {
	p.i++ // the opening bracket
	for {
		p.skipBlank()
		if p.eof() {
			return p.errorf("unterminated %c", open)
		}
		switch c := p.peek(); c {
		case close:
			p.i++
			return nil
		case ',':
			p.i++
		case '=':
			p.i++ // inside an inline table, between key and value
		default:
			if open == '{' && (isBareKeyByte(c) || c == '"' || c == '\'') {
				// An inline-table key, or a value: try key syntax only when
				// an '=' follows; otherwise fall through to value parsing.
				save, saveLine := p.i, p.line
				if _, _, err := p.key(); err == nil {
					p.skipSpace()
					if !p.eof() && p.peek() == '=' {
						continue
					}
				}
				p.i, p.line = save, saveLine
			}
			if _, _, err := p.value(); err != nil {
				return err
			}
		}
	}
}
