package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// readSecret obtains a secret without exposing it in argv. In order:
//
//  1. the named environment variable, if set;
//  2. an interactive, no-echo terminal prompt, when stdin is a terminal;
//  3. a single line read from stdin, for piping (e.g. `... < token.txt`).
//
// The prompt is written to stderr so stdout stays clean for redirection.
func (a *App) readSecret(envName, prompt string) (string, error) {
	if s := strings.TrimSpace(a.getenv(envName)); s != "" {
		return s, nil
	}

	if f, ok := a.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(a.err, prompt)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(a.err)
		if err != nil {
			return "", fmt.Errorf("read secret: %w", err)
		}
		secret := strings.TrimSpace(string(b))
		if secret == "" {
			return "", fmt.Errorf("no secret provided")
		}
		return secret, nil
	}

	// Non-interactive: read one line from stdin.
	line, err := bufio.NewReader(a.in).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read secret: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("no secret provided (set $%s or pipe it via stdin)", envName)
	}
	return line, nil
}
