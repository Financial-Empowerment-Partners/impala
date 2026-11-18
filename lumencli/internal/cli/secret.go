package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// EnvSecret is the environment variable used to pass a secret seed without
// placing it in argv.
const EnvSecret = "LUMEN_SECRET"

// EnvCardPIN is the environment variable used to pass an Impala card's user
// PIN (sep10 login --card --pin) without placing it in argv.
const EnvCardPIN = "LUMEN_CARD_PIN"

// readSecret obtains a secret seed without exposing it in argv. In order:
//
//  1. $LUMEN_SECRET, if set;
//  2. an interactive, no-echo terminal prompt, when stdin is a terminal;
//  3. a single line read from stdin, for piping (e.g. `... < seed.txt`).
//
// The prompt is written to stderr so stdout stays clean for redirection.
func (a *App) readSecret(prompt string) (string, error) {
	return a.readSecretFrom(EnvSecret, "the seed", prompt)
}

// readSecretFrom is readSecret for any secret: envVar is consulted first,
// then a no-echo prompt, then one line of stdin. noun names the secret in
// the error when none is given ("the seed", "the PIN").
func (a *App) readSecretFrom(envVar, noun, prompt string) (string, error) {
	if s := strings.TrimSpace(a.getenv(envVar)); s != "" {
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
	line, err := a.lineReader().ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read secret: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("no secret provided (set $%s or pipe %s via stdin)", envVar, noun)
	}
	return line, nil
}
