// Package config resolves impalactl's settings and stores the credentials
// obtained by `impalactl login`.
//
// Credentials live in a single 0600 file inside a 0700 directory, and they
// record the endpoint they were issued by: a token minted by one bridge is
// never sent to another, so pointing --endpoint at a different deployment
// cannot leak a production token into a test one (or vice versa).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Environment variables read by the CLI. Secrets are taken from the
// environment (or a prompt) rather than argv, which is world-readable on most
// systems and lands in shell history.
const (
	// EnvConfigDir overrides where credentials are stored.
	EnvConfigDir = "IMPALA_CONFIG_DIR"
	// EnvEndpoint is the default bridge base URL.
	EnvEndpoint = "IMPALA_ENDPOINT"
	// EnvToken is a bearer temporal JWT to use as-is, bypassing the store.
	EnvToken = "IMPALA_TOKEN"
	// EnvPassword supplies the login password non-interactively.
	EnvPassword = "IMPALA_PASSWORD"
	// EnvSecretSeed supplies a Stellar secret seed non-interactively.
	EnvSecretSeed = "IMPALA_SECRET_SEED"
)

const (
	credentialsFile = "credentials.json"
	lockFile        = "credentials.lock"
	// lockStaleAfter bounds how long a crashed process can wedge a refresh.
	lockStaleAfter = 30 * time.Second
	lockPollEvery  = 25 * time.Millisecond
)

// Credentials is the persisted result of a successful login.
type Credentials struct {
	// Endpoint the tokens were issued by; they are only ever sent back there.
	Endpoint  string `json:"endpoint"`
	AccountID string `json:"account_id"`
	Role      string `json:"role,omitempty"`
	// TemporalToken is the short-lived bearer token (1 h).
	TemporalToken string `json:"temporal_token"`
	// RefreshToken is single-use: each refresh rotates it, and replaying a
	// rotated-out one revokes the whole family server-side. It must be
	// persisted before the replacement is used.
	RefreshToken string `json:"refresh_token"`
	UpdatedAt    int64  `json:"updated_at"`
}

// Store is a credential store rooted at a directory.
type Store struct {
	dir string
}

// NewStore resolves the config directory from the environment:
// $IMPALA_CONFIG_DIR, else $XDG_CONFIG_HOME/impalactl, else
// $HOME/.config/impalactl. Nothing is created until Save is called.
func NewStore(getenv func(string) string) (*Store, error) {
	if dir := strings.TrimSpace(getenv(EnvConfigDir)); dir != "" {
		return &Store{dir: dir}, nil
	}
	if xdg := strings.TrimSpace(getenv("XDG_CONFIG_HOME")); xdg != "" {
		return &Store{dir: filepath.Join(xdg, "impalactl")}, nil
	}
	home := strings.TrimSpace(getenv("HOME"))
	if home == "" {
		return nil, fmt.Errorf("cannot locate a config directory: set $%s or $HOME", EnvConfigDir)
	}
	return &Store{dir: filepath.Join(home, ".config", "impalactl")}, nil
}

// Dir returns the store's directory.
func (s *Store) Dir() string { return s.dir }

// Path returns the credentials file path.
func (s *Store) Path() string { return filepath.Join(s.dir, credentialsFile) }

// Load reads the stored credentials. A missing file is not an error: it
// returns (nil, nil), meaning "not logged in".
func (s *Store) Load() (*Credentials, error) {
	data, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("parse %s: %w (delete it and log in again)", s.Path(), err)
	}
	return &creds, nil
}

// Save writes credentials atomically with 0600 permissions. The temp file is
// created in the destination directory so the rename cannot cross filesystems
// and never leaves a half-written credentials file behind.
func (s *Store) Save(creds *Credentials) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", s.dir, err)
	}
	creds.UpdatedAt = time.Now().Unix()
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(s.dir, credentialsFile+".*")
	if err != nil {
		return fmt.Errorf("create temp credentials file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temp credentials file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write credentials: %w", err)
	}
	// fsync before the rename: a token lost to a crash here would strand the
	// account on a burned refresh token.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync credentials: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close credentials: %w", err)
	}
	if err := os.Rename(tmpName, s.Path()); err != nil {
		return fmt.Errorf("install credentials: %w", err)
	}
	return nil
}

// Clear removes the stored credentials. Removing an absent file succeeds.
func (s *Store) Clear() error {
	if err := os.Remove(s.Path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove credentials: %w", err)
	}
	return nil
}

// Lock takes an exclusive advisory lock over the credential file, waiting up
// to wait for a competing holder.
//
// This serializes refresh-token rotation between concurrent impalactl
// processes. Rotation is single-use server-side, so two processes refreshing
// the same token would get the second one's family revoked; holders re-read
// the store after acquiring so the loser of a race adopts the winner's tokens
// instead of burning its own.
//
// The returned release function is always safe to call, including on error.
func (s *Store) Lock(wait time.Duration) (func(), error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return func() {}, fmt.Errorf("create %s: %w", s.dir, err)
	}
	path := filepath.Join(s.dir, lockFile)
	deadline := time.Now().Add(wait)

	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return func() {}, fmt.Errorf("acquire lock %s: %w", path, err)
		}

		// Take over a lock abandoned by a crashed process.
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > lockStaleAfter {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return func() {}, fmt.Errorf("timed out waiting for %s (remove it if no impalactl is running)", path)
		}
		time.Sleep(lockPollEvery)
	}
}
