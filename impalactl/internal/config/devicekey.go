package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Device keys: a P-256 key held by THIS machine as a possession factor
// (docs/mfa-card-pin-biometrics.md §4). The private key lives in a 0600 file
// inside a 0700 directory under the same config directory as the
// credentials, and like them it is scoped: one file per (endpoint, account),
// and a file is only ever used for the pair recorded inside it.
//
// A key in a file is a possession factor and nothing more: whoever can read
// the file holds the factor. It is never declared biometric.

const deviceKeyDir = "device-keys"

// DeviceKey is a stored device key.
type DeviceKey struct {
	// Endpoint and AccountID scope the key: it signs only for this account,
	// and only toward this bridge.
	Endpoint  string `json:"endpoint"`
	AccountID string `json:"account_id"`
	// KeyID is the bridge's handle, empty while an enrollment is in flight
	// (the private key is written before the bridge is asked, so a key the
	// bridge accepted is never one this machine has lost).
	KeyID string `json:"key_id,omitempty"`
	Label string `json:"label,omitempty"`
	// PrivateKey is the PKCS#8 DER private key, hex-encoded.
	PrivateKey string `json:"private_key_pkcs8"`
	// PublicKey is the 65-byte uncompressed SEC1 point, hex-encoded: what the
	// bridge stores.
	PublicKey string `json:"public_key"`
	CreatedAt int64  `json:"created_at"`
}

// DeviceKeyPath returns the file a device key for (endpoint, account) lives in.
func (s *Store) DeviceKeyPath(endpoint, accountID string) string {
	sum := sha256.Sum256([]byte(endpoint + "\x00" + accountID))
	return filepath.Join(s.dir, deviceKeyDir, hex.EncodeToString(sum[:16])+".json")
}

// LoadDeviceKey reads the device key for (endpoint, account). A missing file
// is (nil, nil). A file whose recorded scope differs from the one asked for is
// an error: it is never used for another pair.
func (s *Store) LoadDeviceKey(endpoint, accountID string) (*DeviceKey, error) {
	path := s.DeviceKeyPath(endpoint, accountID)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read device key: %w", err)
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users (mode %v): chmod 600 it, "+
			"or revoke the key (`impalactl mfa device revoke`) if it may have been copied", path, info.Mode().Perm())
	}
	var key DeviceKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if key.Endpoint != endpoint || key.AccountID != accountID {
		return nil, fmt.Errorf("%s is scoped to %s at %s, not %s at %s: refusing to use it",
			path, key.AccountID, key.Endpoint, accountID, endpoint)
	}
	if strings.TrimSpace(key.PrivateKey) == "" || strings.TrimSpace(key.PublicKey) == "" {
		return nil, fmt.Errorf("%s holds no key", path)
	}
	return &key, nil
}

// SaveDeviceKey writes a device key atomically with 0600 permissions.
func (s *Store) SaveDeviceKey(key *DeviceKey) error {
	if key.Endpoint == "" || key.AccountID == "" {
		return errors.New("device key has no endpoint or account")
	}
	if key.CreatedAt == 0 {
		key.CreatedAt = time.Now().Unix()
	}
	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return fmt.Errorf("encode device key: %w", err)
	}
	data = append(data, '\n')
	path := s.DeviceKeyPath(key.Endpoint, key.AccountID)
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", s.dir, err)
	}
	if err := writeAtomic(filepath.Dir(path), filepath.Base(path), data); err != nil {
		return fmt.Errorf("device key: %w", err)
	}
	return nil
}

// DeleteDeviceKey removes the device key for (endpoint, account). Removing
// an absent file succeeds.
func (s *Store) DeleteDeviceKey(endpoint, accountID string) error {
	if err := os.Remove(s.DeviceKeyPath(endpoint, accountID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove device key: %w", err)
	}
	return nil
}
