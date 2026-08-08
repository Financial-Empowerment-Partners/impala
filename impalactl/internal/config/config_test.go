package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func envFrom(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func TestNewStorePrecedence(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "explicit override wins",
			env:  map[string]string{EnvConfigDir: "/tmp/explicit", "XDG_CONFIG_HOME": "/tmp/xdg", "HOME": "/tmp/home"},
			want: "/tmp/explicit",
		},
		{
			name: "xdg before home",
			env:  map[string]string{"XDG_CONFIG_HOME": "/tmp/xdg", "HOME": "/tmp/home"},
			want: filepath.Join("/tmp/xdg", "impalactl"),
		},
		{
			name: "home fallback",
			env:  map[string]string{"HOME": "/tmp/home"},
			want: filepath.Join("/tmp/home", ".config", "impalactl"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewStore(envFrom(tc.env))
			if err != nil {
				t.Fatalf("NewStore: %v", err)
			}
			if store.Dir() != tc.want {
				t.Errorf("Dir() = %q, want %q", store.Dir(), tc.want)
			}
		})
	}
}

func TestNewStoreWithoutHome(t *testing.T) {
	if _, err := NewStore(envFrom(nil)); err == nil {
		t.Error("NewStore with no HOME returned nil error")
	}
}

// newTempStore points the store at a directory that does not exist yet, so
// the tests exercise the permissions the store itself creates.
func newTempStore(t *testing.T) *Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "impalactl")
	store, err := NewStore(envFrom(map[string]string{EnvConfigDir: dir}))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestSaveLoadRoundTrip(t *testing.T) {
	store := newTempStore(t)

	if creds, err := store.Load(); err != nil || creds != nil {
		t.Fatalf("Load on an empty store = (%v, %v), want (nil, nil)", creds, err)
	}

	want := &Credentials{
		Endpoint:      "https://bridge.example.com",
		AccountID:     "alice",
		Role:          "admin",
		TemporalToken: "temporal",
		RefreshToken:  "refresh",
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if want.UpdatedAt == 0 {
		t.Error("Save did not stamp UpdatedAt")
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if *got != *want {
		t.Errorf("Load() = %+v, want %+v", got, want)
	}
}

func TestSavePermissions(t *testing.T) {
	store := newTempStore(t)
	if err := store.Save(&Credentials{Endpoint: "http://localhost:8080"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatalf("stat credentials: %v", err)
	}
	// Tokens are bearer credentials: no group or world access.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credentials mode = %o, want 600", perm)
	}
	dirInfo, err := os.Stat(store.Dir())
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("config dir mode = %o, want 700", perm)
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	store := newTempStore(t)
	for range 3 {
		if err := store.Save(&Credentials{Endpoint: "http://localhost:8080"}); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	entries, err := os.ReadDir(store.Dir())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != credentialsFile {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory contains %v, want just %s", names, credentialsFile)
	}
}

func TestClearIsIdempotent(t *testing.T) {
	store := newTempStore(t)
	if err := store.Clear(); err != nil {
		t.Errorf("Clear on an empty store: %v", err)
	}
	if err := store.Save(&Credentials{Endpoint: "http://localhost:8080"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if creds, err := store.Load(); err != nil || creds != nil {
		t.Errorf("Load after Clear = (%v, %v), want (nil, nil)", creds, err)
	}
}

func TestLoadRejectsCorruptFile(t *testing.T) {
	store := newTempStore(t)
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Error("Load on a corrupt file returned nil error")
	}
}

func TestLockExcludesSecondHolder(t *testing.T) {
	store := newTempStore(t)

	release, err := store.Lock(time.Second)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	// A second acquisition must not succeed while the first is held: two
	// processes rotating the same single-use refresh token would get the
	// account's token family revoked.
	if _, err := store.Lock(50 * time.Millisecond); err == nil {
		t.Error("second Lock succeeded while the first was held")
	}

	release()

	// Releasing must hand the lock to the next caller.
	release2, err := store.Lock(time.Second)
	if err != nil {
		t.Fatalf("Lock after release: %v", err)
	}
	release2()
}

// A held lock must never be handed to a second caller just because it has been
// held a while. The previous sentinel scheme aged locks out after 30s, so a
// refresh slower than that had its lock stolen — and the two processes then
// both presented the same single-use refresh token, which the bridge treats as
// theft and answers by revoking the whole token family.
func TestHeldLockIsNotStolenOverTime(t *testing.T) {
	store := newTempStore(t)

	release, err := store.Lock(time.Second)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer release()

	// Backdate the lock file well past any plausible staleness window. With a
	// kernel lock this is irrelevant, which is exactly the point.
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(filepath.Join(store.Dir(), lockFile), old, old); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Lock(50 * time.Millisecond); err == nil {
		t.Error("an old but still-held lock was stolen by a second caller")
	}
}

// An abandoned lock file must not wedge the CLI forever: the kernel drops the
// lock when its holder goes away, so a leftover file is always re-acquirable.
func TestStaleLockFileDoesNotBlockAcquisition(t *testing.T) {
	store := newTempStore(t)
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(store.Dir(), lockFile)
	if err := os.WriteFile(leftover, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(leftover, old, old); err != nil {
		t.Fatal(err)
	}

	release, err := store.Lock(time.Second)
	if err != nil {
		t.Fatalf("a leftover lock file blocked acquisition: %v", err)
	}
	release()
}
