//go:build !unix

package config

import (
	"os"
	"time"
)

// lockFileExclusive is a no-op on platforms without flock.
//
// Serialization across concurrent processes is unavailable there, so two
// simultaneous impalactl invocations could both rotate the same single-use
// refresh token and trip the bridge's reuse detection. Single-process use is
// unaffected. The supported platforms for this tool are unix-like; this stub
// exists so the package still builds elsewhere rather than silently pretending
// to lock.
func lockFileExclusive(_ *os.File, _ time.Duration) error { return nil }

func unlockFile(_ *os.File) {}
