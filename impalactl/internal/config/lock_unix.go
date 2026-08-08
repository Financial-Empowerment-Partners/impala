//go:build unix

package config

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// lockFileExclusive takes a kernel advisory lock (flock) on f, retrying until
// wait elapses.
//
// A kernel lock is what makes refresh-rotation serialization actually hold: it
// is released automatically when the process exits or crashes, so there is no
// staleness heuristic to get wrong. The previous sentinel-file scheme had to
// guess when a holder had died, and guessed wrong whenever a refresh took
// longer than the timeout — stealing the lock from a live holder and causing
// exactly the double-rotation (and consequent family revocation) it existed to
// prevent.
func lockFileExclusive(f *os.File, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		if time.Now().After(deadline) {
			return errTimedOut
		}
		time.Sleep(lockPollEvery)
	}
}

// unlockFile releases a lock taken by lockFileExclusive. Closing the file
// would release it too; this is explicit so the intent is visible.
func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
