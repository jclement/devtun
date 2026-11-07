//go:build unix

package hostcfg

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes an exclusive flock without waiting, reporting false when
// another open file holds it. flock is per open file, not per process, so two
// stores in one process exclude each other exactly as two processes do.
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

func unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
