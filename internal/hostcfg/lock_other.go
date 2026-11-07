//go:build !unix && !windows

package hostcfg

import "os"

// tryLock has no interprocess lock to take on this platform; devtun does not
// ship for it, and the in-process mutex still serialises one process's writes.
func tryLock(*os.File) (bool, error) { return true, nil }

func unlock(*os.File) {}
