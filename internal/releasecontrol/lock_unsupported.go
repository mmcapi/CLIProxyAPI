//go:build !linux && !darwin && !freebsd && !windows

package releasecontrol

import (
	"errors"
	"os"
)

func lockFile(*os.File) error   { return errors.New("refresh ownership file locking unsupported") }
func unlockFile(*os.File) error { return errors.New("refresh ownership file locking unsupported") }
