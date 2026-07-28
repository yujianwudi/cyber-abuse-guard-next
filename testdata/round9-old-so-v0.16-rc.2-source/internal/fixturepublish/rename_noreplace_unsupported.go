//go:build !linux && !darwin && !ios && !windows

package fixturepublish

import (
	"errors"
	"runtime"
)

func renameNoReplace(_, _ string) error {
	return errors.New("fixturepublish: atomic no-replace directory rename is unsupported on " + runtime.GOOS)
}
