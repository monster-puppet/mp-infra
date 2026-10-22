//go:build !linux && !windows

package report

import "errors"

func diskUsage(string) (uint64, uint64, error) {
	return 0, 0, errors.New("disk checks are not supported on this OS")
}
