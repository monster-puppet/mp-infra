//go:build !linux && !windows

package report

import "errors"

func uptimeSeconds() (float64, error) {
	return 0, errors.New("host.uptime is not supported on this OS")
}
