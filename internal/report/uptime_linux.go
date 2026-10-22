//go:build linux

package report

import "os"

func uptimeSeconds() (float64, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	return parseProcUptime(string(b))
}
