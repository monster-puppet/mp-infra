//go:build windows

package report

import "syscall"

var procGetTickCount64 = syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")

func uptimeSeconds() (float64, error) {
	if err := procGetTickCount64.Find(); err != nil {
		return 0, err
	}
	ms, _, _ := procGetTickCount64.Call()
	return float64(ms) / 1000, nil
}
