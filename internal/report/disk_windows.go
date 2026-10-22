//go:build windows

package report

import (
	"syscall"
	"unsafe"
)

var procGetDiskFreeSpaceExW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

func diskUsage(mount string) (total, free uint64, err error) {
	p, err := syscall.UTF16PtrFromString(mount)
	if err != nil {
		return 0, 0, err
	}
	var avail, tot, totFree uint64
	r, _, e := procGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&avail)), uintptr(unsafe.Pointer(&tot)), uintptr(unsafe.Pointer(&totFree)))
	if r == 0 {
		return 0, 0, e
	}
	return tot, avail, nil
}
