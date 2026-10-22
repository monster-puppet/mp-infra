//go:build linux

package report

import "syscall"

func diskUsage(mount string) (total, free uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(mount, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize)
	// Bavail, not Bfree: space root keeps in reserve is not usable by services.
	return st.Blocks * bs, st.Bavail * bs, nil
}
