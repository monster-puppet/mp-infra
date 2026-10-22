//go:build !windows

package report

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

func localAccounts(context.Context) ([]string, error) {
	return linuxAccounts("/")
}

// localListeners reads the listening TCP sockets from /proc and names the
// process behind each one by matching socket inodes in /proc/<pid>/fd.
func localListeners(context.Context) ([]string, error) {
	var ls []procListener
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			if f == "/proc/net/tcp" {
				return nil, err
			}
			continue
		}
		ls = append(ls, parseProcNetTCP(string(b))...)
	}
	procs := socketOwners()
	var items []string
	for _, l := range ls {
		if it, ok := listenerItem(l.Addr, l.Port, procs[l.Inode]); ok {
			items = append(items, it)
		}
	}
	return items, nil
}

// socketOwners maps socket inode to process name. Best effort: a process that
// exits mid-scan is skipped.
func socketOwners() map[string]string {
	m := map[string]string{}
	fds, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fd := range fds {
		target, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		if _, ok := m[inode]; ok {
			continue
		}
		pid := filepath.Dir(filepath.Dir(fd))
		if comm, err := os.ReadFile(filepath.Join(pid, "comm")); err == nil {
			m[inode] = strings.TrimSpace(string(comm))
		}
	}
	return m
}
