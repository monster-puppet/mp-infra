package report

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// The parsers in this file are platform-neutral so they are tested on Linux CI.
// The collectors that call them per platform are in security_other.go and
// security_windows.go.

// --- auth.logins.<host> ---

// Login is one user and address in the data of auth.logins.<host>.
type Login struct {
	Source string `json:"source"`
	User   string `json:"user,omitempty"`
	IP     string `json:"ip"`
	Count  int    `json:"count"`
	// Device is set by the server when IP is the public address of a personal
	// tailnet device (see server.tailnetLoginsRule).
	Device string `json:"device,omitempty"`
}

const maxLogins = 50

// evalLogins lists successful logins. Any login from an address outside the
// allowed networks (the tailnet, loopback, the configured extras) is crit: on
// these hosts that is either someone working around the VPN or someone who got in.
func evalLogins(id string, l *config.Logins, outs []string, errs []error) Check {
	type key struct{ src, user, ip string }
	counts := map[key]int{}
	var failed []string
	for i, src := range l.Sources {
		if errs[i] != nil {
			failed = append(failed, src.Name+": "+Clip(errs[i].Error(), 200))
		}
		re := regexp.MustCompile(src.Pattern)
		ipIdx, userIdx := re.SubexpIndex("ip"), re.SubexpIndex("user")
		for _, line := range strings.Split(outs[i], "\n") {
			m := re.FindStringSubmatch(strings.TrimRight(line, "\r"))
			if m == nil || ipIdx < 0 || m[ipIdx] == "" {
				continue
			}
			k := key{src: src.Name, ip: Clip(m[ipIdx], 64)}
			if userIdx > 0 {
				k.user = Clip(m[userIdx], 64)
			}
			counts[k]++
		}
	}
	var all, outside []Login
	total := 0
	for k, n := range counts {
		lg := Login{Source: k.src, User: k.user, IP: k.ip, Count: n}
		total += n
		all = append(all, lg)
		if !allowedIP(k.ip, l.Nets) {
			outside = append(outside, lg)
		}
	}
	byCount := func(ls []Login) {
		sort.Slice(ls, func(i, j int) bool {
			if ls[i].Count != ls[j].Count {
				return ls[i].Count > ls[j].Count
			}
			return ls[i].IP+ls[i].User < ls[j].IP+ls[j].User
		})
	}
	byCount(all)
	byCount(outside)
	if len(all) > maxLogins {
		all = all[:maxLogins]
	}
	if len(outside) > maxLogins {
		outside = outside[:maxLogins]
	}
	c := Check{ID: id}
	c.State, c.Summary = LoginsVerdict(total, outside, nil, len(failed))
	if outside == nil {
		outside = []Login{}
	}
	if all == nil {
		all = []Login{}
	}
	if failed == nil {
		failed = []string{}
	}
	c.Data = mustJSON(map[string]any{"total": total, "outside": outside, "logins": all, "errors": failed})
	return c
}

// LoginsVerdict is the state and summary of auth.logins.<host>: crit when a
// login came from outside the allowed networks, warn when a source failed.
// fromDevices are logins the server matched to a personal tailnet device's
// public address; they are named but do not raise the state.
func LoginsVerdict(total int, outside, fromDevices []Login, failed int) (eval.State, string) {
	state, summary := eval.OK, ""
	switch {
	case len(outside) > 0:
		state = eval.Crit
		o := outside[0]
		summary = fmt.Sprintf("login from outside the tailnet: %s from %s (%s)", orUnknown(o.User), o.IP, o.Source)
		if len(outside) > 1 {
			summary += fmt.Sprintf(" and %d more", len(outside)-1)
		}
	case len(fromDevices) > 0:
		o := fromDevices[0]
		summary = fmt.Sprintf("%d logins in 24 h; %s from %s, the public address of tailnet device %s", total, orUnknown(o.User), o.IP, o.Device)
		if len(fromDevices) > 1 {
			summary += fmt.Sprintf(" and %d more", len(fromDevices)-1)
		}
	case total == 0:
		summary = "no logins in 24 h"
	default:
		summary = fmt.Sprintf("%d logins in 24 h, all from the tailnet or allowed networks", total)
	}
	if failed > 0 {
		state = eval.Worst(state, eval.Warn)
		summary += fmt.Sprintf("; %d source(s) failed", failed)
	}
	return state, summary
}

func orUnknown(s string) string {
	if s == "" {
		return "someone"
	}
	return s
}

// allowedIP reports whether ip is in one of nets. An address that does not parse
// (a hostname from sshd with UseDNS) is not allowed.
func allowedIP(ip string, nets []netip.Prefix) bool {
	a, err := netip.ParseAddr(strings.Trim(ip, "[]"))
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, n := range nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// --- baseline checks: sec.accounts.<host>, sec.listeners.<host> ---

const (
	maxItems   = 300
	maxItemLen = 200
)

// itemsCheck reports a sorted list of facts and its hash. The server compares the
// list with the last accepted one; the agent always reports ok.
func itemsCheck(id, what string, items []string) Check {
	seen := map[string]bool{}
	var clean []string
	for _, it := range items {
		it = Clip(strings.TrimSpace(it), maxItemLen)
		if it != "" && !seen[it] {
			seen[it] = true
			clean = append(clean, it)
		}
	}
	sort.Strings(clean)
	if len(clean) > maxItems {
		clean = clean[:maxItems]
	}
	sum := sha256.Sum256([]byte(strings.Join(clean, "\n")))
	h := hex.EncodeToString(sum[:])
	if clean == nil {
		clean = []string{}
	}
	return Check{
		ID:      id,
		State:   eval.OK,
		Summary: fmt.Sprintf("%s: %d", what, len(clean)),
		Data:    mustJSON(map[string]any{"hash": h, "items": clean}),
	}
}

// --- Linux accounts ---

// noLogin are shells that cannot log in.
var noLogin = map[string]bool{
	"/sbin/nologin": true, "/usr/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true,
	"/bin/sync": true, "/sbin/shutdown": true, "/sbin/halt": true, "": true,
}

// adminGroups grant root through sudo or polkit.
var adminGroups = map[string]bool{"wheel": true, "sudo": true, "admin": true, "root": true}

// linuxAccounts lists what decides who can get a root shell on the host under
// root (normally "/"): accounts with uid 0 or a login shell, members of the admin
// groups, the sudoers files, and every key in an authorized_keys file.
func linuxAccounts(root string) ([]string, error) {
	passwd, err := os.ReadFile(filepath.Join(root, "etc/passwd"))
	if err != nil {
		return nil, err
	}
	var items []string
	homes := map[string]string{}
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 7 || strings.HasPrefix(f[0], "#") {
			continue
		}
		user, uid, home, shell := f[0], f[2], f[5], f[6]
		if uid == "0" {
			items = append(items, "uid0 "+user)
		}
		if !noLogin[shell] {
			items = append(items, "shell "+user+" "+shell)
			homes[user] = home
		}
	}
	if group, err := os.ReadFile(filepath.Join(root, "etc/group")); err == nil {
		for _, line := range strings.Split(string(group), "\n") {
			f := strings.Split(strings.TrimSpace(line), ":")
			if len(f) < 4 || !adminGroups[f[0]] {
				continue
			}
			for _, m := range strings.Split(f[3], ",") {
				if m != "" {
					items = append(items, "group "+f[0]+" "+m)
				}
			}
		}
	}
	sudoers := []string{filepath.Join(root, "etc/sudoers")}
	if more, err := filepath.Glob(filepath.Join(root, "etc/sudoers.d/*")); err == nil {
		sudoers = append(sudoers, more...)
	}
	for _, p := range sudoers {
		if b, err := os.ReadFile(p); err == nil {
			sum := sha256.Sum256(b)
			rel, _ := filepath.Rel(root, p)
			items = append(items, "sudoers /"+filepath.ToSlash(rel)+" "+hex.EncodeToString(sum[:6]))
		}
	}
	// root's keys count even when root has no login shell listed.
	if _, ok := homes["root"]; !ok {
		homes["root"] = "/root"
	}
	for user, home := range homes {
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			b, err := os.ReadFile(filepath.Join(root, home, ".ssh", name))
			if err != nil {
				continue
			}
			for _, k := range parseAuthorizedKeys(string(b)) {
				items = append(items, "key "+user+" "+k)
			}
		}
	}
	return items, nil
}

var keyType = regexp.MustCompile(`^(ssh-|ecdsa-|sk-)[a-z0-9@.-]+$`)

// parseAuthorizedKeys returns "type SHA256:fingerprint comment" for each key.
// Options before the key type (from="...",command="...") are part of the item,
// shortened to their names, so adding a forced command shows up too.
func parseAuthorizedKeys(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		i := 0
		for i < len(f) && !keyType.MatchString(f[i]) {
			i++
		}
		if i+1 >= len(f) {
			out = append(out, "unparsed "+Clip(line, 60))
			continue
		}
		fp := "?"
		if blob, err := base64.StdEncoding.DecodeString(f[i+1]); err == nil {
			sum := sha256.Sum256(blob)
			fp = "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
		}
		item := f[i] + " " + fp
		if c := strings.Join(f[i+2:], " "); c != "" {
			item += " " + c
		}
		if i > 0 {
			item += " [options]"
		}
		out = append(out, item)
	}
	return out
}

// parseWindowsAccounts reads the lines printed by windowsAccountsScript.
func parseWindowsAccounts(out string) []string {
	var items []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			items = append(items, line)
		}
	}
	return items
}

// windowsAccountsScript lists enabled local users and the members of the groups
// that can log in remotely or administer the host.
const windowsAccountsScript = `$ErrorActionPreference = 'Stop'
Get-LocalUser | Where-Object Enabled | ForEach-Object { "user " + $_.Name }
foreach ($g in 'Administrators', 'Remote Desktop Users', 'Remote Management Users') {
  Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | ForEach-Object { "group $g " + $_.Name }
}`

// --- listeners ---

// dynamicPort is where Windows (and most kernels) hand out dynamic ports. A
// listener there is reported without its port so a reboot that reshuffles RPC
// ports is not a change; a new process listening there still is.
const dynamicPort = 49152

func listenerItem(addr netip.Addr, port int, proc string) (string, bool) {
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return "", false
	}
	p := strconv.Itoa(port)
	if port >= dynamicPort {
		p = "dynamic"
	}
	a := addr.String()
	if addr.Is6() {
		a = "[" + a + "]"
	}
	if proc == "" {
		proc = "?"
	}
	return "tcp " + a + ":" + p + " " + proc, true
}

// procListener is one listening socket from /proc/net/tcp{,6}.
type procListener struct {
	Addr  netip.Addr
	Port  int
	Inode string
}

// parseProcNetTCP reads /proc/net/tcp or tcp6 and returns the sockets in state
// LISTEN (0A). Addresses are hex, in host (little-endian) byte order per 32-bit word.
func parseProcNetTCP(s string) []procListener {
	var out []procListener
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		hexAddr, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil {
			continue
		}
		raw, err := hex.DecodeString(hexAddr)
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		for i := 0; i < len(raw); i += 4 {
			raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		addr, _ := netip.AddrFromSlice(raw)
		out = append(out, procListener{Addr: addr, Port: int(port), Inode: f[9]})
	}
	return out
}

// parseWindowsListeners reads "address port process" lines from
// windowsListenersScript.
func parseWindowsListeners(out string) []string {
	var items []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(f[0])
		port, perr := strconv.Atoi(f[1])
		if err != nil || perr != nil {
			continue
		}
		proc := ""
		if len(f) > 2 {
			proc = f[2]
		}
		if it, ok := listenerItem(addr, port, proc); ok {
			items = append(items, it)
		}
	}
	return items
}

const windowsListenersScript = `$ErrorActionPreference = 'Stop'
Get-NetTCPConnection -State Listen | ForEach-Object {
  $p = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
  "$($_.LocalAddress) $($_.LocalPort) $p" }`
