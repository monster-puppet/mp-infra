package report

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/eval"
)

// --- sec.fail2ban.<host> ---

type f2bJail struct {
	Name      string `json:"name"`
	BannedNow int    `json:"banned_now"`
	Total     int    `json:"total_since_start"`
}

var (
	f2bJailList = regexp.MustCompile(`(?m)Jail list:\s*(.*)$`)
	f2bCurrent  = regexp.MustCompile(`(?m)Currently banned:\s*(\d+)`)
	f2bTotal    = regexp.MustCompile(`(?m)Total banned:\s*(\d+)`)
	f2bIP       = regexp.MustCompile(`'([0-9a-fA-F.:]+)'`)
	f2bBanLine  = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ fail2ban\.actions\s.*\[([^\]]+)\] Ban (\S+)`)
)

// parseF2BJails reads the jail names from `fail2ban-client status`.
func parseF2BJails(out string) []string {
	m := f2bJailList.FindStringSubmatch(out)
	if m == nil {
		return nil
	}
	var jails []string
	for _, j := range strings.Split(m[1], ",") {
		if j = strings.TrimSpace(j); j != "" {
			jails = append(jails, j)
		}
	}
	return jails
}

// parseF2BJail reads `fail2ban-client status <jail>`.
func parseF2BJail(name, out string) f2bJail {
	j := f2bJail{Name: name}
	if m := f2bCurrent.FindStringSubmatch(out); m != nil {
		j.BannedNow, _ = strconv.Atoi(m[1])
	}
	if m := f2bTotal.FindStringSubmatch(out); m != nil {
		j.Total, _ = strconv.Atoi(m[1])
	}
	return j
}

// parseF2BBanned returns the distinct addresses in `fail2ban-client banned`
// ([{'sshd': ['192.0.2.1', ...]}, {'recidive': [...]}]), sorted: an address in
// sshd and recidive at once is one banned attacker.
func parseF2BBanned(out string) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var ips []netip.Addr
	for _, m := range f2bIP.FindAllStringSubmatch(out, -1) {
		if a, err := netip.ParseAddr(m[1]); err == nil && !seen[a.Unmap()] {
			seen[a.Unmap()] = true
			ips = append(ips, a.Unmap())
		}
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	return ips
}

// countF2BBans counts "Ban" actions in fail2ban.log newer than since. The log's
// times are the host's local time. "Restore Ban" after a restart is not a new ban.
func countF2BBans(r io.Reader, since time.Time, loc *time.Location) int {
	n := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		m := f2bBanLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], loc); err == nil && t.After(since) {
			n++
		}
	}
	return n
}

// f2bUnban is what the check data says about unbanning: whether this agent acts
// on unban requests (fail2ban.unban), the addresses banned now (for the server's
// "currently banned on" lookup) and the results of the last unbans it ran.
type f2bUnban struct {
	Enabled bool
	Banned  []netip.Addr
	Results []UnbanResult
}

// maxBannedIPs caps banned_ips; the data must also stay under MaxData, so the
// list is cut earlier when the addresses are long.
const maxBannedIPs = 1000

// fail2banCheck: ok while fail2ban runs with an sshd jail, warn when it does not
// (SSH is open to the internet without it). The summary and data carry the
// counts the network map sums up.
func fail2banCheck(id string, running bool, jails []f2bJail, bannedNow, bans24h int, errMsg string, u f2bUnban) Check {
	sort.Slice(jails, func(i, j int) bool { return jails[i].Name < jails[j].Name })
	data := map[string]any{"running": running, "jails": jails, "banned_now": bannedNow, "bans_24h": bans24h, "unban": u.Enabled}
	if len(u.Results) > 0 {
		data["unban_results"] = u.Results
	}
	if running {
		// What is left of MaxData after everything else, with room for the
		// "banned_ips" key and "banned_ips_cut".
		room := MaxData - len(mustJSON(data)) - 64
		ips := []string{}
		for _, a := range u.Banned {
			s := a.String()
			if len(ips) == maxBannedIPs || room < len(s)+3 {
				data["banned_ips_cut"] = true
				break
			}
			room -= len(s) + 3
			ips = append(ips, s)
		}
		data["banned_ips"] = ips
	}
	if !running {
		data["error"] = Clip(errMsg, 200)
		return Check{ID: id, State: eval.Warn, Summary: "fail2ban is not running: SSH has no ban protection", Data: mustJSON(data)}
	}
	hasSSH := false
	for _, j := range jails {
		hasSSH = hasSSH || j.Name == "sshd"
	}
	if !hasSSH {
		return Check{ID: id, State: eval.Warn, Summary: "fail2ban runs without an sshd jail", Data: mustJSON(data)}
	}
	return Check{ID: id, State: eval.OK, Data: mustJSON(data),
		Summary: fmt.Sprintf("%s banned now, %s new bans in 24 h", thousands(bannedNow), thousands(bans24h))}
}

// thousands formats n with commas: 12,045.
func thousands(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		return "-" + thousands(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// --- unban (fail2ban.unban) ---
//
// The one thing the agent changes on its host, and only when its own config
// says unban: true. The server's reply to a report may name addresses to unban;
// each must be a plain IP address, and the agent runs one fixed command per
// address, `<client> unban <ip>`, without a shell.

// MaxUnbans is the most addresses one reply may ask the agent to unban.
const MaxUnbans = 20

// UnbanResult is the outcome of one unban, sent back in the next report.
type UnbanResult struct {
	IP  string `json:"ip"`
	OK  bool   `json:"ok"`
	Msg string `json:"msg"`
}

// ParseUnbanIP accepts a plain IPv4 or IPv6 address and nothing else: no CIDR,
// no hostname, no zone, no spaces. It returns the canonical form.
func ParseUnbanIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", Clip(s, 64))
	}
	return a.Unmap(), nil
}

// ValidUnbans checks a reply's list: at most MaxUnbans entries, each a plain IP
// address. Anything else refuses the whole list.
func ValidUnbans(ips []string) ([]netip.Addr, error) {
	if len(ips) > MaxUnbans {
		return nil, fmt.Errorf("%d addresses to unban, limit %d", len(ips), MaxUnbans)
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, s := range ips {
		a, err := ParseUnbanIP(s)
		if err != nil {
			return nil, err
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

// Unban runs `<client> unban <ip>` for each address.
func Unban(ctx context.Context, client []string, ips []string) ([]UnbanResult, error) {
	return unban(ctx, client, ips, run)
}

func unban(ctx context.Context, client []string, ips []string, exec func(context.Context, []string, map[string]string) (string, error)) ([]UnbanResult, error) {
	addrs, err := ValidUnbans(ips)
	if err != nil {
		return nil, err
	}
	var out []UnbanResult
	for _, a := range addrs {
		res, err := exec(ctx, append(append([]string{}, client...), "unban", a.String()), nil)
		r := UnbanResult{IP: a.String(), OK: err == nil, Msg: strings.TrimSpace(res)}
		if err != nil {
			r.Msg = err.Error()
		}
		r.Msg = Clip(r.Msg, 200)
		out = append(out, r)
	}
	return out, nil
}

// UnbanResultsFile is where the agent keeps unban results until the next report
// has carried them to the server: next to agent.yaml.
func UnbanResultsFile(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "unban-results.json")
}

// SaveUnbanResults writes results to path; earlier results not yet reported are kept.
func SaveUnbanResults(path string, results []UnbanResult) error {
	all := append(loadUnbanResults(path), results...)
	if len(all) > MaxUnbans {
		all = all[len(all)-MaxUnbans:]
	}
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// loadUnbanResults reads the results file; a missing or broken file is none.
func loadUnbanResults(path string) []UnbanResult {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64<<10 {
		return nil
	}
	var rs []UnbanResult
	if json.Unmarshal(b, &rs) != nil {
		return nil
	}
	if len(rs) > MaxUnbans {
		rs = rs[len(rs)-MaxUnbans:]
	}
	for i := range rs {
		rs[i].IP, rs[i].Msg = Clip(rs[i].IP, 64), Clip(rs[i].Msg, 200)
	}
	return rs
}
