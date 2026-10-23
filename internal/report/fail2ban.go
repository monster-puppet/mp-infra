package report

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
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

// parseF2BBanned counts the distinct addresses in `fail2ban-client banned`
// ([{'sshd': ['192.0.2.1', ...]}, {'recidive': [...]}]): an address in sshd and
// recidive at once is one banned attacker.
func parseF2BBanned(out string) int {
	seen := map[netip.Addr]bool{}
	for _, m := range f2bIP.FindAllStringSubmatch(out, -1) {
		if a, err := netip.ParseAddr(m[1]); err == nil {
			seen[a.Unmap()] = true
		}
	}
	return len(seen)
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

// fail2banCheck: ok while fail2ban runs with an sshd jail, warn when it does not
// (SSH is open to the internet without it). The summary and data carry the
// counts the network map sums up.
func fail2banCheck(id string, running bool, jails []f2bJail, bannedNow, bans24h int, errMsg string) Check {
	sort.Slice(jails, func(i, j int) bool { return jails[i].Name < jails[j].Name })
	data := map[string]any{"running": running, "jails": jails, "banned_now": bannedNow, "bans_24h": bans24h}
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
