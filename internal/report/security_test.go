package report

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

func TestAuthPerIP(t *testing.T) {
	af := &config.AuthFailures{WarnPerIP: 2, Sources: []config.AuthSource{{Name: "ssh", Pattern: `from (?P<ip>\S+)`}}}
	c := evalAuth("auth.failures.h", af, []string{"from 192.0.2.1\nfrom 192.0.2.1\nfrom 192.0.2.2\n"}, []error{nil}, now)
	if c.State != eval.Warn || !strings.Contains(c.Summary, "brute force from 192.0.2.1") {
		t.Errorf("%+v", c)
	}
	c = evalAuth("auth.failures.h", af, []string{"from 192.0.2.1\nfrom 192.0.2.2\n"}, []error{nil}, now)
	if c.State != eval.OK {
		t.Errorf("below per-IP threshold: %+v", c)
	}
}

func loginCfg() *config.Logins {
	return &config.Logins{
		Nets: append(append([]netip.Prefix{}, config.DefaultLoginNets...), netip.MustParsePrefix("198.51.100.0/24")),
		Sources: []config.AuthSource{
			{Name: "ssh", Pattern: `Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)`},
			{Name: "rdp", Pattern: `^(?P<user>\S+) (?P<ip>[0-9a-fA-F.:]+) \d+$`},
		},
	}
}

func TestLogins(t *testing.T) {
	l := loginCfg()
	ssh := "Accepted publickey for marcus from 100.101.102.103 port 50000 ssh2\n" +
		"Accepted publickey for marcus from 100.101.102.103 port 50001 ssh2\n" +
		"Accepted password for deploy from 198.51.100.4 port 1 ssh2\n" +
		"Failed password for root from 203.0.113.9 port 2 ssh2\n"
	now := time.Date(2026, 10, 22, 17, 0, 0, 0, time.UTC)
	c := evalLogins("auth.logins.h", l, []string{ssh, "Administrator fd7a:115c:a1e0::1 10\r\n"}, []error{nil, nil}, now)
	if c.State != eval.OK || !strings.Contains(c.Summary, "4 logins") {
		t.Errorf("allowed logins: %+v", c)
	}

	ssh += "Accepted password for root from 203.0.113.9 port 3 ssh2\n"
	c = evalLogins("auth.logins.h", l, []string{ssh, "Administrator ::ffff:192.0.2.50 10\n"}, []error{nil, nil}, now)
	if c.State != eval.Crit || !strings.Contains(c.Summary, "outside the tailnet") || !strings.Contains(c.Summary, "and 1 more") {
		t.Errorf("outside login: %+v", c)
	}
	if out := data(t, c)["outside"].([]any); len(out) != 2 {
		t.Errorf("outside = %v", out)
	}

	c = evalLogins("auth.logins.h", l, []string{"", ""}, []error{nil, errors.New("no journal")}, now)
	if c.State != eval.Warn || !strings.Contains(c.Summary, "no logins") {
		t.Errorf("failed source: %+v", c)
	}
}

// A source with a "time" group records the newest login per user and address,
// and the summary says how long ago the outside login was.
func TestLoginsLast(t *testing.T) {
	l := &config.Logins{
		Nets: config.DefaultLoginNets,
		Sources: []config.AuthSource{
			{Name: "ssh", Pattern: `^(?P<time>\S+) \S+ sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)`},
			{Name: "rdp", Pattern: `^(?P<time>\S+) (?P<user>\S+) (?P<ip>[0-9a-fA-F.:]+) \d+$`},
		},
	}
	ssh := "2026-10-22T10:51:48+0200 jenkins sshd[1]: Accepted publickey for root from 198.211.111.194 port 1 ssh2\n" +
		"2026-10-22T09:00:00+02:00 jenkins sshd[2]: Accepted publickey for root from 198.211.111.194 port 2 ssh2\n" +
		"2026-10-22T18:40:00+0200 jenkins sshd[3]: Accepted publickey for root from 100.102.193.92 port 3 ssh2\n"
	rdp := "2026-10-22T14:20:00.1234567Z Administrator 100.102.193.92 10\r\n"
	now := time.Date(2026, 10, 22, 17, 0, 0, 0, time.UTC)
	c := evalLogins("auth.logins.h", l, []string{ssh, rdp}, []error{nil, nil}, now)
	want := "login from outside the tailnet: root from 198.211.111.194 (ssh), last 8 h ago"
	if c.State != eval.Crit || c.Summary != want {
		t.Errorf("summary = %q, want %q", c.Summary, want)
	}
	out := data(t, c)["outside"].([]any)
	if got := out[0].(map[string]any)["last"]; got != "2026-10-22T08:51:48Z" {
		t.Errorf("outside last = %v", got)
	}
	for _, lg := range data(t, c)["logins"].([]any) {
		if m := lg.(map[string]any); m["source"] == "rdp" && m["last"] != "2026-10-22T14:20:00Z" {
			t.Errorf("rdp last = %v", m["last"])
		}
	}

	// Without a time group (an older agent config) the summary is unchanged.
	c = evalLogins("auth.logins.h", loginCfg(), []string{"Accepted publickey for root from 198.211.111.194 port 1 ssh2\n", ""}, []error{nil, nil}, now)
	if c.Summary != "login from outside the tailnet: root from 198.211.111.194 (ssh)" {
		t.Errorf("no time group: %q", c.Summary)
	}
}

func TestAllowedIP(t *testing.T) {
	nets := config.DefaultLoginNets
	for ip, want := range map[string]bool{
		"100.64.0.1": true, "100.127.255.255": true, "100.128.0.1": false, "127.0.0.1": true,
		"::1": true, "::ffff:100.70.1.1": true, "203.0.113.1": false, "host.example": false, "": false,
	} {
		if got := allowedIP(ip, nets); got != want {
			t.Errorf("allowedIP(%q) = %v", ip, got)
		}
	}
}

func write(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A made-up public key blob in the ed25519 shape; it belongs to no one.
const testKey = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func TestLinuxAccounts(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"+
		"bin:x:1:1:bin:/bin:/sbin/nologin\n"+
		"toor:x:0:0::/home/toor:/bin/sh\n"+
		"marcus:x:1000:1000::/home/marcus:/bin/bash\n"+
		"perforce:x:1001:1001::/p4:/usr/sbin/nologin\n")
	write(t, root, "etc/group", "wheel:x:10:marcus\nusers:x:100:marcus,perforce\n")
	write(t, root, "etc/sudoers", "root ALL=(ALL) ALL\n")
	write(t, root, "etc/sudoers.d/90-ci", "jenkins ALL=(ALL) NOPASSWD: ALL\n")
	write(t, root, "root/.ssh/authorized_keys", "# comment\nssh-ed25519 "+testKey+" marcus@laptop\n")
	write(t, root, "home/marcus/.ssh/authorized_keys", `from="100.64.0.0/10" ssh-ed25519 `+testKey+"\n")
	items, err := linuxAccounts(root)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(items, "\n")
	for _, want := range []string{
		"uid0 root", "uid0 toor", "shell marcus /bin/bash", "group wheel marcus",
		"sudoers /etc/sudoers ", "sudoers /etc/sudoers.d/90-ci ",
		"key root ssh-ed25519 SHA256:", " marcus@laptop",
		"key marcus ssh-ed25519 SHA256:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, bad := range []string{"bin", "perforce", "users"} {
		for _, it := range items {
			if strings.Contains(it, " "+bad) {
				t.Errorf("unexpected %q", it)
			}
		}
	}
	if !strings.Contains(got, "[options]") {
		t.Error("key options not marked")
	}
}

func TestItemsCheck(t *testing.T) {
	a := itemsCheck("sec.x.h", "things", []string{"b", "a", "a", " "})
	b := itemsCheck("sec.x.h", "things", []string{"a", "b"})
	if string(a.Data) != string(b.Data) || a.Summary != "things: 2" {
		t.Errorf("%s / %s", a.Data, b.Data)
	}
}

func TestParseProcNetTCP(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1 0000000000000000 100 0 0 10 0
   2: 0A00000A:0016 0B00000A:D431 01 00000000:00000000 02:000A7214 00000000     0        0 3333 4 0000000000000000 20 4 30 10 -1
   3: 0202000A:C350 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4444 1 0000000000000000 100 0 0 10 0
`
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0682 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   997        0 5555 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6666 1 0000000000000000 100 0 0 10 0
`
	owners := map[string]string{"1111": "sshd", "5555": "p4d_1"}
	var items []string
	for _, l := range append(parseProcNetTCP(tcp), parseProcNetTCP(tcp6)...) {
		if it, ok := listenerItem(l.Addr, l.Port, owners[l.Inode]); ok {
			items = append(items, it)
		}
	}
	want := "tcp 0.0.0.0:22 sshd|tcp 10.0.2.2:dynamic ?|tcp [::]:1666 p4d_1"
	if got := strings.Join(items, "|"); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParseWindowsListeners(t *testing.T) {
	out := "0.0.0.0 3389 svchost\r\n127.0.0.1 9001 node\r\n:: 49668 lsass\r\n0.0.0.0 4444\r\ngarbage\r\n"
	got := strings.Join(parseWindowsListeners(out), "|")
	want := "tcp 0.0.0.0:3389 svchost|tcp [::]:dynamic lsass|tcp 0.0.0.0:4444 ?"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestAuthLast4h(t *testing.T) {
	// payload_test's now is 14:05 UTC: two of the three failures fall in the last 4 h.
	af := &config.AuthFailures{Sources: []config.AuthSource{{Name: "ssh",
		Pattern: `^(?P<time>\S+) \S+ sshd\[\d+\]: (?:Failed password|Invalid user) .* from (?P<ip>[0-9a-fA-F.:]+)`}}}
	out := "2026-10-22T09:00:00+0000 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2\n" +
		"2026-10-22T12:30:00+0200 h sshd[2]: Invalid user admin from 192.0.2.2 port 22\n" +
		"2026-10-22T14:00:00+0000 h sshd[3]: Failed password for root from 192.0.2.1 port 22 ssh2\n"
	c := evalAuth("auth.failures.h", af, []string{out}, []error{nil}, now)
	if !strings.Contains(string(c.Data), `"last_4h":2`) || !strings.Contains(string(c.Data), `"total":3`) {
		t.Errorf("%s", c.Data)
	}
	if !strings.Contains(c.Summary, "3 failed logins in 24 h (2 in 4 h)") || !strings.Contains(string(c.Data), `"last":"2026-10-22T14:00:00Z"`) {
		t.Errorf("summary %q data %s", c.Summary, c.Data)
	}
	// A source without a time group: no 4 h count at all rather than a short one.
	af.Sources = append(af.Sources, config.AuthSource{Name: "rdp", Pattern: `^(?P<ip>\S+)$`})
	c = evalAuth("auth.failures.h", af, []string{out, "198.51.100.7\n"}, []error{nil, nil}, now)
	if strings.Contains(string(c.Data), "last_4h") {
		t.Errorf("partial 4 h count: %s", c.Data)
	}
}

func TestAuthBruteForceEnded(t *testing.T) {
	// now is 14:05 UTC. 192.0.2.1 failed 3 times, last at 09:00: over 4 h ago.
	af := &config.AuthFailures{WarnPerIP: 3, Sources: []config.AuthSource{{Name: "rdp",
		Pattern: `^(?P<time>\S+) (?P<ip>[0-9a-fA-F.:]+)\s*$`}}}
	old := "2026-10-22T08:00:00Z 192.0.2.1\n2026-10-22T08:30:00Z 192.0.2.1\n2026-10-22T09:00:00.1234567Z 192.0.2.1\n"
	c := evalAuth("auth.failures.h", af, []string{old}, []error{nil}, now)
	if c.State != eval.OK || !strings.Contains(c.Summary, "brute force from 192.0.2.1 ended, last 5 h ago") {
		t.Errorf("ended: %s %q", c.State, c.Summary)
	}
	// One more failure 10 minutes ago: it is going on, so warn.
	c = evalAuth("auth.failures.h", af, []string{old + "2026-10-22T13:55:00Z 192.0.2.1\n"}, []error{nil}, now)
	if c.State != eval.Warn || !strings.Contains(c.Summary, "brute force from 192.0.2.1, last 10 min ago") {
		t.Errorf("ongoing: %s %q", c.State, c.Summary)
	}
}
