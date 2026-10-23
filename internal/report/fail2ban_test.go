package report

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/eval"
)

func TestFail2banCaptured(t *testing.T) {
	// jenkins, fail2ban 1.1.0, captured 2026-10-23; addresses replaced.
	jails := parseF2BJails(readFixture(t, "fail2ban_status.txt"))
	if strings.Join(jails, ",") != "recidive,sshd" {
		t.Fatalf("jails: %v", jails)
	}
	sshd := parseF2BJail("sshd", readFixture(t, "fail2ban_status_sshd.txt"))
	if sshd.BannedNow != 49 || sshd.Total != 3353 {
		t.Errorf("sshd: %+v", sshd)
	}
	ips := parseF2BBanned(readFixture(t, "fail2ban_banned.txt"))
	if len(ips) != 49 || ips[0].String() != "198.51.100.1" || ips[1].String() != "198.51.100.2" || ips[48].String() != "198.51.100.49" {
		t.Errorf("banned: %d %v", len(ips), ips)
	}
	// The log's times are local to the host; here they are read as UTC.
	log := readFixture(t, "fail2ban_log.txt")
	if n := countF2BBans(strings.NewReader(log), time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), time.UTC); n != 9 {
		t.Errorf("bans since 22 Oct: %d", n)
	}
	if n := countF2BBans(strings.NewReader(log), time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC), time.UTC); n != 0 {
		t.Errorf("bans since 09:00: %d", n)
	}
	c := fail2banCheck("sec.fail2ban.jenkins", true, []f2bJail{sshd, {Name: "recidive"}}, 49, 9, "", f2bUnban{Enabled: true, Banned: ips})
	if c.State != eval.OK || c.Summary != "49 banned now, 9 new bans in 24 h" {
		t.Errorf("check: %s %q", c.State, c.Summary)
	}
	var d struct {
		Unban     bool     `json:"unban"`
		BannedIPs []string `json:"banned_ips"`
		Bans24h   int      `json:"bans_24h"`
	}
	if err := json.Unmarshal(c.Data, &d); err != nil || !d.Unban || len(d.BannedIPs) != 49 || d.BannedIPs[0] != "198.51.100.1" || d.Bans24h != 9 {
		t.Errorf("data: %v %+v", err, d)
	}
}

func TestFail2banStates(t *testing.T) {
	// One address in sshd and recidive is one banned attacker; IPv6 counts too.
	if ips := parseF2BBanned(`[{'sshd': ['192.0.2.1', '192.0.2.2']}, {'recidive': ['192.0.2.1', '2001:db8::1']}]`); len(ips) != 3 {
		t.Errorf("unique: %v", ips)
	}
	// A restart restores bans; those are not new.
	log := "2026-10-23 08:00:00,000 fail2ban.actions        [1]: NOTICE  [sshd] Restore Ban 192.0.2.1\n" +
		"2026-10-23 08:00:01,000 fail2ban.actions        [1]: NOTICE  [sshd] Ban 192.0.2.2\n" +
		"2026-10-23 08:00:02,000 fail2ban.actions        [1]: NOTICE  [sshd] Unban 192.0.2.3\n"
	if n := countF2BBans(strings.NewReader(log), time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), time.UTC); n != 1 {
		t.Errorf("restore counted: %d", n)
	}
	if c := fail2banCheck("sec.fail2ban.h", false, nil, 0, 0, "Failed to access socket path", f2bUnban{}); c.State != eval.Warn || !strings.Contains(c.Summary, "not running") {
		t.Errorf("down: %s %q", c.State, c.Summary)
	}
	if c := fail2banCheck("sec.fail2ban.h", true, []f2bJail{{Name: "recidive"}}, 0, 0, "", f2bUnban{}); c.State != eval.Warn || c.Summary != "fail2ban runs without an sshd jail" {
		t.Errorf("no sshd: %s %q", c.State, c.Summary)
	}
	if thousands(12045) != "12,045" || thousands(7) != "7" {
		t.Error("thousands")
	}
}

func TestFail2banBannedIPsFitMaxData(t *testing.T) {
	// 1,000 long IPv6 addresses do not fit in MaxData: the list is cut, not the report.
	var ips []netip.Addr
	for i := 0; i < 1500; i++ {
		ips = append(ips, netip.MustParseAddr(fmt.Sprintf("2001:db8:ffff:ffff:ffff:ffff:ffff:%x", i)))
	}
	results := make([]UnbanResult, MaxUnbans)
	for i := range results {
		results[i] = UnbanResult{IP: "2001:db8::1", Msg: strings.Repeat("x", 200)}
	}
	c := fail2banCheck("sec.fail2ban.h", true, []f2bJail{{Name: "sshd"}}, 1500, 0, "", f2bUnban{Banned: ips, Results: results})
	if len(c.Data) > MaxData {
		t.Fatalf("data is %d bytes, limit %d", len(c.Data), MaxData)
	}
	var d struct {
		BannedIPs []string      `json:"banned_ips"`
		Cut       bool          `json:"banned_ips_cut"`
		Results   []UnbanResult `json:"unban_results"`
	}
	if err := json.Unmarshal(c.Data, &d); err != nil || !d.Cut || len(d.BannedIPs) < 100 || len(d.BannedIPs) >= 1000 || len(d.Results) != MaxUnbans {
		t.Errorf("%v: cut %v, %d addresses, %d results", err, d.Cut, len(d.BannedIPs), len(d.Results))
	}
	// Short IPv4 addresses stop at 1,000.
	ips = ips[:0]
	for i := 0; i < 1200; i++ {
		ips = append(ips, netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}))
	}
	c = fail2banCheck("sec.fail2ban.h", true, []f2bJail{{Name: "sshd"}}, 1200, 0, "", f2bUnban{Banned: ips})
	var d2 struct {
		BannedIPs []string `json:"banned_ips"`
	}
	if err := json.Unmarshal(c.Data, &d2); err != nil || len(d2.BannedIPs) != maxBannedIPs || len(c.Data) > MaxData {
		t.Errorf("%v: %d addresses, %d bytes", err, len(d2.BannedIPs), len(c.Data))
	}
}

// injections are addresses the server (or someone who took it over) might send
// that are not plain IP addresses.
var injections = []string{
	"1.2.3.4; rm -rf /", "1.2.3.4 && reboot", "1.2.3.4|sh", "$(reboot)", "`reboot`",
	"1.2.3.4/24", "2001:db8::/32", "example.com", "localhost", " 1.2.3.4", "1.2.3.4 ",
	"1.2.3.4\n", "-h", "--all", "fe80::1%eth0", "fe80::1%;reboot", "", "1.2.3", "1.2.3.4.5",
}

func TestUnbanValidation(t *testing.T) {
	for _, bad := range injections {
		if _, err := ParseUnbanIP(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
		if _, err := ValidUnbans([]string{"192.0.2.1", bad}); err == nil {
			t.Errorf("list with %q accepted", bad)
		}
	}
	if a, err := ParseUnbanIP("::ffff:192.0.2.1"); err != nil || a.String() != "192.0.2.1" {
		t.Errorf("mapped: %v %v", a, err)
	}
	many := make([]string, MaxUnbans+1)
	for i := range many {
		many[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	if _, err := ValidUnbans(many); err == nil {
		t.Error("21 addresses accepted")
	}
	if ips, err := ValidUnbans(many[:MaxUnbans]); err != nil || len(ips) != MaxUnbans {
		t.Errorf("20 addresses: %v %v", ips, err)
	}
}

func TestUnbanRunsFixedArgv(t *testing.T) {
	var calls [][]string
	exec := func(_ context.Context, argv []string, env map[string]string) (string, error) {
		calls = append(calls, argv)
		if argv[len(argv)-1] == "2001:db8::1" {
			return "", fmt.Errorf("fail2ban-client: exit status 255: not banned")
		}
		return "1\n", nil
	}
	client := []string{"/usr/bin/fail2ban-client"}
	res, err := unban(context.Background(), client, []string{"192.0.2.7", "2001:db8::1", "192.0.2.7"}, exec)
	if err != nil {
		t.Fatal(err)
	}
	want := `[[/usr/bin/fail2ban-client unban 192.0.2.7] [/usr/bin/fail2ban-client unban 2001:db8::1]]`
	if fmt.Sprint(calls) != want {
		t.Errorf("argv: %v", calls)
	}
	if len(res) != 2 || !res[0].OK || res[0].Msg != "1" || res[1].OK || !strings.Contains(res[1].Msg, "not banned") {
		t.Errorf("results: %+v", res)
	}
	// An injection attempt refuses the whole list and runs nothing.
	for _, bad := range injections {
		calls = nil
		if _, err := unban(context.Background(), client, []string{"192.0.2.7", bad}, exec); err == nil || len(calls) != 0 {
			t.Errorf("%q: %v, %d calls", bad, err, len(calls))
		}
	}
	if len(client) != 1 || client[0] != "/usr/bin/fail2ban-client" {
		t.Errorf("client argv modified: %v", client)
	}
}

func TestUnbanResultsFile(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "agent.yaml")
	file := UnbanResultsFile(cfg)
	if filepath.Dir(file) != filepath.Dir(cfg) || filepath.Base(file) != "unban-results.json" {
		t.Fatalf("file: %s", file)
	}
	if loadUnbanResults(file) != nil {
		t.Error("results without a file")
	}
	if err := SaveUnbanResults(file, []UnbanResult{{IP: "192.0.2.7", OK: true, Msg: "1"}}); err != nil {
		t.Fatal(err)
	}
	if rs := loadUnbanResults(file); len(rs) != 1 || rs[0].IP != "192.0.2.7" || !rs[0].OK {
		t.Errorf("loaded: %+v", rs)
	}
	os.WriteFile(file, []byte("not json"), 0o600)
	if loadUnbanResults(file) != nil {
		t.Error("a broken file gave results")
	}
}
