package report

import (
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
	if n := parseF2BBanned(readFixture(t, "fail2ban_banned.txt")); n != 49 {
		t.Errorf("banned: %d", n)
	}
	// The log's times are local to the host; here they are read as UTC.
	log := readFixture(t, "fail2ban_log.txt")
	if n := countF2BBans(strings.NewReader(log), time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), time.UTC); n != 9 {
		t.Errorf("bans since 22 Oct: %d", n)
	}
	if n := countF2BBans(strings.NewReader(log), time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC), time.UTC); n != 0 {
		t.Errorf("bans since 09:00: %d", n)
	}
	c := fail2banCheck("sec.fail2ban.jenkins", true, []f2bJail{sshd, {Name: "recidive"}}, 49, 9, "")
	if c.State != eval.OK || c.Summary != "49 banned now, 9 new bans in 24 h" {
		t.Errorf("check: %s %q", c.State, c.Summary)
	}
}

func TestFail2banStates(t *testing.T) {
	// One address in sshd and recidive is one banned attacker; IPv6 counts too.
	if n := parseF2BBanned(`[{'sshd': ['192.0.2.1', '192.0.2.2']}, {'recidive': ['192.0.2.1', '2001:db8::1']}]`); n != 3 {
		t.Errorf("unique: %d", n)
	}
	// A restart restores bans; those are not new.
	log := "2026-10-23 08:00:00,000 fail2ban.actions        [1]: NOTICE  [sshd] Restore Ban 192.0.2.1\n" +
		"2026-10-23 08:00:01,000 fail2ban.actions        [1]: NOTICE  [sshd] Ban 192.0.2.2\n" +
		"2026-10-23 08:00:02,000 fail2ban.actions        [1]: NOTICE  [sshd] Unban 192.0.2.3\n"
	if n := countF2BBans(strings.NewReader(log), time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), time.UTC); n != 1 {
		t.Errorf("restore counted: %d", n)
	}
	if c := fail2banCheck("sec.fail2ban.h", false, nil, 0, 0, "Failed to access socket path"); c.State != eval.Warn || !strings.Contains(c.Summary, "not running") {
		t.Errorf("down: %s %q", c.State, c.Summary)
	}
	if c := fail2banCheck("sec.fail2ban.h", true, []f2bJail{{Name: "recidive"}}, 0, 0, ""); c.State != eval.Warn || c.Summary != "fail2ban runs without an sshd jail" {
		t.Errorf("no sshd: %s %q", c.State, c.Summary)
	}
	if thousands(12045) != "12,045" || thousands(7) != "7" {
		t.Error("thousands")
	}
}
