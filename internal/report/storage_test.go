package report

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRAIDCaptured(t *testing.T) {
	// The NAS as captured: data arrays healthy, md3 a single disk, and the system
	// partitions md0/md1 missing their copy on disk 5.
	s := readFixture(t, "synology_mdstat.txt")
	arrays := parseMdstat(s)
	if len(arrays) != 6 || arrays[0].Name != "md4" || arrays[0].Level != "raid5" || arrays[0].Want != 4 || arrays[0].Map != "UUUU" {
		t.Fatalf("parse: %+v", arrays)
	}
	c := raidCheck("raid.nas", s, []string{"md0", "md1"})
	want := "md1 (system partition) 4 of 5 disks; md0 (system partition) 4 of 5 disks"
	if c.State != eval.Warn || !strings.HasPrefix(c.Summary, want) {
		t.Errorf("system arrays: %s %q", c.State, c.Summary)
	}
	// Without the system list the same gap is a degraded array.
	if c := raidCheck("raid.nas", s, nil); c.State != eval.Crit || !strings.Contains(c.Summary, "md0 raid1 degraded, 4 of 5 disks") {
		t.Errorf("no system list: %s %q", c.State, c.Summary)
	}
	// Repaired: healthy, with the one-disk array noted.
	fixed := strings.ReplaceAll(s, "[5/4] [UUUU_]", "[5/5] [UUUUU]")
	if c := raidCheck("raid.nas", fixed, []string{"md0", "md1"}); c.State != eval.OK || c.Summary != "6 arrays healthy; md3 is one disk, no redundancy" {
		t.Errorf("repaired: %s %q", c.State, c.Summary)
	}
}

func TestRAIDStates(t *testing.T) {
	for _, tc := range []struct {
		name, mdstat string
		state        eval.State
		summary      string
	}{
		{"rebuild", "md2 : active raid1 sdb1[2] sda1[0]\n      100 blocks [2/1] [U_]\n      [==>...]  recovery = 12.6% (1/8) finish=10min\n",
			eval.Crit, "md2 raid1 degraded, 1 of 2 disks"},
		{"resync", "md2 : active raid1 sdb1[1] sda1[0]\n      100 blocks [2/2] [UU]\n      [=>....]  resync = 5.0% (1/20)\n",
			eval.Warn, "md2 resync 5%"},
		{"scrub", "md2 : active raid1 sdb1[1] sda1[0]\n      100 blocks [2/2] [UU]\n      [=>....]  check = 40.0% (1/2)\n",
			eval.OK, "1 arrays healthy; md2 scrubbing 40%"},
		{"failed member", "md2 : active raid5 sdc1[2](F) sdb1[1] sda1[0]\n      100 blocks [3/2] [UU_]\n",
			eval.Crit, "md2 raid5 degraded, 2 of 3 disks"},
		{"inactive", "md9 : inactive sda1[0](S)\n      100 blocks\n", eval.Crit, "md9 inactive"},
		{"none", "Personalities : \nunused devices: <none>\n", eval.OK, "no md arrays"},
	} {
		if c := raidCheck("raid.h", tc.mdstat, nil); c.State != tc.state || c.Summary != tc.summary {
			t.Errorf("%s: %s %q", tc.name, c.State, c.Summary)
		}
	}
}

func TestSMARTCaptured(t *testing.T) {
	sata1 := parseSmart("/dev/sata1", readFixture(t, "synology_smart_sata1.txt"))
	if sata1.Health != "PASSED" || sata1.Model != "ST10000VN0004-1ZD101" || sata1.Reallocated != 0 || sata1.Hours != 57166 || sata1.TempC != 34 {
		t.Errorf("sata1: %+v", sata1)
	}
	// IronWolf Pro names attribute 5 Retired_Sectors_Count; matched by number.
	sata4 := parseSmart("/dev/sata4", readFixture(t, "synology_smart_sata4.txt"))
	if sata4.Health != "PASSED" || sata4.Hours != 28815 || sata4.TempC != 40 {
		t.Errorf("sata4: %+v", sata4)
	}
	sata5 := parseSmart("/dev/sata5", readFixture(t, "synology_smart_sata5.txt"))
	if sata5.Reallocated != 8 || len(sata5.FailedPast) != 1 || sata5.FailedPast[0] != "Airflow_Temperature_Cel" || len(sata5.FailingNow) != 0 {
		t.Errorf("sata5: %+v", sata5)
	}
	c := smartCheck("smart.nas", []smartDisk{sata5, sata1, sata4})
	if c.State != eval.Warn || c.Summary != "sata5 8 reallocated sectors" {
		t.Errorf("check: %s %q", c.State, c.Summary)
	}
	if c := smartCheck("smart.nas", []smartDisk{sata1, sata4}); c.State != eval.OK || c.Summary != "2 drives passed" {
		t.Errorf("healthy: %s %q", c.State, c.Summary)
	}
}

func TestSMARTStates(t *testing.T) {
	ok := smartDisk{Device: "/dev/sda", Health: "PASSED"}
	for _, tc := range []struct {
		name    string
		d       smartDisk
		state   eval.State
		summary string
	}{
		{"failed", smartDisk{Device: "/dev/sda", Health: "FAILED!"}, eval.Crit, "sda health FAILED!"},
		{"pending", smartDisk{Device: "/dev/sda", Health: "PASSED", Pending: 3}, eval.Crit, "sda 3 pending, 0 uncorrectable sectors"},
		{"failing now", smartDisk{Device: "/dev/sda", Health: "PASSED", FailingNow: []string{"Reallocated_Sector_Ct"}}, eval.Crit, "sda failing now: Reallocated_Sector_Ct"},
		{"unreadable", smartDisk{Device: "/dev/nvme0n1", Error: "smartctl: exit status 2"}, eval.Warn, "nvme0n1 unreadable"},
		{"ok", ok, eval.OK, "1 drives passed"},
	} {
		if c := smartCheck("smart.h", []smartDisk{tc.d}); c.State != tc.state || c.Summary != tc.summary {
			t.Errorf("%s: %s %q", tc.name, c.State, c.Summary)
		}
	}
	// The NVMe output of DSM's smartctl 6.5: no verdict.
	if d := parseSmart("/dev/nvme0n1", "Read NVMe Identify Controller failed: NVMe Status 0x02\n"); d.Health != "" {
		t.Errorf("nvme: %+v", d)
	}
}

func TestDSMAuthLog(t *testing.T) {
	// DSM's web logins fail in auth.log, which holds weeks: only the last 24 h count.
	log := readFixture(t, "synology_auth_log.txt")
	af := &config.AuthFailures{Sources: []config.AuthSource{
		{Name: "dsm-web", Pattern: `^(?P<time>\S+) .*pam_unix\(webui:auth\): authentication failure;.* rhost=(?P<ip>[0-9a-fA-F.:]+)`},
		{Name: "ssh", Pattern: `^(?P<time>\S+) .*(?:Failed password|Invalid user) .* from (?P<ip>[0-9a-fA-F.:]+)`},
	}}
	for _, src := range af.Sources {
		regexp.MustCompile(src.Pattern)
	}
	at := func(s string) time.Time { tt, _ := time.Parse(time.RFC3339, s); return tt }
	// 2026-10-23 09:00 CEST: the three web failures (22 Oct 13:30) and the one
	// invalid ssh user are within 24 h.
	c := evalAuth("auth.failures.nas", af, []string{log, log}, []error{nil, nil}, at("2026-10-23T09:00:00+02:00"))
	if !strings.HasPrefix(c.Summary, "4 failed logins in 24 h") {
		t.Errorf("within: %s %q", c.State, c.Summary)
	}
	// A day later the web failures have aged out.
	c = evalAuth("auth.failures.nas", af, []string{log, log}, []error{nil, nil}, at("2026-10-23T14:00:00+02:00"))
	if !strings.HasPrefix(c.Summary, "1 failed login") {
		t.Errorf("aged: %s %q", c.State, c.Summary)
	}
	// Failures from an ignored network (the office LAN) are not counted.
	af.IgnoreNets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	c = evalAuth("auth.failures.nas", af, []string{log, log}, []error{nil, nil}, at("2026-10-23T09:00:00+02:00"))
	if !strings.HasPrefix(c.Summary, "0 failed logins in 24 h") || !strings.Contains(string(c.Data), `"ignored":4`) {
		t.Errorf("ignored: %s %q %s", c.State, c.Summary, c.Data)
	}
}
