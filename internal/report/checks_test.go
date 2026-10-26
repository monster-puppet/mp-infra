package report

// These tests exercise the rules of each collector with small inline inputs in the
// documented format of each source. They are not captured host output: fixtures
// captured from the real hosts belong in testdata/ (see testdata/README.md).

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

func data(t *testing.T, c Check) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(c.Data, &m); err != nil {
		t.Fatalf("%s data: %v", c.ID, err)
	}
	return m
}

func TestUptime(t *testing.T) {
	s, err := parseProcUptime("90061.50 12.00\n")
	if err != nil || s != 90061.5 {
		t.Fatal(s, err)
	}
	if _, err := parseProcUptime(""); err == nil {
		t.Error("empty input accepted")
	}
	if c := uptimeCheck(s); c.Summary != "up 1d 1h" || c.State != eval.OK {
		t.Errorf("%+v", c)
	}
}

func TestHuman(t *testing.T) {
	for d, want := range map[time.Duration]string{
		42 * time.Second:            "42s",
		5 * time.Minute:             "5m",
		2*time.Hour + 3*time.Minute: "2h 3m",
		50 * time.Hour:              "2d 2h",
		-90 * time.Second:           "1m",
	} {
		if got := Human(d); got != want {
			t.Errorf("Human(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestDisk(t *testing.T) {
	for in, want := range map[string]string{"/": "disk.h.root", "/var/lib": "disk.h.var-lib", `C:\`: "disk.h.c", "/p4": "disk.h.p4"} {
		if got := diskID("h", in); got != want {
			t.Errorf("diskID(%q) = %q", in, got)
		}
	}
	cases := []struct {
		total, free uint64
		want        eval.State
	}{
		{100, 30, eval.OK},
		{100, 20, eval.Warn},
		{100, 10, eval.Crit},
		{0, 0, eval.Warn},
	}
	for _, c := range cases {
		if got := diskCheck("disk.h.root", "/", c.total, c.free, 80, 90); got.State != c.want {
			t.Errorf("disk %d/%d = %s, want %s", c.free, c.total, got.State, c.want)
		}
	}
	if got := bytesHuman(3 << 30); got != "3.0 GiB" {
		t.Errorf("bytesHuman = %q", got)
	}
}

func TestCheckpoint(t *testing.T) {
	now := time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC)
	ok := "2026-10-22T02:05:01 start\ncontinuation line without a timestamp\n2026-10-22T02:05:42 end\n"
	if c := evalCheckpoint(ok, now.Add(-12*time.Hour), 26*time.Hour, now); c.State != eval.OK {
		t.Errorf("fresh run: %+v", c)
	}
	if c := evalCheckpoint(ok, now.Add(-27*time.Hour), 26*time.Hour, now); c.State != eval.Crit || !strings.Contains(c.Summary, "no checkpoint") {
		t.Errorf("old run: %+v", c)
	}
	aborted := "2026-10-22T02:05:01 start\nAborting checkpoint\n"
	c := evalCheckpoint(aborted, now.Add(-time.Hour), 26*time.Hour, now)
	if c.State != eval.Crit || data(t, c)["aborting"] != "Aborting checkpoint" {
		t.Errorf("aborted: %+v", c)
	}
	if data(t, c)["last_entry"] != "2026-10-22T02:05:01 start" {
		t.Errorf("last_entry = %v", data(t, c)["last_entry"])
	}

	// Through the file, as the collector reads it.
	p := filepath.Join(t.TempDir(), "checkpoint.log")
	os.WriteFile(p, []byte(ok), 0o600)
	if c, err := checkpointCheck(p, 26*time.Hour, time.Now()); err != nil || c.State != eval.OK {
		t.Errorf("file: %+v %v", c, err)
	}
	if _, err := checkpointCheck(p+".missing", 26*time.Hour, time.Now()); err == nil {
		t.Error("missing log did not fail")
	}
}

func TestTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("0123456789"), 0o600)
	if s, _ := tail(p, 4); s != "6789" {
		t.Errorf("tail = %q", s)
	}
	if s, _ := tail(p, 100); s != "0123456789" {
		t.Errorf("tail = %q", s)
	}
}

func TestOfflineDB(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	if c, _ := offlineDBCheck(dir, 26*time.Hour, now); c.State != eval.Crit {
		t.Errorf("empty dir: %+v", c)
	}
	os.WriteFile(filepath.Join(dir, "db.counters"), nil, 0o600)
	if c, _ := offlineDBCheck(dir, 26*time.Hour, now); c.State != eval.OK {
		t.Errorf("fresh: %+v", c)
	}
	if c := evalOfflineDB(3, now.Add(-30*time.Hour), 26*time.Hour, now); c.State != eval.Crit {
		t.Errorf("old: %+v", c)
	}
}

func TestLicence(t *testing.T) {
	noise := "Enter password:\nUser perforce logged in.\n"
	c, err := licenceCheck(noise + "... userCount 4\n... userLimit 5\n... clientCount 30\n... clientLimit 20\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.State != eval.Warn || c.Summary != "4/5 users, 30/20 clients (at limit)" {
		t.Errorf("%+v", c)
	}
	c, _ = licenceCheck("... userCount 4\n... userLimit unlimited\n")
	if c.State != eval.OK || c.Summary != "4 users" {
		t.Errorf("unlimited: %+v", c)
	}
	if _, err := licenceCheck(noise); err == nil {
		t.Error("noise only accepted")
	}
	if _, err := licenceCheck("... other 1\n"); err == nil {
		t.Error("no counts accepted")
	}
}

func TestFirewall(t *testing.T) {
	a := firewallCheck("fw.rules.h", "public\n  services: ssh\n")
	b := firewallCheck("fw.rules.h", "public\r\n  services: ssh\r\n\r\n")
	if data(t, a)["hash"] != data(t, b)["hash"] {
		t.Error("line endings changed the hash")
	}
	c := firewallCheck("fw.rules.h", "public\n  services: ssh http\n")
	if data(t, a)["hash"] == data(t, c)["hash"] {
		t.Error("different rules, same hash")
	}
}

func TestSecurityUpdates(t *testing.T) {
	dnf := "Last metadata expiration check: 0:01:00 ago.\n" +
		"RLSA-2026:1001 Important/Sec. pkg-a-1.0-1.el8.x86_64\n" +
		"RLSA-2026:1001 Important/Sec. pkg-b-1.0-1.el8.x86_64\n" +
		"FEDORA-EPEL-2026-abc Moderate/Sec. pkg-c-2.0-1.el8.x86_64\n" +
		"ALSA-2026:7 Low/Sec. pkg-d-1-1.el8.noarch\n"
	got := parseDnfSecurity(dnf)
	if len(got) != 2 || got[0].Key != "RLSA-2026:1001" || got[1].Key != "ALSA-2026:7" {
		t.Errorf("dnf = %+v", got)
	}

	apt := "Listing...\n" +
		"pkg-a/noble-updates,noble-security 1.2 amd64 [upgradable from: 1.1]\n" +
		"pkg-b/noble-updates 2.0 amd64 [upgradable from: 1.9]\n"
	if got := parseAptUpgradable(apt); len(got) != 1 || got[0].Key != "pkg-a/1.2" {
		t.Errorf("apt = %+v", got)
	}

	win, err := parseWindowsUpdates(`[{"Id":"u-1","Title":"Cumulative Update"},{"Id":"","Title":"x"}]`)
	if err != nil || len(win) != 1 || win[0].Key != "u-1" {
		t.Errorf("windows = %+v %v", win, err)
	}
	if win, err := parseWindowsUpdates(""); err != nil || len(win) != 0 {
		t.Errorf("empty windows = %+v %v", win, err)
	}
	if _, err := parseWindowsUpdates("not json"); err == nil {
		t.Error("bad windows output accepted")
	}

	many := make([]Update, 150)
	c := updatesCheck("os.security_updates.h", "dnf", many)
	if d := data(t, c); d["count"].(float64) != 150 || len(d["items"].([]any)) != maxUpdates {
		t.Errorf("cap: %v", d["count"])
	}
}

func TestVersion(t *testing.T) {
	v := config.Version{Name: "p4d", Pattern: `Rev\. P4D/[^/]+/(\d{4}\.\d)/`, Min: "2024.1"}
	c, err := versionCheck("pkg.version.p4d", v, "Rev. P4D/LINUX26X86_64/2023.2/2519561 (2023/12/01).\n")
	if err != nil || c.State != eval.Warn || !strings.Contains(c.Summary, "2023.2") {
		t.Errorf("%+v %v", c, err)
	}
	if _, err := versionCheck("pkg.version.p4d", v, "nothing"); err == nil {
		t.Error("no match accepted")
	}
	c, _ = versionCheck("pkg.version.php", config.Version{Name: "php", Min: "8.1"}, "8.2.10\nmore\n")
	if c.State != eval.OK || c.Summary != "php 8.2.10" {
		t.Errorf("%+v", c)
	}

	cases := []struct {
		a, b string
		want int
	}{
		{"2024.1", "2023.2", 1},
		{"2023.2", "2023.2", 0},
		{"2.462.3", "2.479", -1},
		{"8.2", "8.2.0", 0},
		{"10", "9", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d", c.a, c.b, got)
		}
	}
}

func TestAuth(t *testing.T) {
	af := &config.AuthFailures{Warn: 3, Sources: []config.AuthSource{
		{Name: "ssh", Pattern: `Failed password .* from (?P<ip>\S+)`},
		{Name: "rdp", Pattern: `^(?P<ip>\d+\.\d+\.\d+\.\d+)$`},
	}}
	outs := []string{
		"Failed password for root from 192.0.2.1 port 22\nAccepted publickey\nFailed password for x from 192.0.2.1 port 1\n",
		"198.51.100.7\n",
	}
	c := evalAuth("auth.failures.h", af, outs, []error{nil, nil}, now)
	d := data(t, c)
	if c.State != eval.Warn || d["total"].(float64) != 3 {
		t.Errorf("%+v", c)
	}
	if top := d["top_ips"].([]any); top[0].(map[string]any)["ip"] != "192.0.2.1" {
		t.Errorf("top = %v", top)
	}
	c = evalAuth("auth.failures.h", &config.AuthFailures{Sources: af.Sources[:1]}, []string{""}, []error{errors.New("boom")}, now)
	if c.State != eval.Warn || !strings.Contains(c.Summary, "1 source(s) failed") {
		t.Errorf("failed source: %+v", c)
	}
}

func failureActions(actions ...uint32) string {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(actions)))
	for _, a := range actions {
		b = binary.LittleEndian.AppendUint32(b, a)
		b = binary.LittleEndian.AppendUint32(b, 60000)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestTailscaleService(t *testing.T) {
	cases := []struct {
		svc  winService
		want eval.State
	}{
		{winService{"Running", "Auto", failureActions(1, 1, 0)}, eval.OK},
		{winService{"Running", "Manual", failureActions(1)}, eval.Crit},
		{winService{"Stopped", "Auto", failureActions(1)}, eval.Crit},
		{winService{"Running", "Auto", failureActions(0)}, eval.Crit},
		{winService{"Running", "Auto", ""}, eval.Crit},
		{winService{}, eval.Crit},
	}
	for _, tc := range cases {
		b, _ := json.Marshal(tc.svc)
		c, err := evalTailscaleService(string(b))
		if err != nil || c.State != tc.want {
			t.Errorf("%+v: %+v %v", tc.svc, c, err)
		}
	}
	if _, err := evalTailscaleService("garbage"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestFirewallAny(t *testing.T) {
	out := `[{"Name":"CoreNet-X","DisplayName":"Core","Protocol":"UDP","LocalPort":"68"},{"Name":"RDP-Open","DisplayName":"RDP","Protocol":"TCP","LocalPort":"3389"}]`
	c, err := evalFirewallAny(out, []string{"CoreNet-X"})
	if err != nil || c.State != eval.Crit || !strings.Contains(c.Summary, "RDP") {
		t.Errorf("%+v %v", c, err)
	}
	c, _ = evalFirewallAny(out, []string{"CoreNet-X", "RDP-Open"})
	if c.State != eval.OK {
		t.Errorf("all accepted: %+v", c)
	}
	if c, err := evalFirewallAny("", nil); err != nil || c.State != eval.OK {
		t.Errorf("empty: %+v %v", c, err)
	}
}

func TestCollectReportsCollectorFailure(t *testing.T) {
	cfg := &config.Agent{Host: "h", DiskWarnPct: 80, DiskCritPct: 90,
		Checkpoint: &config.FileAge{Path: filepath.Join(t.TempDir(), "missing.log"), MaxAge: time.Hour}}
	p := Collect(context.Background(), cfg, "test")
	var found bool
	for _, c := range p.Checks {
		if c.ID == "p4.checkpoint" {
			found = true
			if c.State != eval.Crit || !strings.HasPrefix(c.Summary, "collector failed") {
				t.Errorf("%+v", c)
			}
		}
	}
	if !found {
		t.Error("no p4.checkpoint check")
	}
	if err := p.Validate(time.Now()); err != nil {
		t.Errorf("collected payload does not validate: %v", err)
	}
}

func TestSSHAuth(t *testing.T) {
	// `sshd -T` prints every keyword, lowercase, one per line; "port" once per port.
	base := "port 22\npermitrootlogin prohibit-password\npubkeyauthentication yes\n" +
		"gssapiauthentication yes\nusepam yes\nauthenticationmethods any\n"
	for _, tc := range []struct {
		name, extra, mode string
		state             eval.State
		summary           string
	}{
		{"keys only", "passwordauthentication no\nkbdinteractiveauthentication no\n", "key", eval.OK, "SSH on 22: keys only, root by key"},
		{"passwords", "passwordauthentication yes\nkbdinteractiveauthentication no\n", "password", eval.Warn, "SSH on 22 accepts passwords"},
		{"keyboard-interactive", "passwordauthentication no\nkbdinteractiveauthentication yes\n", "password", eval.Warn, "SSH on 22 accepts passwords"},
		{"old openssh", "passwordauthentication no\nchallengeresponseauthentication yes\n", "password", eval.Warn, "SSH on 22 accepts passwords"},
		{"root by password", "passwordauthentication yes\nkbdinteractiveauthentication no\npermitrootlogin yes\n", "password", eval.Crit, "SSH on 22 accepts passwords, root included"},
		{"key then password", "passwordauthentication yes\nkbdinteractiveauthentication no\nauthenticationmethods publickey,password\n", "key", eval.OK, "SSH on 22: keys only, root by key"},
		{"key or password", "passwordauthentication yes\nkbdinteractiveauthentication no\nauthenticationmethods publickey password\n", "password", eval.Warn, "SSH on 22 accepts passwords"},
		{"no way in", "pubkeyauthentication no\npasswordauthentication no\nkbdinteractiveauthentication no\n", "none", eval.OK, "SSH on 22: no key or password login"},
	} {
		// The first value of a keyword wins, as in sshd_config, so the case's
		// lines go first.
		c, err := sshAuthCheck("ssh.auth.h", tc.extra+base)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if c.State != tc.state || c.Summary != tc.summary || data(t, c)["mode"] != tc.mode {
			t.Errorf("%s: %s %q %v", tc.name, c.State, c.Summary, data(t, c)["mode"])
		}
	}
	c, err := sshAuthCheck("ssh.auth.h", "port 22\nport 2222\npubkeyauthentication yes\npasswordauthentication no\n")
	if err != nil || c.Summary != "SSH on 22, 2222: keys only" {
		t.Errorf("two ports: %q %v", c.Summary, err)
	}
	if _, err := sshAuthCheck("ssh.auth.h", "sshd: no hostkeys available -- exiting.\n"); err == nil {
		t.Error("garbage output passed")
	}
}

func TestSSHAuthCaptured(t *testing.T) {
	// Both hosts: keys only, PermitRootLogin prohibit-password, which sshd -T prints
	// as "without-password". monster-p4 runs OpenSSH 8.0 (challengeresponse and
	// kbdinteractive), jenkins 8.7 (kbdinteractive only).
	for _, f := range []string{"sshd_T_monster-p4.txt", "sshd_T_jenkins.txt"} {
		b, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		c, err := sshAuthCheck("ssh.auth.h", string(b))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		d := data(t, c)
		if c.State != eval.OK || c.Summary != "SSH on 22: keys only, root by key" ||
			d["mode"] != "key" || d["password"] != false || d["permit_root_login"] != "without-password" {
			t.Errorf("%s: %s %q %v", f, c.State, c.Summary, d)
		}
	}
}

func TestDefender(t *testing.T) {
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	status := `"RealTimeProtectionEnabled":%s,"AntivirusSignatureLastUpdated":%q,"IsTamperProtected":true`
	fresh := "2026-10-25T21:00:00.0000000Z"
	for _, tc := range []struct {
		name, out string
		state     eval.State
		want      string
	}{
		{"none", `{"Detections":[],` + fmt.Sprintf(status, "true", fresh) + `}`,
			eval.OK, "Defender on, signatures 12h 0m old, no detections in 7 days"},
		{"own exe", `{"Detections":{"Time":"2026-10-25T21:24:00.0000000Z","Threat":"Trojan:Win32/Bearfoos.A!ml",` +
			`"Resources":["file:_C:\\ProgramData\\mp-infra\\mpinfra.exe","taskscheduler:_C:\\Windows\\System32\\Tasks\\mp-infra-report"],` +
			`"ActionSuccess":true},` + fmt.Sprintf(status, "true", fresh) + `}`,
			eval.Crit, `Defender quarantined the mp-infra agent: Trojan:Win32/Bearfoos.A!ml in C:\ProgramData\mp-infra\mpinfra.exe`},
		{"detection", `{"Detections":[{"Time":"2026-10-24T10:00:00Z","Threat":"PUA:Win32/Example",` +
			`"Resources":"file:_C:\\Users\\builder\\Downloads\\tool.exe","ActionSuccess":false}],` + fmt.Sprintf(status, "true", fresh) + `}`,
			eval.Crit, `Defender: 1 detection(s) in 7 days, latest PUA:Win32/Example in C:\Users\builder\Downloads\tool.exe (action failed)`},
		{"rtp off", `{"Detections":null,` + fmt.Sprintf(status, "false", fresh) + `}`,
			eval.Warn, "Defender real-time protection off"},
		{"old signatures", `{"Detections":[],` + fmt.Sprintf(status, "true", "2026-10-21T09:00:00Z") + `}`,
			eval.Warn, "Defender signatures 5d 0h old"},
		{"no signature date", `{"Detections":[],` + fmt.Sprintf(status, "true", "") + `}`,
			eval.Warn, "Defender signature age unknown"},
	} {
		c, err := evalDefender("av.defender.jenkins-win", tc.out, now)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if c.ID != "av.defender.jenkins-win" || c.State != tc.state || c.Summary != tc.want {
			t.Errorf("%s: %s %s %q, want %s %q", tc.name, c.ID, c.State, c.Summary, tc.state, tc.want)
		}
	}
	if _, err := evalDefender("av.defender.x", "not json", now); err == nil {
		t.Error("bad output accepted")
	}

	// Lists are capped at 50 and strings clipped.
	var b strings.Builder
	b.WriteString(`{"Detections":[`)
	for i := 0; i < 60; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"Time":"2026-10-25T00:00:00Z","Threat":%q,"Resources":["file:_C:\\x.exe"],"ActionSuccess":true}`, strings.Repeat("T", 500))
	}
	b.WriteString(`],` + fmt.Sprintf(status, "true", fresh) + `}`)
	c, err := evalDefender("av.defender.x", b.String(), now)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Detections []struct {
			Threat string `json:"threat"`
		} `json:"detections"`
	}
	if err := json.Unmarshal(c.Data, &d); err != nil || len(d.Detections) != 50 || len(d.Detections[0].Threat) != 200 {
		t.Errorf("caps: %d detections, %v", len(d.Detections), err)
	}
	if len(c.Summary) > MaxSummary {
		t.Errorf("summary too long: %d", len(c.Summary))
	}
}
