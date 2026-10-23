package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/alert"
	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/probe"
	"github.com/monster-puppet/mp-infra/internal/report"
	"github.com/monster-puppet/mp-infra/internal/store"
)

var t0 = time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC)

type sink struct {
	mu   sync.Mutex
	msgs []alert.Message
}

func (s *sink) Name() string { return "test" }
func (s *sink) Send(_ context.Context, m alert.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, m)
	return nil
}

func setup(t *testing.T, hosts ...config.Host) (*Server, *sink, *time.Time) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Server{Hosts: hosts, StaleAfter: 15 * time.Minute, DB: filepath.Join(t.TempDir(), "s.db")}
	cfg.ApplyDefaults()
	clock := t0
	s := New(cfg, st, config.Tokens{}, "test")
	s.Now = func() time.Time { return clock }
	s.started = t0
	snk := &sink{}
	s.Alerter.Senders = []alert.Sender{snk}
	return s, snk, &clock
}

func payload(host string, checks ...report.Check) *report.Payload {
	return &report.Payload{Host: host, AgentVersion: "1", CollectedAt: t0, Checks: checks}
}

func TestSweepStale(t *testing.T) {
	s, snk, clock := setup(t, config.Host{Name: "a"}, config.Host{Name: "b"}, config.Host{Name: "c", NoReport: true})
	ctx := context.Background()
	if err := s.Ingest(ctx, "a", []byte(`{}`), payload("a", report.Check{ID: "host.uptime", State: eval.OK})); err != nil {
		t.Fatal(err)
	}
	s.Store.PutCheck(ctx, store.Check{Host: "a", ID: "ts.online.a", State: eval.OK}, t0)

	// Within stale_after of startup nothing is swept.
	*clock = t0.Add(10 * time.Minute)
	s.Sweep(ctx)
	if len(snk.msgs) != 0 {
		t.Fatalf("swept during startup grace: %+v", snk.msgs)
	}

	*clock = t0.Add(16 * time.Minute)
	s.Sweep(ctx)
	got := map[string]eval.State{}
	checks, _ := s.Store.Checks(ctx)
	for _, c := range checks {
		got[c.Host+"/"+c.ID] = c.State
	}
	want := map[string]eval.State{
		"a/host.uptime":  eval.Stale,
		"a/report.fresh": eval.Stale,
		"a/ts.online.a":  eval.OK, // probes are not the agent's to make stale
		"b/report.fresh": eval.Stale,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
	if _, ok := got["c/report.fresh"]; ok {
		t.Error("no_report host swept")
	}
	// One message for the sweep, a's stale host.uptime folded into its line.
	if len(snk.msgs) != 1 || snk.msgs[0].Subject != "[STALE] 2 hosts: 2 stopped reporting" {
		t.Errorf("alerts = %+v", snk.msgs)
	}

	// Sweeping again sends nothing new; a fresh report recovers.
	s.Sweep(ctx)
	if len(snk.msgs) != 1 {
		t.Errorf("repeated alerts: %d", len(snk.msgs))
	}
	s.Ingest(ctx, "a", []byte(`{}`), payload("a", report.Check{ID: "host.uptime", State: eval.OK}))
	if len(snk.msgs) != 2 || snk.msgs[1].Subject != "[RECOVERED] a reporting again (1 check back to ok)" {
		t.Errorf("recovery alerts = %+v", snk.msgs)
	}
}

func TestIngestRateLimit(t *testing.T) {
	s, _, clock := setup(t, config.Host{Name: "a"})
	ctx := context.Background()
	if err := s.Ingest(ctx, "a", []byte(`{}`), payload("a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, "a", []byte(`{}`), payload("a")); err != ErrTooSoon {
		t.Errorf("second report: %v", err)
	}
	*clock = t0.Add(31 * time.Second)
	if err := s.Ingest(ctx, "a", []byte(`{}`), payload("a")); err != nil {
		t.Errorf("after interval: %v", err)
	}
}

func updates(keys ...string) report.Check {
	items := make([]report.Update, len(keys))
	for i, k := range keys {
		items[i] = report.Update{Key: k}
	}
	b, _ := json.Marshal(map[string]any{"source": "dnf", "count": len(keys), "items": items})
	return report.Check{ID: "os.security_updates.a", State: eval.OK, Data: b}
}

func TestUpdatesRule(t *testing.T) {
	s, _, clock := setup(t, config.Host{Name: "a"})
	ctx := context.Background()
	state := func() eval.State {
		c, _ := s.Store.Check(ctx, "a", "os.security_updates.a")
		return c.State
	}
	s.Ingest(ctx, "a", []byte(`{}`), payload("a", updates()))
	if state() != eval.OK {
		t.Errorf("none pending: %s", state())
	}
	*clock = t0.Add(time.Hour)
	s.Ingest(ctx, "a", []byte(`{}`), payload("a", updates("RLSA-1")))
	if state() != eval.Warn {
		t.Errorf("new advisory: %s", state())
	}
	*clock = t0.Add(15 * 24 * time.Hour)
	s.Ingest(ctx, "a", []byte(`{}`), payload("a", updates("RLSA-1", "RLSA-2")))
	if state() != eval.Crit {
		t.Errorf("15 days pending: %s", state())
	}
	*clock = t0.Add(16 * 24 * time.Hour)
	s.Ingest(ctx, "a", []byte(`{}`), payload("a", updates("RLSA-2")))
	if state() != eval.Warn {
		t.Errorf("old one installed: %s", state())
	}
}

func TestStatus(t *testing.T) {
	s, _, _ := setup(t, config.Host{Name: "a"})
	ctx := context.Background()
	s.Store.PutCheck(ctx, store.Check{Host: "a", ID: "x", State: eval.Crit}, t0)
	s.Store.PutCheck(ctx, store.Check{Host: "a", ID: "y", State: eval.Warn}, t0)
	s.Store.PutCheck(ctx, store.Check{Host: "a", ID: "z", State: eval.Crit}, t0)
	s.Store.Ack(ctx, "a", "z", eval.Crit, t0.Add(time.Hour), "m", "", t0)
	st, err := s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != eval.Crit || st.Summary != "1 crit, 1 warn" || len(st.Items) != 3 || st.Items[0].Check != "x" {
		t.Errorf("%+v", st)
	}
}

func TestDeadmanAndProbes(t *testing.T) {
	var hits int
	hb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer hb.Close()
	s, _, _ := setup(t, config.Host{Name: "a"})
	ctx := context.Background()
	t.Setenv("DEADMAN", hb.URL)
	s.Cfg.Alerts.DeadmanURLEnv = "DEADMAN"
	s.Deadman(ctx)
	c, _ := s.Store.Check(ctx, config.ServeHost, "serve.self")
	if hits != 1 || c == nil || c.State != eval.OK {
		t.Errorf("deadman: hits %d, %+v", hits, c)
	}

	s.Cfg.TCP = []config.TCPTarget{{Name: "hb", Addr: hb.Listener.Addr().String()}}
	s.ProbeOnce(ctx)
	if c, _ := s.Store.Check(ctx, config.ServeHost, "tcp.hb"); c == nil || c.State != eval.OK {
		t.Errorf("probe not stored: %+v", c)
	}
}

func TestDaily(t *testing.T) {
	s, _, _ := setup(t, config.Host{Name: "a"})
	s.Daily(context.Background())
	if fi, err := os.Stat(s.Cfg.DB + ".backup"); err != nil || fi.Size() == 0 {
		t.Fatalf("no backup: %v", err)
	}
}

func TestBruteForceActive(t *testing.T) {
	s, _, clock := setup(t, config.Host{Name: "a"})
	ctx := context.Background()
	fail := func(total, top int) report.Check {
		d, _ := json.Marshal(map[string]any{"total": total, "top_ips": []map[string]any{{"ip": "203.0.113.5", "count": top}, {"ip": "198.51.100.1", "count": 40}}})
		return report.Check{ID: "auth.failures.a", State: eval.OK, Summary: "n failed logins in 24 h", Data: d}
	}
	get := func() *store.Check {
		c, _ := s.Store.Check(ctx, "a", "auth.failures.a")
		return c
	}
	send := func(c report.Check) {
		t.Helper()
		if err := s.Ingest(ctx, "a", []byte(`{}`), payload("a", c)); err != nil {
			t.Fatal(err)
		}
	}
	send(fail(500, 100))
	if c := get(); c.State != eval.OK {
		t.Fatalf("first report: %+v", c)
	}
	*clock = clock.Add(5 * time.Minute)
	send(fail(510, 105)) // +10: background noise
	if c := get(); c.State != eval.OK || strings.Contains(c.Summary, "active") {
		t.Fatalf("+10: %+v", c)
	}
	*clock = clock.Add(5 * time.Minute)
	send(fail(700, 290)) // +190 in 5 min
	c := get()
	if c.State != eval.Warn || !strings.Contains(c.Summary, "active brute force: 190 failed logins in the last 5 min, mostly from 203.0.113.5") {
		t.Fatalf("+190: %+v", c)
	}
	var d map[string]any
	json.Unmarshal([]byte(c.Data), &d)
	if d["active"] != true || d["recent_ip"] != "203.0.113.5" || d["total"].(float64) != 700 {
		t.Errorf("data: %v", d)
	}
	*clock = clock.Add(5 * time.Minute)
	send(fail(705, 290)) // the attack stopped
	if c := get(); c.State != eval.OK {
		t.Errorf("after attack: %+v", c)
	}
	*clock = clock.Add(time.Hour)
	send(fail(900, 400)) // a big jump after a long gap is not "now"
	if c := get(); c.State != eval.OK {
		t.Errorf("after gap: %+v", c)
	}
}

func TestTailnetLogins(t *testing.T) {
	s, _, _ := setup(t, config.Host{Name: "a"})
	ctx := context.Background()
	devs := []probe.TSDevice{
		// Three devices behind one home NAT: the connected one names the address,
		// by its Tailscale name, not its OS hostname.
		{Name: "localhost", Machine: "marcus-phone", LastSeen: t0, PublicIPs: []string{"203.0.113.7"}},
		{Name: "MarcusLaptop", Machine: "marcus-laptop", Connected: true, LastSeen: t0.Add(-time.Hour), PublicIPs: []string{"203.0.113.7"}},
		{Name: "old-pc", LastSeen: t0.Add(-48 * time.Hour), PublicIPs: []string{"203.0.113.7"}},
		{Name: "jenkins", Tags: []string{"tag:ci-untrusted"}, PublicIPs: []string{"198.51.100.9"}},
	}
	if _, err := s.Store.PutCheck(ctx, store.Check{Host: config.ServeHost, ID: "ts.devices", State: eval.OK,
		Data: string(mustJSON(map[string]any{"devices": devs}))}, t0); err != nil {
		t.Fatal(err)
	}
	logins := func(ips ...string) report.Check {
		var out []report.Login
		for _, ip := range ips {
			out = append(out, report.Login{Source: "ssh", User: "root", IP: ip, Count: 1})
		}
		st, sum := report.LoginsVerdict(t0, len(ips)+2, out, nil, 0)
		d, _ := json.Marshal(map[string]any{"total": len(ips) + 2, "outside": out, "logins": out, "errors": []string{}})
		return report.Check{ID: "auth.logins.a", State: st, Summary: sum, Data: d}
	}
	for i, tc := range []struct {
		ips   []string
		state eval.State
		want  string
	}{
		{[]string{"203.0.113.7"}, eval.OK, "3 logins in 24 h; root from 203.0.113.7, the public address of tailnet device marcus-laptop"},
		{[]string{"::ffff:203.0.113.7", "198.51.100.9"}, eval.Crit, "login from outside the tailnet: root from 198.51.100.9 (ssh)"},
		{[]string{"192.0.2.1"}, eval.Crit, "login from outside the tailnet: root from 192.0.2.1 (ssh)"},
	} {
		s.lastIn = map[string]time.Time{}
		if err := s.Ingest(ctx, "a", []byte(`{}`), payload("a", logins(tc.ips...))); err != nil {
			t.Fatal(err)
		}
		c, _ := s.Store.Check(ctx, "a", "auth.logins.a")
		if c.State != tc.state || c.Summary != tc.want {
			t.Errorf("%d: %s %q", i, c.State, c.Summary)
		}
	}
}
