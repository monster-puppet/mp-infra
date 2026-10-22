package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/alert"
	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
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
	if len(snk.msgs) != 3 {
		t.Errorf("alerts = %d, want 3", len(snk.msgs))
	}

	// Sweeping again sends nothing new; a fresh report recovers.
	s.Sweep(ctx)
	if len(snk.msgs) != 3 {
		t.Errorf("repeated alerts: %d", len(snk.msgs))
	}
	s.Ingest(ctx, "a", []byte(`{}`), payload("a", report.Check{ID: "host.uptime", State: eval.OK}))
	if len(snk.msgs) != 5 {
		t.Errorf("recovery alerts = %d, want 5", len(snk.msgs))
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
