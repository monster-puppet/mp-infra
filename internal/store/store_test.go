package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/eval"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var t0 = time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC)

func TestSaveReportTransitions(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	tr, err := s.SaveReport(ctx, "a", t0, []byte(`{}`), []Check{{ID: "host.uptime", State: eval.OK, Summary: "up"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 1 || tr[0].OldState != "" || tr[0].NewState != eval.OK {
		t.Fatalf("first report transitions = %+v", tr)
	}
	tr, _ = s.SaveReport(ctx, "a", t0.Add(5*time.Minute), []byte(`{}`), []Check{{ID: "host.uptime", State: eval.OK, Summary: "up"}})
	if len(tr) != 0 {
		t.Fatalf("same state recorded a transition: %+v", tr)
	}
	tr, _ = s.SaveReport(ctx, "a", t0.Add(10*time.Minute), []byte(`{}`), []Check{{ID: "host.uptime", State: eval.Crit, Summary: "down"}})
	if len(tr) != 1 || tr[0].OldState != eval.OK || tr[0].NewState != eval.Crit {
		t.Fatalf("crit transition = %+v", tr)
	}

	c, err := s.Check(ctx, "a", "host.uptime")
	if err != nil || c == nil {
		t.Fatal(c, err)
	}
	if !c.Since.Equal(t0.Add(10*time.Minute)) || !c.UpdatedAt.Equal(t0.Add(10*time.Minute)) {
		t.Errorf("since %s updated %s", c.Since, c.UpdatedAt)
	}
	all, _ := s.Transitions(ctx, "a", "", 10)
	if len(all) != 2 || all[0].NewState != eval.Crit {
		t.Errorf("transitions = %+v", all)
	}
	if other, _ := s.Transitions(ctx, "b", "", 10); len(other) != 0 {
		t.Errorf("host filter leaked: %+v", other)
	}
	last, _ := s.LastReports(ctx)
	if !last["a"].Equal(t0.Add(10 * time.Minute)) {
		t.Errorf("last report = %s", last["a"])
	}
}

func TestMarkStaleSkipsServerChecks(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	s.SaveReport(ctx, "a", t0, []byte(`{}`), []Check{{ID: "host.uptime", State: eval.OK}})
	s.PutCheck(ctx, Check{Host: "a", ID: "ts.online.a", State: eval.OK}, t0)

	tr, err := s.MarkStale(ctx, "a", t0.Add(time.Hour), func(id string) bool { return !eval.ServerOwned(id) })
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 1 || tr[0].CheckID != "host.uptime" || tr[0].NewState != eval.Stale {
		t.Fatalf("transitions = %+v", tr)
	}
	if tr, _ := s.MarkStale(ctx, "a", t0.Add(2*time.Hour), func(string) bool { return true }); len(tr) != 1 || tr[0].CheckID != "ts.online.a" {
		t.Fatalf("second sweep = %+v", tr)
	}
	tr, _ = s.SaveReport(ctx, "a", t0.Add(3*time.Hour), []byte(`{}`), []Check{{ID: "host.uptime", State: eval.OK}})
	if len(tr) != 1 || tr[0].OldState != eval.Stale || tr[0].NewState != eval.OK {
		t.Fatalf("recovery = %+v", tr)
	}
}

func TestAck(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	s.SaveReport(ctx, "a", t0, []byte(`{}`), []Check{{ID: "x", State: eval.Warn}})

	if err := s.Ack(ctx, "a", "x", eval.Crit, t0.Add(time.Hour), "m", "", t0); err == nil {
		t.Error("ack of a state the check is not in succeeded")
	}
	if err := s.Ack(ctx, "a", "x", eval.Warn, t0.Add(time.Hour), "marcus", "accepted", t0); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Check(ctx, "a", "x")
	if !c.Acked(t0.Add(30*time.Minute)) || c.Acked(t0.Add(2*time.Hour)) || c.AckBy != "marcus" {
		t.Errorf("ack = %+v", c)
	}
	// A state change clears the acknowledgement.
	s.SaveReport(ctx, "a", t0.Add(time.Minute), []byte(`{}`), []Check{{ID: "x", State: eval.Crit}})
	c, _ = s.Check(ctx, "a", "x")
	if c.Acked(t0.Add(2 * time.Minute)) {
		t.Error("ack survived a state change")
	}
}

func TestSeenBaselineKV(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	m, err := s.SyncSeen(ctx, "a", "os", []string{"x", "y"}, t0)
	if err != nil || len(m) != 2 {
		t.Fatal(m, err)
	}
	m, _ = s.SyncSeen(ctx, "a", "os", []string{"y", "z"}, t0.Add(time.Hour))
	if len(m) != 2 || !m["y"].Equal(t0) || !m["z"].Equal(t0.Add(time.Hour)) {
		t.Fatalf("seen = %v", m)
	}

	if _, _, ok, _ := s.Baseline(ctx, "a", "fw"); ok {
		t.Error("baseline before set")
	}
	s.SetBaseline(ctx, "a", "fw", "h1", "auto", t0)
	if v, _, ok, _ := s.Baseline(ctx, "a", "fw"); !ok || v != "h1" {
		t.Errorf("baseline = %q", v)
	}

	s.Set(ctx, "k", "v")
	if v, _ := s.Get(ctx, "k"); v != "v" {
		t.Errorf("kv = %q", v)
	}
	if v, _ := s.Get(ctx, "missing"); v != "" {
		t.Errorf("missing kv = %q", v)
	}
}

func TestAlertsPruneBackup(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if at, _ := s.LastAlert(ctx, "a", "x"); !at.IsZero() {
		t.Error("alert before any sent")
	}
	s.RecordAlert(ctx, Alert{Host: "a", CheckID: "x", Channel: "slack", Kind: eval.Problem, At: t0})
	if at, _ := s.LastAlert(ctx, "a", "x"); !at.Equal(t0) {
		t.Errorf("last alert = %s", at)
	}

	s.SaveReport(ctx, "a", t0, []byte(`{}`), nil)
	s.SaveReport(ctx, "a", t0.Add(100*24*time.Hour), []byte(`{}`), nil)
	if n, _ := s.PruneReports(ctx, t0.Add(90*24*time.Hour)); n != 1 {
		t.Errorf("pruned %d", n)
	}

	dst := filepath.Join(t.TempDir(), "b.db")
	for i := 0; i < 2; i++ { // second run replaces the first copy
		if err := s.Backup(ctx, dst); err != nil {
			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(dst); err != nil || fi.Size() == 0 {
		t.Fatal(fi, err)
	}
}
