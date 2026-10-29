package eval

import (
	"testing"
	"time"
)

func TestWorst(t *testing.T) {
	cases := []struct{ a, b, want State }{
		{OK, OK, OK},
		{"", OK, OK},
		{OK, Warn, Warn},
		{Warn, OK, Warn},
		{Warn, Crit, Crit},
		{Stale, Warn, Stale},
		{Stale, Crit, Crit},
		{Crit, Stale, Crit},
	}
	for _, c := range cases {
		if got := Worst(c.a, c.b); got != c.want {
			t.Errorf("Worst(%s, %s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestValid(t *testing.T) {
	for s, want := range map[State]bool{OK: true, Warn: true, Crit: true, Stale: false, "": false, "OK": false} {
		if s.Valid() != want {
			t.Errorf("%q.Valid() = %v", s, !want)
		}
	}
}

func TestIsStale(t *testing.T) {
	now := time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC)
	cases := []struct {
		last time.Time
		want bool
	}{
		{time.Time{}, true},
		{now.Add(-time.Minute), false},
		{now.Add(-15 * time.Minute), false},
		{now.Add(-15*time.Minute - time.Second), true},
	}
	for _, c := range cases {
		if got := IsStale(c.last, now, 15*time.Minute); got != c.want {
			t.Errorf("IsStale(%s) = %v", c.last, got)
		}
	}
}

func TestThresholds(t *testing.T) {
	higher := []struct {
		v, warn, crit float64
		want          State
	}{
		{79, 80, 90, OK},
		{80, 80, 90, Warn},
		{89.9, 80, 90, Warn},
		{90, 80, 90, Crit},
		{99, 0, 90, Crit},
		{85, 0, 90, OK},
	}
	for _, c := range higher {
		if got := Higher(c.v, c.warn, c.crit); got != c.want {
			t.Errorf("Higher(%v, %v, %v) = %s, want %s", c.v, c.warn, c.crit, got, c.want)
		}
	}
	lower := []struct {
		v, warn, crit float64
		want          State
	}{
		{30, 21, 7, OK},
		{21, 21, 7, OK},
		{20, 21, 7, Warn},
		{6.9, 21, 7, Crit},
		{-1, 21, 7, Crit},
	}
	for _, c := range lower {
		if got := Lower(c.v, c.warn, c.crit); got != c.want {
			t.Errorf("Lower(%v, %v, %v) = %s, want %s", c.v, c.warn, c.crit, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		old, new State
		want     AlertKind
	}{
		{"", OK, NoAlert},
		{"", Warn, NoAlert},
		{"", Crit, Problem},
		{"", Stale, Problem},
		{OK, Warn, NoAlert},
		{Warn, OK, NoAlert},
		{OK, Crit, Problem},
		{Warn, Stale, Problem},
		{Crit, Stale, Problem},
		{Stale, Crit, Problem},
		{Crit, OK, Recovery},
		{Stale, Warn, Recovery},
		{Crit, Crit, NoAlert},
	}
	for _, c := range cases {
		if got := Classify(c.old, c.new); got != c.want {
			t.Errorf("Classify(%q, %q) = %q, want %q", c.old, c.new, got, c.want)
		}
	}
}

func TestServerOwned(t *testing.T) {
	for id, want := range map[string]bool{
		"ts.online.jenkins-win":       true,
		"jenkins.agent.windows":       true,
		"win.breakglass_job":          true,
		"report.fresh":                true,
		"app.timelog":                 true,
		"win.tailscale_service":       false,
		"host.uptime":                 false,
		"p4.checkpoint":               false,
		"os.security_updates.jenkins": false,
		"tsx.something":               false,
	} {
		if ServerOwned(id) != want {
			t.Errorf("ServerOwned(%q) = %v", id, !want)
		}
	}
}

func TestAckLimit(t *testing.T) {
	if AckLimit(OK) != 0 || AckLimit(Crit) != 24*time.Hour || AckLimit(Stale) != 24*time.Hour || AckLimit(Warn) <= 24*time.Hour {
		t.Error("unexpected ack limits")
	}
}
