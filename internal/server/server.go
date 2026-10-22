// Package server is the core of `mpinfra serve`: it ingests reports, applies the
// server-side rules to them, sweeps for stale hosts, runs the probes and drives
// the alerter. HTTP lives in package web.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/monster-puppet/mp-infra/internal/alert"
	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/probe"
	"github.com/monster-puppet/mp-infra/internal/report"
	"github.com/monster-puppet/mp-infra/internal/store"
)

// Server holds everything serve needs.
type Server struct {
	Cfg     *config.Server
	Store   *store.Store
	Tokens  config.Tokens
	Prober  *probe.Prober
	Alerter *alert.Alerter
	Version string
	Now     func() time.Time

	// MinReportInterval rejects reports that come faster than this per host, so a
	// compromised host cannot flood the database.
	MinReportInterval time.Duration

	started time.Time
	mu      sync.Mutex
	lastIn  map[string]time.Time
}

// New wires a Server from a config and an open store.
func New(cfg *config.Server, st *store.Store, tokens config.Tokens, version string) *Server {
	s := &Server{
		Cfg:               cfg,
		Store:             st,
		Tokens:            tokens,
		Prober:            probe.New(cfg, st),
		Version:           version,
		Now:               time.Now,
		MinReportInterval: 30 * time.Second,
		lastIn:            map[string]time.Time{},
	}
	s.Alerter = &alert.Alerter{
		Store:    st,
		Senders:  alert.Senders(cfg.Alerts),
		BaseURL:  cfg.BaseURL,
		Reminder: cfg.Alerts.CritReminder,
		DigestAt: cfg.Alerts.DigestAt,
		Now:      func() time.Time { return s.Now() },
	}
	s.started = s.Now()
	return s
}

// ErrTooSoon is returned by Ingest when a host reports faster than allowed.
var ErrTooSoon = errors.New("report too soon after the previous one")

// Ingest stores a validated report for host, the host the token belongs to.
// The caller has already checked p.Host == host.
func (s *Server) Ingest(ctx context.Context, host string, body []byte, p *report.Payload) error {
	now := s.Now()
	s.mu.Lock()
	if last, ok := s.lastIn[host]; ok && now.Sub(last) < s.MinReportInterval {
		s.mu.Unlock()
		return ErrTooSoon
	}
	s.lastIn[host] = now
	s.mu.Unlock()

	checks := make([]store.Check, 0, len(p.Checks)+1)
	for _, c := range p.Checks {
		sc := store.Check{ID: c.ID, State: c.State, Summary: c.Summary, Data: string(c.Data)}
		if err := s.applyRules(ctx, host, &sc, now); err != nil {
			return err
		}
		checks = append(checks, sc)
	}
	checks = append(checks, store.Check{ID: "report.fresh", State: eval.OK,
		Summary: fmt.Sprintf("agent %s reported %d checks", p.AgentVersion, len(p.Checks)),
		Data:    string(mustJSON(map[string]any{"agent_version": p.AgentVersion, "collected_at": p.CollectedAt}))})
	ts, err := s.Store.SaveReport(ctx, host, now, body, checks)
	if err != nil {
		return err
	}
	s.Alerter.Transitions(ctx, ts)
	return nil
}

// applyRules re-evaluates the checks whose state the server decides from what the
// agent reported.
func (s *Server) applyRules(ctx context.Context, host string, c *store.Check, now time.Time) error {
	switch {
	case strings.HasPrefix(c.ID, "fw.rules."):
		return s.firewallRule(ctx, host, c, now)
	case strings.HasPrefix(c.ID, "os.security_updates."):
		return s.updatesRule(ctx, host, c, now)
	}
	return nil
}

// firewallRule compares the reported rules hash with the accepted one. The first
// hash ever seen is accepted automatically; a change is warn until someone
// accepts it in the UI.
func (s *Server) firewallRule(ctx context.Context, host string, c *store.Check, now time.Time) error {
	var d struct {
		Hash string `json:"hash"`
	}
	if json.Unmarshal([]byte(c.Data), &d) != nil || d.Hash == "" {
		return nil // the collector failed; keep its state
	}
	base, at, ok, err := s.Store.Baseline(ctx, host, c.ID)
	if err != nil {
		return err
	}
	if !ok {
		if err := s.Store.SetBaseline(ctx, host, c.ID, d.Hash, "first report", now); err != nil {
			return err
		}
		c.State, c.Summary = eval.OK, "firewall rules recorded as the accepted baseline"
		return nil
	}
	if base == d.Hash {
		c.State, c.Summary = eval.OK, "firewall rules unchanged since "+at.Local().Format("2006-01-02")
		return nil
	}
	c.State = eval.Warn
	c.Summary = fmt.Sprintf("firewall rules changed (accepted %s is %s, now %s)", at.Local().Format("2006-01-02"), short(base), short(d.Hash))
	return nil
}

// AcceptFirewall accepts the currently reported firewall rules of host.
func (s *Server) AcceptFirewall(ctx context.Context, host, id, by string) error {
	if !strings.HasPrefix(id, "fw.rules.") {
		return fmt.Errorf("%s is not a firewall check", id)
	}
	c, err := s.Store.Check(ctx, host, id)
	if err != nil || c == nil {
		return fmt.Errorf("no check %s/%s", host, id)
	}
	var d struct {
		Hash string `json:"hash"`
	}
	if json.Unmarshal([]byte(c.Data), &d) != nil || d.Hash == "" {
		return errors.New("no firewall hash reported")
	}
	now := s.Now()
	if err := s.Store.SetBaseline(ctx, host, id, d.Hash, by, now); err != nil {
		return err
	}
	c.State, c.Summary = eval.OK, "firewall rules accepted by "+by
	t, err := s.Store.PutCheck(ctx, *c, now)
	if err != nil {
		return err
	}
	if t != nil {
		s.Alerter.Transitions(ctx, []store.Transition{*t})
	}
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// updatesRule sets the state of a security update check from how long each
// update has been pending, counted from when the server first saw it.
func (s *Server) updatesRule(ctx context.Context, host string, c *store.Check, now time.Time) error {
	var d struct {
		Source string          `json:"source"`
		Count  int             `json:"count"`
		Items  []report.Update `json:"items"`
	}
	if json.Unmarshal([]byte(c.Data), &d) != nil || d.Source == "" {
		return nil
	}
	keys := make([]string, 0, len(d.Items))
	for _, it := range d.Items {
		if it.Key != "" && len(it.Key) <= 200 {
			keys = append(keys, it.Key)
		}
	}
	seen, err := s.Store.SyncSeen(ctx, host, c.ID, keys, now)
	if err != nil {
		return err
	}
	if d.Count == 0 && len(keys) == 0 {
		c.State, c.Summary = eval.OK, "no pending security updates"
		return nil
	}
	var oldest time.Time
	for _, t := range seen {
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	age := now.Sub(oldest)
	c.State = eval.Warn
	if age >= s.Cfg.Thresholds.UpdatesCritAge {
		c.State = eval.Crit
	}
	c.Summary = fmt.Sprintf("%d pending security updates, oldest pending %s", d.Count, report.Human(age))
	return nil
}

// Sweep marks hosts that stopped reporting as stale. For the first stale_after
// after startup it does nothing, so a restart does not page for every host.
func (s *Server) Sweep(ctx context.Context) error {
	now := s.Now()
	if now.Sub(s.started) < s.Cfg.StaleAfter {
		return nil
	}
	last, err := s.Store.LastReports(ctx)
	if err != nil {
		return err
	}
	var all []store.Transition
	for _, h := range s.Cfg.Hosts {
		if h.NoReport || !eval.IsStale(last[h.Name], now, s.Cfg.StaleAfter) {
			continue
		}
		summary := "never reported"
		if !last[h.Name].IsZero() {
			summary = "no report for " + report.Human(now.Sub(last[h.Name]))
		}
		t, err := s.Store.PutCheck(ctx, store.Check{Host: h.Name, ID: "report.fresh", State: eval.Stale, Summary: summary}, now)
		if err != nil {
			return err
		}
		if t != nil {
			all = append(all, *t)
		}
		ts, err := s.Store.MarkStale(ctx, h.Name, now, func(id string) bool { return !eval.ServerOwned(id) })
		if err != nil {
			return err
		}
		all = append(all, ts...)
	}
	s.Alerter.Transitions(ctx, all)
	return nil
}

// ProbeOnce runs every probe and stores the results.
func (s *Server) ProbeOnce(ctx context.Context) {
	now := s.Now()
	var all []store.Transition
	for _, c := range s.Prober.Run(ctx) {
		if !eval.CheckID.MatchString(c.ID) {
			log.Printf("probe returned invalid check id %q", c.ID)
			continue
		}
		t, err := s.Store.PutCheck(ctx, store.Check{Host: c.Host, ID: c.ID, State: c.State, Summary: c.Summary, Data: string(mustJSON(c.Data))}, now)
		if err != nil {
			log.Printf("store probe %s/%s: %v", c.Host, c.ID, err)
			continue
		}
		if t != nil {
			all = append(all, *t)
		}
	}
	s.Alerter.Transitions(ctx, all)
}

// Deadman pings the heartbeat URL and records the result as serve.self.
func (s *Server) Deadman(ctx context.Context) {
	u := config.Env(s.Cfg.Alerts.DeadmanURLEnv)
	if u == "" {
		return
	}
	c := store.Check{Host: config.ServeHost, ID: "serve.self", State: eval.OK, Summary: "dead-man heartbeat sent"}
	if err := alert.Ping(ctx, u); err != nil {
		// warn, not crit: the heartbeat service emails us itself if pings stop.
		c.State, c.Summary = eval.Warn, err.Error()
	}
	t, err := s.Store.PutCheck(ctx, c, s.Now())
	if err == nil && t != nil {
		s.Alerter.Transitions(ctx, []store.Transition{*t})
	}
}

// Retention is how long raw reports are kept.
const Retention = 90 * 24 * time.Hour

// Daily prunes old reports and writes the VACUUM INTO backup next to the DB.
func (s *Server) Daily(ctx context.Context) {
	if n, err := s.Store.PruneReports(ctx, s.Now().Add(-Retention)); err != nil {
		log.Printf("prune reports: %v", err)
	} else if n > 0 {
		log.Printf("pruned %d reports older than 90 days", n)
	}
	if err := s.Store.Backup(ctx, s.Cfg.DB+".backup"); err != nil {
		log.Printf("backup: %v", err)
	}
}

// Run drives the periodic work until ctx ends.
func (s *Server) Run(ctx context.Context) {
	go every(ctx, time.Minute, func() {
		if err := s.Sweep(ctx); err != nil {
			log.Printf("sweep: %v", err)
		}
		if err := s.Alerter.Reminders(ctx); err != nil {
			log.Printf("reminders: %v", err)
		}
		if err := s.Alerter.Digest(ctx); err != nil {
			log.Printf("digest: %v", err)
		}
	})
	go every(ctx, s.Cfg.ProbeInterval, func() { s.ProbeOnce(ctx) })
	go every(ctx, 5*time.Minute, func() { s.Deadman(ctx) })
	go every(ctx, 24*time.Hour, func() { s.Daily(ctx) })
	<-ctx.Done()
}

// every runs f now and then every d.
func every(ctx context.Context, d time.Duration, f func()) {
	f()
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

// Status is the one-line summary for /api/status.json.
type Status struct {
	State   eval.State   `json:"state"`
	Summary string       `json:"summary"`
	At      time.Time    `json:"at"`
	Items   []StatusItem `json:"items"`
}

type StatusItem struct {
	Host    string     `json:"host"`
	Check   string     `json:"check"`
	State   eval.State `json:"state"`
	Summary string     `json:"summary"`
	Acked   bool       `json:"acked,omitempty"`
}

// Status summarizes every non-ok check.
func (s *Server) Status(ctx context.Context) (*Status, error) {
	checks, err := s.Store.Checks(ctx)
	if err != nil {
		return nil, err
	}
	now := s.Now()
	st := &Status{State: eval.OK, At: now.UTC().Truncate(time.Second), Items: []StatusItem{}}
	counts := map[eval.State]int{}
	for _, c := range checks {
		if c.State == eval.OK {
			continue
		}
		acked := c.Acked(now)
		st.Items = append(st.Items, StatusItem{c.Host, c.ID, c.State, c.Summary, acked})
		if acked {
			continue
		}
		counts[c.State]++
		st.State = eval.Worst(st.State, c.State)
	}
	sort.Slice(st.Items, func(i, j int) bool {
		a, b := st.Items[i], st.Items[j]
		if a.State.Severity() != b.State.Severity() {
			return a.State.Severity() > b.State.Severity()
		}
		return a.Host+a.Check < b.Host+b.Check
	})
	var parts []string
	for _, k := range []eval.State{eval.Crit, eval.Stale, eval.Warn} {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
		}
	}
	st.Summary = "all ok"
	if len(parts) > 0 {
		st.Summary = strings.Join(parts, ", ")
	}
	return st, nil
}

func mustJSON(v any) []byte {
	if v == nil {
		return []byte(`{}`)
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 || b[0] != '{' {
		return []byte(`{}`)
	}
	return b
}
