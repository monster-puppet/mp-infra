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
	"net/netip"
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
	if b, ok := BaselineFor(c.ID); ok {
		return s.baselineRule(ctx, host, c, b, now)
	}
	switch {
	case strings.HasPrefix(c.ID, "os.security_updates."):
		return s.updatesRule(ctx, host, c, now)
	case strings.HasPrefix(c.ID, "auth.failures."):
		return s.bruteForceRule(ctx, host, c, now)
	case strings.HasPrefix(c.ID, "auth.logins."):
		return s.tailnetLoginsRule(ctx, c, now)
	case strings.HasPrefix(c.ID, "endpoint."):
		s.endpointRule(c, now)
	}
	return nil
}

// tailnetLoginsRule takes logins whose address is the public address of a
// personal tailnet device (from the last ts.devices probe) out of "outside", so
// someone SSHing to a host's public address from home is not a break-in. Tagged
// devices are servers and CI and do not count: a login from jenkins's public
// address is still crit. The device lists only current endpoints, so a login
// from the device's previous address hours ago stays crit.
func (s *Server) tailnetLoginsRule(ctx context.Context, c *store.Check, now time.Time) error {
	var d map[string]json.RawMessage
	var outside []report.Login
	var total int
	var errs []string
	if json.Unmarshal([]byte(c.Data), &d) != nil || json.Unmarshal(d["outside"], &outside) != nil || len(outside) == 0 {
		return nil
	}
	json.Unmarshal(d["total"], &total)
	json.Unmarshal(d["errors"], &errs)
	devices, err := s.personalDeviceIPs(ctx)
	if err != nil || len(devices) == 0 {
		return err
	}
	still, fromDevices := []report.Login{}, []report.Login{}
	for _, o := range outside {
		a, err := netip.ParseAddr(strings.Trim(o.IP, "[]"))
		if name, ok := devices[a.Unmap()]; err == nil && ok {
			o.Device = name
			fromDevices = append(fromDevices, o)
		} else {
			still = append(still, o)
		}
	}
	if len(fromDevices) == 0 {
		return nil
	}
	c.State, c.Summary = report.LoginsVerdict(now, total, still, fromDevices, len(errs))
	c.Summary = report.Clip(c.Summary, report.MaxSummary)
	d["outside"], d["from_devices"] = mustJSON(still), mustJSON(fromDevices)
	c.Data = string(mustJSON(d))
	return nil
}

// personalDeviceIPs maps the public addresses of untagged tailnet devices to
// their Tailscale names. Devices behind one NAT share an address: the one
// connected now names it, else the one seen last.
func (s *Server) personalDeviceIPs(ctx context.Context) (map[netip.Addr]string, error) {
	devices, err := s.tsDevices(ctx)
	if err != nil {
		return nil, err
	}
	best := map[netip.Addr]probe.TSDevice{}
	for _, dv := range devices {
		if len(dv.Tags) > 0 {
			continue
		}
		for _, ip := range dv.PublicIPs {
			a, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			a = a.Unmap()
			if b, ok := best[a]; !ok || dv.Connected && !b.Connected ||
				dv.Connected == b.Connected && dv.LastSeen.After(b.LastSeen) {
				best[a] = dv
			}
		}
	}
	out := map[netip.Addr]string{}
	for a, dv := range best {
		out[a] = dv.Name
		if dv.Machine != "" {
			out[a] = dv.Machine
		}
	}
	return out, nil
}

// bruteForceWindow is the longest gap between two reports that still counts as
// "now" when comparing their failed-login totals.
const bruteForceWindow = 15 * time.Minute

type failuresData struct {
	Total  int `json:"total"`
	TopIPs []struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	} `json:"top_ips"`
}

// bruteForceRule compares the 24-hour failed-login count with the previous
// report's. When it grew by Thresholds.BruteForceActive or more since then, a
// brute force is going on right now: the check turns warn, its summary says so
// and names the address that grew most, and its data gets "active".
func (s *Server) bruteForceRule(ctx context.Context, host string, c *store.Check, now time.Time) error {
	var cur failuresData
	if json.Unmarshal([]byte(c.Data), &cur) != nil {
		return nil
	}
	prev, err := s.Store.Check(ctx, host, c.ID)
	if err != nil || prev == nil || now.Sub(prev.UpdatedAt) > bruteForceWindow {
		return err
	}
	var old failuresData
	if json.Unmarshal([]byte(prev.Data), &old) != nil {
		return nil
	}
	recent := cur.Total - old.Total
	if recent < s.Cfg.Thresholds.BruteForceActive {
		return nil
	}
	before := map[string]int{}
	for _, t := range old.TopIPs {
		before[t.IP] = t.Count
	}
	ip, most := "", 0
	for _, t := range cur.TopIPs {
		if d := t.Count - before[t.IP]; d > most {
			ip, most = t.IP, d
		}
	}
	mins := int(now.Sub(prev.UpdatedAt).Round(time.Minute) / time.Minute)
	summary := fmt.Sprintf("active brute force: %d failed logins in the last %d min", recent, max(mins, 1))
	if ip != "" {
		summary += ", mostly from " + ip
	}
	c.State = eval.Worst(c.State, eval.Warn)
	c.Summary = report.Clip(summary+"; "+c.Summary, report.MaxSummary)
	var d map[string]any
	if json.Unmarshal([]byte(c.Data), &d) == nil {
		d["active"] = true
		d["recent"] = recent
		d["recent_minutes"] = mins
		if ip != "" {
			d["recent_ip"] = ip
		}
		c.Data = string(mustJSON(d))
	}
	return nil
}

// Baseline describes a drift check: the agent reports a hash (and, for item
// lists, the items), the server compares it with the accepted one.
type Baseline struct {
	Prefix  string
	What    string     // "firewall rules"
	Changed eval.State // the state of a change until someone accepts it
}

// Baselines are the drift checks. A changed admin account or SSH key is crit, so
// it alerts at once: that is what a break-in leaves behind.
var Baselines = []Baseline{
	{"fw.rules.", "firewall rules", eval.Warn},
	{"sec.accounts.", "accounts and SSH keys", eval.Crit},
	{"sec.listeners.", "listening ports", eval.Warn},
}

// BaselineFor returns the drift check id belongs to.
func BaselineFor(id string) (Baseline, bool) {
	for _, b := range Baselines {
		if strings.HasPrefix(id, b.Prefix) {
			return b, true
		}
	}
	return Baseline{}, false
}

type baselineData struct {
	Hash  string   `json:"hash"`
	Items []string `json:"items"`
}

// baselineValue is what the baselines table stores: the hash, then the items one
// per line, so a later change can say what was added and removed. Firewall
// checks have no items and store the hash alone.
func baselineValue(d baselineData) string {
	var items []string
	for _, it := range d.Items {
		if !strings.ContainsAny(it, "\r\n") {
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		return d.Hash
	}
	return d.Hash + "\n" + strings.Join(items, "\n")
}

func splitBaseline(v string) (hash string, items []string) {
	hash, rest, ok := strings.Cut(v, "\n")
	if ok {
		items = strings.Split(rest, "\n")
	}
	return hash, items
}

// baselineRule compares the reported hash with the accepted one. The first hash
// ever seen is accepted automatically; a change keeps b.Changed until someone
// accepts it in the UI.
func (s *Server) baselineRule(ctx context.Context, host string, c *store.Check, b Baseline, now time.Time) error {
	var d baselineData
	if json.Unmarshal([]byte(c.Data), &d) != nil || d.Hash == "" {
		return nil // the collector failed; keep its state
	}
	base, at, ok, err := s.Store.Baseline(ctx, host, c.ID)
	if err != nil {
		return err
	}
	if !ok {
		if err := s.Store.SetBaseline(ctx, host, c.ID, baselineValue(d), "first report", now); err != nil {
			return err
		}
		c.State, c.Summary = eval.OK, b.What+" recorded as the accepted baseline"
		return nil
	}
	baseHash, baseItems := splitBaseline(base)
	if baseHash == d.Hash {
		c.State, c.Summary = eval.OK, b.What+" unchanged since "+at.Local().Format("2006-01-02")
		return nil
	}
	c.State = b.Changed
	added, removed := diffItems(baseItems, d.Items)
	if len(added)+len(removed) == 0 {
		c.Summary = fmt.Sprintf("%s changed (accepted %s is %s, now %s)", b.What, at.Local().Format("2006-01-02"), short(baseHash), short(d.Hash))
		return nil
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "new: "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "gone: "+strings.Join(removed, ", "))
	}
	c.Summary = report.Clip(b.What+" changed since "+at.Local().Format("2006-01-02")+"; "+strings.Join(parts, "; "), report.MaxSummary)
	return nil
}

// diffItems returns the items only in now (added) and only in base (removed).
func diffItems(base, now []string) (added, removed []string) {
	in := func(xs []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	b, n := in(base), in(now)
	for _, x := range now {
		if !b[x] {
			added = append(added, x)
		}
	}
	for _, x := range base {
		if !n[x] {
			removed = append(removed, x)
		}
	}
	return added, removed
}

// AcceptBaseline accepts what host currently reports for a drift check, or the
// current notices of a security-notice check.
func (s *Server) AcceptBaseline(ctx context.Context, host, id, by string) error {
	if probe.NoticeAcceptable(id) {
		return s.acceptNotice(ctx, host, id, by)
	}
	b, ok := BaselineFor(id)
	if !ok {
		return fmt.Errorf("%s is not a drift check", id)
	}
	c, err := s.Store.Check(ctx, host, id)
	if err != nil || c == nil {
		return fmt.Errorf("no check %s/%s", host, id)
	}
	var d baselineData
	if json.Unmarshal([]byte(c.Data), &d) != nil || d.Hash == "" {
		return errors.New("nothing reported to accept")
	}
	now := s.Now()
	if err := s.Store.SetBaseline(ctx, host, id, baselineValue(d), by, now); err != nil {
		return err
	}
	c.State, c.Summary = eval.OK, b.What+" accepted by "+by
	t, err := s.Store.PutCheck(ctx, *c, now)
	if err != nil {
		return err
	}
	if t != nil {
		s.Alerter.Transitions(ctx, []store.Transition{*t})
	}
	return nil
}

// acceptNotice marks a notice check's current items as seen and turns it ok; the
// next probe run keeps it ok until a new notice arrives.
func (s *Server) acceptNotice(ctx context.Context, host, id, by string) error {
	c, err := s.Store.Check(ctx, host, id)
	if err != nil || c == nil {
		return fmt.Errorf("no check %s/%s", host, id)
	}
	if err := probe.AcceptNotice(ctx, s.Store, id, []byte(c.Data)); err != nil {
		return err
	}
	now := s.Now()
	c.State, c.Summary = eval.OK, "notices accepted by "+by
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
		if h.NoReport || !eval.IsStale(last[h.Name], now, s.Cfg.StaleAfterFor(h.Name)) {
			continue
		}
		if h.Endpoint && last[h.Name].IsZero() {
			continue // enrolled, waiting for the launcher's first report
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
