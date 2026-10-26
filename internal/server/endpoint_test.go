package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/probe"
	"github.com/monster-puppet/mp-infra/internal/report"
	"github.com/monster-puppet/mp-infra/internal/store"
)

func seedDevices(t *testing.T, s *Server, devs ...probe.TSDevice) {
	t.Helper()
	if _, err := s.Store.PutCheck(context.Background(), store.Check{Host: config.ServeHost, ID: "ts.devices", State: eval.OK,
		Data: string(mustJSON(map[string]any{"devices": devs}))}, t0); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointHost(t *testing.T) {
	s, _, _ := setup(t, config.Host{Name: "pc-a", Endpoint: true}, config.Host{Name: "pc-b", Endpoint: true},
		config.Host{Name: "jenkins"})
	seedDevices(t, s,
		probe.TSDevice{Name: "PC-A", Addr: "100.64.0.1", Host: "pc-a"},
		// Two devices claim pc-b (one renamed to its hostname): neither may report.
		probe.TSDevice{Name: "PC-B", Addr: "100.64.0.2", Host: "pc-b"},
		probe.TSDevice{Name: "pc-b", Addr: "100.64.0.3", Host: "pc-b"},
		probe.TSDevice{Name: "jenkins", Addr: "100.64.0.4", Host: "jenkins"},
		probe.TSDevice{Name: "phone", Addr: "100.64.0.5"},
	)
	for _, tc := range []struct {
		addr string
		host string
		ok   bool
	}{
		{"100.64.0.1", "pc-a", true},
		{"::ffff:100.64.0.1", "pc-a", true},
		{"100.64.0.2", "", false}, // ambiguous
		{"100.64.0.4", "", false}, // token host
		{"100.64.0.5", "", false}, // not a configured host
		{"100.64.0.9", "", false}, // unknown device
		{"203.0.113.1", "", false},
	} {
		host, ok := s.EndpointHost(context.Background(), netip.MustParseAddr(tc.addr))
		if host != tc.host || ok != tc.ok {
			t.Errorf("%s: got %q %v", tc.addr, host, ok)
		}
	}
}

func TestEndpointRule(t *testing.T) {
	s, _, _ := setup(t, config.Host{Name: "pc", Endpoint: true})
	ctx := context.Background()
	recent := t0.Add(-10 * 24 * time.Hour).Format("2006-01-02")
	for i, tc := range []struct {
		id    string
		data  map[string]any
		state eval.State
		want  string
	}{
		{"endpoint.bitlocker.pc", map[string]any{"protection": 1}, eval.OK, "system drive encrypted (BitLocker on)"},
		{"endpoint.bitlocker.pc", map[string]any{"protection": 2}, eval.Crit, "system drive not encrypted (BitLocker off)"},
		{"endpoint.bitlocker.pc", map[string]any{}, eval.Warn, "BitLocker state unknown"},
		{"endpoint.bitlocker.pc", map[string]any{"error": "COM failed\nmore"}, eval.Warn, "launcher could not read this: COM failed"},
		{"endpoint.av.pc", map[string]any{"products": []map[string]any{{"name": "Windows Defender", "state": 397568}},
			"defender": map[string]any{"mode": "Normal", "rtp": true, "tamper": true, "sig_age_days": 0}},
			eval.OK, "Windows Defender on and up to date"},
		{"endpoint.av.pc", map[string]any{"products": []map[string]any{{"name": "Vendor AV", "state": 266240},
			{"name": "Windows Defender", "state": 393472}}, "defender": map[string]any{"mode": "Passive"}},
			eval.OK, "Vendor AV on and up to date"},
		{"endpoint.av.pc", map[string]any{"products": []map[string]any{{"name": "Windows Defender", "state": 393472}}},
			eval.Crit, "no antivirus enabled"},
		{"endpoint.av.pc", map[string]any{"products": []map[string]any{{"name": "Windows Defender", "state": 397568}},
			"defender": map[string]any{"mode": "Normal", "rtp": true, "tamper": true, "sig_age_days": 5}},
			eval.Warn, "Defender signatures 5 days old"},
		{"endpoint.av.pc", map[string]any{"products": []map[string]any{{"name": "Windows Defender", "state": 397568}},
			"defender": map[string]any{"mode": "Normal", "rtp": false}},
			eval.Crit, "Defender real-time protection off"},
		{"endpoint.av.pc", map[string]any{"products": []map[string]any{{"name": "Windows Defender", "state": 397568}},
			"defender": map[string]any{"mode": "Normal", "rtp": true, "tamper": true, "sig_age_days": 0,
				"detections": map[string]any{"count": 2, "names": []string{"Trojan:Win32/Bearfoos.A!ml", "PUA:Win32/Example"}}}},
			eval.Crit, "Defender: 2 detection(s) in 7 days: Trojan:Win32/Bearfoos.A!ml, PUA:Win32/Example"},
		{"endpoint.av.pc", map[string]any{"products": []map[string]any{{"name": "Windows Defender", "state": 397568}},
			"defender": map[string]any{"mode": "Normal", "rtp": true, "tamper": true, "sig_age_days": 0,
				"detections": map[string]any{"count": 0}}},
			eval.OK, "Windows Defender on and up to date"},
		{"endpoint.firewall.pc", map[string]any{"profiles": map[string]bool{"Domain": true, "Private": true, "Public": true}},
			eval.OK, "Windows Firewall on for all profiles"},
		{"endpoint.firewall.pc", map[string]any{"profiles": map[string]bool{"Domain": true, "Private": false, "Public": false}},
			eval.Warn, "Windows Firewall off for Private, Public"},
		{"endpoint.boot.pc", map[string]any{"secure_boot": 1, "tpm_present": true, "tpm_version": "2.0"}, eval.OK, "Secure Boot on, TPM 2.0"},
		{"endpoint.boot.pc", map[string]any{"secure_boot": 0, "tpm_present": true, "tpm_version": "2.0"}, eval.Warn, "Secure Boot off"},
		{"endpoint.screenlock.pc", map[string]any{"policy_secs": 900}, eval.OK, "screen locks after 15 min (machine inactivity limit)"},
		{"endpoint.screenlock.pc", map[string]any{"saver_active": true, "saver_secure": true, "saver_secs": 1800},
			eval.Warn, "screen locks after 30 min (screensaver with sign-in), limit 15 min"},
		{"endpoint.screenlock.pc", map[string]any{"saver_active": true, "saver_secure": false, "saver_secs": 300},
			eval.Warn, "no automatic screen lock"},
		{"endpoint.os.pc", map[string]any{"build": 26200, "ubr": 7019, "last_update": recent}, eval.OK, "build 26200.7019, updated " + recent},
		{"endpoint.os.pc", map[string]any{"build": 26100, "ubr": 1}, eval.Crit, "build 26100.1 is out of support (minimum 26200)"},
		{"endpoint.os.pc", map[string]any{"build": 26200, "ubr": 1, "last_update": "2026-01-01", "reboot_pending": true},
			eval.Warn, "build 26200.1: no update installed for 295 days, reboot pending"},
	} {
		s.lastIn = map[string]time.Time{}
		c := report.Check{ID: tc.id, State: eval.OK, Data: mustJSON(tc.data)}
		if err := s.Ingest(ctx, "pc", []byte(`{}`), payload("pc", c)); err != nil {
			t.Fatal(err)
		}
		got, _ := s.Store.Check(ctx, "pc", tc.id)
		if got.State != tc.state || got.Summary != tc.want {
			t.Errorf("%d %s: %s %q", i, tc.id, got.State, got.Summary)
		}
	}
}

func TestEndpointStale(t *testing.T) {
	s, snk, clock := setup(t, config.Host{Name: "pc", Endpoint: true}, config.Host{Name: "new-pc", Endpoint: true})
	ctx := context.Background()
	if err := s.Ingest(ctx, "pc", []byte(`{}`), payload("pc", report.Check{ID: "endpoint.boot.pc", State: eval.OK,
		Data: mustJSON(map[string]any{"secure_boot": 1, "tpm_present": true, "tpm_version": "2.0"})})); err != nil {
		t.Fatal(err)
	}
	// Off for two days: not stale. new-pc never reported: waiting, not stale.
	*clock = t0.Add(48 * time.Hour)
	s.Sweep(ctx)
	if len(snk.msgs) != 0 {
		t.Fatalf("alerted for a sleeping endpoint: %+v", snk.msgs)
	}
	*clock = t0.Add(8 * 24 * time.Hour)
	s.Sweep(ctx)
	c, _ := s.Store.Check(ctx, "pc", "report.fresh")
	if c == nil || c.State != eval.Stale {
		t.Fatalf("pc not stale after 8 days: %+v", c)
	}
	if c, _ := s.Store.Check(ctx, "new-pc", "report.fresh"); c != nil {
		t.Fatalf("never-reported endpoint marked: %+v", c)
	}
}

func TestEndpointCheckAllowed(t *testing.T) {
	for id, want := range map[string]bool{
		"endpoint.av.pc": true, "os.security_updates.pc": true,
		"auth.logins.pc": false, "host.uptime": false, "sec.accounts.pc": false,
	} {
		if EndpointCheckAllowed(id) != want {
			t.Errorf("%s: want %v", id, want)
		}
	}
}
