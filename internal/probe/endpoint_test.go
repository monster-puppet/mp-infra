package probe

import (
	"strings"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
)

// An endpoint host gets no ts.online or ts.key_expiry check, but its device is
// known (not "unexpected") and carries the host, which the report API needs. It
// is found by its hostname or by its Tailscale name.
func TestTailscaleEndpoints(t *testing.T) {
	p := newProber(t, &config.Server{Hosts: []config.Host{
		{Name: "tacco-pc", Endpoint: true}, // by hostname
		{Name: "rchau-pc", Endpoint: true}, // by Tailscale name; hostname pet_computer
		{Name: "gone-pc", Endpoint: true},  // no such device: no check either
	}})
	cs := p.evalTailscale([]tsDevice{
		{Hostname: "TACCO-PC", Name: "mkrautwurst-pc.tail.ts.net", LastSeen: t0.Add(-48 * time.Hour),
			Expires: t0.Add(24 * time.Hour), Addresses: []string{"100.64.0.10"}},
		{Hostname: "pet_computer", Name: "rchau-pc.tail.ts.net", LastSeen: t0, Addresses: []string{"100.64.0.11"}},
		{Hostname: "Pet-Computer", Name: "ricky-desktop.tail.ts.net", LastSeen: t0.Add(-700 * 24 * time.Hour), Addresses: []string{"100.64.0.12"}},
	})
	hosts := map[string]string{}
	for _, c := range cs {
		if strings.HasPrefix(c.ID, "ts.online.") || strings.HasPrefix(c.ID, "ts.key_expiry.") {
			t.Errorf("unexpected %s", c.ID)
		}
		if c.ID == "ts.devices" {
			for _, d := range c.Data.(map[string]any)["devices"].([]TSDevice) {
				hosts[d.Addr] = d.Host
			}
			u := c.Data.(map[string]any)["unexpected"].([]string)
			if len(u) != 1 || u[0] != "ricky-desktop" {
				t.Errorf("unexpected: %v", u)
			}
		}
	}
	want := map[string]string{"100.64.0.10": "tacco-pc", "100.64.0.11": "rchau-pc", "100.64.0.12": ""}
	for a, h := range want {
		if hosts[a] != h {
			t.Errorf("%s: host %q, want %q", a, hosts[a], h)
		}
	}
}
