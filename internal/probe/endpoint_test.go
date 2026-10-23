package probe

import (
	"strings"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
)

// An endpoint host gets no ts.online or ts.key_expiry check, but its device is
// known (not "unexpected") and carries the host, which the report API needs.
func TestTailscaleSkipsEndpoints(t *testing.T) {
	p := newProber(t, &config.Server{Hosts: []config.Host{{Name: "tacco-pc", Endpoint: true}}})
	cs := p.evalTailscale([]tsDevice{{Hostname: "TACCO-PC", LastSeen: t0.Add(-48 * time.Hour),
		Expires: t0.Add(24 * time.Hour), Addresses: []string{"100.64.0.10"}}})
	for _, c := range cs {
		if strings.HasPrefix(c.ID, "ts.online.") || strings.HasPrefix(c.ID, "ts.key_expiry.") {
			t.Errorf("unexpected %s", c.ID)
		}
		if c.ID == "ts.devices" {
			devs := c.Data.(map[string]any)["devices"].([]TSDevice)
			if len(devs) != 1 || devs[0].Host != "tacco-pc" || devs[0].Addr != "100.64.0.10" {
				t.Errorf("devices: %+v", devs)
			}
			if u := c.Data.(map[string]any)["unexpected"].([]string); len(u) != 0 {
				t.Errorf("unexpected: %v", u)
			}
		}
	}
}
