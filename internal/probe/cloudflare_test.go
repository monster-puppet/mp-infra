package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

func tunnel(name, status string, versions ...string) map[string]any {
	var conns []map[string]any
	for _, v := range versions {
		conns = append(conns, map[string]any{"client_version": v, "colo_name": "arn02"})
	}
	return map[string]any{"name": name, "status": status, "connections": conns}
}

func TestTunnels(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{
			tunnel("nas", "healthy", "2026.10.4", "2026.10.4"),
			tunnel("old", "healthy", "2025.10.1", "2026.10.4"),
			tunnel("stale", "healthy", "2026.6.0"),
			tunnel("degraded", "degraded", "2026.10.4"),
			tunnel("down", "down", "2026.10.4"),
			tunnel("empty", "inactive"),
		}})
	}))
	defer srv.Close()
	t.Setenv("CF_TEST_TOKEN", "tok")
	p := newProber(t, &config.Server{
		Hosts: []config.Host{{Name: "nas"}},
		Cloudflare: config.Cloudflare{TokenEnv: "CF_TEST_TOKEN", AccountID: "acct", APIURL: srv.URL,
			MinVersion: "2026.1.0", Tunnels: map[string]string{"nas": "nas", "missing": ""}},
	})
	cs := p.tunnelChecks(context.Background())
	if gotAuth != "Bearer tok" || gotPath != "/accounts/acct/cfd_tunnel" {
		t.Errorf("request auth=%q path=%q", gotAuth, gotPath)
	}
	for id, st := range map[string]eval.State{
		"tunnel.nas": eval.OK, "tunnel.old": eval.Crit, "tunnel.stale": eval.Warn, "tunnel.degraded": eval.Warn,
		"tunnel.down": eval.Crit, "tunnel.empty": eval.Crit, "tunnel.missing": eval.Crit,
	} {
		if c := find(t, cs, id); c.State != st {
			t.Errorf("%s = %s (%s), want %s", id, c.State, c.Summary, st)
		}
	}
	if c := find(t, cs, "tunnel.nas"); c.Host != "nas" || c.Summary != "healthy, 2 connection(s), cloudflared 2026.10.4" {
		t.Errorf("nas = %+v", c)
	}
	if c := find(t, cs, "tunnel.old"); c.Host != config.ServeHost || !strings.Contains(c.Summary, "2025.10.1 is below the required 2026.1.0") {
		t.Errorf("old = %+v", c)
	}
	if c := find(t, cs, "tunnel.stale"); !strings.Contains(c.Summary, "days old") {
		t.Errorf("stale = %+v", c)
	}
}

func TestTunnelsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer srv.Close()
	t.Setenv("CF_TEST_TOKEN", "tok")
	p := newProber(t, &config.Server{
		Hosts:      []config.Host{{Name: "nas"}},
		Cloudflare: config.Cloudflare{TokenEnv: "CF_TEST_TOKEN", AccountID: "acct", APIURL: srv.URL, Tunnels: map[string]string{"nas": "nas"}},
	})
	cs := p.tunnelChecks(context.Background())
	if c := find(t, cs, "tunnel.nas"); c.State != eval.Warn || c.Host != "nas" || strings.Contains(c.Summary, "tok") {
		t.Errorf("nas = %+v", c)
	}
	if len(newProber(t, &config.Server{}).tunnelChecks(context.Background())) != 0 {
		t.Error("unconfigured cloudflare must add no checks")
	}
}

func TestCmpVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"2025.10.1", "2026.10.2", -1}, {"2026.10.4", "2026.10.2", 1}, {"2026.9.0", "2026.10.0", -1}, {"2026.10", "2026.10.0", 0}} {
		if got := cmpVersion(c.a, c.b); got != c.want {
			t.Errorf("cmpVersion(%s, %s) = %d", c.a, c.b, got)
		}
	}
}
