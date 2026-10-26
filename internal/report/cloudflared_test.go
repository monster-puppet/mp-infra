package report

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// Lines as the NAS's cloudflared 2026.10.4 serves them (2026-10-26).
func cfdMetrics(version, conns string) string {
	return "# TYPE build_info gauge\n" +
		`build_info{goversion="go1.27.3",revision="2026-10-26-11:25 UTC",type="",version="` + version + `"} 1` + "\n" +
		"# TYPE cloudflared_tunnel_ha_connections gauge\n" +
		"cloudflared_tunnel_ha_connections " + conns + "\n" +
		`go_info{version="go1.27.3"} 1` + "\n"
}

func TestCloudflaredCheck(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	cfg := &config.Cloudflared{MinVersion: "2026.1.0", MaxAgeDays: 90}
	for _, c := range []struct {
		name, metrics string
		want          eval.State
		summary       string
	}{
		{"current", cfdMetrics("2026.10.4", "4"), eval.OK, "cloudflared 2026.10.4, 4 tunnel connection(s)"},
		{"below min", cfdMetrics("2025.10.1", "4"), eval.Crit, "below the required 2026.1.0"},
		{"old", cfdMetrics("2026.6.0", "4"), eval.Warn, "days old"},
		{"down", cfdMetrics("2026.10.4", "0"), eval.Crit, "the tunnel is down"},
		{"no version", "go_info 1\n", eval.Crit, "no version"},
	} {
		got := cloudflaredCheck("cloudflared.nas", c.metrics, cfg, now)
		if got.State != c.want || !strings.Contains(got.Summary, c.summary) {
			t.Errorf("%s: %s %q", c.name, got.State, got.Summary)
		}
	}
}

func TestFetchCloudflaredMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(cfdMetrics("2026.10.4", "4")))
	}))
	defer srv.Close()
	out, err := fetchCloudflaredMetrics(context.Background(), srv.URL+"/metrics")
	if err != nil || !strings.Contains(out, "2026.10.4") {
		t.Fatalf("fetch = %q, %v", out, err)
	}
	if _, err := fetchCloudflaredMetrics(context.Background(), "http://127.0.0.1:1/metrics"); err == nil {
		t.Error("want an error for a closed port")
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
