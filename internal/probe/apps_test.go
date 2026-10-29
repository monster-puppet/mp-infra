package probe

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

// appServer is one TLS server whose paths play the apps: each test app points at
// its own path, and its health endpoint at /health/<name>.
func appServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte("<title>Invoice scanner</title>"))
		case "/login":
			http.Redirect(w, r, "/login?next=%2F", http.StatusFound)
		case "/401":
			w.WriteHeader(http.StatusUnauthorized)
		case "/503":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/unbound":
			// exe.dev's proxy when nothing listens on the VM's port.
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("<h1>Port 5000 unbound.</h1><p>We dialed port 5000 on this VM and nobody answered.</p>"))
		case "/slow":
			time.Sleep(60 * time.Millisecond)
		case "/health/ok":
			w.Write([]byte(`{"status":"ok","summary":"all good"}`))
		case "/health/warn":
			w.Write([]byte(`{"status":"warn","summary":"Dropbox upload failing"}`))
		case "/health/crit":
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"crit","summary":"database locked"}`))
		case "/health/bad":
			w.Write([]byte("<html>not json</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestApps(t *testing.T) {
	srv := appServer(t)
	app := func(name, path string) config.AppTarget {
		return config.AppTarget{Name: name, URL: srv.URL + path, VM: "mp-" + name}
	}
	withHealth := func(a config.AppTarget, health string) config.AppTarget {
		a.Health = "/health/" + health
		return a
	}
	contains := app("contains", "/ok")
	contains.Contains = "Timelog"
	cfg := &config.Server{Thresholds: config.Thresholds{AppSlowMS: 30}, Apps: []config.AppTarget{
		app("ok", "/ok"),
		app("login", "/login"),
		app("auth", "/401"),
		app("down", "/503"),
		app("unbound", "/unbound"),
		app("slow", "/slow"),
		withHealth(app("health-ok", "/ok"), "ok"),
		withHealth(app("health-warn", "/ok"), "warn"),
		withHealth(app("health-crit", "/login"), "crit"),
		withHealth(app("health-bad", "/ok"), "bad"),
		withHealth(app("health-gone", "/ok"), "nope"),
		contains,
	}}
	p := newProber(t, cfg)
	p.now = time.Now
	p.client.Transport = srv.Client().Transport // trust the test certificate
	cs := p.appChecks(context.Background())
	if len(cs) != len(cfg.Apps) {
		t.Fatalf("%d checks for %d apps", len(cs), len(cfg.Apps))
	}
	for _, tc := range []struct {
		id    string
		state eval.State
		sum   string // must appear in the summary
	}{
		{"app.ok", eval.OK, "200 in "},
		{"app.login", eval.OK, "302 to /login?next=%2F in "},
		{"app.auth", eval.OK, "401 in "},
		{"app.down", eval.Crit, "503 Service Unavailable"},
		{"app.unbound", eval.Crit, "Port 5000 unbound (app not running)"},
		{"app.slow", eval.Warn, "(slow)"},
		{"app.health-ok", eval.OK, "200 in "},
		{"app.health-warn", eval.Warn, "health: Dropbox upload failing"},
		{"app.health-crit", eval.Crit, "health: database locked"},
		{"app.health-bad", eval.Warn, "health endpoint failed: 200 OK, not JSON"},
		{"app.health-gone", eval.Warn, "health endpoint failed: 404 Not Found"},
		{"app.contains", eval.Crit, `lacks "Timelog"`},
	} {
		c := find(t, cs, tc.id)
		if c.Host != config.ServeHost || c.State != tc.state || !strings.Contains(c.Summary, tc.sum) {
			t.Errorf("%s: %s %s %q, want %s with %q", tc.id, c.Host, c.State, c.Summary, tc.state, tc.sum)
		}
	}

	ok := find(t, cs, "app.ok")
	if !strings.Contains(ok.Summary, ", cert ") || strings.Contains(ok.Summary, "health") {
		t.Errorf("ok summary: %q", ok.Summary)
	}
	d := ok.Data.(map[string]any)
	if d["status"] != 200 || d["vm"] != "mp-ok" || d["cert_days"] == nil || d["cert_not_after"] == nil {
		t.Errorf("ok data: %+v", d)
	}
	if d := find(t, cs, "app.login").Data.(map[string]any); d["location"] != "/login?next=%2F" {
		t.Errorf("login data: %+v", d)
	}
	if d := find(t, cs, "app.health-warn").Data.(map[string]any); d["health_status"] != "warn" || d["health_summary"] != "Dropbox upload failing" {
		t.Errorf("health data: %+v", d)
	}
	// The worse part leads: a crit health says so first.
	if s := find(t, cs, "app.health-crit").Summary; !strings.HasPrefix(s, "health: database locked; 302 to") {
		t.Errorf("health-crit summary: %q", s)
	}
	if s := find(t, cs, "app.unbound").Summary; strings.Contains(s, "cert") {
		t.Errorf("unbound summary: %q", s)
	}
}

func TestAppCertAndTransport(t *testing.T) {
	srv := appServer(t)
	cfg := &config.Server{Apps: []config.AppTarget{{Name: "x", URL: srv.URL + "/ok"}}}

	// Untrusted certificate: the handshake fails, which is crit.
	p := newProber(t, cfg)
	if c := p.appChecks(context.Background())[0]; c.State != eval.Crit || !strings.HasPrefix(c.Summary, "certificate invalid: ") {
		t.Errorf("untrusted cert: %s %q", c.State, c.Summary)
	}

	// Trusted, close to expiry: the TLS thresholds apply.
	p.client.Transport = srv.Client().Transport
	exp := srv.Certificate().NotAfter
	for _, tc := range []struct {
		left  time.Duration
		state eval.State
	}{{60 * 24 * time.Hour, eval.OK}, {10 * 24 * time.Hour, eval.Warn}, {3 * 24 * time.Hour, eval.Crit}} {
		p.now = func() time.Time { return exp.Add(-tc.left) }
		c := p.appChecks(context.Background())[0]
		if c.State != tc.state {
			t.Errorf("%s left: %s %q, want %s", tc.left, c.State, c.Summary, tc.state)
		}
	}

	// Nothing listening.
	srv.Close()
	p.now = time.Now
	if c := p.appChecks(context.Background())[0]; c.State != eval.Crit || !strings.HasPrefix(c.Summary, "unreachable: ") {
		t.Errorf("closed: %s %q", c.State, c.Summary)
	}
}
