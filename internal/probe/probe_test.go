package probe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

var t0 = time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC)

func newProber(t *testing.T, cfg *config.Server) *Prober {
	t.Helper()
	cfg.ApplyDefaults()
	p := New(cfg, &memKV{m: map[string]string{}})
	p.now = func() time.Time { return t0 }
	return p
}

type memKV struct {
	mu sync.Mutex
	m  map[string]string
}

func (k *memKV) Get(_ context.Context, key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.m[key], nil
}

func (k *memKV) Set(_ context.Context, key, v string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[key] = v
	return nil
}

func find(t *testing.T, cs []Check, id string) Check {
	t.Helper()
	for _, c := range cs {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %s in %+v", id, cs)
	return Check{}
}

func TestTCPAndHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()

	p := newProber(t, &config.Server{
		TCP:  []config.TCPTarget{{Name: "up", Addr: addr}, {Name: "down", Addr: closed}},
		HTTP: []config.HTTPTarget{{Name: "ok", URL: srv.URL + "/"}, {Name: "bad", URL: srv.URL + "/down"}, {Name: "want503", URL: srv.URL + "/down", Status: 503}},
	})
	p.now = time.Now
	ctx := context.Background()
	tcp := p.tcpChecks(ctx)
	if find(t, tcp, "tcp.up").State != eval.OK || find(t, tcp, "tcp.down").State != eval.Crit {
		t.Errorf("tcp = %+v", tcp)
	}
	h := p.httpChecks(ctx)
	if find(t, h, "http.ok").State != eval.OK || find(t, h, "http.bad").State != eval.Crit || find(t, h, "http.want503").State != eval.OK {
		t.Errorf("http = %+v", h)
	}
}

func TestTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	p := newProber(t, &config.Server{TLS: []config.TLSTarget{{Name: "x", URL: srv.URL}}})
	p.now = time.Now

	// Untrusted: the handshake fails, which is crit.
	if c := p.tlsChecks(context.Background())[0]; c.State != eval.Crit {
		t.Errorf("untrusted cert: %+v", c)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	p.roots = pool
	if c := p.tlsChecks(context.Background())[0]; c.State != eval.OK {
		t.Errorf("trusted cert: %+v", c)
	}
	// Close to expiry.
	p.now = func() time.Time { return srv.Certificate().NotAfter.Add(-5 * 24 * time.Hour) }
	if c := p.tlsChecks(context.Background())[0]; c.State != eval.Crit {
		// the handshake uses the real clock, so only the days-left math moves
		t.Errorf("5 days left: %+v", c)
	}
	p.now = func() time.Time { return srv.Certificate().NotAfter.Add(-10 * 24 * time.Hour) }
	if c := p.tlsChecks(context.Background())[0]; c.State != eval.Warn {
		t.Errorf("10 days left: %+v", c)
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	if v, ok := f[h]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

func TestDNS(t *testing.T) {
	old := resolver
	defer func() { resolver = old }()
	resolver = fakeResolver{"a.example": {"192.0.2.2", "192.0.2.1"}, "b.example": {"192.0.2.9"}}
	p := newProber(t, &config.Server{DNS: []config.DNSTarget{
		{Name: "a", Host: "a.example", Expected: []string{"192.0.2.1", "192.0.2.2"}},
		{Name: "b", Host: "b.example", Expected: []string{"192.0.2.1"}},
		{Name: "c", Host: "c.example", Expected: []string{"192.0.2.1"}},
	}})
	cs := p.dnsChecks(context.Background())
	if find(t, cs, "dns.a").State != eval.OK || find(t, cs, "dns.b").State != eval.Crit || find(t, cs, "dns.c").State != eval.Crit {
		t.Errorf("%+v", cs)
	}
}

func TestPortScan(t *testing.T) {
	old := dialPort
	defer func() { dialPort = old }()
	open := map[int]bool{22: true, 443: true, 3389: true}
	dialPort = func(_ context.Context, ip string, port int) bool { return ip == "192.0.2.10" && open[port] }

	p := newProber(t, &config.Server{
		ScanPorts: []int{22, 80, 443, 3389},
		Hosts: []config.Host{
			{Name: "a", PublicIP: "192.0.2.10", ExpectedPublicPorts: []int{22, 443, 3389}},
			{Name: "b", PublicIP: "192.0.2.10", ExpectedPublicPorts: []int{22, 443}},
			{Name: "c", PublicIP: "192.0.2.11", ExpectedPublicPorts: []int{22}},
			{Name: "d", PublicIP: "PUBLIC_IP"},
			{Name: "e"},
		},
	})
	cs := p.portChecks(context.Background())
	if len(cs) != 4 {
		t.Fatalf("got %d checks", len(cs))
	}
	if c := find(t, cs, "ports.public.a"); c.State != eval.OK || c.Host != "a" {
		t.Errorf("a: %+v", c)
	}
	if c := find(t, cs, "ports.public.b"); c.State != eval.Crit || !strings.Contains(c.Summary, "3389") {
		t.Errorf("b: %+v", c)
	}
	if c := find(t, cs, "ports.public.c"); c.State != eval.Warn {
		t.Errorf("c: %+v", c)
	}
	if c := find(t, cs, "ports.public.d"); c.State != eval.Warn {
		t.Errorf("d: %+v", c)
	}
}

func TestTailscale(t *testing.T) {
	var tokenCalls int
	devices := []map[string]any{
		{"hostname": "monster-p4", "name": "monster-p4.tail.ts.net", "connectedToControl": true, "keyExpiryDisabled": true, "lastSeen": t0},
		{"hostname": "jenkins", "connectedToControl": false, "keyExpiryDisabled": true, "lastSeen": t0.Add(-10 * time.Minute)},
		{"hostname": "WIN-AWS", "connectedToControl": false, "keyExpiryDisabled": false, "lastSeen": t0.Add(-20 * time.Minute), "expires": t0.Add(10 * 24 * time.Hour)},
		{"hostname": "old-laptop", "connectedToControl": false, "lastSeen": t0.Add(-40 * 24 * time.Hour)},
		{"hostname": "marcus-phone", "connectedToControl": true, "lastSeen": t0,
			"clientConnectivity": map[string]any{"endpoints": []string{"203.0.113.7:41641", "192.168.1.20:41641", "[2001:db8::7]:41641", "203.0.113.7:1234", "100.64.0.3:1", "junk"}}},
		{"hostname": "DESKTOP-4KQ2", "name": "studio-pc.tail.ts.net", "connectedToControl": true, "lastSeen": t0},
		{"hostname": "Marcuss-iPad", "name": "ipad-renamed.tail.ts.net.", "connectedToControl": true, "lastSeen": t0},
		{"hostname": "stranger", "connectedToControl": true, "lastSeen": t0, "os": "macOS", "addresses": []string{"100.64.0.9", "fd7a::9"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			tokenCalls++
			r.ParseForm()
			if r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "csecret" {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
		case "/api/v2/tailnet/-/devices":
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"devices": devices})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	t.Setenv("TS_ID", "cid")
	t.Setenv("TS_SECRET", "csecret")
	p := newProber(t, &config.Server{
		Hosts: []config.Host{{Name: "monster-p4"}, {Name: "jenkins"}, {Name: "jenkins-win"}, {Name: "missing"}, {Name: "p4-game", NotOnTailnet: true}},
		Tailscale: config.Tailscale{ClientIDEnv: "TS_ID", ClientSecretEnv: "TS_SECRET", APIURL: srv.URL,
			Devices: map[string]string{"jenkins-win": "WIN-AWS"}, ExpectedDevices: []string{"marcus-phone", "old-laptop", "IPAD-renamed"}},
	})
	cs := p.tailscaleChecks(context.Background())
	want := map[string]eval.State{
		"ts.api":                    eval.OK,
		"ts.online.monster-p4":      eval.OK,
		"ts.key_expiry.monster-p4":  eval.OK,
		"ts.online.jenkins":         eval.Warn,
		"ts.online.jenkins-win":     eval.Crit,
		"ts.key_expiry.jenkins-win": eval.Crit,
		"ts.online.missing":         eval.Crit,
		"ts.devices":                eval.Warn,
	}
	for id, st := range want {
		if c := find(t, cs, id); c.State != st {
			t.Errorf("%s = %s (%s), want %s", id, c.State, c.Summary, st)
		}
	}
	for _, c := range cs {
		if strings.Contains(c.ID, "p4-game") {
			t.Errorf("not_on_tailnet host got %s", c.ID)
		}
	}
	if c := find(t, cs, "ts.online.jenkins-win"); c.Host != "jenkins-win" {
		t.Errorf("filed under %q", c.Host)
	}
	d := find(t, cs, "ts.devices")
	if !strings.Contains(d.Summary, "stranger") || !strings.Contains(d.Summary, "old-laptop") {
		t.Errorf("devices: %s", d.Summary)
	}
	// A renamed device is reported by its Tailscale name and may be expected by it.
	if !strings.Contains(d.Summary, "studio-pc") || strings.Contains(d.Summary, "DESKTOP-4KQ2") || strings.Contains(d.Summary, "ipad") {
		t.Errorf("renamed devices: %s", d.Summary)
	}
	list := d.Data.(map[string]any)["devices"].([]TSDevice)
	if len(list) != len(devices) {
		t.Fatalf("device list: %+v", list)
	}
	for _, dv := range list {
		switch dv.Name {
		case "stranger":
			if dv.OS != "macOS" || dv.Addr != "100.64.0.9" || !dv.Connected || dv.Host != "" {
				t.Errorf("stranger: %+v", dv)
			}
		case "marcus-phone":
			if got := strings.Join(dv.PublicIPs, " "); got != "203.0.113.7 2001:db8::7" {
				t.Errorf("marcus-phone public IPs: %q", got)
			}
		case "DESKTOP-4KQ2":
			if dv.Machine != "studio-pc" {
				t.Errorf("machine name: %+v", dv)
			}
		case "Marcuss-iPad":
			if dv.Machine != "ipad-renamed" {
				t.Errorf("machine name: %+v", dv)
			}
		case "WIN-AWS":
			if dv.Host != "jenkins-win" {
				t.Errorf("WIN-AWS not tied to its host: %+v", dv)
			}
		}
	}
	p.tailscaleChecks(context.Background())
	if tokenCalls != 1 {
		t.Errorf("token fetched %d times, want cached", tokenCalls)
	}

	t.Setenv("TS_SECRET", "wrong")
	p2 := newProber(t, &config.Server{Tailscale: p.cfg.Tailscale})
	if cs := p2.tailscaleChecks(context.Background()); len(cs) != 1 || cs[0].ID != "ts.api" || cs[0].State != eval.Crit {
		t.Errorf("bad credentials: %+v", cs)
	}
	t.Setenv("TS_SECRET", "")
	if cs := p2.tailscaleChecks(context.Background()); cs != nil {
		t.Errorf("unconfigured: %+v", cs)
	}
}

func TestJenkins(t *testing.T) {
	offline := true
	var triggers int
	lastSuccess := t0.Add(-30 * 24 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, pw, ok := r.BasicAuth(); !ok || u != "mpinfra" || pw != "jt" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/computer/windows/api/json":
			json.NewEncoder(w).Encode(map[string]any{"offline": offline, "offlineCauseReason": "disconnected"})
		case r.URL.Path == "/job/break-glass/api/json":
			json.NewEncoder(w).Encode(map[string]any{
				"lastCompletedBuild":  map[string]any{"number": 7, "result": "SUCCESS", "timestamp": lastSuccess.UnixMilli()},
				"lastSuccessfulBuild": map[string]any{"number": 7, "result": "SUCCESS", "timestamp": lastSuccess.UnixMilli()},
			})
		case r.URL.Path == "/job/break-glass/buildWithParameters" && r.Method == http.MethodPost:
			if r.URL.Query().Get("ACTION") != "status" {
				w.WriteHeader(400)
				return
			}
			triggers++
			w.WriteHeader(201)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	t.Setenv("JT", "jt")
	p := newProber(t, &config.Server{
		Hosts: []config.Host{{Name: "jenkins-win"}},
		Jenkins: config.Jenkins{URL: srv.URL, User: "mpinfra", TokenEnv: "JT", Agents: []string{"windows"},
			AgentHosts: map[string]string{"windows": "jenkins-win"}, BreakglassJob: "break-glass", BreakglassHost: "jenkins-win", BreakglassMonthly: true},
	})
	ctx := context.Background()
	cs := p.jenkinsChecks(ctx)
	if c := find(t, cs, "jenkins.agent.windows"); c.State != eval.Warn || c.Host != "jenkins-win" {
		t.Errorf("first offline: %+v", c)
	}
	bg := find(t, cs, "win.breakglass_job")
	if bg.State != eval.OK || !strings.Contains(bg.Summary, "started the monthly") || triggers != 1 {
		t.Errorf("breakglass: %+v, triggers %d", bg, triggers)
	}

	p.now = func() time.Time { return t0.Add(6 * time.Minute) }
	cs = p.jenkinsChecks(ctx)
	if c := find(t, cs, "jenkins.agent.windows"); c.State != eval.Crit {
		t.Errorf("offline 6 min: %+v", c)
	}
	if triggers != 1 {
		t.Errorf("triggered again within a day: %d", triggers)
	}
	offline = false
	if c := find(t, p.jenkinsChecks(ctx), "jenkins.agent.windows"); c.State != eval.OK {
		t.Errorf("online: %+v", c)
	}

	// Older than 35 days is crit; a failed last run is crit.
	p.now = func() time.Time { return t0.Add(10 * 24 * time.Hour) }
	if c := find(t, p.jenkinsChecks(ctx), "win.breakglass_job"); c.State != eval.Crit {
		t.Errorf("old success: %+v", c)
	}
	failed := &jenkinsBuild{Number: 8, Result: "FAILURE", Timestamp: t0.UnixMilli()}
	if c := p.evalBreakglass("x", failed, &jenkinsBuild{Number: 7, Timestamp: t0.UnixMilli()}); c.State != eval.Crit {
		t.Errorf("failed run: %+v", c)
	}
	if c := p.evalBreakglass("x", nil, nil); c.State != eval.Crit {
		t.Errorf("never run: %+v", c)
	}
}

func TestSnapshots(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dot" {
			w.WriteHeader(401)
			return
		}
		var snaps []map[string]any
		switch r.URL.Path {
		case "/v2/droplets/1/snapshots":
			snaps = []map[string]any{{"id": "a", "name": "old", "created_at": t0.Add(-90 * 24 * time.Hour)}, {"id": "b", "name": "new", "created_at": t0.Add(-10 * 24 * time.Hour)}}
		case "/v2/droplets/2/snapshots":
			snaps = []map[string]any{{"id": "c", "name": "x", "created_at": t0.Add(-40 * 24 * time.Hour)}}
		case "/v2/droplets/3/snapshots":
			snaps = []map[string]any{}
		default:
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"snapshots": snaps, "links": map[string]any{}})
	}))
	defer srv.Close()
	t.Setenv("DOT", "dot")
	p := newProber(t, &config.Server{
		Hosts: []config.Host{{Name: "jenkins"}},
		DO: config.DigitalOcean{TokenEnv: "DOT", APIURL: srv.URL, Droplets: []config.Droplet{
			{Name: "jenkins", ID: 1}, {Name: "monster-p4", ID: 2}, {Name: "empty", ID: 3}, {Name: "gone", ID: 4}}},
	})
	cs := p.snapshotChecks(context.Background())
	for id, st := range map[string]eval.State{"snapshot.age.jenkins": eval.OK, "snapshot.age.monster-p4": eval.Warn, "snapshot.age.empty": eval.Crit, "snapshot.age.gone": eval.Crit} {
		if c := find(t, cs, id); c.State != st {
			t.Errorf("%s = %s (%s)", id, c.State, c.Summary)
		}
	}
	if find(t, cs, "snapshot.age.jenkins").Host != "jenkins" || find(t, cs, "snapshot.age.empty").Host != config.ServeHost {
		t.Error("host filing")
	}
}

func TestNotion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer nt" || r.Header.Get("Notion-Version") == "" || r.URL.Path != "/v1/databases/db1/query" {
			w.WriteHeader(401)
			return
		}
		var q map[string]any
		json.NewDecoder(r.Body).Decode(&q)
		title := func(s string) map[string]any {
			return map[string]any{"properties": map[string]any{"Name": map[string]any{"type": "title", "title": []any{map[string]any{"plain_text": s}}}}}
		}
		if q["start_cursor"] == nil {
			json.NewEncoder(w).Encode(map[string]any{"results": []any{title("Rotate bot token")}, "has_more": true, "next_cursor": "c2"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": []any{title("Enable 2FA")}, "has_more": false})
	}))
	defer srv.Close()
	t.Setenv("NT", "nt")
	p := newProber(t, &config.Server{Notion: config.Notion{TokenEnv: "NT", DatabaseID: "db1", DoneProperty: "Done", APIURL: srv.URL}})
	cs := p.notionChecks(context.Background())
	if len(cs) != 1 || cs[0].State != eval.Warn || !strings.HasPrefix(cs[0].Summary, "2 open") {
		t.Errorf("%+v", cs)
	}
}

func TestRunWithNothingConfigured(t *testing.T) {
	p := newProber(t, &config.Server{})
	if cs := p.Run(context.Background()); len(cs) != 0 {
		t.Errorf("%+v", cs)
	}
}
