package web

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/server"
	"github.com/monster-puppet/mp-infra/internal/store"
)

var now = time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC)

type env struct {
	srv     *server.Server
	ui      http.Handler
	reports http.Handler
	clock   *time.Time
}

func setup(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Server{Hosts: []config.Host{{Name: "monster-p4"}, {Name: "jenkins"}, {Name: "jenkins-win"}}, StaleAfter: 15 * time.Minute}
	cfg.ApplyDefaults()
	tokens := config.Tokens{}
	for _, h := range cfg.Hosts {
		sum := sha256.Sum256([]byte("tok-" + h.Name))
		tokens[h.Name] = sum[:]
	}
	srv := server.New(cfg, st, tokens, "test")
	clock := now
	srv.Now = func() time.Time { return clock }
	w := New(srv, nil)
	return &env{srv: srv, ui: w.UI(), reports: w.Reports(), clock: &clock}
}

func body(host, summary string) string {
	return fmt.Sprintf(`{"host":%q,"agent_version":"0.1.0","collected_at":%q,"checks":[{"id":"host.uptime","state":"ok","summary":%q,"data":{"seconds":5}}]}`,
		host, now.Format(time.RFC3339), summary)
}

func (e *env) post(token, b string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/report", strings.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.reports.ServeHTTP(rec, req)
	return rec
}

func (e *env) get(path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.ui.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestReportAuth(t *testing.T) {
	e := setup(t)
	cases := []struct {
		name  string
		token string
		body  string
		code  int
	}{
		{"no token", "", body("monster-p4", "x"), 401},
		{"unknown token", "nope", body("monster-p4", "x"), 401},
		{"host A's token for host B", "tok-jenkins-win", body("monster-p4", "x"), 403},
		{"invalid body", "tok-monster-p4", `{"host":"monster-p4"}`, 400},
		{"reserved id", "tok-monster-p4", strings.Replace(body("monster-p4", "x"), "host.uptime", "ts.online.monster-p4", 1), 400},
		{"too large", "tok-monster-p4", strings.Repeat(" ", 300<<10) + body("monster-p4", "x"), 413},
		{"ok", "tok-monster-p4", body("monster-p4", "up 5s"), 204},
		{"too soon", "tok-monster-p4", body("monster-p4", "up 5s"), 429},
	}
	for _, c := range cases {
		if rec := e.post(c.token, c.body); rec.Code != c.code {
			t.Errorf("%s: %d %s, want %d", c.name, rec.Code, rec.Body.String(), c.code)
		}
	}
	checks, _ := e.srv.Store.Checks(context.Background())
	for _, c := range checks {
		if c.Host != "monster-p4" {
			t.Errorf("a refused report wrote %s/%s", c.Host, c.ID)
		}
	}
}

func TestReportPortServesNothingElse(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/", "/healthz", "/api/status.json", "/history"} {
		rec := httptest.NewRecorder()
		e.reports.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != 404 && rec.Code != 405 {
			t.Errorf("report port served %s: %d", p, rec.Code)
		}
	}
}

func TestPages(t *testing.T) {
	e := setup(t)
	if rec := e.post("tok-monster-p4", body("monster-p4", `<script>alert(1)</script>`)); rec.Code != 204 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	home := e.get("/")
	if home.Code != 200 {
		t.Fatal(home.Code)
	}
	h := home.Body.String()
	if strings.Contains(h, "<script>alert") || !strings.Contains(h, "&lt;script&gt;") {
		t.Error("summary not escaped")
	}
	for _, want := range []string{"monster-p4", "jenkins-win", "never reported", "host.uptime", `http-equiv="refresh"`, "/static/style.css"} {
		if !strings.Contains(h, want) {
			t.Errorf("home lacks %q", want)
		}
	}
	if csp := home.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP = %q", csp)
	}

	if rec := e.get("/check/monster-p4/host.uptime"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Transitions") {
		t.Errorf("check page: %d", rec.Code)
	}
	if rec := e.get("/check/monster-p4/nope"); rec.Code != 404 {
		t.Errorf("missing check: %d", rec.Code)
	}
	if rec := e.get("/history?host=monster-p4"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "host.uptime") {
		t.Errorf("history: %d", rec.Code)
	}
	if rec := e.get("/healthz"); rec.Code != 200 {
		t.Errorf("healthz: %d", rec.Code)
	}
	for _, p := range []string{"/static/style.css", "/static/fonts/heading-font.woff2", "/static/images/logo-small.png"} {
		if rec := e.get(p); rec.Code != 200 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

func TestStatusJSON(t *testing.T) {
	e := setup(t)
	e.srv.Store.PutCheck(context.Background(), store.Check{Host: "jenkins", ID: "disk.jenkins.root", State: eval.Warn, Summary: "85%"}, now)
	e.srv.Store.PutCheck(context.Background(), store.Check{Host: "jenkins", ID: "x", State: eval.OK}, now)
	rec := e.get("/api/status.json")
	var st server.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.State != eval.Warn || st.Summary != "1 warn" || len(st.Items) != 1 {
		t.Errorf("%+v", st)
	}
}

func form(path string, v url.Values, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	return req
}

func TestAckFlow(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.srv.Store.PutCheck(ctx, store.Check{Host: "jenkins", ID: "disk.jenkins.root", State: eval.Crit}, now)
	path := "/check/jenkins/disk.jenkins.root/ack"

	// Cross-site and header-less posts are refused.
	for _, h := range []map[string]string{nil, {"Sec-Fetch-Site": "cross-site"}, {"Origin": "http://evil.example"}} {
		rec := httptest.NewRecorder()
		e.ui.ServeHTTP(rec, form(path, url.Values{"for": {"4h0m0s"}, "state": {"crit"}}, h))
		if rec.Code != 403 {
			t.Errorf("headers %v: %d", h, rec.Code)
		}
	}
	same := map[string]string{"Sec-Fetch-Site": "same-origin"}

	// Crit cannot be acknowledged for more than 24 h.
	rec := httptest.NewRecorder()
	e.ui.ServeHTTP(rec, form(path, url.Values{"for": {"168h0m0s"}, "state": {"crit"}}, same))
	if c, _ := e.srv.Store.Check(ctx, "jenkins", "disk.jenkins.root"); c.Acked(now) {
		t.Error("crit acknowledged for 7 days")
	}
	rec = httptest.NewRecorder()
	e.ui.ServeHTTP(rec, form(path, url.Values{"for": {"4h0m0s"}, "state": {"crit"}, "note": {"replacing disk"}}, map[string]string{"Origin": "http://example.com"}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("ack: %d %s", rec.Code, rec.Body.String())
	}
	c, _ := e.srv.Store.Check(ctx, "jenkins", "disk.jenkins.root")
	if !c.Acked(now) || c.AckNote != "replacing disk" {
		t.Errorf("not acked: %+v", c)
	}
	rec = httptest.NewRecorder()
	e.ui.ServeHTTP(rec, form("/check/jenkins/disk.jenkins.root/unack", nil, same))
	if c, _ := e.srv.Store.Check(ctx, "jenkins", "disk.jenkins.root"); c.Acked(now) {
		t.Error("unack did not remove the acknowledgement")
	}
}

func TestFirewallAccept(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	fw := func(hash string) string {
		return fmt.Sprintf(`{"host":"jenkins","agent_version":"1","collected_at":%q,"checks":[{"id":"fw.rules.jenkins","state":"ok","summary":"x","data":{"hash":%q}}]}`,
			now.Format(time.RFC3339), hash)
	}
	e.post("tok-jenkins", fw("aaaa"))
	*e.clock = e.clock.Add(time.Minute)
	e.post("tok-jenkins", fw("bbbb"))
	c, _ := e.srv.Store.Check(ctx, "jenkins", "fw.rules.jenkins")
	if c.State != eval.Warn {
		t.Fatalf("changed rules: %+v", c)
	}
	page := e.get("/check/jenkins/fw.rules.jenkins").Body.String()
	if !strings.Contains(page, "Accept current firewall rules") {
		t.Error("no accept button")
	}
	rec := httptest.NewRecorder()
	e.ui.ServeHTTP(rec, form("/check/jenkins/fw.rules.jenkins/accept", nil, map[string]string{"Sec-Fetch-Site": "same-origin"}))
	if c, _ := e.srv.Store.Check(ctx, "jenkins", "fw.rules.jenkins"); c.State != eval.OK {
		t.Errorf("after accept: %+v", c)
	}
	*e.clock = e.clock.Add(time.Minute)
	e.post("tok-jenkins", fw("bbbb"))
	if c, _ := e.srv.Store.Check(ctx, "jenkins", "fw.rules.jenkins"); c.State != eval.OK {
		t.Errorf("accepted rules reported again: %+v", c)
	}
}

func TestWhoisLoopback(t *testing.T) {
	w := NewTailscaleWhois(filepath.Join(t.TempDir(), "missing.sock"))
	if got := w.Whois(context.Background(), "127.0.0.1:5555"); got != "local" {
		t.Errorf("loopback = %q", got)
	}
	if got := w.Whois(context.Background(), "100.64.0.9:5555"); got != "100.64.0.9" {
		t.Errorf("no tailscaled = %q", got)
	}
}

func TestAgo(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Second: "just now", 5 * time.Minute: "5 min ago", 3 * time.Hour: "3 h ago", 72 * time.Hour: "3 d ago"} {
		if got := ago(now, now.Add(-d)); got != want {
			t.Errorf("ago(%s) = %q", d, got)
		}
	}
	if ago(now, time.Time{}) != "never" {
		t.Error("zero time")
	}
}

func TestHostLabels(t *testing.T) {
	e := setup(t)
	e.srv.Cfg.Hosts[0].Label, e.srv.Cfg.Hosts[0].OS = "Perforce <main>", "rocky"
	e.srv.Cfg.Hosts[2].OS = "windows"
	if rec := e.post("tok-monster-p4", body("monster-p4", "up")); rec.Code != 204 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	h := e.get("/").Body.String()
	for _, want := range []string{"Perforce &lt;main&gt;", `href="/history?host=monster-p4"`, "Rocky Linux", "os-linux", `class="os-icon os-windows"`} {
		if !strings.Contains(h, want) {
			t.Errorf("home lacks %q", want)
		}
	}
	if strings.Contains(h, "Perforce <main>") {
		t.Error("label not escaped")
	}
	if c := e.get("/check/monster-p4/host.uptime").Body.String(); !strings.Contains(c, "Perforce &lt;main&gt;") || !strings.Contains(c, "/history?host=monster-p4") {
		t.Error("check page does not show the label")
	}
	if hist := e.get("/history").Body.String(); !strings.Contains(hist, `<option value="monster-p4">Perforce &lt;main&gt;</option>`) {
		t.Error("history filter does not show the label")
	}
}

func TestEditHost(t *testing.T) {
	e := setup(t)
	same := map[string]string{"Sec-Fetch-Site": "same-origin"}
	post := func(host string, v url.Values, h map[string]string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		e.ui.ServeHTTP(rec, form("/host/"+host, v, h))
		return rec
	}
	if rec := e.get("/host/jenkins-win"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="label"`) {
		t.Fatalf("edit page: %d", rec.Code)
	}
	if rec := e.get("/host/serve"); rec.Code != 404 {
		t.Errorf("serve edit page: %d", rec.Code)
	}
	if rec := post("jenkins-win", url.Values{"label": {"x"}}, map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != 403 {
		t.Errorf("cross-site save: %d", rec.Code)
	}
	if rec := post("nope", url.Values{"label": {"x"}}, same); rec.Code != 404 {
		t.Errorf("unknown host: %d", rec.Code)
	}
	for _, bad := range []url.Values{{"os": {"beos"}}, {"label": {strings.Repeat("x", 41)}}, {"label": {"a\x00b"}}} {
		if rec := post("jenkins-win", bad, same); !strings.Contains(rec.Header().Get("Location"), "Not+saved") {
			t.Errorf("%v accepted: %d %s", bad, rec.Code, rec.Header().Get("Location"))
		}
	}
	if rec := post("jenkins-win", url.Values{"label": {"  Build <agent>  "}, "os": {"windows"}}, same); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	h := e.get("/").Body.String()
	if !strings.Contains(h, "Build &lt;agent&gt;") || !strings.Contains(h, "os-windows") || !strings.Contains(h, `href="/host/jenkins-win"`) {
		t.Error("home does not show the saved label and OS")
	}
	// The change survives a restart of serve.
	if New(e.srv, nil).label("jenkins-win") != "Build <agent>" {
		t.Error("label not persisted")
	}
	// An empty label falls back to the host name, even over a config label.
	e.srv.Cfg.Hosts[2].Label = "from config"
	post("jenkins-win", url.Values{"label": {""}}, same)
	if got := New(e.srv, nil).label("jenkins-win"); got != "jenkins-win" {
		t.Errorf("label = %q", got)
	}
}

func TestTailnetDevices(t *testing.T) {
	e := setup(t)
	data := `{"count":4,"devices":[
		{"name":"jenkins","os":"linux","addr":"100.64.0.2","connected":true,"host":"jenkins"},
		{"name":"studio-mac","os":"macOS","addr":"100.64.0.5","connected":true,"tags":["tag:dev"]},
		{"name":"<b>phone</b>","os":"iOS","connected":true},
		{"name":"old-pc","os":"windows","connected":false,"last_seen":"2026-10-20T14:00:00Z"}]}`
	e.srv.Store.PutCheck(context.Background(), store.Check{Host: config.ServeHost, ID: "ts.devices", State: eval.OK, Summary: "4 devices", Data: data}, now)
	h := e.get("/").Body.String()
	for _, want := range []string{"Tailnet", "2 other devices connected", "1 offline", "studio-mac", "100.64.0.5", "tag:dev", "os-laptop", "os-phone", "&lt;b&gt;phone", "old-pc", "last seen 2 d ago"} {
		if !strings.Contains(h, want) {
			t.Errorf("home lacks %q", want)
		}
	}
	if strings.Contains(h, `<span class="device-name">jenkins</span>`) {
		t.Error("configured host listed as another device")
	}
}

func TestAccountsBaseline(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	acc := func(items string) string {
		return fmt.Sprintf(`{"host":"jenkins","agent_version":"1","collected_at":%q,"checks":[{"id":"sec.accounts.jenkins","state":"ok","summary":"x","data":{"hash":%q,"items":[%s]}}]}`,
			now.Format(time.RFC3339), items, items)
	}
	e.post("tok-jenkins", acc(`"uid0 root","key root ssh-ed25519 SHA256:aaa marcus"`))
	*e.clock = e.clock.Add(time.Minute)
	e.post("tok-jenkins", acc(`"uid0 root","uid0 toor","key root ssh-ed25519 SHA256:aaa marcus"`))
	c, _ := e.srv.Store.Check(ctx, "jenkins", "sec.accounts.jenkins")
	if c.State != eval.Crit || !strings.Contains(c.Summary, "new: uid0 toor") {
		t.Fatalf("new root account: %+v", c)
	}
	page := e.get("/check/jenkins/sec.accounts.jenkins").Body.String()
	if !strings.Contains(page, "Accept current accounts and SSH keys") {
		t.Error("no accept button")
	}
	rec := httptest.NewRecorder()
	e.ui.ServeHTTP(rec, form("/check/jenkins/sec.accounts.jenkins/accept", nil, map[string]string{"Sec-Fetch-Site": "same-origin"}))
	if c, _ := e.srv.Store.Check(ctx, "jenkins", "sec.accounts.jenkins"); c.State != eval.OK {
		t.Errorf("after accept: %+v", c)
	}
	*e.clock = e.clock.Add(time.Minute)
	e.post("tok-jenkins", acc(`"uid0 root"`))
	if c, _ := e.srv.Store.Check(ctx, "jenkins", "sec.accounts.jenkins"); c.State != eval.Crit || !strings.Contains(c.Summary, "gone: uid0 toor, key root") {
		t.Errorf("removed key: %+v", c)
	}
}

func TestShortID(t *testing.T) {
	for _, tc := range [][3]string{
		{"monster-p4", "disk.monster-p4.root", "disk.root"},
		{"jenkins", "ts.online.jenkins", "ts.online"},
		{"jenkins", "pkg.version.p4d", "pkg.version.p4d"},
		{"serve", "tls.code-review", "tls.code-review"},
		{"jenkins", "jenkins", "jenkins"},
	} {
		if got := shortID(tc[0], tc[1]); got != tc[2] {
			t.Errorf("shortID(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
}

func TestNetMap(t *testing.T) {
	hosts := []config.Host{{Name: "a", PublicIP: "192.0.2.1"}, {Name: "b", NotOnTailnet: true}}
	cv := func(host, id string, s eval.State) checkView {
		return checkView{Check: store.Check{Host: host, ID: id, State: s, Summary: id}, Effective: s}
	}
	all := []checkView{
		cv("a", "ports.public.a", eval.OK),
		cv("a", "auth.logins.a", eval.Crit),
		cv("a", "ts.online.a", eval.OK),
		cv("a", "disk.a.root", eval.Warn),
	}
	m := buildMap(hosts, nil, all, nil)
	a, b := m.Nodes[0], m.Nodes[1]
	if a.Internet.State != "crit" || a.Internet.Href != "/check/a/auth.logins.a" || a.Tailnet.State != "ok" {
		t.Errorf("a: %+v", a)
	}
	if b.Internet.On || b.Tailnet.On {
		t.Errorf("b has no public IP and is not on the tailnet: %+v", b)
	}
	if len(m.Narrow) != 2 || m.H <= 0 || a.Internet.Path == "" {
		t.Errorf("layout: %+v", m)
	}
}
