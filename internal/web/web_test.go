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
	for _, want := range []string{"monster-p4", "jenkins-win", "never reported", "host.uptime", `http-equiv="refresh"`, "/static/app.js", "/static/style.css"} {
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
		{"name":"MacBook-Pro-7","machine":"studio-mac","os":"macOS","addr":"100.64.0.5","connected":true,"tags":["tag:dev"]},
		{"name":"<b>phone</b>","os":"iOS","connected":true},
		{"name":"old-pc","os":"windows","connected":false,"last_seen":"2026-10-20T14:00:00Z"}]}`
	e.srv.Store.PutCheck(context.Background(), store.Check{Host: config.ServeHost, ID: "ts.devices", State: eval.OK, Summary: "4 devices", Data: data}, now)
	h := e.get("/").Body.String()
	for _, want := range []string{"Tailnet", "2 other devices connected", "1 offline", "studio-mac", "100.64.0.5", "tag:dev", "os-laptop", "os-phone", "&lt;b&gt;phone", "old-pc", "last seen 2 d ago"} {
		if !strings.Contains(h, want) {
			t.Errorf("home lacks %q", want)
		}
	}
	if strings.Contains(h, "MacBook-Pro-7") {
		t.Error("renamed device shown by its hostname")
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
	m := buildMap(hosts, nil, nil, all, nil)
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

func TestNetMapSealed(t *testing.T) {
	// Nothing open and nothing wrong: no line and no badges. A problem keeps the
	// line's colour and pulse even with nothing open.
	hosts := []config.Host{{Name: "a", PublicIP: "192.0.2.1"}, {Name: "b", PublicIP: "192.0.2.2"}, {Name: "c", PublicIP: "192.0.2.3"}}
	cv := func(host, id string, s eval.State, data string) checkView {
		return checkView{Check: store.Check{Host: host, ID: id, State: s, Summary: id, Data: data}, Effective: s}
	}
	all := []checkView{
		cv("a", "ports.public.a", eval.OK, `{"open":[]}`),
		cv("b", "ports.public.b", eval.OK, `{"open":[]}`),
		cv("b", "auth.failures.b", eval.Warn, `{}`),
		cv("c", "ports.public.c", eval.OK, `{"open":[22],"expected":[22]}`),
	}
	m := buildMap(hosts, nil, nil, all, nil)
	if l := m.Nodes[0].Internet; !l.Sealed || len(l.Badges) > 0 || len(m.Narrow[0].Internet.Badges) > 0 {
		t.Errorf("a: %+v", l)
	}
	if l := m.Nodes[1].Internet; l.Sealed || l.State != "warn" {
		t.Errorf("b: %+v", l)
	}
	if l := m.Nodes[2].Internet; l.Sealed || l.Icon == "lock" {
		t.Errorf("c: %+v", l)
	}
}

func TestNetMapSSHAuth(t *testing.T) {
	hosts := []config.Host{{Name: "a", PublicIP: "192.0.2.1"}, {Name: "b", PublicIP: "192.0.2.2"}, {Name: "c", PublicIP: "192.0.2.3"}}
	cv := func(host, id string, s eval.State, data string) checkView {
		return checkView{Check: store.Check{Host: host, ID: id, State: s, Summary: id, Data: data}, Effective: s}
	}
	ports := `{"open":[22,443],"expected":[22,443]}`
	all := []checkView{
		cv("a", "ports.public.a", eval.OK, ports),
		cv("a", "ssh.auth.a", eval.OK, `{"ports":[22],"mode":"key"}`),
		cv("b", "ports.public.b", eval.OK, ports),
		cv("b", "ssh.auth.b", eval.Warn, `{"ports":[22],"mode":"password"}`),
		cv("c", "ports.public.c", eval.OK, ports),
		cv("c", "ssh.auth.c", eval.OK, `{"ports":[22],"mode":"<script>"}`), // hostile report
	}
	m := buildMap(hosts, nil, nil, all, nil)
	chip := func(n int, port string) mapBadge {
		for _, b := range m.Nodes[n].Internet.Badges {
			if b.Chip == port {
				return b
			}
		}
		t.Fatalf("node %d: no chip %s in %+v", n, port, m.Nodes[n].Internet.Badges)
		return mapBadge{}
	}
	if c := chip(0, "22"); c.Auth != "key" || c.Class != "open" || !strings.Contains(c.Title, "keys only") || c.W != chipW("22")+authW {
		t.Errorf("a:22 %+v", c)
	}
	if c := chip(0, "443"); c.Auth != "" {
		t.Errorf("a:443 %+v", c)
	}
	b := m.Nodes[1].Internet
	if c := chip(1, "22"); c.Auth != "password" || c.Class != "pwd" || !strings.Contains(c.Title, "accepts passwords") {
		t.Errorf("b:22 %+v", c)
	}
	if b.State != "warn" || b.Alert != nil {
		t.Errorf("b: passwords colour the line without an alert icon: %+v", b)
	}
	if c := chip(2, "22"); c.Auth != "" {
		t.Errorf("c:22 took an unknown mode: %+v", c)
	}
}

func TestNetMapLinks(t *testing.T) {
	hosts := []config.Host{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	links := []config.Link{
		{From: "a", To: "c", Port: 1666},
		{From: "b", To: "a", Port: 50001, Public: true, Check: "jenkins.agent.b"},
		{From: "c", To: "b", Check: "x.y"},        // its check sits on a, not an end
		{From: "a", To: "gone", Label: "ignored"}, // not on the map
	}
	all := []checkView{
		{Check: store.Check{Host: "b", ID: "jenkins.agent.b", Summary: "agent b offline"}, Effective: eval.Warn},
		{Check: store.Check{Host: "a", ID: "x.y"}, Effective: eval.Crit},
	}
	m := buildMap(hosts, links, nil, all, nil)
	if len(m.Links) != 3 || len(m.NarrowLinks) != 3 {
		t.Fatalf("links: %+v", m.Links)
	}
	ac, ba, cb := m.Links[0], m.Links[1], m.Links[2]
	if ac.State != "none" || len(ac.Badges) != 1 || ac.Badges[0].Chip != "1666" || !strings.Contains(ac.Title, "a → c :1666 over the tailnet") {
		t.Errorf("a->c: %+v", ac)
	}
	if ba.State != "warn" || ba.Href != "/check/b/jenkins.agent.b" || !strings.Contains(ba.Title, "agent b offline") {
		t.Errorf("b->a: %+v", ba)
	}
	if cb.State != "none" || cb.Href != "" || len(cb.Badges) != 0 {
		t.Errorf("c->b took a check from a host it does not touch: %+v", cb)
	}
	// Tailnet arcs bulge right of the column, public ones left; both arrive at To.
	if !strings.HasPrefix(ac.Path, "M635 ") || !strings.HasPrefix(ba.Path, "M365 ") || ac.Arrow == "" || m.NarrowLinks[0].Badges != nil {
		t.Errorf("layout: %q %q %+v", ac.Path, ba.Path, m.NarrowLinks[0])
	}
}

func TestNetMapDevices(t *testing.T) {
	hosts := []config.Host{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	tn := &tailnetView{}
	for _, os := range []string{"laptop", "phone", "windows", "linux", "device", "laptop", "phone", "linux", "linux", "linux", "linux", "linux"} {
		tn.Online = append(tn.Online, deviceView{Name: "d", OS: os, OSName: os, Addr: "100.64.0.1", Logo: "linux"})
	}
	m := buildMap(hosts, nil, nil, nil, tn)
	// Three rows of two fit in a three-host bubble: five devices and "+7".
	if len(m.Devices) != 5 || len(m.MoreDevices) != 1 || m.MoreDevices[0].Chip != "+7" {
		t.Fatalf("devices %d, more %+v", len(m.Devices), m.MoreDevices)
	}
	if m.Devices[0].Shape != "laptop" || m.Devices[1].Shape != "phone" || m.Devices[2].Shape != "monitor" || m.Devices[0].Logo != "linux" || m.Devices[0].Title != "d · laptop · 100.64.0.1" {
		t.Errorf("shapes: %+v", m.Devices[:3])
	}
	for _, d := range m.Devices {
		if d.X < m.W-mapPad-mapBubbleW || d.X > m.W-mapPad || d.Y > m.H-30 {
			t.Errorf("device outside the bubble: %+v (map %vx%v)", d, m.W, m.H)
		}
	}
}

func TestNetMapFailed4h(t *testing.T) {
	hosts := []config.Host{{Name: "a"}, {Name: "b"}}
	cv := func(host, data string) checkView {
		return checkView{Check: store.Check{Host: host, ID: "auth.failures." + host, Data: data}, Effective: eval.OK}
	}
	m := buildMap(hosts, nil, nil, []checkView{cv("a", `{"total":10000,"last_4h":1200}`), cv("b", `{"total":984,"last_4h":3}`)}, nil)
	if m.Failed != "10,984" || m.Failed4h != "1,203" {
		t.Errorf("both timed: %q %q", m.Failed, m.Failed4h)
	}
	// b's agent has no timestamps yet: no 4 h figure rather than a short one.
	m = buildMap(hosts, nil, nil, []checkView{cv("a", `{"total":10000,"last_4h":1200}`), cv("b", `{"total":984}`)}, nil)
	if m.Failed != "10,984" || m.Failed4h != "" {
		t.Errorf("one untimed: %q %q", m.Failed, m.Failed4h)
	}
}

func TestMetersAndChart(t *testing.T) {
	e := setup(t)
	disk := func(pct float64) string {
		return fmt.Sprintf(`{"host":"jenkins","agent_version":"1","collected_at":%q,"checks":[{"id":"disk.jenkins.root","state":"ok","summary":"/ %.0f%% used","data":{"mount":"/","total_bytes":1000,"free_bytes":%d,"used_pct":%v}}]}`,
			e.clock.Format(time.RFC3339), pct, int(1000-pct*10), pct)
	}
	start := *e.clock
	*e.clock = start.Add(-13 * 24 * time.Hour)
	for i := 0; i < 40; i++ {
		if i == 20 {
			*e.clock = e.clock.Add(3 * 24 * time.Hour) // agent down: a gap in the line
		}
		if rec := e.post("tok-jenkins", disk(50+float64(i)/2)); rec.Code != http.StatusNoContent {
			t.Fatalf("post: %d %s", rec.Code, rec.Body)
		}
		*e.clock = e.clock.Add(6 * time.Hour)
	}
	e.post("tok-jenkins", disk(72)) // now

	h := e.get("/").Body.String()
	if !strings.Contains(h, `<rect width="72.0" height="6" class="meter-fill fill-ok"/>`) || !strings.Contains(h, ">72%<") {
		t.Errorf("home lacks the disk meter")
	}
	// The CSP allows no inline styles, so nothing may depend on one.
	if strings.Contains(h, "style=") {
		t.Errorf("home uses a style attribute, which the CSP blocks")
	}

	p := e.get("/check/jenkins/disk.jenkins.root").Body.String()
	for _, want := range []string{`class="chart"`, "Disk used: now 72%, 50% to 72%", "<title>", "100%"} {
		if !strings.Contains(p, want) {
			t.Errorf("check page lacks %q", want)
		}
	}
	if n := strings.Count(p, `class="chart-hit"`); n != 41 {
		t.Errorf("%d chart points, want 41", n)
	}
	if line := between(p, `class="chart-area"/>`, `" class="chart-line"`); strings.Count(line, "M") != 2 {
		t.Errorf("line not broken at the gap: %s", line)
	}

	// Probe results have no history: no chart, but the meter.
	data := `{"days_left":10,"not_after":"2026-11-01T00:00:00Z"}`
	e.srv.Store.PutCheck(context.Background(), store.Check{Host: config.ServeHost, ID: "tls.site", State: eval.OK, Summary: "x", Data: data}, now)
	p = e.get("/check/serve/tls.site").Body.String()
	if strings.Contains(p, `class="chart"`) || !strings.Contains(p, ">10 d<") {
		t.Errorf("tls check page: chart or no meter")
	}
}

func between(s, a, b string) string {
	_, s, _ = strings.Cut(s, a)
	s, _, _ = strings.Cut(s, b)
	return s
}

func TestMeters(t *testing.T) {
	th := config.Thresholds{SnapshotCritDays: 60}
	cases := []struct {
		id, data string
		want     []string // name value pct
	}{
		{"disk.x.root", `{"used_pct":91.4,"total_bytes":100,"free_bytes":9}`, []string{" 91% 91.4"}},
		{"disk.x.root", `{"used_pct":120}`, []string{" 120% 100.0"}},
		{"p4.licence", `{"user_count":5,"user_limit":5,"client_count":40}`, []string{"users 5/5 100.0"}},
		{"tls.a", `{"days_left":45}`, []string{" 45 d 50.0"}},
		{"ts.key_expiry.h", `{"key_expiry_disabled":true,"expires":"0001-01-01T00:00:00Z"}`, nil},
		{"ts.key_expiry.h", `{"key_expiry_disabled":false,"expires":"2026-12-21T14:00:00Z"}`, []string{" 60 d 33.3"}},
		{"snapshot.age.d", `{"age_days":30}`, []string{" 30 d 50.0"}},
		{"host.uptime", `{"seconds":5}`, nil},
		{"disk.x.root", `not json`, nil},
	}
	for _, c := range cases {
		var got []string
		for _, m := range meters(checkView{Check: store.Check{ID: c.id, Data: c.data}}, th, now) {
			got = append(got, fmt.Sprintf("%s %s %.1f", m.Name, m.Value, m.Pct))
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s %s: %q, want %q", c.id, c.data, got, c.want)
		}
	}
}

func TestNoticeAccept(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	data := `{"items":[{"id":"https://exe.dev/security/emudhra-compromise","title":"Third-party: eMudhra CA cert compromise","link":"https://exe.dev/security/emudhra-compromise","date":"2026-10-20T00:00:00Z","new":true}],"new":1}`
	e.srv.Store.PutCheck(ctx, store.Check{Host: "serve", ID: "notice.exe-dev", State: eval.Crit, Summary: "1 new", Data: data}, now)
	page := e.get("/check/serve/notice.exe-dev").Body.String()
	if !strings.Contains(page, "Accept current notices") || !strings.Contains(page, `href="https://exe.dev/security/emudhra-compromise"`) {
		t.Fatalf("no accept button or notice link:\n%s", page)
	}
	rec := httptest.NewRecorder()
	e.ui.ServeHTTP(rec, form("/check/serve/notice.exe-dev/accept", nil, map[string]string{"Sec-Fetch-Site": "same-origin"}))
	if c, _ := e.srv.Store.Check(ctx, "serve", "notice.exe-dev"); c.State != eval.OK {
		t.Errorf("after accept: %+v", c)
	}
	if seen, _ := e.srv.Store.Get(ctx, "notice.exe-dev.seen"); !strings.Contains(seen, "emudhra-compromise") {
		t.Errorf("seen list %q", seen)
	}
	// The Jenkins match clears itself: no accept button.
	e.srv.Store.PutCheck(ctx, store.Check{Host: "serve", ID: "notice.jenkins.installed", State: eval.Crit, Summary: "x", Data: `{}`}, now)
	if strings.Contains(e.get("/check/serve/notice.jenkins.installed").Body.String(), "Accept current") {
		t.Error("accept offered for notice.jenkins.installed")
	}
}

func TestProblemsOnly(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for _, h := range []string{"monster-p4", "jenkins", "jenkins-win"} {
		if rec := e.post("tok-"+h, body(h, "up 5s")); rec.Code != 204 {
			t.Fatal(rec.Code, rec.Body.String())
		}
	}
	e.srv.Store.PutCheck(ctx, store.Check{Host: "serve", ID: "notice.exe-dev", State: eval.Crit, Summary: "1 new notice", Data: `{}`}, now)
	e.srv.Store.PutCheck(ctx, store.Check{Host: "serve", ID: "tls.example", State: eval.OK, Summary: "valid 80 d", Data: `{}`}, now)
	e.srv.Store.PutCheck(ctx, store.Check{Host: "serve", ID: "ts.devices", State: eval.OK, Summary: "1 device",
		Data: `{"devices":[{"name":"studio-mac","os":"macOS","connected":true}]}`}, now)

	all := e.get("/").Body.String()
	for _, want := range []string{`section-title">Hosts<`, `section-title">Tailnet<`, "Certificates", "Security notices"} {
		if !strings.Contains(all, want) {
			t.Errorf("all view lacks %q", want)
		}
	}

	rec := e.get("/?view=problems")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("set view: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	e.ui.ServeHTTP(out, req)
	h := out.Body.String()
	if !strings.Contains(h, "Security notices") || !strings.Contains(h, "1 new notice") {
		t.Error("problems view lacks the crit notice")
	}
	for _, gone := range []string{`section-title">Hosts<`, `section-title">Tailnet<`, "Certificates", "up 5s"} {
		if strings.Contains(h, gone) {
			t.Errorf("problems view shows %q", gone)
		}
	}

	rec = e.get("/?view=all")
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
		t.Errorf("view=all did not clear the cookie: %+v", c)
	}
}
