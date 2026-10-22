package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

func TestParseFeeds(t *testing.T) {
	// Tailscale: the title is only the id; the escaped HTML description fills it in.
	ts := `<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>TS-2026-013</title><link>https://tailscale.com/security-bulletins/#ts-2026-013</link>
<guid>https://tailscale.com/security-bulletins/#ts-2026-013</guid><pubDate>Wed, 21 Oct 2026 00:00:00 GMT</pubDate>
<description>&lt;p&gt;&lt;strong&gt;&lt;em&gt;Description&lt;/em&gt;&lt;/strong&gt;: Leaked private keys for eMudhra TLS intermediate certificates&lt;/p&gt;</description></item>
</channel></rss>`
	items, err := parseFeed([]byte(ts), config.NoticeFeed{URL: "https://x"})
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	if it := items[0]; it.Title != "TS-2026-013 Leaked private keys for eMudhra TLS intermediate certificates" ||
		it.ID != "https://tailscale.com/security-bulletins/#ts-2026-013" || !it.Date.Equal(time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("tailscale: %+v", it)
	}

	// Jenkins pads every field with newlines.
	jk := "<rss version=\"2.0\"><channel><item>\n<title>\nJenkins Security Advisory 2026-09-16\n</title>\n<pubDate>\nWed, 16 Sep 2026 12:00:00 +0000\n</pubDate>\n<link>\nhttps://www.jenkins.io/security/advisory/2026-09-16/\n</link>\n</item></channel></rss>"
	items, err = parseFeed([]byte(jk), config.NoticeFeed{URL: "https://x"})
	if err != nil || len(items) != 1 || items[0].Title != "Jenkins Security Advisory 2026-09-16" ||
		items[0].Link != "https://www.jenkins.io/security/advisory/2026-09-16/" || items[0].Date.IsZero() {
		t.Errorf("jenkins: %+v %v", items, err)
	}

	// exe.dev: real feed.
	body, _ := os.ReadFile("testdata/exe-dev-security.atom")
	items, err = parseFeed(body, config.NoticeFeed{URL: "https://x"})
	if err != nil || len(items) != 2 || items[0].Title != "Third-party: eMudhra CA cert compromise" ||
		items[0].Link != "https://exe.dev/security/emudhra-compromise" || items[0].Date.Format("2006-01-02") != "2026-10-20" {
		t.Errorf("exe.dev: %+v %v", items, err)
	}

	// PHP: real feed, security releases of the 8.3 branch only.
	body, _ = os.ReadFile("testdata/php-releases.atom")
	items, err = parseFeed(body, config.NoticeFeed{URL: "https://x", Tag: "security", Title: `^PHP 8\.3\.`})
	if err != nil || len(items) != 1 || items[0].Title != "PHP 8.3.36 released!" {
		t.Errorf("php: %+v %v", items, err)
	}

	// DigitalOcean: Atom category term filter.
	do := `<feed xmlns="http://www.w3.org/2005/Atom">
<entry><title type="html"><![CDATA[Patch PHP now]]></title><id>a</id><link href="https://do/a"/><category term="trust-security"/><published>2026-10-21T21:46:53.195Z</published></entry>
<entry><title>New GPUs</title><id>b</id><link href="https://do/b"/><category term="product-updates"/></entry></feed>`
	items, err = parseFeed([]byte(do), config.NoticeFeed{URL: "https://x", Tag: "trust-security"})
	if err != nil || len(items) != 1 || items[0].Title != "Patch PHP now" {
		t.Errorf("do: %+v %v", items, err)
	}

	if _, err := parseFeed([]byte("not xml at all"), config.NoticeFeed{URL: "https://x"}); err == nil {
		t.Error("garbage parsed")
	}
}

func rss(items ...string) string {
	return `<rss version="2.0"><channel>` + strings.Join(items, "") + `</channel></rss>`
}

func rssItem(id string, at time.Time) string {
	return fmt.Sprintf(`<item><title>Bulletin %s</title><guid>%s</guid><link>https://v/%s</link><pubDate>%s</pubDate></item>`, id, id, id, at.Format(time.RFC1123Z))
}

func noticeProber(t *testing.T, feedURL string) *Prober {
	t.Helper()
	return newProber(t, &config.Server{Notices: config.Notices{Enabled: true, KEVDisabled: true,
		Feeds: []config.NoticeFeed{{Name: "vendor", URL: feedURL, State: "crit"}}}})
}

func TestNoticeLifecycle(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(rss(rssItem("old", t0.Add(-30*24*time.Hour)), rssItem("recent", t0.Add(-3*24*time.Hour))))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("User-Agent") != noticeUA {
			t.Errorf("user agent %q", r.Header.Get("User-Agent"))
		}
		w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	p := noticeProber(t, srv.URL)
	ctx := context.Background()

	// First run: the 30-day-old bulletin counts as seen, the recent one is new.
	c := find(t, p.noticeChecks(ctx), "notice.vendor")
	if c.State != eval.Crit || !strings.HasPrefix(c.Summary, "1 new: Bulletin recent (2026-10-19)") {
		t.Fatalf("first run: %+v", c)
	}

	// Accept: the next run is ok, and it does not fetch again within the interval.
	data, _ := json.Marshal(c.Data)
	if err := AcceptNotice(ctx, p.kv, "notice.vendor", data); err != nil {
		t.Fatal(err)
	}
	c = find(t, p.noticeChecks(ctx), "notice.vendor")
	if c.State != eval.OK || hits.Load() != 1 {
		t.Fatalf("after accept: %+v, %d fetches", c, hits.Load())
	}

	// A new bulletin after the interval is crit again; the accepted ones stay seen.
	body.Store(rss(rssItem("newest", t0), rssItem("old", t0.Add(-30*24*time.Hour)), rssItem("recent", t0.Add(-3*24*time.Hour))))
	p.now = func() time.Time { return t0.Add(61 * time.Minute) }
	c = find(t, p.noticeChecks(ctx), "notice.vendor")
	if c.State != eval.Crit || !strings.HasPrefix(c.Summary, "1 new: Bulletin newest") || hits.Load() != 2 {
		t.Fatalf("new bulletin: %+v, %d fetches", c, hits.Load())
	}

	// The feed failing keeps the last list and warns at least.
	body.Store("<html>Bad gateway")
	p.now = func() time.Time { return t0.Add(3 * time.Hour) }
	c = find(t, p.noticeChecks(ctx), "notice.vendor")
	if c.State != eval.Crit || !strings.HasPrefix(c.Summary, "feed unreachable") || !strings.Contains(c.Summary, "1 new") {
		t.Fatalf("broken feed: %+v", c)
	}

	if AcceptNotice(ctx, p.kv, JenkinsWarningsID, data) == nil {
		t.Error("jenkins warnings accepted")
	}
}

func TestNoticeFirstRunEmptyThenItems(t *testing.T) {
	// The seen list is only seeded once there are items; an empty first fetch
	// must not make every later notice look "old".
	var body atomic.Value
	body.Store(rss())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body.Load().(string))) }))
	defer srv.Close()
	p := noticeProber(t, srv.URL)
	ctx := context.Background()
	if c := find(t, p.noticeChecks(ctx), "notice.vendor"); c.State != eval.OK || c.Summary != "no notices" {
		t.Fatalf("empty: %+v", c)
	}
	body.Store(rss(rssItem("a", t0.Add(-40*24*time.Hour))))
	p.now = func() time.Time { return t0.Add(2 * time.Hour) }
	if c := find(t, p.noticeChecks(ctx), "notice.vendor"); c.State != eval.OK {
		t.Fatalf("old item on first seeding: %+v", c)
	}
}

func TestNoticeRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/moved":
			http.Redirect(w, r, srv.URL+"/feed", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
		case "/feed":
			w.Write([]byte(rss(rssItem("x", t0))))
		}
	}))
	defer srv.Close()
	p := noticeProber(t, srv.URL+"/moved")
	if c := find(t, p.noticeChecks(context.Background()), "notice.vendor"); c.State != eval.Crit {
		t.Errorf("redirect not followed: %+v", c)
	}
	p = noticeProber(t, srv.URL+"/loop")
	if c := find(t, p.noticeChecks(context.Background()), "notice.vendor"); c.State != eval.Warn || !strings.Contains(c.Summary, "redirects") {
		t.Errorf("redirect loop: %+v", c)
	}
}

func TestParseKEV(t *testing.T) {
	cat := `{"vulnerabilities":[
{"cveID":"CVE-2024-23897","vendorProject":"Jenkins","product":"Jenkins Command Line Interface (CLI)","vulnerabilityName":"Jenkins CLI Path Traversal","dateAdded":"2024-08-19"},
{"cveID":"CVE-2019-12922","vendorProject":"phpMyAdmin","product":"phpMyAdmin","vulnerabilityName":"phpMyAdmin CSRF","dateAdded":"2022-03-25"},
{"cveID":"CVE-2024-4577","vendorProject":"PHP Group","product":"PHP","vulnerabilityName":"PHP-CGI OS Command Injection","dateAdded":"2024-06-12"},
{"cveID":"CVE-2026-1","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"x","dateAdded":"2026-10-20"}]}`
	items, err := parseKEV([]byte(cat), config.DefaultKEVProducts)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	if got := strings.Join(ids, ","); got != "CVE-2024-23897,CVE-2024-4577" {
		t.Errorf("matched %s", got)
	}
	if items[0].Link != "https://nvd.nist.gov/vuln/detail/CVE-2024-23897" {
		t.Errorf("link %q", items[0].Link)
	}
}

func TestJenkinsWarnings(t *testing.T) {
	uc := `{"warnings":[
{"id":"SECURITY-1","type":"plugin","name":"git-client","message":"&lt;b&gt;XSS&lt;/b&gt;","url":"https://jenkins.io/a","versions":[{"lastVersion":"3.1","pattern":"3[.]0|3[.]1(|[.-].*)"}]},
{"id":"SECURITY-2","type":"plugin","name":"git-client","message":"old","url":"https://jenkins.io/b","versions":[{"lastVersion":"2.9","pattern":"2[.].*"}]},
{"id":"SECURITY-3","type":"plugin","name":"script-security","message":"all versions","url":"https://jenkins.io/c","versions":[]},
{"id":"core-2_560","type":"core","name":"core","message":"core bug","url":"https://jenkins.io/d","versions":[{"lastVersion":"2.560","pattern":"2[.]5[0-5][0-9](|[.-].*)|2[.]560"}]},
{"id":"SECURITY-4","type":"plugin","name":"not-installed","message":"x","url":"https://jenkins.io/e","versions":[]}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/uc":
			w.Write([]byte(uc))
		case "/pluginManager/api/json":
			if u, pw, _ := r.BasicAuth(); u != "mpinfra" || pw != "jt" {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("X-Jenkins", "2.568.3")
			w.Write([]byte(`{"plugins":[{"shortName":"git-client","version":"3.1.2"},{"shortName":"script-security","version":"1300.v1"}]}`))
		}
	}))
	defer srv.Close()
	t.Setenv("JT", "jt")
	p := newProber(t, &config.Server{Hosts: []config.Host{{Name: "jenkins"}},
		Jenkins: config.Jenkins{URL: srv.URL, User: "mpinfra", TokenEnv: "JT"},
		Notices: config.Notices{Enabled: true, KEVDisabled: true, Feeds: []config.NoticeFeed{}, JenkinsWarnings: true, UpdateCenterURL: srv.URL + "/uc"}})
	p.cfg.Notices.Feeds = nil // only the Jenkins match in this test
	c := find(t, p.noticeChecks(context.Background()), JenkinsWarningsID)
	if c.Host != "jenkins" || c.State != eval.Crit || !strings.Contains(c.Summary, "git-client 3.1.2 (SECURITY-1)") ||
		!strings.Contains(c.Summary, "script-security 1300.v1 (SECURITY-3)") || strings.Contains(c.Summary, "SECURITY-2") || strings.Contains(c.Summary, "core") {
		t.Errorf("%+v", c)
	}
}

func TestNoticesOff(t *testing.T) {
	p := newProber(t, &config.Server{Notices: config.Notices{Enabled: false}})
	if cs := p.noticeChecks(context.Background()); len(cs) != 0 {
		t.Errorf("%+v", cs)
	}
}
