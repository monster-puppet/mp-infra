package probe

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// Security notices: vendors' public feeds (RSS/Atom), CISA's Known Exploited
// Vulnerabilities and the Jenkins update centre's warnings. Feeds and KEV become
// notice.<name> checks on serve that stay warn/crit until someone accepts the
// current notices (AcceptNotice); notice.jenkins.installed clears by itself once
// the affected core or plugin is updated.

const (
	// noticeFirstRun: on a feed's first run, items older than this are taken as
	// already seen, so only recent notices show up.
	noticeFirstRun = 14 * 24 * time.Hour
	noticeMaxItems = 20  // items kept per feed, newest first
	noticeMaxSeen  = 500 // accepted ids kept per feed
	// JenkinsWarningsID is the update-centre match; it cannot be accepted.
	JenkinsWarningsID = "notice.jenkins.installed"
	noticeUA          = "mp-infra security-notice reader (+https://monster-puppet.com)"
)

// NoticeItem is one notice as stored in a check's data.
type NoticeItem struct {
	ID    string    `json:"id"`
	Title string    `json:"title"`
	Link  string    `json:"link,omitempty"`
	Date  time.Time `json:"date,omitempty"`
	New   bool      `json:"new,omitempty"`
}

type noticeCache struct {
	at    time.Time
	items []NoticeItem
	err   error
}

func noticeSeenKey(id string) string { return id + ".seen" }

func (p *Prober) noticeChecks(ctx context.Context) []Check {
	n := p.cfg.Notices
	if !n.Enabled {
		return nil
	}
	var out []Check
	for _, f := range n.Feeds {
		id := "notice." + f.Name
		items, err := p.cachedNotices(ctx, id, n.Interval, func(ctx context.Context) ([]NoticeItem, error) {
			return p.fetchFeed(ctx, f)
		})
		out = append(out, p.noticeCheck(ctx, id, f.Name, eval.State(f.State), items, err))
	}
	if !n.KEVDisabled {
		items, err := p.cachedNotices(ctx, "notice.kev", n.SlowInterval, p.fetchKEV)
		out = append(out, p.noticeCheck(ctx, "notice.kev", "CISA known exploited", eval.Crit, items, err))
	}
	if n.JenkinsWarnings {
		if c, ok := p.jenkinsWarnings(ctx); ok {
			out = append(out, c)
		}
	}
	return out
}

// cachedNotices fetches at most once per interval and returns the last result in
// between, so the checks keep their content between fetches.
func (p *Prober) cachedNotices(ctx context.Context, id string, every time.Duration, fetch func(context.Context) ([]NoticeItem, error)) ([]NoticeItem, error) {
	now := p.now()
	p.mu.Lock()
	c, ok := p.notices[id]
	p.mu.Unlock()
	if ok && now.Sub(c.at) < every {
		return c.items, c.err
	}
	items, err := fetch(ctx)
	if err != nil && ok && c.err == nil {
		// Keep showing the last good list; the error goes in the summary.
		items = c.items
	}
	p.mu.Lock()
	p.notices[id] = noticeCache{at: now, items: items, err: err}
	p.mu.Unlock()
	return items, err
}

// noticeCheck marks items not yet accepted as new. On the first run (no seen list
// stored) everything older than noticeFirstRun counts as seen.
func (p *Prober) noticeCheck(ctx context.Context, id, what string, state eval.State, items []NoticeItem, ferr error) Check {
	c := Check{Host: config.ServeHost, ID: id, State: eval.OK}
	seen, err := p.noticeSeen(ctx, id, items)
	if err != nil {
		return errCheck(config.ServeHost, id, eval.Warn, err)
	}
	var fresh []NoticeItem
	shown := make([]NoticeItem, len(items))
	for i, it := range items {
		it.New = !seen[it.ID]
		if it.New {
			fresh = append(fresh, it)
		}
		shown[i] = it
	}
	data := map[string]any{"items": shown, "new": len(fresh)}
	switch {
	case len(fresh) > 0:
		c.State = state
		parts := make([]string, 0, len(fresh))
		for _, it := range fresh {
			s := it.Title
			if !it.Date.IsZero() {
				s += " (" + it.Date.UTC().Format("2006-01-02") + ")"
			}
			parts = append(parts, s)
		}
		c.Summary = fmt.Sprintf("%d new: %s", len(fresh), strings.Join(parts, "; "))
	case len(items) == 0 && ferr == nil:
		c.Summary = "no notices"
	default:
		c.Summary = "no new notices"
		if len(items) > 0 {
			c.Summary += ", latest " + items[0].Title
		}
	}
	if ferr != nil {
		data["error"] = clip(ferr.Error(), 300)
		c.State = eval.Worst(c.State, eval.Warn)
		c.Summary = "feed unreachable: " + clip(ferr.Error(), 150) + "; " + c.Summary
	}
	c.Summary = clip(c.Summary, 300)
	c.Data = data
	return c
}

// noticeSeen returns the accepted ids for a notice check, seeding them on the
// first run that has items.
func (p *Prober) noticeSeen(ctx context.Context, id string, items []NoticeItem) (map[string]bool, error) {
	seen := map[string]bool{}
	if p.kv == nil {
		return seen, nil
	}
	raw, err := p.kv.Get(ctx, noticeSeenKey(id))
	if err != nil {
		return nil, err
	}
	if raw == "" {
		if len(items) == 0 {
			return seen, nil
		}
		cutoff := p.now().Add(-noticeFirstRun)
		var old []string
		for _, it := range items {
			if !it.Date.IsZero() && it.Date.Before(cutoff) {
				old = append(old, it.ID)
			}
		}
		// A marker line keeps an all-new first run from seeding again next time.
		if err := p.kv.Set(ctx, noticeSeenKey(id), strings.Join(append([]string{"#seeded"}, old...), "\n")); err != nil {
			return nil, err
		}
		raw = strings.Join(old, "\n")
	}
	for _, s := range strings.Split(raw, "\n") {
		if s != "" {
			seen[s] = true
		}
	}
	return seen, nil
}

// NoticeAcceptable reports whether id is a notice check that is accepted by hand.
func NoticeAcceptable(id string) bool {
	return strings.HasPrefix(id, "notice.") && id != JenkinsWarningsID
}

// AcceptNotice marks every item in a notice check's data as seen.
func AcceptNotice(ctx context.Context, kv KV, id string, data []byte) error {
	if !NoticeAcceptable(id) {
		return fmt.Errorf("%s is not a notice check", id)
	}
	var d struct {
		Items []NoticeItem `json:"items"`
	}
	if json.Unmarshal(data, &d) != nil || len(d.Items) == 0 {
		return errors.New("no notices to accept")
	}
	raw, err := kv.Get(ctx, noticeSeenKey(id))
	if err != nil {
		return err
	}
	lines := []string{"#seeded"}
	have := map[string]bool{"#seeded": true}
	for _, it := range d.Items {
		if !have[it.ID] {
			have[it.ID] = true
			lines = append(lines, it.ID)
		}
	}
	for _, s := range strings.Split(raw, "\n") {
		if s != "" && !have[s] && len(lines) < noticeMaxSeen {
			have[s] = true
			lines = append(lines, s)
		}
	}
	return kv.Set(ctx, noticeSeenKey(id), strings.Join(lines, "\n"))
}

// --- fetching ---

// fetch GETs a public feed, following up to 3 redirects that stay on https (or
// the original scheme). The probe client never follows redirects, because it
// carries tokens; these requests carry none.
func (p *Prober) fetch(ctx context.Context, u string) ([]byte, error) {
	for hop := 0; ; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", noticeUA)
		resp, err := p.client.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 == 3 {
			loc, err := resp.Location()
			if err != nil || hop >= 3 {
				return nil, fmt.Errorf("GET %s: too many or bad redirects", redact(u))
			}
			if loc.Scheme != "https" && loc.Scheme != req.URL.Scheme {
				return nil, fmt.Errorf("GET %s: redirect to %s refused", redact(u), loc.Scheme)
			}
			u = loc.String()
			continue
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("GET %s: %s", redact(u), resp.Status)
		}
		return body, nil
	}
}

type feedDoc struct {
	Items   []feedItem `xml:"channel>item"` // RSS
	Entries []feedItem `xml:"entry"`        // Atom
}

type feedItem struct {
	Title       string     `xml:"title"`
	Links       []feedLink `xml:"link"`
	GUID        string     `xml:"guid"`
	ID          string     `xml:"id"`
	PubDate     string     `xml:"pubDate"`
	Published   string     `xml:"published"`
	Updated     string     `xml:"updated"`
	Description string     `xml:"description"`
	Summary     string     `xml:"summary"`
	Categories  []feedCat  `xml:"category"`
	PHPTags     []string   `xml:"http://php.net/ns/releases tag"`
}

type feedLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
	Text string `xml:",chardata"`
}

type feedCat struct {
	Term string `xml:"term,attr"`
	Text string `xml:",chardata"`
}

func (p *Prober) fetchFeed(ctx context.Context, f config.NoticeFeed) ([]NoticeItem, error) {
	body, err := p.fetch(ctx, f.URL)
	if err != nil {
		return nil, err
	}
	return parseFeed(body, f)
}

var feedDateLayouts = []string{time.RFC1123Z, time.RFC1123, time.RFC3339Nano, time.RFC3339, "Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST"}

func parseFeedDate(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, l := range feedDateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

var (
	tagRE     = regexp.MustCompile(`<[^>]*>`)
	descLabel = regexp.MustCompile(`^Description\s*:\s*`)
)

// plain strips markup and squeezes whitespace.
func plain(s string) string {
	return strings.Join(strings.Fields(html.UnescapeString(tagRE.ReplaceAllString(html.UnescapeString(s), " "))), " ")
}

func parseFeed(body []byte, f config.NoticeFeed) ([]NoticeItem, error) {
	var doc feedDoc
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	// Not strict, with HTML entities: some feeds carry &nbsp; and the like. No
	// HTML auto-close, which would end RSS <link> elements early.
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: not an RSS or Atom feed: %w", redact(f.URL), err)
	}
	var title *regexp.Regexp
	if f.Title != "" {
		title = regexp.MustCompile(f.Title) // checked when the config loaded
	}
	var out []NoticeItem
	for _, it := range append(doc.Items, doc.Entries...) {
		t := plain(it.Title)
		if title != nil && !title.MatchString(t) {
			continue
		}
		if f.Tag != "" && !it.hasTag(f.Tag) {
			continue
		}
		// Bulletins titled only with an id (Tailscale's TS-2026-013) get the start
		// of their description.
		if !strings.Contains(t, " ") {
			d := descLabel.ReplaceAllString(plain(firstPara(firstNonEmpty(it.Description, it.Summary))), "")
			if d != "" {
				t = clip(t+" "+d, 140)
			}
		}
		link := it.link()
		if id := strings.TrimSpace(it.ID); link == "" && (strings.HasPrefix(id, "https://") || strings.HasPrefix(id, "http://")) {
			link = id // PHP's entries only carry enclosure links; the id is the release page
		}
		n := NoticeItem{
			ID:    clip(firstNonEmpty(strings.TrimSpace(it.GUID), strings.TrimSpace(it.ID), link, t), 300),
			Title: clip(t, 200),
			Link:  link,
			Date:  parseFeedDate(firstNonEmpty(it.PubDate, it.Published, it.Updated)),
		}
		if n.ID == "" {
			continue
		}
		out = append(out, n)
	}
	return sortNotices(out), nil
}

func (it feedItem) hasTag(tag string) bool {
	for _, c := range it.Categories {
		if strings.EqualFold(strings.TrimSpace(c.Term), tag) || strings.EqualFold(strings.TrimSpace(c.Text), tag) {
			return true
		}
	}
	for _, t := range it.PHPTags {
		if strings.EqualFold(strings.TrimSpace(t), tag) {
			return true
		}
	}
	return false
}

func (it feedItem) link() string {
	for _, l := range it.Links {
		if l.Href != "" && (l.Rel == "" || l.Rel == "alternate") {
			return strings.TrimSpace(l.Href)
		}
	}
	for _, l := range it.Links {
		if s := strings.TrimSpace(l.Text); s != "" {
			return s
		}
	}
	return ""
}

// firstPara is the HTML up to the end of the first paragraph.
func firstPara(h string) string {
	if i := strings.Index(strings.ToLower(h), "</p>"); i >= 0 {
		return h[:i]
	}
	return h
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

// sortNotices orders newest first and keeps noticeMaxItems.
func sortNotices(items []NoticeItem) []NoticeItem {
	sort.SliceStable(items, func(i, j int) bool { return items[i].Date.After(items[j].Date) })
	if len(items) > noticeMaxItems {
		items = items[:noticeMaxItems]
	}
	return items
}

// --- CISA KEV ---

type kevCatalog struct {
	Vulnerabilities []struct {
		CVE       string `json:"cveID"`
		Vendor    string `json:"vendorProject"`
		Product   string `json:"product"`
		Name      string `json:"vulnerabilityName"`
		DateAdded string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

func (p *Prober) fetchKEV(ctx context.Context) ([]NoticeItem, error) {
	body, err := p.fetch(ctx, p.cfg.Notices.KEVURL)
	if err != nil {
		return nil, err
	}
	return parseKEV(body, p.cfg.Notices.KEVProducts)
}

func parseKEV(body []byte, products []string) ([]NoticeItem, error) {
	var cat kevCatalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, fmt.Errorf("KEV catalogue: %w", err)
	}
	var res []*regexp.Regexp
	for _, p := range products {
		if p = strings.TrimSpace(p); p != "" {
			res = append(res, regexp.MustCompile(`(?i)\b`+regexp.QuoteMeta(p)+`\b`))
		}
	}
	var out []NoticeItem
	for _, v := range cat.Vulnerabilities {
		what := v.Vendor + " " + v.Product
		match := false
		for _, re := range res {
			if re.MatchString(what) {
				match = true
				break
			}
		}
		if !match || v.CVE == "" {
			continue
		}
		d, _ := time.Parse("2006-01-02", v.DateAdded)
		out = append(out, NoticeItem{
			ID:    v.CVE,
			Title: clip(v.CVE+" "+v.Vendor+" "+v.Product+": "+v.Name, 200),
			Link:  "https://nvd.nist.gov/vuln/detail/" + v.CVE,
			Date:  d,
		})
	}
	return sortNotices(out), nil
}

// --- Jenkins update centre ---

type ucWarning struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // core or plugin
	Name     string `json:"name"`
	Message  string `json:"message"`
	URL      string `json:"url"`
	Versions []struct {
		LastVersion string `json:"lastVersion"`
		Pattern     string `json:"pattern"`
	} `json:"versions"`
}

// installedComponent is a Jenkins core or plugin version.
type installedComponent struct{ Type, Name, Version string }

// jenkinsWarnings matches the update centre's warnings against the installed core
// and plugins. ok is false when the jenkins section is not configured.
func (p *Prober) jenkinsWarnings(ctx context.Context) (Check, bool) {
	j := p.cfg.Jenkins
	token := config.Env(j.TokenEnv)
	if j.URL == "" || token == "" {
		return Check{}, false
	}
	id, host := JenkinsWarningsID, p.hostFor("jenkins")
	warnings, err := p.cachedWarnings(ctx)
	if err != nil {
		return errCheck(host, id, eval.Warn, fmt.Errorf("update centre: %w", err)), true
	}
	installed, err := p.jenkinsInstalled(ctx, token)
	if err != nil {
		return errCheck(host, id, eval.Warn, err), true
	}
	return evalJenkinsWarnings(host, warnings, installed), true
}

func (p *Prober) cachedWarnings(ctx context.Context) ([]ucWarning, error) {
	now := p.now()
	p.mu.Lock()
	c, ok := p.ucWarnings, !p.ucAt.IsZero() && now.Sub(p.ucAt) < p.cfg.Notices.SlowInterval
	p.mu.Unlock()
	if ok {
		return c, nil
	}
	body, err := p.fetch(ctx, p.cfg.Notices.UpdateCenterURL)
	if err != nil {
		return nil, err
	}
	var uc struct {
		Warnings []ucWarning `json:"warnings"`
	}
	if err := json.Unmarshal(body, &uc); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.ucWarnings, p.ucAt = uc.Warnings, now
	p.mu.Unlock()
	return uc.Warnings, nil
}

func (p *Prober) jenkinsInstalled(ctx context.Context, token string) ([]installedComponent, error) {
	req, err := p.jenkinsReq(ctx, http.MethodGet, "/pluginManager/api/json?tree=plugins[shortName,version]", token)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s: %s", redact(req.URL.String()), resp.Status)
	}
	var pm struct {
		Plugins []struct {
			ShortName string `json:"shortName"`
			Version   string `json:"version"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(body, &pm); err != nil {
		return nil, fmt.Errorf("plugin list: %w", err)
	}
	var out []installedComponent
	if v := resp.Header.Get("X-Jenkins"); v != "" {
		out = append(out, installedComponent{"core", "core", v})
	}
	for _, pl := range pm.Plugins {
		out = append(out, installedComponent{"plugin", pl.ShortName, pl.Version})
	}
	return out, nil
}

func evalJenkinsWarnings(host string, warnings []ucWarning, installed []installedComponent) Check {
	type match struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Message string `json:"message"`
		URL     string `json:"url"`
	}
	var hits []match
	for _, comp := range installed {
		for _, w := range warnings {
			if w.Type != comp.Type || w.Name != comp.Name || !warningApplies(w, comp.Version) {
				continue
			}
			hits = append(hits, match{w.ID, comp.Name, comp.Version, clip(plain(w.Message), 200), w.URL})
		}
	}
	c := Check{Host: host, ID: JenkinsWarningsID, State: eval.OK, Data: map[string]any{"matches": hits, "installed": len(installed), "warnings": len(warnings)}}
	if len(hits) == 0 {
		c.Summary = fmt.Sprintf("no security warnings for the %d installed components", len(installed))
		return c
	}
	c.State = eval.Crit
	parts := make([]string, len(hits))
	for i, h := range hits {
		parts[i] = fmt.Sprintf("%s %s (%s)", h.Name, h.Version, h.ID)
	}
	c.Summary = clip(fmt.Sprintf("%d security warning(s) for installed Jenkins components: %s", len(hits), strings.Join(parts, ", ")), 300)
	return c
}

// warningApplies uses Jenkins' rule: no version ranges means every version, else
// the version must fully match one of the patterns.
func warningApplies(w ucWarning, version string) bool {
	if len(w.Versions) == 0 {
		return true
	}
	for _, v := range w.Versions {
		re, err := regexp.Compile(`^(?:` + v.Pattern + `)$`)
		if err == nil && re.MatchString(version) {
			return true
		}
	}
	return false
}
