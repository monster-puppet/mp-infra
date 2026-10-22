// Package web serves the UI (tailnet members) and the report API (reporting
// hosts) on two separate handlers, so each can listen on its own port.
package web

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/probe"
	"github.com/monster-puppet/mp-infra/internal/report"
	"github.com/monster-puppet/mp-infra/internal/server"
	"github.com/monster-puppet/mp-infra/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Web holds the handlers.
type Web struct {
	srv    *server.Server
	who    Whoiser
	google *GoogleAuth // nil: no sign-in, the tailnet ACL is the only gate
	pages  map[string]*template.Template

	mcpTokens config.Tokens // MCP clients; empty: no /mcp

	mu   sync.RWMutex
	meta map[string]store.HostMeta // labels and OS set in the UI, by host
}

// New builds the handlers. who may be nil (viewer shown as their address).
func New(srv *server.Server, who Whoiser) *Web {
	if who == nil {
		who = noWhois{}
	}
	w := &Web{srv: srv, who: who, pages: map[string]*template.Template{}, meta: map[string]store.HostMeta{}}
	if m, err := srv.Store.HostMetas(context.Background()); err != nil {
		log.Printf("host labels: %v", err)
	} else {
		w.meta = m
	}
	funcs := template.FuncMap{
		"ago":      func(t time.Time) string { return ago(srv.Now(), t) },
		"date":     func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
		"checkURL": checkURL,
		"shortID":  shortID,
		"add":      func(a, b any) float64 { return num(a) + num(b) },
		"sub":      func(a, b any) float64 { return num(a) - num(b) },
		"half":     func(a any) float64 { return num(a) / 2 },
		"badge":    func(x, y any) mapBadge { return mapBadge{X: num(x), Y: num(y), Icon: "target"} },
		"pathEsc":  url.PathEscape,
		"label":    w.label,
		"osName":   func(os string) string { return config.OSNames[os] },
	}
	for _, page := range []string{"home", "check", "history", "error", "signin", "host"} {
		w.pages[page] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+page+".html"))
	}
	return w
}

// RequireGoogle puts every UI page except the open ones behind Google sign-in.
// Call it before UI.
func (w *Web) RequireGoogle(g *GoogleAuth) { w.google = g }

// hosts returns the configured hosts with the labels and OS set in the UI applied.
func (w *Web) hosts() []config.Host {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]config.Host, len(w.srv.Cfg.Hosts))
	for i, h := range w.srv.Cfg.Hosts {
		if m, ok := w.meta[h.Name]; ok {
			h.Label, h.OS = m.Label, m.OS
		}
		out[i] = h
	}
	return out
}

func (w *Web) host(name string) (config.Host, bool) {
	for _, h := range w.hosts() {
		if h.Name == name {
			return h, true
		}
	}
	return config.Host{}, false
}

// label is the name the UI shows for a host: its label, else its name.
func (w *Web) label(host string) string {
	if h, ok := w.host(host); ok {
		return h.DisplayName()
	}
	return host
}

func checkURL(host, id string) string {
	return "/check/" + url.PathEscape(host) + "/" + url.PathEscape(id)
}

// shortID drops the host name from a check id where the card already says which
// host it is: "disk.monster-p4.root" -> "disk.root", "ts.online.jenkins" ->
// "ts.online". The full id stays in the link and the title.
func shortID(host, id string) string {
	if host == "" {
		return id
	}
	if s := strings.Replace(id, "."+host+".", ".", 1); s != id {
		return s
	}
	if s, ok := strings.CutSuffix(id, "."+host); ok && s != "" {
		return s
	}
	return id
}

// UI returns the handler for the members-only UI port.
func (w *Web) UI() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	files := http.FileServer(http.FS(static))
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheFor(24*time.Hour, files)))
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, r *http.Request) { fmt.Fprintln(rw, "ok") })
	mux.HandleFunc("GET /api/status.json", w.status)
	mux.HandleFunc("GET /{$}", w.home)
	mux.HandleFunc("GET /check/{host}/{id}", w.check)
	mux.HandleFunc("POST /check/{host}/{id}/ack", w.sameOrigin(w.ack))
	mux.HandleFunc("POST /check/{host}/{id}/unack", w.sameOrigin(w.unack))
	mux.HandleFunc("POST /check/{host}/{id}/accept", w.sameOrigin(w.accept))
	mux.HandleFunc("GET /history", w.history)
	mux.HandleFunc("GET /host/{host}", w.hostPage)
	mux.HandleFunc("POST /host/{host}", w.sameOrigin(w.saveHost))
	if len(w.mcpTokens) > 0 {
		mux.HandleFunc(MCPPath, w.mcp)
	}
	if w.google == nil {
		return w.logged(secure(mux))
	}
	mux.HandleFunc("GET /auth/login", w.google.login)
	mux.HandleFunc("GET /auth/callback", w.callback)
	mux.HandleFunc("POST /auth/logout", w.sameOrigin(w.logout))
	return w.logged(secure(w.google.require(mux)))
}

// Reports returns the handler for the report port: one endpoint, nothing else.
func (w *Web) Reports() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+report.Path, w.report)
	return w.logged(mux)
}

func cacheFor(d time.Duration, h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(d.Seconds())))
		h.ServeHTTP(rw, r)
	})
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hd := rw.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		h.ServeHTTP(rw, r)
	})
}

// sameOrigin rejects cross-site form posts. It is the CSRF defence, with or
// without Google sign-in: a page elsewhere must not be able to acknowledge an alert.
func (w *Web) sameOrigin(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
			if site != "same-origin" {
				http.Error(rw, "cross-site request refused", http.StatusForbidden)
				return
			}
		} else if o := r.Header.Get("Origin"); o == "" || !originMatches(o, r.Host) {
			http.Error(rw, "cross-site request refused", http.StatusForbidden)
			return
		}
		h(rw, r)
	}
}

func originMatches(origin, host string) bool {
	u, err := url.Parse(origin)
	return err == nil && u.Host == host
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

type viewerKey struct{}

func viewer(r *http.Request) string {
	v, _ := r.Context().Value(viewerKey{}).(string)
	return v
}

// logged resolves the viewer and logs every request with who made it. With Google
// sign-in the viewer is the signed-in account and the tailnet identity is logged too.
func (w *Web) logged(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		who := w.who.Whois(r.Context(), r.RemoteAddr)
		ctx := r.Context()
		viewer, extra := who, ""
		if w.google != nil {
			email := w.google.session(r)
			ctx = context.WithValue(ctx, signedInKey{}, email)
			viewer, extra = email, fmt.Sprintf(" tailnet=%q", who)
		}
		sw := &statusWriter{ResponseWriter: rw, code: 200}
		h.ServeHTTP(sw, r.WithContext(context.WithValue(ctx, viewerKey{}, viewer)))
		log.Printf("%s %s %s %d %s viewer=%q%s", r.RemoteAddr, r.Method, r.URL.Path, sw.code, time.Since(start).Round(time.Millisecond), viewer, extra)
	})
}

// --- report API ---

func (w *Web) report(rw http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	tok = strings.TrimSpace(tok)
	if !ok || tok == "" {
		http.Error(rw, "missing bearer token", http.StatusUnauthorized)
		return
	}
	sum := sha256.Sum256([]byte(tok))
	host, ok := w.srv.Tokens.Lookup(sum[:])
	if !ok {
		http.Error(rw, "unknown token", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, report.MaxBody))
	if err != nil {
		http.Error(rw, "report too large", http.StatusRequestEntityTooLarge)
		return
	}
	p, err := report.Decode(strings.NewReader(string(body)), w.srv.Now())
	if err != nil {
		http.Error(rw, "invalid report: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.Host != host {
		log.Printf("report for %q with %q's token refused", p.Host, host)
		http.Error(rw, "token does not belong to this host", http.StatusForbidden)
		return
	}
	switch err := w.srv.Ingest(r.Context(), host, body, p); {
	case errors.Is(err, server.ErrTooSoon):
		http.Error(rw, err.Error(), http.StatusTooManyRequests)
	case err != nil:
		log.Printf("ingest %s: %v", host, err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
	default:
		rw.WriteHeader(http.StatusNoContent)
	}
}

// --- pages ---

type page struct {
	Title    string
	Section  string
	Viewer   string
	SignedIn bool // Google sign-in is on and the viewer is signed in
	Refresh  bool
	Version  string
	Data     any
}

func (w *Web) render(rw http.ResponseWriter, r *http.Request, name string, code int, p page) {
	p.Viewer = viewer(r)
	p.SignedIn = signedIn(r) != ""
	p.Version = w.srv.Version
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	if err := w.pages[name].Execute(rw, p); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

func (w *Web) fail(rw http.ResponseWriter, r *http.Request, code int, msg string) {
	w.render(rw, r, "error", code, page{Title: http.StatusText(code), Data: msg})
}

type checkView struct {
	store.Check
	Effective eval.State // the state that counts: ok while acknowledged
	Acked     bool
	Age       string
	Meters    []meter
}

type rowView struct {
	Name   string
	Host   string // the host's name on a host row, "" on a group row
	Edit   string // link to the host's settings
	OS     string // icon family, see config.OSFamily
	OSName string
	Link   string
	State  eval.State
	Note   string
	Checks []checkView
	Counts map[eval.State]int
	Wide   bool // a group with many checks spans the whole grid row
}

type homeData struct {
	Overall eval.State
	Summary string
	Hosts   []rowView
	Tailnet *tailnetView
	Map     *mapView
	Groups  []rowView
	Empty   bool
}

// tailnetView lists the tailnet devices that are not configured hosts.
type tailnetView struct {
	Online  []deviceView
	Offline []deviceView
	Age     string
}

type deviceView struct {
	Name   string
	OS     string // icon family
	Logo   string // OS logo on the network map: windows, apple, linux, android or ""
	OSName string
	Addr   string
	Tags   string
	Seen   string
}

// deviceFamily maps a Tailscale device OS to an icon family.
func deviceFamily(os string) string {
	switch strings.ToLower(os) {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "macos":
		return "laptop"
	case "ios", "android":
		return "phone"
	}
	return "device"
}

// deviceLogo maps a Tailscale device OS to its logo on the network map.
func deviceLogo(os string) string {
	switch os = strings.ToLower(os); os {
	case "windows", "linux", "android":
		return os
	case "macos", "ios", "ipados", "tvos":
		return "apple"
	}
	return ""
}

// deviceOSName capitalises the OS names Tailscale sends in lower case.
func deviceOSName(os string) string {
	switch os {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "android":
		return "Android"
	}
	return os
}

// tailnet builds the device list from the data of the ts.devices check.
func tailnet(c checkView, now time.Time) *tailnetView {
	var data struct {
		Devices []probe.TSDevice `json:"devices"`
	}
	if json.Unmarshal([]byte(c.Data), &data) != nil || len(data.Devices) == 0 {
		return nil
	}
	// Show the name the device has in Tailscale; data stored before it was
	// recorded only has the hostname.
	for i, d := range data.Devices {
		if d.Machine != "" {
			data.Devices[i].Name = d.Machine
		}
	}
	sort.Slice(data.Devices, func(i, j int) bool {
		return strings.ToLower(data.Devices[i].Name) < strings.ToLower(data.Devices[j].Name)
	})
	t := &tailnetView{Age: c.Age}
	for _, d := range data.Devices {
		if d.Host != "" {
			continue
		}
		v := deviceView{Name: d.Name, OS: deviceFamily(d.OS), Logo: deviceLogo(d.OS), OSName: deviceOSName(d.OS), Addr: d.Addr, Tags: strings.Join(d.Tags, " ")}
		if d.Connected {
			t.Online = append(t.Online, v)
			continue
		}
		v.Seen = "last seen " + ago(now, d.LastSeen)
		t.Offline = append(t.Offline, v)
	}
	return t
}

// groups are the cross-host rows on the home page, by check id prefix.
var groups = []struct {
	name     string
	prefixes []string
}{
	{"Tailscale", []string{"ts."}},
	{"Jenkins", []string{"jenkins.", "win.breakglass"}},
	{"Public ports", []string{"ports.", "fw.", "win.fw."}},
	{"Certificates", []string{"tls."}},
	{"DNS and reachability", []string{"dns.", "http.", "tcp."}},
	{"Patches", []string{"os.security_updates.", "pkg.version."}},
	{"Disks and snapshots", []string{"disk.", "snapshot."}},
	{"Licences", []string{"p4.licence"}},
	{"Security", []string{"auth.", "sec."}},
	{"Security notices", []string{"notice."}},
	{"OpSec", []string{"opsec."}},
	{"Monitor", []string{"serve."}},
}

// wideGroup is the number of checks from which a group card spans the row, so
// one long card does not stretch the short ones next to it.
const wideGroup = 5

func (w *Web) view(c store.Check, now time.Time) checkView {
	v := checkView{Check: c, Effective: c.State, Acked: c.Acked(now), Age: ago(now, c.UpdatedAt)}
	if v.Acked {
		v.Effective = eval.OK
	}
	v.Meters = meters(v, w.srv.Cfg.Thresholds, now)
	return v
}

func sortChecks(cs []checkView) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Effective.Severity() != b.Effective.Severity() {
			return a.Effective.Severity() > b.Effective.Severity()
		}
		return a.Host+"/"+a.ID < b.Host+"/"+b.ID
	})
}

func newRow(name string, cs []checkView) rowView {
	r := rowView{Name: name, Checks: cs, Counts: map[eval.State]int{}, State: eval.OK}
	for _, c := range cs {
		r.State = eval.Worst(r.State, c.Effective)
		r.Counts[c.Effective]++
	}
	sortChecks(r.Checks)
	return r
}

func sortRows(rows []rowView) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].State.Severity() != rows[j].State.Severity() {
			return rows[i].State.Severity() > rows[j].State.Severity()
		}
		return false
	})
}

func (w *Web) home(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	checks, err := w.srv.Store.Checks(ctx)
	if err != nil {
		w.fail(rw, r, 500, err.Error())
		return
	}
	last, err := w.srv.Store.LastReports(ctx)
	if err != nil {
		w.fail(rw, r, 500, err.Error())
		return
	}
	now := w.srv.Now()
	byHost := map[string][]checkView{}
	var all []checkView
	d := homeData{Overall: eval.OK, Empty: len(checks) == 0}
	for _, c := range checks {
		v := w.view(c, now)
		byHost[c.Host] = append(byHost[c.Host], v)
		all = append(all, v)
		if c.Host == config.ServeHost && c.ID == "ts.devices" {
			d.Tailnet = tailnet(v, now)
		}
	}
	hosts := w.hosts()
	for _, h := range hosts {
		row := newRow(h.DisplayName(), byHost[h.Name])
		row.Host, row.OS, row.OSName = h.Name, config.OSFamily(h.OS), config.OSNames[h.OS]
		row.Edit = "/host/" + url.PathEscape(h.Name)
		row.Link = "/history?host=" + url.QueryEscape(h.Name)
		switch {
		case h.NoReport:
			row.Note = "no agent"
		case last[h.Name].IsZero():
			row.Note = "never reported"
			row.State = eval.Worst(row.State, eval.Stale)
		default:
			row.Note = "reported " + ago(now, last[h.Name])
			if eval.IsStale(last[h.Name], now, w.srv.Cfg.StaleAfter) {
				row.State = eval.Worst(row.State, eval.Stale)
			}
		}
		d.Hosts = append(d.Hosts, row)
	}
	d.Map = buildMap(hosts, w.srv.Cfg.Links, d.Hosts, all, d.Tailnet)
	sortRows(d.Hosts)
	for _, g := range groups {
		var cs []checkView
		for _, c := range all {
			for _, p := range g.prefixes {
				if strings.HasPrefix(c.ID, p) {
					cs = append(cs, c)
					break
				}
			}
		}
		if len(cs) > 0 {
			row := newRow(g.name, cs)
			row.Wide = len(cs) >= wideGroup
			d.Groups = append(d.Groups, row)
		}
	}
	sortRows(d.Groups)
	// Wide groups first, so the narrow ones after them fill whole rows.
	sort.SliceStable(d.Groups, func(i, j int) bool { return d.Groups[i].Wide && !d.Groups[j].Wide })
	counts := map[eval.State]int{}
	for _, row := range d.Hosts {
		d.Overall = eval.Worst(d.Overall, row.State)
	}
	for _, c := range all {
		d.Overall = eval.Worst(d.Overall, c.Effective)
		counts[c.Effective]++
	}
	var parts []string
	for _, s := range []eval.State{eval.Crit, eval.Stale, eval.Warn, eval.OK} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	d.Summary = strings.Join(parts, " · ")
	w.render(rw, r, "home", 200, page{Title: "Infra watch", Section: "home", Refresh: true, Data: d})
}

type ackOption struct {
	Value string
	Label string
}

type checkData struct {
	Check       checkView
	Chart       *chartView
	DataPretty  string
	Transitions []store.Transition
	AckOptions  []ackOption
	CanAccept   bool
	AcceptWhat  string
	AcceptHelp  string
	Notices     []probe.NoticeItem // a notice check's items, newest first
	Flash       string
}

var ackChoices = []struct {
	d     time.Duration
	label string
}{
	{4 * time.Hour, "4 hours"},
	{24 * time.Hour, "24 hours"},
	{7 * 24 * time.Hour, "7 days"},
	{30 * 24 * time.Hour, "30 days"},
	{90 * 24 * time.Hour, "90 days"},
}

func (w *Web) check(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host, id := r.PathValue("host"), r.PathValue("id")
	c, err := w.srv.Store.Check(ctx, host, id)
	if err != nil {
		w.fail(rw, r, 500, err.Error())
		return
	}
	if c == nil {
		w.fail(rw, r, 404, "No such check.")
		return
	}
	ts, err := w.srv.Store.Transitions(ctx, host, id, 30)
	if err != nil {
		w.fail(rw, r, 500, err.Error())
		return
	}
	now := w.srv.Now()
	d := checkData{Check: w.view(*c, now), Transitions: ts, Flash: r.URL.Query().Get("msg")}
	if d.Chart, err = w.checkChart(ctx, host, id, now); err != nil {
		w.fail(rw, r, 500, err.Error())
		return
	}
	var pretty any
	if json.Unmarshal([]byte(c.Data), &pretty) == nil {
		b, _ := json.MarshalIndent(pretty, "", "  ")
		d.DataPretty = string(b)
	}
	limit := eval.AckLimit(c.State)
	for _, a := range ackChoices {
		if a.d <= limit {
			d.AckOptions = append(d.AckOptions, ackOption{a.d.String(), a.label})
		}
	}
	if b, ok := server.BaselineFor(c.ID); ok && c.State != eval.OK {
		d.CanAccept, d.AcceptWhat = true, b.What
	}
	if strings.HasPrefix(c.ID, "notice.") {
		var nd struct {
			Items []probe.NoticeItem `json:"items"`
		}
		if json.Unmarshal([]byte(c.Data), &nd) == nil {
			d.Notices = nd.Items
		}
	}
	if _, ok := server.BaselineFor(c.ID); !ok && probe.NoticeAcceptable(c.ID) && c.State != eval.OK {
		d.CanAccept, d.AcceptWhat = true, "notices"
		d.AcceptHelp = "Mark every notice listed below as seen. The check turns ok until the vendor publishes a new one. Only do this once you have checked whether they affect us."
	}
	w.render(rw, r, "check", 200, page{Title: w.label(c.Host) + " · " + c.ID, Section: "home", Data: d})
}

func (w *Web) back(rw http.ResponseWriter, r *http.Request, msg string) {
	u := checkURL(r.PathValue("host"), r.PathValue("id"))
	if msg != "" {
		u += "?msg=" + url.QueryEscape(msg)
	}
	http.Redirect(rw, r, u, http.StatusSeeOther)
}

func (w *Web) ack(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host, id := r.PathValue("host"), r.PathValue("id")
	d, err := time.ParseDuration(r.FormValue("for"))
	state := eval.State(r.FormValue("state"))
	if err != nil || d <= 0 || d > eval.AckLimit(state) {
		w.back(rw, r, "That acknowledgement is not allowed for a "+string(state)+" check.")
		return
	}
	note := report.Clip(strings.TrimSpace(r.FormValue("note")), 300)
	now := w.srv.Now()
	if err := w.srv.Store.Ack(ctx, host, id, state, now.Add(d), viewer(r), note, now); err != nil {
		w.back(rw, r, "Not acknowledged: "+err.Error())
		return
	}
	log.Printf("ack %s/%s %s for %s by %q: %s", host, id, state, d, viewer(r), note)
	w.back(rw, r, "")
}

func (w *Web) unack(rw http.ResponseWriter, r *http.Request) {
	if err := w.srv.Store.Unack(r.Context(), r.PathValue("host"), r.PathValue("id")); err != nil {
		w.back(rw, r, err.Error())
		return
	}
	w.back(rw, r, "")
}

func (w *Web) accept(rw http.ResponseWriter, r *http.Request) {
	host, id := r.PathValue("host"), r.PathValue("id")
	if err := w.srv.AcceptBaseline(r.Context(), host, id, viewer(r)); err != nil {
		w.back(rw, r, "Not accepted: "+err.Error())
		return
	}
	log.Printf("baseline %s/%s accepted by %q", host, id, viewer(r))
	w.back(rw, r, "")
}

type hostData struct {
	Host     config.Host
	OSList   []string
	MaxLabel int
	Changed  string // who set the label and OS in the UI, and when
	Flash    string
}

func (w *Web) hostPage(rw http.ResponseWriter, r *http.Request) {
	h, ok := w.host(r.PathValue("host"))
	if !ok {
		w.fail(rw, r, 404, "No such host.")
		return
	}
	d := hostData{Host: h, OSList: config.OSList, MaxLabel: config.MaxLabel, Flash: r.URL.Query().Get("msg")}
	w.mu.RLock()
	if m, ok := w.meta[h.Name]; ok {
		d.Changed = "by " + m.By + " " + ago(w.srv.Now(), m.At)
	}
	w.mu.RUnlock()
	w.render(rw, r, "host", 200, page{Title: h.DisplayName(), Section: "home", Data: d})
}

func (w *Web) saveHost(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("host")
	if !w.srv.Cfg.HasHost(name) {
		w.fail(rw, r, 404, "No such host.")
		return
	}
	label, os := strings.TrimSpace(r.FormValue("label")), r.FormValue("os")
	if err := config.CheckHostMeta(label, os); err != nil {
		http.Redirect(rw, r, "/host/"+url.PathEscape(name)+"?msg="+url.QueryEscape("Not saved: "+err.Error()), http.StatusSeeOther)
		return
	}
	m := store.HostMeta{Label: label, OS: os, By: viewer(r), At: w.srv.Now()}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.srv.Store.SetHostMeta(r.Context(), name, m); err != nil {
		w.fail(rw, r, 500, err.Error())
		return
	}
	w.meta[name] = m
	log.Printf("host %s: label %q os %q set by %q", name, label, os, m.By)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

type historyData struct {
	Hosts       []string
	Host        string
	Transitions []store.Transition
}

func (w *Web) history(rw http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	ts, err := w.srv.Store.Transitions(r.Context(), host, "", 200)
	if err != nil {
		w.fail(rw, r, 500, err.Error())
		return
	}
	d := historyData{Host: host, Transitions: ts, Hosts: []string{}}
	for _, h := range w.srv.Cfg.Hosts {
		d.Hosts = append(d.Hosts, h.Name)
	}
	d.Hosts = append(d.Hosts, config.ServeHost)
	w.render(rw, r, "history", 200, page{Title: "History", Section: "history", Refresh: true, Data: d})
}

func (w *Web) status(rw http.ResponseWriter, r *http.Request) {
	st, err := w.srv.Status(r.Context())
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(rw).Encode(st)
}

// ago formats the time since t: "just now", "4 min ago", "3 h ago", "2 d ago".
func ago(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d d ago", int(d.Hours()/24))
}

// --- viewer identity ---

// Whoiser names the tailnet user behind a remote address.
type Whoiser interface {
	Whois(ctx context.Context, remoteAddr string) string
}

type noWhois struct{}

func (noWhois) Whois(_ context.Context, remoteAddr string) string {
	host, _, _ := net.SplitHostPort(remoteAddr)
	return host
}
