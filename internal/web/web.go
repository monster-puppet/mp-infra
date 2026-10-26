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
	"net/netip"
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
		"checkName": endpointCheckName,
		"add":      func(a, b any) float64 { return num(a) + num(b) },
		"sub":      func(a, b any) float64 { return num(a) - num(b) },
		"half":     func(a any) float64 { return num(a) / 2 },
		"badge":    func(x, y any) mapBadge { return mapBadge{X: num(x), Y: num(y), Icon: "target"} },
		"glowArgs": func(id string, w, h any) mapGlow { return mapGlow{ID: id, W: num(w), H: num(h)} },
		"pathEsc":  url.PathEscape,
		"label":    w.label,
		"osName":   func(os string) string { return config.OSNames[os] },
		// The badge colour of an unban row's state (store.Unban.State).
		"unbanClass": func(state string) string {
			return map[string]string{"waiting": "new", "sent": "warn", "done": "ok", "failed": "crit", "expired": "stale"}[state]
		},
	}
	for _, page := range []string{"home", "check", "history", "error", "signin", "host", "unban"} {
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
// endpointCheckName is a check's name on an endpoint's mini card.
func endpointCheckName(host, id string) string {
	s := strings.TrimPrefix(shortID(host, id), "endpoint.")
	if n, ok := map[string]string{"bitlocker": "BitLocker", "av": "Antivirus", "firewall": "Firewall",
		"boot": "Secure Boot", "screenlock": "Screen lock", "os": "Windows", "os.security_updates": "Updates"}[s]; ok {
		return n
	}
	return s
}

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
	mux.HandleFunc("GET /unban", w.unbanPage)
	mux.HandleFunc("POST /unban", w.sameOrigin(w.unban))
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
	mux.HandleFunc("GET "+WhoamiPath, w.whoami)
	return w.logged(mux)
}

// WhoamiPath tells an endpoint (the MP Launcher) which host it reports as. Its
// Tailscale name and its computer name often differ, and only the server knows
// which one the config uses.
const WhoamiPath = "/api/whoami"

func (w *Web) whoami(rw http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	host, ok := w.srv.EndpointHost(r.Context(), ap.Addr())
	if !ok {
		http.NotFound(rw, r) // not an enrolled endpoint: nothing to report
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"host": host})
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
	var host string
	endpoint := false
	if r.Header.Get("Authorization") == "" {
		// No token: only an endpoint host, identified by its tailnet address.
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err == nil {
			host, endpoint = w.srv.EndpointHost(r.Context(), ap.Addr())
		}
		if !endpoint {
			http.Error(rw, "missing bearer token", http.StatusUnauthorized)
			return
		}
	} else {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		tok = strings.TrimSpace(tok)
		if !ok || tok == "" {
			http.Error(rw, "missing bearer token", http.StatusUnauthorized)
			return
		}
		sum := sha256.Sum256([]byte(tok))
		host, ok = w.srv.Tokens.Lookup(sum[:])
		if !ok {
			http.Error(rw, "unknown token", http.StatusUnauthorized)
			return
		}
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
	if endpoint {
		for _, c := range p.Checks {
			if !server.EndpointCheckAllowed(c.ID) {
				http.Error(rw, "endpoint hosts may not send "+c.ID, http.StatusForbidden)
				return
			}
		}
	}
	switch err := w.srv.Ingest(r.Context(), host, body, p); {
	case errors.Is(err, server.ErrTooSoon):
		http.Error(rw, err.Error(), http.StatusTooManyRequests)
	case err != nil:
		log.Printf("ingest %s: %v", host, err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
	default:
		w.reportReply(rw, r, host, endpoint)
	}
}

// reportReply answers a stored report: 204, or 200 with the addresses waiting
// to be unbanned on this host (see server.TakeUnbans).
func (w *Web) reportReply(rw http.ResponseWriter, r *http.Request, host string, endpoint bool) {
	var ips []string
	if !endpoint {
		var err error
		if ips, err = w.srv.TakeUnbans(r.Context(), host); err != nil {
			log.Printf("unbans for %s: %v", host, err)
		}
	}
	if len(ips) == 0 {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	log.Printf("unban sent to %s: %s", host, strings.Join(ips, " "))
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(report.Reply{Unban: ips})
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
	Hidden int  // checks left out by the warnings or errors view
}

type homeData struct {
	Overall eval.State
	Summary string
	Hosts   []rowView
	Tailnet *tailnetView
	Map     *mapView
	Groups  []rowView
	Empty   bool
	// View is the home page filter: viewAll, viewWarnings (ok checks hidden)
	// or viewErrors (only crit and stale). In the filtered views cards left
	// with nothing to show, and sections left with no cards, are hidden.
	View   string
	Hidden int // checks hidden
}

// viewCookie keeps the home page's view choice. It is a display preference,
// nothing more.
const viewCookie = "mpinfra_view"

const (
	viewAll      = "all"
	viewWarnings = "warnings"
	viewErrors   = "errors"
)

// viewFrom reads the view cookie value. "problems" is the old name of the
// warnings view.
func viewFrom(v string) string {
	switch v {
	case viewWarnings, "problems":
		return viewWarnings
	case viewErrors:
		return viewErrors
	}
	return viewAll
}

// minSeverity is the lowest state severity a view shows.
func minSeverity(view string) int {
	switch view {
	case viewWarnings:
		return eval.Warn.Severity()
	case viewErrors:
		return eval.Crit.Severity()
	}
	return 0
}

// filterRows drops the checks below severity min from rows, and the rows left
// with nothing at or above it. It returns the rows kept and the number of
// checks dropped.
func filterRows(rows []rowView, min int) ([]rowView, int) {
	var out []rowView
	hidden := 0
	for _, r := range rows {
		var cs []checkView
		for _, c := range r.Checks {
			if c.Effective.Severity() >= min {
				cs = append(cs, c)
			}
		}
		r.Hidden = len(r.Checks) - len(cs)
		hidden += r.Hidden
		if len(cs) == 0 && r.State.Severity() < min {
			continue
		}
		r.Checks = cs
		if r.Host == "" {
			r.Wide = len(cs) >= wideGroup
		}
		out = append(out, r)
	}
	return out, hidden
}

// tailnetView lists the tailnet devices that are not server hosts: personal
// devices, and workstations that are endpoint hosts.
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
	// Set for an endpoint host: its name, its row's state, a link to its checks
	// and what is wrong ("Secure Boot off"), or "" when all is well. Label, Note
	// and Checks fill the mini card shown on hover.
	Host    string
	State   eval.State
	Href    string
	Problem string
	Label   string
	Note    string
	Checks  []checkView
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
func tailnet(c checkView, now time.Time, endpoint func(host string) bool) *tailnetView {
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
		if d.Host != "" && !endpoint(d.Host) {
			continue // a server: drawn as a host on the map
		}
		v := deviceView{Name: d.Name, OS: deviceFamily(d.OS), Logo: deviceLogo(d.OS), OSName: deviceOSName(d.OS), Addr: d.Addr, Tags: strings.Join(d.Tags, " "),
			Host: d.Host}
		if d.Connected {
			t.Online = append(t.Online, v)
			continue
		}
		v.Seen = "last seen " + ago(now, d.LastSeen)
		t.Offline = append(t.Offline, v)
	}
	return t
}

// markEndpoints gives each endpoint device its host row's state, a link to the
// row and the summary of its worst check.
func (t *tailnetView) markEndpoints(rows []rowView) {
	if t == nil {
		return
	}
	byHost := map[string]rowView{}
	for _, r := range rows {
		if r.Host != "" {
			byHost[r.Host] = r
		}
	}
	mark := func(ds []deviceView) {
		for i := range ds {
			r, ok := byHost[ds[i].Host]
			if ds[i].Host == "" || !ok {
				continue
			}
			ds[i].State, ds[i].Href = r.State, r.Link
			ds[i].Label, ds[i].Note = r.Name, r.Note
			for _, c := range r.Checks {
				if c.ID != "report.fresh" { // the note already says when it reported
					ds[i].Checks = append(ds[i].Checks, c)
				}
			}
			worst := eval.OK
			for _, c := range r.Checks {
				if c.Effective != eval.OK && eval.Worst(worst, c.Effective) != worst {
					worst, ds[i].Problem = c.Effective, c.Summary
				}
			}
			if ds[i].Problem == "" && r.State != eval.OK {
				ds[i].Problem = r.Note
			}
		}
	}
	mark(t.Online)
	mark(t.Offline)
}

// filter keeps the endpoint devices at or above severity min, or returns nil
// when there are none: personal devices carry no state.
func (t *tailnetView) filter(min int) *tailnetView {
	if t == nil {
		return nil
	}
	keep := func(ds []deviceView) []deviceView {
		var out []deviceView
		for _, d := range ds {
			if d.Host != "" && d.State != "" && d.State.Severity() >= min {
				out = append(out, d)
			}
		}
		return out
	}
	p := &tailnetView{Online: keep(t.Online), Offline: keep(t.Offline), Age: t.Age}
	if len(p.Online)+len(p.Offline) == 0 {
		return nil
	}
	return p
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
	{"Security", []string{"auth.", "sec.", "endpoint.", "av."}},
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
	// ?view= sets the preference and redirects, so the page URL (and its
	// refresh) stays plain "/".
	if v := r.URL.Query().Get("view"); v != "" {
		c := &http.Cookie{Name: viewCookie, Value: viewFrom(v), Path: "/", MaxAge: 365 * 24 * 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode}
		if c.Value == viewAll {
			c.Value, c.MaxAge = "", -1
		}
		http.SetCookie(rw, c)
		http.Redirect(rw, r, "/", http.StatusSeeOther)
		return
	}
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
			d.Tailnet = tailnet(v, now, w.srv.Cfg.IsEndpoint)
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
		case h.Endpoint && last[h.Name].IsZero():
			row.Note = "waiting for the launcher's first report"
		case last[h.Name].IsZero():
			row.Note = "never reported"
			row.State = eval.Worst(row.State, eval.Stale)
		default:
			row.Note = "reported " + ago(now, last[h.Name])
			if eval.IsStale(last[h.Name], now, w.srv.Cfg.StaleAfterFor(h.Name)) {
				row.State = eval.Worst(row.State, eval.Stale)
			}
		}
		d.Hosts = append(d.Hosts, row)
	}
	d.Tailnet.markEndpoints(d.Hosts)
	d.Map = buildMap(hosts, w.srv.Cfg.Links, d.Hosts, all, d.Tailnet)
	// Workstations live in the Tailnet card, not among the agents; they still
	// count toward the overall state.
	var agents []rowView
	for _, row := range d.Hosts {
		d.Overall = eval.Worst(d.Overall, row.State)
		if !w.srv.Cfg.IsEndpoint(row.Host) {
			agents = append(agents, row)
		}
	}
	d.Hosts = agents
	sortRows(d.Hosts)
	for _, g := range groups {
		var cs []checkView
		for _, c := range all {
			if w.srv.Cfg.IsEndpoint(c.Host) {
				continue
			}
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
	counts := map[eval.State]int{}
	d.View = viewAll
	if c, err := r.Cookie(viewCookie); err == nil {
		d.View = viewFrom(c.Value)
	}
	if d.View != viewAll {
		min := minSeverity(d.View)
		var n int
		d.Hosts, d.Hidden = filterRows(d.Hosts, min)
		d.Groups, n = filterRows(d.Groups, min)
		d.Hidden += n
		d.Tailnet = d.Tailnet.filter(min)
	}
	sortRows(d.Groups)
	// Wide groups first, so the narrow ones after them fill whole rows.
	sort.SliceStable(d.Groups, func(i, j int) bool { return d.Groups[i].Wide && !d.Groups[j].Wide })
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

// --- unban ---

type unbanData struct {
	Enabled  bool // admins are configured
	Admin    bool // the viewer may unban
	Hosts    []string
	IP       string   // the address looked up (?ip=)
	BannedOn []string // hosts whose latest report lists IP as banned
	Requests []unbanRequest
	Flash    string
}

// unbanRequest is one request: one address, by one viewer at one time, on
// every host that accepted unbans then.
type unbanRequest struct {
	IP, By string
	At     time.Time
	Hosts  []store.Unban
}

func (w *Web) unbanPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := unbanData{Enabled: len(w.srv.Cfg.Admins) > 0, Admin: w.srv.Cfg.IsAdmin(viewer(r)), Flash: r.URL.Query().Get("msg")}
	hosts, banned, err := w.srv.UnbanHosts(ctx)
	if err != nil {
		w.fail(rw, r, 500, err.Error())
		return
	}
	d.Hosts = hosts
	if ip := strings.TrimSpace(r.URL.Query().Get("ip")); ip != "" {
		a, err := report.ParseUnbanIP(ip)
		if err != nil {
			d.Flash = err.Error()
		} else {
			d.IP = a.String()
			for _, h := range w.srv.Cfg.Hosts {
				for _, b := range banned[h.Name] {
					if b == d.IP {
						d.BannedOn = append(d.BannedOn, h.Name)
						break
					}
				}
			}
		}
	}
	rows, err := w.srv.Unbans(ctx, 50)
	if err != nil {
		w.fail(rw, r, 500, err.Error())
		return
	}
	for _, u := range rows {
		n := len(d.Requests)
		if n == 0 || d.Requests[n-1].IP != u.IP || d.Requests[n-1].By != u.RequestedBy || !d.Requests[n-1].At.Equal(u.RequestedAt) {
			d.Requests = append(d.Requests, unbanRequest{IP: u.IP, By: u.RequestedBy, At: u.RequestedAt})
			n++
		}
		d.Requests[n-1].Hosts = append(d.Requests[n-1].Hosts, u)
	}
	w.render(rw, r, "unban", 200, page{Title: "Unban an IP", Section: "home", Data: d})
}

func (w *Web) unban(rw http.ResponseWriter, r *http.Request) {
	if !w.srv.Cfg.IsAdmin(viewer(r)) {
		log.Printf("unban refused for %q: not an admin", viewer(r))
		w.fail(rw, r, http.StatusForbidden, "Only admins can unban an address.")
		return
	}
	ip := strings.TrimSpace(r.FormValue("ip"))
	hosts, err := w.srv.RequestUnban(r.Context(), ip, viewer(r))
	if err != nil {
		http.Redirect(rw, r, "/unban?msg="+url.QueryEscape("Not queued: "+err.Error()), http.StatusSeeOther)
		return
	}
	a, _ := report.ParseUnbanIP(ip)
	log.Printf("unban %s on %s requested by %q", a, strings.Join(hosts, ", "), viewer(r))
	http.Redirect(rw, r, "/unban?ip="+url.QueryEscape(a.String()), http.StatusSeeOther)
}
