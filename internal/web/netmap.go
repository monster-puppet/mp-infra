package web

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// The network map on the home page: the internet on one side, the tailnet on the
// other, every host in between with a line to each network it is on. A line takes
// the worst state of the checks about that side of the host, so a brute force or
// an open port lights up the internet side and a dropped Tailscale the other.
// It is plain SVG built here; the template only draws it.

// Which checks colour which line.
var (
	internetChecks = []string{"ports.public.", "auth.", "win.fw.", "fw.rules."}
	tailnetChecks  = []string{"ts.online.", "ts.key_expiry.", "win.tailscale_service"}
)

type mapLink struct {
	On    bool   // the host is on this network
	State string // ok, warn, crit, stale or none
	Title string
	Href  string
	Path  string // SVG path, filled in by layout

	// What the line carries, drawn as badges on it instead of text.
	Icon  string     // tailnet: link, clock, x or question
	Ports []portChip // internet: the public ports
	Alert *mapBadge  // internet: a login or firewall problem
	// Badges are the above, placed on the line by layout.
	Badges []mapBadge
}

// portChip is one public port on an internet line.
type portChip struct {
	Port  int
	Class string // open (expected), bad (open, not expected), closed (expected, closed)
}

// mapBadge is an icon or a text chip sitting on a line.
type mapBadge struct {
	X, Y  float64
	W     float64 // chip width; icons are round
	Icon  string  // link, clock, x, question, lock, alert, target
	Chip  string
	Class string // the colour: ok, warn, crit, stale, none, or a portChip class
	Title string
	Href  string
}

type mapNode struct {
	Name     string
	Host     string
	OS       string
	State    eval.State
	Href     string
	X, Y     float64 // centre
	Internet mapLink
	Tailnet  mapLink
	// Failed logins on this host in the last 24 h, from auth.failures.
	Failed      string // "1,832 failed logins · 203.0.113.5", "" when none
	FailedShort string // "1,832 failed", for the phone layout
	FailedState string // the check's state, or "active" during a brute force
	FailedHref  string
}

type mapView struct {
	Nodes        []mapNode
	InternetNote string
	TailnetNote  string
	// Wide layout: networks left and right of a host column.
	W, H float64
	// Narrow layout (phones): networks above and below a row of hosts.
	Narrow []mapNode
	NW, NH float64
}

const (
	mapW, mapRow, mapPad   = 1000.0, 84.0, 28.0
	mapBubbleW, mapNodeW   = 150.0, 270.0
	mapNarrowW, mapNarrowH = 400.0, 380.0
)

func (m *mapView) layout() {
	n := float64(len(m.Nodes))
	m.W, m.H = mapW, max(240, n*mapRow+2*mapPad)
	inEdge, tsEdge := mapPad+mapBubbleW, mapW-mapPad-mapBubbleW
	left, right := (mapW-mapNodeW)/2, (mapW+mapNodeW)/2
	mid := m.H / 2
	for i := range m.Nodes {
		nd := &m.Nodes[i]
		nd.X, nd.Y = mapW/2, mid+(float64(i)-(n-1)/2)*mapRow
		// Lines bend toward the middle of each bubble so they read as converging.
		ey := nd.Y + (mid-nd.Y)*0.4
		var ix, iy, tx, ty float64
		nd.Internet.Path, ix, iy = curve(left, nd.Y, left-60, nd.Y, inEdge+60, ey, inEdge, ey)
		nd.Tailnet.Path, tx, ty = curve(right, nd.Y, right+60, nd.Y, tsEdge-60, ey, tsEdge, ey)
		nd.Internet.Badges = nd.Internet.wideBadges(ix, iy)
		nd.Tailnet.Badges = nd.Tailnet.wideBadges(tx, ty)
		nd.Name = clipRunes(nd.Name, 20)
	}

	m.NW, m.NH = mapNarrowW, mapNarrowH
	m.Narrow = append([]mapNode(nil), m.Nodes...)
	step := mapNarrowW / max(1, n)
	top, bottom := 78.0, mapNarrowH-78
	for i := range m.Narrow {
		nd := &m.Narrow[i]
		nd.Name = clipRunes(nd.Name, 12)
		nd.X, nd.Y = step*(float64(i)+0.5), mapNarrowH/2
		ex := mapNarrowW/2 + (nd.X-mapNarrowW/2)*0.6
		var ix, iy, tx, ty float64
		nd.Internet.Path, ix, iy = curve(nd.X, nd.Y-24, nd.X, nd.Y-60, ex, top+30, ex, top)
		nd.Tailnet.Path, _, _ = curve(nd.X, nd.Y+24, nd.X, nd.Y+60, ex, bottom-30, ex, bottom)
		// Low on the line, clear of the host's caption.
		tx, ty = bezier(0.8, nd.X, nd.Y+24, nd.X, nd.Y+60, ex, bottom-30, ex, bottom)
		nd.Internet.Badges = nd.Internet.narrowBadge(ix, iy)
		nd.Tailnet.Badges = nd.Tailnet.narrowBadge(tx, ty)
	}
}

// bezier returns the point at t on a cubic Bézier.
func bezier(t, x0, y0, x1, y1, x2, y2, x3, y3 float64) (float64, float64) {
	u := 1 - t
	a, b, c, d := u*u*u, 3*u*u*t, 3*u*t*t, t*t*t
	return a*x0 + b*x1 + c*x2 + d*x3, a*y0 + b*y1 + c*y2 + d*y3
}

// curve returns a cubic Bézier as an SVG path and its midpoint.
func curve(x0, y0, x1, y1, x2, y2, x3, y3 float64) (string, float64, float64) {
	return fmt.Sprintf("M%.0f %.0f C%.0f %.0f %.0f %.0f %.0f %.0f", x0, y0, x1, y1, x2, y2, x3, y3),
		(x0 + 3*x1 + 3*x2 + x3) / 8, (y0 + 3*y1 + 3*y2 + y3) / 8
}

const (
	iconW    = 26.0
	badgeGap = 4.0
	maxChips = 5
)

func chipW(text string) float64 { return 12 + 7*float64(len(text)) }

// wideBadges lays out the line's badges in a row centred on (x, y): the alert
// first, then one chip per port.
func (l mapLink) wideBadges(x, y float64) []mapBadge {
	if !l.On {
		return nil
	}
	var bs []mapBadge
	if l.Icon != "" {
		bs = append(bs, mapBadge{Icon: l.Icon, Class: l.State, Title: l.Title, Href: l.Href})
	}
	if l.Alert != nil {
		bs = append(bs, *l.Alert)
	}
	ports := l.Ports
	more := 0
	if len(ports) > maxChips {
		ports, more = ports[:maxChips-1], len(ports)-(maxChips-1)
	}
	for _, p := range ports {
		bs = append(bs, mapBadge{Chip: fmt.Sprint(p.Port), Class: p.Class, Title: portTitle(p), Href: l.Href})
	}
	if more > 0 {
		bs = append(bs, mapBadge{Chip: fmt.Sprintf("+%d", more), Class: "open", Title: l.Title, Href: l.Href})
	}
	total := -badgeGap
	for i := range bs {
		if bs[i].Icon != "" {
			bs[i].W = iconW
		} else {
			bs[i].W = chipW(bs[i].Chip)
		}
		total += bs[i].W + badgeGap
	}
	at := x - total/2
	for i := range bs {
		bs[i].X, bs[i].Y = at+bs[i].W/2, y
		at += bs[i].W + badgeGap
	}
	return bs
}

// narrowBadge sums the line up in one badge for the phone layout.
func (l mapLink) narrowBadge(x, y float64) []mapBadge {
	if !l.On {
		return nil
	}
	b := mapBadge{X: x, Y: y, W: iconW, Icon: l.Icon, Class: l.State, Title: l.Title, Href: l.Href}
	switch {
	case l.Alert != nil:
		b.Icon, b.Class = l.Alert.Icon, l.Alert.Class
	case l.Icon == "":
		open, bad := 0, 0
		for _, p := range l.Ports {
			if p.Class == "bad" {
				bad++
			}
			if p.Class != "closed" {
				open++
			}
		}
		switch {
		case bad > 0:
			b.Icon, b.Chip, b.Class = "", fmt.Sprintf("%d open", open), "bad"
		case open > 0:
			b.Icon, b.Chip, b.Class = "", fmt.Sprintf("%d open", open), l.State
		default:
			b.Icon = "lock"
		}
		if b.Chip != "" {
			b.W = chipW(b.Chip)
		}
	}
	return []mapBadge{b}
}

func portTitle(p portChip) string {
	switch p.Class {
	case "bad":
		return fmt.Sprintf("port %d open, not expected", p.Port)
	case "closed":
		return fmt.Sprintf("port %d expected open, closed", p.Port)
	}
	return fmt.Sprintf("port %d open", p.Port)
}

// buildMap makes the map from the configured hosts and every current check.
func buildMap(hosts []config.Host, rows []rowView, all []checkView, tn *tailnetView) *mapView {
	if len(hosts) == 0 {
		return nil
	}
	state := map[string]eval.State{}
	for _, r := range rows {
		state[r.Host] = r.State
	}
	m := &mapView{}
	failed := 0
	for _, h := range hosts {
		nd := mapNode{Name: h.DisplayName(), Host: h.Name, OS: config.OSFamily(h.OS), State: state[h.Name],
			Href: "/history?host=" + h.Name}
		var in, ts []checkView
		for _, c := range all {
			if c.Host != h.Name {
				continue
			}
			if hasPrefix(c.ID, internetChecks) {
				in = append(in, c)
				if strings.HasPrefix(c.ID, "auth.failures.") {
					var d struct {
						Total int `json:"total"`
						Top   []struct {
							IP string `json:"ip"`
						} `json:"top_ips"`
						Active   bool   `json:"active"`
						Recent   int    `json:"recent"`
						RecentIP string `json:"recent_ip"`
					}
					switch {
					case json.Unmarshal([]byte(c.Data), &d) != nil:
					case d.Active:
						// Set by the server when the count jumps between two reports.
						failed += d.Total
						nd.Failed = "Under attack"
						if d.RecentIP != "" {
							nd.Failed += " · " + d.RecentIP
						}
						nd.Failed = clipRunes(nd.Failed, 36)
						nd.FailedShort = "under attack"
						nd.FailedState = "active"
						nd.FailedHref = checkURL(c.Host, c.ID)
					case d.Total > 0:
						failed += d.Total
						nd.Failed = fmt.Sprintf("%s failed login%s / 24 h", thousands(d.Total), plural(d.Total))
						if len(d.Top) > 0 && d.Top[0].IP != "" {
							nd.Failed += " · " + d.Top[0].IP
						}
						nd.Failed = clipRunes(nd.Failed, 36)
						nd.FailedShort = thousands(d.Total) + " failed"
						nd.FailedState = string(c.Effective)
						nd.FailedHref = checkURL(c.Host, c.ID)
					}
				}
			}
			if hasPrefix(c.ID, tailnetChecks) {
				ts = append(ts, c)
			}
		}
		if nd.FailedState == "active" {
			nd.Href = nd.FailedHref
		}
		nd.Internet = internetLink(h.PublicIP != "", in)
		nd.Tailnet = tailnetLink(!h.NotOnTailnet, ts)
		if nd.State == eval.Stale {
			for _, l := range []*mapLink{&nd.Internet, &nd.Tailnet} {
				if l.On && l.State == "ok" {
					l.State = string(eval.Stale)
					if l.Icon == "link" {
						l.Icon = "question"
					}
				}
			}
		}
		m.Nodes = append(m.Nodes, nd)
	}
	if failed > 0 {
		m.InternetNote = fmt.Sprintf("%s failed logins / 24 h", thousands(failed))
	}
	if tn != nil {
		m.TailnetNote = fmt.Sprintf("+%d other device%s", len(tn.Online), plural(len(tn.Online)))
	}
	m.layout()
	return m
}

// summarize sets the line's state, tooltip and link from the worst of cs.
func summarize(l *mapLink, cs []checkView) (worst *checkView) {
	l.State = "none"
	var titles []string
	for i, c := range cs {
		titles = append(titles, shortID(c.Host, c.ID)+": "+c.Summary)
		if worst == nil || c.Effective.Severity() > worst.Effective.Severity() {
			worst = &cs[i]
		}
	}
	l.Title = strings.Join(titles, "\n")
	if worst != nil {
		l.State, l.Href = string(worst.Effective), checkURL(worst.Host, worst.ID)
	}
	return worst
}

// tailnetLink: one icon for how the host is on the tailnet.
func tailnetLink(on bool, cs []checkView) mapLink {
	l := mapLink{On: on}
	if !on {
		return l
	}
	summarize(&l, cs)
	l.Icon = map[string]string{"ok": "link", "warn": "clock", "crit": "x"}[l.State]
	if l.Icon == "" {
		l.Icon = "question"
	}
	if l.Title == "" {
		l.Title = "no Tailscale data yet"
	}
	return l
}

// internetLink: a chip per public port, and an alert icon for the worst login or
// firewall problem.
func internetLink(on bool, cs []checkView) mapLink {
	l := mapLink{On: on}
	if !on {
		return l
	}
	summarize(&l, cs)
	var ports *checkView
	var problem *checkView
	for i, c := range cs {
		if strings.HasPrefix(c.ID, "ports.public.") {
			ports = &cs[i]
			continue
		}
		if c.Effective != eval.OK && (problem == nil || c.Effective.Severity() > problem.Effective.Severity()) {
			problem = &cs[i]
		}
	}
	if problem != nil {
		l.Alert = &mapBadge{Icon: "alert", Class: string(problem.Effective), Title: problem.Summary, Href: checkURL(problem.Host, problem.ID)}
		if strings.HasPrefix(problem.ID, "auth.failures.") {
			l.Alert.Icon = "target"
			var d struct {
				Active bool `json:"active"`
			}
			if json.Unmarshal([]byte(problem.Data), &d) == nil && d.Active {
				l.Alert.Class = "active" // red and pulsing, see style.css
			}
		}
	}
	if ports == nil {
		if problem == nil {
			l.Icon = "question"
			if l.Title == "" {
				l.Title = "public ports not scanned yet"
			}
		}
		return l
	}
	var d struct {
		Open       []int `json:"open"`
		Expected   []int `json:"expected"`
		Unexpected []int `json:"unexpected"`
		Closed     []int `json:"expected_closed"`
	}
	json.Unmarshal([]byte(ports.Data), &d)
	bad := map[int]bool{}
	for _, p := range d.Unexpected {
		bad[p] = true
	}
	for _, p := range d.Open {
		cls := "open"
		if bad[p] {
			cls = "bad"
		}
		l.Ports = append(l.Ports, portChip{p, cls})
	}
	for _, p := range d.Closed {
		l.Ports = append(l.Ports, portChip{p, "closed"})
	}
	sort.Slice(l.Ports, func(i, j int) bool { return l.Ports[i].Port < l.Ports[j].Port })
	if len(l.Ports) == 0 && problem == nil {
		l.Icon = "lock" // nothing open to the internet
	}
	if l.Href == "" || problem == nil {
		l.Href = checkURL(ports.Host, ports.ID)
	}
	return l
}

func hasPrefix(id string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// thousands formats 1832 as "1,832".
func thousands(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// num converts a template number (an int literal or a float64 field) for the
// SVG arithmetic helpers.
func num(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case float64:
		return n
	}
	return 0
}
