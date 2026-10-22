package web

import (
	"encoding/json"
	"fmt"
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
	Label string
	Title string
	Href  string
	Path  string // SVG path, filled in by layout
	LX    float64
	LY    float64
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
	mapW, mapRow, mapPad   = 1000.0, 76.0, 28.0
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
		nd.Internet.Path = fmt.Sprintf("M%.0f %.0f C%.0f %.0f %.0f %.0f %.0f %.0f", left, nd.Y, left-60, nd.Y, inEdge+60, ey, inEdge, ey)
		nd.Tailnet.Path = fmt.Sprintf("M%.0f %.0f C%.0f %.0f %.0f %.0f %.0f %.0f", right, nd.Y, right+60, nd.Y, tsEdge-60, ey, tsEdge, ey)
		nd.Internet.LX, nd.Internet.LY = (left+inEdge)/2, (nd.Y+ey)/2-10
		nd.Tailnet.LX, nd.Tailnet.LY = (right+tsEdge)/2, (nd.Y+ey)/2-10
		nd.Name = clipRunes(nd.Name, 20)
	}

	m.NW, m.NH = mapNarrowW, mapNarrowH
	m.Narrow = append([]mapNode(nil), m.Nodes...)
	for i := range m.Narrow {
		m.Narrow[i].Name = clipRunes(m.Narrow[i].Name, 12)
	}
	step := mapNarrowW / max(1, n)
	top, bottom := 78.0, mapNarrowH-78
	for i := range m.Narrow {
		nd := &m.Narrow[i]
		nd.X, nd.Y = step*(float64(i)+0.5), mapNarrowH/2
		nd.Internet.Path = fmt.Sprintf("M%.0f %.0f C%.0f %.0f %.0f %.0f %.0f %.0f", nd.X, nd.Y-24, nd.X, nd.Y-60, mapNarrowW/2+(nd.X-mapNarrowW/2)*0.6, top+30, mapNarrowW/2+(nd.X-mapNarrowW/2)*0.6, top)
		nd.Tailnet.Path = fmt.Sprintf("M%.0f %.0f C%.0f %.0f %.0f %.0f %.0f %.0f", nd.X, nd.Y+24, nd.X, nd.Y+60, mapNarrowW/2+(nd.X-mapNarrowW/2)*0.6, bottom-30, mapNarrowW/2+(nd.X-mapNarrowW/2)*0.6, bottom)
	}
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
					}
					if json.Unmarshal([]byte(c.Data), &d) == nil {
						failed += d.Total
					}
				}
			}
			if hasPrefix(c.ID, tailnetChecks) {
				ts = append(ts, c)
			}
		}
		nd.Internet = link(h.PublicIP != "", in, "ports.public.")
		nd.Tailnet = link(!h.NotOnTailnet, ts, "ts.online.")
		if nd.State == eval.Stale {
			for _, l := range []*mapLink{&nd.Internet, &nd.Tailnet} {
				if l.On && l.State == "ok" {
					l.State = string(eval.Stale)
				}
			}
		}
		m.Nodes = append(m.Nodes, nd)
	}
	if failed > 0 {
		m.InternetNote = fmt.Sprintf("%d failed logins / 24 h", failed)
	}
	if tn != nil {
		m.TailnetNote = fmt.Sprintf("+%d other device%s", len(tn.Online), plural(len(tn.Online)))
	}
	m.layout()
	return m
}

// link sums up one side of a host. The label is the worst check's summary when
// something is wrong, else the summary of the main check for that side.
func link(on bool, cs []checkView, main string) mapLink {
	l := mapLink{On: on, State: "none", Label: "no checks yet"}
	if !on {
		return l
	}
	worst := -1
	var titles []string
	for i, c := range cs {
		titles = append(titles, c.ID+": "+string(c.Effective)+" · "+c.Summary)
		if worst < 0 || c.Effective.Severity() > cs[worst].Effective.Severity() {
			worst = i
		}
	}
	if worst < 0 {
		return l
	}
	w := cs[worst]
	l.State, l.Href, l.Label = string(w.Effective), checkURL(w.Host, w.ID), w.Summary
	if w.Effective == eval.OK {
		for _, c := range cs {
			if strings.HasPrefix(c.ID, main) {
				l.Href, l.Label = checkURL(c.Host, c.ID), c.Summary
			}
		}
	}
	l.Label = clipRunes(l.Label, 26)
	l.Title = strings.Join(titles, "\n")
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
