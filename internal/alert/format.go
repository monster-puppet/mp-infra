package alert

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/report"
)

// Item is one check in an alert. Kind is empty for a digest line.
type Item struct {
	Host    string
	CheckID string
	Kind    eval.AlertKind
	Old     eval.State
	New     eval.State
	Summary string
	Since   time.Time // reminders: when the bad state began
	Note    string    // digest: acknowledgement
}

// freshID is the check that says whether a host reports at all.
const freshID = "report.fresh"

const (
	maxLinesPerHost = 8   // more go behind a link to the host page
	maxSlackSummary = 200 // runes; the full summary is on the check page
	maxSlackBlocks  = 45  // Slack allows 50
)

type slackText struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

type slackBlock struct {
	Type     string      `json:"type"`
	Text     *slackText  `json:"text,omitempty"`
	Elements []slackText `json:"elements,omitempty"`
}

func header(s string) slackBlock {
	return slackBlock{Type: "header", Text: &slackText{Type: "plain_text", Text: clipRunes(s, 150), Emoji: true}}
}

func section(s string) slackBlock {
	return slackBlock{Type: "section", Text: &slackText{Type: "mrkdwn", Text: s}}
}

func contextBlock(s string) slackBlock {
	return slackBlock{Type: "context", Elements: []slackText{{Type: "mrkdwn", Text: s}}}
}

// entry is an item as shown: when a host stops reporting (or comes back), the
// stale checks it drags along are folded into its report.fresh line.
type entry struct {
	Item
	folded int
}

type hostGroup struct {
	host    string
	entries []entry
}

// rank orders entries and hosts: hosts that stopped reporting, crit, stale, warn,
// then recoveries.
func rank(it Item) int {
	switch {
	case it.Kind == eval.Recovery:
		return 4
	case it.CheckID == freshID && it.New == eval.Stale:
		return 0
	case it.New == eval.Crit:
		return 1
	case it.New == eval.Stale:
		return 2
	}
	return 3
}

// group sorts items by host, worst host first. A host's report.fresh entry comes
// first and absorbs the checks that went stale (or came back) with it.
func group(items []Item) []hostGroup {
	by := map[string][]Item{}
	var hosts []string
	for _, it := range items {
		if _, ok := by[it.Host]; !ok {
			hosts = append(hosts, it.Host)
		}
		by[it.Host] = append(by[it.Host], it)
	}
	var out []hostGroup
	worst := map[string]int{}
	for _, h := range hosts {
		its := by[h]
		sort.SliceStable(its, func(i, j int) bool {
			if ri, rj := rank(its[i]), rank(its[j]); ri != rj {
				return ri < rj
			}
			return its[i].CheckID < its[j].CheckID
		})
		g := hostGroup{host: h}
		var fresh *entry
		for _, it := range its {
			if it.CheckID == freshID {
				fresh = &entry{Item: it}
			}
		}
		down := fresh != nil && fresh.New == eval.Stale
		back := fresh != nil && fresh.Kind == eval.Recovery && fresh.Old == eval.Stale
		var rest []entry
		for _, it := range its {
			switch {
			case it.CheckID == freshID:
			case down && it.New == eval.Stale && it.Kind == fresh.Kind,
				back && it.Kind == eval.Recovery && it.Old == eval.Stale && it.New == eval.OK:
				fresh.folded++
			default:
				rest = append(rest, entry{Item: it})
			}
		}
		if fresh != nil {
			g.entries = append(g.entries, *fresh)
		}
		g.entries = append(g.entries, rest...)
		worst[h] = rank(its[0])
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if wi, wj := worst[out[i].host], worst[out[j].host]; wi != wj {
			return wi < wj
		}
		return out[i].host < out[j].host
	})
	return out
}

func label(s eval.State) string {
	if s == "" {
		return "new"
	}
	return string(s)
}

func emoji(it Item) string {
	switch {
	case it.Kind == eval.Recovery && it.New == eval.Warn:
		return ":large_yellow_circle:"
	case it.Kind == eval.Recovery:
		return ":large_green_circle:"
	case it.New == eval.Crit:
		return ":alert:" // custom emoji in the Monster Puppet workspace
	case it.New == eval.Stale:
		return ":hourglass:"
	}
	return ":large_yellow_circle:"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// headline says what happened to e in a few words, without the host.
func (e entry) headline(now time.Time) string {
	if e.CheckID == freshID {
		n := plural(e.folded, "check", "checks")
		switch {
		case e.Kind == eval.Reminder && e.folded > 0:
			return fmt.Sprintf("still not reporting after %s (%s stale)", report.Human(now.Sub(e.Since)), n)
		case e.Kind == eval.Reminder:
			return "still not reporting after " + report.Human(now.Sub(e.Since))
		case e.New == eval.Stale && e.folded > 0:
			return fmt.Sprintf("stopped reporting (%s stale)", n)
		case e.New == eval.Stale:
			return "stopped reporting"
		case e.Kind == eval.Recovery && e.folded > 0:
			return fmt.Sprintf("reporting again (%s back to ok)", n)
		case e.Kind == eval.Recovery:
			return "reporting again"
		}
	}
	switch e.Kind {
	case eval.Recovery:
		if e.New == eval.Warn {
			return "recovered to warn"
		}
		return "recovered"
	case eval.Reminder:
		return fmt.Sprintf("still %s after %s", e.New, report.Human(now.Sub(e.Since)))
	case eval.Problem:
		return string(e.New)
	}
	return ""
}

func (a *Alerter) checkURL(host, id string) string {
	if a.BaseURL == "" {
		return ""
	}
	return strings.TrimRight(a.BaseURL, "/") + "/check/" + url.PathEscape(host) + "/" + url.PathEscape(id)
}

func (a *Alerter) hostURL(host string) string {
	if a.BaseURL == "" {
		return ""
	}
	return strings.TrimRight(a.BaseURL, "/") + "/host/" + url.PathEscape(host)
}

// slackLink is a Slack link to u labelled text, or the bare text without a URL.
func slackLink(u, text string) string {
	if u == "" {
		return slackEscape(text)
	}
	return "<" + slackEscape(u) + "|" + slackEscape(text) + ">"
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n-1])) + "…"
}

// slackLine is one entry in a host section.
func (a *Alerter) slackLine(e entry, now time.Time) string {
	var b strings.Builder
	b.WriteString(emoji(e.Item) + " ")
	if e.CheckID == freshID && e.Kind != "" {
		b.WriteString("*" + slackEscape(e.headline(now)) + "*")
	} else {
		b.WriteString(slackLink(a.checkURL(e.Host, e.CheckID), e.CheckID))
		if h := e.headline(now); h != "" && e.Kind != eval.Problem {
			b.WriteString(" _" + slackEscape(h) + "_")
		}
	}
	if e.Summary != "" {
		b.WriteString(" — " + slackEscape(clipRunes(e.Summary, maxSlackSummary)))
	}
	if e.Note != "" {
		b.WriteString(" _(" + slackEscape(e.Note) + ")_")
	}
	return b.String()
}

// compose builds the message for items. digest is the date of a daily digest, or
// empty for alerts.
func (a *Alerter) compose(items []Item, digest string) Message {
	now := a.now()
	groups := group(items)
	var all []entry
	for _, g := range groups {
		all = append(all, g.entries...)
	}

	// Subject and header line.
	var subject, title string
	switch {
	case digest != "":
		subject = fmt.Sprintf("[DIGEST] %d warning(s) %s", len(all), digest)
		title = fmt.Sprintf(":large_yellow_circle: %s · %s", plural(len(all), "warning", "warnings"), digest)
	case len(all) == 1:
		e := all[0]
		subject = fmt.Sprintf("[%s] %s %s", tag(e.Item), e.Host, e.CheckID)
		verb := e.headline(now)
		if e.Kind == eval.Problem {
			verb = "is " + verb
		}
		title = emoji(e.Item) + " " + e.Host + " · " + e.CheckID + " " + verb
		if e.CheckID == freshID {
			subject = fmt.Sprintf("[%s] %s %s", tag(e.Item), e.Host, e.headline(now))
			title = emoji(e.Item) + " " + e.Host + " " + e.headline(now)
		}
	default:
		worst := all[0].Item
		for _, e := range all {
			if rank(e.Item) < rank(worst) {
				worst = e.Item
			}
		}
		where := plural(len(groups), "host", "hosts")
		if len(groups) == 1 {
			where = groups[0].host
		}
		subject = fmt.Sprintf("[%s] %s: %s", tag(worst), where, counts(all, now))
		title = emoji(worst) + " " + where + ": " + counts(all, now)
	}

	// Plain text, for mail.
	var text []string
	for _, g := range groups {
		for _, e := range g.entries {
			text = append(text, a.plainLine(e, now))
		}
	}
	if digest != "" && a.BaseURL != "" {
		text = append(text, strings.TrimRight(a.BaseURL, "/")+"/")
	}

	// Slack: a header, one section per host, a footer.
	blocks := []slackBlock{header(title)}
	single := len(all) == 1 && digest == ""
	if single {
		e := all[0]
		var body []string
		if e.Summary != "" {
			body = append(body, slackEscape(clipRunes(e.Summary, maxSlackSummary*2)))
		}
		if e.Note != "" {
			body = append(body, "_"+slackEscape(e.Note)+"_")
		}
		if len(body) > 0 {
			blocks = append(blocks, section(strings.Join(body, "\n")))
		}
		var foot []string
		switch {
		case e.Kind == eval.Reminder:
			foot = append(foot, fmt.Sprintf("%s since %s", e.New, e.Since.Local().Format("Jan 2 15:04")))
		case e.CheckID != freshID:
			foot = append(foot, fmt.Sprintf("%s → %s", label(e.Old), label(e.New)))
		}
		if e.CheckID == freshID {
			if u := a.hostURL(e.Host); u != "" {
				foot = append(foot, slackLink(u, "Open host"))
			}
		} else if u := a.checkURL(e.Host, e.CheckID); u != "" {
			foot = append(foot, slackLink(u, "Open check"))
		}
		if len(foot) > 0 {
			blocks = append(blocks, contextBlock(strings.Join(foot, "  ·  ")))
		}
	} else {
		for i, g := range groups {
			if len(blocks) >= maxSlackBlocks {
				blocks = append(blocks, contextBlock(fmt.Sprintf("…and %s more", plural(len(groups)-i, "host", "hosts"))))
				break
			}
			lines := []string{"*" + slackLink(a.hostURL(g.host), g.host) + "*"}
			for j, e := range g.entries {
				if j == maxLinesPerHost {
					lines = append(lines, "…and "+slackLink(a.hostURL(g.host), fmt.Sprintf("%d more", len(g.entries)-j)))
					break
				}
				lines = append(lines, a.slackLine(e, now))
			}
			blocks = append(blocks, section(strings.Join(lines, "\n")))
		}
		if a.BaseURL != "" {
			blocks = append(blocks, contextBlock(slackLink(strings.TrimRight(a.BaseURL, "/")+"/", "Open dashboard")))
		}
	}
	return Message{Subject: subject, Text: strings.Join(text, "\n\n"), Blocks: blocks}
}

// tag is the bracketed word at the start of a subject.
func tag(it Item) string {
	switch it.Kind {
	case eval.Recovery:
		return "RECOVERED"
	case eval.Reminder:
		return "STILL " + strings.ToUpper(string(it.New))
	}
	return strings.ToUpper(string(it.New))
}

// counts summarises entries, e.g. "2 crit, 1 recovered".
func counts(all []entry, now time.Time) string {
	var down, back, crit, stale, still, rec int
	for _, e := range all {
		switch {
		case e.CheckID == freshID && e.New == eval.Stale && e.Kind != eval.Reminder:
			down++
		case e.CheckID == freshID && e.Kind == eval.Recovery:
			back++
		case e.Kind == eval.Recovery:
			rec++
		case e.Kind == eval.Reminder:
			still++
		case e.New == eval.Crit:
			crit++
		case e.New == eval.Stale:
			stale++
		}
	}
	var parts []string
	add := func(n int, s string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	add(down, "stopped reporting")
	add(crit, "crit")
	add(stale, "stale")
	add(still, "still unresolved")
	add(back, "reporting again")
	add(rec, "recovered")
	return strings.Join(parts, ", ")
}

// plainLine is one item in a mail.
func (a *Alerter) plainLine(e entry, now time.Time) string {
	var head string
	switch e.Kind {
	case eval.Reminder:
		head = fmt.Sprintf("%s · %s has been %s since %s", e.Host, e.CheckID, e.New, e.Since.Local().Format("2006-01-02 15:04"))
	case "":
		head = e.Host + " · " + e.CheckID
	default:
		head = fmt.Sprintf("%s · %s: %s → %s", e.Host, e.CheckID, label(e.Old), label(e.New))
	}
	lines := []string{head}
	if e.Kind == "" {
		lines[0] += ": " + e.Summary
		if e.Note != "" {
			lines[0] += " (" + e.Note + ")"
		}
	} else if e.Summary != "" {
		lines = append(lines, "  "+e.Summary)
	}
	if e.folded > 0 {
		lines = append(lines, "  "+e.headline(now))
	}
	if u := a.checkURL(e.Host, e.CheckID); u != "" {
		lines = append(lines, "  "+u)
	}
	return strings.Join(lines, "\n")
}
