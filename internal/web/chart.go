package web

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/store"
)

// The history chart on a check page: one number from the check's data in the
// host's stored reports, one point per slot over the last 30 days. Only report
// checks have a history; probe results are not kept.

const (
	chartDays  = 30
	chartSlot  = 6 * time.Hour
	chartW     = 640.0
	chartH     = 180.0
	chartLeft  = 44.0 // room for the y labels
	chartRight = 12.0
	chartTop   = 12.0
	chartBot   = 24.0 // room for the x labels
)

// chartSeries says which number of a check to chart and how to print it.
type chartSeries struct {
	key   string
	title string
	max   float64 // fixed top of the y axis, 0 to fit the data
	fmt   func(float64) string
}

func seriesFor(host, id string) (chartSeries, bool) {
	if host == config.ServeHost {
		return chartSeries{}, false
	}
	switch {
	case strings.HasPrefix(id, "disk."):
		return chartSeries{"used_pct", "Disk used", 100, func(v float64) string { return fmt.Sprintf("%.0f%%", v) }}, true
	case strings.HasPrefix(id, "auth.failures."):
		return chartSeries{"total", "Failed logins in the 24 h before each report", 0, func(v float64) string { return thousands(int(v)) }}, true
	case id == "p4.licence":
		return chartSeries{"user_count", "Licensed users", 0, func(v float64) string { return fmt.Sprintf("%.0f", v) }}, true
	}
	return chartSeries{}, false
}

type chartPoint struct {
	X, Y  float64
	Left  float64 // hover column for this point
	Width float64
	Title string
}

type chartTick struct {
	X, Y   float64
	Label  string
	Anchor string // text-anchor, so the end labels stay inside the chart
}

type chartView struct {
	Title          string
	W, H           float64
	Line, Area     string
	Points         []chartPoint
	Last           *chartPoint
	YTicks, XTicks []chartTick
	Bottom, Right  float64 // plot edges, for the grid lines
	Latest, Range  string  // "72%", "64% to 72%"
}

// checkChart reads the samples for one check and draws them, or returns nil when
// there are fewer than two points.
func (w *Web) checkChart(ctx context.Context, host, id string, now time.Time) (*chartView, error) {
	s, ok := seriesFor(host, id)
	if !ok {
		return nil, nil
	}
	rs, err := w.srv.Store.SampleReports(ctx, host, now.Add(-chartDays*24*time.Hour), chartSlot)
	if err != nil {
		return nil, err
	}
	return drawChart(s, samples(rs, id, s.key), now), nil
}

type sample struct {
	at time.Time
	v  float64
}

// samples pulls the number out of each report that has the check.
func samples(rs []store.ReportSample, id, key string) []sample {
	var out []sample
	for _, r := range rs {
		var body struct {
			Checks []struct {
				ID   string                     `json:"id"`
				Data map[string]json.RawMessage `json:"data"`
			} `json:"checks"`
		}
		if json.Unmarshal([]byte(r.Body), &body) != nil {
			continue
		}
		for _, c := range body.Checks {
			var v float64
			if c.ID != id || json.Unmarshal(c.Data[key], &v) != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			out = append(out, sample{r.At, v})
			break
		}
	}
	return out
}

func drawChart(s chartSeries, ps []sample, now time.Time) *chartView {
	if len(ps) < 2 {
		return nil
	}
	c := &chartView{Title: s.title, W: chartW, H: chartH, Bottom: chartH - chartBot, Right: chartW - chartRight}
	start := now.Add(-chartDays * 24 * time.Hour)
	lo, hi := ps[0].v, ps[0].v
	for _, p := range ps {
		lo, hi = math.Min(lo, p.v), math.Max(hi, p.v)
	}
	top := s.max
	if top == 0 {
		top = niceCeil(hi)
	}
	x := func(t time.Time) float64 {
		return chartLeft + (c.Right-chartLeft)*t.Sub(start).Seconds()/now.Sub(start).Seconds()
	}
	y := func(v float64) float64 {
		return c.Bottom - (c.Bottom-chartTop)*math.Max(0, math.Min(v, top))/top
	}
	for _, v := range []float64{0, top / 2, top} {
		c.YTicks = append(c.YTicks, chartTick{X: chartLeft - 6, Y: y(v), Label: s.fmt(v), Anchor: "end"})
	}
	for i := 0; i <= 3; i++ {
		t := start.Add(time.Duration(i) * chartDays * 24 * time.Hour / 3)
		anchor := map[int]string{0: "start", 3: "end"}[i]
		if anchor == "" {
			anchor = "middle"
		}
		c.XTicks = append(c.XTicks, chartTick{X: x(t), Y: chartH - 6, Label: t.Local().Format("2 Jan"), Anchor: anchor})
	}

	// A gap of more than two slots (the agent was down) breaks the line.
	var line, area strings.Builder
	runStart := 0
	closeRun := func(end int) {
		if end-runStart < 1 {
			return
		}
		fmt.Fprintf(&area, "L%.1f %.1f L%.1f %.1f Z ", x(ps[end].at), c.Bottom, x(ps[runStart].at), c.Bottom)
	}
	for i, p := range ps {
		cmd := "L"
		if i == 0 || p.at.Sub(ps[i-1].at) > 2*chartSlot {
			if i > 0 {
				closeRun(i - 1)
			}
			cmd, runStart = "M", i
		}
		fmt.Fprintf(&line, "%s%.1f %.1f ", cmd, x(p.at), y(p.v))
		fmt.Fprintf(&area, "%s%.1f %.1f ", cmd, x(p.at), y(p.v))
	}
	closeRun(len(ps) - 1)
	c.Line, c.Area = strings.TrimSpace(line.String()), strings.TrimSpace(area.String())

	// Each point owns the column halfway to its neighbours, so hovering anywhere
	// over the plot names the nearest point.
	for i, p := range ps {
		l, r := chartLeft, c.Right
		if i > 0 {
			l = (x(ps[i-1].at) + x(p.at)) / 2
		}
		if i < len(ps)-1 {
			r = (x(p.at) + x(ps[i+1].at)) / 2
		}
		c.Points = append(c.Points, chartPoint{X: x(p.at), Y: y(p.v), Left: l, Width: r - l,
			Title: p.at.Local().Format("2 Jan 15:04") + " · " + s.fmt(p.v)})
	}
	c.Last = &c.Points[len(c.Points)-1]
	c.Latest = s.fmt(ps[len(ps)-1].v)
	c.Range = s.fmt(lo) + " to " + s.fmt(hi)
	return c
}

// niceCeil rounds up to an even multiple of a power of ten, at least 2, so the
// middle tick is a whole number too.
func niceCeil(v float64) float64 {
	if v <= 2 {
		return 2
	}
	p := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 4, 6, 8, 10} {
		if v <= m*p {
			return m * p
		}
	}
	return 10 * p
}
