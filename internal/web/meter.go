package web

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
)

// A meter is a small bar under a check's summary for a number that has a natural
// scale: how full a disk is, licences used, days left on a certificate. The fill
// takes the check's colour; the text beside it stays in the text colour.
type meter struct {
	Name  string  // "users", or "" when the check has one meter
	Pct   float64 // fill, 0 to 100
	Value string  // "72%", "12/15", "41 d"
	Title string
}

// Scales for the meters that count down to an expiry: a full bar is this many
// days left. Let's Encrypt certificates last 90 days, Tailscale node keys 180.
const (
	tlsScaleDays = 90
	keyScaleDays = 180
)

func meters(c checkView, th config.Thresholds, now time.Time) []meter {
	var d map[string]any
	if json.Unmarshal([]byte(c.Data), &d) != nil {
		return nil
	}
	f := func(k string) (float64, bool) {
		v, ok := d[k].(float64)
		return v, ok && !math.IsNaN(v) && !math.IsInf(v, 0)
	}
	switch {
	case strings.HasPrefix(c.ID, "disk."):
		pct, ok := f("used_pct")
		if !ok {
			return nil
		}
		m := meter{Pct: pct, Value: fmt.Sprintf("%.0f%%", pct), Title: fmt.Sprintf("%.0f%% used", pct)}
		if total, ok := f("total_bytes"); ok {
			free, _ := f("free_bytes")
			m.Title = fmt.Sprintf("%s of %s used", bytesHuman(total-free), bytesHuman(total))
		}
		return []meter{m.clamp()}
	case c.ID == "p4.licence":
		var out []meter
		for _, kind := range []string{"user", "client"} {
			n, ok1 := f(kind + "_count")
			limit, ok2 := f(kind + "_limit")
			if !ok1 || !ok2 || limit <= 0 {
				continue
			}
			out = append(out, meter{Name: kind + "s", Pct: n / limit * 100, Value: fmt.Sprintf("%.0f/%.0f", n, limit),
				Title: fmt.Sprintf("%.0f of %.0f %s licences used", n, limit, kind)}.clamp())
		}
		return out
	case strings.HasPrefix(c.ID, "tls."):
		left, ok := f("days_left")
		if !ok {
			return nil
		}
		return []meter{daysLeft(left, tlsScaleDays)}
	case strings.HasPrefix(c.ID, "ts.key_expiry."):
		if off, _ := d["key_expiry_disabled"].(bool); off {
			return nil
		}
		exp, _ := d["expires"].(string)
		t, err := time.Parse(time.RFC3339, exp)
		if err != nil || t.Year() < 2000 {
			return nil
		}
		return []meter{daysLeft(t.Sub(now).Hours()/24, keyScaleDays)}
	case strings.HasPrefix(c.ID, "snapshot.age."):
		age, ok := f("age_days")
		if !ok || th.SnapshotCritDays <= 0 {
			return nil
		}
		return []meter{meter{Pct: age / th.SnapshotCritDays * 100, Value: fmt.Sprintf("%.0f d", age),
			Title: fmt.Sprintf("newest snapshot %.0f days old, crit at %.0f", age, th.SnapshotCritDays)}.clamp()}
	}
	return nil
}

// daysLeft is a bar that empties as an expiry comes closer.
func daysLeft(left, scale float64) meter {
	return meter{Pct: left / scale * 100, Value: fmt.Sprintf("%.0f d", left),
		Title: fmt.Sprintf("%.0f days left (full bar: %.0f)", left, scale)}.clamp()
}

func (m meter) clamp() meter {
	m.Pct = math.Max(0, math.Min(100, m.Pct))
	return m
}

func bytesHuman(b float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", b)
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}
