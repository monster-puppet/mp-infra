package report

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/monster-puppet/mp-infra/internal/eval"
)

// --- raid.<host> ---

// mdArray is one md array from /proc/mdstat.
type mdArray struct {
	Name    string   `json:"name"`
	Level   string   `json:"level"`
	State   string   `json:"state"`   // active, inactive
	Members []string `json:"members"` // sata1p5[0]; "(F)" marks a failed one
	Want    int      `json:"want"`    // members the array should have
	Have    int      `json:"have"`    // members working
	Map     string   `json:"map"`     // UU_U
	Action  string   `json:"action,omitempty"` // recovery, resync, reshape or check
	Pct     float64  `json:"pct,omitempty"`    // progress of Action
	System  bool     `json:"system,omitempty"`
}

var (
	mdHead   = regexp.MustCompile(`^(md\d+)\s*:\s*(\S+)\s*(?:\((?:auto-)?read-only\)\s*)?(\S*)\s*(.*)$`)
	mdCount  = regexp.MustCompile(`\[(\d+)/(\d+)\]\s*\[([U_]+)\]`)
	mdAction = regexp.MustCompile(`\b(recovery|resync|reshape|check)\s*=\s*([\d.]+)%`)
)

// parseMdstat reads /proc/mdstat: an "mdN : state level members" line, then
// indented lines with "[want/have] [UU_]" and, while it runs, a progress line.
func parseMdstat(s string) []mdArray {
	var out []mdArray
	for _, line := range strings.Split(s, "\n") {
		if m := mdHead.FindStringSubmatch(strings.TrimSpace(line)); m != nil && !strings.HasPrefix(line, " ") {
			a := mdArray{Name: m[1], State: m[2], Level: m[3], Members: strings.Fields(m[4])}
			if a.State == "inactive" { // "md9 : inactive sda1[0]": no level
				a.Level, a.Members = "", strings.Fields(m[3]+" "+m[4])
			}
			out = append(out, a)
			continue
		}
		if len(out) == 0 || !strings.HasPrefix(line, " ") {
			continue
		}
		a := &out[len(out)-1]
		if m := mdCount.FindStringSubmatch(line); m != nil {
			a.Want, _ = strconv.Atoi(m[1])
			a.Have, _ = strconv.Atoi(m[2])
			a.Map = m[3]
		}
		if m := mdAction.FindStringSubmatch(line); m != nil {
			a.Action = m[1]
			a.Pct, _ = strconv.ParseFloat(m[2], 64)
		}
	}
	return out
}

// raidCheck: crit when a data array is inactive or missing a member, warn when
// only a system array (an OS copy on every disk) is, or while an array rebuilds.
// A scrub ("check") is normal. A one-disk array is fine but has no redundancy,
// so the summary says so.
func raidCheck(id, mdstat string, system []string) Check {
	arrays := parseMdstat(mdstat)
	if len(arrays) == 0 {
		return Check{ID: id, State: eval.OK, Summary: "no md arrays", Data: mustJSON(map[string]any{"arrays": arrays})}
	}
	sys := map[string]bool{}
	for _, n := range system {
		sys[n] = true
	}
	state := eval.OK
	var crit, warn, notes []string
	for i := range arrays {
		a := &arrays[i]
		a.System = sys[a.Name]
		failed := 0
		for _, m := range a.Members {
			if strings.Contains(m, "(F)") {
				failed++
			}
		}
		degraded := a.State == "inactive" || failed > 0 || a.Have < a.Want || strings.Contains(a.Map, "_")
		switch {
		case degraded && a.System:
			warn = append(warn, fmt.Sprintf("%s (system partition) %d of %d disks", a.Name, a.Have, a.Want))
			state = eval.Worst(state, eval.Warn)
		case a.State == "inactive":
			crit = append(crit, a.Name+" inactive")
			state = eval.Crit
		case degraded:
			crit = append(crit, fmt.Sprintf("%s %s degraded, %d of %d disks", a.Name, a.Level, a.Have, a.Want))
			state = eval.Crit
		case a.Action != "" && a.Action != "check":
			warn = append(warn, fmt.Sprintf("%s %s %.0f%%", a.Name, a.Action, a.Pct))
			state = eval.Worst(state, eval.Warn)
		case a.Action == "check":
			notes = append(notes, fmt.Sprintf("%s scrubbing %.0f%%", a.Name, a.Pct))
		case a.Want == 1 && !a.System:
			notes = append(notes, a.Name+" is one disk, no redundancy")
		}
	}
	summary := strings.Join(append(append(crit, warn...), notes...), "; ")
	if len(crit)+len(warn) == 0 {
		head := fmt.Sprintf("%d arrays healthy", len(arrays))
		if summary != "" {
			head += "; " + summary
		}
		summary = head
	}
	return Check{ID: id, State: state, Summary: Clip(summary, 300), Data: mustJSON(map[string]any{"arrays": arrays})}
}

// --- smart.<host> ---

// smartDisk is what one smartctl run says about a drive.
type smartDisk struct {
	Device      string `json:"device"`
	Model       string `json:"model,omitempty"`
	Health      string `json:"health"` // PASSED, FAILED, or "" when unread
	Reallocated int64  `json:"reallocated"`
	Pending     int64  `json:"pending"`
	Uncorrect   int64  `json:"uncorrectable"`
	Hours       int64  `json:"power_on_hours,omitempty"`
	TempC       int64  `json:"temp_c,omitempty"`
	FailingNow  []string `json:"failing_now,omitempty"` // attributes at or under threshold now
	FailedPast  []string `json:"failed_in_past,omitempty"`
	Error       string `json:"error,omitempty"`
}

var (
	smartHealth = regexp.MustCompile(`(?m)^SMART overall-health self-assessment test result:\s*(\S+)|^SMART Health Status:\s*(\S+)`)
	smartModel  = regexp.MustCompile(`(?m)^(?:Device Model|Model Number|Product):\s*(.+)$`)
	smartAttr   = regexp.MustCompile(`^\s*(\d+)\s+(\S+)\s+0x[0-9a-fA-F]+\s+\d+\s+\d+\s+\d+\s+\S+\s+\S+\s+(\S+)\s+(\d+)`)
)

// parseSmart reads `smartctl -H -A -i`. Attributes are matched by number, not
// name: vendors name 5, 197 and 198 differently (Seagate IronWolf Pro calls 5
// Retired_Sectors_Count).
func parseSmart(device, out string) smartDisk {
	d := smartDisk{Device: device}
	if m := smartModel.FindStringSubmatch(out); m != nil {
		d.Model = Clip(strings.TrimSpace(m[1]), 60)
	}
	if m := smartHealth.FindStringSubmatch(out); m != nil {
		d.Health = m[1] + m[2]
		if d.Health == "OK" { // SAS and NVMe say OK
			d.Health = "PASSED"
		}
	}
	for _, line := range strings.Split(out, "\n") {
		m := smartAttr.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		raw, _ := strconv.ParseInt(m[4], 10, 64)
		switch m[1] {
		case "5":
			d.Reallocated = raw
		case "197":
			d.Pending = raw
		case "198":
			d.Uncorrect = raw
		case "9":
			d.Hours = raw
		case "194":
			d.TempC = raw
		}
		switch m[3] {
		case "FAILING_NOW":
			d.FailingNow = append(d.FailingNow, m[2])
		case "In_the_past":
			d.FailedPast = append(d.FailedPast, m[2])
		}
	}
	return d
}

// smartCheck: crit when a drive fails its self-assessment, has an attribute
// failing now, or has pending or uncorrectable sectors; warn on reallocated
// sectors (the drive has started to wear out) or a drive that could not be read.
func smartCheck(id string, disks []smartDisk) Check {
	sort.Slice(disks, func(i, j int) bool { return disks[i].Device < disks[j].Device })
	state := eval.OK
	var crit, warn []string
	name := func(d smartDisk) string { return strings.TrimPrefix(d.Device, "/dev/") }
	for _, d := range disks {
		switch {
		case d.Health == "":
			warn = append(warn, name(d)+" unreadable")
			state = eval.Worst(state, eval.Warn)
		case d.Health != "PASSED":
			crit = append(crit, name(d)+" health "+d.Health)
			state = eval.Crit
		case len(d.FailingNow) > 0:
			crit = append(crit, name(d)+" failing now: "+strings.Join(d.FailingNow, ", "))
			state = eval.Crit
		case d.Pending > 0 || d.Uncorrect > 0:
			crit = append(crit, fmt.Sprintf("%s %d pending, %d uncorrectable sectors", name(d), d.Pending, d.Uncorrect))
			state = eval.Crit
		case d.Reallocated > 0:
			warn = append(warn, fmt.Sprintf("%s %d reallocated sectors", name(d), d.Reallocated))
			state = eval.Worst(state, eval.Warn)
		}
	}
	summary := fmt.Sprintf("%d drives passed", len(disks))
	if bad := append(crit, warn...); len(bad) > 0 {
		summary = strings.Join(bad, "; ")
	}
	return Check{ID: id, State: state, Summary: Clip(summary, 300), Data: mustJSON(map[string]any{"disks": disks})}
}
