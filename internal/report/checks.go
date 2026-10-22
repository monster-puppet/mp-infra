package report

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// --- host.uptime ---

func uptimeCheck(sec float64) Check {
	d := time.Duration(sec) * time.Second
	return Check{ID: "host.uptime", State: eval.OK, Summary: "up " + Human(d), Data: mustJSON(map[string]any{"seconds": int64(sec)})}
}

// parseProcUptime reads the first field of /proc/uptime.
func parseProcUptime(s string) (float64, error) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, errors.New("empty /proc/uptime")
	}
	return strconv.ParseFloat(f[0], 64)
}

// Human formats a duration as "3d 4h", "5h 2m" or "42s".
func Human(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd %dh", d/(24*time.Hour), (d%(24*time.Hour))/time.Hour)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", d/time.Hour, (d%time.Hour)/time.Minute)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}

// --- disk.<host>.<mount> ---

var notIDChar = regexp.MustCompile(`[^a-z0-9]+`)

// diskID builds a check id from a mount point: "/" -> root, "/var/lib" -> var-lib,
// `C:\` -> c.
func diskID(host, mount string) string {
	m := strings.Trim(notIDChar.ReplaceAllString(strings.ToLower(mount), "-"), "-")
	if m == "" {
		m = "root"
	}
	return "disk." + host + "." + m
}

func diskCheck(id, mount string, total, free uint64, warn, crit float64) Check {
	if total == 0 {
		return Check{ID: id, State: eval.Warn, Summary: mount + ": size 0"}
	}
	pct := float64(total-free) / float64(total) * 100
	return Check{
		ID:      id,
		State:   eval.Higher(pct, warn, crit),
		Summary: fmt.Sprintf("%s %.0f%% used, %s free", mount, pct, bytesHuman(free)),
		Data:    mustJSON(map[string]any{"mount": mount, "total_bytes": total, "free_bytes": free, "used_pct": pct}),
	}
}

func bytesHuman(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// --- p4.checkpoint ---

// tsLine matches the start of a timestamped log line. checkpoint.log has
// continuation lines without a timestamp; those are never treated as a new entry.
var tsLine = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}`)

const tailBytes = 1 << 20

// checkpointCheck reads the tail of checkpoint.log. The last run is the file's last
// write. It is crit when that is older than maxAge or the log says "Aborting".
func checkpointCheck(path string, maxAge time.Duration, now time.Time) (Check, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Check{}, err
	}
	body, err := tail(path, tailBytes)
	if err != nil {
		return Check{}, err
	}
	return evalCheckpoint(body, fi.ModTime(), maxAge, now), nil
}

func evalCheckpoint(body string, mod time.Time, maxAge time.Duration, now time.Time) Check {
	age := now.Sub(mod)
	var abort, lastTS string
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if tsLine.MatchString(line) {
			lastTS = line
		}
		if abort == "" && strings.Contains(line, "Aborting") {
			abort = strings.TrimSpace(line)
		}
	}
	data := map[string]any{"last_write": mod.UTC().Format(time.RFC3339), "age_seconds": int64(age.Seconds())}
	if lastTS != "" {
		data["last_entry"] = Clip(lastTS, 300)
	}
	c := Check{ID: "p4.checkpoint", State: eval.OK, Data: mustJSON(data)}
	switch {
	case abort != "":
		c.State = eval.Crit
		c.Summary = "checkpoint aborted: " + abort
		data["aborting"] = Clip(abort, 300)
		c.Data = mustJSON(data)
	case age > maxAge:
		c.State = eval.Crit
		c.Summary = "no checkpoint for " + Human(age)
	default:
		c.Summary = fmt.Sprintf("checkpoint %s ok, %s ago", mod.Local().Format("15:04"), Human(age))
	}
	return c
}

func tail(path string, n int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if off := fi.Size() - n; off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, n))
	return string(b), err
}

// --- p4.offline_db ---

// offlineDBCheck looks at the db.* files in the SDP offline_db directory. The
// offline db is usable when they exist and were updated by the last journal
// replay, within maxAge.
func offlineDBCheck(dir string, maxAge time.Duration, now time.Time) (Check, error) {
	files, err := filepath.Glob(filepath.Join(dir, "db.*"))
	if err != nil {
		return Check{}, err
	}
	var newest time.Time
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return evalOfflineDB(len(files), newest, maxAge, now), nil
}

func evalOfflineDB(n int, newest time.Time, maxAge time.Duration, now time.Time) Check {
	c := Check{ID: "p4.offline_db", State: eval.OK}
	if n == 0 {
		c.State = eval.Crit
		c.Summary = "no db.* files in offline_db"
		return c
	}
	age := now.Sub(newest)
	c.Data = mustJSON(map[string]any{"files": n, "newest": newest.UTC().Format(time.RFC3339), "age_seconds": int64(age.Seconds())})
	if age > maxAge {
		c.State = eval.Crit
		c.Summary = fmt.Sprintf("offline db not updated for %s", Human(age))
		return c
	}
	c.Summary = fmt.Sprintf("offline db updated %s ago (%d db files)", Human(age), n)
	return c
}

// --- p4.licence ---

// parseZtag reads "... key value" lines from p4 -ztag output and ignores
// everything else, such as SDP login noise.
func parseZtag(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "... ") {
			continue
		}
		k, v, _ := strings.Cut(strings.TrimPrefix(line, "... "), " ")
		if _, dup := m[k]; !dup {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// licenceCheck evaluates `p4 -ztag license -u`: users and clients against the
// licensed limits. A missing or non-numeric limit means unlimited.
func licenceCheck(out string) (Check, error) {
	z := parseZtag(out)
	if len(z) == 0 {
		return Check{}, errors.New("no ztag fields in p4 license output")
	}
	c := Check{ID: "p4.licence", State: eval.OK}
	data := map[string]any{}
	var parts []string
	for _, kind := range []string{"user", "client"} {
		count, err := strconv.Atoi(z[kind+"Count"])
		if err != nil {
			continue
		}
		data[kind+"_count"] = count
		limit, err := strconv.Atoi(z[kind+"Limit"])
		if err != nil || limit <= 0 {
			parts = append(parts, fmt.Sprintf("%d %ss", count, kind))
			continue
		}
		data[kind+"_limit"] = limit
		parts = append(parts, fmt.Sprintf("%d/%d %ss", count, limit, kind))
		if count >= limit {
			c.State = eval.Warn
		}
	}
	if len(parts) == 0 {
		return Check{}, errors.New("p4 license output has no userCount or clientCount")
	}
	c.Summary = strings.Join(parts, ", ")
	if c.State == eval.Warn {
		c.Summary += " (at limit)"
	}
	c.Data = mustJSON(data)
	return c, nil
}

// --- fw.rules.<host> ---

const maxFirewallText = 8 << 10

// firewallCheck hashes the firewall listing. The server compares the hash to the
// last accepted one; the agent always reports ok.
func firewallCheck(id, out string) Check {
	norm := strings.TrimSpace(strings.ReplaceAll(out, "\r\n", "\n"))
	sum := sha256.Sum256([]byte(norm))
	h := hex.EncodeToString(sum[:])
	return Check{
		ID:      id,
		State:   eval.OK,
		Summary: "firewall rules " + h[:12],
		Data:    mustJSON(map[string]any{"hash": h, "text": Clip(norm, maxFirewallText)}),
	}
}

// --- os.security_updates.<host> ---

// Update is one pending security update.
type Update struct {
	Key   string `json:"key"`
	Title string `json:"title,omitempty"`
}

const maxUpdates = 100

func updatesCheck(id, source string, items []Update) Check {
	total := len(items)
	if len(items) > maxUpdates {
		items = items[:maxUpdates]
	}
	return Check{
		ID:      id,
		State:   eval.OK, // the server sets the state from how long each item has been pending
		Summary: fmt.Sprintf("%d pending security updates", total),
		Data:    mustJSON(map[string]any{"source": source, "count": total, "items": items}),
	}
}

var dnfAdvisory = regexp.MustCompile(`^[A-Z][A-Z0-9]*-\d{4}[:-]\d+`)

// parseDnfSecurity reads `dnf -q updateinfo list --security`: one advisory id, its
// type/severity and a package per line. One update per advisory.
func parseDnfSecurity(out string) []Update {
	seen := map[string]bool{}
	var items []Update
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !dnfAdvisory.MatchString(f[0]) || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		items = append(items, Update{Key: f[0], Title: f[1] + " " + f[2]})
	}
	return items
}

// parseAptUpgradable reads `apt list --upgradable` and keeps packages whose
// candidate comes from a -security suite.
func parseAptUpgradable(out string) []Update {
	var items []Update
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name, suites, ok := strings.Cut(f[0], "/")
		if !ok || !strings.Contains(suites, "-security") {
			continue
		}
		items = append(items, Update{Key: name + "/" + f[1], Title: name + " " + f[1]})
	}
	return items
}

// parseWindowsUpdates reads the JSON array printed by the Windows Update script.
func parseWindowsUpdates(out string) ([]Update, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	var raw []struct {
		ID    string `json:"Id"`
		Title string `json:"Title"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("windows update output: %w", err)
	}
	var items []Update
	for _, r := range raw {
		if r.ID != "" {
			items = append(items, Update{Key: r.ID, Title: r.Title})
		}
	}
	return items, nil
}

func securityUpdates(ctx context.Context, source string) ([]Update, error) {
	switch source {
	case "dnf":
		out, err := run(ctx, []string{"dnf", "-q", "updateinfo", "list", "--security"}, nil)
		if err != nil {
			return nil, err
		}
		return parseDnfSecurity(out), nil
	case "apt":
		out, err := run(ctx, []string{"apt", "list", "--upgradable"}, map[string]string{"LC_ALL": "C"})
		if err != nil {
			return nil, err
		}
		return parseAptUpgradable(out), nil
	case "windows":
		out, err := powershell(ctx, windowsUpdateScript)
		if err != nil {
			return nil, err
		}
		return parseWindowsUpdates(out)
	}
	return nil, fmt.Errorf("unknown security_updates source %q", source)
}

// windowsUpdateScript lists pending software updates that carry an MSRC severity.
const windowsUpdateScript = `$ErrorActionPreference = 'Stop'
$s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$r = $s.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
$u = @($r.Updates | Where-Object { $_.MsrcSeverity } | ForEach-Object {
  [pscustomobject]@{ Id = $_.Identity.UpdateID; Title = $_.Title } })
ConvertTo-Json -Compress -InputObject $u`

// --- pkg.version.<name> ---

func versionCheck(id string, v config.Version, out string) (Check, error) {
	ver := strings.TrimSpace(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
	if v.Pattern != "" {
		m := regexp.MustCompile(v.Pattern).FindStringSubmatch(out)
		if m == nil {
			return Check{}, fmt.Errorf("version pattern did not match output")
		}
		ver = m[0]
		if len(m) > 1 {
			ver = m[1]
		}
	}
	ver = Clip(strings.TrimSpace(ver), 100)
	c := Check{ID: id, State: eval.OK, Summary: v.Name + " " + ver}
	data := map[string]any{"version": ver}
	if v.Min != "" {
		data["min"] = v.Min
		if CompareVersions(ver, v.Min) < 0 {
			c.State = eval.Warn
			c.Summary += " (below " + v.Min + ")"
		}
	}
	c.Data = mustJSON(data)
	return c, nil
}

var digits = regexp.MustCompile(`\d+`)

// CompareVersions compares the numeric parts of two version strings
// ("2024.1/2596294" vs "2023.2"): -1, 0 or 1.
func CompareVersions(a, b string) int {
	pa, pb := digits.FindAllString(a, -1), digits.FindAllString(b, -1)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// --- auth.failures.<host> ---

type authCount struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
	Error  string `json:"error,omitempty"`
}

type ipCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

func authCheck(ctx context.Context, id string, af *config.AuthFailures) (Check, error) {
	outs := make([]string, len(af.Sources))
	errs := make([]error, len(af.Sources))
	for i, src := range af.Sources {
		outs[i], errs[i] = run(ctx, src.Cmd, src.Env)
	}
	return evalAuth(id, af, outs, errs), nil
}

func evalAuth(id string, af *config.AuthFailures, outs []string, errs []error) Check {
	total := 0
	ips := map[string]int{}
	var per []authCount
	failed := 0
	for i, src := range af.Sources {
		ac := authCount{Source: src.Name}
		if errs[i] != nil {
			ac.Error = Clip(errs[i].Error(), 200)
			failed++
		}
		re := regexp.MustCompile(src.Pattern)
		ipIdx := re.SubexpIndex("ip")
		for _, line := range strings.Split(outs[i], "\n") {
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			ac.Count++
			if ipIdx > 0 && m[ipIdx] != "" {
				ips[Clip(m[ipIdx], 64)]++
			}
		}
		total += ac.Count
		per = append(per, ac)
	}
	top := make([]ipCount, 0, len(ips))
	for ip, n := range ips {
		top = append(top, ipCount{ip, n})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].IP < top[j].IP
	})
	if len(top) > 10 {
		top = top[:10]
	}
	c := Check{ID: id, State: eval.OK, Summary: fmt.Sprintf("%d failed logins in 24 h", total)}
	if len(top) > 0 {
		c.Summary += fmt.Sprintf(", top %s (%d)", top[0].IP, top[0].Count)
	}
	if af.Warn > 0 && total >= af.Warn {
		c.State = eval.Warn
	}
	if af.WarnPerIP > 0 && len(top) > 0 && top[0].Count >= af.WarnPerIP {
		c.State = eval.Warn
		c.Summary += fmt.Sprintf("; brute force from %s", top[0].IP)
	}
	if failed > 0 {
		c.State = eval.Warn
		c.Summary += fmt.Sprintf("; %d source(s) failed", failed)
	}
	c.Data = mustJSON(map[string]any{"total": total, "sources": per, "top_ips": top})
	return c
}
