package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

func (p *Prober) jenkinsChecks(ctx context.Context) []Check {
	j := p.cfg.Jenkins
	token := config.Env(j.TokenEnv)
	if j.URL == "" || token == "" {
		return nil
	}
	var out []Check
	for _, name := range j.Agents {
		out = append(out, p.jenkinsAgent(ctx, name, token))
	}
	if j.BreakglassJob != "" {
		out = append(out, p.breakglass(ctx, token))
	}
	return out
}

func (p *Prober) jenkinsReq(ctx context.Context, method, path, token string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.cfg.Jenkins.URL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.cfg.Jenkins.User, token)
	return req, nil
}

func (p *Prober) jenkinsAgent(ctx context.Context, name, token string) Check {
	id := "jenkins.agent." + name
	host := p.hostFor(p.cfg.Jenkins.AgentHosts[name])
	req, err := p.jenkinsReq(ctx, http.MethodGet, "/computer/"+url.PathEscape(name)+"/api/json?tree=offline,temporarilyOffline,offlineCauseReason", token)
	if err != nil {
		return errCheck(host, id, eval.Crit, err)
	}
	var c struct {
		Offline            bool   `json:"offline"`
		TemporarilyOffline bool   `json:"temporarilyOffline"`
		OfflineCauseReason string `json:"offlineCauseReason"`
	}
	if err := p.doJSON(req, &c); err != nil {
		return errCheck(host, id, eval.Crit, err)
	}
	return p.evalAgent(host, id, name, c.Offline, c.OfflineCauseReason)
}

// evalAgent applies the offline grace period: offline for less than the grace is
// warn, longer is crit. The first-offline time is kept in memory.
func (p *Prober) evalAgent(host, id, name string, offline bool, reason string) Check {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !offline {
		delete(p.jenkinsOffline, name)
		return Check{Host: host, ID: id, State: eval.OK, Summary: "agent " + name + " online", Data: map[string]any{"offline": false}}
	}
	since, ok := p.jenkinsOffline[name]
	if !ok {
		since = now
		p.jenkinsOffline[name] = now
	}
	off := now.Sub(since)
	c := Check{Host: host, ID: id, State: eval.Warn, Summary: "agent " + name + " offline " + humanAgo(off),
		Data: map[string]any{"offline": true, "offline_since": since, "reason": clip(reason, 300)}}
	if reason != "" {
		c.Summary += ": " + clip(reason, 200)
	}
	if off >= p.cfg.Thresholds.JenkinsOfflineGrace {
		c.State = eval.Crit
	}
	return c
}

type jenkinsBuild struct {
	Number    int    `json:"number"`
	Result    string `json:"result"`
	Timestamp int64  `json:"timestamp"` // ms
}

func (b *jenkinsBuild) time() time.Time {
	if b == nil {
		return time.Time{}
	}
	return time.UnixMilli(b.Timestamp)
}

const breakglassKey = "breakglass.last_trigger"

// breakglass checks that the break-glass job last succeeded recently. With
// breakglass_monthly it also starts an ACTION=status build once the last success
// is 28 days old (and no trigger was sent in the last day), so the route is proven
// every month. The status action only reads.
func (p *Prober) breakglass(ctx context.Context, token string) Check {
	const id = "win.breakglass_job"
	j := p.cfg.Jenkins
	host := p.hostFor(j.BreakglassHost)
	job := "/job/" + url.PathEscape(j.BreakglassJob)
	req, err := p.jenkinsReq(ctx, http.MethodGet, job+"/api/json?tree=lastCompletedBuild[number,result,timestamp],lastSuccessfulBuild[number,result,timestamp]", token)
	if err != nil {
		return errCheck(host, id, eval.Crit, err)
	}
	var body struct {
		LastCompleted  *jenkinsBuild `json:"lastCompletedBuild"`
		LastSuccessful *jenkinsBuild `json:"lastSuccessfulBuild"`
	}
	if err := p.doJSON(req, &body); err != nil {
		return errCheck(host, id, eval.Crit, err)
	}
	c := p.evalBreakglass(host, body.LastCompleted, body.LastSuccessful)
	if j.BreakglassMonthly && p.kv != nil {
		if msg := p.maybeTriggerBreakglass(ctx, token, body.LastSuccessful); msg != "" {
			c.Summary = clip(c.Summary+"; "+msg, 300)
		}
	}
	return c
}

func (p *Prober) evalBreakglass(host string, completed, success *jenkinsBuild) Check {
	const id = "win.breakglass_job"
	now := p.now()
	max := p.cfg.Thresholds.BreakglassMaxAge
	data := map[string]any{}
	if completed != nil {
		data["last_completed"] = map[string]any{"number": completed.Number, "result": completed.Result, "at": completed.time()}
	}
	if success != nil {
		data["last_success"] = map[string]any{"number": success.Number, "at": success.time()}
	}
	c := Check{Host: host, ID: id, State: eval.OK, Data: data}
	switch {
	case success == nil:
		c.State = eval.Crit
		c.Summary = "no successful break-glass run"
	case completed != nil && completed.Result != "SUCCESS":
		c.State = eval.Crit
		c.Summary = fmt.Sprintf("last run #%d %s", completed.Number, completed.Result)
	case now.Sub(success.time()) > max:
		c.State = eval.Crit
		c.Summary = fmt.Sprintf("last success #%d %s, older than %.0f days", success.Number, humanAgo(now.Sub(success.time())), days(max))
	default:
		c.Summary = fmt.Sprintf("last success #%d %s", success.Number, humanAgo(now.Sub(success.time())))
	}
	return c
}

func (p *Prober) maybeTriggerBreakglass(ctx context.Context, token string, success *jenkinsBuild) string {
	now := p.now()
	if success != nil && now.Sub(success.time()) < 28*24*time.Hour {
		return ""
	}
	last, _ := p.kv.Get(ctx, breakglassKey)
	if ts, err := strconv.ParseInt(last, 10, 64); err == nil && now.Sub(time.Unix(ts, 0)) < 24*time.Hour {
		return ""
	}
	req, err := p.jenkinsReq(ctx, http.MethodPost, "/job/"+url.PathEscape(p.cfg.Jenkins.BreakglassJob)+"/buildWithParameters?ACTION=status", token)
	if err != nil {
		return "status build not started: " + err.Error()
	}
	p.kv.Set(ctx, breakglassKey, strconv.FormatInt(now.Unix(), 10))
	if err := p.doJSON(req, nil); err != nil {
		return "status build not started: " + err.Error()
	}
	return "started the monthly ACTION=status build"
}
