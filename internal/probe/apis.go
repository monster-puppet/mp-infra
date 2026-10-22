package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// --- DigitalOcean snapshots ---

type doSnapshot struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (p *Prober) snapshotChecks(ctx context.Context) []Check {
	do := p.cfg.DO
	token := config.Env(do.TokenEnv)
	if token == "" || len(do.Droplets) == 0 {
		return nil
	}
	var out []Check
	for _, d := range do.Droplets {
		id := "snapshot.age." + d.Name
		host := p.hostFor(d.Name)
		snaps, err := p.doSnapshots(ctx, token, d.ID)
		if err != nil {
			out = append(out, errCheck(host, id, eval.Crit, err))
			continue
		}
		out = append(out, p.evalSnapshots(host, id, snaps))
	}
	return out
}

func (p *Prober) doSnapshots(ctx context.Context, token string, droplet int64) ([]doSnapshot, error) {
	api := strings.TrimRight(p.cfg.DO.APIURL, "/")
	next := api + "/v2/droplets/" + strconv.FormatInt(droplet, 10) + "/snapshots?per_page=200"
	var all []doSnapshot
	for page := 0; next != "" && page < 10; page++ {
		// Only follow pagination links back to the same API, so the token never
		// goes anywhere else.
		if !strings.HasPrefix(next, api+"/") {
			return nil, fmt.Errorf("unexpected pagination link")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		var body struct {
			Snapshots []doSnapshot `json:"snapshots"`
			Links     struct {
				Pages struct {
					Next string `json:"next"`
				} `json:"pages"`
			} `json:"links"`
		}
		if err := p.doJSON(req, &body); err != nil {
			return nil, err
		}
		all = append(all, body.Snapshots...)
		next = body.Links.Pages.Next
	}
	return all, nil
}

func (p *Prober) evalSnapshots(host, id string, snaps []doSnapshot) Check {
	if len(snaps) == 0 {
		return Check{Host: host, ID: id, State: eval.Crit, Summary: "no snapshots"}
	}
	newest := snaps[0]
	for _, s := range snaps[1:] {
		if s.CreatedAt.After(newest.CreatedAt) {
			newest = s
		}
	}
	age := days(p.now().Sub(newest.CreatedAt))
	th := p.cfg.Thresholds
	return Check{Host: host, ID: id, State: eval.Higher(age, th.SnapshotWarnDays, th.SnapshotCritDays),
		Summary: fmt.Sprintf("newest snapshot %.0f days old (%s)", age, clip(newest.Name, 100)),
		Data:    map[string]any{"count": len(snaps), "newest": newest.Name, "created_at": newest.CreatedAt, "age_days": age}}
}

// --- Notion OpSec checklist ---

const notionVersion = "2022-06-28"

func (p *Prober) notionChecks(ctx context.Context) []Check {
	n := p.cfg.Notion
	token := config.Env(n.TokenEnv)
	if token == "" || n.DatabaseID == "" || n.DoneProperty == "" {
		return nil
	}
	const id = "opsec.items"
	titles, count, err := p.notionOpen(ctx, token)
	if err != nil {
		return []Check{errCheck(config.ServeHost, id, eval.Warn, err)}
	}
	c := Check{Host: config.ServeHost, ID: id, State: eval.OK, Summary: "no open OpSec items",
		Data: map[string]any{"open": count, "titles": titles}}
	if count > 0 {
		c.State = eval.Warn
		c.Summary = fmt.Sprintf("%d open OpSec item(s)", count)
		if len(titles) > 0 {
			c.Summary += ", e.g. " + clip(titles[0], 120)
		}
	}
	return []Check{c}
}

func (p *Prober) notionOpen(ctx context.Context, token string) ([]string, int, error) {
	n := p.cfg.Notion
	url := strings.TrimRight(n.APIURL, "/") + "/v1/databases/" + n.DatabaseID + "/query"
	var titles []string
	count := 0
	cursor := ""
	for page := 0; page < 20; page++ {
		q := map[string]any{
			"filter":    map[string]any{"property": n.DoneProperty, "checkbox": map[string]any{"equals": false}},
			"page_size": 100,
		}
		if cursor != "" {
			q["start_cursor"] = cursor
		}
		b, _ := json.Marshal(q)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Notion-Version", notionVersion)
		req.Header.Set("Content-Type", "application/json")
		var body struct {
			Results []struct {
				Properties map[string]struct {
					Type  string `json:"type"`
					Title []struct {
						PlainText string `json:"plain_text"`
					} `json:"title"`
				} `json:"properties"`
			} `json:"results"`
			HasMore    bool   `json:"has_more"`
			NextCursor string `json:"next_cursor"`
		}
		if err := p.doJSON(req, &body); err != nil {
			return nil, 0, fmt.Errorf("notion: %w", err)
		}
		for _, r := range body.Results {
			count++
			for _, prop := range r.Properties {
				if prop.Type != "title" || len(titles) >= 20 {
					continue
				}
				var t strings.Builder
				for _, part := range prop.Title {
					t.WriteString(part.PlainText)
				}
				if t.Len() > 0 {
					titles = append(titles, clip(t.String(), 200))
				}
			}
		}
		if !body.HasMore || body.NextCursor == "" {
			break
		}
		cursor = body.NextCursor
	}
	return titles, count, nil
}
