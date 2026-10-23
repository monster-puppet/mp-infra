package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

// Path is the report endpoint on the report port.
const Path = "/api/report"

// Reply is what the server may answer a report with (200, application/json):
// addresses to unban. A 204 is no reply.
type Reply struct {
	Unban []string `json:"unban"`
}

// maxReply is the most of a reply the agent reads.
const maxReply = 16 << 10

// Send POSTs a payload to serverURL with the host's bearer token. It returns the
// server's reply, or nil when there is none.
func Send(ctx context.Context, client *http.Client, serverURL, token string, p *Payload) (*Reply, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBody {
		return nil, fmt.Errorf("report is %d bytes, limit %d", len(body), MaxBody)
	}
	url := strings.TrimRight(serverURL, "/") + Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || mt != "application/json" {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
		}
		return nil, nil
	}
	var r Reply
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReply)).Decode(&r); err != nil {
		return nil, fmt.Errorf("report stored, but the reply is unreadable: %v", err)
	}
	return &r, nil
}
