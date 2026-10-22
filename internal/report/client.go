package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Path is the report endpoint on the report port.
const Path = "/api/report"

// Send POSTs a payload to serverURL with the host's bearer token.
func Send(ctx context.Context, client *http.Client, serverURL, token string, p *Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(body) > MaxBody {
		return fmt.Errorf("report is %d bytes, limit %d", len(body), MaxBody)
	}
	url := strings.TrimRight(serverURL, "/") + Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
