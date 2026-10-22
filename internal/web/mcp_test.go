package web

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monster-puppet/mp-infra/internal/config"
)

func mcpEnv(t *testing.T) (*env, http.Handler) {
	t.Helper()
	e := setup(t)
	sum := sha256.Sum256([]byte("mcp-secret"))
	w := New(e.srv, nil)
	w.EnableMCP(config.Tokens{"ops-agent": sum[:]})
	return e, w.UI()
}

func mcpPost(h http.Handler, token, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, MCPPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type rpcReply struct {
	ID     json.RawMessage `json:"id"`
	Result struct {
		ProtocolVersion string           `json:"protocolVersion"`
		Tools           []map[string]any `json:"tools"`
		Content         []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	} `json:"result"`
	Error *rpcError `json:"error"`
}

func call(t *testing.T, h http.Handler, method, params string) rpcReply {
	t.Helper()
	rec := mcpPost(h, "mcp-secret", `{"jsonrpc":"2.0","id":7,"method":"`+method+`","params":`+params+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", method, rec.Code, rec.Body)
	}
	var r rpcReply
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("%s: %v: %s", method, err, rec.Body)
	}
	if string(r.ID) != "7" {
		t.Fatalf("%s: id %s", method, r.ID)
	}
	return r
}

// tool calls a tool and decodes its JSON text result into out.
func tool(t *testing.T, h http.Handler, name, args string, out any) rpcReply {
	t.Helper()
	r := call(t, h, "tools/call", `{"name":"`+name+`","arguments":`+args+`}`)
	if r.Error == nil && !r.Result.IsError && out != nil {
		if err := json.Unmarshal([]byte(r.Result.Content[0].Text), out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	return r
}

func TestMCPOffWithoutTokens(t *testing.T) {
	e := setup(t)
	if rec := mcpPost(e.ui, "anything", `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
}

func TestMCPAuth(t *testing.T) {
	_, h := mcpEnv(t)
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	for _, tok := range []string{"", "wrong"} {
		if rec := mcpPost(h, tok, initReq); rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("token %q: %d", tok, rec.Code)
		}
	}
	if rec := mcpPost(h, "mcp-secret", initReq, "Origin", "https://evil.example"); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site origin: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, MCPPath, nil)
	req.Header.Set("Authorization", "Bearer mcp-secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	if rec := mcpPost(h, "mcp-secret", strings.Repeat("x", mcpMaxBody+1)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("huge body: %d", rec.Code)
	}
}

func TestMCPProtocol(t *testing.T) {
	_, h := mcpEnv(t)
	r := call(t, h, "initialize", `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-code","version":"1"}}`)
	if r.Error != nil || r.Result.ProtocolVersion != "2025-06-18" {
		t.Fatalf("initialize: %+v", r)
	}
	if r := call(t, h, "initialize", `{"protocolVersion":"1999-01-01"}`); r.Result.ProtocolVersion != mcpLatest {
		t.Errorf("unknown version answered with %q", r.Result.ProtocolVersion)
	}
	if rec := mcpPost(h, "mcp-secret", `{"jsonrpc":"2.0","method":"notifications/initialized"}`); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Errorf("notification: %d %q", rec.Code, rec.Body)
	}
	r = call(t, h, "tools/list", `{}`)
	if len(r.Result.Tools) != len(mcpHandlers) {
		t.Fatalf("tools/list: %d tools", len(r.Result.Tools))
	}
	for _, tl := range r.Result.Tools {
		if _, ok := mcpHandlers[tl["name"].(string)]; !ok {
			t.Errorf("listed tool %v has no handler", tl["name"])
		}
		if ann := tl["annotations"].(map[string]any); ann["readOnlyHint"] != true {
			t.Errorf("%v is not marked read-only", tl["name"])
		}
	}
	if r := call(t, h, "resources/list", `{}`); r.Error == nil || r.Error.Code != rpcNoMethod {
		t.Errorf("unsupported method: %+v", r.Error)
	}
	if r := call(t, h, "tools/call", `{"name":"ack"}`); r.Error == nil || r.Error.Code != rpcInvalidParams {
		t.Errorf("unknown tool: %+v", r.Error)
	}
	rec := mcpPost(h, "mcp-secret", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`)
	if !strings.Contains(rec.Body.String(), `"code":-32700`) {
		t.Errorf("batch: %s", rec.Body)
	}
}

func TestMCPTools(t *testing.T) {
	e, h := mcpEnv(t)
	if rec := e.post("tok-monster-p4", body("monster-p4", "up 5 s")); rec.Code != http.StatusNoContent {
		t.Fatalf("report: %d %s", rec.Code, rec.Body)
	}

	var st struct {
		State string `json:"state"`
		Hosts []struct {
			Name  string `json:"name"`
			Stale bool   `json:"stale"`
		} `json:"hosts"`
	}
	tool(t, h, "status", `{}`, &st)
	// jenkins and jenkins-win never reported.
	if st.State != "stale" || len(st.Hosts) != 3 {
		t.Fatalf("status: %+v", st)
	}
	for _, hs := range st.Hosts {
		if hs.Stale != (hs.Name != "monster-p4") {
			t.Errorf("%s stale=%v", hs.Name, hs.Stale)
		}
	}

	var list struct {
		Count  int `json:"count"`
		Checks []struct {
			ID   string          `json:"id"`
			Data json.RawMessage `json:"data"`
		} `json:"checks"`
	}
	tool(t, h, "list_checks", `{"host":"monster-p4","state":"ok"}`, &list)
	ids := map[string]bool{}
	for _, c := range list.Checks {
		ids[c.ID] = true
		if c.Data != nil {
			t.Errorf("list_checks returned data for %s", c.ID)
		}
	}
	if list.Count != len(list.Checks) || !ids["host.uptime"] || !ids["report.fresh"] {
		t.Fatalf("list_checks: %+v", list)
	}
	tool(t, h, "list_checks", `{"state":"crit"}`, &list)
	if list.Count != 0 {
		t.Errorf("crit checks: %d", list.Count)
	}

	var got struct {
		Check struct {
			Summary string `json:"summary"`
			Data    struct {
				Seconds int `json:"seconds"`
			} `json:"data"`
		} `json:"check"`
		Transitions []struct {
			To string `json:"to"`
		} `json:"transitions"`
	}
	tool(t, h, "get_check", `{"host":"monster-p4","id":"host.uptime"}`, &got)
	if got.Check.Summary != "up 5 s" || got.Check.Data.Seconds != 5 || len(got.Transitions) != 1 || got.Transitions[0].To != "ok" {
		t.Fatalf("get_check: %+v", got)
	}

	var hist struct {
		Transitions []json.RawMessage `json:"transitions"`
	}
	tool(t, h, "history", `{"host":"jenkins"}`, &hist)
	if hist.Transitions == nil || len(hist.Transitions) != 0 {
		t.Errorf("jenkins history: %s", hist.Transitions)
	}

	for _, bad := range []struct{ name, args string }{
		{"get_check", `{"host":"monster-p4"}`},
		{"get_check", `{"host":"nope","id":"host.uptime"}`},
		{"get_check", `{"host":"monster-p4","id":"missing"}`},
		{"list_checks", `{"state":"red"}`},
		{"history", `{"limit":100000}`},
		{"status", `{"extra":1}`},
	} {
		if r := tool(t, h, bad.name, bad.args, nil); r.Error != nil || !r.Result.IsError {
			t.Errorf("%s %s: want a tool error, got %+v", bad.name, bad.args, r)
		}
	}
}

func TestMCPOpenWithGoogle(t *testing.T) {
	e := setupGoogle(t)
	sum := sha256.Sum256([]byte("mcp-secret"))
	w := New(e.srv, nil)
	w.EnableMCP(config.Tokens{"ops-agent": sum[:]})
	w.RequireGoogle(e.g)
	h := w.UI()
	if r := call(t, h, "ping", `{}`); r.Error != nil {
		t.Fatalf("ping behind Google sign-in: %+v", r.Error)
	}
	if rec := mcpPost(h, "", `{}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token behind Google sign-in: %d", rec.Code)
	}
}
