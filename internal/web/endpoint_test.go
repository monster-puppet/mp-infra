package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/probe"
	"github.com/monster-puppet/mp-infra/internal/store"
)

func TestReportEndpointAuth(t *testing.T) {
	e := setup(t)
	e.srv.MinReportInterval = 0
	e.srv.Cfg.Hosts = append(e.srv.Cfg.Hosts, config.Host{Name: "tacco-pc", Endpoint: true})
	devs := []probe.TSDevice{
		{Name: "TACCO-PC", Addr: "100.64.0.10", Host: "tacco-pc"},
		{Name: "other-pc", Addr: "100.64.0.11"},
		{Name: "jenkins", Addr: "100.64.0.12", Host: "jenkins"},
	}
	d, _ := json.Marshal(map[string]any{"devices": devs})
	if _, err := e.srv.Store.PutCheck(context.Background(), store.Check{Host: config.ServeHost, ID: "ts.devices",
		State: eval.OK, Data: string(d)}, now); err != nil {
		t.Fatal(err)
	}
	post := func(from, b string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/report", strings.NewReader(b))
		req.RemoteAddr = from
		rec := httptest.NewRecorder()
		e.reports.ServeHTTP(rec, req)
		return rec.Code
	}
	check := func(host, id string) string {
		return fmt.Sprintf(`{"host":%q,"agent_version":"launcher-1","collected_at":%q,"checks":[{"id":%q,"state":"ok","data":{"protection":1}}]}`,
			host, now.Format(time.RFC3339), id)
	}
	for i, tc := range []struct {
		from, body string
		want       int
	}{
		{"100.64.0.10:5555", check("tacco-pc", "endpoint.bitlocker.tacco-pc"), http.StatusNoContent},
		// Another tailnet device claiming to be tacco-pc.
		{"100.64.0.11:5555", check("tacco-pc", "endpoint.bitlocker.tacco-pc"), http.StatusUnauthorized},
		// A token host without its token.
		{"100.64.0.12:5555", check("jenkins", "endpoint.bitlocker.jenkins"), http.StatusUnauthorized},
		// From outside the tailnet.
		{"203.0.113.5:5555", check("tacco-pc", "endpoint.bitlocker.tacco-pc"), http.StatusUnauthorized},
		// The right device sending for another host, or a check it may not send.
		{"100.64.0.10:5555", check("jenkins", "endpoint.bitlocker.jenkins"), http.StatusForbidden},
		{"100.64.0.10:5555", check("tacco-pc", "auth.logins.tacco-pc"), http.StatusForbidden},
	} {

		if got := post(tc.from, tc.body); got != tc.want {
			t.Errorf("%d: got %d, want %d", i, got, tc.want)
		}
	}
	c, _ := e.srv.Store.Check(context.Background(), "tacco-pc", "endpoint.bitlocker.tacco-pc")
	if c == nil || c.State != eval.OK {
		t.Fatalf("endpoint check not stored: %+v", c)
	}
}
