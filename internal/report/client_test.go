package report

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendReply(t *testing.T) {
	var status int
	var ctype, body string
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if ctype != "" {
			rw.Header().Set("Content-Type", ctype)
		}
		rw.WriteHeader(status)
		rw.Write([]byte(body))
	}))
	defer ts.Close()
	p := &Payload{Host: "jenkins", AgentVersion: "1", CollectedAt: time.Now()}
	cases := []struct {
		status      int
		ctype, body string
		unban       int // -1: no reply
		err         bool
	}{
		{204, "", "", -1, false},
		{200, "application/json", `{"unban":["192.0.2.7","192.0.2.8"]}`, 2, false},
		{200, "application/json; charset=utf-8", `{"unban":["192.0.2.7"]}`, 1, false},
		{200, "text/plain", `{"unban":["192.0.2.7"]}`, -1, false}, // not JSON: no reply
		{202, "application/json", `{"unban":["192.0.2.7"]}`, -1, false},
		{200, "application/json", `{"unban":`, -1, true},
		{403, "text/plain", "token does not belong to this host", -1, true},
	}
	for _, c := range cases {
		status, ctype, body = c.status, c.ctype, c.body
		r, err := Send(context.Background(), nil, ts.URL, "tok", p)
		if (err != nil) != c.err {
			t.Errorf("%d %s: err %v", c.status, c.ctype, err)
		}
		if (c.unban < 0) != (r == nil) || (r != nil && len(r.Unban) != c.unban) {
			t.Errorf("%d %s: reply %+v", c.status, c.ctype, r)
		}
	}
}
