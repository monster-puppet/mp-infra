package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/store"
)

type fakeSender struct {
	mu   sync.Mutex
	msgs []Message
}

func (f *fakeSender) Name() string { return "fake" }
func (f *fakeSender) Send(_ context.Context, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
	return nil
}

var t0 = time.Date(2026, 10, 22, 14, 0, 0, 0, time.Local)

func setup(t *testing.T) (*Alerter, *fakeSender, *store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	f := &fakeSender{}
	now := t0
	a := &Alerter{Store: s, Senders: []Sender{f}, BaseURL: "http://100.64.0.1:8098", Reminder: 12 * time.Hour, DigestAt: "08:00",
		Now: func() time.Time { return now }}
	return a, f, s
}

func TestTransitions(t *testing.T) {
	a, f, s := setup(t)
	ctx := context.Background()
	tr := []store.Transition{
		{ID: 1, Host: "monster-p4", CheckID: "p4.checkpoint", OldState: eval.OK, NewState: eval.Crit, Summary: "aborted"},
		{ID: 2, Host: "jenkins", CheckID: "disk.jenkins.root", OldState: eval.OK, NewState: eval.Warn},
		{ID: 3, Host: "jenkins", CheckID: "host.uptime", OldState: eval.Stale, NewState: eval.OK},
	}
	a.Transitions(ctx, tr)
	if len(f.msgs) != 2 {
		t.Fatalf("sent %d, want 2: %+v", len(f.msgs), f.msgs)
	}
	if f.msgs[0].Subject != "[CRIT] monster-p4 p4.checkpoint" || !strings.Contains(f.msgs[0].Text, "ok → crit") ||
		!strings.Contains(f.msgs[0].Text, "http://100.64.0.1:8098/check/monster-p4/p4.checkpoint") {
		t.Errorf("problem message: %+v", f.msgs[0])
	}
	if !strings.HasPrefix(f.msgs[1].Subject, "[RECOVERED]") {
		t.Errorf("recovery message: %+v", f.msgs[1])
	}
	if last, _ := s.LastAlert(ctx, "monster-p4", "p4.checkpoint"); !last.Equal(t0.Truncate(time.Second)) {
		t.Errorf("not recorded: %s", last)
	}
}

func TestReminders(t *testing.T) {
	a, f, s := setup(t)
	ctx := context.Background()
	s.SaveReport(ctx, "h", t0.Add(-13*time.Hour), []byte(`{}`), []store.Check{{ID: "crit", State: eval.Crit}, {ID: "warn", State: eval.Warn}})
	s.SaveReport(ctx, "h2", t0.Add(-13*time.Hour), []byte(`{}`), []store.Check{{ID: "acked", State: eval.Crit}})
	s.SaveReport(ctx, "h3", t0.Add(-1*time.Hour), []byte(`{}`), []store.Check{{ID: "young", State: eval.Crit}})
	s.Ack(ctx, "h2", "acked", eval.Crit, t0.Add(time.Hour), "m", "", t0)

	a.Reminders(ctx)
	if len(f.msgs) != 1 || !strings.HasPrefix(f.msgs[0].Subject, "[STILL CRIT] h crit") {
		t.Fatalf("%+v", f.msgs)
	}
	a.Reminders(ctx)
	if len(f.msgs) != 1 {
		t.Errorf("reminded twice within 12 h")
	}
	a.Now = func() time.Time { return t0.Add(12*time.Hour + time.Minute) }
	a.Reminders(ctx)
	if len(f.msgs) < 2 {
		t.Errorf("no second reminder after 12 h")
	}
}

func TestDigest(t *testing.T) {
	a, f, s := setup(t)
	ctx := context.Background()
	s.SaveReport(ctx, "h", t0, []byte(`{}`), []store.Check{{ID: "w", State: eval.Warn, Summary: "80% used"}, {ID: "ok", State: eval.OK}})

	a.Now = func() time.Time { return time.Date(2026, 10, 23, 7, 0, 0, 0, time.Local) }
	a.Digest(ctx)
	if len(f.msgs) != 0 {
		t.Fatal("digest before 08:00")
	}
	a.Now = func() time.Time { return time.Date(2026, 10, 23, 8, 1, 0, 0, time.Local) }
	a.Digest(ctx)
	a.Digest(ctx)
	if len(f.msgs) != 1 || !strings.Contains(f.msgs[0].Text, "h · w: 80% used") {
		t.Fatalf("%+v", f.msgs)
	}
}

func TestSlack(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	err := (&Slack{URL: srv.URL}).Send(context.Background(), Message{Subject: "[CRIT] x", Text: "<!channel> & <http://evil|click>"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got["text"], "<!channel>") || !strings.Contains(got["text"], "&lt;!channel&gt; &amp;") {
		t.Errorf("not escaped: %q", got["text"])
	}

	srv.Close()
	err = (&Slack{URL: srv.URL + "/services/SECRET"}).Send(context.Background(), Message{})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error leaks the webhook url: %v", err)
	}
}

func TestSMTPMessage(t *testing.T) {
	s := &SMTP{From: "mpinfra@example.com", To: []string{"a@example.com", "b@example.com"}}
	msg := string(s.message(Message{Subject: "[CRIT] x\r\nBcc: evil@example.com", Text: "line1\nline2"}, t0))
	if strings.Contains(msg, "\r\nBcc:") {
		t.Errorf("header injection: %q", msg)
	}
	if !strings.Contains(msg, "To: a@example.com, b@example.com\r\n") || !strings.HasSuffix(msg, "line1\r\nline2\r\n") {
		t.Errorf("%q", msg)
	}
}

func TestPing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/fail" {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	if err := Ping(context.Background(), srv.URL+"/ok"); err != nil || hits != 1 {
		t.Errorf("%v %d", err, hits)
	}
	if err := Ping(context.Background(), srv.URL+"/fail"); err == nil {
		t.Error("500 accepted")
	}
}
