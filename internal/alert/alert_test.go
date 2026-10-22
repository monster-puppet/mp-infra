package alert

import (
	"context"
	"encoding/json"
	"io"
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
	if len(f.msgs) != 1 {
		t.Fatalf("sent %d, want 1: %+v", len(f.msgs), f.msgs)
	}
	m := f.msgs[0]
	if m.Subject != "[CRIT] 2 hosts: 1 crit, 1 recovered" || !strings.Contains(m.Text, "ok → crit") ||
		!strings.Contains(m.Text, "http://100.64.0.1:8098/check/monster-p4/p4.checkpoint") {
		t.Errorf("message: %+v", m)
	}
	// monster-p4 (crit) comes before jenkins (recovered).
	if p4, j := strings.Index(m.Text, "monster-p4"), strings.Index(m.Text, "jenkins"); p4 > j {
		t.Errorf("worst host not first:\n%s", m.Text)
	}
	for _, id := range []string{"p4.checkpoint", "host.uptime"} {
		if last, _ := s.LastAlert(ctx, map[string]string{"p4.checkpoint": "monster-p4", "host.uptime": "jenkins"}[id], id); !last.Equal(t0.Truncate(time.Second)) {
			t.Errorf("%s not recorded: %s", id, last)
		}
	}

	f.msgs = nil
	a.Transitions(ctx, tr[:1])
	if len(f.msgs) != 1 || f.msgs[0].Subject != "[CRIT] monster-p4 p4.checkpoint" {
		t.Errorf("single: %+v", f.msgs)
	}
}

// A host that stops reporting is one line, not one per check.
func TestHostDownFolds(t *testing.T) {
	a, f, _ := setup(t)
	tr := []store.Transition{{ID: 1, Host: "jenkins", CheckID: "report.fresh", OldState: eval.OK, NewState: eval.Stale, Summary: "no report for 20m"}}
	for i, id := range []string{"disk.root", "host.uptime", "jenkins.queue"} {
		tr = append(tr, store.Transition{ID: int64(i + 2), Host: "jenkins", CheckID: id, OldState: eval.OK, NewState: eval.Stale, Summary: "no report from jenkins"})
	}
	a.Transitions(context.Background(), tr)
	if len(f.msgs) != 1 {
		t.Fatalf("sent %d", len(f.msgs))
	}
	m := f.msgs[0]
	if m.Subject != "[STALE] jenkins stopped reporting (3 checks stale)" {
		t.Errorf("subject %q", m.Subject)
	}
	b, _ := json.Marshal(m.Blocks)
	if strings.Contains(string(b), "disk.root") {
		t.Errorf("stale checks not folded: %s", b)
	}

	// Back again: folded the same way, but a check that came back crit is listed.
	f.msgs = nil
	tr = []store.Transition{
		{Host: "jenkins", CheckID: "report.fresh", OldState: eval.Stale, NewState: eval.OK},
		{Host: "jenkins", CheckID: "disk.root", OldState: eval.Stale, NewState: eval.OK},
		{Host: "jenkins", CheckID: "host.uptime", OldState: eval.Stale, NewState: eval.Crit, Summary: "rebooted"},
	}
	a.Transitions(context.Background(), tr)
	b, _ = json.Marshal(f.msgs[0].Blocks)
	if f.msgs[0].Subject != "[CRIT] jenkins: 1 crit, 1 reporting again" || !strings.Contains(string(b), "host.uptime") ||
		strings.Contains(string(b), "disk.root") || !strings.Contains(string(b), "1 check back to ok") {
		t.Errorf("%s\n%s", f.msgs[0].Subject, b)
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
	var raw []byte
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
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
	}))
	a := &Alerter{BaseURL: "http://100.64.0.1:8098", Now: func() time.Time { return t0 }}
	m := a.compose([]Item{{Host: "h", CheckID: "x", Kind: eval.Problem, Old: eval.OK, New: eval.Crit, Summary: "<!channel> & <http://evil|click>"}}, "")
	if err := (&Slack{URL: srv.URL}).Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "<!channel>") || !strings.Contains(string(raw), `"blocks"`) ||
		!strings.Contains(string(raw), `\u0026lt;!channel\u0026gt;`) {
		t.Errorf("blocks not escaped: %s", raw)
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
