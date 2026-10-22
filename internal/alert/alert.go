// Package alert sends alerts on state changes to Slack and email, the 12-hour
// reminder for unacknowledged crit, the daily warn digest, and the dead-man ping.
package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/store"
)

// Message is one alert.
type Message struct {
	Subject string
	Text    string
}

// Sender delivers a message on one channel.
type Sender interface {
	Name() string
	Send(ctx context.Context, m Message) error
}

// Senders builds the configured channels. A channel whose secret env var is unset
// is left out.
func Senders(cfg config.Alerts) []Sender {
	var out []Sender
	if u := config.Env(cfg.SlackWebhookEnv); u != "" {
		out = append(out, &Slack{URL: u})
	}
	if cfg.SMTPHost != "" && len(cfg.MailTo) > 0 {
		out = append(out, &SMTP{Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser,
			Password: config.Env(cfg.SMTPPasswordEnv), From: cfg.MailFrom, To: cfg.MailTo})
	}
	return out
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

// Slack posts to an incoming webhook.
type Slack struct{ URL string }

func (s *Slack) Name() string { return "slack" }

// slackEscape escapes the three characters Slack treats as markup, so a summary
// cannot ping <!channel> or forge a link.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func (s *Slack) Send(ctx context.Context, m Message) error {
	body, _ := json.Marshal(map[string]string{"text": "*" + slackEscape(m.Subject) + "*\n" + slackEscape(m.Text)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		// The webhook URL is a secret; never put it in an error.
		if ue, ok := err.(*url.Error); ok {
			return fmt.Errorf("slack: %v", ue.Err)
		}
		return fmt.Errorf("slack: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("slack: %s", resp.Status)
	}
	return nil
}

// SMTP sends plain-text mail. Port 465 uses implicit TLS, anything else STARTTLS
// when the server offers it.
type SMTP struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	To       []string
}

func (s *SMTP) Name() string { return "email" }

// headerSafe strips CR and LF so a summary cannot inject mail headers.
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
}

func (s *SMTP) message(m Message, now time.Time) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(s.From))
	fmt.Fprintf(&b, "To: %s\r\n", headerSafe(strings.Join(s.To, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", headerSafe(m.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(m.Text, "\n", "\r\n"))
	b.WriteString("\r\n")
	return b.Bytes()
}

func (s *SMTP) Send(ctx context.Context, m Message) error {
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	var auth smtp.Auth
	if s.User != "" {
		auth = smtp.PlainAuth("", s.User, s.Password, s.Host)
	}
	msg := s.message(m, time.Now())
	if s.Port != 465 {
		return smtp.SendMail(addr, auth, s.From, s.To, msg)
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 20 * time.Second}, Config: &tls.Config{ServerName: s.Host}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(s.From); err != nil {
		return err
	}
	for _, to := range s.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// Ping hits the dead-man heartbeat URL.
func Ping(ctx context.Context, rawURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("deadman: bad url")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			return fmt.Errorf("deadman: %v", ue.Err)
		}
		return fmt.Errorf("deadman: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("deadman: %s", resp.Status)
	}
	return nil
}

// Alerter decides what to send and records every attempt in alerts_sent.
type Alerter struct {
	Store    *store.Store
	Senders  []Sender
	BaseURL  string
	Reminder time.Duration
	DigestAt string // HH:MM local
	Now      func() time.Time
}

func (a *Alerter) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Alerter) link(host, id string) string {
	if a.BaseURL == "" {
		return ""
	}
	return strings.TrimRight(a.BaseURL, "/") + "/check/" + url.PathEscape(host) + "/" + url.PathEscape(id)
}

func label(s eval.State) string {
	if s == "" {
		return "new"
	}
	return string(s)
}

// Format builds the message for a transition.
func (a *Alerter) Format(t store.Transition, kind eval.AlertKind) Message {
	tag := strings.ToUpper(string(t.NewState))
	if kind == eval.Recovery {
		tag = "RECOVERED"
	}
	if kind == eval.Reminder {
		tag = "STILL " + tag
	}
	subj := fmt.Sprintf("[%s] %s %s", tag, t.Host, t.CheckID)
	text := fmt.Sprintf("%s · %s: %s → %s\n%s", t.Host, t.CheckID, label(t.OldState), label(t.NewState), t.Summary)
	if kind == eval.Reminder {
		text = fmt.Sprintf("%s · %s has been %s since %s\n%s", t.Host, t.CheckID, t.NewState, t.At.Local().Format("2006-01-02 15:04"), t.Summary)
	}
	if l := a.link(t.Host, t.CheckID); l != "" {
		text += "\n" + l
	}
	return Message{Subject: subj, Text: text}
}

// Transitions sends alerts for the transitions that call for one.
func (a *Alerter) Transitions(ctx context.Context, ts []store.Transition) {
	for _, t := range ts {
		kind := eval.Classify(t.OldState, t.NewState)
		if kind == eval.NoAlert {
			continue
		}
		a.send(ctx, t.ID, t.Host, t.CheckID, kind, a.Format(t, kind))
	}
}

func (a *Alerter) send(ctx context.Context, tid int64, host, id string, kind eval.AlertKind, m Message) {
	if len(a.Senders) == 0 {
		log.Printf("alert (no channel configured): %s", m.Subject)
		a.Store.RecordAlert(ctx, store.Alert{TransitionID: tid, Host: host, CheckID: id, Channel: "none", Kind: kind, At: a.now()})
		return
	}
	for _, s := range a.Senders {
		err := s.Send(ctx, m)
		rec := store.Alert{TransitionID: tid, Host: host, CheckID: id, Channel: s.Name(), Kind: kind, At: a.now()}
		if err != nil {
			rec.Error = err.Error()
			log.Printf("alert via %s failed: %v", s.Name(), err)
		}
		a.Store.RecordAlert(ctx, rec)
	}
}

// Reminders re-sends crit and stale checks that are not acknowledged, at most once
// per reminder interval.
func (a *Alerter) Reminders(ctx context.Context) error {
	if a.Reminder <= 0 {
		return nil
	}
	checks, err := a.Store.Checks(ctx)
	if err != nil {
		return err
	}
	now := a.now()
	for _, c := range checks {
		if !c.State.Bad() || c.Acked(now) || now.Sub(c.Since) < a.Reminder {
			continue
		}
		last, err := a.Store.LastAlert(ctx, c.Host, c.ID)
		if err != nil {
			return err
		}
		if !last.IsZero() && now.Sub(last) < a.Reminder {
			continue
		}
		t := store.Transition{Host: c.Host, CheckID: c.ID, NewState: c.State, Summary: c.Summary, At: c.Since}
		a.send(ctx, 0, c.Host, c.ID, eval.Reminder, a.Format(t, eval.Reminder))
	}
	return nil
}

const digestKey = "digest.last"

// Digest sends the daily list of warn items once per day after DigestAt.
func (a *Alerter) Digest(ctx context.Context) error {
	if a.DigestAt == "" {
		return nil
	}
	at, err := time.Parse("15:04", a.DigestAt)
	if err != nil {
		return err
	}
	now := a.now()
	due := time.Date(now.Year(), now.Month(), now.Day(), at.Hour(), at.Minute(), 0, 0, now.Location())
	today := now.Format("2006-01-02")
	if now.Before(due) {
		return nil
	}
	if last, err := a.Store.Get(ctx, digestKey); err != nil || last == today {
		return err
	}
	if err := a.Store.Set(ctx, digestKey, today); err != nil {
		return err
	}
	checks, err := a.Store.Checks(ctx)
	if err != nil {
		return err
	}
	var lines []string
	for _, c := range checks {
		if c.State != eval.Warn {
			continue
		}
		line := fmt.Sprintf("• %s · %s: %s", c.Host, c.ID, c.Summary)
		if c.Acked(now) {
			line += fmt.Sprintf(" (acknowledged until %s by %s)", c.AckUntil.Local().Format("2006-01-02"), c.AckBy)
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	text := strings.Join(lines, "\n")
	if a.BaseURL != "" {
		text += "\n" + strings.TrimRight(a.BaseURL, "/") + "/"
	}
	a.send(ctx, 0, config.ServeHost, "digest", eval.Reminder,
		Message{Subject: fmt.Sprintf("[DIGEST] %d warning(s) %s", len(lines), today), Text: text})
	return nil
}
