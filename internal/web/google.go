package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
)

// Google endpoints. Tests point them at a fake.
const (
	GoogleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	GoogleTokenURL = "https://oauth2.googleapis.com/token"
)

const (
	sessionCookie = "mpinfra_session"
	flowCookie    = "mpinfra_oauth"
	flowTTL       = 10 * time.Minute
)

// GoogleAuth signs viewers in with Google (OpenID Connect authorization code flow
// with PKCE) and keeps them signed in with an HMAC-signed cookie. There is no
// server-side session table: the allow list is re-checked on every request, so
// removing someone from the config locks them out at the next restart.
type GoogleAuth struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	Domain       string
	Emails       map[string]bool
	TTL          time.Duration
	Secure       bool // set the Secure flag on cookies (https base_url)
	Client       *http.Client
	Now          func() time.Time
	key          []byte
}

// NewGoogleAuth builds the sign-in from the server config and its env vars.
func NewGoogleAuth(cfg *config.Server) (*GoogleAuth, error) {
	g := cfg.GoogleLogin
	secret := config.Env(g.ClientSecretEnv)
	if secret == "" {
		return nil, fmt.Errorf("google_login: %s is not set", g.ClientSecretEnv)
	}
	key := config.Env(g.SessionKeyEnv)
	if len(key) < 32 {
		return nil, fmt.Errorf("google_login: %s must hold at least 32 characters", g.SessionKeyEnv)
	}
	base := strings.TrimSuffix(cfg.BaseURL, "/")
	a := &GoogleAuth{
		ClientID:     g.ClientID,
		ClientSecret: secret,
		RedirectURL:  base + "/auth/callback",
		AuthURL:      GoogleAuthURL,
		TokenURL:     GoogleTokenURL,
		Domain:       strings.ToLower(g.AllowedDomain),
		Emails:       map[string]bool{},
		TTL:          g.SessionTTL,
		Secure:       strings.HasPrefix(base, "https://"),
		Client:       &http.Client{Timeout: 15 * time.Second},
		Now:          time.Now,
		key:          []byte(key),
	}
	for _, e := range g.AllowedEmails {
		a.Emails[strings.ToLower(strings.TrimSpace(e))] = true
	}
	return a, nil
}

// SetKey sets the cookie signing key (tests).
func (a *GoogleAuth) SetKey(k []byte) { a.key = k }

// allowed reports whether a verified Google account may see the UI.
func (a *GoogleAuth) allowed(email, hd string) bool {
	email = strings.ToLower(email)
	if a.Emails[email] {
		return true
	}
	// hd is set by Google only for Workspace accounts; the email suffix alone could
	// be a consumer account registered with a work address.
	return a.Domain != "" && strings.EqualFold(hd, a.Domain) && strings.HasSuffix(email, "@"+a.Domain)
}

// open paths need no sign-in: health checks, the status line other tools read,
// static files for the sign-in page, and the sign-in flow itself.
func open(path string) bool {
	return path == "/healthz" || path == "/api/status.json" ||
		strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/auth/")
}

// require lets signed-in viewers through and sends everyone else to Google.
func (a *GoogleAuth) require(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if open(r.URL.Path) || signedIn(r) != "" {
			h.ServeHTTP(rw, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(rw, "sign in first", http.StatusUnauthorized)
			return
		}
		http.Redirect(rw, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	})
}

type signedInKey struct{}

func signedIn(r *http.Request) string {
	v, _ := r.Context().Value(signedInKey{}).(string)
	return v
}

// session returns the signed-in email from the request's cookie, or "".
func (a *GoogleAuth) session(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	v, ok := a.verify(c.Value)
	if !ok {
		return ""
	}
	email, exp, ok := strings.Cut(v, "|")
	sec, err := strconv.ParseInt(exp, 10, 64)
	if !ok || err != nil || a.Now().Unix() >= sec {
		return ""
	}
	// The cookie only holds accounts that passed the hd check at sign-in.
	if !a.allowed(email, a.Domain) {
		return ""
	}
	return email
}

// sign returns base64(v) + "." + base64(HMAC-SHA256(v)).
func (a *GoogleAuth) sign(v string) string {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(v))
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(v)) + "." + enc.EncodeToString(m.Sum(nil))
}

func (a *GoogleAuth) verify(s string) (string, bool) {
	p, sig, ok := strings.Cut(s, ".")
	if !ok {
		return "", false
	}
	enc := base64.RawURLEncoding
	v, err1 := enc.DecodeString(p)
	got, err2 := enc.DecodeString(sig)
	if err1 != nil || err2 != nil {
		return "", false
	}
	m := hmac.New(sha256.New, a.key)
	m.Write(v)
	if !hmac.Equal(got, m.Sum(nil)) {
		return "", false
	}
	return string(v), true
}

func (a *GoogleAuth) setCookie(rw http.ResponseWriter, name, value, path string, ttl time.Duration) {
	http.SetCookie(rw, &http.Cookie{
		Name: name, Value: value, Path: path, MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteLaxMode,
	})
}

func (a *GoogleAuth) clearCookie(rw http.ResponseWriter, name, path string) {
	http.SetCookie(rw, &http.Cookie{Name: name, Path: path, MaxAge: -1, HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteLaxMode})
}

func randomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// localPath keeps the post-sign-in redirect on this site.
func localPath(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

// flow is what the browser carries from /auth/login to /auth/callback.
type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Exp      int64  `json:"e"`
}

func (a *GoogleAuth) login(rw http.ResponseWriter, r *http.Request) {
	f := flow{State: randomString(), Nonce: randomString(), Verifier: randomString(),
		Next: localPath(r.URL.Query().Get("next")), Exp: a.Now().Add(flowTTL).Unix()}
	b, _ := json.Marshal(f)
	a.setCookie(rw, flowCookie, a.sign(string(b)), "/auth/", flowTTL)
	challenge := sha256.Sum256([]byte(f.Verifier))
	q := url.Values{
		"client_id":             {a.ClientID},
		"redirect_uri":          {a.RedirectURL},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"state":                 {f.State},
		"nonce":                 {f.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}
	if a.Domain != "" {
		q.Set("hd", a.Domain)
	}
	http.Redirect(rw, r, a.AuthURL+"?"+q.Encode(), http.StatusSeeOther)
}

var errDenied = errors.New("denied")

func (w *Web) callback(rw http.ResponseWriter, r *http.Request) {
	a := w.google
	c, err := r.Cookie(flowCookie)
	a.clearCookie(rw, flowCookie, "/auth/")
	if err != nil {
		w.signinPage(rw, r, http.StatusBadRequest, "The sign-in took too long or cookies are blocked. Try again.")
		return
	}
	var f flow
	v, ok := a.verify(c.Value)
	if !ok || json.Unmarshal([]byte(v), &f) != nil || a.Now().Unix() >= f.Exp {
		w.signinPage(rw, r, http.StatusBadRequest, "The sign-in took too long. Try again.")
		return
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
		w.signinPage(rw, r, http.StatusBadRequest, "The sign-in did not match this browser. Try again.")
		return
	}
	if e := q.Get("error"); e != "" {
		w.signinPage(rw, r, http.StatusForbidden, "Google did not sign you in ("+e+").")
		return
	}
	email, err := a.exchange(r.Context(), q.Get("code"), f)
	if errors.Is(err, errDenied) {
		log.Printf("google sign-in refused for %q", email)
		w.signinPage(rw, r, http.StatusForbidden, email+" may not open this page. Sign in with a Monster Puppet account.")
		return
	}
	if err != nil {
		log.Printf("google sign-in: %v", err)
		w.signinPage(rw, r, http.StatusBadGateway, "Google sign-in failed. Try again.")
		return
	}
	exp := a.Now().Add(a.TTL).Unix()
	a.setCookie(rw, sessionCookie, a.sign(email+"|"+strconv.FormatInt(exp, 10)), "/", a.TTL)
	log.Printf("google sign-in: %s", email)
	http.Redirect(rw, r, localPath(f.Next), http.StatusSeeOther)
}

// exchange trades the code for an ID token and checks its claims. The token comes
// straight from Google's token endpoint over TLS, so per OpenID Connect Core
// 3.1.3.7 its signature need not be checked; issuer, audience, expiry and nonce are.
func (a *GoogleAuth) exchange(ctx context.Context, code string, f flow) (string, error) {
	if code == "" {
		return "", errors.New("no code in callback")
	}
	form := url.Values{
		"code":          {code},
		"client_id":     {a.ClientID},
		"client_secret": {a.ClientSecret},
		"redirect_uri":  {a.RedirectURL},
		"grant_type":    {"authorization_code"},
		"code_verifier": {f.Verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint: %s", resp.Status)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return "", errors.New("token endpoint: no id_token")
	}
	parts := strings.Split(tok.IDToken, ".")
	if len(parts) != 3 {
		return "", errors.New("id_token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("id_token payload is not base64url")
	}
	var c struct {
		Iss      string `json:"iss"`
		Aud      string `json:"aud"`
		Exp      int64  `json:"exp"`
		Nonce    string `json:"nonce"`
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
		HD       string `json:"hd"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", errors.New("id_token payload is not JSON")
	}
	switch {
	case c.Iss != "https://accounts.google.com" && c.Iss != "accounts.google.com":
		return "", fmt.Errorf("id_token issuer %q", c.Iss)
	case c.Aud != a.ClientID:
		return "", errors.New("id_token is for another client")
	case a.Now().Unix() >= c.Exp:
		return "", errors.New("id_token expired")
	case subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(f.Nonce)) != 1:
		return "", errors.New("id_token nonce mismatch")
	case c.Email == "" || !c.Verified:
		return c.Email, errDenied
	case !a.allowed(c.Email, c.HD):
		return c.Email, errDenied
	}
	return strings.ToLower(c.Email), nil
}

func (w *Web) logout(rw http.ResponseWriter, r *http.Request) {
	w.google.clearCookie(rw, sessionCookie, "/")
	w.signinPage(rw, r, http.StatusOK, "Signed out.")
}

func (w *Web) signinPage(rw http.ResponseWriter, r *http.Request, code int, msg string) {
	w.render(rw, r, "signin", code, page{Title: "Sign in", Data: msg})
}
