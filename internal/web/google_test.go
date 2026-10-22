package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeGoogle struct {
	claims      map[string]any
	gotVerifier string
}

func (f *fakeGoogle) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if r.FormValue("code") != "good-code" || r.FormValue("client_secret") != "secret" {
		http.Error(rw, "bad", http.StatusBadRequest)
		return
	}
	f.gotVerifier = r.FormValue("code_verifier")
	b, _ := json.Marshal(f.claims)
	enc := base64.RawURLEncoding
	json.NewEncoder(rw).Encode(map[string]string{"id_token": enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(b) + ".sig"})
}

type gEnv struct {
	*env
	g      *GoogleAuth
	google *fakeGoogle
}

func setupGoogle(t *testing.T) *gEnv {
	t.Helper()
	e := setup(t)
	fg := &fakeGoogle{}
	ts := httptest.NewServer(fg)
	t.Cleanup(ts.Close)
	g := &GoogleAuth{
		ClientID: "cid", ClientSecret: "secret", RedirectURL: "https://ui.example.ts.net/auth/callback",
		AuthURL: "https://accounts.example/auth", TokenURL: ts.URL, Domain: "example.com",
		Emails: map[string]bool{"guest@other.example": true}, TTL: time.Hour, Secure: true,
		Client: ts.Client(), Now: func() time.Time { return *e.clock },
	}
	g.SetKey([]byte(strings.Repeat("k", 32)))
	w := New(e.srv, nil)
	w.RequireGoogle(g)
	e.ui = w.UI()
	return &gEnv{env: e, g: g, google: fg}
}

func (e *gEnv) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.ui.ServeHTTP(rec, req)
	return rec
}

func cookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// signIn runs the whole flow for the given ID token claims and returns the
// callback response.
func (e *gEnv) signIn(t *testing.T, claims map[string]any, next string) *httptest.ResponseRecorder {
	t.Helper()
	rec := e.get("/auth/login?next=" + url.QueryEscape(next))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	q := loc.Query()
	if q.Get("hd") != "example.com" || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != e.g.RedirectURL {
		t.Fatalf("auth request: %s", loc)
	}
	if _, ok := claims["nonce"]; !ok {
		claims["nonce"] = q.Get("nonce")
	}
	e.google.claims = claims
	return e.get("/auth/callback?code=good-code&state="+url.QueryEscape(q.Get("state")), cookie(rec, flowCookie))
}

func claims(email, hd string) map[string]any {
	return map[string]any{"iss": "https://accounts.google.com", "aud": "cid", "exp": now.Add(time.Hour).Unix(),
		"email": email, "email_verified": true, "hd": hd}
}

func TestGoogleRedirectsWhenSignedOut(t *testing.T) {
	e := setupGoogle(t)
	rec := e.get("/history?host=jenkins")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/auth/login?next=%2Fhistory%3Fhost%3Djenkins" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, p := range []string{"/healthz", "/api/status.json", "/static/style.css"} {
		if rec := e.get(p); rec.Code != http.StatusOK {
			t.Errorf("%s: %d, want open", p, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/check/jenkins/host.uptime/unack", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec = httptest.NewRecorder()
	e.ui.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("post while signed out: %d", rec.Code)
	}
}

func TestGoogleSignIn(t *testing.T) {
	e := setupGoogle(t)
	rec := e.signIn(t, claims("Ana@Example.com", "example.com"), "/history")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/history" {
		t.Fatalf("callback: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if e.google.gotVerifier == "" {
		t.Error("no PKCE verifier sent")
	}
	s := cookie(rec, sessionCookie)
	if s == nil || !s.HttpOnly || !s.Secure || s.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie: %+v", s)
	}
	page := e.get("/", s)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "ana@example.com") || !strings.Contains(page.Body.String(), "Sign out") {
		t.Fatalf("home: %d", page.Code)
	}
	*e.clock = now.Add(2 * time.Hour)
	if rec := e.get("/", s); rec.Code != http.StatusSeeOther {
		t.Errorf("expired session: %d", rec.Code)
	}
}

func TestGoogleAllowList(t *testing.T) {
	e := setupGoogle(t)
	// guest is on allowed_emails, from any domain
	if rec := e.signIn(t, claims("guest@other.example", ""), "/"); rec.Code != http.StatusSeeOther {
		t.Errorf("allowed email: %d", rec.Code)
	}
	unverified := claims("ana@example.com", "example.com")
	unverified["email_verified"] = false
	for name, c := range map[string]map[string]any{
		"other domain":         claims("eve@gmail.com", ""),
		"address without hd":   claims("eve@example.com", ""),
		"workspace of another": claims("eve@example.com.evil", "example.com.evil"),
		"unverified":           unverified,
	} {
		rec := e.signIn(t, c, "/")
		if rec.Code != http.StatusForbidden || cookie(rec, sessionCookie) != nil {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}

func TestGoogleRejectsBadTokens(t *testing.T) {
	e := setupGoogle(t)
	for name, mod := range map[string]func(map[string]any){
		"wrong audience": func(c map[string]any) { c["aud"] = "other" },
		"wrong issuer":   func(c map[string]any) { c["iss"] = "https://evil.example" },
		"expired":        func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() },
		"wrong nonce":    func(c map[string]any) { c["nonce"] = "replayed" },
	} {
		c := claims("ana@example.com", "example.com")
		mod(c)
		if rec := e.signIn(t, c, "/"); rec.Code != http.StatusBadGateway || cookie(rec, sessionCookie) != nil {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}

func TestGoogleCallbackNeedsMatchingState(t *testing.T) {
	e := setupGoogle(t)
	rec := e.get("/auth/login")
	flow := cookie(rec, flowCookie)
	if rec := e.get("/auth/callback?code=good-code&state=forged", flow); rec.Code != http.StatusBadRequest {
		t.Errorf("forged state: %d", rec.Code)
	}
	if rec := e.get("/auth/callback?code=good-code&state=x"); rec.Code != http.StatusBadRequest {
		t.Errorf("no flow cookie: %d", rec.Code)
	}
}

func TestGoogleTamperedSession(t *testing.T) {
	e := setupGoogle(t)
	forged := &http.Cookie{Name: sessionCookie, Value: e.g.sign("ana@example.com|9999999999")}
	if rec := e.get("/", forged); rec.Code != 200 {
		t.Fatalf("validly signed: %d", rec.Code)
	}
	other := &GoogleAuth{}
	other.SetKey([]byte(strings.Repeat("x", 32)))
	forged.Value = other.sign("ana@example.com|9999999999")
	if rec := e.get("/", forged); rec.Code != http.StatusSeeOther {
		t.Errorf("signed with another key: %d", rec.Code)
	}
	// a session for someone since removed from the allow list no longer works
	forged.Value = e.g.sign("eve@gmail.com|9999999999")
	if rec := e.get("/", forged); rec.Code != http.StatusSeeOther {
		t.Errorf("not allowed: %d", rec.Code)
	}
}

func TestLocalPath(t *testing.T) {
	for in, want := range map[string]string{
		"/check/a/b?x=1":   "/check/a/b?x=1",
		"//evil.example/":  "/",
		"/\\evil.example":  "/",
		"https://evil.ex/": "/",
		"":                 "/",
	} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
}
