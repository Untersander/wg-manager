package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestAuth() *Auth {
	return NewAuth("secret", "test-session")
}

func TestLoginGet_Unauthenticated(t *testing.T) {
	a := newTestAuth()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	a.LoginGet(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestLoginPost_WrongPassword(t *testing.T) {
	a := newTestAuth()

	form := url.Values{}
	form.Set("password", "wrongpassword")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.LoginPost(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (re-rendered login page)", w.Code)
	}
	// No session cookie should be set
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "test-session" {
			t.Errorf("unexpected session cookie set on failed login")
		}
	}
}

func TestLoginPost_CorrectPassword(t *testing.T) {
	a := newTestAuth()

	form := url.Values{}
	form.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.LoginPost(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "test-session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie to be set after successful login")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie should be HttpOnly")
	}
}

func TestLogout(t *testing.T) {
	a := newTestAuth()

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	w := httptest.NewRecorder()
	a.Logout(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

func TestRequire_RedirectsUnauthenticated(t *testing.T) {
	a := newTestAuth()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := a.Require(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

func TestRequire_AllowsAuthenticated(t *testing.T) {
	a := newTestAuth()

	// First, log in to get a valid session token
	form := url.Values{}
	form.Set("password", "secret")
	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginW := httptest.NewRecorder()
	a.LoginPost(loginW, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginW.Result().Cookies() {
		if c.Name == "test-session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie from login")
	}

	// Now make an authenticated request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := a.Require(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRequire_BlocksInvalidCSRF(t *testing.T) {
	a := newTestAuth()

	// Log in first
	form := url.Values{}
	form.Set("password", "secret")
	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginW := httptest.NewRecorder()
	a.LoginPost(loginW, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginW.Result().Cookies() {
		if c.Name == "test-session" {
			sessionCookie = c
		}
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := a.Require(next)

	postForm := url.Values{}
	postForm.Set("csrf_token", "invalid-csrf-token")
	req := httptest.NewRequest(http.MethodPost, "/peers", strings.NewReader(postForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for invalid CSRF", w.Code)
	}
}

func TestRateLimit(t *testing.T) {
	a := newTestAuth()

	// Burn through the 5-attempt allowance
	for i := 0; i < 5; i++ {
		form := url.Values{}
		form.Set("password", "wrong")
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		a.LoginPost(w, req)
	}

	// Next attempt should be rate-limited
	form := url.Values{}
	form.Set("password", "wrong")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	a.LoginPost(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 after rate limit exceeded", w.Code)
	}
}
