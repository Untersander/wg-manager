package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
)

type Auth struct {
	Password          string
	SessionCookieName string

	mu       sync.RWMutex
	sessions map[string]struct{}
}

func NewAuth(password, sessionCookieName string) *Auth {
	return &Auth{
		Password:          password,
		SessionCookieName: sessionCookieName,
		sessions:          map[string]struct{}{},
	}
}

func (a *Auth) LoginGet(w http.ResponseWriter, r *http.Request) {
	if isAuthed := a.isAuthenticated(r); isAuthed {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = loginTemplate.Execute(w, map[string]any{"Error": ""})
}

func (a *Auth) LoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if r.FormValue("password") != a.Password {
		_ = loginTemplate.Execute(w, map[string]any{"Error": "invalid password"})
		return
	}

	token := randomToken(32)
	a.mu.Lock()
	a.sessions[token] = struct{}{}
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     a.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(a.SessionCookieName)
	if err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     a.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(a.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	a.mu.RLock()
	_, ok := a.sessions[cookie.Value]
	a.mu.RUnlock()
	return ok
}

func randomToken(size int) string {
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
