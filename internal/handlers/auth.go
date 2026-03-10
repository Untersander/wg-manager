package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"wg-manager/internal/views"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type Auth struct {
	Password          string
	SessionCookieName string
	signingKey        []byte
	tokenTTL          time.Duration
	limiters          map[string]*ipLimiter
	limitersMu        sync.Mutex
}

func NewAuth(password, sessionCookieName string) *Auth {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("failed to generate signing key: " + err.Error())
	}
	return &Auth{
		Password:          password,
		SessionCookieName: sessionCookieName,
		signingKey:        key,
		tokenTTL:          2 * time.Hour,
		limiters:          make(map[string]*ipLimiter),
	}
}

func (a *Auth) LoginGet(w http.ResponseWriter, r *http.Request) {
	if a.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := views.LoginPage("").Render(r.Context(), w); err != nil {
		slog.Error("failed rendering login page", "error", err)
	}
}

func (a *Auth) LoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	ip := clientIP(r)
	if !a.allowLogin(ip) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}

	if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(a.Password)) != 1 {
		if err := views.LoginPage("invalid password").Render(r.Context(), w); err != nil {
			slog.Error("failed rendering login page", "error", err)
		}
		return
	}

	token, err := a.createToken()
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     a.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		cookie, _ := r.Cookie(a.SessionCookieName)
		csrf := a.csrfToken(cookie.Value)
		ctx := context.WithValue(r.Context(), views.CSRFKey, csrf)

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf_token")), []byte(csrf)) != 1 {
				http.Error(w, "invalid request", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Auth) createToken() (string, error) {
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(a.tokenTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "wg-manager",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.signingKey)
}

func (a *Auth) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(a.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		return a.signingKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return false
	}

	return token.Valid
}

func (a *Auth) csrfToken(sessionToken string) string {
	mac := hmac.New(sha256.New, a.signingKey)
	mac.Write([]byte(sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *Auth) allowLogin(ip string) bool {
	a.limitersMu.Lock()
	defer a.limitersMu.Unlock()

	now := time.Now()
	for k, v := range a.limiters {
		if now.Sub(v.lastSeen) > 10*time.Minute {
			delete(a.limiters, k)
		}
	}

	lim, ok := a.limiters[ip]
	if !ok {
		lim = &ipLimiter{
			limiter: rate.NewLimiter(rate.Every(12*time.Second), 5),
		}
		a.limiters[ip] = lim
	}
	lim.lastSeen = now
	return lim.limiter.Allow()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
