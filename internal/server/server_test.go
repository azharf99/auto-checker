package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"auto-checker/internal/algonova"
	"auto-checker/internal/config"
	"auto-checker/internal/store"
)

func TestServerAuthAndRateLimiter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "server_test.db")
	st, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer st.Close()

	cfg := &config.Config{
		BaseURL:       "https://lms.algonova.id",
		CookieFile:    filepath.Join(t.TempDir(), "cookies.json"),
		DBPath:        dbPath,
		DashboardUser: "azharfa",
		DashboardPass: "MySecurePass!",
		SessionTTL:    24 * time.Hour,
		DiscoveryMode: "unreviewed",
		Timeframe:     "current",
		DryRun:        true,
	}

	client, err := algonova.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	client.AttachCookieStore(st)

	srv := NewServer(cfg, client, st)
	handler := srv.Handler()

	// 1. Unauthenticated GET / should redirect to /login
	reqRoot := httptest.NewRequest(http.MethodGet, "/", nil)
	recRoot := httptest.NewRecorder()
	handler.ServeHTTP(recRoot, reqRoot)
	if recRoot.Code != http.StatusFound || recRoot.Header().Get("Location") != "/login" {
		t.Fatalf("expected 302 redirect to /login for unauthenticated /, got status=%d loc=%q",
			recRoot.Code, recRoot.Header().Get("Location"))
	}

	// 2. Unauthenticated GET /api/status should return 401
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	recStatus := httptest.NewRecorder()
	handler.ServeHTTP(recStatus, reqStatus)
	if recStatus.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /api/status, got %d", recStatus.Code)
	}

	// 3. Valid Login on IP 10.0.0.1
	loginBody, _ := json.Marshal(map[string]string{
		"username": "azharfa",
		"password": "MySecurePass!",
	})
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
	reqLogin.RemoteAddr = "10.0.0.1:12345"
	recLogin := httptest.NewRecorder()
	handler.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid login, got %d: %s", recLogin.Code, recLogin.Body.String())
	}
	cookies := recLogin.Result().Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			authCookie = c
			break
		}
	}
	if authCookie == nil || !authCookie.HttpOnly {
		t.Fatalf("expected HttpOnly %s cookie on login", sessionCookieName)
	}

	// 4. Authenticated GET /api/status should return 200
	reqAuthed := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	reqAuthed.AddCookie(authCookie)
	recAuthed := httptest.NewRecorder()
	handler.ServeHTTP(recAuthed, reqAuthed)
	if recAuthed.Code != http.StatusOK {
		t.Fatalf("expected 200 on authenticated /api/status, got %d", recAuthed.Code)
	}

	// 5. Brute-force protection on IP 10.0.0.99 (5 wrong attempts -> 6th returns 429)
	badBody, _ := json.Marshal(map[string]string{
		"username": "azharfa",
		"password": "wrongpassword",
	})
	for i := 1; i <= 5; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(badBody))
		r.RemoteAddr = "10.0.0.99:5555"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, w.Code)
		}
	}
	rBlocked := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(badBody))
	rBlocked.RemoteAddr = "10.0.0.99:5555"
	wBlocked := httptest.NewRecorder()
	handler.ServeHTTP(wBlocked, rBlocked)
	if wBlocked.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt: expected 429 Too Many Requests, got %d", wBlocked.Code)
	}
}
