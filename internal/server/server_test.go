package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auto-checker/internal/algonova"
	"auto-checker/internal/config"
	"auto-checker/internal/store"
)

func TestMultiUserServerAuthAndRBAC(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "server_multiuser_test.db")
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
		DashboardPass: "AdminSecret123!",
		SessionTTL:    24 * time.Hour,
		DiscoveryMode: "unreviewed",
		Timeframe:     "current",
		DryRun:        true,
	}

	client, err := algonova.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	srv := NewServer(cfg, client, st)
	defer srv.Close()
	handler := srv.Handler()

	// 1. Unauthenticated GET / harus redirect 302 ke /login
	reqRoot := httptest.NewRequest(http.MethodGet, "/", nil)
	recRoot := httptest.NewRecorder()
	handler.ServeHTTP(recRoot, reqRoot)
	if recRoot.Code != http.StatusFound || recRoot.Header().Get("Location") != "/login" {
		t.Fatalf("expected 302 redirect to /login for unauthenticated /, got status=%d loc=%q",
			recRoot.Code, recRoot.Header().Get("Location"))
	}

	// 2. Unauthenticated GET /api/status harus return 401
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	recStatus := httptest.NewRecorder()
	handler.ServeHTTP(recStatus, reqStatus)
	if recStatus.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /api/status, got %d", recStatus.Code)
	}

	// 3. Admin Login berhasil
	adminLoginBody, _ := json.Marshal(map[string]string{
		"username": "azharfa",
		"password": "AdminSecret123!",
	})
	reqAdminLogin := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(adminLoginBody))
	reqAdminLogin.RemoteAddr = "10.0.0.1:12345"
	recAdminLogin := httptest.NewRecorder()
	handler.ServeHTTP(recAdminLogin, reqAdminLogin)
	if recAdminLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 on admin login, got %d: %s", recAdminLogin.Code, recAdminLogin.Body.String())
	}
	adminCookies := recAdminLogin.Result().Cookies()
	var adminAuthCookie *http.Cookie
	for _, c := range adminCookies {
		if c.Name == sessionCookieName {
			adminAuthCookie = c
			break
		}
	}
	if adminAuthCookie == nil || !adminAuthCookie.HttpOnly {
		t.Fatalf("expected HttpOnly %s cookie on admin login", sessionCookieName)
	}

	// 4. Admin membuat user Guru baru
	createTeacherBody, _ := json.Marshal(map[string]string{
		"username":    "guru_siti",
		"displayName": "Siti Nurhaliza",
		"password":    "PasswordSiti123!",
		"role":        "teacher",
	})
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/admin/users", bytes.NewReader(createTeacherBody))
	reqCreate.AddCookie(adminAuthCookie)
	reqCreate.Header.Set("Content-Type", "application/json")
	recCreate := httptest.NewRecorder()
	handler.ServeHTTP(recCreate, reqCreate)
	if recCreate.Code != http.StatusOK {
		t.Fatalf("expected 200 on admin creating user, got %d: %s", recCreate.Code, recCreate.Body.String())
	}

	// 5. Guru (Teacher) Login
	teacherLoginBody, _ := json.Marshal(map[string]string{
		"username": "guru_siti",
		"password": "PasswordSiti123!",
	})
	reqTeacherLogin := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(teacherLoginBody))
	reqTeacherLogin.RemoteAddr = "10.0.0.2:22222"
	recTeacherLogin := httptest.NewRecorder()
	handler.ServeHTTP(recTeacherLogin, reqTeacherLogin)
	if recTeacherLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 on teacher login, got %d: %s", recTeacherLogin.Code, recTeacherLogin.Body.String())
	}
	var teacherAuthCookie *http.Cookie
	for _, c := range recTeacherLogin.Result().Cookies() {
		if c.Name == sessionCookieName {
			teacherAuthCookie = c
			break
		}
	}

	// 6. Guru mengakses /api/status -> role harus "teacher"
	reqTeacherStatus := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	reqTeacherStatus.AddCookie(teacherAuthCookie)
	recTeacherStatus := httptest.NewRecorder()
	handler.ServeHTTP(recTeacherStatus, reqTeacherStatus)
	if recTeacherStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 on teacher status, got %d", recTeacherStatus.Code)
	}
	var teacherStatusData map[string]any
	_ = json.Unmarshal(recTeacherStatus.Body.Bytes(), &teacherStatusData)
	if teacherStatusData["role"] != "teacher" || teacherStatusData["currentUser"] != "guru_siti" {
		t.Fatalf("unexpected teacher status data: %+v", teacherStatusData)
	}

	// 7. Guru mencoba mengakses endpoint Admin -> Harus ditolak 403 Forbidden!
	reqForbidden := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	reqForbidden.AddCookie(teacherAuthCookie)
	recForbidden := httptest.NewRecorder()
	handler.ServeHTTP(recForbidden, reqForbidden)
	if recForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for teacher accessing admin endpoint, got %d", recForbidden.Code)
	}

	// 8. Guru mengganti password mandiri (/api/user/change-password)
	changePassBody, _ := json.Marshal(map[string]string{
		"oldPassword": "PasswordSiti123!",
		"newPassword": "PasswordSitiBaru456!",
	})
	reqChange := httptest.NewRequest(http.MethodPost, "/api/user/change-password", bytes.NewReader(changePassBody))
	reqChange.AddCookie(teacherAuthCookie)
	reqChange.Header.Set("Content-Type", "application/json")
	recChange := httptest.NewRecorder()
	handler.ServeHTTP(recChange, reqChange)
	if recChange.Code != http.StatusOK {
		t.Fatalf("expected 200 on changing password, got %d: %s", recChange.Code, recChange.Body.String())
	}

	// 9. Login ulang dengan password baru
	reqLoginNew := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(`{"username":"guru_siti","password":"PasswordSitiBaru456!"}`)))
	reqLoginNew.RemoteAddr = "10.0.0.2:33333"
	recLoginNew := httptest.NewRecorder()
	handler.ServeHTTP(recLoginNew, reqLoginNew)
	if recLoginNew.Code != http.StatusOK {
		t.Fatalf("expected 200 on login with new password, got %d", recLoginNew.Code)
	}

	// 10. Admin menonaktifkan akun Guru Siti
	toggleBody, _ := json.Marshal(map[string]any{
		"userId":   2,
		"isActive": false,
	})
	reqToggle := httptest.NewRequest(http.MethodPost, "/api/admin/users/toggle-active", bytes.NewReader(toggleBody))
	reqToggle.AddCookie(adminAuthCookie)
	reqToggle.Header.Set("Content-Type", "application/json")
	recToggle := httptest.NewRecorder()
	handler.ServeHTTP(recToggle, reqToggle)
	if recToggle.Code != http.StatusOK {
		t.Fatalf("expected 200 on admin toggling active, got %d: %s", recToggle.Code, recToggle.Body.String())
	}

	// Sesi Guru Siti harus langsung tidak valid (401)
	reqDeactivatedStatus := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	reqDeactivatedStatus.AddCookie(teacherAuthCookie)
	recDeactivatedStatus := httptest.NewRecorder()
	handler.ServeHTTP(recDeactivatedStatus, reqDeactivatedStatus)
	if recDeactivatedStatus.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for deactivated user session, got %d", recDeactivatedStatus.Code)
	}
}

func TestServerPanicRecoveryAndResilientAPI(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "server_panic_test.db")
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
		DashboardPass: "AdminSecret123!",
	}

	client, err := algonova.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	srv := NewServer(cfg, client, st)
	defer srv.Close()

	// Test panic middleware handling
	panicHandler := srv.recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulated critical crash")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test-panic", nil)
	rec := httptest.NewRecorder()
	panicHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on panic recovery, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected application/json on recovered API error, got %s", ct)
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("expected valid JSON error response, got: %s", rec.Body.String())
	}
	if res["error"] == nil {
		t.Fatalf("expected error field in JSON response")
	}
}
