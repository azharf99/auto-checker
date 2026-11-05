package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"auto-checker/internal/algonova"
	"auto-checker/internal/config"
	"auto-checker/internal/store"
)

const sessionCookieName = "autochecker_session"

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,32}$`)

//go:embed dashboard.html
var dashboardHTML []byte

//go:embed login.html
var loginHTML []byte

type LogEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}

type loginAttemptInfo struct {
	failures int
	resetAt  time.Time
}

type UserScanState struct {
	mu    sync.Mutex
	items []algonova.YellowLevelItem
	byKey map[string]algonova.YellowLevelItem
}

type userCookieStoreAdapter struct {
	store  *store.Store
	userID int64
}

func (a *userCookieStoreAdapter) SaveAlgonovaCookies(cookies []algonova.SavedCookie) error {
	return a.store.SaveUserAlgonovaCookies(a.userID, cookies)
}

func (a *userCookieStoreAdapter) LoadAlgonovaCookies() ([]algonova.SavedCookie, error) {
	return a.store.LoadUserAlgonovaCookies(a.userID)
}

// Server menyediakan Web Dashboard multi-user yang dilindungi autentikasi ketat, SQLite Store, dan Background Scheduler terisolasi.
type Server struct {
	cfg *config.Config
	db  *store.Store

	clientMu sync.RWMutex
	clients  map[int64]*algonova.Client

	scanMu    sync.RWMutex
	userScans map[int64]*UserScanState

	rateMu        sync.Mutex
	loginAttempts map[string]*loginAttemptInfo

	cronTicker *time.Ticker
	cronStop   chan struct{}
}

func NewServer(cfg *config.Config, defaultClient *algonova.Client, db *store.Store) *Server {
	s := &Server{
		cfg:           cfg,
		db:            db,
		clients:       make(map[int64]*algonova.Client),
		userScans:     make(map[int64]*UserScanState),
		loginAttempts: make(map[string]*loginAttemptInfo),
		cronStop:      make(chan struct{}),
	}

	if db != nil {
		adminUser, _ := db.EnsureAdminUser(cfg.DashboardUser, cfg.DashboardPass)
		if adminUser != nil && defaultClient != nil {
			defaultClient.AttachCookieStore(&userCookieStoreAdapter{store: db, userID: adminUser.ID})
			s.clients[adminUser.ID] = defaultClient
		}
	}

	s.addServerLog(1, "Server diinisialisasi (Multi-User RBAC Aktif, User Admin: %s)", cfg.DashboardUser)

	// Jalankan multi-user background scheduler runner
	s.cronTicker = time.NewTicker(1 * time.Minute)
	go s.runSchedulerLoop()

	return s
}

func (s *Server) Close() {
	if s.cronTicker != nil {
		s.cronTicker.Stop()
	}
	select {
	case <-s.cronStop:
	default:
		close(s.cronStop)
	}
}

func (s *Server) getClientForUser(userID int64) (*algonova.Client, error) {
	s.clientMu.RLock()
	c, ok := s.clients[userID]
	s.clientMu.RUnlock()
	if ok {
		return c, nil
	}

	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if c, ok := s.clients[userID]; ok {
		return c, nil
	}

	newClient, err := algonova.NewClient(s.cfg)
	if err != nil {
		return nil, fmt.Errorf("create algonova client: %w", err)
	}

	if s.db != nil {
		adapter := &userCookieStoreAdapter{store: s.db, userID: userID}
		newClient.AttachCookieStore(adapter)
	}

	s.clients[userID] = newClient
	return newClient, nil
}

func (s *Server) getUserScanState(userID int64) *UserScanState {
	s.scanMu.RLock()
	st, ok := s.userScans[userID]
	s.scanMu.RUnlock()
	if ok {
		return st
	}

	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if st, ok := s.userScans[userID]; ok {
		return st
	}

	st = &UserScanState{byKey: make(map[string]algonova.YellowLevelItem)}
	s.userScans[userID] = st
	return st
}

func (s *Server) addServerLog(userID int64, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	timeStr := time.Now().Format("15:04:05")
	fmt.Printf("[%s] [User %d] %s\n", timeStr, userID, msg)

	if s.db != nil {
		_ = s.db.AddUserLog(userID, timeStr, msg)
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public Routes
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)

	// Protected Routes (Semua Pengguna Terautentikasi)
	mux.HandleFunc("GET /", s.requireAuthPage(s.handleIndex))
	mux.HandleFunc("GET /api/status", s.requireAuthAPI(s.handleStatus))
	mux.HandleFunc("GET /api/history", s.requireAuthAPI(s.handleHistory))
	mux.HandleFunc("POST /api/algonova-session", s.requireAuthAPI(s.handleAlgonovaSession))
	mux.HandleFunc("POST /api/scan", s.requireAuthAPI(s.handleScan))
	mux.HandleFunc("POST /api/execute", s.requireAuthAPI(s.handleExecute))
	mux.HandleFunc("POST /api/scheduler", s.requireAuthAPI(s.handleScheduler))
	mux.HandleFunc("POST /api/user/change-password", s.requireAuthAPI(s.handleUserChangePassword))

	// Protected Routes (Khusus Role Admin)
	mux.HandleFunc("GET /api/admin/users", s.requireAdminAPI(s.handleAdminListUsers))
	mux.HandleFunc("POST /api/admin/users", s.requireAdminAPI(s.handleAdminCreateUser))
	mux.HandleFunc("POST /api/admin/users/reset-password", s.requireAdminAPI(s.handleAdminResetPassword))
	mux.HandleFunc("POST /api/admin/users/toggle-active", s.requireAdminAPI(s.handleAdminToggleActive))
	mux.HandleFunc("POST /api/admin/users/delete", s.requireAdminAPI(s.handleAdminDeleteUser))

	return s.securityMiddleware(mux)
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strict Security Headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:;")

		// CSRF Prevention untuk Request Mutasi (POST, PUT, DELETE)
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")
			reqWith := r.Header.Get("X-Requested-With")
			contentType := r.Header.Get("Content-Type")

			// Izinkan jika request menyertakan header json atau x-requested-with (khas fetch/ajax yang memicu preflight)
			isJSON := strings.Contains(strings.ToLower(contentType), "application/json")
			isAJAX := strings.EqualFold(reqWith, "xmlhttprequest")

			if !isJSON && !isAJAX && (origin != "" || referer != "") {
				host := r.Host
				if origin != "" && !strings.Contains(origin, host) {
					writeJSON(w, http.StatusForbidden, map[string]any{"error": "CSRF: Origin request tidak sesuai"})
					return
				}
				if referer != "" && !strings.Contains(referer, host) {
					writeJSON(w, http.StatusForbidden, map[string]any{"error": "CSRF: Referer request tidak sesuai"})
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) getAuthenticatedUser(r *http.Request) (*store.User, bool) {
	ck, err := r.Cookie(sessionCookieName)
	if err != nil || strings.TrimSpace(ck.Value) == "" {
		return nil, false
	}
	if s.db == nil {
		return nil, false
	}
	return s.db.ValidateUserSession(ck.Value)
}

func (s *Server) requireAuthPage(next func(http.ResponseWriter, *http.Request, *store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.getAuthenticatedUser(r)
		if !ok || u == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r, u)
	}
}

func (s *Server) requireAuthAPI(next func(http.ResponseWriter, *http.Request, *store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.getAuthenticatedUser(r)
		if !ok || u == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "sesi tidak valid atau telah berakhir"})
			return
		}
		next(w, r, u)
	}
}

func (s *Server) requireAdminAPI(next func(http.ResponseWriter, *http.Request, *store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.getAuthenticatedUser(r)
		if !ok || u == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "sesi tidak valid atau telah berakhir"})
			return
		}
		if u.Role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "akses khusus administrator"})
			return
		}
		next(w, r, u)
	}
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getAuthenticatedUser(r); ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(loginHTML)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) checkLoginRateLimit(ip, username string) error {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	cleanUser := strings.ToLower(strings.TrimSpace(username))
	key := fmt.Sprintf("%s:%s", ip, cleanUser)

	for _, k := range []string{key, ip} {
		info, exists := s.loginAttempts[k]
		if !exists || now.After(info.resetAt) {
			s.loginAttempts[k] = &loginAttemptInfo{
				failures: 0,
				resetAt:  now.Add(15 * time.Minute),
			}
			continue
		}
		if info.failures >= 5 {
			rem := time.Until(info.resetAt).Round(time.Second)
			return fmt.Errorf("terlalu banyak percobaan login gagal; coba lagi dalam %s", rem)
		}
	}
	return nil
}

func (s *Server) recordLoginFailure(ip, username string) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	cleanUser := strings.ToLower(strings.TrimSpace(username))
	key := fmt.Sprintf("%s:%s", ip, cleanUser)

	for _, k := range []string{key, ip} {
		info, exists := s.loginAttempts[k]
		if !exists || now.After(info.resetAt) {
			s.loginAttempts[k] = &loginAttemptInfo{failures: 1, resetAt: now.Add(15 * time.Minute)}
		} else {
			info.failures++
		}
	}
}

func (s *Server) clearLoginFailures(ip, username string) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	cleanUser := strings.ToLower(strings.TrimSpace(username))
	delete(s.loginAttempts, fmt.Sprintf("%s:%s", ip, cleanUser))
	delete(s.loginAttempts, ip)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format request tidak valid"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if err := s.checkLoginRateLimit(ip, req.Username); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": err.Error()})
		return
	}

	if s.db == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "database belum siap"})
		return
	}

	// 1. Coba autentikasi database lokal terlebih dahulu (cepat)
	u, localErr := s.db.AuthenticateUser(req.Username, req.Password)
	if localErr == nil && u != nil {
		s.completeUserLogin(w, r, u, ip)
		return
	}

	// 2. Jika autentikasi lokal gagal (misal user baru atau password LMS berubah),
	// coba autentikasi langsung ke LMS Algonova!
	// Fitur ini memungkinkan guru langsung login dengan akun LMS resmi mereka tanpa pendaftaran manual.
	lmsClient, err := algonova.NewClient(s.cfg)
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		lmsAuthErr := lmsClient.Login(ctx, req.Username, req.Password)
		cancel()

		if lmsAuthErr == nil {
			cleanUser := strings.ToLower(req.Username)
			existingUser, _ := s.db.GetUserByUsername(cleanUser)
			if existingUser == nil {
				// Daftarkan otomatis sebagai guru (role: teacher)
				displayName := req.Username
				existingUser, err = s.db.CreateUser(cleanUser, displayName, req.Password, "teacher")
				if err != nil {
					s.addServerLog(1, "[AUTH] Gagal auto-register user %q: %v", req.Username, err)
				} else {
					s.addServerLog(existingUser.ID, "[AUTH] Akun guru %q berhasil didaftarkan otomatis via login Algonova LMS", req.Username)
				}
			} else {
				// Perbarui password lokal agar selalu sinkron dengan LMS
				_ = s.db.UpdateUserPassword(existingUser.ID, req.Password)
			}

			if existingUser != nil {
				// Simpan cookies Algonova yang baru didapat ke database
				cookies := lmsClient.GetSavedCookies()
				if len(cookies) > 0 {
					_ = s.db.SaveUserAlgonovaCookies(existingUser.ID, cookies)
				}

				// Daftarkan client ke client pool agar langsung aktif
				s.clientMu.Lock()
				lmsClient.AttachCookieStore(&userCookieStoreAdapter{store: s.db, userID: existingUser.ID})
				s.clients[existingUser.ID] = lmsClient
				s.clientMu.Unlock()

				s.completeUserLogin(w, r, existingUser, ip)
				return
			}
		}
	}

	// 3. Jika kedua metode gagal
	s.recordLoginFailure(ip, req.Username)
	s.addServerLog(1, "[AUTH] Login gagal untuk user %q dari IP %s", req.Username, ip)
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error": "Username atau password salah. Pastikan menggunakan kredensial Algonova LMS atau password dashboard yang valid.",
	})
}

func (s *Server) completeUserLogin(w http.ResponseWriter, r *http.Request, u *store.User, ip string) {
	s.clearLoginFailures(ip, u.Username)
	userAgent := r.UserAgent()
	token, err := s.db.CreateUserSession(u.ID, u.Username, s.cfg.SessionTTL, ip, userAgent)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "gagal membuat sesi login"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	})

	s.addServerLog(u.ID, "[AUTH] User %q (%s) berhasil login dari IP %s", u.Username, u.Role, ip)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"userId":      u.ID,
		"username":    u.Username,
		"displayName": u.DisplayName,
		"role":        u.Role,
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookieName); err == nil && s.db != nil {
		_ = s.db.DeleteSession(ck.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request, u *store.User) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(dashboardHTML)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, u *store.User) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	client, err := s.getClientForUser(u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	unreviewedCount, err := client.EnsureAuthenticated(ctx)
	authOK := err == nil

	cronEnabled := s.db.GetUserSetting(u.ID, "cron_enabled", "false") == "true"
	cronInterval := s.db.GetUserSetting(u.ID, "cron_interval", "6h")
	cronAutoExec := s.db.GetUserSetting(u.ID, "cron_auto_exec", "false") == "true"

	logs, _ := s.db.GetUserRecentLogs(u.ID, 150)
	var logEntries []LogEntry
	for _, l := range logs {
		logEntries = append(logEntries, LogEntry{Time: l.Time, Message: l.Message})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"currentUser":           u.Username,
		"displayName":           u.DisplayName,
		"role":                  u.Role,
		"authenticated":         authOK,
		"unreviewedGlobalCount": unreviewedCount,
		"cookies":               client.CurrentCookiesSummary(),
		"cronEnabled":           cronEnabled,
		"cronInterval":          cronInterval,
		"cronAutoExec":          cronAutoExec,
		"logs":                  logEntries,
	})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request, u *store.User) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"history": []any{}})
		return
	}
	history, err := s.db.GetUserExecutionHistory(u.ID, 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": history})
}

type algonovaSessionReq struct {
	RawCookies string `json:"rawCookies"`
}

func (s *Server) handleAlgonovaSession(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req algonovaSessionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	client, err := s.getClientForUser(u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	if strings.TrimSpace(req.RawCookies) != "" {
		client.SetRawCookies(req.RawCookies)
		s.addServerLog(u.ID, "[SESSION] Cookie Algonova user %q diperbarui manual.", u.Username)
	}

	count, err := client.EnsureAuthenticated(r.Context())
	if err != nil {
		s.addServerLog(u.ID, "[SESSION] Verifikasi Algonova gagal: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}

	s.addServerLog(u.ID, "[SESSION] Sesi Algonova user %q aktif & tersimpan di SQLite (Unreviewed=%d).", u.Username, count)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                "ok",
		"unreviewedGlobalCount": count,
	})
}

type scanRequest struct {
	Mode          string `json:"mode"`
	GroupIDs      string `json:"groupIds"`
	Timeframe     string `json:"timeframe"`
	OnlyScheduled bool   `json:"onlyScheduled"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	client, err := s.getClientForUser(u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	if _, err := client.EnsureAuthenticated(r.Context()); err != nil {
		s.addServerLog(u.ID, "Gagal autentikasi Algonova saat scan: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}

	gids := config.ParseGroupIDs(req.GroupIDs)
	s.addServerLog(u.ID, "Memulai scan Read-Only (mode=%s, groupIds=%v, timeframe=%s)...", req.Mode, gids, req.Timeframe)

	items, err := client.Discover(r.Context(), algonova.DiscoverOptions{
		Mode:          req.Mode,
		GroupIDs:      gids,
		OnlyScheduled: req.OnlyScheduled,
		Timeframe:     req.Timeframe,
	})
	if err != nil {
		s.addServerLog(u.ID, "Scan error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	scanState := s.getUserScanState(u.ID)
	scanState.mu.Lock()
	scanState.items = items
	scanState.byKey = make(map[string]algonova.YellowLevelItem, len(items))
	for _, it := range items {
		scanState.byKey[it.Key] = it
	}
	scanState.mu.Unlock()

	s.addServerLog(u.ID, "Scan selesai: ditemukan %d level kuning (student_success).", len(items))
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

type executeRequest struct {
	Keys   []string `json:"keys"`
	DryRun bool     `json:"dryRun"`
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req executeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	scanState := s.getUserScanState(u.ID)
	scanState.mu.Lock()
	var targets []algonova.YellowLevelItem
	for _, k := range req.Keys {
		if it, ok := scanState.byKey[k]; ok {
			targets = append(targets, it)
		}
	}
	scanState.mu.Unlock()

	if len(targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tidak ada item valid milik Anda yang dipilih"})
		return
	}

	client, err := s.getClientForUser(u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	modeLabel := "EXECUTE (POST)"
	if req.DryRun {
		modeLabel = "DRY-RUN (Simulasi Read-Only)"
	}
	s.addServerLog(u.ID, "Memulai %s untuk %d level...", modeLabel, len(targets))

	results := client.CheckBatch(r.Context(), targets, req.DryRun, func(idx, total int, res algonova.CheckResult) {
		if s.db != nil {
			_ = s.db.AddUserExecutionHistory(u.ID, res)
		}
	})

	succeeded := 0
	for _, res := range results {
		if res.Success {
			succeeded++
		}
	}

	s.addServerLog(u.ID, "Selesai %s: %d/%d level berhasil diproses.", modeLabel, succeeded, len(results))
	writeJSON(w, http.StatusOK, map[string]any{
		"dryRun":    req.DryRun,
		"total":     len(results),
		"succeeded": succeeded,
		"results":   results,
	})
}

type schedulerRequest struct {
	Enabled     bool   `json:"enabled"`
	Interval    string `json:"interval"`
	AutoExecute bool   `json:"autoExecute"`
}

func (s *Server) handleScheduler(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req schedulerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	intervalDur, err := time.ParseDuration(req.Interval)
	if err != nil || intervalDur < 10*time.Minute {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "interval harus berformat durasi valid minimal 10m (misal 30m, 1h, 6h)"})
		return
	}

	enabledStr := "false"
	if req.Enabled {
		enabledStr = "true"
	}
	autoExecStr := "false"
	if req.AutoExecute {
		autoExecStr = "true"
	}

	_ = s.db.SetUserSetting(u.ID, "cron_enabled", enabledStr)
	_ = s.db.SetUserSetting(u.ID, "cron_interval", req.Interval)
	_ = s.db.SetUserSetting(u.ID, "cron_auto_exec", autoExecStr)

	statusStr := "dimatikan"
	if req.Enabled {
		statusStr = fmt.Sprintf("diaktifkan (interval: %s, auto-exec: %v)", req.Interval, req.AutoExecute)
	}
	s.addServerLog(u.ID, "[CRON] Pengaturan scheduler %s.", statusStr)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"cronEnabled": req.Enabled,
	})
}

type changePasswordReq struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) handleUserChangePassword(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req changePasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format request tidak valid"})
		return
	}

	// Verifikasi password lama
	if _, err := s.db.AuthenticateUser(u.Username, req.OldPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "password lama tidak sesuai"})
		return
	}

	if len(req.NewPassword) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "password baru minimal 8 karakter"})
		return
	}

	if err := s.db.UpdateUserPassword(u.ID, req.NewPassword); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	s.addServerLog(u.ID, "[AUTH] Password akun berhasil diubah.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "password berhasil diperbarui"})
}

// ---------------- Admin Handlers ----------------

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request, u *store.User) {
	users, err := s.db.ListUsers()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

type createUserReq struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req createUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format request tidak valid"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if !usernameRegex.MatchString(req.Username) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "username harus 3-32 karakter alfanumerik atau garis bawah/strip"})
		return
	}

	newUser, err := s.db.CreateUser(req.Username, req.DisplayName, req.Password, req.Role)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	s.addServerLog(u.ID, "[ADMIN] Akun baru %q (%s) dibuat oleh %s", newUser.Username, newUser.Role, u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "user": newUser})
}

type resetPasswordReq struct {
	UserID      int64  `json:"userId"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) handleAdminResetPassword(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req resetPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format request tidak valid"})
		return
	}

	targetUser, err := s.db.GetUserByID(req.UserID)
	if err != nil || targetUser == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "pengguna tidak ditemukan"})
		return
	}

	if err := s.db.UpdateUserPassword(req.UserID, req.NewPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	_ = s.db.DeleteUserSessions(req.UserID)
	s.addServerLog(u.ID, "[ADMIN] Password user %q di-reset oleh admin %s", targetUser.Username, u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "password pengguna berhasil di-reset"})
}

type toggleActiveReq struct {
	UserID   int64 `json:"userId"`
	IsActive bool  `json:"isActive"`
}

func (s *Server) handleAdminToggleActive(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req toggleActiveReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format request tidak valid"})
		return
	}

	if req.UserID == u.ID {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Anda tidak dapat menonaktifkan akun sendiri"})
		return
	}

	targetUser, err := s.db.GetUserByID(req.UserID)
	if err != nil || targetUser == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "pengguna tidak ditemukan"})
		return
	}

	if err := s.db.UpdateUserStatus(req.UserID, req.IsActive); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	actionStr := "diaktifkan"
	if !req.IsActive {
		actionStr = "dinonaktifkan"
	}
	s.addServerLog(u.ID, "[ADMIN] Akun user %q %s oleh admin %s", targetUser.Username, actionStr, u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

type deleteUserReq struct {
	UserID int64 `json:"userId"`
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req deleteUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format request tidak valid"})
		return
	}

	if req.UserID == u.ID {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Anda tidak dapat menghapus akun sendiri"})
		return
	}

	targetUser, err := s.db.GetUserByID(req.UserID)
	if err != nil || targetUser == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "pengguna tidak ditemukan"})
		return
	}

	if err := s.db.DeleteUser(req.UserID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	s.clientMu.Lock()
	delete(s.clients, req.UserID)
	s.clientMu.Unlock()

	s.scanMu.Lock()
	delete(s.userScans, req.UserID)
	s.scanMu.Unlock()

	s.addServerLog(u.ID, "[ADMIN] Akun user %q beserta seluruh datanya dihapus permanen oleh %s", targetUser.Username, u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// ---------------- Multi-User Background Scheduler Loop ----------------

func (s *Server) runSchedulerLoop() {
	for {
		select {
		case <-s.cronStop:
			return
		case <-s.cronTicker.C:
			s.runScheduledChecks()
		}
	}
}

func (s *Server) runScheduledChecks() {
	if s.db == nil {
		return
	}

	userIDs, err := s.db.ListUsersWithCronEnabled()
	if err != nil || len(userIDs) == 0 {
		return
	}

	now := time.Now()
	for _, uid := range userIDs {
		intervalStr := s.db.GetUserSetting(uid, "cron_interval", "6h")
		dur, err := time.ParseDuration(intervalStr)
		if err != nil || dur < 10*time.Minute {
			dur = 6 * time.Hour
		}

		lastRunStr := s.db.GetUserSetting(uid, "cron_last_run", "")
		if lastRunStr != "" {
			if t, err := time.Parse(time.RFC3339, lastRunStr); err == nil {
				if now.Sub(t) < dur {
					continue
				}
			}
		}

		_ = s.db.SetUserSetting(uid, "cron_last_run", now.Format(time.RFC3339))
		autoExec := s.db.GetUserSetting(uid, "cron_auto_exec", "false") == "true"
		s.executeUserCron(uid, autoExec)
	}
}

func (s *Server) executeUserCron(userID int64, autoExec bool) {
	client, err := s.getClientForUser(userID)
	if err != nil {
		s.addServerLog(userID, "[CRON] Gagal memuat client: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if _, err := client.EnsureAuthenticated(ctx); err != nil {
		s.addServerLog(userID, "[CRON] Autentikasi Algonova gagal: %v", err)
		return
	}

	items, err := client.Discover(ctx, algonova.DiscoverOptions{
		Mode:      s.cfg.DiscoveryMode,
		Timeframe: s.cfg.Timeframe,
	})
	if err != nil {
		s.addServerLog(userID, "[CRON] Gagal mencari tugas kuning: %v", err)
		return
	}

	scanState := s.getUserScanState(userID)
	scanState.mu.Lock()
	scanState.items = items
	scanState.byKey = make(map[string]algonova.YellowLevelItem, len(items))
	for _, it := range items {
		scanState.byKey[it.Key] = it
	}
	scanState.mu.Unlock()

	s.addServerLog(userID, "[CRON] Ditemukan %d tugas kuning.", len(items))
	if len(items) == 0 || !autoExec {
		return
	}

	results := client.CheckBatch(ctx, items, false, func(idx, total int, res algonova.CheckResult) {
		if s.db != nil {
			_ = s.db.AddUserExecutionHistory(userID, res)
		}
	})

	okCount := 0
	for _, r := range results {
		if r.Success {
			okCount++
		}
	}
	s.addServerLog(userID, "[CRON] Selesai menceklis otomatis %d/%d level tugas.", okCount, len(results))
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
