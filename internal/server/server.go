package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"auto-checker/internal/algonova"
	"auto-checker/internal/config"
	"auto-checker/internal/store"
)

const sessionCookieName = "autochecker_session"

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

// Server menyediakan Web Dashboard yang dilindungi autentikasi, SQLite Store, dan Built-in Cron Scheduler.
type Server struct {
	cfg    *config.Config
	client *algonova.Client
	db     *store.Store

	mu          sync.Mutex
	scanned     []algonova.YellowLevelItem
	scannedByID map[string]algonova.YellowLevelItem
	logs        []LogEntry

	cronEnabled  bool
	cronInterval time.Duration
	cronAutoExec bool
	cronCancel   context.CancelFunc

	rateMu        sync.Mutex
	loginAttempts map[string]*loginAttemptInfo
}

func NewServer(cfg *config.Config, client *algonova.Client, db *store.Store) *Server {
	s := &Server{
		cfg:           cfg,
		client:        client,
		db:            db,
		scannedByID:   make(map[string]algonova.YellowLevelItem),
		cronEnabled:   cfg.EnableCron,
		cronInterval:  cfg.CronInterval,
		cronAutoExec:  cfg.CronAutoExec,
		loginAttempts: make(map[string]*loginAttemptInfo),
	}

	if db != nil {
		_ = db.EnsureAdminUser(cfg.DashboardUser, cfg.DashboardPass)

		// Muat konfigurasi scheduler yang tersimpan di SQLite
		if v := db.GetSetting("cron_enabled", ""); v != "" {
			s.cronEnabled = v == "true"
		}
		if v := db.GetSetting("cron_interval", ""); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d >= time.Minute {
				s.cronInterval = d
			}
		}
		if v := db.GetSetting("cron_auto_exec", ""); v != "" {
			s.cronAutoExec = v == "true"
		}

		// Muat riwayat log terakhir dari SQLite
		if savedLogs, err := db.GetRecentLogs(150); err == nil {
			for _, l := range savedLogs {
				s.logs = append(s.logs, LogEntry{Time: l.Time, Message: l.Message})
			}
		}
	}

	s.addLog("Server diinisialisasi (Auth Aktif, User Admin: %s, Cron: %v)", cfg.DashboardUser, s.cronEnabled)
	if s.cronEnabled {
		s.startCronLocked()
	}
	return s
}

func (s *Server) addLog(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	timeStr := time.Now().Format("15:04:05")
	entry := LogEntry{
		Time:    timeStr,
		Message: msg,
	}
	fmt.Printf("[%s] %s\n", entry.Time, entry.Message)

	s.mu.Lock()
	s.logs = append(s.logs, entry)
	if len(s.logs) > 200 {
		s.logs = s.logs[len(s.logs)-200:]
	}
	s.mu.Unlock()

	if s.db != nil {
		_ = s.db.AddLog(timeStr, msg)
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public Routes (Login)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)

	// Protected Routes (Membutuhkan Sesi Login Valid)
	mux.HandleFunc("GET /", s.requireAuthPage(s.handleIndex))
	mux.HandleFunc("GET /api/status", s.requireAuthAPI(s.handleStatus))
	mux.HandleFunc("GET /api/history", s.requireAuthAPI(s.handleHistory))
	mux.HandleFunc("POST /api/algonova-session", s.requireAuthAPI(s.handleAlgonovaSession))
	mux.HandleFunc("POST /api/scan", s.requireAuthAPI(s.handleScan))
	mux.HandleFunc("POST /api/execute", s.requireAuthAPI(s.handleExecute))
	mux.HandleFunc("POST /api/scheduler", s.requireAuthAPI(s.handleScheduler))
	return mux
}

func (s *Server) getAuthenticatedUser(r *http.Request) (string, bool) {
	ck, err := r.Cookie(sessionCookieName)
	if err != nil || strings.TrimSpace(ck.Value) == "" {
		return "", false
	}
	if s.db == nil {
		return "", false
	}
	return s.db.ValidateSession(ck.Value)
}

func (s *Server) requireAuthPage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.getAuthenticatedUser(r); !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAuthAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.getAuthenticatedUser(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "sesi tidak valid atau belum login"})
			return
		}
		next(w, r)
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

func (s *Server) checkLoginRateLimit(ip string) error {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	info, exists := s.loginAttempts[ip]
	if !exists || now.After(info.resetAt) {
		s.loginAttempts[ip] = &loginAttemptInfo{
			failures: 0,
			resetAt:  now.Add(1 * time.Minute),
		}
		return nil
	}
	if info.failures >= 5 {
		rem := time.Until(info.resetAt).Round(time.Second)
		return fmt.Errorf("terlalu banyak percobaan login gagal; silakan coba lagi dalam %s", rem)
	}
	return nil
}

func (s *Server) recordLoginFailure(ip string) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	info, exists := s.loginAttempts[ip]
	if !exists || now.After(info.resetAt) {
		s.loginAttempts[ip] = &loginAttemptInfo{failures: 1, resetAt: now.Add(1 * time.Minute)}
		return
	}
	info.failures++
}

func (s *Server) clearLoginFailures(ip string) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
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

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if err := s.checkLoginRateLimit(ip); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": err.Error()})
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format request tidak valid"})
		return
	}

	if s.db == nil || !s.db.VerifyUser(req.Username, req.Password) {
		s.recordLoginFailure(ip)
		s.addLog("[AUTH] Percobaan login gagal untuk user %q dari IP %s", req.Username, ip)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "username atau password salah"})
		return
	}

	s.clearLoginFailures(ip)
	token, err := s.db.CreateSession(strings.TrimSpace(req.Username), s.cfg.SessionTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "gagal membuat sesi login"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	})

	s.addLog("[AUTH] User %q berhasil login ke Web Dashboard dari IP %s", req.Username, ip)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "username": req.Username})
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
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(dashboardHTML)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	currentUser, _ := s.getAuthenticatedUser(r)
	unreviewedCount, err := s.client.EnsureAuthenticated(ctx)
	authOK := err == nil

	s.mu.Lock()
	logsCopy := make([]LogEntry, len(s.logs))
	copy(logsCopy, s.logs)
	cronEnabled := s.cronEnabled
	cronInterval := s.cronInterval.String()
	cronAutoExec := s.cronAutoExec
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"currentUser":           currentUser,
		"authenticated":         authOK,
		"unreviewedGlobalCount": unreviewedCount,
		"cookies":               s.client.CurrentCookiesSummary(),
		"cronEnabled":           cronEnabled,
		"cronInterval":          cronInterval,
		"cronAutoExec":          cronAutoExec,
		"logs":                  logsCopy,
	})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"history": []any{}})
		return
	}
	history, err := s.db.GetExecutionHistory(100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": history})
}

type algonovaSessionReq struct {
	RawCookies string `json:"rawCookies"`
}

func (s *Server) handleAlgonovaSession(w http.ResponseWriter, r *http.Request) {
	var req algonovaSessionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	if strings.TrimSpace(req.RawCookies) != "" {
		s.client.SetRawCookies(req.RawCookies)
		s.addLog("[SESSION] Cookie Algonova diperbarui manual dari Web Dashboard.")
	}

	count, err := s.client.EnsureAuthenticated(r.Context())
	if err != nil {
		s.addLog("[SESSION] Verifikasi/Re-login Algonova gagal: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}

	s.addLog("[SESSION] Sesi Algonova aktif & tersimpan di SQLite (Global Unreviewed=%d).", count)
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

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	if _, err := s.client.EnsureAuthenticated(r.Context()); err != nil {
		s.addLog("Gagal autentikasi saat scan: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}

	gids := config.ParseGroupIDs(req.GroupIDs)
	s.addLog("Memulai scan Read-Only (mode=%s, groupIds=%v, timeframe=%s)...", req.Mode, gids, req.Timeframe)

	items, err := s.client.Discover(r.Context(), algonova.DiscoverOptions{
		Mode:          req.Mode,
		GroupIDs:      gids,
		OnlyScheduled: req.OnlyScheduled,
		Timeframe:     req.Timeframe,
	})
	if err != nil {
		s.addLog("Scan error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	s.mu.Lock()
	s.scanned = items
	s.scannedByID = make(map[string]algonova.YellowLevelItem, len(items))
	for _, it := range items {
		s.scannedByID[it.Key] = it
	}
	s.mu.Unlock()

	s.addLog("Scan selesai: ditemukan %d level kuning (student_success).", len(items))
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

type executeRequest struct {
	Keys   []string `json:"keys"`
	DryRun bool     `json:"dryRun"`
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	var req executeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	s.mu.Lock()
	var targets []algonova.YellowLevelItem
	for _, k := range req.Keys {
		if it, ok := s.scannedByID[k]; ok {
			targets = append(targets, it)
		}
	}
	s.mu.Unlock()

	if len(targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tidak ada item valid yang dipilih"})
		return
	}

	modeLabel := "EXECUTE (POST)"
	if req.DryRun {
		modeLabel = "DRY-RUN (Simulasi Read-Only)"
	}
	s.addLog("Memulai %s untuk %d level...", modeLabel, len(targets))

	results := s.client.CheckBatch(r.Context(), targets, req.DryRun, func(idx, total int, res algonova.CheckResult) {
		if s.db != nil {
			_ = s.db.AddExecutionHistory(res)
		}
		if res.Success {
			s.addLog("[%d/%d] OK (%s) -> Siswa: %s | Task %d Level %d (%d objektif diceklis)",
				idx, total, modeLabel, res.Item.StudentName, res.Item.TaskID, res.Item.LevelPosition, res.ObjectivesChecked)
		} else {
			s.addLog("[%d/%d] GAGAL -> Siswa: %s | Level %d: %s",
				idx, total, res.Item.StudentName, res.Item.LevelID, res.Error)
		}
	})

	succeeded := 0
	for _, res := range results {
		if res.Success {
			succeeded++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results":   results,
		"succeeded": succeeded,
		"total":     len(results),
	})
}

type schedulerRequest struct {
	Enabled     bool   `json:"enabled"`
	Interval    string `json:"interval"`
	AutoExecute bool   `json:"autoExecute"`
}

func (s *Server) handleScheduler(w http.ResponseWriter, r *http.Request) {
	var req schedulerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	s.mu.Lock()
	if s.cronCancel != nil {
		s.cronCancel()
		s.cronCancel = nil
	}
	if d, err := time.ParseDuration(req.Interval); err == nil && d >= time.Minute {
		s.cronInterval = d
	}
	s.cronEnabled = req.Enabled
	s.cronAutoExec = req.AutoExecute
	if s.cronEnabled {
		s.startCronLocked()
	}
	intervalStr := s.cronInterval.String()
	s.mu.Unlock()

	if s.db != nil {
		_ = s.db.SetSetting("cron_enabled", fmt.Sprintf("%v", req.Enabled))
		_ = s.db.SetSetting("cron_interval", intervalStr)
		_ = s.db.SetSetting("cron_auto_exec", fmt.Sprintf("%v", req.AutoExecute))
	}

	s.addLog("Scheduler diperbarui & disimpan ke SQLite: enabled=%v, interval=%s, autoExecute=%v", req.Enabled, intervalStr, req.AutoExecute)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) startCronLocked() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cronCancel = cancel
	interval := s.cronInterval
	if interval < time.Minute {
		interval = 6 * time.Hour
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runScheduledJob(ctx)
			}
		}
	}()
}

func (s *Server) runScheduledJob(ctx context.Context) {
	s.mu.Lock()
	autoExec := s.cronAutoExec
	s.mu.Unlock()

	s.addLog("[CRON] Menjalankan pemeriksaan terjadwal (autoExecute=%v)...", autoExec)
	if _, err := s.client.EnsureAuthenticated(ctx); err != nil {
		s.addLog("[CRON] Autentikasi gagal: %v", err)
		return
	}

	items, err := s.client.Discover(ctx, algonova.DiscoverOptions{
		Mode:          s.cfg.DiscoveryMode,
		GroupIDs:      s.cfg.GroupIDs,
		OnlyScheduled: s.cfg.OnlyScheduled,
		Timeframe:     s.cfg.Timeframe,
	})
	if err != nil {
		s.addLog("[CRON] Gagal mencari tugas kuning: %v", err)
		return
	}

	s.mu.Lock()
	s.scanned = items
	s.scannedByID = make(map[string]algonova.YellowLevelItem, len(items))
	for _, it := range items {
		s.scannedByID[it.Key] = it
	}
	s.mu.Unlock()

	s.addLog("[CRON] Ditemukan %d tugas kuning.", len(items))
	if len(items) == 0 || !autoExec {
		return
	}

	results := s.client.CheckBatch(ctx, items, false, func(idx, total int, res algonova.CheckResult) {
		if s.db != nil {
			_ = s.db.AddExecutionHistory(res)
		}
	})
	okCount := 0
	for _, r := range results {
		if r.Success {
			okCount++
		}
	}
	s.addLog("[CRON] Selesai menceklis otomatis %d/%d level tugas.", okCount, len(results))
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
