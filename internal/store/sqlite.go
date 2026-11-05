package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"auto-checker/internal/algonova"
)

// User merepresentasikan akun pengguna (admin atau guru) pada auto-checker.
type User struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayName"`
	Role        string    `json:"role"` // "admin" atau "teacher"
	IsActive    bool      `json:"isActive"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// LogRecord merepresentasikan 1 baris log aktivitas di tabel activity_logs.
type LogRecord struct {
	ID        int64  `json:"id"`
	UserID    int64  `json:"userId"`
	Time      string `json:"time"`
	Message   string `json:"message"`
	CreatedAt string `json:"createdAt"`
}

// HistoryRecord merepresentasikan 1 baris riwayat eksekusi di tabel execution_history.
type HistoryRecord struct {
	ID                int64  `json:"id"`
	UserID            int64  `json:"userId"`
	GroupID           int    `json:"groupId"`
	GroupTitle        string `json:"groupTitle"`
	StudentID         int    `json:"studentId"`
	StudentName       string `json:"studentName"`
	LessonID          int    `json:"lessonId"`
	TaskID            int    `json:"taskId"`
	TaskTitle         string `json:"taskTitle"`
	LevelID           int    `json:"levelId"`
	LevelPosition     int    `json:"levelPosition"`
	LevelTitle        string `json:"levelTitle"`
	ObjectivesChecked int    `json:"objectivesChecked"`
	DryRun            bool   `json:"dryRun"`
	Success           bool   `json:"success"`
	Error             string `json:"error,omitempty"`
	CheckedAt         string `json:"checkedAt"`
}

// Store mengelola penyimpanan SQLite untuk pengguna multi-tenant, sesi, cookie Algonova, pengaturan, dan log audit.
type Store struct {
	db *sql.DB
}

// NewSQLiteStore membuka atau membuat file database SQLite dan menjalankan migrasi skema otomatis.
func NewSQLiteStore(dbPath string) (*Store, error) {
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("create db dir %q: %w", dir, err)
			}
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", dbPath, err)
	}
	// Gunakan 1 koneksi terpusat + WAL mode untuk integritas data SQLite
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func parseDBTime(ns sql.NullString) time.Time {
	if !ns.Valid || strings.TrimSpace(ns.String) == "" {
		return time.Now().UTC()
	}
	s := strings.TrimSpace(ns.String)
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Now().UTC()
}

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func hasColumn(db *sql.DB, tableName, colName string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, colName) {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) migrate() error {
	initQueries := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'teacher',
			display_name TEXT NOT NULL DEFAULT '',
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS dashboard_sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL DEFAULT 1,
			username TEXT NOT NULL,
			ip_address TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS user_algonova_cookies (
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			domain TEXT NOT NULL,
			path TEXT NOT NULL,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY (user_id, name)
		);`,
		`CREATE TABLE IF NOT EXISTS user_settings (
			user_id INTEGER NOT NULL,
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY (user_id, key)
		);`,
		`CREATE TABLE IF NOT EXISTS activity_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL DEFAULT 1,
			time_label TEXT NOT NULL,
			message TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS execution_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL DEFAULT 1,
			group_id INTEGER NOT NULL,
			group_title TEXT NOT NULL,
			student_id INTEGER NOT NULL,
			student_name TEXT NOT NULL,
			lesson_id INTEGER NOT NULL,
			task_id INTEGER NOT NULL,
			task_title TEXT NOT NULL,
			level_id INTEGER NOT NULL,
			level_position INTEGER NOT NULL,
			level_title TEXT NOT NULL,
			objectives_checked INTEGER NOT NULL,
			dry_run INTEGER NOT NULL,
			success INTEGER NOT NULL,
			error TEXT NOT NULL,
			checked_at DATETIME NOT NULL
		);`,
	}

	for _, q := range initQueries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("sqlite init query failed: %w", err)
		}
	}

	// Dynamic column checks and migrations for existing databases
	if has, _ := hasColumn(s.db, "users", "role"); !has {
		_, _ = s.db.Exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'teacher'`)
	}
	if has, _ := hasColumn(s.db, "users", "display_name"); !has {
		_, _ = s.db.Exec(`ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`)
	}
	if has, _ := hasColumn(s.db, "users", "is_active"); !has {
		_, _ = s.db.Exec(`ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1`)
	}
	if has, _ := hasColumn(s.db, "users", "created_at"); !has {
		_, _ = s.db.Exec(`ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT '2026-01-01 00:00:00'`)
	}

	// Backfill existing user records
	_, _ = s.db.Exec(`UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL OR created_at = ''`)
	_, _ = s.db.Exec(`UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL OR updated_at = ''`)
	_, _ = s.db.Exec(`UPDATE users SET role = 'admin' WHERE id = 1 AND (role IS NULL OR role = '' OR role = 'teacher')`)

	if has, _ := hasColumn(s.db, "dashboard_sessions", "user_id"); !has {
		_, _ = s.db.Exec(`ALTER TABLE dashboard_sessions ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1`)
	}
	if has, _ := hasColumn(s.db, "dashboard_sessions", "ip_address"); !has {
		_, _ = s.db.Exec(`ALTER TABLE dashboard_sessions ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''`)
	}
	if has, _ := hasColumn(s.db, "dashboard_sessions", "user_agent"); !has {
		_, _ = s.db.Exec(`ALTER TABLE dashboard_sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`)
	}

	if has, _ := hasColumn(s.db, "activity_logs", "user_id"); !has {
		_, _ = s.db.Exec(`ALTER TABLE activity_logs ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1`)
	}
	if has, _ := hasColumn(s.db, "execution_history", "user_id"); !has {
		_, _ = s.db.Exec(`ALTER TABLE execution_history ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1`)
	}

	// Create indices for fast multi-tenant queries
	_, _ = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON activity_logs (user_id, id DESC)`)
	_, _ = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_execution_history_user ON execution_history (user_id, id DESC)`)
	_, _ = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON dashboard_sessions (user_id)`)

	// Data migration from old single-user tables to user_id = 1 if applicable
	var oldCookieCount int
	_ = s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='algonova_cookies'`).Scan(&oldCookieCount)
	if oldCookieCount > 0 {
		var newCount int
		_ = s.db.QueryRow(`SELECT count(*) FROM user_algonova_cookies WHERE user_id = 1`).Scan(&newCount)
		if newCount == 0 {
			_, _ = s.db.Exec(`INSERT OR IGNORE INTO user_algonova_cookies (user_id, name, value, domain, path, updated_at)
				SELECT 1, name, value, domain, path, updated_at FROM algonova_cookies`)
		}
	}

	var oldSettingsCount int
	_ = s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='app_settings'`).Scan(&oldSettingsCount)
	if oldSettingsCount > 0 {
		var newSettingsCount int
		_ = s.db.QueryRow(`SELECT count(*) FROM user_settings WHERE user_id = 1`).Scan(&newSettingsCount)
		if newSettingsCount == 0 {
			_, _ = s.db.Exec(`INSERT OR IGNORE INTO user_settings (user_id, key, value, updated_at)
				SELECT 1, key, value, updated_at FROM app_settings`)
		}
	}

	return nil
}

// EnsureAdminUser membuat atau memperbarui user admin Web Dashboard dengan role "admin".
func (s *Store) EnsureAdminUser(username, plainPassword string) (*User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || plainPassword == "" {
		return nil, errors.New("username dan password tidak boleh kosong")
	}

	var u User
	var existingHash string
	var role, disp sql.NullString
	var isActive sql.NullInt64
	var created, updated sql.NullString
	now := time.Now().UTC()
	err := s.db.QueryRow(`
		SELECT id, username, password_hash, COALESCE(role, 'admin'), COALESCE(display_name, username),
		       COALESCE(is_active, 1), created_at, updated_at
		FROM users WHERE username = ?
	`, username).Scan(&u.ID, &u.Username, &existingHash, &role, &disp, &isActive, &created, &updated)

	if err == nil {
		// User sudah ada, verifikasi apakah password cocok
		if bcrypt.CompareHashAndPassword([]byte(existingHash), []byte(plainPassword)) == nil {
			// Pastikan role tetap admin dan aktif
			if role.String != "admin" || isActive.Int64 != 1 {
				_, _ = s.db.Exec(`UPDATE users SET role = 'admin', is_active = 1, updated_at = ? WHERE id = ?`, now, u.ID)
			}
			return s.GetUserByID(u.ID)
		}
	}

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	displayName := username
	if disp.Valid && disp.String != "" {
		displayName = disp.String
	}

	res, err := s.db.Exec(`
		INSERT INTO users (username, password_hash, role, display_name, is_active, created_at, updated_at)
		VALUES (?, ?, 'admin', ?, 1, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			password_hash = excluded.password_hash,
			role = 'admin',
			is_active = 1,
			updated_at = excluded.updated_at
	`, username, string(hashBytes), displayName, now, now)
	if err != nil {
		return nil, err
	}

	id, _ := res.LastInsertId()
	if id == 0 && u.ID != 0 {
		id = u.ID
	}
	return s.GetUserByID(id)
}

// AuthenticateUser memverifikasi username dan password. Jika valid dan aktif, mengembalikan struct User.
func (s *Store) AuthenticateUser(username, plainPassword string) (*User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	var u User
	var hash string
	var role, disp sql.NullString
	var isActive sql.NullInt64
	var created, updated sql.NullString
	err := s.db.QueryRow(`
		SELECT id, username, password_hash, COALESCE(role, 'teacher'), COALESCE(display_name, username),
		       COALESCE(is_active, 1), created_at, updated_at
		FROM users WHERE username = ?
	`, username).Scan(&u.ID, &u.Username, &hash, &role, &disp, &isActive, &created, &updated)
	if err != nil {
		return nil, errors.New("username atau password salah")
	}

	if isActive.Int64 != 1 {
		return nil, errors.New("akun Anda telah dinonaktifkan oleh administrator")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword)); err != nil {
		return nil, errors.New("username atau password salah")
	}
	u.Role = role.String
	u.DisplayName = disp.String
	u.IsActive = true
	u.CreatedAt = parseDBTime(created)
	u.UpdatedAt = parseDBTime(updated)
	return &u, nil
}

// VerifyUser mempertahankan kompatibilitas lama (boolean).
func (s *Store) VerifyUser(username, plainPassword string) bool {
	u, err := s.AuthenticateUser(username, plainPassword)
	return err == nil && u != nil
}

// GetUserByID mengambil user berdasarkan ID.
func (s *Store) GetUserByID(id int64) (*User, error) {
	var u User
	var role, disp sql.NullString
	var isActive sql.NullInt64
	var created, updated sql.NullString
	err := s.db.QueryRow(`
		SELECT id, username, COALESCE(role, 'teacher'), COALESCE(display_name, username),
		       COALESCE(is_active, 1), created_at, updated_at
		FROM users WHERE id = ?
	`, id).Scan(&u.ID, &u.Username, &role, &disp, &isActive, &created, &updated)
	if err != nil {
		return nil, err
	}
	u.Role = role.String
	u.DisplayName = disp.String
	u.IsActive = isActive.Int64 == 1
	u.CreatedAt = parseDBTime(created)
	u.UpdatedAt = parseDBTime(updated)
	return &u, nil
}

// GetUserByUsername mengambil user berdasarkan username.
func (s *Store) GetUserByUsername(username string) (*User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	var u User
	var role, disp sql.NullString
	var isActive sql.NullInt64
	var created, updated sql.NullString
	err := s.db.QueryRow(`
		SELECT id, username, COALESCE(role, 'teacher'), COALESCE(display_name, username),
		       COALESCE(is_active, 1), created_at, updated_at
		FROM users WHERE username = ?
	`, username).Scan(&u.ID, &u.Username, &role, &disp, &isActive, &created, &updated)
	if err != nil {
		return nil, err
	}
	u.Role = role.String
	u.DisplayName = disp.String
	u.IsActive = isActive.Int64 == 1
	u.CreatedAt = parseDBTime(created)
	u.UpdatedAt = parseDBTime(updated)
	return &u, nil
}

// ListUsers mengambil seluruh daftar user untuk keperluan panel admin.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`
		SELECT id, username, COALESCE(role, 'teacher'), COALESCE(display_name, username),
		       COALESCE(is_active, 1), created_at, updated_at
		FROM users ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var role, disp sql.NullString
		var isActive sql.NullInt64
		var created, updated sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &role, &disp, &isActive, &created, &updated); err != nil {
			return nil, err
		}
		u.Role = role.String
		u.DisplayName = disp.String
		u.IsActive = isActive.Int64 == 1
		u.CreatedAt = parseDBTime(created)
		u.UpdatedAt = parseDBTime(updated)
		users = append(users, u)
	}
	return users, rows.Err()
}

// CreateUser menambahkan pengguna baru (dilakukan oleh Admin).
func (s *Store) CreateUser(username, displayName, plainPassword, role string) (*User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if len(username) < 3 || len(username) > 32 {
		return nil, errors.New("username harus 3 - 32 karakter")
	}
	if len(plainPassword) < 8 {
		return nil, errors.New("password minimal 8 karakter")
	}
	if role != "admin" {
		role = "teacher"
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = username
	}

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	res, err := s.db.Exec(`
		INSERT INTO users (username, password_hash, role, display_name, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, ?, ?)
	`, username, string(hashBytes), role, displayName, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("username %q sudah digunakan", username)
		}
		return nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.GetUserByID(id)
}

// UpdateUserPassword mengubah password user tertentu.
func (s *Store) UpdateUserPassword(userID int64, newPlainPassword string) error {
	if len(newPlainPassword) < 8 {
		return errors.New("password baru minimal 8 karakter")
	}
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(newPlainPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, string(hashBytes), now, userID)
	return err
}

// UpdateUserStatus mengaktifkan / menonaktifkan akun user.
func (s *Store) UpdateUserStatus(userID int64, isActive bool) error {
	now := time.Now().UTC()
	val := 0
	if isActive {
		val = 1
	}
	_, err := s.db.Exec(`UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?`, val, now, userID)
	if err != nil {
		return err
	}
	if !isActive {
		_ = s.DeleteUserSessions(userID)
	}
	return nil
}

// DeleteUser menghapus user beserta seluruh data terisolasi miliknya (cascade).
func (s *Store) DeleteUser(userID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, _ = tx.Exec(`DELETE FROM dashboard_sessions WHERE user_id = ?`, userID)
	_, _ = tx.Exec(`DELETE FROM user_algonova_cookies WHERE user_id = ?`, userID)
	_, _ = tx.Exec(`DELETE FROM user_settings WHERE user_id = ?`, userID)
	_, _ = tx.Exec(`DELETE FROM activity_logs WHERE user_id = ?`, userID)
	_, _ = tx.Exec(`DELETE FROM execution_history WHERE user_id = ?`, userID)
	_, err = tx.Exec(`DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// CreateSession membuat token sesi acak kriptografis 32-byte dan menyimpannya ke dashboard_sessions.
func (s *Store) CreateSession(username string, ttl time.Duration) (string, error) {
	u, err := s.GetUserByUsername(username)
	if err != nil {
		return "", err
	}
	return s.CreateUserSession(u.ID, u.Username, ttl, "", "")
}

// CreateUserSession membuat token sesi lengkap dengan user_id, ip, dan user-agent.
func (s *Store) CreateUserSession(userID int64, username string, ttl time.Duration, ip, userAgent string) (string, error) {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	now := time.Now().UTC()
	exp := now.Add(ttl)

	// Bersihkan sesi yang sudah expired terlebih dahulu
	_, _ = s.db.Exec(`DELETE FROM dashboard_sessions WHERE expires_at <= ?`, now)

	_, err := s.db.Exec(`
		INSERT INTO dashboard_sessions (token, user_id, username, ip_address, user_agent, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, token, userID, username, ip, userAgent, exp, now)
	if err != nil {
		return "", err
	}
	return token, nil
}

// ValidateSession memeriksa apakah token sesi valid dan user masih aktif. Mengembalikan username dan bool (kompatibel).
func (s *Store) ValidateSession(token string) (string, bool) {
	u, ok := s.ValidateUserSession(token)
	if !ok || u == nil {
		return "", false
	}
	return u.Username, true
}

// ValidateUserSession memeriksa token dan mengembalikan struct *User lengkap jika valid dan aktif.
func (s *Store) ValidateUserSession(token string) (*User, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}
	var u User
	var role, disp sql.NullString
	var isActive sql.NullInt64
	var created, updated sql.NullString
	var expiresAt time.Time
	err := s.db.QueryRow(`
		SELECT u.id, u.username, COALESCE(u.role, 'teacher'), COALESCE(u.display_name, u.username),
		       COALESCE(u.is_active, 1), u.created_at, u.updated_at, s.expires_at
		FROM dashboard_sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.token = ?
	`, token).Scan(&u.ID, &u.Username, &role, &disp, &isActive, &created, &updated, &expiresAt)
	if err != nil {
		return nil, false
	}

	if time.Now().UTC().After(expiresAt) {
		_, _ = s.db.Exec(`DELETE FROM dashboard_sessions WHERE token = ?`, token)
		return nil, false
	}

	if isActive.Int64 != 1 {
		_, _ = s.db.Exec(`DELETE FROM dashboard_sessions WHERE token = ?`, token)
		return nil, false
	}

	u.Role = role.String
	u.DisplayName = disp.String
	u.IsActive = true
	u.CreatedAt = parseDBTime(created)
	u.UpdatedAt = parseDBTime(updated)
	return &u, true
}

// DeleteSession menghapus token sesi saat user melakukan Logout.
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM dashboard_sessions WHERE token = ?`, strings.TrimSpace(token))
	return err
}

// DeleteUserSessions menghapus seluruh sesi aktif milik user tertentu.
func (s *Store) DeleteUserSessions(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM dashboard_sessions WHERE user_id = ?`, userID)
	return err
}

// SaveUserAlgonovaCookies menyimpan daftar cookie sesi Algonova khusus untuk user tertentu.
func (s *Store) SaveUserAlgonovaCookies(userID int64, cookies []algonova.SavedCookie) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	for _, ck := range cookies {
		if strings.TrimSpace(ck.Name) == "" {
			continue
		}
		domain := ck.Domain
		if domain == "" {
			domain = "lms.algonova.id"
		}
		path := ck.Path
		if path == "" {
			path = "/"
		}
		_, err := tx.Exec(`
			INSERT INTO user_algonova_cookies (user_id, name, value, domain, path, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(user_id, name) DO UPDATE SET
				value = excluded.value,
				domain = excluded.domain,
				path = excluded.path,
				updated_at = excluded.updated_at
		`, userID, ck.Name, ck.Value, domain, path, now)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadUserAlgonovaCookies mengambil seluruh cookie sesi Algonova milik user tertentu.
func (s *Store) LoadUserAlgonovaCookies(userID int64) ([]algonova.SavedCookie, error) {
	rows, err := s.db.Query(`
		SELECT name, value, domain, path
		FROM user_algonova_cookies
		WHERE user_id = ?
		ORDER BY name ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []algonova.SavedCookie
	for rows.Next() {
		var ck algonova.SavedCookie
		if err := rows.Scan(&ck.Name, &ck.Value, &ck.Domain, &ck.Path); err != nil {
			return nil, err
		}
		out = append(out, ck)
	}
	return out, rows.Err()
}

// SaveAlgonovaCookies kompatibilitas lama (tersimpan ke user_id = 1).
func (s *Store) SaveAlgonovaCookies(cookies []algonova.SavedCookie) error {
	return s.SaveUserAlgonovaCookies(1, cookies)
}

// LoadAlgonovaCookies kompatibilitas lama (terbaca dari user_id = 1).
func (s *Store) LoadAlgonovaCookies() ([]algonova.SavedCookie, error) {
	return s.LoadUserAlgonovaCookies(1)
}

// SetUserSetting menyimpan pasangan key-value konfigurasi untuk user tertentu.
func (s *Store) SetUserSetting(userID int64, key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO user_settings (user_id, key, value, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id, key) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at
	`, userID, key, value, time.Now().UTC())
	return err
}

// GetUserSetting membaca nilai konfigurasi untuk user tertentu atau mengembalikan fallback.
func (s *Store) GetUserSetting(userID int64, key, fallback string) string {
	var val string
	if err := s.db.QueryRow(`SELECT value FROM user_settings WHERE user_id = ? AND key = ?`, userID, key).Scan(&val); err != nil {
		return fallback
	}
	return val
}

// SetSetting kompatibilitas lama (tersimpan ke user_id = 1).
func (s *Store) SetSetting(key, value string) error {
	return s.SetUserSetting(1, key, value)
}

// GetSetting kompatibilitas lama (terbaca dari user_id = 1).
func (s *Store) GetSetting(key, fallback string) string {
	return s.GetUserSetting(1, key, fallback)
}

// ListUsersWithCronEnabled mengambil ID semua user aktif yang mengaktifkan scheduler otomatis.
func (s *Store) ListUsersWithCronEnabled() ([]int64, error) {
	rows, err := s.db.Query(`
		SELECT s.user_id
		FROM user_settings s
		JOIN users u ON s.user_id = u.id
		WHERE u.is_active = 1 AND s.key = 'cron_enabled' AND s.value = 'true'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

// AddUserLog mencatat log aktivitas untuk user tertentu (dibatasi 300 per user).
func (s *Store) AddUserLog(userID int64, timeLabel, message string) error {
	_, err := s.db.Exec(`
		INSERT INTO activity_logs (user_id, time_label, message, created_at)
		VALUES (?, ?, ?, ?)
	`, userID, timeLabel, message, time.Now().UTC())
	if err != nil {
		return err
	}
	_, _ = s.db.Exec(`
		DELETE FROM activity_logs
		WHERE user_id = ? AND id NOT IN (
			SELECT id FROM activity_logs WHERE user_id = ? ORDER BY id DESC LIMIT 300
		)
	`, userID, userID)
	return nil
}

// GetUserRecentLogs mengambil log aktivitas terbaru milik user tertentu.
func (s *Store) GetUserRecentLogs(userID int64, limit int) ([]LogRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
		SELECT id, user_id, time_label, message, created_at
		FROM (
			SELECT id, user_id, time_label, message, created_at
			FROM activity_logs
			WHERE user_id = ?
			ORDER BY id DESC
			LIMIT ?
		)
		ORDER BY id ASC
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LogRecord
	for rows.Next() {
		var r LogRecord
		var createdAt time.Time
		if err := rows.Scan(&r.ID, &r.UserID, &r.Time, &r.Message, &createdAt); err != nil {
			return nil, err
		}
		r.CreatedAt = createdAt.Local().Format("2006-01-02 15:04:05")
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddLog kompatibilitas lama (tersimpan ke user_id = 1).
func (s *Store) AddLog(timeLabel, message string) error {
	return s.AddUserLog(1, timeLabel, message)
}

// GetRecentLogs kompatibilitas lama (terbaca dari user_id = 1).
func (s *Store) GetRecentLogs(limit int) ([]LogRecord, error) {
	return s.GetUserRecentLogs(1, limit)
}

// AddUserExecutionHistory mencatat hasil eksekusi checklist 1 level ke execution_history milik user tertentu.
func (s *Store) AddUserExecutionHistory(userID int64, res algonova.CheckResult) error {
	dryInt := 0
	if res.DryRun {
		dryInt = 1
	}
	succInt := 0
	if res.Success {
		succInt = 1
	}

	_, err := s.db.Exec(`
		INSERT INTO execution_history (
			user_id, group_id, group_title, student_id, student_name,
			lesson_id, task_id, task_title, level_id, level_position, level_title,
			objectives_checked, dry_run, success, error, checked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		userID,
		res.Item.GroupID,
		res.Item.GroupTitle,
		res.Item.StudentID,
		res.Item.StudentName,
		res.Item.LessonID,
		res.Item.TaskID,
		res.Item.TaskTitle,
		res.Item.LevelID,
		res.Item.LevelPosition,
		res.Item.LevelTitle,
		res.ObjectivesChecked,
		dryInt,
		succInt,
		res.Error,
		res.CheckedAt.UTC(),
	)
	return err
}

// GetUserExecutionHistory mengambil daftar riwayat eksekusi terbaru milik user tertentu.
func (s *Store) GetUserExecutionHistory(userID int64, limit int) ([]HistoryRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
		SELECT
			id, user_id, group_id, group_title, student_id, student_name,
			lesson_id, task_id, task_title, level_id, level_position, level_title,
			objectives_checked, dry_run, success, error, checked_at
		FROM execution_history
		WHERE user_id = ?
		ORDER BY id DESC
		LIMIT ?
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HistoryRecord
	for rows.Next() {
		var h HistoryRecord
		var dryInt, succInt int
		var checkedAt time.Time
		if err := rows.Scan(
			&h.ID, &h.UserID, &h.GroupID, &h.GroupTitle, &h.StudentID, &h.StudentName,
			&h.LessonID, &h.TaskID, &h.TaskTitle, &h.LevelID, &h.LevelPosition, &h.LevelTitle,
			&h.ObjectivesChecked, &dryInt, &succInt, &h.Error, &checkedAt,
		); err != nil {
			return nil, err
		}
		h.DryRun = dryInt == 1
		h.Success = succInt == 1
		h.CheckedAt = checkedAt.Local().Format("2006-01-02 15:04:05")
		out = append(out, h)
	}
	return out, rows.Err()
}

// AddExecutionHistory kompatibilitas lama (tersimpan ke user_id = 1).
func (s *Store) AddExecutionHistory(res algonova.CheckResult) error {
	return s.AddUserExecutionHistory(1, res)
}

// GetExecutionHistory kompatibilitas lama (terbaca dari user_id = 1).
func (s *Store) GetExecutionHistory(limit int) ([]HistoryRecord, error) {
	return s.GetUserExecutionHistory(1, limit)
}
