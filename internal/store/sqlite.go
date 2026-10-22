package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"auto-checker/internal/algonova"
)

// LogRecord merepresentasikan 1 baris log aktivitas di tabel activity_logs.
type LogRecord struct {
	ID        int64  `json:"id"`
	Time      string `json:"time"`
	Message   string `json:"message"`
	CreatedAt string `json:"createdAt"`
}

// HistoryRecord merepresentasikan 1 baris riwayat eksekusi di tabel execution_history.
type HistoryRecord struct {
	ID                int64  `json:"id"`
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

// Store mengelola penyimpanan SQLite untuk user, session, cookie Algonova, pengaturan, dan log audit.
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
	// Gunakan 1 koneksi tulis terpusat + WAL mode untuk mencegah SQLITE_BUSY pada akses konkuren
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) migrate() error {
	queries := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS dashboard_sessions (
			token TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS algonova_cookies (
			name TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			domain TEXT NOT NULL,
			path TEXT NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS app_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS activity_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			time_label TEXT NOT NULL,
			message TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS execution_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
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

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("sqlite migration failed: %w", err)
		}
	}
	return nil
}

// EnsureAdminUser membuat atau memperbarui user admin Web Dashboard dengan password ter-hash (bcrypt).
func (s *Store) EnsureAdminUser(username, plainPassword string) error {
	username = strings.TrimSpace(username)
	if username == "" || plainPassword == "" {
		return nil
	}

	var existingHash string
	err := s.db.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, username).Scan(&existingHash)
	if err == nil {
		if bcrypt.CompareHashAndPassword([]byte(existingHash), []byte(plainPassword)) == nil {
			return nil
		}
	}

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO users (username, password_hash, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			password_hash = excluded.password_hash,
			updated_at = excluded.updated_at
	`, username, string(hashBytes), time.Now().UTC())
	return err
}

// VerifyUser memeriksa apakah username dan password cocok dengan data di tabel users.
func (s *Store) VerifyUser(username, plainPassword string) bool {
	var hash string
	err := s.db.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, strings.TrimSpace(username)).Scan(&hash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword)) == nil
}

// CreateSession membuat token sesi acak kriptografis 32-byte dan menyimpannya ke dashboard_sessions.
func (s *Store) CreateSession(username string, ttl time.Duration) (string, error) {
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
		INSERT INTO dashboard_sessions (token, username, expires_at, created_at)
		VALUES (?, ?, ?, ?)
	`, token, username, exp, now)
	if err != nil {
		return "", err
	}
	return token, nil
}

// ValidateSession memeriksa apakah token sesi masih valid dan belum expired.
func (s *Store) ValidateSession(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	var username string
	var expiresAt time.Time
	err := s.db.QueryRow(`SELECT username, expires_at FROM dashboard_sessions WHERE token = ?`, token).Scan(&username, &expiresAt)
	if err != nil {
		return "", false
	}
	if time.Now().UTC().After(expiresAt) {
		_, _ = s.db.Exec(`DELETE FROM dashboard_sessions WHERE token = ?`, token)
		return "", false
	}
	return username, true
}

// DeleteSession menghapus token sesi saat user melakukan Logout.
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM dashboard_sessions WHERE token = ?`, strings.TrimSpace(token))
	return err
}

// SaveAlgonovaCookies menyimpan daftar cookie sesi Algonova ke dalam tabel algonova_cookies.
func (s *Store) SaveAlgonovaCookies(cookies []algonova.SavedCookie) error {
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
			INSERT INTO algonova_cookies (name, value, domain, path, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET
				value = excluded.value,
				domain = excluded.domain,
				path = excluded.path,
				updated_at = excluded.updated_at
		`, ck.Name, ck.Value, domain, path, now)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadAlgonovaCookies mengambil seluruh cookie sesi Algonova yang tersimpan di SQLite.
func (s *Store) LoadAlgonovaCookies() ([]algonova.SavedCookie, error) {
	rows, err := s.db.Query(`SELECT name, value, domain, path FROM algonova_cookies ORDER BY name ASC`)
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

// SetSetting menyimpan pasangan key-value konfigurasi ke tabel app_settings.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO app_settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at
	`, key, value, time.Now().UTC())
	return err
}

// GetSetting membaca nilai konfigurasi dari tabel app_settings atau mengembalikan fallback jika belum ada.
func (s *Store) GetSetting(key, fallback string) string {
	var val string
	if err := s.db.QueryRow(`SELECT value FROM app_settings WHERE key = ?`, key).Scan(&val); err != nil {
		return fallback
	}
	return val
}

// AddLog mencatat 1 baris log aktivitas ke tabel activity_logs dan menjaga jumlah baris maksimal 500.
func (s *Store) AddLog(timeLabel, message string) error {
	_, err := s.db.Exec(`
		INSERT INTO activity_logs (time_label, message, created_at)
		VALUES (?, ?, ?)
	`, timeLabel, message, time.Now().UTC())
	if err != nil {
		return err
	}
	_, _ = s.db.Exec(`
		DELETE FROM activity_logs
		WHERE id NOT IN (
			SELECT id FROM activity_logs ORDER BY id DESC LIMIT 500
		)
	`)
	return nil
}

// GetRecentLogs mengambil log aktivitas terbaru secara berurutan (lama -> baru) untuk ditampilkan di UI.
func (s *Store) GetRecentLogs(limit int) ([]LogRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
		SELECT id, time_label, message, created_at
		FROM (
			SELECT id, time_label, message, created_at
			FROM activity_logs
			ORDER BY id DESC
			LIMIT ?
		)
		ORDER BY id ASC
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LogRecord
	for rows.Next() {
		var r LogRecord
		var createdAt time.Time
		if err := rows.Scan(&r.ID, &r.Time, &r.Message, &createdAt); err != nil {
			return nil, err
		}
		r.CreatedAt = createdAt.Local().Format("2006-01-02 15:04:05")
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddExecutionHistory mencatat hasil eksekusi checklist 1 level ke tabel execution_history.
func (s *Store) AddExecutionHistory(res algonova.CheckResult) error {
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
			group_id, group_title, student_id, student_name,
			lesson_id, task_id, task_title, level_id, level_position, level_title,
			objectives_checked, dry_run, success, error, checked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
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

// GetExecutionHistory mengambil daftar riwayat eksekusi terbaru (baru -> lama).
func (s *Store) GetExecutionHistory(limit int) ([]HistoryRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
		SELECT
			id, group_id, group_title, student_id, student_name,
			lesson_id, task_id, task_title, level_id, level_position, level_title,
			objectives_checked, dry_run, success, error, checked_at
		FROM execution_history
		ORDER BY id DESC
		LIMIT ?
	`, limit)
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
			&h.ID, &h.GroupID, &h.GroupTitle, &h.StudentID, &h.StudentName,
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
