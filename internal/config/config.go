package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config menyimpan seluruh konfigurasi aplikasi auto-checker.
type Config struct {
	BaseURL        string
	Username       string
	Password       string
	RawCookies     string
	CookieFile     string
	DBPath         string
	DashboardUser  string
	DashboardPass  string
	SessionTTL     time.Duration
	DiscoveryMode  string // "both", "unreviewed", atau "schedule"
	Timeframe      string // "current", "all", "past" (untuk mode schedule)
	GroupIDs       []int  // Filter opsional untuk groupId tertentu
	OnlyScheduled  bool   // Jika true pada mode unreviewed, hanya proses grup yang ada di jadwal aktif
	DryRun         bool   // Jika true, hanya baca/scan tanpa kirim POST perubahan nilai
	RequestDelay   time.Duration
	LevelDelay     time.Duration
	MaxRetries     int
	ServerAddr     string // Contoh: ":8080"
	CronInterval   time.Duration
	EnableCron     bool
	CronAutoExec   bool // Apakah cron otomatis mengeksekusi POST (default false demi keamanan awal)
	SinglepageVer  string
	UserAgent      string
}

// Load membaca file .env (jika ada) dan menggabungkannya dengan environment variables sistem.
func Load(envPath string) *Config {
	if envPath != "" {
		_ = loadDotEnv(envPath)
	}

	algoUser := getEnv("ALGONOVA_USERNAME", "")
	algoPass := getEnv("ALGONOVA_PASSWORD", "")

	dashUser := getEnv("DASHBOARD_USERNAME", algoUser)
	if dashUser == "" {
		dashUser = "admin"
	}
	dashPass := getEnv("DASHBOARD_PASSWORD", algoPass)
	if dashPass == "" {
		dashPass = "admin123"
	}

	cfg := &Config{
		BaseURL:       getEnv("ALGONOVA_BASE_URL", "https://lms.algonova.id"),
		Username:      algoUser,
		Password:      algoPass,
		RawCookies:    getEnv("ALGONOVA_COOKIES", ""),
		CookieFile:    getEnv("ALGONOVA_COOKIE_FILE", "cookies.json"),
		DBPath:        getEnv("DB_PATH", "data/autochecker.db"),
		DashboardUser: dashUser,
		DashboardPass: dashPass,
		SessionTTL:    time.Duration(getEnvInt("SESSION_TTL_HOURS", 168)) * time.Hour,
		DiscoveryMode: getEnv("DISCOVERY_MODE", "unreviewed"),
		Timeframe:     getEnv("SCHEDULE_TIMEFRAME", "current"),
		GroupIDs:      parseIntList(getEnv("GROUP_IDS", "")),
		OnlyScheduled: getEnvBool("ONLY_SCHEDULED_GROUPS", false),
		DryRun:        getEnvBool("DRY_RUN", true),
		RequestDelay:  time.Duration(getEnvInt("REQUEST_DELAY_MS", 650)) * time.Millisecond,
		LevelDelay:    time.Duration(getEnvInt("LEVEL_DELAY_MS", 1500)) * time.Millisecond,
		MaxRetries:    getEnvInt("MAX_RETRIES", 5),
		ServerAddr:    getEnv("SERVER_ADDR", ":8080"),
		CronInterval:  parseDuration(getEnv("CRON_INTERVAL", "6h"), 6*time.Hour),
		EnableCron:    getEnvBool("ENABLE_CRON", false),
		CronAutoExec:  getEnvBool("CRON_AUTO_EXECUTE", false),
		SinglepageVer: getEnv("SINGLEPAGE_VERSION", "2026-10-20T08:30:38.752Z"),
		UserAgent:     getEnv("USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return cfg
}

func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
	return scanner.Err()
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := getEnv(key, "")
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvBool(key string, fallback bool) bool {
	v := strings.ToLower(getEnv(key, ""))
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// ParseGroupIDs mengubah string "2175084,1813549" menjadi slice int.
func ParseGroupIDs(raw string) []int {
	return parseIntList(raw)
}

func parseIntList(raw string) []int {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []int
	seen := make(map[int]bool)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if id, err := strconv.Atoi(part); err == nil && id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
