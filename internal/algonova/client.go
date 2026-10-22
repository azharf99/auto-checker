package algonova

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"auto-checker/internal/config"
)

// SavedCookie digunakan untuk menyimpan/memuat cookie dari file JSON lokal atau SQLite.
type SavedCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// CookieStore adalah kontrak penyimpanan cookie sesi Algonova (mis. diimplementasikan oleh SQLite Store).
type CookieStore interface {
	SaveAlgonovaCookies(cookies []SavedCookie) error
	LoadAlgonovaCookies() ([]SavedCookie, error)
}

// Client mengelola komunikasi HTTP ke LMS Algonova beserta sesi cookie, rate-limiting, dan exponential backoff.
type Client struct {
	cfg         *config.Config
	httpClient  *http.Client
	baseURL     *url.URL
	cookieStore CookieStore

	rateMu  sync.Mutex
	lastReq time.Time

	cacheMu      sync.RWMutex
	studentNames map[int]map[int]string // groupID -> studentID -> fullName
	groupTitles  map[int]string         // groupID -> title

	// BaseBackoff dapat dikustomisasi pada unit test (default 2500ms sesuai frontend Algonova).
	BaseBackoff time.Duration
}

// NewClient menginisialisasi Client Algonova beserta CookieJar.
func NewClient(cfg *config.Config) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL %q: %w", cfg.BaseURL, err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	c := &Client{
		cfg:     cfg,
		baseURL: u,
		httpClient: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if strings.Contains(req.URL.Path, "/auth/v3/login") {
					return http.ErrUseLastResponse
				}
				if len(via) >= 10 {
					return errors.New("stopped after 10 redirects")
				}
				return nil
			},
		},
		studentNames: make(map[int]map[int]string),
		groupTitles:  make(map[int]string),
		BaseBackoff:  2500 * time.Millisecond,
	}

	if cfg.CookieFile != "" {
		_ = c.LoadCookiesFromFile(cfg.CookieFile)
	}
	if strings.TrimSpace(cfg.RawCookies) != "" {
		c.SetRawCookies(cfg.RawCookies)
	}

	return c, nil
}

// AttachCookieStore menghubungkan Client dengan SQLite CookieStore, memuat cookie dari DB,
// dan otomatis memigrasikan cookie dari file JSON ke DB jika DB masih kosong.
func (c *Client) AttachCookieStore(cs CookieStore) {
	if cs == nil {
		return
	}
	c.cookieStore = cs
	saved, err := cs.LoadAlgonovaCookies()
	if err == nil && len(saved) > 0 {
		var cookies []*http.Cookie
		for _, sc := range saved {
			if sc.Name == "" {
				continue
			}
			cookies = append(cookies, &http.Cookie{
				Name:  sc.Name,
				Value: sc.Value,
				Path:  "/",
			})
		}
		if len(cookies) > 0 {
			c.httpClient.Jar.SetCookies(c.baseURL, cookies)
		}
		return
	}
	// Jika DB belum punya cookie tapi CookieJar sudah memuat dari cookies.json / .env, simpan ke DB
	_ = c.PersistCookies()
}

// SetRawCookies mem-parsing string header Cookie (mis. "a=1; b=2") ke dalam CookieJar dan menyimpannya ke DB.
func (c *Client) SetRawCookies(raw string) {
	parts := strings.Split(raw, ";")
	var cookies []*http.Cookie
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:  strings.TrimSpace(kv[0]),
			Value: strings.TrimSpace(kv[1]),
			Path:  "/",
		})
	}
	if len(cookies) > 0 {
		c.httpClient.Jar.SetCookies(c.baseURL, cookies)
		_ = c.PersistCookies()
	}
}

// LoadCookiesFromFile memuat daftar cookie dari file JSON.
func (c *Client) LoadCookiesFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var saved []SavedCookie
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	var cookies []*http.Cookie
	for _, sc := range saved {
		if sc.Name == "" {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:  sc.Name,
			Value: sc.Value,
			Path:  "/",
		})
	}
	if len(cookies) > 0 {
		c.httpClient.Jar.SetCookies(c.baseURL, cookies)
	}
	return nil
}

// PersistCookies menyimpan cookie aktif ke SQLite (jika terhubung) dan ke file cadangan JSON.
func (c *Client) PersistCookies() error {
	cookies := c.httpClient.Jar.Cookies(c.baseURL)
	var saved []SavedCookie
	for _, ck := range cookies {
		saved = append(saved, SavedCookie{
			Name:   ck.Name,
			Value:  ck.Value,
			Domain: c.baseURL.Hostname(),
			Path:   "/",
		})
	}
	if c.cookieStore != nil && len(saved) > 0 {
		_ = c.cookieStore.SaveAlgonovaCookies(saved)
	}
	if c.cfg.CookieFile != "" && len(saved) > 0 {
		data, err := json.MarshalIndent(saved, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(c.cfg.CookieFile, data, 0600)
	}
	return nil
}

// SaveCookiesToFile menyimpan cookie aktif saat ini ke SQLite & file JSON agar sesi bertahan antar-run.
func (c *Client) SaveCookiesToFile(path string) error {
	return c.PersistCookies()
}

// CurrentCookiesSummary mengembalikan daftar nama cookie yang sedang aktif (untuk diagnostik/UI).
func (c *Client) CurrentCookiesSummary() map[string]string {
	out := make(map[string]string)
	for _, ck := range c.httpClient.Jar.Cookies(c.baseURL) {
		val := ck.Value
		if len(val) > 12 {
			val = val[:6] + "..." + val[len(val)-4:]
		}
		out[ck.Name] = val
	}
	return out
}

// EnsureAuthenticated memastikan sesi cookie valid; jika belum/expired, otomatis login dengan Username & Password.
func (c *Client) EnsureAuthenticated(ctx context.Context) (int, error) {
	count, err := c.GetUnreviewedCount(ctx)
	if err == nil {
		if c.cfg.CookieFile != "" {
			_ = c.SaveCookiesToFile(c.cfg.CookieFile)
		}
		return count, nil
	}

	if c.cfg.Username == "" || c.cfg.Password == "" {
		return 0, fmt.Errorf("session not authenticated (%v) and ALGONOVA_USERNAME/PASSWORD not provided", err)
	}

	if err := c.Login(ctx, c.cfg.Username, c.cfg.Password); err != nil {
		return 0, fmt.Errorf("auto-login failed: %w", err)
	}

	count, err = c.GetUnreviewedCount(ctx)
	if err != nil {
		return 0, fmt.Errorf("session verification after login failed: %w", err)
	}
	return count, nil
}

// Login melakukan autentikasi langsung ke endpoint /s/auth/api/e/user/auth dan menginisialisasi sesi Backoffice.
func (c *Client) Login(ctx context.Context, username, password string) error {
	_ = c.doJSON(ctx, http.MethodPost, "/api/v2/user/exists", map[string]any{
		"login": username,
	}, nil)

	var authResp AuthResponse
	err := c.doJSON(ctx, http.MethodPost, "/s/auth/api/e/user/auth", map[string]any{
		"login":    username,
		"password": password,
		"code":     nil,
	}, &authResp)
	if err != nil {
		return fmt.Errorf("auth request error: %w", err)
	}
	if authResp.Item.Step != "" && authResp.Item.Step != "success" {
		return fmt.Errorf("unexpected auth step %q (2FA or verification required)", authResp.Item.Step)
	}

	_, statusCode, err := c.doRaw(ctx, http.MethodGet, "/group/default/schedule?per-page=1", nil, "text/html,application/xhtml+xml")
	if err != nil {
		return fmt.Errorf("failed initializing backoffice session: %w", err)
	}
	if statusCode >= 400 {
		return fmt.Errorf("backoffice initialization returned HTTP %d", statusCode)
	}

	if c.cfg.CookieFile != "" {
		_ = c.SaveCookiesToFile(c.cfg.CookieFile)
	}
	return nil
}

// GetUnreviewedCount memanggil GET /api/v2/teacher-dashboard/task/unreviewed (Read-Only).
func (c *Client) GetUnreviewedCount(ctx context.Context) (int, error) {
	var env APIEnvelope[UnreviewedCountData]
	if err := c.doJSON(ctx, http.MethodGet, "/api/v2/teacher-dashboard/task/unreviewed", nil, &env); err != nil {
		return 0, err
	}
	if env.Status != "success" {
		return 0, fmt.Errorf("unexpected API status: %s", env.Status)
	}
	return env.Data.Count, nil
}

// waitRateLimit menerapkan jeda antar-request ditambah random jitter (0-40%) agar trafik natural seperti manusia.
func (c *Client) waitRateLimit(ctx context.Context) error {
	baseDelay := c.cfg.RequestDelay
	if baseDelay <= 0 {
		return nil
	}
	// Tambahkan jitter acak hingga +40% dari baseDelay
	jitterMax := int64(baseDelay) * 40 / 100
	var jitter time.Duration
	if jitterMax > 0 {
		jitter = time.Duration(rand.Int64N(jitterMax))
	}
	targetDelay := baseDelay + jitter

	c.rateMu.Lock()
	elapsed := time.Since(c.lastReq)
	wait := targetDelay - elapsed
	if wait > 0 {
		c.lastReq = time.Now().Add(wait)
	} else {
		c.lastReq = time.Now()
	}
	c.rateMu.Unlock()

	if wait > 0 {
		return sleepContext(ctx, wait)
	}
	return nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// computeBackoff menghitung waktu tunggu saat terkena HTTP 429 / 502 / 503 / 504,
// menghormati header Retry-After jika ada, atau menggunakan rumus exponential backoff Algonova (base << attempt, maks 60s).
func (c *Client) computeBackoff(attempt int, retryAfterHeader string) time.Duration {
	if s := strings.TrimSpace(retryAfterHeader); s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
			return time.Duration(secs)*time.Second + 500*time.Millisecond
		}
	}
	base := c.BaseBackoff
	if base <= 0 {
		base = 2500 * time.Millisecond
	}
	shift := attempt
	if shift > 5 {
		shift = 5
	}
	wait := base * time.Duration(1<<shift)
	if wait > 60*time.Second {
		wait = 60 * time.Second
	}
	// Tambahkan sedikit jitter (0..500ms)
	if base >= 100*time.Millisecond {
		wait += time.Duration(rand.Int64N(int64(500 * time.Millisecond)))
	}
	return wait
}

func isRetryableStatus(status int) bool {
	return status == http.StatusTooManyRequests ||
		status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout
}

func (c *Client) doRaw(ctx context.Context, method, pathOrURL string, body any, accept string) ([]byte, int, error) {
	fullURL := pathOrURL
	if !strings.HasPrefix(pathOrURL, "http://") && !strings.HasPrefix(pathOrURL, "https://") {
		if !strings.HasPrefix(pathOrURL, "/") {
			pathOrURL = "/" + pathOrURL
		}
		fullURL = c.cfg.BaseURL + pathOrURL
	}

	var marshaledBody []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request body: %w", err)
		}
		marshaledBody = b
	}

	maxRetries := c.cfg.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	var lastBytes []byte
	var lastStatus int

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := c.waitRateLimit(ctx); err != nil {
			return nil, 0, err
		}

		var bodyReader io.Reader
		if marshaledBody != nil {
			bodyReader = bytes.NewReader(marshaledBody)
		}

		req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
		if err != nil {
			return nil, 0, err
		}

		req.Header.Set("User-Agent", c.cfg.UserAgent)
		if accept != "" {
			req.Header.Set("Accept", accept)
		} else {
			req.Header.Set("Accept", "application/json, text/plain, */*")
		}
		if marshaledBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if strings.HasPrefix(pathOrURL, "/platform/api/") {
			req.Header.Set("X-Singlepage-Version", c.cfg.SinglepageVer)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			// Jika error jaringan sementara dan masih ada kuota retry, lakukan backoff
			if attempt < maxRetries && ctx.Err() == nil {
				wait := c.computeBackoff(attempt, "")
				fmt.Printf("[RATE-LIMIT/NET] Request %s %s gagal (%v). Menunggu %s sebelum retry (%d/%d)...\n",
					method, pathOrURL, err, wait.Round(10*time.Millisecond), attempt+1, maxRetries)
				if err := sleepContext(ctx, wait); err != nil {
					return nil, 0, err
				}
				continue
			}
			return nil, 0, err
		}

		respBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, readErr
		}

		lastBytes = respBytes
		lastStatus = resp.StatusCode

		if isRetryableStatus(resp.StatusCode) && attempt < maxRetries {
			wait := c.computeBackoff(attempt, resp.Header.Get("Retry-After"))
			fmt.Printf("[RATE-LIMIT] Terdeteksi HTTP %d pada %s %s. Menunggu %s sebelum retry (%d/%d)...\n",
				resp.StatusCode, method, pathOrURL, wait.Round(10*time.Millisecond), attempt+1, maxRetries)
			if err := sleepContext(ctx, wait); err != nil {
				return respBytes, resp.StatusCode, err
			}
			continue
		}

		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "/auth/") || strings.Contains(loc, "login") {
				return respBytes, resp.StatusCode, fmt.Errorf("unauthorized (redirected to %s)", loc)
			}
		}

		if bytes.Contains(respBytes, []byte("http-equiv=\"refresh\"")) && bytes.Contains(respBytes, []byte("/auth/v3/login")) {
			return respBytes, http.StatusUnauthorized, errors.New("unauthorized (meta refresh to /auth/v3/login)")
		}

		return respBytes, resp.StatusCode, nil
	}

	return lastBytes, lastStatus, nil
}

func (c *Client) doJSON(ctx context.Context, method, pathOrURL string, reqBody any, out any) error {
	respBytes, statusCode, err := c.doRaw(ctx, method, pathOrURL, reqBody, "application/json, text/plain, */*")
	if err != nil {
		return err
	}
	if statusCode < 200 || statusCode >= 300 {
		snippet := string(respBytes)
		if len(snippet) > 240 {
			snippet = snippet[:240] + "..."
		}
		return fmt.Errorf("HTTP %d from %s %s: %s", statusCode, method, pathOrURL, snippet)
	}
	if out != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, out); err != nil {
			snippet := string(respBytes)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			return fmt.Errorf("decode JSON from %s: %w (body: %s)", pathOrURL, err, snippet)
		}
	}
	return nil
}

// GetStudentName mengembalikan nama lengkap siswa di suatu grup (menggunakan cache in-memory agar hemat request).
func (c *Client) GetStudentName(ctx context.Context, groupID, studentID int) string {
	c.cacheMu.RLock()
	if m, ok := c.studentNames[groupID]; ok {
		if name, found := m[studentID]; found {
			c.cacheMu.RUnlock()
			return name
		}
		c.cacheMu.RUnlock()
		return fmt.Sprintf("Student #%d", studentID)
	}
	c.cacheMu.RUnlock()

	path := fmt.Sprintf("/api/v2/group/student/index?groupId=%d", groupID)
	var env APIEnvelope[GroupStudentIndexData]
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &env); err != nil {
		return fmt.Sprintf("Student #%d", studentID)
	}

	m := make(map[int]string)
	for _, s := range env.Data.Items {
		name := strings.TrimSpace(s.FullName)
		if name == "" {
			name = strings.TrimSpace(s.FirstName + " " + s.LastName)
		}
		if s.FirstName != "" && s.FirstName == s.LastName {
			name = s.FirstName
		}
		m[s.ID] = name
	}

	c.cacheMu.Lock()
	c.studentNames[groupID] = m
	c.cacheMu.Unlock()

	if name, ok := m[studentID]; ok && name != "" {
		return name
	}
	return fmt.Sprintf("Student #%d", studentID)
}

// CacheGroupTitle menyimpan nama grup ke dalam cache.
func (c *Client) CacheGroupTitle(groupID int, title string) {
	if groupID <= 0 || strings.TrimSpace(title) == "" {
		return
	}
	c.cacheMu.Lock()
	c.groupTitles[groupID] = strings.TrimSpace(title)
	c.cacheMu.Unlock()
}

// GetCachedGroupTitle mengambil nama grup dari cache atau mengembalikan fallback "Group #<id>".
func (c *Client) GetCachedGroupTitle(groupID int) string {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	if t, ok := c.groupTitles[groupID]; ok && t != "" {
		return t
	}
	return fmt.Sprintf("Group #%d", groupID)
}
