package store

import (
	"path/filepath"
	"testing"
	"time"

	"auto-checker/internal/algonova"
)

func TestSQLiteStoreLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer st.Close()

	// 1. User Auth & bcrypt
	if err := st.EnsureAdminUser("azharfa", "SecretPass123!"); err != nil {
		t.Fatalf("EnsureAdminUser failed: %v", err)
	}
	if st.VerifyUser("azharfa", "WrongPass") {
		t.Fatalf("expected VerifyUser false for wrong password")
	}
	if !st.VerifyUser("azharfa", "SecretPass123!") {
		t.Fatalf("expected VerifyUser true for correct password")
	}

	// 2. Dashboard Session
	token, err := st.CreateSession("azharfa", 2*time.Hour)
	if err != nil || token == "" {
		t.Fatalf("CreateSession failed: token=%q err=%v", token, err)
	}
	username, valid := st.ValidateSession(token)
	if !valid || username != "azharfa" {
		t.Fatalf("ValidateSession failed: username=%q valid=%v", username, valid)
	}
	if err := st.DeleteSession(token); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}
	_, validAfterDelete := st.ValidateSession(token)
	if validAfterDelete {
		t.Fatalf("expected session invalid after DeleteSession")
	}

	// 3. Algonova Cookies
	err = st.SaveAlgonovaCookies([]algonova.SavedCookie{
		{Name: "_backendMainSessionId", Value: "sess123", Domain: ".algonova.id", Path: "/"},
		{Name: "accessToken", Value: "jwt456", Domain: ".algonova.id", Path: "/"},
	})
	if err != nil {
		t.Fatalf("SaveAlgonovaCookies failed: %v", err)
	}
	cookies, err := st.LoadAlgonovaCookies()
	if err != nil || len(cookies) != 2 {
		t.Fatalf("LoadAlgonovaCookies expected 2 cookies, got %d (err=%v)", len(cookies), err)
	}

	// 4. App Settings
	if err := st.SetSetting("interval_minutes", "120"); err != nil {
		t.Fatalf("SetSetting failed: %v", err)
	}
	if got := st.GetSetting("interval_minutes", "60"); got != "120" {
		t.Fatalf("GetSetting expected 120, got %s", got)
	}

	// 5. Activity Logs & Execution History
	if err := st.AddLog("19:30:00", "Test log entry"); err != nil {
		t.Fatalf("AddLog failed: %v", err)
	}
	logs, err := st.GetRecentLogs(10)
	if err != nil || len(logs) != 1 || logs[0].Message != "Test log entry" {
		t.Fatalf("GetRecentLogs unexpected: %+v (err=%v)", logs, err)
	}

	err = st.AddExecutionHistory(algonova.CheckResult{
		Item: algonova.YellowLevelItem{
			GroupID:        2175084,
			GroupTitle:     "ID-IND-PS-76",
			LessonID:       33163,
			LessonTitle:    "M2L4 Tuple",
			TaskID:         78507,
			LevelID:        1488258,
			LevelTitle:     "Level 1",
			StudentID:      100125754,
			StudentName:    "Siti Khodijah",
			TaskPreviewURL: "https://lms.algonova.id/task-preview/78507",
		},
		DryRun:            false,
		ObjectivesChecked: 4,
		Success:           true,
		CheckedAt:         time.Now(),
	})
	if err != nil {
		t.Fatalf("AddExecutionHistory failed: %v", err)
	}
	hist, err := st.GetExecutionHistory(10)
	if err != nil || len(hist) != 1 || hist[0].StudentName != "Siti Khodijah" || hist[0].ObjectivesChecked != 4 {
		t.Fatalf("GetExecutionHistory unexpected: %+v (err=%v)", hist, err)
	}
}
