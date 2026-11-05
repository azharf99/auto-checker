package store

import (
	"path/filepath"
	"testing"
	"time"

	"auto-checker/internal/algonova"
)

func TestSQLiteStoreMultiUserLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_multiuser.db")
	st, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer st.Close()

	// 1. Inisialisasi Admin User
	adminUser, err := st.EnsureAdminUser("azharfa", "SecretPass123!")
	if err != nil {
		t.Fatalf("EnsureAdminUser failed: %v", err)
	}
	if adminUser.Role != "admin" || adminUser.Username != "azharfa" {
		t.Fatalf("Unexpected adminUser: %+v", adminUser)
	}

	// 2. Admin membuat user Guru baru
	teacherUser, err := st.CreateUser("kolega_budi", "Budi Guru", "BudiPassSecure123!", "teacher")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if teacherUser.Role != "teacher" || teacherUser.Username != "kolega_budi" {
		t.Fatalf("Unexpected teacherUser: %+v", teacherUser)
	}

	// 3. Autentikasi Pengguna
	u, err := st.AuthenticateUser("kolega_budi", "BudiPassSecure123!")
	if err != nil || u.ID != teacherUser.ID {
		t.Fatalf("AuthenticateUser failed: %v", err)
	}
	_, err = st.AuthenticateUser("kolega_budi", "WrongPassword!")
	if err == nil {
		t.Fatalf("expected error for wrong password")
	}

	// 4. Sesi Multi-User
	sessAdmin, err := st.CreateUserSession(adminUser.ID, adminUser.Username, 2*time.Hour, "127.0.0.1", "AdminBrowser")
	if err != nil {
		t.Fatalf("CreateUserSession admin failed: %v", err)
	}
	sessTeacher, err := st.CreateUserSession(teacherUser.ID, teacherUser.Username, 2*time.Hour, "127.0.0.2", "TeacherBrowser")
	if err != nil {
		t.Fatalf("CreateUserSession teacher failed: %v", err)
	}

	valAdmin, ok := st.ValidateUserSession(sessAdmin)
	if !ok || valAdmin.Username != "azharfa" || valAdmin.Role != "admin" {
		t.Fatalf("ValidateUserSession admin failed: ok=%v, valAdmin=%+v", ok, valAdmin)
	}
	valTeacher, ok := st.ValidateUserSession(sessTeacher)
	if !ok || valTeacher.Username != "kolega_budi" || valTeacher.Role != "teacher" {
		t.Fatalf("ValidateUserSession teacher failed: ok=%v, valTeacher=%+v", ok, valTeacher)
	}

	// 5. Isolasi Cookie Algonova (Teacher A vs Teacher B)
	err = st.SaveUserAlgonovaCookies(adminUser.ID, []algonova.SavedCookie{
		{Name: "accessToken", Value: "admin-jwt-token"},
	})
	if err != nil {
		t.Fatalf("SaveUserAlgonovaCookies admin failed: %v", err)
	}
	err = st.SaveUserAlgonovaCookies(teacherUser.ID, []algonova.SavedCookie{
		{Name: "accessToken", Value: "budi-jwt-token"},
	})
	if err != nil {
		t.Fatalf("SaveUserAlgonovaCookies teacher failed: %v", err)
	}

	adminCookies, _ := st.LoadUserAlgonovaCookies(adminUser.ID)
	teacherCookies, _ := st.LoadUserAlgonovaCookies(teacherUser.ID)
	if len(adminCookies) != 1 || adminCookies[0].Value != "admin-jwt-token" {
		t.Fatalf("Admin cookies leaked or corrupted: %+v", adminCookies)
	}
	if len(teacherCookies) != 1 || teacherCookies[0].Value != "budi-jwt-token" {
		t.Fatalf("Teacher cookies leaked or corrupted: %+v", teacherCookies)
	}

	// 6. Isolasi Pengaturan & Scheduler
	_ = st.SetUserSetting(adminUser.ID, "cron_enabled", "true")
	_ = st.SetUserSetting(teacherUser.ID, "cron_enabled", "false")
	cronUsers, err := st.ListUsersWithCronEnabled()
	if err != nil || len(cronUsers) != 1 || cronUsers[0] != adminUser.ID {
		t.Fatalf("ListUsersWithCronEnabled unexpected: %+v (err=%v)", cronUsers, err)
	}

	// 7. Isolasi Log Aktivitas
	_ = st.AddUserLog(adminUser.ID, "10:00:00", "Admin scan started")
	_ = st.AddUserLog(teacherUser.ID, "10:01:00", "Budi check executed")
	adminLogs, _ := st.GetUserRecentLogs(adminUser.ID, 10)
	teacherLogs, _ := st.GetUserRecentLogs(teacherUser.ID, 10)
	if len(adminLogs) != 1 || adminLogs[0].Message != "Admin scan started" {
		t.Fatalf("Admin logs corrupted or leaked: %+v", adminLogs)
	}
	if len(teacherLogs) != 1 || teacherLogs[0].Message != "Budi check executed" {
		t.Fatalf("Teacher logs corrupted or leaked: %+v", teacherLogs)
	}

	// 8. Isolasi Riwayat Eksekusi
	_ = st.AddUserExecutionHistory(teacherUser.ID, algonova.CheckResult{
		Item: algonova.YellowLevelItem{
			GroupID: 2175084, GroupTitle: "Kelas Budi", StudentID: 101, StudentName: "Andi",
			TaskID: 1, LevelID: 1, LevelPosition: 1, LevelTitle: "L1",
		},
		Success:   true,
		CheckedAt: time.Now(),
	})
	adminHist, _ := st.GetUserExecutionHistory(adminUser.ID, 10)
	teacherHist, _ := st.GetUserExecutionHistory(teacherUser.ID, 10)
	if len(adminHist) != 0 {
		t.Fatalf("Admin unexpectedly has history: %+v", adminHist)
	}
	if len(teacherHist) != 1 || teacherHist[0].StudentName != "Andi" {
		t.Fatalf("Teacher history missing: %+v", teacherHist)
	}

	// 9. Nonaktifkan Akun Pengguna (Revoke Sesi Seketika)
	err = st.UpdateUserStatus(teacherUser.ID, false)
	if err != nil {
		t.Fatalf("UpdateUserStatus failed: %v", err)
	}
	_, ok = st.ValidateUserSession(sessTeacher)
	if ok {
		t.Fatalf("Deactivated user session must be invalid")
	}
	_, err = st.AuthenticateUser("kolega_budi", "BudiPassSecure123!")
	if err == nil {
		t.Fatalf("Deactivated user should not be able to authenticate")
	}

	// 10. Hapus Akun Pengguna (Cascade Delete)
	err = st.DeleteUser(teacherUser.ID)
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	_, err = st.GetUserByID(teacherUser.ID)
	if err == nil {
		t.Fatalf("expected error when getting deleted user")
	}
}
