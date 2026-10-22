package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"auto-checker/internal/algonova"
	"auto-checker/internal/config"
	"auto-checker/internal/server"
	"auto-checker/internal/store"
)

func main() {
	var (
		envFile       = flag.String("env", ".env", "Path ke file konfigurasi .env")
		serveMode     = flag.Bool("serve", false, "Jalankan Web Dashboard & Built-in Cron Scheduler")
		addrFlag      = flag.String("addr", "", "Alamat listen Web Dashboard (contoh :8080)")
		modeFlag      = flag.String("mode", "", "Mode discovery: unreviewed | schedule | both")
		groupIDsFlag  = flag.String("group-id", "", "Filter Group ID tertentu (pisah koma, contoh: 2175084)")
		timeframeFlag = flag.String("timeframe", "", "Rentang waktu jadwal: current | all | past")
		onlySchedFlag = flag.Bool("only-scheduled", false, "Batasi unreviewed-list hanya pada grup di jadwal aktif")
		dryRunFlag    = flag.Bool("dry-run", true, "Mode aman Read-Only (simulasi tanpa mengirim POST ke Algonova)")
		executeFlag   = flag.Bool("execute", false, "Eksekusi POST nyata untuk menceklis tugas kuning menjadi hijau")
	)
	flag.Parse()

	cfg := config.Load(*envFile)

	if *addrFlag != "" {
		cfg.ServerAddr = *addrFlag
	}
	if *modeFlag != "" {
		cfg.DiscoveryMode = *modeFlag
	}
	if *groupIDsFlag != "" {
		if strings.EqualFold(strings.TrimSpace(*groupIDsFlag), "all") {
			cfg.GroupIDs = nil
		} else {
			cfg.GroupIDs = config.ParseGroupIDs(*groupIDsFlag)
		}
	}
	if *timeframeFlag != "" {
		cfg.Timeframe = *timeframeFlag
	}
	if *onlySchedFlag {
		cfg.OnlyScheduled = true
	}

	// Demi keamanan, dryRun selalu aktif kecuali user secara eksplisit memberikan --execute atau --dry-run=false
	dryRun := *dryRunFlag
	if *executeFlag {
		dryRun = false
	}
	cfg.DryRun = dryRun

	// Inisialisasi SQLite Database
	dbStore, err := store.NewSQLiteStore(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FATAL] Gagal membuka database SQLite (%s): %v\n", cfg.DBPath, err)
		os.Exit(1)
	}
	defer dbStore.Close()

	client, err := algonova.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FATAL] Gagal membuat Algonova client: %v\n", err)
		os.Exit(1)
	}
	client.AttachCookieStore(dbStore)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *serveMode {
		runWebServer(ctx, cfg, client, dbStore)
		return
	}

	runCLI(ctx, cfg, client, dbStore, dryRun)
}

func runWebServer(ctx context.Context, cfg *config.Config, client *algonova.Client, dbStore *store.Store) {
	srv := server.NewServer(cfg, client, dbStore)
	httpSrv := &http.Server{
		Addr:              cfg.ServerAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	displayURL := cfg.ServerAddr
	if strings.HasPrefix(displayURL, ":") {
		displayURL = "http://localhost" + displayURL
	}
	fmt.Println("==================================================================")
	fmt.Printf(" Algonova Auto-Checker Web Dashboard aktif di: %s\n", displayURL)
	fmt.Printf(" Database SQLite : %s\n", cfg.DBPath)
	fmt.Printf(" Akun Login Web  : %s\n", cfg.DashboardUser)
	fmt.Println(" Tekan Ctrl+C untuk menghentikan server.")
	fmt.Println("==================================================================")

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "[FATAL] HTTP server error: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(ctx context.Context, cfg *config.Config, client *algonova.Client, dbStore *store.Store, dryRun bool) {
	fmt.Println("==================================================================")
	fmt.Println(" Algonova Auto-Checker CLI")
	fmt.Printf(" Base URL       : %s\n", cfg.BaseURL)
	fmt.Printf(" Database SQLite: %s\n", cfg.DBPath)
	fmt.Printf(" Discovery Mode : %s\n", cfg.DiscoveryMode)
	if len(cfg.GroupIDs) > 0 {
		fmt.Printf(" Filter GroupID : %v\n", cfg.GroupIDs)
	} else {
		fmt.Printf(" Filter GroupID : Semua Grup (OnlyScheduled=%v, Timeframe=%s)\n", cfg.OnlyScheduled, cfg.Timeframe)
	}
	if dryRun {
		fmt.Println(" Mode Eksekusi  : DRY-RUN (100% Read-Only — Tidak ada POST nilai yang dikirim)")
	} else {
		fmt.Println(" Mode Eksekusi  : EXECUTE (Mengirim POST checklist ke LMS Algonova)")
	}
	fmt.Println("==================================================================")

	unreviewedTotal, err := client.EnsureAuthenticated(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[ERROR] Gagal autentikasi ke LMS Algonova: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[AUTH] Sesi valid! Total tugas unreviewed global di akun Anda: %d\n\n", unreviewedTotal)

	items, err := client.Discover(ctx, algonova.DiscoverOptions{
		Mode:          cfg.DiscoveryMode,
		GroupIDs:      cfg.GroupIDs,
		OnlyScheduled: cfg.OnlyScheduled,
		Timeframe:     cfg.Timeframe,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Gagal memindai tugas kuning: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[SCAN] Ditemukan %d level berstatus kuning (student_success):\n", len(items))
	if len(items) == 0 {
		fmt.Println("Tidak ada tugas kuning yang perlu diceklis untuk filter ini.")
		return
	}

	for i, it := range items {
		fmt.Printf("\n------------------------------------------------------------------\n")
		fmt.Printf("#%d [%s] Group: %s (ID: %d)\n", i+1, it.Source, it.GroupTitle, it.GroupID)
		fmt.Printf("   Lesson  : %s (LessonID: %d)\n", it.LessonTitle, it.LessonID)
		fmt.Printf("   Siswa   : %s (StudentID: %d)\n", it.StudentName, it.StudentID)
		fmt.Printf("   Task    : %s (TaskID: %d, Track: %d)\n", it.TaskTitle, it.TaskID, it.Track)
		fmt.Printf("   Level   : [Level %d] %s (LevelID: %d, Mechanic: %s, Status: %s)\n",
			it.LevelPosition, it.LevelTitle, it.LevelID, it.LevelMechanic, it.Status)
		fmt.Printf("   URL     : %s\n", it.TaskPreviewURL)
		if len(it.Objectives) > 0 {
			fmt.Printf("   Objektif (%d butir):\n", len(it.Objectives))
			for j, obj := range it.Objectives {
				fmt.Printf("     %d) [Siswa: %-9s | Guru: %-9s] %s (hint_id: %s)\n",
					j+1, obj.StudentStatus, obj.TeacherStatus, obj.Title, obj.HintID)
			}
		} else {
			fmt.Println("   Objektif: (Tidak ada sub-objektif hints; langsung ubah status level -> complete)")
		}
	}

	fmt.Printf("\n==================================================================\n")
	results := client.CheckBatch(ctx, items, dryRun, func(idx, total int, res algonova.CheckResult) {
		if dbStore != nil {
			_ = dbStore.AddExecutionHistory(res)
		}
		if res.DryRun {
			fmt.Printf("[DRY-RUN %d/%d] Simulasi OK -> %s | Level %d (%d objektif akan diceklis + status -> complete)\n",
				idx, total, res.Item.StudentName, res.Item.LevelID, res.ObjectivesChecked)
		} else if res.Success {
			fmt.Printf("[EXECUTED %d/%d] BERHASIL -> %s | Level %d (%d objektif diceklis + status -> complete)\n",
				idx, total, res.Item.StudentName, res.Item.LevelID, res.ObjectivesChecked)
		} else {
			fmt.Printf("[FAILED %d/%d] GAGAL -> %s | Level %d: %s\n",
				idx, total, res.Item.StudentName, res.Item.LevelID, res.Error)
		}
	})

	okCount := 0
	for _, r := range results {
		if r.Success {
			okCount++
		}
	}
	if dbStore != nil {
		modeStr := "EXECUTE"
		if dryRun {
			modeStr = "DRY-RUN"
		}
		_ = dbStore.AddLog(time.Now().Format("15:04:05"), fmt.Sprintf("[CLI %s] Selesai memproses %d/%d level kuning", modeStr, okCount, len(results)))
	}
	fmt.Println("==================================================================")
	if dryRun {
		fmt.Printf("Selesai! %d/%d level siap diceklis (Mode DRY-RUN: 0 request POST dikirim).\n", okCount, len(results))
		fmt.Println("Gunakan flag --execute jika Anda sudah mengizinkan eksekusi POST nyata.")
	} else {
		fmt.Printf("Selesai! %d/%d level berhasil diceklis menjadi Hijau (complete).\n", okCount, len(results))
	}
}
