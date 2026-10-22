# Algonova `auto-checker` (Golang)

Aplikasi otomasi berbasis **Golang** untuk membantu Guru Algonova Indonesia memeriksa dan menceklis otomatis tugas khusus siswa yang berstatus **Kuning (`student_success` / Pending Teacher Review)** menjadi **Hijau (`complete`)**.

---

## Fitur Utama

1. **Direct REST API Engine (Tanpa Overhead Browser Berat)**
   Menembak langsung endpoint internal `/api/v2/*` dan `/platform/api/*` dengan *session cookie* sehingga sangat cepat dan hanya membutuhkan RAM ~25 MB di VPS Docker.
2. **Keamanan Web Dashboard (Auth + Brute-Force Protection)**
   - Seluruh halaman Web Dashboard (`/`) dan endpoint `/api/*` dilindungi autentikasi session (`HttpOnly`, `SameSite=Lax`, password di-hash dengan `bcrypt`).
   - Dilengkapi **IP Rate-Limiter** yang memblokir sementara IP setelah 5x percobaan login gagal berturut-turut.
3. **Database Ringan SQLite (`modernc.org/sqlite` — Pure Go, Zero CGO)**
   Menyimpan akun user, session login, *session cookie* Algonova (`_backendMainSessionId`, `accessToken`), pengaturan Cron Scheduler, log aktivitas, dan riwayat eksekusi di dalam satu file `data/autochecker.db` (mode WAL) tanpa butuh container database terpisah.
4. **Anti Rate-Limit & Auto-Retry (Exponential Backoff)**
   Dilengkapi jeda *humanized jitter* antar request (`ALGONOVA_REQUEST_DELAY_MS=650`) dan antar siswa (`ALGONOVA_LEVEL_DELAY_MS=1500`), serta *auto-retry* pintar jika terdeteksi HTTP `429 Too Many Requests` atau gangguan jaringan sementara.
5. **2 Mode Pencarian Tugas Kuning (`Discovery Mode`)**
   - `unreviewed`: Menggunakan shortcut internal `/platform/api/v2/task/unreviewed-list` untuk menemukan seluruh tugas kuning secara instan (global maupun per-grup).
   - `schedule`: Menelusuri halaman Jadwal (`/group/default/schedule`), mengambil daftar grup aktif, membuka tab Progress tiap grup (`/api/v2/group/lesson/index` & `/api/v2/group/lesson/view/{id}`), dan memfilter level kuning.
   - `both`: Menggabungkan kedua metode di atas dengan deduplikasi otomatis.
6. **Mekanisme Checklist 2-Tahap Sesuai Frontend React Algonova**
   - **Tahap 1**: Mengirim `POST /platform/api/v1/teacherComment/step` (`status: "success"`) untuk setiap objektif/pertanyaan (`hint_id`) pada level tersebut.
   - **Tahap 2**: Mengirim `POST /platform/api/v2/level/change-multi-status` untuk mengubah status level dari `student_success` (Kuning) menjadi `complete` (Hijau).

---

## Cara Menjalankan di Lokal

### 1. Mode CLI — Simulasi Read-Only (`--dry-run`)
Cek tugas kuning pada 1 grup tertentu (misal `2175084`) menggunakan mode `both`:
```powershell
go run ./cmd/auto-checker --group-id=2175084 --mode=both --dry-run
```

Cek seluruh tugas kuning di semua grup Anda (Read-Only):
```powershell
go run ./cmd/auto-checker --group-id=all --mode=unreviewed --dry-run
```

### 2. Mode CLI — Eksekusi Checklist Nyata (`--execute`)
Setelah Anda yakin dengan hasil `--dry-run`, tambahkan flag `--execute`:
```powershell
go run ./cmd/auto-checker --group-id=all --mode=unreviewed --execute
```

### 3. Mode Web Dashboard + Cron Scheduler (`--serve`)
Jalankan server web lokal di `http://localhost:8080`:
```powershell
go run ./cmd/auto-checker --serve --addr=:8080
```
Buka `http://localhost:8080/login` dan masuk menggunakan kredensial `DASHBOARD_USERNAME` & `DASHBOARD_PASSWORD` yang ada di file `.env`.

---

## Cara Deploy ke VPS Menggunakan Docker

```bash
# 1. Pastikan file .env sudah diisi (terutama DASHBOARD_USERNAME & DASHBOARD_PASSWORD)
# 2. Build dan jalankan container di background
docker compose up -d --build

# 3. Lihat log aplikasi
docker compose logs -f
```
Seluruh database SQLite akan tersimpan secara persisten di folder `./data/autochecker.db` pada host VPS Anda.
