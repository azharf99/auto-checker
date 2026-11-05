# Algonova `auto-checker` (Golang)

Aplikasi otomasi berbasis **Golang** untuk membantu Guru Algonova Indonesia memeriksa dan menceklis otomatis tugas khusus siswa yang berstatus **Kuning (`student_success` / Pending Teacher Review)** menjadi **Hijau (`complete`)**.

Aplikasi ini mendukung **Multi-User (Multi-Tenant)** dengan isolasi data ketat (*Zero Data Leakage / Zero Compromise Security*), sehingga dapat digunakan bersama oleh rekan sesama guru secara aman tanpa risiko data siswa atau cookie tertukar/terbaca.

---

## Fitur Utama

1. **Arsitektur Multi-User & Role-Based Access Control (RBAC)**
   - **Isolasi Akun & Cookie 100%**: Setiap guru memiliki sesi dan penyimpanan cookie Algonova terisolasi di database SQLite (`user_algonova_cookies`). Guru A tidak dapat melihat, menimpa, atau mengakses sesi Guru B.
   - **Per-User Client & Scan State**: Hasil scan tugas murid dan eksekusi checklist diisolasi berdasarkan identitas pengguna (`user_id`), mencegah kerentanan IDOR (*Insecure Direct Object Reference*).
   - **Manajemen Pengguna (Admin Panel)**: Akun Admin dapat menambah guru baru, mereset password, mengaktifkan/menonaktifkan akun, atau menghapus pengguna.
   - **Self-Service Ganti Password**: Setiap guru dapat mengganti password akunnya sendiri kapan saja.

2. **Keamanan Web Dashboard Berlapis (Enterprise-Grade Security)**
   - Autentikasi sesi berbasis token kriptografis 256-bit di dalam cookie `HttpOnly`, `SameSite=Lax`, dan auto-flag `Secure` saat HTTPS.
   - **Dual Rate-Limiter (Anti Brute-Force)**: Memblokir IP dan username secara otomatis selama 15 menit jika terdeteksi 5x percobaan login gagal berturut-turut.
   - **Proteksi CSRF**: Memeriksa header mutasi `Origin`, `Referer`, dan `X-Requested-With`.
   - **Security Headers**: Dilengkapi header `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, dan `Content-Security-Policy`.

3. **Direct REST API Engine (Tanpa Overhead Browser Berat)**
   Menembak langsung endpoint internal `/api/v2/*` dan `/platform/api/*` dengan *session cookie* masing-masing guru sehingga sangat cepat dan hanya membutuhkan RAM ~25 MB di VPS Docker.

4. **Multi-User Background Scheduler (Cron)**
   Setiap guru dapat mengatur interval pengecekan otomatis akunnya sendiri (misal: 1 jam, 6 jam) dan memilih apakah ingin auto-approve atau notifikasi saja.

5. **Anti Rate-Limit & Auto-Retry (Exponential Backoff)**
   Dilengkapi jeda *humanized jitter* antar request (`ALGONOVA_REQUEST_DELAY_MS=650`) dan antar siswa (`ALGONOVA_LEVEL_DELAY_MS=1500`), serta *auto-retry* pintar jika terdeteksi HTTP `429 Too Many Requests` atau gangguan jaringan sementara.

6. **Database Ringan SQLite (`modernc.org/sqlite` — Pure Go, Zero CGO)**
   Menyimpan seluruh data (users, sessions, user cookies, scheduler settings, activity logs, execution history) dalam satu file `data/autochecker.db` (mode WAL).

---

## Cara Menjalankan di Lokal

### 1. Mode CLI — Simulasi Read-Only (`--dry-run`)
Cek tugas kuning pada 1 grup tertentu (misal `2175084`):
```powershell
go run ./cmd/auto-checker --group-id=2175084 --mode=both --dry-run
```

Cek seluruh tugas kuning di semua grup Anda (Read-Only):
```powershell
go run ./cmd/auto-checker --group-id=all --mode=unreviewed --dry-run
```

### 2. Mode CLI — Eksekusi Checklist Nyata (`--execute`)
```powershell
go run ./cmd/auto-checker --group-id=all --mode=unreviewed --execute
```

### 3. Mode Web Dashboard Multi-User (`--serve`)
Jalankan server web lokal di `http://localhost:8080`:
```powershell
go run ./cmd/auto-checker --serve --addr=:8080
```
- Buka `http://localhost:8080/login` dan masuk menggunakan akun admin (`DASHBOARD_USERNAME` & `DASHBOARD_PASSWORD` di `.env`).
- Dari menu header, klik **"Kelola Pengguna"** untuk menambahkan akun kolega Anda.
- Kolega Anda kemudian dapat login, memasukkan cookie Algonova miliknya melalui tombol **"Update Cookie Algonova Saya"**, dan memindai serta meng-approve tugas siswa di kelasnya sendiri!

---

## Cara Deploy ke VPS Menggunakan Docker & Nginx

```bash
# 1. Pastikan file .env sudah diisi di VPS (/opt/auto-checker/.env)
# 2. Build dan jalankan container di background
docker compose up -d --build

# 3. Pantau log
docker compose logs -f
```
Aplikasi akan bind secara aman di `127.0.0.1:8097` dan diteruskan oleh Nginx ke subdomain `https://autocheck.azharfa.cloud`.
