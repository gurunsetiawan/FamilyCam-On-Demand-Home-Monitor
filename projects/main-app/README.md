# FamilyCam (On-Demand Home Monitor)

FamilyCam adalah aplikasi monitoring rumah berbasis Rust yang kamera-nya aktif saat dibutuhkan, bukan merekam 24 jam.

Filosofi utama:
- default kamera mati
- user login lalu start manual
- auto-stop saat idle
- akses lewat jaringan privat (VPN/LAN)

## Status Implementasi
- Single-client streaming MJPEG
- Login sederhana berbasis cookie session
- Start/stop kamera on-demand
- Snapshot JPEG
- Auto-shutdown idle
- Logging ke file harian
- Telegram notify (opsional)
- Probe kamera via API dan CLI

## Scope Repo Ini
Folder ini adalah jalur stabil FamilyCam (non-WebRTC) untuk penggunaan harian.

Eksperimen WebRTC dipisah di:
- `../webrtc-experiment/webrtc-rs-poc`

## Tech Stack
- Bahasa: Rust
- Backend/API: `axum`, `tokio`
- Media pipeline: `ffmpeg`, `v4l2` (`/dev/video*`)
- Frontend: HTML statis, Bulma, HTMX, JS vanilla
- Integrasi opsional: Telegram Bot API
- Deploy: `systemd` (template ada di `deploy/`)

## Prasyarat
- Linux (target utama Orange Pi/Raspberry Pi)
- Rust toolchain
- `ffmpeg`
- `v4l-utils` (untuk probe format kamera)

Install dependency OS:

```bash
sudo apt update
sudo apt install -y ffmpeg v4l-utils
```

## Konfigurasi
Copy env:

```bash
cp .env.example .env
```

Catatan: file `.env` otomatis di-load saat startup.

Variable utama:
- `APP_NAME`
- `APP_PASSWORD`
- `BIND_ADDR`
- `AUTO_SHUTDOWN_SECONDS`
- `CAMERA_DEVICE`
- `CAMERA_INPUT_FORMAT`
- `TELEGRAM_BOT_TOKEN` (opsional)
- `TELEGRAM_CHAT_ID` (opsional)

## Menjalankan Aplikasi
Dev mode:

```bash
cargo run
```

Build release:

```bash
cargo build --release
```

App default listen di `0.0.0.0:8080` (bisa diubah via `BIND_ADDR`).

## Probe Kamera
Mode CLI (tanpa start web server):

```bash
cargo run -- --probe-cameras
```

Endpoint API (harus login dulu):

```bash
GET /cameras
```

Set device kamera runtime (tanpa edit `.env`, tidak persist setelah restart):

```bash
POST /camera/select
Content-Type: application/json

{
  "device": "/dev/video0",
  "input_format": "mjpeg"
}
```

## Troubleshooting Kamera
Untuk diagnosa cepat masalah kamera (permission, device busy, service/port):

```bash
cd /home/iwan/Project/family-cam-on-demand-home-monitor
scripts/check-camera.sh
```

Pilihan tambahan:

```bash
# cek device tertentu
scripts/check-camera.sh --device /dev/video1

# skip test ffmpeg satu frame
scripts/check-camera.sh --no-ffmpeg-test
```

## Endpoint Utama
- `GET /health`
- `POST /login`
- `GET /status` (auth)
- `GET /cameras` (auth)
- `POST /camera/select` (auth)
- `POST /start` (auth)
- `POST /stop` (auth)
- `GET /stream` (auth, single-client)
- `GET /snapshot` (auth)
- `POST /panic` (auth)

## Single-Client Streaming
`/stream` hanya mengizinkan 1 koneksi aktif. Jika ada koneksi kedua saat stream sedang dipakai, request akan ditolak.

Saat stream aktif, snapshot diambil dari frame stream terakhir agar tidak bentrok akses device kamera.

## Logging
Log aplikasi ditulis ke:

```text
logs/familycam.log.YYYY-MM-DD
```

Contoh event:
- app boot
- login success
- start/stop kamera
- snapshot
- panic trigger
- auto-shutdown idle

## Deploy dengan systemd
Template service:
- `deploy/familycam.service`
- `deploy/README.md`

Ringkas:

```bash
sudo usermod -aG video orangepi
sudo cp deploy/familycam.service /etc/systemd/system/familycam.service
sudo systemctl daemon-reload
sudo systemctl enable familycam
sudo systemctl start familycam
sudo systemctl status familycam
```

## Pengujian
```bash
cargo check
cargo test
```

## Catatan Keamanan
- Gunakan di VPN/LAN, jangan expose port ke internet publik.
- Ganti `APP_PASSWORD` default sebelum production.
- Gunakan user non-root untuk menjalankan service.

## Lisensi
Mengikuti lisensi root repository: **Apache-2.0**.
Lihat [LICENSE](/home/iwan/Project/family-cam-on-demand-home-monitor/LICENSE).
