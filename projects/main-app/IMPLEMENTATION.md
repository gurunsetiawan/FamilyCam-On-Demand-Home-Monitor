# FamilyCam V1 Implementation Plan

## Progress Saat Ini
- [x] Fase 1 - Skeleton App
- [x] Fase 2 - Camera Service + State Machine
- [x] Fase 3 - Streaming + Snapshot (single-client)
- [x] Fase 4 - Auth + Auto Shutdown + Logging
- [x] Fase 5 - Notify + Hardening + Deploy (artefak kode & template)

## 1) Keputusan Final
- Streaming: `single-client` dulu.
- Arsitektur: modular monolith (tetap satu binary).
- Runtime: Rust (`axum` + `tokio`) + `ffmpeg` backend.
- Deploy target: Orange Pi + `systemd`.

## 2) Scope V1
### In Scope
- Login sederhana (cookie session, 1 password dari `.env`).
- Start camera.
- Stop camera.
- Live stream MJPEG.
- Snapshot.
- Auto shutdown idle (default 120 detik).
- Logging aktivitas.
- Telegram notification (start, panic, boot, optional auto-stop).

### Out of Scope
- WebRTC.
- Two-way audio.
- Multi-client streaming.
- Database.
- AI detection.

## 3) Struktur Kode (Target)
```text
src/
  main.rs
  config/mod.rs
  core/state.rs
  core/errors.rs
  camera/traits.rs
  camera/ffmpeg_backend.rs
  camera/service.rs
  web/routes.rs
  web/handlers.rs
  web/middleware.rs
  notify/telegram.rs
  logging/mod.rs
static/
  index.html
  bulma.min.css
logs/
snapshots/
```

## 4) Spesifikasi Teknis Penting
### 4.1 State Machine
- `Idle`
- `Starting`
- `Streaming`
- `Stopping`

Transisi valid:
- `Idle -> Starting -> Streaming`
- `Streaming -> Stopping -> Idle`

### 4.2 Single-Client Rule
- Hanya 1 koneksi aktif ke `GET /stream`.
- Gunakan permit global (mis. semaphore 1).
- Jika ada klien kedua saat stream aktif: balas `409 Conflict` atau `423 Locked`.

### 4.3 Idle Tracking
`last_activity` wajib di-update saat:
- sukses `POST /start`
- frame stream terkirim
- snapshot sukses
- request stop

### 4.4 Endpoint V1
- `GET /health`
- `GET /` (dashboard)
- `POST /login`
- `GET /cameras` (probe kamera, auth required)
- `POST /camera/select` (set device runtime, auth required)
- `POST /start`
- `POST /stop`
- `GET /stream`
- `GET /snapshot`
- `POST /panic`

### 4.5 Camera Probe CLI
- Jalankan binary dengan mode probe tanpa start server:
```bash
cargo run -- --probe-cameras
```

## 5) Rencana Implementasi Bertahap
### Fase 0 - Prasyarat Device
Tasks:
- Install dependency OS.
- Verifikasi device kamera dan format.
- Uji command ffmpeg manual.

Commands:
```bash
sudo apt update
sudo apt install -y ffmpeg v4l-utils
v4l2-ctl --list-devices
v4l2-ctl --list-formats-ext -d /dev/video0
ffmpeg -f v4l2 -input_format mjpeg -i /dev/video0 -f mjpeg -t 3 -
```

Definition of Done:
- `/dev/video0` terbaca.
- Format MJPEG tersedia (atau fallback diset).
- ffmpeg bisa capture tanpa crash.

### Fase 1 - Skeleton App
Tasks:
- Inisialisasi project Rust.
- Tambah modul dasar (`config`, `core`, `camera`, `web`).
- Tambah `AppState` dan wiring router.

Commands:
```bash
cargo init --bin .
cargo add axum tokio --features tokio/full
cargo add anyhow tracing tracing-subscriber serde --features serde/derive
cargo check
```

Definition of Done:
- `cargo check` hijau.
- `GET /health` balas `200`.

### Fase 2 - Camera Service + State Machine
Tasks:
- Implement `CameraBackend` trait.
- Implement `FfmpegBackend`.
- Implement `CameraService` dengan transisi state eksplisit.
- Tambah proteksi transisi invalid.

Definition of Done:
- `start()` saat `Streaming` idempotent.
- `stop()` saat `Idle` idempotent.
- Error start/stop tidak meninggalkan state rusak.

### Fase 3 - Streaming + Snapshot (Single-Client)
Tasks:
- Implement `GET /stream` MJPEG.
- Tambah guard single-client (permit 1).
- Implement `GET /snapshot`.
- Pastikan release permit saat client disconnect.

Definition of Done:
- Klien pertama stream sukses.
- Klien kedua ditolak dengan status yang disepakati.
- Snapshot berhasil saat kamera aktif.

Verifikasi manual:
```bash
curl -i http://127.0.0.1:8080/stream
curl -i http://127.0.0.1:8080/snapshot
```

### Fase 4 - Auth + Auto Shutdown + Logging
Tasks:
- Middleware auth cookie session.
- Login handler (`POST /login`).
- Background task auto-stop idle.
- Logging ke file (`logs/familycam.log`).

Definition of Done:
- Route privat butuh session valid.
- Kamera auto-stop setelah idle timeout.
- Log event utama tercatat: boot, login, start, snapshot, stop, auto-stop.

### Fase 5 - Notify + Hardening + Deploy
Tasks:
- Integrasi Telegram notify.
- Buat `systemd` unit.
- Hardening service + restart policy.
- Verifikasi after reboot.

`/etc/systemd/system/familycam.service` minimum:
```ini
[Unit]
Description=FamilyCam On-Demand Camera
After=network.target

[Service]
Type=simple
User=orangepi
WorkingDirectory=/opt/familycam
ExecStart=/opt/familycam/familycam
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
MemoryMax=200M

[Install]
WantedBy=multi-user.target
```

Commands:
```bash
sudo systemctl daemon-reload
sudo systemctl enable familycam
sudo systemctl start familycam
sudo systemctl status familycam
journalctl -u familycam -f
```

Definition of Done:
- Service start otomatis setelah reboot.
- Jika process crash, service restart otomatis.
- Kamera tetap bisa di-start/stop normal dari web.

## 6) Environment Variables
Contoh `.env`:
```env
APP_PASSWORD=change-me
BIND_ADDR=0.0.0.0:8080
AUTO_SHUTDOWN_SECONDS=120
CAMERA_DEVICE=/dev/video0
CAMERA_INPUT_FORMAT=mjpeg
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

## 7) Test Checklist (UAT)
- Boot service, login, start stream, stop stream.
- Buka stream dari device A (sukses), device B (ditolak).
- Snapshot saat streaming (sukses).
- Diam > idle timeout lalu pastikan auto-stop.
- Cabut kamera saat running: service tidak hang.
- Restart device: service balik up.

## 8) Risiko & Mitigasi
- Kamera tidak support MJPEG:
  Gunakan fallback format + turunkan resolusi/fps.
- ffmpeg zombie process:
  Selalu kill + wait child saat stop/error path.
- Deadlock state lock:
  Jaga urutan lock konsisten, hindari lock bersarang lama.
- Session bocor:
  Set cookie `HttpOnly`, expiry pendek, rotate secret berkala.

## 9) Definition of Done V1
- Semua fitur in-scope berjalan di Orange Pi.
- Single-client stream enforced.
- Auto-shutdown stabil.
- Service survive reboot.
- Tidak ada crash pada flow utama selama uji 30-60 menit.
