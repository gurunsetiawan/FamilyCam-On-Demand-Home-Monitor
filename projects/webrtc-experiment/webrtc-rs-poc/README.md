# FamilyCam WebRTC-rs PoC

PoC ini terpisah dari `projects/main-app` untuk eksperimen WebRTC native di Rust (`webrtc-rs`).

Diagram alur data end-to-end:
- [docs/DATAFLOW.md](/home/iwan/Project/family-cam-on-demand-home-monitor/docs/DATAFLOW.md)

## Tech Stack
- Bahasa: Rust
- Backend/API: `axum`, `tokio`
- WebRTC: `webrtc-rs`
- RTP parser: crate `rtp`
- Media publisher: `ffmpeg`
- Kamera probe: `v4l2-ctl` (`v4l-utils`)
- Frontend: HTML/CSS/JS vanilla (single page dashboard)

## Scope Saat Ini (R2 Awal)
- Endpoint signaling minimal:
  - `POST /webrtc/offer`
  - `POST /webrtc/candidate`
  - `GET /webrtc/sessions?token=...`
  - `DELETE /webrtc/session/:id?token=...`
- Session manager in-memory dengan:
  - max session hard limit (default `3`)
  - TTL cleanup (default `600` detik)
- Publisher safety guard:
  - auto-stop jika viewer `0` selama grace period (default `20` detik)
  - auto-stop jika durasi stream melewati batas (default `1800` detik)
- RTP ingest via UDP:
  - server listen RTP (default `127.0.0.1:5004`)
  - paket RTP ditulis ke `TrackLocalStaticRTP`
  - `healthz` menampilkan statistik RTP (`rtp_packets`, `rtp_parse_errors`, dll)
  - `metrics` menampilkan runtime counters ringkas (process/session/publisher/ingest)
- Publisher helper endpoint (owner-only):
  - `GET /publisher/status?token=...`
  - `POST /publisher/start?token=...`
  - `POST /publisher/stop?token=...`
- Camera probe endpoint (owner-only):
  - `GET /camera/probe?token=...`
- UI dashboard 2 kolom di `/`:
  - viewer panel
  - publisher + camera probe panel (lebih ringkas, tidak memanjang ke bawah)

## Jalankan
1. Salin env:
```bash
cp .env.example .env
```
2. Start server:
```bash
cargo run
```
3. Start publisher internal (default ffmpeg testsrc):
```bash
curl -X POST "http://127.0.0.1:9080/publisher/start?token=<POC_OWNER_TOKEN>"
```
4. Buka:
```text
http://127.0.0.1:9080
```
Di UI sudah ada panel `Publisher Control (Owner)` untuk status/start/stop publisher langsung.
Status publisher juga auto-refresh tiap 5 detik saat owner token sudah diisi.
Untuk webcam, klik `Probe Cameras` lalu pilih device/format dan klik `Start Webcam`.
Kalau yang muncul color bars, itu `test pattern` (bukan webcam) dari `Start Test Pattern`.
UI menyimpan `owner token` dan setting kamera (`device/format/fps/resolusi`) di `localStorage` browser.
Ada tombol `Clear Saved Settings` untuk menghapus semua data tersimpan tersebut.
Field FPS dan resolusi memakai dropdown supaya lebih aman dari typo.

## Troubleshooting Singkat
- Video muncul color bars:
  - itu `Start Test Pattern`, bukan webcam.
  - klik `Probe Cameras`, pilih device/format, lalu `Start Webcam`.
- `camera probe` gagal:
  - pastikan `v4l2-ctl` tersedia (`sudo apt install v4l-utils`).
- `Start Webcam` gagal:
  - pastikan device benar (`/dev/video0` dst) dan user punya akses grup `video`.

## Opsional: Pengirim RTP Manual
Kalau ingin kirim RTP sendiri (tanpa endpoint publisher), contoh ffmpeg:
```bash
ffmpeg -re -stream_loop -1 -i sample.mp4 \
  -an -c:v libx264 -preset ultrafast -tune zerolatency \
  -pix_fmt yuv420p -f rtp rtp://127.0.0.1:5004
```
Contoh webcam Linux:
```bash
ffmpeg -f v4l2 -input_format h264 -framerate 15 -video_size 640x480 \
  -i /dev/video0 -an -c:v copy -f rtp rtp://127.0.0.1:5004
```

## Environment
- `POC_BIND_ADDR` default: `0.0.0.0:9080`
- `POC_MAX_SESSIONS` default: `3`
- `POC_MAX_VIEWERS` alias lama (tetap didukung; fallback jika `POC_MAX_SESSIONS` tidak diisi)
- `POC_SESSION_TTL_SECS` default: `600`
- `POC_AUTO_STOP_NO_VIEWERS_SECS` default: `20`
- `POC_MAX_STREAM_SECS` default: `1800` (30 menit)
- `POC_OWNER_TOKEN` default: `owner-dev-token`
- `POC_ICE_SERVERS` default: `stun:stun.l.google.com:19302`
  - contoh multi server: `stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302`
- `POC_ICE_UDP4_ONLY` default: `true` (lebih stabil untuk banyak jaringan mobile/VPN)
- `POC_ICE_DISCONNECTED_TIMEOUT_SECS` default: `12`
- `POC_ICE_FAILED_TIMEOUT_SECS` default: `45`
- `POC_ICE_KEEPALIVE_INTERVAL_SECS` default: `2`
- `POC_RTP_LISTEN_ADDR` default: `127.0.0.1:5004`
- `POC_VIDEO_MIME` default: `video/H264`
- `POC_VIDEO_CLOCK_RATE` default: `90000`
- `POC_VIDEO_FMTP` default: `level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f`
- `POC_PUBLISHER_BIN` default: `ffmpeg`
- `POC_PUBLISHER_ARGS` default:
  - `-f lavfi -i testsrc=size=640x360:rate=10 -an -c:v libx264 -preset ultrafast -tune zerolatency -pix_fmt yuv420p -profile:v baseline -level 3.1 -g 30 -keyint_min 30 -sc_threshold 0 -f rtp rtp://127.0.0.1:5004`
- `RUST_LOG` default: `familycam_webrtc_rs_poc=info,webrtc=warn`

## API Ringkas
### `POST /webrtc/offer`
Body:
```json
{ "sdp": "v=0..." }
```
Response:
```json
{
  "session_id": "uuid",
  "sdp": "v=0...",
  "type": "answer"
}
```

### `POST /webrtc/candidate`
Body:
```json
{
  "session_id": "uuid",
  "candidate": "candidate:...",
  "sdpMid": "0",
  "sdpMLineIndex": 0,
  "usernameFragment": "..."
}
```

### `GET /webrtc/sessions?token=...`
Owner-only, lihat viewer aktif.

### `DELETE /webrtc/session/:id?token=...`
Owner-only, paksa tutup sesi viewer.

### `GET /publisher/status?token=...`
Owner-only, cek status proses ffmpeg publisher.

### `POST /publisher/start?token=...`
Owner-only, start publisher dari env default.
Body opsional untuk override:
```json
{
  "bin": "ffmpeg",
  "args": ["-f","v4l2","-input_format","h264","-framerate","15","-video_size","640x480","-i","/dev/video0","-an","-c:v","copy","-f","rtp","rtp://127.0.0.1:5004"]
}
```

### `POST /publisher/stop?token=...`
Owner-only, stop publisher aktif.

### `GET /camera/probe?token=...`
Owner-only, list kamera `/dev/video*` dan format yang tersedia dari `v4l2-ctl`.

### `GET /metrics`
Ringkasan runtime counters:
- uptime app
- jumlah sesi aktif + limit
- status publisher
- statistik ingest RTP
- metrik proses (`rss_kb`, `threads`, `open_fds`, `cpu_*_ticks`)

### `GET /healthz`
Selain status dasar, endpoint ini juga mengembalikan konfigurasi ICE aktif (`ice_servers`, mode UDP4-only, timeout ICE).

## Lisensi
Mengikuti lisensi root repository: **Apache-2.0**.
Lihat [LICENSE](/home/iwan/Project/family-cam-on-demand-home-monitor/LICENSE).
