# FamilyCam Go + Pion (Beta)

Komponen Beta pembanding untuk `projects/beta-webrtc-rs/webrtc-rs-poc`.

Tujuan:
- bandingkan stabilitas koneksi
- bandingkan resource usage (CPU/RAM)
- bandingkan kompleksitas implementasi

## Fitur
- signaling minimal (`/webrtc/offer`, `/webrtc/candidate`)
- RTP ingest UDP -> track Pion
- UI viewer sederhana di `/`
- publisher helper (`/publisher/start|stop|status`)
- camera probe (owner) + dropdown device/format/fps/resolution di UI
- session TTL cleanup + max session limit
- auto-stop publisher saat tidak ada viewer
- endpoint `/healthz` dan `/metrics`

## Jalankan
```bash
cd projects/beta-go-pion
cp .env.example .env
sudo apt install -y ffmpeg v4l-utils
go mod tidy
go run .
```

Buka browser:
```text
http://127.0.0.1:9180
```

## Endpoint ringkas
- `GET /healthz`
- `GET /metrics`
- `POST /webrtc/offer`
- `POST /webrtc/candidate`
- `GET /webrtc/sessions` (owner)
- `GET /camera/probe` (owner)
- `GET /publisher/status` (owner)
- `POST /publisher/start` (owner)
- `POST /publisher/stop` (owner)

Owner auth:
- Header utama: `Authorization: Bearer <token>`
- Query `?token=` masih fallback kompatibilitas

## Test Webcam dari UI
1. Isi `Owner Token`.
2. Klik `Probe Cameras`.
3. Pilih `Device`, `Format`, `FPS`, `Resolution`.
4. Klik `Start Webcam`.
5. Klik `Connect` di panel Viewer.

## Contoh publisher webcam manual
```bash
ffmpeg -f v4l2 -input_format mjpeg -framerate 15 -video_size 640x360 \
  -i /dev/video0 -an \
  -c:v libx264 -preset ultrafast -tune zerolatency -pix_fmt yuv420p \
  -profile:v baseline -level 3.1 -g 30 -keyint_min 30 -sc_threshold 0 \
  -f rtp rtp://127.0.0.1:6004
```

## Catatan perbandingan dengan webrtc-rs-poc
- Port default beda supaya bisa jalan berdampingan:
  - Go Pion: `9180`
  - Rust webrtc-rs: `9080`
- RTP ingest default beda:
  - Go Pion: `127.0.0.1:6004`
  - Rust webrtc-rs: `127.0.0.1:5004`
