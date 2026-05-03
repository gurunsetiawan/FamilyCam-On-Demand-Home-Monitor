# WebRTC Rust (Beta)

Folder ini berisi implementasi WebRTC Rust FamilyCam dengan status **Beta**.

## Isi Folder
- `webrtc-rs-poc/`
  - aplikasi WebRTC berbasis `webrtc-rs` (status: Beta).

- Dokumentasi runnable untuk publik ada di `webrtc-rs-poc/README.md`.

## Status Beta Saat Ini
`webrtc-rs-poc` sudah punya:
- signaling dasar (`offer/candidate`)
- RTP ingest dari ffmpeg ke WebRTC track
- control publisher ffmpeg (`/publisher/start|stop|status`)
- camera probe (`/camera/probe`)
- hard limit session viewer + TTL cleanup
- auto-stop publisher saat tidak ada viewer & saat melewati durasi maksimum
- runtime metrics endpoint (`/metrics`)
- UI dashboard 2 kolom + auto refresh status
- simpan setting UI di browser (`localStorage`) + clear button
- owner auth via `Authorization: Bearer <token>` (query token masih fallback kompatibilitas)
- in-memory rate limiting (`offer`, `owner control`, `status`)
- publisher start/stop cooldown
- structured publisher request untuk mode webcam

Quick run:
```bash
cd webrtc-rs-poc
cargo run
```

## Tech Stack (Eksperimen)
- Bahasa: Rust
- Web framework: `axum`, `tokio`
- WebRTC backend: `webrtc-rs`
- RTP/media source: `ffmpeg` + UDP RTP ingest
- Camera tooling: `v4l2-ctl` (`v4l-utils`)
- Frontend PoC: HTML/CSS/JS vanilla

## Lisensi
Mengikuti lisensi root repository: **Apache-2.0**.
Lihat [LICENSE](/home/iwan/Project/family-cam-on-demand-home-monitor/LICENSE).

## Catatan
- Implementasi production tetap berada di `../main-app`.
