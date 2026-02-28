# WebRTC Experiment

Folder ini berisi prototype eksperimen WebRTC untuk FamilyCam.

## Isi Folder
- `webrtc-rs-poc/`
  - aplikasi PoC WebRTC berbasis `webrtc-rs` (jalur eksperimen terpisah).

- Dokumentasi runnable untuk publik ada di `webrtc-rs-poc/README.md`.

## Status PoC Saat Ini
`webrtc-rs-poc` sudah punya:
- signaling dasar (`offer/candidate`)
- RTP ingest dari ffmpeg ke WebRTC track
- control publisher ffmpeg (`/publisher/start|stop|status`)
- camera probe (`/camera/probe`)
- UI dashboard 2 kolom + auto refresh status
- simpan setting UI di browser (`localStorage`) + clear button

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
