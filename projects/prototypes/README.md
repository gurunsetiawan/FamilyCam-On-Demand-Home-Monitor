# Beta Components

Folder ini berisi komponen **Beta** untuk evaluasi dan rollout bertahap arsitektur WebRTC.

## Daftar
- `go-pion-poc/`
  - WebRTC menggunakan Go + Pion (status: Beta).
  - Tujuan: pembanding langsung terhadap `projects/webrtc-experiment/webrtc-rs-poc`.
- `kotlin-android-viewer/`
  - Android native viewer/control (status: Beta).
  - Dokumen utama: `kotlin-android-viewer/LIBRARY_RESEARCH.md`.

## Script Pendukung
- Benchmark webrtc-rs:
  - `/home/iwan/Project/family-cam-on-demand-home-monitor/scripts/benchmark-webrtc-rs.sh`
- Control helper webrtc-rs (health/probe/publisher):
  - `/home/iwan/Project/family-cam-on-demand-home-monitor/scripts/control-webrtc-rs.sh`

## Cara pakai cepat
```bash
cd go-pion-poc
cp .env.example .env
go mod tidy
go run .
```

Buka:
```text
http://127.0.0.1:9180
```

Android prototype:
```bash
cd kotlin-android-viewer
./gradlew :app:help
```
