# Kotlin Android Viewer (Beta)

Android native viewer/control untuk backend FamilyCam (Go/Rust), status **Beta**.

Status saat ini:
- Riset library selesai di [LIBRARY_RESEARCH.md](/home/iwan/Project/family-cam-on-demand-home-monitor/projects/prototypes/kotlin-android-viewer/LIBRARY_RESEARCH.md)
- Integrasi owner control endpoint sudah aktif (`probe`, `publisher status/start/stop`)
- Integrasi WebRTC native dasar sudah aktif (`connect/disconnect` + video renderer)
- Owner auth dikirim via `Authorization: Bearer <token>`

## Pilihan stack yang dikunci
- WebRTC: `io.github.webrtc-sdk:android:137.7151.05`
- Networking: `OkHttp 5.3.2`
- Serialization: `kotlinx.serialization 1.10.0`
- UI: Jetpack Compose (BOM `2026.02.01`)

## Struktur awal
- `app/` Android app module
- `gradle/libs.versions.toml` katalog dependency
- `app/src/main/java/com/familycam/viewer/MainActivity.kt` implementasi UI + API + WebRTC
- `gradlew` + `gradle/wrapper/` sudah disiapkan

## Fitur yang sudah ada
1. Input `Server URL` dan `Owner Token`
2. Viewer:
   - `Connect` / `Disconnect`
   - Render video via `SurfaceViewRenderer`
3. Owner controls:
   - `Probe` kamera (`/camera/probe`)
   - `Status` publisher
   - `Test` pattern publisher
   - `Start Webcam` (ffmpeg args runtime)
   - `Stop` publisher
   - Dropdown otomatis untuk `Device`, `Format`, `FPS`, `Resolution`
   - Manual override tetap tersedia (textfield)
4. Panel log sederhana di UI

## Menjalankan
```bash
cd projects/prototypes/kotlin-android-viewer
./gradlew :app:help
```

Untuk build APK, pastikan Android SDK sudah terpasang dan `sdk.dir` tersedia di `local.properties` (atau set `ANDROID_HOME`).

Build APK debug:
```bash
./gradlew :app:assembleDebug
```

APK output:
```text
app/build/outputs/apk/debug/app-debug.apk
```
