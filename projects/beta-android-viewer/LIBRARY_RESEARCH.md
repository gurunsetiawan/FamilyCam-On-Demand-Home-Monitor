# Kotlin Android Viewer - Library Research (Maret 2026)

Tujuan riset ini: pilih library untuk aplikasi Android native (`beta-android-viewer`) yang bisa jadi viewer/control untuk FamilyCam.

## Keputusan Final (per 1 Maret 2026)
- Library WebRTC utama: `io.github.webrtc-sdk:android:137.7151.05`
- Fallback jika ada isu kompatibilitas device/build: `com.infobip:google-webrtc`
- HTTP/signaling client: `OkHttp`
- JSON: `kotlinx.serialization`
- UI: Jetpack Compose

## Kebutuhan utama
- Viewer live video latency rendah (utama: WebRTC)
- Kontrol endpoint existing (`/webrtc/*`, `/publisher/*`, `/camera/probe`)
- Simpel untuk dipelihara (DIY home CCTV)

## Opsi Library

### 1) Custom WebRTC client (paling cocok dengan backend sekarang)
Ini tetap pakai backend kamu (beta-go-pion / webrtc-rs-poc), jadi Android app hanya viewer + signaling client.

Library kandidat:
- WebRTC core Android:
  - `org.webrtc` via prebuilt AAR pihak ketiga (karena build dari source cukup berat)
  - Kandidat artifact:
    - `com.dafruits:webrtc-android`
    - `com.infobip:google-webrtc`
- Signaling HTTP/WebSocket:
  - `OkHttp` (WebSocket + HTTP)
  - atau `Ktor Client` + plugin WebSockets
- JSON:
  - `kotlinx.serialization`
- UI:
  - Jetpack Compose + Material 3
- Penyimpanan config ringan (token, URL server):
  - Jetpack DataStore

Kelebihan:
- Paling dekat dengan arsitektur sekarang
- Tidak perlu ganti media server/vendor
- Kontrol penuh ke alur signaling

Kekurangan:
- Integrasi `org.webrtc` di Android perlu disiplin lifecycle (renderer/peer connection)
- Kualitas/stabilitas AAR tergantung vendor artifact yang dipakai

### 2) Ecosystem SDK (cepat jalan, tapi ubah arsitektur)

#### LiveKit Android SDK
- SDK Android matang, dokumentasi bagus, fitur realtime lengkap.
- Cocok kalau backend pindah ke LiveKit server stack.

#### Jitsi Meet SDK
- Cepat untuk skenario conference/room.
- Tapi cenderung overkill untuk use case 1 kamera + viewer keluarga.

Kelebihan:
- Cepat dapat fitur realtime production-grade

Kekurangan:
- Backend harus ikut model platform mereka
- Integrasi dengan endpoint custom kamu jadi kurang natural

### 3) Non-WebRTC fallback untuk mobile

#### Media3 ExoPlayer (HLS)
- Cocok untuk fallback stream stabil (latency lebih tinggi dari WebRTC).
- Bagus untuk mode hemat resource, bukan mode ultra-low-latency.

Catatan:
- Untuk MJPEG, biasanya perlu pipeline custom; lebih aman fallback ke HLS/WebRTC.

## Rekomendasi untuk FamilyCam

### Rekomendasi utama (MVP Android)
- `org.webrtc` via `io.github.webrtc-sdk:android`
- `OkHttp` untuk signaling HTTP + WebSocket
- `kotlinx.serialization` untuk payload JSON
- `Jetpack Compose` untuk UI
- `DataStore` untuk simpan server URL + owner token

### Rekomendasi arsitektur
- Tetap pakai backend sekarang sebagai source of truth.
- Android app hanya:
  - Connect/Disconnect viewer
  - Status koneksi
  - Start/Stop publisher (owner)
  - Probe kamera + pilih format/fps/resolusi (owner)
- Fallback plan:
  - jika network buruk, tambah mode HLS via Media3.

## Risiko teknis yang harus diputuskan sebelum coding
- Versi artifact `org.webrtc` harus diuji di beberapa device Android
- Target Android min SDK (Jitsi butuh API 24)
- Mau full custom signaling (recommended) atau pivot ke ecosystem (LiveKit/Jitsi)

---

## Sumber (official/primary)
- WebRTC native Android build docs: https://webrtc.googlesource.com/src/+/main/docs/native-code/android/
- Maven Central `com.dafruits:webrtc-android`: https://central.sonatype.com/artifact/com.dafruits/webrtc-android
- Maven Central `com.infobip:google-webrtc`: https://central.sonatype.com/artifact/com.infobip/google-webrtc
- OkHttp official docs: https://square.github.io/okhttp/
- Ktor Client WebSockets docs: https://ktor.io/docs/client-websockets.html
- Kotlinx Serialization docs: https://kotlinlang.org/docs/serialization.html
- Jetpack Compose docs: https://developer.android.com/compose
- Jetpack DataStore docs: https://developer.android.com/topic/libraries/architecture/datastore
- Android Media3 release notes/docs: https://developer.android.com/jetpack/androidx/releases/media3
- LiveKit Android SDK docs: https://docs.livekit.io/home/quickstarts/kotlin/
- Jitsi Meet Android SDK docs: https://jitsi.github.io/handbook/docs/dev-guide/dev-guide-android-sdk/
