#!/usr/bin/env bash
set -u

# FamilyCam camera diagnostics helper.
# Usage:
#   scripts/check-camera.sh
#   scripts/check-camera.sh --device /dev/video1
#   scripts/check-camera.sh --no-ffmpeg-test

DEVICE="/dev/video0"
RUN_FFMPEG_TEST=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --device)
      DEVICE="${2:-}"
      shift 2
      ;;
    --no-ffmpeg-test)
      RUN_FFMPEG_TEST=0
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: scripts/check-camera.sh [options]

Options:
  --device <path>      Camera device to test (default: /dev/video0)
  --no-ffmpeg-test     Skip one-frame ffmpeg capture test
  -h, --help           Show this help
USAGE
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 1
      ;;
  esac
done

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

section() {
  printf '\n=== %s ===\n' "$1"
}

run_cmd() {
  echo "> $*"
  "$@"
}

run_cmd_allow_fail() {
  echo "> $*"
  "$@" || true
}

section "System"
date -Is
uname -a

section "User & Groups"
id

section "Video Devices"
if compgen -G "/dev/video*" >/dev/null; then
  run_cmd ls -l /dev/video*
else
  echo "No /dev/video* found"
fi

if have_cmd getfacl && compgen -G "/dev/video*" >/dev/null; then
  section "Device ACL"
  for dev in /dev/video*; do
    echo "# $dev"
    run_cmd_allow_fail getfacl -cp "$dev"
  done
fi

if have_cmd v4l2-ctl && compgen -G "/dev/video*" >/dev/null; then
  section "V4L2 Formats"
  for dev in /dev/video*; do
    echo "# $dev"
    run_cmd_allow_fail v4l2-ctl -d "$dev" --all
    run_cmd_allow_fail v4l2-ctl -d "$dev" --list-formats-ext
  done
else
  section "V4L2 Formats"
  echo "v4l2-ctl not found (install: sudo apt install -y v4l-utils)"
fi

section "Camera Lock Check"
if compgen -G "/dev/video*" >/dev/null; then
  if have_cmd fuser; then
    run_cmd_allow_fail fuser -v /dev/video*
  else
    echo "fuser not found"
  fi
  if have_cmd lsof; then
    run_cmd_allow_fail lsof /dev/video*
  else
    echo "lsof not found"
  fi
fi

section "Related Processes"
if have_cmd pgrep; then
  run_cmd_allow_fail pgrep -af "familycam|webrtc-rs-poc|ffmpeg|v4l2|cargo run"
else
  echo "pgrep not found"
fi

section "Listening Ports (8080/9080)"
if have_cmd ss; then
  run_cmd_allow_fail ss -ltnp '( sport = :8080 or sport = :9080 )'
else
  echo "ss not found"
fi

if have_cmd curl; then
  section "HTTP Probe"
  for port in 8080 9080; do
    url="http://127.0.0.1:${port}/health"
    echo "> curl -sS -m 2 -i $url | head -n 1"
    curl -sS -m 2 -i "$url" 2>/dev/null | head -n 1 || echo "(unreachable)"
  done
fi

if [[ "$RUN_FFMPEG_TEST" -eq 1 ]]; then
  section "ffmpeg One-Frame Test"
  if ! have_cmd ffmpeg; then
    echo "ffmpeg not found"
  elif [[ ! -e "$DEVICE" ]]; then
    echo "Device not found: $DEVICE"
  else
    echo "Target device: $DEVICE"
    if have_cmd timeout; then
      cmd=(timeout 8s)
    else
      cmd=()
    fi

    echo "> ${cmd[*]} ffmpeg -hide_banner -loglevel error -f v4l2 -input_format mjpeg -video_size 640x480 -i $DEVICE -frames:v 1 -f null -"
    if "${cmd[@]}" ffmpeg -hide_banner -loglevel error -f v4l2 -input_format mjpeg -video_size 640x480 -i "$DEVICE" -frames:v 1 -f null -; then
      echo "ffmpeg test OK (mjpeg)"
    else
      echo "mjpeg test failed, trying fallback format auto-detect"
      echo "> ${cmd[*]} ffmpeg -hide_banner -loglevel error -f v4l2 -i $DEVICE -frames:v 1 -f null -"
      if "${cmd[@]}" ffmpeg -hide_banner -loglevel error -f v4l2 -i "$DEVICE" -frames:v 1 -f null -; then
        echo "ffmpeg test OK (auto format)"
      else
        echo "ffmpeg test FAILED"
      fi
    fi
  fi
fi

section "Summary Hints"
echo "- Jika 'Device or resource busy', hentikan proses yang pakai /dev/video* lalu ulangi tes."
echo "- Jika permission ditolak, cek user saat run app dan group/ACL device kamera."
echo "- Jika port 8080/9080 tidak listen, app belum jalan atau crash saat start."
