#!/usr/bin/env bash
set -euo pipefail

# Control helper for projects/webrtc-experiment/webrtc-rs-poc.
# Provides quick owner actions for camera probe and publisher lifecycle.

BASE_URL="${FAMILYCAM_URL:-http://127.0.0.1:9080}"
OWNER_TOKEN="${FAMILYCAM_OWNER_TOKEN:-}"
DEVICE="/dev/video0"
INPUT_FORMAT="mjpeg"
FPS="15"
RESOLUTION="640x360"
BIN="ffmpeg"
JSON=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/control-webrtc-rs.sh [global options] <command>

Global options:
  --url <base_url>          Server URL (default: http://127.0.0.1:9080)
  --token <owner_token>     Owner token (or env FAMILYCAM_OWNER_TOKEN)
  --device <path>           Webcam device (default: /dev/video0)
  --input-format <fmt>      v4l2 input format for ffmpeg (default: mjpeg)
  --fps <n>                 Framerate (default: 15)
  --resolution <WxH>        Video size (default: 640x360)
  --bin <path>              Publisher binary (default: ffmpeg)
  --json                    Print raw JSON response
  -h, --help                Show this help

Commands:
  health                    GET /healthz
  metrics                   GET /metrics
  sessions                  GET /webrtc/sessions (owner)
  probe                     GET /camera/probe (owner)
  pub-status                GET /publisher/status (owner)
  pub-start-test            POST /publisher/start (owner, default env args)
  pub-start-webcam          POST /publisher/start (owner, ffmpeg webcam args)
  pub-stop                  POST /publisher/stop (owner)

Examples:
  scripts/control-webrtc-rs.sh health
  scripts/control-webrtc-rs.sh --token owner-dev-token probe
  scripts/control-webrtc-rs.sh --token owner-dev-token pub-start-test
  scripts/control-webrtc-rs.sh --token owner-dev-token --device /dev/video1 --fps 10 pub-start-webcam
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

print_json() {
  local raw="$1"
  if [[ "${JSON}" -eq 1 ]]; then
    printf '%s\n' "${raw}"
    return
  fi
  if command -v jq >/dev/null 2>&1; then
    printf '%s\n' "${raw}" | jq .
  else
    printf '%s\n' "${raw}"
  fi
}

require_owner() {
  if [[ -z "${OWNER_TOKEN}" ]]; then
    echo "Owner token is required for this command. Use --token or FAMILYCAM_OWNER_TOKEN." >&2
    exit 1
  fi
}

req_get() {
  local path="$1"
  curl -fsS "${BASE_URL}${path}"
}

req_owner_get() {
  local path="$1"
  require_owner
  curl -fsS "${BASE_URL}${path}?token=${OWNER_TOKEN}"
}

req_owner_post_json() {
  local path="$1"
  local body="${2:-{}}"
  require_owner
  curl -fsS -X POST "${BASE_URL}${path}?token=${OWNER_TOKEN}" \
    -H 'content-type: application/json' \
    -d "${body}"
}

get_rtp_listen_addr() {
  local health
  health="$(req_get "/healthz")"
  if command -v jq >/dev/null 2>&1; then
    printf '%s\n' "${health}" | jq -r '.rtp_listen // empty'
  else
    printf '%s\n' "${health}" | sed -n 's/.*"rtp_listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
  fi
}

build_webcam_start_body() {
  local rtp_addr
  rtp_addr="$(get_rtp_listen_addr)"
  if [[ -z "${rtp_addr}" ]]; then
    echo "Cannot determine rtp_listen from /healthz." >&2
    exit 1
  fi

  local args=(
    "-f" "v4l2"
  )
  if [[ -n "${INPUT_FORMAT}" ]]; then
    args+=("-input_format" "${INPUT_FORMAT}")
  fi
  if [[ -n "${FPS}" ]]; then
    args+=("-framerate" "${FPS}")
  fi
  if [[ -n "${RESOLUTION}" ]]; then
    args+=("-video_size" "${RESOLUTION}")
  fi
  args+=(
    "-i" "${DEVICE}"
    "-an"
    "-c:v" "libx264"
    "-preset" "ultrafast"
    "-tune" "zerolatency"
    "-pix_fmt" "yuv420p"
    "-profile:v" "baseline"
    "-level" "3.1"
    "-g" "30"
    "-keyint_min" "30"
    "-sc_threshold" "0"
    "-f" "rtp"
    "rtp://${rtp_addr}"
  )

  if command -v jq >/dev/null 2>&1; then
    jq -n --arg bin "${BIN}" --argjson args "$(printf '%s\n' "${args[@]}" | jq -R . | jq -cs .)" \
      '{bin: $bin, args: $args}'
  else
    # Minimal JSON builder fallback.
    local json='{"bin":"'"${BIN}"'","args":['
    local first=1
    local a
    for a in "${args[@]}"; do
      if [[ "${first}" -eq 0 ]]; then
        json+=","
      fi
      first=0
      json+="\"${a}\""
    done
    json+="]}"
    printf '%s\n' "${json}"
  fi
}

COMMAND=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) BASE_URL="${2:-}"; shift 2 ;;
    --token) OWNER_TOKEN="${2:-}"; shift 2 ;;
    --device) DEVICE="${2:-}"; shift 2 ;;
    --input-format) INPUT_FORMAT="${2:-}"; shift 2 ;;
    --fps) FPS="${2:-}"; shift 2 ;;
    --resolution) RESOLUTION="${2:-}"; shift 2 ;;
    --bin) BIN="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    health|metrics|sessions|probe|pub-status|pub-start-test|pub-start-webcam|pub-stop)
      COMMAND="$1"
      shift
      break
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${COMMAND}" ]]; then
  usage
  exit 1
fi

need_cmd curl

case "${COMMAND}" in
  health)
    print_json "$(req_get "/healthz")"
    ;;
  metrics)
    print_json "$(req_get "/metrics")"
    ;;
  sessions)
    print_json "$(req_owner_get "/webrtc/sessions")"
    ;;
  probe)
    print_json "$(req_owner_get "/camera/probe")"
    ;;
  pub-status)
    print_json "$(req_owner_get "/publisher/status")"
    ;;
  pub-start-test)
    print_json "$(req_owner_post_json "/publisher/start" '{}')"
    ;;
  pub-start-webcam)
    body="$(build_webcam_start_body)"
    print_json "$(req_owner_post_json "/publisher/start" "${body}")"
    ;;
  pub-stop)
    print_json "$(req_owner_post_json "/publisher/stop" '{}')"
    ;;
esac
