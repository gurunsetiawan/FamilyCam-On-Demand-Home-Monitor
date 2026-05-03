#!/usr/bin/env bash
set -euo pipefail

# Control helper for projects/beta-webrtc-rs/webrtc-rs-poc.
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
  curl -fsS "${BASE_URL}${path}" \
    -H "Authorization: Bearer ${OWNER_TOKEN}"
}

req_owner_post_json() {
  local path="$1"
  local body="${2:-{}}"
  require_owner
  curl -fsS -X POST "${BASE_URL}${path}" \
    -H "Authorization: Bearer ${OWNER_TOKEN}" \
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
  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg device "${DEVICE}" \
      --arg input_format "${INPUT_FORMAT}" \
      --arg resolution "${RESOLUTION}" \
      --argjson fps "${FPS}" \
      '{"test_pattern":false,"device":$device,"input_format":$input_format,"fps":$fps,"resolution":$resolution}'
  else
    printf '{"test_pattern":false,"device":"%s","input_format":"%s","fps":%s,"resolution":"%s"}\n' \
      "${DEVICE}" "${INPUT_FORMAT}" "${FPS}" "${RESOLUTION}"
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
