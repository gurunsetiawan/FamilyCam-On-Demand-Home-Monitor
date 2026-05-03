#!/usr/bin/env bash
set -euo pipefail

# Benchmark helper for projects/beta-webrtc-rs/webrtc-rs-poc.
# Collects /healthz and /metrics snapshots periodically and writes CSV summary.
#
# Examples:
#   scripts/benchmark-webrtc-rs.sh
#   scripts/benchmark-webrtc-rs.sh --duration 300 --interval 2
#   scripts/benchmark-webrtc-rs.sh --owner-token token123
#   scripts/benchmark-webrtc-rs.sh --start-app --app-dir projects/beta-webrtc-rs/webrtc-rs-poc

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${ROOT_DIR}/projects/beta-webrtc-rs/webrtc-rs-poc"
BASE_URL="http://127.0.0.1:9080"
DURATION_SECS=120
INTERVAL_SECS=2
OWNER_TOKEN=""
OUT_DIR=""
START_APP=0
START_CMD="cargo run"
WAIT_HEALTH_SECS=60

usage() {
  cat <<'USAGE'
Usage: scripts/benchmark-webrtc-rs.sh [options]

Options:
  --duration <secs>         Benchmark duration (default: 120)
  --interval <secs>         Sampling interval (default: 2)
  --url <base_url>          Server base URL (default: http://127.0.0.1:9080)
  --owner-token <token>     Optional owner token (collect /publisher/status)
  --out-dir <path>          Output directory (default: auto timestamped)
  --app-dir <path>          webrtc-rs app dir (default: projects/beta-webrtc-rs/webrtc-rs-poc)
  --start-app               Start app before benchmark
  --start-cmd <command>     Command used with --start-app (default: cargo run)
  --wait-health <secs>      Health wait timeout when --start-app (default: 60)
  -h, --help                Show this help
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION_SECS="${2:-}"; shift 2 ;;
    --interval) INTERVAL_SECS="${2:-}"; shift 2 ;;
    --url) BASE_URL="${2:-}"; shift 2 ;;
    --owner-token) OWNER_TOKEN="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --app-dir) APP_DIR="${2:-}"; shift 2 ;;
    --start-app) START_APP=1; shift ;;
    --start-cmd) START_CMD="${2:-}"; shift 2 ;;
    --wait-health) WAIT_HEALTH_SECS="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 1
      ;;
  esac
done

need_cmd curl
need_cmd jq

if [[ -z "${OUT_DIR}" ]]; then
  RUN_ID="$(date +%Y%m%d-%H%M%S)"
  OUT_DIR="${ROOT_DIR}/benchmarks/webrtc-rs/${RUN_ID}"
fi

mkdir -p "${OUT_DIR}/raw/healthz" "${OUT_DIR}/raw/metrics" "${OUT_DIR}/raw/publisher"

CSV_FILE="${OUT_DIR}/samples.csv"
SUMMARY_FILE="${OUT_DIR}/summary.txt"
META_FILE="${OUT_DIR}/meta.txt"
APP_LOG_FILE="${OUT_DIR}/app.log"

echo "timestamp_iso,unix,sessions,rtp_packets,rtp_bytes,publisher_running,publisher_pid,rtp_parse_errors,rtp_write_errors,app_uptime_secs,process_rss_kb,process_threads,process_open_fds" > "${CSV_FILE}"

APP_PID=""
cleanup() {
  if [[ -n "${APP_PID}" ]]; then
    if kill -0 "${APP_PID}" >/dev/null 2>&1; then
      kill "${APP_PID}" >/dev/null 2>&1 || true
      wait "${APP_PID}" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT

wait_for_health() {
  local deadline now
  deadline=$(( $(date +%s) + WAIT_HEALTH_SECS ))
  while true; do
    if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    now=$(date +%s)
    if (( now >= deadline )); then
      return 1
    fi
    sleep 1
  done
}

if [[ "${START_APP}" -eq 1 ]]; then
  if [[ ! -d "${APP_DIR}" ]]; then
    echo "Invalid --app-dir: ${APP_DIR}" >&2
    exit 1
  fi
  (
    cd "${APP_DIR}"
    bash -lc "${START_CMD}" >"${APP_LOG_FILE}" 2>&1
  ) &
  APP_PID="$!"
  if ! wait_for_health; then
    echo "App did not become healthy within ${WAIT_HEALTH_SECS}s. See ${APP_LOG_FILE}" >&2
    exit 1
  fi
else
  if ! curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    echo "Server not reachable at ${BASE_URL}. Start app first or use --start-app." >&2
    exit 1
  fi
fi

{
  echo "run_started_iso=$(date -Is)"
  echo "base_url=${BASE_URL}"
  echo "duration_secs=${DURATION_SECS}"
  echo "interval_secs=${INTERVAL_SECS}"
  echo "owner_token_set=$([[ -n "${OWNER_TOKEN}" ]] && echo true || echo false)"
  echo "start_app=$([[ "${START_APP}" -eq 1 ]] && echo true || echo false)"
  echo "start_cmd=${START_CMD}"
  echo "app_dir=${APP_DIR}"
} > "${META_FILE}"

echo "Benchmark started: ${OUT_DIR}"
START_UNIX="$(date +%s)"
END_UNIX=$(( START_UNIX + DURATION_SECS ))
SAMPLE_IDX=0

while (( $(date +%s) <= END_UNIX )); do
  TS_UNIX="$(date +%s)"
  TS_ISO="$(date -Is)"
  SAMPLE_IDX=$(( SAMPLE_IDX + 1 ))

  HEALTH_JSON="$(curl -fsS "${BASE_URL}/healthz" || echo '{}')"
  METRICS_JSON="$(curl -fsS "${BASE_URL}/metrics" || echo '{}')"

  echo "${HEALTH_JSON}" | jq . > "${OUT_DIR}/raw/healthz/${SAMPLE_IDX}.json" 2>/dev/null || echo "${HEALTH_JSON}" > "${OUT_DIR}/raw/healthz/${SAMPLE_IDX}.json"
  echo "${METRICS_JSON}" | jq . > "${OUT_DIR}/raw/metrics/${SAMPLE_IDX}.json" 2>/dev/null || echo "${METRICS_JSON}" > "${OUT_DIR}/raw/metrics/${SAMPLE_IDX}.json"

  if [[ -n "${OWNER_TOKEN}" ]]; then
    PUB_JSON="$(curl -fsS "${BASE_URL}/publisher/status?token=${OWNER_TOKEN}" || echo '{}')"
    echo "${PUB_JSON}" | jq . > "${OUT_DIR}/raw/publisher/${SAMPLE_IDX}.json" 2>/dev/null || echo "${PUB_JSON}" > "${OUT_DIR}/raw/publisher/${SAMPLE_IDX}.json"
  fi

  SESSIONS="$(echo "${HEALTH_JSON}" | jq -r '.sessions // 0' 2>/dev/null || echo 0)"
  RTP_PACKETS="$(echo "${HEALTH_JSON}" | jq -r '.rtp_packets // 0' 2>/dev/null || echo 0)"
  RTP_BYTES="$(echo "${HEALTH_JSON}" | jq -r '.rtp_bytes // 0' 2>/dev/null || echo 0)"
  PUB_RUNNING="$(echo "${HEALTH_JSON}" | jq -r '.publisher_running // false' 2>/dev/null || echo false)"
  PUB_PID="$(echo "${HEALTH_JSON}" | jq -r '.publisher_pid // 0' 2>/dev/null || echo 0)"
  PARSE_ERRS="$(echo "${HEALTH_JSON}" | jq -r '.rtp_parse_errors // 0' 2>/dev/null || echo 0)"
  WRITE_ERRS="$(echo "${HEALTH_JSON}" | jq -r '.rtp_write_errors // 0' 2>/dev/null || echo 0)"
  UPTIME_SECS="$(echo "${METRICS_JSON}" | jq -r '.app_uptime_secs // 0' 2>/dev/null || echo 0)"
  RSS_KB="$(echo "${METRICS_JSON}" | jq -r '.process.rss_kb // 0' 2>/dev/null || echo 0)"
  THREADS="$(echo "${METRICS_JSON}" | jq -r '.process.threads // 0' 2>/dev/null || echo 0)"
  OPEN_FDS="$(echo "${METRICS_JSON}" | jq -r '.process.open_fds // 0' 2>/dev/null || echo 0)"

  echo "${TS_ISO},${TS_UNIX},${SESSIONS},${RTP_PACKETS},${RTP_BYTES},${PUB_RUNNING},${PUB_PID},${PARSE_ERRS},${WRITE_ERRS},${UPTIME_SECS},${RSS_KB},${THREADS},${OPEN_FDS}" >> "${CSV_FILE}"
  sleep "${INTERVAL_SECS}"
done

SAMPLE_COUNT="$(awk 'END{print NR-1}' "${CSV_FILE}")"
FIRST_RTP="$(awk -F, 'NR==2{print $4}' "${CSV_FILE}")"
LAST_RTP="$(awk -F, 'END{print $4}' "${CSV_FILE}")"
[[ -z "${FIRST_RTP}" ]] && FIRST_RTP=0
[[ -z "${LAST_RTP}" ]] && LAST_RTP=0
RTP_DELTA=$(( LAST_RTP - FIRST_RTP ))
AVG_SESSIONS="$(awk -F, 'NR>1{sum+=$3; n++} END{if(n>0) printf "%.2f", sum/n; else print "0"}' "${CSV_FILE}")"
MAX_SESSIONS="$(awk -F, 'NR>1{if($3>m)m=$3} END{print m+0}' "${CSV_FILE}")"
MAX_RSS_KB="$(awk -F, 'NR>1{if($11>m)m=$11} END{print m+0}' "${CSV_FILE}")"
MAX_THREADS="$(awk -F, 'NR>1{if($12>m)m=$12} END{print m+0}' "${CSV_FILE}")"
MAX_FDS="$(awk -F, 'NR>1{if($13>m)m=$13} END{print m+0}' "${CSV_FILE}")"

{
  echo "Benchmark Summary"
  echo "================="
  echo "out_dir=${OUT_DIR}"
  echo "samples=${SAMPLE_COUNT}"
  echo "duration_secs=${DURATION_SECS}"
  echo "interval_secs=${INTERVAL_SECS}"
  echo "avg_sessions=${AVG_SESSIONS}"
  echo "max_sessions=${MAX_SESSIONS}"
  echo "rtp_packets_first=${FIRST_RTP}"
  echo "rtp_packets_last=${LAST_RTP}"
  echo "rtp_packets_delta=${RTP_DELTA}"
  echo "max_process_rss_kb=${MAX_RSS_KB}"
  echo "max_process_threads=${MAX_THREADS}"
  echo "max_process_open_fds=${MAX_FDS}"
} | tee "${SUMMARY_FILE}"

echo
echo "Saved:"
echo "- ${CSV_FILE}"
echo "- ${SUMMARY_FILE}"
echo "- ${META_FILE}"
if [[ "${START_APP}" -eq 1 ]]; then
  echo "- ${APP_LOG_FILE}"
fi
