use std::{
    collections::{BTreeSet, HashMap},
    env,
    net::SocketAddr,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use bytes::Bytes;
use ice::{mdns::MulticastDnsMode, network_type::NetworkType};
use interceptor::registry::Registry;
use rtp::packet::Packet;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, UdpSocket},
    process::Command,
    sync::{Mutex, RwLock},
    time::{interval, sleep, timeout},
};
use tracing::{error, info, warn};
use util::marshal::Unmarshal;
use uuid::Uuid;
use webrtc::{
    api::{
        interceptor_registry::register_default_interceptors, media_engine::MediaEngine, APIBuilder,
    },
    ice_transport::{ice_candidate::RTCIceCandidateInit, ice_server::RTCIceServer},
    peer_connection::{
        configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
        sdp::session_description::RTCSessionDescription, RTCPeerConnection,
    },
    rtp_transceiver::{rtp_codec::RTCRtpCodecCapability, rtp_sender::RTCRtpSender},
    track::track_local::{
        track_local_static_rtp::TrackLocalStaticRTP, TrackLocal, TrackLocalWriter,
    },
};

#[derive(Clone)]
struct AppConfig {
    bind_addr: SocketAddr,
    max_sessions: usize,
    ttl_secs: u64,
    auto_stop_no_viewers_secs: u64,
    max_stream_secs: u64,
    owner_token: String,
    ice_servers: Vec<String>,
    ice_udp4_only: bool,
    ice_disconnected_timeout_secs: u64,
    ice_failed_timeout_secs: u64,
    ice_keepalive_interval_secs: u64,
    rtp_listen_addr: SocketAddr,
    video_mime_type: String,
    video_clock_rate: u32,
    video_fmtp_line: String,
    publisher_bin: String,
    publisher_args: Vec<String>,
}

impl AppConfig {
    fn from_env() -> Result<Self> {
        let bind_addr = env::var("POC_BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9080".to_string())
            .parse()
            .context("invalid POC_BIND_ADDR")?;
        let max_sessions = env::var("POC_MAX_SESSIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .or_else(|| {
                env::var("POC_MAX_VIEWERS")
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
            })
            .unwrap_or(3);
        let ttl_secs = env::var("POC_SESSION_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(600);
        let auto_stop_no_viewers_secs = env::var("POC_AUTO_STOP_NO_VIEWERS_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(20);
        let max_stream_secs = env::var("POC_MAX_STREAM_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1800);
        let owner_token =
            env::var("POC_OWNER_TOKEN").unwrap_or_else(|_| "owner-dev-token".to_string());
        let ice_servers = env::var("POC_ICE_SERVERS")
            .unwrap_or_else(|_| "stun:stun.l.google.com:19302".to_string())
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let ice_udp4_only = parse_env_bool("POC_ICE_UDP4_ONLY", true);
        let ice_disconnected_timeout_secs = env::var("POC_ICE_DISCONNECTED_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(12);
        let ice_failed_timeout_secs = env::var("POC_ICE_FAILED_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(45);
        let ice_keepalive_interval_secs = env::var("POC_ICE_KEEPALIVE_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2);
        let rtp_listen_addr = env::var("POC_RTP_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:5004".to_string())
            .parse()
            .context("invalid POC_RTP_LISTEN_ADDR")?;
        let video_mime_type =
            env::var("POC_VIDEO_MIME").unwrap_or_else(|_| "video/H264".to_string());
        let video_clock_rate = env::var("POC_VIDEO_CLOCK_RATE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(90_000);
        let video_fmtp_line = env::var("POC_VIDEO_FMTP").unwrap_or_else(|_| {
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f".to_string()
        });
        let publisher_bin = env::var("POC_PUBLISHER_BIN").unwrap_or_else(|_| "ffmpeg".to_string());
        let publisher_default_args = format!(
            "-f lavfi -i testsrc=size=640x360:rate=10 -an -c:v libx264 -preset ultrafast -tune zerolatency -pix_fmt yuv420p -profile:v baseline -level 3.1 -g 30 -keyint_min 30 -sc_threshold 0 -f rtp rtp://{}",
            rtp_listen_addr
        );
        let publisher_args = env::var("POC_PUBLISHER_ARGS")
            .unwrap_or(publisher_default_args)
            .split_whitespace()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        Ok(Self {
            bind_addr,
            max_sessions,
            ttl_secs,
            auto_stop_no_viewers_secs,
            max_stream_secs,
            owner_token,
            ice_servers,
            ice_udp4_only,
            ice_disconnected_timeout_secs,
            ice_failed_timeout_secs,
            ice_keepalive_interval_secs,
            rtp_listen_addr,
            video_mime_type,
            video_clock_rate,
            video_fmtp_line,
            publisher_bin,
            publisher_args,
        })
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    started_unix: u64,
    started_instant: Instant,
    webrtc_api: Arc<webrtc::api::API>,
    video_track: Arc<TrackLocalStaticRTP>,
    sessions: Arc<RwLock<HashMap<Uuid, SessionEntry>>>,
    ingest_stats: Arc<Mutex<IngestStats>>,
    publisher: Arc<Mutex<PublisherState>>,
}

struct SessionEntry {
    peer: Arc<RTCPeerConnection>,
    created_unix: u64,
    last_seen: Instant,
}

#[derive(Clone, Default)]
struct IngestStats {
    packets: u64,
    bytes: u64,
    parse_errors: u64,
    write_errors: u64,
    last_packet_unix: Option<u64>,
    last_source: Option<String>,
}

struct PublisherState {
    running: Option<PublisherProcess>,
    last_exit: Option<PublisherExitInfo>,
}

impl Default for PublisherState {
    fn default() -> Self {
        Self {
            running: None,
            last_exit: None,
        }
    }
}

struct PublisherProcess {
    child: tokio::process::Child,
    pid: Option<u32>,
    started_unix: u64,
    command: String,
    args: Vec<String>,
}

#[derive(Clone, Serialize)]
struct PublisherExitInfo {
    exited_unix: u64,
    code: Option<i32>,
    success: bool,
}

#[derive(Serialize)]
struct SessionInfo {
    session_id: Uuid,
    created_unix: u64,
    idle_secs: u64,
}

#[derive(Debug)]
enum ApiError {
    BadRequest(String),
    Unauthorized,
    NotFound,
    Conflict(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "session not found".to_string()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::Internal(err.to_string())
    }
}

#[derive(Deserialize)]
struct OfferRequest {
    sdp: String,
}

#[derive(Serialize)]
struct OfferResponse {
    session_id: Uuid,
    sdp: String,
    #[serde(rename = "type")]
    sdp_type: String,
}

#[derive(Deserialize)]
struct CandidateRequest {
    session_id: Uuid,
    candidate: String,
    #[serde(rename = "sdpMid")]
    sdp_mid: Option<String>,
    #[serde(rename = "sdpMLineIndex")]
    sdp_mline_index: Option<u16>,
    #[serde(rename = "usernameFragment")]
    username_fragment: Option<String>,
}

#[derive(Deserialize)]
struct OwnerQuery {
    token: String,
}

#[derive(Serialize)]
struct SessionsResponse {
    count: usize,
    max: usize,
    sessions: Vec<SessionInfo>,
}

#[derive(Default, Deserialize)]
struct PublisherStartRequest {
    bin: Option<String>,
    args: Option<Vec<String>>,
}

#[derive(Serialize)]
struct PublisherStatusResponse {
    running: bool,
    pid: Option<u32>,
    started_unix: Option<u64>,
    command: Option<String>,
    args: Vec<String>,
    last_exit: Option<PublisherExitInfo>,
}

#[derive(Serialize)]
struct CameraProbeResponse {
    count: usize,
    cameras: Vec<CameraOption>,
}

#[derive(Clone, Serialize)]
struct CameraOption {
    label: String,
    path: String,
    formats: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG")
                .unwrap_or_else(|_| "familycam_webrtc_rs_poc=info,webrtc=warn".to_string()),
        )
        .init();

    let config = AppConfig::from_env()?;
    let webrtc_api = Arc::new(build_webrtc_api(&config)?);
    let video_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: config.video_mime_type.clone(),
            clock_rate: config.video_clock_rate,
            channels: 0,
            sdp_fmtp_line: config.video_fmtp_line.clone(),
            rtcp_feedback: vec![],
        },
        "video".to_string(),
        "familycam".to_string(),
    ));

    let state = AppState {
        config: config.clone(),
        started_unix: now_unix(),
        started_instant: Instant::now(),
        webrtc_api,
        video_track,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        ingest_stats: Arc::new(Mutex::new(IngestStats::default())),
        publisher: Arc::new(Mutex::new(PublisherState::default())),
    };
    spawn_cleanup_task(state.clone());
    spawn_rtp_ingest_task(state.clone());
    spawn_publisher_guard_task(state.clone());

    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/webrtc/offer", post(webrtc_offer))
        .route("/webrtc/candidate", post(webrtc_candidate))
        .route("/webrtc/sessions", get(webrtc_sessions))
        .route("/webrtc/session/:id", delete(webrtc_close_session))
        .route("/publisher/status", get(publisher_status))
        .route("/publisher/start", post(publisher_start))
        .route("/publisher/stop", post(publisher_stop))
        .route("/camera/probe", get(camera_probe))
        .with_state(state.clone());

    let listener = TcpListener::bind(config.bind_addr).await?;
    info!(
        "webrtc-rs poc listening on http://{} (RTP ingest: {})",
        config.bind_addr, config.rtp_listen_addr
    );
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_webrtc_api(config: &AppConfig) -> Result<webrtc::api::API> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;

    let mut setting_engine = webrtc::api::setting_engine::SettingEngine::default();
    setting_engine.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);
    if config.ice_udp4_only {
        setting_engine.set_network_types(vec![NetworkType::Udp4]);
    }
    setting_engine.set_ice_timeouts(
        Some(Duration::from_secs(config.ice_disconnected_timeout_secs)),
        Some(Duration::from_secs(config.ice_failed_timeout_secs)),
        Some(Duration::from_secs(config.ice_keepalive_interval_secs)),
    );

    Ok(APIBuilder::new()
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build())
}

fn ensure_owner(state: &AppState, token: &str) -> Result<(), ApiError> {
    if token == state.config.owner_token {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

fn refresh_publisher_state_locked(state: &mut PublisherState) {
    if let Some(process) = state.running.as_mut() {
        match process.child.try_wait() {
            Ok(Some(status)) => {
                state.last_exit = Some(PublisherExitInfo {
                    exited_unix: now_unix(),
                    code: status.code(),
                    success: status.success(),
                });
                state.running = None;
            }
            Ok(None) => {}
            Err(err) => {
                warn!("publisher try_wait failed: {err}");
            }
        }
    }
}

fn publisher_status_response(state: &PublisherState) -> PublisherStatusResponse {
    if let Some(process) = state.running.as_ref() {
        PublisherStatusResponse {
            running: true,
            pid: process.pid,
            started_unix: Some(process.started_unix),
            command: Some(process.command.clone()),
            args: process.args.clone(),
            last_exit: state.last_exit.clone(),
        }
    } else {
        PublisherStatusResponse {
            running: false,
            pid: None,
            started_unix: None,
            command: None,
            args: Vec::new(),
            last_exit: state.last_exit.clone(),
        }
    }
}

async fn publisher_status(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<OwnerQuery>,
) -> Result<Json<PublisherStatusResponse>, ApiError> {
    ensure_owner(&state, &query.token)?;
    let mut publisher = state.publisher.lock().await;
    refresh_publisher_state_locked(&mut publisher);
    Ok(Json(publisher_status_response(&publisher)))
}

async fn publisher_start(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<OwnerQuery>,
    req: Option<Json<PublisherStartRequest>>,
) -> Result<Json<PublisherStatusResponse>, ApiError> {
    ensure_owner(&state, &query.token)?;
    let req = req.map(|v| v.0).unwrap_or_default();

    let mut publisher = state.publisher.lock().await;
    refresh_publisher_state_locked(&mut publisher);
    if publisher.running.is_some() {
        return Err(ApiError::Conflict("publisher sudah berjalan".to_string()));
    }

    let bin = req
        .bin
        .unwrap_or_else(|| state.config.publisher_bin.clone());
    let args = req
        .args
        .unwrap_or_else(|| state.config.publisher_args.clone());
    if args.is_empty() {
        return Err(ApiError::BadRequest(
            "publisher args kosong, isi POC_PUBLISHER_ARGS atau body args".to_string(),
        ));
    }

    let mut cmd = Command::new(&bin);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let child = cmd
        .spawn()
        .map_err(|e| ApiError::Internal(format!("start publisher gagal: {e}")))?;
    let pid = child.id();
    publisher.running = Some(PublisherProcess {
        child,
        pid,
        started_unix: now_unix(),
        command: bin.clone(),
        args: args.clone(),
    });
    info!("publisher started pid={pid:?} cmd={} args={:?}", bin, args);

    Ok(Json(publisher_status_response(&publisher)))
}

async fn publisher_stop(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<OwnerQuery>,
) -> Result<Json<PublisherStatusResponse>, ApiError> {
    ensure_owner(&state, &query.token)?;
    if !stop_publisher_process(&state, "owner request").await? {
        return Err(ApiError::Conflict(
            "publisher tidak sedang berjalan".to_string(),
        ));
    }

    let mut publisher = state.publisher.lock().await;
    refresh_publisher_state_locked(&mut publisher);
    Ok(Json(publisher_status_response(&publisher)))
}

async fn camera_probe(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<OwnerQuery>,
) -> Result<Json<CameraProbeResponse>, ApiError> {
    ensure_owner(&state, &query.token)?;
    let cameras = probe_cameras().await?;
    Ok(Json(CameraProbeResponse {
        count: cameras.len(),
        cameras,
    }))
}

async fn probe_cameras() -> Result<Vec<CameraOption>, ApiError> {
    let output = Command::new("v4l2-ctl")
        .arg("--list-devices")
        .output()
        .await
        .map_err(|e| ApiError::Internal(format!("gagal jalankan v4l2-ctl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::Internal(format!(
            "v4l2-ctl --list-devices gagal: {}",
            stderr.trim()
        )));
    }

    let mut camera_entries: Vec<(String, String)> = Vec::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut current_label = String::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            current_label = trimmed.trim_end_matches(':').to_string();
            continue;
        }
        if trimmed.starts_with("/dev/video") {
            let label = if current_label.is_empty() {
                "Camera".to_string()
            } else {
                current_label.clone()
            };
            camera_entries.push((label, trimmed.to_string()));
        }
    }

    let mut cameras = Vec::new();
    for (label, path) in camera_entries {
        let mut formats = probe_formats_for_device(&path).await;
        formats.sort();
        cameras.push(CameraOption {
            label,
            path,
            formats,
        });
    }

    Ok(cameras)
}

async fn probe_formats_for_device(path: &str) -> Vec<String> {
    let output = Command::new("v4l2-ctl")
        .args(["--device", path, "--list-formats-ext"])
        .output()
        .await;
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut set = BTreeSet::new();
    for line in stdout.lines() {
        if let Some(start) = line.find('\'') {
            let rest = &line[start + 1..];
            if let Some(end) = rest.find('\'') {
                let code = rest[..end].trim();
                if !code.is_empty() && code.len() <= 8 {
                    set.insert(code.to_string());
                }
            }
        }
    }
    set.into_iter().collect()
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn healthz(State(state): State<AppState>) -> Json<serde_json::Value> {
    let current = state.sessions.read().await.len();
    let stats = state.ingest_stats.lock().await;
    let mut publisher = state.publisher.lock().await;
    refresh_publisher_state_locked(&mut publisher);
    let publisher_running = publisher.running.is_some();
    let publisher_pid = publisher.running.as_ref().and_then(|p| p.pid);
    Json(serde_json::json!({
        "status": "ok",
        "sessions": current,
        "max_sessions": state.config.max_sessions,
        "max_viewers": state.config.max_sessions,
        "auto_stop_no_viewers_secs": state.config.auto_stop_no_viewers_secs,
        "max_stream_secs": state.config.max_stream_secs,
        "ice_servers": state.config.ice_servers,
        "ice_udp4_only": state.config.ice_udp4_only,
        "ice_disconnected_timeout_secs": state.config.ice_disconnected_timeout_secs,
        "ice_failed_timeout_secs": state.config.ice_failed_timeout_secs,
        "ice_keepalive_interval_secs": state.config.ice_keepalive_interval_secs,
        "publisher_running": publisher_running,
        "publisher_pid": publisher_pid,
        "rtp_listen": state.config.rtp_listen_addr.to_string(),
        "video_mime": state.config.video_mime_type,
        "rtp_packets": stats.packets,
        "rtp_bytes": stats.bytes,
        "rtp_parse_errors": stats.parse_errors,
        "rtp_write_errors": stats.write_errors,
        "rtp_last_packet_unix": stats.last_packet_unix,
        "rtp_last_source": stats.last_source,
    }))
}

async fn metrics(State(state): State<AppState>) -> Json<serde_json::Value> {
    let sessions_count = state.sessions.read().await.len();
    let ingest = state.ingest_stats.lock().await.clone();
    let publisher_status = {
        let mut publisher = state.publisher.lock().await;
        refresh_publisher_state_locked(&mut publisher);
        publisher_status_response(&publisher)
    };
    let process = collect_process_metrics().await;
    Json(serde_json::json!({
        "status": "ok",
        "app_started_unix": state.started_unix,
        "app_uptime_secs": state.started_instant.elapsed().as_secs(),
        "sessions": {
            "current": sessions_count,
            "max": state.config.max_sessions
        },
        "config": {
            "ice_servers": state.config.ice_servers,
            "ice_udp4_only": state.config.ice_udp4_only,
            "ice_disconnected_timeout_secs": state.config.ice_disconnected_timeout_secs,
            "ice_failed_timeout_secs": state.config.ice_failed_timeout_secs,
            "ice_keepalive_interval_secs": state.config.ice_keepalive_interval_secs,
            "rtp_listen": state.config.rtp_listen_addr.to_string(),
            "max_stream_secs": state.config.max_stream_secs,
            "auto_stop_no_viewers_secs": state.config.auto_stop_no_viewers_secs
        },
        "publisher": publisher_status,
        "ingest": {
            "rtp_packets": ingest.packets,
            "rtp_bytes": ingest.bytes,
            "rtp_parse_errors": ingest.parse_errors,
            "rtp_write_errors": ingest.write_errors,
            "rtp_last_packet_unix": ingest.last_packet_unix,
            "rtp_last_source": ingest.last_source,
        },
        "process": process
    }))
}

async fn webrtc_offer(
    State(state): State<AppState>,
    Json(req): Json<OfferRequest>,
) -> Result<Json<OfferResponse>, ApiError> {
    let session_id = Uuid::new_v4();
    let rtc_config = if state.config.ice_servers.is_empty() {
        RTCConfiguration::default()
    } else {
        RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: state.config.ice_servers.clone(),
                ..Default::default()
            }],
            ..Default::default()
        }
    };
    let peer = Arc::new(
        state
            .webrtc_api
            .new_peer_connection(rtc_config)
            .await
            .map_err(|e| ApiError::Internal(format!("create peer connection failed: {e}")))?,
    );

    insert_session(&state, session_id, peer.clone()).await?;
    attach_peer_cleanup(state.clone(), session_id, peer.clone());

    let setup_result = async {
        let local_track: Arc<dyn TrackLocal + Send + Sync> = state.video_track.clone();
        let sender = peer
            .add_track(local_track)
            .await
            .map_err(|e| anyhow!("add track failed: {e}"))?;
        spawn_rtcp_reader(session_id, sender);

        let offer =
            RTCSessionDescription::offer(req.sdp).map_err(|e| anyhow!("invalid offer sdp: {e}"))?;
        peer.set_remote_description(offer)
            .await
            .map_err(|e| anyhow!("set remote description failed: {e}"))?;
        let answer = peer
            .create_answer(None)
            .await
            .map_err(|e| anyhow!("create answer failed: {e}"))?;
        let mut gather_complete = peer.gathering_complete_promise().await;
        peer.set_local_description(answer)
            .await
            .map_err(|e| anyhow!("set local description failed: {e}"))?;
        let _ = gather_complete.recv().await;
        let local = peer
            .local_description()
            .await
            .ok_or_else(|| anyhow!("local description unavailable"))?;
        Ok::<RTCSessionDescription, anyhow::Error>(local)
    }
    .await;

    match setup_result {
        Ok(local) => {
            touch_session(&state, session_id).await;
            Ok(Json(OfferResponse {
                session_id,
                sdp: local.sdp,
                sdp_type: "answer".to_string(),
            }))
        }
        Err(err) => {
            warn!("offer setup failed for {session_id}: {err}");
            remove_and_close_session(&state, session_id).await;
            Err(ApiError::BadRequest(err.to_string()))
        }
    }
}

fn spawn_rtcp_reader(session_id: Uuid, sender: Arc<RTCRtpSender>) {
    tokio::spawn(async move {
        loop {
            match sender.read_rtcp().await {
                Ok(_) => {}
                Err(err) => {
                    info!("rtcp reader closed for session {session_id}: {err}");
                    break;
                }
            }
        }
    });
}

async fn webrtc_candidate(
    State(state): State<AppState>,
    Json(req): Json<CandidateRequest>,
) -> Result<StatusCode, ApiError> {
    let peer = get_peer(&state, req.session_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let init = RTCIceCandidateInit {
        candidate: req.candidate,
        sdp_mid: req.sdp_mid,
        sdp_mline_index: req.sdp_mline_index,
        username_fragment: req.username_fragment,
    };
    peer.add_ice_candidate(init)
        .await
        .map_err(|e| ApiError::BadRequest(format!("invalid candidate: {e}")))?;
    touch_session(&state, req.session_id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn webrtc_sessions(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<OwnerQuery>,
) -> Result<Json<SessionsResponse>, ApiError> {
    ensure_owner(&state, &query.token)?;

    let sessions = {
        let guard = state.sessions.read().await;
        guard
            .iter()
            .map(|(session_id, entry)| SessionInfo {
                session_id: *session_id,
                created_unix: entry.created_unix,
                idle_secs: entry.last_seen.elapsed().as_secs(),
            })
            .collect::<Vec<_>>()
    };
    Ok(Json(SessionsResponse {
        count: sessions.len(),
        max: state.config.max_sessions,
        sessions,
    }))
}

async fn webrtc_close_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<OwnerQuery>,
) -> Result<StatusCode, ApiError> {
    ensure_owner(&state, &query.token)?;

    let removed = remove_session(&state, id).await;
    match removed {
        Some(entry) => {
            if let Err(err) = entry.peer.close().await {
                warn!("close peer failed for {id}: {err}");
            }
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(ApiError::NotFound),
    }
}

async fn insert_session(
    state: &AppState,
    session_id: Uuid,
    peer: Arc<RTCPeerConnection>,
) -> Result<(), ApiError> {
    let mut guard = state.sessions.write().await;
    if guard.len() >= state.config.max_sessions {
        let _ = peer.close().await;
        return Err(ApiError::Conflict(format!(
            "viewer penuh: maksimal {}",
            state.config.max_sessions
        )));
    }
    let now = Instant::now();
    guard.insert(
        session_id,
        SessionEntry {
            peer,
            created_unix: now_unix(),
            last_seen: now,
        },
    );
    Ok(())
}

async fn touch_session(state: &AppState, session_id: Uuid) {
    let mut guard = state.sessions.write().await;
    if let Some(entry) = guard.get_mut(&session_id) {
        entry.last_seen = Instant::now();
    }
}

async fn get_peer(state: &AppState, session_id: Uuid) -> Option<Arc<RTCPeerConnection>> {
    let guard = state.sessions.read().await;
    guard.get(&session_id).map(|entry| entry.peer.clone())
}

async fn remove_session(state: &AppState, session_id: Uuid) -> Option<SessionEntry> {
    let mut guard = state.sessions.write().await;
    guard.remove(&session_id)
}

async fn remove_and_close_session(state: &AppState, session_id: Uuid) {
    if let Some(entry) = remove_session(state, session_id).await {
        if let Err(err) = entry.peer.close().await {
            warn!("close peer failed for {session_id}: {err}");
        }
    }
}

fn attach_peer_cleanup(state: AppState, session_id: Uuid, peer: Arc<RTCPeerConnection>) {
    peer.on_peer_connection_state_change(Box::new(move |pc_state: RTCPeerConnectionState| {
        let state_cleanup = state.clone();
        Box::pin(async move {
            info!("session {session_id} state: {pc_state}");
            if matches!(
                pc_state,
                RTCPeerConnectionState::Failed
                    | RTCPeerConnectionState::Closed
                    | RTCPeerConnectionState::Disconnected
            ) {
                let _ = remove_session(&state_cleanup, session_id).await;
            }
        })
    }));
}

fn spawn_cleanup_task(state: AppState) {
    tokio::spawn(async move {
        let ttl = Duration::from_secs(state.config.ttl_secs);
        let mut ticker = interval(Duration::from_secs(15));
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let expired = {
                let mut guard = state.sessions.write().await;
                let expired_ids = guard
                    .iter()
                    .filter_map(|(id, entry)| {
                        let idle = now.duration_since(entry.last_seen);
                        if idle >= ttl {
                            Some(*id)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                expired_ids
                    .into_iter()
                    .filter_map(|id| guard.remove(&id))
                    .collect::<Vec<_>>()
            };

            for session in expired {
                if let Err(err) = session.peer.close().await {
                    warn!("close expired peer failed: {err}");
                }
            }
        }
    });
}

fn spawn_publisher_guard_task(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(5));
        let mut no_viewers_since: Option<Instant> = None;
        loop {
            ticker.tick().await;
            let viewer_count = state.sessions.read().await.len();
            let now = Instant::now();

            if viewer_count == 0 {
                if no_viewers_since.is_none() {
                    no_viewers_since = Some(now);
                }
            } else {
                no_viewers_since = None;
            }

            let mut stop_reason: Option<String> = None;
            {
                let mut publisher = state.publisher.lock().await;
                refresh_publisher_state_locked(&mut publisher);
                if let Some(process) = publisher.running.as_ref() {
                    if state.config.max_stream_secs > 0 {
                        let run_secs = now_unix().saturating_sub(process.started_unix);
                        if run_secs >= state.config.max_stream_secs {
                            stop_reason = Some(format!(
                                "auto-stop: max stream duration reached ({}s >= {}s)",
                                run_secs, state.config.max_stream_secs
                            ));
                        }
                    }

                    if stop_reason.is_none()
                        && state.config.auto_stop_no_viewers_secs > 0
                        && viewer_count == 0
                    {
                        if let Some(since) = no_viewers_since {
                            let idle_secs = now.duration_since(since).as_secs();
                            if idle_secs >= state.config.auto_stop_no_viewers_secs {
                                stop_reason =
                                    Some(format!("auto-stop: no viewers for {}s", idle_secs));
                            }
                        }
                    }
                }
            }

            if let Some(reason) = stop_reason {
                match stop_publisher_process(&state, &reason).await {
                    Ok(true) => {
                        info!("{reason}");
                        no_viewers_since = None;
                    }
                    Ok(false) => {}
                    Err(err) => warn!("publisher guard stop failed: {err:?}"),
                }
            }
        }
    });
}

fn spawn_rtp_ingest_task(state: AppState) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = run_rtp_ingest_loop(state.clone()).await {
                error!("rtp ingest loop error: {err}");
                sleep(Duration::from_secs(2)).await;
            }
        }
    });
}

async fn run_rtp_ingest_loop(state: AppState) -> Result<()> {
    let socket = UdpSocket::bind(state.config.rtp_listen_addr)
        .await
        .with_context(|| format!("bind RTP socket failed: {}", state.config.rtp_listen_addr))?;
    info!(
        "RTP ingest listening on udp://{}",
        state.config.rtp_listen_addr
    );

    let mut buf = vec![0u8; 2048];
    loop {
        let (size, source) = socket
            .recv_from(&mut buf)
            .await
            .context("RTP recv failed")?;

        let mut raw = Bytes::copy_from_slice(&buf[..size]);
        match Packet::unmarshal(&mut raw) {
            Ok(pkt) => {
                {
                    let mut stats = state.ingest_stats.lock().await;
                    stats.packets = stats.packets.saturating_add(1);
                    stats.bytes = stats.bytes.saturating_add(size as u64);
                    stats.last_packet_unix = Some(now_unix());
                    stats.last_source = Some(source.to_string());
                }

                if let Err(err) = state.video_track.write_rtp(&pkt).await {
                    let mut stats = state.ingest_stats.lock().await;
                    stats.write_errors = stats.write_errors.saturating_add(1);
                    warn!("RTP write failed: {err}");
                }
            }
            Err(err) => {
                let mut stats = state.ingest_stats.lock().await;
                stats.parse_errors = stats.parse_errors.saturating_add(1);
                warn!("RTP parse failed from {source}: {err}");
            }
        }
    }
}

async fn stop_publisher_process(state: &AppState, reason: &str) -> Result<bool, ApiError> {
    let mut process = {
        let mut publisher = state.publisher.lock().await;
        refresh_publisher_state_locked(&mut publisher);
        publisher.running.take()
    };

    let Some(mut process) = process.take() else {
        return Ok(false);
    };

    let pid = process.pid;
    if let Err(err) = process.child.start_kill() {
        warn!("publisher start_kill failed for pid={pid:?}: {err}");
    }

    let wait_result = timeout(Duration::from_secs(5), process.child.wait()).await;
    let exit_info = match wait_result {
        Ok(Ok(status)) => PublisherExitInfo {
            exited_unix: now_unix(),
            code: status.code(),
            success: status.success(),
        },
        Ok(Err(err)) => {
            return Err(ApiError::Internal(format!(
                "gagal menunggu publisher stop: {err}"
            )));
        }
        Err(_) => {
            let _ = process.child.kill().await;
            let status = process
                .child
                .wait()
                .await
                .map_err(|e| ApiError::Internal(format!("force kill publisher gagal: {e}")))?;
            PublisherExitInfo {
                exited_unix: now_unix(),
                code: status.code(),
                success: status.success(),
            }
        }
    };

    let mut publisher = state.publisher.lock().await;
    publisher.last_exit = Some(exit_info);
    refresh_publisher_state_locked(&mut publisher);
    info!("publisher stopped pid={pid:?} reason={reason}");
    Ok(true)
}

async fn collect_process_metrics() -> serde_json::Value {
    let mut rss_kb: Option<u64> = None;
    let mut thread_count: Option<u64> = None;
    if let Ok(status) = tokio::fs::read_to_string("/proc/self/status").await {
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("VmRSS:") {
                rss_kb = value
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u64>().ok());
            } else if let Some(value) = line.strip_prefix("Threads:") {
                thread_count = value.trim().parse::<u64>().ok();
            }
        }
    }

    let mut cpu_user_ticks: Option<u64> = None;
    let mut cpu_system_ticks: Option<u64> = None;
    if let Ok(stat) = tokio::fs::read_to_string("/proc/self/stat").await {
        if let Some(end_comm) = stat.rfind(") ") {
            let rest = &stat[end_comm + 2..];
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() > 12 {
                cpu_user_ticks = parts.get(11).and_then(|v| v.parse::<u64>().ok());
                cpu_system_ticks = parts.get(12).and_then(|v| v.parse::<u64>().ok());
            }
        }
    }
    let cpu_total_ticks = match (cpu_user_ticks, cpu_system_ticks) {
        (Some(u), Some(s)) => Some(u.saturating_add(s)),
        _ => None,
    };

    let mut open_fds: u64 = 0;
    if let Ok(mut dir) = tokio::fs::read_dir("/proc/self/fd").await {
        loop {
            match dir.next_entry().await {
                Ok(Some(_)) => open_fds = open_fds.saturating_add(1),
                Ok(None) => break,
                Err(_) => {
                    open_fds = 0;
                    break;
                }
            }
        }
    }

    serde_json::json!({
        "pid": std::process::id(),
        "rss_kb": rss_kb,
        "threads": thread_count,
        "open_fds": open_fds,
        "cpu_user_ticks": cpu_user_ticks,
        "cpu_system_ticks": cpu_system_ticks,
        "cpu_total_ticks": cpu_total_ticks
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(raw) => {
            let v = raw.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
                || (!matches!(v.as_str(), "0" | "false" | "no" | "off") && default)
        }
        Err(_) => default,
    }
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>FamilyCam WebRTC-rs PoC</title>
    <style>
      :root {
        --bg: #f1f5f9;
        --card: #ffffff;
        --border: #e2e8f0;
        --text: #0f172a;
        --muted: #475569;
        --good: #16a34a;
        --warn: #ef4444;
        --soft: #dbeafe;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Segoe UI", "Noto Sans", sans-serif;
        color: var(--text);
        background: radial-gradient(circle at 5% 0%, #e0f2fe 0%, var(--bg) 45%);
      }
      .app {
        max-width: 1220px;
        margin: 0 auto;
        padding: 16px;
      }
      .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 14px;
      }
      .topbar h2 {
        margin: 0;
        letter-spacing: 0.2px;
      }
      .pill {
        background: var(--soft);
        border: 1px solid #bfdbfe;
        border-radius: 999px;
        padding: 7px 12px;
        font-size: 13px;
        color: #1e3a8a;
      }
      .layout {
        display: grid;
        grid-template-columns: 1.65fr 1fr;
        gap: 14px;
      }
      .card {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 14px;
        box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08);
        padding: 14px;
      }
      .card h4 {
        margin: 2px 0 10px 0;
      }
      .row {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        align-items: center;
        margin-bottom: 9px;
      }
      .meta {
        color: var(--muted);
        font-size: 14px;
      }
      button {
        border: 0;
        border-radius: 10px;
        padding: 9px 12px;
        cursor: pointer;
        font-weight: 700;
      }
      .primary { background: var(--good); color: white; }
      .danger { background: var(--warn); color: white; }
      .secondary { background: #e2e8f0; color: #0f172a; }
      input, select {
        border: 1px solid #cbd5e1;
        border-radius: 9px;
        padding: 8px 10px;
        min-height: 38px;
        background: #fff;
        color: var(--text);
      }
      input[type="password"] { min-width: 220px; }
      select { min-width: 170px; }
      #video {
        width: 100%;
        margin-top: 10px;
        border-radius: 12px;
        border: 1px solid #1e293b;
        background: #020617;
        aspect-ratio: 16 / 9;
        max-height: 60vh;
        object-fit: contain;
      }
      #log {
        margin-top: 10px;
        white-space: pre-wrap;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        background: #0f172a;
        color: #e2e8f0;
        border-radius: 10px;
        padding: 10px;
        min-height: 120px;
        max-height: 190px;
        overflow: auto;
      }
      .token-note {
        margin: 0;
        color: var(--muted);
        font-size: 13px;
      }
      @media (max-width: 980px) {
        .layout { grid-template-columns: 1fr; }
        #video { max-height: 46vh; }
      }
    </style>
  </head>
  <body>
    <div class="app">
      <div class="topbar">
        <h2>FamilyCam WebRTC-rs PoC</h2>
        <div class="pill">RTP Target: <strong id="rtpListen">127.0.0.1:5004</strong></div>
      </div>

      <div class="layout">
        <section class="card">
          <h4>Viewer</h4>
          <div class="row">
            <button id="connect" class="primary">Connect</button>
            <button id="disconnect" class="danger">Disconnect</button>
          </div>
          <div class="meta"><strong>Session:</strong> <span id="session">-</span></div>
          <div class="meta"><strong>State:</strong> <span id="state">idle</span></div>
          <video id="video" autoplay playsinline muted></video>
        </section>

        <aside class="card">
          <h4>Controls</h4>
          <div class="row">
            <label for="ownerToken"><strong>Owner Token</strong></label>
            <input id="ownerToken" type="password" placeholder="owner-dev-token" />
            <button id="clearSaved" class="secondary">Clear Saved Settings</button>
          </div>
          <p class="token-note">Token dipakai untuk publisher control dan camera probe.</p>
          <div class="row">
            <button id="pubStatus" class="secondary">Publisher Status</button>
            <button id="pubStart" class="secondary">Start Test Pattern</button>
            <button id="pubStop" class="danger">Stop Publisher</button>
          </div>
          <div class="meta"><strong>Publisher:</strong> <span id="publisherState">unknown</span></div>
          <hr />
          <div class="row">
            <button id="probeCamera" class="secondary">Probe Cameras</button>
          </div>
          <div class="row">
            <select id="cameraDevice">
              <option value="">Pilih kamera...</option>
            </select>
            <select id="cameraFormat">
              <option value="__auto__">Format auto</option>
            </select>
          </div>
          <div class="row">
            <select id="cameraFps">
              <option value="">FPS auto</option>
              <option value="5">5 fps</option>
              <option value="10">10 fps</option>
              <option value="15">15 fps</option>
              <option value="20">20 fps</option>
              <option value="24">24 fps</option>
              <option value="30">30 fps</option>
            </select>
            <select id="cameraSize">
              <option value="">Resolusi auto</option>
              <option value="320x240">320x240</option>
              <option value="640x360">640x360</option>
              <option value="640x480">640x480</option>
              <option value="848x480">848x480</option>
              <option value="960x540">960x540</option>
              <option value="1280x720">1280x720</option>
            </select>
          </div>
          <div class="row">
            <button id="startWebcam" class="primary">Start Webcam</button>
          </div>
          <div id="log"></div>
        </aside>
      </div>
    </div>
    <script>
      const STORAGE_KEY = "familycam_webrtc_poc_ui_v1";
      let pc = null;
      let sessionId = null;
      let publisherPollInFlight = false;
      let healthPollInFlight = false;
      let lastPublisherSummary = "";
      const uiState = {
        rtpListen: "127.0.0.1:5004",
        iceServers: ["stun:stun.l.google.com:19302"],
        cameraFormatsByPath: new Map(),
        preferredCameraDevice: "",
        preferredCameraFormat: "__auto__",
      };
      const elLog = document.getElementById("log");
      const elState = document.getElementById("state");
      const elSession = document.getElementById("session");
      const elOwnerToken = document.getElementById("ownerToken");
      const elPublisherState = document.getElementById("publisherState");
      const elRtpListen = document.getElementById("rtpListen");
      const elCameraDevice = document.getElementById("cameraDevice");
      const elCameraFormat = document.getElementById("cameraFormat");
      const elCameraFps = document.getElementById("cameraFps");
      const elCameraSize = document.getElementById("cameraSize");
      const video = document.getElementById("video");

      function log(msg) {
        const line = `[${new Date().toISOString()}] ${msg}`;
        elLog.textContent = `${line}\n${elLog.textContent}`.slice(0, 6000);
        console.log(msg);
      }

      function loadUiPreferences() {
        try {
          const raw = localStorage.getItem(STORAGE_KEY);
          if (!raw) return null;
          const parsed = JSON.parse(raw);
          return parsed && typeof parsed === "object" ? parsed : null;
        } catch (_) {
          return null;
        }
      }

      function saveUiPreferences() {
        const data = {
          ownerToken: elOwnerToken.value || "",
          cameraDevice: elCameraDevice.value || "",
          cameraFormat: elCameraFormat.value || "__auto__",
          cameraFps: elCameraFps.value || "",
          cameraSize: elCameraSize.value || "",
        };
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
        } catch (_) {
          // ignore storage quota/private mode errors
        }
      }

      function setSelectValueIfExists(selectEl, value) {
        if (!selectEl) return;
        const stringValue = value == null ? "" : String(value);
        const exists = Array.from(selectEl.options).some((opt) => opt.value === stringValue);
        selectEl.value = exists ? stringValue : "";
      }

      function restoreUiPreferences() {
        const data = loadUiPreferences();
        if (!data) return;
        if (typeof data.ownerToken === "string") elOwnerToken.value = data.ownerToken;
        if (typeof data.cameraFps === "string") setSelectValueIfExists(elCameraFps, data.cameraFps);
        if (typeof data.cameraSize === "string") setSelectValueIfExists(elCameraSize, data.cameraSize);
        if (typeof data.cameraDevice === "string") uiState.preferredCameraDevice = data.cameraDevice;
        if (typeof data.cameraFormat === "string") uiState.preferredCameraFormat = data.cameraFormat;
      }

      function clearSavedSettings() {
        try {
          localStorage.removeItem(STORAGE_KEY);
        } catch (_) {
          // ignore storage errors
        }
        elOwnerToken.value = "";
        setSelectValueIfExists(elCameraFps, "");
        setSelectValueIfExists(elCameraSize, "");
        uiState.preferredCameraDevice = "";
        uiState.preferredCameraFormat = "__auto__";
        uiState.cameraFormatsByPath.clear();
        elCameraDevice.innerHTML = `<option value="">Pilih kamera...</option>`;
        elCameraFormat.innerHTML = `<option value="__auto__">Format auto</option>`;
        elPublisherState.textContent = "unknown";
        lastPublisherSummary = "";
        log("saved settings dibersihkan");
      }

      function ownerToken() {
        return elOwnerToken.value.trim();
      }

      async function publisherRequest(path, method = "GET", body = null) {
        const token = ownerToken();
        if (!token) {
          throw new Error("owner token belum diisi");
        }
        const url = `${path}?token=${encodeURIComponent(token)}`;
        const resp = await fetch(url, {
          method,
          headers: { "Content-Type": "application/json" },
          body: body ? JSON.stringify(body) : null,
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          throw new Error(data.error || `HTTP ${resp.status}`);
        }
        return data;
      }

      function renderPublisherStatus(data) {
        const running = data.running ? "running" : "stopped";
        const pid = data.pid ? ` pid=${data.pid}` : "";
        const summary = `${running}${pid}`;
        elPublisherState.textContent = summary;
        return summary;
      }

      async function refreshHealth(silent = true) {
        if (healthPollInFlight) return;
        healthPollInFlight = true;
        try {
          const resp = await fetch("/healthz");
          const data = await resp.json();
          if (resp.ok && data.rtp_listen) {
            uiState.rtpListen = data.rtp_listen;
            elRtpListen.textContent = data.rtp_listen;
          }
          if (resp.ok && Array.isArray(data.ice_servers)) {
            uiState.iceServers = data.ice_servers.filter((v) => typeof v === "string" && v.trim().length > 0);
          }
          if (!silent) {
            log(`health ok rtp=${uiState.rtpListen} ice=${uiState.iceServers.join(",") || "-"}`);
          }
        } catch (_) {
          if (!silent) {
            log("health check gagal");
          }
        } finally {
          healthPollInFlight = false;
        }
      }

      async function doPublisherStatus() {
        try {
          const data = await publisherRequest("/publisher/status");
          const summary = renderPublisherStatus(data);
          lastPublisherSummary = summary;
          log(`publisher status: ${data.running ? "running" : "stopped"}`);
        } catch (err) {
          log(`publisher status gagal: ${err.message || err}`);
        }
      }

      async function doPublisherStart() {
        try {
          const data = await publisherRequest("/publisher/start", "POST");
          const summary = renderPublisherStatus(data);
          lastPublisherSummary = summary;
          log(`publisher started pid=${data.pid || "-"}`);
        } catch (err) {
          log(`publisher start gagal: ${err.message || err}`);
        }
      }

      async function doPublisherStop() {
        try {
          const data = await publisherRequest("/publisher/stop", "POST");
          const summary = renderPublisherStatus(data);
          lastPublisherSummary = summary;
          log("publisher stopped");
        } catch (err) {
          log(`publisher stop gagal: ${err.message || err}`);
        }
      }

      function toFfmpegInputFormat(formatCode) {
        if (!formatCode || formatCode === "__auto__") return null;
        const mapping = {
          MJPG: "mjpeg",
          JPEG: "mjpeg",
          H264: "h264",
          YUYV: "yuyv422",
          YUY2: "yuyv422",
          NV12: "nv12",
        };
        const key = formatCode.toUpperCase();
        return mapping[key] || formatCode.toLowerCase();
      }

      function setDeviceOptions(cameras) {
        uiState.cameraFormatsByPath.clear();
        elCameraDevice.innerHTML = `<option value="">Pilih kamera...</option>`;
        for (const cam of cameras) {
          uiState.cameraFormatsByPath.set(cam.path, cam.formats || []);
          const option = document.createElement("option");
          option.value = cam.path;
          option.textContent = `${cam.label} (${cam.path})`;
          elCameraDevice.appendChild(option);
        }

        if (
          uiState.preferredCameraDevice &&
          uiState.cameraFormatsByPath.has(uiState.preferredCameraDevice)
        ) {
          elCameraDevice.value = uiState.preferredCameraDevice;
        }
      }

      function refreshFormatOptions(preferredFormat = null) {
        const path = elCameraDevice.value;
        const formats = uiState.cameraFormatsByPath.get(path) || [];
        elCameraFormat.innerHTML = `<option value="__auto__">Format auto</option>`;
        for (const f of formats) {
          const option = document.createElement("option");
          option.value = f;
          option.textContent = f;
          elCameraFormat.appendChild(option);
        }

        const formatToApply = preferredFormat || uiState.preferredCameraFormat || "__auto__";
        const exists = Array.from(elCameraFormat.options).some((opt) => opt.value === formatToApply);
        elCameraFormat.value = exists ? formatToApply : "__auto__";
      }

      async function doCameraProbe() {
        try {
          const data = await publisherRequest("/camera/probe");
          setDeviceOptions(data.cameras || []);
          refreshFormatOptions();
          saveUiPreferences();
          log(`probe selesai: ${data.count || 0} camera ditemukan`);
        } catch (err) {
          log(`camera probe gagal: ${err.message || err}`);
        }
      }

      async function doStartWebcam() {
        try {
          await refreshHealth(true);
          const device = elCameraDevice.value;
          if (!device) {
            log("pilih kamera dulu");
            return;
          }
          const format = elCameraFormat.value;
          const fps = elCameraFps.value.trim();
          const size = elCameraSize.value.trim();
          saveUiPreferences();

          const args = ["-f", "v4l2"];
          const ffFormat = toFfmpegInputFormat(format);
          if (ffFormat) args.push("-input_format", ffFormat);
          if (fps) args.push("-framerate", fps);
          if (size) args.push("-video_size", size);
          args.push("-i", device, "-an");

          const formatCode = (format || "").toUpperCase();
          const canCopy = formatCode === "H264";
          if (canCopy) {
            args.push("-c:v", "copy");
          } else {
            args.push(
              "-c:v", "libx264",
              "-preset", "ultrafast",
              "-tune", "zerolatency",
              "-pix_fmt", "yuv420p",
              "-profile:v", "baseline",
              "-level", "3.1",
              "-g", "30",
              "-keyint_min", "30",
              "-sc_threshold", "0"
            );
          }
          args.push("-f", "rtp", `rtp://${uiState.rtpListen}`);

          const data = await publisherRequest("/publisher/start", "POST", { bin: "ffmpeg", args });
          const summary = renderPublisherStatus(data);
          lastPublisherSummary = summary;
          log(`webcam publisher started ${device} -> ${uiState.rtpListen}`);
        } catch (err) {
          log(`start webcam gagal: ${err.message || err}`);
        }
      }

      async function pollPublisherStatus() {
        if (publisherPollInFlight) return;
        const token = ownerToken();
        if (!token) return;
        publisherPollInFlight = true;
        try {
          const data = await publisherRequest("/publisher/status");
          const summary = renderPublisherStatus(data);
          if (summary !== lastPublisherSummary) {
            log(`publisher auto-refresh: ${summary}`);
            lastPublisherSummary = summary;
          }
        } catch (_) {
          // silent on background poll to avoid noisy logs
        } finally {
          publisherPollInFlight = false;
        }
      }

      async function connect() {
        if (pc) return;
        const iceServers = (uiState.iceServers || []).map((url) => ({ urls: url }));
        pc = iceServers.length > 0
          ? new RTCPeerConnection({ iceServers })
          : new RTCPeerConnection();
        log(`connect using ICE servers: ${iceServers.map((s) => s.urls).join(",") || "(none)"}`);
        pc.addTransceiver("video", { direction: "recvonly" });
        pc.ontrack = (ev) => {
          if (ev.streams && ev.streams[0]) {
            video.srcObject = ev.streams[0];
            log("received remote video track");
          }
        };
        pc.onconnectionstatechange = () => {
          elState.textContent = pc.connectionState;
          log(`pc state = ${pc.connectionState}`);
        };
        pc.onicecandidate = async (ev) => {
          if (!ev.candidate || !sessionId) return;
          try {
            await fetch("/webrtc/candidate", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                session_id: sessionId,
                candidate: ev.candidate.candidate,
                sdpMid: ev.candidate.sdpMid,
                sdpMLineIndex: ev.candidate.sdpMLineIndex,
                usernameFragment: ev.candidate.usernameFragment,
              }),
            });
          } catch (err) {
            log(`candidate post error: ${err}`);
          }
        };

        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        const resp = await fetch("/webrtc/offer", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sdp: offer.sdp }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          log(`offer failed: ${JSON.stringify(data)}`);
          await disconnect();
          return;
        }
        sessionId = data.session_id;
        elSession.textContent = sessionId;
        await pc.setRemoteDescription({ type: data.type, sdp: data.sdp });
        log(`connected with session ${sessionId}`);
      }

      async function disconnect() {
        if (!pc) return;
        try {
          pc.close();
        } catch (_) {}
        pc = null;
        elState.textContent = "closed";
        if (sessionId) {
          log(`session ${sessionId} closed locally`);
        }
        sessionId = null;
        elSession.textContent = "-";
      }

      document.getElementById("connect").addEventListener("click", connect);
      document.getElementById("disconnect").addEventListener("click", disconnect);
      document.getElementById("pubStatus").addEventListener("click", doPublisherStatus);
      document.getElementById("pubStart").addEventListener("click", doPublisherStart);
      document.getElementById("pubStop").addEventListener("click", doPublisherStop);
      document.getElementById("probeCamera").addEventListener("click", doCameraProbe);
      document.getElementById("startWebcam").addEventListener("click", doStartWebcam);
      document.getElementById("clearSaved").addEventListener("click", clearSavedSettings);
      elCameraDevice.addEventListener("change", () => {
        refreshFormatOptions("__auto__");
        saveUiPreferences();
      });
      elCameraFormat.addEventListener("change", saveUiPreferences);
      elCameraFps.addEventListener("change", saveUiPreferences);
      elCameraSize.addEventListener("change", saveUiPreferences);
      elOwnerToken.addEventListener("input", saveUiPreferences);
      elOwnerToken.addEventListener("change", pollPublisherStatus);
      elOwnerToken.addEventListener("blur", pollPublisherStatus);
      restoreUiPreferences();
      refreshHealth(true);
      if (ownerToken()) {
        doCameraProbe();
        pollPublisherStatus();
      }
      setInterval(pollPublisherStatus, 5000);
      setInterval(() => refreshHealth(true), 6000);
    </script>
  </body>
</html>
"#;
