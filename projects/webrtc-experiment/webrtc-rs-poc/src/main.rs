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
    ice_transport::ice_candidate::RTCIceCandidateInit,
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
    max_viewers: usize,
    ttl_secs: u64,
    owner_token: String,
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
        let max_viewers = env::var("POC_MAX_VIEWERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(3);
        let ttl_secs = env::var("POC_SESSION_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(600);
        let owner_token =
            env::var("POC_OWNER_TOKEN").unwrap_or_else(|_| "owner-dev-token".to_string());
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
            "-f lavfi -i testsrc=size=640x360:rate=10 -an -c:v libx264 -preset ultrafast -tune zerolatency -pix_fmt yuv420p -f rtp rtp://{}",
            rtp_listen_addr
        );
        let publisher_args = env::var("POC_PUBLISHER_ARGS")
            .unwrap_or(publisher_default_args)
            .split_whitespace()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        Ok(Self {
            bind_addr,
            max_viewers,
            ttl_secs,
            owner_token,
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

#[derive(Default)]
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
    let webrtc_api = Arc::new(build_webrtc_api()?);
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
        webrtc_api,
        video_track,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        ingest_stats: Arc::new(Mutex::new(IngestStats::default())),
        publisher: Arc::new(Mutex::new(PublisherState::default())),
    };
    spawn_cleanup_task(state.clone());
    spawn_rtp_ingest_task(state.clone());

    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
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

fn build_webrtc_api() -> Result<webrtc::api::API> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;

    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;

    Ok(APIBuilder::new()
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

    let mut process = {
        let mut publisher = state.publisher.lock().await;
        refresh_publisher_state_locked(&mut publisher);
        publisher.running.take()
    };

    let Some(mut process) = process.take() else {
        return Err(ApiError::Conflict(
            "publisher tidak sedang berjalan".to_string(),
        ));
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

    {
        let mut publisher = state.publisher.lock().await;
        publisher.last_exit = Some(exit_info);
        refresh_publisher_state_locked(&mut publisher);
        info!("publisher stopped pid={pid:?}");
        Ok(Json(publisher_status_response(&publisher)))
    }
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
        "max_viewers": state.config.max_viewers,
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

async fn webrtc_offer(
    State(state): State<AppState>,
    Json(req): Json<OfferRequest>,
) -> Result<Json<OfferResponse>, ApiError> {
    let session_id = Uuid::new_v4();
    let peer = Arc::new(
        state
            .webrtc_api
            .new_peer_connection(RTCConfiguration::default())
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
        max: state.config.max_viewers,
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
    if guard.len() >= state.config.max_viewers {
        let _ = peer.close().await;
        return Err(ApiError::Conflict(format!(
            "viewer penuh: maksimal {}",
            state.config.max_viewers
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
            <input id="cameraFps" type="text" placeholder="FPS (contoh 15)" />
            <input id="cameraSize" type="text" placeholder="Resolusi (contoh 640x480)" />
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

      function restoreUiPreferences() {
        const data = loadUiPreferences();
        if (!data) return;
        if (typeof data.ownerToken === "string") elOwnerToken.value = data.ownerToken;
        if (typeof data.cameraFps === "string") elCameraFps.value = data.cameraFps;
        if (typeof data.cameraSize === "string") elCameraSize.value = data.cameraSize;
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
        elCameraFps.value = "";
        elCameraSize.value = "";
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
          if (!silent) {
            log(`health ok rtp=${uiState.rtpListen}`);
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
              "-pix_fmt", "yuv420p"
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
        pc = new RTCPeerConnection();
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
      elCameraFps.addEventListener("input", saveUiPreferences);
      elCameraSize.addEventListener("input", saveUiPreferences);
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
