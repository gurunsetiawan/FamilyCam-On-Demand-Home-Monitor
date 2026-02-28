use std::{collections::BTreeSet, path::Path, sync::Arc};

use axum::{
    Json,
    body::Body,
    extract::{Form, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, SET_COOKIE},
    },
    response::{Html, IntoResponse, Redirect, Response},
};
use bytes::Bytes;
use serde::Serialize;
use tokio::{
    fs,
    io::AsyncReadExt,
    sync::mpsc::{self},
    time::{Duration, sleep},
};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};

use crate::{
    app_state::AppState,
    camera::{discovery, jpeg::JpegFrameAccumulator},
    core::errors::AppError,
};

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    password: String,
}

#[derive(serde::Deserialize)]
pub struct CameraSelectRequest {
    device: String,
    input_format: Option<String>,
}

#[derive(Serialize)]
pub struct CameraSelectResponse {
    device: String,
    input_format: String,
    message: &'static str,
}

pub async fn root() -> Redirect {
    Redirect::to("/static/index.html")
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Form(payload): Form<LoginRequest>,
) -> Result<Response, AppError> {
    if payload.password != state.config.app_password {
        return Err(AppError::new(StatusCode::UNAUTHORIZED, "invalid password"));
    }

    let cookie_value = format!(
        "{}={}; HttpOnly; Path=/; Max-Age=1800; SameSite=Lax",
        state.session_cookie_name, state.session_token
    );
    let cookie_header = HeaderValue::from_str(&cookie_value)
        .map_err(|err| AppError::internal(format!("failed to set session cookie: {err}")))?;

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie_header);

    info!("login success");
    Ok((StatusCode::OK, headers, "ok").into_response())
}

pub async fn status(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    let camera = state.camera.lock().await;
    let status = camera.status();

    let label = if status.stream_active {
        "Streaming"
    } else if status.enabled {
        "Started"
    } else {
        "Idle"
    };
    let color = if status.stream_active {
        "is-success"
    } else if status.enabled {
        "is-warning"
    } else {
        "is-dark"
    };

    Ok(Html(format!(
        "<span class=\"tag {color} is-medium\">{label}</span>"
    )))
}

pub async fn cameras() -> Result<Json<Vec<discovery::CameraProbeInfo>>, AppError> {
    let list = discovery::probe_cameras()
        .await
        .map_err(|err| AppError::internal(format!("camera probe failed: {err}")))?;
    Ok(Json(list))
}

pub async fn camera_select(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CameraSelectRequest>,
) -> Result<Json<CameraSelectResponse>, AppError> {
    let selected_device = payload.device.trim().to_string();
    if !selected_device.starts_with("/dev/video") {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "device must start with /dev/video",
        ));
    }
    if !Path::new(&selected_device).exists() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            format!("device not found: {selected_device}"),
        ));
    }

    let selected_format = payload
        .input_format
        .unwrap_or_else(|| state.config.camera_input_format.clone())
        .trim()
        .to_string();
    if selected_format.is_empty() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "input_format cannot be empty",
        ));
    }

    let discovered = discovery::probe_cameras()
        .await
        .map_err(|err| AppError::internal(format!("camera probe failed: {err}")))?;
    let known_devices: BTreeSet<String> = discovered
        .into_iter()
        .flat_map(|camera| camera.devices.into_iter().map(|item| item.path))
        .collect();
    if !known_devices.is_empty() && !known_devices.contains(&selected_device) {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            format!("device is not in probe result: {selected_device}"),
        ));
    }

    {
        let mut camera = state.camera.lock().await;
        if camera.is_enabled() || camera.is_stream_active() {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "stop camera and stream first before switching device",
            ));
        }

        camera
            .reconfigure_backend(|backend| {
                backend.set_device(selected_device.clone());
                backend.set_input_format(selected_format.clone());
            })
            .map_err(|err| AppError::new(StatusCode::CONFLICT, err.to_string()))?;
    }

    info!(
        "camera runtime reconfigured: device={} input_format={}",
        selected_device, selected_format
    );
    state.notify(format!(
        "{} camera switched to {} ({})",
        state.config.app_name, selected_device, selected_format
    ));

    Ok(Json(CameraSelectResponse {
        device: selected_device,
        input_format: selected_format,
        message: "camera runtime config updated",
    }))
}

pub async fn start(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    {
        let mut camera = state.camera.lock().await;
        camera
            .start()
            .await
            .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, err.to_string()))?;
    }
    state.update_activity().await;
    info!("camera start requested");
    state.notify(format!("{} camera started from web", state.config.app_name));
    Ok(Html(
        "<span class=\"tag is-warning is-medium\">Started</span>",
    ))
}

pub async fn stop(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    {
        let mut camera = state.camera.lock().await;
        camera
            .stop()
            .await
            .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, err.to_string()))?;
    }

    // Wait briefly until stream session actually closes so device lock is released.
    for _ in 0..20 {
        let stream_active = {
            let camera = state.camera.lock().await;
            camera.is_stream_active()
        };
        if !stream_active {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    state.clear_latest_stream_frame().await;
    state.update_activity().await;
    info!("camera stop requested");
    Ok(Html("<span class=\"tag is-dark is-medium\">Idle</span>"))
}

pub async fn stream(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let permit = state
        .stream_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::new(StatusCode::LOCKED, "single-client mode: stream busy"))?;

    let session = {
        let mut camera = state.camera.lock().await;
        camera.open_stream_session().await.map_err(|err| {
            AppError::new(
                StatusCode::CONFLICT,
                format!("camera cannot stream: {}", err),
            )
        })?
    };
    let mut child = session.child;
    let mut cancel_rx = session.cancel_rx;

    let mut stdout = child.stdout.take().ok_or_else(|| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing ffmpeg stdout pipe for stream",
        )
    })?;

    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    let task_state = state.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        let mut frame_acc = JpegFrameAccumulator::new();
        loop {
            tokio::select! {
                changed = cancel_rx.changed() => {
                    if changed.is_ok() && *cancel_rx.borrow() {
                        info!("stream cancelled by stop request");
                    }
                    break;
                }
                read = stdout.read(&mut buffer) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            task_state.update_activity().await;
                            if let Some(frame) = frame_acc.push_chunk(&buffer[..n]) {
                                task_state.set_latest_stream_frame(frame).await;
                            }
                            if tx.send(Ok(Bytes::copy_from_slice(&buffer[..n]))).await.is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            let _ = tx.send(Err(err)).await;
                            break;
                        }
                    }
                }
            }
        }

        if let Err(err) = child.kill().await {
            warn!("failed to kill ffmpeg stream child: {err}");
        }
        if let Err(err) = child.wait().await {
            warn!("failed to wait ffmpeg stream child: {err}");
        }

        {
            let mut camera = task_state.camera.lock().await;
            camera.finish_stream_session();
        }
        task_state.clear_latest_stream_frame().await;

        drop(permit);
        info!("stream session closed");
    });

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("multipart/x-mixed-replace; boundary=familycam"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    Ok((
        StatusCode::OK,
        headers,
        Body::from_stream(ReceiverStream::new(rx)),
    )
        .into_response())
}

pub async fn snapshot(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let stream_active = {
        let camera = state.camera.lock().await;
        camera.is_stream_active()
    };

    if stream_active {
        if let Some(frame) = state.latest_stream_frame().await {
            state.update_activity().await;
            info!("snapshot served from active stream frame cache");
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            return Ok((StatusCode::OK, headers, frame).into_response());
        }
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "stream active but no frame cached yet; wait a moment and retry snapshot",
        ));
    }

    let snapshot_path = state.snapshot_path().clone();

    let mut last_error: Option<anyhow::Error> = None;
    for _ in 0..5 {
        let result = {
            let camera = state.camera.lock().await;
            camera.snapshot(&snapshot_path).await
        };
        match result {
            Ok(_) => {
                last_error = None;
                break;
            }
            Err(err) => {
                let msg = err.to_string().to_lowercase();
                if msg.contains("resource busy") || msg.contains("device or resource busy") {
                    last_error = Some(err);
                    sleep(Duration::from_millis(150)).await;
                    continue;
                }
                return Err(AppError::new(
                    StatusCode::CONFLICT,
                    format!("snapshot failed: {err}"),
                ));
            }
        }
    }
    if let Some(err) = last_error {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            format!(
                "snapshot failed: {}. device still busy, stop other camera apps and retry",
                err
            ),
        ));
    }

    state.update_activity().await;
    info!("snapshot generated");
    let data = fs::read(&snapshot_path)
        .await
        .map_err(|err| AppError::internal(format!("failed to read snapshot: {err}")))?;

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    Ok((StatusCode::OK, headers, data).into_response())
}

pub async fn panic(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    error!("panic endpoint triggered");
    state.notify(format!("{} panic button triggered", state.config.app_name));
    Ok((StatusCode::ACCEPTED, "panic event queued"))
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use axum::{
        extract::{Form, State},
        http::{StatusCode, header::SET_COOKIE},
        response::IntoResponse,
    };

    use crate::{
        app_state::AppState,
        camera::{ffmpeg_backend::FfmpegBackend, service::CameraService},
        config::AppConfig,
    };

    use super::{LoginRequest, login};

    fn test_state() -> Arc<AppState> {
        let config = AppConfig {
            app_name: "FamilyCam".to_string(),
            bind_addr: "127.0.0.1:8080"
                .parse::<SocketAddr>()
                .expect("socket addr should parse"),
            auto_shutdown_seconds: 120,
            camera_device: "/dev/video0".to_string(),
            camera_input_format: "mjpeg".to_string(),
            app_password: "topsecret".to_string(),
            telegram_bot_token: None,
            telegram_chat_id: None,
        };
        let camera = CameraService::new(FfmpegBackend::new(
            config.camera_device.clone(),
            config.camera_input_format.clone(),
        ));
        Arc::new(AppState::new(
            config,
            camera,
            "sessiontoken".to_string(),
            None,
        ))
    }

    #[tokio::test]
    async fn login_success_sets_session_cookie() {
        let state = test_state();
        let response = login(
            State(state),
            Form(LoginRequest {
                password: "topsecret".to_string(),
            }),
        )
        .await
        .expect("login should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(SET_COOKIE));
    }

    #[tokio::test]
    async fn login_fails_with_wrong_password() {
        let state = test_state();
        let err = login(
            State(state),
            Form(LoginRequest {
                password: "wrong-password".to_string(),
            }),
        )
        .await
        .expect_err("login should fail");

        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
