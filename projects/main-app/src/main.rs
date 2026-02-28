mod app_state;
mod camera;
mod config;
mod core;
mod notify;
mod web;

use std::{sync::Arc, time::Duration};

use app_state::AppState;
use camera::{ffmpeg_backend::FfmpegBackend, service::CameraService};
use config::AppConfig;
use notify::telegram::TelegramNotifier;
use tokio::time::sleep;
use tracing::{error, info};
use tracing_appender::rolling;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    if std::env::args().any(|arg| arg == "--probe-cameras") {
        let cameras = camera::discovery::probe_cameras().await?;
        println!("{}", serde_json::to_string_pretty(&cameras)?);
        return Ok(());
    }

    tokio::fs::create_dir_all("logs").await?;
    let file_appender = rolling::daily("logs", "familycam.log");
    let (non_blocking, _log_guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(non_blocking)
        .with_max_level(tracing::Level::INFO)
        .init();

    let config = AppConfig::from_env()?;
    tokio::fs::create_dir_all("static").await?;
    tokio::fs::create_dir_all("snapshots").await?;

    let backend = FfmpegBackend::new(
        config.camera_device.clone(),
        config.camera_input_format.clone(),
    );
    let camera = CameraService::new(backend);
    let session_token = format!(
        "{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    );

    let notifier = TelegramNotifier::from_config(&config);
    let state = Arc::new(AppState::new(
        config.clone(),
        camera,
        session_token,
        notifier,
    ));
    let app = web::routes::build_router(state.clone());
    state.notify(format!(
        "{} booted on {} (device: {})",
        config.app_name, config.bind_addr, config.camera_device
    ));

    {
        let auto_state = state.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(15)).await;
                let idle_seconds = auto_state.idle_seconds().await;
                if idle_seconds <= auto_state.config.auto_shutdown_seconds {
                    continue;
                }

                let mut camera = auto_state.camera.lock().await;
                if camera.is_enabled() {
                    info!(
                        "Auto shutdown triggered after {} seconds idle",
                        idle_seconds
                    );
                    if let Err(err) = camera.stop().await {
                        error!("Failed to auto stop camera: {err}");
                    } else {
                        auto_state.notify(format!(
                            "{} auto-stopped after {idle_seconds}s idle",
                            auto_state.config.app_name
                        ));
                    }
                }
            }
        });
    }

    info!("FamilyCam listening on {}", config.bind_addr);
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
