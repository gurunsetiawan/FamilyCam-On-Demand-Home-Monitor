use std::{path::PathBuf, sync::Arc, time::Instant};

use tokio::sync::{Mutex, Semaphore};
use tracing::warn;

use crate::{
    camera::service::CameraService, config::AppConfig, notify::telegram::TelegramNotifier,
};

pub struct AppState {
    pub config: AppConfig,
    pub camera: Mutex<CameraService<crate::camera::ffmpeg_backend::FfmpegBackend>>,
    pub stream_limit: Arc<Semaphore>,
    pub last_activity: Mutex<Instant>,
    pub session_token: String,
    pub session_cookie_name: &'static str,
    pub notifier: Option<Arc<TelegramNotifier>>,
    latest_stream_frame: Mutex<Option<Vec<u8>>>,
    snapshot_path: PathBuf,
}

impl AppState {
    pub fn new(
        config: AppConfig,
        camera: CameraService<crate::camera::ffmpeg_backend::FfmpegBackend>,
        session_token: String,
        notifier: Option<TelegramNotifier>,
    ) -> Self {
        Self {
            config,
            camera: Mutex::new(camera),
            stream_limit: Arc::new(Semaphore::new(1)),
            last_activity: Mutex::new(Instant::now()),
            session_token,
            session_cookie_name: "familycam_session",
            notifier: notifier.map(Arc::new),
            latest_stream_frame: Mutex::new(None),
            snapshot_path: PathBuf::from("snapshots/latest.jpg"),
        }
    }

    pub async fn update_activity(&self) {
        let mut last_activity = self.last_activity.lock().await;
        *last_activity = Instant::now();
    }

    pub async fn idle_seconds(&self) -> u64 {
        let last_activity = self.last_activity.lock().await;
        last_activity.elapsed().as_secs()
    }

    pub fn snapshot_path(&self) -> &PathBuf {
        &self.snapshot_path
    }

    pub async fn set_latest_stream_frame(&self, frame: Vec<u8>) {
        let mut latest = self.latest_stream_frame.lock().await;
        *latest = Some(frame);
    }

    pub async fn latest_stream_frame(&self) -> Option<Vec<u8>> {
        let latest = self.latest_stream_frame.lock().await;
        latest.clone()
    }

    pub async fn clear_latest_stream_frame(&self) {
        let mut latest = self.latest_stream_frame.lock().await;
        *latest = None;
    }

    pub fn notify(&self, message: impl Into<String>) {
        let Some(notifier) = self.notifier.clone() else {
            return;
        };
        let message = message.into();

        tokio::spawn(async move {
            if let Err(err) = notifier.send_message(&message).await {
                warn!("telegram notify failed: {err}");
            }
        });
    }
}
