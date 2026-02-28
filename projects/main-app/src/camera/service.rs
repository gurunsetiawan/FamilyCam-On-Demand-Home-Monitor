use anyhow::{Result, bail};
use tokio::{process::Child, sync::watch};

use crate::core::state::{CameraState, CameraStatus};

use super::traits::CameraBackend;

pub struct StreamSession {
    pub child: Child,
    pub cancel_rx: watch::Receiver<bool>,
}

pub struct CameraService<B: CameraBackend> {
    backend: B,
    state: CameraState,
    enabled: bool,
    stream_active: bool,
    stream_cancel_tx: Option<watch::Sender<bool>>,
}

impl<B: CameraBackend> CameraService<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: CameraState::Idle,
            enabled: false,
            stream_active: false,
            stream_cancel_tx: None,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.enabled {
            return Ok(());
        }

        self.state = CameraState::Starting;
        self.enabled = true;
        self.state = CameraState::Idle;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.enabled && !self.stream_active {
            return Ok(());
        }

        self.state = CameraState::Stopping;
        self.enabled = false;
        if let Some(cancel_tx) = self.stream_cancel_tx.take() {
            let _ = cancel_tx.send(true);
        }

        if !self.stream_active {
            self.state = CameraState::Idle;
        }
        Ok(())
    }

    pub async fn open_stream_session(&mut self) -> Result<StreamSession> {
        if !self.enabled {
            bail!("camera is not started");
        }
        if self.stream_active {
            bail!("stream already active");
        }

        self.state = CameraState::Starting;
        let child = self.backend.spawn_stream().await?;
        let (cancel_tx, cancel_rx) = watch::channel(false);
        self.stream_cancel_tx = Some(cancel_tx);
        self.stream_active = true;
        self.state = CameraState::Streaming;

        Ok(StreamSession { child, cancel_rx })
    }

    pub fn finish_stream_session(&mut self) {
        self.stream_active = false;
        self.stream_cancel_tx = None;
        self.state = CameraState::Idle;
    }

    pub async fn snapshot(&self, output_path: &std::path::Path) -> Result<()> {
        self.backend.take_snapshot(output_path).await
    }

    pub fn is_stream_active(&self) -> bool {
        self.stream_active
    }

    pub fn reconfigure_backend(&mut self, update: impl FnOnce(&mut B)) -> Result<()> {
        if self.enabled || self.stream_active {
            bail!("stop camera and close stream before reconfiguring");
        }

        update(&mut self.backend);
        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn status(&self) -> CameraStatus {
        CameraStatus {
            enabled: self.enabled,
            stream_active: self.stream_active,
            state: self.state,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;

    use async_trait::async_trait;
    use tokio::process::{Child, Command};

    use crate::camera::traits::CameraBackend;

    use super::CameraService;

    struct MockBackend;

    #[async_trait]
    impl CameraBackend for MockBackend {
        async fn spawn_stream(&self) -> anyhow::Result<Child> {
            let child = Command::new("sh")
                .arg("-c")
                .arg("sleep 30")
                .stdout(Stdio::piped())
                .spawn()?;
            Ok(child)
        }

        async fn take_snapshot(&self, output_path: &std::path::Path) -> anyhow::Result<()> {
            tokio::fs::write(output_path, b"test").await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn start_and_stop_are_idempotent() {
        let mut service = CameraService::new(MockBackend);

        service.start().await.expect("first start should succeed");
        service.start().await.expect("second start should succeed");
        assert!(service.is_enabled());

        service.stop().await.expect("first stop should succeed");
        service.stop().await.expect("second stop should succeed");
        assert!(!service.is_enabled());
    }

    #[tokio::test]
    async fn cannot_open_stream_when_not_started() {
        let mut service = CameraService::new(MockBackend);
        let result = service.open_stream_session().await;
        assert!(result.is_err(), "stream should fail when camera is idle");
        let err = result.err().expect("error should exist");
        assert!(err.to_string().contains("not started"));
    }

    #[tokio::test]
    async fn only_one_stream_session_is_allowed() {
        let mut service = CameraService::new(MockBackend);
        service.start().await.expect("camera should start");

        let mut session = service
            .open_stream_session()
            .await
            .expect("first stream should succeed");

        let result = service.open_stream_session().await;
        assert!(result.is_err(), "second stream should fail");
        let err = result.err().expect("error should exist");
        assert!(err.to_string().contains("already active"));

        let _ = session.child.kill().await;
        let _ = session.child.wait().await;
        service.finish_stream_session();

        service.stop().await.expect("camera should stop");
    }
}
