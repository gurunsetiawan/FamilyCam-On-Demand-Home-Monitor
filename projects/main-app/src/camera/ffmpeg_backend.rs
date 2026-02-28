use std::{path::Path, process::Stdio};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::process::{Child, Command};

use super::traits::CameraBackend;

#[derive(Debug, Clone)]
pub struct FfmpegBackend {
    device: String,
    input_format: String,
}

impl FfmpegBackend {
    pub fn new(device: String, input_format: String) -> Self {
        Self {
            device,
            input_format,
        }
    }

    pub fn set_device(&mut self, device: String) {
        self.device = device;
    }

    pub fn set_input_format(&mut self, input_format: String) {
        self.input_format = input_format;
    }
}

#[async_trait]
impl CameraBackend for FfmpegBackend {
    async fn spawn_stream(&self) -> Result<Child> {
        let child = Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "v4l2",
                "-input_format",
                &self.input_format,
                "-i",
                &self.device,
                "-f",
                "mpjpeg",
                "-boundary_tag",
                "familycam",
                "pipe:1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn ffmpeg stream process")?;

        Ok(child)
    }

    async fn take_snapshot(&self, output_path: &Path) -> Result<()> {
        let status = Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "v4l2",
                "-input_format",
                &self.input_format,
                "-i",
                &self.device,
                "-frames:v",
                "1",
                "-y",
            ])
            .arg(output_path.as_os_str())
            .status()
            .await
            .context("failed to execute ffmpeg snapshot command")?;

        if !status.success() {
            bail!("ffmpeg snapshot exited with {status}");
        }

        Ok(())
    }
}
