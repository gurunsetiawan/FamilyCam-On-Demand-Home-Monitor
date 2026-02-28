use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use tokio::process::Child;

#[async_trait]
pub trait CameraBackend: Send + Sync {
    async fn spawn_stream(&self) -> Result<Child>;
    async fn take_snapshot(&self, output_path: &Path) -> Result<()>;
}
