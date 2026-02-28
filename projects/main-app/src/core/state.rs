use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraState {
    Idle,
    Starting,
    Streaming,
    Stopping,
}

#[derive(Debug, Clone, Serialize)]
pub struct CameraStatus {
    pub enabled: bool,
    pub stream_active: bool,
    pub state: CameraState,
}
