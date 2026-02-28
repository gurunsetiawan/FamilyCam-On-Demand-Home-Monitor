use std::collections::BTreeSet;

use anyhow::Result;
use serde::Serialize;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct CameraDeviceInfo {
    pub path: String,
    pub formats: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CameraProbeInfo {
    pub name: String,
    pub devices: Vec<CameraDeviceInfo>,
}

pub async fn probe_cameras() -> Result<Vec<CameraProbeInfo>> {
    match v4l2_probe().await {
        Ok(list) if !list.is_empty() => Ok(list),
        _ => fallback_probe_from_dev().await,
    }
}

async fn v4l2_probe() -> Result<Vec<CameraProbeInfo>> {
    let output = Command::new("v4l2-ctl")
        .arg("--list-devices")
        .output()
        .await?;
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut current_name = String::new();
    let mut current_devices: Vec<String> = Vec::new();
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();

    for raw in stdout.lines() {
        let line = raw.trim_end();
        if line.is_empty() {
            if !current_name.is_empty() && !current_devices.is_empty() {
                groups.push((current_name.clone(), current_devices.clone()));
            }
            current_name.clear();
            current_devices.clear();
            continue;
        }

        if raw.starts_with(' ') || raw.starts_with('\t') {
            let value = line.trim();
            if value.starts_with("/dev/video") {
                current_devices.push(value.to_string());
            }
        } else {
            if !current_name.is_empty() && !current_devices.is_empty() {
                groups.push((current_name.clone(), current_devices.clone()));
                current_devices.clear();
            }
            current_name = line.trim_end_matches(':').to_string();
        }
    }
    if !current_name.is_empty() && !current_devices.is_empty() {
        groups.push((current_name, current_devices));
    }

    let mut output = Vec::new();
    for (name, devices) in groups {
        let mut info_devices = Vec::new();
        for path in devices {
            let formats = probe_formats(&path).await.unwrap_or_default();
            info_devices.push(CameraDeviceInfo { path, formats });
        }
        output.push(CameraProbeInfo {
            name,
            devices: info_devices,
        });
    }

    Ok(output)
}

async fn probe_formats(device_path: &str) -> Result<Vec<String>> {
    let output = Command::new("v4l2-ctl")
        .args(["--list-formats-ext", "-d", device_path])
        .output()
        .await?;
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut formats = BTreeSet::new();
    for line in stdout.lines() {
        if let Some(first) = line.find('\'') {
            let tail = &line[first + 1..];
            if let Some(second) = tail.find('\'') {
                let value = tail[..second].trim();
                if !value.is_empty() {
                    formats.insert(value.to_string());
                }
            }
        }
    }
    Ok(formats.into_iter().collect())
}

async fn fallback_probe_from_dev() -> Result<Vec<CameraProbeInfo>> {
    let mut paths = Vec::new();
    let mut dir = tokio::fs::read_dir("/dev").await?;
    while let Some(entry) = dir.next_entry().await? {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("video") {
            paths.push(format!("/dev/{name}"));
        }
    }
    paths.sort();

    if paths.is_empty() {
        return Ok(Vec::new());
    }

    let devices = paths
        .into_iter()
        .map(|path| CameraDeviceInfo {
            path,
            formats: Vec::new(),
        })
        .collect();
    Ok(vec![CameraProbeInfo {
        name: "Detected video devices".to_string(),
        devices,
    }])
}
