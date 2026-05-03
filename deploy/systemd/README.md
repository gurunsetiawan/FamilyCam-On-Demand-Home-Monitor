# FamilyCam systemd services

Target deploy path in these unit files:

```text
/opt/familycam
```

## Build binaries

Main app:

```bash
cd /opt/familycam/projects/main-app
cargo build --release
```

WebRTC Rust PoC:

```bash
cd /opt/familycam/projects/beta-webrtc-rs/webrtc-rs-poc
cargo build --release
```

Go Pion PoC:

```bash
cd /opt/familycam/projects/beta-go-pion
go build -o familycam-go-pion-poc .
```

## Install dependencies

```bash
sudo apt install -y ffmpeg v4l-utils
sudo usermod -aG video orangepi
```

Log out and log in again after changing the `video` group.

## Install one service

Run only one streaming backend at a time unless you intentionally changed ports and camera devices.

Main app:

```bash
sudo cp /opt/familycam/deploy/systemd/familycam-main-app.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now familycam-main-app
```

WebRTC Rust PoC:

```bash
sudo cp /opt/familycam/deploy/systemd/familycam-webrtc-rs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now familycam-webrtc-rs
```

Go Pion PoC:

```bash
sudo cp /opt/familycam/deploy/systemd/familycam-go-pion.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now familycam-go-pion
```

## Verify

```bash
systemctl status familycam-main-app
systemctl status familycam-webrtc-rs
systemctl status familycam-go-pion
journalctl -u familycam-go-pion -f
```
