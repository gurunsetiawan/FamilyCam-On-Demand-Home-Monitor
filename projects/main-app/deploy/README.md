# Deploy FamilyCam with systemd

## Tech Stack Deploy
- OS target: Linux (Debian/Ubuntu/Armbian sejenis)
- Service manager: `systemd`
- Binary app: Rust release binary (`cargo build --release`)
- Dependensi runtime utama: `ffmpeg`, `v4l-utils`

## Build
```bash
cd /opt/familycam/projects/main-app
cargo build --release
```

## Prepare environment
```bash
cp .env.example .env
# edit .env values
```

## Install service
```bash
sudo usermod -aG video orangepi
sudo cp projects/main-app/deploy/familycam.service /etc/systemd/system/familycam.service
sudo systemctl daemon-reload
sudo systemctl enable familycam
sudo systemctl start familycam
```

## Verify
```bash
sudo systemctl status familycam
journalctl -u familycam -f
```

## Lisensi
Mengikuti lisensi root repository: **Apache-2.0**.
Lihat [LICENSE](/home/iwan/Project/family-cam-on-demand-home-monitor/LICENSE).
