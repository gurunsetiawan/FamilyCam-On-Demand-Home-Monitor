use std::{env, net::SocketAddr};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub app_name: String,
    pub bind_addr: SocketAddr,
    pub auto_shutdown_seconds: u64,
    pub camera_device: String,
    pub camera_input_format: String,
    pub app_password: String,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let app_name = env::var("APP_NAME").unwrap_or_else(|_| "FamilyCam".to_owned());
        let bind_addr = env::var("BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
            .parse()?;
        let auto_shutdown_seconds = env::var("AUTO_SHUTDOWN_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(120);

        let camera_device = env::var("CAMERA_DEVICE").unwrap_or_else(|_| "/dev/video0".to_owned());
        let camera_input_format =
            env::var("CAMERA_INPUT_FORMAT").unwrap_or_else(|_| "mjpeg".to_owned());
        let app_password = env::var("APP_PASSWORD").unwrap_or_else(|_| "change-me".to_owned());
        let telegram_bot_token = env::var("TELEGRAM_BOT_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let telegram_chat_id = env::var("TELEGRAM_CHAT_ID")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Ok(Self {
            app_name,
            bind_addr,
            auto_shutdown_seconds,
            camera_device,
            camera_input_format,
            app_password,
            telegram_bot_token,
            telegram_chat_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::AppConfig;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("failed to lock env mutex")
    }

    fn set_env(key: &str, value: &str) {
        unsafe { std::env::set_var(key, value) }
    }

    fn remove_env(key: &str) {
        unsafe { std::env::remove_var(key) }
    }

    #[test]
    fn from_env_uses_default_password_if_unset() {
        let _guard = lock_env();
        remove_env("APP_PASSWORD");
        set_env("BIND_ADDR", "127.0.0.1:8080");

        let config = AppConfig::from_env().expect("config should parse");
        assert_eq!(config.app_password, "change-me");
    }

    #[test]
    fn from_env_uses_password_from_environment() {
        let _guard = lock_env();
        set_env("APP_PASSWORD", "unit-test-password");
        set_env("BIND_ADDR", "127.0.0.1:8080");

        let config = AppConfig::from_env().expect("config should parse");
        assert_eq!(config.app_password, "unit-test-password");
    }

    #[test]
    fn from_env_reads_password_from_dotenv_file() {
        let _guard = lock_env();
        remove_env("APP_PASSWORD");
        set_env("BIND_ADDR", "127.0.0.1:8080");

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!("familycam-dotenv-{suffix}.env"));
        fs::write(&path, "APP_PASSWORD=dotenv-test-password\n")
            .expect("should write temporary dotenv file");

        dotenvy::from_path_override(&path).expect("dotenv file should load");
        let config = AppConfig::from_env().expect("config should parse");
        assert_eq!(config.app_password, "dotenv-test-password");

        let _ = fs::remove_file(path);
    }
}
