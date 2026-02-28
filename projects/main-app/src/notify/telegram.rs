use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::Serialize;

use crate::config::AppConfig;

#[derive(Clone)]
pub struct TelegramNotifier {
    bot_token: String,
    chat_id: String,
    client: Client,
}

#[derive(Serialize)]
struct SendMessageRequest<'a> {
    chat_id: &'a str,
    text: &'a str,
}

impl TelegramNotifier {
    pub fn from_config(config: &AppConfig) -> Option<Self> {
        let bot_token = config.telegram_bot_token.clone()?;
        let chat_id = config.telegram_chat_id.clone()?;
        Some(Self {
            bot_token,
            chat_id,
            client: Client::new(),
        })
    }

    pub async fn send_message(&self, message: &str) -> Result<()> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let response = self
            .client
            .post(url)
            .json(&SendMessageRequest {
                chat_id: &self.chat_id,
                text: message,
            })
            .send()
            .await
            .context("failed to send telegram request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!("telegram error status={status} body={body}");
        }

        Ok(())
    }
}
