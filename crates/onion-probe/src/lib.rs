use std::path::PathBuf;

use anyhow::Context;
use hypertor::{OnionApp, OnionService, ServeResponse, ServingApp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionProbeConfig {
    pub state_dir: PathBuf,
    pub virtual_port: u16,
    pub clearnet_bind: Option<String>,
    pub nickname: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("a writable Tor state directory is required")]
    MissingStateDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupRecord {
    pub onion_url: String,
    pub state_dir: PathBuf,
}

impl OnionProbeConfig {
    pub fn production(state_dir: PathBuf) -> Self {
        Self::try_new(Some(state_dir)).expect("production configuration supplies a state directory")
    }

    pub fn try_new(state_dir: Option<PathBuf>) -> Result<Self, ConfigError> {
        let state_dir = state_dir.ok_or(ConfigError::MissingStateDirectory)?;

        Ok(Self {
            state_dir,
            virtual_port: 80,
            clearnet_bind: None,
            nickname: "deaddrop-feasibility".to_owned(),
        })
    }
}

pub fn health_app() -> OnionApp {
    OnionApp::new().get("/health", |_request| async {
        ServeResponse::json(&serde_json::json!({
            "service": "deaddrop-feasibility",
            "status": "ok"
        }))
    })
}

pub async fn launch(config: &OnionProbeConfig) -> anyhow::Result<(StartupRecord, ServingApp)> {
    prepare_state_dir(&config.state_dir)?;

    let onion = OnionService::builder()
        .nickname(config.nickname.clone())
        .context("invalid onion service nickname")?
        .state_dir(&config.state_dir)
        .port(config.virtual_port)
        .launch()
        .await
        .context("failed to launch embedded Arti onion service")?;

    let startup = StartupRecord {
        onion_url: format!("http://{}", onion.onion_address()),
        state_dir: config.state_dir.clone(),
    };
    let running = health_app()
        .serve_on(onion)
        .await
        .context("failed to serve HTTP over the onion service")?;

    Ok((startup, running))
}

pub fn prepare_state_dir(state_dir: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(state_dir).with_context(|| {
        format!(
            "failed to create Tor state directory {}",
            state_dir.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to restrict Tor state directory {} to owner-only access",
                    state_dir.display()
                )
            },
        )?;
    }

    Ok(())
}
