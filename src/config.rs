use config::{Case, Config, Environment, File};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Deserialize, Default, Debug)]
pub struct Settings {
    pub bind: Option<SocketAddr>,
    pub loki_url: String,
    pub credentials: Option<BasicCredentials>,
    pub org_id: Option<String>,
}
#[derive(Deserialize, Default, Debug)]
pub struct BasicCredentials {
    pub username: String,
    pub password: String,
}
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Cannot parse config {0}")]
    CannotParseConfig(config::ConfigError),
    #[error("Cannot get settings: {0}")]
    CannotGetSettings(config::ConfigError),
}

fn create_settings() -> Result<Settings, ConfigError> {
    let cfg = Config::builder()
        .add_source(File::with_name("config.yaml").required(false))
        .add_source(
            Environment::with_prefix("app")
                .separator("_")
                .try_parsing(true)
                .convert_case(Case::Snake),
        )
        .build()
        .map_err(ConfigError::CannotParseConfig)?;
    let settings: Settings = cfg
        .get("settings")
        .map_err(ConfigError::CannotGetSettings)?;
    Ok(settings)
}

lazy_static! {
    pub static ref CONFIG: Settings = create_settings().expect("Cannot load configuration");
}
