use std::str::Utf8Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Cannot listen to signal: {0}")]
    CannotListenSignals(std::io::Error),
    #[error("Error on reading config: {0}")]
    ConfigError(#[from] config::ConfigError),
    #[error("Cannot bind socket: {0}")]
    CannotBindSocket(std::io::Error),
    #[error("Cannot decode packet: {0}")]
    CannotDecodePacket(#[from] std::io::Error),
    #[error("Cannot decode utf string: {0}")]
    CannotDecodeUtfString(Utf8Error),
    #[error("Invalid header field: {0}")]
    InvalidHeaderField(Box<str>),
}
