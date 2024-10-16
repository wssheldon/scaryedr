use anyhow::Error;
use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
pub trait LoggerPlugin: Send + Sync {
    async fn log_event(&self, event: Value) -> Result<(), Error>;
    async fn flush(&self) -> Result<(), Error>;
}

pub mod config {
    use super::LoggerPlugin;
    use std::sync::Arc;

    pub struct LoggerConfig {
        pub logger: Arc<dyn LoggerPlugin>,
    }
}
