use async_trait::async_trait;

use super::ApiError;
use crate::db::DatabaseTransaction;

/// Provides an interface to call APIs of other modules
#[async_trait]
pub trait ModuleInterconect<'a>: Sync + Send {
    /// Simulates a call to an API endpoint of another module.
    /// This has lower latency.
    async fn call(
        &'a self,
        dbtx: &'a mut DatabaseTransaction<'a>,
        module: &'static str,
        path: String,
        data: serde_json::Value,
    ) -> Result<serde_json::Value, ApiError>;
}
