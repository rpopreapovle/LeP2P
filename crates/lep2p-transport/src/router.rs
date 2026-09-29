//! Control-plane router for HTTP/3 JSON endpoints.

use crate::CallCtx;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

/// Error returned by an endpoint handler; serialized as a JSON error response.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl ControlError {
    pub fn code(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::NotImplemented(_) => 501,
            Self::Internal(_) => 500,
        }
    }
}

pub type EndpointResult = Result<Value, ControlError>;

/// A single control endpoint callable over HTTP/3.
#[async_trait]
pub trait Endpoint: Send + Sync + 'static {
    async fn call(&self, ctx: &CallCtx, body: Value) -> EndpointResult;
}

/// Dispatch a control request by path to registered endpoints.
pub struct Router {
    routes: RwLock<HashMap<String, Arc<dyn Endpoint>>>,
}

impl Default for Router {
    fn default() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
        }
    }
}

impl Router {
    /// Register an endpoint under exactly one path (e.g. `/v1/ping`).
    pub fn register<E: Endpoint>(&self, path: impl Into<String>, ep: E) {
        let mut r = self.routes.write().unwrap();
        r.insert(path.into(), Arc::new(ep));
    }

    pub fn route(&self, path: &str) -> Option<Arc<dyn Endpoint>> {
        self.routes.read().unwrap().get(path).cloned()
    }

    pub fn has(&self, path: &str) -> bool {
        self.routes.read().unwrap().contains_key(path)
    }
}

/// Decode a JSON body into a concrete request type, rejecting bad bodies.
pub fn decode<T: DeserializeOwned>(body: Value) -> Result<T, ControlError> {
    serde_json::from_value(body).map_err(|e| ControlError::BadRequest(e.to_string()))
}

/// Wrap a value into an OK JSON body.
pub fn ok<T: Serialize>(value: T) -> Result<Value, ControlError> {
    serde_json::to_value(value).map_err(|e| ControlError::Internal(e.to_string()))
}

/// Convenience for async-fn style handlers without returning serde_json.
#[macro_export]
macro_rules! json_value {
    ($($json:tt)*) => {
        ::serde_json::json!($($json)*)
    };
}
