use crate::{Endpoint, Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(flatten)]
    pub fields: super::ExtraFields,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Op {
    #[serde(default)]
    pub seq_id: Option<i64>,
    #[serde(default)]
    pub user_seq: Option<i64>,
    pub op_type: String,
    pub payload: Value,
    #[serde(default)]
    pub client_op_id: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub seq_id: i64,
    #[serde(default)]
    pub user_seq: i64,
    #[serde(default)]
    pub complete: Option<bool>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Submit {
    pub ops: Vec<Op>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Ops {
    #[serde(default)]
    pub ops: Vec<Op>,
    #[serde(default)]
    pub next_since: Option<i64>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Applied {
    pub client_op_id: String,
    pub seq_id: i64,
    pub user_seq: i64,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Rejected {
    pub client_op_id: String,
    pub reason: Value,
}
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitResult {
    #[serde(default)]
    pub applied: Vec<Applied>,
    #[serde(default)]
    pub rejected: Vec<Rejected>,
}
#[derive(Clone, Deserialize)]
pub struct StreamToken {
    #[serde(alias = "stream_token")]
    pub token: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}
crate::redacted_debug!(StreamToken; show: [expires_at]; hide: [token]);

pub fn snapshot() -> Endpoint<(), Snapshot> {
    Endpoint::new(Method::Get, "/api/v1/sync/snapshot", false).limits(0, 32 * 1024 * 1024)
}
pub fn ops(since: i64, limit: u16) -> Endpoint<(), Ops> {
    Endpoint::new(
        Method::Get,
        format!("/api/v1/sync/ops?since={since}&limit={limit}"),
        false,
    )
    .limits(0, 16 * 1024 * 1024)
}
pub fn submit() -> Endpoint<Submit, SubmitResult> {
    Endpoint::new(Method::Post, "/api/v1/sync/ops", true)
        .capabilities()
        .limits(4 * 1024 * 1024, 4 * 1024 * 1024)
}
pub fn stream_token() -> Endpoint<(), StreamToken> {
    Endpoint::new(Method::Post, "/api/v1/sync/stream-token", false)
}
pub fn stream(token: &str) -> crate::RawEndpoint<()> {
    crate::RawEndpoint::new(
        Endpoint::new(
            Method::Get,
            format!("/api/v1/sync/stream?token={}", crate::request::component(token)),
            false,
        )
        .sensitive_path()
        .limits(0, 1024 * 1024),
    )
}
