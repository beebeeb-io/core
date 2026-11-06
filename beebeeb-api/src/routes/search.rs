use crate::{Endpoint, Method, RawEndpoint};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub shards: Vec<ShardVersion>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardVersion {
    pub bucket: i32,
    pub page: i32,
    pub version: i64,
}
pub fn legacy_index() -> RawEndpoint<()> {
    RawEndpoint::new(Endpoint::new(Method::Get, "/api/v1/index", false).limits(0, 16 * 1024 * 1024))
}
pub fn manifest() -> Endpoint<(), Manifest> {
    Endpoint::new(Method::Get, "/api/v1/search-index/shards", false)
}
pub fn shard(bucket: i32, page: i32) -> RawEndpoint<()> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Get,
            format!("/api/v1/search-index/shards/{bucket}/{page}"),
            false,
        )
        .limits(0, 160 * 1024),
    )
}
pub fn put_shard(bucket: i32, page: i32) -> RawEndpoint<Vec<u8>> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Put,
            format!("/api/v1/search-index/shards/{bucket}/{page}"),
            true,
        )
        .raw_body()
        .limits(160 * 1024, 1024),
    )
}
