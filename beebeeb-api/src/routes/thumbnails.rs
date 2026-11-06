use crate::{Endpoint, Method, RawEndpoint, request::component};

#[derive(Debug, Clone, Copy)]
pub enum Variant {
    Small,
    Medium,
    Large,
}
impl Variant {
    fn suffix(self) -> &'static str {
        match self {
            Self::Small => "/small",
            Self::Medium => "",
            Self::Large => "/large",
        }
    }
}

pub fn get(file_id: &str, variant: Variant) -> RawEndpoint<()> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Get,
            format!("/api/v1/files/{}/thumbnail{}", component(file_id), variant.suffix()),
            false,
        )
        .limits(0, 16 * 1024 * 1024),
    )
}
pub fn put(file_id: &str, variant: Variant) -> RawEndpoint<Vec<u8>> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Put,
            format!("/api/v1/files/{}/thumbnail{}", component(file_id), variant.suffix()),
            true,
        )
        .raw_body()
        .limits(16 * 1024 * 1024, 1024),
    )
}
