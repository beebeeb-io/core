//! Purchase routes are opt-in so mobile builds can omit them completely.

use crate::{Endpoint, Method};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub price_cents: u64,
    pub currency: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Plans {
    #[serde(default)]
    pub plans: Vec<Plan>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Subscription {
    pub status: String,
    #[serde(default)]
    pub plan_id: Option<String>,
}
pub fn plans() -> Endpoint<(), Plans> {
    Endpoint::new(Method::Get, "/api/v1/billing/plans", false).public()
}
pub fn subscription() -> Endpoint<(), Subscription> {
    Endpoint::new(Method::Get, "/api/v1/billing/subscription", false)
}
