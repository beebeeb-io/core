//! Storage quota constants and calculations.
//!
//! Shared across server, CLI, web (WASM), and mobile (UniFFI).
//! All storage values use SI bytes (1 TB = 10^12 bytes).

use serde::{Deserialize, Serialize};

pub const ONE_TB: i64 = 1_000_000_000_000;
pub const MAX_TOTAL_STORAGE: i64 = 99 * ONE_TB;

pub const FREE_QUOTA: i64 = 5_000_000_000;
pub const BASIC_QUOTA: i64 = ONE_TB;
pub const PRO_QUOTA: i64 = 5 * ONE_TB;
pub const BUSINESS_QUOTA: i64 = 10 * ONE_TB;

pub const STORAGE_ADDON_CENTS_PER_TB: i64 = 1099;
pub const USER_ADDON_CENTS: i64 = 499;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Plan {
    Free,
    Basic,
    Pro,
    Business,
}

impl Plan {
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "basic" | "personal" => Plan::Basic,
            "pro" => Plan::Pro,
            "business" | "data_hoarder" => Plan::Business,
            _ => Plan::Free,
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            Plan::Free => "free",
            Plan::Basic => "basic",
            Plan::Pro => "pro",
            Plan::Business => "business",
        }
    }

    pub fn base_storage_bytes(&self) -> i64 {
        match self {
            Plan::Free => FREE_QUOTA,
            Plan::Basic => BASIC_QUOTA,
            Plan::Pro => PRO_QUOTA,
            Plan::Business => BUSINESS_QUOTA,
        }
    }

    pub fn can_add_storage(&self) -> bool {
        matches!(self, Plan::Pro | Plan::Business)
    }

    pub fn can_add_users(&self) -> bool {
        matches!(self, Plan::Business)
    }

    pub fn max_extra_tb(&self) -> i64 {
        if self.can_add_storage() {
            99 - (self.base_storage_bytes() / ONE_TB)
        } else {
            0
        }
    }

    pub fn max_extra_users(&self) -> i64 {
        if self.can_add_users() { 47 } else { 0 }
    }
}

pub fn effective_quota(plan: Plan, extra_tb: i64, bonus_bytes: i64) -> i64 {
    if !plan.can_add_storage() && extra_tb > 0 {
        return (plan.base_storage_bytes() + bonus_bytes).min(MAX_TOTAL_STORAGE);
    }
    let total = plan.base_storage_bytes() + (extra_tb * ONE_TB) + bonus_bytes;
    total.min(MAX_TOTAL_STORAGE)
}

pub fn monthly_cost_cents(plan: Plan, extra_tb: i64, extra_users: i64) -> i64 {
    let base = match plan {
        Plan::Free => 0,
        Plan::Basic => 1099,
        Plan::Pro => 5495,
        Plan::Business => 10990,
    };
    base + (extra_tb * STORAGE_ADDON_CENTS_PER_TB) + (extra_users * USER_ADDON_CENTS)
}

pub fn format_storage_si(bytes: i64) -> String {
    if bytes < 1_000 {
        return format!("{bytes} B");
    }
    if bytes < 1_000_000 {
        return format!("{} KB", bytes / 1_000);
    }
    if bytes < 1_000_000_000 {
        return format!("{} MB", bytes / 1_000_000);
    }
    if bytes < ONE_TB {
        return format!("{} GB", bytes / 1_000_000_000);
    }
    let tb = bytes as f64 / ONE_TB as f64;
    format!("{tb:.1} TB")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_quota_zero_extra() {
        assert_eq!(effective_quota(Plan::Free, 0, 0), FREE_QUOTA);
        assert_eq!(effective_quota(Plan::Basic, 0, 0), BASIC_QUOTA);
        assert_eq!(effective_quota(Plan::Pro, 0, 0), PRO_QUOTA);
        assert_eq!(effective_quota(Plan::Business, 0, 0), BUSINESS_QUOTA);
    }

    #[test]
    fn effective_quota_extra_tb_on_pro() {
        assert_eq!(
            effective_quota(Plan::Pro, 3, 0),
            PRO_QUOTA + 3 * ONE_TB
        );
    }

    #[test]
    fn effective_quota_capped_at_99_tb() {
        assert_eq!(
            effective_quota(Plan::Pro, 200, 0),
            MAX_TOTAL_STORAGE
        );
    }

    #[test]
    fn effective_quota_ignores_extra_tb_for_free_and_basic() {
        // Free plan ignores extra_tb
        assert_eq!(effective_quota(Plan::Free, 5, 0), FREE_QUOTA);
        // Basic plan ignores extra_tb
        assert_eq!(effective_quota(Plan::Basic, 5, 0), BASIC_QUOTA);
    }

    #[test]
    fn effective_quota_with_bonus_bytes() {
        let bonus = 500_000_000; // 500 MB bonus
        assert_eq!(
            effective_quota(Plan::Pro, 0, bonus),
            PRO_QUOTA + bonus
        );
        // Free plan with bonus but extra_tb=0 still gets bonus
        assert_eq!(
            effective_quota(Plan::Free, 0, bonus),
            FREE_QUOTA + bonus
        );
    }

    #[test]
    fn monthly_cost_cents_all_plans() {
        assert_eq!(monthly_cost_cents(Plan::Free, 0, 0), 0);
        assert_eq!(monthly_cost_cents(Plan::Basic, 0, 0), 1099);
        assert_eq!(monthly_cost_cents(Plan::Pro, 0, 0), 5495);
        assert_eq!(monthly_cost_cents(Plan::Business, 0, 0), 10990);
    }

    #[test]
    fn monthly_cost_cents_with_addons() {
        // Pro + 2 extra TB
        assert_eq!(
            monthly_cost_cents(Plan::Pro, 2, 0),
            5495 + 2 * STORAGE_ADDON_CENTS_PER_TB
        );
        // Business + 3 extra TB + 5 extra users
        assert_eq!(
            monthly_cost_cents(Plan::Business, 3, 5),
            10990 + 3 * STORAGE_ADDON_CENTS_PER_TB + 5 * USER_ADDON_CENTS
        );
    }

    #[test]
    fn plan_from_slug_all_variants() {
        assert_eq!(Plan::from_slug("free"), Plan::Free);
        assert_eq!(Plan::from_slug("basic"), Plan::Basic);
        assert_eq!(Plan::from_slug("personal"), Plan::Basic);
        assert_eq!(Plan::from_slug("pro"), Plan::Pro);
        assert_eq!(Plan::from_slug("business"), Plan::Business);
        assert_eq!(Plan::from_slug("data_hoarder"), Plan::Business);
        // Unknown slugs default to Free
        assert_eq!(Plan::from_slug("enterprise"), Plan::Free);
        assert_eq!(Plan::from_slug(""), Plan::Free);
    }

    #[test]
    fn plan_slug_roundtrip() {
        for plan in [Plan::Free, Plan::Basic, Plan::Pro, Plan::Business] {
            assert_eq!(Plan::from_slug(plan.slug()), plan);
        }
    }

    #[test]
    fn format_storage_si_various() {
        assert_eq!(format_storage_si(0), "0 B");
        assert_eq!(format_storage_si(512), "512 B");
        assert_eq!(format_storage_si(1_500), "1 KB");
        assert_eq!(format_storage_si(2_500_000), "2 MB");
        assert_eq!(format_storage_si(5_000_000_000), "5 GB");
        assert_eq!(format_storage_si(ONE_TB), "1.0 TB");
        assert_eq!(format_storage_si(5 * ONE_TB), "5.0 TB");
        assert_eq!(format_storage_si(99 * ONE_TB), "99.0 TB");
    }

    #[test]
    fn max_extra_tb_per_plan() {
        assert_eq!(Plan::Free.max_extra_tb(), 0);
        assert_eq!(Plan::Basic.max_extra_tb(), 0);
        assert_eq!(Plan::Pro.max_extra_tb(), 94);   // 99 - 5
        assert_eq!(Plan::Business.max_extra_tb(), 89); // 99 - 10
    }

    #[test]
    fn max_extra_users_per_plan() {
        assert_eq!(Plan::Free.max_extra_users(), 0);
        assert_eq!(Plan::Basic.max_extra_users(), 0);
        assert_eq!(Plan::Pro.max_extra_users(), 0);
        assert_eq!(Plan::Business.max_extra_users(), 47);
    }

    #[test]
    fn can_add_storage_per_plan() {
        assert!(!Plan::Free.can_add_storage());
        assert!(!Plan::Basic.can_add_storage());
        assert!(Plan::Pro.can_add_storage());
        assert!(Plan::Business.can_add_storage());
    }

    #[test]
    fn can_add_users_per_plan() {
        assert!(!Plan::Free.can_add_users());
        assert!(!Plan::Basic.can_add_users());
        assert!(!Plan::Pro.can_add_users());
        assert!(Plan::Business.can_add_users());
    }
}
