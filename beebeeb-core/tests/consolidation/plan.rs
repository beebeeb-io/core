//! Move 5 — quota and plan maths (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/plan.json`: every plan's row in
//! the table, the strict slug lookup, and the add-on maths (extra TB, bonus
//! bytes, the zero-add-on baseline, the 99 TB cap, and costs).

use beebeeb_types::{Plan, PlanTable, effective_quota, monthly_cost_cents};
use serde_json::Value;

pub const CONCEPT: &str = "plan";

fn i64_of(value: &Value, key: &str, id: &str) -> i64 {
    value[key]
        .as_i64()
        .unwrap_or_else(|| panic!("{id}: `{key}` must be an integer"))
}

#[test]
fn plan_cases_match_core() {
    let cases = super::cases(CONCEPT);

    let mut rows = 0;
    let mut quotas = 0;
    let mut costs = 0;

    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        let slug = case["slug"].as_str().expect("case slug");
        match case["kind"].as_str().expect("case kind") {
            "table" => {
                rows += 1;
                let table = PlanTable::from_slug(slug).unwrap_or_else(|| panic!("{id}: `{slug}` must be a known slug"));
                let want = &case["expected"];
                assert_eq!(table.slug, slug, "{id}: canonical slug");
                assert_eq!(
                    table.base_storage_bytes,
                    i64_of(want, "base_storage_bytes", id),
                    "{id}: base storage"
                );
                assert_eq!(
                    table.max_extra_tb,
                    i64_of(want, "max_extra_tb", id),
                    "{id}: max extra TB"
                );
                assert_eq!(
                    table.max_extra_users,
                    i64_of(want, "max_extra_users", id),
                    "{id}: max extra users"
                );
                assert_eq!(
                    table.monthly_base_cents,
                    i64_of(want, "monthly_base_cents", id),
                    "{id}: base price"
                );
                assert_eq!(
                    table.can_add_storage,
                    want["can_add_storage"].as_bool().expect("can_add_storage"),
                    "{id}: can add storage"
                );
                assert_eq!(
                    table.can_add_users,
                    want["can_add_users"].as_bool().expect("can_add_users"),
                    "{id}: can add users"
                );
                // The lenient lookup the wasm exports use resolves the same row.
                assert_eq!(PlanTable::for_slug(slug), table, "{id}: for_slug");
                // And the free functions still answer the plan's own values.
                assert_eq!(
                    effective_quota(table.plan, 0, 0),
                    table.effective_quota(0, 0),
                    "{id}: effective_quota delegates"
                );
                assert_eq!(
                    monthly_cost_cents(table.plan, 0, 0),
                    table.monthly_cost_cents(0, 0),
                    "{id}: monthly_cost_cents delegates"
                );
            }
            "unknown-slug" => {
                assert!(PlanTable::from_slug(slug).is_none(), "{id}: `{slug}` must not resolve");
                assert_eq!(
                    PlanTable::for_slug(slug).plan,
                    Plan::Free,
                    "{id}: the lenient lookup keeps its historical Free fallback"
                );
            }
            "quota" => {
                quotas += 1;
                let table = PlanTable::from_slug(slug).unwrap_or_else(|| panic!("{id}: `{slug}` must be a known slug"));
                let extra_tb = i64_of(case, "extra_tb", id);
                let bonus_bytes = i64_of(case, "bonus_bytes", id);
                let want = i64_of(case, "expected", id);
                assert_eq!(
                    table.effective_quota(extra_tb, bonus_bytes),
                    want,
                    "{id}: the table's quota"
                );
                assert_eq!(
                    effective_quota(table.plan, extra_tb, bonus_bytes),
                    want,
                    "{id}: the free function delegates"
                );
            }
            "cost" => {
                costs += 1;
                let table = PlanTable::from_slug(slug).unwrap_or_else(|| panic!("{id}: `{slug}` must be a known slug"));
                let extra_tb = i64_of(case, "extra_tb", id);
                let extra_users = i64_of(case, "extra_users", id);
                let want = i64_of(case, "expected", id);
                assert_eq!(
                    table.monthly_cost_cents(extra_tb, extra_users),
                    want,
                    "{id}: the table's cost"
                );
                assert_eq!(
                    monthly_cost_cents(table.plan, extra_tb, extra_users),
                    want,
                    "{id}: the free function delegates"
                );
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }

    assert_eq!(rows, 5, "one row per plan");
    assert_eq!(quotas, 5, "the quota cases");
    assert_eq!(costs, 2, "the cost cases");
    for required in ["plan_unknown_slug", "quota_zero_addons", "quota_over_quota"] {
        assert!(
            cases.iter().any(|case| case["id"] == required),
            "missing named case `{required}`"
        );
    }

    // The table is the whole catalogue, in slug order, and covers every Plan.
    let all = PlanTable::all();
    assert_eq!(
        all.iter().map(|row| row.slug).collect::<Vec<_>>(),
        ["free", "starter", "basic", "pro", "business"],
        "the table's order"
    );
    for plan in [Plan::Free, Plan::Starter, Plan::Basic, Plan::Pro, Plan::Business] {
        assert!(all.iter().any(|row| row.plan == plan), "missing a row for {plan:?}");
    }
}
