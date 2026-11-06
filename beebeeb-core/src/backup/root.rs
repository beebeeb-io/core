//! Which folder is the Backups root (spec §4.2 rule 5).
//!
//! The root is the folder with the `backups_root` role. An account from before
//! the role has none yet: then the oldest live root-level folder named exactly
//! `Backups` is claimed (the server flags it through `PUT /backups/root`) and
//! the other same-name roots merge into it. Every client computes the same
//! survivor from the same listing, whatever its order, so two clients migrating
//! at once converge.

use uuid::Uuid;

use beebeeb_types::backup::SystemRole;

use super::layout::ROOT_NAME;

/// One live or trashed root-level folder, as the client lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootCandidate {
    pub id: Uuid,
    /// The decrypted name; `None` while it cannot be decrypted (a pending
    /// name never counts as `Backups`).
    pub name: Option<String>,
    pub is_trashed: bool,
    pub created_at_ms: i64,
    pub system_role: Option<SystemRole>,
}

/// What the client does about the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootPlan {
    /// A flagged root exists.
    Use(Uuid),
    /// No flag yet: claim `id`, then merge `merge_from` (sorted by id) into it.
    Claim { id: Uuid, merge_from: Vec<Uuid> },
    /// No root exists: create one.
    Create,
}

/// Spec §4.2 rule 5. Trashed folders never count.
pub fn resolve_root(candidates: &[RootCandidate]) -> RootPlan {
    let oldest = |c: &&RootCandidate| (c.created_at_ms, c.id);
    let flagged = candidates
        .iter()
        .filter(|c| !c.is_trashed && c.system_role == Some(SystemRole::BackupsRoot))
        .min_by_key(oldest);
    if let Some(root) = flagged {
        return RootPlan::Use(root.id);
    }
    let mut named: Vec<&RootCandidate> = candidates
        .iter()
        .filter(|c| !c.is_trashed && c.name.as_deref() == Some(ROOT_NAME))
        .collect();
    named.sort_by_key(oldest);
    match named.split_first() {
        None => RootPlan::Create,
        Some((survivor, rest)) => {
            let mut merge_from: Vec<Uuid> = rest.iter().map(|c| c.id).collect();
            merge_from.sort();
            RootPlan::Claim {
                id: survivor.id,
                merge_from,
            }
        }
    }
}
