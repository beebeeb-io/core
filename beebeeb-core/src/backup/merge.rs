//! Merging legacy duplicate roots into the survivor (spec §4.2 rule 6).
//!
//! This is iOS's rule (tasks 0813/0814) moved into core, not changed: the
//! oldest root survives, the duplicates' children move into it, same-name
//! folders merge, and each emptied duplicate goes to Trash. Depth is unbounded
//! (iOS stopped at 2). A name clash keeps both, with core's `keep_both_name`,
//! so a merge never overwrites anything.

use std::collections::HashSet;

use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use super::fold_name;
use crate::sync::conflict::{InvalidKeepBothTime, keep_both_name};

/// One folder or file of a tree, as the client lists it (decrypted names).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeNode {
    pub id: Uuid,
    pub name: String,
    pub is_folder: bool,
    pub children: Vec<MergeNode>,
}

/// One server mutation of the merge, in replay order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeStep {
    Move {
        id: Uuid,
        new_parent: Uuid,
    },
    /// A move into a folder that already has the name: keep both.
    MoveRenamed {
        id: Uuid,
        new_parent: Uuid,
        new_name: String,
    },
    /// An emptied duplicate folder.
    Trash {
        id: Uuid,
    },
}

fn merge_into(
    target: &mut MergeNode,
    source: &MergeNode,
    clash_label: &str,
    hhmm: &str,
    steps: &mut Vec<MergeStep>,
) -> Result<(), InvalidKeepBothTime> {
    for child in &source.children {
        // Two siblings that differ only in case collide in a drive, so they
        // merge.
        let key = fold_name(&child.name);
        match target.children.iter().position(|t| fold_name(&t.name) == key) {
            Some(i) if child.is_folder && target.children[i].is_folder => {
                merge_into(&mut target.children[i], child, clash_label, hhmm, steps)?;
                steps.push(MergeStep::Trash { id: child.id });
            }
            Some(_) => {
                // The same fold as the clash test above. keep_both_name
                // lowercases its candidate, so it gets the name in NFC: then
                // its test is exactly `fold_name`.
                let taken: HashSet<String> = target.children.iter().map(|t| fold_name(&t.name)).collect();
                let original: String = child.name.nfc().collect();
                let new_name = keep_both_name(&original, clash_label, hhmm, &taken)?;
                steps.push(MergeStep::MoveRenamed {
                    id: child.id,
                    new_parent: target.id,
                    new_name: new_name.clone(),
                });
                target.children.push(MergeNode {
                    name: new_name,
                    ..child.clone()
                });
            }
            None => {
                steps.push(MergeStep::Move {
                    id: child.id,
                    new_parent: target.id,
                });
                target.children.push(child.clone());
            }
        }
    }
    Ok(())
}

/// The steps that merge `duplicates` (in the given order) into `survivor`:
/// each duplicate's children first, depth-first, then the duplicate itself to
/// Trash. A clash is named `keep_both_name(name, clash_label, hhmm, ..)`; pass
/// `hhmm` with a dot (`"14.05"`), as `keep_both_name` documents, because a `:`
/// is refused on Windows and shows as `/` in Finder (plan Amendment 1, item 4).
/// Replaying the steps in order is safe: a step only ever names a row that an
/// earlier step left in place. A clash with a time that is not `HH.MM` refuses
/// the whole plan, so no step is returned for a merge that cannot finish.
pub fn plan_merge(
    survivor: &MergeNode,
    duplicates: &[MergeNode],
    clash_label: &str,
    hhmm: &str,
) -> Result<Vec<MergeStep>, InvalidKeepBothTime> {
    let mut target = survivor.clone();
    let mut steps = Vec::new();
    for duplicate in duplicates {
        merge_into(&mut target, duplicate, clash_label, hhmm, &mut steps)?;
        steps.push(MergeStep::Trash { id: duplicate.id });
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(n: u128, name: &str) -> MergeNode {
        MergeNode {
            id: Uuid::from_u128(n),
            name: name.into(),
            is_folder: false,
            children: Vec::new(),
        }
    }

    fn folder(n: u128, children: Vec<MergeNode>) -> MergeNode {
        MergeNode {
            id: Uuid::from_u128(n),
            name: "Backups".into(),
            is_folder: true,
            children,
        }
    }

    /// A clash needs a keep-both name; a time that is not `HH.MM` refuses the
    /// whole plan instead of naming a copy with it. Mutant: the error dropped.
    #[test]
    fn a_clash_with_a_bad_time_returns_no_steps() {
        let survivor = folder(1, vec![file(2, "a.txt")]);
        let duplicate = folder(3, vec![file(4, "A.TXT")]);
        assert!(plan_merge(&survivor, std::slice::from_ref(&duplicate), "merged", "14:05").is_err());
        let steps = plan_merge(&survivor, &[duplicate], "merged", "14.05").expect("HH.MM");
        assert!(matches!(steps[0], MergeStep::MoveRenamed { .. }));
    }
}
