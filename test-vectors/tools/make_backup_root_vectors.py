"""Generator for test-vectors/consolidation/backup_root.json (LD-0113 A4).

Root resolution (use the flagged root, claim the oldest live "Backups", or
create one) and the merge plan for legacy duplicate roots (spec §4.2 rules 5-6,
the iOS rule of tasks 0813/0814 moved into core). Independent of core: every
expected answer is written here from the spec. Usage:
    python3 -I test-vectors/tools/make_backup_root_vectors.py test-vectors/consolidation/backup_root.json
"""
import json
import sys


def uid(n: int) -> str:
    return f"{n:08x}-0000-4000-8000-000000000000"


cases = []


def cand(n, name, created, trashed=False, role=None):
    return {"id": uid(n), "name": name, "is_trashed": trashed, "created_at_ms": created, "system_role": role}


def root(id_, candidates, expect):
    cases.append({"id": id_, "kind": "root", "candidates": candidates, "expect": expect})


root("root_none_creates", [], "create")
root("root_one_is_claimed", [cand(1, "Backups", 1000)], {"claim": {"id": uid(1), "merge_from": []}})
# Task 0811: one iOS account grew six same-name roots.
six = [cand(6, "Backups", 5000), cand(2, "Backups", 1000), cand(5, "Backups", 3000),
       cand(1, "Backups", 2000), cand(4, "Backups", 6000), cand(3, "Backups", 4000)]
root("root_six_same_name_claims_the_oldest", six,
     {"claim": {"id": uid(2), "merge_from": [uid(1), uid(3), uid(4), uid(5), uid(6)]}})
root("root_oldest_trashed_claims_the_next", [cand(1, "Backups", 1000, trashed=True), cand(2, "Backups", 2000),
                                              cand(3, "Backups", 3000)],
     {"claim": {"id": uid(2), "merge_from": [uid(3)]}})
root("root_flagged_wins_over_older_unflagged", [cand(1, "Backups", 1000), cand(2, "Backups", 9000, role="backups_root")],
     {"use": uid(2)})
root("root_flagged_with_pending_name_is_used", [cand(1, "Backups", 1000), cand(2, None, 9000, role="backups_root")],
     {"use": uid(2)})
root("root_flagged_in_trash_does_not_count", [cand(1, "Backups", 5000), cand(2, "Backups", 1000, trashed=True,
                                                                                  role="backups_root")],
     {"claim": {"id": uid(1), "merge_from": []}})
root("root_all_names_pending_creates", [cand(1, None, 1000), cand(2, None, 2000)], "create")
root("root_pending_name_never_counts", [cand(1, None, 1000), cand(2, "Backups", 2000)],
     {"claim": {"id": uid(2), "merge_from": []}})
root("root_tie_on_created_at_takes_the_smallest_id", [cand(9, "Backups", 1000), cand(7, "Backups", 1000)],
     {"claim": {"id": uid(7), "merge_from": [uid(9)]}})
root("root_name_must_be_exact", [cand(1, "backups", 1000), cand(2, "Backups ", 1000), cand(3, "Backup", 1000)],
     "create")
root("root_other_folders_are_ignored", [cand(1, "Documents", 1000), cand(2, "Backups", 3000),
                                         cand(3, "Photos", 500)],
     {"claim": {"id": uid(2), "merge_from": []}})


def node(n, name, folder, children=()):
    return {"id": uid(n), "name": name, "is_folder": folder, "children": list(children)}


def move(n, parent):
    return {"move": {"id": uid(n), "new_parent": uid(parent)}}


def move_renamed(n, parent, name):
    return {"move_renamed": {"id": uid(n), "new_parent": uid(parent), "new_name": name}}


def trash(n):
    return {"trash": uid(n)}


def merge(id_, survivor, duplicates, steps):
    cases.append({
        "id": id_,
        "kind": "merge",
        "survivor": survivor,
        "duplicates": duplicates,
        "clash_label": "merged",
        "hhmm": "14.05",
        "expect": steps,
    })


merge("merge_empty_duplicate_is_only_trashed", node(1, "Backups", True), [node(2, "Backups", True)], [trash(2)])
merge("merge_moves_children_then_trashes",
      node(1, "Backups", True, [node(10, "iPhone", True)]),
      [node(2, "Backups", True, [node(20, "GLegion", True), node(21, "notes.txt", False)])],
      [move(20, 1), move(21, 1), trash(2)])
# Both sides hold iPhone/Camera Roll/2026-05: recurse, move the leaves, trash each emptied folder.
merge("merge_nested_same_name_folders_recurse",
      node(1, "Backups", True, [
          node(10, "iPhone", True, [node(11, "Camera Roll", True, [node(12, "2026-05", True, [
              node(13, "IMG_1.heic", False)])])])]),
      [node(2, "Backups", True, [
          node(20, "iPhone", True, [node(21, "Camera Roll", True, [
              node(22, "2026-05", True, [node(23, "IMG_2.heic", False)]),
              node(24, "2026-06", True, [node(25, "IMG_3.heic", False)])])])])],
      [move(23, 12), trash(22), move(24, 11), trash(21), trash(20), trash(2)])
merge("merge_file_clash_keeps_both",
      node(1, "Backups", True, [node(10, "IMG_1.heic", False)]),
      [node(2, "Backups", True, [node(20, "IMG_1.heic", False)])],
      [move_renamed(20, 1, "IMG_1 (merged, 14.05).heic"), trash(2)])
merge("merge_second_clash_counts_up",
      node(1, "Backups", True, [node(10, "IMG_1.heic", False)]),
      [node(2, "Backups", True, [node(20, "IMG_1.heic", False)]),
       node(3, "Backups", True, [node(30, "IMG_1.heic", False)])],
      [move_renamed(20, 1, "IMG_1 (merged, 14.05).heic"), trash(2),
       move_renamed(30, 1, "IMG_1 (merged, 14.05) 2.heic"), trash(3)])
merge("merge_folder_clashing_with_a_file_keeps_both",
      node(1, "Backups", True, [node(10, "Notes", False)]),
      [node(2, "Backups", True, [node(20, "Notes", True, [node(21, "a.txt", False)])])],
      [move_renamed(20, 1, "Notes (merged, 14.05)"), trash(2)])
merge("merge_names_compare_case_insensitively",
      node(1, "Backups", True, [node(10, "Camera Roll", True)]),
      [node(2, "Backups", True, [node(20, "camera roll", True, [node(21, "IMG_9.heic", False)])])],
      [move(21, 10), trash(20), trash(2)])
# A folder moved in from the first duplicate receives the second duplicate's same-name folder.
merge("merge_later_duplicate_merges_into_a_moved_folder",
      node(1, "Backups", True),
      [node(2, "Backups", True, [node(20, "Camera Roll", True, [node(21, "x.jpg", False)])]),
       node(3, "Backups", True, [node(30, "Camera Roll", True, [node(31, "y.jpg", False)])])],
      [move(20, 1), trash(2), move(31, 20), trash(30), trash(3)])

doc = {
    "description": "LD-0113 Backups root (spec 2026-11-06-backup-from-source §4.2 rules 5-6): resolve_root (a flagged "
    "live root wins; else the oldest live root-level folder named exactly Backups is claimed, ties by id, the rest "
    "merge into it; a pending name never counts; else create) and plan_merge (children move depth-first, same-name "
    "folders recurse, a clash keeps both with core's keep_both_name, emptied duplicates go to Trash last).",
    "source": "spec §4.2 rules 5-6 + mobile src/services/BackupService.ts:829-960 (tasks 0811, 0813, 0814); written by "
    "test-vectors/tools/make_backup_root_vectors.py (independent of core)",
    "cases": cases,
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(len(cases))
