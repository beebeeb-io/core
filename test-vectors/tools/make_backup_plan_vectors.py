"""Generator for test-vectors/consolidation/backup_plan.json (LD-0113 A5).

The pass planner (new / changed / unchanged / gone, unique moves, the budget,
folders to ensure), removed-elsewhere (Guus 2026-11-06 15:00, "A"), folder
presence, key normalisation and rebuilding records from the remote tree (spec
§4.2 rules 9-11). Independent of core: every expected answer is written here
from the spec. Usage:
    python3 -I test-vectors/tools/make_backup_plan_vectors.py test-vectors/consolidation/backup_plan.json
"""
import json
import sys
import unicodedata


def uid(n: int) -> str:
    return f"{n:08x}-0000-4000-8000-0000000000aa"


GIB = 1024 ** 3
NO_LIMIT = {"max_uploads": 1000, "max_bytes": 1000 * GIB}
cases = []


def e(key, size=10, m=1000, is_dir=False):
    return {"key": key, "is_dir": is_dir, "size": size, "modified_ms": m}


def r(key, rid, size=10, m=1000, up=5000, state="backed_up"):
    return {"key": key, "size": size, "modified_ms": m, "remote_id": uid(rid), "uploaded_at_ms": up, "state": state}


def up(key, size=10, reason="new"):
    return {"key": key, "size": size, "reason": reason}


def plan(id_, entries, records, live, expect, budget=None):
    full = {"uploads": [], "moves": [], "folders": [], "mark_removed_elsewhere": [], "unchanged": 0,
            "gone_locally": 0, "deferred": 0}
    full.update(expect)
    cases.append({"id": id_, "kind": "plan", "entries": entries, "records": records,
                  "live_remote": [uid(n) for n in live], "budget": budget or NO_LIMIT, "expect": full})


plan("plan_new_file", [e("a.jpg")], [], [], {"uploads": [up("a.jpg")]})
plan("plan_new_file_in_subfolders", [e("2026/05/a.jpg")], [], [],
     {"uploads": [up("2026/05/a.jpg")], "folders": ["2026", "2026/05"]})
plan("plan_changed_by_size", [e("a.jpg", size=11)], [r("a.jpg", 1)], [1], {"uploads": [up("a.jpg", 11, "changed")]})
plan("plan_changed_by_mtime", [e("a.jpg", m=2000)], [r("a.jpg", 1)], [1], {"uploads": [up("a.jpg", 10, "changed")]})
plan("plan_unchanged", [e("a.jpg")], [r("a.jpg", 1)], [1], {"unchanged": 1})
plan("plan_gone_locally_stays_in_the_backup", [], [r("b.jpg", 1)], [1], {"gone_locally": 1})
plan("plan_directories_are_not_uploaded", [e("empty", 0, 1000, True)], [], [], {})
plan("plan_unique_move", [e("new/a.jpg")], [r("old/a.jpg", 1)], [1],
     {"moves": [{"remote_id": uid(1), "from_key": "old/a.jpg", "to_key": "new/a.jpg"}], "folders": ["new"]})
plan("case_only_rename_is_a_move", [e("img.jpg")], [r("IMG.JPG", 1)], [1],
     {"moves": [{"remote_id": uid(1), "from_key": "IMG.JPG", "to_key": "img.jpg"}]})
plan("plan_ambiguous_move_two_targets_uploads", [e("x/a.jpg"), e("y/a.jpg")], [r("old/a.jpg", 1)], [1],
     {"uploads": [up("x/a.jpg"), up("y/a.jpg")], "folders": ["x", "y"], "gone_locally": 1})
plan("plan_ambiguous_move_two_sources_uploads", [e("new/a.jpg")], [r("p/a.jpg", 1), r("q/a.jpg", 2)], [1, 2],
     {"uploads": [up("new/a.jpg")], "folders": ["new"], "gone_locally": 2})
plan("plan_move_needs_the_same_name", [e("b.jpg")], [r("a.jpg", 1)], [1], {"uploads": [up("b.jpg")], "gone_locally": 1})
plan("plan_move_needs_the_same_mtime", [e("new/a.jpg", m=1001)], [r("old/a.jpg", 1)], [1],
     {"uploads": [up("new/a.jpg")], "folders": ["new"], "gone_locally": 1})
plan("plan_move_needs_a_live_source", [e("new/a.jpg")], [r("old/a.jpg", 1)], [],
     {"uploads": [up("new/a.jpg")], "folders": ["new"], "mark_removed_elsewhere": ["old/a.jpg"], "gone_locally": 1})
plan("plan_budget_of_two_with_three_new", [e("a.jpg"), e("b.jpg"), e("c.jpg")], [], [],
     {"uploads": [up("a.jpg"), up("b.jpg")], "deferred": 1}, {"max_uploads": 2, "max_bytes": 1000 * GIB})
plan("plan_big_file_alone_is_planned", [e("film.mkv", size=4831838208)], [], [],
     {"uploads": [up("film.mkv", 4831838208)]}, {"max_uploads": 256, "max_bytes": GIB})
plan("plan_bytes_budget_stops_at_the_first_overflow", [e("a.bin", 60), e("b.bin", 60), e("c.bin", 10)], [], [],
     {"uploads": [up("a.bin", 60)], "deferred": 2}, {"max_uploads": 256, "max_bytes": 100})
plan("plan_deferred_upload_ensures_no_folder", [e("a/x.jpg"), e("b/y.jpg")], [], [],
     {"uploads": [up("a/x.jpg")], "folders": ["a"], "deferred": 1}, {"max_uploads": 1, "max_bytes": 1000 * GIB})
plan("plan_folders_are_deduplicated_parents_first", [e("b/c/x.jpg"), e("a/y.jpg"), e("b/z.jpg")], [], [],
     {"uploads": [up("a/y.jpg"), up("b/c/x.jpg"), up("b/z.jpg")], "folders": ["a", "b", "b/c"]})
plan("plan_nfd_record_matches_nfc_entry", [e(unicodedata.normalize("NFC", "René.jpg"))],
     [r(unicodedata.normalize("NFD", "René.jpg"), 1)], [1], {"unchanged": 1})
plan("removed_elsewhere_unchanged_plans_nothing", [e("a.jpg")], [r("a.jpg", 1)], [],
     {"mark_removed_elsewhere": ["a.jpg"]})
plan("removed_elsewhere_already_marked_and_unchanged", [e("a.jpg")], [r("a.jpg", 1, state="removed_elsewhere")], [], {})
plan("removed_elsewhere_then_changed_uploads", [e("a.jpg", m=9000)], [r("a.jpg", 1, state="removed_elsewhere")], [],
     {"uploads": [up("a.jpg", 10, "changed")]})
plan("removed_elsewhere_noticed_and_changed", [e("a.jpg", size=12)], [r("a.jpg", 1)], [],
     {"mark_removed_elsewhere": ["a.jpg"], "uploads": [up("a.jpg", 12, "changed")]})
plan("restored_from_trash_before_the_pass_changes_nothing", [e("a.jpg")], [r("a.jpg", 1)], [1], {"unchanged": 1})

for raw, expected in [("a\\b\\c.jpg", "a/b/c.jpg"), ("/a/b.jpg", "a/b.jpg"), ("a/b.jpg", "a/b.jpg"),
                      ("René/x.jpg", "René/x.jpg")]:
    cases.append({"id": f"normalize_key_{len(cases)}", "kind": "normalize_key", "raw": raw, "expected": expected})

for dev, cat, expected in [(True, None, "present"), (True, True, "present"), (True, False, "category_deleted"),
                           (False, True, "device_deleted"), (False, None, "device_deleted")]:
    cases.append({"id": f"presence_{expected}_{len(cases)}", "kind": "presence", "device_folder_live": dev,
                  "category_folder_live": cat, "expect": expected})


def remote(key, rid, size=10, up_ms=5000):
    return {"key": key, "remote_id": uid(rid), "size": size, "uploaded_at_ms": up_ms}


def rebuild(id_, remotes, entries, expect):
    cases.append({"id": id_, "kind": "rebuild", "remote": remotes, "entries": entries, "expect": expect})


rebuild("rebuild_uploaded_after_the_change_is_backed_up", [remote("a.jpg", 1, up_ms=5000)], [e("a.jpg", m=1000)],
        [r("a.jpg", 1, m=1000, up=5000)])
rebuild("rebuild_uploaded_before_the_change_uploads", [remote("a.jpg", 1, up_ms=500)], [e("a.jpg", m=1000)], [])
rebuild("rebuild_uploaded_at_the_same_ms_uploads", [remote("a.jpg", 1, up_ms=1000)], [e("a.jpg", m=1000)], [])
rebuild("rebuild_size_differs_uploads", [remote("a.jpg", 1, size=11)], [e("a.jpg")], [])
rebuild("rebuild_missing_remotely_uploads", [remote("b.jpg", 1)], [e("a.jpg")], [])
rebuild("rebuild_nfd_remote_key_matches", [remote(unicodedata.normalize("NFD", "René.jpg"), 1)],
        [e("René.jpg")], [r("René.jpg", 1)])
rebuild("rebuild_two_remote_copies_takes_the_newest", [remote("a.jpg", 1, up_ms=3000), remote("a.jpg", 2, up_ms=4000)],
        [e("a.jpg")], [r("a.jpg", 2, up=4000)])
rebuild("rebuild_ignores_directories", [remote("d", 1)], [e("d", 0, 1000, True)], [])

doc = {
    "description": "LD-0113 backup pass planner (spec 2026-11-06-backup-from-source §4.2 rules 9-11): new, changed "
    "(size or mtime), unchanged, gone (stays in the backup), unique moves (same size, mtime and case-folded name, "
    "unique both ways), the per-pass budget (a prefix; the first upload always fits), parent folders parents-first, "
    "removed elsewhere (stays deleted until it changes), folder presence, key normalisation, and rebuilding records "
    "from the remote tree (uploaded strictly after the last change).",
    "source": "spec §4.2 rules 9-11 + plan Task A5 + Guus 2026-11-06 15:00 (\"A\"); written by "
    "test-vectors/tools/make_backup_plan_vectors.py (independent of core)",
    "cases": cases,
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(len(cases))
