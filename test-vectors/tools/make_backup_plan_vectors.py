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


def up(key, size=10, reason="new", record=None, rid=None):
    """record: the paired record's key (review #3); rid: the remote a Changed upload versions."""
    return {"key": key, "size": size, "reason": reason, "record_key": record,
            "remote_id": uid(rid) if rid is not None else None}


def mark(key, rid):
    """A record to mark removed elsewhere, as the pass read it (review 4 #3): the host marks it only while the
    record at `key` still names `rid` (compare-and-set)."""
    return {"key": key, "remote_id": uid(rid)}


def plan(id_, entries, records, live, expect, budget=None, unseen=(), complete=True, held=()):
    full = {"uploads": [], "moves": [], "folders": [], "mark_removed_elsewhere": [], "unchanged": 0,
            "gone_locally": 0, "deferred": 0, "held": 0, "deferred_unknown": 0}
    full.update(expect)
    cases.append({"id": id_, "kind": "plan", "entries": entries, "records": records,
                  "live_remote": [uid(n) for n in live], "live_remote_complete": complete,
                  "unseen": list(unseen), "held": list(held), "budget": budget or NO_LIMIT, "expect": full})


plan("plan_new_file", [e("a.jpg")], [], [], {"uploads": [up("a.jpg")]})
plan("plan_new_file_in_subfolders", [e("2026/05/a.jpg")], [], [],
     {"uploads": [up("2026/05/a.jpg")], "folders": ["2026", "2026/05"]})
plan("plan_changed_by_size", [e("a.jpg", size=11)], [r("a.jpg", 1)], [1],
     {"uploads": [up("a.jpg", 11, "changed", "a.jpg", 1)]})
plan("plan_changed_by_mtime", [e("a.jpg", m=2000)], [r("a.jpg", 1)], [1],
     {"uploads": [up("a.jpg", 10, "changed", "a.jpg", 1)]})
# Review #3: a Changed upload carries the paired record's key and id, so a normalised pairing never loses them.
plan("changed_under_a_normalised_pairing_carries_the_record", [e(unicodedata.normalize("NFC", "René.jpg"), m=2000)],
     [r(unicodedata.normalize("NFD", "René.jpg"), 1)], [1],
     {"uploads": [up(unicodedata.normalize("NFC", "René.jpg"), 10, "changed",
                     unicodedata.normalize("NFD", "René.jpg"), 1)]})
# Spec Amendment 5 (lead 17:34): keys are the raw names on Linux and Windows. An upgrade from NFC keys still pairs
# through the fallback with no re-upload; a twin that appears later never takes the existing file's record.
plan("plan_nfc_record_matches_nfd_entry_without_a_twin", [e(unicodedata.normalize("NFD", "René.jpg"))],
     [r(unicodedata.normalize("NFC", "René.jpg"), 1)], [1], {"unchanged": 1})
plan("twin_appears_the_nfd_file_keeps_its_record_the_nfc_twin_is_new",
     [e(unicodedata.normalize("NFD", "René.jpg")), e(unicodedata.normalize("NFC", "René.jpg"), size=99, m=7000)],
     [r(unicodedata.normalize("NFD", "René.jpg"), 1)], [1],
     {"unchanged": 1, "uploads": [up(unicodedata.normalize("NFC", "René.jpg"), 99)]})
# Review #1: held keys (a lasting failure, or in flight) are skipped and charged nothing.
plan("held_keys_are_skipped_and_not_charged", [e("a.jpg"), e("b.jpg"), e("c.jpg"), e("d.jpg")], [], [],
     {"uploads": [up("c.jpg"), up("d.jpg")], "held": 2}, {"max_uploads": 2, "max_bytes": 1000 * GIB},
     held=["a.jpg", "b.jpg"])
plan("first_key_not_held_always_fits", [e("a.bin", 200), e("b.bin", 150), e("c.bin", 10)], [], [],
     {"uploads": [up("b.bin", 150)], "deferred": 1, "held": 1}, {"max_uploads": 256, "max_bytes": 100},
     held=["a.bin"])
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
     {"uploads": [up("new/a.jpg")], "folders": ["new"], "mark_removed_elsewhere": [mark("old/a.jpg", 1)], "gone_locally": 1})
# Review 4 #7: a budget of 0 uploads counts as 1 (the first upload always fits), so a pass never stalls silently.
plan("plan_budget_of_zero_uploads_counts_as_one", [e("a.jpg"), e("b.jpg")], [], [],
     {"uploads": [up("a.jpg")], "deferred": 1}, {"max_uploads": 0, "max_bytes": 1000 * GIB})
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
     {"mark_removed_elsewhere": [mark("a.jpg", 1)]})
plan("removed_elsewhere_already_marked_and_unchanged", [e("a.jpg")], [r("a.jpg", 1, state="removed_elsewhere")], [], {})
# Ruling A (Guus 2026-11-06): it stays deleted until it changes on the device, then it comes back as a NEW file,
# never as a version of the trashed or purged remote file.
plan("removed_elsewhere_then_changed_uploads", [e("a.jpg", m=9000)], [r("a.jpg", 1, state="removed_elsewhere")], [],
     {"uploads": [up("a.jpg", 10, "new", "a.jpg")]})
plan("removed_elsewhere_noticed_and_changed", [e("a.jpg", size=12)], [r("a.jpg", 1)], [],
     {"mark_removed_elsewhere": [mark("a.jpg", 1)], "uploads": [up("a.jpg", 12, "new", "a.jpg")]})
# Restored from Trash: the remote is live again, so the record is held again, whatever its state.
plan("restored_from_trash_after_the_mark_is_unchanged", [e("a.jpg")], [r("a.jpg", 1, state="removed_elsewhere")], [1],
     {"unchanged": 1})
plan("restored_from_trash_after_the_mark_is_a_move_source", [e("sub/a.jpg")],
     [r("a.jpg", 1, state="removed_elsewhere")], [1],
     {"moves": [{"remote_id": uid(1), "from_key": "a.jpg", "to_key": "sub/a.jpg"}], "folders": ["sub"]})
plan("restored_from_trash_after_the_mark_and_changed_is_a_version", [e("a.jpg", m=9000)],
     [r("a.jpg", 1, state="removed_elsewhere")], [1], {"uploads": [up("a.jpg", 10, "changed", "a.jpg", 1)]})
# A partial listing (a page missing, an entry dropped) proves no deletion. A record missing from it is UNKNOWN,
# not dead (lead 17:28): no upload, no move, no mark; the next complete listing decides.
plan("partial_listing_marks_nothing_removed", [e("a.jpg"), e("b.jpg", m=2000)], [r("a.jpg", 1), r("b.jpg", 2)], [],
     {"deferred_unknown": 1}, complete=False)
plan("partial_listing_takes_no_move_source_from_an_unlisted_record", [e("new/a.jpg")], [r("old/a.jpg", 1)], [],
     {"deferred_unknown": 1, "gone_locally": 1}, complete=False)
# Review 4 #6: an unlisted record with the same signature as a live one makes the match not unique, so the move
# waits for a complete listing (the new entry may be the unlisted record's file).
plan("partial_listing_an_unlisted_twin_source_makes_the_move_wait", [e("z/a.jpg")],
     [r("x/a.jpg", 1), r("y/a.jpg", 2)], [1], {"deferred_unknown": 1, "gone_locally": 2}, complete=False)
plan("partial_listing_listed_record_behaves_as_normal", [e("a.jpg", m=2000), e("c.jpg")], [r("a.jpg", 1)], [1],
     {"uploads": [up("a.jpg", 10, "changed", "a.jpg", 1), up("c.jpg")]}, complete=False)
plan("partial_listing_still_counts_what_it_lists", [e("a.jpg"), e("b.jpg")], [r("a.jpg", 1), r("b.jpg", 2)], [1],
     {"unchanged": 1}, complete=False)
plan("restored_from_trash_before_the_pass_changes_nothing", [e("a.jpg")], [r("a.jpg", 1)], [1], {"unchanged": 1})
# Plan Amendment 1, items 5-6: what the walk did not look into is not gone.
plan("unreadable_folder_records_are_not_gone_or_move_sources", [e("open/a.jpg")], [r("closed/a.jpg", 1)], [1],
     {"uploads": [up("open/a.jpg")], "folders": ["open"]}, unseen=["closed"])
plan("notlocal_folder_records_are_not_move_sources", [e("Camera/IMG_1.jpg")], [r("OneDrive/IMG_1.jpg", 1)], [1],
     {"uploads": [up("Camera/IMG_1.jpg")], "folders": ["Camera"]}, unseen=["OneDrive"])
plan("unseen_records_are_not_marked_removed_elsewhere", [], [r("closed/x.jpg", 1)], [], {}, unseen=["closed"])
plan("unseen_file_key_is_untouched", [], [r("cloud.jpg", 1)], [1], {}, unseen=["cloud.jpg"])
plan("unseen_nested_folder_covers_its_subtree", [], [r("a/b/c/d.jpg", 1)], [1], {}, unseen=["a/b"])
plan("unseen_prefix_is_a_path_prefix_only", [], [r("closed-2/a.jpg", 1)], [1], {"gone_locally": 1},
     unseen=["closed"])
# Delta 3 #3: a record matches an unseen key raw, or, when no entry has its exact key, by its normalised key (the
# exact-then-normalised rule of Amendment 5), so a record under a folder the walk did not look into is never gone and
# never a move source, whatever its normal form. An entry matches raw only: an unreadable NFD folder never hides the
# files of its readable NFC twin, and a record whose exact entry is there stays paired with it.
plan("unseen_nfc_key_covers_its_nfd_record", [e("Other/a.jpg")], [r(unicodedata.normalize("NFD", "Café/a.jpg"), 1)],
     [1], {"uploads": [up("Other/a.jpg")], "folders": ["Other"]}, unseen=[unicodedata.normalize("NFC", "Café")])
plan("unseen_nfd_key_covers_an_nfc_record_with_no_exact_entry", [], [r(unicodedata.normalize("NFC", "René/x.jpg"), 1)],
     [1], {}, unseen=[unicodedata.normalize("NFD", "René")])
plan("unseen_nfd_twin_keeps_the_nfc_record_its_entry_has", [e(unicodedata.normalize("NFC", "René/x.jpg"))],
     [r(unicodedata.normalize("NFC", "René/x.jpg"), 1)], [1], {"unchanged": 1},
     unseen=[unicodedata.normalize("NFD", "René")])
# Review 4 #2: the record matches by its folded key too (fold_name: NFC and case), so a record under a folder that
# was renamed only in case and could not be read this pass is never gone and never a move source.
plan("unseen_case_renamed_folder_covers_its_record", [e("Other/a.jpg")], [r("Photos/a.jpg", 1)], [1],
     {"uploads": [up("Other/a.jpg")], "folders": ["Other"]}, unseen=["photos"])
plan("unseen_nfd_twin_folder_hides_nothing_of_the_nfc_twin",
     [e(unicodedata.normalize("NFC", "René/a.jpg"))], [r(unicodedata.normalize("NFD", "René/b.jpg"), 2)], [2],
     {"uploads": [up(unicodedata.normalize("NFC", "René/a.jpg"))], "folders": [unicodedata.normalize("NFC", "René")]},
     unseen=[unicodedata.normalize("NFD", "René")])
plan("unseen_root_covers_every_record", [], [r("a.jpg", 1), r("x/b.jpg", 2), r("c.jpg", 3)], [1, 2], {},
     unseen=[""])
plan("entry_under_unseen_is_not_planned", [e("closed/a.jpg"), e("b.jpg")], [], [],
     {"uploads": [up("b.jpg")]}, unseen=["closed"])

for raw, expected in [("a\\b\\c.jpg", "a/b/c.jpg"), ("/a/b.jpg", "a/b.jpg"), ("a/b.jpg", "a/b.jpg"),
                      ("René/x.jpg", "René/x.jpg")]:
    cases.append({"id": f"normalize_key_{len(cases)}", "kind": "normalize_key", "raw": raw, "expected": expected})

for dev, cat, expected in [(True, None, "present"), (True, True, "present"), (True, False, "category_deleted"),
                           (False, True, "device_deleted"), (False, None, "device_deleted")]:
    cases.append({"id": f"presence_{expected}_{len(cases)}", "kind": "presence", "device_folder_live": dev,
                  "category_folder_live": cat, "expect": expected})


def remote(key, rid, size=10, up_ms=5000):
    return {"key": key, "remote_id": uid(rid), "size": size, "uploaded_at_ms": up_ms}


# The clock of a rebuild (LD-0123): offset_ms = server_now - device_now (None: not known), margin_ms its uncertainty.
# A copy counts only when uploaded_at_ms > modified_ms + offset_ms + margin_ms; with no offset known the offset is 0
# and the margin is at least the one-sided 10-minute floor. EXACT: offset 0, margin 0, the v0.2.1 "strictly after"
# rule, which the cases below that are about keys and sizes keep.
FLOOR_MS = 10 * 60 * 1000
EXACT = {"offset_ms": 0, "margin_ms": 0}
UNKNOWN = {"offset_ms": None, "margin_ms": 0}
HOUR = 3600 * 1000
T = 1_762_430_400_000  # the server's clock at the upload in the clock cases


def rebuild(id_, remotes, entries, expect, clock=None):
    cases.append({"id": id_, "kind": "rebuild", "remote": remotes, "entries": entries,
                  "clock": clock or EXACT, "expect": expect})


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
rebuild("rebuild_exact_key_before_normalized",
        [remote("a\\b.jpg", 1, up_ms=6000), remote("a/b.jpg", 2, up_ms=5000)],
        [e("a/b.jpg"), e("a\\b.jpg")], [r("a/b.jpg", 2, up=5000), r("a\\b.jpg", 1, up=6000)])
rebuild("rebuild_shared_normalized_key_is_not_guessed", [remote("a\\b.jpg", 1)],
        [e("a/b.jpg"), e("/a/b.jpg")], [])
# LD-0123. The device clock runs 1 h behind and says so through the offset. The file was edited, same size, 20 minutes
# AFTER the upload; its device mtime reads 40 minutes before the upload. "Uploaded after the mtime" alone would mark it
# backed up and the edit would never be uploaded. With the offset it is uploaded again.
rebuild("rebuild_device_clock_behind_same_size_edit_uploads_again", [remote("a.jpg", 1, up_ms=T)],
        [e("a.jpg", m=T + 20 * 60 * 1000 - HOUR)], [], {"offset_ms": HOUR, "margin_ms": 2_500})
# The device clock runs 1 h ahead: a copy made 30 minutes after the edit reads as made before the mtime. With no offset
# known it is uploaded once more (the floor is one-sided: it never lowers the bar); with the offset it is backed up.
rebuild("rebuild_device_clock_ahead_uploads_once_more_only", [remote("a.jpg", 1, up_ms=T)],
        [e("a.jpg", m=T - 30 * 60 * 1000 + HOUR)], [], UNKNOWN)
rebuild("rebuild_device_clock_ahead_offset_known_marks_backed_up", [remote("a.jpg", 1, up_ms=T)],
        [e("a.jpg", m=T - 30 * 60 * 1000 + HOUR)], [r("a.jpg", 1, m=T - 30 * 60 * 1000 + HOUR, up=T)],
        {"offset_ms": -HOUR, "margin_ms": 2_500})
# A small measured offset inside the margin: a copy made after mtime + offset + margin is backed up; one made exactly
# at that sum is not (strictly later), and nor is one made inside the margin.
rebuild("rebuild_offset_measured_within_margin_marks_backed_up",
        [remote("a.jpg", 1, up_ms=T + 3_801), remote("b.jpg", 2, up_ms=T + 3_800), remote("c.jpg", 3, up_ms=T + 3_000)],
        [e("a.jpg", m=T), e("b.jpg", m=T), e("c.jpg", m=T)], [r("a.jpg", 1, m=T, up=T + 3_801)],
        {"offset_ms": 1_500, "margin_ms": 2_300})
# No offset known: the floor. Uploaded 10 minutes after the mtime is not enough; 1 ms more is.
rebuild("rebuild_no_offset_known_uses_ten_minute_floor",
        [remote("a.jpg", 1, up_ms=T + FLOOR_MS), remote("b.jpg", 2, up_ms=T + FLOOR_MS + 1)],
        [e("a.jpg", m=T), e("b.jpg", m=T)], [r("b.jpg", 2, m=T, up=T + FLOOR_MS + 1)], UNKNOWN)
# With no offset known a margin wider than the floor still counts: the floor is a minimum.
rebuild("rebuild_no_offset_known_wider_margin_wins_over_the_floor",
        [remote("a.jpg", 1, up_ms=T + 15 * 60 * 1000), remote("b.jpg", 2, up_ms=T + 20 * 60 * 1000 + 1)],
        [e("a.jpg", m=T), e("b.jpg", m=T)], [r("b.jpg", 2, m=T, up=T + 20 * 60 * 1000 + 1)],
        {"offset_ms": None, "margin_ms": 20 * 60 * 1000})

doc = {
    "description": "LD-0113 backup pass planner (spec 2026-11-06-backup-from-source §4.2 rules 9-11): new, changed "
    "(size or mtime), unchanged, gone (stays in the backup), unique moves (same size, mtime and case-folded name, "
    "unique both ways), the per-pass budget (a prefix; the first upload always fits), parent folders parents-first, "
    "removed elsewhere (stays deleted until it changes), folder presence, key normalisation, and rebuilding records "
    "from the remote tree (uploaded after the last change by the device clock's measured offset and margin, or the "
    "one-sided 10-minute floor when no offset is known: LD-0123).",
    "source": "spec §4.2 rules 9-11 + plan Task A5 + Guus 2026-11-06 15:00 (\"A\") + LD-0123; written by "
    "test-vectors/tools/make_backup_plan_vectors.py (independent of core)",
    "cases": cases,
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(len(cases))
