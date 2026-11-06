"""Generator for test-vectors/consolidation/backup_protect.json (LD-0113 A2).

Independent of core: the expected words and skip answers are written here from
the spec (§4.2 rules 1, 7, 8; Amendments 7 and 8, Guus 2026-11-06 19:30, 19:33
and 20:04) and mobile's protected-folders.ts, never read back from Rust. Usage: python3 -I test-vectors/tools/make_backup_protect_vectors.py test-vectors/consolidation/backup_protect.json
"""
import json
import sys

# Guus 2026-11-06 20:04, "keep it Backups and just add a read-only badge": the words name the folder.
DEL = "Backups is a system folder and can't be deleted."  # mobile protected-folders.ts:11
MOV = "Backups is a system folder and can't be moved."  # mobile protected-folders.ts:12
REN = "Backups is a system folder and can't be renamed."  # new (spec §4.2 rule 7)
MANAGED = "Backups are managed in the Beebeeb app. Open Beebeeb to delete a backup."
READ_ONLY = ("Backups are read-only: each device writes its own. Change the file on that device, or save a copy "
             "outside Backups.")
BADGE = "Read-only"
MUTATIONS = ["trash", "delete", "rename", "move", "create", "write"]
STRUCTURAL = {"trash", "delete", "rename", "move"}
# The root's own words: what was tried, for the four structural mutations; a new item or a content change is
# read-only.
ROOT_WORDS = {"trash": DEL, "delete": DEL, "rename": REN, "move": MOV, "create": READ_ONLY, "write": READ_ONLY}
POSITIONS = ["root", "device_folder", "manifest", "category_folder", "inside", "outside"]
MANIFEST = ".device.json"

cases = []
# The root's name, the badge every client shows on it, and the origin header every request of a backup pass carries
# (Amendment 8; the server ignores it until phase 2).
cases.append({"id": "names_root_badge_and_origin", "kind": "names", "root_name": "Backups", "badge": BADGE,
              "origin_header": "X-Beebeeb-Origin", "origin_backup": "backup"})

# The server's root rule (phase 1): only the root's trash, delete, rename and move are refused. A new item in the
# root (a device folder) and a content change are ok: the whole rule is the clients' (and the server's in phase 2).
for m in MUTATIONS:
    for target, role in [("root", "backups_root"), ("child", None), ("other", None)]:
        cases.append({
            "id": f"root_{m}_{target}",
            "kind": "root_mutation",
            "target": target,
            "role": role,
            "mutation": m,
            "expect": ROOT_WORDS[m] if role and m in STRUCTURAL else "ok",
        })
cases.append({
    "id": "root_move_into_root_allowed",
    "kind": "root_mutation",
    "target": "an item moved into the root (the item has no role)",
    "role": None,
    "mutation": "move",
    "expect": "ok",
})

# A row's position: its depth below the flagged root (None: not under it) and, at depth 2, its name: a device
# folder's manifest is its own position (lead 20:01), and only it is hidden from every listing.
for id_, depth, name, expected in [
    ("none", None, "Pictures", "outside"),
    ("none_manifest_name", None, MANIFEST, "outside"),
    ("0", 0, "Backups", "root"),
    ("1", 1, "GLegion", "device_folder"),
    ("1_manifest_name", 1, MANIFEST, "device_folder"),
    ("2", 2, "Pictures", "category_folder"),
    ("2_manifest", 2, MANIFEST, "manifest"),
    ("2_manifest_name_other_case", 2, ".Device.json", "category_folder"),
    ("3", 3, "beach.jpg", "inside"),
    ("3_manifest_name", 3, MANIFEST, "inside"),
    ("7", 7, "beach.jpg", "inside"),
]:
    cases.append({"id": f"position_at_depth_{id_}", "kind": "position", "depth": depth, "name": name,
                  "expected": expected, "hidden": expected == "manifest"})


# The app rule (web, desktop in the app, the iOS app, the CLI; Guus 19:33 "Both, staged"): the root refuses
# everything with its own words; a device's manifest refuses everything (lead 20:01); under it, a backup can be
# deleted (trash or delete) and nothing else changes; outside is ok. 6 positions x 6 mutations.
def app_expect(position, m):
    if position == "outside":
        return "ok"
    if position == "root":
        return ROOT_WORDS[m]
    if position == "manifest":
        return READ_ONLY
    return "ok" if m in {"trash", "delete"} else READ_ONLY


for position in POSITIONS:
    for m in MUTATIONS:
        cases.append({"id": f"app_{m}_{position}", "kind": "app_mutation", "position": position, "mutation": m,
                      "expect": app_expect(position, m)})

def skip(id_, name, expect, is_dir=False, is_link=False, not_local=False):
    cases.append({
        "id": id_,
        "kind": "skip",
        "name": name,
        "is_dir": is_dir,
        "is_link": is_link,
        "not_local": not_local,
        "expect": expect,
    })


skip("skip_desktop_ini", "desktop.ini", "junk")
skip("skip_desktop_ini_upper", "DESKTOP.INI", "junk")
skip("skip_thumbs_db", "Thumbs.db", "junk")
skip("skip_thumbs_db_lower", "thumbs.db", "junk")
skip("skip_ds_store", ".DS_Store", "junk")
skip("skip_icon_cr", "Icon\r", "junk")
skip("skip_office_lock", "~$Quarterly report.docx", "junk")
skip("skip_crdownload", "setup.exe.crdownload", "junk")
skip("skip_part", "movie.mkv.part", "junk")
skip("skip_part_upper", "MOVIE.MKV.PART", "junk")
skip("skip_partial", "photo.jpg.partial", "junk")
skip("skip_recycle_bin", "$RECYCLE.BIN", "junk", is_dir=True)
skip("skip_system_volume_information", "System Volume Information", "junk", is_dir=True)
skip("keep_thumbs_db_lookalike", ".Thumbs.db.txt", None)
skip("keep_icon_without_cr", "Icon", None)
skip("keep_part_in_the_middle", "report.part.pdf", None)
skip("keep_tilde_without_dollar", "~notes.txt", None)
skip("skip_photos_library_folder", "Photos Library.photoslibrary", "library_bundle", is_dir=True)
skip("keep_photos_library_named_file", "Photos Library.photoslibrary", None)
skip("skip_music_library_folder", "Music Library.musiclibrary", "library_bundle", is_dir=True)
skip("skip_tv_library_folder", "TV Library.tvlibrary", "library_bundle", is_dir=True)
skip("skip_library_bundle_mixed_case", "Old.PhotosLibrary", "library_bundle", is_dir=True)
skip("skip_symlink", "shortcut", "link", is_link=True)
skip("skip_not_local_file", "IMG_0001.HEIC", "not_local", not_local=True)
skip("skip_not_local_folder", "Holiday 2025", "not_local", is_dir=True, not_local=True)
skip("precedence_junk_over_not_local", "Thumbs.db", "junk", not_local=True)
skip("precedence_not_local_over_link", "cloud placeholder.jpg", "not_local", is_link=True, not_local=True)
skip("skip_icloud_stub", ".IMG_0001.HEIC.icloud", "not_local")
skip("skip_icloud_stub_upper", ".notes.ICLOUD", "not_local")
skip("keep_icloud_without_dot", "IMG_0001.icloud", None)
skip("keep_bare_dot_icloud", ".icloud", None)
skip("keep_dot_git_folder", "." + "git", None, is_dir=True)
skip("keep_hidden_file", ".bashrc", None)
skip("keep_ordinary_photo", "IMG_0001.HEIC", None)

cases.append({
    "id": "layout_rel_path",
    "kind": "rel_path",
    "device": "GLegion",
    "category": "pictures",
    "rel": "2026/beach.jpg",
    "expected": "Backups/GLegion/Pictures/2026/beach.jpg",
})
cases.append({
    "id": "layout_rel_path_category_folder",
    "kind": "rel_path",
    "device": "Guus's iPhone",
    "category": "camera_roll",
    "rel": "",
    "expected": "Backups/Guus's iPhone/Camera Roll",
})
cases.append({
    "id": "layout_own_backup_refusal",
    "kind": "own_backup_refusal",
    "source_path": "C:\\Users\\guus\\Pictures\\beach.jpg",
    "expected": "This is a backup of C:\\Users\\guus\\Pictures\\beach.jpg. Change the original instead.",
})

# Review #5: a custom folder's name is made safe like a device folder's and never equals a fixed category folder
# or another custom folder of the device (folded: NFC + lowercase); it gets " (2)", " (3)", ...
def custom(id_, raw, expected, taken=()):
    cases.append({"id": id_, "kind": "custom_name", "raw": raw, "taken": list(taken), "expected": expected})


custom("custom_plain_name_is_kept", "Projects", "Projects")
custom("custom_fixed_name_gets_a_suffix", "Pictures", "Pictures (2)")
custom("custom_fixed_name_differs_only_in_case", "pictures", "pictures (2)")
custom("custom_camera_roll_display_name_clashes", "Camera Roll", "Camera Roll (2)")
custom("custom_other_custom_name_gets_a_suffix", "Projects", "Projects (2)", ["Projects"])
custom("custom_second_clash_counts_up", "Projects", "Projects (3)", ["Projects", "projects (2)"])
custom("custom_separator_is_replaced", "a/b", "a_b")
custom("custom_reserved_windows_name", "CON", "CON_")
custom("custom_nothing_usable_is_folder", "", "Folder")
# Delta 3 #1: a name is at most 200 UTF-8 bytes, suffix included. The base is cut to make room, never the suffix,
# so two long names that share their first 200 bytes get two folders (the runner also checks that the category
# folder of the stored name is the name itself).
LONG = "a" * 200
custom("custom_long_name_is_cut_to_200_bytes", LONG + "x" * 50, LONG)
custom("custom_long_clash_keeps_its_suffix", LONG + "y" * 50, "a" * 196 + " (2)", [LONG])
custom("custom_long_multibyte_clash_cuts_at_a_char_boundary", "é" * 120, "é" * 98 + " (2)",
       ["é" * 100])
# Review 4 #4: a reserved stem's `_` stays inside the 200 bytes, so the stored name is its own folder's name and
# never the folder of another custom name that cleans to the same 200 bytes.
custom("custom_reserved_stem_at_the_byte_cap", "CON." + "a" * 196, "CON_." + "a" * 195)
custom("custom_reserved_stem_at_the_cap_never_shares_a_folder", "CON." + "a" * 196, "CON_." + "a" * 191 + " (2)",
       ["CON_." + "a" * 195])
cases.append({
    "id": "layout_rel_path_long_custom_name_keeps_its_suffix",
    "kind": "rel_path",
    "device": "GLegion",
    "category": "custom:" + "a" * 196 + " (2)",
    "rel": "x.txt",
    "expected": "Backups/GLegion/" + "a" * 196 + " (2)/x.txt",
})
cases.append({
    "id": "layout_rel_path_custom_name_is_safe",
    "kind": "rel_path",
    "device": "GLegion",
    "category": "custom:a/b",
    "rel": "x.txt",
    "expected": "Backups/GLegion/a_b/x.txt",
})

# The drive rule (Explorer, Finder, the iOS Files app; Guus 17:49 "Protect the whole tree", 19:30 and 19:33):
# nothing at or under the root is trashed, deleted, renamed, moved, created or changed. Precedence: the root's own
# words for its structural mutations; then the own-active-backup words; then "managed in the app" for a structural
# mutation and "read-only" for a create, a write or anything on a device's manifest; outside is ok. 6 positions x 6
# mutations, then 6 own-active cases and one precedence case.
SOURCE = "C:\\Users\\guus\\Pictures\\beach.jpg"
OWN = f"This is a backup of {SOURCE}. Change the original instead."


def drive_expect(position, m):
    if position == "outside":
        return "ok"
    if position == "root" and m in STRUCTURAL:
        return ROOT_WORDS[m]
    if position == "manifest":
        return READ_ONLY
    return MANAGED if m in STRUCTURAL else READ_ONLY


for position in POSITIONS:
    for m in MUTATIONS:
        cases.append({"id": f"drive_{m}_{position}", "kind": "drive_mutation", "position": position,
                      "own_active_source": None, "mutation": m, "expect": drive_expect(position, m)})
for m in MUTATIONS:
    cases.append({"id": f"drive_{m}_own_active", "kind": "drive_mutation", "position": "inside",
                  "own_active_source": SOURCE, "mutation": m, "expect": OWN})
cases.append({"id": "drive_trash_root_words_before_own_active", "kind": "drive_mutation", "position": "root",
              "own_active_source": SOURCE, "mutation": "trash", "expect": DEL})

doc = {
    "description": "LD-0113 backup protection and skip rules (spec 2026-11-06-backup-from-source §4.2 rules 1, 7 and 8; "
    "Amendments 7 and 8, lead 2026-11-06 20:01, Guus 20:04): the root name, its badge and the origin header; the server's "
    "root rule (6 mutations x {the root, a child, another row}, a move into the root allowed); the position of a row by "
    "its depth below the root and its name (a device's manifest), and which rows are hidden; the app rule and the "
    "drive rule (6 positions x 6 mutations each, the drive rule's own-active words and their precedence); the "
    "never-backed-up names, library bundles (folders only), links and not-local entries with their precedence; custom "
    "folder names; and the layout path.",
    "source": "Guus 2026-11-06 17:49, 19:30, 19:33 and 20:04 (the rules, their words and the badge), lead 20:01 (the "
    "manifest) + mobile src/lib/protected-folders.ts (the delete and move words, byte-for-byte) + spec §4.2; written by "
    "test-vectors/tools/make_backup_protect_vectors.py (independent of core)",
    "cases": cases,
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(len(cases))
