"""Generator for test-vectors/consolidation/backup_protect.json (LD-0113 A2).

Independent of core: the expected words and skip answers are written here from
the spec (§4.2 rules 1, 7, 8) and mobile's protected-folders.ts, never read back
from Rust. Usage: python3 -I test-vectors/tools/make_backup_protect_vectors.py test-vectors/consolidation/backup_protect.json
"""
import json
import sys

DEL = "Backups is a system folder and can't be deleted."  # mobile protected-folders.ts:11
MOV = "Backups is a system folder and can't be moved."  # mobile protected-folders.ts:12
REN = "Backups is a system folder and can't be renamed."  # new (spec §4.2 rule 7)
WORDS = {"trash": DEL, "delete": DEL, "rename": REN, "move": MOV}

cases = []
for m in ["trash", "delete", "rename", "move"]:
    for target, role in [("root", "backups_root"), ("child", None), ("other", None)]:
        cases.append({
            "id": f"protect_{m}_{target}",
            "kind": "mutation",
            "target": target,
            "role": role,
            "mutation": m,
            "expect": WORDS[m] if role else "ok",
        })
cases.append({
    "id": "protect_move_into_root_allowed",
    "kind": "mutation",
    "target": "an item moved into the root (the item has no role)",
    "role": None,
    "mutation": "move",
    "expect": "ok",
})


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

# The drive rule (Guus 2026-11-06 17:49, "Protect the whole tree"): in Explorer, Finder and the iOS Files app
# nothing at or under the root can be deleted, renamed or moved. Precedence: the root's own words; then the
# own-active-backup words; then "managed in the app"; else ok. 4 mutations x {root, under root, own active, outside}.
APP = "Backups are managed in the Beebeeb app. Open Beebeeb to delete or move a backup."
SOURCE = "C:\\Users\\guus\\Pictures\\beach.jpg"
OWN = f"This is a backup of {SOURCE}. Change the original instead."
for m in ["trash", "delete", "rename", "move"]:
    for target, is_root, under, own, expect in [
        ("root", True, False, None, WORDS[m]),
        ("under_root", False, True, None, APP),
        ("own_active", False, True, SOURCE, OWN),
        ("outside", False, False, None, "ok"),
    ]:
        cases.append({"id": f"drive_{m}_{target}", "kind": "drive_mutation", "is_root": is_root,
                      "under_root": under, "own_active_source": own, "mutation": m, "expect": expect})

doc = {
    "description": "LD-0113 backup protection and skip rules (spec 2026-11-06-backup-from-source §4.2 rules 1, 7 and 8): "
    "the 4 x 3 mutation matrix (trash, delete, rename, move against the Backups root, a child and another row), "
    "a move into the root allowed, the never-backed-up names, library bundles (folders only), links and not-local "
    "entries with their precedence, and the layout path.",
    "source": "mobile src/lib/protected-folders.ts (the delete and move words, byte-for-byte) + spec §4.2; "
    "written by test-vectors/tools/make_backup_protect_vectors.py (independent of core)",
    "cases": cases,
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(len(cases))
