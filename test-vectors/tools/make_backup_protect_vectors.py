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
