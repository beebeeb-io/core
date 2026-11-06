"""Generator for test-vectors/consolidation/backup_device.json (LD-0113 A3).

Device-folder naming, device identity (find_device_folder), the device id
derived from the OS machine id, and the device manifest (spec §4.2 rules 2-4).
Independent of core: names are written from the spec, ids are computed here with
hashlib. Usage:
    python3 -I test-vectors/tools/make_backup_device_vectors.py test-vectors/consolidation/backup_device.json
"""
import hashlib
import json
import sys
import uuid

LABEL = b"beebeeb/backup-device-id/v1"


def device_id_from_machine_id(machine_id: str) -> str:
    """SHA-256(LABEL || 0x00 || trimmed id), first 16 bytes, RFC 4122 v8 bits."""
    b = bytearray(hashlib.sha256(LABEL + b"\x00" + machine_id.strip().encode("utf-8")).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x80  # version 8
    b[8] = (b[8] & 0x3F) | 0x80  # variant 10xx (RFC 4122)
    return str(uuid.UUID(bytes=bytes(b)))


ME = "a3f2b1c4-5d6e-4f70-8a9b-0c1d2e3f4a5b"  # "my" device id in the naming cases
OTHER = "0d4e5f60-7182-4a3b-9c4d-5e6f708192a3"
F1 = "11111111-1111-4111-8111-111111111111"
F2 = "22222222-2222-4222-8222-222222222222"

cases = []


def name(id_, raw, expected, taken=()):
    cases.append({
        "id": id_,
        "kind": "name",
        "raw": raw,
        "my_id": ME,
        "taken": [{"name": n, "device_id": d} for n, d in taken],
        "expected": expected,
    })


name("name_glegion_unchanged", "GLegion", "GLegion")
name("name_iphone_unchanged", "Guus's iPhone", "Guus's iPhone")
name("name_reserved_con", "CON", "CON_")
name("name_reserved_lowercase", "com1", "com1_")
name("name_reserved_with_extension", "CON.local", "CON_.local")
name("name_trailing_dot", "name.", "name_")
name("name_trailing_space", "name ", "name_")
name("name_separator", "a/b", "a_b")
name("name_backslash", "a\\b", "a_b")
name("name_windows_characters", "a:b*c?", "a_b_c_")
name("name_control_character", "a\tb", "a_b")
name("name_bidi_override_removed", "‮GLegion", "GLegion")
name("name_empty", "", "Device")
name("name_only_dots", "...", "Device")
name("name_only_separators", "///", "Device")
name("name_only_space", " ", "Device")
name("name_only_invisible", "​", "Device")
name("name_nfd_becomes_nfc", "René's Mac", "René's Mac")
name("name_long_is_cut_to_200_bytes", "a" * 300, "a" * 200)
name("name_collision_other_id", "GLegion", "GLegion (a3f2)", [("GLegion", OTHER)])
name("name_collision_manifest_less", "GLegion", "GLegion (a3f2)", [("GLegion", None)])
name("name_collision_differs_only_in_case", "GLegion", "GLegion (a3f2)", [("glegion", OTHER)])
name("name_collision_with_my_own_id", "GLegion", "GLegion", [("GLegion", ME)])
name("name_collision_twice_widens_suffix", "GLegion", "GLegion (a3f2b1c4)",
     [("GLegion", OTHER), ("GLegion (a3f2)", OTHER)])
name("name_no_collision_with_other_names", "GLegion", "GLegion", [("Guus's iPhone", OTHER)])

GLEGION_MACHINE = "7f3e9c2a-1b4d-4e8f-9a6c-5d2b8e1f0a3c"
for id_, raw in [("machine_id_trimmed", " 4c4c4544-0042 "), ("machine_id_plain", "4c4c4544-0042"),
                 ("machine_id_windows_guid", GLEGION_MACHINE)]:
    cases.append({
        "id": id_,
        "kind": "machine_id",
        "machine_id": raw,
        "expected": device_id_from_machine_id(raw),
        "source": "python3 -c \"import hashlib,uuid; b=bytearray(hashlib.sha256(b'beebeeb/backup-device-id/v1'+b'\\x00'"
                  f"+{raw.strip()!r}.encode()).digest()[:16]); b[6]=b[6]&15|128; b[8]=b[8]&63|128; "
                  "print(uuid.UUID(bytes=bytes(b)))\"",
    })

DESKTOP_ID = device_id_from_machine_id(GLEGION_MACHINE)


def manifest(device_id, platform=None, device_name="GLegion"):
    m = {"version": 1, "device_id": device_id, "device_name": device_name}
    if platform:
        m["platform"] = platform
    return m


def find(id_, me, candidates, expect):
    cases.append({
        "id": id_,
        "kind": "find",
        "me": me,
        "candidates": [{"folder_id": f, "name": n, "manifest": m} for f, n, m in candidates],
        "expect": expect,
    })


WIN = {"device_id": ME, "name": "GLegion", "platform": "windows"}
find("find_by_id", WIN, [(F1, "GLegion", manifest(ME, "windows"))], {"existing": F1})
find("find_renamed_folder_by_id", WIN, [(F1, "Guus's gaming PC", manifest(ME, "windows"))], {"existing": F1})
find("find_reinstall_same_machine_id",
     {"device_id": DESKTOP_ID, "name": "GLegion", "platform": "windows"},
     [(F1, "GLegion", manifest(DESKTOP_ID, "windows"))], {"existing": F1})
find("find_by_id_wins_over_legacy", WIN,
     [(F1, "GLegion", None), (F2, "Old name", manifest(ME, "windows"))], {"existing": F2})
find("find_adopts_manifest_less_legacy_on_windows", WIN, [(F1, "GLegion", None)], {"adopt_legacy": F1})
find("find_adopts_manifest_less_legacy_on_linux",
     {"device_id": ME, "name": "guus-laptop", "platform": "linux"},
     [(F1, "guus-laptop", None)], {"adopt_legacy": F1})
find("find_legacy_is_never_adopted_on_ios",
     {"device_id": ME, "name": "GLegion", "platform": "ios"},
     [(F1, "GLegion", None)], {"create": "GLegion (a3f2)"})
find("find_legacy_needs_the_exact_name", WIN, [(F1, "glegion", None)], {"create": "GLegion (a3f2)"})
find("find_same_name_other_id_creates_suffixed", WIN,
     [(F1, "GLegion", manifest(OTHER, "windows"))], {"create": "GLegion (a3f2)"})
find("find_same_name_other_platform_creates_suffixed", WIN,
     [(F1, "GLegion", manifest(OTHER, "ios"))], {"create": "GLegion (a3f2)"})
find("find_nothing_creates", WIN, [], {"create": "GLegion"})

IOS_MANIFEST = json.dumps({
    "version": 1,
    "device_id": "0b7e4a2c-9d1f-4c3a-8e5b-2f6d9a1c7e40",
    "device_name": "Example iPhone",
    "device_model": "iPhone 17 Pro",
    "os_version": "iOS 26.5",
    "app_version": "1.0.214",
    "created_at": "2026-05-01T09:30:00.000Z",
    "deletion_behavior": "keep",
    "keep_vault_unlocked": False,
    "backups": {
        "camera_roll": {"enabled": True, "last_sync": "2026-11-05T21:14:03.120Z", "items_synced": 4210,
                        "include_videos": True, "wifi_only": True, "background_enabled": True,
                        "legacy_items_migrated": 0},
        "contacts": {"enabled": False, "last_sync": None, "items_synced": 0, "contact_count": 0},
        "calendar": {"enabled": False, "last_sync": None, "items_synced": 0, "calendar_count": 0},
    },
}, ensure_ascii=False)
DESKTOP_MANIFEST = json.dumps({
    "version": 1,
    "device_id": DESKTOP_ID,
    "device_name": "GLegion",
    "platform": "windows",
    "folders": [
        {"category": "pictures", "enabled": True, "last_pass_at_ms": 1762430400000, "items": 18342},
        {"category": "documents", "enabled": False, "last_pass_at_ms": None, "items": 0},
    ],
}, ensure_ascii=False)
FUTURE_MANIFEST = json.dumps({
    "version": 1,
    "device_id": DESKTOP_ID,
    "device_name": "GLegion",
    "platform": "windows",
    "a_future_field": {"nested": [1, 2, 3], "flag": True},
}, ensure_ascii=False)
LEGACY_ID_MANIFEST = json.dumps({
    "version": 1,
    "device_id": "legacy-device-7",
    "device_name": "Old iPad",
    "platform": "visionos",
}, ensure_ascii=False)


def man(id_, text, device_id, platform, device_name, folders):
    cases.append({
        "id": id_,
        "kind": "manifest",
        "json": text,
        "expect": {"device_id": device_id, "platform": platform, "device_name": device_name, "folders": folders},
    })


man("manifest_real_ios_round_trips", IOS_MANIFEST, "0b7e4a2c-9d1f-4c3a-8e5b-2f6d9a1c7e40", None,
    "Example iPhone", 0)
man("manifest_desktop_round_trips", DESKTOP_MANIFEST, DESKTOP_ID, "windows", "GLegion", 2)
man("manifest_unknown_field_is_kept", FUTURE_MANIFEST, DESKTOP_ID, "windows", "GLegion", 0)
man("manifest_non_uuid_id_and_unknown_platform_are_kept_verbatim", LEGACY_ID_MANIFEST, None, None,
    "Old iPad", 0)
cases.append({"id": "manifest_not_an_object_is_an_error", "kind": "manifest_error", "json": "[1, 2]"})
cases.append({"id": "manifest_not_json_is_an_error", "kind": "manifest_error", "json": "{\"version\": 1,"})

doc = {
    "description": "LD-0113 device folders (spec 2026-11-06-backup-from-source §4.2 rules 2-4): the device folder "
    "name under path_safety's portable rules with the device-id suffix on a collision, find_device_folder "
    "(by id, legacy desktop adoption, create), the device id derived from the OS machine id, and the device "
    "manifest (a real iOS manifest round-trips; unknown fields are kept).",
    "source": "spec §4.2 rules 2-4 + mobile src/services/BackupService.ts:94-125 (the iOS manifest shape, values "
    "replaced); written by test-vectors/tools/make_backup_device_vectors.py (ids via hashlib, independent of core)",
    "cases": cases,
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(len(cases))
