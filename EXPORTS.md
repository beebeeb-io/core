# beebeeb-wasm / uniffi exports — branch `feat/LD-0113-backup-rules`

LD-0113 (backups from the real folder, a protected Backups root, backup rules
in core). Base: tag `v0.2.0` (`3db0cc26f286`). Additive only: nothing in v0.2.0
is renamed, retyped or removed.

## WASM

Counts are the `export function` / `export class` names in the generated
`beebeeb_wasm.d.ts` (`wasm-pack build beebeeb-wasm --target web`), which is
what a bundler sees: `grep -c "^export function\|^export class" beebeeb_wasm.d.ts`,
and `comm` over the sorted names for the added and removed lists.

- base (`v0.2.0`): 149 names
- head: 157 names
- **removed: 0**
- **added: 8** (the eight `backup*` names below)

| Name | What |
| --- | --- |
| `backupCheckAppMutation(position, mutation)` | The app rule, the web's own (spec Amendment 8): core's words when `mutation` (`trash`, `delete`, `rename`, `move`, `create`, `write`) of a row at `position` (`root`, `device_folder`, `manifest`, `category_folder`, `inside`, `outside`; for `create`, the destination folder) is refused, else `undefined`. The root and a device's manifest refuse everything; under the root only trash and delete are allowed. |
| `backupCheckDriveMutation(position, ownActiveSource, mutation)` | The drive rule (Explorer, Finder, the Files app), same words: the root's words, then the own-active-backup words, then "Backups are managed in the Beebeeb app…" or "Backups are read-only…" for anything at or under the root, else `undefined`. |
| `backupCheckRootMutation(role, mutation)` | The server's root rule: the root's words for a trash / delete / rename / move of the `backups_root` row, else `undefined`. |
| `backupPositionAtDepth(depth?, name)` | A row's position from its depth below the flagged root (`undefined`: not under it) and its name (`manifest` for a device folder's `.device.json`). |
| `backupIsHiddenItem(depth?, name)` | `true` for a row no listing shows (a device folder's `.device.json`). |
| `backupRootBadge()` | The badge shown on the Backups root, `"Read-only"`. |
| `backupProtectionMany(roles: string[])` | One byte per listing row, 1 = the protected root (one crossing per listing). A role this build does not know is protected (1), never a throw. |
| `backupParseManifest(json)` | A decrypted `.device.json` as a plain object; unknown fields kept. |

Every unknown mutation, position or role string throws, except in
`backupProtectionMany`. Dialog copy (the device-folder confirmation) stays in
the web UI. The web client keeps the row's `system_role` from the listing and
passes it here.

## UniFFI

Counts are the `uniffi_beebeeb_uniffi_fn_*` and `uniffi_beebeeb_uniffi_checksum_*`
symbols in the generated `beebeeb_uniffiFFI.h` (`uniffi-bindgen generate
--language swift` over the built library), base against head:
`grep -c -E "uniffi_beebeeb_uniffi_(fn|checksum)_" beebeeb_uniffiFFI.h`, and `comm`
over the sorted symbols.

- base (`v0.2.0`): 576 symbols
- head: 608 symbols
- **removed: 0**
- **added: 32** (16 functions, each with its checksum)

| Function | What |
| --- | --- |
| `backup_check_app_mutation(position, mutation)` | `throws -> String?`: the app rule (the iOS app), the refusal words or none; `position` from `backup_position_at_depth`, for `create` the destination folder; the root and a device's manifest refuse everything |
| `backup_check_drive_mutation(position, own_active_source, mutation)` | `throws -> String?`: the drive rule (Files app), same precedence as core |
| `backup_check_root_mutation(role, mutation)` | `throws -> String?`: the server's root rule |
| `backup_position_at_depth(depth, name)` | `"root"`, `"device_folder"`, `"manifest"` (a device folder's `.device.json`), `"category_folder"`, `"inside"` or `"outside"` (`depth` none) |
| `backup_is_hidden_item(depth, name)` | `true` for a row no listing shows (the manifest) |
| `backup_root_badge()` / `backup_root_name()` | `"Read-only"`, the badge shown on the Backups root; `"Backups"`, the name of a root made on `BackupRootPlan.Create` |
| `backup_origin_header()` | `BackupHeader { name: "X-Beebeeb-Origin", value: "backup" }`, sent on every request of a backup pass |
| `backup_skip_reason(name, is_dir, is_link, not_local)` | Why an entry is never backed up, or none |
| `backup_resolve_root(candidates)` | `BackupRootPlan`: `Use`, `Claim { id, merge_from }`, `Create` |
| `backup_plan_merge(survivor, duplicates, clash_label, hhmm)` | `[BackupMergeStep]` from flat listing rows; pass `hhmm` with a dot |
| `backup_device_folder_name(raw, my_id, taken)` | The device folder name, with the device-id suffix on a collision; ids are strings (a UUID or an iOS legacy id) |
| `backup_find_device_folder(me, candidates)` | `BackupDeviceFolderChoice`: `Existing`, `AdoptLegacy`, `Create { name }`; a manifest that does not parse is "unreadable" (not mine, not adoptable), never an error; a legacy non-UUID id matches `Existing` |
| `backup_parse_manifest(json)` / `backup_serialize_manifest(manifest)` | `.device.json`; unknown fields cross as `other_json` (the manifest's, and each `BackupFolderState`'s own); only a document that is not a JSON object fails to parse |
| `backup_plan_pass(entries, records, live_remote, live_remote_complete, unseen, held, max_uploads, max_bytes)` | `BackupPassPlan` with `held` and `deferred_unknown`; each upload carries `record_key` and, for `changed`, `remote_id`; `mark_removed_elsewhere` is `[BackupRecordRef]` (key and remote id): mark a record only while it still names that remote id; `max_uploads` 0 counts as 1 (iOS passes an empty `unseen` and asset ids with `/` replaced by `\|`) |

Every string the binding parses (mutation, position, role, platform, record
state, id) that it does not know is `CryptoError.InvalidInput`, never a pass.

The committed `beebeeb-uniffi/bindings/` copy is regenerated by `build-ios.sh`
/ `build-android.sh` on the platform rung; this branch does not commit it.
Before this branch it was already behind v0.2.0's source (43 functions of
v0.2.0 are missing from the committed header), so a regeneration also brings
those in.

## Rust (rustdoc JSON, private items included)

`beebeeb_core` +211 items, `beebeeb_types` +33, `beebeeb_uniffi` +439 (the
uniffi scaffolding behind the 16 exports), `beebeeb_wasm` +13; **0 removed and 0
changed** in all four (rustdoc JSON of `v0.2.0` and of this branch, pinned
1.96.0, item paths compared). New crate: `beebeeb-backup`.
