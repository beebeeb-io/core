# beebeeb-wasm / uniffi exports — branch `feat/LD-0121-first-pass-baseline`

LD-0121, spec `2026-11-06-backup-from-source-design.md` Amendment 12c (Guus,
2026-11-07 20:45): the first pass's baseline and the pass gate when the
notices could not be read. Base: tag `v0.2.2` (`2d89adc1e2e3`). Additive only:
nothing in v0.2.2 is renamed, retyped or removed.

## WASM

Counted from source: the `js_name = …` names in `beebeeb-wasm/src` of the
v0.2.2 tree and of this branch, with `comm` over the sorted names. The
generated `.d.ts` is type-checked by CI's WASM JS surface job.

- base (`v0.2.2`): 149 names
- head: 152 names
- **removed: 0**
- **added: 3**

| Name | What |
| --- | --- |
| `backupFirstPassBaseline(setupAtMs?, legacyLastBackupMs?)` | The `lastPassAtMs` of a device with none under the new engine: the setup time, or an upgraded device's last old-engine backup; with both, the earlier; with neither, 0. A value that is not a whole number of milliseconds throws. |
| `backupPassGate(noticesFetchOk, notices, lastPassAtMs, listing)` | `{outcome: "run", stopped: [{category, reason}]}` (as `backupStop`), or `{outcome: "check_failed"}` when the notices could not be read: upload nothing, turn nothing off, keep `lastPassAtMs`, retry next pass. `notices` is not read when the fetch failed. |
| `backupCheckFailedWords()` | "Couldn't check — will retry." |

## UniFFI

Counted from source: the `#[uniffi::export]` functions in `beebeeb-uniffi/src`
of both trees, with `comm` over the sorted names.

- base (`v0.2.2`): 108 functions
- head: 111 functions
- **removed: 0**
- **added: 3**

| Function | What |
| --- | --- |
| `backup_first_pass_baseline(setup_at_ms, legacy_last_backup_ms)` | `Int64`, as `backupFirstPassBaseline` |
| `backup_pass_gate(notices_fetch_ok, notices, last_pass_at_ms, listing)` | `throws -> BackupPassGate` (`Run { stopped }` or `CheckFailed`); the listing parses as for `backup_stop` |
| `backup_check_failed_words()` | "Couldn't check — will retry." |

## Rust (rustdoc JSON, private items included)

The same instrument as v0.2.2's PRs (each item keyed by its path, ids replaced
by the paths they point to, docs, spans, child lists and blanket/auto-trait impl
members left out), `v0.2.2` against this branch, pinned 1.96.0:

| Crate | Added | Removed | Changed |
| --- | --- | --- | --- |
| `beebeeb_core` | 37 | 0 | 0 |
| `beebeeb_types` | 0 | 0 | 0 |
| `beebeeb_uniffi` | 73 | 0 | 0 |
| `beebeeb_wasm` | 33 | 0 | 0 |
| `beebeeb_backup` | 0 | 0 | 0 |
