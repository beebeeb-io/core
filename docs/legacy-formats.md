# Legacy formats

Compatibility paths are readers only unless a row below explicitly describes an update to an existing
row. New files and new metadata use v2 and purpose subkeys. Do not add a fallback without adding it here,
its allowed caller, hostile-input tests, and a removal condition.

| Legacy path | What it reads | Allowed callers and write rule | Remove only when |
| --- | --- | --- | --- |
| `ChunkFormat::V1Legacy`, `ExpectedChunkFormat::Unrecorded`, and the v1 branch of `resume_policy` | Old no-AAD file frames and old metadata with no recorded format. Unrecorded frame 0 detects once and locks the stream. | File-content readers may use the value returned by `decrypt_file_metadata` or `decrypt_file_metadata_with_key`; never a server field. A persisted v1 session may continue only with a v1 writer. Production writers use `WRITE_FORMAT` and never create v1. | Every stored v1 version is migrated or deliberately retired, all metadata records a supported format, all clients read v2, and the service refuses v1 writes. |
| Raw-file-key metadata fallback | Names, thumbnails, and notes sealed before purpose subkeys. | Only `decrypt_file_metadata`, `decrypt_name_metadata`, `decrypt_thumbnail`, and `decrypt_note` compatibility branches. New metadata uses `METADATA_SEAL_WRITE` (`MetadataSeal::Subkey`); generic no-AAD functions are not metadata writers. | Every stored value has been re-sealed under its purpose subkey and old clients can no longer write raw-key metadata. |
| `OwnerKeyConvention::Binary` and `OwnerKeyConvention::UpperRepair` | Owner rows whose key used 16 UUID bytes, and rows produced from uppercase UUID text. | Owner-key resolvers only. Do not create a row under either convention. Existing binary rows can be resolved for an in-place operation. Any row whose name or any version resolves as upper repair is read-only; save edits as a new core-minted item. | An inventory proves no row resolves under either convention and repair/migration has completed on every supported account. |
| `open_legacy_child_key`, `verify_legacy_folder_key`, and `open_legacy_invite_owner_copy` | Unbound 60-byte shared-folder child wraps and old invite owner copies. | Only the named compatibility entry points and their binding wrappers. New child wraps, custody records, and invite owner copies use their purpose-bound APIs. Never fall back after a purpose-bound opener fails. | All shared folders and invites have purpose-bound custody and child records, legacy copies are removed, and supported clients no longer request these openers. |
| `encrypt::decrypt_chunks_to_file`, `encrypt::decrypt_contiguous_to_file`, and `file_encrypt::decrypt_chunks_to_file` | Disk or contiguous legacy content layouts, with v1/v2 selected by authenticated metadata. | Native and UniFFI compatibility reads only. They write a sibling temporary file and rename only after the full stream authenticates. New transfer code uses streaming readers and publishers. | No supported caller or stored job uses these disk layouts and migrations have removed their persisted resume/cache records. |
| OPAQUE v0 Identity KSF | Password files registered under the old unstretched KSF. | Only `client_login_finish_legacy_upgrade`, reached from trusted migration state. Normal `client_login_finish` accepts `MIN_KSF_VERSION` through `CURRENT_KSF_VERSION`, currently v1 only. New registration is v1. No `password_hash` dual-state implementation exists in this workspace. | Every v0 account has authenticated once through the migration path and re-registered under v1, and the service no longer advertises or stores v0. |

## Guards

- `WRITE_FORMAT` is `ChunkFormat::V2` and has a compile-time assertion.
- `ChunkEncryptor::with_format` is compiled only for tests or the `test-support` feature.
- `production_write_format_is_v2` and `p1b_write_switch_uses_v2_and_purpose_subkeys` pin file and
  metadata writes.
- `client_login_finish` rejects v0 and unknown KSF versions; v0 has a separately named migration entry.
- `scripts/check-no-legacy-writes.sh` checks these production switches and test-only seam attributes.
- `scripts/check-test-vectors.sh` regenerates every generated vector in a temporary directory and runs
  every independent Python checker.
