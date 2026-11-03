# beebeeb-wasm / uniffi exports — branch `feat/2326-request-row-shipped-seal`

Task 2275 §15 + 2326 delta2 (request-row shipped seal). Base: core #65 head
`2f5cd8a` (branch point; the generated WASM package at `5894fa4`, its parent,
has the same 145 export names).

Counts are the `export function` / `export class` names in the generated
`beebeeb_wasm.d.ts`, which is what a bundler sees.

- base: 145 names
- head: 149 names
- **removed: 0**
- **added: 4**

Added names:

| Name | Since | What |
| --- | --- | --- |
| `mintGuestItemId` | 2326 §15 | Mint a guest (F) item id with no master key |
| `sealRequestRename` | 2326 §15 | Seal a request-row rename under the §15 string-derived key |
| `previewableBatchFor` | core #65 merge | Per-platform preview table (`web` / `desktop` / `mobile`) |
| `WasmRequestContentReader` | 2326 delta2 P2-2 | Request-row content reader: `fileId`, `chunkFormat`, `decryptor()`, `openFrame(...)` |

Nothing was renamed or removed. The request-row content handle changed shape;
`WasmChunkDecryptor`, `ChunkDecryptorHandle` and `FileKeyHandle` are untouched.

## Changed result shapes

The request-row results no longer carry raw keys. Each row below is a change,
not a removal; the exported function/class names are unchanged.

| Surface | Before | Replacement |
| --- | --- | --- |
| WASM `resolveRequestRow` result | `content: WasmChunkDecryptor`; before delta2 also `contentKey` / `nameKey` | `content: WasmRequestContentReader` (`fileId`, `chunkFormat`, `decryptor()`, `openFrame(versionId, index, isLast, format, frame)`); no key fields |
| WASM `resolveRequestRow.renameTarget` | `{origin, pin, key}` | `{origin, pin}`; seal with `sealRequestRename(master, itemId, pin, filename, mimeType)` |
| uniffi `RequestRowKeys` | `content: ChunkDecryptorHandle`; before delta2 also `content_key`, `name_key` | `content: RequestContentReader`; no key fields |
| uniffi `resolve_request_row` | returned `RequestRowKeys.content: ChunkDecryptorHandle` | returns `RequestRowKeys.content: RequestContentReader` (same name, new shape) |
| uniffi `resolve_request_row_detailed` | returned `ResolvedRequestRow.content: ChunkDecryptorHandle` | returns `ResolvedRequestRow.content: RequestContentReader` (same name, new shape) |
| uniffi `ResolvedRequestRow` | `content: ChunkDecryptorHandle` | `content: RequestContentReader` |
| uniffi `RequestRenameTarget` | `{origin, pin, key: FileKeyHandle}` | `{origin, pin}`; seal with `MasterKeyHandle::seal_request_rename` |

`RequestContentReader` (uniffi) / `WasmRequestContentReader` (WASM) has no key
getter; the key is zeroized when the reader drops, it is bound to the row's
file id and chunk-format pin, `decryptor()` returns a fresh sequential
decryptor per call, and `open_frame` / `openFrame` reads one frame by index.

## UniFFI additions and generated-binding shape (2326, request content)

The `cargo check` surface is not the whole story for UniFFI: the committed
Kotlin/Swift bindings are generated from these annotations. This branch adds
three items to the UniFFI surface (all additions; nothing removed):

| uniffi item | Kind | What |
| --- | --- | --- |
| `RequestContentReader` | object | Request-row content reader: `file_id`, `chunk_format`, `decryptor()`, `open_frame(...)`; no key getter |
| `MasterKeyHandle::seal_request_rename` | method | Seal a request-row rename under the §15 string-derived key |
| `mint_guest_item_id` | function | Mint a guest (F) item id with no master key |

The generated bindings must be regenerated for these three (`build-ios.sh` /
`build-android.sh`); the in-tree Rust tests do not compile the Swift/Kotlin
glue.

One uniffi caller change (not an export change): the request-row readers used
to be consumed as `content.push_frame(...)`; they are now
`content.decryptor().push_frame(...)`, because every call returns a fresh
sequential cursor. Callers that kept the old `ChunkDecryptorHandle`-shaped
field still compile against the record but must follow the new call.

The WASM counts above are unchanged by these docs: 145 base, 149 head,
0 removed, 4 added.

## Reconciliation of the changed-shape count

The delta report said **4 changed** and the reviewer said **3**. Both are
right about different sets:

- 4 changed exported shapes = the WASM `resolveRequestRow` result plus the
  three uniffi records (`RequestRowKeys`, `ResolvedRequestRow`,
  `RequestRenameTarget`).
- the reviewer's 3 = the uniffi records only (the same three).
- the table above has 7 rows because it also lists `resolve_request_row`,
  `resolve_request_row_detailed` and `resolveRequestRow.renameTarget`: those
  are the same record changes seen at their entry points, plus the removed
  `renameTarget.key` field. They are not additional exported names.

The earlier delta report's "4 changed" counted the request-row records; no
exported item was removed in either count.

## Artifact

The generated WASM package for the branch head is under
`bb-gate-logs/fullspeed/core-wasm-pkg/<head-sha>/` (web target, release); its
`EXPORTS.md` repeats these counts for that head.
