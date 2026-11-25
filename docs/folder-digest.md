# Folder digest v1

`bb-folder-digest-v1` is a 32-byte value per folder (and one per account root) that changes when anything a
listing shows about the folder's subtree changes. The server keeps it; a client compares the digest it holds with
the server's and reads further down only where the two differ. An idle tree of 41,000 items is then checked in a
handful of requests instead of one listing per folder.

Code: `beebeeb-core/src/folder_digest.rs`. Wire types: `beebeeb-types/src/folder_digest.rs`
(`FolderDigestPage`, `FolderDigestChild`). Vectors: `test-vectors/folder_digest_v1.json`, read by the module's tests
(`cargo test -p beebeeb-core folder_digest`); their expected hex was written by an independent BLAKE3.

## v1 never changes

This is a wire format between every client and the server. Once v1 ships, its bytes, contexts, sort order and
child set stay as written here. A change is a v2: new derive-key contexts, a new algorithm string, new vectors,
and the server sending the algorithm it computed. The two contexts are BLAKE3 `derive_key` contexts, not HKDF
labels, so they are not in `label_table_tests.rs` (that table lists the `b"beebeeb…"` HKDF, AAD and salt labels).

## The definition

All hashing is BLAKE3 in its key-derivation mode, `derive_key(context, input)`, 32 bytes out.

- `ALGORITHM` = `bb-folder-digest-v1`.
- **Name hash** of a child: `derive_key("beebeeb folder digest v1 name", name_encrypted)` over the UTF-8 bytes of
  the name ciphertext string (`name_hash`).
- **Record** of a child: 114 bytes (`encode_record`):

  | Offset | Bytes | Field |
  |---|---|---|
  | 0 | 1 | kind: 1 file, 2 folder |
  | 1 | 1 | flags: bit 0 = uploading, other bits 0 |
  | 2 | 16 | id (the UUID's 16 bytes, `Uuid::as_bytes`) |
  | 18 | 8 | size_bytes, i64 big-endian |
  | 26 | 8 | version_number, i64 big-endian |
  | 34 | 16 | object_version_id (`current_object_version_id`), zeros when none |
  | 50 | 32 | name hash |
  | 82 | 32 | the child folder's digest; zeros for a file |

- **Folder digest** (`folder_digest`): `derive_key("beebeeb folder digest v1", count || records)` where `count` is
  the number of children as a u64 big-endian and `records` are the children's records sorted by id bytes
  ascending. The input order does not matter.
- **Empty**: a folder with no children has `EMPTY` = `derive_key("beebeeb folder digest v1", 0u64 BE)` =
  `db890c62967d99016e43cbf649ab13075e3d1b6b94d791b9071ed95be0a58795`. A folder with no stored digest row has this
  digest.
- **Hex** on the wire: 64 lowercase characters (`to_hex`); `from_hex` takes exactly that form and nothing else.

A file's record is the server's row as it is, also while it is uploading: a new version's init already changes
size and version, so the digest changes then and again when the upload completes. A folder's record has
uploading false, size 0, version 0, no object version, and its own digest, so a change anywhere below a folder
changes every digest on the path to the root.

## The child set

The children of folder F are the rows of `files` with `user_id = F.user_id AND parent_id = F AND NOT
is_trashed`. The children of the root of account U are the rows with `user_id = U AND parent_id IS NULL AND NOT
is_trashed`. That is exactly what `GET /api/v1/files` (`trashed=false`) lists to the owner; rows that are
still uploading (`is_uploading`) are included.

## Not in the digest, on purpose

Thumbnails, previews, the star, the note, the storage pool, the system role and every timestamp. None of them is
something a sync or backup pass compares, and each changes on its own (a thumbnail lands after the upload, a
star is a click): putting them in would make the digest change where no client has anything to do. A client
that needs one of them reads it from the listing it makes for a folder that did change.

## Why the name ciphertext is hashed as its stored string

The server cannot read a name, and different clients have written names in different envelope formats over
time. Every client and the server do hold the same string: the one the server stores and sends in JSON. Hashing
those bytes, with no base64 or envelope decoding first, gives every party the same input whatever the format,
and a rename (a new ciphertext) always changes the digest. The hash is over ciphertext only; no plaintext name
ever enters a digest.

## How a client walks

1. Read the root's digest (`GET /api/v1/folder-digests`, `limit=0` for the digest alone). Equal to the digest the
   client holds for the root: nothing below changed, the walk ends after one request.
2. Otherwise read the root's children with their digests (every page). For each child folder whose digest
   differs from the held one, or that is new, go down the same way. A child folder whose digest is equal is not
   read: nothing below it changed.
3. Files and removed children of a folder that differed are found by the listing the client makes for that
   folder.
4. Every page carries the folder's digest at that page's read. When it changes between pages, start that
   folder again.
5. **After-read rule.** Store a folder's digest as held only after the client has read and applied that
   folder's listing, and store the digest the server sent *before* that listing (not a later one). A write that
   lands between the digest read and the listing then shows up as a difference on the next walk instead of
   being hidden by a digest that already includes it.
