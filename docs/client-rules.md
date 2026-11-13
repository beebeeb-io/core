# Rules for projects using core

These are target boundaries for every Beebeeb product. Existing exceptions are named below; they are
not precedent for new code.

## Never implement in a client

A client must not:

1. Encrypt, decrypt, derive keys, or hash for a security decision outside core.
2. Choose, store, or pass raw key bytes. This is a target rule; current binding exceptions are below.
3. Define key labels, AAD, nonces, wire formats, or file formats.
4. Mint file or folder IDs.
5. Trust a server field for a chunk format or choose a write format.
6. Implement sign-in, second factor, reset, recovery, unlock, or sign-out policy.
7. Choose chunk sizes, limits, retry, backoff, timeout, or resume policy.
8. Decide sync, conflict, deduplication, backup, password, session, thumbnail, or cache policy.
9. Call the Beebeeb API directly, except for the web transport exception below.
10. Open or change core's local database, or publish plaintext outside paths core names.
11. Log or display keys, tokens, signed URLs, recovery material, or other secrets.
12. Use a different core revision from the shared release pin, or hand-edit bindings or vectors.
13. Work around a missing core operation; add the operation to core first.

## Operations that go through core

Core owns account flows; key storage decisions and cryptography; file creation and mutation; upload,
download, resume, and publish rules; the local tree and sync; thumbnails and previews; backup and
deduplication; sharing, contact keys, file requests, and search; limits, retry guidance, and error codes.

A platform draws UI, maps typed errors to wording, performs requested OS work such as background
transfer or image encoding, reports the outcome, and renders core events.

## Native client boundary

Rust products use `beebeeb-client`; Swift and Kotlin products use `NativeClientHandle` and its opaque
service handles. Those services own authentication and devices, files and sync, uploads, downloads,
thumbnails, sharing, contacts, search, settings, backup, File Provider, and coordinated sign-out.
Applications must not retain an account key or session token alongside those services.

Password acceptance, after any configured authenticator, produces a locked session. A new device then
uses exactly one account-key source: device approval, passkey plus email code, or recovery key plus
email code. Account-key proof runs before the session is installed. The email ticket belongs to key
proof, not the password request. Signup is web-only; native clients surface the typed web URL.

A native app locks at two levels, and core holds the one state machine (`Client::lock_state`); a client
never tracks "locked" beside it, never reads the key entry itself and never compares passwords itself.
`Client::start_from_store` replaces any start-up restore: the app starts `ScreenLocked` (key loaded, work
runs) or `VaultClosed` (the key entry is not read; work is stopped), never open. The screen lock opens
with `unlock_screen_platform_verified` (only after the operating system's own user-verification prompt
returned success for the current user) or `unlock_screen_with_password`; a closed vault opens only
with `sign_in_on_device` (plus `submit_two_factor`) and `unlock_known_device`. While `ScreenLocked` a
host shows no file name, account data or thumbnail and keeps the window out of screen capture. Core
itself refuses every call a person drives except unlock, lock vault and sign out (`screen_locked_allows`,
answered as `ClientError::ScreenLocked`; a sign-out there removes this device only), and keeps sync,
transfers and backup running; the list is in `docs/agent-notes.md`, "What the screen lock refuses". A
host never works around a refusal, and asks `Client::check_call` before a path core cannot see (a read
of the local store or the search index that would show a name). After
`SessionExpired` a host calls `Client::session_ended`. Both levels are locks on the app, not
encryption of the device: copy says "locked" and "sync is paused", never "encrypted while locked",
and never that the password protects the files or the key. The host's `SecretStore` must be
this-device-only and non-roaming. The password path (`ClientConfig::lock_password_path`) stays off
until the server it talks to has the password proof and reports the password counter.

The secret store keeps `session.owner`, `session.master_key`, `session.api_url`, and
`account.generation` as shared device state. Each app has `session.token.{app_id}`, registered in
`session.app_ids`. The hardware UUID and identity secret are device-local and must never sync. Signing
out one app removes only its token; whole-device sign-out goes through `ServiceCoordinator` so work,
caches, account rows, directories, tokens, and shared key state are removed in order.

## Web transport exception

Web may use `fetch` for plain API transport with core-defined request and response types, and may use
browser storage. Cryptography still goes through `beebeeb-wasm`. Host JavaScript is inside the web
client's trust boundary, so this exception does not protect against modified code served to the browser.

## Raw-key migration inventory

New exports must use opaque handles or purpose-specific operations. The following UniFFI exports are
absent from the default Swift/Kotlin surface and exist only with the default-off `legacy-bindings`
feature. The WASM entries remain browser compatibility surface while browser storage is byte-based.

| Binding | Raw secret-producing exports still present |
| --- | --- |
| UniFFI | `MasterKeyResult.key`, `RecoveryPhraseResult.master_key`, `OpaqueLoginFinishResult.session_key`, `OpaqueLoginFinishResult.export_key`, `derive_file_key`, `recover_from_phrase`, `derive_x25519_private`, `x25519_shared_secret`, `derive_share_key`, `derive_request_wrap_key`, `unwrap_request_private`, `open_request_upload`, `transfer_derive_key`, `MasterKeyHandle::derive_x25519_private`, `MasterKeyHandle::export_for_keychain` |
| WASM | `derive_master_key`, `derive_file_key`, `recover_from_phrase`, `opaque_login_finish` (`session_key`, `export_key`), `derive_x25519_private`, `x25519_shared_secret`, `derive_share_key`, `derive_request_wrap_key`, `unwrap_request_private`, `open_request_upload`, `transfer_derive_key`, `ownerFileKeyForName`, `ownerFileKeyForContent`, `unwrapFolderChild`, `unwrapOwnerFileKey`, `openLegacyInviteOwnerCopy`, `unwrapInviteOwnerCopy`, `unwrapFolderCustody`, `unwrapLinkOwnerKey`, `openLegacyChildKey` |

Legacy free functions also accept raw master, file, private, shared, and transfer keys. Keep them only
for an existing native app that temporarily builds and regenerates with `legacy-bindings`; never enable
that feature for a new app. Web keys necessarily cross between WASM and its JavaScript host until web
storage and service APIs are handle-based.

## Enforcement and pins

- CI rejects new legacy writers, generated-vector drift, and undocumented raw export names.
- Consumer repositories reject forbidden crypto or direct-network imports outside named adapters.
- All consumers move together to one reviewed core revision. The server uses `CORE_REV`; native Rust
  consumers pin the Cargo git `rev`; web updates its lockfile and generated WASM package through its
  sync command; mobile regenerates Swift and Kotlin bindings from that same revision.
- `scripts/check-core-pins-documented.sh` checks that any `CORE_REV`-style identifier in this repository
  is named here. A consumer-specific exception must be documented with its reason and owner.
