# beebeeb-wasm / uniffi exports

## Branch `fix/v028-review` (review hardening before v0.2.8): changed signatures, removed 0, added 0 exports

The full list is CHANGELOG `[Unreleased]` → "Changed". Exports whose signature changed:

- **WASM:** `passkeyParseRegistrationStart(answerJson, expectedRpId, allowLocalhost)`,
  `passkeyParseAssertionStart(answerJson, expectedRpId, allowLocalhost)`,
  `shareRebuildLink(appUrl, masterKey, ownerWrappedKey?, ownerWrappedToken?, wrappedFileKey?)`,
  `AccountFlow.changePassword(current, newPassword, recoveryCheckB64, x25519PublicB64, onboardingStatus,
  onboardingBody, breachCheck?)`; `new AuthStepUp(password, purpose?, cliCode?)` refuses a `cliCode` with another
  purpose. WASM keeps raw key bytes (its convention).
- **UniFFI:** `passkey_parse_registration_start` / `passkey_parse_assertion_start` (+ `expected_rp_id`,
  `allow_localhost`); `AccountFlowHandle::change_password` (+ `onboarding_status`, `onboarding_body`,
  `breach_check: Option<BreachCheckHandle>`); `StepUpFlow::new` refuses a `cli_code` with another purpose; keys as
  handles: `SignupCreatedFfi.master_key`, `RecoveredFfi::SignedIn.master_key`, `DeviceRequestEventFfi::Approved.master_key`,
  `ApprovalFlow::approve`, `MemberInviteFlow::new`, `share_approve_file_invite_request`, `share_open_member_file_key`,
  `CreateLinkFlow::new` / `bundle` (`BundleItemFfi.file_key`), `share_rebuild_link` (+ `wrapped_file_key`),
  `share_open_link_file_key`, `FolderShareFlow::new` / `link`, `CreateRequestFlow`, `share_rebuild_folder_link` and
  the file-request rebuild take or return `MasterKeyHandle` / `FileKeyHandle`.

## Branch `feat/v2-share-flows`

Desktop v2 B05b (Guus: every crypto and account flow lives in core). Person shares of a file and double-encrypted
file links move into core as `beebeeb_core::share_flow`, byte-identical to web (web's `share-wrap-kat` vectors and
the `x25519_share_key_exchange` vector are pinned in `share_flow::tests`). Measured against `main` at `e3eeb8b`.
Additive only, except `auth_flow::Method` gains `Delete` (a host that matches it exhaustively adds one arm).

## WASM

Counted from source (unique `js_name = …` under `beebeeb-wasm/src`): base 187, head 193.

- **removed: 0**
- **added: 6**

| Name | What |
| --- | --- |
| `shareWrapKey(wrapKey, key)` / `shareUnwrapKey(wrapKey, wrapped)` | Web's `wrapKeyForShare` / `unwrapKeyFromShare`: `nonce(12) \|\| ct`, no AAD. |
| `ShareMemberInvite(itemId, isFolder, email, masterKey, fileKey)` | `start()`, `onResponse(...)` → `{kind: "send"}` / `"shared"` / `"invited"` / `"awaiting_approval"`. A folder throws `invalid_input` (use `ShareFolderInvite`). |
| `ShareFolderInvite(folderId, email, sharedFoldersWrite, custodySeen, custodyUnreadable, masterKey)` (B05c) | `start()` / `onResponse(...)` → `{kind: "send", request, markCustodySeen}` (persist the id BEFORE sending) / `"shared"` / `"invited"` / `"awaiting_approval"`. Throws `folder_key_unverified`, `folder_keys_unavailable`, `folder_needs_upgrade`, `folder_too_large`. |
| `ShareFolderInvite.link(folderId, appUrl, accessLevel, label?, expiresInHours?, capBytes?, maxOpens?, passphrase?, custodySeen, custodyUnreadable, masterKey)` (B05c) | Web's `createFolderLinkWithKeys`: same steps, ends `{kind: "link_created", shareId, link, display, accessLevel, passphraseProtected, keyVersion}`. |
| `ShareCreateRequest(appUrl, title, description?, targetFolderId?, maxFiles?, maxTotalBytes?, expiresInSecs?, masterKey)` (B05c) | A file request (web `pages/file-request.tsx`): `start()`, `onResponse(...)` → `{id, link, display}`; `link` is `/r/{token}#{b64url(R_pub)}`. |
| `shareRebuildFolderLink(appUrl, masterKey, shareId, ownerWrappedKey?, ownerWrappedToken?, wrappedFolderKey?, passphraseProtected)` (B05c) | Web `rebuildFolderLinkUrl`: the owner's folder link, or `undefined`. UniFFI: `share_rebuild_folder_link`. |
| `fileRequestRebuildLink(appUrl, masterKey, token?, wrappedPrivateKey?, wrapNonce?)` (B05c) | Web `handleCopyExisting`: the request's link again, or `undefined`. |
| `shareCreateBundle(appUrl, fileIds, positions, fileKeys, masterKey, expiresInHours?, maxOpens?, passphrase?)` (B05c) | A `ShareCreateLink` over an ordered set of files (web's bundle branch); `fileKeys` is the 32-byte keys concatenated. |
| `ShareCreateLink(appUrl, fileId, masterKey, fileKey, expiresInHours?, maxOpens?, passphrase?)` | `start()`, `onResponse(...)` → `{kind: "send"}` (one retry on an untyped 409) / `{kind: "created", shareId, link, display}`. |
| `shareRebuildLink(appUrl, masterKey, ownerWrappedKey?, ownerWrappedToken?, wrappedFileKey?)` | Web's `buildShareLink`: the owner's link, or `undefined`. |
| `shareOpenMemberFileKey(masterKey, ownerPublicKey, fileId, sealed)` | The recipient side of a person share. |

## UniFFI

- **removed: 0**
- **added:** objects `MemberInviteFlow`, `CreateLinkFlow`; enums `InviteStepFfi`, `LinkStepFfi`; error
  `ShareFlowFfiError::Flow { code }`; functions `share_approve_file_invite_request`, `share_open_member_file_key`,
  `share_rebuild_link`, `share_open_link_file_key`, `share_revoke_request`. Requests reuse `AuthHttpRequest`.
- **added (B05c):** object `FolderShareFlow` (constructor `new` = a folder invite, `link` = a folder link), enum
  `FolderStepFfi` (`Send` carries `mark_custody_seen`; `LinkCreated` carries `link` with `#key=` and `display`).
- **added (B05c):** object `CreateRequestFlow`, record `CreatedRequestFfi`, functions `file_request_rebuild_link`,
  `file_request_close_request`; `CreateLinkFlow.bundle` constructor with record `BundleItemFfi`.

The committed Kotlin bindings under `bindings/` are not regenerated here.

## Rust

New module `beebeeb_core::share_flow` (`member`, `link`; B05c: `folder` with `folder::link`, `folder_keys`, `request`, `bundle`); `auth_flow::Method::Delete`
and (B05c) `Method::Put`, with their `account_flows` arms. `ShareFlowError::FolderInviteUnsupported` is gone (B05c):
four folder codes replace it.

# beebeeb-wasm / uniffi exports — branch `feat/v2-auth-wiring`

Desktop v2 B10b: server PR #422's routes wired into `account_flows` and `auth_flow`, and the bindings for B11's
`signup_flow` / `recovery_flow` (crypto rule 0). Measured against `main` at `e3eeb8b`.

**Not additive: 2 signatures change** (the server now asks for more). Both in Rust, UniFFI and WASM:
- `AccountFlow::delete_account(password)` → `delete_account(password, code?)`: it now calls
  `POST /auth/account/delete-request` (the server mails a link; nothing is scheduled), outcome `deletion_requested`.
- `AccountFlow::set_activity_logging(on)` → `set_activity_logging(on, password?)`: turning it off steps up inside.

## WASM

- **removed: 0; changed: 2** (`AccountFlow.deleteAccount`, `AccountFlow.setActivityLogging`)
- **added:** classes `SignupFlow`, `PhraseRecovery`; functions `signupPolicyRequest`, `recoveryUnknownWordPositions`;
  methods `AccountFlow.regenerateBackupCodes`, `deleteConfirm`, `deleteCancel`; `AuthApproval.deny`, `onDenyResponse`.
- Outcome kinds added: `deletion_requested` (`link_expires_at`), `deletion_cancelled` (`not_restored`);
  `deletion_scheduled` gains `cancel_until`. Error codes added: `second_factor_required`, `link_invalid`,
  `confirmation_required`.

## UniFFI

- **removed: 0; changed: 2** (`AccountFlowHandle.delete_account`, `set_activity_logging`; record
  `AccountFlowOutcome` gains `cancel_until`, `link_expires_at`, `not_restored`)
- **added:** objects `SignupFlowHandle`, `PhraseRecoveryHandle`; record `SignupCreatedFfi`; enum `RecoveredFfi`;
  error `SignupFlowFfiError::Flow { code, retry_after_secs }`; functions `signup_policy_request`,
  `recovery_unknown_word_positions`; methods `AccountFlowHandle.regenerate_backup_codes`, `delete_confirm`,
  `delete_cancel`; `ApprovalFlow.deny`, `on_deny_response`.

---

# beebeeb-wasm / uniffi exports — branch `feat/v2-auth-flows`

Desktop v2 B10 (`docs/superpowers/specs/2026-11-08-desktop-v2-design.md`, crypto review rule 0): the sign-in,
step-up and device-approval flows move into core. Additive only: nothing is renamed, retyped or removed. Measured
against `main` at `124389a` (v0.2.7).

## WASM

- **removed: 0**
- **added: 4 classes** (`js_name` count +4)

| Name | What |
| --- | --- |
| `AuthSignIn(email, password)` | `start()`, `onResponse(status, body, retryAfter?)` → `{kind: "send", request}` / `{kind: "signed_in", sessionToken}` / `{kind: "second_factor"}`; `verifyRequest(code)`, `onVerifyResponse(...)` → session token. |
| `AuthStepUp(password, purpose?, cliCode?)` | `start()`, `onResponse(...)` → `{kind: "send"}` / `{kind: "confirmed"}`; `attachConfirmToken(path, body)` → the consuming request with `confirmToken`. |
| `AuthDeviceRequest()` | `initFrame(deviceName?, client, version, os)`, `onFrame(text)` → `{kind: "waiting", userCode, verificationUri, expiresIn}` / `{kind: "approved", sessionToken, masterKey}`. |
| `AuthApproval(code)` | `start()`, `onLookupResponse(...)` → facts, `codeMatches(typed)`, `approve(typed, password, masterKey)`, `onResponse(...)` → `{kind: "send"}` / `{kind: "approved"}`. |

Errors throw `JsError(code)`: `invalid_credentials`, `wrong_code`, `rate_limited:<secs>`, `account_deleted`,
`opaque_unavailable`, `request_not_found`, `already_handled`, `expired`, `denied`, `keys_did_not_arrive`, …

## UniFFI

- **removed: 0**
- **added:** objects `SignInFlow`, `StepUpFlow`, `DeviceRequestFlow`, `ApprovalFlow`; records `AuthHttpRequest`,
  `AuthHttpResponse`, `RequesterFactsFfi`; enums `SignInStepFfi`, `StepUpStepFfi`, `DeviceRequestEventFfi`,
  `ApproveStepFfi`; error `AuthFlowFfiError::Flow { code, retry_after_secs }`. Same shapes as WASM.

---

# beebeeb-wasm / uniffi exports — branch `feat/passkey-vault-primitive`

B15 (desktop v2, passkeys; Guus 2026-11-08: the logic in core, only the platform call in each client). Measured
against `124389a` (v0.2.7). Additive only: nothing is renamed, retyped or removed.

## WASM

Counted from source: the unique `js_name = …` names under `beebeeb-wasm/src` (`grep -o | sort -u | wc -l`).

- base (`124389a`): 156 names
- head: 162 names
- **removed: 0**
- **added: 6**

| Name | What |
| --- | --- |
| `passkeyPrfEvalInput()` | The 32-byte `prf.eval.first` web passes (`beebeeb.io/vault-wrap-key/v1`, zero-padded). |
| `passkeyWrapVaultKey(prfOutput, masterKey)` | The escrow blob `nonce(12) || ct(32) || tag(16)`; web's `encryptVaultBlob` format. |
| `passkeyUnwrapVaultKey(prfOutput, blob)` | The 32-byte vault key; throws on a wrong PRF output, a changed byte or a blob that is not 60 bytes. |
| `passkeyParseRegistrationStart(answerJson)` | `register-start`'s answer as `RegistrationStart` JSON. |
| `passkeyParseAssertionStart(answerJson)` | `login-start`'s answer as `AssertionStart` JSON. |
| `passkeyEscrowBody(credentialId, blob)` | The `vault-key-escrow` POST body. |

Web keeps its TS (`src/lib/passkey-vault.ts`) until a later web task switches; the vectors prove parity.

## UniFFI

- **removed: 0**
- **added: 10** free functions (`passkey_prf_eval_input`, `passkey_hmac_secret_salt`, `passkey_wrap_vault_key`,
  `passkey_unwrap_vault_key` → `MasterKeyHandle` (no raw key crosses), `passkey_parse_registration_start`,
  `passkey_registration_finish_body`, `passkey_escrow_body`, `passkey_parse_assertion_start`,
  `passkey_assertion_finish_body`, `passkey_parse_escrow`).

The committed Kotlin bindings under `bindings/` are not regenerated here.

## Rust

New module `beebeeb_core::passkey` (`ceremony`, `flow`); no existing item changed.
