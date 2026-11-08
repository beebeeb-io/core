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
