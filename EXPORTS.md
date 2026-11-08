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
