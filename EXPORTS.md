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

# beebeeb-wasm / uniffi exports — branch `feat/LD-0121-notice-overlap`

LD-0121, spec `2026-11-06-backup-from-source-design.md` Amendment 12d (server
#415 review finding 1; Guus 2026-11-08 03:16, "Go w recommended"): a backup
pass reads the removal notices with a 10-minute overlap and remembers the
notice ids it acted on. Ships as core v0.2.5. Measured against tag `v0.2.3`
(`df93011`); tag `v0.2.4` (`1d1a335`, the zip 8 → 9 bump) changes no file
under `src/` (`git diff --name-only v0.2.3 v0.2.4 -- '*/src/*'` is empty), so
every count below holds against v0.2.4 too. Additive only: nothing in v0.2.4
is renamed, retyped or removed; `backup_stop` / `backup_pass_gate`
(`backupStop` / `backupPassGate`) keep their behaviour and are documented as
superseded.

## WASM

Counted from source: the `js_name = …` names in `beebeeb-wasm/src` of the
v0.2.3 tree and of this branch, with `comm` over the sorted names. The
generated `.d.ts` is type-checked by CI's WASM JS surface job.

- base (`v0.2.3`): 152 names
- head: 156 names
- **removed: 0**
- **added: 4**

| Name | What |
| --- | --- |
| `backupNoticeOverlapMs()` | 600000: how far before `lastPassAtMs` a notice still counts (a notice's `created_at` is the start of the server transaction that wrote it, not its commit). |
| `backupNoticesSince(lastPassAtMs)` | The `since` to send to `GET /api/v1/notifications` (inclusive, integer ms): `lastPassAtMs` minus the overlap, never below 0. A value that is not a whole number of milliseconds throws. |
| `backupStopV2(notices, lastPassAtMs, acknowledged, listing)` | `{stopped: [{category, reason}], acknowledged: [id]}`. A notice (`{id, type, data, created_at_ms}`) counts when it is after `lastPassAtMs` minus the overlap and its `id` is not in `acknowledged`; `acknowledged` in the answer replaces the stored set. An `id` that is not a non-empty string is no id (never acknowledged). `acknowledged` may be `undefined`/`null`; a non-string entry throws. |
| `backupPassGateV2(noticesFetchOk, notices, lastPassAtMs, acknowledged, listing)` | `{outcome: "run", stopped, acknowledged}` (as `backupStopV2`), or `{outcome: "check_failed"}` when the notices could not be read: keep both `lastPassAtMs` and the acknowledged set. |

## UniFFI

Counted from source: the free functions directly under a `#[uniffi::export]`
in `beebeeb-uniffi/src` of both trees, with `comm` over the sorted names (this
scan counts v0.2.3 as 110; v0.2.3's own file said 111 by a scanner not in the
repo; the delta is the same either way).

- base (`v0.2.3`): 110 functions
- head: 114 functions
- **removed: 0**
- **added: 4**

| Function | What |
| --- | --- |
| `backup_notice_overlap_ms()` | `Int64`, as `backupNoticeOverlapMs` |
| `backup_notices_since(last_pass_at_ms)` | `Int64`, as `backupNoticesSince` |
| `backup_stop_v2(notices, last_pass_at_ms, acknowledged, listing)` | `throws -> BackupStopOutcome` (`stopped`, `acknowledged`); rows are `BackupNoticeRowV2` (`id: String?`, `kind`, `data_json`, `created_at_ms`); the listing parses as for `backup_stop` |
| `backup_pass_gate_v2(notices_fetch_ok, notices, last_pass_at_ms, acknowledged, listing)` | `throws -> BackupPassGateV2` (`Run { stopped, acknowledged }` or `CheckFailed`) |

The committed Kotlin bindings under `bindings/` are not regenerated here (they
do not carry the v0.2.2/v0.2.3 backup functions either).

## Rust (rustdoc JSON, private items included)

Each item keyed by its path, ids replaced by the paths they point to, docs,
spans, child lists and blanket/auto-trait impl members left out; `v0.2.3`
against this branch, rustc 1.96.0 (`RUSTC_BOOTSTRAP=1`, separate target dirs
per tree). Seen red: with the inputs swapped it reports `beebeeb_core` 43
removed, and a head with `backup_stop`'s `last_pass_at_ms` retyped to `u64`
reports 1 changed.

| Crate | Added | Removed | Changed |
| --- | --- | --- | --- |
| `beebeeb_core` | 43 | 0 | 0 |
| `beebeeb_types` | 0 | 0 | 0 |
| `beebeeb_uniffi` | 124 | 0 | 0 |
| `beebeeb_wasm` | 18 | 0 | 0 |
| `beebeeb_backup` | 0 | 0 | 0 |
