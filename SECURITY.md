# Security

Report vulnerabilities to **security@beebeeb.io**. We aim to acknowledge reports within 48 hours and
keep reporters updated. Do not open a public issue for an unpatched vulnerability or run automated
scanners against production.

## Threat model

Core assumes the device, operating-system key store, and native client code are trusted. The service
stores ciphertext and protocol metadata, controls API answers and ordering, and may deny service.
Possession of a session token alone does not provide a file key.

With an honest native client and secret keys, a malicious storage or API service cannot forge an
AES-GCM tag, open v2 file content, reorder or splice v2 chunks without detection, or open a
passkey-sealed master key without the passkey PRF output. It can always omit data, delay work, return
errors, exhaust availability, or serve stale information where the client has no trusted newer state.

Important current limits:

- V2 metadata carries a version ID and monotonic counter. A device that remembers a higher counter can
  detect rollback. A new device, or any device that never observed the newer counter, can still be
  shown old metadata and matching old content. There is no account-wide signed freshness state.
- The web client executes code delivered by the service. Modified host JavaScript can capture keys or
  plaintext before or after WASM runs; WASM cannot protect itself from its host page.
- Contact fingerprints and safety numbers support key-change warnings, but first use has no prior pin.
  A service that substitutes a contact key on the first exchange can receive data sealed to that key.
- V1 file chunks authenticate each chunk but do not bind file identity, version, position, or finality.
  A malicious service can reorder, duplicate, splice, drop, or truncate old v1 content in ways v2
  rejects. Unrecorded old metadata also retains compatibility detection. See
  [docs/legacy-formats.md](docs/legacy-formats.md).
- Key proof authenticates possession to an honest verifier; it does not authenticate the service to a
  client. `KeyProofVerifier` contains the service's ephemeral private key until its one verification
  attempt consumes it. A live reader of any shared challenge store that holds this state can start a
  challenge, read that private state, and compute a valid response. A static copy made after the state
  was discarded cannot do that.
- Local native storage is intentionally not database-encrypted. It can contain decrypted names and
  metadata. Platforms must apply their documented file protection and backup exclusions.

## Review status

Core has not had an independent security review. Public security claims must remain specific and
testable until one has happened.

The following new cryptographic or protocol surfaces have not yet received independent review and
require it before security claims depend on them:

- the SPAKE2 camera-less device-link path, including its dependency's timing behavior;
- binding the displayed code into the QR device-link seal and its new format;
- one-time key proof and the service-side lifetime of verifier state;
- resumable v2 encryption and its persisted source/version state;
- passkey sealing, including account and credential binding.

Review should include the binding surfaces and real client/server integration, not only the Rust unit
tests.
