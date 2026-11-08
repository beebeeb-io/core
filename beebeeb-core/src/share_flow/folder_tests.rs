//! Folder invites: the pinned vectors the folder flow's output is built from
//! (`test-vectors/vectors.json`, the same file web's KATs read), and the task-2133 key rules,
//! ported from web `test/folder-share*.test.ts` behaviour (`findExistingFolderKey`,
//! `buildFolderInvite`, `ensureOwnerFolderKey`, `assertNoSeenAncestor`).
use serde_json::{Value, json};

use super::folder::{FolderInviteInput, FolderShare, FolderStep};
use super::folder_keys::*;
use super::member::InviteOutcome;
use super::member::PeerKeyExpectation;
use super::*;
use crate::auth_flow::Method;
use crate::kdf;
use crate::opaque::derive_x25519_public;

const FOLDER: &str = "2237c000-0000-4000-8000-000000000001";
const CHILD_FILE: &str = "2237c000-0000-4000-8000-000000000002";
const CHILD_DIR: &str = "2237c000-0000-4000-8000-000000000003";
const GRANDCHILD: &str = "2237c000-0000-4000-8000-000000000004";
const PARENT: &str = "2237c000-0000-4000-8000-0000000000aa";
const INVITE: &str = "7a1d1c2e-0000-4000-8000-000000000009";

fn vector(name: &str) -> Value {
    let all: Value = serde_json::from_str(include_str!("../../../test-vectors/vectors.json")).expect("vectors");
    all["vectors"]
        .as_array()
        .or_else(|| all.as_array())
        .expect("vector list")
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("vector {name} missing"))
        .clone()
}

fn hexv(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().expect(key)).expect("hex")
}

fn key32(v: &Value, key: &str) -> [u8; 32] {
    hexv(v, key).try_into().expect("32 bytes")
}

fn master() -> MasterKey {
    MasterKey::from_bytes([3; 32])
}

fn resp(status: u16, body: Value) -> HttpResponse {
    HttpResponse::new(status, body)
}

fn sent(step: FolderStep) -> (Method, String, Option<Value>, Option<String>) {
    match step {
        FolderStep::Send(s) => (s.request.method, s.request.path, s.request.body, s.mark_custody_seen),
        other => panic!("expected a request, got {other:?}"),
    }
}

fn input(flag: bool, custody: CustodyMemory) -> FolderInviteInput<'static> {
    FolderInviteInput {
        folder_id: FOLDER,
        email: " Bob@Beebeeb.TEST ",
        shared_folders_write: flag,
        custody,
        peer_key: PeerKeyExpectation::NotCompared,
    }
}

fn invite_row(id: &str, status: &str, created: &str, blob: Option<String>) -> Value {
    json!({ "id": id, "file_id": FOLDER, "is_folder_share": true, "status": status,
            "created_at": created, "encrypted_owner_folder_key": blob })
}

fn non_utf8_key(byte: u8) -> FileKey {
    let mut k = [byte; 32];
    k[0] = 0x80;
    FileKey::from_bytes(k)
}

/// Answer the descendant listing: FOLDER holds a file and a folder; that folder holds one file.
fn answer_listing(flow: &mut FolderShare, first: FolderStep) -> (String, Value) {
    let (m, p, _, _) = sent(first);
    assert_eq!(
        (m, p.as_str()),
        (
            Method::Get,
            format!("/api/v1/files?parent_id={FOLDER}&limit=500").as_str()
        )
    );
    let step = flow
        .on_response(resp(
            200,
            json!({ "files": [{ "id": CHILD_FILE, "is_folder": false }], "next_cursor": "c/1 x" }),
        ))
        .unwrap();
    let (_, p, _, _) = sent(step);
    assert_eq!(p, format!("/api/v1/files?parent_id={FOLDER}&limit=500&cursor=c%2F1+x"));
    let step = flow
        .on_response(resp(
            200,
            json!({ "files": [{ "id": CHILD_DIR, "is_folder": true }], "next_cursor": null }),
        ))
        .unwrap();
    let (_, p, _, _) = sent(step);
    assert_eq!(p, format!("/api/v1/files?parent_id={CHILD_DIR}&limit=500"));
    let step = flow
        .on_response(resp(
            200,
            json!({ "files": [{ "id": GRANDCHILD, "is_folder": false }] }),
        ))
        .unwrap();
    let (m, p, body, _) = sent(step);
    assert_eq!(m, Method::Post);
    (p, body.expect("invite body"))
}

fn folder_key_from_id(body: &Value, candidates: &[&FileKey]) -> FileKey {
    let id = body["folder_key_id"].as_str().unwrap();
    let k = candidates
        .iter()
        .find(|k| folder_key_id_b64(k) == id)
        .expect("the invite's folder_key_id names a known key");
    FileKey::from_bytes(*k.as_bytes())
}

// ── Pinned vectors ───────────────────────────────────────────────────────────

#[test]
fn vector_folder_key_id_is_the_wire_id() {
    let v = vector("folder_key_id");
    let key = FileKey::from_bytes(key32(&v, "folder_key_hex"));
    assert_eq!(folder_key_id_b64(&key), b64(&hexv(&v, "expected_key_id_hex")));
}

fn child_vector(name: &str, is_folder: bool) {
    let v = vector(name);
    let folder_key = FileKey::from_bytes(key32(&v, "folder_key_hex"));
    let child = FileKey::from_bytes(key32(&v, "child_key_hex"));
    let root = v["shared_folder_id"].as_str().unwrap();
    let item = v["item_id"].as_str().unwrap();
    let nonce: [u8; 12] = hexv(&v, "nonce_hex").try_into().unwrap();
    let ru = *uuid::Uuid::parse_str(root).unwrap().as_bytes();
    let iu = *uuid::Uuid::parse_str(item).unwrap().as_bytes();
    let kind = if is_folder {
        FOLDER_CHILD_FOLDER
    } else {
        FOLDER_CHILD_FILE
    };
    assert_eq!(kind as u64, v["kind"].as_u64().unwrap());
    let pinned = kdf::wrap_folder_child_with_nonce(&folder_key, &ru, &iu, kind, &child, &nonce).unwrap();
    assert_eq!(frame(pinned), hexv(&v, "wrapped_hex"), "{name}: byte-exact");
    // The flow's L7 seal opens for exactly this (root, item, kind), and not as the other kind.
    let sealed = seal_folder_child(FolderWrapFormat::L7, &folder_key, root, item, is_folder, &child).unwrap();
    let blob = split(&b64_decode(&sealed).unwrap()).unwrap();
    let opened = kdf::unwrap_folder_child(&folder_key, &ru, &iu, kind, &blob).unwrap();
    assert_eq!(opened.as_bytes(), child.as_bytes());
    let other = if is_folder {
        FOLDER_CHILD_FILE
    } else {
        FOLDER_CHILD_FOLDER
    };
    assert!(kdf::unwrap_folder_child(&folder_key, &ru, &iu, other, &blob).is_err());
}

#[test]
fn vector_folder_child_file_v1() {
    child_vector("folder_child_file_v1", false);
}

#[test]
fn vector_folder_child_folder_v1() {
    child_vector("folder_child_folder_v1", true);
}

#[test]
fn vector_invite_owner_copy_v1_opens_in_the_flow() {
    let v = vector("invite_owner_copy_v1");
    let m = MasterKey::from_bytes(key32(&v, "master_key_hex"));
    let rec = v["record_id"].as_str().unwrap();
    match open_owner_copy(&m, rec, &hexv(&v, "wrapped_hex")).unwrap() {
        OwnerCopyOpen::Opened(k) => assert_eq!(k.as_bytes().to_vec(), hexv(&v, "plaintext_hex")),
        OwnerCopyOpen::AuthFailed => panic!("pinned owner copy must open"),
    }
    // Another folder id is an authentication failure (it may fall through to the legacy proof).
    assert!(matches!(
        open_owner_copy(&m, "folder-other", &hexv(&v, "wrapped_hex")).unwrap(),
        OwnerCopyOpen::AuthFailed
    ));
}

#[test]
fn vector_folder_custody_v1_opens_with_the_custody_purpose_only() {
    let v = vector("folder_custody_v1");
    let m = MasterKey::from_bytes(key32(&v, "master_key_hex"));
    let rec = v["record_id"].as_str().unwrap();
    let blob = split(&hexv(&v, "wrapped_hex")).unwrap();
    let k = kdf::unwrap_folder_custody(&m, rec.as_bytes(), &blob).unwrap();
    assert_eq!(k.as_bytes().to_vec(), hexv(&v, "plaintext_hex"));
    assert!(matches!(
        open_owner_copy(&m, rec, &hexv(&v, "wrapped_hex")).unwrap(),
        OwnerCopyOpen::AuthFailed
    ));
}

// ── Flag off: invite-only folders (legacy format) ────────────────────────────

#[test]
fn flag_off_no_active_invite_mints_and_seals_every_descendant() {
    let m = master();
    let (mut flow, first) = FolderShare::invite(input(false, CustodyMemory::default()), &m).unwrap();
    let (_, p, _, _) = sent(first);
    assert_eq!(p, "/api/v1/shares/invites/sent");
    let step = flow.on_response(resp(200, json!({ "invites": [] }))).unwrap();
    let (path, body) = answer_listing(&mut flow, step);
    assert_eq!(path, "/api/v1/shares/invites");
    assert_eq!(body["recipient_email"], "bob@beebeeb.test");
    assert_eq!(body["is_folder_share"], true);
    assert_eq!(body["encrypted_folder_key"], "");
    assert!(body.get("format").is_none(), "a legacy write carries no format");
    let owner = b64_decode(body["encrypted_owner_folder_key"].as_str().unwrap()).unwrap();
    let key = kdf::unwrap_invite_owner_copy(&m, FOLDER.as_bytes(), &split(&owner).unwrap()).unwrap();
    assert_eq!(body["folder_key_id"], folder_key_id_b64(&key));
    let rows = body["folder_keys"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "every descendant, no root row for a legacy folder");
    for row in rows {
        let id = row["file_id"].as_str().unwrap();
        let wrap = b64_decode(row["encrypted_file_key"].as_str().unwrap()).unwrap();
        let child = unwrap_key_from_share(key.as_bytes(), &wrap).unwrap();
        assert_eq!(child.as_slice(), kdf::derive_file_key(&m, id.as_bytes()).as_bytes());
    }
    // Claimed: the folder key is sealed for the recipient and approved.
    let bob = MasterKey::from_bytes([9; 32]);
    let bob_pub = derive_x25519_public(&crate::opaque::derive_x25519_private(&bob));
    let step = flow
        .on_response(resp(
            200,
            json!({ "invite_id": INVITE, "status": "claimed", "recipient_public_key": b64(&bob_pub) }),
        ))
        .unwrap();
    let (_, p, body, _) = sent(step);
    assert_eq!(p, format!("/api/v1/shares/invites/{INVITE}/approve"));
    let sealed = b64_decode(body.unwrap()["encrypted_file_key"].as_str().unwrap()).unwrap();
    let owner_pub = derive_x25519_public(&crate::opaque::derive_x25519_private(&m));
    let opened = open_member_file_key(&bob, &owner_pub, FOLDER, &sealed).unwrap();
    assert_eq!(opened.as_bytes(), key.as_bytes());
    match flow.on_response(resp(200, json!({}))).unwrap() {
        FolderStep::Done(InviteOutcome::Shared {
            invite_id,
            recipient_public_key,
        }) => {
            assert_eq!(invite_id, INVITE);
            assert_eq!(recipient_public_key, bob_pub);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn flag_off_reuses_the_newest_owner_copy_that_opens() {
    let m = master();
    let (old, new) = (non_utf8_key(1), non_utf8_key(2));
    let invites = json!({ "invites": [
        invite_row("aa01", "approved", "2026-11-01T00:00:00Z", Some(owner_copy_b64(&m, FOLDER, &old).unwrap())),
        invite_row("aa02", "invited", "2026-11-05T00:00:00Z", Some(owner_copy_b64(&m, FOLDER, &new).unwrap())),
        invite_row("aa03", "denied", "2026-11-07T00:00:00Z", Some(owner_copy_b64(&m, FOLDER, &non_utf8_key(4)).unwrap())),
    ]});
    let (mut flow, _) = FolderShare::invite(input(false, CustodyMemory::default()), &m).unwrap();
    let step = flow.on_response(resp(200, invites)).unwrap();
    let (_, body) = answer_listing(&mut flow, step);
    let used = folder_key_from_id(&body, &[&old, &new]);
    assert_eq!(
        used.as_bytes(),
        new.as_bytes(),
        "the newest ACTIVE invite's key, a denied one never"
    );
}

#[test]
fn flag_off_active_invites_without_an_owner_copy_never_mint() {
    let (mut flow, _) = FolderShare::invite(input(false, CustodyMemory::default()), &master()).unwrap();
    let invites = json!({ "invites": [invite_row("aa01", "claimed", "2026-11-01", None)] });
    assert_eq!(
        flow.on_response(resp(200, invites)).unwrap_err(),
        ShareFlowError::FolderKeyUnverified
    );
    assert_eq!(
        flow.on_response(resp(200, json!({}))).unwrap_err(),
        ShareFlowError::WrongState
    );
}

/// A legacy owner copy (sealed under the folder-name key) and rows that prove it.
fn legacy_fixture(m: &MasterKey, key: &FileKey) -> (String, Value) {
    let copy = wrap_key_for_share(kdf::derive_file_key(m, FOLDER.as_bytes()).as_bytes(), key.as_bytes()).unwrap();
    let wrap = seal_folder_child(
        FolderWrapFormat::LegacyInvite,
        key,
        FOLDER,
        CHILD_FILE,
        false,
        &kdf::derive_file_key(m, CHILD_FILE.as_bytes()),
    )
    .unwrap();
    (
        b64(&copy),
        json!({ "keys": [{ "file_id": CHILD_FILE, "encrypted_file_key": wrap }] }),
    )
}

#[test]
fn flag_off_a_legacy_copy_is_reused_only_with_proof_from_the_approved_invite() {
    let m = master();
    let key = non_utf8_key(5);
    let (copy, rows) = legacy_fixture(&m, &key);
    let invites = json!({ "invites": [
        invite_row("bb01", "approved", "2026-11-01", Some(copy.clone())),
        invite_row("bb02", "invited", "2026-11-02", None),
    ]});
    let (mut flow, _) = FolderShare::invite(input(false, CustodyMemory::default()), &m).unwrap();
    let (_, p, _, _) = sent(flow.on_response(resp(200, invites.clone())).unwrap());
    assert_eq!(p, "/api/v1/shares/invites/bb01/folder-keys");
    let step = flow.on_response(resp(200, rows)).unwrap();
    let (_, body) = answer_listing(&mut flow, step);
    assert_eq!(folder_key_from_id(&body, &[&key]).as_bytes(), key.as_bytes());

    // Rows that do not prove it: refused, never minted.
    let (mut flow, _) = FolderShare::invite(input(false, CustodyMemory::default()), &m).unwrap();
    flow.on_response(resp(200, invites.clone())).unwrap();
    let err = flow.on_response(resp(200, json!({ "keys": [] }))).unwrap_err();
    assert_eq!(err, ShareFlowError::FolderKeyUnverified);

    // "invite not approved" is no proof; any other failure aborts as it is.
    let (mut flow, _) = FolderShare::invite(input(false, CustodyMemory::default()), &m).unwrap();
    flow.on_response(resp(200, invites.clone())).unwrap();
    let err = flow
        .on_response(resp(400, json!({ "error": "Invite not approved" })))
        .unwrap_err();
    assert_eq!(err, ShareFlowError::FolderKeyUnverified);
    let (mut flow, _) = FolderShare::invite(input(false, CustodyMemory::default()), &m).unwrap();
    flow.on_response(resp(200, invites)).unwrap();
    assert_eq!(
        flow.on_response(resp(500, json!({}))).unwrap_err(),
        ShareFlowError::Server { status: 500 }
    );

    // No approved invite: no proof is possible.
    let (mut flow, _) = FolderShare::invite(input(false, CustodyMemory::default()), &m).unwrap();
    let only_invited = json!({ "invites": [invite_row("bb03", "claimed", "2026-11-03", Some(copy))] });
    assert_eq!(
        flow.on_response(resp(200, only_invited)).unwrap_err(),
        ShareFlowError::FolderKeyUnverified
    );
}

#[test]
fn flag_off_a_folder_under_a_custody_folder_refuses_the_legacy_format() {
    let memory = CustodyMemory::new([PARENT.to_uppercase()], false);
    let (mut flow, first) = FolderShare::invite(input(false, memory.clone()), &master()).unwrap();
    let (_, p, _, _) = sent(first);
    assert_eq!(p, format!("/api/v1/files/{FOLDER}"));
    let err = flow.on_response(resp(200, json!({ "parent_id": PARENT }))).unwrap_err();
    assert_eq!(err, ShareFlowError::FolderKeysUnavailable);
    // A 404 parent ends the walk: legacy is allowed.
    let (mut flow, _) = FolderShare::invite(input(false, memory.clone()), &master()).unwrap();
    let (_, p, _, _) = sent(flow.on_response(resp(404, json!({}))).unwrap());
    assert_eq!(p, "/api/v1/shares/invites/sent");
    // The folder itself seen, or an unreadable memory: refused before any request.
    let seen = CustodyMemory::new([FOLDER.to_owned()], false);
    assert_eq!(
        FolderShare::invite(input(false, seen), &master()).unwrap_err(),
        ShareFlowError::FolderKeysUnavailable
    );
    let unreadable = CustodyMemory::new(Vec::<String>::new(), true);
    assert_eq!(
        FolderShare::invite(input(false, unreadable), &master()).unwrap_err(),
        ShareFlowError::FolderKeysUnavailable
    );
}

// ── Flag on: custody folders (L7) ────────────────────────────────────────────

#[test]
fn flag_on_custody_record_gives_l7_wraps_and_marks_the_folder_seen() {
    let m = master();
    let key = non_utf8_key(6);
    let custody = b64(&frame(kdf::wrap_folder_custody(&m, FOLDER.as_bytes(), &key).unwrap()));
    let (mut flow, first) = FolderShare::invite(input(true, CustodyMemory::default()), &m).unwrap();
    let (_, p, _, _) = sent(first);
    assert_eq!(p, format!("/api/v1/shared-folders/{FOLDER}"));
    let step = flow
        .on_response(resp(200, json!({ "owner_wrapped_folder_key": custody })))
        .unwrap();
    let FolderStep::Send(s) = &step else { panic!() };
    assert_eq!(
        s.mark_custody_seen.as_deref(),
        Some(FOLDER),
        "recorded before the key is used"
    );
    let (_, body) = answer_listing(&mut flow, step);
    assert_eq!(body["format"], "l7");
    assert_eq!(
        body["encrypted_owner_folder_key"], custody,
        "the owner copy is the custody record"
    );
    assert_eq!(body["folder_key_id"], folder_key_id_b64(&key));
    let rows = body["folder_keys"].as_array().unwrap();
    assert_eq!(rows.len(), 4, "the root's name key + 3 descendants");
    assert_eq!(rows[0]["file_id"], FOLDER);
    let ru = *uuid::Uuid::parse_str(FOLDER).unwrap().as_bytes();
    for (row, kind) in rows.iter().zip([2u8, 1, 2, 1]) {
        let id = row["file_id"].as_str().unwrap();
        let iu = *uuid::Uuid::parse_str(id).unwrap().as_bytes();
        let blob = split(&b64_decode(row["encrypted_file_key"].as_str().unwrap()).unwrap()).unwrap();
        let child = kdf::unwrap_folder_child(&key, &ru, &iu, kind, &blob).unwrap();
        assert_eq!(child.as_bytes(), kdf::derive_file_key(&m, id.as_bytes()).as_bytes());
    }
    assert!(flow.custody().has_seen(FOLDER));
}

#[test]
fn flag_on_no_record_registers_a_fresh_custody_key() {
    let m = master();
    let (mut flow, _) = FolderShare::invite(input(true, CustodyMemory::default()), &m).unwrap();
    let (_, p, _, _) = sent(flow.on_response(resp(404, json!({}))).unwrap());
    assert_eq!(p, "/api/v1/shares/invites/sent");
    let (method, p, body, _) = sent(flow.on_response(resp(200, json!({ "invites": [] }))).unwrap());
    assert_eq!(
        (method, p.as_str()),
        (Method::Put, format!("/api/v1/shared-folders/{FOLDER}/key").as_str())
    );
    let body = body.unwrap();
    assert_eq!(body["key_version"], 1);
    let wrapped = body["owner_wrapped_folder_key"].as_str().unwrap().to_owned();
    let key =
        kdf::unwrap_folder_custody(&m, FOLDER.as_bytes(), &split(&b64_decode(&wrapped).unwrap()).unwrap()).unwrap();
    let step = flow.on_response(resp(200, json!({ "created": true }))).unwrap();
    let (_, invite) = answer_listing(&mut flow, step);
    assert_eq!(invite["folder_key_id"], folder_key_id_b64(&key));
    assert_eq!(invite["encrypted_owner_folder_key"], wrapped);
}

#[test]
fn flag_on_a_lost_registration_race_uses_the_winners_key() {
    let m = master();
    let theirs = non_utf8_key(7);
    let (mut flow, _) = FolderShare::invite(input(true, CustodyMemory::default()), &m).unwrap();
    flow.on_response(resp(404, json!({}))).unwrap();
    flow.on_response(resp(200, json!({ "invites": [] }))).unwrap();
    let (_, p, _, _) = sent(
        flow.on_response(resp(409, json!({ "code": "key_version_conflict" })))
            .unwrap(),
    );
    assert_eq!(p, format!("/api/v1/shared-folders/{FOLDER}"));
    let custody = b64(&frame(
        kdf::wrap_folder_custody(&m, FOLDER.as_bytes(), &theirs).unwrap(),
    ));
    let step = flow
        .on_response(resp(200, json!({ "owner_wrapped_folder_key": custody })))
        .unwrap();
    let (_, invite) = answer_listing(&mut flow, step);
    assert_eq!(invite["folder_key_id"], folder_key_id_b64(&theirs));
}

#[test]
fn flag_on_refusals_never_mint_or_write() {
    let m = master();
    // Seen with custody before, now "no record": refused (L7c).
    let seen = CustodyMemory::new([FOLDER.to_owned()], false);
    let (mut flow, _) = FolderShare::invite(input(true, seen), &m).unwrap();
    assert_eq!(
        flow.on_response(resp(404, json!({}))).unwrap_err(),
        ShareFlowError::FolderKeysUnavailable
    );
    // Active flag-off invites and no custody: the upgrade is needed; nothing is written.
    let (mut flow, _) = FolderShare::invite(input(true, CustodyMemory::default()), &m).unwrap();
    flow.on_response(resp(404, json!({}))).unwrap();
    let invites = json!({ "invites": [invite_row("cc01", "invited", "2026-11-01", None)] });
    assert_eq!(
        flow.on_response(resp(200, invites)).unwrap_err(),
        ShareFlowError::FolderNeedsUpgrade
    );
    // The server refuses fresh custody for a folder with legacy rows.
    let (mut flow, _) = FolderShare::invite(input(true, CustodyMemory::default()), &m).unwrap();
    flow.on_response(resp(404, json!({}))).unwrap();
    flow.on_response(resp(200, json!({ "invites": [] }))).unwrap();
    assert_eq!(
        flow.on_response(resp(409, json!({ "code": "upgrade_required" })))
            .unwrap_err(),
        ShareFlowError::FolderNeedsUpgrade
    );
    // A custody read that is no answer (500, or 501 on this leg) aborts.
    let (mut flow, _) = FolderShare::invite(input(true, CustodyMemory::default()), &m).unwrap();
    assert_eq!(
        flow.on_response(resp(500, json!({}))).unwrap_err(),
        ShareFlowError::Server { status: 500 }
    );
    // A custody record that does not open aborts; it is never replaced.
    let (mut flow, _) = FolderShare::invite(input(true, CustodyMemory::default()), &m).unwrap();
    let wrong = b64(&frame(
        kdf::wrap_folder_custody(&MasterKey::from_bytes([8; 32]), FOLDER.as_bytes(), &non_utf8_key(1)).unwrap(),
    ));
    assert_eq!(
        flow.on_response(resp(200, json!({ "owner_wrapped_folder_key": wrong })))
            .unwrap_err(),
        ShareFlowError::Crypto
    );
}

#[test]
fn a_full_page_without_a_cursor_is_too_large_to_share() {
    let (mut flow, _) = FolderShare::invite(input(false, CustodyMemory::default()), &master()).unwrap();
    flow.on_response(resp(200, json!({ "invites": [] }))).unwrap();
    let page: Vec<Value> = (0..SHARE_PAGE_LIMIT)
        .map(|i| json!({ "id": format!("2237c000-0000-4000-8000-{i:012x}"), "is_folder": false }))
        .collect();
    assert_eq!(
        flow.on_response(resp(200, json!({ "files": page }))).unwrap_err(),
        ShareFlowError::FolderTooLarge
    );
}

#[test]
fn custody_memory_matches_any_form_of_a_uuid() {
    let mem = CustodyMemory::new([FOLDER.to_owned()], false);
    assert!(mem.has_seen(&FOLDER.to_uppercase()));
    assert!(mem.has_seen(&format!("{{{FOLDER}}}")));
    assert!(mem.has_seen(&format!("urn:uuid:{FOLDER}")));
    assert!(mem.has_seen(&FOLDER.replace('-', "")));
    assert!(mem.has_seen("not-a-uuid"), "an id that is no UUID counts as seen");
    assert!(!mem.has_seen(PARENT));
}

/// B05e: a folder seal to a key other than the compared one stops before sealing.
#[test]
fn a_folder_seal_to_a_key_other_than_the_compared_one_is_refused() {
    let m = master();
    let bob_pub = derive_x25519_public(&crate::opaque::derive_x25519_private(&MasterKey::from_bytes([9; 32])));
    let other_pub = derive_x25519_public(&crate::opaque::derive_x25519_private(&MasterKey::from_bytes([8; 32])));
    let mut i = input(false, CustodyMemory::default());
    i.peer_key = PeerKeyExpectation::Compared(super::safety::key_fingerprint(&bob_pub).unwrap());
    let (mut flow, first) = FolderShare::invite(i, &m).unwrap();
    sent(first);
    let step = flow.on_response(resp(200, json!({ "invites": [] }))).unwrap();
    let (path, _) = answer_listing(&mut flow, step);
    assert_eq!(path, "/api/v1/shares/invites");
    let step = flow
        .on_response(resp(
            200,
            json!({ "invite_id": INVITE, "status": "claimed", "recipient_public_key": b64(&other_pub) }),
        ))
        .unwrap();
    match step {
        FolderStep::Done(InviteOutcome::PeerKeyChanged {
            invite_id,
            recipient_public_key,
        }) => {
            assert_eq!(invite_id, INVITE);
            assert_eq!(recipient_public_key, other_pub);
        }
        other => panic!("a seal request was built: {other:?}"),
    }
}

#[test]
fn an_upper_case_item_id_is_refused_never_used_as_key_input() {
    let m = master();
    let upper = FOLDER.to_ascii_uppercase();
    let input = FolderInviteInput {
        folder_id: &upper,
        email: "bob@beebeeb.test",
        shared_folders_write: false,
        custody: CustodyMemory::default(),
        peer_key: PeerKeyExpectation::NotCompared,
    };
    assert_eq!(
        FolderShare::invite(input, &m).err(),
        Some(ShareFlowError::InvalidInput("folder id")),
        "an upper-case folder id is refused before any request"
    );
    // A child id from the listing is HKDF info too: an upper-case one stops the share.
    let (mut flow, first) = FolderShare::invite(input_for_child_test(), &m).unwrap();
    let _ = sent(first);
    let step = flow.on_response(resp(200, json!({ "invites": [] }))).unwrap();
    let _ = sent(step);
    let upper_child = CHILD_FILE.to_ascii_uppercase();
    assert_eq!(
        flow.on_response(resp(
            200,
            json!({ "files": [{ "id": upper_child, "is_folder": false }] })
        ))
        .err(),
        Some(ShareFlowError::InvalidInput("child id"))
    );
}

fn input_for_child_test() -> FolderInviteInput<'static> {
    input(false, CustodyMemory::default())
}
