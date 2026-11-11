//! Name clashes that arrive through the sync engine (1022 G5, "Auto-name, no
//! question"): a rename is checked in the item's own folder, a move in its
//! destination, and a snapshot names clashing siblings the same whatever
//! order the server lists them in. The second item takes core's
//! `drive_conflict_name`.

use std::sync::Arc;

use beebeeb_core::{
    chunk_stream::ExpectedChunkFormat,
    encrypt::encrypt_name_for_new_item,
    item_id::NewItemId,
    kdf::MasterKey,
    sync::{CompleteSnapshot, SyncEngine, SyncPosition, TreeNode},
};
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{Client, ClientConfig, Session, test_support::ScriptedTransport};

const KEY: [u8; 32] = [41; 32];
/// Core's conflict name when the writing device is not known by name.
const CONFLICT: &str = "a (conflict, device).txt";

struct Item {
    id: Uuid,
    item: NewItemId,
}

fn new_item(master: &MasterKey) -> Item {
    let item = NewItemId::owner(master).unwrap();
    Item {
        id: Uuid::parse_str(item.as_str()).unwrap(),
        item,
    }
}

fn sealed(master: &MasterKey, item: &Item, name: &str) -> String {
    encrypt_name_for_new_item(master, &item.item, name, None, ExpectedChunkFormat::V2).unwrap()
}

fn node(master: &MasterKey, item: &Item, parent: Option<Uuid>, real: &str, local: &str, is_folder: bool) -> TreeNode {
    TreeNode {
        id: item.id,
        name: local.into(),
        name_undecryptable: false,
        name_encrypted: sealed(master, item, real),
        parent_id: parent,
        is_folder,
        size_bytes: 0,
        mime_type: None,
        content_hash: None,
        version_number: 1,
        has_thumbnail: false,
        storage_pool_id: None,
        is_trashed: false,
        is_starred: false,
        updated_at: Utc::now(),
    }
}

fn engine_with(nodes: Vec<TreeNode>) -> SyncEngine {
    let mut engine = SyncEngine::new("device-1".into());
    engine
        .apply_complete_snapshot(CompleteSnapshot::new(nodes, SyncPosition::new(1, 1)).unwrap())
        .unwrap();
    engine
}

fn client(answer: Value) -> Client {
    let client = Client::new(
        ClientConfig::for_tests(),
        Arc::new(ScriptedTransport::json(200, serde_json::to_vec(&answer).unwrap())),
    )
    .unwrap();
    client.set_authentication("token", "user-1").unwrap();
    client
}

fn session() -> Session {
    Session::from_parts_for_test("https://api.example", "token", "user-1", KEY, 1).unwrap()
}

/// Apply one remote op (seq 2) through catch-up.
async fn apply(engine: &mut SyncEngine, op_type: &str, payload: Value) {
    let answer = json!({"ops": [{"seq_id": 2, "user_seq": 2, "op_type": op_type, "payload": payload}]});
    client(answer).catch_up_sync(&session(), engine, 100).await.unwrap();
}

fn name(engine: &SyncEngine, item: &Item) -> String {
    engine.get_node(item.id).unwrap().name.clone()
}

#[tokio::test]
async fn a_rename_is_checked_in_the_items_own_folder() {
    let master = MasterKey::from_bytes(KEY);
    let (docs, x, a) = (new_item(&master), new_item(&master), new_item(&master));
    let mut engine = engine_with(vec![
        node(&master, &docs, None, "Docs", "Docs", true),
        node(&master, &x, Some(docs.id), "x.txt", "x.txt", false),
        node(&master, &a, Some(docs.id), "a.txt", "a.txt", false),
    ]);

    // The server's rename op carries no parent id.
    let renamed = sealed(&master, &x, "a.txt");
    apply(
        &mut engine,
        "file_rename",
        json!({"id": x.id.to_string(), "new_name_encrypted": renamed}),
    )
    .await;

    assert_eq!(name(&engine, &a), "a.txt");
    assert_eq!(name(&engine, &x), CONFLICT);
}

#[tokio::test]
async fn a_rename_to_a_name_only_another_folder_holds_keeps_its_name() {
    let master = MasterKey::from_bytes(KEY);
    let (docs, x, a) = (new_item(&master), new_item(&master), new_item(&master));
    let mut engine = engine_with(vec![
        node(&master, &docs, None, "Docs", "Docs", true),
        node(&master, &x, Some(docs.id), "x.txt", "x.txt", false),
        node(&master, &a, None, "a.txt", "a.txt", false),
    ]);

    let renamed = sealed(&master, &x, "a.txt");
    apply(
        &mut engine,
        "file_rename",
        json!({"id": x.id.to_string(), "new_name_encrypted": renamed}),
    )
    .await;

    assert_eq!(name(&engine, &x), "a.txt");
}

#[tokio::test]
async fn a_move_into_a_folder_holding_its_name_takes_a_conflict_name() {
    let master = MasterKey::from_bytes(KEY);
    let (docs, kept, moved) = (new_item(&master), new_item(&master), new_item(&master));
    let mut engine = engine_with(vec![
        node(&master, &docs, None, "Docs", "Docs", true),
        node(&master, &kept, Some(docs.id), "a.txt", "a.txt", false),
        node(&master, &moved, None, "a.txt", "a.txt", false),
    ]);

    // The server's move op carries no name at all.
    apply(
        &mut engine,
        "file_move",
        json!({"id": moved.id.to_string(), "old_parent_id": null, "new_parent_id": docs.id.to_string()}),
    )
    .await;

    let node = engine.get_node(moved.id).unwrap();
    assert_eq!(node.parent_id, Some(docs.id));
    assert_eq!(node.name, CONFLICT);
    assert_eq!(name(&engine, &kept), "a.txt");
}

#[tokio::test]
async fn a_move_out_of_a_clash_takes_its_own_name_back() {
    let master = MasterKey::from_bytes(KEY);
    let (docs, kept, moved) = (new_item(&master), new_item(&master), new_item(&master));
    let mut engine = engine_with(vec![
        node(&master, &docs, None, "Docs", "Docs", true),
        node(&master, &kept, Some(docs.id), "a.txt", "a.txt", false),
        node(&master, &moved, Some(docs.id), "a.txt", CONFLICT, false),
    ]);

    apply(
        &mut engine,
        "file_move",
        json!({"id": moved.id.to_string(), "new_parent_id": null}),
    )
    .await;

    let node = engine.get_node(moved.id).unwrap();
    assert_eq!(node.parent_id, None);
    assert_eq!(node.name, "a.txt");
}

#[tokio::test]
async fn a_create_with_a_taken_name_takes_a_conflict_name_from_its_own_name() {
    let master = MasterKey::from_bytes(KEY);
    let (kept, created) = (new_item(&master), new_item(&master));
    let mut engine = engine_with(vec![node(&master, &kept, None, "A.TXT", "A.TXT", false)]);

    let sealed_name = sealed(&master, &created, "a.txt");
    apply(
        &mut engine,
        "file_create",
        json!({"id": created.id.to_string(), "parent_id": null, "name_encrypted": sealed_name}),
    )
    .await;

    // The normal forms clash; the new name comes from the incoming name only.
    assert_eq!(name(&engine, &created), CONFLICT);
    assert_eq!(name(&engine, &kept), "A.TXT");
}

fn snapshot_answer(master: &MasterKey, items: &[(&Item, &str)]) -> Value {
    let nodes: Vec<Value> = items
        .iter()
        .map(|(item, real)| json!({"id": item.id.to_string(), "parent_id": null, "name_encrypted": sealed(master, item, real)}))
        .collect();
    json!({"nodes": nodes, "seq_id": 5, "user_seq": 5, "complete": true})
}

async fn refresh(engine: &mut SyncEngine, answer: Value) {
    client(answer).refresh_sync_snapshot(&session(), engine).await.unwrap();
}

#[tokio::test]
async fn snapshot_names_do_not_depend_on_the_servers_order() {
    let master = MasterKey::from_bytes(KEY);
    let (mut first, mut second) = (new_item(&master), new_item(&master));
    if second.id < first.id {
        std::mem::swap(&mut first, &mut second);
    }
    for order in [[&first, &second], [&second, &first]] {
        let mut engine = SyncEngine::new("device-1".into());
        refresh(
            &mut engine,
            snapshot_answer(&master, &[(order[0], "a.txt"), (order[1], "a.txt")]),
        )
        .await;

        assert_eq!(name(&engine, &first), "a.txt", "smallest id keeps the name");
        assert_eq!(name(&engine, &second), CONFLICT);
    }
}

#[tokio::test]
async fn a_snapshot_leaves_the_name_with_the_sibling_that_holds_it() {
    let master = MasterKey::from_bytes(KEY);
    let (mut first, mut second) = (new_item(&master), new_item(&master));
    if second.id < first.id {
        std::mem::swap(&mut first, &mut second);
    }
    // The larger id already holds the name (it was there first); the smaller
    // one arrived second and took the conflict name.
    let mut engine = engine_with(vec![
        node(&master, &second, None, "a.txt", "a.txt", false),
        node(&master, &first, None, "a.txt", CONFLICT, false),
    ]);

    refresh(
        &mut engine,
        snapshot_answer(&master, &[(&first, "a.txt"), (&second, "a.txt")]),
    )
    .await;

    assert_eq!(name(&engine, &second), "a.txt");
    assert_eq!(name(&engine, &first), CONFLICT);
}

#[tokio::test]
async fn a_conflict_name_never_takes_another_siblings_real_name() {
    let master = MasterKey::from_bytes(KEY);
    let mut items = [new_item(&master), new_item(&master), new_item(&master)];
    items.sort_by_key(|item| item.id);
    let [one, two, real] = items;
    let mut engine = SyncEngine::new("device-1".into());

    refresh(
        &mut engine,
        snapshot_answer(&master, &[(&real, CONFLICT), (&two, "a.txt"), (&one, "a.txt")]),
    )
    .await;

    assert_eq!(name(&engine, &one), "a.txt");
    assert_eq!(name(&engine, &real), CONFLICT, "a real name is kept");
    assert_eq!(name(&engine, &two), "a (conflict, device) (2).txt");
}

// ── Only core's decryption names an item (review r4, finding 10) ────────────

/// Apply remote ops `ops` (seq 2, 3, ...) through catch-up.
async fn apply_all(engine: &mut SyncEngine, ops: Vec<(&str, Value)>) -> Result<(), crate::sync::SyncLoopError> {
    let ops: Vec<Value> = ops
        .into_iter()
        .enumerate()
        .map(|(index, (op_type, payload))| {
            let seq = 2 + index as i64;
            json!({"seq_id": seq, "user_seq": seq, "op_type": op_type, "payload": payload})
        })
        .collect();
    client(json!({ "ops": ops }))
        .catch_up_sync(&session(), engine, 100)
        .await
}

#[tokio::test]
async fn a_plaintext_server_name_without_a_sealed_name_names_nothing_and_sync_goes_on() {
    let master = MasterKey::from_bytes(KEY);
    let (x, created, after) = (new_item(&master), new_item(&master), new_item(&master));
    let mut engine = engine_with(vec![node(&master, &x, None, "x.txt", "x.txt", false)]);
    let after_name = sealed(&master, &after, "after.txt");

    apply_all(
        &mut engine,
        vec![
            ("file_rename", json!({"id": x.id.to_string(), "new_name": "../x"})),
            (
                "file_create",
                json!({"id": created.id.to_string(), "parent_id": null, "name": "chosen.txt"}),
            ),
            (
                "file_create",
                json!({"id": after.id.to_string(), "parent_id": null, "name_encrypted": after_name}),
            ),
        ],
    )
    .await
    .unwrap();

    assert_eq!(name(&engine, &x), "x.txt", "no sealed name: the rename names nothing");
    let created_node = engine.get_node(created.id).unwrap();
    assert!(created_node.name_undecryptable);
    assert_eq!(created_node.name, "");
    assert_eq!(name(&engine, &after), "after.txt", "the loop went on");
}

#[tokio::test]
async fn a_plaintext_server_name_never_outranks_a_sealed_name_that_does_not_open() {
    let master = MasterKey::from_bytes(KEY);
    let other = MasterKey::from_bytes([42; 32]);
    let y = new_item(&master);
    let mut engine = engine_with(vec![node(&master, &y, None, "y.txt", "y.txt", false)]);
    let not_ours = sealed(&other, &y, "sealed elsewhere.txt");

    apply_all(
        &mut engine,
        vec![(
            "file_rename",
            json!({"id": y.id.to_string(), "new_name": "chosen.txt", "new_name_undecryptable": false,
                   "new_name_encrypted": not_ours}),
        )],
    )
    .await
    .unwrap();

    let node = engine.get_node(y.id).unwrap();
    assert!(node.name_undecryptable, "the server's plaintext is never shown");
    assert_eq!(node.name, "");
}

#[tokio::test]
async fn a_sealed_name_the_path_rule_refuses_is_shown_undecryptable_and_sync_goes_on() {
    let master = MasterKey::from_bytes(KEY);
    let (unsafe_item, after) = (new_item(&master), new_item(&master));
    let mut engine = engine_with(Vec::new());
    let unsafe_name = sealed(&master, &unsafe_item, "../escape");
    let after_name = sealed(&master, &after, "after.txt");

    apply_all(
        &mut engine,
        vec![
            (
                "file_create",
                json!({"id": unsafe_item.id.to_string(), "parent_id": null, "name_encrypted": unsafe_name}),
            ),
            (
                "file_create",
                json!({"id": after.id.to_string(), "parent_id": null, "name_encrypted": after_name}),
            ),
        ],
    )
    .await
    .unwrap();

    let node = engine.get_node(unsafe_item.id).unwrap();
    assert!(node.name_undecryptable);
    assert_eq!(node.name, "");
    assert_eq!(name(&engine, &after), "after.txt");
}

#[tokio::test]
async fn a_snapshot_name_the_path_rule_refuses_is_shown_undecryptable() {
    let master = MasterKey::from_bytes(KEY);
    let (unsafe_item, fine) = (new_item(&master), new_item(&master));
    let mut engine = SyncEngine::new("device-1".into());

    refresh(
        &mut engine,
        snapshot_answer(&master, &[(&unsafe_item, "../escape"), (&fine, "fine.txt")]),
    )
    .await;

    let node = engine.get_node(unsafe_item.id).unwrap();
    assert!(node.name_undecryptable);
    assert_eq!(node.name, "");
    assert_eq!(name(&engine, &fine), "fine.txt");
}

// ── A restore is checked in the item's folder (review r5, P2-3) ─────────────

/// `/Docs/a.txt` is in the Trash, and a trashed item holds no name, so a
/// rename makes `/Docs/x.txt` into `a.txt`. Restoring the first `a.txt` must
/// not leave two of them in `/Docs`.
fn restore_after_a_rename(master: &MasterKey) -> (Vec<TreeNode>, Vec<(&'static str, Value)>, Item, Item) {
    let (docs, x, a) = (new_item(master), new_item(master), new_item(master));
    let mut trashed = node(master, &a, Some(docs.id), "a.txt", "a.txt", false);
    trashed.is_trashed = true;
    let nodes = vec![
        node(master, &docs, None, "Docs", "Docs", true),
        node(master, &x, Some(docs.id), "x.txt", "x.txt", false),
        trashed,
    ];
    let ops = vec![
        (
            "file_rename",
            json!({"id": x.id.to_string(), "new_name_encrypted": sealed(master, &x, "a.txt")}),
        ),
        ("file_restore", json!({"id": a.id.to_string()})),
    ];
    (nodes, ops, x, a)
}

#[tokio::test]
async fn a_restore_never_leaves_two_equal_names_in_one_folder() {
    let master = MasterKey::from_bytes(KEY);
    let (nodes, ops, x, a) = restore_after_a_rename(&master);
    let mut engine = engine_with(nodes);

    apply_all(&mut engine, ops).await.unwrap();

    assert_eq!(name(&engine, &x), "a.txt", "the trashed item held no name");
    assert_eq!(name(&engine, &a), CONFLICT);
    assert!(!engine.get_node(a.id).unwrap().is_trashed);
}

/// The same on the store-backed engine the File Provider uses.
#[tokio::test]
async fn a_restore_on_the_store_backed_engine_never_leaves_two_equal_names() {
    let master = MasterKey::from_bytes(KEY);
    let (nodes, ops, x, a) = restore_after_a_rename(&master);
    let mut engine =
        SyncEngine::with_store_backed("device-1".into(), beebeeb_store::Store::open_in_memory().unwrap()).unwrap();
    engine
        .apply_complete_snapshot(CompleteSnapshot::new(nodes, SyncPosition::new(1, 1)).unwrap())
        .unwrap();

    apply_all(&mut engine, ops).await.unwrap();

    let stored = |item: &Item| engine.lookup_node(item.id).unwrap().unwrap();
    assert_eq!(stored(&x).name, "a.txt");
    assert_eq!(stored(&a).name, CONFLICT);
    assert!(!stored(&a).is_trashed);
}

// ── The writing device's name (task 2388, Guus 2026-11-08 07:05) ────────────

const WORK_LAPTOP: &str = "d0000000-0000-4000-8000-000000000001";
const ODD_NAME: &str = "d0000000-0000-4000-8000-000000000002";

fn device(id: &str, reported_name: &str, hostname_encrypted: Option<String>) -> Value {
    json!({"id": id, "hostname": "", "platform": "macos", "last_seen": "2026-11-08T06:00:00Z",
           "created_at": "2026-11-01T06:00:00Z", "reported_name": reported_name,
           "hostname_encrypted": hostname_encrypted})
}

/// One catch-up pass: remote renames (seq 2, 3, ...), each written by the
/// device `writer`, then the device list `devices` if a clash asks for it.
/// Returns the transport, to count what was asked.
async fn renames_written_by(
    engine: &mut SyncEngine,
    renames: Vec<(Value, Option<&str>)>,
    devices: Value,
) -> ScriptedTransport {
    let ops: Vec<Value> = renames
        .into_iter()
        .enumerate()
        .map(|(index, (payload, writer))| {
            let seq = 2 + index as i64;
            json!({"seq_id": seq, "user_seq": seq, "op_type": "file_rename", "payload": payload, "device_id": writer})
        })
        .collect();
    let transport = ScriptedTransport::json(200, serde_json::to_vec(&json!({ "ops": ops })).unwrap());
    transport.push_json(200, serde_json::to_vec(&json!({ "devices": devices })).unwrap());
    let client = Client::new(ClientConfig::for_tests(), Arc::new(transport.clone())).unwrap();
    client.set_authentication("token", "user-1").unwrap();
    client.catch_up_sync(&session(), engine, 100).await.unwrap();
    transport
}

fn device_list_reads(transport: &ScriptedTransport) -> usize {
    transport
        .requests()
        .iter()
        .filter(|request| request.path() == "/api/v1/clients/devices")
        .count()
}

#[tokio::test]
async fn a_clash_names_the_device_that_wrote_it() {
    let master = MasterKey::from_bytes(KEY);
    let (x, a) = (new_item(&master), new_item(&master));
    let mut engine = engine_with(vec![
        node(&master, &x, None, "x.txt", "x.txt", false),
        node(&master, &a, None, "a.txt", "a.txt", false),
    ]);

    let transport = renames_written_by(
        &mut engine,
        vec![(
            json!({"id": x.id.to_string(), "new_name_encrypted": sealed(&master, &x, "a.txt")}),
            Some(WORK_LAPTOP),
        )],
        json!([device(WORK_LAPTOP, "Work laptop", None)]),
    )
    .await;

    assert_eq!(name(&engine, &x), "a (conflict, Work laptop).txt");
    assert_eq!(name(&engine, &a), "a.txt");
    assert_eq!(device_list_reads(&transport), 1);
}

/// The name the device sealed under the account's key wins over the one it
/// reported in plain text.
#[tokio::test]
async fn a_sealed_device_name_wins_over_the_reported_one() {
    let master = MasterKey::from_bytes(KEY);
    let (x, a) = (new_item(&master), new_item(&master));
    let mut engine = engine_with(vec![
        node(&master, &x, None, "x.txt", "x.txt", false),
        node(&master, &a, None, "a.txt", "a.txt", false),
    ]);
    let hostname = beebeeb_core::client_meta::seal_client_meta(
        &master,
        &Uuid::parse_str(WORK_LAPTOP).unwrap(),
        None,
        beebeeb_core::client_meta::ClientMetaField::DeviceHostname,
        "Studio Mac",
    )
    .unwrap();

    renames_written_by(
        &mut engine,
        vec![(
            json!({"id": x.id.to_string(), "new_name_encrypted": sealed(&master, &x, "a.txt")}),
            Some(WORK_LAPTOP),
        )],
        json!([device(WORK_LAPTOP, "Reported", Some(hostname))]),
    )
    .await;

    assert_eq!(name(&engine, &x), "a (conflict, Studio Mac).txt");
}

/// An unknown writer, or a name the path rule refuses, keeps core's
/// `device`; the list is read once for the whole pass, never per op.
#[tokio::test]
async fn an_unknown_or_unsafe_writer_keeps_device_and_the_list_is_read_once() {
    let master = MasterKey::from_bytes(KEY);
    let (x, a, y, b) = (
        new_item(&master),
        new_item(&master),
        new_item(&master),
        new_item(&master),
    );
    let mut engine = engine_with(vec![
        node(&master, &x, None, "x.txt", "x.txt", false),
        node(&master, &a, None, "a.txt", "a.txt", false),
        node(&master, &y, None, "y.txt", "y.txt", false),
        node(&master, &b, None, "b.txt", "b.txt", false),
    ]);

    let transport = renames_written_by(
        &mut engine,
        vec![
            (
                json!({"id": x.id.to_string(), "new_name_encrypted": sealed(&master, &x, "a.txt")}),
                Some("d0000000-0000-4000-8000-0000000000ff"),
            ),
            (
                json!({"id": y.id.to_string(), "new_name_encrypted": sealed(&master, &y, "b.txt")}),
                Some(ODD_NAME),
            ),
        ],
        json!([device(ODD_NAME, "..", None)]),
    )
    .await;

    assert_eq!(name(&engine, &x), CONFLICT);
    assert_eq!(name(&engine, &y), "b (conflict, device).txt");
    assert_eq!(device_list_reads(&transport), 1);
}
