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
