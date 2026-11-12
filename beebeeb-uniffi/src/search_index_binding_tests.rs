//! `SearchIndexHandle` and `search_index_sync_plan` through the binding (moved out of `lib.rs`).

use super::*;

fn test_master_key() -> Arc<MasterKeyHandle> {
    MasterKeyHandle::from_keychain_bytes(vec![7u8; 32]).unwrap()
}

#[test]
fn round_trip_through_binding_finds_nested_term() {
    let mk = test_master_key();
    let files = vec![
        SearchFileEntry {
            file_id: "top".into(),
            name: "readme.txt".into(),
        },
        SearchFileEntry {
            file_id: "deep".into(),
            name: "buried_treasure_xyzzy.txt".into(),
        },
    ];
    let idx = SearchIndexHandle::build(files, search_index::DEFAULT_NUM_SHARDS);

    let shards = idx.encrypt_shards(&mk).unwrap();
    assert!(!shards.is_empty());
    let restored = SearchIndexHandle::from_encrypted_shards(&mk, shards, idx.num_shards().unwrap()).unwrap();

    assert_eq!(restored.query("xyzzy".into()).unwrap(), vec!["deep".to_string()]);
    assert_eq!(restored.file_count().unwrap(), 2);

    // Incremental: dirty buckets drive a partial re-encrypt.
    let dirty = restored.upsert("new".into(), "another_file.pdf".into()).unwrap();
    assert!(!dirty.is_empty());
    assert!(!restored.encrypt_buckets(&mk, dirty).unwrap().is_empty());
    assert_eq!(restored.query("another".into()).unwrap(), vec!["new".to_string()]);
}

#[test]
fn wrong_master_key_fails_decrypt_through_binding() {
    let mk = test_master_key();
    let idx = SearchIndexHandle::build(
        vec![SearchFileEntry {
            file_id: "a".into(),
            name: "secret.txt".into(),
        }],
        search_index::DEFAULT_NUM_SHARDS,
    );
    let shards = idx.encrypt_shards(&mk).unwrap();
    let wrong = MasterKeyHandle::from_keychain_bytes(vec![9u8; 32]).unwrap();
    assert!(SearchIndexHandle::from_encrypted_shards(&wrong, shards, idx.num_shards().unwrap()).is_err());
}

#[test]
fn sync_plan_through_binding() {
    let local = vec![ShardRefDto {
        bucket: 1,
        page: 0,
        version: 2,
    }];
    let remote = vec![ShardRefDto {
        bucket: 3,
        page: 0,
        version: 1,
    }];
    let plan = search_index_sync_plan(local, remote, true);
    assert_eq!(plan.to_put.len(), 1);
    assert_eq!(plan.to_put[0].bucket, 1);
    assert_eq!(plan.to_delete.len(), 1);
    assert_eq!(plan.to_delete[0].bucket, 3);
    assert!(plan.to_get.is_empty());
}

/// An index whose lock was poisoned the way a panic during another call
/// poisons it: the guard is held while the thread unwinds.
fn poisoned_index() -> Arc<SearchIndexHandle> {
    let idx = SearchIndexHandle::build(
        vec![SearchFileEntry {
            file_id: "a".into(),
            name: "secret.txt".into(),
        }],
        search_index::DEFAULT_NUM_SHARDS,
    );
    let clone = Arc::clone(&idx);
    let panicked = std::thread::spawn(move || {
        let _guard = clone.inner.lock();
        panic!("a panic while the index is locked");
    })
    .join();
    assert!(panicked.is_err());
    assert!(idx.inner.is_poisoned());
    idx
}

/// One binding call on the index, named for the failure message.
type IndexCall<'a> = (&'static str, Box<dyn Fn() -> Result<(), CryptoError> + 'a>);

#[test]
fn a_poisoned_index_answers_with_an_error_never_a_panic_across_ffi() {
    let idx = poisoned_index();
    let mk = test_master_key();
    let calls: Vec<IndexCall> = vec![
        ("num_shards", Box::new(|| idx.num_shards().map(drop))),
        ("file_count", Box::new(|| idx.file_count().map(drop))),
        (
            "upsert",
            Box::new(|| idx.upsert("b".into(), "other.txt".into()).map(drop)),
        ),
        ("remove", Box::new(|| idx.remove("a".into()).map(drop))),
        ("query", Box::new(|| idx.query("secret".into()).map(drop))),
        ("encrypt_shards", Box::new(|| idx.encrypt_shards(&mk).map(drop))),
        (
            "encrypt_buckets",
            Box::new(|| idx.encrypt_buckets(&mk, vec![0]).map(drop)),
        ),
    ];
    let mut panicked = Vec::new();
    for (name, call) in &calls {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(call)) {
            Ok(answer) => assert!(
                matches!(answer, Err(CryptoError::InvalidInput { .. })),
                "{name} on a poisoned index answered {answer:?}, not InvalidInput"
            ),
            Err(_) => panicked.push(*name),
        }
    }
    assert!(
        panicked.is_empty(),
        "{} of {} calls panicked across FFI: {panicked:?}",
        panicked.len(),
        calls.len()
    );
    let left = idx.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(left.file_count(), 0, "the decrypted names were dropped");
}
