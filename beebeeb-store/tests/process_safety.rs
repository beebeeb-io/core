#![cfg(feature = "test-support")]

use beebeeb_store::Store;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

#[test]
fn separate_process_writers_finish_without_corruption_or_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("shared.sqlite");
    let helper = env!("CARGO_BIN_EXE_store-test-helper");
    let mut first = Command::new(helper)
        .args(["write", db.to_str().unwrap(), "a", "100"])
        .spawn()
        .unwrap();
    let mut second = Command::new(helper)
        .args(["write", db.to_str().unwrap(), "b", "100"])
        .spawn()
        .unwrap();
    assert!(first.wait().unwrap().success());
    assert!(second.wait().unwrap().success());
    let store = Store::open(&db).unwrap();
    assert_eq!(store.op_count().unwrap(), 200);
    store.integrity_check().unwrap();
}

#[test]
fn killed_process_cannot_publish_half_a_write() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("killed.sqlite");
    let helper = env!("CARGO_BIN_EXE_store-test-helper");
    let mut child = Command::new(helper)
        .args(["hold-write", db.to_str().unwrap()])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "READY");
    child.kill().unwrap();
    child.wait().unwrap();
    let store = Store::open(&db).unwrap();
    assert_eq!(store.op_count().unwrap(), 0);
    store.integrity_check().unwrap();
}
