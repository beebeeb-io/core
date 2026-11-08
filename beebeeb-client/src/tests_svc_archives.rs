//! The native archive service against an in-process file server: range reads
//! (v1 and v2), extraction of the plain fixtures (every landed file decrypted
//! and its SHA-256 compared with the fixture's content), passwords, stop,
//! storage full, Backups, a version change and the temp root.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use beebeeb_api::{Answer, Header, Method};
use beebeeb_core::archives::{
    ArchivePassword, ArchivePlatform, ExtractOutcome, ExtractSummary, FailReason, PlanRefusal, PreviewState, Selection,
    SkipReason,
};
use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkEncryptor, ExpectedChunkFormat};
use beebeeb_core::encrypt::{decrypt_file_metadata, decrypt_name_metadata, encrypt_chunk, encrypt_name_with_version};
use beebeeb_core::kdf::{MasterKey, derive_file_key};
use beebeeb_store::{Store, TransferState};
use beebeeb_types::limits::MemoryBudget;
use tempfile::{TempDir, tempdir};
use tokio::sync::broadcast;

use crate::archives::{
    ArchiveEvent, ArchiveId, ArchiveService, ArchiveServiceError, ExtractDestination, ExtractOptions, ExtractionId,
};
use crate::downloads::{DownloadFile, DownloadService, DownloadServiceError};
use crate::uploads::{NetworkKind, UploadService, UploadServiceError, transfer_now_ms};
use crate::{Client, ClientConfig, TransportError, TransportFuture};

const KEY: [u8; 32] = [0x42; 32];
const PASSWORD: &str = "beebeeb-test-password";

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test-vectors/archives")
        .join(name);
    std::fs::read(path).unwrap()
}

// ── The in-process file server ─────────────────────────────────────────────

#[derive(Clone, Default)]
struct Row {
    parent_id: Option<String>,
    name_encrypted: String,
    is_folder: bool,
    size: u64,
    version: String,
    system_role: Option<&'static str>,
    chunks: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Pending {
    file_id: String,
    parent_id: Option<String>,
    size: u64,
    chunks: BTreeMap<u32, Vec<u8>>,
}

#[derive(Default)]
struct State {
    rows: BTreeMap<String, Row>,
    sessions: HashMap<String, Pending>,
    used: i64,
    limit: i64,
    chunk_gets: Vec<(String, u32)>,
    /// The archive gets a new version on the next chunk read.
    bump_on_chunk_get: Option<String>,
    /// Uploads that may still start before the account is full.
    uploads_left: Option<usize>,
    /// Folder creates answered `409 name_conflict` before one succeeds.
    folder_conflicts: usize,
}

#[derive(Clone, Default)]
struct Server {
    state: Arc<Mutex<State>>,
}

fn json(status: u16, value: serde_json::Value) -> Answer {
    Answer::new(
        status,
        vec![Header::new("Content-Type", "application/json")],
        serde_json::to_vec(&value).unwrap(),
    )
}

impl Server {
    fn new() -> Self {
        let server = Self::default();
        server.state.lock().unwrap().limit = 1 << 40;
        server
    }

    fn insert(&self, id: &str, row: Row) {
        self.state.lock().unwrap().rows.insert(id.into(), row);
    }

    fn row_json(id: &str, row: &Row) -> serde_json::Value {
        let mut value = serde_json::json!({
            "id": id, "parent_id": row.parent_id, "name_encrypted": row.name_encrypted,
            "is_folder": row.is_folder, "size_bytes": row.size,
        });
        if let Some(role) = row.system_role {
            value["system_role"] = role.into();
        }
        if !row.is_folder {
            value["download_version"] = serde_json::json!({"object_version_id": row.version});
        }
        value
    }

    fn answer(&self, method: Method, path: &str, body: &[u8]) -> Answer {
        let mut state = self.state.lock().unwrap();
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let parts: Vec<&str> = route.trim_start_matches("/api/v1/").split('/').collect();
        match (method, parts.as_slice()) {
            (Method::Get, ["files", "usage"]) => json(
                200,
                serde_json::json!({"used_bytes": state.used, "plan_limit_bytes": state.limit, "plan_name": "test"}),
            ),
            (Method::Get, ["files"]) => {
                let parent = query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("parent_id="))
                    .map(str::to_owned);
                let files: Vec<_> = state
                    .rows
                    .iter()
                    .filter(|(_, row)| row.parent_id == parent)
                    .map(|(id, row)| Self::row_json(id, row))
                    .collect();
                json(200, serde_json::json!({"files": files, "next_cursor": null}))
            }
            (Method::Get, ["files", id, "chunks", index]) => {
                let index: u32 = index.parse().unwrap();
                state.chunk_gets.push(((*id).to_owned(), index));
                if state.bump_on_chunk_get.as_deref() == Some(*id) {
                    state.bump_on_chunk_get = None;
                    state.rows.get_mut(*id).unwrap().version = "a-new-version".into();
                }
                let frame = state.rows[*id].chunks[index as usize].clone();
                Answer::new(
                    200,
                    vec![Header::new("Content-Type", "application/octet-stream")],
                    frame,
                )
            }
            (Method::Get, ["files", id]) => match state.rows.get(*id) {
                Some(row) => json(200, Self::row_json(id, row)),
                None => json(404, serde_json::json!({"error": "not_found"})),
            },
            (Method::Post, ["files", "folder"]) => {
                if state.folder_conflicts > 0 {
                    state.folder_conflicts -= 1;
                    return json(409, serde_json::json!({"error": "name_conflict"}));
                }
                let request: serde_json::Value = serde_json::from_slice(body).unwrap();
                let id = request["folder_id"].as_str().unwrap().to_owned();
                let row = Row {
                    parent_id: request["parent_id"].as_str().map(str::to_owned),
                    name_encrypted: request["name_encrypted"].as_str().unwrap().to_owned(),
                    is_folder: true,
                    ..Row::default()
                };
                let answer = Self::row_json(&id, &row);
                state.rows.insert(id, row);
                json(200, answer)
            }
            (Method::Post, ["uploads", "init"]) => {
                if let Some(left) = state.uploads_left.as_mut() {
                    if *left == 0 {
                        return json(507, serde_json::json!({"error": "quota_exceeded"}));
                    }
                    *left -= 1;
                }
                let request: serde_json::Value = serde_json::from_slice(body).unwrap();
                let file_id = request["file_id"].as_str().unwrap().to_owned();
                let size = request["file_size_bytes"].as_u64().unwrap();
                let session = format!("session-{}", state.sessions.len());
                state.sessions.insert(
                    session.clone(),
                    Pending {
                        file_id: file_id.clone(),
                        parent_id: request["parent_id"].as_str().map(str::to_owned),
                        size,
                        chunks: BTreeMap::new(),
                    },
                );
                let count = size.div_ceil(UPLOAD_STRIDE).max(1);
                json(
                    200,
                    serde_json::json!({"upload_session_id": session, "file_id": file_id,
                        "chunk_size_bytes": UPLOAD_STRIDE, "chunk_count": count}),
                )
            }
            (Method::Post, ["uploads", session, "token"]) => json(
                200,
                serde_json::json!({"token": "scoped", "upload_session_id": session,
                    "expires_at": "2099-01-01T00:00:00Z"}),
            ),
            (Method::Post, ["uploads", session, "complete"]) => {
                let request: serde_json::Value = serde_json::from_slice(body).unwrap();
                let pending = state.sessions.remove(*session).unwrap();
                let row = Row {
                    parent_id: pending.parent_id,
                    name_encrypted: request["name_encrypted"].as_str().unwrap().to_owned(),
                    size: pending.size,
                    version: format!("{session}-version"),
                    chunks: pending.chunks.into_values().collect(),
                    ..Row::default()
                };
                state.used += row.size as i64;
                state.rows.insert(pending.file_id, row);
                json(200, serde_json::json!({}))
            }
            _ => panic!("unexpected request {method:?} {route}"),
        }
    }

    /// The platform's chunk PUT.
    fn put_chunk(&self, url: &str, body: Vec<u8>) {
        let rest = url.split("/api/v1/uploads/").nth(1).unwrap();
        let (session, index) = rest.split_once("/chunks/").unwrap();
        let index: u32 = index.parse().unwrap();
        let mut state = self.state.lock().unwrap();
        state.sessions.get_mut(session).unwrap().chunks.insert(index, body);
    }

    fn chunk_gets(&self) -> Vec<(String, u32)> {
        self.state.lock().unwrap().chunk_gets.clone()
    }

    fn row_count(&self) -> usize {
        self.state.lock().unwrap().rows.len()
    }
}

const UPLOAD_STRIDE: u64 = 4096;

impl crate::Transport for Server {
    fn send<'a>(&'a self, request: beebeeb_api::Request, _limit: usize) -> TransportFuture<'a> {
        Box::pin(async move { Ok::<_, TransportError>(self.answer(request.method(), request.path(), request.body())) })
    }
}

// ── Files on the server ────────────────────────────────────────────────────

/// Seal `data` as one v2 version of `file_id` (stride `stride`) and put it in
/// `parent`.
fn put_v2(server: &Server, file_id: &str, name: &str, parent: Option<&str>, data: &[u8], stride: u64) -> DownloadFile {
    let master = MasterKey::from_bytes(KEY);
    #[allow(deprecated)]
    let mut encryptor = ChunkEncryptor::for_push_with_chunk_size(&master, file_id, data.len() as u64, stride).unwrap();
    let chunks: Vec<Vec<u8>> = if data.is_empty() {
        vec![encryptor.push_chunk(&[]).unwrap().data]
    } else {
        data.chunks(stride as usize)
            .map(|piece| encryptor.push_chunk(piece).unwrap().data)
            .collect()
    };
    let commitment = encryptor.version_commitment_after(None).unwrap();
    encryptor.finish().unwrap();
    let name_encrypted =
        encrypt_name_with_version(&master, file_id, name, None, ExpectedChunkFormat::V2, commitment).unwrap();
    put_row(
        server,
        file_id,
        parent,
        name_encrypted,
        data.len() as u64,
        stride,
        chunks,
    )
}

/// Seal `data` as a legacy v1 file (no AAD, unrecorded pin).
fn put_v1(server: &Server, file_id: &str, parent: Option<&str>, data: &[u8], stride: u64) -> DownloadFile {
    let master = MasterKey::from_bytes(KEY);
    let key = derive_file_key(&master, file_id.as_bytes());
    let chunks = data
        .chunks(stride as usize)
        .map(|piece| {
            let blob = encrypt_chunk(&key, piece).unwrap();
            [blob.nonce, blob.ciphertext].concat()
        })
        .collect();
    #[allow(deprecated)]
    let name_encrypted = beebeeb_core::encrypt::encrypt_name(&master, file_id, "legacy.bin", None).unwrap();
    put_row(
        server,
        file_id,
        parent,
        name_encrypted,
        data.len() as u64,
        stride,
        chunks,
    )
}

fn put_row(
    server: &Server,
    file_id: &str,
    parent: Option<&str>,
    name_encrypted: String,
    size: u64,
    stride: u64,
    chunks: Vec<Vec<u8>>,
) -> DownloadFile {
    let count = chunks.len() as u32;
    server.insert(
        file_id,
        Row {
            parent_id: parent.map(str::to_owned),
            name_encrypted: name_encrypted.clone(),
            size,
            version: "listed-version".into(),
            chunks,
            ..Row::default()
        },
    );
    DownloadFile {
        file_id: file_id.into(),
        name_encrypted,
        size_bytes: size,
        chunk_size_bytes: stride,
        chunk_count: count,
        object_version_id: "listed-version".into(),
    }
}

fn put_folder(server: &Server, id: &str, parent: Option<&str>, role: Option<&'static str>) {
    let master = MasterKey::from_bytes(KEY);
    #[allow(deprecated)]
    let name_encrypted = beebeeb_core::encrypt::encrypt_name(&master, id, "folder", None).unwrap();
    server.insert(
        id,
        Row {
            parent_id: parent.map(str::to_owned),
            name_encrypted,
            is_folder: true,
            system_role: role,
            ..Row::default()
        },
    );
}

/// The tree the server holds under `parent`: folder paths (ending in `/`)
/// and each file's decrypted content.
fn tree(server: &Server, parent: Option<&str>) -> BTreeMap<String, Vec<u8>> {
    let master = MasterKey::from_bytes(KEY);
    let state = server.state.lock().unwrap();
    let mut out = BTreeMap::new();
    let mut queue = vec![(parent.map(str::to_owned), String::new())];
    while let Some((folder, prefix)) = queue.pop() {
        for (id, row) in state.rows.iter().filter(|(_, row)| row.parent_id == folder) {
            if row.is_folder {
                let name = decrypt_name_metadata(&master, id, &row.name_encrypted).unwrap().name;
                if row.system_role.is_none() && name != "folder" {
                    out.insert(format!("{prefix}{name}/"), Vec::new());
                    queue.push((Some(id.clone()), format!("{prefix}{name}/")));
                }
                continue;
            }
            if row.version == "listed-version" || row.version == "a-new-version" {
                continue; // the archive itself
            }
            let metadata = decrypt_file_metadata(&master, id, &row.name_encrypted).unwrap();
            let mut decryptor = ChunkDecryptor::for_current_version(&master, id, &metadata);
            let mut content = Vec::new();
            for frame in &row.chunks {
                content.extend(decryptor.push_frame(frame).unwrap().data);
            }
            decryptor.finish().unwrap();
            out.insert(format!("{prefix}{}", metadata.name), content);
        }
    }
    out
}

fn sha(map: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
    map.iter()
        .map(|(path, content)| (path.clone(), beebeeb_core::hash::sha256(content)))
        .collect()
}

// ── The client side ────────────────────────────────────────────────────────

struct Env {
    server: Server,
    root: TempDir,
    downloads: Arc<DownloadService>,
    uploads: Arc<UploadService>,
    service: ArchiveService,
    events: broadcast::Receiver<ArchiveEvent>,
}

impl Env {
    fn with_server(server: Server) -> Self {
        let root = tempdir().unwrap();
        let client = Arc::new(Client::new(ClientConfig::for_tests(), Arc::new(server.clone())).unwrap());
        client.set_authentication("token", "owner").unwrap();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let master = Arc::new(MasterKey::from_bytes(KEY));
        let downloads = Arc::new(
            DownloadService::new_for_test(
                Arc::clone(&client),
                Arc::clone(&store),
                Arc::clone(&master),
                root.path().join("cache"),
                1 << 30,
                MemoryBudget::MOBILE_APP,
            )
            .unwrap(),
        );
        let uploads = Arc::new(
            UploadService::new_for_test(Arc::clone(&client), store, master, root.path().join("staging")).unwrap(),
        );
        let service = ArchiveService::new(
            client,
            Arc::clone(&downloads),
            Arc::clone(&uploads),
            root.path().join("archives"),
            ArchivePlatform::MobileApp,
        )
        .unwrap();
        let events = service.observe();
        Self {
            server,
            root,
            downloads,
            uploads,
            service,
            events,
        }
    }

    fn temp_files(&self) -> usize {
        std::fs::read_dir(self.root.path().join("archives")).unwrap().count()
    }

    async fn next_event(&mut self) -> ArchiveEvent {
        tokio::time::timeout(Duration::from_secs(10), self.events.recv())
            .await
            .expect("an archive event within 10 s")
            .unwrap()
    }

    /// Open `file` and wait for its listing.
    async fn open_listed(&mut self, file: &DownloadFile, name: &str, parent: Option<&str>) -> ArchiveId {
        let id = self
            .service
            .open(file, name.into(), parent.map(str::to_owned))
            .await
            .unwrap();
        loop {
            if let ArchiveEvent::Model { id: seen, model } = self.next_event().await
                && seen == id
                && model.state != PreviewState::Reading
            {
                assert_eq!(model.state, PreviewState::Listed, "{name}: {model:?}");
                return id;
            }
        }
    }

    async fn finished(&mut self, run: ExtractionId) -> ExtractSummary {
        loop {
            if let ArchiveEvent::Finished { id, summary } = self.next_event().await
                && id == run
            {
                return summary;
            }
        }
    }

    /// The platform: run every queued upload to its end.
    async fn pump(&self) -> Vec<UploadServiceError> {
        let mut errors = Vec::new();
        loop {
            let now = transfer_now_ms().unwrap();
            match self.uploads.next_transfers(16, NetworkKind::WiFi, now).await {
                Ok(None) => return errors,
                Ok(Some((id, requests))) => {
                    for request in requests {
                        self.server
                            .put_chunk(&request.url, std::fs::read(&request.body_path).unwrap());
                        self.uploads
                            .transfer_finished(id, &request.ticket, 200, None, None, &[], now)
                            .await
                            .unwrap();
                    }
                }
                Err(error) => errors.push(error),
            }
        }
    }

    /// Pump uploads until the run finishes.
    async fn pump_until_finished(&mut self, run: ExtractionId) -> ExtractSummary {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the run did not finish within 10 s"
            );
            self.pump().await;
            match tokio::time::timeout(Duration::from_millis(20), self.events.recv()).await {
                Ok(Ok(ArchiveEvent::Finished { id, summary })) if id == run => return summary,
                Ok(Err(error)) => panic!("events: {error}"),
                _ => {}
            }
        }
    }

    async fn queued_uploads(&self, n: usize) {
        for _ in 0..500 {
            if self.uploads.list().unwrap().len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{n} uploads were not queued");
    }
}

fn options(destination: ExtractDestination) -> ExtractOptions {
    ExtractOptions {
        selection: Selection::All,
        destination,
        device_free_bytes: None,
        wifi_only: false,
        upload_disk_limit: None,
    }
}

fn expected(entries: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    entries
        .iter()
        .map(|(path, content)| ((*path).to_owned(), content.to_vec()))
        .collect()
}

fn story() -> Vec<u8> {
    let mut story = b"Once upon a time, ".repeat(30);
    story.push(b'\n');
    story.extend(std::iter::repeat_n(b'z', 600));
    story
}

const JPEG: &[u8] = b"\xff\xd8\xff\xe0 not really a JPEG\n";

// ── Tests ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn read_range_v1_and_v2() {
    let server = Server::new();
    let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
    let v2 = put_v2(
        &server,
        "11111111-2222-4333-8444-555555555555",
        "v2.bin",
        None,
        &data,
        256,
    );
    let v1 = put_v1(&server, "22222222-2222-4333-8444-555555555555", None, &data, 256);
    let env = Env::with_server(server.clone());

    for file in [&v2, &v1] {
        // Within chunk 2: frame 0 opens first (I3), then chunk 2.
        let before = server.chunk_gets().len();
        assert_eq!(env.downloads.read_range(file, 600..700).await.unwrap(), &data[600..700]);
        let gets: Vec<u32> = server.chunk_gets()[before..].iter().map(|(_, i)| *i).collect();
        assert_eq!(gets, [0, 2], "{}", file.file_id);
        // Across chunk boundaries, to the end.
        assert_eq!(env.downloads.read_range(file, 200..1000).await.unwrap(), &data[200..]);
    }

    // One reader, the same chunk twice: the second read opens a new session
    // (frame 0 again), never the same index twice in one `RangeOpener`.
    let mut reader = env.downloads.range_reader(&v2).unwrap();
    assert_eq!(env.downloads.read_with(&mut reader, 0..10).await.unwrap(), &data[..10]);
    assert_eq!(
        env.downloads.read_with(&mut reader, 300..310).await.unwrap(),
        &data[300..310]
    );
    let before = server.chunk_gets().len();
    assert_eq!(
        env.downloads.read_with(&mut reader, 260..270).await.unwrap(),
        &data[260..270]
    );
    let gets: Vec<u32> = server.chunk_gets()[before..].iter().map(|(_, i)| *i).collect();
    assert_eq!(gets, [0, 1]);

    // A v2 frame served at another index never authenticates.
    {
        let mut state = server.state.lock().unwrap();
        let row = state.rows.get_mut(&v2.file_id).unwrap();
        row.chunks.swap(1, 2);
    }
    assert!(matches!(
        env.downloads.read_range(&v2, 300..310).await,
        Err(DownloadServiceError::Truncated)
    ));
}

#[tokio::test]
async fn archive_service_extracts_fixture_hashes_match() {
    let tar_files: &[(&str, &[u8])] = &[
        ("plain/", b""),
        ("plain/abs.txt", b"absolute\n"),
        ("plain/dev/", b""),
        ("plain/docs/", b""),
        ("plain/docs/readme.txt", b"Read me.\n"),
        ("plain/photos/", b""),
        ("plain/photos/2024/", b""),
        ("plain/photos/2024/beach.jpg", JPEG),
        ("plain/zeros.bin", &[0u8; 3000]),
    ];
    let story = story();
    let cases: Vec<(&str, BTreeMap<String, Vec<u8>>)> = vec![
        (
            "plain.zip",
            expected(&[
                ("plain/", b""),
                ("plain/docs/", b""),
                ("plain/docs/readme.txt", b"Read me.\n"),
                ("plain/empty.txt", b""),
                ("plain/notes.txt", b"Notes.\n"),
                ("plain/photos/", b""),
                ("plain/photos/2024/", b""),
                ("plain/photos/2024/beach.jpg", JPEG),
                ("plain/story.txt", &story),
            ]),
        ),
        ("plain.tar", expected(tar_files)),
        ("plain.tgz", expected(tar_files)),
        ("notes.txt.gz", expected(&[("notes.txt", b"Notes.\nNotes.\nNotes.\n")])),
        ("two-members.gz", expected(&[("two-members", b"first\nsecond\n")])),
        (
            "slip.zip",
            expected(&[
                ("slip/", b""),
                ("slip/etc/", b""),
                ("slip/etc/x", b"x"),
                ("slip/ok.txt", b"x"),
                ("slip/x", b"x"),
                ("slip/y.txt", b"x"),
            ]),
        ),
        ("macos.zip", expected(&[("macos/", b""), ("macos/a.txt", b"Data.\n")])),
    ];
    for (name, want) in cases {
        let server = Server::new();
        put_folder(&server, "aaaaaaaa-0000-4000-8000-000000000001", None, None);
        let parent = Some("aaaaaaaa-0000-4000-8000-000000000001");
        let file = put_v2(
            &server,
            "bbbbbbbb-0000-4000-8000-000000000001",
            name,
            parent,
            &fixture(name),
            256,
        );
        let mut env = Env::with_server(server.clone());
        let id = env.open_listed(&file, name, parent).await;
        let run = env
            .service
            .extract(id, options(ExtractDestination::NextToArchive), None)
            .await
            .unwrap();
        let summary = env.pump_until_finished(run).await;
        assert_eq!(summary.outcome, ExtractOutcome::Done, "{name}: {summary:?}");
        let files = want.keys().filter(|path| !path.ends_with('/')).count() as u32;
        assert_eq!((summary.files_done, summary.files_total), (files, files), "{name}");
        let landed = tree(&server, parent);
        // Every file lands with the fixture's bytes, and nothing lands outside
        // the destination (the whole tree under the archive's folder is this).
        assert_eq!(sha(&landed), sha(&want), "{name}");
        assert_eq!(env.temp_files(), 0, "{name}");
    }
}

#[tokio::test]
async fn archive_service_password_fixture() {
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000002",
        "aes256.zip",
        None,
        &fixture("aes256.zip"),
        512,
    );
    let mut env = Env::with_server(server.clone());
    let id = env.open_listed(&file, "aes256.zip", None).await;
    let secret = b"The protected test file.\n".repeat(40);

    // Open: no password, a wrong one, the right one.
    assert!(matches!(
        env.service.open_entry(id, 0, None).await,
        Err(ArchiveServiceError::PasswordNeeded)
    ));
    let wrong = env
        .service
        .open_entry(id, 0, Some(ArchivePassword::new("not-it".into())))
        .await;
    assert!(matches!(wrong, Err(ArchiveServiceError::WrongPassword)));
    assert!(!format!("{wrong:?}").contains("not-it"));
    let opened = env
        .service
        .open_entry(id, 0, Some(ArchivePassword::new(PASSWORD.into())))
        .await
        .unwrap();
    assert_eq!(opened, secret);

    // Extract without a password: the run asks, a wrong one asks again, the
    // right one extracts.
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    let mut asked = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while asked.len() < 2 {
        assert!(tokio::time::Instant::now() < deadline, "asked {asked:?} within 10 s");
        if let ArchiveEvent::Model { model, .. } = env.next_event().await
            && let PreviewState::NeedsPassword { wrong } = model.state
        {
            asked.push(wrong);
            let password = if wrong { PASSWORD } else { "still-not-it" };
            env.service.supply_password(run, ArchivePassword::new(password.into()));
        }
    }
    assert_eq!(asked, [false, true]);
    let summary = env.pump_until_finished(run).await;
    assert_eq!(summary.outcome, ExtractOutcome::Done);
    assert_eq!(
        tree(&server, None),
        expected(&[("aes256/", b""), ("aes256/secret.txt", &secret)])
    );
    assert_eq!(env.temp_files(), 0);
}

#[tokio::test]
async fn archive_service_stop_midway() {
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000003",
        "plain.zip",
        None,
        &fixture("plain.zip"),
        256,
    );
    let mut env = Env::with_server(server.clone());
    let id = env.open_listed(&file, "plain.zip", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    env.queued_uploads(5).await;
    // One upload finishes, then the person stops.
    let now = transfer_now_ms().unwrap();
    let (upload, requests) = env
        .uploads
        .next_transfers(16, NetworkKind::WiFi, now)
        .await
        .unwrap()
        .unwrap();
    for request in requests {
        env.server
            .put_chunk(&request.url, std::fs::read(&request.body_path).unwrap());
        env.uploads
            .transfer_finished(upload, &request.ticket, 200, None, None, &[], now)
            .await
            .unwrap();
    }
    for _ in 0..200 {
        if let Ok(Ok(ArchiveEvent::Model { model, .. })) =
            tokio::time::timeout(Duration::from_millis(10), env.events.recv()).await
            && model.state == PreviewState::Extracting
            && model
                .summary
                .as_ref()
                .is_some_and(|s| s.text.starts_with("Extracting 1 of"))
        {
            break;
        }
    }
    env.service.cancel(run);
    let summary = env.finished(run).await;
    assert_eq!(summary.outcome, ExtractOutcome::Stopped);
    assert_eq!((summary.files_done, summary.files_total), (1, 5));
    // Exactly what the summary says is in the folder; the other uploads are
    // cancelled and no staged file is left.
    let landed = tree(&server, None);
    assert_eq!(landed.keys().filter(|p| !p.ends_with('/')).count(), 1);
    let states: Vec<TransferState> = env.uploads.list().unwrap().into_iter().map(|u| u.state).collect();
    assert_eq!(states.iter().filter(|s| **s == TransferState::Succeeded).count(), 1);
    assert_eq!(states.iter().filter(|s| **s == TransferState::Cancelled).count(), 4);
    assert!(env.pump().await.is_empty());
    assert_eq!(tree(&server, None).len(), landed.len());
    assert_eq!(env.temp_files(), 0);
}

#[tokio::test]
async fn archive_service_storage_full() {
    // The plan: more than the free space refuses before anything is written.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000004",
        "plain.zip",
        None,
        &fixture("plain.zip"),
        256,
    );
    server.state.lock().unwrap().limit = 100;
    let mut env = Env::with_server(server.clone());
    let id = env.open_listed(&file, "plain.zip", None).await;
    let refused = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await;
    assert!(matches!(
        refused,
        Err(ArchiveServiceError::Plan(PlanRefusal::Quota { .. }))
    ));
    assert_eq!(server.row_count(), 1, "nothing was written");

    // The server: the account fills up after two uploads.
    {
        let mut state = server.state.lock().unwrap();
        state.limit = 1 << 40;
        state.uploads_left = Some(2);
    }
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    let summary = env.pump_until_finished(run).await;
    assert_eq!(summary.outcome, ExtractOutcome::Failed(FailReason::StorageFull));
    assert_eq!(summary.files_done, 2);
    let landed = tree(&server, None);
    assert_eq!(landed.keys().filter(|p| !p.ends_with('/')).count(), 2);
    assert_eq!(env.temp_files(), 0);
}

#[tokio::test]
async fn archive_service_backups_refused() {
    let server = Server::new();
    let root = "cccccccc-0000-4000-8000-000000000001";
    let device = "cccccccc-0000-4000-8000-000000000002";
    let category = "cccccccc-0000-4000-8000-000000000003";
    put_folder(&server, root, None, Some("backups_root"));
    put_folder(&server, device, Some(root), None);
    put_folder(&server, category, Some(device), None);
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000005",
        "plain.zip",
        Some(category),
        &fixture("plain.zip"),
        256,
    );
    let mut env = Env::with_server(server.clone());
    let id = env.open_listed(&file, "plain.zip", Some(category)).await;
    // Inside Backups the preview offers "Extract to…", never "Extract" (A8).
    let model = env.service.preview(id, Vec::new(), Vec::new()).await.unwrap();
    let actions: Vec<&str> = model.actions.iter().map(|a| a.kind.as_str()).collect();
    assert_eq!(actions, ["extract_to"]);
    let rows = server.row_count();
    for destination in [
        ExtractDestination::NextToArchive,
        ExtractDestination::Folder(Some(device.into())),
        ExtractDestination::Folder(Some(root.into())),
    ] {
        let refused = env.service.extract(id, options(destination), None).await;
        assert!(matches!(refused, Err(ArchiveServiceError::Plan(PlanRefusal::Backups))));
        assert_eq!(refused.err().unwrap().to_string(), PlanRefusal::Backups.text().text);
    }
    assert_eq!(server.row_count(), rows, "nothing was created");
    assert!(env.uploads.list().unwrap().is_empty());
    // Extract to a folder outside Backups works.
    let run = env
        .service
        .extract(id, options(ExtractDestination::Folder(None)), None)
        .await
        .unwrap();
    assert_eq!(env.pump_until_finished(run).await.outcome, ExtractOutcome::Done);
}

#[tokio::test]
async fn archive_service_version_change_fails() {
    // Between the preview and Extract.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000006",
        "plain.tar",
        None,
        &fixture("plain.tar"),
        256,
    );
    let mut env = Env::with_server(server.clone());
    let id = env.open_listed(&file, "plain.tar", None).await;
    server
        .state
        .lock()
        .unwrap()
        .rows
        .get_mut(&file.file_id)
        .unwrap()
        .version = "a-new-version".into();
    let reads = server.chunk_gets().len();
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    let summary = env.finished(run).await;
    assert_eq!(summary.outcome, ExtractOutcome::Failed(FailReason::Changed));
    assert_eq!(summary.files_done, 0);
    assert_eq!(server.chunk_gets().len(), reads, "nothing was read");

    // During it: the version changes at the extraction's first read.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000007",
        "plain.tar",
        None,
        &fixture("plain.tar"),
        256,
    );
    let mut env = Env::with_server(server.clone());
    let id = env.open_listed(&file, "plain.tar", None).await;
    server.state.lock().unwrap().bump_on_chunk_get = Some(file.file_id.clone());
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    let summary = env.pump_until_finished(run).await;
    assert_eq!(summary.outcome, ExtractOutcome::Failed(FailReason::Changed));
    assert!(summary.files_done < summary.files_total, "{summary:?}");
    let landed = tree(&server, None);
    assert_eq!(
        landed.keys().filter(|p| !p.ends_with('/')).count() as u32,
        summary.files_done
    );
    assert_eq!(env.temp_files(), 0);
}

#[tokio::test]
async fn archive_service_temp_files_deleted() {
    let data = fixture("plain.zip");
    // Done.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000008",
        "plain.zip",
        None,
        &data,
        256,
    );
    let mut env = Env::with_server(server);
    let id = env.open_listed(&file, "plain.zip", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    assert_eq!(env.pump_until_finished(run).await.outcome, ExtractOutcome::Done);
    assert_eq!(env.temp_files(), 0, "after Done");

    // Stopped with every file staged and queued.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000009",
        "plain.zip",
        None,
        &data,
        256,
    );
    let mut env = Env::with_server(server);
    let id = env.open_listed(&file, "plain.zip", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    env.queued_uploads(5).await;
    assert_eq!(env.temp_files(), 5, "five files staged");
    env.service.cancel(run);
    assert_eq!(env.finished(run).await.outcome, ExtractOutcome::Stopped);
    assert_eq!(env.temp_files(), 0, "after Stopped");

    // Failed (storage full) with files still queued.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-00000000000a",
        "plain.zip",
        None,
        &data,
        256,
    );
    server.state.lock().unwrap().uploads_left = Some(0);
    let mut env = Env::with_server(server);
    let id = env.open_listed(&file, "plain.zip", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    let summary = env.pump_until_finished(run).await;
    assert_eq!(summary.outcome, ExtractOutcome::Failed(FailReason::StorageFull));
    assert_eq!(env.temp_files(), 0, "after Failed");

    // A file left by an earlier process is deleted when the service starts.
    let leftover = env.root.path().join("archives").join("archive-1-1.bbtmp");
    std::fs::write(&leftover, b"plaintext").unwrap();
    let _service = ArchiveService::new(
        Arc::new(Client::new(ClientConfig::for_tests(), Arc::new(Server::new())).unwrap()),
        Arc::clone(&env.downloads),
        Arc::clone(&env.uploads),
        env.root.path().join("archives"),
        ArchivePlatform::MobileApp,
    )
    .unwrap();
    assert!(!leftover.exists());
}

#[tokio::test]
async fn archive_service_folder_race_takes_the_next_number() {
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-00000000000b",
        "macos.zip",
        None,
        &fixture("macos.zip"),
        256,
    );
    server.state.lock().unwrap().folder_conflicts = 1;
    let mut env = Env::with_server(server.clone());
    let id = env.open_listed(&file, "macos.zip", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    let summary = env.pump_until_finished(run).await;
    assert_eq!(summary.outcome, ExtractOutcome::Done);
    assert_eq!(summary.target_name, "macos (2)");
    assert_eq!(summary.skipped.len(), 2);
    assert!(
        summary
            .skipped
            .iter()
            .all(|(_, reason)| *reason == SkipReason::MacResource)
    );
    assert_eq!(
        tree(&server, None),
        expected(&[("macos (2)/", b""), ("macos (2)/a.txt", b"Data.\n")])
    );
}
