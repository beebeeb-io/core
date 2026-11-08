//! The extraction step machine (spec §5.2): folders first, files in
//! archive order, published only after their check, streaming limits,
//! passwords, cancel, failures and races.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;

use beebeeb_core::archives::{
    ArchiveIdentity, ArchivePassword, ArchivePlatform, ArchiveSession, ByteSource, DestinationInfo, ExtractOutcome,
    ExtractRequest, ExtractStep, ExtractSummary, Extraction, FailReason, NodeKind, Selection, SessionStep, SkipReason,
    plan_extraction,
};
use beebeeb_core::name_clash::TakenNames;
use zip::CompressionMethod::{Deflated, Stored};

use crate::support::{Blocking, Chaos, RawZip, RawZipEntry, TEST_PASSWORD, drive, zip9};

fn identity(version: &str) -> ArchiveIdentity {
    ArchiveIdentity {
        file_id: "file-1".into(),
        object_version_id: version.into(),
    }
}

fn request(name: &str) -> ExtractRequest {
    ExtractRequest {
        archive_name: name.into(),
        selection: Selection::All,
        destination: DestinationInfo {
            siblings: TakenNames::new(),
            backup_position: None,
            writable: true,
        },
        server_free_bytes: u64::MAX,
        device_free_bytes: None,
        platform: ArchivePlatform::Native,
    }
}

fn start<S: ByteSource>(
    source: S,
    name: &str,
    password: Option<&str>,
    grant: impl FnMut(&mut S, beebeeb_core::archives::ByteRange),
) -> Extraction<S> {
    start_on(ArchivePlatform::Native, source, name, password, grant)
}

fn start_on<S: ByteSource>(
    platform: ArchivePlatform,
    source: S,
    name: &str,
    password: Option<&str>,
    grant: impl FnMut(&mut S, beebeeb_core::archives::ByteRange),
) -> Extraction<S> {
    start_selected(platform, source, name, Selection::All, password, grant)
}

fn start_selected<S: ByteSource>(
    platform: ArchivePlatform,
    source: S,
    name: &str,
    selection: Selection,
    password: Option<&str>,
    grant: impl FnMut(&mut S, beebeeb_core::archives::ByteRange),
) -> Extraction<S> {
    let mut session = ArchiveSession::open(source, platform);
    assert_eq!(drive(&mut session, grant), SessionStep::Listed);
    let mut request = request(name);
    request.selection = selection;
    let plan = plan_extraction(session.listing().unwrap(), &request).unwrap();
    Extraction::start(
        session,
        identity("v1"),
        plan,
        password.map(|p| ArchivePassword::new(p.into())),
    )
}

/// What a driver saw: every step (data shortened to its length) and the
/// bytes each published file carried.
#[derive(Default)]
struct Run {
    log: Vec<String>,
    published: BTreeMap<String, Vec<u8>>,
    data_bytes: u64,
    summary: Option<ExtractSummary>,
}

/// Drive to the end: folders are created at once, every upload finishes
/// at once, demands are answered by `grant`, passwords come from
/// `passwords` in turn (then cancel).
fn run<S: ByteSource>(
    x: &mut Extraction<S>,
    mut grant: impl FnMut(&mut S, beebeeb_core::archives::ByteRange),
    mut passwords: Vec<&str>,
    mut hook: impl FnMut(&mut Extraction<S>, &ExtractStep),
) -> Run {
    let mut out = Run::default();
    let mut names: HashMap<u32, String> = HashMap::new();
    let mut staged: HashMap<u32, Vec<u8>> = HashMap::new();
    for _ in 0..1_000_000 {
        let step = x.step();
        hook(x, &step);
        match &step {
            ExtractStep::NeedBytes(range) => grant(x.source_mut(), *range),
            ExtractStep::NeedPassword { entry, wrong } => {
                out.log.push(format!("password? {entry} wrong={wrong}"));
                if passwords.is_empty() {
                    x.cancel();
                } else {
                    x.supply_password(ArchivePassword::new(passwords.remove(0).into()));
                }
            }
            ExtractStep::CreateFolder { node, parent, name } => {
                out.log.push(format!("folder {node} in {parent:?} {name}"));
                let path = parent.map_or(name.clone(), |p| format!("{}/{name}", names[&p]));
                names.insert(*node, path);
                x.folder_created(*node, format!("remote-{node}"));
            }
            ExtractStep::FileBegin {
                node,
                parent,
                name,
                size,
            } => {
                out.log.push(format!("begin {node} {name} {size}"));
                let path = parent.map_or(name.clone(), |p| format!("{}/{name}", names[&p]));
                names.insert(*node, path);
                staged.insert(*node, Vec::new());
            }
            ExtractStep::FileData { node, bytes } => {
                out.data_bytes += bytes.len() as u64;
                staged.get_mut(node).expect("data after begin").extend_from_slice(bytes);
            }
            ExtractStep::FileEnd { node } => {
                out.log.push(format!("end {node}"));
                out.published.insert(names[node].clone(), staged.remove(node).unwrap());
                x.upload_finished(*node, true);
            }
            ExtractStep::FileSkipped { node, reason } => {
                out.log.push(format!("skip {node} {reason:?}"));
                staged.remove(node);
            }
            ExtractStep::Progress(_) => {}
            ExtractStep::Waiting => out.log.push("waiting".into()),
            ExtractStep::Finished(summary) => {
                out.summary = Some(summary.clone());
                return out;
            }
        }
    }
    panic!("the extraction never finished");
}

fn blocking_run(bytes: Vec<u8>, name: &str, passwords: Vec<&str>) -> Run {
    let mut x = start(Blocking(bytes), name, None, |_, r| panic!("{r:?}"));
    run(&mut x, |_, r| panic!("{r:?}"), passwords, |_, _| {})
}

#[test]
fn extract_folders_first_then_files_in_offset_order() {
    let entries = vec![
        RawZipEntry::stored("b/deep/z.txt", b"z"),
        RawZipEntry::stored("a.txt", b"a"),
        RawZipEntry::stored("b/y.txt", b"y"),
    ];
    let mut zip = RawZip::of(entries);
    zip.cd_order = Some(vec![2, 1, 0]); // the central directory lists them backwards
    let out = blocking_run(zip.build(), "x.zip", vec![]);
    let order: Vec<_> = out
        .log
        .iter()
        .filter(|l| l.starts_with("folder") || l.starts_with("begin"))
        .cloned()
        .collect();
    assert_eq!(
        order,
        vec![
            "folder 0 in None x",
            "folder 1 in Some(0) b",
            "folder 4 in Some(1) deep",
            "begin 5 z.txt 1",
            "begin 3 a.txt 1",
            "begin 2 y.txt 1",
        ]
    );
    assert_eq!(out.summary.unwrap().outcome, ExtractOutcome::Done);
}

#[test]
fn extract_publishes_only_after_verified() {
    let mut bad = RawZipEntry::deflated("bad.txt", &b"corrupt me ".repeat(100));
    bad.crc ^= 1;
    let out = blocking_run(
        RawZip::of(vec![bad, RawZipEntry::stored("good.txt", b"good")]).build(),
        "p.zip",
        vec![],
    );
    assert_eq!(out.published.keys().collect::<Vec<_>>(), vec!["p/good.txt"]);
    assert!(out.log.iter().any(|l| l == "skip 1 Corrupt"), "{:?}", out.log);
    assert!(!out.log.iter().any(|l| l == "end 1"));
    let summary = out.summary.unwrap();
    assert_eq!((summary.files_done, summary.files_total), (1, 2));
    assert_eq!(summary.skipped, vec![("bad.txt".to_string(), SkipReason::Corrupt)]);
}

#[test]
fn extract_cut_at_declared_size() {
    let mut liar = RawZipEntry::deflated("liar.txt", &vec![b'L'; 512 * 1024]);
    liar.uncompressed = 1000;
    let out = blocking_run(RawZip::of(vec![liar]).build(), "l.zip", vec![]);
    assert!(
        out.data_bytes <= 1001,
        "{} bytes passed a declared 1000",
        out.data_bytes
    );
    assert!(out.log.iter().any(|l| l == "skip 1 Bomb"), "{:?}", out.log);
    assert!(out.published.is_empty());
}

#[test]
fn extract_total_never_passes_declared() {
    let zip = RawZip::of(vec![
        RawZipEntry::stored("one", &[1u8; 100]),
        RawZipEntry::stored("two", &[2u8; 100]),
    ])
    .build();
    let mut session = ArchiveSession::open(Blocking(zip), ArchivePlatform::Native);
    drive(&mut session, |_, r| panic!("{r:?}"));
    let mut plan = plan_extraction(session.listing().unwrap(), &request("t.zip")).unwrap();
    plan.totals.bytes = 150; // headers that lie about the total
    let mut x = Extraction::start(session, identity("v1"), plan, None);
    let out = run(&mut x, |_, r| panic!("{r:?}"), vec![], |_, _| {});
    assert!(
        out.data_bytes <= 150,
        "{} bytes passed a declared total of 150",
        out.data_bytes
    );
    assert_eq!(out.published.keys().collect::<Vec<_>>(), vec!["t/one"]);
    assert!(out.log.iter().any(|l| l == "skip 2 Bomb"), "{:?}", out.log);
}

#[test]
fn extract_gzip_ratio_bomb_stops() {
    // 1.25 GiB of zeros at about 1,030:1: past 1 GiB of output the ratio
    // rule cuts it.
    let mut encoder = flate2::GzBuilder::new()
        .filename("bomb.bin")
        .write(Vec::new(), flate2::Compression::best());
    let chunk = vec![0u8; 1 << 20];
    for _ in 0..1280 {
        encoder.write_all(&chunk).unwrap();
    }
    let gz = encoder.finish().unwrap();
    assert!(
        gz.len() < 1280 * 1024 * 1024 / 1000,
        "the fixture compresses {} bytes",
        gz.len()
    );
    // Native refuses it while listing (the scan passes 1 GiB); the phone
    // scans 256 MiB, lists it as incomplete, and the extraction cuts it.
    let mut session = ArchiveSession::open(Blocking(gz.clone()), ArchivePlatform::Native);
    assert_eq!(
        drive(&mut session, |_, r| panic!("{r:?}")),
        SessionStep::Refused(beebeeb_core::archives::ArchiveRefusal::Bomb)
    );
    let mut x = start_on(ArchivePlatform::MobileApp, Blocking(gz), "bomb.bin.gz", None, |_, r| {
        panic!("{r:?}")
    });
    let out = run(&mut x, |_, r| panic!("{r:?}"), vec![], |_, _| {});
    assert!(out.log.iter().any(|l| l == "skip 0 Bomb"), "{:?}", out.log);
    assert!(out.published.is_empty());
    assert!(out.data_bytes < 1280 * 1024 * 1024);
}

#[test]
fn extract_needs_password_once() {
    let bytes = zip9(&[
        ("one.txt", Deflated, Some((TEST_PASSWORD, true)), b"first secret"),
        ("plain.txt", Stored, None, b"plain"),
        ("two.txt", Deflated, Some((TEST_PASSWORD, true)), b"second secret"),
    ]);
    let out = blocking_run(bytes, "s.zip", vec!["not it", TEST_PASSWORD]);
    let asked: Vec<_> = out.log.iter().filter(|l| l.starts_with("password?")).cloned().collect();
    assert_eq!(asked, vec!["password? 0 wrong=false", "password? 0 wrong=true"]);
    assert_eq!(out.published.len(), 3);
    assert_eq!(out.published["s/two.txt"], b"second secret");
}

#[test]
fn extract_cancel_midway_summary() {
    let zip = RawZip::of((0..5).map(|i| RawZipEntry::stored(&format!("f{i}"), b"data")).collect()).build();
    let mut x = start(Blocking(zip), "c.zip", None, |_, r| panic!("{r:?}"));
    let mut ends = 0;
    let out = run(
        &mut x,
        |_, r| panic!("{r:?}"),
        vec![],
        |x, step| {
            if matches!(step, ExtractStep::FileEnd { .. }) {
                ends += 1;
                if ends == 2 {
                    x.cancel();
                }
            }
        },
    );
    let summary = out.summary.unwrap();
    assert_eq!(summary.outcome, ExtractOutcome::Stopped);
    assert_eq!((summary.files_done, summary.files_total), (2, 5));
}

#[test]
fn failed_midway_summary_counts_only_finished_uploads() {
    let zip = RawZip::of((0..4).map(|i| RawZipEntry::stored(&format!("f{i}"), b"data")).collect()).build();
    let mut x = start(Blocking(zip), "f.zip", None, |_, r| panic!("{r:?}"));
    let mut log = Vec::new();
    let summary = loop {
        match x.step() {
            ExtractStep::CreateFolder { node, .. } => x.folder_created(node, "r".into()),
            ExtractStep::FileEnd { node } => {
                log.push(node);
                match log.len() {
                    1 => x.upload_finished(node, true), // finished
                    2 => {}                             // still uploading when the network goes
                    _ => x.run_failed(FailReason::Network),
                }
            }
            ExtractStep::Finished(summary) => break summary,
            ExtractStep::NeedBytes(r) => panic!("{r:?}"),
            _ => {}
        }
    };
    assert_eq!(summary.outcome, ExtractOutcome::Failed(FailReason::Network));
    assert_eq!((summary.files_done, summary.files_total), (1, 4));
}

#[test]
fn destination_race_409_takes_next_number() {
    let zip = RawZip::of(vec![RawZipEntry::stored("p.jpg", b"jpeg")]).build();
    let mut x = start(Blocking(zip), "photos.zip", None, |_, r| panic!("{r:?}"));
    let mut folders = Vec::new();
    let summary = loop {
        match x.step() {
            ExtractStep::CreateFolder { node: 0, name, .. } => {
                folders.push(name.clone());
                if folders.len() == 1 {
                    x.folder_name_taken(0); // another device made "photos" a moment ago
                } else {
                    x.folder_created(0, "remote".into());
                }
            }
            ExtractStep::FileEnd { node } => x.upload_finished(node, true),
            ExtractStep::Finished(summary) => break summary,
            _ => {}
        }
    };
    assert_eq!(folders, vec!["photos", "photos (2)"]);
    assert_eq!(summary.target_name, "photos (2)");
    assert_eq!(summary.files_done, 1);
}

#[test]
fn version_change_between_preview_and_extract_is_refused() {
    let zip = RawZip::of((0..3).map(|i| RawZipEntry::stored(&format!("f{i}"), b"data")).collect()).build();
    let mut x = start(Blocking(zip), "v.zip", None, |_, r| panic!("{r:?}"));
    x.identity_seen(&identity("v2"));
    let out = run(&mut x, |_, r| panic!("{r:?}"), vec![], |_, _| {});
    assert_eq!(
        out.summary.unwrap().outcome,
        ExtractOutcome::Failed(FailReason::Changed)
    );
    assert!(out.published.is_empty());
    // The same identity seen again changes nothing.
    let zip = RawZip::of(vec![RawZipEntry::stored("f", b"data")]).build();
    let mut same = start(Blocking(zip), "v.zip", None, |_, r| panic!("{r:?}"));
    same.identity_seen(&identity("v1"));
    assert_eq!(
        run(&mut same, |_, r| panic!("{r:?}"), vec![], |_, _| {})
            .summary
            .unwrap()
            .outcome,
        ExtractOutcome::Done
    );
}

#[test]
fn extract_zip_slip_fixture_has_no_node_outside() {
    let names = [
        "../x",
        "/etc/x",
        "C:\\x",
        "..\\..\\x",
        "a\0b",
        "ok/../../../x",
        "fine.txt",
    ];
    let zip = RawZip::of(names.iter().map(|n| RawZipEntry::stored(n, b"payload")).collect()).build();
    let mut session = ArchiveSession::open(Blocking(zip), ArchivePlatform::Native);
    drive(&mut session, |_, r| panic!("{r:?}"));
    let plan = plan_extraction(session.listing().unwrap(), &request("slip.zip")).unwrap();
    // Every node's parents end at the destination folder (node 0).
    let parent_of: HashMap<u32, Option<u32>> = plan.nodes.iter().map(|n| (n.id, n.parent)).collect();
    let outside = plan
        .nodes
        .iter()
        .filter(|n| {
            let mut at = n.id;
            let mut hops = 0;
            while let Some(Some(p)) = parent_of.get(&at) {
                at = *p;
                hops += 1;
                if hops > 100 {
                    return true;
                }
            }
            at != 0 || n.name.contains(['/', '\\']) || n.name == ".." || n.name == "."
        })
        .count();
    assert_eq!(outside, 0);
    let files: Vec<_> = plan
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::File)
        .map(|n| n.name.as_str())
        .collect();
    // /etc/x becomes etc/x and C:\x becomes x (different folders); the
    // other four are refused.
    assert_eq!(files, vec!["x", "x", "fine.txt"]);
    let mut x = Extraction::start(session, identity("v1"), plan, None);
    let out = run(&mut x, |_, r| panic!("{r:?}"), vec![], |_, _| {});
    assert!(
        out.published.keys().all(|p| p.starts_with("slip/")),
        "{:?}",
        out.published.keys()
    );
    assert_eq!(out.summary.unwrap().skipped.len(), 4);
}

#[test]
fn extract_chaos_source_equal_output() {
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 241) as u8).collect();
    let bytes = zip9(&[
        ("a.txt", Stored, None, b"alpha"),
        ("dir/b.bin", Deflated, None, &big),
        ("dir/c.txt", Deflated, Some((TEST_PASSWORD, true)), b"gamma"),
    ]);
    let expected = blocking_run(bytes.clone(), "c.zip", vec![TEST_PASSWORD]);
    for seed in [3u64, 11, 29] {
        let mut x = start(Chaos::new(bytes.clone(), seed), "c.zip", None, |s, r| s.grant(r));
        let chaotic = run(&mut x, |s, r| s.grant(r), vec![TEST_PASSWORD], |_, _| {});
        assert_eq!(chaotic.published, expected.published, "seed {seed}");
        assert_eq!(chaotic.log, expected.log, "seed {seed}");
    }
    assert_eq!(expected.published["c/dir/b.bin"], big);
}

#[test]
fn extract_storage_full_reported() {
    let zip = RawZip::of((0..3).map(|i| RawZipEntry::stored(&format!("f{i}"), b"data")).collect()).build();
    let mut x = start(Blocking(zip), "s.zip", None, |_, r| panic!("{r:?}"));
    let mut ends = 0;
    let out = run(
        &mut x,
        |_, r| panic!("{r:?}"),
        vec![],
        |x, step| {
            if matches!(step, ExtractStep::FileEnd { .. }) {
                ends += 1;
                if ends == 2 {
                    x.run_failed(FailReason::StorageFull);
                }
            }
        },
    );
    let summary = out.summary.unwrap();
    assert_eq!(summary.outcome, ExtractOutcome::Failed(FailReason::StorageFull));
    assert_eq!(summary.files_done, 2);
}

#[test]
fn extract_password_dropped_on_cancel() {
    let bytes = zip9(&[("one.txt", Deflated, Some((TEST_PASSWORD, false)), b"secret")]);
    let mut x = start(Blocking(bytes), "p.zip", Some(TEST_PASSWORD), |_, r| panic!("{r:?}"));
    assert!(x.holds_password());
    x.cancel();
    assert!(!x.holds_password());
    let ExtractStep::Finished(summary) = x.step() else {
        panic!("a cancelled extraction finishes")
    };
    assert_eq!(summary.outcome, ExtractOutcome::Stopped);
    assert!(!x.holds_password());
}

#[test]
fn extract_tgz_past_an_incomplete_listing() {
    use crate::support::{TarBuilder, gzip, gzip_zeros_member, octal, tar_header};
    // The phone lists 256 MiB of this tgz; the entries after the big one
    // are not in its listing, and extracting still writes them, named by
    // the planner's rules.
    let big_len = 260u64 * 1024 * 1024;
    let mut head = TarBuilder::default();
    head.file("first.txt", b"first")
        .raw(&tar_header(b"big.bin", b'0', &octal(big_len, 12), true));
    let mut head_bytes = head.finish();
    head_bytes.truncate(head_bytes.len() - 1024);
    let tail = TarBuilder::default()
        .file("late/after.txt", b"after")
        .file("first.txt", b"again")
        .finish();
    let tgz = [gzip(&head_bytes), gzip_zeros_member(big_len), gzip(&tail)].concat();
    let mut x = start_on(ArchivePlatform::MobileApp, Blocking(tgz), "t.tgz", None, |_, r| {
        panic!("{r:?}")
    });
    let out = run(&mut x, |_, r| panic!("{r:?}"), vec![], |_, _| {});
    let summary = out.summary.unwrap();
    assert_eq!(summary.outcome, ExtractOutcome::Done);
    assert_eq!((summary.files_done, summary.files_total), (4, 4));
    let mut names: Vec<_> = out.published.keys().cloned().collect();
    names.sort();
    assert_eq!(
        names,
        vec!["t/big.bin", "t/first (2).txt", "t/first.txt", "t/late/after.txt"]
    );
    assert_eq!(out.published["t/late/after.txt"], b"after");
    assert_eq!(out.published["t/big.bin"].len() as u64, big_len);
}

#[test]
fn extract_tgz_trailer_mismatch_fails_damaged() {
    use crate::support::{TarBuilder, gzip, gzip_zeros_member, octal, tar_header};
    // The same shape as above, with the last member's CRC-32 broken. The
    // phone's listing stops before it, so only the extraction can see it:
    // at the stream's end, after the files were published, and it must
    // say so instead of reporting a clean run.
    let big_len = 260u64 * 1024 * 1024;
    let mut head = TarBuilder::default();
    head.file("first.txt", b"first")
        .raw(&tar_header(b"big.bin", b'0', &octal(big_len, 12), true));
    let mut head_bytes = head.finish();
    head_bytes.truncate(head_bytes.len() - 1024);
    let mut last = gzip(&TarBuilder::default().file("after.txt", b"after").finish());
    let at = last.len() - 8;
    last[at] ^= 0xFF;
    let tgz = [gzip(&head_bytes), gzip_zeros_member(big_len), last].concat();
    let mut x = start_on(ArchivePlatform::MobileApp, Blocking(tgz), "t.tgz", None, |_, r| {
        panic!("{r:?}")
    });
    let out = run(&mut x, |_, r| panic!("{r:?}"), vec![], |_, _| {});
    let summary = out.summary.unwrap();
    assert_eq!(summary.outcome, ExtractOutcome::Failed(FailReason::Damaged));
    assert_eq!(summary.files_done, 3);
}

/// A tgz the phone lists only partly: `first.txt` and a 260 MiB entry in
/// the listing, `tail` past it.
fn partly_listed_tgz(listed: &[(&str, &[u8])], tail: &[(&str, &[u8])]) -> Vec<u8> {
    use crate::support::{TarBuilder, gzip, gzip_zeros_member, octal, tar_header};
    let big_len = 260u64 * 1024 * 1024;
    let mut head = TarBuilder::default();
    for (name, data) in listed {
        head.file(name, data);
    }
    head.raw(&tar_header(b"big.bin", b'0', &octal(big_len, 12), true));
    let mut head_bytes = head.finish();
    head_bytes.truncate(head_bytes.len() - 1024);
    let mut rest = TarBuilder::default();
    for (name, data) in tail {
        rest.file(name, data);
    }
    [gzip(&head_bytes), gzip_zeros_member(big_len), gzip(&rest.finish())].concat()
}

/// Extract Selected on a partly listed tgz writes the selection only:
/// nothing past the listing, and the stream is not read past the last
/// selected file (review finding).
#[test]
fn extract_selected_on_a_partly_listed_tgz_writes_only_the_selection() {
    let tgz = partly_listed_tgz(&[("first.txt", b"first")], &[("late/after.txt", b"after")]);
    let len = tgz.len() as u64;
    let mut x = start_selected(
        ArchivePlatform::MobileApp,
        crate::support::Recording::new(tgz),
        "t.tgz",
        Selection::Paths(vec!["first.txt".into()]),
        None,
        |_, r| panic!("{r:?}"),
    );
    let listed_reads = x.source_mut().bytes_read();
    let out = run(&mut x, |_, r| panic!("{r:?}"), vec![], |_, _| {});
    let summary = out.summary.unwrap();
    assert_eq!(summary.outcome, ExtractOutcome::Done);
    assert_eq!((summary.files_done, summary.files_total), (1, 1));
    assert_eq!(out.published.keys().cloned().collect::<Vec<_>>(), vec!["t/first.txt"]);
    let extract_reads = x.source_mut().bytes_read() - listed_reads;
    assert!(
        extract_reads < len / 2,
        "read {extract_reads} of {len} bytes to extract one small file"
    );
}

/// An entry past the listing goes into the folder the planner made for
/// its archive folder, even when the planner numbered that folder
/// (review finding).
#[test]
fn extract_tgz_tail_entry_joins_a_renamed_planned_folder() {
    let tgz = partly_listed_tgz(&[("a", b"file a"), ("a/y.txt", b"listed")], &[("a/x.txt", b"tail")]);
    let mut x = start_on(ArchivePlatform::MobileApp, Blocking(tgz), "t.tgz", None, |_, r| {
        panic!("{r:?}")
    });
    let out = run(&mut x, |_, r| panic!("{r:?}"), vec![], |_, _| {});
    assert_eq!(out.summary.unwrap().outcome, ExtractOutcome::Done);
    let mut names: Vec<_> = out.published.keys().cloned().collect();
    names.sort();
    assert_eq!(names, vec!["t/a", "t/a (2)/x.txt", "t/a (2)/y.txt", "t/big.bin"]);
}

/// A wrong password that passes entry `pass`'s check byte and fails entry
/// `fail`'s: found by a fixed search, so the same one every run.
fn quick_check_candidate(bytes: &[u8], pass: u32, fail: u32) -> String {
    use beebeeb_core::archives::PasswordStep;
    let mut session = ArchiveSession::open(Blocking(bytes.to_vec()), ArchivePlatform::Native);
    assert_eq!(drive(&mut session, |_, r| panic!("{r:?}")), SessionStep::Listed);
    let mut check =
        |index: u32, candidate: &str| session.check_password(index, &ArchivePassword::new(candidate.into()));
    (0..100_000)
        .map(|i| format!("candidate-{i}"))
        .find(|c| check(pass, c) == PasswordStep::Accepted && check(fail, c) == PasswordStep::Wrong)
        .expect("about one in 256 candidates passes one check byte and not the other")
}

#[test]
fn empty_zipcrypto_entry_never_proves_a_password() {
    // An empty ZipCrypto entry is guarded by its check byte alone (the CRC
    // of no data matches anything): a wrong password that passes it must
    // not count as proven, so the next protected entry asks again instead
    // of being skipped as "uses another password".
    let bytes = crate::support::fixture("zipcrypto-crc-check.zip");
    let wrong = quick_check_candidate(&bytes, 0, 1);
    let out = blocking_run(bytes, "c.zip", vec![&wrong, TEST_PASSWORD]);
    let asked: Vec<_> = out.log.iter().filter(|l| l.starts_with("password?")).cloned().collect();
    assert_eq!(
        asked,
        vec!["password? 0 wrong=false", "password? 1 wrong=true"],
        "{:?}",
        out.log
    );
    assert_eq!(out.published["c/secret.txt"], crate::support::fixture_secret());
    assert_eq!(out.published["c/empty.txt"], b"");
    assert!(out.summary.unwrap().skipped.is_empty());
}

#[test]
fn extract_tries_the_encoding_that_verified_first() {
    // The archive was made with the password's CP437 bytes; its UTF-8 bytes
    // pass the second entry's check byte too. Once the first entry verified
    // with CP437, the second must be read with CP437 first, not decoded as
    // garbage under UTF-8 and skipped as damaged.
    let bytes = crate::support::fixture("zipcrypto-cp437-quick-check.zip");
    let out = blocking_run(bytes, "q.zip", vec![crate::support::CP437_TEST_PASSWORD]);
    assert_eq!(out.published["q/first.txt"], b"First.\n".repeat(20), "{:?}", out.log);
    assert_eq!(out.published["q/second.txt"], b"Second.\n".repeat(20), "{:?}", out.log);
    assert!(out.summary.unwrap().skipped.is_empty());
}

#[test]
fn wrong_password_passing_quick_check_asks_again_and_retries_the_entry() {
    // The first protected entry, read with a wrong password that passed its
    // check byte, fails its CRC: its staged bytes are dropped, the person is
    // asked again, and the same entry is read again with the new password.
    let bytes = crate::support::fixture("zipcrypto-crc-check.zip");
    let wrong = quick_check_candidate(&bytes, 1, 0);
    let mut x = start_selected(
        ArchivePlatform::Native,
        Blocking(bytes),
        "r.zip",
        Selection::Paths(vec!["secret.txt".into()]),
        Some(&wrong),
        |_, r| panic!("{r:?}"),
    );
    let out = run(&mut x, |_, r| panic!("{r:?}"), vec![TEST_PASSWORD], |_, _| {});
    let summary = out.summary.unwrap();
    assert_eq!(
        out.published["r/secret.txt"],
        crate::support::fixture_secret(),
        "{:?}",
        out.log
    );
    assert_eq!((summary.files_done, summary.files_total), (1, 1));
    assert!(summary.skipped.is_empty(), "{:?}", summary.skipped);
    let begins = out.log.iter().filter(|l| l.starts_with("begin")).count();
    assert_eq!(begins, 2, "read once with each password: {:?}", out.log);
    assert!(out.log.contains(&"password? 1 wrong=true".to_string()), "{:?}", out.log);
}

#[test]
fn plaintext_steps_debug_shows_lengths_only() {
    use beebeeb_core::archives::PieceStep;
    let plaintext = b"the person's file".to_vec();
    let listed = format!("{:?}", plaintext);
    let piece = format!("{:?}", PieceStep::Data(plaintext.clone()));
    let step = format!(
        "{:?}",
        ExtractStep::FileData {
            node: 3,
            bytes: plaintext.clone()
        }
    );
    for shown in [&piece, &step] {
        assert!(!shown.contains(&listed), "{shown}");
        assert!(!shown.contains("person"), "{shown}");
        assert!(shown.contains("17 bytes"), "{shown}");
    }
    assert!(step.contains("node: 3"), "{step}");
}

#[test]
fn a_password_supplied_while_not_asked_for_is_dropped() {
    // A doubled or stale answer (no prompt open) must not replace the
    // password an open entry is read with: that entry would credit its
    // proof to the new password, and the next entry would be skipped as
    // "uses another password".
    let bytes = crate::support::fixture("zipcrypto-cp437-quick-check.zip");
    let mut x = start(
        Blocking(bytes),
        "q.zip",
        Some(crate::support::CP437_TEST_PASSWORD),
        |_, r| panic!("{r:?}"),
    );
    let mut supplied = false;
    let out = run(
        &mut x,
        |_, r| panic!("{r:?}"),
        vec![],
        |x, step| {
            if !supplied && matches!(step, ExtractStep::FileBegin { .. }) {
                supplied = true;
                x.supply_password(ArchivePassword::new("not-it".into()));
            }
        },
    );
    assert!(supplied);
    let summary = out.summary.unwrap();
    assert!(summary.skipped.is_empty(), "{:?} {:?}", summary.skipped, out.log);
    assert_eq!(out.published["q/first.txt"], b"First.\n".repeat(20));
    assert_eq!(out.published["q/second.txt"], b"Second.\n".repeat(20));
}
