//! The extraction planner (spec §5.2): destination, names and clashes,
//! skips, limits, quota and Backups, decided before anything is written.

use beebeeb_core::archives::{
    ArchiveEntry, ArchiveFormat, ArchiveListing, ArchivePlatform, ArchiveTotals, DestinationInfo, EntryCipher,
    EntryKind, ExtractRequest, ExtractionPlan, NodeKind, PlanRefusal, PlanTarget, Protection, Selection, SkipReason,
    destination_stem, entry_path, plan_extraction,
};
use beebeeb_core::backup::BackupPosition;
use beebeeb_core::name_clash::TakenNames;

const GIB: u64 = 1024 * 1024 * 1024;

/// A listing from `(path, kind, size, skip)` rows, in archive order.
fn listing(format: ArchiveFormat, rows: &[(&str, EntryKind, u64, Option<SkipReason>)]) -> ArchiveListing {
    let entries = rows
        .iter()
        .enumerate()
        .map(|(i, (path, kind, size, skip))| ArchiveEntry {
            index: i as u32,
            display_path: path.to_string(),
            path: entry_path(path).ok(),
            kind: *kind,
            size: *size,
            compressed_size: *size,
            cipher: EntryCipher::None,
            modified: None,
            skip: skip.clone().or_else(|| entry_path(path).err()),
        })
        .collect();
    ArchiveListing {
        format,
        entries,
        totals: ArchiveTotals::default(),
        protection: Protection::None,
        uses_zipcrypto: false,
        complete: true,
    }
}

fn files(paths: &[&str]) -> ArchiveListing {
    let rows: Vec<_> = paths.iter().map(|p| (*p, EntryKind::File, 10u64, None)).collect();
    listing(ArchiveFormat::Zip, &rows)
}

fn request(name: &str) -> ExtractRequest {
    ExtractRequest {
        archive_name: name.to_string(),
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

/// Every node as `parent-name/name`, the target's children first-level.
fn tree(plan: &ExtractionPlan) -> Vec<String> {
    let name_of = |id: u32| plan.nodes.iter().find(|n| n.id == id).unwrap();
    plan.nodes
        .iter()
        .map(|node| {
            let mut parts = vec![node.name.clone()];
            let mut parent = node.parent;
            while let Some(id) = parent {
                let p = name_of(id);
                parts.push(p.name.clone());
                parent = p.parent;
            }
            parts.reverse();
            parts.join("/")
        })
        .collect()
}

#[test]
fn plan_destination_stem() {
    let rows = [
        ("photos.zip", "photos"),
        ("src.tar.gz", "src"),
        ("data.TGZ", "data"),
        ("a.tar", "a"),
        (".zip", "Archive"),
        ("x.gz", "x"),
        ("notes.txt.gz", "notes.txt"),
        ("...", "Archive"),
        ("release.v2.zip", "release.v2"),
    ];
    for (name, stem) in rows {
        assert_eq!(destination_stem(name), stem, "{name}");
    }
}

#[test]
fn plan_destination_clash_numbered() {
    let mut req = request("photos.zip");
    req.destination.siblings.insert("Photos");
    let plan = plan_extraction(&files(&["a.jpg"]), &req).unwrap();
    assert_eq!(plan.target, PlanTarget::Folder(0));
    assert_eq!(tree(&plan), vec!["photos (2)", "photos (2)/a.jpg"]);
}

#[test]
fn plan_gz_single_file_target_is_file() {
    let gz = listing(ArchiveFormat::Gzip, &[("notes.txt", EntryKind::File, 11, None)]);
    let plan = plan_extraction(&gz, &request("notes.txt.gz")).unwrap();
    assert_eq!(plan.target, PlanTarget::File(0));
    assert_eq!(plan.nodes.len(), 1);
    assert_eq!(
        (plan.nodes[0].name.as_str(), plan.nodes[0].kind, plan.nodes[0].entry),
        ("notes.txt", NodeKind::File, Some(0))
    );
    let mut taken = request("notes.txt.gz");
    taken.destination.siblings.insert("notes.txt");
    assert_eq!(plan_extraction(&gz, &taken).unwrap().nodes[0].name, "notes (2).txt");
}

#[test]
fn plan_duplicate_entries_numbered() {
    let plan = plan_extraction(&files(&["x.txt", "x.txt", "x.txt"]), &request("d.zip")).unwrap();
    assert_eq!(tree(&plan), vec!["d", "d/x.txt", "d/x (2).txt", "d/x (3).txt"]);
    assert_eq!(
        plan.renamed,
        vec![(1, "x (2).txt".to_string()), (2, "x (3).txt".to_string())]
    );
}

#[test]
fn plan_case_variant_numbered() {
    let plan = plan_extraction(
        &files(&["README", "readme", "Cafe\u{301}", "Caf\u{e9}"]),
        &request("d.zip"),
    )
    .unwrap();
    assert_eq!(
        tree(&plan),
        vec!["d", "d/README", "d/readme (2)", "d/Cafe\u{301}", "d/Caf\u{e9} (2)"]
    );
}

#[test]
fn plan_file_then_folder_same_name() {
    let rows = [("a", EntryKind::File, 1, None), ("a/b.txt", EntryKind::File, 1, None)];
    let plan = plan_extraction(&listing(ArchiveFormat::Zip, &rows), &request("d.zip")).unwrap();
    assert_eq!(tree(&plan), vec!["d", "d/a", "d/a (2)", "d/a (2)/b.txt"]);
    let kinds: Vec<_> = plan.nodes.iter().map(|n| n.kind).collect();
    assert_eq!(
        kinds,
        vec![NodeKind::Folder, NodeKind::File, NodeKind::Folder, NodeKind::File]
    );
}

#[test]
fn plan_skips_carry_reasons() {
    let rows = [
        ("ok.txt", EntryKind::File, 1, None),
        ("link", EntryKind::Symlink, 0, Some(SkipReason::Link)),
        ("../evil", EntryKind::File, 1, None),
        ("dev", EntryKind::Device, 0, Some(SkipReason::Device)),
    ];
    let plan = plan_extraction(&listing(ArchiveFormat::Tar, &rows), &request("t.tar")).unwrap();
    assert_eq!(tree(&plan), vec!["t", "t/ok.txt"]);
    assert_eq!(
        plan.skipped,
        vec![
            (1, SkipReason::Link),
            (2, SkipReason::OutsideFolder),
            (3, SkipReason::Device)
        ]
    );
    assert_eq!(plan.totals.skipped, 3);
    assert_eq!(plan.totals.files, 1);
}

#[test]
fn plan_macosx_counted() {
    let plan = plan_extraction(&files(&["photo.jpg", "__MACOSX/._photo.jpg"]), &request("p.zip")).unwrap();
    assert_eq!(plan.skipped, vec![(1, SkipReason::MacResource)]);
    assert_eq!(tree(&plan), vec!["p", "p/photo.jpg"]);
}

#[test]
fn plan_refuses_over_quota() {
    let mut req = request("d.zip");
    req.server_free_bytes = 100;
    let refusal = plan_extraction(
        &listing(ArchiveFormat::Zip, &[("big", EntryKind::File, 1000, None)]),
        &req,
    );
    assert_eq!(
        refusal,
        Err(PlanRefusal::Quota {
            needed: 1028,
            free: 100
        })
    );
}

#[test]
fn plan_refuses_device_space() {
    let mut req = request("d.zip");
    req.device_free_bytes = Some(500);
    let rows = [("a", EntryKind::File, 400, None), ("b", EntryKind::File, 1000, None)];
    assert_eq!(
        plan_extraction(&listing(ArchiveFormat::Zip, &rows), &req),
        Err(PlanRefusal::DeviceSpace {
            needed: 1000,
            free: 500
        })
    );
    req.device_free_bytes = Some(1000);
    assert!(plan_extraction(&listing(ArchiveFormat::Zip, &rows), &req).is_ok());
}

#[test]
fn plan_refuses_backups_destination() {
    let mut refused = 0;
    for position in BackupPosition::ALL {
        let mut req = request("d.zip");
        req.destination.backup_position = Some(position);
        let result = plan_extraction(&files(&["a"]), &req);
        if position == BackupPosition::Outside {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(PlanRefusal::Backups), "{position:?}");
            refused += 1;
        }
    }
    assert_eq!(refused, 5);
}

#[test]
fn plan_refuses_read_only() {
    let mut req = request("d.zip");
    req.destination.writable = false;
    assert_eq!(plan_extraction(&files(&["a"]), &req), Err(PlanRefusal::ReadOnlyFolder));
}

#[test]
fn plan_refuses_over_100k() {
    let names: Vec<String> = (0..100_001).map(|i| format!("f{i}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    assert_eq!(
        plan_extraction(&files(&refs), &request("d.zip")),
        Err(PlanRefusal::TooMany)
    );
    assert!(plan_extraction(&files(&refs[..99_999]), &request("d.zip")).is_ok());
}

#[test]
fn plan_refuses_total_over_256_gib() {
    let rows: Vec<_> = (0..5).map(|_| ("part", EntryKind::File, 60 * GIB, None)).collect();
    let refusal = plan_extraction(&listing(ArchiveFormat::Zip, &rows), &request("d.zip"));
    assert_eq!(refusal, Err(PlanRefusal::TooLarge { total: 300 * GIB }));
}

#[test]
fn plan_web_entries_over_2_gib_skipped_with_notice() {
    let rows = [
        ("big.iso", EntryKind::File, 3 * GIB, None),
        ("small.txt", EntryKind::File, 5, None),
    ];
    let mut req = request("d.zip");
    req.platform = ArchivePlatform::Browser;
    let plan = plan_extraction(&listing(ArchiveFormat::Zip, &rows), &req).unwrap();
    assert_eq!(plan.skipped, vec![(0, SkipReason::TooLarge)]);
    assert_eq!(tree(&plan), vec!["d", "d/small.txt"]);
    let notice = plan
        .notices
        .iter()
        .find(|n| n.key == "refuse_web_entry_too_large")
        .expect("the notice");
    assert_eq!(
        notice.text,
        "1 file is larger than 2.1 GB, more than the browser can extract. Extract the rest here, or use the Beebeeb app or bb extract for all of them."
    );
    req.platform = ArchivePlatform::Native;
    let native = plan_extraction(&listing(ArchiveFormat::Zip, &rows), &req).unwrap();
    assert!(native.skipped.is_empty() && native.notices.is_empty());
}

#[test]
fn plan_selection_keeps_parent_folders() {
    let rows = [
        ("top.txt", EntryKind::File, 1, None),
        ("dir/sub/a.txt", EntryKind::File, 1, None),
        ("dir/sub/b.txt", EntryKind::File, 1, None),
        ("dir/other/c.txt", EntryKind::File, 1, None),
    ];
    let mut req = request("d.zip");
    req.selection = Selection::Paths(vec!["dir/sub/a.txt".into(), "dir/other".into()]);
    let plan = plan_extraction(&listing(ArchiveFormat::Zip, &rows), &req).unwrap();
    assert_eq!(
        tree(&plan),
        vec![
            "d",
            "d/dir",
            "d/dir/sub",
            "d/dir/sub/a.txt",
            "d/dir/other",
            "d/dir/other/c.txt"
        ]
    );
    req.selection = Selection::Paths(vec!["nothing/here".into()]);
    assert_eq!(
        plan_extraction(&listing(ArchiveFormat::Zip, &rows), &req),
        Err(PlanRefusal::Empty)
    );
}

#[test]
fn plan_quota_uses_ciphertext_size() {
    let rows = [("f", EntryKind::File, 10_000, None)];
    let mut req = request("d.zip");
    req.server_free_bytes = 10_000;
    assert_eq!(
        plan_extraction(&listing(ArchiveFormat::Zip, &rows), &req),
        Err(PlanRefusal::Quota {
            needed: 10_028,
            free: 10_000
        })
    );
    req.server_free_bytes = 10_028;
    assert!(plan_extraction(&listing(ArchiveFormat::Zip, &rows), &req).is_ok());
    // An empty archive refuses as empty.
    assert_eq!(plan_extraction(&files(&[]), &request("e.zip")), Err(PlanRefusal::Empty));
}
