//! The preview screen model (spec §5.3): one row of the state table per
//! test, plus rows, notes and platform differences.

use beebeeb_core::archives::{
    ActionKind, ArchiveEntry, ArchiveFormat, ArchiveListing, ArchivePlatform, ArchivePreviewModel, ArchiveRefusal,
    ArchiveTotals, DestinationInfo, DestinationKind, EntryCipher, EntryKind, ExtractOutcome, ExtractProgress,
    ExtractRequest, ExtractSummary, FailReason, ForeignFormat, ListingState, PreviewInput, PreviewState, Protection,
    Selection, SkipReason, archive_preview, entry_path, plan_extraction,
};
use beebeeb_core::name_clash::TakenNames;

const MIB: u64 = 1024 * 1024;

fn entry(i: u32, path: &str, kind: EntryKind, size: u64) -> ArchiveEntry {
    ArchiveEntry {
        index: i,
        display_path: path.into(),
        path: entry_path(path).ok(),
        kind,
        size,
        compressed_size: size,
        cipher: EntryCipher::None,
        modified: None,
        skip: entry_path(path).err(),
    }
}

fn listing(entries: Vec<ArchiveEntry>) -> ArchiveListing {
    let files = entries.iter().filter(|e| e.kind == EntryKind::File).count() as u32;
    let folders = entries.iter().filter(|e| e.kind == EntryKind::Folder).count() as u32;
    let bytes = entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| e.size)
        .sum();
    ArchiveListing {
        format: ArchiveFormat::Zip,
        entries,
        totals: ArchiveTotals {
            files,
            folders,
            bytes,
            compressed_bytes: bytes,
            skipped: 0,
        },
        protection: Protection::None,
        uses_zipcrypto: false,
        complete: true,
    }
}

fn sample() -> ArchiveListing {
    listing(vec![
        entry(0, "docs", EntryKind::Folder, 0),
        entry(1, "docs/report.pdf", EntryKind::File, 2 * MIB),
        entry(2, "photo.jpg", EntryKind::File, 1500),
        entry(3, "notes.txt", EntryKind::File, 12),
    ])
}

fn input<'a>(listing: ListingState<'a>) -> PreviewInput<'a> {
    PreviewInput {
        archive_name: "holiday.zip",
        listing,
        folder: &[],
        selection: &[],
        platform: ArchivePlatform::Browser,
        destination: DestinationKind::NextTo,
        password: None,
        progress: None,
        summary: None,
        plan: None,
    }
}

fn kinds(actions: &[beebeeb_core::archives::PreviewAction]) -> Vec<(ActionKind, String, bool)> {
    actions
        .iter()
        .map(|a| (a.kind, a.label.text.clone(), a.enabled))
        .collect()
}

fn texts(model: &ArchivePreviewModel) -> Vec<String> {
    model.notices.iter().map(|n| n.text.clone()).collect()
}

#[test]
fn preview_reading_state() {
    let model = archive_preview(&input(ListingState::Reading));
    assert_eq!(model.state, PreviewState::Reading);
    assert_eq!(model.title, "holiday.zip");
    assert_eq!(model.summary.unwrap().text, "Reading the archive\u{2026}");
    assert_eq!(kinds(&model.actions), vec![(ActionKind::Stop, "Stop".into(), true)]);
    assert!(model.rows.is_empty());
}

#[test]
fn preview_listed_actions_in_order() {
    let listing = sample();
    let model = archive_preview(&input(ListingState::Listed(&listing)));
    assert_eq!(model.state, PreviewState::Listed);
    assert_eq!(model.kind_label.unwrap().text, "ZIP archive");
    assert_eq!(model.summary.unwrap().text, "3 files, 1 folder \u{b7} 2.1 MB");
    assert_eq!(
        kinds(&model.actions),
        vec![(ActionKind::Extract, "Extract".into(), true)]
    );
    assert!(model.selection_actions.is_empty());
    let names: Vec<_> = model.rows.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["docs", "notes.txt", "photo.jpg"]);
    // One file selected: Extract 1 item, Download, Open.
    let selection = ["photo.jpg".to_string()];
    let mut one = input(ListingState::Listed(&listing));
    one.selection = &selection;
    let model = archive_preview(&one);
    assert_eq!(
        kinds(&model.selection_actions),
        vec![
            (ActionKind::ExtractSelected, "Extract 1 item".into(), true),
            (ActionKind::Download, "Download".into(), true),
            (ActionKind::Open, "Open".into(), true),
        ]
    );
    // Two selected: only Extract 2 items.
    let selection = ["photo.jpg".to_string(), "docs".to_string()];
    one.selection = &selection;
    assert_eq!(
        kinds(&archive_preview(&one).selection_actions),
        vec![(ActionKind::ExtractSelected, "Extract 2 items".into(), true)]
    );
    // Inside a folder, the breadcrumb and that folder's rows.
    let folder = ["docs".to_string()];
    let mut inside = input(ListingState::Listed(&listing));
    inside.folder = &folder;
    let model = archive_preview(&inside);
    assert_eq!(model.path, vec!["docs"]);
    assert_eq!(
        model.rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        vec!["report.pdf"]
    );
    assert_eq!(model.rows[0].size_label.as_deref(), Some("2.1 MB"));
}

#[test]
fn preview_backups_offers_extract_to() {
    let listing = sample();
    let mut backups = input(ListingState::Listed(&listing));
    backups.destination = DestinationKind::ChooseFolder; // the archive is under Backups
    assert_eq!(
        kinds(&archive_preview(&backups).actions),
        vec![(ActionKind::ExtractTo, "Extract to\u{2026}".into(), true)]
    );
}

#[test]
fn preview_read_only_offers_extract_to() {
    let listing = sample();
    let mut shared = input(ListingState::Listed(&listing));
    shared.destination = DestinationKind::ChooseFolder; // a folder the person cannot add to
    let model = archive_preview(&shared);
    assert_eq!(model.actions.len(), 1);
    assert_eq!(model.actions[0].kind, ActionKind::ExtractTo);
}

#[test]
fn preview_empty_disables_extract() {
    let empty = listing(vec![]);
    let model = archive_preview(&input(ListingState::Listed(&empty)));
    assert_eq!(model.summary.unwrap().text, "This archive is empty.");
    assert_eq!(
        kinds(&model.actions),
        vec![(ActionKind::Extract, "Extract".into(), false)]
    );
}

#[test]
fn preview_open_only_for_viewable_within_budget() {
    let rows = [
        (ArchivePlatform::MobileApp, 32 * MIB),
        (ArchivePlatform::Browser, 64 * MIB),
        (ArchivePlatform::Native, 256 * MIB),
    ];
    for (platform, budget) in rows {
        let listing = listing(vec![
            entry(0, "fits.jpg", EntryKind::File, budget),
            entry(1, "too-big.jpg", EntryKind::File, budget + 1),
            entry(2, "program.exe", EntryKind::File, 10),
        ]);
        let mut view = input(ListingState::Listed(&listing));
        view.platform = platform;
        let model = archive_preview(&view);
        let open: Vec<_> = model
            .rows
            .iter()
            .map(|r| (r.name.as_str(), r.actions.contains(&ActionKind::Open)))
            .collect();
        assert_eq!(
            open,
            vec![("fits.jpg", true), ("program.exe", false), ("too-big.jpg", false)],
            "{platform:?}"
        );
        assert!(
            model.rows.iter().all(|r| r.actions.contains(&ActionKind::Download)),
            "{platform:?}"
        );
    }
}

#[test]
fn preview_protection_notices() {
    let mut some = sample();
    some.entries[2].cipher = EntryCipher::Aes { bits: 256, ae: 2 };
    some.protection = Protection::Some;
    let model = archive_preview(&input(ListingState::Listed(&some)));
    assert_eq!(
        texts(&model),
        vec![
            "Some files in this archive are protected by a password.",
            "The password protects the files' contents, not their names."
        ]
    );
    assert!(model.rows.iter().find(|r| r.name == "photo.jpg").unwrap().locked);
    some.protection = Protection::All;
    assert_eq!(
        texts(&archive_preview(&input(ListingState::Listed(&some))))[0],
        "The files in this archive are protected by a password."
    );
}

#[test]
fn preview_zipcrypto_warning() {
    let mut weak = sample();
    weak.entries[3].cipher = EntryCipher::ZipCrypto;
    weak.protection = Protection::Some;
    weak.uses_zipcrypto = true;
    let notices = texts(&archive_preview(&input(ListingState::Listed(&weak))));
    assert!(notices.contains(
        &"This archive uses ZipCrypto, an old protection that can be broken without the password. Files you extract are stored with Beebeeb's own encryption.".to_string()
    ));
}

#[test]
fn preview_incomplete_listing_notice() {
    let mut partial = sample();
    partial.complete = false;
    partial.format = ArchiveFormat::TarGzip;
    let model = archive_preview(&input(ListingState::Listed(&partial)));
    assert_eq!(model.kind_label.as_ref().unwrap().text, "TAR archive, gzip-compressed");
    assert_eq!(
        texts(&model),
        vec!["This archive is too large to list here. Extract it to see all its files."]
    );
}

#[test]
fn preview_row_notes_for_every_skip_reason() {
    let reasons = [
        (SkipReason::Link, "Link, not extracted"),
        (SkipReason::Device, "Special file, not extracted"),
        (SkipReason::OutsideFolder, "Points outside the folder, not extracted"),
        (SkipReason::UnusableName, "Name can't be used, not extracted"),
        (
            SkipReason::Method("bzip2".into()),
            "Uses bzip2 compression, which Beebeeb can't open",
        ),
        (SkipReason::TooLarge, "Too large to extract here"),
        (SkipReason::Bomb, "Expands far more than a normal file, not extracted"),
        (SkipReason::MacResource, "macOS resource data, not extracted"),
        (SkipReason::Corrupt, "Damaged in the archive, not extracted"),
        (SkipReason::OtherPassword, "Uses a different password, not extracted"),
        (
            SkipReason::Unsupported("Sparse file".into()),
            "Sparse file, not extracted",
        ),
    ];
    let entries = reasons
        .iter()
        .enumerate()
        .map(|(i, (reason, _))| ArchiveEntry {
            skip: Some(reason.clone()),
            ..entry(i as u32, &format!("f{i:02}"), EntryKind::File, 1)
        })
        .collect();
    let listing = listing(entries);
    let model = archive_preview(&input(ListingState::Listed(&listing)));
    let notes: Vec<_> = model
        .rows
        .iter()
        .map(|r| r.note.as_ref().map(|n| n.text.as_str()))
        .collect();
    let expected: Vec<_> = reasons.iter().map(|(_, text)| Some(*text)).collect();
    assert_eq!(notes, expected);
    assert!(
        model.rows.iter().all(|r| r.actions.is_empty()),
        "a skipped entry offers nothing"
    );
    // An entry whose path points outside is still listed, at the top.
    let outside = listing_with_outside();
    let model = archive_preview(&input(ListingState::Listed(&outside)));
    assert_eq!(
        model.rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        vec!["../evil.sh", "ok.txt"]
    );
}

fn listing_with_outside() -> ArchiveListing {
    listing(vec![
        entry(0, "../evil.sh", EntryKind::File, 5),
        entry(1, "ok.txt", EntryKind::File, 2),
    ])
}

#[test]
fn preview_renamed_note_matches_plan() {
    let listing = listing(vec![
        entry(0, "README", EntryKind::File, 1),
        entry(1, "readme", EntryKind::File, 1),
    ]);
    let request = ExtractRequest {
        archive_name: "holiday.zip".into(),
        selection: Selection::All,
        destination: DestinationInfo {
            siblings: TakenNames::new(),
            backup_position: None,
            writable: true,
        },
        server_free_bytes: u64::MAX,
        device_free_bytes: None,
        platform: ArchivePlatform::Browser,
    };
    let plan = plan_extraction(&listing, &request).unwrap();
    let mut view = input(ListingState::Listed(&listing));
    view.plan = Some(&plan);
    let model = archive_preview(&view);
    let notes: Vec<_> = model
        .rows
        .iter()
        .map(|r| (r.name.as_str(), r.note.as_ref().map(|n| n.text.clone())))
        .collect();
    assert_eq!(
        notes,
        vec![
            ("README", None),
            ("readme", Some("Saved as \"readme (2)\"".to_string()))
        ]
    );
}

#[test]
fn preview_needs_password_wrong() {
    let listing = sample();
    let mut ask = input(ListingState::Listed(&listing));
    ask.password = Some(false);
    let model = archive_preview(&ask);
    assert_eq!(model.state, PreviewState::NeedsPassword { wrong: false });
    assert_eq!(model.summary.as_ref().unwrap().text, "Enter the archive's password");
    assert_eq!(
        texts(&model),
        vec!["\"holiday.zip\" is protected by a password. Beebeeb uses it on this device only and doesn't keep it."]
    );
    assert_eq!(
        kinds(&model.actions),
        vec![
            (ActionKind::Extract, "Extract".into(), true),
            (ActionKind::Cancel, "Cancel".into(), true)
        ]
    );
    ask.password = Some(true);
    let model = archive_preview(&ask);
    assert_eq!(model.state, PreviewState::NeedsPassword { wrong: true });
    assert_eq!(texts(&model)[1], "That password didn't work. Check it and try again.");
}

#[test]
fn preview_extracting_keep_open_only_mobile() {
    let listing = sample();
    let progress = ExtractProgress {
        files_done: 1,
        files_total: 3,
        bytes_done: 1500,
        bytes_total: 2 * MIB,
        current: "photo.jpg".into(),
    };
    for (platform, keep_open) in [
        (ArchivePlatform::MobileApp, true),
        (ArchivePlatform::Browser, false),
        (ArchivePlatform::Native, false),
    ] {
        let mut view = input(ListingState::Listed(&listing));
        view.platform = platform;
        view.progress = Some(&progress);
        let model = archive_preview(&view);
        assert_eq!(model.state, PreviewState::Extracting);
        assert_eq!(
            model.summary.as_ref().unwrap().text,
            "Extracting 1 of 3 files \u{b7} 1.5 KB of 2.1 MB"
        );
        assert_eq!(
            texts(&model) == vec!["Keep Beebeeb open until extraction finishes."],
            keep_open,
            "{platform:?}"
        );
        assert_eq!(kinds(&model.actions), vec![(ActionKind::Stop, "Stop".into(), true)]);
    }
}

#[test]
fn preview_finished_states_words() {
    let listing = sample();
    let summary = |outcome, skipped: Vec<(String, SkipReason)>, renamed: Vec<(String, String)>| ExtractSummary {
        outcome,
        target_name: "holiday".into(),
        files_done: 2,
        files_total: 3,
        skipped,
        renamed,
    };
    let rows = [
        (
            summary(ExtractOutcome::Done, vec![], vec![]),
            "Extracted 2 files to \"holiday\".",
            vec![ActionKind::OpenFolder],
        ),
        (
            summary(
                ExtractOutcome::Done,
                vec![("link".into(), SkipReason::Link)],
                vec![("readme".into(), "readme (2)".into())],
            ),
            "Extracted 2 files to \"holiday\". 1 was not extracted; the list says why.",
            vec![ActionKind::OpenFolder],
        ),
        (
            summary(ExtractOutcome::Stopped, vec![], vec![]),
            "Extraction stopped. 2 of 3 files are in \"holiday\"; the rest were not extracted.",
            vec![ActionKind::OpenFolder, ActionKind::MoveToTrash],
        ),
        (
            summary(ExtractOutcome::Failed(FailReason::StorageFull), vec![], vec![]),
            "Your storage is full. 2 of 3 files were extracted to \"holiday\".",
            vec![ActionKind::OpenFolder, ActionKind::MoveToTrash],
        ),
        (
            summary(ExtractOutcome::Failed(FailReason::Network), vec![], vec![]),
            "The connection was lost. 2 of 3 files were extracted to \"holiday\".",
            vec![ActionKind::OpenFolder, ActionKind::MoveToTrash],
        ),
        (
            summary(ExtractOutcome::Failed(FailReason::Damaged), vec![], vec![]),
            "The archive is damaged after 2 of 3 files. Those files are in \"holiday\".",
            vec![ActionKind::OpenFolder, ActionKind::MoveToTrash],
        ),
        (
            summary(ExtractOutcome::Failed(FailReason::Changed), vec![], vec![]),
            "The archive changed while it was being extracted. 2 of 3 files are in \"holiday\". Open it again to extract the new version.",
            vec![ActionKind::OpenFolder, ActionKind::MoveToTrash],
        ),
        (
            summary(ExtractOutcome::Failed(FailReason::AccountBlocked), vec![], vec![]),
            "Extraction stopped. 2 of 3 files are in \"holiday\"; the rest were not extracted.",
            vec![ActionKind::OpenFolder, ActionKind::MoveToTrash],
        ),
    ];
    for (summary, text, actions) in rows {
        let mut view = input(ListingState::Listed(&listing));
        view.summary = Some(&summary);
        let model = archive_preview(&view);
        assert_eq!(model.state, PreviewState::Finished);
        assert_eq!(model.summary.as_ref().unwrap().text, text);
        assert_eq!(
            model.actions.iter().map(|a| a.kind).collect::<Vec<_>>(),
            actions,
            "{text}"
        );
        // The skipped list is the rows, each with its note.
        assert_eq!(model.rows.len(), summary.skipped.len());
        if !summary.renamed.is_empty() {
            assert_eq!(
                texts(&model),
                vec!["1 file had the same name as another file and was renamed."]
            );
        }
    }
}

#[test]
fn preview_refused_offers_download() {
    let rows = [
        (
            ArchiveRefusal::Foreign(ForeignFormat::Rar),
            "This is a RAR archive. Beebeeb opens ZIP, TAR, TGZ and GZ files.",
        ),
        (
            ArchiveRefusal::Truncated,
            "This archive ends too early. It may not have finished uploading.",
        ),
        (
            ArchiveRefusal::NotAnArchive,
            "This file isn't an archive Beebeeb can open. Beebeeb opens ZIP, TAR, TGZ and GZ files.",
        ),
    ];
    for (refusal, text) in rows {
        let model = archive_preview(&input(ListingState::Refused(refusal)));
        assert_eq!(model.state, PreviewState::Refused);
        assert_eq!(model.summary.unwrap().text, text);
        assert_eq!(
            kinds(&model.actions),
            vec![(ActionKind::Download, "Download".into(), true)]
        );
    }
}
