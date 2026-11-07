//! Entry names and paths (spec §6.1): decode, NFC, path rules, zip-slip.

use beebeeb_core::archives::{RawName, SkipReason, decode_name, entry_path};

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    crc.sum()
}

fn zip(raw: &[u8], utf8_flag: bool) -> String {
    decode_name(RawName::Zip {
        raw,
        utf8_flag,
        unicode_path: None,
    })
}

fn components(decoded: &str) -> Vec<String> {
    entry_path(decoded)
        .unwrap_or_else(|r| panic!("{decoded:?} refused: {r:?}"))
        .components
}

#[test]
fn names_utf8_flag() {
    assert_eq!(zip("résumé/€.txt".as_bytes(), true), "résumé/€.txt");
    // With the flag, bytes that are also CP437 text are still read as UTF-8.
    assert_eq!(zip(b"caf\xC3\xA9", true), "café");
}

#[test]
fn names_utf8_flag_invalid_bytes_unusable() {
    let decoded = zip(b"bad\xFF\xFEname.txt", true);
    assert!(decoded.contains('\u{FFFD}'), "{decoded:?}");
    assert_eq!(entry_path(&decoded), Err(SkipReason::UnusableName));
}

#[test]
fn names_unicode_path_extra_wins_when_crc_matches() {
    let raw = b"caf\x82.txt"; // CP437 "café.txt"
    let unicode = "café-unicode.txt".as_bytes();
    let decoded = decode_name(RawName::Zip {
        raw,
        utf8_flag: false,
        unicode_path: Some((crc32(raw), unicode)),
    });
    assert_eq!(decoded, "café-unicode.txt");
}

#[test]
fn names_unicode_path_extra_ignored_on_crc_mismatch() {
    let raw = b"caf\x82.txt";
    let unicode = "renamed-elsewhere.txt".as_bytes();
    let decoded = decode_name(RawName::Zip {
        raw,
        utf8_flag: false,
        unicode_path: Some((crc32(raw) ^ 1, unicode)),
    });
    assert_eq!(decoded, "café.txt");
}

#[test]
fn names_unflagged_valid_utf8_is_utf8() {
    // Older macOS wrote UTF-8 without setting bit 11.
    assert_eq!(zip("naïve/日本.txt".as_bytes(), false), "naïve/日本.txt");
    assert_eq!(zip(b"plain-ascii.txt", false), "plain-ascii.txt");
}

#[test]
fn names_unflagged_cp437() {
    assert_eq!(zip(b"\x82", false), "é");
    assert_eq!(zip(b"Gr\x81\xE1e \x9C5.txt", false), "Grüße £5.txt");
    assert_eq!(zip(b"\xFF", false), "\u{a0}");
}

#[test]
fn names_tar_pax_path_wins() {
    let decoded = decode_name(RawName::Tar {
        pax_path: Some("long/pax/päth.txt".as_bytes()),
        gnu_long: Some(b"gnu/long.txt\0"),
        prefix: b"pre\0\0\0",
        name: b"short.txt\0\0\0",
    });
    assert_eq!(decoded, "long/pax/päth.txt");
    let gnu = decode_name(RawName::Tar {
        pax_path: None,
        gnu_long: Some(b"gnu/long.txt\0"),
        prefix: b"",
        name: b"x\0",
    });
    assert_eq!(gnu, "gnu/long.txt");
    let ustar = decode_name(RawName::Tar {
        pax_path: None,
        gnu_long: None,
        prefix: b"pre/fix\0\0",
        name: b"name.txt\0\0",
    });
    assert_eq!(ustar, "pre/fix/name.txt");
}

#[test]
fn names_tar_latin1_fallback() {
    let decoded = decode_name(RawName::Tar {
        pax_path: None,
        gnu_long: None,
        prefix: b"",
        name: b"caf\xE9.txt\0",
    });
    assert_eq!(decoded, "café.txt");
}

#[test]
fn names_nfc() {
    let nfd = "cafe\u{301}.txt";
    let decoded = zip(nfd.as_bytes(), true);
    assert_eq!(decoded, "caf\u{e9}.txt");
    assert_eq!(components(&decoded), vec!["caf\u{e9}.txt"]);
}

#[test]
fn names_nul_is_unusable() {
    assert_eq!(entry_path("a\0b.txt"), Err(SkipReason::UnusableName));
    assert_eq!(entry_path("dir/evil.txt\0.jpg"), Err(SkipReason::UnusableName));
}

#[test]
fn names_control_char_is_unusable() {
    assert_eq!(entry_path("a\nb"), Err(SkipReason::UnusableName));
    assert_eq!(entry_path("dir/\u{1b}[31mred"), Err(SkipReason::UnusableName));
    assert_eq!(entry_path("c1\u{85}x"), Err(SkipReason::UnusableName));
}

#[test]
fn names_backslash_splits() {
    assert_eq!(components("a\\b.txt"), vec!["a", "b.txt"]);
    assert_eq!(components("a/b\\c/d.txt"), vec!["a", "b", "c", "d.txt"]);
}

#[test]
fn names_absolute_made_relative() {
    assert_eq!(components("/etc/x"), vec!["etc", "x"]);
    assert_eq!(components("\\etc\\x"), vec!["etc", "x"]);
}

#[test]
fn names_drive_prefix_removed() {
    assert_eq!(components("C:\\x"), vec!["x"]);
    assert_eq!(components("d:/dir/x.txt"), vec!["dir", "x.txt"]);
    assert_eq!(components("C:x"), vec!["x"]);
}

#[test]
fn names_unc_prefix_removed() {
    assert_eq!(components("\\\\server\\share\\x"), vec!["x"]);
    assert_eq!(components("//server/share/dir/x"), vec!["dir", "x"]);
}

#[test]
fn names_dotdot_is_outside() {
    for path in [
        "../x",
        "a/../../x",
        "..\\x",
        "a/..",
        "..",
        "a\\..\\..\\..\\x",
        "/../x",
        "C:\\..\\x",
    ] {
        assert_eq!(entry_path(path), Err(SkipReason::OutsideFolder), "{path:?}");
    }
    // Four dots is a name, not a parent; it is rewritten for Windows.
    assert_eq!(components("....//x"), vec!["____", "x"]);
}

#[test]
fn names_dot_and_empty_dropped() {
    assert_eq!(components("./a//b/./c.txt"), vec!["a", "b", "c.txt"]);
    assert_eq!(components("folder/"), vec!["folder"]);
    assert_eq!(entry_path("./"), Err(SkipReason::UnusableName));
    assert_eq!(entry_path("/"), Err(SkipReason::UnusableName));
}

#[test]
fn names_reserved_device_prefixed() {
    assert_eq!(components("CON.txt"), vec!["_CON.txt"]);
    assert_eq!(components("dir/COM\u{b9}"), vec!["dir", "_COM\u{b9}"]);
    assert_eq!(components("what?.txt"), vec!["what_.txt"]);
    assert_eq!(components("trailing. "), vec!["trailing__"]);
}

#[test]
fn names_component_256_bytes_unusable() {
    let ok = "a".repeat(255);
    assert_eq!(components(&ok), vec![ok.clone()]);
    assert_eq!(entry_path(&"a".repeat(256)), Err(SkipReason::UnusableName));
    assert_eq!(
        entry_path(&format!("dir/{}", "é".repeat(128))),
        Err(SkipReason::UnusableName)
    );
}

#[test]
fn names_depth_65_unusable() {
    let deep64 = vec!["d"; 64].join("/");
    assert_eq!(components(&deep64).len(), 64);
    let deep65 = vec!["d"; 65].join("/");
    assert_eq!(entry_path(&deep65), Err(SkipReason::UnusableName));
}

#[test]
fn names_path_4097_bytes_unusable() {
    let mut parts = vec!["p".repeat(240); 16];
    parts.push("q".repeat(240));
    let exactly_4096 = parts.join("/");
    assert_eq!(exactly_4096.len(), 4096);
    assert_eq!(components(&exactly_4096).len(), 17);
    parts.pop();
    parts.push("q".repeat(241));
    let over = parts.join("/");
    assert_eq!(over.len(), 4097);
    assert_eq!(entry_path(&over), Err(SkipReason::UnusableName));
}

#[test]
fn names_macosx_is_mac_resource() {
    assert_eq!(entry_path("__MACOSX/._photo.jpg"), Err(SkipReason::MacResource));
    assert_eq!(entry_path("__MACOSX/"), Err(SkipReason::MacResource));
    assert_eq!(entry_path("__MACOSX/dir/._a"), Err(SkipReason::MacResource));
    // Only the top-level folder is macOS's resource tree.
    assert_eq!(components("dir/__MACOSX"), vec!["dir", "__MACOSX"]);
}

#[test]
fn undecodable_name_never_fails_the_listing() {
    // Shift-JIS "テスト.txt" with no UTF-8 flag: not UTF-8, shown as CP437.
    let sjis = b"\x83\x65\x83\x58\x83\x67.txt";
    let decoded = zip(sjis, false);
    assert_eq!(decoded, "âeâXâg.txt");
    assert_eq!(components(&decoded), vec!["âeâXâg.txt"]);
    // A lone surrogate in a pax path (invalid UTF-8) falls back to
    // ISO-8859-1: a name, never an error; its C1 control makes it unusable.
    let surrogate = decode_name(RawName::Tar {
        pax_path: Some(b"bad\xED\xA0\x80.txt"),
        gnu_long: None,
        prefix: b"",
        name: b"x\0",
    });
    assert_eq!(surrogate, "bad\u{ed}\u{a0}\u{80}.txt");
    assert_eq!(entry_path(&surrogate), Err(SkipReason::UnusableName));
}
