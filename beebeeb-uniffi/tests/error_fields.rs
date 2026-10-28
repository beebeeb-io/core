use std::path::{Path, PathBuf};

use beebeeb_uniffi::UploadError;

fn rust_sources(dir: &Path, paths: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, paths);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            paths.push(path);
        }
    }
}

#[test]
fn exported_errors_never_have_message_fields() {
    let mut paths = Vec::new();
    rust_sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut paths);
    paths.sort();
    let mut checked = 0;
    let mut offending = Vec::new();

    for path in paths {
        let source = std::fs::read_to_string(&path).unwrap();
        for item in source.split("#[derive(").skip(1) {
            let (derive, item) = item.split_once(")]").expect("unterminated derive attribute");
            let derive: String = derive.chars().filter(|c| !c.is_whitespace()).collect();
            if !derive.split(',').any(|name| name == "uniffi::Error") {
                continue;
            }

            let mut lines = item.lines();
            let declaration = lines
                .find(|line| {
                    let line = line.trim_start();
                    line.starts_with("pub enum ") || line.starts_with("enum ")
                })
                .expect("UniFFI error must declare an enum");
            let indent = &declaration[..declaration.len() - declaration.trim_start().len()];
            let closing = format!("{indent}}}");
            // Source guard for rustfmt's enum layout. Require the closing line
            // so a changed layout cannot silently turn the check into a no-op.
            assert!(declaration.trim_end().ends_with('{'), "unrecognized error enum layout: {declaration}");
            let mut body = String::new();
            let mut closed = false;
            for line in lines {
                if line.trim_end() == closing {
                    closed = true;
                    break;
                }
                let line = line.trim();
                if !line.starts_with('#') && !line.starts_with("//") {
                    body.push_str(line);
                    body.push(' ');
                }
            }
            assert!(closed, "unrecognized error enum layout: {declaration}");
            checked += 1;
            for field in body.split(['{', '}', ',']) {
                if let Some((name, _)) = field.split_once(':')
                    && matches!(name.trim(), "message" | "r#message")
                {
                    offending.push(format!("{}: {declaration}: {}", path.display(), field.trim()));
                }
            }
        }
    }

    assert!(checked >= 5, "expected at least five exported errors, checked {checked}");
    assert!(
        offending.is_empty(),
        "UniFFI error fields collide with Kotlin Exception.message; use detail instead:\n{}",
        offending.join("\n")
    );
}

#[test]
fn upload_server_error_preserves_status_and_display() {
    let error = UploadError::from(beebeeb_upload::UploadError::ServerError {
        status: 503,
        message: "upstream unavailable".into(),
    });
    assert!(matches!(error, UploadError::ServerError { status: 503, .. }));
    assert_eq!(error.to_string(), "server error (HTTP 503): upstream unavailable");
}

#[test]
fn upload_client_error_preserves_status_and_display() {
    let error = UploadError::from(beebeeb_upload::UploadError::ClientError {
        status: 400,
        message: "invalid request".into(),
    });
    assert!(matches!(error, UploadError::ClientError { status: 400, .. }));
    assert_eq!(error.to_string(), "client error (HTTP 400): invalid request");
}
