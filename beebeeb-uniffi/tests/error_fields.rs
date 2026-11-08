//! A UniFFI error field named `message` collides with Kotlin's
//! `Exception.message`: the generated class declares `message` twice and the
//! Android binding does not compile. Both guards run in the default feature
//! set, so the workspace `cargo test` in CI runs them (the `legacy-bindings`
//! upload tests below stay behind their feature).

use std::path::{Path, PathBuf};

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
            assert!(
                declaration.trim_end().ends_with('{'),
                "unrecognized error enum layout: {declaration}"
            );
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

    assert!(
        checked >= 5,
        "expected at least five exported errors, checked {checked}"
    );
    assert!(
        offending.is_empty(),
        "UniFFI error fields collide with Kotlin Exception.message; use detail instead:\n{}",
        offending.join("\n")
    );
}

/// The generated Kotlin, both committed copies: no exception class has a
/// constructor property named `message`. Catches what the source scan cannot
/// see (an error derived through `cfg_attr`, a remote type) once the bindings
/// are regenerated.
#[test]
fn generated_kotlin_exceptions_never_declare_message() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let copies = [
        crate_dir.join("bindings/uniffi/beebeeb_uniffi/beebeeb_uniffi.kt"),
        crate_dir.join("../bindings/kotlin/uniffi/beebeeb_uniffi/beebeeb_uniffi.kt"),
    ];
    for copy in copies {
        let source = std::fs::read_to_string(&copy).unwrap_or_else(|e| panic!("{}: {e}", copy.display()));
        let families: Vec<&str> = source
            .lines()
            .filter_map(|line| line.strip_prefix("sealed class ")?.split_once(": kotlin.Exception()"))
            .map(|(name, _)| name.trim())
            .collect();
        assert!(
            families.len() >= 5,
            "{}: expected at least five exception families, found {families:?}",
            copy.display()
        );
        let mut variants = 0;
        let mut offending = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            let Some(family) = families
                .iter()
                .find(|f| line.trim_start().starts_with(&format!(") : {f}()")))
            else {
                continue;
            };
            let start = lines[..at]
                .iter()
                .rposition(|l| l.trim_start().starts_with("class "))
                .expect("a variant's constructor follows its class line");
            variants += 1;
            if lines[start..at].iter().any(|l| l.contains("`message`")) {
                offending.push(format!("{family}.{}", lines[start].trim()));
            }
        }
        assert!(
            variants >= 10,
            "{}: expected exception variants with fields, found {variants}",
            copy.display()
        );
        assert!(
            offending.is_empty(),
            "{}: exception fields named `message` collide with Kotlin Exception.message; use detail:\n{}",
            copy.display(),
            offending.join("\n")
        );
    }
}

#[cfg(feature = "legacy-bindings")]
mod upload {
    use beebeeb_uniffi::UploadError;

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
}
