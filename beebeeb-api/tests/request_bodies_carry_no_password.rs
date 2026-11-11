//! An account password is proved with OPAQUE and never sent. Two scans of the
//! sources keep it out of request bodies:
//!
//! - no `Serialize` type of this crate declares a password field;
//! - no production source of `beebeeb-core` or `beebeeb-client` names a
//!   password as a JSON key (the sans-IO flows build their bodies with `json!`).
//!
//! What they do not see: a field renamed with `#[serde(rename)]`, a derive
//! split over several lines or behind `cfg_attr`, a hand-written `Serialize`,
//! and a body built in another crate. None of these forms is used for a
//! request today.

use std::path::{Path, PathBuf};

/// Names that put an account password in a request body.
const PASSWORD_FIELDS: [&str; 4] = ["password", "current_password", "new_password", "old_password"];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("source directory must be readable") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn derives_serialize(attribute: &str) -> bool {
    let Some(list) = attribute
        .trim()
        .strip_prefix("#[derive(")
        .and_then(|rest| rest.strip_suffix(")]"))
    else {
        return false;
    };
    list.split(',')
        .map(str::trim)
        .any(|item| item == "Serialize" || item.ends_with("::Serialize"))
}

fn declared_name(line: &str) -> Option<&str> {
    let declaration = line
        .trim_start()
        .trim_start_matches("pub(crate) ")
        .trim_start_matches("pub ");
    let rest = declaration
        .strip_prefix("struct ")
        .or_else(|| declaration.strip_prefix("enum "))?;
    Some(
        rest.split(|c: char| !c.is_alphanumeric() && c != '_')
            .next()
            .unwrap_or(""),
    )
}

fn field_name(line: &str) -> Option<&str> {
    let field = line
        .trim_start()
        .trim_start_matches("pub(crate) ")
        .trim_start_matches("pub ");
    let (name, _) = field.split_once(':')?;
    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')).then_some(name)
}

/// The `Serialize` types of one source file, each with the password fields it declares.
fn serialised_types(source: &str) -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    let mut serialised = false;
    let mut open: Option<(String, Vec<String>)> = None;
    for line in source.lines() {
        if let Some((_, fields)) = open.as_mut() {
            if line == "}" {
                found.extend(open.take());
            } else if let Some(name) = field_name(line) {
                if PASSWORD_FIELDS.contains(&name) {
                    fields.push(name.to_owned());
                }
            }
            continue;
        }
        if line.trim_start().starts_with("#[derive(") {
            serialised = derives_serialize(line);
        } else if let Some(name) = declared_name(line) {
            if serialised && line.trim_end().ends_with('{') {
                open = Some((name.to_owned(), Vec::new()));
            }
            serialised = false;
        } else if !line.trim_start().starts_with("#[") && !line.trim_start().starts_with("///") {
            serialised = false;
        }
    }
    found
}

#[test]
fn no_request_type_carries_an_account_password() {
    let mut files = Vec::new();
    rust_sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    let mut request_types = 0;
    let mut offenders = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("source file must be readable");
        for (name, fields) in serialised_types(&source) {
            request_types += 1;
            if !fields.is_empty() {
                offenders.push(format!("{}: {name} {{ {} }}", file.display(), fields.join(", ")));
            }
        }
    }
    assert!(
        request_types >= 60,
        "the scan saw only {request_types} Serialize types in {} files",
        files.len()
    );
    assert!(
        offenders.is_empty(),
        "request types with an account password field:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_scan_reports_a_password_field_and_ignores_answers() {
    let source = "\
#[derive(Clone, Serialize)]
pub struct Bad {
    pub email: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub password: Rules,
}

#[derive(Serialize)]
#[serde(rename_all = \"snake_case\")]
pub(crate) enum AlsoBad {
    Change {
        password: String,
    },
}
";
    assert_eq!(
        serialised_types(source),
        vec![
            ("Bad".to_owned(), vec!["new_password".to_owned()]),
            ("AlsoBad".to_owned(), vec!["password".to_owned()]),
        ]
    );
}

/// A source file's code before its inline test module, if it has one.
fn production_part(source: &str) -> &str {
    let mut offset = 0;
    let mut lines = source.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        if line.trim() == "#[cfg(test)]" && lines.peek().is_some_and(|next| next.trim_start().starts_with("mod ")) {
            return &source[..offset];
        }
        offset += line.len();
    }
    source
}

/// The lines (1-based) on which a password is named as a JSON key: `"password":`.
fn password_keys(source: &str) -> Vec<usize> {
    let mut found = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let names_one = PASSWORD_FIELDS.iter().any(|name| {
            let key = format!("\"{name}\"");
            line.match_indices(&key)
                .any(|(at, _)| line[at + key.len()..].trim_start().starts_with(':'))
        });
        if names_one {
            found.push(index + 1);
        }
    }
    found
}

fn is_test_source(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let in_test_directory = path
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|component| component.as_os_str().to_str())
        .any(|part| part == "bin" || part == "tests" || part.starts_with("tests_"));
    in_test_directory
        || name == "tests.rs"
        || name == "test_support.rs"
        || name.ends_with("_tests.rs")
        || name.starts_with("tests_")
}

#[test]
fn no_json_request_body_names_an_account_password() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for crate_sources in ["beebeeb-core/src", "beebeeb-client/src"] {
        rust_sources(&workspace.join(crate_sources), &mut files);
    }
    files.retain(|file| !is_test_source(file.strip_prefix(&workspace).expect("a workspace path")));
    assert!(
        files.len() >= 170,
        "the scan saw only {} production sources",
        files.len()
    );
    let mut offenders = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("source file must be readable");
        for line in password_keys(production_part(&source)) {
            offenders.push(format!("{}:{line}", file.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "a password named as a JSON key in production code:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_json_scan_reports_a_password_key_and_stops_at_the_tests() {
    let source = "\
fn body(secret: &str) -> Value {
    json!({ \"email\": \"a@b.test\", \"new_password\" : secret })
}
fn policy(document: &Value) -> u64 {
    document[\"password\"][\"min_length\"].as_u64().unwrap_or(12)
}

#[cfg(test)]
mod tests {
    const ANSWER: &str = r#\"{\"password\": {\"min_length\": 12}}\"#;
}
";
    assert_eq!(password_keys(production_part(source)), [2]);
    assert_eq!(password_keys(source), [2, 10]);
}
