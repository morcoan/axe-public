use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

pub const PASSWORD_LIST: &[&str] = &["", "infected", "malware", "virus", "password"];

#[derive(Clone, Debug, Serialize)]
pub struct ExtractionResult {
    pub source: String,
    pub format: String,
    pub files: Vec<PathBuf>,
    pub errors: Vec<String>,
    pub skipped: bool,
    pub reason: Option<String>,
    pub password_used: Option<String>,
}

impl ExtractionResult {
    fn empty(source: &Path, format: &str) -> Self {
        Self {
            source: source.to_string_lossy().to_string(),
            format: format.to_string(),
            files: Vec::new(),
            errors: Vec::new(),
            skipped: false,
            reason: None,
            password_used: None,
        }
    }

    fn skipped(source: &Path, format: &str, reason: impl Into<String>) -> Self {
        let mut r = Self::empty(source, format);
        r.skipped = true;
        r.reason = Some(reason.into());
        r
    }

    fn failed(source: &Path, format: &str, error: impl Into<String>) -> Self {
        let mut r = Self::empty(source, format);
        r.errors.push(error.into());
        r
    }
}

pub fn is_archive_path(path: &Path) -> bool {
    detect_archive_format(path).is_some()
}

pub fn detect_archive_format(path: &Path) -> Option<&'static str> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("zip") | Some("jar") | Some("apk") => Some("zip"),
        Some("7z") => Some("7z"),
        Some("rar") => Some("rar"),
        Some("tar") => Some("tar"),
        Some("gz") | Some("tgz") => Some("tar.gz"),
        _ => detect_from_magic(path),
    }
}

fn detect_from_magic(path: &Path) -> Option<&'static str> {
    let mut buf = [0u8; 8];
    let mut f = File::open(path).ok()?;
    let n = f.read(&mut buf).ok()?;
    let head = &buf[..n];
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return Some("zip");
    }
    if head.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return Some("7z");
    }
    if head.starts_with(b"Rar!\x1A\x07") {
        return Some("rar");
    }
    if head.starts_with(&[0x1F, 0x8B]) {
        return Some("tar.gz");
    }
    None
}

pub fn extract_archive(src: &Path, dest: &Path) -> ExtractionResult {
    let format = match detect_archive_format(src) {
        Some(f) => f,
        None => {
            return ExtractionResult::skipped(src, "unknown", "format_not_detected");
        }
    };
    if let Err(err) = fs::create_dir_all(dest) {
        return ExtractionResult::failed(src, format, format!("create_dest_failed: {err}"));
    }
    match format {
        "zip" => extract_zip(src, dest),
        "7z" => extract_7z(src, dest),
        "tar" => extract_tar(src, dest, false),
        "tar.gz" => extract_tar(src, dest, true),
        "rar" => ExtractionResult::skipped(src, "rar", "rar_not_supported_in_pure_rust"),
        other => ExtractionResult::skipped(src, other, "format_not_supported"),
    }
}

fn safe_join(dest: &Path, name: &str) -> Option<PathBuf> {
    let mut joined = dest.to_path_buf();
    let candidate = Path::new(name);
    for component in candidate.components() {
        match component {
            Component::Normal(part) => joined.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    let canon_dest = dest.canonicalize().ok()?;
    let canon_target_parent = joined.parent().and_then(|p| p.canonicalize().ok());
    if let Some(parent) = canon_target_parent {
        if !parent.starts_with(&canon_dest) {
            return None;
        }
    }
    Some(joined)
}

fn extract_zip(src: &Path, dest: &Path) -> ExtractionResult {
    let mut out = ExtractionResult::empty(src, "zip");
    for password in PASSWORD_LIST {
        let file = match File::open(src) {
            Ok(f) => f,
            Err(err) => {
                out.errors.push(format!("open_failed: {err}"));
                return out;
            }
        };
        let reader = BufReader::new(file);
        let mut archive = match zip::ZipArchive::new(reader) {
            Ok(a) => a,
            Err(err) => {
                out.errors.push(format!("zip_open_failed: {err}"));
                return out;
            }
        };
        let mut password_failed = false;
        let mut produced: Vec<PathBuf> = Vec::new();
        let mut local_errors: Vec<String> = Vec::new();
        for i in 0..archive.len() {
            let mut entry = match if password.is_empty() {
                archive.by_index(i)
            } else {
                archive.by_index_decrypt(i, password.as_bytes())
            } {
                Ok(e) => e,
                Err(zip::result::ZipError::UnsupportedArchive(reason))
                    if reason.contains("password") =>
                {
                    password_failed = true;
                    break;
                }
                Err(err) => {
                    local_errors.push(format!("entry_{i}_open_failed: {err}"));
                    continue;
                }
            };
            if entry.is_dir() {
                continue;
            }
            let entry_name = entry.name().to_string();
            let target = match safe_join(dest, &entry_name) {
                Some(p) => p,
                None => {
                    local_errors.push(format!("rejected_path_traversal: {entry_name}"));
                    continue;
                }
            };
            if let Some(parent) = target.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let mut buf = Vec::new();
            if let Err(err) = entry.read_to_end(&mut buf) {
                local_errors.push(format!("entry_{i}_read_failed: {err}"));
                continue;
            }
            match File::create(&target) {
                Ok(mut f) => match f.write_all(&buf) {
                    Ok(()) => produced.push(target),
                    Err(err) => local_errors.push(format!("entry_{i}_write_failed: {err}")),
                },
                Err(err) => local_errors.push(format!("entry_{i}_create_failed: {err}")),
            }
        }
        if password_failed {
            continue;
        }
        out.files = produced;
        out.errors.extend(local_errors);
        out.password_used = if password.is_empty() {
            None
        } else {
            Some(password.to_string())
        };
        return out;
    }
    out.errors
        .push("all_passwords_failed_or_archive_encrypted".to_string());
    out
}

fn extract_7z(src: &Path, dest: &Path) -> ExtractionResult {
    let mut out = ExtractionResult::empty(src, "7z");
    // sevenz-rust 0.6 only supports password-less decompress in the top-level helper.
    // Encrypted 7z archives are reported with a clear error; rerun via 7z CLI for those.
    match sevenz_rust::decompress_file(src, dest) {
        Ok(()) => {
            collect_files_recursive(dest, &mut out.files);
        }
        Err(err) => {
            out.errors.push(format!("7z_extract_failed: {err}"));
        }
    }
    out
}

fn extract_tar(src: &Path, dest: &Path, gzipped: bool) -> ExtractionResult {
    let mut out = ExtractionResult::empty(src, if gzipped { "tar.gz" } else { "tar" });
    let file = match File::open(src) {
        Ok(f) => f,
        Err(err) => {
            out.errors.push(format!("open_failed: {err}"));
            return out;
        }
    };
    let reader: Box<dyn Read> = if gzipped {
        Box::new(flate2::read::GzDecoder::new(BufReader::new(file)))
    } else {
        Box::new(BufReader::new(file))
    };
    let mut archive = tar::Archive::new(reader);
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(err) => {
            out.errors.push(format!("tar_entries_failed: {err}"));
            return out;
        }
    };
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(err) => {
                out.errors.push(format!("entry_iter_failed: {err}"));
                continue;
            }
        };
        let path_in_archive = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(err) => {
                out.errors.push(format!("entry_path_failed: {err}"));
                continue;
            }
        };
        let name = path_in_archive.to_string_lossy().to_string();
        let target = match safe_join(dest, &name) {
            Some(p) => p,
            None => {
                out.errors.push(format!("rejected_path_traversal: {name}"));
                continue;
            }
        };
        if entry.header().entry_type().is_dir() {
            let _ = fs::create_dir_all(&target);
            continue;
        }
        if let Some(parent) = target.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match entry.unpack(&target) {
            Ok(_) => out.files.push(target),
            Err(err) => out
                .errors
                .push(format!("entry_unpack_failed_{name}: {err}")),
        }
    }
    out
}

fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if path.is_file() {
            out.push(path);
        } else if path.is_dir() {
            collect_files_recursive(&path, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    #[test]
    fn detects_zip_by_extension() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.zip");
        fs::write(&p, b"PK\x03\x04dummy").unwrap();
        assert_eq!(Some("zip"), detect_archive_format(&p));
    }

    #[test]
    fn detects_7z_by_magic() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("noext");
        fs::write(&p, b"7z\xBC\xAF\x27\x1Crest").unwrap();
        assert_eq!(Some("7z"), detect_archive_format(&p));
    }

    #[test]
    fn detects_rar_by_magic() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("noext");
        fs::write(&p, b"Rar!\x1A\x07\x00").unwrap();
        assert_eq!(Some("rar"), detect_archive_format(&p));
    }

    #[test]
    fn rar_is_skipped_with_reason() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("a.rar");
        fs::write(&src, b"Rar!\x1A\x07\x00garbage").unwrap();
        let dest = tmp.path().join("out");
        let result = extract_archive(&src, &dest);
        assert_eq!("rar", result.format);
        assert!(result.skipped);
        assert_eq!(
            Some("rar_not_supported_in_pure_rust".to_string()),
            result.reason
        );
    }

    fn write_zip_with_paths(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let opts: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            writer.start_file(name.to_string(), opts).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
    }

    #[test]
    fn zip_extraction_blocks_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let zip_path = tmp.path().join("evil.zip");
        write_zip_with_paths(
            &zip_path,
            &[
                ("safe.bin", b"good"),
                ("../escaped.bin", b"bad"),
                ("nested/../../escape2.bin", b"bad2"),
            ],
        );
        let dest = tmp.path().join("out");
        let result = extract_archive(&zip_path, &dest);
        let names: Vec<_> = result
            .files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();
        assert!(names.contains(&"safe.bin"));
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("rejected_path_traversal")),
            "expected at least one rejection, got errors: {:?}",
            result.errors
        );
        let outside = tmp.path().join("escaped.bin");
        assert!(
            !outside.exists(),
            "path traversal should not have escaped the dest dir"
        );
    }

    #[test]
    fn zip_extraction_extracts_basic_files() {
        let tmp = TempDir::new().unwrap();
        let zip_path = tmp.path().join("basic.zip");
        write_zip_with_paths(
            &zip_path,
            &[("a.txt", b"hello"), ("nested/b.txt", b"world")],
        );
        let dest = tmp.path().join("out");
        let result = extract_archive(&zip_path, &dest);
        assert_eq!(2, result.files.len(), "expected 2 files, got {:?}", result);
        assert!(
            result.errors.is_empty(),
            "no errors expected: {:?}",
            result.errors
        );
        assert_eq!(b"hello", fs::read(dest.join("a.txt")).unwrap().as_slice());
        assert_eq!(
            b"world",
            fs::read(dest.join("nested").join("b.txt"))
                .unwrap()
                .as_slice()
        );
    }
}
