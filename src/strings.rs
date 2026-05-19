use crate::image::BinaryImage;
use crate::pe::{SectionRecord, StringRecord};

pub fn classify_string(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut tags = Vec::new();
    if lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://") {
        tags.push("url".to_string());
    }
    if lower.starts_with("hkcu")
        || lower.starts_with("hklm")
        || lower.starts_with("hkcr")
        || lower.starts_with("hku")
        || lower.starts_with("hkey_")
    {
        tags.push("registry".to_string());
    }
    if looks_like_path(text) {
        tags.push("path".to_string());
    }
    if lower.contains(".pdb") {
        tags.push("pdb".to_string());
    }
    if looks_like_guid(text) {
        tags.push("guid".to_string());
    }
    if looks_like_format(text) {
        tags.push("format".to_string());
    }
    if [
        "cmd.exe",
        "powershell",
        "rundll32",
        "regsvr32",
        "schtasks",
        "wmic",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        tags.push("command".to_string());
    }
    tags.sort();
    tags.dedup();
    tags
}

pub fn import_categories(symbol: &str) -> Vec<String> {
    let name = symbol
        .rsplit('!')
        .next()
        .unwrap_or(symbol)
        .to_ascii_lowercase();
    let groups: [(&str, &[&str]); 10] = [
        (
            "file",
            &[
                "createfile",
                "readfile",
                "writefile",
                "deletefile",
                "copyfile",
                "movefile",
            ],
        ),
        (
            "process",
            &[
                "createprocess",
                "shellexecute",
                "winexec",
                "openprocess",
                "terminateprocess",
            ],
        ),
        (
            "registry",
            &["regopen", "regcreate", "regset", "regquery", "regdelete"],
        ),
        (
            "network",
            &[
                "socket",
                "connect",
                "send",
                "recv",
                "internet",
                "winhttp",
                "wsastartup",
                "urlmon",
            ],
        ),
        ("crypto", &["crypt", "bcrypt", "ncrypt", "cert"]),
        (
            "anti_debug",
            &[
                "isdebuggerpresent",
                "checkremotedebuggerpresent",
                "ntqueryinformationprocess",
            ],
        ),
        (
            "service",
            &[
                "openscmanager",
                "createservice",
                "openservice",
                "startservice",
            ],
        ),
        (
            "thread",
            &["createthread", "beginthread", "queueuserapc", "sleep"],
        ),
        (
            "memory",
            &[
                "virtualalloc",
                "virtualprotect",
                "writeprocessmemory",
                "readprocessmemory",
                "mapviewoffile",
            ],
        ),
        (
            "module",
            &["loadlibrary", "getprocaddress", "getmodulehandle"],
        ),
    ];
    groups
        .iter()
        .filter_map(|(category, needles)| {
            needles
                .iter()
                .any(|needle| name.contains(needle))
                .then(|| (*category).to_string())
        })
        .collect()
}

pub fn extract_strings_from(
    bytes: &[u8],
    base: u64,
    sections: &[SectionRecord],
    max_strings: usize,
) -> Vec<StringRecord> {
    let mut rows = Vec::new();
    for section in sections {
        let data = section.data(bytes);
        scan_ascii(base, section, data, max_strings, &mut rows);
        if rows.len() >= max_strings {
            break;
        }
        scan_utf16(base, section, data, max_strings, &mut rows);
        if rows.len() >= max_strings {
            break;
        }
    }
    rows
}

pub fn extract_strings(image: &dyn BinaryImage, max_strings: usize) -> Vec<StringRecord> {
    extract_strings_from(image.bytes(), image.base(), image.sections(), max_strings)
}

pub fn extract_strings_pe(image: &crate::pe::PEImage, max_strings: usize) -> Vec<StringRecord> {
    extract_strings_from(image.bytes(), image.base, &image.sections, max_strings)
}

fn scan_ascii(
    base: u64,
    section: &crate::pe::SectionRecord,
    data: &[u8],
    max_strings: usize,
    rows: &mut Vec<StringRecord>,
) {
    let mut start = None;
    for (idx, byte) in data.iter().copied().enumerate() {
        if (0x20..=0x7e).contains(&byte) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(begin) = start.take() {
            push_ascii(base, section, data, begin, idx, max_strings, rows);
        }
    }
    if let Some(begin) = start {
        push_ascii(base, section, data, begin, data.len(), max_strings, rows);
    }
}

fn push_ascii(
    base: u64,
    section: &crate::pe::SectionRecord,
    data: &[u8],
    begin: usize,
    end: usize,
    max_strings: usize,
    rows: &mut Vec<StringRecord>,
) {
    if rows.len() >= max_strings || end.saturating_sub(begin) < 5 {
        return;
    }
    let file_offset = section.raw_start as u64 + begin as u64;
    let va = base + section.rva as u64 + begin as u64;
    let text = String::from_utf8_lossy(&data[begin..end]).to_string();
    rows.push(StringRecord {
        va,
        rva: va.saturating_sub(base),
        file_offset,
        encoding: "ASCII".to_string(),
        size: end - begin,
        classifiers: classify_string(&text),
        section: Some(section.name.clone()),
        text,
    });
}

fn scan_utf16(
    base: u64,
    section: &crate::pe::SectionRecord,
    data: &[u8],
    max_strings: usize,
    rows: &mut Vec<StringRecord>,
) {
    let mut i = 0usize;
    while i + 10 <= data.len() && rows.len() < max_strings {
        let start = i;
        let mut units = Vec::new();
        while i + 1 < data.len() && (0x20..=0x7e).contains(&data[i]) && data[i + 1] == 0 {
            units.push(data[i] as u16);
            i += 2;
        }
        if units.len() >= 5 {
            let text = String::from_utf16_lossy(&units);
            let file_offset = section.raw_start as u64 + start as u64;
            let va = base + section.rva as u64 + start as u64;
            rows.push(StringRecord {
                va,
                rva: va.saturating_sub(base),
                file_offset,
                encoding: "UTF-16LE".to_string(),
                size: units.len() * 2,
                classifiers: classify_string(&text),
                section: Some(section.name.clone()),
                text,
            });
        }
        i = if i == start { i + 2 } else { i + 2 };
    }
}

fn looks_like_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    (bytes.len() > 3 && bytes[1] == b':' && bytes[2] == b'\\')
        || text.starts_with("\\\\")
        || text.starts_with("/")
}

fn looks_like_guid(text: &str) -> bool {
    let clean = text.trim_matches(|ch| ch == '{' || ch == '}');
    let parts: Vec<&str> = clean.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(parts.iter())
            .all(|(len, part)| part.len() == *len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

fn looks_like_format(text: &str) -> bool {
    text.contains("\\n")
        || text.contains("\\r")
        || text.contains("%s")
        || text.contains("%d")
        || text.contains("%u")
        || text.contains("%x")
        || text.contains("%X")
        || text.contains("%f")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_urls() {
        assert!(classify_string("https://example.com/x").contains(&"url".to_string()));
        assert!(classify_string("http://attacker.bad/").contains(&"url".to_string()));
        assert!(classify_string("ftp://foo/bar").contains(&"url".to_string()));
        assert!(!classify_string("hello world").contains(&"url".to_string()));
    }

    #[test]
    fn classifies_registry() {
        assert!(classify_string("HKLM\\Software\\Foo").contains(&"registry".to_string()));
        assert!(classify_string("HKCU\\Software\\Bar").contains(&"registry".to_string()));
        assert!(classify_string("HKEY_LOCAL_MACHINE\\X").contains(&"registry".to_string()));
        assert!(!classify_string("Software\\Foo").contains(&"registry".to_string()));
    }

    #[test]
    fn classifies_paths() {
        assert!(classify_string("C:\\Windows\\System32").contains(&"path".to_string()));
        assert!(classify_string("\\\\server\\share").contains(&"path".to_string()));
        assert!(classify_string("/etc/passwd").contains(&"path".to_string()));
        assert!(!classify_string("hello world").contains(&"path".to_string()));
    }

    #[test]
    fn classifies_pdb() {
        assert!(classify_string("c:\\build\\out.pdb").contains(&"pdb".to_string()));
    }

    #[test]
    fn classifies_guid() {
        assert!(
            classify_string("550E8400-E29B-41D4-A716-446655440000").contains(&"guid".to_string())
        );
        assert!(
            classify_string("{550E8400-E29B-41D4-A716-446655440000}").contains(&"guid".to_string())
        );
        assert!(!classify_string("not-a-guid").contains(&"guid".to_string()));
    }

    #[test]
    fn classifies_format_strings() {
        assert!(classify_string("hello %s").contains(&"format".to_string()));
        assert!(classify_string("%d items").contains(&"format".to_string()));
        assert!(classify_string("value: %X").contains(&"format".to_string()));
        assert!(classify_string(r"line\nbreak").contains(&"format".to_string()));
    }

    #[test]
    fn classifies_commands() {
        assert!(classify_string("cmd.exe /c whoami").contains(&"command".to_string()));
        assert!(classify_string("powershell -ec ZQBjAGgA").contains(&"command".to_string()));
        assert!(classify_string("rundll32 user32.dll").contains(&"command".to_string()));
        assert!(classify_string("schtasks /create").contains(&"command".to_string()));
        assert!(!classify_string("hello world").contains(&"command".to_string()));
    }

    #[test]
    fn extracts_ascii_string_with_file_offset_and_va() {
        let sections = vec![SectionRecord {
            name: ".rdata".to_string(),
            rva: 0x2000,
            va: 0x140002000,
            virtual_size: 64,
            raw_start: 0x400,
            raw_size: 64,
            data_size: 64,
            executable: false,
            readable: true,
            writable: false,
            entropy: 0.0,
            data_range: 0x400..0x440,
        }];
        // bytes layout: 0x400..0x440 mirrors section.data_range 0..64
        let mut bytes = vec![0u8; 0x440];
        let needle = b"Hello, World!\0";
        bytes[0x400..0x400 + needle.len()].copy_from_slice(needle);
        let rows = extract_strings_from(&bytes, 0x140000000, &sections, 16);
        assert_eq!(1, rows.len(), "expected exactly one extracted ASCII run");
        let row = &rows[0];
        assert_eq!("Hello, World!", row.text);
        assert_eq!("ASCII", row.encoding);
        assert_eq!(0x400, row.file_offset);
        assert_eq!(0x140002000, row.va);
        assert_eq!(0x2000, row.rva);
    }

    #[test]
    fn extracts_utf16_string_with_correct_va() {
        let sections = vec![SectionRecord {
            name: ".rdata".to_string(),
            rva: 0x2000,
            va: 0x140002000,
            virtual_size: 64,
            raw_start: 0x400,
            raw_size: 64,
            data_size: 64,
            executable: false,
            readable: true,
            writable: false,
            entropy: 0.0,
            data_range: 0x400..0x440,
        }];
        let mut bytes = vec![0u8; 0x440];
        // UTF-16LE: H, e, l, l, o
        let needle = [b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, 0, 0];
        bytes[0x400..0x400 + needle.len()].copy_from_slice(&needle);
        let rows = extract_strings_from(&bytes, 0x140000000, &sections, 16);
        let utf16 = rows.iter().find(|r| r.encoding == "UTF-16LE");
        assert!(utf16.is_some(), "expected at least one UTF-16LE row");
        let row = utf16.unwrap();
        assert_eq!("Hello", row.text);
        assert_eq!(0x140002000, row.va);
    }
}
