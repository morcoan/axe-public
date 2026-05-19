//! Sink catalog — argument-role-aware sink modeling.
//!
//! v1.0 ships ~30 sinks across 12 bug-class templates. Each sink
//! has typed `args: &[ArgRole]` that lets chain queries ask
//! template-specific questions like "is the size argument tainted?"
//! or "does any arg have FormatString role and taint?".
//!
//! **Codex finding 4 fix:** this catalog is the SINGLE SOURCE OF
//! TRUTH for the dangerous-API list. `src/portable.rs::dangerous_api`
//! is refactored into a projection over this catalog
//! (`SinkCatalog::v1_0().is_legacy_dangerous(name)`). Parity tests
//! enforce:
//! - Every name in the original legacy list maps to a `Sink` with
//!   `legacy_dangerous = true`.
//! - Every `Sink` with `legacy_dangerous = true` is returned by
//!   `dangerous_api(name)`.
//! - Existing `vuln_candidates.jsonl` output is byte-identical when
//!   `--vuln-discovery off` (default).

#![allow(dead_code)]

use serde::Serialize;

/// Semantic role of an argument in a sink call. Templates filter by
/// role: `unchecked_copy_length` cares about `Destination` + `Source`
/// + `ByteCount`; `format_string_controlled` cares about
/// `FormatString`; `dangerous_memory_perm_transition` cares about
/// `Pointer` + `Size` + `Flags`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgRole {
    Destination,
    Source,
    ByteCount,
    Size,
    Pointer,
    Flags,
    FormatString,
    Path,
    Handle,
    Other,
}

/// A sink description. `legacy_dangerous = true` means this sink is
/// in the back-compat dangerous-API list consumed by
/// `src/portable.rs::dangerous_api`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Sink {
    pub api: &'static str,
    pub args: &'static [ArgRole],
    pub legacy_dangerous: bool,
    pub description: &'static str,
}

/// Read-only registry of every v1.0 sink. Indexed by `api` for fast
/// lookup; iterator preserves declaration order.
pub struct SinkCatalog {
    sinks: &'static [Sink],
}

impl SinkCatalog {
    pub fn v1_0() -> Self {
        Self { sinks: V1_0_SINKS }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Sink> {
        self.sinks.iter()
    }

    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Lookup by substring match — returns the entry whose `api` is
    /// the LONGEST substring match of `name`. Longest-match prevents
    /// e.g. `lookup("VirtualAllocEx")` from accidentally returning
    /// the `VirtualAlloc` entry just because it was declared first;
    /// both APIs are substrings but `VirtualAllocEx` is the more
    /// specific match.
    pub fn lookup(&self, name: &str) -> Option<&Sink> {
        let lower = name.to_lowercase();
        self.sinks
            .iter()
            .filter(|s| lower.contains(&s.api.to_lowercase()))
            .max_by_key(|s| s.api.len())
    }

    /// **Single source of truth for the legacy `dangerous_api` list.**
    /// Returns `true` iff there's a catalog entry whose `api` is a
    /// case-insensitive substring of `name` AND that entry has
    /// `legacy_dangerous = true`. Codex finding 4 fix.
    pub fn is_legacy_dangerous(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.sinks
            .iter()
            .any(|s| s.legacy_dangerous && lower.contains(&s.api.to_lowercase()))
    }
}

/// The v1.0 sink registry. ~30 sinks covering all 12 v1.0 templates.
///
/// The 9 entries with `legacy_dangerous = true` are exactly the
/// original `dangerous_api` list (case-insensitive substring match):
/// strcpy, sprintf, memcpy, rtlcopymemory, deviceiocontrol,
/// virtualprotect, virtualallocex, writeprocessmemory,
/// createremotethread.
pub const V1_0_SINKS: &[Sink] = &[
    // Memory copy family — `unchecked_copy_length`,
    // `signed_unsigned_length_confusion`, `missing_bounds_check_var_mismatch`.
    Sink {
        api: "memcpy",
        args: &[ArgRole::Destination, ArgRole::Source, ArgRole::ByteCount],
        legacy_dangerous: true,
        description: "Raw memory copy. Tainted byte count without dst-size bound is the canonical heap/stack overflow.",
    },
    Sink {
        api: "memmove",
        args: &[ArgRole::Destination, ArgRole::Source, ArgRole::ByteCount],
        legacy_dangerous: false,
        description: "Like memcpy but tolerates overlap. Same overflow risk.",
    },
    Sink {
        api: "strcpy",
        args: &[ArgRole::Destination, ArgRole::Source],
        legacy_dangerous: true,
        description: "Null-terminated string copy with no length cap. Classic buffer overflow.",
    },
    Sink {
        api: "strcat",
        args: &[ArgRole::Destination, ArgRole::Source],
        legacy_dangerous: false,
        description: "Null-terminated string concat with no length cap.",
    },
    Sink {
        api: "strncpy",
        args: &[ArgRole::Destination, ArgRole::Source, ArgRole::ByteCount],
        legacy_dangerous: false,
        description: "Bounded string copy but doesn't null-terminate on truncation.",
    },
    Sink {
        api: "RtlCopyMemory",
        args: &[ArgRole::Destination, ArgRole::Source, ArgRole::ByteCount],
        legacy_dangerous: true,
        description: "Windows kernel memory copy. Same risk as memcpy.",
    },
    // Format-string family — `format_string_controlled`.
    Sink {
        api: "sprintf",
        args: &[ArgRole::Destination, ArgRole::FormatString, ArgRole::Other],
        legacy_dangerous: true,
        description: "Format into buffer. Tainted format = arbitrary memory write via %n.",
    },
    Sink {
        api: "snprintf",
        args: &[ArgRole::Destination, ArgRole::ByteCount, ArgRole::FormatString, ArgRole::Other],
        legacy_dangerous: false,
        description: "Bounded format into buffer. Tainted format still problematic via %n.",
    },
    Sink {
        api: "printf",
        args: &[ArgRole::FormatString, ArgRole::Other],
        legacy_dangerous: false,
        description: "stdout format. Tainted format leaks memory via %s/%x or writes via %n.",
    },
    Sink {
        api: "fprintf",
        args: &[ArgRole::Handle, ArgRole::FormatString, ArgRole::Other],
        legacy_dangerous: false,
        description: "File-stream format. Same risks as printf.",
    },
    Sink {
        api: "vfprintf",
        args: &[ArgRole::Handle, ArgRole::FormatString, ArgRole::Other],
        legacy_dangerous: false,
        description: "va_list variant of fprintf. Tainted format has the same printf-family risk.",
    },
    Sink {
        api: "vsprintf",
        args: &[ArgRole::Destination, ArgRole::FormatString, ArgRole::Other],
        legacy_dangerous: false,
        description: "va_list variant of sprintf.",
    },
    Sink {
        api: "__stdio_common_vfprintf",
        args: &[
            ArgRole::Other,
            ArgRole::Handle,
            ArgRole::FormatString,
            ArgRole::Other,
            ArgRole::Other,
        ],
        legacy_dangerous: false,
        description: "MSVC CRT wrapper for vfprintf. The third argument is the attacker-relevant format string.",
    },
    // Memory-management family — `tainted_allocation_size`,
    // `integer_overflow_before_alloc`, `dangerous_memory_perm_transition`.
    Sink {
        api: "malloc",
        args: &[ArgRole::Size],
        legacy_dangerous: false,
        description: "Heap allocation. Tainted size enables zero-or-small alloc followed by oversize write.",
    },
    Sink {
        api: "calloc",
        args: &[ArgRole::Size, ArgRole::Size],
        legacy_dangerous: false,
        description: "Calloc(n, sz) — n*sz can integer-overflow when tainted.",
    },
    Sink {
        api: "realloc",
        args: &[ArgRole::Pointer, ArgRole::Size],
        legacy_dangerous: false,
        description: "Realloc with tainted size. Failure-mode aliasing also a UAF risk.",
    },
    Sink {
        api: "VirtualAlloc",
        args: &[ArgRole::Pointer, ArgRole::Size, ArgRole::Flags, ArgRole::Flags],
        legacy_dangerous: false,
        description: "Reserve/commit virtual memory. Executable allocs are notable.",
    },
    Sink {
        api: "VirtualAllocEx",
        args: &[ArgRole::Handle, ArgRole::Pointer, ArgRole::Size, ArgRole::Flags, ArgRole::Flags],
        legacy_dangerous: true,
        description: "Allocate in a remote process. Cross-process executable alloc = injection precursor.",
    },
    Sink {
        api: "VirtualProtect",
        args: &[ArgRole::Pointer, ArgRole::Size, ArgRole::Flags, ArgRole::Pointer],
        legacy_dangerous: true,
        description: "Change page protection. W→X transition with attacker-influenced region is the canonical perm-transition red flag.",
    },
    Sink {
        api: "WriteProcessMemory",
        args: &[ArgRole::Handle, ArgRole::Pointer, ArgRole::Pointer, ArgRole::ByteCount, ArgRole::Pointer],
        legacy_dangerous: true,
        description: "Write to another process's address space — the second half of a classic injection chain.",
    },
    Sink {
        api: "CreateRemoteThread",
        args: &[ArgRole::Handle, ArgRole::Pointer, ArgRole::Size, ArgRole::Pointer, ArgRole::Pointer, ArgRole::Flags, ArgRole::Pointer],
        legacy_dangerous: true,
        description: "Spawn a thread in another process — the third half of a classic injection chain.",
    },
    // I/O / IOCTL family — `path_traversal_to_file_op`, `toctou_file_access`.
    Sink {
        api: "DeviceIoControl",
        args: &[ArgRole::Handle, ArgRole::Flags, ArgRole::Pointer, ArgRole::ByteCount, ArgRole::Pointer, ArgRole::ByteCount, ArgRole::Pointer, ArgRole::Pointer],
        legacy_dangerous: true,
        description: "User-mode IOCTL to driver. Tainted input buffer + driver-side parsing = kernel attack surface.",
    },
    Sink {
        api: "CreateFile",
        args: &[ArgRole::Path, ArgRole::Flags, ArgRole::Flags, ArgRole::Pointer, ArgRole::Flags, ArgRole::Flags, ArgRole::Handle],
        legacy_dangerous: false,
        description: "Open file or device by path. Tainted path = path-traversal candidate.",
    },
    Sink {
        api: "fopen",
        args: &[ArgRole::Path, ArgRole::Flags],
        legacy_dangerous: false,
        description: "POSIX file open by path.",
    },
    Sink {
        api: "open",
        args: &[ArgRole::Path, ArgRole::Flags],
        legacy_dangerous: false,
        description: "POSIX low-level open.",
    },
    Sink {
        api: "unlink",
        args: &[ArgRole::Path],
        legacy_dangerous: false,
        description: "Delete file by path.",
    },
    Sink {
        api: "DeleteFile",
        args: &[ArgRole::Path],
        legacy_dangerous: false,
        description: "Windows delete by path.",
    },
    Sink {
        api: "rename",
        args: &[ArgRole::Path, ArgRole::Path],
        legacy_dangerous: false,
        description: "POSIX file rename — TOCTOU candidate.",
    },
    // Auth / permission family — `auth_check_after_action`,
    // `missing_caller_validation`.
    Sink {
        api: "AccessCheck",
        args: &[ArgRole::Handle, ArgRole::Handle, ArgRole::Flags, ArgRole::Pointer, ArgRole::Pointer, ArgRole::Pointer, ArgRole::Pointer, ArgRole::Pointer],
        legacy_dangerous: false,
        description: "Windows ACL check — when called AFTER the protected action, this is the canonical auth-check-after-action smell.",
    },
    Sink {
        api: "ImpersonateNamedPipeClient",
        args: &[ArgRole::Handle],
        legacy_dangerous: false,
        description: "Take on client's security context — must be paired with RevertToSelf.",
    },
    // Deserialization family — `deserialization_to_dangerous_type`.
    Sink {
        api: "BinaryFormatter::Deserialize",
        args: &[ArgRole::Source],
        legacy_dangerous: false,
        description: ".NET BinaryFormatter deserialization — gadget-chain risk.",
    },
    Sink {
        api: "pickle.loads",
        args: &[ArgRole::Source],
        legacy_dangerous: false,
        description: "Python pickle deserialize — arbitrary-code-execution on untrusted input.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact legacy list from the original `dangerous_api`. The
    /// parity tests below assert bidirectional equivalence between
    /// this list and `SinkCatalog::is_legacy_dangerous`.
    const LEGACY_DANGEROUS_LIST: &[&str] = &[
        "strcpy",
        "sprintf",
        "memcpy",
        "rtlcopymemory",
        "deviceiocontrol",
        "virtualprotect",
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
    ];

    #[test]
    fn v1_0_has_at_least_25_sinks() {
        // The exact count grows as templates expand. Hold at ≥25 as a
        // floor so accidental deletions get caught.
        assert!(SinkCatalog::v1_0().len() >= 25);
    }

    #[test]
    fn every_legacy_dangerous_name_maps_to_a_legacy_dangerous_sink() {
        // Codex finding 4 parity test (direction A): every entry in
        // the legacy list resolves to a catalog Sink with
        // legacy_dangerous = true.
        let cat = SinkCatalog::v1_0();
        for legacy in LEGACY_DANGEROUS_LIST {
            let s = cat.lookup(legacy).unwrap_or_else(|| {
                panic!("legacy dangerous API {legacy} has no SinkCatalog entry")
            });
            assert!(
                s.legacy_dangerous,
                "catalog entry for {legacy} must have legacy_dangerous = true"
            );
        }
    }

    #[test]
    fn every_legacy_dangerous_sink_is_returned_by_is_legacy_dangerous() {
        // Codex finding 4 parity test (direction B): every Sink with
        // legacy_dangerous = true is hit by is_legacy_dangerous.
        let cat = SinkCatalog::v1_0();
        for s in cat.iter() {
            if s.legacy_dangerous {
                assert!(
                    cat.is_legacy_dangerous(s.api),
                    "Sink {} is legacy_dangerous but is_legacy_dangerous returns false",
                    s.api
                );
            }
        }
    }

    #[test]
    fn is_legacy_dangerous_uses_case_insensitive_substring_match() {
        let cat = SinkCatalog::v1_0();
        // Original dangerous_api used `lower.contains(needle)`. Verify
        // we preserve that semantic.
        assert!(cat.is_legacy_dangerous("memcpy"));
        assert!(cat.is_legacy_dangerous("MEMCPY"));
        assert!(cat.is_legacy_dangerous("KERNEL32.dll::memcpy"));
        assert!(cat.is_legacy_dangerous("__imp_memcpy"));
        assert!(!cat.is_legacy_dangerous("strcat")); // not in legacy list
        assert!(!cat.is_legacy_dangerous("printf")); // not in legacy list
    }

    #[test]
    fn is_legacy_dangerous_byte_identical_to_original_dangerous_api_semantic() {
        // The original was:
        //   fn dangerous_api(symbol: &str) -> bool {
        //     let lower = symbol.to_ascii_lowercase();
        //     LEGACY_DANGEROUS_LIST.iter().any(|n| lower.contains(n))
        //   }
        // Build a small fuzzing corpus and assert agreement.
        let cat = SinkCatalog::v1_0();
        let corpus = [
            "memcpy",
            "Memcpy",
            "kernel32!memcpy",
            "__imp_RtlCopyMemory",
            "VirtualProtect",
            "VirtualProtectEx",
            "VirtualProtectStub",
            "WriteProcessMemory",
            "_WriteProcessMemory@20",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "DeviceIoControl",
            "strcpy",
            "wcscpy",
            "sprintf",
            "snprintf",
            "printf", // strcpy substring hit
            "fopen",
            "open",
            "calloc",
            "malloc",
            "free",
            "BinaryFormatter::Deserialize",
            // negatives
            "GetWindowText",
            "DispatchMessage",
            "Sleep",
            "ExitProcess",
        ];
        for input in corpus {
            let lower = input.to_ascii_lowercase();
            let original = LEGACY_DANGEROUS_LIST.iter().any(|n| lower.contains(n));
            let projection = cat.is_legacy_dangerous(input);
            assert_eq!(
                original, projection,
                "disagreement on {input}: original={original}, projection={projection}"
            );
        }
    }

    #[test]
    fn lookup_returns_matching_sink_by_substring() {
        let cat = SinkCatalog::v1_0();
        let s = cat.lookup("memcpy").unwrap();
        assert_eq!(s.api, "memcpy");
        let s2 = cat.lookup("KERNEL32::VirtualProtect").unwrap();
        assert_eq!(s2.api, "VirtualProtect");
    }

    #[test]
    fn lookup_returns_none_for_unknown_api() {
        let cat = SinkCatalog::v1_0();
        assert!(cat.lookup("not_a_real_api").is_none());
    }

    #[test]
    fn memcpy_has_three_typed_args() {
        let cat = SinkCatalog::v1_0();
        let s = cat.lookup("memcpy").unwrap();
        assert_eq!(s.args.len(), 3);
        assert_eq!(s.args[0], ArgRole::Destination);
        assert_eq!(s.args[1], ArgRole::Source);
        assert_eq!(s.args[2], ArgRole::ByteCount);
    }

    #[test]
    fn virtualprotect_args_carry_pointer_size_flags() {
        let cat = SinkCatalog::v1_0();
        let s = cat.lookup("VirtualProtect").unwrap();
        assert_eq!(s.args[0], ArgRole::Pointer);
        assert_eq!(s.args[1], ArgRole::Size);
        assert_eq!(s.args[2], ArgRole::Flags);
    }

    #[test]
    fn sprintf_has_format_string_role() {
        let cat = SinkCatalog::v1_0();
        let s = cat.lookup("sprintf").unwrap();
        assert!(s.args.contains(&ArgRole::FormatString));
    }

    #[test]
    fn deviceiocontrol_is_legacy_dangerous_with_typed_args() {
        let cat = SinkCatalog::v1_0();
        let s = cat.lookup("DeviceIoControl").unwrap();
        assert!(s.legacy_dangerous);
        assert!(s.args.contains(&ArgRole::Handle));
        assert!(s.args.contains(&ArgRole::Pointer));
    }
}
