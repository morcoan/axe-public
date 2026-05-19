//! Capture committed memory regions of the target into
//! `RegionBuffer`s + emit the snapshot artifacts.
//!
//! `capture()` enumerates the target's address space, filters
//! to interesting regions (Committed Private + Image + Mapped),
//! reads each into a `RegionBuffer` via `ReadProcessMemory`,
//! and returns them. `emit_snapshot()` writes each buffer to
//! `regions/region_NN.bin` and serializes the
//! `SnapshotManifest` to `unpack_provenance.json` — all via
//! `AtomicWriter` so a crash mid-emit doesn't leave half-written
//! files in the consumer's path.

use std::path::Path;

use crate::atomic_write::write_atomic;
use crate::unpack::memory_map::{self, RegionInfo, RegionKind, RegionState};
use crate::unpack::region_buffer::RegionBuffer;
use crate::unpack::snapshot::{RegionDescriptor, RegionOrigin, SnapshotManifest};
use crate::unpack::UnpackError;

/// Filter for which regions to capture. The defaults are tuned
/// for unpacking: skip enormous mapped files (data, not code),
/// include image + heap + dynamically allocated.
#[derive(Clone, Debug)]
pub struct CaptureFilter {
    pub include_image: bool,
    pub include_private: bool,
    pub include_mapped: bool,
    /// Regions larger than this many bytes are skipped (would
    /// blow up the snapshot directory). Default 64 MB.
    pub max_region_bytes: u64,
}

impl Default for CaptureFilter {
    fn default() -> Self {
        Self {
            include_image: true,
            include_private: true,
            include_mapped: false, // mapped files are usually data
            max_region_bytes: 64 * 1024 * 1024,
        }
    }
}

/// One captured region — buffer + the origin metadata that
/// goes into the manifest.
pub struct CapturedRegion {
    pub buffer: RegionBuffer,
    pub permissions: String,
    pub origin: RegionOrigin,
}

/// Walk committed regions of the target and read each into a
/// `RegionBuffer`. Returns the captured set in VA order.
///
/// Reads that fail (page paged out, permission denied) are
/// silently skipped — the snapshot reflects whatever Aurora
/// could actually read.
#[cfg(windows)]
pub fn capture(
    process: windows::Win32::Foundation::HANDLE,
    filter: &CaptureFilter,
) -> Result<Vec<CapturedRegion>, UnpackError> {
    let regions = memory_map::enumerate(process)?;
    let mut out = Vec::new();
    for r in regions {
        if r.state != RegionState::Committed {
            continue;
        }
        if !include_kind(filter, r.kind) {
            continue;
        }
        if r.size > filter.max_region_bytes {
            continue;
        }
        if r.protect == "---" {
            continue; // PAGE_NOACCESS — can't read anyway
        }
        let buf = read_region(process, &r)?;
        out.push(CapturedRegion {
            buffer: buf,
            permissions: r.protect.clone(),
            origin: RegionOrigin {
                alloc_api: match r.kind {
                    RegionKind::Image => "initial".to_string(),
                    RegionKind::Mapped => "mapped".to_string(),
                    RegionKind::Private => "VirtualAlloc".to_string(),
                    RegionKind::None => "unknown".to_string(),
                },
                alloc_site_va: format!("0x{:016x}", r.allocation_base),
                alloc_size_requested: r.size,
            },
        });
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn capture(_process: (), _filter: &CaptureFilter) -> Result<Vec<CapturedRegion>, UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

#[cfg(windows)]
fn read_region(
    process: windows::Win32::Foundation::HANDLE,
    r: &RegionInfo,
) -> Result<RegionBuffer, UnpackError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let mut bytes = vec![0u8; r.size as usize];
    let mut got: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            r.base as *const _,
            bytes.as_mut_ptr() as *mut _,
            r.size as usize,
            Some(&mut got),
        )
    };
    if ok.is_err() || got == 0 {
        // Page paged out / inaccessible — return an empty
        // buffer so the caller can still record the region's
        // existence with size_bytes=0.
        bytes.clear();
    } else {
        bytes.truncate(got);
    }
    Ok(RegionBuffer::from_bytes(r.base, bytes))
}

fn include_kind(filter: &CaptureFilter, kind: RegionKind) -> bool {
    match kind {
        RegionKind::Image => filter.include_image,
        RegionKind::Mapped => filter.include_mapped,
        RegionKind::Private => filter.include_private,
        RegionKind::None => false,
    }
}

/// Emit the snapshot to disk: writes each region as
/// `regions/region_NN.bin` and the manifest as
/// `unpack_provenance.json`. Updates `manifest.regions` with
/// `RegionDescriptor`s pointing at the freshly written blobs.
///
/// Returns the cumulative number of bytes written.
pub fn emit_snapshot(
    out_dir: &Path,
    manifest: &mut SnapshotManifest,
    captured: &[CapturedRegion],
) -> Result<u64, UnpackError> {
    std::fs::create_dir_all(out_dir.join("regions")).map_err(UnpackError::Io)?;
    let mut total: u64 = 0;
    let mut descriptors: Vec<RegionDescriptor> = Vec::with_capacity(captured.len());
    for (idx, cap) in captured.iter().enumerate() {
        let blob_name = format!("regions/region_{:02}.bin", idx);
        let blob_path = out_dir.join(&blob_name);
        cap.buffer.dump_to(&blob_path).map_err(UnpackError::Io)?;
        total += cap.buffer.size() as u64;
        let d =
            cap.buffer
                .to_descriptor(idx as u32, &cap.permissions, cap.origin.clone(), &blob_name);
        descriptors.push(d);
    }
    manifest.regions = descriptors;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(UnpackError::Json)?;
    let manifest_path = out_dir.join("unpack_provenance.json");
    write_atomic(&manifest_path, &manifest_bytes).map_err(UnpackError::Io)?;
    total += manifest_bytes.len() as u64;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unpack::snapshot::{
        AntiVmProfile, ExecutionProvenance, SourceBinary, SNAPSHOT_SCHEMA,
    };

    #[test]
    fn capture_filter_defaults_exclude_mapped_files() {
        let f = CaptureFilter::default();
        assert!(f.include_image);
        assert!(f.include_private);
        assert!(!f.include_mapped);
        assert_eq!(f.max_region_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn include_kind_respects_filter_flags() {
        let f = CaptureFilter {
            include_image: false,
            include_private: true,
            include_mapped: true,
            max_region_bytes: 1024,
        };
        assert!(!include_kind(&f, RegionKind::Image));
        assert!(include_kind(&f, RegionKind::Private));
        assert!(include_kind(&f, RegionKind::Mapped));
        assert!(!include_kind(&f, RegionKind::None));
    }

    #[test]
    fn emit_snapshot_writes_manifest_and_region_blobs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut manifest = SnapshotManifest::new(
            "test:0",
            SourceBinary {
                path: "synthetic".into(),
                hash_blake3: "0".into(),
                size_bytes: 0,
            },
            "debug",
        );
        let captured = vec![
            CapturedRegion {
                buffer: RegionBuffer::from_bytes(0x140001000, vec![0xAA; 1024]),
                permissions: "R-X".into(),
                origin: RegionOrigin {
                    alloc_api: "initial".into(),
                    alloc_site_va: "0x140001000".into(),
                    alloc_size_requested: 1024,
                },
            },
            CapturedRegion {
                buffer: RegionBuffer::from_bytes(0x140002000, vec![0xBB; 2048]),
                permissions: "RW-".into(),
                origin: RegionOrigin {
                    alloc_api: "VirtualAlloc".into(),
                    alloc_site_va: "0x140002000".into(),
                    alloc_size_requested: 2048,
                },
            },
        ];
        let total = emit_snapshot(tmp.path(), &mut manifest, &captured).expect("emit");
        assert!(total > 3072);
        // Manifest exists and is well-formed.
        let manifest_text = std::fs::read_to_string(tmp.path().join("unpack_provenance.json"))
            .expect("read manifest");
        let parsed: serde_json::Value = serde_json::from_str(&manifest_text).expect("parse");
        assert_eq!(parsed["schema"], SNAPSHOT_SCHEMA);
        assert_eq!(parsed["regions"].as_array().unwrap().len(), 2);
        // Blobs exist with correct sizes.
        let blob0 =
            std::fs::read(tmp.path().join("regions").join("region_00.bin")).expect("blob 0");
        assert_eq!(blob0.len(), 1024);
        let blob1 =
            std::fs::read(tmp.path().join("regions").join("region_01.bin")).expect("blob 1");
        assert_eq!(blob1.len(), 2048);
        // The descriptors point at the blobs.
        assert_eq!(manifest.regions[0].blob_path, "regions/region_00.bin");
        assert_eq!(manifest.regions[0].size_bytes, 1024);
        assert_eq!(manifest.regions[1].size_bytes, 2048);
        // And the SnapshotManifest is fully shaped (no missing
        // required fields).
        let _ = manifest.execution_provenance;
        let _ = manifest.anti_vm_profile;
    }

    #[test]
    fn emit_snapshot_preserves_anti_vm_profile_fields() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut manifest = SnapshotManifest::new(
            "test:1",
            SourceBinary {
                path: "synthetic".into(),
                hash_blake3: "0".into(),
                size_bytes: 0,
            },
            "whp",
        );
        manifest.anti_vm_profile = AntiVmProfile {
            user_mode_hooks_installed: vec!["IsDebuggerPresent".into()],
            anti_debug_hooks_installed: vec!["NtQueryInformationProcess".into()],
            whp_used: true,
            driver_used: false,
            devirt_used: false,
            devirt_trace_path: None,
        };
        manifest.execution_provenance = ExecutionProvenance::in_progress();
        emit_snapshot(tmp.path(), &mut manifest, &[]).expect("emit");
        let text =
            std::fs::read_to_string(tmp.path().join("unpack_provenance.json")).expect("read");
        let v: serde_json::Value = serde_json::from_str(&text).expect("parse");
        assert_eq!(v["tracer_mode"], "whp");
        assert_eq!(v["anti_vm_profile"]["whp_used"], true);
        assert_eq!(
            v["anti_vm_profile"]["user_mode_hooks_installed"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn capture_on_non_windows_returns_unsupported() {
        match capture((), &CaptureFilter::default()) {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }

    #[cfg(windows)]
    #[test]
    fn capture_own_process_returns_nonempty_set() {
        use windows::Win32::System::Threading::GetCurrentProcess;
        let regions =
            capture(unsafe { GetCurrentProcess() }, &CaptureFilter::default()).expect("capture");
        assert!(
            !regions.is_empty(),
            "own process must have ≥1 capturable region"
        );
        // At least one region should have nonzero captured bytes.
        let nonempty = regions.iter().filter(|r| r.buffer.size() > 0).count();
        assert!(
            nonempty >= 1,
            "expected ≥1 region with captured bytes, got {}",
            nonempty
        );
    }
}
