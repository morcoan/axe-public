//! Group C integration — composes memory_map + guard_pages +
//! write_log + api_intercept + snapshot_capture against a real
//! Windows process (Aurora's own test binary). Windows-only.

#![cfg(all(windows, feature = "unpack"))]

use axe_core::unpack::api_intercept::{resolve_all, resolve_one, ApiKind};
use axe_core::unpack::guard_pages::{
    decode_guard_violation, GuardAccessKind, STATUS_GUARD_PAGE_VIOLATION,
};
use axe_core::unpack::memory_map::{
    committed_only, enumerate, image_only, RegionKind, RegionState,
};
use axe_core::unpack::snapshot::{SnapshotManifest, SourceBinary};
use axe_core::unpack::snapshot_capture::{capture, emit_snapshot, CaptureFilter};
use axe_core::unpack::write_log::WriteLog;

#[test]
fn enumerate_then_capture_then_snapshot_self_process() {
    use windows::Win32::System::Threading::GetCurrentProcess;
    let process = unsafe { GetCurrentProcess() };
    // Step 13: enumerate regions
    let regions = enumerate(process).expect("enumerate");
    assert!(regions.len() > 10);

    // Step 17: capture (uses Step 13 internally)
    let captured = capture(
        process,
        &CaptureFilter {
            include_image: true,
            include_private: false, // skip heap to keep snapshot small
            include_mapped: false,
            max_region_bytes: 4 * 1024 * 1024,
        },
    )
    .expect("capture");
    assert!(
        !captured.is_empty(),
        "expected ≥1 image region in own process"
    );

    // Emit to a tempdir + verify the on-disk shape
    let tmp = tempfile::TempDir::new().unwrap();
    let mut manifest = SnapshotManifest::new(
        "test:integration",
        SourceBinary {
            path: "self-process".into(),
            hash_blake3: "0".into(),
            size_bytes: 0,
        },
        "debug",
    );
    let total = emit_snapshot(tmp.path(), &mut manifest, &captured).expect("emit");
    assert!(total > 1024);
    assert_eq!(manifest.regions.len(), captured.len());
    // Manifest file exists
    assert!(tmp.path().join("unpack_provenance.json").exists());
    // First region blob exists
    assert!(tmp.path().join("regions").join("region_00.bin").exists());
}

#[test]
fn committed_filter_excludes_free_and_reserved_regions() {
    use windows::Win32::System::Threading::GetCurrentProcess;
    let regions = enumerate(unsafe { GetCurrentProcess() }).expect("enumerate");
    let committed = committed_only(&regions);
    for r in &committed {
        assert_eq!(r.state, RegionState::Committed);
    }
    let images = image_only(&regions);
    for r in &images {
        assert_eq!(r.kind, RegionKind::Image);
    }
}

#[test]
fn api_intercept_resolves_kernel32_memory_apis() {
    let table = resolve_all();
    let alloc_count = table
        .iter()
        .filter(|b| b.kind == ApiKind::MemoryAlloc)
        .count();
    let protect_count = table
        .iter()
        .filter(|b| b.kind == ApiKind::MemoryProtect)
        .count();
    let write_count = table
        .iter()
        .filter(|b| b.kind == ApiKind::MemoryWrite)
        .count();
    assert!(alloc_count >= 2, "expected ≥2 memory-alloc APIs to resolve");
    assert!(
        protect_count >= 2,
        "expected ≥2 memory-protect APIs to resolve"
    );
    assert!(write_count >= 1, "expected ≥1 memory-write API to resolve");
    // Each resolved address is non-zero and points into the
    // kernel32 / ntdll range (well above 0x100000).
    for bp in &table {
        assert!(bp.address > 0x100000);
    }
}

#[test]
fn virtual_alloc_resolves_to_a_concrete_kernel32_address() {
    let addr = resolve_one("kernel32.dll", "VirtualAlloc").expect("VirtualAlloc resolves");
    assert!(addr > 0x100000);
}

#[test]
fn write_log_with_decoded_guard_violation_round_trips_to_jsonl() {
    // Synthesize a guard-page violation; decode it; record in
    // the log; emit jsonl; parse back.
    let v = decode_guard_violation(STATUS_GUARD_PAGE_VIOLATION, &[1, 0x140005678]).expect("decode");
    assert_eq!(v.access, GuardAccessKind::Write);

    let mut log = WriteLog::new();
    log.record_access(100, 0x140001000, v.faulting_address, v.access, Some(0));

    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("guard_page_log.jsonl");
    log.emit_jsonl(&path).expect("emit");
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains("0x0000000140005678"));
    assert!(text.contains("\"access\":\"write\""));
}
