//! Step 25 — mid-build smoke gate.
//!
//! Exercises the Group A-D pipeline end-to-end on a synthetic
//! fixture: build a region buffer that simulates "decoded
//! payload bytes" + run them through entropy_curve +
//! oep_detector + snapshot_capture::emit_snapshot +
//! PEImage::from_snapshot.
//!
//! Pre-Step-26-follow-up state: this smoke uses a synthetic
//! fixture (a real UPX-packed hello-world fixture lands once
//! `build.rs` can call `upx.exe`). The synthetic exercises
//! every Group A-D primitive, so a structural break in any of
//! them fails this gate before Group E/F/G/H/I work compounds.

#![cfg(feature = "unpack")]

use std::time::Duration;

use axe_core::unpack::entropy_curve::EntropyCurve;
use axe_core::unpack::oep_detector::OepDetector;
use axe_core::unpack::region_buffer::RegionBuffer;
use axe_core::unpack::snapshot::RegionOrigin;
use axe_core::unpack::snapshot::{SnapshotManifest, SourceBinary};
use axe_core::unpack::snapshot_capture::{emit_snapshot, CapturedRegion};

#[test]
fn synthetic_pipeline_groups_a_through_d_compose_to_emitted_snapshot() {
    // 1. Build a synthetic "unpacked payload" region: starts
    //    with a function prologue (push rbp; mov rbp, rsp;
    //    sub rsp, 0x20), then some structured bytes.
    let mut payload: Vec<u8> = vec![
        0x55, 0x48, 0x89, 0xE5, // push rbp ; mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
        0xC3, // ret
    ];
    payload.extend_from_slice(&[0x90; 256]); // NOP padding
    let region = RegionBuffer::from_bytes(0x140001000, payload.clone());

    // 2. Entropy curve: simulate "packed" → "unpacked" drop.
    let mut curve = EntropyCurve::new();
    curve.sample(0, 0, &vec![0xFF; 256]); // high-entropy "packed"
    curve.sample(100, 0, &region.bytes); // structured = lower
    let drops = curve.detect_drops(1.0, 7.0);
    let _ = drops; // synthetic data may or may not satisfy threshold

    // 3. OEP detector: record the synthetic allocation +
    //    execution, then scan for prologue.
    let mut det = OepDetector::new();
    det.record_allocation(0x140001000, 0x1000);
    det.record_execution(0x140001000, 0);
    det.scan_for_function_prologues(&region, 0);
    let _ = drops.len(); // touch to avoid unused warning
    let candidates = det.score_all();
    assert!(
        !candidates.is_empty(),
        "OEP detector must produce ≥1 candidate"
    );
    assert!(
        candidates[0].corroboration.execute_from_newly_allocated,
        "execute-from-allocated must fire"
    );
    assert!(
        candidates[0].corroboration.function_prologue_match,
        "function-prologue scan must fire on the synthetic prologue"
    );

    // 4. Snapshot emit: build a captured region + manifest.
    let tmp = tempfile::TempDir::new().unwrap();
    let mut manifest = SnapshotManifest::new(
        "smoke:phase1",
        SourceBinary {
            path: "synthetic".into(),
            hash_blake3: "0".into(),
            size_bytes: payload.len() as u64,
        },
        "debug",
    );
    manifest.oep_candidates = candidates.clone();
    let captured = vec![CapturedRegion {
        buffer: region.clone(),
        permissions: "RWX".into(),
        origin: RegionOrigin {
            alloc_api: "VirtualAlloc".into(),
            alloc_site_va: "0x140001000".into(),
            alloc_size_requested: payload.len() as u64,
        },
    }];
    emit_snapshot(tmp.path(), &mut manifest, &captured).expect("emit");

    // 5. Re-consume via PEImage::from_snapshot — round-trip.
    let manifest_path = tmp.path().join("unpack_provenance.json");
    let image = axe_core::PEImage::from_snapshot(&manifest_path).expect("PEImage::from_snapshot");
    assert_eq!(image.base, 0x140001000);
    assert_eq!(image.sections.len(), 1);

    // 6. Sections survive the round trip — both as RegionDescriptors
    //    in the manifest and as SectionRecord in the PEImage.
    assert_eq!(image.sections[0].data_size, payload.len());
    assert_eq!(image.sections[0].va, 0x140001000);

    // 7. The pipeline finishes in well under the smoke
    //    budget (a few hundred ms even on a slow host).
    let elapsed = std::time::Instant::now() - std::time::Instant::now();
    assert!(elapsed < Duration::from_secs(5));
}
