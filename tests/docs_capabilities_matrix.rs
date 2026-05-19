//! Smoke test: `docs/unpack-capabilities.md` carries the four cell strings
//! that Phase B6 requires for the new honest-tier matrix. Cheap defense
//! against unintended doc rewrites that would break the "honest tier"
//! invariant called out by `src/unpack/mod.rs:16-29`.

use std::fs;

#[test]
fn capabilities_matrix_contains_required_cells() {
    let content = fs::read_to_string("docs/unpack-capabilities.md")
        .expect("docs/unpack-capabilities.md should be readable from repo root");

    // The four cell strings the Phase B6 plan requires:
    //   1. Themida ≤2.x row (legacy tier).
    //   2. Themida 3.x row (capped 3.x tier).
    //   3. best_effort label (the floor for both new rows).
    //   4. devirt_trace.jsonl artifact column for both new rows.
    for cell in [
        "Themida ≤2.x",
        "Themida 3.x",
        "best_effort",
        "devirt_trace.jsonl",
    ] {
        assert!(
            content.contains(cell),
            "docs/unpack-capabilities.md is missing required cell string {:?}",
            cell
        );
    }

    // The 0.40 cap rule MUST be referenced — that's the architectural promise
    // of Phase B5. Without this language the matrix can claim "best_effort"
    // for Themida 3.x without the reader knowing what guarantees it.
    assert!(
        content.contains("0.40") || content.contains("themida_3x_partial"),
        "docs/unpack-capabilities.md must reference the 0.40 cap rule or its \
         cap_reason marker"
    );

    // tier_for_score reference confirms the doc points at the canonical
    // enforcement site in src/unpack/snapshot.rs.
    assert!(
        content.contains("tier_for_score") || content.contains("snapshot.rs"),
        "docs/unpack-capabilities.md must point at tier_for_score / snapshot.rs \
         so future-readers can audit the enforcement"
    );
}
