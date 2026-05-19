//! Exception-handling fact extraction.
//!
//! Consumes the existing [`ExceptionRecord`] rows from
//! [`crate::pe`] (raw `.pdata` entries) and lifts each one into a
//! normalized [`EhFunctionFact`] under
//! [`crate::facts::ClaimSource::ExceptionHandling`].
//!
//! Step 4 ships the FH3 path (`__CxxFrameHandler3`). Step 5 adds SEH,
//! step 6 adds Itanium `.eh_frame`/LSDA, step 7 adds the
//! highest-risk FH4 packed format.

#![allow(dead_code)]

pub mod catch_resolver;
pub mod fact;
pub mod itanium;
pub mod lsda;
pub mod pe_fh3;
pub mod pe_fh4;
pub mod pe_seh;
pub mod pe_unwind;

pub use fact::{
    CatchHandler, CatchKind, CleanupAction, EhAbi, EhFunctionFact, TryRegion, UnwindRange,
    EH_SCHEMA,
};

use crate::facts::{Claim, ClaimSource, EvidenceRef};
use crate::image::BinaryImage;
use crate::pe::{ExceptionRecord, ImportRecord, RttiRecord};

/// Walk every `.pdata` exception record, classify the personality
/// routine, and dispatch to the corresponding per-ABI parser.
pub fn extract_eh(
    image: &dyn BinaryImage,
    exceptions: &[ExceptionRecord],
    imports: &[ImportRecord],
    rtti: &[RttiRecord],
) -> Vec<EhFunctionFact> {
    if exceptions.is_empty() {
        return Vec::new();
    }
    let Some(pe) = image.as_pe() else {
        // Non-PE images: dispatch to the Itanium `.eh_frame` walker.
        return itanium::extract_itanium(image);
    };

    let resolver = catch_resolver::CatchResolver::from_rtti(rtti);
    let mut facts = Vec::new();

    for exc in exceptions {
        let Some(unwind) = pe_unwind::parse_unwind_info(pe, exc) else {
            continue;
        };
        if !unwind.has_exception_handler() {
            // Pure unwind-only entry (no language handler).
            continue;
        }
        let personality = pe_unwind::resolve_personality(&unwind, imports);

        let fact_opt = match personality.kind {
            pe_unwind::PersonalityKind::CxxFrameHandler3 => {
                pe_fh3::parse_fh3(pe, exc, &unwind, &personality, &resolver)
            }
            pe_unwind::PersonalityKind::CxxFrameHandler4 => {
                pe_fh4::parse_fh4(pe, exc, &unwind, &personality)
            }
            pe_unwind::PersonalityKind::CSpecificHandler => {
                pe_seh::parse_seh(pe, exc, &unwind, &personality, false)
            }
            pe_unwind::PersonalityKind::GSHandlerCheckEH => {
                pe_seh::parse_seh(pe, exc, &unwind, &personality, true)
            }
            // GxxPersonalityV0 on PE (MinGW) — Itanium path; rare. Falls
            // through to Unknown until that cross-format edge case lands.
            pe_unwind::PersonalityKind::GxxPersonalityV0 | pe_unwind::PersonalityKind::Unknown => {
                Some(unknown_fact(exc, &personality))
            }
        };

        if let Some(fact) = fact_opt {
            facts.push(fact);
        }
    }

    facts
}

/// Low-confidence placeholder fact for personalities not yet decoded
/// in this slice. Records the unwind range, personality name, and
/// confidence 0.40 so consumers can tell that EH metadata is present
/// even if the parser cannot reach the per-ABI structures yet.
fn unknown_fact(exc: &ExceptionRecord, personality: &pe_unwind::Personality) -> EhFunctionFact {
    EhFunctionFact {
        schema: EH_SCHEMA,
        function_va: exc.begin,
        function_end_va: exc.end,
        abi: EhAbi::Unknown,
        personality: personality.name.clone(),
        personality_va: personality.va,
        unwind_ranges: vec![UnwindRange {
            begin_va: exc.begin,
            end_va: exc.end,
        }],
        try_regions: Vec::new(),
        catch_handlers: Vec::new(),
        cleanup_actions: Vec::new(),
        claim: Claim::new((), ClaimSource::ExceptionHandling)
            .with_score(0.40)
            .with_evidence(vec![EvidenceRef::Section {
                name: ".pdata".into(),
                va: exc.begin,
            }]),
    }
}
