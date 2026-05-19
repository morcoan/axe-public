//! Itanium ABI `.eh_frame` / LSDA exception-handling extractor.
//!
//! Walks the `.eh_frame` section (CIE / FDE records) via `gimli` and
//! emits one [`EhFunctionFact`] per FDE. The LSDA pointer is recorded
//! as evidence; full LSDA content (call-site, action, type tables)
//! lands in a follow-up alongside the FH4 work — see
//! [`crate::eh::lsda`].
//!
//! Used for ELF and Mach-O binaries (PE goes through FH3 / FH4 / SEH).

#![allow(dead_code)]

use gimli::{BaseAddresses, CieOrFde, EhFrame, RunTimeEndian, UnwindSection};
use object::{Object, ObjectSection};

use crate::eh::fact::{EhAbi, EhFunctionFact, UnwindRange, EH_SCHEMA};
use crate::facts::{Claim, ClaimSource, EvidenceRef};
use crate::image::BinaryImage;

pub fn extract_itanium(image: &dyn BinaryImage) -> Vec<EhFunctionFact> {
    let Ok(obj) = object::read::File::parse(image.bytes()) else {
        return Vec::new();
    };
    let Some(eh_section) = obj.section_by_name(".eh_frame") else {
        return Vec::new();
    };
    let eh_data = match eh_section.uncompressed_data() {
        Ok(data) => data.into_owned(),
        Err(_) => return Vec::new(),
    };
    if eh_data.is_empty() {
        return Vec::new();
    }

    let endian = if obj.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let eh_frame = EhFrame::new(&eh_data, endian);
    let bases = BaseAddresses::default().set_eh_frame(eh_section.address());

    let mut facts = Vec::new();
    let mut entries = eh_frame.entries(&bases);
    loop {
        let entry = match entries.next() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => break,
        };
        let partial = match entry {
            CieOrFde::Cie(_) => continue,
            CieOrFde::Fde(partial) => partial,
        };
        let fde = match partial.parse(EhFrame::cie_from_offset) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let pc_start = fde.initial_address();
        let pc_end = pc_start.wrapping_add(fde.len());
        let has_lsda = fde.lsda().is_some();

        let abi = if has_lsda {
            EhAbi::ItaniumCxx
        } else {
            EhAbi::ItaniumCleanup
        };
        // Confidence: with LSDA we have real EH structure; without, we
        // only know the unwind range (still useful but lower signal).
        let score = if has_lsda { 0.93 } else { 0.70 };

        let mut evidence = vec![EvidenceRef::Section {
            name: ".eh_frame".into(),
            va: pc_start,
        }];
        if let Some(lsda) = fde.lsda() {
            let va = match lsda {
                gimli::Pointer::Direct(v) | gimli::Pointer::Indirect(v) => v,
            };
            evidence.push(EvidenceRef::RawAddr { va });
        }

        // The personality for Itanium C++ EH is typically
        // `__gxx_personality_v0`. The exact symbol resolution requires
        // matching the personality pointer (from the CIE) against the
        // dynamic symbol table; deferring that to a follow-up keeps
        // step 6 focused on the walker plumbing.
        let personality = if has_lsda {
            Some("__gxx_personality_v0".to_string())
        } else {
            None
        };

        facts.push(EhFunctionFact {
            schema: EH_SCHEMA,
            function_va: pc_start,
            function_end_va: pc_end,
            abi,
            personality,
            personality_va: None,
            unwind_ranges: vec![UnwindRange {
                begin_va: pc_start,
                end_va: pc_end,
            }],
            try_regions: Vec::new(),
            catch_handlers: Vec::new(),
            cleanup_actions: Vec::new(),
            claim: Claim::new((), ClaimSource::ExceptionHandling)
                .with_score(score)
                .with_evidence(evidence),
        });
    }

    let _ = image; // image is used for format dispatch upstream; bytes
                   // come via the object crate's re-parse here.
    facts
}

#[cfg(test)]
mod tests {
    // Integration of this pass against a synthesized ELF with a real
    // .eh_frame section is exercised by the step-15 real-binary smoke
    // test. Unit tests here would essentially re-test gimli; the
    // value-add is in the wiring + EhFunctionFact shape, which the
    // step-15 invariant test covers end-to-end.
    //
    // A targeted regression test for "no .eh_frame → empty Vec" is
    // also covered by the existing tests/multi_format.rs ELF fixture,
    // which has no .eh_frame and asserts the file is empty JSONL.
}
