//! C++ class layout reconstruction.
//!
//! Layered on top of the existing `crate::cpp` vtable-ownership pass
//! and `VTableRecord`/`RttiRecord`/`DebugTypeRecord` outputs. Emits
//! rich [`ClassFact`] records carrying source attribution
//! (PDB / DWARF / MSVC RTTI / Itanium ABI / heuristic), per-field
//! confidence (via [`crate::facts::Claim`]), and evidence references.
//!
//! Step 8 ships only the demangling shim ([`names`]). Step 9 adds the
//! fact types and PDB layout pass; step 10 the MSVC RTTI walker; step
//! 11 multi-inheritance + adjustor thunks; step 12 the Itanium ABI
//! walker; step 13 the heuristic constraint collector; step 14 the
//! cross-source merge solver; step 15 the cross-fixture coverage
//! invariant.

#![allow(dead_code)]

pub mod fact;
pub mod heuristic;
pub mod itanium_abi;
pub mod msvc_rtti;
pub mod names;
pub mod pdb_layout;
pub mod solver;
pub mod thunks;

pub use fact::{
    build_class_id, BaseClassFact, ClassFact, CppAbi, FieldFact, MethodFact, VTableFact,
    CLASS_SCHEMA,
};

use crate::debug_symbols::DebugTypeRecord;
use crate::image::Format;
use crate::ir::IrInstruction;
use crate::pe::{FunctionRecord, RttiRecord, StringRecord, TypeHintRecord, VTableRecord};
use crate::semantic_index::FunctionSemanticIndex;

/// Build [`ClassFact`] rows from every available source, then
/// cross-source merge so each class appears exactly once.
///
/// Step 14 (final): runs PDB/DWARF + MSVC RTTI (with thunk
/// enrichment) + Itanium typeinfo + heuristic ctor analysis →
/// solver merger → field-type enrichment.
pub fn build_class_facts(
    debug_types: &[DebugTypeRecord],
    vtables: &[VTableRecord],
    rtti: &[RttiRecord],
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    strings: &[StringRecord],
    image_format: Format,
    type_hints: &[TypeHintRecord],
) -> Vec<ClassFact> {
    let adjustor_thunks = thunks::detect_adjustor_thunks(functions, semantic_index, ir);
    let mut layered = pdb_layout::collect(debug_types);
    layered.extend(msvc_rtti::collect(vtables, rtti, &adjustor_thunks));
    layered.extend(itanium_abi::collect(strings, image_format));
    layered.extend(heuristic::collect(functions, semantic_index, ir));
    let mut merged = solver::merge(layered);
    solver::enrich_field_types(&mut merged, type_hints);
    merged
}
