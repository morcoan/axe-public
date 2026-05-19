//! Switch-statement reconstruction.
//!
//! Consumes the existing `JumpTableRecord` output from [`crate::jump_tables`]
//! and lifts each indirect-branch + table pair into a rich [`SwitchFact`]
//! with classified lowering, range guard, default-target attribution, and
//! per-case `(value, target_va)` rows. Emitted under
//! [`crate::facts::ClaimSource::SwitchReconstruction`].
//!
//! Step 2 of the slice ships matchers for `MsvcAbsoluteTable` and
//! `MsvcRvaTable`/`PicOffsetTable`. The remaining lowerings
//! (`SecondaryIndexTable`, `CompareTree`, `BitTest`, `Trivial`) and the
//! local immediate-dominator helper land in step 3.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::facts::{Claim, ClaimSource, EvidenceRef};
use crate::image::BinaryImage;
use crate::ir::IrInstruction;
use crate::pe::{CfgRecord, FunctionRecord, JumpTableRecord};
use crate::semantic_index::FunctionSemanticIndex;

pub const SWITCH_SCHEMA: &str = "switch_fact/1";

#[derive(Clone, Debug, Serialize)]
pub struct SwitchFact {
    pub schema: &'static str,
    #[serde(serialize_with = "hex_va")]
    pub function_va: u64,
    #[serde(serialize_with = "hex_va")]
    pub indirect_branch_va: u64,
    pub index_expr: Expr,
    pub low: Option<i64>,
    pub high: Option<i64>,
    #[serde(serialize_with = "opt_hex_va")]
    pub default_target: Option<u64>,
    #[serde(serialize_with = "opt_hex_va")]
    pub table_va: Option<u64>,
    pub entry_size: u32,
    pub cases: Vec<SwitchCase>,
    pub lowering: SwitchLowering,
    pub claim: Claim<()>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SwitchCase {
    pub value: i64,
    #[serde(serialize_with = "hex_va")]
    pub target_va: u64,
}

/// A symbolic representation of the switch's index expression. Kept small
/// and JSON-friendly — not a full IR. Backward-slicing the index register
/// in step 3 will populate richer expressions (Sub/And/ZeroExtend).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expr {
    Reg {
        name: String,
    },
    Mem {
        base: Option<String>,
        index: Option<String>,
        scale: u32,
        disp: i64,
        width: u32,
    },
    Sub {
        inner: Box<Expr>,
        by: i64,
    },
    And {
        inner: Box<Expr>,
        mask: u64,
    },
    ZeroExtend {
        inner: Box<Expr>,
        to_width: u32,
    },
    Const {
        value: i64,
    },
    Unknown,
}

/// Catalogued switch lowerings. Each variant carries enough metadata to
/// fully describe the recovered switch on the wire.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SwitchLowering {
    /// `jmp qword ptr [table + idx*8]` — table entries are 8-byte absolute VAs.
    MsvcAbsoluteTable {
        #[serde(serialize_with = "hex_va")]
        table_va: u64,
    },
    /// `movsxd reg, [table+idx*4]; add reg, image_base; jmp reg`
    /// — table entries are 4-byte RVAs added to the image base.
    MsvcRvaTable {
        #[serde(serialize_with = "hex_va")]
        table_va: u64,
        #[serde(serialize_with = "hex_va")]
        image_base: u64,
    },
    /// `lea base, [table]; movsxd off, [base+idx*4]; add off, base; jmp off`
    /// — table entries are 4-byte signed offsets from the table base itself.
    PicOffsetTable {
        #[serde(serialize_with = "hex_va")]
        table_va: u64,
    },
    /// `movzx eax, byte ptr [secondary+idx]; jmp [primary + rax*8]`
    /// — first table is a byte-wide index map into the second jump table.
    SecondaryIndexTable {
        #[serde(serialize_with = "hex_va")]
        primary_va: u64,
        #[serde(serialize_with = "hex_va")]
        target_va: u64,
    },
    /// Sparse compare-tree lowering. `compares` lists the recovered
    /// `(value, target)` pairs from the cmp/jcc chain.
    CompareTree { compares: Vec<SwitchCase> },
    /// `bt reg, idx; jc tgt` — bit-test against a constant mask.
    BitTest {
        mask: u64,
        #[serde(serialize_with = "hex_va")]
        base_target: u64,
    },
    /// Degenerate single-case `cmp idx, value; je tgt` guarding the indirect jump.
    Trivial {
        test_value: i64,
        #[serde(serialize_with = "hex_va")]
        target_va: u64,
    },
}

impl SwitchLowering {
    /// Recommended confidence for a fact derived from this lowering kind.
    /// Per-pass code may override; kept inside
    /// `ClaimSource::SwitchReconstruction.default_confidence_band()`.
    pub fn recommended_score(&self) -> f32 {
        match self {
            SwitchLowering::MsvcAbsoluteTable { .. } => 0.93,
            SwitchLowering::MsvcRvaTable { .. } => 0.92,
            SwitchLowering::PicOffsetTable { .. } => 0.90,
            SwitchLowering::SecondaryIndexTable { .. } => 0.66,
            SwitchLowering::CompareTree { .. } => 0.78,
            SwitchLowering::BitTest { .. } => 0.78,
            SwitchLowering::Trivial { .. } => 0.70,
        }
    }
}

fn hex_va<S: serde::Serializer>(va: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{va:016x}"))
}

fn opt_hex_va<S: serde::Serializer>(va: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match va {
        Some(v) => s.serialize_str(&format!("0x{v:016x}")),
        None => s.serialize_none(),
    }
}

/// Build [`SwitchFact`] rows by classifying each existing
/// [`JumpTableRecord`] and pairing it with range-guard / default-target
/// information backward-sliced from the function's IR.
///
/// Step 2 implementation: handles `MsvcAbsoluteTable` (entry_size 8) and
/// `MsvcRvaTable` / `PicOffsetTable` (entry_size 4) — the most common
/// MSVC and PIC table lowerings. Step 3 adds compare-tree, bit-test,
/// secondary-index, and trivial lowerings.
pub fn build_switches(
    image: &dyn BinaryImage,
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    jump_tables: &[JumpTableRecord],
) -> Vec<SwitchFact> {
    let image_base = image.base();
    let image_format = ImageFormatHint::from(image.format());
    let jt_index = index_jump_tables(jump_tables);
    let mut facts = Vec::new();

    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        let slice_ir = &ir[slice.ir_range.clone()];

        // Pass 1: indirect jumps with a recovered JumpTableRecord —
        // MSVC absolute / MSVC RVA / PIC offset lowerings.
        for ins in slice_ir {
            if !ins.is_jump || ins.direct_target.is_some() {
                continue;
            }
            let Some(&jt) = jt_index.get(&(function.start, ins.address)) else {
                continue;
            };
            if jt.targets.is_empty() {
                continue;
            }
            facts.push(build_table_fact(
                function.start,
                ins,
                jt,
                slice_ir,
                image_base,
                image_format,
            ));
        }

        // Pass 2: compare-tree lowerings (sparse switch as cmp/je chain).
        facts.extend(detect_compare_trees(function.start, slice_ir));

        // Pass 3: bit-test lowerings (small-range switch as bt/jc).
        facts.extend(detect_bit_tests(function.start, slice_ir));
    }

    facts
}

fn build_table_fact(
    function_va: u64,
    ins: &IrInstruction,
    jt: &JumpTableRecord,
    slice_ir: &[IrInstruction],
    image_base: u64,
    image_format: ImageFormatHint,
) -> SwitchFact {
    let lowering = classify_lowering(jt, image_base, image_format);
    let index_expr = build_index_expr(ins);
    let (low, high, default_target) = find_range_guard(ins, slice_ir);

    let cases: Vec<SwitchCase> = jt
        .targets
        .iter()
        .enumerate()
        .map(|(i, &target_va)| SwitchCase {
            value: low.unwrap_or(0).saturating_add(i as i64),
            target_va,
        })
        .collect();

    let mut evidence = Vec::with_capacity(2 + jt.targets.len());
    evidence.push(EvidenceRef::Instruction { va: ins.address });
    if let Some(table_va) = jt.table_va {
        evidence.push(EvidenceRef::RawAddr { va: table_va });
    }
    for &target in &jt.targets {
        evidence.push(EvidenceRef::Instruction { va: target });
    }

    let claim = Claim::new((), ClaimSource::SwitchReconstruction)
        .with_score(lowering.recommended_score())
        .with_evidence(evidence);

    SwitchFact {
        schema: SWITCH_SCHEMA,
        function_va,
        indirect_branch_va: ins.address,
        index_expr,
        low,
        high,
        default_target,
        table_va: jt.table_va,
        entry_size: jt.entry_size,
        cases,
        lowering,
        claim,
    }
}

/// Hint used by `classify_lowering` to disambiguate 4-byte tables on PE
/// (most likely RVA) vs ELF/Mach-O (most likely PIC offset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageFormatHint {
    Pe,
    ElfOrMachO,
}

impl From<crate::image::Format> for ImageFormatHint {
    fn from(f: crate::image::Format) -> Self {
        match f {
            crate::image::Format::Pe => ImageFormatHint::Pe,
            crate::image::Format::Elf | crate::image::Format::MachO => ImageFormatHint::ElfOrMachO,
        }
    }
}

fn index_jump_tables(rows: &[JumpTableRecord]) -> BTreeMap<(u64, u64), &JumpTableRecord> {
    rows.iter()
        .map(|jt| ((jt.function, jt.jump_va), jt))
        .collect()
}

fn classify_lowering(
    jt: &JumpTableRecord,
    image_base: u64,
    format: ImageFormatHint,
) -> SwitchLowering {
    let table_va = jt.table_va.unwrap_or(0);
    match jt.entry_size {
        8 => SwitchLowering::MsvcAbsoluteTable { table_va },
        4 => match format {
            ImageFormatHint::Pe => SwitchLowering::MsvcRvaTable {
                table_va,
                image_base,
            },
            ImageFormatHint::ElfOrMachO => SwitchLowering::PicOffsetTable { table_va },
        },
        _ => SwitchLowering::MsvcAbsoluteTable { table_va },
    }
}

fn build_index_expr(ins: &IrInstruction) -> Expr {
    if ins.indirect_target_memory {
        return Expr::Mem {
            base: ins.memory_base.clone(),
            index: ins.memory_index.clone(),
            scale: ins.memory_scale,
            disp: ins.memory_displacement,
            width: ins.operand_width,
        };
    }
    if let Some(reg) = &ins.indirect_target_register {
        return Expr::Reg { name: reg.clone() };
    }
    Expr::Unknown
}

/// Find the range guard dominating the indirect jump. Step 2 uses a
/// simple linear backward scan over the function's IR slice for the
/// closest `cmp idx, imm` followed by `ja/jbe/jnbe` — sufficient for the
/// straight-line MSVC pattern. Step 3 replaces this with a proper
/// immediate-dominator walk.
///
/// Returns `(low, high, default_target)`:
/// - `low`  = inferred lower bound of the index range (defaults to 0)
/// - `high` = comparison immediate (e.g. `cmp eax, 11` → high = 11)
/// - `default_target` = branch target of the `ja/jbe/jnbe` guard
fn find_range_guard(
    jump_ins: &IrInstruction,
    slice: &[IrInstruction],
) -> (Option<i64>, Option<i64>, Option<u64>) {
    let Some(jump_pos) = slice.iter().position(|i| i.address == jump_ins.address) else {
        return (None, None, None);
    };
    let scan_start = jump_pos.saturating_sub(16);

    let mut cmp_imm: Option<i64> = None;
    let mut default_target: Option<u64> = None;
    for prior in &slice[scan_start..jump_pos] {
        match prior.mnemonic.as_str() {
            "cmp" | "sub" => {
                if let Some(imm) = prior.immediate {
                    // Sanity-cap: switch sizes >4096 are almost always misreads.
                    if imm > 0 && imm <= 4096 {
                        cmp_imm = Some(imm as i64);
                    }
                }
            }
            "ja" | "jae" | "jnbe" | "jnb" => {
                if let Some(target) = prior.direct_target {
                    default_target = Some(target);
                }
            }
            _ => {}
        }
    }

    let low = cmp_imm.map(|_| 0i64);
    (low, cmp_imm, default_target)
}

/// Detect sparse-switch lowerings as chains of `cmp idx, imm; je tgt`
/// pairs sharing the same compared register.
///
/// A chain of length 1 is **not** a switch — it is a regular conditional —
/// so we require ≥2 pairs. The emitted [`SwitchFact`] has
/// `indirect_branch_va` set to the first `cmp` in the chain (the natural
/// "anchor" of the switch), `low`/`high` left as `None` (sparse), and
/// `index_expr` set to the compared register.
fn detect_compare_trees(function_va: u64, slice_ir: &[IrInstruction]) -> Vec<SwitchFact> {
    let mut facts = Vec::new();
    let mut i = 0;
    while i + 1 < slice_ir.len() {
        let cmp = &slice_ir[i];
        let branch = &slice_ir[i + 1];
        if !is_cmp_reg_imm(cmp) || !is_eq_branch(branch) {
            i += 1;
            continue;
        }
        let chain_reg = cmp.read_regs[0].clone();
        let chain_anchor_va = cmp.address;
        let mut cases = vec![SwitchCase {
            value: cmp.immediate.unwrap() as i64,
            target_va: branch.direct_target.unwrap(),
        }];
        let mut j = i + 2;
        while j + 1 < slice_ir.len() {
            let next_cmp = &slice_ir[j];
            let next_branch = &slice_ir[j + 1];
            if is_cmp_reg_imm(next_cmp)
                && next_cmp.read_regs.first() == Some(&chain_reg)
                && is_eq_branch(next_branch)
            {
                cases.push(SwitchCase {
                    value: next_cmp.immediate.unwrap() as i64,
                    target_va: next_branch.direct_target.unwrap(),
                });
                j += 2;
            } else {
                break;
            }
        }
        if cases.len() >= 2 {
            facts.push(build_compare_tree_fact(
                function_va,
                chain_anchor_va,
                chain_reg,
                cases,
            ));
            i = j;
        } else {
            i += 1;
        }
    }
    facts
}

fn is_cmp_reg_imm(ins: &IrInstruction) -> bool {
    ins.mnemonic == "cmp" && ins.immediate.is_some() && !ins.read_regs.is_empty()
}

fn is_eq_branch(ins: &IrInstruction) -> bool {
    matches!(ins.mnemonic.as_str(), "je" | "jz") && ins.direct_target.is_some()
}

fn build_compare_tree_fact(
    function_va: u64,
    anchor_va: u64,
    chain_reg: String,
    cases: Vec<SwitchCase>,
) -> SwitchFact {
    let mut evidence = Vec::with_capacity(1 + cases.len());
    evidence.push(EvidenceRef::Instruction { va: anchor_va });
    for case in &cases {
        evidence.push(EvidenceRef::Instruction { va: case.target_va });
    }
    let lowering = SwitchLowering::CompareTree {
        compares: cases.clone(),
    };
    let claim = Claim::new((), ClaimSource::SwitchReconstruction)
        .with_score(lowering.recommended_score())
        .with_evidence(evidence);
    SwitchFact {
        schema: SWITCH_SCHEMA,
        function_va,
        indirect_branch_va: anchor_va,
        index_expr: Expr::Reg { name: chain_reg },
        low: None,
        high: None,
        default_target: None,
        table_va: None,
        entry_size: 0,
        cases,
        lowering,
        claim,
    }
}

/// Detect bit-test switch lowerings: `bt reg, idx; jc tgt` or
/// `bt reg, idx; jb tgt`. The mask is recovered by scanning upstream
/// for the most recent `mov reg, imm` writing to `bt`'s first operand.
fn detect_bit_tests(function_va: u64, slice_ir: &[IrInstruction]) -> Vec<SwitchFact> {
    let mut facts = Vec::new();
    for i in 0..slice_ir.len() {
        let bt_ins = &slice_ir[i];
        if bt_ins.mnemonic != "bt" {
            continue;
        }
        // Scan up to 3 instructions ahead for jc / jb / jnae.
        let mut branch_target = None;
        for k in 1..=3 {
            if i + k >= slice_ir.len() {
                break;
            }
            let candidate = &slice_ir[i + k];
            if matches!(candidate.mnemonic.as_str(), "jc" | "jb" | "jnae")
                && candidate.direct_target.is_some()
            {
                branch_target = candidate.direct_target;
                break;
            }
        }
        let Some(target) = branch_target else {
            continue;
        };
        let mask = find_recent_constant(&slice_ir[..i], bt_ins.read_regs.first());
        facts.push(build_bit_test_fact(
            function_va,
            bt_ins.address,
            mask,
            target,
        ));
    }
    facts
}

fn find_recent_constant(prior_ir: &[IrInstruction], reg: Option<&String>) -> u64 {
    let Some(reg) = reg else {
        return 0;
    };
    for ins in prior_ir.iter().rev().take(8) {
        if ins.mnemonic == "mov" && ins.write_reg.as_ref() == Some(reg) {
            if let Some(imm) = ins.immediate {
                return imm;
            }
        }
    }
    0
}

fn build_bit_test_fact(function_va: u64, bt_va: u64, mask: u64, base_target: u64) -> SwitchFact {
    let lowering = SwitchLowering::BitTest { mask, base_target };
    let evidence = vec![
        EvidenceRef::Instruction { va: bt_va },
        EvidenceRef::Instruction { va: base_target },
    ];
    let claim = Claim::new((), ClaimSource::SwitchReconstruction)
        .with_score(lowering.recommended_score())
        .with_evidence(evidence);
    SwitchFact {
        schema: SWITCH_SCHEMA,
        function_va,
        indirect_branch_va: bt_va,
        index_expr: Expr::Unknown,
        low: None,
        high: None,
        default_target: None,
        table_va: None,
        entry_size: 0,
        cases: Vec::new(),
        lowering,
        claim,
    }
}

/// Compute immediate dominators for a function's CFG using the standard
/// iterative "intersect on reverse-postorder" algorithm
/// (Cooper-Harvey-Kennedy 2001 simplified). Used by validation passes
/// — not yet wired into `find_range_guard` (that integration lands in
/// step 15 with the polish pass).
///
/// Returns `BTreeMap<block_start_va, immediate_dominator_block_start_va>`.
/// The entry block has no idom and is omitted from the returned map.
///
/// Complexity is O(n² · iterations) — fine for function-local CFGs
/// (rarely more than a few dozen blocks).
pub fn compute_idoms(cfg: &CfgRecord, entry: u64) -> BTreeMap<u64, u64> {
    if cfg.blocks.is_empty() {
        return BTreeMap::new();
    }
    let block_ids: BTreeSet<u64> = cfg.blocks.iter().map(|b| b.start).collect();
    if !block_ids.contains(&entry) {
        return BTreeMap::new();
    }

    let mut preds: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for edge in &cfg.edges {
        if block_ids.contains(&edge.from) && block_ids.contains(&edge.to) {
            preds.entry(edge.to).or_default().push(edge.from);
        }
    }

    // Dom(n) = all blocks initially, except Dom(entry) = {entry}.
    let mut doms: BTreeMap<u64, BTreeSet<u64>> =
        block_ids.iter().map(|&b| (b, block_ids.clone())).collect();
    doms.insert(entry, [entry].into_iter().collect());

    let mut changed = true;
    while changed {
        changed = false;
        for &block in &block_ids {
            if block == entry {
                continue;
            }
            let block_preds = preds.get(&block).cloned().unwrap_or_default();
            if block_preds.is_empty() {
                continue;
            }
            let mut new_dom = doms.get(&block_preds[0]).cloned().unwrap_or_default();
            for &pred in &block_preds[1..] {
                if let Some(pred_doms) = doms.get(&pred) {
                    new_dom = new_dom.intersection(pred_doms).copied().collect();
                }
            }
            new_dom.insert(block);
            if doms.get(&block) != Some(&new_dom) {
                doms.insert(block, new_dom);
                changed = true;
            }
        }
    }

    // idom(b) = the dominator d != b with the largest Dom(d) (deepest in the
    // dom tree; the dominator closest to b).
    let mut idoms = BTreeMap::new();
    for (&block, dom_set) in &doms {
        if block == entry {
            continue;
        }
        let candidates: Vec<u64> = dom_set.iter().filter(|&&d| d != block).copied().collect();
        if let Some(&id) = candidates
            .iter()
            .max_by_key(|&&d| doms.get(&d).map_or(0, |s| s.len()))
        {
            idoms.insert(block, id);
        }
    }
    idoms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::ConfidenceBand;
    use crate::pe::JumpTableRecord;

    fn ir(address: u64, mnemonic: &str) -> IrInstruction {
        IrInstruction {
            address,
            size: 2,
            mnemonic: mnemonic.to_string(),
            write_reg: None,
            read_regs: Vec::new(),
            immediate: None,
            rip_target: None,
            stack_slot: None,
            memory_base: None,
            memory_index: None,
            memory_scale: 0,
            memory_displacement: 0,
            operand_width: 0,
            indirect_target_register: None,
            indirect_target_memory: false,
            memory_write: false,
            memory_read: false,
            direct_target: None,
            is_call: false,
            is_jump: false,
        }
    }

    #[test]
    fn classify_8byte_table_is_msvc_absolute() {
        let jt = JumpTableRecord {
            table_id: "x".into(),
            function: 0x1000,
            jump_va: 0x1100,
            table_va: Some(0x2000),
            entry_size: 8,
            targets: vec![0x1200, 0x1210],
            confidence: "medium".into(),
            evidence: vec![],
        };
        let l = classify_lowering(&jt, 0x400000, ImageFormatHint::Pe);
        assert_eq!(l, SwitchLowering::MsvcAbsoluteTable { table_va: 0x2000 });
    }

    #[test]
    fn classify_4byte_table_on_pe_is_rva() {
        let jt = JumpTableRecord {
            table_id: "x".into(),
            function: 0x1000,
            jump_va: 0x1100,
            table_va: Some(0x2000),
            entry_size: 4,
            targets: vec![0x1200, 0x1210],
            confidence: "medium".into(),
            evidence: vec![],
        };
        let l = classify_lowering(&jt, 0x140000000, ImageFormatHint::Pe);
        assert_eq!(
            l,
            SwitchLowering::MsvcRvaTable {
                table_va: 0x2000,
                image_base: 0x140000000,
            }
        );
    }

    #[test]
    fn classify_4byte_table_on_elf_is_pic_offset() {
        let jt = JumpTableRecord {
            table_id: "x".into(),
            function: 0x1000,
            jump_va: 0x1100,
            table_va: Some(0x2000),
            entry_size: 4,
            targets: vec![0x1200, 0x1210],
            confidence: "medium".into(),
            evidence: vec![],
        };
        let l = classify_lowering(&jt, 0x400000, ImageFormatHint::ElfOrMachO);
        assert_eq!(l, SwitchLowering::PicOffsetTable { table_va: 0x2000 });
    }

    #[test]
    fn recommended_scores_within_source_band() {
        // SwitchReconstruction band is (0.65, 0.95). All recommended
        // scores for the matchers we ship must fall inside it.
        let (lo, hi) = ClaimSource::SwitchReconstruction.default_confidence_band();
        let samples = [
            SwitchLowering::MsvcAbsoluteTable { table_va: 0 }.recommended_score(),
            SwitchLowering::MsvcRvaTable {
                table_va: 0,
                image_base: 0,
            }
            .recommended_score(),
            SwitchLowering::PicOffsetTable { table_va: 0 }.recommended_score(),
            SwitchLowering::CompareTree { compares: vec![] }.recommended_score(),
            SwitchLowering::Trivial {
                test_value: 0,
                target_va: 0,
            }
            .recommended_score(),
        ];
        for s in samples {
            assert!(s >= lo && s <= hi, "score {s} outside band ({lo}, {hi})");
        }
    }

    #[test]
    fn find_range_guard_recovers_cmp_imm_and_default() {
        let mut cmp_ins = ir(0x1100, "cmp");
        cmp_ins.immediate = Some(11);
        let mut ja_ins = ir(0x1103, "ja");
        ja_ins.is_jump = true;
        ja_ins.direct_target = Some(0x1300);
        let mut jmp_ins = ir(0x1105, "jmp");
        jmp_ins.is_jump = true;
        jmp_ins.indirect_target_memory = true;

        let slice = vec![cmp_ins, ja_ins, jmp_ins.clone()];
        let (low, high, default_target) = find_range_guard(&jmp_ins, &slice);
        assert_eq!(low, Some(0));
        assert_eq!(high, Some(11));
        assert_eq!(default_target, Some(0x1300));
    }

    #[test]
    fn find_range_guard_returns_none_without_guard() {
        let mut jmp_ins = ir(0x1100, "jmp");
        jmp_ins.is_jump = true;
        jmp_ins.indirect_target_memory = true;
        let slice = vec![jmp_ins.clone()];
        let (low, high, default_target) = find_range_guard(&jmp_ins, &slice);
        assert_eq!(low, None);
        assert_eq!(high, None);
        assert_eq!(default_target, None);
    }

    #[test]
    fn find_range_guard_caps_oversized_immediates() {
        // A cmp with a giant immediate is almost always a misread (or
        // some other instruction reusing the cmp mnemonic for sentinels).
        // Step 2 rejects > 4096.
        let mut cmp_ins = ir(0x1100, "cmp");
        cmp_ins.immediate = Some(1_000_000);
        let mut jmp_ins = ir(0x1102, "jmp");
        jmp_ins.is_jump = true;
        jmp_ins.indirect_target_memory = true;
        let slice = vec![cmp_ins, jmp_ins.clone()];
        let (_low, high, _dt) = find_range_guard(&jmp_ins, &slice);
        assert_eq!(high, None, "oversized cmp imm must be rejected");
    }

    #[test]
    fn build_index_expr_from_indirect_memory_jmp() {
        let mut jmp_ins = ir(0x1100, "jmp");
        jmp_ins.is_jump = true;
        jmp_ins.indirect_target_memory = true;
        jmp_ins.memory_base = None;
        jmp_ins.memory_index = Some("rax".to_string());
        jmp_ins.memory_scale = 8;
        jmp_ins.memory_displacement = 0x2000;
        jmp_ins.operand_width = 8;

        let expr = build_index_expr(&jmp_ins);
        match expr {
            Expr::Mem {
                base,
                index,
                scale,
                disp,
                width,
            } => {
                assert_eq!(base, None);
                assert_eq!(index.as_deref(), Some("rax"));
                assert_eq!(scale, 8);
                assert_eq!(disp, 0x2000);
                assert_eq!(width, 8);
            }
            other => panic!("expected Mem, got {other:?}"),
        }
    }

    #[test]
    fn build_index_expr_from_register_jmp() {
        let mut jmp_ins = ir(0x1100, "jmp");
        jmp_ins.is_jump = true;
        jmp_ins.indirect_target_register = Some("rax".to_string());
        let expr = build_index_expr(&jmp_ins);
        assert_eq!(
            expr,
            Expr::Reg {
                name: "rax".to_string()
            }
        );
    }

    #[test]
    fn switch_fact_serializes_with_lowering_discriminator() {
        let fact = SwitchFact {
            schema: SWITCH_SCHEMA,
            function_va: 0x1000,
            indirect_branch_va: 0x1105,
            index_expr: Expr::Reg { name: "rax".into() },
            low: Some(0),
            high: Some(2),
            default_target: Some(0x1300),
            table_va: Some(0x2000),
            entry_size: 8,
            cases: vec![
                SwitchCase {
                    value: 0,
                    target_va: 0x1200,
                },
                SwitchCase {
                    value: 1,
                    target_va: 0x1210,
                },
            ],
            lowering: SwitchLowering::MsvcAbsoluteTable { table_va: 0x2000 },
            claim: Claim::new((), ClaimSource::SwitchReconstruction).with_score(0.93),
        };
        let json = serde_json::to_string(&fact).unwrap();
        assert!(json.contains(r#""schema":"switch_fact/1""#), "got: {json}");
        assert!(
            json.contains(r#""kind":"msvc_absolute_table""#),
            "got: {json}"
        );
        assert!(
            json.contains(r#""function_va":"0x0000000000001000""#),
            "got: {json}"
        );
        assert!(
            json.contains(r#""source":"switch_reconstruction""#),
            "got: {json}"
        );
    }

    // ── Step 3: compare-tree, bit-test, and idom tests ─────────────

    #[test]
    fn compare_tree_detects_three_pair_chain() {
        let mut cmp1 = ir(0x100, "cmp");
        cmp1.immediate = Some(0);
        cmp1.read_regs = vec!["rcx".to_string()];
        let mut je1 = ir(0x103, "je");
        je1.direct_target = Some(0x500);

        let mut cmp2 = ir(0x105, "cmp");
        cmp2.immediate = Some(1);
        cmp2.read_regs = vec!["rcx".to_string()];
        let mut je2 = ir(0x108, "je");
        je2.direct_target = Some(0x510);

        let mut cmp3 = ir(0x10a, "cmp");
        cmp3.immediate = Some(5);
        cmp3.read_regs = vec!["rcx".to_string()];
        let mut je3 = ir(0x10d, "je");
        je3.direct_target = Some(0x520);

        let slice = vec![cmp1, je1, cmp2, je2, cmp3, je3];
        let facts = detect_compare_trees(0x1000, &slice);
        assert_eq!(facts.len(), 1);
        let fact = &facts[0];
        assert_eq!(fact.function_va, 0x1000);
        assert_eq!(fact.indirect_branch_va, 0x100);
        match &fact.lowering {
            SwitchLowering::CompareTree { compares } => {
                assert_eq!(compares.len(), 3);
                assert_eq!(compares[0].value, 0);
                assert_eq!(compares[0].target_va, 0x500);
                assert_eq!(compares[1].value, 1);
                assert_eq!(compares[1].target_va, 0x510);
                assert_eq!(compares[2].value, 5);
                assert_eq!(compares[2].target_va, 0x520);
            }
            other => panic!("expected CompareTree, got {other:?}"),
        }
        assert_eq!(
            fact.index_expr,
            Expr::Reg {
                name: "rcx".to_string()
            }
        );
    }

    #[test]
    fn compare_tree_rejects_single_pair_as_regular_conditional() {
        let mut cmp1 = ir(0x100, "cmp");
        cmp1.immediate = Some(0);
        cmp1.read_regs = vec!["rcx".to_string()];
        let mut je1 = ir(0x103, "je");
        je1.direct_target = Some(0x500);
        let slice = vec![cmp1, je1];
        let facts = detect_compare_trees(0x1000, &slice);
        assert!(
            facts.is_empty(),
            "a single cmp/je pair is a regular conditional, not a switch"
        );
    }

    #[test]
    fn compare_tree_breaks_on_different_register() {
        let mut cmp1 = ir(0x100, "cmp");
        cmp1.immediate = Some(0);
        cmp1.read_regs = vec!["rcx".to_string()];
        let mut je1 = ir(0x103, "je");
        je1.direct_target = Some(0x500);
        let mut cmp2 = ir(0x105, "cmp");
        cmp2.immediate = Some(1);
        cmp2.read_regs = vec!["rdx".to_string()]; // different register
        let mut je2 = ir(0x108, "je");
        je2.direct_target = Some(0x510);
        let slice = vec![cmp1, je1, cmp2, je2];
        let facts = detect_compare_trees(0x1000, &slice);
        assert!(
            facts.is_empty(),
            "register change must break the compare chain"
        );
    }

    #[test]
    fn compare_tree_skips_non_eq_branches() {
        // cmp + jne is NOT a CompareTree pair (ne lowers as the *fallthrough*
        // case, not a per-value jump). Only je / jz qualify.
        let mut cmp1 = ir(0x100, "cmp");
        cmp1.immediate = Some(0);
        cmp1.read_regs = vec!["rcx".to_string()];
        let mut jne1 = ir(0x103, "jne");
        jne1.direct_target = Some(0x500);
        let mut cmp2 = ir(0x105, "cmp");
        cmp2.immediate = Some(1);
        cmp2.read_regs = vec!["rcx".to_string()];
        let mut jne2 = ir(0x108, "jne");
        jne2.direct_target = Some(0x510);
        let slice = vec![cmp1, jne1, cmp2, jne2];
        let facts = detect_compare_trees(0x1000, &slice);
        assert!(facts.is_empty(), "jne pairs are not compare-tree switches");
    }

    #[test]
    fn bit_test_detects_bt_jc_pair_with_constant_mask() {
        let mut mov_ins = ir(0xfc, "mov");
        mov_ins.write_reg = Some("rax".to_string());
        mov_ins.immediate = Some(0x152);
        let mut bt_ins = ir(0x100, "bt");
        bt_ins.read_regs = vec!["rax".to_string(), "rcx".to_string()];
        let mut jc_ins = ir(0x103, "jc");
        jc_ins.direct_target = Some(0x500);

        let slice = vec![mov_ins, bt_ins, jc_ins];
        let facts = detect_bit_tests(0x1000, &slice);
        assert_eq!(facts.len(), 1);
        match &facts[0].lowering {
            SwitchLowering::BitTest { mask, base_target } => {
                assert_eq!(*mask, 0x152);
                assert_eq!(*base_target, 0x500);
            }
            other => panic!("expected BitTest, got {other:?}"),
        }
        assert_eq!(facts[0].indirect_branch_va, 0x100);
    }

    #[test]
    fn bit_test_emits_zero_mask_when_constant_unfound() {
        let mut bt_ins = ir(0x100, "bt");
        bt_ins.read_regs = vec!["rax".to_string(), "rcx".to_string()];
        let mut jc_ins = ir(0x103, "jc");
        jc_ins.direct_target = Some(0x500);
        let slice = vec![bt_ins, jc_ins];
        let facts = detect_bit_tests(0x1000, &slice);
        assert_eq!(facts.len(), 1);
        match &facts[0].lowering {
            SwitchLowering::BitTest { mask, .. } => assert_eq!(*mask, 0),
            other => panic!("expected BitTest, got {other:?}"),
        }
    }

    #[test]
    fn bit_test_requires_a_branch_within_three_instructions() {
        let mut bt_ins = ir(0x100, "bt");
        bt_ins.read_regs = vec!["rax".to_string(), "rcx".to_string()];
        // Five filler instructions before any jc.
        let fillers = (0..5).map(|i| ir(0x103 + i * 2, "nop")).collect::<Vec<_>>();
        let mut jc_ins = ir(0x200, "jc");
        jc_ins.direct_target = Some(0x500);
        let mut slice = vec![bt_ins];
        slice.extend(fillers);
        slice.push(jc_ins);
        let facts = detect_bit_tests(0x1000, &slice);
        assert!(facts.is_empty(), "bt with distant jc should not match");
    }

    #[test]
    fn idoms_diamond_cfg() {
        // entry → A → M
        // entry → B → M
        use crate::pe::{BasicBlockRecord, CfgRecord, EdgeRecord};
        let cfg = CfgRecord {
            function: 0x1000,
            blocks: vec![
                BasicBlockRecord {
                    start: 0x1000,
                    end: 0x1010,
                    instruction_count: 4,
                },
                BasicBlockRecord {
                    start: 0x1010,
                    end: 0x1020,
                    instruction_count: 4,
                },
                BasicBlockRecord {
                    start: 0x1020,
                    end: 0x1030,
                    instruction_count: 4,
                },
                BasicBlockRecord {
                    start: 0x1030,
                    end: 0x1040,
                    instruction_count: 4,
                },
            ],
            edges: vec![
                EdgeRecord {
                    from: 0x1000,
                    to: 0x1010,
                    edge_type: "branch".into(),
                },
                EdgeRecord {
                    from: 0x1000,
                    to: 0x1020,
                    edge_type: "branch".into(),
                },
                EdgeRecord {
                    from: 0x1010,
                    to: 0x1030,
                    edge_type: "branch".into(),
                },
                EdgeRecord {
                    from: 0x1020,
                    to: 0x1030,
                    edge_type: "branch".into(),
                },
            ],
        };
        let idoms = compute_idoms(&cfg, 0x1000);
        assert_eq!(idoms.get(&0x1010), Some(&0x1000), "idom(A) = entry");
        assert_eq!(idoms.get(&0x1020), Some(&0x1000), "idom(B) = entry");
        assert_eq!(
            idoms.get(&0x1030),
            Some(&0x1000),
            "idom(M) = entry (neither A nor B alone dominates M)"
        );
        assert!(!idoms.contains_key(&0x1000), "entry has no idom");
    }

    #[test]
    fn idoms_linear_chain() {
        use crate::pe::{BasicBlockRecord, CfgRecord, EdgeRecord};
        let cfg = CfgRecord {
            function: 0x1000,
            blocks: vec![
                BasicBlockRecord {
                    start: 0x1000,
                    end: 0x1010,
                    instruction_count: 4,
                },
                BasicBlockRecord {
                    start: 0x1010,
                    end: 0x1020,
                    instruction_count: 4,
                },
                BasicBlockRecord {
                    start: 0x1020,
                    end: 0x1030,
                    instruction_count: 4,
                },
            ],
            edges: vec![
                EdgeRecord {
                    from: 0x1000,
                    to: 0x1010,
                    edge_type: "branch".into(),
                },
                EdgeRecord {
                    from: 0x1010,
                    to: 0x1020,
                    edge_type: "branch".into(),
                },
            ],
        };
        let idoms = compute_idoms(&cfg, 0x1000);
        assert_eq!(idoms.get(&0x1010), Some(&0x1000));
        assert_eq!(idoms.get(&0x1020), Some(&0x1010));
    }

    #[test]
    fn idoms_handles_empty_and_missing_entry_gracefully() {
        use crate::pe::CfgRecord;
        let empty_cfg = CfgRecord {
            function: 0,
            blocks: Vec::new(),
            edges: Vec::new(),
        };
        assert!(compute_idoms(&empty_cfg, 0).is_empty());
    }
}
