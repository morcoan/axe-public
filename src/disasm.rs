use crate::image::BinaryImage;
use crate::ir::IrInstruction;
use crate::pe::{DisasmRange, InstructionRecord, XrefRecord};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, NasmFormatter};
use std::collections::{BTreeMap, BTreeSet};

pub struct DisasmOutput {
    pub instructions: Vec<InstructionRecord>,
    pub ir: Vec<IrInstruction>,
    pub xrefs: Vec<XrefRecord>,
    pub direct_code_targets: BTreeSet<u64>,
    pub capped: bool,
}

pub fn disassemble(
    image: &dyn BinaryImage,
    ranges: &[DisasmRange],
    import_symbols: &BTreeMap<u64, String>,
    string_texts: &BTreeMap<u64, String>,
    max_xrefs: usize,
    max_instructions: usize,
) -> DisasmOutput {
    let mut instructions = Vec::new();
    let mut ir = Vec::new();
    let mut xrefs = Vec::new();
    let mut direct_code_targets = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut formatter = NasmFormatter::new();
    let mut capped = false;

    for range in ranges {
        if instructions.len() >= max_instructions {
            capped = true;
            break;
        }
        let Some(section) = image.section_by_rva(range.section_rva) else {
            continue;
        };
        let data = section.data(image.bytes());
        let start_off = range.start.saturating_sub(section.va) as usize;
        let end_off = range.end.saturating_sub(section.va) as usize;
        if start_off >= data.len() || start_off >= end_off {
            continue;
        }
        let end_off = end_off.min(data.len());
        let mut decoder = Decoder::with_ip(
            64,
            &data[start_off..end_off],
            range.start,
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            if instructions.len() >= max_instructions {
                capped = true;
                break;
            }
            let instr = decoder.decode();
            let address = instr.ip();
            if !seen.insert(address) {
                continue;
            }
            let formatted = format_instruction(&mut formatter, &instr);
            let (mnemonic, op_str) = split_instruction(&formatted);
            let flow = instr.flow_control();
            let is_call = matches!(flow, FlowControl::Call | FlowControl::IndirectCall);
            let is_jump = matches!(
                flow,
                FlowControl::UnconditionalBranch
                    | FlowControl::IndirectBranch
                    | FlowControl::ConditionalBranch
            );
            let is_ret = matches!(flow, FlowControl::Return);
            let mut groups = Vec::new();
            if is_call {
                groups.push("call".to_string());
            }
            if is_jump {
                groups.push("jump".to_string());
            }
            if is_ret {
                groups.push("ret".to_string());
            }

            let ir_record = IrInstruction::from_iced(&instr, &mnemonic, is_call, is_jump);

            if instr.is_ip_rel_memory_operand() {
                add_xref(
                    image,
                    &mut xrefs,
                    import_symbols,
                    string_texts,
                    max_xrefs,
                    address,
                    instr.ip_rel_memory_address(),
                    if is_call { "call" } else { "operand" },
                );
            }
            if is_call || is_jump {
                let target = instr.near_branch_target();
                if target != 0 {
                    add_xref(
                        image,
                        &mut xrefs,
                        import_symbols,
                        string_texts,
                        max_xrefs,
                        address,
                        target,
                        if is_call { "call" } else { "branch" },
                    );
                    if is_call
                        && image
                            .section_for_va(target)
                            .map(|s| s.executable)
                            .unwrap_or(false)
                    {
                        direct_code_targets.insert(target);
                    }
                }
            }

            instructions.push(InstructionRecord {
                address,
                size: instr.len() as u32,
                mnemonic,
                op_str,
                section: section.name.clone(),
                groups,
                is_call,
                is_jump,
                is_ret,
                branch_target: branch_target(&instr),
            });
            ir.push(ir_record);
        }
    }
    instructions.sort_by_key(|row| row.address);
    ir.sort_by_key(|row| row.address);
    xrefs.sort_by_key(|row| row.from);
    DisasmOutput {
        instructions,
        ir,
        xrefs,
        direct_code_targets,
        capped,
    }
}

fn format_instruction(formatter: &mut NasmFormatter, instr: &iced_x86::Instruction) -> String {
    let mut output = String::new();
    formatter.format(instr, &mut output);
    output
}

fn split_instruction(text: &str) -> (String, String) {
    let trimmed = text.trim();
    if let Some((mnemonic, rest)) = trimmed.split_once(char::is_whitespace) {
        (mnemonic.to_string(), rest.trim().to_string())
    } else {
        (trimmed.to_string(), String::new())
    }
}

fn branch_target(instr: &iced_x86::Instruction) -> Option<u64> {
    let target = instr.near_branch_target();
    (target != 0).then_some(target)
}

fn add_xref(
    image: &dyn BinaryImage,
    xrefs: &mut Vec<XrefRecord>,
    import_symbols: &BTreeMap<u64, String>,
    string_texts: &BTreeMap<u64, String>,
    max_xrefs: usize,
    from: u64,
    target: u64,
    role: &str,
) {
    if xrefs.len() >= max_xrefs {
        return;
    }
    if let Some(symbol) = import_symbols.get(&target) {
        xrefs.push(XrefRecord {
            kind: "import".to_string(),
            from,
            target,
            role: role.to_string(),
            symbol: Some(symbol.clone()),
            text: None,
            encoding: None,
            section: None,
        });
    } else if let Some(text) = string_texts.get(&target) {
        xrefs.push(XrefRecord {
            kind: "string".to_string(),
            from,
            target,
            role: role.to_string(),
            symbol: None,
            text: Some(text.clone()),
            encoding: None,
            section: None,
        });
    } else if let Some(section) = image.section_for_va(target) {
        xrefs.push(XrefRecord {
            kind: if section.executable { "code" } else { "data" }.to_string(),
            from,
            target,
            role: role.to_string(),
            symbol: None,
            text: None,
            encoding: None,
            section: Some(section.name.clone()),
        });
    }
}
