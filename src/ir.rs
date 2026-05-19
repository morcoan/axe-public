use iced_x86::{Instruction, OpKind, Register};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct IrInstruction {
    pub address: u64,
    pub size: u32,
    pub mnemonic: String,
    pub write_reg: Option<String>,
    pub read_regs: Vec<String>,
    pub immediate: Option<u64>,
    pub rip_target: Option<u64>,
    pub stack_slot: Option<i64>,
    pub memory_base: Option<String>,
    pub memory_index: Option<String>,
    pub memory_scale: u32,
    pub memory_displacement: i64,
    pub operand_width: u32,
    pub indirect_target_register: Option<String>,
    pub indirect_target_memory: bool,
    pub memory_write: bool,
    pub memory_read: bool,
    pub direct_target: Option<u64>,
    pub is_call: bool,
    pub is_jump: bool,
}

impl IrInstruction {
    pub fn from_iced(instr: &Instruction, mnemonic: &str, is_call: bool, is_jump: bool) -> Self {
        let mut read_regs = Vec::new();
        let mut write_reg = None;
        let mut immediate = None;
        let mut memory_write = false;
        let mut memory_read = false;
        let mut stack_slot = None;
        let mut memory_base = None;
        let mut memory_index = None;
        let mut memory_scale = 0;
        let mut memory_displacement = 0;
        let mut operand_width = 0;

        for operand in 0..instr.op_count() {
            match instr.op_kind(operand) {
                OpKind::Register => {
                    let reg = normalize_register(instr.op_register(operand));
                    if operand == 0 && writes_first_operand(mnemonic) {
                        write_reg = reg;
                    } else if let Some(reg) = reg {
                        push_unique(&mut read_regs, reg);
                    }
                }
                OpKind::Memory
                | OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegRSI
                | OpKind::MemorySegDI
                | OpKind::MemorySegEDI
                | OpKind::MemorySegRDI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI => {
                    memory_base = normalize_register(instr.memory_base());
                    memory_index = normalize_register(instr.memory_index());
                    memory_scale = instr.memory_index_scale();
                    memory_displacement = instr.memory_displacement64() as i64;
                    operand_width = instr.memory_size().size() as u32;
                    if operand == 0 && writes_first_operand(mnemonic) {
                        memory_write = true;
                    } else {
                        memory_read = true;
                    }
                    if let Some(reg) = memory_base.clone() {
                        push_unique(&mut read_regs, reg);
                    }
                    if let Some(reg) = memory_index.clone() {
                        push_unique(&mut read_regs, reg);
                    }
                    if let Some(slot) = stack_slot_for(instr) {
                        stack_slot = Some(slot);
                    }
                }
                OpKind::Immediate8
                | OpKind::Immediate8_2nd
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64 => {
                    immediate = Some(instr.immediate(operand));
                }
                _ => {}
            }
        }
        let direct_target = branch_target(instr);
        let (indirect_target_register, indirect_target_memory) =
            indirect_target_operand(instr, is_call || is_jump, direct_target.is_none());

        Self {
            address: instr.ip(),
            size: instr.len() as u32,
            mnemonic: mnemonic.to_string(),
            write_reg,
            read_regs,
            immediate,
            rip_target: instr
                .is_ip_rel_memory_operand()
                .then(|| instr.ip_rel_memory_address()),
            stack_slot,
            memory_base,
            memory_index,
            memory_scale,
            memory_displacement,
            operand_width,
            indirect_target_register,
            indirect_target_memory,
            memory_write,
            memory_read,
            direct_target,
            is_call,
            is_jump,
        }
    }
}

pub fn normalize_register(reg: Register) -> Option<String> {
    let name = format!("{:?}", reg).to_ascii_lowercase();
    let normalized = match name.as_str() {
        "al" | "ah" | "ax" | "eax" | "rax" => "rax",
        "bl" | "bh" | "bx" | "ebx" | "rbx" => "rbx",
        "cl" | "ch" | "cx" | "ecx" | "rcx" => "rcx",
        "dl" | "dh" | "dx" | "edx" | "rdx" => "rdx",
        "sil" | "si" | "esi" | "rsi" => "rsi",
        "dil" | "di" | "edi" | "rdi" => "rdi",
        "spl" | "sp" | "esp" | "rsp" => "rsp",
        "bpl" | "bp" | "ebp" | "rbp" => "rbp",
        "r8b" | "r8w" | "r8d" | "r8" => "r8",
        "r9b" | "r9w" | "r9d" | "r9" => "r9",
        "r10b" | "r10w" | "r10d" | "r10" => "r10",
        "r11b" | "r11w" | "r11d" | "r11" => "r11",
        "r12b" | "r12w" | "r12d" | "r12" => "r12",
        "r13b" | "r13w" | "r13d" | "r13" => "r13",
        "r14b" | "r14w" | "r14d" | "r14" => "r14",
        "r15b" | "r15w" | "r15d" | "r15" => "r15",
        "none" => return None,
        _ => return Some(name),
    };
    Some(normalized.to_string())
}

fn writes_first_operand(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "mov"
            | "movzx"
            | "movsxd"
            | "lea"
            | "xor"
            | "add"
            | "sub"
            | "and"
            | "or"
            | "shl"
            | "shr"
            | "sar"
            | "rol"
            | "ror"
    )
}

fn stack_slot_for(instr: &Instruction) -> Option<i64> {
    let base = normalize_register(instr.memory_base())?;
    if base != "rsp" && base != "rbp" {
        return None;
    }
    Some(instr.memory_displacement64() as i64)
}

fn branch_target(instr: &Instruction) -> Option<u64> {
    let target = instr.near_branch_target();
    (target != 0).then_some(target)
}

fn indirect_target_operand(
    instr: &Instruction,
    is_control_flow: bool,
    lacks_direct_target: bool,
) -> (Option<String>, bool) {
    if !is_control_flow || !lacks_direct_target || instr.op_count() == 0 {
        return (None, false);
    }
    match instr.op_kind(0) {
        OpKind::Register => (normalize_register(instr.op_register(0)), false),
        OpKind::Memory
        | OpKind::MemorySegSI
        | OpKind::MemorySegESI
        | OpKind::MemorySegRSI
        | OpKind::MemorySegDI
        | OpKind::MemorySegEDI
        | OpKind::MemorySegRDI
        | OpKind::MemoryESDI
        | OpKind::MemoryESEDI
        | OpKind::MemoryESRDI => (None, true),
        _ => (None, false),
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    #[test]
    fn ir_decodes_rip_relative_lea_into_rcx() {
        let bytes = [0x48, 0x8D, 0x0D, 0xF9, 0x0F, 0x00, 0x00];
        let mut decoder = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
        let instr = decoder.decode();
        let ir = IrInstruction::from_iced(&instr, "lea", false, false);

        assert_eq!(Some("rcx".to_string()), ir.write_reg);
        assert_eq!(Some(0x2000), ir.rip_target);
    }

    #[test]
    fn ir_decodes_direct_call_target() {
        let bytes = [0xE8, 0x0B, 0x00, 0x00, 0x00];
        let mut decoder = Decoder::with_ip(64, &bytes, 0x1400, DecoderOptions::NONE);
        let instr = decoder.decode();
        let ir = IrInstruction::from_iced(&instr, "call", true, false);

        assert!(ir.is_call);
        assert_eq!(Some(0x1410), ir.direct_target);
    }
}
