use crate::pe::{FunctionRecord, InstructionRecord};
use crate::portable::{parse_int, EmulationTraceRecord, PortableInput};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub struct BranchPredicate {
    pub site_va: u64,
    pub mnemonic: String,
    pub left: String,
    pub right: String,
    pub predicate: String,
    pub left_value: Option<u64>,
    pub right_value: Option<u64>,
}

#[derive(Clone)]
pub struct NativeEmulationResult {
    pub function: u64,
    pub start_va: u64,
    pub unsupported_instructions: Vec<String>,
    pub cap_hit: bool,
    pub predicates: Vec<BranchPredicate>,
    pub trace: EmulationTraceRecord,
    pub visited_path: Vec<u64>,
    pub oob_write_sites: Vec<u64>,
}

#[derive(Default, Clone)]
struct NativeState {
    registers: BTreeMap<String, u64>,
    stack: BTreeMap<i64, u64>,
    last_compare: Option<(String, String, Option<u64>, Option<u64>)>,
    memory_events: Vec<String>,
    api_stub_events: Vec<String>,
    oob_write_sites: Vec<u64>,
    flags_zf: bool,
    flags_sf: bool,
    flags_cf: bool,
    flags_of: bool,
}

pub fn emulate(input: &PortableInput<'_>) -> Option<NativeEmulationResult> {
    let function = input.functions.first()?;
    emulate_function(input, function, None, None)
}

pub fn emulate_function(
    input: &PortableInput<'_>,
    function: &FunctionRecord,
    initial_regs: Option<&BTreeMap<String, u64>>,
    budget_override: Option<usize>,
) -> Option<NativeEmulationResult> {
    let cap = budget_override.unwrap_or_else(|| match input.emulation_budget {
        "max" => 512,
        "high" => 192,
        _ => 96,
    });
    let rows: Vec<&InstructionRecord> = input
        .instructions
        .iter()
        .filter(|row| row.address >= function.start && row.address < function.end)
        .collect();
    if rows.is_empty() {
        return None;
    }
    let by_va: BTreeMap<u64, &InstructionRecord> =
        rows.iter().map(|row| (row.address, *row)).collect();
    let addresses: Vec<u64> = rows.iter().map(|row| row.address).collect();
    let mut state = NativeState::default();
    if let Some(regs) = initial_regs {
        for (name, value) in regs {
            state.registers.insert(name.clone(), *value);
        }
    }
    let mut steps = 0usize;
    let mut supported_steps = 0usize;
    let mut unsupported: Vec<String> = Vec::new();
    let mut predicates: Vec<BranchPredicate> = Vec::new();
    let mut cap_hit = false;
    let mut visited_edges: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut visited_path: Vec<u64> = Vec::new();
    let mut pc = function.start;
    if !by_va.contains_key(&pc) {
        pc = addresses[0];
    }
    let mut exit_reason = "function_end".to_string();

    while let Some(row) = by_va.get(&pc).copied() {
        if steps >= cap {
            cap_hit = true;
            exit_reason = "budget_cap".to_string();
            break;
        }
        steps += 1;
        visited_path.push(row.address);
        let next_pc = next_address(&addresses, row.address);
        match emulate_instruction(row, &mut state) {
            StepOutcome::Supported => {
                supported_steps += 1;
                if row.is_ret || row.mnemonic.eq_ignore_ascii_case("ret") {
                    exit_reason = "return".to_string();
                    break;
                }
                pc = next_pc.unwrap_or(function.end);
            }
            StepOutcome::ApiStub(api) => {
                supported_steps += 1;
                apply_api_return_heuristic(&api, &mut state);
                state
                    .api_stub_events
                    .push(format!("0x{:016X}:{api}", row.address));
                pc = next_pc.unwrap_or(function.end);
            }
            StepOutcome::Branch(predicate) => {
                supported_steps += 1;
                predicates.push(predicate.clone());
                let target = row.branch_target.unwrap_or_default();
                let take_branch = branch_is_satisfied(&predicate, &state);
                let chosen = if take_branch { Some(target) } else { next_pc };
                let Some(chosen) = chosen else {
                    exit_reason = "branch_exit".to_string();
                    break;
                };
                if !visited_edges.insert((row.address, chosen)) {
                    exit_reason = "loop_guard".to_string();
                    break;
                }
                pc = chosen;
            }
            StepOutcome::Unsupported(reason) => {
                if unsupported.len() < 16 {
                    unsupported.push(format!(
                        "0x{:016X}: {} {} ({reason})",
                        row.address, row.mnemonic, row.op_str
                    ));
                }
                pc = next_pc.unwrap_or(function.end);
            }
        }
        if pc >= function.end {
            break;
        }
    }

    if supported_steps == 0 {
        return None;
    }
    let status = if cap_hit { "failed_capped" } else { "executed" }.to_string();
    let trace = EmulationTraceRecord {
        trace_id: format!("emu:{:016X}:0000", function.start),
        function: function.start,
        start_va: function.start,
        status,
        step_count: steps,
        supported_steps,
        unsupported_instructions: unsupported.clone(),
        cap_hit,
        budget: input.emulation_budget.to_string(),
        api_stubs: input
            .imports
            .iter()
            .take(16)
            .map(|row| row.symbol.clone())
            .collect(),
        api_stub_events: state.api_stub_events.clone(),
        memory_events: state.memory_events.clone(),
        exit_reason,
        registers: state.registers.clone(),
        evidence: vec![function.start],
    };
    Some(NativeEmulationResult {
        function: function.start,
        start_va: function.start,
        unsupported_instructions: unsupported,
        cap_hit,
        predicates,
        trace,
        visited_path,
        oob_write_sites: state.oob_write_sites,
    })
}

enum StepOutcome {
    Supported,
    ApiStub(String),
    Branch(BranchPredicate),
    Unsupported(String),
}

fn emulate_instruction(row: &InstructionRecord, state: &mut NativeState) -> StepOutcome {
    let mnemonic = row.mnemonic.to_ascii_lowercase();
    let operands = split_operands(&row.op_str);
    match mnemonic.as_str() {
        "mov" => emulate_mov(row, &operands, state),
        "movzx" | "movsx" | "movsxd" => emulate_mov(row, &operands, state),
        "lea" => emulate_lea(&operands, state),
        "xor" | "add" | "sub" | "and" | "or" | "shl" | "shr" | "sar" | "sal" | "rol" | "ror" => {
            emulate_binary(&mnemonic, &operands, state)
        }
        "inc" | "dec" | "neg" | "not" | "bswap" => emulate_unary(&mnemonic, &operands, state),
        "cmp" | "test" => {
            if operands.len() >= 2 {
                let lhs = normalize_operand(&operands[0]);
                let rhs = normalize_operand(&operands[1]);
                let left_val = value_of(&operands[0], state);
                let right_val = value_of(&operands[1], state);
                state.last_compare = Some((lhs, rhs, left_val, right_val));
                if let (Some(l), Some(r)) = (left_val, right_val) {
                    let diff = if mnemonic == "cmp" {
                        l.wrapping_sub(r)
                    } else {
                        l & r
                    };
                    state.flags_zf = diff == 0;
                    state.flags_sf = (diff as i64) < 0;
                    if mnemonic == "cmp" {
                        state.flags_cf = l < r;
                        let sl = l as i64;
                        let sr = r as i64;
                        state.flags_of = ((sl ^ sr) & (sl ^ (sl.wrapping_sub(sr)))) < 0;
                    } else {
                        state.flags_cf = false;
                        state.flags_of = false;
                    }
                }
                StepOutcome::Supported
            } else {
                StepOutcome::Unsupported("missing comparison operands".to_string())
            }
        }
        "call" => StepOutcome::ApiStub(row.op_str.trim().to_string()),
        "ret" | "nop" | "push" | "pop" | "leave" | "endbr64" | "endbr32" | "cdq" | "cqo" => {
            StepOutcome::Supported
        }
        "cmovz" | "cmove" | "cmovnz" | "cmovne" | "cmovg" | "cmovl" | "cmovge" | "cmovle"
        | "cmova" | "cmovae" | "cmovb" | "cmovbe" | "cmovs" | "cmovns" => {
            if conditional_holds(&mnemonic[4..], state) {
                emulate_mov(row, &operands, state)
            } else {
                StepOutcome::Supported
            }
        }
        m if m.starts_with("set") && operands.len() == 1 => {
            let held = conditional_holds(&m[3..], state);
            let dst = normalize_operand(&operands[0]);
            if let Some(reg) = register_name(&dst) {
                state
                    .registers
                    .insert(reg.to_string(), if held { 1 } else { 0 });
            }
            StepOutcome::Supported
        }
        _ if mnemonic.starts_with('j') && row.branch_target.is_some() => {
            let (left, right, lv, rv) = state
                .last_compare
                .clone()
                .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string(), None, None));
            StepOutcome::Branch(BranchPredicate {
                site_va: row.address,
                mnemonic: mnemonic.clone(),
                left: left.clone(),
                right: right.clone(),
                predicate: format!(
                    "{} if cmp {}, {} -> 0x{:016X}",
                    mnemonic,
                    left,
                    right,
                    row.branch_target.unwrap_or_default()
                ),
                left_value: lv,
                right_value: rv,
            })
        }
        _ => {
            StepOutcome::Unsupported("unsupported mnemonic in native bounded emulator".to_string())
        }
    }
}

fn emulate_mov(
    row: &InstructionRecord,
    operands: &[String],
    state: &mut NativeState,
) -> StepOutcome {
    if operands.len() < 2 {
        return StepOutcome::Unsupported("missing mov operands".to_string());
    }
    let dst = normalize_operand(&operands[0]);
    let src = normalize_operand(&operands[1]);
    if dst.starts_with('[') {
        state.memory_events.push(format!("write {dst} <= {src}"));
        if let (Some(slot), Some(value)) = (stack_slot(&dst), value_of(&src, state)) {
            state.stack.insert(slot, value);
        } else if !looks_like_stack_or_image(&dst) {
            state.oob_write_sites.push(row.address);
        }
        return StepOutcome::Supported;
    }
    if src.starts_with('[') {
        state.memory_events.push(format!("read {src} => {dst}"));
    }
    if let Some(reg) = register_name(&dst) {
        if let Some(value) = value_of(&src, state) {
            state.registers.insert(reg.to_string(), value);
        } else if let Some(slot) = stack_slot(&src) {
            if let Some(value) = state.stack.get(&slot).copied() {
                state.registers.insert(reg.to_string(), value);
            }
        }
        return StepOutcome::Supported;
    }
    StepOutcome::Unsupported("unsupported mov operand form".to_string())
}

fn emulate_lea(operands: &[String], state: &mut NativeState) -> StepOutcome {
    if operands.len() < 2 {
        return StepOutcome::Unsupported("missing lea operands".to_string());
    }
    let dst = normalize_operand(&operands[0]);
    let src = normalize_operand(&operands[1]);
    let Some(reg) = register_name(&dst) else {
        return StepOutcome::Unsupported("lea destination is not a register".to_string());
    };
    if let Some(value) = parse_effective_address(&src) {
        state.registers.insert(reg.to_string(), value);
    }
    StepOutcome::Supported
}

fn emulate_binary(mnemonic: &str, operands: &[String], state: &mut NativeState) -> StepOutcome {
    if operands.len() < 2 {
        return StepOutcome::Unsupported("missing binary operands".to_string());
    }
    let dst = normalize_operand(&operands[0]);
    let src = normalize_operand(&operands[1]);
    let Some(reg) = register_name(&dst) else {
        return StepOutcome::Unsupported("binary destination is not a register".to_string());
    };
    let lhs = state.registers.get(reg).copied().unwrap_or_default();
    let rhs = value_of(&src, state).unwrap_or_default();
    let value = match mnemonic {
        "xor" if normalize_operand(&operands[0]) == normalize_operand(&operands[1]) => 0,
        "xor" => lhs ^ rhs,
        "and" => lhs & rhs,
        "or" => lhs | rhs,
        "add" => lhs.wrapping_add(rhs),
        "sub" => lhs.wrapping_sub(rhs),
        "shl" | "sal" => lhs.wrapping_shl((rhs & 63) as u32),
        "shr" => lhs.wrapping_shr((rhs & 63) as u32),
        "sar" => ((lhs as i64).wrapping_shr((rhs & 63) as u32)) as u64,
        "rol" => lhs.rotate_left((rhs & 63) as u32),
        "ror" => lhs.rotate_right((rhs & 63) as u32),
        _ => lhs,
    };
    state.registers.insert(reg.to_string(), value);
    state.flags_zf = value == 0;
    state.flags_sf = (value as i64) < 0;
    StepOutcome::Supported
}

fn emulate_unary(mnemonic: &str, operands: &[String], state: &mut NativeState) -> StepOutcome {
    if operands.len() < 1 {
        return StepOutcome::Unsupported("missing unary operand".to_string());
    }
    let dst = normalize_operand(&operands[0]);
    let Some(reg) = register_name(&dst) else {
        return StepOutcome::Unsupported("unary destination is not a register".to_string());
    };
    let cur = state.registers.get(reg).copied().unwrap_or_default();
    let value = match mnemonic {
        "inc" => cur.wrapping_add(1),
        "dec" => cur.wrapping_sub(1),
        "neg" => (!cur).wrapping_add(1),
        "not" => !cur,
        "bswap" => cur.swap_bytes(),
        _ => cur,
    };
    state.registers.insert(reg.to_string(), value);
    state.flags_zf = value == 0;
    state.flags_sf = (value as i64) < 0;
    StepOutcome::Supported
}

fn conditional_holds(suffix: &str, state: &NativeState) -> bool {
    match suffix {
        "z" | "e" => state.flags_zf,
        "nz" | "ne" => !state.flags_zf,
        "s" => state.flags_sf,
        "ns" => !state.flags_sf,
        "c" | "b" | "nae" => state.flags_cf,
        "nc" | "ae" | "nb" => !state.flags_cf,
        "be" | "na" => state.flags_cf || state.flags_zf,
        "a" | "nbe" => !state.flags_cf && !state.flags_zf,
        "l" | "nge" => state.flags_sf != state.flags_of,
        "ge" | "nl" => state.flags_sf == state.flags_of,
        "le" | "ng" => state.flags_zf || (state.flags_sf != state.flags_of),
        "g" | "nle" => !state.flags_zf && (state.flags_sf == state.flags_of),
        "o" => state.flags_of,
        "no" => !state.flags_of,
        _ => false,
    }
}

fn branch_is_satisfied(predicate: &BranchPredicate, state: &NativeState) -> bool {
    let mnem = predicate.mnemonic.as_str();
    if mnem == "jmp" {
        return true;
    }
    let suffix = mnem.strip_prefix('j').unwrap_or(mnem);
    if state.last_compare.is_some() {
        return conditional_holds(suffix, state);
    }
    let left = predicate
        .left_value
        .or_else(|| value_of(&predicate.left, state));
    let right = predicate
        .right_value
        .or_else(|| value_of(&predicate.right, state));
    match (mnem, left, right) {
        ("je" | "jz", Some(left), Some(right)) => left == right,
        ("jne" | "jnz", Some(left), Some(right)) => left != right,
        ("ja" | "jnbe" | "jg" | "jnle", Some(left), Some(right)) => left > right,
        ("jae" | "jnb" | "jge" | "jnl", Some(left), Some(right)) => left >= right,
        ("jb" | "jnae" | "jl" | "jnge", Some(left), Some(right)) => left < right,
        ("jbe" | "jna" | "jle" | "jng", Some(left), Some(right)) => left <= right,
        _ => false,
    }
}

fn apply_api_return_heuristic(api_text: &str, state: &mut NativeState) {
    use crate::winapi::prototype;
    let symbol = api_text.trim();
    if symbol.is_empty() {
        return;
    }
    let return_value = match prototype(symbol) {
        Some(proto) => match proto.return_type {
            "HANDLE" => 0x1234_0000,
            "LPVOID" | "PVOID" | "LPCWSTR" | "LPWSTR" | "LPCSTR" | "LPSTR" => 0x2000_0000,
            "BOOL" => 1,
            "HRESULT" | "NTSTATUS" => 0,
            "DWORD" | "ULONG" | "UINT" => 0,
            "SIZE_T" => 0,
            _ => 0,
        },
        None => 0,
    };
    state.registers.insert("rax".to_string(), return_value);
    state
        .registers
        .insert("eax".to_string(), return_value & 0xFFFF_FFFF);
}

fn split_operands(op_str: &str) -> Vec<String> {
    op_str
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalize_operand(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("qword ptr")
        .trim_start_matches("dword ptr")
        .trim_start_matches("word ptr")
        .trim_start_matches("byte ptr")
        .trim()
        .to_ascii_lowercase()
}

fn register_name(value: &str) -> Option<&str> {
    const REGISTERS: &[&str] = &[
        "rax", "eax", "ax", "al", "rbx", "ebx", "bx", "bl", "rcx", "ecx", "cx", "cl", "rdx", "edx",
        "dx", "dl", "rsi", "esi", "si", "rdi", "edi", "di", "rsp", "esp", "sp", "rbp", "ebp", "bp",
        "r8", "r8d", "r8w", "r8b", "r9", "r9d", "r9w", "r9b", "r10", "r10d", "r10w", "r10b", "r11",
        "r11d", "r11w", "r11b", "r12", "r12d", "r12w", "r12b", "r13", "r13d", "r13w", "r13b",
        "r14", "r14d", "r14w", "r14b", "r15", "r15d", "r15w", "r15b",
    ];
    REGISTERS.iter().copied().find(|reg| *reg == value)
}

fn value_of(value: &str, state: &NativeState) -> Option<u64> {
    let normalized = normalize_operand(value);
    parse_int(&normalized).or_else(|| {
        register_name(&normalized)
            .and_then(|reg| state.registers.get(reg).copied())
            .or_else(|| stack_slot(&normalized).and_then(|slot| state.stack.get(&slot).copied()))
    })
}

fn stack_slot(value: &str) -> Option<i64> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    if !(inner.starts_with("rsp") || inner.starts_with("rbp")) {
        return None;
    }
    if inner == "rsp" || inner == "rbp" {
        return Some(0);
    }
    let sign_index = inner
        .find('+')
        .or_else(|| inner[1..].find('-').map(|idx| idx + 1))?;
    let sign = inner.as_bytes()[sign_index] as char;
    let amount = parse_int(&inner[sign_index + 1..])? as i64;
    Some(if sign == '-' { -amount } else { amount })
}

fn looks_like_stack_or_image(operand: &str) -> bool {
    let inner = operand.trim_start_matches('[').trim_end_matches(']');
    inner.starts_with("rsp")
        || inner.starts_with("rbp")
        || inner.starts_with("rip")
        || inner.contains("0x14")
        || inner.contains("0x40")
}

fn parse_effective_address(value: &str) -> Option<u64> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    if let Some(rest) = inner.strip_prefix("rip+") {
        return parse_int(rest);
    }
    if let Some(rest) = inner.strip_prefix("rip-") {
        return parse_int(rest).map(|amount| 0u64.wrapping_sub(amount));
    }
    parse_int(inner)
}

fn next_address(addresses: &[u64], current: u64) -> Option<u64> {
    addresses.iter().copied().find(|addr| *addr > current)
}
