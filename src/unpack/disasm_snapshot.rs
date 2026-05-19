//! Disassemble out of a `RegionBuffer` (snapshot mode).
//!
//! Parallel to `src/disasm.rs:1-51` which feeds iced-x86 from a
//! file-slice. This adapter feeds from an in-memory buffer with
//! a real VA — the OEP detector + scan_iat_calls + function-
//! prologue scanner all use this entry point.

use iced_x86::{Decoder, DecoderOptions, Instruction};

use crate::unpack::region_buffer::RegionBuffer;

/// Decode up to `max_instructions` from `buffer` starting at
/// byte `offset` (which corresponds to VA `buffer.va_base +
/// offset`). Stops on invalid instruction or buffer end.
pub fn disasm_at(
    buffer: &RegionBuffer,
    offset: usize,
    max_instructions: usize,
) -> Vec<Instruction> {
    let bytes = &buffer.bytes;
    if offset >= bytes.len() {
        return Vec::new();
    }
    let slice = &bytes[offset..];
    let ip = buffer.va_base.wrapping_add(offset as u64);
    let mut decoder = Decoder::with_ip(64, slice, ip, DecoderOptions::NONE);
    let mut out = Vec::with_capacity(max_instructions);
    let mut count = 0;
    while decoder.can_decode() && count < max_instructions {
        let ins = decoder.decode();
        if ins.is_invalid() {
            break;
        }
        out.push(ins);
        count += 1;
    }
    out
}

/// Function-prologue scanner. Returns the VA of the first
/// likely prologue found in `buffer` starting at `offset`.
///
/// Heuristic patterns (x86-64):
/// - `push rbp; mov rbp, rsp` (classic SysV-style; still seen
///   in MSVC debug builds)
/// - `sub rsp, imm8` (MSVC release, small frames)
/// - `sub rsp, imm32` (MSVC release, larger frames)
/// - `mov [rsp+N], reg` immediately followed by `sub rsp, ...`
///
/// Returns `None` if no plausible prologue is found within
/// `search_limit` bytes.
pub fn find_first_function_prologue(buffer: &RegionBuffer, search_limit: usize) -> Option<u64> {
    let bytes = &buffer.bytes;
    let scan_end = bytes.len().min(search_limit);
    let mut i = 0;
    while i < scan_end {
        if looks_like_prologue(&bytes[i..]) {
            return Some(buffer.va_base.wrapping_add(i as u64));
        }
        i += 1;
    }
    None
}

/// True when the byte sequence at `bytes` starts with one of
/// the well-known x86-64 function prologue patterns.
pub fn looks_like_prologue(bytes: &[u8]) -> bool {
    // push rbp ; mov rbp, rsp  =  55 48 89 E5
    if bytes.len() >= 4 && bytes[0..4] == [0x55, 0x48, 0x89, 0xE5] {
        return true;
    }
    // sub rsp, imm8           =  48 83 EC <imm8>
    if bytes.len() >= 4 && bytes[0..3] == [0x48, 0x83, 0xEC] {
        return true;
    }
    // sub rsp, imm32          =  48 81 EC <imm32>
    if bytes.len() >= 7 && bytes[0..3] == [0x48, 0x81, 0xEC] {
        return true;
    }
    // push rbx / push rsi / push rdi etc followed by sub rsp
    if bytes.len() >= 5
        && (bytes[0] == 0x53 || bytes[0] == 0x56 || bytes[0] == 0x57)
        && bytes[1..4] == [0x48, 0x83, 0xEC]
    {
        return true;
    }
    // push rbp variants (x64 with REX prefix on push)
    if bytes.len() >= 5 && bytes[0] == 0x40 && bytes[1] == 0x55 && bytes[2..5] == [0x48, 0x89, 0xE5]
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disasm_at_decodes_simple_mov_ret() {
        // mov eax, 0x42 ; ret  =  B8 42 00 00 00 C3
        let buf = RegionBuffer::from_bytes(0x140001000, vec![0xB8, 0x42, 0x00, 0x00, 0x00, 0xC3]);
        let insns = disasm_at(&buf, 0, 10);
        assert!(insns.len() >= 2);
        // First should be MOV
        assert_eq!(insns[0].ip(), 0x140001000);
    }

    #[test]
    fn disasm_at_returns_empty_past_end() {
        let buf = RegionBuffer::from_bytes(0, vec![0xC3]);
        assert!(disasm_at(&buf, 99, 10).is_empty());
    }

    #[test]
    fn disasm_at_caps_at_max_instructions() {
        let buf = RegionBuffer::from_bytes(0, vec![0x90; 100]); // 100 NOPs
        let insns = disasm_at(&buf, 0, 5);
        assert_eq!(insns.len(), 5);
    }

    #[test]
    fn looks_like_prologue_push_rbp_mov_rbp_rsp() {
        assert!(looks_like_prologue(&[0x55, 0x48, 0x89, 0xE5]));
    }

    #[test]
    fn looks_like_prologue_sub_rsp_imm8() {
        assert!(looks_like_prologue(&[0x48, 0x83, 0xEC, 0x28]));
    }

    #[test]
    fn looks_like_prologue_sub_rsp_imm32() {
        assert!(looks_like_prologue(&[
            0x48, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00
        ]));
    }

    #[test]
    fn looks_like_prologue_push_rbx_then_sub_rsp() {
        assert!(looks_like_prologue(&[0x53, 0x48, 0x83, 0xEC, 0x20]));
    }

    #[test]
    fn looks_like_prologue_rejects_random_bytes() {
        assert!(!looks_like_prologue(&[0x00, 0x00, 0x00, 0x00]));
        assert!(!looks_like_prologue(&[0xFF, 0xFF, 0xFF, 0xFF]));
        assert!(!looks_like_prologue(&[0x90, 0x90, 0x90, 0x90]));
    }

    #[test]
    fn find_first_prologue_after_some_padding() {
        let mut bytes = vec![0x90u8; 16]; // NOP pad
        bytes.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]); // prologue
        let buf = RegionBuffer::from_bytes(0x140001000, bytes);
        let found = find_first_function_prologue(&buf, 64);
        assert_eq!(found, Some(0x140001000 + 16));
    }

    #[test]
    fn find_first_prologue_returns_none_for_no_prologue() {
        let buf = RegionBuffer::from_bytes(0, vec![0x90; 1024]);
        assert!(find_first_function_prologue(&buf, 1024).is_none());
    }
}
