//! Legacy VMProtect (≤2.x) handler-dispatch detection.
//!
//! VMProtect's dispatcher pattern: a tight loop reading the
//! next byte of virtualized bytecode, indexing into a handler
//! table, and jumping. Aurora detects the pattern (a `jmp
//! qword ptr [reg+reg*8]` indirect dispatch) + counts the
//! distinct handler bodies.

/// Detect the canonical VMProtect dispatcher byte pattern in
/// a region. Returns `true` if the pattern is present.
///
/// The pattern (one variant): `48 8B 84 D8 ... FF E0` =
/// `mov rax, [rax+rbx*8+disp]` followed by `jmp rax`.
pub fn dispatcher_present(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let mut i = 0;
    while i + 8 <= bytes.len() {
        // mov rax, [reg+reg*8+disp32] = 48 8B 84 D? <disp32>
        if bytes[i] == 0x48 && bytes[i + 1] == 0x8B && bytes[i + 2] == 0x84 {
            // Scan a few bytes forward for jmp rax (FF E0)
            for j in 1..=16 {
                if i + 6 + j < bytes.len()
                    && bytes[i + 6 + j] == 0xFF
                    && bytes[i + 6 + j + 1] == 0xE0
                {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_no_dispatcher() {
        assert!(!dispatcher_present(&[]));
        assert!(!dispatcher_present(&[0x90]));
    }

    #[test]
    fn random_bytes_no_dispatcher() {
        assert!(!dispatcher_present(&[0xAA; 64]));
    }

    #[test]
    fn classic_dispatcher_pattern_detected() {
        // mov rax, [rax+rbx*8+0x10] ; jmp rax
        let pattern: &[u8] = &[
            0x48, 0x8B, 0x84, 0xD8, 0x10, 0x00, 0x00, 0x00, // mov rax, [rax+rbx*8+0x10]
            0xFF, 0xE0, // jmp rax
        ];
        assert!(dispatcher_present(pattern));
    }
}
