//! Legacy Themida (≤2.x) handler-dispatch detection.
//!
//! Themida's dispatcher historically uses a longer prologue
//! sequence with several junk instructions before the real
//! handler index lookup. The detector accepts a wider window.

/// Detect a Themida-shaped dispatcher in `bytes`. Returns
/// `true` if the pattern matches.
///
/// Heuristic: presence of `pushfq` (0x9C) followed within 32
/// bytes by `popfq` (0x9D) followed by an indirect call
/// (`FF 14`).
pub fn dispatcher_present(bytes: &[u8]) -> bool {
    if bytes.len() < 6 {
        return false;
    }
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i] != 0x9C {
            continue;
        }
        let window_end = (i + 32).min(bytes.len());
        let window = &bytes[i + 1..window_end];
        if let Some(pos) = window.iter().position(|&b| b == 0x9D) {
            let after_popfq = i + 1 + pos + 1;
            if after_popfq + 1 < bytes.len()
                && bytes[after_popfq] == 0xFF
                && (bytes[after_popfq + 1] == 0x14 || bytes[after_popfq + 1] == 0x15)
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_no_dispatcher() {
        assert!(!dispatcher_present(&[]));
    }

    #[test]
    fn random_bytes_no_dispatcher() {
        assert!(!dispatcher_present(&[0xAA; 64]));
    }

    #[test]
    fn pushfq_popfq_indirect_call_detected() {
        let pattern: &[u8] = &[
            0x9C, // pushfq
            0x90, 0x90, // junk
            0x9D, // popfq
            0xFF, 0x14, 0x25, 0x00, 0x00, 0x00, 0x00, // call [imm32]
        ];
        assert!(dispatcher_present(pattern));
    }
}
