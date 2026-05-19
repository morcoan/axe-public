//! Crypto constant detection: scan code + rodata for known crypto constants
//! (AES S-box, SHA-1/SHA-256 init values, MD5 round constants, RC4 perm hint,
//! CRC32 table, ChaCha20 constants, Tiny Encryption).
//!
//! Emits `crypto_constants.jsonl` — one record per match with VA, section,
//! algorithm name, and confidence.

use crate::image::BinaryImage;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct CryptoConstantRecord {
    pub schema: &'static str,
    pub algorithm: &'static str,
    pub kind: &'static str, // "sbox" | "init" | "round_constant" | "table" | "string"
    pub confidence: &'static str, // "high" | "medium" | "low"
    pub va: u64,
    pub section: String,
    pub match_length: usize,
    pub description: &'static str,
}

pub fn detect_constants(image: &dyn BinaryImage) -> Vec<CryptoConstantRecord> {
    let mut out = Vec::new();
    let bytes = image.bytes();
    for section in image.sections() {
        if section.executable && !section.readable {
            continue;
        }
        // Skip TLS/very-small sections
        if section.data_size < 16 {
            continue;
        }
        let data = section.data(bytes);
        scan_aes_sbox(data, section, &mut out);
        scan_sha256_init(data, section, &mut out);
        scan_sha1_init(data, section, &mut out);
        scan_md5_round_constants(data, section, &mut out);
        scan_crc32_table(data, section, &mut out);
        scan_chacha20_constants(data, section, &mut out);
        scan_rc4_perm(data, section, &mut out);
        scan_tea_delta(data, section, &mut out);
    }
    out
}

fn push_record(
    out: &mut Vec<CryptoConstantRecord>,
    section: &crate::pe::SectionRecord,
    offset: usize,
    match_length: usize,
    algorithm: &'static str,
    kind: &'static str,
    confidence: &'static str,
    description: &'static str,
) {
    out.push(CryptoConstantRecord {
        schema: "crypto_constant/1",
        algorithm,
        kind,
        confidence,
        va: section.va + offset as u64,
        section: section.name.clone(),
        match_length,
        description,
    });
}

// AES S-box: 256-byte permutation. First 16 bytes: 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
const AES_SBOX_PREFIX: [u8; 16] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
];

fn scan_aes_sbox(
    data: &[u8],
    section: &crate::pe::SectionRecord,
    out: &mut Vec<CryptoConstantRecord>,
) {
    if data.len() < 256 {
        return;
    }
    for i in 0..=data.len().saturating_sub(16) {
        if data[i..i + 16] == AES_SBOX_PREFIX {
            // Verify a few more bytes from the S-box for high confidence
            // AES_SBOX[16..20] = ca 82 c9 7d
            let extended = i + 20 <= data.len() && data[i + 16..i + 20] == [0xca, 0x82, 0xc9, 0x7d];
            push_record(
                out,
                section,
                i,
                if extended { 256 } else { 16 },
                "AES",
                "sbox",
                if extended { "high" } else { "medium" },
                "AES forward S-box (Rijndael substitution table)",
            );
        }
    }
}

// SHA-256 H0..H7 initial hash values (8 × u32, big-endian in spec but typically
// stored little-endian in compiled code).
const SHA256_INIT_LE: [u8; 32] = [
    0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
    0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b, 0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b,
];
const SHA256_INIT_BE: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
];

fn scan_sha256_init(
    data: &[u8],
    section: &crate::pe::SectionRecord,
    out: &mut Vec<CryptoConstantRecord>,
) {
    for needle in [&SHA256_INIT_LE, &SHA256_INIT_BE] {
        if data.len() < needle.len() {
            continue;
        }
        for i in 0..=data.len().saturating_sub(needle.len()) {
            if &data[i..i + needle.len()] == needle.as_slice() {
                push_record(
                    out,
                    section,
                    i,
                    needle.len(),
                    "SHA-256",
                    "init",
                    "high",
                    "SHA-256 initial hash values (H0..H7)",
                );
            }
        }
    }
}

// SHA-1 H0..H4 initial values
const SHA1_INIT_LE: [u8; 20] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xf0, 0xe1, 0xd2, 0xc3,
];
const SHA1_INIT_BE: [u8; 20] = [
    0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
    0xc3, 0xd2, 0xe1, 0xf0,
];

fn scan_sha1_init(
    data: &[u8],
    section: &crate::pe::SectionRecord,
    out: &mut Vec<CryptoConstantRecord>,
) {
    for needle in [&SHA1_INIT_LE, &SHA1_INIT_BE] {
        if data.len() < needle.len() {
            continue;
        }
        for i in 0..=data.len().saturating_sub(needle.len()) {
            if &data[i..i + needle.len()] == needle.as_slice() {
                push_record(
                    out,
                    section,
                    i,
                    needle.len(),
                    "SHA-1",
                    "init",
                    "high",
                    "SHA-1 initial hash values (H0..H4)",
                );
            }
        }
    }
}

// MD5 round constants T[1..4]: d76aa478 e8c7b756 242070db c1bdceee
const MD5_ROUND_PREFIX_LE: [u8; 16] = [
    0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8, 0xdb, 0x70, 0x20, 0x24, 0xee, 0xce, 0xbd, 0xc1,
];

fn scan_md5_round_constants(
    data: &[u8],
    section: &crate::pe::SectionRecord,
    out: &mut Vec<CryptoConstantRecord>,
) {
    if data.len() < 16 {
        return;
    }
    for i in 0..=data.len().saturating_sub(16) {
        if data[i..i + 16] == MD5_ROUND_PREFIX_LE {
            push_record(
                out,
                section,
                i,
                16,
                "MD5",
                "round_constant",
                "high",
                "MD5 round constants T[1..4]",
            );
        }
    }
}

// CRC32 IEEE table first 4 entries: 0x00000000, 0x77073096, 0xee0e612c, 0x990951ba
const CRC32_TABLE_PREFIX_LE: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee, 0xba, 0x51, 0x09, 0x99,
];

fn scan_crc32_table(
    data: &[u8],
    section: &crate::pe::SectionRecord,
    out: &mut Vec<CryptoConstantRecord>,
) {
    if data.len() < 16 {
        return;
    }
    for i in 0..=data.len().saturating_sub(16) {
        if data[i..i + 16] == CRC32_TABLE_PREFIX_LE {
            push_record(
                out,
                section,
                i,
                16,
                "CRC32",
                "table",
                "high",
                "CRC32 IEEE 802.3 polynomial table (first 4 entries)",
            );
        }
    }
}

// ChaCha20 "expand 32-byte k" constant (16 bytes ASCII)
const CHACHA20_CONST: &[u8] = b"expand 32-byte k";

fn scan_chacha20_constants(
    data: &[u8],
    section: &crate::pe::SectionRecord,
    out: &mut Vec<CryptoConstantRecord>,
) {
    if data.len() < CHACHA20_CONST.len() {
        return;
    }
    for i in 0..=data.len().saturating_sub(CHACHA20_CONST.len()) {
        if &data[i..i + CHACHA20_CONST.len()] == CHACHA20_CONST {
            push_record(
                out,
                section,
                i,
                CHACHA20_CONST.len(),
                "ChaCha20/Salsa20",
                "string",
                "high",
                "ChaCha20/Salsa20 constant 'expand 32-byte k'",
            );
        }
    }
}

// RC4: the algorithm has no fixed constants, but the KSA initializes S[i]=i.
// We detect a 256-byte run `00 01 02 ... ff` somewhere in the section (often
// in BSS/.data but sometimes statically initialized).
fn scan_rc4_perm(
    data: &[u8],
    section: &crate::pe::SectionRecord,
    out: &mut Vec<CryptoConstantRecord>,
) {
    if data.len() < 256 {
        return;
    }
    for i in 0..=data.len().saturating_sub(256) {
        let mut all_match = true;
        for k in 0..256 {
            if data[i + k] != k as u8 {
                all_match = false;
                break;
            }
        }
        if all_match {
            push_record(
                out,
                section,
                i,
                256,
                "RC4",
                "table",
                "medium",
                "256-byte identity permutation S[i]=i — RC4 KSA initial state or similar",
            );
            // Skip past this match to avoid double-counting overlapping windows.
            return;
        }
    }
}

// TEA/XTEA delta: 0x9e3779b9 (the golden-ratio constant)
const TEA_DELTA_LE: [u8; 4] = [0xb9, 0x79, 0x37, 0x9e];

fn scan_tea_delta(
    data: &[u8],
    section: &crate::pe::SectionRecord,
    out: &mut Vec<CryptoConstantRecord>,
) {
    if data.len() < 4 {
        return;
    }
    let mut hits = 0;
    for i in 0..=data.len().saturating_sub(4) {
        if data[i..i + 4] == TEA_DELTA_LE {
            if hits == 0 {
                push_record(
                    out,
                    section,
                    i,
                    4,
                    "TEA/XTEA",
                    "round_constant",
                    "medium",
                    "TEA/XTEA delta constant 0x9E3779B9 (golden ratio)",
                );
            }
            hits += 1;
            if hits > 4 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{Format, ParsedImage};
    use crate::pe::SectionRecord;

    fn build_image_with(data: Vec<u8>) -> ParsedImage {
        let len = data.len();
        let section = SectionRecord {
            name: ".rdata".to_string(),
            rva: 0x1000,
            va: 0x140001000,
            virtual_size: len as u32,
            raw_start: 0x400,
            raw_size: len as u32,
            data_size: len,
            executable: false,
            readable: true,
            writable: false,
            entropy: 6.0,
            data_range: 0x400..0x400 + len,
        };
        let mut bytes = vec![0u8; 0x400 + len];
        bytes[0x400..].copy_from_slice(&data);
        ParsedImage {
            format: Format::Pe,
            bytes,
            base: 0x140000000,
            entry_va: 0x140001000,
            machine: 0x8664,
            sections: vec![section],
            imports: Vec::new(),
            exports: Vec::new(),
            function_seeds: Vec::new(),
            source_path: "test".to_string(),
        }
    }

    #[test]
    fn detects_aes_sbox() {
        let mut data = vec![0xAA; 100];
        data.extend_from_slice(&AES_SBOX_PREFIX);
        data.extend_from_slice(&[0xca, 0x82, 0xc9, 0x7d]);
        data.extend(std::iter::repeat(0u8).take(240)); // pad out
        let image = build_image_with(data);
        let records = detect_constants(&image);
        assert!(
            records
                .iter()
                .any(|r| r.algorithm == "AES" && r.confidence == "high"),
            "expected high-confidence AES detection, got {records:?}"
        );
    }

    #[test]
    fn detects_sha256_init_be() {
        let mut data = vec![0xAA; 40];
        data.extend_from_slice(&SHA256_INIT_BE);
        let image = build_image_with(data);
        let records = detect_constants(&image);
        assert!(records.iter().any(|r| r.algorithm == "SHA-256"));
    }

    #[test]
    fn detects_md5_round_constants() {
        let mut data = vec![0xAA; 20];
        data.extend_from_slice(&MD5_ROUND_PREFIX_LE);
        let image = build_image_with(data);
        let records = detect_constants(&image);
        assert!(records.iter().any(|r| r.algorithm == "MD5"));
    }

    #[test]
    fn detects_chacha20_constant() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(CHACHA20_CONST);
        let image = build_image_with(data);
        let records = detect_constants(&image);
        assert!(records.iter().any(|r| r.algorithm == "ChaCha20/Salsa20"));
    }

    #[test]
    fn detects_tea_delta() {
        let mut data = vec![0xAA; 20];
        data.extend_from_slice(&TEA_DELTA_LE);
        let image = build_image_with(data);
        let records = detect_constants(&image);
        assert!(records.iter().any(|r| r.algorithm == "TEA/XTEA"));
    }

    #[test]
    fn rejects_random_bytes() {
        let data: Vec<u8> = (0..1024).map(|i| (i * 37) as u8).collect();
        let image = build_image_with(data);
        let records = detect_constants(&image);
        // Should not detect any of the specific crypto primitives in pseudo-random bytes
        let high_conf = records.iter().filter(|r| r.confidence == "high").count();
        assert_eq!(0, high_conf, "false positives in random data: {records:?}");
    }
}
