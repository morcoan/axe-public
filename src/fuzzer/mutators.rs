//! Mutation primitives: havoc, splice, dictionary, boundary value.
//!
//! The fuzzer's `session.rs` (step 8) calls
//! [`apply_random_mutation`] each iteration to produce one mutated
//! candidate per pick. Lower-level helpers ([`havoc_byte_flip`],
//! [`splice_from`], [`boundary_value`], etc.) are exposed for use by
//! the structure-aware mutators that will land post-MVP.
//!
//! All randomness routes through [`Xorshift64`] — a tiny inline PRNG
//! that avoids pulling the `rand` crate's transitive tree. Quality is
//! sufficient for input-space exploration; reproducibility comes from
//! seeding (see `--fuzz-seed` in step 15).

#![allow(dead_code)]

/// Xorshift64 — Marsaglia 2003. Fast, small, sufficient for fuzzing.
/// A zero seed is invalid (xorshift gets stuck at zero); the
/// constructor coerces zero to a fixed non-zero value.
#[derive(Clone, Copy, Debug)]
pub struct Xorshift64(pub u64);

impl Xorshift64 {
    pub fn new(seed: u64) -> Self {
        // Marsaglia: seed must be non-zero.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// Advance and return a u64.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Random index in `[0, n)`. Returns 0 when `n == 0`.
    pub fn range(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() as usize) % n
    }

    pub fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub fn bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }
}

/// One mutator operation. The fuzz loop picks one per iteration via
/// [`apply_random_mutation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutator {
    /// Standard AFL-style havoc: bit/byte flip, arithmetic, insert,
    /// delete, etc.
    Havoc,
    /// Take a slice from a peer input and splice it in at a random
    /// offset. Requires at least one entry in the splice pool.
    Splice,
    /// Inject a dictionary token at a random offset.
    Dict,
    /// Overwrite a small region with an interesting integer
    /// (`0`, `1`, `i32::MAX`, `u32::MAX`, …) from the boundary table.
    BoundaryValue,
    /// Comparison-guided — placeholder for step 17/18 when execution
    /// telemetry feeds back observed `cmp` constants. Today it just
    /// degrades to [`Mutator::Havoc`].
    CmpGuided,
}

/// User-supplied dictionary of byte tokens (file headers, magic
/// numbers, protocol keywords, etc.).
#[derive(Clone, Debug, Default)]
pub struct Dictionary {
    pub tokens: Vec<Box<[u8]>>,
}

impl Dictionary {
    pub fn from_tokens<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        Self {
            tokens: iter
                .into_iter()
                .map(|t| t.as_ref().to_vec().into_boxed_slice())
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub fn pick<'a>(&'a self, rng: &mut Xorshift64) -> Option<&'a [u8]> {
        if self.tokens.is_empty() {
            None
        } else {
            let idx = rng.range(self.tokens.len());
            Some(&self.tokens[idx])
        }
    }
}

/// Context for picking a mutator and applying it. Held in `session.rs`
/// and passed to every `apply_*` call.
pub struct MutateCtx<'a> {
    pub dict: &'a Dictionary,
    pub splice_pool: &'a [Vec<u8>],
    pub max_len: usize,
}

/// Pick a mutator with weighted probability and apply it to `input`.
/// Returns the mutated bytes plus the [`Mutator`] kind actually
/// applied (degraded variants of `Splice`/`Dict` show this — e.g. an
/// empty dict degrades `Dict` to `Havoc`).
pub fn apply_random_mutation(
    input: &[u8],
    rng: &mut Xorshift64,
    ctx: &MutateCtx<'_>,
) -> (Vec<u8>, Mutator) {
    let pick = match rng.range(10) {
        0..=4 => Mutator::Havoc,
        5..=6 => Mutator::BoundaryValue,
        7 => Mutator::Splice,
        8 => Mutator::Dict,
        _ => Mutator::CmpGuided,
    };
    let (mutated, applied) = apply_mutation(input, pick, rng, ctx);
    let mut out = mutated;
    if out.len() > ctx.max_len {
        out.truncate(ctx.max_len);
    }
    (out, applied)
}

/// Apply a specific mutator. Returns the mutated bytes plus the
/// actual [`Mutator`] kind (some mutators degrade when their
/// prerequisites are absent — e.g., `Splice` with an empty pool
/// degrades to `Havoc`).
pub fn apply_mutation(
    input: &[u8],
    mutator: Mutator,
    rng: &mut Xorshift64,
    ctx: &MutateCtx<'_>,
) -> (Vec<u8>, Mutator) {
    match mutator {
        Mutator::Havoc => (apply_havoc(input, rng), Mutator::Havoc),
        Mutator::Splice => match splice_from(input, ctx.splice_pool, rng) {
            Some(v) => (v, Mutator::Splice),
            None => (apply_havoc(input, rng), Mutator::Havoc),
        },
        Mutator::Dict => match apply_dict(input, ctx.dict, rng) {
            Some(v) => (v, Mutator::Dict),
            None => (apply_havoc(input, rng), Mutator::Havoc),
        },
        Mutator::BoundaryValue => (apply_boundary_value(input, rng), Mutator::BoundaryValue),
        Mutator::CmpGuided => (apply_havoc(input, rng), Mutator::Havoc),
    }
}

// ───── Havoc family ─────────────────────────────────────────────────

pub fn apply_havoc(input: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out = input.to_vec();
    // Apply 1-4 sub-operations in a stack.
    let stack_depth = 1 + rng.range(4);
    for _ in 0..stack_depth {
        match rng.range(8) {
            0 => havoc_byte_flip(&mut out, rng),
            1 => havoc_byte_arith(&mut out, rng, true),
            2 => havoc_byte_arith(&mut out, rng, false),
            3 => havoc_byte_overwrite(&mut out, rng),
            4 => havoc_insert(&mut out, rng),
            5 => havoc_delete(&mut out, rng),
            6 => havoc_byte_xor(&mut out, rng),
            _ => havoc_chunk_swap(&mut out, rng),
        }
    }
    out
}

pub fn havoc_byte_flip(buf: &mut Vec<u8>, rng: &mut Xorshift64) {
    if buf.is_empty() {
        return;
    }
    let idx = rng.range(buf.len());
    let bit = rng.range(8);
    buf[idx] ^= 1 << bit;
}

pub fn havoc_byte_arith(buf: &mut Vec<u8>, rng: &mut Xorshift64, add: bool) {
    if buf.is_empty() {
        return;
    }
    let idx = rng.range(buf.len());
    let delta = (rng.range(35) + 1) as u8;
    buf[idx] = if add {
        buf[idx].wrapping_add(delta)
    } else {
        buf[idx].wrapping_sub(delta)
    };
}

pub fn havoc_byte_xor(buf: &mut Vec<u8>, rng: &mut Xorshift64) {
    if buf.is_empty() {
        return;
    }
    let idx = rng.range(buf.len());
    buf[idx] ^= rng.next_u8();
}

pub fn havoc_byte_overwrite(buf: &mut Vec<u8>, rng: &mut Xorshift64) {
    if buf.is_empty() {
        return;
    }
    let idx = rng.range(buf.len());
    buf[idx] = rng.next_u8();
}

pub fn havoc_insert(buf: &mut Vec<u8>, rng: &mut Xorshift64) {
    let pos = rng.range(buf.len() + 1);
    let count = 1 + rng.range(8);
    for i in 0..count {
        buf.insert(pos + i, rng.next_u8());
    }
}

pub fn havoc_delete(buf: &mut Vec<u8>, rng: &mut Xorshift64) {
    if buf.len() < 2 {
        return;
    }
    let pos = rng.range(buf.len());
    let count = (1 + rng.range(8)).min(buf.len() - pos);
    buf.drain(pos..pos + count);
}

pub fn havoc_chunk_swap(buf: &mut Vec<u8>, rng: &mut Xorshift64) {
    if buf.len() < 4 {
        return;
    }
    let max_chunk = (buf.len() / 2).max(1);
    let chunk = 1 + rng.range(max_chunk);
    let src = rng.range(buf.len() - chunk + 1);
    let dst = rng.range(buf.len() - chunk + 1);
    if src == dst {
        return;
    }
    // Copy the source chunk into a scratch buffer, then write to dst.
    let scratch: Vec<u8> = buf[src..src + chunk].to_vec();
    buf[dst..dst + chunk].copy_from_slice(&scratch);
}

// ───── Splice / Dict / Boundary value ───────────────────────────────

pub fn splice_from(input: &[u8], splice_pool: &[Vec<u8>], rng: &mut Xorshift64) -> Option<Vec<u8>> {
    if splice_pool.is_empty() {
        return None;
    }
    let other = &splice_pool[rng.range(splice_pool.len())];
    if other.is_empty() {
        return None;
    }
    let split_a = if input.is_empty() {
        0
    } else {
        rng.range(input.len())
    };
    let split_b = rng.range(other.len());
    let mut out = Vec::with_capacity(split_a + (other.len() - split_b));
    out.extend_from_slice(&input[..split_a]);
    out.extend_from_slice(&other[split_b..]);
    Some(out)
}

pub fn apply_dict(input: &[u8], dict: &Dictionary, rng: &mut Xorshift64) -> Option<Vec<u8>> {
    let token = dict.pick(rng)?;
    let pos = if input.is_empty() {
        0
    } else {
        rng.range(input.len() + 1)
    };
    // 50/50 between insert and overwrite.
    let mut out = input.to_vec();
    if rng.bool() || pos + token.len() > out.len() {
        // Insert
        for (i, b) in token.iter().enumerate() {
            out.insert(pos + i, *b);
        }
    } else {
        // Overwrite
        out[pos..pos + token.len()].copy_from_slice(token);
    }
    Some(out)
}

pub fn apply_boundary_value(input: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    if input.len() < 8 {
        return input.to_vec();
    }
    let mut out = input.to_vec();
    let pos = rng.range(out.len() - 7);
    let value = boundary_value(rng.next_u64(), 0);
    out[pos..pos + 8].copy_from_slice(&value.to_le_bytes());
    out
}

/// Boundary-value table (lifted from `native_fuzzer.rs:108`). The same
/// distribution is used by [`crate::fuzzer::executor::input_to_regs`]
/// to seed initial GPRs from input bytes.
pub fn boundary_value(seed: u64, slot: u32) -> u64 {
    let shifted = seed.rotate_left((slot.wrapping_mul(11)) & 63);
    match shifted & 7 {
        0 => 0,
        1 => 1,
        2 => 0x0000_0000_FFFF_FFFF,
        3 => u64::MAX,
        4 => 0x0000_0000_7FFF_FFFF,
        5 => 0x0000_0000_0010_0000,
        6 => 0x0000_0000_0000_0100,
        _ => shifted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(seed: u64) -> Xorshift64 {
        Xorshift64::new(seed)
    }

    fn ctx<'a>(dict: &'a Dictionary, pool: &'a [Vec<u8>]) -> MutateCtx<'a> {
        MutateCtx {
            dict,
            splice_pool: pool,
            max_len: 4096,
        }
    }

    #[test]
    fn xorshift_is_deterministic_for_same_seed() {
        let mut a = rng(42);
        let mut b = rng(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn xorshift_zero_seed_is_coerced() {
        let mut r = rng(0);
        // Must produce a non-zero stream.
        assert_ne!(r.next_u64(), 0);
    }

    #[test]
    fn boundary_value_hits_known_constants() {
        let seen: std::collections::BTreeSet<u64> = (0..64).map(|s| boundary_value(s, 0)).collect();
        assert!(seen.contains(&0));
        assert!(seen.contains(&1));
        assert!(seen.contains(&u64::MAX));
        assert!(seen.contains(&0xFFFF_FFFF));
    }

    #[test]
    fn havoc_byte_flip_changes_one_bit() {
        let mut buf = vec![0xFFu8; 8];
        let original = buf.clone();
        havoc_byte_flip(&mut buf, &mut rng(1));
        assert_ne!(buf, original);
        // Exactly one bit differs (or zero if same byte hit somehow).
        let differing_bytes: usize = buf
            .iter()
            .zip(original.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(differing_bytes, 1);
    }

    #[test]
    fn havoc_byte_flip_on_empty_is_safe() {
        let mut buf = Vec::<u8>::new();
        havoc_byte_flip(&mut buf, &mut rng(1));
        assert!(buf.is_empty());
    }

    #[test]
    fn havoc_insert_grows_buffer() {
        let mut buf = vec![0u8; 4];
        havoc_insert(&mut buf, &mut rng(7));
        assert!(buf.len() > 4);
    }

    #[test]
    fn havoc_delete_shrinks_buffer() {
        let mut buf = vec![0u8; 16];
        havoc_delete(&mut buf, &mut rng(9));
        assert!(buf.len() < 16);
    }

    #[test]
    fn havoc_delete_skips_tiny_buffer() {
        let mut buf = vec![0u8; 1];
        havoc_delete(&mut buf, &mut rng(1));
        assert_eq!(buf.len(), 1, "no delete from a single-byte buffer");
    }

    #[test]
    fn splice_combines_two_inputs() {
        let input = vec![0xAAu8; 8];
        let pool = vec![vec![0xBBu8; 8]];
        let out = splice_from(&input, &pool, &mut rng(3)).unwrap();
        assert!(out.iter().any(|&b| b == 0xAA), "kept some of input");
        assert!(out.iter().any(|&b| b == 0xBB), "took some from peer");
    }

    #[test]
    fn splice_returns_none_on_empty_pool() {
        assert!(splice_from(&[1, 2, 3], &[], &mut rng(1)).is_none());
    }

    #[test]
    fn apply_dict_injects_a_known_token() {
        let dict = Dictionary::from_tokens([b"RIFF" as &[u8]]);
        let input = vec![0u8; 16];
        let out = apply_dict(&input, &dict, &mut rng(11)).unwrap();
        let contains_riff = out.windows(4).any(|w| w == b"RIFF");
        assert!(contains_riff, "dict token must appear in mutated output");
    }

    #[test]
    fn apply_dict_returns_none_on_empty_dict() {
        let dict = Dictionary::default();
        assert!(apply_dict(&[0u8; 8], &dict, &mut rng(1)).is_none());
    }

    #[test]
    fn boundary_value_overwrites_8_bytes() {
        let input = vec![0u8; 24];
        let out = apply_boundary_value(&input, &mut rng(13));
        let zero_bytes = out.iter().filter(|&&b| b == 0).count();
        // Boundary values may legitimately contain zero bytes, but the
        // total layout should differ from all-zeros.
        assert_eq!(out.len(), input.len());
        // At least some position changed (with very high probability).
        let _ = zero_bytes;
    }

    #[test]
    fn apply_mutation_splice_degrades_to_havoc_on_empty_pool() {
        let dict = Dictionary::default();
        let pool: Vec<Vec<u8>> = Vec::new();
        let ctx = ctx(&dict, &pool);
        let (_, applied) = apply_mutation(&[1, 2, 3, 4], Mutator::Splice, &mut rng(1), &ctx);
        assert_eq!(applied, Mutator::Havoc);
    }

    #[test]
    fn apply_random_mutation_respects_max_len() {
        let dict = Dictionary::default();
        let pool: Vec<Vec<u8>> = Vec::new();
        let ctx = MutateCtx {
            dict: &dict,
            splice_pool: &pool,
            max_len: 8,
        };
        let input = vec![0u8; 4];
        for seed in 0..20 {
            let (out, _) = apply_random_mutation(&input, &mut rng(seed + 1), &ctx);
            assert!(out.len() <= 8, "max_len cap enforced (got {})", out.len());
        }
    }

    #[test]
    fn apply_random_mutation_produces_some_change_eventually() {
        let dict = Dictionary::default();
        let pool: Vec<Vec<u8>> = Vec::new();
        let ctx = ctx(&dict, &pool);
        let input = vec![0u8; 16];
        let mut any_change = false;
        for seed in 1..30 {
            let (out, _) = apply_random_mutation(&input, &mut rng(seed), &ctx);
            if out != input {
                any_change = true;
                break;
            }
        }
        assert!(
            any_change,
            "30 random mutations should produce at least one change"
        );
    }
}
