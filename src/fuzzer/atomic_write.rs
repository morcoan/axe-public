//! Back-compat re-export of the relocated `atomic_write` module.
//!
//! The actual implementation moved to `src/atomic_write.rs` in Step 2
//! of the dynamic-trace plan (Codex finding 1 fix) so the
//! `dynamic-trace` feature can reuse the same temp-write-then-rename
//! discipline without enabling the `fuzzer` feature stack.
//!
//! Every fuzzer call site that imports `crate::fuzzer::atomic_write::*`
//! continues to compile unchanged.

#![allow(dead_code)]

pub use crate::atomic_write::*;
