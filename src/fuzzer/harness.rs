//! In-process harness registry + declarative `fuzz_target!` macro.
//!
//! The `InProcessExecutor` (step 17) drives a `fn(&[u8])` harness
//! function compiled into the same binary as the fuzzer. This module
//! provides:
//!
//! 1. [`HarnessFn`] — the signature every harness must satisfy.
//! 2. [`HarnessEntry`] — registry record.
//! 3. [`HarnessRegistry`] — global registry built via explicit
//!    [`register`] calls (typically from a `ctor`/`#[link_section]`
//!    init block or from `main` before constructing the executor).
//! 4. [`fuzz_target!`] — declarative macro that defines a harness
//!    and a registration helper without the user touching the
//!    registry directly.
//!
//! Why no `inventory`/`linkme`: both crates rely on linker section
//! tricks that have known issues on MSVC. The explicit-register
//! pattern works identically on every platform at the cost of one
//! `register()` call per harness in `main()`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Contract a harness must satisfy: deterministic function from
/// input bytes to side effects. Panics in the harness are caught
/// by the InProcessExecutor's signal/panic-hook layer.
pub type HarnessFn = fn(&[u8]);

#[derive(Clone, Copy, Debug)]
pub struct HarnessEntry {
    pub name: &'static str,
    pub func: HarnessFn,
}

/// Global process-wide harness registry. Thread-safe via a Mutex
/// because registration typically happens from `main` before any
/// fuzzer threads spin up; runtime contention is negligible.
pub struct HarnessRegistry {
    entries: Mutex<BTreeMap<&'static str, HarnessFn>>,
}

impl HarnessRegistry {
    pub const fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn register(&self, name: &'static str, func: HarnessFn) {
        let mut g = self.entries.lock().unwrap();
        g.insert(name, func);
    }

    pub fn lookup(&self, name: &str) -> Option<HarnessFn> {
        let g = self.entries.lock().unwrap();
        g.get(name).copied()
    }

    pub fn names(&self) -> Vec<&'static str> {
        let g = self.entries.lock().unwrap();
        g.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        let g = self.entries.lock().unwrap();
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        let g = self.entries.lock().unwrap();
        g.is_empty()
    }

    /// Test helper — wipe the registry. Not exposed in non-test
    /// builds to prevent accidental clears.
    #[cfg(test)]
    pub fn clear(&self) {
        let mut g = self.entries.lock().unwrap();
        g.clear();
    }
}

impl Default for HarnessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The global registry. `main()` registers harnesses against this
/// instance before constructing the InProcessExecutor.
pub static REGISTRY: HarnessRegistry = HarnessRegistry::new();

/// Top-level register call — sugar for `REGISTRY.register(...)`.
pub fn register(name: &'static str, func: HarnessFn) {
    REGISTRY.register(name, func);
}

pub fn lookup(name: &str) -> Option<HarnessFn> {
    REGISTRY.lookup(name)
}

/// Declarative harness definition + registration helper.
///
/// ```ignore
/// use axe_core::fuzzer::harness;
/// axe_core::fuzz_target!(my_parser, |data: &[u8]| {
///     // your fuzz target body
///     let _ = my_lib::parse(data);
/// });
///
/// // In main():
/// my_parser::register();
/// ```
///
/// Expands to a module containing the harness function and a
/// `register()` fn that adds it to [`REGISTRY`].
#[macro_export]
macro_rules! fuzz_target {
    ($name:ident, $body:expr) => {
        pub mod $name {
            #[allow(unused_imports)]
            use super::*;

            pub fn target(data: &[u8]) {
                let f: fn(&[u8]) = $body;
                f(data)
            }

            pub fn register() {
                $crate::fuzzer::harness::register(stringify!($name), target);
            }

            pub const NAME: &str = stringify!($name);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests share the global REGISTRY, so they must not run in
    // parallel against each other. Serialize via this Mutex held
    // for the whole test body.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn no_op(_data: &[u8]) {}

    #[test]
    fn register_then_lookup_roundtrip() {
        let _g = TEST_LOCK.lock().unwrap();
        REGISTRY.clear();
        register("rt_target", no_op);
        let f = lookup("rt_target").expect("registered");
        f(b"hello"); // should not panic; no state to assert
        assert!(REGISTRY.names().contains(&"rt_target"));
    }

    #[test]
    fn lookup_missing_returns_none() {
        let _g = TEST_LOCK.lock().unwrap();
        REGISTRY.clear();
        assert!(lookup("never_registered").is_none());
    }

    #[test]
    fn names_lists_registered_harnesses() {
        let _g = TEST_LOCK.lock().unwrap();
        REGISTRY.clear();
        register("h_one", no_op);
        register("h_two", no_op);
        let mut n = REGISTRY.names();
        n.sort();
        assert_eq!(n, vec!["h_one", "h_two"]);
    }

    #[test]
    fn double_register_replaces_previous() {
        let _g = TEST_LOCK.lock().unwrap();
        REGISTRY.clear();
        fn first(_d: &[u8]) {}
        fn second(_d: &[u8]) {}
        register("twice", first);
        register("twice", second);
        // Both registrations succeed; the BTreeMap keeps the latest.
        assert_eq!(REGISTRY.len(), 1);
        let f = lookup("twice").unwrap();
        // Function pointers compare equal when they point at the same
        // generated code — we check that the registry returns *some*
        // valid fn pointer; identity-equality between fn(&[u8]) is
        // not always guaranteed by the language.
        f(b"");
        let _ = f as fn(&[u8]); // type-check only
    }
}
