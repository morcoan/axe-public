//! MSVC + Itanium mangled-name demangling.
//!
//! Tries MSVC mangling first (recognized by the leading `?`), then
//! falls back to Itanium (recognized by the leading `_Z`). Returns
//! `None` for names that match neither convention.
//!
//! Both demanglers are pure-Rust (no C deps): `msvc_demangler` for
//! the Microsoft scheme and `cpp_demangle` for the Itanium ABI.

#![allow(dead_code)]

/// Demangle a C++ symbol name. Tries MSVC then Itanium.
///
/// Returns `None` if neither demangler accepts the input. The
/// returned string is the human-readable form (e.g. `class Foo` for
/// `?AVFoo@@` or `std::exception::what() const` for `_ZNKSt9exception4whatEv`).
pub fn demangle(mangled: &str) -> Option<String> {
    demangle_msvc(mangled).or_else(|| demangle_itanium(mangled))
}

/// MSVC-only demangle (skips trying Itanium). Useful when the source
/// is known to be a Microsoft TypeDescriptor name.
pub fn demangle_msvc(mangled: &str) -> Option<String> {
    if !mangled.starts_with('?') && !mangled.starts_with(".?") {
        return None;
    }
    // .?AV / .?AU / .?AW prefixes appear in TypeDescriptor names
    // (the leading '.' is a discriminator, not part of the mangling).
    let stripped = mangled.strip_prefix('.').unwrap_or(mangled);
    msvc_demangler::demangle(stripped, msvc_demangler::DemangleFlags::llvm()).ok()
}

/// Itanium-only demangle (skips trying MSVC). Useful when the source
/// is known to be a GCC/Clang mangled name.
pub fn demangle_itanium(mangled: &str) -> Option<String> {
    if !mangled.starts_with("_Z") && !mangled.starts_with("_ZTI") {
        return None;
    }
    // For `_ZTI` typeinfo names, strip the prefix to get the type
    // name itself (Itanium typeinfo wraps the type's mangled name).
    let target = mangled.strip_prefix("_ZTI").unwrap_or(mangled);
    let prefixed = if target.starts_with("_Z") {
        target.to_string()
    } else {
        format!("_Z{target}")
    };
    cpp_demangle::Symbol::new(prefixed.as_bytes())
        .ok()
        .and_then(|sym| sym.demangle(&cpp_demangle::DemangleOptions::default()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_mangled_strings() {
        assert!(demangle("hello").is_none());
        assert!(demangle("").is_none());
        assert!(demangle("Foo").is_none());
    }

    #[test]
    fn demangles_msvc_function() {
        // `?Foo@@QEAA@XZ` is `public: __cdecl Foo::Foo(void)` ish.
        let r = demangle_msvc("?Foo@@QEAA@XZ");
        assert!(r.is_some(), "expected MSVC demangle to succeed");
        let s = r.unwrap();
        assert!(s.contains("Foo"), "got: {s}");
    }

    #[test]
    fn demangles_msvc_type_descriptor() {
        // `.?AVexception@std@@` is the TypeDescriptor name for `std::exception`.
        let r = demangle_msvc(".?AVexception@std@@");
        assert!(r.is_some(), "expected TypeDescriptor demangle to succeed");
        let s = r.unwrap();
        assert!(s.contains("exception") || s.contains("std"), "got: {s}");
    }

    #[test]
    fn demangles_itanium_function() {
        // `_ZNSt9exception4whatEv` is `std::exception::what()`.
        let r = demangle_itanium("_ZNSt9exception4whatEv");
        assert!(r.is_some(), "expected Itanium demangle to succeed");
        let s = r.unwrap();
        assert!(s.contains("exception"), "got: {s}");
        assert!(s.contains("what"), "got: {s}");
    }

    #[test]
    fn demangle_auto_dispatches_on_prefix() {
        assert!(demangle("?Foo@@QEAA@XZ").is_some(), "MSVC route");
        assert!(
            demangle("_ZNSt9exception4whatEv").is_some(),
            "Itanium route"
        );
        assert!(demangle("plain_name").is_none(), "non-mangled rejected");
    }

    #[test]
    fn rejects_non_msvc_input_in_msvc_path() {
        assert!(demangle_msvc("_ZNSt9exception4whatEv").is_none());
    }

    #[test]
    fn rejects_non_itanium_input_in_itanium_path() {
        assert!(demangle_itanium("?Foo@@QEAA@XZ").is_none());
    }
}
