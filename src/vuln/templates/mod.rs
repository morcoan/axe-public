//! Template registry — 12 v1.0 templates across 3 sub-modules.
//!
//! Re-exported via `crate::vuln::bug_class::TemplateRegistry::load_v1_0`.

pub mod auth;
pub mod data_handling;
#[cfg(feature = "vuln-discovery-lifetime")]
pub mod lifetime;
pub mod memory;
