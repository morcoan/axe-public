//! Normalized exception-handling fact types.
//!
//! Shared across all EH ABIs (MSVC FH3, FH4, SEH, Itanium). Per-ABI parsers
//! emit into the same [`EhFunctionFact`] shape so downstream LLM consumers
//! don't need to branch on `abi`.

#![allow(dead_code)]

use serde::Serialize;

use crate::facts::Claim;

pub const EH_SCHEMA: &str = "eh_function_fact/1";

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EhAbi {
    MsvcFH3,
    MsvcFH4,
    MsSEH,
    MsGSHandlerEH,
    ItaniumCxx,
    ItaniumCleanup,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct EhFunctionFact {
    pub schema: &'static str,
    #[serde(serialize_with = "hex_va")]
    pub function_va: u64,
    #[serde(serialize_with = "hex_va")]
    pub function_end_va: u64,
    pub abi: EhAbi,
    pub personality: Option<String>,
    #[serde(serialize_with = "opt_hex_va")]
    pub personality_va: Option<u64>,
    pub unwind_ranges: Vec<UnwindRange>,
    pub try_regions: Vec<TryRegion>,
    pub catch_handlers: Vec<CatchHandler>,
    pub cleanup_actions: Vec<CleanupAction>,
    pub claim: Claim<()>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UnwindRange {
    #[serde(serialize_with = "hex_va")]
    pub begin_va: u64,
    #[serde(serialize_with = "hex_va")]
    pub end_va: u64,
}

/// A C++ `try { … }` region. FH3/FH4 populate `try_state_low/high`
/// (native state index model); Itanium populates `call_site_index`
/// (native call-site IP-range model). Both populate `try_begin_va/end_va`
/// so consumers can ignore native semantics.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TryRegion {
    #[serde(serialize_with = "hex_va")]
    pub try_begin_va: u64,
    #[serde(serialize_with = "hex_va")]
    pub try_end_va: u64,
    pub try_state_low: Option<i32>,
    pub try_state_high: Option<i32>,
    pub call_site_index: Option<u32>,
    pub catch_handler_indices: Vec<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CatchHandler {
    #[serde(serialize_with = "hex_va")]
    pub handler_va: u64,
    pub catch_kind: CatchKind,
    pub adjectives: u32,
    pub frame_offset: Option<i32>,
    #[serde(serialize_with = "opt_hex_va")]
    pub continuation_va: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatchKind {
    /// `catch (T)` / `catch (T&)` / `catch (T const&)`.
    Typed {
        type_name: Option<String>,
        #[serde(serialize_with = "hex_va")]
        type_descriptor_va: u64,
    },
    /// `catch (...)`.
    Ellipsis,
    /// `__finally` / Itanium cleanup landing pad.
    Cleanup,
    /// SEH `__except (filter)` clause.
    Filter,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanupAction {
    #[serde(serialize_with = "hex_va")]
    pub region_begin_va: u64,
    #[serde(serialize_with = "hex_va")]
    pub region_end_va: u64,
    #[serde(serialize_with = "opt_hex_va")]
    pub landing_pad_va: Option<u64>,
    #[serde(serialize_with = "opt_hex_va")]
    pub unwind_handler_va: Option<u64>,
    pub state_from: Option<i32>,
    pub state_to: Option<i32>,
}

fn hex_va<S: serde::Serializer>(va: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{va:016x}"))
}

fn opt_hex_va<S: serde::Serializer>(va: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match va {
        Some(v) => s.serialize_str(&format!("0x{v:016x}")),
        None => s.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::ClaimSource;

    #[test]
    fn fact_serializes_with_schema_and_abi() {
        let fact = EhFunctionFact {
            schema: EH_SCHEMA,
            function_va: 0x140001000,
            function_end_va: 0x140001100,
            abi: EhAbi::MsvcFH3,
            personality: Some("__CxxFrameHandler3".into()),
            personality_va: Some(0x140002000),
            unwind_ranges: vec![UnwindRange {
                begin_va: 0x140001000,
                end_va: 0x140001100,
            }],
            try_regions: vec![TryRegion {
                try_begin_va: 0x140001030,
                try_end_va: 0x140001080,
                try_state_low: Some(0),
                try_state_high: Some(1),
                call_site_index: None,
                catch_handler_indices: vec![0],
            }],
            catch_handlers: vec![CatchHandler {
                handler_va: 0x1400010a0,
                catch_kind: CatchKind::Typed {
                    type_name: Some(".?AVexception@std@@".into()),
                    type_descriptor_va: 0x140003000,
                },
                adjectives: 0,
                frame_offset: Some(0x20),
                continuation_va: None,
            }],
            cleanup_actions: Vec::new(),
            claim: Claim::new((), ClaimSource::ExceptionHandling).with_score(0.95),
        };
        let json = serde_json::to_string(&fact).unwrap();
        assert!(json.contains(r#""schema":"eh_function_fact/1""#));
        assert!(json.contains(r#""abi":"msvc_f_h3""#) || json.contains(r#""abi":"msvc_fh3""#));
        assert!(json.contains(r#""kind":"typed""#));
        assert!(json.contains(r#""source":"exception_handling""#));
    }
}
