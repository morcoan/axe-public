//! [`Z3ExternalSmt2Backend`] — Codex finding 3 mitigation.
//!
//! Spawns `z3 -smt2 -in -t:<ms>`, pipes the [`emit_query`]-rendered
//! SMT-LIB string to stdin, then parses stdout for `sat`/`unsat`/
//! `unknown`, the `(define-fun input_b<i> () (_ BitVec 8) #x<HH>)`
//! model entries, and the s-expression `(c_05 c_TGT c_11)` unsat-core
//! list. The emitter's `name_map` reverse-translates `c_NN` names back
//! to constraint [`NodeId`]s so the ladder can detect authoritative
//! branch-unreachability.
//!
//! Discipline (Codex finding 3): a bare `unsat` reply without a
//! parseable `(get-unsat-core)` line is downgraded to
//! [`SolveStatus::Unknown`] with `reason: "external_unsat_without_core"`.
//! The ladder treats it as a budget shortfall, never as proof of
//! unreachability.

#![allow(dead_code)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::concolic::backend::{BranchQuery, SmtBackend, SolveReport, SolveStatus};
use crate::concolic::expr::{ExprDag, NodeId};
use crate::concolic::smt2_emit::{emit_query, EmittedQuery};

pub const BACKEND_NAME: &str = "z3_external_smt2";

/// Configuration the ladder hands to the external backend at
/// construction time.
#[derive(Clone, Debug)]
pub struct ExternalZ3Config {
    /// Binary name or absolute path. Default `"z3"`.
    pub z3_binary: String,
    /// Extra args (e.g. `["-T:<ms>"]` for global wall-clock).
    /// `-smt2`, `-in`, and `-t:<ms>` are always injected.
    pub extra_args: Vec<String>,
}

impl Default for ExternalZ3Config {
    fn default() -> Self {
        Self {
            z3_binary: "z3".to_string(),
            extra_args: Vec::new(),
        }
    }
}

pub struct Z3ExternalSmt2Backend {
    config: ExternalZ3Config,
}

impl Z3ExternalSmt2Backend {
    pub fn new(config: ExternalZ3Config) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(ExternalZ3Config::default())
    }

    fn run_z3(
        &self,
        smt2: &str,
        timeout: Duration,
    ) -> Result<(String, Duration), ExternalRunError> {
        let timeout_ms = timeout.as_millis().min(u64::MAX as u128) as u64;
        let mut cmd = Command::new(&self.config.z3_binary);
        cmd.arg("-smt2")
            .arg("-in")
            .arg(format!("-t:{}", timeout_ms))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for a in &self.config.extra_args {
            cmd.arg(a);
        }
        let started = Instant::now();
        let mut child = cmd.spawn().map_err(ExternalRunError::SpawnFailed)?;
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(smt2.as_bytes())
                .map_err(ExternalRunError::StdinWrite)?;
            // Drop sin to close stdin so z3 exits.
        }
        let output = child
            .wait_with_output()
            .map_err(ExternalRunError::WaitFailed)?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok((stdout, started.elapsed()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExternalRunError {
    #[error("spawn failed (is `z3` on PATH?): {0}")]
    SpawnFailed(std::io::Error),
    #[error("stdin write failed: {0}")]
    StdinWrite(std::io::Error),
    #[error("wait failed: {0}")]
    WaitFailed(std::io::Error),
}

impl SmtBackend for Z3ExternalSmt2Backend {
    fn solve_branch(&mut self, query: &BranchQuery, dag: &ExprDag) -> SolveReport {
        let emitted = emit_query(query, dag);
        match self.run_z3(&emitted.smt2, query.timeout) {
            Ok((stdout, elapsed)) => parse_z3_response(stdout, elapsed, emitted, query),
            Err(e) => SolveReport {
                status: SolveStatus::Unknown,
                time_ms: 0,
                input_model: None,
                smt2: emitted.smt2,
                reason: Some(format!("z3_external_run_error: {e}")),
                unsat_core: Vec::new(),
                unsat_assumptions_returned: false,
                backend: BACKEND_NAME,
            },
        }
    }

    fn dump_smt2(&self, query: &BranchQuery, dag: &ExprDag) -> String {
        emit_query(query, dag).smt2
    }

    fn name(&self) -> &'static str {
        BACKEND_NAME
    }
}

/// Parse a Z3 `-smt2 -in` stdout into a [`SolveReport`].
///
/// Recognized lines (the order Z3 emits them):
/// - `sat` / `unsat` / `unknown` — first non-comment word
/// - If `sat`: `(model ... (define-fun input_b<i> () (_ BitVec 8) #xAB) ...)` —
///   could be one big block or multiple `(define-fun ...)` top-levels.
/// - If `unsat`: optionally `(c_03 c_TGT c_05)` — the unsat core
///   list returned from `(get-unsat-core)`.
/// - Possibly `(error "…")` if the engine had a parse/protocol issue.
pub fn parse_z3_response(
    stdout: String,
    elapsed: Duration,
    emitted: EmittedQuery,
    query: &BranchQuery,
) -> SolveReport {
    let time_ms = elapsed.as_millis() as u64;
    let mut status_line: Option<&str> = None;
    let mut error_seen = false;
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with("(error") {
            error_seen = true;
            continue;
        }
        if status_line.is_none()
            && (line == "sat" || line == "unsat" || line == "unknown" || line == "timeout")
        {
            status_line = Some(line);
        }
    }
    let status_word = match status_line {
        Some(s) => s,
        None => {
            return SolveReport {
                status: SolveStatus::Unknown,
                time_ms,
                input_model: None,
                smt2: emitted.smt2,
                reason: Some("z3_external_no_status_line".into()),
                unsat_core: Vec::new(),
                unsat_assumptions_returned: false,
                backend: BACKEND_NAME,
            };
        }
    };

    match status_word {
        "sat" => {
            let model = parse_model_input_bytes(&stdout, query.input_bytes);
            SolveReport {
                status: SolveStatus::Sat,
                time_ms,
                input_model: Some(model),
                smt2: emitted.smt2,
                reason: None,
                unsat_core: Vec::new(),
                unsat_assumptions_returned: false,
                backend: BACKEND_NAME,
            }
        }
        "unsat" => {
            let core_names = parse_unsat_core(&stdout);
            // Reverse-map names → NodeIds. Names not present in the
            // emitter's table are dropped (likely `c_TGT` plus
            // emitter-internal helpers we don't track).
            let mut unsat_core: Vec<NodeId> = Vec::new();
            for name in &core_names {
                if let Some((_, nid)) = emitted.name_map.iter().find(|(n, _)| n == name) {
                    unsat_core.push(*nid);
                }
            }
            let core_was_returned = !core_names.is_empty() && !error_seen;
            if !core_was_returned {
                // Codex finding 3: bare unsat without a parseable core
                // is not authoritative. Downgrade to Unknown so the
                // ladder doesn't label the branch unreachable.
                return SolveReport {
                    status: SolveStatus::Unknown,
                    time_ms,
                    input_model: None,
                    smt2: emitted.smt2,
                    reason: Some("external_unsat_without_core".into()),
                    unsat_core: Vec::new(),
                    unsat_assumptions_returned: false,
                    backend: BACKEND_NAME,
                };
            }
            SolveReport {
                status: SolveStatus::Unsat,
                time_ms,
                input_model: None,
                smt2: emitted.smt2,
                reason: None,
                unsat_core,
                unsat_assumptions_returned: true,
                backend: BACKEND_NAME,
            }
        }
        "unknown" => SolveReport {
            status: SolveStatus::Unknown,
            time_ms,
            input_model: None,
            smt2: emitted.smt2,
            reason: Some("z3_external_unknown".into()),
            unsat_core: Vec::new(),
            unsat_assumptions_returned: false,
            backend: BACKEND_NAME,
        },
        "timeout" => SolveReport {
            status: SolveStatus::Timeout,
            time_ms,
            input_model: None,
            smt2: emitted.smt2,
            reason: Some("z3_external_timeout".into()),
            unsat_core: Vec::new(),
            unsat_assumptions_returned: false,
            backend: BACKEND_NAME,
        },
        other => SolveReport {
            status: SolveStatus::Unknown,
            time_ms,
            input_model: None,
            smt2: emitted.smt2,
            reason: Some(format!("z3_external_unexpected_status: {other}")),
            unsat_core: Vec::new(),
            unsat_assumptions_returned: false,
            backend: BACKEND_NAME,
        },
    }
}

/// Parse `(define-fun input_b<i> () (_ BitVec 8) #x<HH>)` lines into
/// a byte vector of size `input_bytes`. Missing bytes default to 0.
/// Also tolerates `#b00010101` binary literals and decimal `(_ bv<N> 8)`.
pub fn parse_model_input_bytes(stdout: &str, input_bytes: u32) -> Vec<u8> {
    let mut out = vec![0u8; input_bytes as usize];
    for line in stdout.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("(define-fun input_b") else {
            continue;
        };
        let idx_end = rest.find(' ').unwrap_or(rest.len());
        let Ok(idx) = rest[..idx_end].parse::<u32>() else {
            continue;
        };
        if idx >= input_bytes {
            continue;
        }
        // Find the literal between the `(_ BitVec 8)` (or similar) and
        // the trailing `)`.
        let after = &rest[idx_end..];
        if let Some(value) = parse_byte_literal(after) {
            out[idx as usize] = value;
        }
    }
    out
}

fn parse_byte_literal(s: &str) -> Option<u8> {
    // Look for `#x<HH>`, `#b<8 bits>`, or `(_ bv<N> 8)`.
    if let Some(pos) = s.find("#x") {
        let rest = &s[pos + 2..];
        let end = rest
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        if end > 0 {
            return u8::from_str_radix(&rest[..end], 16).ok();
        }
    }
    if let Some(pos) = s.find("#b") {
        let rest = &s[pos + 2..];
        let end = rest
            .find(|c: char| c != '0' && c != '1')
            .unwrap_or(rest.len());
        if end > 0 {
            return u8::from_str_radix(&rest[..end], 2).ok();
        }
    }
    if let Some(pos) = s.find("(_ bv") {
        let rest = &s[pos + 5..];
        let end = rest.find(' ').unwrap_or(rest.len());
        if end > 0 {
            return rest[..end].parse::<u8>().ok();
        }
    }
    None
}

/// Parse a `(get-unsat-core)` reply: `(c_05 c_TGT c_11)` → vector of
/// names. Tolerates an empty `()` reply (returns empty vec).
pub fn parse_unsat_core(stdout: &str) -> Vec<String> {
    let mut names = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix('(').and_then(|x| x.strip_suffix(')')) else {
            continue;
        };
        // Heuristic: only treat a parenthesized line as a core if
        // every space-separated token starts with `c_`.
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        if tokens.iter().all(|t| t.starts_with("c_")) {
            for t in tokens {
                names.push(t.to_string());
            }
            return names;
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concolic::backend::SolveStatus;
    use crate::concolic::expr::{Expr, ExprDag, Sort};
    use std::time::Duration;

    fn dummy_query(target: NodeId) -> BranchQuery {
        BranchQuery {
            input_bytes: 4,
            path_constraints: vec![],
            target_branch: target,
            want_taken: true,
            timeout: Duration::from_millis(100),
            prefer_logic: Some("QF_BV"),
        }
    }

    fn dummy_emitted() -> EmittedQuery {
        EmittedQuery {
            smt2: "; placeholder\n(check-sat)\n".to_string(),
            name_map: vec![("c_00".into(), 1), ("c_01".into(), 2), ("c_TGT".into(), 99)],
        }
    }

    #[test]
    fn parse_sat_with_model() {
        let stdout = "sat\n(define-fun input_b0 () (_ BitVec 8) #x7f)\n(define-fun input_b3 () (_ BitVec 8) #x46)\n";
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let r = parse_z3_response(
            stdout.into(),
            Duration::from_millis(5),
            dummy_emitted(),
            &dummy_query(t),
        );
        assert_eq!(r.status, SolveStatus::Sat);
        let model = r.input_model.unwrap();
        assert_eq!(model.len(), 4);
        assert_eq!(model[0], 0x7f);
        assert_eq!(model[3], 0x46);
        assert_eq!(model[1], 0); // missing → default 0
    }

    #[test]
    fn parse_unsat_with_core_sets_authoritative_flag() {
        let stdout = "unsat\n(c_00 c_TGT)\n";
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let r = parse_z3_response(
            stdout.into(),
            Duration::from_millis(5),
            dummy_emitted(),
            &dummy_query(t),
        );
        assert_eq!(r.status, SolveStatus::Unsat);
        assert!(r.unsat_assumptions_returned);
        assert_eq!(r.unsat_core, vec![1, 99]); // c_00 → 1, c_TGT → 99
        assert!(r.is_authoritative_unreachable());
    }

    #[test]
    fn parse_unsat_without_core_downgrades_to_unknown() {
        let stdout = "unsat\n"; // No core line.
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let r = parse_z3_response(
            stdout.into(),
            Duration::from_millis(5),
            dummy_emitted(),
            &dummy_query(t),
        );
        assert_eq!(r.status, SolveStatus::Unknown);
        assert_eq!(r.reason.as_deref(), Some("external_unsat_without_core"));
        assert!(!r.unsat_assumptions_returned);
        assert!(!r.is_authoritative_unreachable());
    }

    #[test]
    fn parse_unsat_with_error_after_downgrades() {
        let stdout = "unsat\n(error \"failed to compute core\")\n";
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let r = parse_z3_response(
            stdout.into(),
            Duration::from_millis(5),
            dummy_emitted(),
            &dummy_query(t),
        );
        // An error after unsat means the core call failed — not
        // authoritative.
        assert_eq!(r.status, SolveStatus::Unknown);
    }

    #[test]
    fn parse_unknown_status_returns_unknown() {
        let stdout = "unknown\n";
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let r = parse_z3_response(
            stdout.into(),
            Duration::from_millis(5),
            dummy_emitted(),
            &dummy_query(t),
        );
        assert_eq!(r.status, SolveStatus::Unknown);
        assert_eq!(r.reason.as_deref(), Some("z3_external_unknown"));
    }

    #[test]
    fn parse_timeout_status_returns_timeout() {
        let stdout = "timeout\n";
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let r = parse_z3_response(
            stdout.into(),
            Duration::from_millis(5),
            dummy_emitted(),
            &dummy_query(t),
        );
        assert_eq!(r.status, SolveStatus::Timeout);
    }

    #[test]
    fn parse_no_status_line_returns_unknown() {
        let stdout = "; just comments\n";
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let r = parse_z3_response(
            stdout.into(),
            Duration::from_millis(5),
            dummy_emitted(),
            &dummy_query(t),
        );
        assert_eq!(r.status, SolveStatus::Unknown);
        assert_eq!(r.reason.as_deref(), Some("z3_external_no_status_line"));
    }

    #[test]
    fn parse_model_handles_binary_and_decimal_literals() {
        let stdout = "sat\n\
            (define-fun input_b0 () (_ BitVec 8) #b00000001)\n\
            (define-fun input_b1 () (_ BitVec 8) (_ bv255 8))\n";
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let r = parse_z3_response(
            stdout.into(),
            Duration::from_millis(5),
            dummy_emitted(),
            &dummy_query(t),
        );
        let model = r.input_model.unwrap();
        assert_eq!(model[0], 1);
        assert_eq!(model[1], 255);
    }

    #[test]
    fn parse_unsat_core_skips_non_c_lines() {
        let stdout = "unsat\n(model)\n(c_00)\n";
        let core = parse_unsat_core(stdout);
        assert_eq!(core, vec!["c_00".to_string()]);
    }

    #[test]
    fn spawn_failure_returns_unknown_with_reason() {
        let mut backend = Z3ExternalSmt2Backend::new(ExternalZ3Config {
            z3_binary: "definitely_not_z3_anywhere".to_string(),
            extra_args: Vec::new(),
        });
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));
        let r = backend.solve_branch(&dummy_query(target), &dag);
        assert_eq!(r.status, SolveStatus::Unknown);
        assert!(r.reason.unwrap().starts_with("z3_external_run_error"));
    }
}
