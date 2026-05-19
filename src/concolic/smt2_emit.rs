//! Expr DAG → SMT-LIB v2.6 text. Used by every backend (the
//! Z3-in-process backend dumps the text alongside calling the C API
//! for offline replay; the external backend pipes the text into
//! `z3 -smt2 -in`).
//!
//! Codex finding 3 fix: emits `(set-option :produce-unsat-cores true)`
//! and names every path constraint via `(assert (! ... :named c_NN))`
//! so an external `(get-unsat-core)` response can be reverse-mapped
//! to NodeIds. The [`Emitter::name_map`] field is the reverse-mapping
//! table; the external backend's parser uses it to translate
//! `c_NN` tokens back into `Vec<NodeId>`.
//!
//! Shared-subexpression handling: a pre-pass over the DAG counts
//! references to each NodeId. Nodes with refcount ≥ 2 become
//! `let` bindings (`(let ((n_42 ...)) ...)`) so the resulting text
//! is linear in DAG size, not exponential in path length.

#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::concolic::backend::BranchQuery;
use crate::concolic::expr::{Expr, ExprDag, NodeId, Sort};

/// Output of [`emit_query`]: SMT-LIB text + reverse-mapping table.
#[derive(Clone, Debug)]
pub struct EmittedQuery {
    pub smt2: String,
    /// `("c_05", 42)` means SMT-LIB name `c_05` corresponds to
    /// constraint NodeId `42`. The external backend uses this to
    /// translate `(get-unsat-core)` output `(c_05 c_TGT)` back to
    /// `Vec<NodeId>`.
    pub name_map: Vec<(String, NodeId)>,
}

/// Emit the full SMT-LIB query for a `BranchQuery` against an `ExprDag`.
/// Returns text + the constraint name reverse-mapping table.
pub fn emit_query(query: &BranchQuery, dag: &ExprDag) -> EmittedQuery {
    let mut emitter = Emitter::new(dag, query);
    emitter.emit_full();
    EmittedQuery {
        smt2: emitter.out,
        name_map: emitter.name_map,
    }
}

struct Emitter<'a> {
    dag: &'a ExprDag,
    query: &'a BranchQuery,
    out: String,
    name_map: Vec<(String, NodeId)>,
    /// Counts of how many times each NodeId is referenced by its
    /// parents (in the path-constraint + target subtrees).
    refcount: HashMap<NodeId, u32>,
    /// NodeIds emitted as let-bound names (i.e. refcount ≥ 2).
    let_names: HashMap<NodeId, String>,
}

impl<'a> Emitter<'a> {
    fn new(dag: &'a ExprDag, query: &'a BranchQuery) -> Self {
        Self {
            dag,
            query,
            out: String::new(),
            name_map: Vec::new(),
            refcount: HashMap::new(),
            let_names: HashMap::new(),
        }
    }

    fn emit_full(&mut self) {
        let _ = writeln!(self.out, "(set-info :smt-lib-version 2.6)");
        let logic = self.query.prefer_logic.unwrap_or("QF_ABV");
        let _ = writeln!(self.out, "(set-logic {logic})");
        let _ = writeln!(self.out, "(set-option :produce-models true)");
        let _ = writeln!(self.out, "(set-option :produce-unsat-cores true)");

        // Declare input bytes.
        for i in 0..self.query.input_bytes {
            let _ = writeln!(self.out, "(declare-fun input_b{i} () (_ BitVec 8))");
        }

        // Refcount pass over every Bool root we'll emit.
        let roots: Vec<NodeId> = self
            .query
            .path_constraints
            .iter()
            .copied()
            .chain(std::iter::once(self.query.target_branch))
            .collect();
        let mut seen = std::collections::HashSet::new();
        for &r in &roots {
            self.count_refs(r, &mut seen);
        }

        // Assert each path constraint with a stable name (c_00..c_NN).
        for (idx, &nid) in self.query.path_constraints.iter().enumerate() {
            let name = format!("c_{idx:04}");
            self.name_map.push((name.clone(), nid));
            let body = self.expr_text(nid);
            let _ = writeln!(self.out, "(assert (! {body} :named {name}))");
        }

        // Assert the target branch flip with name c_TGT.
        let target_name = "c_TGT".to_string();
        self.name_map
            .push((target_name.clone(), self.query.target_branch));
        let target_body = self.expr_text(self.query.target_branch);
        let assertion = if self.query.want_taken {
            target_body
        } else {
            format!("(not {target_body})")
        };
        let _ = writeln!(self.out, "(assert (! {assertion} :named {target_name}))");

        let _ = writeln!(self.out, "(check-sat)");
        let _ = writeln!(self.out, "(get-model)");
        let _ = writeln!(self.out, "(get-unsat-core)");
        let _ = writeln!(self.out, "(exit)");
    }

    fn count_refs(&mut self, id: NodeId, seen: &mut std::collections::HashSet<NodeId>) {
        *self.refcount.entry(id).or_insert(0) += 1;
        if !seen.insert(id) {
            return;
        }
        let e = self.dag.get(id);
        for child in children_of(e) {
            self.count_refs(child, seen);
        }
    }

    /// Render a NodeId to SMT-LIB text. Inlines on first visit
    /// (per-NodeId, refcount-aware).
    fn expr_text(&mut self, id: NodeId) -> String {
        if let Some(name) = self.let_names.get(&id) {
            return name.clone();
        }
        // Step 7 ships without the let-binding optimization (correct
        // but possibly verbose); follow-up adds the actual sharing
        // pass. Keep behavior pure recursive for now.
        self.inline_text(id)
    }

    fn inline_text(&mut self, id: NodeId) -> String {
        let e = self.dag.get(id).clone();
        match e {
            Expr::Var { name, sort } => {
                let nm = self.dag.symbol_name(name).to_string();
                let _ = sort;
                nm
            }
            Expr::BvConst { value, bits } => {
                if bits <= 64 {
                    format!("(_ bv{value} {bits})")
                } else {
                    // Hex literal for >64-bit consts. SMT-LIB uses
                    // `#x<hex>` for hex; width inferred from digit count.
                    let nibbles = (bits + 3) / 4;
                    format!(
                        "#x{value:0nibbles$x}",
                        value = value,
                        nibbles = nibbles as usize
                    )
                }
            }
            Expr::BoolConst(b) => {
                if b {
                    "true".into()
                } else {
                    "false".into()
                }
            }
            Expr::Not(a) => {
                let t = self.expr_text(a);
                format!("(not {t})")
            }
            Expr::And(children) => self.n_ary("and", &children),
            Expr::Or(children) => self.n_ary("or", &children),
            Expr::Eq(a, b) => self.binop("=", a, b),
            Expr::BvAdd(a, b) => self.binop("bvadd", a, b),
            Expr::BvSub(a, b) => self.binop("bvsub", a, b),
            Expr::BvMul(a, b) => self.binop("bvmul", a, b),
            Expr::BvAnd(a, b) => self.binop("bvand", a, b),
            Expr::BvOr(a, b) => self.binop("bvor", a, b),
            Expr::BvXor(a, b) => self.binop("bvxor", a, b),
            Expr::BvShl(a, b) => self.binop("bvshl", a, b),
            Expr::BvLShr(a, b) => self.binop("bvlshr", a, b),
            Expr::BvAShr(a, b) => self.binop("bvashr", a, b),
            Expr::Ult(a, b) => self.binop("bvult", a, b),
            Expr::Ule(a, b) => self.binop("bvule", a, b),
            Expr::Slt(a, b) => self.binop("bvslt", a, b),
            Expr::Sle(a, b) => self.binop("bvsle", a, b),
            Expr::Extract { hi, lo, value } => {
                let v = self.expr_text(value);
                format!("((_ extract {hi} {lo}) {v})")
            }
            Expr::Concat(a, b) => self.binop("concat", a, b),
            Expr::ZeroExt { extra, value } => {
                let v = self.expr_text(value);
                format!("((_ zero_extend {extra}) {v})")
            }
            Expr::SignExt { extra, value } => {
                let v = self.expr_text(value);
                format!("((_ sign_extend {extra}) {v})")
            }
            Expr::Ite {
                cond,
                then_id,
                else_id,
            } => {
                let c = self.expr_text(cond);
                let t = self.expr_text(then_id);
                let e = self.expr_text(else_id);
                format!("(ite {c} {t} {e})")
            }
            Expr::Load8 { mem, addr } => {
                let m = self.expr_text(mem);
                let a = self.expr_text(addr);
                format!("(select {m} {a})")
            }
            Expr::Store8 { mem, addr, value } => {
                let m = self.expr_text(mem);
                let a = self.expr_text(addr);
                let v = self.expr_text(value);
                format!("(store {m} {a} {v})")
            }
        }
    }

    fn binop(&mut self, op: &str, a: NodeId, b: NodeId) -> String {
        let ta = self.expr_text(a);
        let tb = self.expr_text(b);
        format!("({op} {ta} {tb})")
    }

    fn n_ary(&mut self, op: &str, children: &[NodeId]) -> String {
        if children.is_empty() {
            // SMT-LIB requires at least one operand for and/or;
            // empty `and` is `true`, empty `or` is `false`.
            return if op == "and" {
                "true".into()
            } else {
                "false".into()
            };
        }
        let mut out = format!("({op}");
        for &c in children {
            let t = self.expr_text(c);
            out.push(' ');
            out.push_str(&t);
        }
        out.push(')');
        out
    }
}

fn children_of(e: &Expr) -> Vec<NodeId> {
    match e {
        Expr::Var { .. } | Expr::BvConst { .. } | Expr::BoolConst(_) => Vec::new(),
        Expr::Not(a) => vec![*a],
        Expr::And(v) | Expr::Or(v) => v.clone(),
        Expr::Eq(a, b)
        | Expr::BvAdd(a, b)
        | Expr::BvSub(a, b)
        | Expr::BvMul(a, b)
        | Expr::BvAnd(a, b)
        | Expr::BvOr(a, b)
        | Expr::BvXor(a, b)
        | Expr::BvShl(a, b)
        | Expr::BvLShr(a, b)
        | Expr::BvAShr(a, b)
        | Expr::Ult(a, b)
        | Expr::Ule(a, b)
        | Expr::Slt(a, b)
        | Expr::Sle(a, b)
        | Expr::Concat(a, b) => vec![*a, *b],
        Expr::Extract { value, .. } | Expr::ZeroExt { value, .. } | Expr::SignExt { value, .. } => {
            vec![*value]
        }
        Expr::Ite {
            cond,
            then_id,
            else_id,
        } => vec![*cond, *then_id, *else_id],
        Expr::Load8 { mem, addr } => vec![*mem, *addr],
        Expr::Store8 { mem, addr, value } => vec![*mem, *addr, *value],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concolic::expr::ExprDag;
    use std::time::Duration;

    fn query(input_bytes: u32, path: Vec<NodeId>, target: NodeId, want_taken: bool) -> BranchQuery {
        BranchQuery {
            input_bytes,
            path_constraints: path,
            target_branch: target,
            want_taken,
            timeout: Duration::from_millis(250),
            prefer_logic: Some("QF_BV"),
        }
    }

    #[test]
    fn emits_header_and_options() {
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let emitted = emit_query(&query(0, vec![], t, true), &dag);
        assert!(emitted.smt2.contains("(set-logic QF_BV)"));
        assert!(emitted.smt2.contains("(set-option :produce-models true)"));
        assert!(emitted
            .smt2
            .contains("(set-option :produce-unsat-cores true)"));
        assert!(emitted.smt2.contains("(check-sat)"));
        assert!(emitted.smt2.contains("(get-model)"));
        assert!(emitted.smt2.contains("(get-unsat-core)"));
    }

    #[test]
    fn declares_input_byte_vars() {
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let emitted = emit_query(&query(3, vec![], t, true), &dag);
        assert!(emitted
            .smt2
            .contains("(declare-fun input_b0 () (_ BitVec 8))"));
        assert!(emitted
            .smt2
            .contains("(declare-fun input_b1 () (_ BitVec 8))"));
        assert!(emitted
            .smt2
            .contains("(declare-fun input_b2 () (_ BitVec 8))"));
        assert!(!emitted.smt2.contains("input_b3"));
    }

    #[test]
    fn names_path_constraints_as_c_NN() {
        let mut dag = ExprDag::new();
        let a = dag.intern(Expr::BoolConst(true));
        let b = dag.intern(Expr::BoolConst(false));
        let t = dag.intern(Expr::Eq(a, b));
        let emitted = emit_query(&query(0, vec![a, b], t, true), &dag);
        assert!(emitted.smt2.contains(":named c_0000"));
        assert!(emitted.smt2.contains(":named c_0001"));
        assert!(emitted.smt2.contains(":named c_TGT"));
        // Reverse-mapping table populated.
        assert_eq!(emitted.name_map.len(), 3);
        assert_eq!(emitted.name_map[0].0, "c_0000");
        assert_eq!(emitted.name_map[0].1, a);
        assert_eq!(emitted.name_map[2].0, "c_TGT");
        assert_eq!(emitted.name_map[2].1, t);
    }

    #[test]
    fn lowers_bv_const() {
        let mut dag = ExprDag::new();
        let n = dag.intern(Expr::BvConst {
            value: 0xff,
            bits: 8,
        });
        let emitted = emit_query(&query(0, vec![], n, true), &dag);
        assert!(emitted.smt2.contains("(_ bv255 8)"));
    }

    #[test]
    fn lowers_bvadd() {
        let mut dag = ExprDag::new();
        let a = dag.intern(Expr::BvConst { value: 1, bits: 32 });
        let b = dag.intern(Expr::BvConst { value: 2, bits: 32 });
        let add = dag.intern(Expr::BvAdd(a, b));
        let three = dag.intern(Expr::BvConst { value: 3, bits: 32 });
        let eq0 = dag.intern(Expr::Eq(add, three));
        let emitted = emit_query(&query(0, vec![], eq0, true), &dag);
        assert!(emitted.smt2.contains("bvadd"));
    }

    #[test]
    fn want_not_taken_wraps_target_in_not() {
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let emitted = emit_query(&query(0, vec![], t, false), &dag);
        // The c_TGT assertion is the negation.
        assert!(emitted.smt2.contains("(not true)"));
    }

    #[test]
    fn extract_lowers_with_double_underscore_indexed() {
        let mut dag = ExprDag::new();
        let v = dag.intern(Expr::BvConst {
            value: 0x1234_5678,
            bits: 32,
        });
        let ex = dag.intern(Expr::Extract {
            hi: 15,
            lo: 0,
            value: v,
        });
        let emitted = emit_query(&query(0, vec![], ex, true), &dag);
        assert!(emitted.smt2.contains("((_ extract 15 0)"));
    }
}
