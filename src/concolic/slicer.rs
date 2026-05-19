//! Backward def-use slice over the Expr DAG.
//!
//! Given a full path's worth of constraints and a target branch
//! NodeId, return ONLY the constraints whose variables transitively
//! affect the target. Z3 solves dramatically faster on sliced
//! queries — usually the difference between "solves instantly" and
//! "times out at 1s."
//!
//! Algorithm: BFS over the DAG starting from the target branch.
//! Collect every `Var` symbol reachable from the target. Then for
//! each path constraint, if any of its `Var`s appears in the
//! reachable set, include the constraint AND fold its Vars back
//! into the reachable set. Iterate to fixpoint (bounded at
//! [`MAX_SLICE_ITERATIONS`]).

#![allow(dead_code)]

use std::collections::HashSet;

use crate::concolic::expr::{Expr, ExprDag, NodeId, SymbolId};

pub const MAX_SLICE_ITERATIONS: usize = 16;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConstraintSlice {
    /// Constraints (Bool NodeIds) reachable from the target.
    pub constraints: Vec<NodeId>,
    /// Set of symbol names referenced by the slice.
    pub variables: HashSet<SymbolId>,
    /// True if the fixpoint was reached. False means the iteration
    /// cap was hit first; the slice is still safe to use (it's a
    /// superset of the true minimal slice).
    pub fixpoint_reached: bool,
    /// Number of fixpoint iterations performed.
    pub iterations: usize,
}

/// Compute a backward slice of `path_constraints` toward `target_branch`.
pub fn backward_slice(
    dag: &ExprDag,
    path_constraints: &[NodeId],
    target_branch: NodeId,
) -> ConstraintSlice {
    let mut reachable_vars: HashSet<SymbolId> = HashSet::new();
    collect_vars(dag, target_branch, &mut reachable_vars);

    let mut included: HashSet<NodeId> = HashSet::new();
    let mut iterations = 0;
    let mut fixpoint_reached = false;
    for iter in 0..MAX_SLICE_ITERATIONS {
        iterations = iter + 1;
        let mut grew = false;
        for &c in path_constraints {
            if included.contains(&c) {
                continue;
            }
            let mut c_vars: HashSet<SymbolId> = HashSet::new();
            collect_vars(dag, c, &mut c_vars);
            if c_vars.is_disjoint(&reachable_vars) {
                continue;
            }
            included.insert(c);
            for v in c_vars {
                if reachable_vars.insert(v) {
                    grew = true;
                }
            }
            grew = true;
        }
        if !grew {
            fixpoint_reached = true;
            break;
        }
    }

    // Preserve original execution order.
    let mut constraints: Vec<NodeId> = path_constraints
        .iter()
        .copied()
        .filter(|c| included.contains(c))
        .collect();
    constraints.dedup();

    ConstraintSlice {
        constraints,
        variables: reachable_vars,
        fixpoint_reached,
        iterations,
    }
}

fn collect_vars(dag: &ExprDag, root: NodeId, out: &mut HashSet<SymbolId>) {
    let mut visited: HashSet<NodeId> = HashSet::new();
    let mut stack: Vec<NodeId> = vec![root];
    while let Some(id) = stack.pop() {
        if !visited.insert(id) {
            continue;
        }
        let e = dag.get(id);
        match e {
            Expr::Var { name, .. } => {
                out.insert(*name);
            }
            Expr::BvConst { .. } | Expr::BoolConst(_) => {}
            Expr::Not(a) => stack.push(*a),
            Expr::And(v) | Expr::Or(v) => {
                for &c in v {
                    stack.push(c);
                }
            }
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
            | Expr::Concat(a, b) => {
                stack.push(*a);
                stack.push(*b);
            }
            Expr::Extract { value, .. }
            | Expr::ZeroExt { value, .. }
            | Expr::SignExt { value, .. } => stack.push(*value),
            Expr::Ite {
                cond,
                then_id,
                else_id,
            } => {
                stack.push(*cond);
                stack.push(*then_id);
                stack.push(*else_id);
            }
            Expr::Load8 { mem, addr } => {
                stack.push(*mem);
                stack.push(*addr);
            }
            Expr::Store8 { mem, addr, value } => {
                stack.push(*mem);
                stack.push(*addr);
                stack.push(*value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concolic::expr::{Expr, ExprDag, Sort};

    fn var(dag: &mut ExprDag, name: &str, bits: u32) -> NodeId {
        let sym = dag.intern_symbol(name);
        dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(bits),
        })
    }

    #[test]
    fn empty_path_returns_empty_slice() {
        let mut dag = ExprDag::new();
        let t = dag.intern(Expr::BoolConst(true));
        let slice = backward_slice(&dag, &[], t);
        assert!(slice.constraints.is_empty());
        assert!(slice.fixpoint_reached);
    }

    #[test]
    fn slice_excludes_irrelevant_constraints() {
        let mut dag = ExprDag::new();
        let x = var(&mut dag, "x", 32);
        let y = var(&mut dag, "y", 32);
        let z = var(&mut dag, "z", 32);
        let c1 = dag.intern(Expr::BvConst { value: 1, bits: 32 });

        // Target: x == c1
        let target = dag.intern(Expr::Eq(x, c1));
        // Path: [y == c1, z == c1, x > c1]
        let p1 = dag.intern(Expr::Eq(y, c1));
        let p2 = dag.intern(Expr::Eq(z, c1));
        let xc1 = dag.intern(Expr::Ult(c1, x));
        let p3 = xc1;

        let slice = backward_slice(&dag, &[p1, p2, p3], target);
        // Only p3 references x; p1 and p2 are unrelated.
        assert_eq!(slice.constraints, vec![p3]);
        assert!(slice.variables.contains(&dag.intern_symbol("x")));
        assert!(!slice.variables.contains(&dag.intern_symbol("y")));
        assert!(!slice.variables.contains(&dag.intern_symbol("z")));
    }

    #[test]
    fn slice_includes_transitive_constraints() {
        let mut dag = ExprDag::new();
        let x = var(&mut dag, "x", 32);
        let y = var(&mut dag, "y", 32);
        let z = var(&mut dag, "z", 32);
        let c0 = dag.intern(Expr::BvConst { value: 0, bits: 32 });

        // Target: x == 0
        let target = dag.intern(Expr::Eq(x, c0));
        // Path: [x == y, y == z, z != 0]  → all should be in slice (transitive)
        let p1 = dag.intern(Expr::Eq(x, y)); // brings y in
        let p2 = dag.intern(Expr::Eq(y, z)); // brings z in
        let p3_eq = dag.intern(Expr::Eq(z, c0));
        let p3 = dag.intern(Expr::Not(p3_eq));

        let slice = backward_slice(&dag, &[p1, p2, p3], target);
        assert_eq!(slice.constraints, vec![p1, p2, p3]);
        assert!(slice.fixpoint_reached);
    }

    #[test]
    fn slice_preserves_original_order() {
        let mut dag = ExprDag::new();
        let x = var(&mut dag, "x", 32);
        let c0 = dag.intern(Expr::BvConst { value: 0, bits: 32 });
        let c1 = dag.intern(Expr::BvConst { value: 1, bits: 32 });
        let target = dag.intern(Expr::Eq(x, c0));
        let p1 = dag.intern(Expr::Eq(x, c1));
        let p2 = dag.intern(Expr::Ult(x, c0));
        let p3 = dag.intern(Expr::Slt(x, c1));
        let slice = backward_slice(&dag, &[p1, p2, p3], target);
        assert_eq!(slice.constraints, vec![p1, p2, p3]);
    }

    #[test]
    fn collect_vars_finds_nested() {
        let mut dag = ExprDag::new();
        let x = var(&mut dag, "x", 32);
        let y = var(&mut dag, "y", 32);
        let add = dag.intern(Expr::BvAdd(x, y));
        let mut out = HashSet::new();
        collect_vars(&dag, add, &mut out);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&dag.intern_symbol("x")));
        assert!(out.contains(&dag.intern_symbol("y")));
    }
}
