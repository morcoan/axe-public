use crate::native_emulator::{BranchPredicate, NativeEmulationResult};
use crate::portable::{parse_int, PortableInput, SymbolicPathRecord};
use std::collections::BTreeMap;

pub fn build_symbolic_paths(
    input: &PortableInput<'_>,
    result: Option<&NativeEmulationResult>,
) -> Vec<SymbolicPathRecord> {
    let Some(result) = result else {
        return Vec::new();
    };
    let cap = match input.emulation_budget {
        "max" => 512,
        "high" => 192,
        _ => 96,
    };
    result
        .predicates
        .iter()
        .take(cap)
        .enumerate()
        .map(|(index, predicate)| {
            let solved = solve_predicate(predicate);
            SymbolicPathRecord {
                path_id: format!("sym:{:016X}:{index:04X}", predicate.site_va),
                function: result.function,
                site_va: predicate.site_va,
                predicate: predicate.predicate.clone(),
                status: if result.cap_hit {
                    "failed_capped".to_string()
                } else {
                    "executed".to_string()
                },
                reason:
                    "bounded native constraint solve over branch predicate; no external SMT engine"
                        .to_string(),
                constraints: solved.constraints,
                satisfiability: solved.satisfiability,
                model: solved.model,
                cap_hit: result.cap_hit,
                evidence: vec![predicate.site_va],
            }
        })
        .collect()
}

struct SolvedPredicate {
    constraints: Vec<String>,
    satisfiability: String,
    model: BTreeMap<String, u64>,
}

fn solve_predicate(predicate: &BranchPredicate) -> SolvedPredicate {
    let relation = relation_for_branch(&predicate.mnemonic).unwrap_or("unknown");
    let constraint = format!("{} {} {}", predicate.left, relation, predicate.right);
    let mut model = BTreeMap::new();
    if relation == "unknown" || predicate.left == "unknown" || predicate.right == "unknown" {
        return SolvedPredicate {
            constraints: vec![constraint],
            satisfiability: "unknown".to_string(),
            model,
        };
    }
    let left_const = predicate.left_value.or_else(|| parse_int(&predicate.left));
    let right_const = predicate
        .right_value
        .or_else(|| parse_int(&predicate.right));
    let satisfiability = match (left_const, right_const) {
        (Some(left), Some(right)) => {
            if relation_holds(relation, left, right) {
                if parse_int(&predicate.left).is_none() && !predicate.left.is_empty() {
                    model.insert(predicate.left.clone(), left);
                }
                if parse_int(&predicate.right).is_none() && !predicate.right.is_empty() {
                    model.insert(predicate.right.clone(), right);
                }
                "satisfiable"
            } else {
                "unsatisfiable"
            }
        }
        (None, Some(right)) => {
            if let Some(value) = satisfying_value(relation, right) {
                model.insert(predicate.left.clone(), value);
                "satisfiable"
            } else {
                "unknown"
            }
        }
        (Some(left), None) => {
            if let Some(value) = satisfying_value_for_right(relation, left) {
                model.insert(predicate.right.clone(), value);
                "satisfiable"
            } else {
                "unknown"
            }
        }
        (None, None) => "unknown",
    };
    SolvedPredicate {
        constraints: vec![constraint],
        satisfiability: satisfiability.to_string(),
        model,
    }
}

fn relation_for_branch(branch: &str) -> Option<&'static str> {
    match branch {
        "je" | "jz" => Some("=="),
        "jne" | "jnz" => Some("!="),
        "ja" | "jnbe" | "jg" | "jnle" => Some(">"),
        "jae" | "jnb" | "jge" | "jnl" => Some(">="),
        "jb" | "jnae" | "jl" | "jnge" => Some("<"),
        "jbe" | "jna" | "jle" | "jng" => Some("<="),
        _ => None,
    }
}

fn relation_holds(relation: &str, left: u64, right: u64) -> bool {
    match relation {
        "==" => left == right,
        "!=" => left != right,
        ">" => left > right,
        ">=" => left >= right,
        "<" => left < right,
        "<=" => left <= right,
        _ => false,
    }
}

fn satisfying_value(relation: &str, right: u64) -> Option<u64> {
    match relation {
        "==" => Some(right),
        "!=" => Some(right.wrapping_add(1)),
        ">" => Some(right.wrapping_add(1)),
        ">=" => Some(right),
        "<" => right.checked_sub(1),
        "<=" => Some(right),
        _ => None,
    }
}

fn satisfying_value_for_right(relation: &str, left: u64) -> Option<u64> {
    match relation {
        "==" => Some(left),
        "!=" => Some(left.wrapping_add(1)),
        ">" => left.checked_sub(1),
        ">=" => Some(left),
        "<" => Some(left.wrapping_add(1)),
        "<=" => Some(left),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn predicate(branch: &str, left: &str, right: &str) -> BranchPredicate {
        BranchPredicate {
            site_va: 0x1000,
            mnemonic: branch.to_string(),
            left: left.to_string(),
            right: right.to_string(),
            predicate: format!("{branch} if cmp {left}, {right}"),
            left_value: None,
            right_value: None,
        }
    }

    #[test]
    fn solver_finds_register_model_for_equal_branch() {
        let solved = solve_predicate(&predicate("je", "rcx", "4"));
        assert_eq!("satisfiable", solved.satisfiability);
        assert_eq!(Some(&4), solved.model.get("rcx"));
    }

    #[test]
    fn solver_reports_unsat_for_constant_contradiction() {
        let solved = solve_predicate(&predicate("je", "5", "4"));
        assert_eq!("unsatisfiable", solved.satisfiability);
    }

    #[test]
    fn solver_reports_unknown_for_unsupported_predicate() {
        let solved = solve_predicate(&predicate("jp", "rcx", "4"));
        assert_eq!("unknown", solved.satisfiability);
    }
}
