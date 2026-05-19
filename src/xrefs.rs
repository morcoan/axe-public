use crate::pe::{FunctionRecord, XrefRecord};

pub fn attach_function_refs(functions: &mut [FunctionRecord], xrefs: &[XrefRecord]) {
    for xref in xrefs {
        let Some(function) = functions
            .iter_mut()
            .find(|func| func.start <= xref.from && xref.from < func.end)
        else {
            continue;
        };
        function.xrefs += 1;
        match xref.kind.as_str() {
            "import" => {
                if let Some(symbol) = &xref.symbol {
                    push_unique(&mut function.calls_imports, symbol.clone());
                }
            }
            "string" => {
                if let Some(text) = &xref.text {
                    push_unique(&mut function.strings, text.clone());
                }
            }
            "code" if xref.role == "call" => push_unique(&mut function.calls, xref.target),
            _ => {}
        }
    }
}

fn push_unique<T: Eq>(target: &mut Vec<T>, value: T) {
    if !target.contains(&value) {
        target.push(value);
    }
}
