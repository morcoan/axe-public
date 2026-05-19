use crate::portable::{KernelArtifactRecord, PortableInput};

pub fn build_kernel_artifacts(input: &PortableInput<'_>) -> Vec<KernelArtifactRecord> {
    let is_driver_path = input.source_path.to_ascii_lowercase().ends_with(".sys");
    let kernel_imports: Vec<String> = input
        .imports
        .iter()
        .filter(|row| is_kernel_symbol(&row.symbol))
        .map(|row| row.symbol.clone())
        .collect();
    let dispatch_routines: Vec<String> = input
        .imports
        .iter()
        .filter_map(|row| dispatch_name(&row.name).or_else(|| dispatch_name(&row.symbol)))
        .collect();
    let device_names: Vec<String> = input
        .strings
        .iter()
        .filter_map(|row| {
            let text = row.text.trim();
            (text.starts_with("\\Device\\") || text.starts_with("\\DosDevices\\"))
                .then(|| text.to_string())
        })
        .take(32)
        .collect();
    let ioctl_codes: Vec<String> = input
        .strings
        .iter()
        .flat_map(|row| extract_ioctl_codes(&row.text))
        .take(64)
        .collect();

    if !is_driver_path
        && kernel_imports.is_empty()
        && dispatch_routines.is_empty()
        && ioctl_codes.is_empty()
        && device_names.is_empty()
    {
        return Vec::new();
    }
    let mut signals = Vec::new();
    if is_driver_path {
        signals.push("driver_extension".to_string());
    }
    if !kernel_imports.is_empty() {
        signals.push("kernel_imports".to_string());
    }
    if !dispatch_routines.is_empty() {
        signals.push("dispatch_routines".to_string());
    }
    if !ioctl_codes.is_empty() {
        signals.push("ioctl_surface".to_string());
    }
    if !device_names.is_empty() {
        signals.push("device_names".to_string());
    }
    if input
        .sections
        .iter()
        .any(|section| section.writable && section.executable)
    {
        signals.push("rwx_section".to_string());
    }
    let evidence = kernel_imports
        .iter()
        .take(8)
        .cloned()
        .chain(device_names.iter().take(4).cloned())
        .chain(ioctl_codes.iter().take(4).cloned())
        .collect();
    vec![KernelArtifactRecord {
        artifact_id: "kernel:driver:0000".to_string(),
        artifact_type: "windows_driver".to_string(),
        kernel_imports: kernel_imports.iter().take(64).cloned().collect(),
        signals,
        dispatch_routines,
        ioctl_codes,
        device_names,
        confidence: if is_driver_path && !kernel_imports.is_empty() {
            "high"
        } else if is_driver_path || !kernel_imports.is_empty() {
            "medium"
        } else {
            "low"
        }
        .to_string(),
        evidence,
    }]
}

fn is_kernel_symbol(symbol: &str) -> bool {
    let symbol = symbol.to_ascii_lowercase();
    symbol.starts_with("ntoskrnl")
        || symbol.starts_with("hal.dll")
        || symbol.starts_with("fltmgr")
        || symbol.contains("iocompleterequest")
        || symbol.contains("iocreatedevice")
        || symbol.contains("iodispatch")
        || symbol.contains("psset")
        || symbol.contains("obregister")
}

fn dispatch_name(symbol: &str) -> Option<String> {
    let lower = symbol.to_ascii_lowercase();
    for name in [
        "IoCreateDevice",
        "IoCreateSymbolicLink",
        "IoDeleteDevice",
        "IoCompleteRequest",
        "IoCreateDriver",
        "DriverEntry",
        "IRP_MJ_DEVICE_CONTROL",
    ] {
        if lower.contains(&name.to_ascii_lowercase()) {
            return Some(name.to_string());
        }
    }
    None
}

fn extract_ioctl_codes(text: &str) -> Vec<String> {
    let mut rows = Vec::new();
    let lower = text.to_ascii_lowercase();
    if lower.contains("ioctl") || lower.contains("ctl_code") {
        for token in text.split(|ch: char| !ch.is_ascii_hexdigit() && ch != 'x' && ch != 'X') {
            let normalized = token.trim();
            if normalized.len() >= 6 && normalized.starts_with("0x") {
                rows.push(normalized.to_string());
            }
        }
    }
    rows
}
