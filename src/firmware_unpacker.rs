use crate::portable::{
    first_guid, write_portable_artifact, FirmwareModuleRecord, PortableInput,
    UnpackedArtifactRecord,
};

pub fn build_firmware_modules(
    input: &PortableInput<'_>,
) -> (Vec<FirmwareModuleRecord>, Vec<UnpackedArtifactRecord>) {
    let source_lower = input.source_path.to_ascii_lowercase();
    let is_efi = source_lower.ends_with(".efi");
    let te_hint = input.bytes.get(0..2).is_some_and(|bytes| bytes == b"VZ");
    let fv_offset = find_bytes(input.bytes, b"_FVH");
    let efi_hint = input
        .exports
        .iter()
        .any(|row| row.name.eq_ignore_ascii_case("efi_main"))
        || input.strings.iter().any(|row| {
            let text = row.text.to_ascii_lowercase();
            text.contains("uefi")
                || text.contains("dxe")
                || text.contains("pei")
                || text.contains("smm")
        });
    if !(is_efi || efi_hint || te_hint || fv_offset.is_some()) {
        return (Vec::new(), Vec::new());
    }

    let module_type = if te_hint {
        "te_image"
    } else if fv_offset.is_some() {
        "firmware_volume"
    } else {
        "efi_pe"
    };
    let classification = if input
        .strings
        .iter()
        .any(|row| row.text.to_ascii_lowercase().contains("dxe"))
    {
        "dxe_driver"
    } else {
        "uefi_module"
    };
    let module = FirmwareModuleRecord {
        module_id: "firmware:native:0000".to_string(),
        module_type: module_type.to_string(),
        classification: classification.to_string(),
        smm_indicator: input
            .strings
            .iter()
            .any(|row| row.text.to_ascii_lowercase().contains("smm")),
        guid: first_guid(input.strings),
        evidence: vec![
            "te_header_or_firmware_volume_or_efi_metadata".to_string(),
            format!("source={}", input.source_path),
        ],
    };
    let data_len = input.bytes.len().min(4096);
    let (output_path, failure_reason) = write_portable_artifact(
        input.out_dir,
        "firmware_module_0000.bin",
        &input.bytes[..data_len],
    );
    let artifact = UnpackedArtifactRecord {
        artifact_id: "artifact:firmware:0000".to_string(),
        parent_sha256: input.sha256.to_string(),
        method: "firmware_module_extract".to_string(),
        confidence: if te_hint || fv_offset.is_some() {
            "medium"
        } else {
            "low"
        }
        .to_string(),
        output_path,
        failure_reason,
        evidence: module.evidence.clone(),
    };
    (vec![module], vec![artifact])
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
